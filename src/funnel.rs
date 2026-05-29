use std::fmt;
use std::hash::{BuildHasher, Hash};
use std::iter::FusedIterator;
use std::marker::PhantomData;
use std::mem::{self, ManuallyDrop};
use std::ops::{ControlFlow, Index, Range};
use std::ptr;
use std::slice;

use allocator_api2::alloc::{Allocator, Global, Layout};
use equivalent::Equivalent;

use crate::common::DefaultHashBuilder;
use crate::common::arena::{self, Arena, ArenaSlots, SlotEntry};
use crate::common::config::{DEFAULT_RESERVE_FRACTION, GROUP_SIZE, INITIAL_CAPACITY};
use crate::common::control::{self, CTRL_EMPTY, CTRL_TOMBSTONE, ControlByte};
use crate::common::error::{EntryView, OccupiedError as CommonOccupiedError, TryReserveError};
use crate::common::iter::{
    IntoKeys as CommonIntoKeys, IntoValues as CommonIntoValues, Keys as CommonKeys, OccupiedSlots,
    Values as CommonValues,
};
use crate::common::math::{self, align, capacity, cast, probe};
use crate::common::simd;

/// Upper bound on `reserve_fraction`;
/// level capacities become unstable beyond this load factor.
pub(crate) const MAX_FUNNEL_RESERVE_FRACTION: f64 = 1.0 / 8.0;

/// One funnel level `A_i` (paper §5). Fixed grid of `β`-sized buckets `A_{i,j}`;
/// inserts hash to one bucket and probe within it. Overflow spills to `A_{i+1}`
/// (or the special array `A_{α+1}`).
struct BucketLevel<T> {
    ctrl_ptr: *mut u8,
    data_ptr: *mut T,
    capacity: u32,
    bucket_count_mask: u32,
    bucket_size_log2: u32,
    salt: u64,
    len: u32,
    tombstones: u32,
}

unsafe impl<T: Send> Send for BucketLevel<T> {}
unsafe impl<T: Sync> Sync for BucketLevel<T> {}

impl<T> ArenaSlots<T> for BucketLevel<T> {
    #[inline]
    fn ctrl_ptr(&self) -> *mut u8 {
        self.ctrl_ptr
    }
    #[inline]
    fn data_ptr(&self) -> *mut T {
        self.data_ptr
    }
    #[inline]
    fn capacity(&self) -> usize {
        self.capacity as usize
    }
}

impl<T> BucketLevel<T> {
    /// Stamps a fresh descriptor at the given arena ptrs.
    /// Caller advances the offset cursor.
    fn new_at(
        level_idx: usize,
        bucket_count: u32,
        bucket_width: u32,
        ctrl_ptr: *mut u8,
        data_ptr: *mut T,
    ) -> Self {
        let cap = bucket_count.saturating_mul(bucket_width);
        Self {
            ctrl_ptr,
            data_ptr,
            capacity: cap,
            bucket_count_mask: bucket_count.saturating_sub(1),
            bucket_size_log2: bucket_width.trailing_zeros(),
            salt: math::level_salt(level_idx),
            len: 0,
            tombstones: 0,
        }
    }

    #[inline]
    fn bucket_index(&self, key_hash: u64) -> usize {
        probe::hash_to_usize(key_hash ^ self.salt) & self.bucket_count_mask as usize
    }

    /// Slot index range covering all entries in `bucket_idx`.
    #[inline]
    fn bucket_range(&self, bucket_idx: usize) -> Range<usize> {
        let start = bucket_idx << self.bucket_size_log2;
        let size = 1usize << self.bucket_size_log2;
        start..start + size
    }

    /// Paper §5 attempted insertion: hash `key_hash` to one bucket `A_{i,j}`,
    /// return the first empty slot in that bucket (or `None` if full).
    fn first_free_in_bucket(&self, key_hash: u64) -> Option<usize> {
        if self.len >= self.capacity {
            return None;
        }
        let bucket_idx = self.bucket_index(key_hash);
        let bucket_range = self.bucket_range(bucket_idx);
        debug_assert_eq!(bucket_range.start % GROUP_SIZE, 0);
        if !bucket_range.start.is_multiple_of(GROUP_SIZE) {
            unsafe { std::hint::unreachable_unchecked() };
        }
        let group_idx = bucket_range.start / GROUP_SIZE;
        let group_ptr = unsafe { self.ctrl_ptr().add(group_idx * GROUP_SIZE) };
        unsafe { simd::free_mask_16(group_ptr) }
            .lowest()
            .map(|offset| bucket_range.start + offset)
    }

    /// Erase slot: become `CTRL_EMPTY` if the bucket has any EMPTY byte
    /// (probe chain terminates here), else `CTRL_TOMBSTONE`.
    /// Returns whether a tombstone was written.
    #[inline]
    fn erase(&self, idx: usize) -> bool {
        let group_idx = idx / GROUP_SIZE;
        let gp = unsafe { self.ctrl_ptr().add(group_idx * GROUP_SIZE) };
        if unsafe { simd::eq_mask_16(gp, CTRL_EMPTY).any() } {
            self.set_control(idx, CTRL_EMPTY);
            false
        } else {
            self.set_control(idx, CTRL_TOMBSTONE);
            true
        }
    }
}

impl<K, V> BucketLevel<SlotEntry<K, V>> {
    /// Probe one bucket for `key`. `StopSearch` on EMPTY: bucket never
    /// overflowed, so the key isn't at a deeper level. Pass `Some(out)`
    /// to record the first free slot; `None` for lookup.
    #[inline]
    fn find_in_bucket<Q>(
        &self,
        key_hash: u64,
        key_fingerprint: u8,
        key: &Q,
        slot_out: Option<&mut Option<usize>>,
    ) -> LookupStep
    where
        Q: Equivalent<K> + ?Sized,
    {
        let wants_free = matches!(&slot_out, Some(out) if out.is_none());
        if self.len == 0 {
            if self.capacity == 0 {
                return LookupStep::Continue;
            }
            if wants_free {
                let bucket_idx = self.bucket_index(key_hash);
                let slot_idx = bucket_idx << self.bucket_size_log2;
                if let Some(out) = slot_out {
                    *out = Some(slot_idx);
                }
            }
            if self.tombstones == 0 {
                return LookupStep::StopSearch;
            }
            return LookupStep::Continue;
        }
        let bucket_idx = self.bucket_index(key_hash);
        let bucket_range = self.bucket_range(bucket_idx);
        debug_assert_eq!(bucket_range.start % GROUP_SIZE, 0);
        if !bucket_range.start.is_multiple_of(GROUP_SIZE) {
            unsafe { std::hint::unreachable_unchecked() };
        }
        let group_idx = bucket_range.start / GROUP_SIZE;
        let group_ptr = unsafe { self.ctrl_ptr().add(group_idx * GROUP_SIZE) };
        let match_mask = unsafe { simd::eq_mask_16(group_ptr, key_fingerprint) };
        for relative_idx in match_mask {
            let slot_idx = bucket_range.start + relative_idx;
            let entry = unsafe { &*self.data_ptr().add(slot_idx) };
            if key.equivalent(&entry.key) {
                return LookupStep::Found(slot_idx);
            }
        }
        if wants_free {
            let free_mask = unsafe { simd::free_mask_16(group_ptr) };
            if let Some(o) = free_mask.lowest()
                && let Some(out) = slot_out
            {
                *out = Some(bucket_range.start + o);
            }
        }
        if unsafe { simd::eq_mask_16(group_ptr, CTRL_EMPTY).any() } {
            LookupStep::StopSearch
        } else {
            LookupStep::Continue
        }
    }
}

/// Per-key odd-step probe over pow2 group count (paper §5 `SpecialPrimary`).
/// Step coprime to `group_count` ⇒ permutation over all groups.
struct ProbeSeq {
    group: usize,
    step: usize,
}

impl ProbeSeq {
    #[inline]
    fn new(group: usize, step: usize) -> Self {
        Self { group, step }
    }

    #[inline]
    fn advance(&mut self, mask: usize) {
        self.group = (self.group + self.step) & mask;
    }
}

/// Half `B` of the special array `A_{α+1}` (paper §5):
/// uniform-probing table capped at `primary_probe_limit` ≈ log log n probes.
/// SIMD-group open addressing with per-key odd-step probing over pow2 `group_count`
/// (step coprime to `group_count` ⇒ permutation over all groups).
struct SpecialPrimary<T> {
    ctrl_ptr: *mut u8,
    data_ptr: *mut T,
    capacity: u32,
    group_count_mask: u32,
    len: u32,
    tombstones: u32,
}

unsafe impl<T: Send> Send for SpecialPrimary<T> {}
unsafe impl<T: Sync> Sync for SpecialPrimary<T> {}

impl<T> ArenaSlots<T> for SpecialPrimary<T> {
    #[inline]
    fn ctrl_ptr(&self) -> *mut u8 {
        self.ctrl_ptr
    }
    #[inline]
    fn data_ptr(&self) -> *mut T {
        self.data_ptr
    }
    #[inline]
    fn capacity(&self) -> usize {
        self.capacity as usize
    }
}

impl<T> SpecialPrimary<T> {
    /// Stamps a fresh primary descriptor.
    /// `group_count_mask` = `group_count - 1` (pow2-1) so probes wrap `& mask`.
    fn new_at(cap: u32, group_count_mask: u32, ctrl_ptr: *mut u8, data_ptr: *mut T) -> Self {
        Self {
            ctrl_ptr,
            data_ptr,
            capacity: cap,
            group_count_mask,
            len: 0,
            tombstones: 0,
        }
    }

    #[inline]
    fn group_count(&self) -> usize {
        if self.capacity == 0 {
            0
        } else {
            self.capacity as usize / GROUP_SIZE
        }
    }
    #[inline]
    fn group_start(&self, key_hash: u64) -> usize {
        probe::hash_to_usize(key_hash.rotate_left(11)) & self.group_count_mask as usize
    }
    /// Per-key odd step over the pow2 `group_count`. The `| 1` forces odd ⇒
    /// coprime to pow2 ⇒ `(group_idx + step) & mask` visits every group
    /// within `group_count` iterations.
    #[inline]
    fn group_step(&self, key_hash: u64) -> usize {
        (probe::hash_to_usize(key_hash.rotate_left(43)) | 1) & self.group_count_mask as usize
    }

    /// Erase slot: drop tombstone unless the group has free space.
    #[inline]
    fn erase(&self, idx: usize) -> bool {
        let group_idx = idx / GROUP_SIZE;
        let gp = unsafe { self.ctrl_ptr().add(group_idx * GROUP_SIZE) };
        if unsafe { simd::eq_mask_16(gp, CTRL_EMPTY).any() } {
            self.set_control(idx, CTRL_EMPTY);
            false
        } else {
            self.set_control(idx, CTRL_TOMBSTONE);
            true
        }
    }
}

/// Half `C` of the special array `A_{α+1}` (paper §5):
/// two-choice table with buckets of size `2 * primary_probe_limit` ≈ 2 log log n.
/// Reached only when a key exhausts the primary's probe budget.
struct SpecialFallback<T> {
    ctrl_ptr: *mut u8,
    data_ptr: *mut T,
    capacity: u32,
    bucket_count: u32,
    bucket_size_log2: u32,
    len: u32,
    tombstones: u32,
}

unsafe impl<T: Send> Send for SpecialFallback<T> {}
unsafe impl<T: Sync> Sync for SpecialFallback<T> {}

impl<T> ArenaSlots<T> for SpecialFallback<T> {
    #[inline]
    fn ctrl_ptr(&self) -> *mut u8 {
        self.ctrl_ptr
    }
    #[inline]
    fn data_ptr(&self) -> *mut T {
        self.data_ptr
    }
    #[inline]
    fn capacity(&self) -> usize {
        self.capacity as usize
    }
}

impl<T> SpecialFallback<T> {
    /// Stamps a fresh fallback descriptor with two-choice bucket geometry.
    fn new_at(
        cap: u32,
        bucket_count: u32,
        bucket_size_log2: u32,
        ctrl_ptr: *mut u8,
        data_ptr: *mut T,
    ) -> Self {
        Self {
            ctrl_ptr,
            data_ptr,
            capacity: cap,
            bucket_count,
            bucket_size_log2,
            len: 0,
            tombstones: 0,
        }
    }

    #[inline]
    fn bucket_range(&self, bucket_idx: usize) -> Range<usize> {
        let start = bucket_idx << self.bucket_size_log2;
        let size = 1usize << self.bucket_size_log2;
        let end = (start + size).min(self.capacity as usize);
        start..end
    }
    #[inline]
    fn bucket_a(&self, key_hash: u64) -> usize {
        probe::hash_to_usize(key_hash.rotate_left(19)) % self.bucket_count as usize
    }
    #[inline]
    fn bucket_b(&self, key_hash: u64) -> usize {
        probe::hash_to_usize(key_hash.rotate_left(37)) % self.bucket_count as usize
    }

    /// Erase slot: drop tombstone unless the group has free space.
    #[inline]
    fn erase(&self, idx: usize) -> bool {
        let group_idx = idx / GROUP_SIZE;
        let gp = unsafe { self.ctrl_ptr().add(group_idx * GROUP_SIZE) };
        if unsafe { simd::eq_mask_16(gp, CTRL_EMPTY).any() } {
            self.set_control(idx, CTRL_EMPTY);
            false
        } else {
            self.set_control(idx, CTRL_TOMBSTONE);
            true
        }
    }
}

/// Combines the special primary (probed first) and the special fallback
/// (when primary hits its probe limit). Together they catch keys that
/// overflowed every bucket level.
struct SpecialArray<T> {
    primary: SpecialPrimary<T>,
    fallback: SpecialFallback<T>,
    total_len: usize,
}

impl<T> SpecialArray<T> {
    /// Drain primary + fallback, calling `f` on each entry. Each slot's
    /// ctrl is cleared *before* the move so an `f` panic leaves no
    /// OCCUPIED ctrl for the map's drop to double-drop.
    fn for_each_occupied<F: FnMut(T)>(&self, mut f: F) {
        for idx in self.primary.occupied() {
            self.primary.set_control(idx, CTRL_EMPTY);
            f(unsafe { self.primary.take(idx) });
        }
        for idx in self.fallback.occupied() {
            self.fallback.set_control(idx, CTRL_EMPTY);
            f(unsafe { self.fallback.take(idx) });
        }
    }
}

/// Where in the funnel structure a key/slot lives. Returned by lookups,
/// consumed by inserts / removes to avoid recomputing the location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotLocation {
    Level { level_idx: usize, slot_idx: usize },
    SpecialPrimary { slot_idx: usize },
    SpecialFallback { slot_idx: usize },
}

/// Out-parameter for free-slot tracking during probes.
/// `None` = lookup-only; `Some(out)` = also record the first free
/// `SlotLocation` seen. Written once; ignored if `*out` is already `Some`.
type FreeSlot<'a> = Option<&'a mut Option<SlotLocation>>;

/// Outcome of probing one bucket / group during lookup.
/// - `Found(slot_idx)`: key matched at slot.
/// - `Continue`: bucket has tombstones; keep probing for the key elsewhere.
/// - `StopSearch`: bucket has free space and no tombstones — key cannot
///   exist further along this hash chain, abort the search.
enum LookupStep {
    Found(usize),
    Continue,
    StopSearch,
}

/// Outcome of the level-walk on a miss.
enum LevelMiss {
    /// EMPTY byte seen; no overflow to special possible.
    ChainClean,
    /// Loop exhausted; key may be in the special array.
    MayContinue,
}

/// Open-addressed hash map using funnel hashing.
///
/// Capacity is split between a stack of bucket-grouped `levels` (each level
/// half the size of the previous) and a `special` array catching overflow.
/// Inserts try level 0 first, then descend to deeper levels, then to
/// `special.primary`, then `special.fallback`. Lookups follow the same
/// order. The funnel structure trades a small probe budget per level for
/// hard worst-case guarantees on lookup cost.
///
/// **Lower bound**: paper §4 proves any greedy open-addressing scheme needs
/// `Ω(log² δ⁻¹)` worst-case probes (`δ` = empty fraction). Funnel matches
/// this asymptotically — no constant-factor rewrite can do better.
pub struct FunnelHashMap<K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    /// Level descriptors (bucket-grouped).
    levels: BucketLevelSlice<K, V>,
    /// Special array descriptor.
    special: SpecialArray<SlotEntry<K, V>>,
    /// Total live entries.
    len: usize,
    /// Total slot count across all levels + special arrays.
    total_slots: usize,
    /// Insert count that triggers resize.
    max_insertions: usize,
    /// Slot reserve fraction.
    reserve_fraction: f64,
    /// Cap on groups probed in the special primary before fallback.
    primary_probe_limit: usize,
    /// Highest level index ever written.
    max_populated_level: usize,
    hash_builder: S,
    alloc: A,
    /// Single allocation: [`ctrl_L0|ctrl_L1|...|ctrl_SP|ctrl_SF`][pad][`slots_L0|...|slots_SP|slots_SF`].
    arena: Arena,
}

unsafe impl<K: Send, V: Send, S: Send, A: Allocator + Clone + Send> Send
    for FunnelHashMap<K, V, S, A>
{
}
unsafe impl<K: Sync, V: Sync, S: Sync, A: Allocator + Clone + Sync> Sync
    for FunnelHashMap<K, V, S, A>
{
}

impl<K, V, S, A: Allocator + Clone> Drop for FunnelHashMap<K, V, S, A> {
    fn drop(&mut self) {
        let arena = mem::replace(&mut self.arena, Arena::empty());
        let guard = arena::DeallocGuard::new(arena, &self.alloc);
        for level in &self.levels {
            level.drop_values();
        }
        self.special.primary.drop_values();
        self.special.fallback.drop_values();
        drop(guard);
    }
}

impl<K, V, S, A> fmt::Debug for FunnelHashMap<K, V, S, A>
where
    K: fmt::Debug + Eq + Hash,
    V: fmt::Debug,
    S: BuildHasher,
    A: Allocator + Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<K, V> Default for FunnelHashMap<K, V, DefaultHashBuilder, Global>
where
    K: Eq + Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

// Global allocator + default hasher constructors.
impl<K, V> FunnelHashMap<K, V, DefaultHashBuilder, Global>
where
    K: Eq + Hash,
{
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity_and_reserve_fraction(0, DEFAULT_RESERVE_FRACTION)
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_capacity_and_reserve_fraction(capacity, DEFAULT_RESERVE_FRACTION)
    }

    #[must_use]
    pub fn with_reserve_fraction(reserve_fraction: f64) -> Self {
        Self::with_capacity_and_reserve_fraction(0, reserve_fraction)
    }

    #[must_use]
    pub fn with_capacity_and_reserve_fraction(capacity: usize, reserve_fraction: f64) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            capacity,
            reserve_fraction,
            DefaultHashBuilder::default(),
            Global,
        )
    }
}

// Global allocator + custom hasher constructors.
impl<K, V, S> FunnelHashMap<K, V, S, Global>
where
    K: Eq + Hash,
    S: BuildHasher,
{
    #[must_use]
    pub fn with_hasher(hash_builder: S) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            0,
            DEFAULT_RESERVE_FRACTION,
            hash_builder,
            Global,
        )
    }

    #[must_use]
    pub fn with_capacity_and_hasher(capacity: usize, hash_builder: S) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            capacity,
            DEFAULT_RESERVE_FRACTION,
            hash_builder,
            Global,
        )
    }

    #[must_use]
    pub fn with_reserve_fraction_and_hasher(reserve_fraction: f64, hash_builder: S) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            0,
            reserve_fraction,
            hash_builder,
            Global,
        )
    }

    #[must_use]
    pub fn with_capacity_and_reserve_fraction_and_hasher(
        capacity: usize,
        reserve_fraction: f64,
        hash_builder: S,
    ) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            capacity,
            reserve_fraction,
            hash_builder,
            Global,
        )
    }
}

// Default hasher + custom allocator constructors.
impl<K, V, A> FunnelHashMap<K, V, DefaultHashBuilder, A>
where
    K: Eq + Hash,
    A: Allocator + Clone,
{
    #[must_use]
    pub fn new_in(alloc: A) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            0,
            DEFAULT_RESERVE_FRACTION,
            DefaultHashBuilder::default(),
            alloc,
        )
    }

    #[must_use]
    pub fn with_capacity_in(capacity: usize, alloc: A) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            capacity,
            DEFAULT_RESERVE_FRACTION,
            DefaultHashBuilder::default(),
            alloc,
        )
    }
}

/// Total ctrl bytes for a funnel layout. Each level rounds bucket count up
/// to pow2 then multiplies by `bw`; special arrays are pre-rounded.
fn funnel_total_ctrl(
    level_bucket_counts: &[usize],
    bucket_width: usize,
    primary_ctrl: usize,
    fallback_ctrl: usize,
) -> usize {
    let bw = bucket_width.next_power_of_two();
    level_bucket_counts
        .iter()
        .map(|&bc| {
            let bc = if bc == 0 { 0 } else { bc.next_power_of_two() };
            bc.saturating_mul(bw)
        })
        .sum::<usize>()
        + primary_ctrl
        + fallback_ctrl
}

/// Fallible single-arena builder for a funnel map.
///
/// `bucket_width` is rounded up to a power of two and applied to each
/// `level_bucket_counts` entry (also rounded up). Returns the arena and
/// the level + special descriptors with offsets stamped into a single
/// contiguous allocation:
/// `[ctrls_L0|ctrls_L1|...|sp_ctrl|sf_ctrl][pad][slots_L0|...|sf_slots]`.
type BucketLevelSlice<K, V> = Box<[BucketLevel<SlotEntry<K, V>>]>;

type FunnelArenaBuild<K, V> = (Arena, BucketLevelSlice<K, V>, SpecialArray<SlotEntry<K, V>>);

/// Subset of [`FunnelArenaBuild`] minus the arena — built by the inner
/// closure of `try_alloc_funnel_arena` so a failure deallocates the arena
/// before returning.
type FunnelArenaInner<K, V> = (BucketLevelSlice<K, V>, SpecialArray<SlotEntry<K, V>>);

/// Layout inputs for [`build_funnel_regions`]: levels + special arrays
/// with their pre-rounded sizes. Split out to keep the builder shallow.
struct FunnelGeometry<'a> {
    level_bucket_counts: &'a [usize],
    bucket_width: u32,
    primary_ctrl: usize,
    fallback_ctrl: usize,
    fallback_bucket_size: usize,
}

/// Stamps level + special descriptors from the arena base. Split out so the
/// alloc-then-deallocate-on-error wrapper stays shallow.
fn build_funnel_regions<K, V>(
    arena_base: *mut u8,
    data_base_off: usize,
    geom: &FunnelGeometry<'_>,
) -> Result<FunnelArenaInner<K, V>, TryReserveError> {
    let slot_size = u32::try_from(mem::size_of::<SlotEntry<K, V>>())
        .map_err(|_| TryReserveError::CapacityOverflow)?;
    let mut ctrl_off: u32 = 0;
    let mut data_off: u32 =
        u32::try_from(data_base_off).map_err(|_| TryReserveError::CapacityOverflow)?;

    let mut levels: Vec<BucketLevel<SlotEntry<K, V>>> = Vec::new();
    levels
        .try_reserve_exact(geom.level_bucket_counts.len())
        .map_err(|_| TryReserveError::AllocError)?;
    let bw32 = geom.bucket_width;
    for (level_idx, &bc_raw) in geom.level_bucket_counts.iter().enumerate() {
        let bc = u32::try_from(if bc_raw == 0 {
            0
        } else {
            bc_raw.next_power_of_two()
        })
        .map_err(|_| TryReserveError::CapacityOverflow)?;
        let cap = bc.saturating_mul(bw32);
        let ctrl_ptr = unsafe { arena_base.add(ctrl_off as usize) };
        let data_ptr = unsafe { arena_base.add(data_off as usize).cast::<SlotEntry<K, V>>() };
        levels.push(BucketLevel::new_at(level_idx, bc, bw32, ctrl_ptr, data_ptr));
        ctrl_off += cap;
        data_off += cap * slot_size;
    }

    let primary_cap =
        u32::try_from(geom.primary_ctrl).map_err(|_| TryReserveError::CapacityOverflow)?;
    let primary_gc_mask = u32::try_from(geom.primary_ctrl / GROUP_SIZE)
        .map_err(|_| TryReserveError::CapacityOverflow)?
        .wrapping_sub(1);
    let primary_ctrl_ptr = unsafe { arena_base.add(ctrl_off as usize) };
    let primary_data_ptr = unsafe { arena_base.add(data_off as usize).cast::<SlotEntry<K, V>>() };
    let primary = SpecialPrimary::new_at(
        primary_cap,
        primary_gc_mask,
        primary_ctrl_ptr,
        primary_data_ptr,
    );
    ctrl_off += primary_cap;
    data_off += primary_cap * slot_size;

    let fallback_cap =
        u32::try_from(geom.fallback_ctrl).map_err(|_| TryReserveError::CapacityOverflow)?;
    let fb_size = geom.fallback_bucket_size.next_power_of_two();
    let fb_count = u32::try_from(if fb_size == 0 {
        0
    } else {
        geom.fallback_ctrl.div_ceil(fb_size)
    })
    .map_err(|_| TryReserveError::CapacityOverflow)?;
    let fb_log2 = u32::try_from(fb_size)
        .map_err(|_| TryReserveError::CapacityOverflow)?
        .trailing_zeros();
    let fallback_ctrl_ptr = unsafe { arena_base.add(ctrl_off as usize) };
    let fallback_data_ptr = unsafe { arena_base.add(data_off as usize).cast::<SlotEntry<K, V>>() };
    let fallback = SpecialFallback::new_at(
        fallback_cap,
        fb_count,
        fb_log2,
        fallback_ctrl_ptr,
        fallback_data_ptr,
    );

    Ok((
        levels.into_boxed_slice(),
        SpecialArray {
            primary,
            fallback,
            total_len: 0,
        },
    ))
}

fn try_alloc_funnel_arena<K, V, A: Allocator + Clone>(
    level_bucket_counts: &[usize],
    bucket_width: usize,
    special_primary_capacity: usize,
    special_fallback_capacity: usize,
    fallback_bucket_size: usize,
    alloc: &A,
) -> Result<FunnelArenaBuild<K, V>, TryReserveError> {
    let bw = bucket_width.next_power_of_two();
    let primary_ctrl = align::round_up_to_pow2_groups(special_primary_capacity);
    let fallback_ctrl = align::round_up_to_group(special_fallback_capacity);
    let total_ctrl = funnel_total_ctrl(
        level_bucket_counts,
        bucket_width,
        primary_ctrl,
        fallback_ctrl,
    );
    let (arena_layout, data_base_off) = arena::layout_for::<K, V>(total_ctrl)?;
    let arena = Arena::try_allocate_with_ctrl_zeroed(arena_layout, total_ctrl, alloc)?;

    let Ok(bw32) = u32::try_from(bw) else {
        arena.deallocate(alloc);
        return Err(TryReserveError::CapacityOverflow);
    };
    let geom = FunnelGeometry {
        level_bucket_counts,
        bucket_width: bw32,
        primary_ctrl,
        fallback_ctrl,
        fallback_bucket_size,
    };

    // `Arena` has no `Drop`, so a bare `?` would leak the allocation if
    // region construction fails. Deallocate explicitly on `Err`.
    match build_funnel_regions::<K, V>(arena.as_ptr(), data_base_off, &geom) {
        Ok((levels, special)) => Ok((arena, levels, special)),
        Err(e) => {
            arena.deallocate(alloc);
            Err(e)
        }
    }
}

fn alloc_funnel_arena<K, V, A: Allocator + Clone>(
    level_bucket_counts: &[usize],
    bucket_width: usize,
    special_primary_capacity: usize,
    special_fallback_capacity: usize,
    fallback_bucket_size: usize,
    alloc: &A,
) -> FunnelArenaBuild<K, V> {
    try_alloc_funnel_arena(
        level_bucket_counts,
        bucket_width,
        special_primary_capacity,
        special_fallback_capacity,
        fallback_bucket_size,
        alloc,
    )
    .unwrap_or_else(|_| {
        let primary_ctrl = align::round_up_to_pow2_groups(special_primary_capacity);
        let fallback_ctrl = align::round_up_to_group(special_fallback_capacity);
        let total_ctrl = funnel_total_ctrl(
            level_bucket_counts,
            bucket_width,
            primary_ctrl,
            fallback_ctrl,
        );
        let layout = match arena::layout_for::<K, V>(total_ctrl) {
            Ok((l, _)) => l,
            Err(_) => Layout::from_size_align(1, 1).unwrap(),
        };
        allocator_api2::alloc::handle_alloc_error(layout)
    })
}

/// Drops occupied slots + deallocates the arena if dropped before
/// extraction. Lets `Clone` panic-safely roll back when user `K::clone` /
/// `V::clone` unwinds — `Arena` has no `Drop`. Owns levels + special so
/// mut-iteration borrows from the guard.
struct ArenaDropGuard<K, V, A: Allocator + Clone> {
    arena: Option<Arena>,
    levels: Option<BucketLevelSlice<K, V>>,
    special: Option<SpecialArray<SlotEntry<K, V>>>,
    alloc: A,
}

impl<K, V, A: Allocator + Clone> Drop for ArenaDropGuard<K, V, A> {
    fn drop(&mut self) {
        if let Some(arena) = self.arena.take() {
            if let Some(levels) = self.levels.take() {
                for level in &levels {
                    level.drop_values();
                }
            }
            if let Some(special) = self.special.take() {
                special.primary.drop_values();
                special.fallback.drop_values();
            }
            arena.deallocate(&self.alloc);
        }
    }
}

impl<K, V, S, A> FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    /// Full constructor. `resize` also calls this with the existing
    /// `hash_builder` and allocator so all keys keep the same hash sequence
    /// across grows.
    ///
    /// # Panics
    ///
    /// Panics if no representable capacity satisfies the requested budget.
    #[must_use]
    pub fn with_capacity_and_reserve_fraction_and_hasher_in(
        capacity: usize,
        reserve_fraction: f64,
        hash_builder: S,
        alloc: A,
    ) -> Self {
        // Paper §5 precondition: δ ≤ 1/8.
        let reserve_fraction =
            capacity::sanitize_reserve_fraction(reserve_fraction).min(MAX_FUNNEL_RESERVE_FRACTION);
        let total_slots = if capacity == 0 {
            0
        } else {
            capacity::capacity_for(INITIAL_CAPACITY, capacity, reserve_fraction)
                .expect("capacity overflow")
        };
        let max_insertions = capacity::max_insertions(total_slots, reserve_fraction);

        let level_count = compute_level_count(reserve_fraction);
        let bucket_width = align::round_up_to_group(compute_bucket_width(reserve_fraction));
        let primary_probe_limit = probe::log_log_probe_limit(total_slots).max(1);

        let mut special_capacity =
            choose_special_capacity(total_slots, reserve_fraction, bucket_width);
        let mut main_capacity = total_slots.saturating_sub(special_capacity);
        let main_remainder = main_capacity % bucket_width.max(1);
        if main_remainder != 0 {
            main_capacity = main_capacity.saturating_sub(main_remainder);
            special_capacity = total_slots.saturating_sub(main_capacity);
        }

        let total_main_buckets = main_capacity.checked_div(bucket_width).unwrap_or(0);
        let level_bucket_counts = partition_funnel_buckets(total_main_buckets, level_count);
        let fallback_bucket_size = (primary_probe_limit.saturating_mul(2)).max(2);
        let primary_ctrl = align::round_up_to_pow2_groups(special_capacity.div_ceil(2));
        let fallback_ctrl =
            align::round_up_to_group(special_capacity.saturating_sub(special_capacity.div_ceil(2)));

        let (arena, levels, special) = alloc_funnel_arena(
            &level_bucket_counts,
            bucket_width,
            primary_ctrl,
            fallback_ctrl,
            fallback_bucket_size,
            &alloc,
        );

        Self {
            levels,
            special,
            len: 0,
            total_slots,
            max_insertions,
            reserve_fraction,
            primary_probe_limit,
            max_populated_level: 0,
            hash_builder,
            alloc,
            arena,
        }
    }

    /// Reference to the map's allocator.
    #[must_use]
    pub fn allocator(&self) -> &A {
        &self.alloc
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Maximum number of inserts the map can absorb before the next resize.
    /// Mirrors [`std::collections::HashMap::capacity`] — returns the insert
    /// budget, not the raw slot count (see `total_slots` field).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.max_insertions
    }

    /// Grow capacity so at least `additional` more inserts fit. No-op if
    /// already large enough. Probe-budget exhaustion may still trigger a
    /// resize mid-fill.
    ///
    /// # Panics
    ///
    /// Panics on capacity overflow. Use [`Self::try_reserve`] for fallible
    /// growth.
    pub fn reserve(&mut self, additional: usize) {
        let needed = self.len.saturating_add(additional);
        if needed <= self.max_insertions {
            return;
        }
        let new_capacity = self.grow_capacity_for(needed).expect("capacity overflow");
        self.resize(new_capacity);
    }

    /// Fallible counterpart to [`Self::reserve`].
    ///
    /// # Errors
    ///
    /// [`TryReserveError::CapacityOverflow`] if `self.len + additional`
    /// overflows; [`TryReserveError::AllocError`] on allocator failure.
    pub fn try_reserve(&mut self, additional: usize) -> Result<(), TryReserveError>
    where
        S: Clone,
    {
        let needed = self
            .len
            .checked_add(additional)
            .ok_or(TryReserveError::CapacityOverflow)?;
        if needed <= self.max_insertions {
            return Ok(());
        }
        let new_capacity = self
            .grow_capacity_for(needed)
            .ok_or(TryReserveError::CapacityOverflow)?;
        self.try_resize(new_capacity)
    }

    /// Shrinks the capacity as much as possible while preserving all live
    /// entries. Mirrors [`std::collections::HashMap::shrink_to_fit`].
    pub fn shrink_to_fit(&mut self) {
        self.shrink_to(0);
    }

    /// Shrinks the capacity with a lower bound. The table won't shrink below
    /// the larger of `min_capacity` and `self.len`. Mirrors
    /// [`std::collections::HashMap::shrink_to`].
    ///
    /// # Panics
    ///
    /// Panics if no representable capacity satisfies
    /// `capacity::max_insertions(cap) >= min_capacity`.
    pub fn shrink_to(&mut self, min_capacity: usize) {
        if self.len == 0 && min_capacity == 0 {
            if self.total_slots > 0 {
                self.resize(0);
            }
            return;
        }
        let lower = self.len.max(min_capacity).max(INITIAL_CAPACITY);
        let new_capacity = capacity::capacity_for(INITIAL_CAPACITY, lower, self.reserve_fraction)
            .expect("capacity overflow");
        if new_capacity >= self.total_slots {
            return;
        }
        self.resize(new_capacity);
    }

    /// Round up to the smallest capacity whose `max_insertions` accommodates
    /// `needed` live entries. Returns `None` if no representable capacity
    /// suffices.
    fn grow_capacity_for(&self, needed: usize) -> Option<usize> {
        capacity::capacity_for(
            self.total_slots.max(INITIAL_CAPACITY),
            needed,
            self.reserve_fraction,
        )
    }

    /// # Panics
    ///
    /// Panics if a resize succeeds but no free slot can be found for the new key.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let key_hash = self.hash_key(&key);
        let key_fingerprint = control::control_fingerprint(key_hash);

        // Scan levels: on match, replace; on miss, retain the first free
        // slot we saw as the insertion candidate.
        let mut candidate: Option<SlotLocation> = None;
        let (found, miss) =
            self.find_in_levels(&key, key_hash, key_fingerprint, Some(&mut candidate));
        if let Some(location) = found {
            return Some(self.replace_existing_value(location, value));
        }

        // Fast path: skip special-array dedup if either:
        // (1) the level chain terminated via a clean EMPTY byte — no
        //     TOMBSTONE seen, so the key cannot have overflowed to special;
        // (2) special is entirely empty.
        // Condition (1) checked first: it's a register value, avoiding the
        // `total_len` memory load when the chain ended cleanly.
        // Both cases require a level-side candidate to place the new entry.
        if candidate.is_some()
            && (matches!(miss, LevelMiss::ChainClean) || self.special.total_len == 0)
        {
            return self.insert_at_location_after_resize_check(
                candidate,
                key_hash,
                key,
                value,
                key_fingerprint,
            );
        }

        // Cold path: key might be in the special array. Outlined to keep insert's hot body compact.
        if let Some(location) =
            self.find_in_special(&key, key_hash, key_fingerprint, Some(&mut candidate))
        {
            return Some(self.replace_existing_value(location, value));
        }

        self.insert_at_location_after_resize_check(candidate, key_hash, key, value, key_fingerprint)
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let key_hash = self.hash_key(key);
        let key_fingerprint = control::control_fingerprint(key_hash);

        let loc = self.find_slot_location_with_hash(key, key_hash, key_fingerprint)?;
        Some(unsafe { &self.slot_ref(loc).value })
    }

    /// Like [`Self::get`] but returns the stored key alongside its value.
    pub fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let key_hash = self.hash_key(key);
        let key_fingerprint = control::control_fingerprint(key_hash);

        let loc = self.find_slot_location_with_hash(key, key_hash, key_fingerprint)?;
        let entry = unsafe { self.slot_ref(loc) };
        Some((&entry.key, &entry.value))
    }

    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let key_hash = self.hash_key(key);
        let key_fingerprint = control::control_fingerprint(key_hash);

        let loc = self.find_slot_location_with_hash(key, key_hash, key_fingerprint)?;
        Some(unsafe { &mut self.slot_mut(loc).value })
    }

    /// Returns `N` disjoint mutable references, mirroring
    /// [`std::collections::HashMap::get_disjoint_mut`]: `None` if any key
    /// misses, panic on aliasing.
    ///
    /// # Panics
    ///
    /// If two input keys resolve to the same physical slot.
    /// Returns `N` disjoint mutable references, mirroring
    /// [`std::collections::HashMap::get_disjoint_mut`]: per-key `Option`
    /// for each lookup, panic on aliasing among the hits.
    ///
    /// # Panics
    ///
    /// If two input keys resolve to the same slot.
    pub fn get_disjoint_mut<Q, const N: usize>(&mut self, keys: [&Q; N]) -> [Option<&mut V>; N]
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let locations = self.locate_disjoint(keys);
        arena::check_disjoint_aliasing(&locations);

        let levels_ptr = self.levels.as_ptr().cast_mut();
        let primary_ptr = &raw mut self.special.primary;
        let fallback_ptr = &raw mut self.special.fallback;
        std::array::from_fn(|i| {
            locations[i].map(|loc| {
                // SAFETY: locations are unique among Somes (asserted above).
                // Raw-pointer chain — no intermediate `&mut BucketLevel`,
                // `&mut SpecialPrimary`, or `&mut SpecialFallback`.
                let value_ptr: *mut V =
                    unsafe { funnel_slot_value_ptr(levels_ptr, primary_ptr, fallback_ptr, loc) };
                unsafe { &mut *value_ptr }
            })
        })
    }

    /// Like [`Self::get_disjoint_mut`] but each yielded element is
    /// `(&K, &mut V)`. Mirrors `std`'s `get_disjoint_key_value_mut`.
    ///
    /// # Panics
    ///
    /// If two input keys resolve to the same slot.
    pub fn get_disjoint_key_value_mut<Q, const N: usize>(
        &mut self,
        keys: [&Q; N],
    ) -> [Option<(&K, &mut V)>; N]
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let locations = self.locate_disjoint(keys);
        arena::check_disjoint_aliasing(&locations);

        let levels_ptr = self.levels.as_ptr().cast_mut();
        let primary_ptr = &raw mut self.special.primary;
        let fallback_ptr = &raw mut self.special.fallback;
        std::array::from_fn(|i| {
            locations[i].map(|loc| {
                // SAFETY: as in `get_disjoint_mut`.
                let (k_ptr, v_ptr) =
                    unsafe { funnel_slot_kv_ptrs(levels_ptr, primary_ptr, fallback_ptr, loc) };
                (unsafe { &*k_ptr }, unsafe { &mut *v_ptr })
            })
        })
    }

    /// Unsafe variant of [`Self::get_disjoint_mut`] that skips the
    /// alias check. Mirrors [`std::collections::HashMap::get_disjoint_unchecked_mut`].
    ///
    /// # Safety
    ///
    /// Among the keys that resolve to occupied slots, all must reference
    /// distinct entries; otherwise the returned references alias and
    /// behavior is undefined.
    pub unsafe fn get_disjoint_unchecked_mut<Q, const N: usize>(
        &mut self,
        keys: [&Q; N],
    ) -> [Option<&mut V>; N]
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let locations = self.locate_disjoint(keys);

        let levels_ptr = self.levels.as_ptr().cast_mut();
        let primary_ptr = &raw mut self.special.primary;
        let fallback_ptr = &raw mut self.special.fallback;
        std::array::from_fn(|i| {
            locations[i].map(|loc| {
                // SAFETY: caller guarantees the hits are pairwise distinct.
                let value_ptr: *mut V =
                    unsafe { funnel_slot_value_ptr(levels_ptr, primary_ptr, fallback_ptr, loc) };
                unsafe { &mut *value_ptr }
            })
        })
    }

    #[inline]
    fn locate_disjoint<Q, const N: usize>(&self, keys: [&Q; N]) -> [Option<SlotLocation>; N]
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        std::array::from_fn(|i| {
            let key = keys[i];
            let key_hash = self.hash_key(key);
            let key_fingerprint = control::control_fingerprint(key_hash);
            self.find_slot_location_with_hash(key, key_hash, key_fingerprint)
        })
    }

    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let key_hash = self.hash_key(key);
        let key_fingerprint = control::control_fingerprint(key_hash);
        self.find_slot_location_with_hash(key, key_hash, key_fingerprint)
            .is_some()
    }

    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.remove_inner(key).map(|(_, v)| v)
    }

    /// Like [`Self::remove`] but returns the stored key alongside its value.
    pub fn remove_entry<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.remove_inner(key)
    }

    fn remove_inner<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let key_hash = self.hash_key(key);
        let key_fingerprint = control::control_fingerprint(key_hash);
        let location = self.find_slot_location_with_hash(key, key_hash, key_fingerprint)?;

        let (removed_entry, needs_resize) = match location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => {
                let level = &mut self.levels[level_idx];
                let removed = unsafe { level.take(slot_idx) };
                if level.erase(slot_idx) {
                    level.tombstones += 1;
                }
                level.len -= 1;
                let needs_resize = level.tombstones as usize > level.capacity() / 2;
                (removed, needs_resize)
            }
            SlotLocation::SpecialPrimary { slot_idx } => {
                let primary = &mut self.special.primary;
                let removed = unsafe { primary.take(slot_idx) };
                if primary.erase(slot_idx) {
                    primary.tombstones += 1;
                }
                primary.len -= 1;
                self.special.total_len -= 1;
                let needs_resize = primary.tombstones as usize > primary.capacity() / 2;
                (removed, needs_resize)
            }
            SlotLocation::SpecialFallback { slot_idx } => {
                let fallback = &mut self.special.fallback;
                let removed = unsafe { fallback.take(slot_idx) };
                if fallback.erase(slot_idx) {
                    fallback.tombstones += 1;
                }
                fallback.len -= 1;
                self.special.total_len -= 1;
                let needs_resize = fallback.tombstones as usize > fallback.capacity() / 2;
                (removed, needs_resize)
            }
        };

        self.len -= 1;
        self.shrink_max_populated_level();
        if needs_resize {
            self.resize(self.total_slots);
        }
        Some((removed_entry.key, removed_entry.value))
    }

    /// Borrowing iterator over `&K`. Order matches [`Self::iter`].
    #[must_use]
    pub fn keys(&self) -> Keys<'_, K, V, A> {
        Keys::new(self.iter())
    }

    /// Borrowing iterator over `&V`. Order matches [`Self::iter`].
    #[must_use]
    pub fn values(&self) -> Values<'_, K, V, A> {
        Values::new(self.iter())
    }

    /// Reference to the map's [`BuildHasher`].
    #[must_use]
    pub fn hasher(&self) -> &S {
        &self.hash_builder
    }

    #[must_use]
    pub fn iter(&self) -> FunnelIter<'_, K, V, A> {
        FunnelIter {
            regions: FunnelRegions::new(
                self.levels.as_ptr().cast_mut(),
                self.levels.len(),
                ptr::from_ref(&self.special.primary).cast_mut(),
                ptr::from_ref(&self.special.fallback).cast_mut(),
            ),
            remaining: self.len,
            _marker: PhantomData,
        }
    }

    /// Mutable iterator yielding `(&K, &mut V)`. Mirrors `HashMap::iter_mut`.
    pub fn iter_mut(&mut self) -> FunnelIterMut<'_, K, V, A> {
        let remaining = self.len;
        let map_ptr = ptr::from_mut(self);
        // Derive sub-ptrs through `map_ptr` so they share its borrow tag.
        let (levels_ptr, levels_len, primary, fallback) = unsafe {
            let levels = &mut (*map_ptr).levels;
            (
                levels.as_mut_ptr(),
                levels.len(),
                ptr::addr_of_mut!((*map_ptr).special.primary),
                ptr::addr_of_mut!((*map_ptr).special.fallback),
            )
        };
        FunnelIterMut {
            regions: FunnelRegions::new(levels_ptr, levels_len, primary, fallback),
            remaining,
            _marker: PhantomData,
            _alloc: PhantomData,
        }
    }

    /// Mutable iterator yielding `&mut V`. Mirrors `HashMap::values_mut`.
    pub fn values_mut(&mut self) -> FunnelValuesMut<'_, K, V, A> {
        FunnelValuesMut {
            inner: self.iter_mut(),
            _alloc: PhantomData,
        }
    }

    /// Consuming iterator yielding owned keys. Mirrors `HashMap::into_keys`.
    #[must_use]
    pub fn into_keys(self) -> FunnelIntoKeys<K, V, S, A> {
        FunnelIntoKeys::new(self.into_iter())
    }

    /// Consuming iterator yielding owned values. Mirrors `HashMap::into_values`.
    #[must_use]
    pub fn into_values(self) -> FunnelIntoValues<K, V, S, A> {
        FunnelIntoValues::new(self.into_iter())
    }

    /// Returns an [`Entry`] for in-place manipulation of `key`'s slot.
    /// Mirrors [`std::collections::HashMap::entry`].
    pub fn entry(&mut self, key: K) -> Entry<'_, K, V, S, A> {
        let key_hash = self.hash_key(&key);
        let key_fingerprint = control::control_fingerprint(key_hash);
        if let Some(location) = self.find_slot_location_with_hash(&key, key_hash, key_fingerprint) {
            Entry::Occupied(OccupiedEntry {
                map: self,
                location,
            })
        } else {
            Entry::Vacant(VacantEntry {
                map: self,
                key,
                key_hash,
            })
        }
    }

    /// Inserts `key`/`value` if absent. Mirrors the unstable
    /// [`std::collections::HashMap::try_insert`].
    ///
    /// # Errors
    ///
    /// Returns [`OccupiedError`] if `key` was already present.
    pub fn try_insert(
        &mut self,
        key: K,
        value: V,
    ) -> Result<&mut V, OccupiedError<'_, K, V, S, A>> {
        match self.entry(key) {
            Entry::Occupied(entry) => Err(OccupiedError { entry, value }),
            Entry::Vacant(entry) => Ok(entry.insert(value)),
        }
    }

    /// Post-lookup insert for a key known to be absent. Returns the chosen
    /// slot so the caller can borrow into it without re-probing.
    fn insert_for_vacant_entry(&mut self, key: K, value: V, key_hash: u64) -> SlotLocation {
        let key_fingerprint = control::control_fingerprint(key_hash);

        let mut location = if self.len < self.max_insertions {
            self.choose_slot_for_new_key(key_hash)
        } else {
            None
        };

        if location.is_none() {
            let new_capacity = if self.total_slots == 0 {
                INITIAL_CAPACITY
            } else {
                self.total_slots.saturating_mul(2)
            };
            self.resize(new_capacity);
            location = Some(
                self.choose_slot_for_new_key(key_hash)
                    .expect("no free slot found after resize"),
            );
        }

        let final_location = location.expect("location set above");
        self.place_new_entry(final_location, key, value, key_fingerprint);
        final_location
    }

    /// Drops every entry for which `f(&K, &mut V)` returns `false`.
    /// Mirrors [`std::collections::HashMap::retain`].
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        self.extract_if(|k, v| !f(k, v)).for_each(drop);
    }

    /// Returns a draining iterator that empties the map. Mirrors
    /// [`std::collections::HashMap::drain`].
    pub fn drain(&mut self) -> Drain<'_, K, V, S, A> {
        let map_ptr = ptr::from_mut(self);
        // Derive sub-ptrs through `map_ptr` so they share its borrow tag.
        let (levels_ptr, levels_len, primary, fallback) = unsafe {
            let levels = &mut (*map_ptr).levels;
            (
                levels.as_mut_ptr(),
                levels.len(),
                ptr::addr_of_mut!((*map_ptr).special.primary),
                ptr::addr_of_mut!((*map_ptr).special.fallback),
            )
        };
        Drain {
            regions: FunnelRegions::new(levels_ptr, levels_len, primary, fallback),
            map_ptr,
            _marker: PhantomData,
        }
    }

    /// Yields and removes `(K, V)` pairs where `f` returned `true`; kept
    /// entries remain in the map. Mirrors
    /// [`std::collections::HashMap::extract_if`].
    pub fn extract_if<F>(&mut self, f: F) -> ExtractIf<'_, K, V, F, S, A>
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        let map_ptr = ptr::from_mut(self);
        let (levels_ptr, levels_len, primary, fallback) = unsafe {
            let levels = &mut (*map_ptr).levels;
            (
                levels.as_mut_ptr(),
                levels.len(),
                ptr::addr_of_mut!((*map_ptr).special.primary),
                ptr::addr_of_mut!((*map_ptr).special.fallback),
            )
        };
        ExtractIf {
            regions: FunnelRegions::new(levels_ptr, levels_len, primary, fallback),
            map_ptr,
            pred: f,
            _marker: PhantomData,
        }
    }

    pub fn clear(&mut self) {
        for level in &mut self.levels {
            for idx in 0..level.capacity() {
                if level.control_at(idx).is_occupied() {
                    unsafe { ptr::drop_in_place(level.data_ptr().add(idx)) };
                }
            }
            level.clear_all_controls();
            level.len = 0;
            level.tombstones = 0;
        }

        for idx in 0..self.special.primary.capacity() {
            if self.special.primary.control_at(idx).is_occupied() {
                unsafe {
                    ptr::drop_in_place(self.special.primary.data_ptr().add(idx));
                };
            }
        }
        self.special.primary.clear_all_controls();
        self.special.primary.len = 0;
        self.special.primary.tombstones = 0;

        for idx in 0..self.special.fallback.capacity() {
            if self.special.fallback.control_at(idx).is_occupied() {
                unsafe {
                    ptr::drop_in_place(self.special.fallback.data_ptr().add(idx));
                };
            }
        }
        self.special.fallback.clear_all_controls();
        self.special.fallback.len = 0;
        self.special.fallback.tombstones = 0;
        self.special.total_len = 0;

        self.len = 0;
        self.max_populated_level = 0;
    }

    /// Fallible counterpart to [`Self::resize`]. Common path leaves `self`
    /// intact on `Err`; a failing 2x-retry allocation may empty `self`.
    fn try_resize(&mut self, new_capacity: usize) -> Result<(), TryReserveError>
    where
        S: Clone,
    {
        let mut target = new_capacity;
        let mut new_map = Self::try_with_slots_and_reserve_fraction_and_hasher_in(
            target,
            self.reserve_fraction,
            self.hash_builder.clone(),
            self.alloc.clone(),
        )?;

        let mut entries: Vec<(K, V)> = Vec::new();
        entries
            .try_reserve(self.len)
            .map_err(|_| TryReserveError::AllocError)?;
        self.drain_entries_into(&mut entries);

        loop {
            let mut overflow: Vec<(K, V)> = Vec::new();
            for (k, v) in entries.drain(..) {
                if let Err(pair) = new_map.try_insert_new_entry_unchecked(k, v) {
                    overflow.push(pair);
                }
            }
            if overflow.is_empty() {
                *self = new_map;
                return Ok(());
            }
            new_map.drain_entries_into(&mut overflow);
            entries = overflow;
            target = target
                .checked_mul(2)
                .ok_or(TryReserveError::CapacityOverflow)?;
            new_map = Self::try_with_slots_and_reserve_fraction_and_hasher_in(
                target,
                self.reserve_fraction,
                self.hash_builder.clone(),
                self.alloc.clone(),
            )?;
        }
    }

    /// Internal fallible ctor for `try_resize`. `slots` is raw slot count
    /// (already inflated by the caller); public ctors take an insertion
    /// budget and inflate via `capacity_for` — this one skips that.
    fn try_with_slots_and_reserve_fraction_and_hasher_in(
        total_slots: usize,
        reserve_fraction: f64,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryReserveError> {
        let reserve_fraction =
            capacity::sanitize_reserve_fraction(reserve_fraction).min(MAX_FUNNEL_RESERVE_FRACTION);
        let max_insertions = capacity::max_insertions(total_slots, reserve_fraction);

        let level_count = compute_level_count(reserve_fraction);
        let bucket_width = align::round_up_to_group(compute_bucket_width(reserve_fraction));
        let primary_probe_limit = probe::log_log_probe_limit(total_slots).max(1);

        let mut special_capacity =
            choose_special_capacity(total_slots, reserve_fraction, bucket_width);
        let mut main_capacity = total_slots.saturating_sub(special_capacity);
        let main_remainder = main_capacity % bucket_width.max(1);
        if main_remainder != 0 {
            main_capacity = main_capacity.saturating_sub(main_remainder);
            special_capacity = total_slots.saturating_sub(main_capacity);
        }

        let total_main_buckets = main_capacity.checked_div(bucket_width).unwrap_or(0);
        let level_bucket_counts = partition_funnel_buckets(total_main_buckets, level_count);
        let fallback_bucket_size = (primary_probe_limit.saturating_mul(2)).max(2);
        let primary_ctrl = align::round_up_to_pow2_groups(special_capacity.div_ceil(2));
        let fallback_ctrl =
            align::round_up_to_group(special_capacity.saturating_sub(special_capacity.div_ceil(2)));
        let (arena, levels, special) = try_alloc_funnel_arena(
            &level_bucket_counts,
            bucket_width,
            primary_ctrl,
            fallback_ctrl,
            fallback_bucket_size,
            &alloc,
        )?;

        Ok(Self {
            levels,
            special,
            len: 0,
            total_slots,
            max_insertions,
            reserve_fraction,
            primary_probe_limit,
            max_populated_level: 0,
            hash_builder,
            alloc,
            arena,
        })
    }

    /// Rebuild in-place at `new_capacity`. Doubles `new_capacity` on
    /// insert overflow (funnel's structural failure mode under adversarial
    /// hashing) until every entry places.
    fn resize(&mut self, mut new_capacity: usize) {
        let mut entries: Vec<(K, V)> = Vec::with_capacity(self.len);
        self.drain_entries_into(&mut entries);
        loop {
            self.install_fresh_storage(new_capacity);
            let mut overflow: Vec<(K, V)> = Vec::new();
            for (k, v) in entries.drain(..) {
                if let Err(pair) = self.try_insert_new_entry_unchecked(k, v) {
                    overflow.push(pair);
                }
            }
            if overflow.is_empty() {
                return;
            }
            entries = overflow;
            self.drain_entries_into(&mut entries);
            new_capacity = new_capacity
                .checked_mul(2)
                .expect("capacity overflow during funnel resize retry");
        }
    }

    /// Move every live entry into `out`; ctrl bytes cleared so `install_fresh_storage`
    /// can free the old arena safely. Each ctrl is cleared *before* the move so
    /// a `Vec::push` realloc panic leaves no OCCUPIED slot behind to double-drop.
    fn drain_entries_into(&mut self, out: &mut Vec<(K, V)>) {
        for level in &self.levels {
            for idx in level.occupied() {
                level.set_control(idx, CTRL_EMPTY);
                let entry = unsafe { level.take(idx) };
                out.push((entry.key, entry.value));
            }
            level.clear_all_controls();
        }
        self.special.for_each_occupied(|entry| {
            out.push((entry.key, entry.value));
        });
        self.special.primary.clear_all_controls();
        self.special.fallback.clear_all_controls();
        for level in &mut self.levels {
            level.len = 0;
            level.tombstones = 0;
        }
        self.special.primary.len = 0;
        self.special.primary.tombstones = 0;
        self.special.fallback.len = 0;
        self.special.fallback.tombstones = 0;
        self.special.total_len = 0;
        self.len = 0;
        self.max_populated_level = 0;
    }

    /// Replace `self`'s tables with empty storage sized for `new_capacity`.
    fn install_fresh_storage(&mut self, new_capacity: usize) {
        let level_count = compute_level_count(self.reserve_fraction);
        let bucket_width = align::round_up_to_group(compute_bucket_width(self.reserve_fraction));
        let mut special_capacity =
            choose_special_capacity(new_capacity, self.reserve_fraction, bucket_width);
        let mut main_capacity = new_capacity.saturating_sub(special_capacity);
        let main_remainder = main_capacity % bucket_width.max(1);
        if main_remainder != 0 {
            main_capacity = main_capacity.saturating_sub(main_remainder);
            special_capacity = new_capacity.saturating_sub(main_capacity);
        }
        let total_main_buckets = main_capacity.checked_div(bucket_width).unwrap_or(0);
        let level_bucket_counts = partition_funnel_buckets(total_main_buckets, level_count);
        let new_primary_probe_limit = probe::log_log_probe_limit(new_capacity).max(1);
        let fallback_bucket_size = (new_primary_probe_limit.saturating_mul(2)).max(2);
        let primary_raw = special_capacity.div_ceil(2);
        let fallback_raw = special_capacity.saturating_sub(primary_raw);
        let primary_ctrl = align::round_up_to_pow2_groups(primary_raw);
        let fallback_ctrl = align::round_up_to_group(fallback_raw);
        let alloc = &self.alloc;

        let (new_arena, new_levels, new_special) = alloc_funnel_arena(
            &level_bucket_counts,
            bucket_width,
            primary_ctrl,
            fallback_ctrl,
            fallback_bucket_size,
            alloc,
        );

        // Drop old levels first (they read from old arena), then replace arena.
        let old_arena = mem::replace(&mut self.arena, new_arena);
        self.levels = new_levels;
        self.special = new_special;
        self.total_slots = new_capacity;
        self.max_insertions = capacity::max_insertions(new_capacity, self.reserve_fraction);
        self.primary_probe_limit = new_primary_probe_limit;
        self.max_populated_level = 0;

        // Free old arena (drain_entries_into already moved all values out).
        old_arena.deallocate(alloc);
    }

    #[inline]
    fn hash_key<Q>(&self, key: &Q) -> u64
    where
        Q: Hash + ?Sized,
    {
        self.hash_builder.hash_one(key)
    }

    /// Paper §5 insertion chain: attempt `L_1`, `L_2`, …, `L_α` in order,
    /// stopping on the first level whose hashed bucket has a free slot;
    /// spill to `A_{α+1}`.
    #[inline]
    fn choose_slot_for_new_key(&self, key_hash: u64) -> Option<SlotLocation> {
        for (level_idx, level) in self.levels.iter().enumerate() {
            if let Some(slot_idx) = level.first_free_in_bucket(key_hash) {
                return Some(SlotLocation::Level {
                    level_idx,
                    slot_idx,
                });
            }
        }

        if let Some(slot_idx) = self.first_free_in_special_primary(key_hash) {
            return Some(SlotLocation::SpecialPrimary { slot_idx });
        }

        self.first_free_in_special_fallback(key_hash)
            .map(|slot_idx| SlotLocation::SpecialFallback { slot_idx })
    }

    /// Walk `A_1..A_α`; record the earliest free slot into `free_slot`.
    /// Returns the key location if found, plus a [`LevelMiss`].
    #[inline]
    fn find_in_levels<Q>(
        &self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
        free_slot: FreeSlot,
    ) -> (Option<SlotLocation>, LevelMiss)
    where
        Q: Equivalent<K> + ?Sized,
    {
        let wants_free = matches!(&free_slot, Some(out) if out.is_none());
        let mut local: Option<SlotLocation> = None;

        for (level_idx, level) in self.levels.iter().enumerate() {
            let mut slot_candidate: Option<usize> = None;
            let out = if wants_free && local.is_none() {
                Some(&mut slot_candidate)
            } else {
                None
            };
            let step = level.find_in_bucket(key_hash, key_fingerprint, key, out);
            if let Some(slot_idx) = slot_candidate {
                local = Some(SlotLocation::Level {
                    level_idx,
                    slot_idx,
                });
            }
            match step {
                LookupStep::Found(slot_idx) => {
                    return (
                        Some(SlotLocation::Level {
                            level_idx,
                            slot_idx,
                        }),
                        LevelMiss::MayContinue,
                    );
                }
                LookupStep::Continue => {}
                LookupStep::StopSearch => {
                    if let Some(out) = free_slot {
                        *out = local;
                    }
                    return (None, LevelMiss::ChainClean);
                }
            }
        }

        if wants_free && let Some(out) = free_slot {
            *out = local;
        }
        (None, LevelMiss::MayContinue)
    }

    /// Probe primary then fallback for `key`. Pass `Some(candidate)` to also
    /// record the first free slot seen (for insert); `None` for lookup-only.
    #[cold]
    #[inline(never)]
    fn find_in_special<Q>(
        &self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
        mut free_slot: FreeSlot,
    ) -> Option<SlotLocation>
    where
        Q: Equivalent<K> + ?Sized,
    {
        match self.find_in_special_primary(key_hash, key_fingerprint, key, free_slot.as_deref_mut())
        {
            LookupStep::Found(slot_idx) => {
                return Some(SlotLocation::SpecialPrimary { slot_idx });
            }
            LookupStep::StopSearch => return None,
            LookupStep::Continue => {}
        }
        self.find_in_special_fallback(key_hash, key_fingerprint, key, free_slot)
            .map(|slot_idx| SlotLocation::SpecialFallback { slot_idx })
    }

    #[inline]
    fn replace_existing_value(&mut self, location: SlotLocation, value: V) -> V {
        match location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => {
                let entry = unsafe { self.levels[level_idx].get_mut(slot_idx) };
                mem::replace(&mut entry.value, value)
            }
            SlotLocation::SpecialPrimary { slot_idx } => {
                let entry = unsafe { self.special.primary.get_mut(slot_idx) };
                mem::replace(&mut entry.value, value)
            }
            SlotLocation::SpecialFallback { slot_idx } => {
                let entry = unsafe { self.special.fallback.get_mut(slot_idx) };
                mem::replace(&mut entry.value, value)
            }
        }
    }

    /// Place a known-novel `key`/`value`. Returns `Err((key, value))` if no
    /// slot is available; the resize loop reclaims and retries at 2x.
    #[inline]
    fn try_insert_new_entry_unchecked(&mut self, key: K, value: V) -> Result<(), (K, V)> {
        let key_hash = self.hash_key(&key);
        let key_fingerprint = control::control_fingerprint(key_hash);
        let Some(location) = self.choose_slot_for_new_key(key_hash) else {
            return Err((key, value));
        };
        self.place_new_entry(location, key, value, key_fingerprint);
        Ok(())
    }

    #[inline]
    /// Insert `key`/`value` into a candidate slot, growing first via
    /// `resize` if `len >= max_insertions`. After resize, the candidate
    /// becomes stale, so this re-locates the slot from scratch.
    fn insert_at_location_after_resize_check(
        &mut self,
        location: Option<SlotLocation>,
        key_hash: u64,
        key: K,
        value: V,
        key_fingerprint: u8,
    ) -> Option<V> {
        let final_location = if self.len >= self.max_insertions || location.is_none() {
            let new_capacity = if self.total_slots == 0 {
                INITIAL_CAPACITY
            } else {
                self.total_slots.saturating_mul(2)
            };
            self.resize(new_capacity);
            self.choose_slot_for_new_key(key_hash)
                .expect("no free slot found after resize")
        } else {
            match location {
                Some(location) => location,
                None => unreachable!("checked for resize above"),
            }
        };

        self.place_new_entry(final_location, key, value, key_fingerprint);
        None
    }

    #[inline]
    fn place_new_entry(&mut self, location: SlotLocation, key: K, value: V, key_fingerprint: u8) {
        match location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => {
                let level = &mut self.levels[level_idx];
                let was_tombstone =
                    level.tombstones != 0 && level.control_at(slot_idx) == CTRL_TOMBSTONE;
                level.write_with_control(slot_idx, SlotEntry { key, value }, key_fingerprint);
                level.len += 1;
                if was_tombstone {
                    level.tombstones -= 1;
                }
                if level_idx > self.max_populated_level {
                    self.max_populated_level = level_idx;
                }
            }
            SlotLocation::SpecialPrimary { slot_idx } => {
                let primary = &mut self.special.primary;
                // Reusing a tombstone slot must decrement the counter;
                // otherwise resize triggers on stale-since-resize counts.
                let was_tombstone =
                    primary.tombstones != 0 && primary.control_at(slot_idx) == CTRL_TOMBSTONE;
                primary.write_with_control(slot_idx, SlotEntry { key, value }, key_fingerprint);
                primary.len += 1;
                if was_tombstone {
                    primary.tombstones -= 1;
                }
                self.special.total_len += 1;
            }
            SlotLocation::SpecialFallback { slot_idx } => {
                let fallback = &mut self.special.fallback;
                let was_tombstone =
                    fallback.tombstones != 0 && fallback.control_at(slot_idx) == CTRL_TOMBSTONE;
                fallback.write_with_control(slot_idx, SlotEntry { key, value }, key_fingerprint);
                fallback.len += 1;
                if was_tombstone {
                    fallback.tombstones -= 1;
                }
                self.special.total_len += 1;
            }
        }
        self.len += 1;
    }

    fn first_free_in_special_primary(&self, key_hash: u64) -> Option<usize> {
        let primary = &self.special.primary;
        if primary.len as usize >= primary.capacity() {
            return None;
        }

        let group_count = primary.group_count();
        let group_limit = self.primary_probe_limit.min(group_count.max(1));
        let mask = primary.group_count_mask as usize;
        let mut probe = ProbeSeq::new(primary.group_start(key_hash), primary.group_step(key_hash));
        for _ in 0..group_limit {
            if let Some(slot_idx) = primary.first_free_in_group(probe.group) {
                return Some(slot_idx);
            }
            probe.advance(mask);
        }
        None
    }

    fn first_free_in_special_fallback(&self, key_hash: u64) -> Option<usize> {
        let fallback = &self.special.fallback;
        if fallback.len as usize >= fallback.capacity() {
            return None;
        }

        let bucket_a = fallback.bucket_a(key_hash);
        let bucket_b = fallback.bucket_b(key_hash);

        for &bucket_idx in &[bucket_a, bucket_b] {
            let range = fallback.bucket_range(bucket_idx);
            for slot_idx in range {
                if fallback.control_at(slot_idx).is_free() {
                    return Some(slot_idx);
                }
            }
        }

        None
    }

    /// Probe special primary for `key`. Bounded by `primary_probe_limit`
    /// groups; if reached without a match and no tombstones seen, returns
    /// `StopSearch` so the caller skips fallback. Pass `Some(out)` to
    /// record the first free `SlotLocation`; `None` for lookup-only.
    #[inline]
    fn find_in_special_primary<Q>(
        &self,
        key_hash: u64,
        key_fingerprint: u8,
        key: &Q,
        free_slot: FreeSlot,
    ) -> LookupStep
    where
        Q: Equivalent<K> + ?Sized,
    {
        let wants_free = matches!(&free_slot, Some(out) if out.is_none());
        let primary = &self.special.primary;

        if primary.capacity() == 0 || primary.len == 0 {
            if wants_free && let Some(out) = free_slot {
                *out = self
                    .first_free_in_special_primary(key_hash)
                    .map(|slot_idx| SlotLocation::SpecialPrimary { slot_idx });
            }
            return LookupStep::Continue;
        }

        let group_count = primary.group_count();
        let group_limit = self.primary_probe_limit.min(group_count.max(1));
        let mask = primary.group_count_mask as usize;
        let mut local: Option<usize> = None;
        let mut probe = ProbeSeq::new(primary.group_start(key_hash), primary.group_step(key_hash));

        let outcome: LookupStep = 'probe: {
            for _ in 0..group_limit {
                // Track free slots only when asked AND we don't already have
                // one. `first_free_in_group` doubles as the "any free?" check;
                // when not tracking we use the cheaper EMPTY-only mask.
                let has_free = if wants_free && local.is_none() {
                    let slot = primary.first_free_in_group(probe.group);
                    if let Some(s) = slot {
                        local = Some(s);
                    }
                    slot.is_some()
                } else {
                    primary.group_match_mask(probe.group, CTRL_EMPTY).any()
                };
                for relative_idx in primary.group_match_mask(probe.group, key_fingerprint) {
                    let slot_idx = probe.group * GROUP_SIZE + relative_idx;
                    let entry = unsafe { primary.get_ref(slot_idx) };
                    if key.equivalent(&entry.key) {
                        break 'probe LookupStep::Found(slot_idx);
                    }
                }
                // StopSearch: probe chain terminated naturally — an EMPTY
                // slot in the group, with no TOMBSTONE that might be hiding
                // an overflow we'd need to chase.
                if has_free && !primary.group_match_mask(probe.group, CTRL_TOMBSTONE).any() {
                    break 'probe LookupStep::StopSearch;
                }
                probe.advance(mask);
            }
            LookupStep::Continue
        };

        if wants_free && let Some(out) = free_slot {
            *out = local.map(|slot_idx| SlotLocation::SpecialPrimary { slot_idx });
        }
        outcome
    }

    /// Probe special fallback for `key` across its two candidate buckets.
    #[inline]
    fn find_in_special_fallback<Q>(
        &self,
        key_hash: u64,
        key_fingerprint: u8,
        key: &Q,
        free_slot: FreeSlot,
    ) -> Option<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let wants_free = matches!(&free_slot, Some(out) if out.is_none());
        let fallback = &self.special.fallback;

        if fallback.capacity() == 0 || fallback.len == 0 {
            if wants_free && let Some(out) = free_slot {
                *out = self
                    .first_free_in_special_fallback(key_hash)
                    .map(|slot_idx| SlotLocation::SpecialFallback { slot_idx });
            }
            return None;
        }

        let bucket_a = fallback.bucket_a(key_hash);
        let bucket_b = fallback.bucket_b(key_hash);

        let mut local: Option<usize> = None;
        let mut found: Option<usize> = None;
        for bucket_idx in [bucket_a, bucket_b] {
            let need_match = found.is_none();
            let need_candidate = wants_free && local.is_none();
            if !need_match && !need_candidate {
                break;
            }
            let range = fallback.bucket_range(bucket_idx);
            if need_candidate {
                for slot_idx in range.clone() {
                    if fallback.control_at(slot_idx).is_free() {
                        local = Some(slot_idx);
                        break;
                    }
                }
            }
            if need_match {
                let controls = unsafe {
                    slice::from_raw_parts(fallback.ctrl_ptr().add(range.start), range.len())
                };
                let mut match_offset = 0;
                while let Some(relative_idx) = control::find_next_fingerprint_in_controls(
                    controls,
                    key_fingerprint,
                    match_offset,
                ) {
                    let slot_idx = range.start + relative_idx;
                    let entry = unsafe { fallback.get_ref(slot_idx) };
                    if key.equivalent(&entry.key) {
                        found = Some(slot_idx);
                        break;
                    }
                    match_offset = relative_idx + 1;
                }
            }
        }

        if wants_free && let Some(out) = free_slot {
            *out = local.map(|slot_idx| SlotLocation::SpecialFallback { slot_idx });
        }
        found
    }

    /// Dispatch `loc` to the right descriptor and return a shared reference
    /// to the slot. SAFETY: `loc` must reference an occupied slot.
    #[inline]
    unsafe fn slot_ref(&self, loc: SlotLocation) -> &SlotEntry<K, V> {
        match loc {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => unsafe { self.levels[level_idx].get_ref(slot_idx) },
            SlotLocation::SpecialPrimary { slot_idx } => unsafe {
                self.special.primary.get_ref(slot_idx)
            },
            SlotLocation::SpecialFallback { slot_idx } => unsafe {
                self.special.fallback.get_ref(slot_idx)
            },
        }
    }

    /// SAFETY: `loc` must reference an occupied slot and caller must hold
    /// exclusive access to the slot.
    #[inline]
    unsafe fn slot_mut(&mut self, loc: SlotLocation) -> &mut SlotEntry<K, V> {
        match loc {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => unsafe { self.levels[level_idx].get_mut(slot_idx) },
            SlotLocation::SpecialPrimary { slot_idx } => unsafe {
                self.special.primary.get_mut(slot_idx)
            },
            SlotLocation::SpecialFallback { slot_idx } => unsafe {
                self.special.fallback.get_mut(slot_idx)
            },
        }
    }

    #[inline]
    fn find_slot_location_with_hash<Q>(
        &self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
    ) -> Option<SlotLocation>
    where
        Q: Equivalent<K> + ?Sized,
    {
        match self.levels[0].find_in_bucket(key_hash, key_fingerprint, key, None) {
            LookupStep::Found(slot_idx) => {
                return Some(SlotLocation::Level {
                    level_idx: 0,
                    slot_idx,
                });
            }
            LookupStep::Continue => {}
            LookupStep::StopSearch => return None,
        }

        // L1+ is empty in steady state at default load; outline only when populated.
        if self.max_populated_level > 0
            && let ControlFlow::Break(result) =
                self.find_in_higher_levels(key, key_hash, key_fingerprint)
        {
            return result;
        }

        // Special tables — only populated under overflow.
        if self.special.total_len == 0 {
            return None;
        }

        self.find_in_special(key, key_hash, key_fingerprint, None)
    }

    #[cold]
    #[inline(never)]
    fn find_in_higher_levels<Q>(
        &self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
    ) -> ControlFlow<Option<SlotLocation>>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let search_limit = (self.max_populated_level + 1).min(self.levels.len());
        for (offset, level) in self.levels[1..search_limit].iter().enumerate() {
            match level.find_in_bucket(key_hash, key_fingerprint, key, None) {
                LookupStep::Found(slot_idx) => {
                    return ControlFlow::Break(Some(SlotLocation::Level {
                        level_idx: offset + 1,
                        slot_idx,
                    }));
                }
                LookupStep::Continue => {}
                LookupStep::StopSearch => return ControlFlow::Break(None),
            }
        }
        ControlFlow::Continue(())
    }

    fn shrink_max_populated_level(&mut self) {
        while self.max_populated_level > 0 && self.levels[self.max_populated_level].len == 0 {
            self.max_populated_level -= 1;
        }
    }
}

/// A view into a single entry in a [`FunnelHashMap`], which may be either
/// vacant or occupied. Constructed via [`FunnelHashMap::entry`].
pub enum Entry<'a, K: 'a, V: 'a, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    /// Slot is occupied; key already lives in the map.
    Occupied(OccupiedEntry<'a, K, V, S, A>),
    /// Slot is vacant; the supplied key does not exist in the map yet.
    Vacant(VacantEntry<'a, K, V, S, A>),
}

/// View of an occupied entry in a [`FunnelHashMap`].
pub struct OccupiedEntry<'a, K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    map: &'a mut FunnelHashMap<K, V, S, A>,
    location: SlotLocation,
}

impl<'a, K, V, S, A> OccupiedEntry<'a, K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    /// Returns a reference to the entry's key.
    #[must_use]
    pub fn key(&self) -> &K {
        unsafe { &self.map.slot_ref(self.location).key }
    }

    /// Returns a reference to the entry's value.
    #[must_use]
    pub fn get(&self) -> &V {
        unsafe { &self.map.slot_ref(self.location).value }
    }

    /// Returns `&mut V`. Borrow is tied to `self`; for the map's lifetime
    /// use [`OccupiedEntry::into_mut`].
    pub fn get_mut(&mut self) -> &mut V {
        unsafe { &mut self.map.slot_mut(self.location).value }
    }

    /// Consumes the entry and returns `&mut V` borrowed from the map.
    #[must_use]
    pub fn into_mut(self) -> &'a mut V {
        unsafe { &mut self.map.slot_mut(self.location).value }
    }

    /// Replaces the entry's value and returns the old one.
    pub fn insert(&mut self, value: V) -> V {
        self.map.replace_existing_value(self.location, value)
    }

    /// Removes the entry and returns its value.
    #[must_use]
    pub fn remove(self) -> V {
        self.remove_entry().1
    }

    /// Removes the entry and returns the `(key, value)` pair.
    #[must_use]
    pub fn remove_entry(self) -> (K, V) {
        let (removed_entry, needs_resize) = match self.location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => {
                let level = &mut self.map.levels[level_idx];
                let removed = unsafe { level.take(slot_idx) };
                if level.erase(slot_idx) {
                    level.tombstones += 1;
                }
                level.len -= 1;
                let needs_resize = level.tombstones as usize > level.capacity() / 2;
                (removed, needs_resize)
            }
            SlotLocation::SpecialPrimary { slot_idx } => {
                let special = &mut self.map.special;
                let primary = &mut special.primary;
                let removed = unsafe { primary.take(slot_idx) };
                if primary.erase(slot_idx) {
                    primary.tombstones += 1;
                }
                primary.len -= 1;
                special.total_len -= 1;
                let needs_resize = primary.tombstones as usize > primary.capacity() / 2;
                (removed, needs_resize)
            }
            SlotLocation::SpecialFallback { slot_idx } => {
                let special = &mut self.map.special;
                let fallback = &mut special.fallback;
                let removed = unsafe { fallback.take(slot_idx) };
                if fallback.erase(slot_idx) {
                    fallback.tombstones += 1;
                }
                fallback.len -= 1;
                special.total_len -= 1;
                let needs_resize = fallback.tombstones as usize > fallback.capacity() / 2;
                (removed, needs_resize)
            }
        };

        self.map.len -= 1;
        self.map.shrink_max_populated_level();
        if needs_resize {
            self.map.resize(self.map.total_slots);
        }
        (removed_entry.key, removed_entry.value)
    }
}

/// View of a vacant entry in a [`FunnelHashMap`].
pub struct VacantEntry<'a, K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    map: &'a mut FunnelHashMap<K, V, S, A>,
    key: K,
    key_hash: u64,
}

impl<'a, K, V, S, A> VacantEntry<'a, K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    /// Returns a reference to the key that would be inserted.
    pub fn key(&self) -> &K {
        &self.key
    }

    /// Consumes the entry and returns the key without inserting.
    #[must_use]
    pub fn into_key(self) -> K {
        self.key
    }

    /// Inserts `value` for the entry's key, returning `&mut V`.
    pub fn insert(self, value: V) -> &'a mut V {
        let location = self
            .map
            .insert_for_vacant_entry(self.key, value, self.key_hash);
        unsafe { &mut self.map.slot_mut(location).value }
    }
}

impl<'a, K, V, S, A> Entry<'a, K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    /// Returns a mutable reference to the entry's value, inserting `default`
    /// first if vacant.
    pub fn or_insert(self, default: V) -> &'a mut V {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(default),
        }
    }

    /// Like [`Entry::or_insert`] but the default is computed lazily.
    pub fn or_insert_with<F: FnOnce() -> V>(self, default: F) -> &'a mut V {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(default()),
        }
    }

    /// Like [`Entry::or_insert_with`] but the default closure receives a
    /// reference to the key.
    pub fn or_insert_with_key<F: FnOnce(&K) -> V>(self, default: F) -> &'a mut V {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let value = default(entry.key());
                entry.insert(value)
            }
        }
    }

    /// Returns a reference to this entry's key.
    pub fn key(&self) -> &K {
        match self {
            Entry::Occupied(entry) => entry.key(),
            Entry::Vacant(entry) => entry.key(),
        }
    }

    /// Runs `f` against the value if the entry is occupied, then returns
    /// the entry for further chaining.
    #[must_use]
    pub fn and_modify<F: FnOnce(&mut V)>(self, f: F) -> Self {
        match self {
            Entry::Occupied(mut entry) => {
                f(entry.get_mut());
                Entry::Occupied(entry)
            }
            Entry::Vacant(entry) => Entry::Vacant(entry),
        }
    }
}

impl<'a, K, V, S, A> Entry<'a, K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
    V: Default,
{
    /// Returns a mutable reference to the value, inserting `V::default()`
    /// first if vacant.
    pub fn or_default(self) -> &'a mut V {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(V::default()),
        }
    }
}

/// Error returned by [`FunnelHashMap::try_insert`] on key collision.
pub type OccupiedError<'a, K, V, S = DefaultHashBuilder, A = Global> =
    CommonOccupiedError<OccupiedEntry<'a, K, V, S, A>, V>;

impl<K, V, S, A> EntryView for OccupiedEntry<'_, K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Key = K;
    type Value = V;
    fn view_key(&self) -> &K {
        self.key()
    }
    fn view_value(&self) -> &V {
        self.get()
    }
}

/// Three-phase iterator state: walk all bucket levels,
/// then the special primary, then the special fallback.
#[derive(Debug, Clone, Copy)]
enum IterPhase {
    Levels,
    Primary,
    Fallback,
    Done,
}

#[derive(Clone, Copy)]
struct FunnelSlot {
    phase: IterPhase,
    level_idx: usize,
    slot_idx: usize,
}

/// Shared phase machine for Funnel's heterogeneous storage regions.
struct FunnelRegions<T> {
    levels: *mut BucketLevel<T>,
    levels_len: usize,
    level_idx: usize,
    primary: *mut SpecialPrimary<T>,
    fallback: *mut SpecialFallback<T>,
    slots: OccupiedSlots,
    phase: IterPhase,
}

impl<T> Clone for FunnelRegions<T> {
    fn clone(&self) -> Self {
        Self {
            levels: self.levels,
            levels_len: self.levels_len,
            level_idx: self.level_idx,
            primary: self.primary,
            fallback: self.fallback,
            slots: self.slots.clone(),
            phase: self.phase,
        }
    }
}

impl<T> FunnelRegions<T> {
    #[inline]
    fn empty() -> Self {
        Self {
            levels: ptr::null_mut(),
            levels_len: 0,
            level_idx: 0,
            primary: ptr::null_mut(),
            fallback: ptr::null_mut(),
            slots: OccupiedSlots::empty(),
            phase: IterPhase::Done,
        }
    }

    #[inline]
    fn new(
        levels: *mut BucketLevel<T>,
        levels_len: usize,
        primary: *mut SpecialPrimary<T>,
        fallback: *mut SpecialFallback<T>,
    ) -> Self {
        let mut me = Self {
            levels,
            levels_len,
            level_idx: 0,
            primary,
            fallback,
            slots: OccupiedSlots::empty(),
            phase: IterPhase::Levels,
        };
        if levels_len > 0 {
            me.slots.set_region(unsafe { &*levels });
        } else {
            me.phase = IterPhase::Primary;
            me.slots.set_region(unsafe { &*primary });
        }
        me
    }

    #[inline]
    fn phase(&self) -> IterPhase {
        self.phase
    }

    #[inline]
    fn next_slot(&mut self) -> Option<FunnelSlot> {
        loop {
            if let Some(slot_idx) = self.slots.step() {
                return Some(FunnelSlot {
                    phase: self.phase,
                    level_idx: self.level_idx,
                    slot_idx,
                });
            }
            self.advance_region();
            if matches!(self.phase, IterPhase::Done) {
                return None;
            }
        }
    }

    #[inline]
    fn next_entry_ptr(&mut self) -> Option<*mut T> {
        loop {
            if let Some(slot_idx) = self.slots.step() {
                let entry_ptr = unsafe {
                    match self.phase {
                        IterPhase::Levels => {
                            (*self.levels.add(self.level_idx)).data_ptr().add(slot_idx)
                        }
                        IterPhase::Primary => (*self.primary).data_ptr().add(slot_idx),
                        IterPhase::Fallback => (*self.fallback).data_ptr().add(slot_idx),
                        IterPhase::Done => std::hint::unreachable_unchecked(),
                    }
                };
                return Some(entry_ptr);
            }
            self.advance_region();
            if matches!(self.phase, IterPhase::Done) {
                return None;
            }
        }
    }

    #[inline]
    fn advance_region(&mut self) {
        match self.phase {
            IterPhase::Levels => {
                self.level_idx += 1;
                if self.level_idx < self.levels_len {
                    self.slots
                        .set_region(unsafe { &*self.levels.add(self.level_idx) });
                } else {
                    self.phase = IterPhase::Primary;
                    self.slots.set_region(unsafe { &*self.primary });
                }
            }
            IterPhase::Primary => {
                self.phase = IterPhase::Fallback;
                self.slots.set_region(unsafe { &*self.fallback });
            }
            IterPhase::Fallback => self.phase = IterPhase::Done,
            IterPhase::Done => {}
        }
    }

    /// SAFETY: `slot` must have been yielded by this cursor and still point to
    /// an initialized entry. The slot must not be read again before being
    /// re-written.
    #[inline]
    unsafe fn take(&self, slot: FunnelSlot) -> T {
        unsafe {
            match slot.phase {
                IterPhase::Levels => (*self.levels.add(slot.level_idx)).take(slot.slot_idx),
                IterPhase::Primary => (*self.primary).take(slot.slot_idx),
                IterPhase::Fallback => (*self.fallback).take(slot.slot_idx),
                IterPhase::Done => std::hint::unreachable_unchecked(),
            }
        }
    }

    #[inline]
    unsafe fn mark_tombstone(&self, slot: FunnelSlot) {
        unsafe {
            match slot.phase {
                IterPhase::Levels => {
                    (*self.levels.add(slot.level_idx)).mark_tombstone(slot.slot_idx);
                }
                IterPhase::Primary => (*self.primary).mark_tombstone(slot.slot_idx),
                IterPhase::Fallback => (*self.fallback).mark_tombstone(slot.slot_idx),
                IterPhase::Done => std::hint::unreachable_unchecked(),
            }
        }
    }
}

/// Borrowing iterator over occupied entries. Uses [`FunnelRegions`] to walk
/// bucket levels → primary → fallback.
pub struct FunnelIter<'a, K, V, A: Allocator + Clone = Global> {
    regions: FunnelRegions<SlotEntry<K, V>>,
    remaining: usize,
    _marker: PhantomData<&'a A>,
}

// SAFETY: behaves as shared borrow of the map's regions.
unsafe impl<K: Sync, V: Sync, A: Allocator + Clone + Sync> Send for FunnelIter<'_, K, V, A> {}
unsafe impl<K: Sync, V: Sync, A: Allocator + Clone + Sync> Sync for FunnelIter<'_, K, V, A> {}

impl<K, V, A: Allocator + Clone> Clone for FunnelIter<'_, K, V, A> {
    fn clone(&self) -> Self {
        Self {
            regions: self.regions.clone(),
            remaining: self.remaining,
            _marker: PhantomData,
        }
    }
}

impl<K: fmt::Debug, V: fmt::Debug, A: Allocator + Clone> fmt::Debug for FunnelIter<'_, K, V, A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

impl<'a, K: 'a, V: 'a, A: Allocator + Clone> Iterator for FunnelIter<'a, K, V, A> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let entry: &'a SlotEntry<K, V> = unsafe { &*self.regions.next_entry_ptr()? };
        self.remaining -= 1;
        Some((&entry.key, &entry.value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<'a, K: 'a, V: 'a, A: Allocator + Clone> ExactSizeIterator for FunnelIter<'a, K, V, A> {}
impl<'a, K: 'a, V: 'a, A: Allocator + Clone> FusedIterator for FunnelIter<'a, K, V, A> {}

impl<'a, K, V, S, A> IntoIterator for &'a FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Item = (&'a K, &'a V);
    type IntoIter = FunnelIter<'a, K, V, A>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Draining iterator. Yields and removes every `(K, V)`; the map is empty
/// once consumed or dropped.
pub struct Drain<'a, K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    regions: FunnelRegions<SlotEntry<K, V>>,
    map_ptr: *mut FunnelHashMap<K, V, S, A>,
    _marker: PhantomData<&'a mut FunnelHashMap<K, V, S, A>>,
}

impl<K, V, S, A: Allocator + Clone> fmt::Debug for Drain<'_, K, V, S, A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Drain")
            .field("phase", &self.regions.phase())
            .field("remaining", &unsafe { (*self.map_ptr).len })
            .finish_non_exhaustive()
    }
}

impl<K, V, S, A: Allocator + Clone> Iterator for Drain<'_, K, V, S, A> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        // Per-yield ctrl byte update is skipped: Drain::drop wipes all ctrls.
        let slot = self.regions.next_slot()?;
        let entry = unsafe { self.regions.take(slot) };
        unsafe { (*self.map_ptr).len -= 1 };
        Some((entry.key, entry.value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = unsafe { (*self.map_ptr).len };
        (len, Some(len))
    }
}

impl<K, V, S, A: Allocator + Clone> ExactSizeIterator for Drain<'_, K, V, S, A> {}
impl<K, V, S, A: Allocator + Clone> FusedIterator for Drain<'_, K, V, S, A> {}

impl<K, V, S, A: Allocator + Clone> Drop for Drain<'_, K, V, S, A> {
    fn drop(&mut self) {
        // Drain any unyielded entries so values run their `Drop`.
        for _ in &mut *self {}
        let map = unsafe { &mut *self.map_ptr };
        for level in &mut map.levels {
            level.clear_all_controls();
            level.len = 0;
            level.tombstones = 0;
        }
        map.special.primary.clear_all_controls();
        map.special.primary.len = 0;
        map.special.primary.tombstones = 0;
        map.special.fallback.clear_all_controls();
        map.special.fallback.len = 0;
        map.special.fallback.tombstones = 0;
        map.special.total_len = 0;
        map.len = 0;
        map.max_populated_level = 0;
    }
}

/// Filtering drain. Yields and removes entries where `pred` returns `true`.
pub struct ExtractIf<'a, K, V, F, S = DefaultHashBuilder, A: Allocator + Clone = Global>
where
    K: Eq + Hash,
    S: BuildHasher,
    F: FnMut(&K, &mut V) -> bool,
{
    regions: FunnelRegions<SlotEntry<K, V>>,
    map_ptr: *mut FunnelHashMap<K, V, S, A>,
    pred: F,
    _marker: PhantomData<&'a mut FunnelHashMap<K, V, S, A>>,
}

impl<K, V, F, S, A: Allocator + Clone> fmt::Debug for ExtractIf<'_, K, V, F, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    F: FnMut(&K, &mut V) -> bool,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ExtractIf")
            .field("phase", &self.regions.phase())
            .field("remaining", &unsafe { (*self.map_ptr).len })
            .finish_non_exhaustive()
    }
}

impl<K, V, F, S, A: Allocator + Clone> Iterator for ExtractIf<'_, K, V, F, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    F: FnMut(&K, &mut V) -> bool,
{
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            while let Some(slot_idx) = self.regions.slots.step() {
                match self.regions.phase {
                    IterPhase::Levels => {
                        let level_ptr = unsafe { self.regions.levels.add(self.regions.level_idx) };
                        let entry = unsafe { (*level_ptr).get_mut(slot_idx) };
                        if (self.pred)(&entry.key, &mut entry.value) {
                            unsafe {
                                if (*level_ptr).erase(slot_idx) {
                                    (*level_ptr).tombstones += 1;
                                }
                                (*level_ptr).len -= 1;
                                (*self.map_ptr).len -= 1;
                                let removed = (*level_ptr).take(slot_idx);
                                return Some((removed.key, removed.value));
                            }
                        }
                    }
                    IterPhase::Primary => {
                        let primary = self.regions.primary;
                        let entry = unsafe { (*primary).get_mut(slot_idx) };
                        if (self.pred)(&entry.key, &mut entry.value) {
                            unsafe {
                                if (*primary).erase(slot_idx) {
                                    (*primary).tombstones += 1;
                                }
                                (*primary).len -= 1;
                                (*self.map_ptr).special.total_len -= 1;
                                (*self.map_ptr).len -= 1;
                                let removed = (*primary).take(slot_idx);
                                return Some((removed.key, removed.value));
                            }
                        }
                    }
                    IterPhase::Fallback => {
                        let fallback = self.regions.fallback;
                        let entry = unsafe { (*fallback).get_mut(slot_idx) };
                        if (self.pred)(&entry.key, &mut entry.value) {
                            unsafe {
                                if (*fallback).erase(slot_idx) {
                                    (*fallback).tombstones += 1;
                                }
                                (*fallback).len -= 1;
                                (*self.map_ptr).special.total_len -= 1;
                                (*self.map_ptr).len -= 1;
                                let removed = (*fallback).take(slot_idx);
                                return Some((removed.key, removed.value));
                            }
                        }
                    }
                    IterPhase::Done => unsafe { std::hint::unreachable_unchecked() },
                }
            }
            self.regions.advance_region();
            if matches!(self.regions.phase, IterPhase::Done) {
                return None;
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(unsafe { (*self.map_ptr).len }))
    }
}

impl<K, V, F, S, A: Allocator + Clone> Drop for ExtractIf<'_, K, V, F, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    F: FnMut(&K, &mut V) -> bool,
{
    fn drop(&mut self) {
        // Tombstones from extracted entries are left in place; subsequent
        // `remove` calls trigger consolidation when their threshold is crossed.
    }
}

/// `&K` iterator returned by [`FunnelHashMap::keys`].
pub type Keys<'a, K, V, A = Global> = CommonKeys<FunnelIter<'a, K, V, A>>;
/// `&V` iterator returned by [`FunnelHashMap::values`].
pub type Values<'a, K, V, A = Global> = CommonValues<FunnelIter<'a, K, V, A>>;

/// `(&K, &mut V)` iterator over levels → primary → fallback. Each
/// `next()` yields a strictly newer slot ⇒ refs are disjoint.
pub struct FunnelIterMut<'a, K, V, A: Allocator + Clone = Global> {
    regions: FunnelRegions<SlotEntry<K, V>>,
    remaining: usize,
    _marker: PhantomData<&'a mut SpecialArray<SlotEntry<K, V>>>,
    _alloc: PhantomData<A>,
}

// SAFETY: exclusive borrow of map regions for its lifetime.
unsafe impl<K: Send, V: Send, A: Allocator + Clone + Send> Send for FunnelIterMut<'_, K, V, A> {}
unsafe impl<K: Sync, V: Sync, A: Allocator + Clone + Sync> Sync for FunnelIterMut<'_, K, V, A> {}

impl<'a, K, V, A: Allocator + Clone> Iterator for FunnelIterMut<'a, K, V, A> {
    type Item = (&'a K, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        // SAFETY: scanner yields a strictly newer slot each call, so forged
        // `&'a mut` refs don't alias across iterations.
        let entry: &'a mut SlotEntry<K, V> = unsafe { &mut *self.regions.next_entry_ptr()? };
        self.remaining -= 1;
        Some((&entry.key, &mut entry.value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K, V, A: Allocator + Clone> ExactSizeIterator for FunnelIterMut<'_, K, V, A> {}
impl<K, V, A: Allocator + Clone> FusedIterator for FunnelIterMut<'_, K, V, A> {}

impl<K, V, A: Allocator + Clone> fmt::Debug for FunnelIterMut<'_, K, V, A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("FunnelIterMut")
            .field("phase", &self.regions.phase())
            .field("remaining", &self.remaining)
            .finish_non_exhaustive()
    }
}

impl<'a, K, V, S, A> IntoIterator for &'a mut FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Item = (&'a K, &'a mut V);
    type IntoIter = FunnelIterMut<'a, K, V, A>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

/// `&mut V` iterator returned by [`FunnelHashMap::values_mut`].
pub struct FunnelValuesMut<'a, K, V, A: Allocator + Clone = Global> {
    inner: FunnelIterMut<'a, K, V, A>,
    _alloc: PhantomData<A>,
}

impl<'a, K, V, A: Allocator + Clone> Iterator for FunnelValuesMut<'a, K, V, A> {
    type Item = &'a mut V;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(_, v)| v)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<K, V, A: Allocator + Clone> ExactSizeIterator for FunnelValuesMut<'_, K, V, A> {}
impl<K, V, A: Allocator + Clone> FusedIterator for FunnelValuesMut<'_, K, V, A> {}

impl<K, V, A: Allocator + Clone> fmt::Debug for FunnelValuesMut<'_, K, V, A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("FunnelValuesMut")
            .field("phase", &self.inner.regions.phase())
            .field("remaining", &self.inner.remaining)
            .finish_non_exhaustive()
    }
}

/// Owned `(K, V)` iterator returned by `FunnelHashMap::into_iter`.
pub struct FunnelIntoIter<K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    regions: FunnelRegions<SlotEntry<K, V>>,
    levels: ManuallyDrop<BucketLevelSlice<K, V>>,
    special: ManuallyDrop<SpecialArray<SlotEntry<K, V>>>,
    arena: ManuallyDrop<Arena>,
    alloc: A,
    remaining: usize,
    _marker: PhantomData<S>,
}

// SAFETY: raw pointers into owned `levels` / `arena`; Send/Sync match map.
unsafe impl<K: Send, V: Send, S: Send, A: Allocator + Clone + Send> Send
    for FunnelIntoIter<K, V, S, A>
{
}
unsafe impl<K: Sync, V: Sync, S: Sync, A: Allocator + Clone + Sync> Sync
    for FunnelIntoIter<K, V, S, A>
{
}

impl<K, V, S, A: Allocator + Clone> FunnelIntoIter<K, V, S, A> {
    #[inline]
    fn refresh_region_ptrs(&mut self) {
        self.regions.levels = self.levels.as_mut_ptr();
        self.regions.primary = ptr::addr_of_mut!(self.special.primary);
        self.regions.fallback = ptr::addr_of_mut!(self.special.fallback);
    }
}

impl<K, V, S, A: Allocator + Clone> Iterator for FunnelIntoIter<K, V, S, A> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        self.refresh_region_ptrs();
        let slot = self.regions.next_slot()?;
        let entry = unsafe {
            let entry = self.regions.take(slot);
            self.regions.mark_tombstone(slot);
            entry
        };
        self.remaining -= 1;
        Some((entry.key, entry.value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K, V, S, A: Allocator + Clone> ExactSizeIterator for FunnelIntoIter<K, V, S, A> {}
impl<K, V, S, A: Allocator + Clone> FusedIterator for FunnelIntoIter<K, V, S, A> {}

impl<K, V, S, A: Allocator + Clone> Drop for FunnelIntoIter<K, V, S, A> {
    fn drop(&mut self) {
        // Guard ensures `levels` / `special` / `arena` are freed even if
        // a `V::drop` panic unwinds out of the drain loop below.
        struct DropGuard<'a, K, V, S, A: Allocator + Clone> {
            iter: &'a mut FunnelIntoIter<K, V, S, A>,
        }
        impl<K, V, S, A: Allocator + Clone> Drop for DropGuard<'_, K, V, S, A> {
            #[inline]
            fn drop(&mut self) {
                unsafe {
                    ManuallyDrop::drop(&mut self.iter.levels);
                    ManuallyDrop::drop(&mut self.iter.special);
                    let arena = ManuallyDrop::take(&mut self.iter.arena);
                    arena.deallocate(&self.iter.alloc);
                }
            }
        }
        let guard = DropGuard { iter: self };
        for _ in guard.iter.by_ref() {}
    }
}

impl<K, V, S, A: Allocator + Clone> fmt::Debug for FunnelIntoIter<K, V, S, A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("FunnelIntoIter")
            .field("phase", &self.regions.phase())
            .field("remaining", &self.remaining)
            .finish_non_exhaustive()
    }
}

impl<K, V, S, A> IntoIterator for FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Item = (K, V);
    type IntoIter = FunnelIntoIter<K, V, S, A>;

    fn into_iter(mut self) -> Self::IntoIter {
        let levels = mem::take(&mut self.levels);
        let special = mem::replace(
            &mut self.special,
            SpecialArray {
                primary: SpecialPrimary::new_at(0, 0, ptr::null_mut(), ptr::null_mut()),
                fallback: SpecialFallback::new_at(0, 0, 0, ptr::null_mut(), ptr::null_mut()),
                total_len: 0,
            },
        );
        let arena = mem::replace(&mut self.arena, Arena::empty());
        let alloc = self.alloc.clone();
        let remaining = self.len;
        let levels_len = levels.len();
        let mut iter = FunnelIntoIter {
            regions: FunnelRegions::empty(),
            levels: ManuallyDrop::new(levels),
            special: ManuallyDrop::new(special),
            arena: ManuallyDrop::new(arena),
            alloc,
            remaining,
            _marker: PhantomData,
        };
        // Derive raw ptrs post-move so moving the Vec/SpecialArray into
        // `ManuallyDrop` does not invalidate the borrow tags.
        iter.regions = FunnelRegions::new(
            iter.levels.as_mut_ptr(),
            levels_len,
            ptr::addr_of_mut!(iter.special.primary),
            ptr::addr_of_mut!(iter.special.fallback),
        );
        iter
    }
}

/// Owned `K` iterator returned by [`FunnelHashMap::into_keys`].
pub type FunnelIntoKeys<K, V, S = DefaultHashBuilder, A = Global> =
    CommonIntoKeys<FunnelIntoIter<K, V, S, A>>;
/// Owned `V` iterator returned by [`FunnelHashMap::into_values`].
pub type FunnelIntoValues<K, V, S = DefaultHashBuilder, A = Global> =
    CommonIntoValues<FunnelIntoIter<K, V, S, A>>;

/// Raw-pointer projection from a `SlotLocation` to its value, without forming
/// any intermediate `&mut BucketLevel` / `&mut SpecialPrimary` /
/// `&mut SpecialFallback`. Used by `get_disjoint_mut*` to hand out disjoint
/// `&mut V` even when multiple keys live in the same sub-table.
///
/// # Safety
///
/// - `levels_ptr` must point to a live `[BucketLevel<SlotEntry<K, V>>]` whose `level_idx`
///   slot exists; same for `primary_ptr` / `fallback_ptr`.
/// - The `slot_idx` carried by `loc` must reference an occupied slot.
#[inline]
unsafe fn funnel_slot_value_ptr<K, V>(
    levels_ptr: *const BucketLevel<SlotEntry<K, V>>,
    primary_ptr: *const SpecialPrimary<SlotEntry<K, V>>,
    fallback_ptr: *const SpecialFallback<SlotEntry<K, V>>,
    loc: SlotLocation,
) -> *mut V {
    let entry = match loc {
        SlotLocation::Level {
            level_idx,
            slot_idx,
        } => unsafe {
            let lvl = &*levels_ptr.add(level_idx);
            lvl.data_ptr().add(slot_idx)
        },
        SlotLocation::SpecialPrimary { slot_idx } => unsafe {
            (*primary_ptr).data_ptr().add(slot_idx)
        },
        SlotLocation::SpecialFallback { slot_idx } => unsafe {
            (*fallback_ptr).data_ptr().add(slot_idx)
        },
    };
    unsafe { &raw mut (*entry).value }
}

/// As [`funnel_slot_value_ptr`] but returns key + value pointers together.
#[inline]
unsafe fn funnel_slot_kv_ptrs<K, V>(
    levels_ptr: *const BucketLevel<SlotEntry<K, V>>,
    primary_ptr: *const SpecialPrimary<SlotEntry<K, V>>,
    fallback_ptr: *const SpecialFallback<SlotEntry<K, V>>,
    loc: SlotLocation,
) -> (*const K, *mut V) {
    let entry = match loc {
        SlotLocation::Level {
            level_idx,
            slot_idx,
        } => unsafe {
            let lvl = &*levels_ptr.add(level_idx);
            lvl.data_ptr().add(slot_idx)
        },
        SlotLocation::SpecialPrimary { slot_idx } => unsafe {
            (*primary_ptr).data_ptr().add(slot_idx)
        },
        SlotLocation::SpecialFallback { slot_idx } => unsafe {
            (*fallback_ptr).data_ptr().add(slot_idx)
        },
    };
    let k_ptr = unsafe { &raw const (*entry).key };
    let v_ptr = unsafe { &raw mut (*entry).value };
    (k_ptr, v_ptr)
}

/// Paper §5: `α = ⌈4 log δ⁻¹ + 10⌉` levels (excluding the special array).
fn compute_level_count(reserve_fraction: f64) -> usize {
    cast::ceil_to_usize((4.0 * (1.0 / reserve_fraction).log2() + 10.0).max(1.0))
}

/// Paper §5: `β = ⌈2 log δ⁻¹⌉` slots per bucket A_{i,j}.
fn compute_bucket_width(reserve_fraction: f64) -> usize {
    cast::ceil_to_usize((2.0 * (1.0 / reserve_fraction).log2()).max(1.0))
}

/// Paper §5: `⌈δn/2⌉ ≤ |A_{α+1}| ≤ ⌊3δn/4⌋`, with the main capacity
/// constrained to a multiple of `β` so each level is `β·a_i` slots.
fn choose_special_capacity(
    total_capacity: usize,
    reserve_fraction: f64,
    bucket_size: usize,
) -> usize {
    if total_capacity == 0 {
        return 0;
    }

    let total_capacity_f64 = cast::usize_to_f64(total_capacity);
    let lower_bound = cast::ceil_to_usize((reserve_fraction * total_capacity_f64) / 2.0);
    let upper_bound = cast::floor_to_usize((3.0 * reserve_fraction * total_capacity_f64) / 4.0);
    let lower_bound = lower_bound.min(total_capacity);
    let upper_bound = upper_bound.min(total_capacity);

    if lower_bound <= upper_bound {
        for special_capacity in (lower_bound..=upper_bound).rev() {
            if (total_capacity - special_capacity).is_multiple_of(bucket_size.max(1)) {
                return special_capacity;
            }
        }
    }

    let target = cast::round_to_usize(
        ((5.0 * reserve_fraction * total_capacity_f64) / 8.0).clamp(0.0, total_capacity_f64),
    );

    let mut best_special_capacity = total_capacity % bucket_size.max(1);
    let mut best_distance = usize::MAX;

    for main_capacity in (0..=total_capacity).step_by(bucket_size.max(1)) {
        let special_capacity = total_capacity - main_capacity;
        let distance = special_capacity.abs_diff(target);
        if distance < best_distance {
            best_distance = distance;
            best_special_capacity = special_capacity;
        }
    }

    // Paper §5: A_{α+1} must be non-empty. Floor at one bucket so the
    // cascade always has a final landing spot.
    if best_special_capacity == 0 {
        best_special_capacity = bucket_size.min(total_capacity);
    }
    best_special_capacity
}

/// Paper §5: split `α` levels with `a_{i+1} = 3a_i/4 ± 1`, geometrically decreasing.
/// Output is monotone non-increasing so `L0` is always the largest.
fn partition_funnel_buckets(total_buckets: usize, level_count: usize) -> Vec<usize> {
    if level_count == 0 {
        return Vec::new();
    }

    if total_buckets == 0 {
        return vec![0; level_count];
    }

    let first_level_guess = {
        let ratio = 0.75f64;
        let denom = 1.0 - ratio.powi(i32::try_from(level_count).expect("level count fits in i32"));
        if denom <= 0.0 {
            total_buckets.max(1)
        } else {
            cast::round_to_usize(
                (((cast::usize_to_f64(total_buckets)) * (1.0 - ratio)) / denom).max(0.0),
            )
        }
    };

    // The closed-form guess may be off by a few buckets — its sum doesn't
    // always hit `total_buckets` exactly under integer rounding. Search
    // outward by `radius` until a valid sequence is found.
    //
    // Worst case `O(total_buckets · level_count)`; in practice `radius`
    // stays at a small constant.
    for radius in 0..=total_buckets {
        let lower = first_level_guess.saturating_sub(radius);
        if let Some(bucket_counts) = build_funnel_bucket_sequence(total_buckets, level_count, lower)
        {
            return bucket_counts;
        }

        let upper = first_level_guess.saturating_add(radius).min(total_buckets);
        if upper != lower
            && let Some(bucket_counts) =
                build_funnel_bucket_sequence(total_buckets, level_count, upper)
        {
            return bucket_counts;
        }
    }

    let mut fallback_counts = vec![0; level_count];
    fallback_counts[0] = total_buckets;
    fallback_counts
}

fn build_funnel_bucket_sequence(
    total_buckets: usize,
    level_count: usize,
    first_level_bucket_count: usize,
) -> Option<Vec<usize>> {
    if level_count == 0 || first_level_bucket_count > total_buckets {
        return None;
    }

    let mut bucket_counts = Vec::with_capacity(level_count);
    bucket_counts.push(first_level_bucket_count);
    let mut remaining = total_buckets.saturating_sub(first_level_bucket_count);
    let mut previous_bucket_count = first_level_bucket_count;

    for level_idx in 1..level_count {
        let levels_after = level_count - level_idx - 1;
        let (min_next_bucket_count, max_next_bucket_count) =
            next_bucket_count_bounds(previous_bucket_count);
        let ideal_next_bucket_count = ((3 * previous_bucket_count + 2) / 4)
            .clamp(min_next_bucket_count, max_next_bucket_count);

        let mut chosen_bucket_count = None;
        let mut best_distance = usize::MAX;
        let candidate_upper_bound = max_next_bucket_count.min(remaining);
        for candidate_bucket_count in min_next_bucket_count..=candidate_upper_bound {
            let remaining_after_candidate = remaining - candidate_bucket_count;
            let (tail_min_sum, tail_max_sum) =
                possible_tail_sum_range(candidate_bucket_count, levels_after);
            if remaining_after_candidate < tail_min_sum || remaining_after_candidate > tail_max_sum
            {
                continue;
            }

            let distance = candidate_bucket_count.abs_diff(ideal_next_bucket_count);
            if distance < best_distance {
                best_distance = distance;
                chosen_bucket_count = Some(candidate_bucket_count);
                if distance == 0 {
                    break;
                }
            }
        }
        let chosen_bucket_count = chosen_bucket_count?;

        bucket_counts.push(chosen_bucket_count);
        remaining -= chosen_bucket_count;
        previous_bucket_count = chosen_bucket_count;
    }

    if remaining == 0 {
        Some(bucket_counts)
    } else {
        None
    }
}

fn next_bucket_count_bounds(current_bucket_count: usize) -> (usize, usize) {
    let scaled = current_bucket_count.saturating_mul(3);
    let min_next_bucket_count = scaled.saturating_sub(4).div_ceil(4);
    let max_next_bucket_count = (scaled.saturating_add(4) / 4).min(current_bucket_count);
    (
        min_next_bucket_count,
        max_next_bucket_count.max(min_next_bucket_count),
    )
}

fn possible_tail_sum_range(start_bucket_count: usize, levels_after: usize) -> (usize, usize) {
    let mut min_sum = 0;
    let mut max_sum = 0;
    let mut min_previous = start_bucket_count;
    let mut max_previous = start_bucket_count;

    for _ in 0..levels_after {
        let (next_min, _) = next_bucket_count_bounds(min_previous);
        let (_, next_max) = next_bucket_count_bounds(max_previous);
        min_sum += next_min;
        max_sum += next_max;
        min_previous = next_min;
        max_previous = next_max;
    }

    (min_sum, max_sum)
}

impl<K, V, S, A> Clone for FunnelHashMap<K, V, S, A>
where
    K: Clone,
    V: Clone,
    S: Clone,
    A: Allocator + Clone,
{
    fn clone(&self) -> Self {
        // Build level_bucket_counts from existing level descriptors.
        let bucket_width = align::round_up_to_group(compute_bucket_width(self.reserve_fraction));
        let primary_ctrl = self.special.primary.capacity as usize;
        let fallback_ctrl = self.special.fallback.capacity as usize;
        let level_bucket_counts: Vec<usize> = self
            .levels
            .iter()
            .map(|l| {
                if l.bucket_count_mask == 0 && l.capacity == 0 {
                    0
                } else {
                    l.bucket_count_mask as usize + 1
                }
            })
            .collect();
        let fallback_bucket_size = (self.primary_probe_limit.saturating_mul(2)).max(2);

        let (arena, levels, special) = alloc_funnel_arena(
            &level_bucket_counts,
            bucket_width,
            primary_ctrl,
            fallback_ctrl,
            fallback_bucket_size,
            &self.alloc,
        );

        // Drop guard: if a user-provided `Clone` impl panics inside
        // [`clone_region_panic_safe`], walk every region's OCCUPIED ctrls to
        // drop already-cloned values, then deallocate the partially-built arena.
        // `Arena` has no `Drop`, so without this the entire arena
        // allocation would leak on unwind.
        let mut guard = ArenaDropGuard::<K, V, A> {
            arena: Some(arena),
            levels: Some(levels),
            special: Some(special),
            alloc: self.alloc.clone(),
        };
        // Panic-safe order: clone value, write slot, then ctrl byte. If a
        // clone panics, only initialized slots carry OCCUPIED ctrls — the
        // guard's `drop_values` walks exactly those.
        for (dst, src_lvl) in guard
            .levels
            .as_deref_mut()
            .unwrap()
            .iter_mut()
            .zip(self.levels.iter())
        {
            arena::clone_region_panic_safe::<K, V>(
                src_lvl.ctrl_ptr,
                dst.ctrl_ptr,
                src_lvl.data_ptr,
                dst.data_ptr,
                src_lvl.capacity as usize,
            );
            dst.len = src_lvl.len;
            dst.tombstones = src_lvl.tombstones;
        }

        let special_mut = guard.special.as_mut().unwrap();
        {
            let s = &self.special.primary;
            let d = &mut special_mut.primary;
            arena::clone_region_panic_safe::<K, V>(
                s.ctrl_ptr,
                d.ctrl_ptr,
                s.data_ptr,
                d.data_ptr,
                s.capacity as usize,
            );
            d.len = s.len;
            d.tombstones = s.tombstones;
        }

        {
            let s = &self.special.fallback;
            let d = &mut special_mut.fallback;
            arena::clone_region_panic_safe::<K, V>(
                s.ctrl_ptr,
                d.ctrl_ptr,
                s.data_ptr,
                d.data_ptr,
                s.capacity as usize,
            );
            d.len = s.len;
            d.tombstones = s.tombstones;
        }

        special_mut.total_len = self.special.total_len;

        // Success: extract from guard so its Drop is a no-op.
        let arena = guard.arena.take().unwrap();
        let levels = guard.levels.take().unwrap();
        let special = guard.special.take().unwrap();
        drop(guard);

        Self {
            levels,
            special,
            len: self.len,
            total_slots: self.total_slots,
            max_insertions: self.max_insertions,
            reserve_fraction: self.reserve_fraction,
            primary_probe_limit: self.primary_probe_limit,
            max_populated_level: self.max_populated_level,
            hash_builder: self.hash_builder.clone(),
            alloc: self.alloc.clone(),
            arena,
        }
    }

    fn clone_from(&mut self, source: &Self) {
        // Reuse `self.arena` when every region's layout matches — same
        // capacities ⇒ same arena offsets, so we save one alloc + dealloc
        // per assignment. Falls back to full clone otherwise.
        let layouts_match = self.levels.len() == source.levels.len()
            && self
                .levels
                .iter()
                .zip(source.levels.iter())
                .all(|(a, b)| a.capacity == b.capacity)
            && self.special.primary.capacity == source.special.primary.capacity
            && self.special.fallback.capacity == source.special.fallback.capacity
            && self.special.fallback.bucket_count == source.special.fallback.bucket_count
            && self.special.fallback.bucket_size_log2 == source.special.fallback.bucket_size_log2;
        if !layouts_match {
            *self = source.clone();
            return;
        }

        for level in &self.levels {
            level.drop_values_and_clear();
        }
        self.special.primary.drop_values_and_clear();
        self.special.fallback.drop_values_and_clear();

        for (dst, src_lvl) in self.levels.iter_mut().zip(source.levels.iter()) {
            arena::clone_region_panic_safe::<K, V>(
                src_lvl.ctrl_ptr,
                dst.ctrl_ptr,
                src_lvl.data_ptr,
                dst.data_ptr,
                src_lvl.capacity as usize,
            );
            dst.len = src_lvl.len;
            dst.tombstones = src_lvl.tombstones;
        }
        {
            let s = &source.special.primary;
            let d = &mut self.special.primary;
            arena::clone_region_panic_safe::<K, V>(
                s.ctrl_ptr,
                d.ctrl_ptr,
                s.data_ptr,
                d.data_ptr,
                s.capacity as usize,
            );
            d.len = s.len;
            d.tombstones = s.tombstones;
        }
        {
            let s = &source.special.fallback;
            let d = &mut self.special.fallback;
            arena::clone_region_panic_safe::<K, V>(
                s.ctrl_ptr,
                d.ctrl_ptr,
                s.data_ptr,
                d.data_ptr,
                s.capacity as usize,
            );
            d.len = s.len;
            d.tombstones = s.tombstones;
        }
        self.special.total_len = source.special.total_len;

        self.len = source.len;
        self.total_slots = source.total_slots;
        self.max_insertions = source.max_insertions;
        self.reserve_fraction = source.reserve_fraction;
        self.primary_probe_limit = source.primary_probe_limit;
        self.max_populated_level = source.max_populated_level;
        self.hash_builder.clone_from(&source.hash_builder);
    }
}

impl<K, V, S, A> PartialEq for FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash,
    V: PartialEq,
    S: BuildHasher,
    A: Allocator + Clone,
{
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        self.iter()
            .all(|(k, v)| other.get(k).is_some_and(|ov| *v == *ov))
    }
}

impl<K, V, S, A> Eq for FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash,
    V: Eq,
    S: BuildHasher,
    A: Allocator + Clone,
{
}

impl<K, Q, V, S, A> Index<&Q> for FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash,
    Q: Hash + Equivalent<K> + ?Sized,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Output = V;

    #[inline]
    fn index(&self, key: &Q) -> &V {
        self.get(key).expect("no entry found for key")
    }
}

impl<K, V, S, A> Extend<(K, V)> for FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        let iter = iter.into_iter();
        let (lo, _) = iter.size_hint();
        if lo > 0 {
            self.reserve(lo);
        }
        for (k, v) in iter {
            self.insert(k, v);
        }
    }
}

impl<'a, K, V, S, A> Extend<(&'a K, &'a V)> for FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash + Copy,
    V: Copy,
    S: BuildHasher,
    A: Allocator + Clone,
{
    fn extend<I: IntoIterator<Item = (&'a K, &'a V)>>(&mut self, iter: I) {
        self.extend(iter.into_iter().map(|(k, v)| (*k, *v)));
    }
}

impl<'a, K, V, S, A> Extend<&'a (K, V)> for FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash + Copy,
    V: Copy,
    S: BuildHasher,
    A: Allocator + Clone,
{
    fn extend<I: IntoIterator<Item = &'a (K, V)>>(&mut self, iter: I) {
        self.extend(iter.into_iter().copied());
    }
}

impl<K, V, S> FromIterator<(K, V)> for FunnelHashMap<K, V, S, Global>
where
    K: Eq + Hash,
    S: BuildHasher + Default,
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let iter = iter.into_iter();
        let (lo, _) = iter.size_hint();
        let mut map = Self::with_capacity_and_hasher(lo, S::default());
        map.extend(iter);
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::hash::{BuildHasher, Hasher};

    struct ConstHasher;

    impl Hasher for ConstHasher {
        fn finish(&self) -> u64 {
            0
        }

        fn write(&mut self, _: &[u8]) {}
    }

    struct ConstHashBuilder;

    impl BuildHasher for ConstHashBuilder {
        type Hasher = ConstHasher;

        fn build_hasher(&self) -> Self::Hasher {
            ConstHasher
        }
    }

    #[test]
    fn funnel_layout_covers_capacity() {
        // `with_capacity(n)` interprets `n` as the insertion budget. Internal
        // slot allocation rounds up so `capacity() >= n` and total slots
        // (level + special) cover that budget.
        let requested = 257;
        let map: FunnelHashMap<i32, i32> = FunnelHashMap::with_capacity(requested);
        assert!(
            map.capacity() >= requested,
            "capacity={} below requested={requested}",
            map.capacity()
        );
        let level_capacity: usize = map.levels.iter().map(BucketLevel::capacity).sum();
        let special_capacity = map.special.primary.capacity() + map.special.fallback.capacity();
        let total = level_capacity + special_capacity;
        assert!(
            total >= requested,
            "total={total} below requested={requested}"
        );
    }

    #[test]
    fn partition_buckets_monotone_paper_invariant() {
        // Paper: A_i are "geometrically decreasing in size" (a_{i+1} = 3a_i/4 ± 1).
        // Concretely, partition output must be monotone non-increasing so that
        // L0 is always largest (highest hit rate, shortest insert chain).
        for total in 0usize..=64 {
            for levels in 1usize..=24 {
                let p = partition_funnel_buckets(total, levels);
                assert_eq!(p.len(), levels, "len mismatch for ({total}, {levels})");
                assert_eq!(
                    p.iter().sum::<usize>(),
                    total,
                    "sum for ({total}, {levels})"
                );
                for w in p.windows(2) {
                    assert!(w[1] <= w[0], "non-monotone for ({total}, {levels}): {p:?}");
                }
            }
        }
    }

    #[test]
    fn special_primary_single_group_edge_case() {
        // Smallest capacity exercises the SpecialPrimary path with
        // `group_count == 1` (`mask == 0`). The odd-step probe must still
        // make forward progress (loop terminates via `group_limit`).
        let mut map: FunnelHashMap<u64, u64> = FunnelHashMap::with_capacity(1);
        assert_eq!(
            map.special.primary.group_count_mask, 0,
            "regression assumes a single-group special primary"
        );
        for i in 0..16 {
            map.insert(i, i * 3);
        }
        for i in 0..16 {
            assert_eq!(map.get(&i), Some(&(i * 3)));
        }
        for i in 0..8 {
            assert_eq!(map.remove(&i), Some(i * 3));
        }
        for i in 0..8 {
            assert_eq!(map.get(&i), None);
        }
        for i in 8..16 {
            assert_eq!(map.get(&i), Some(&(i * 3)));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // FIXME: takes too long
    fn delete_insert_cycles_trigger_rebuild() {
        // Exercises the tombstone cleanup path: 6000 remove+insert cycles
        // on a 12K map forces level.tombstones > capacity/2.
        let n = 12_000;
        let mut map = FunnelHashMap::with_capacity(n * 2);
        for i in 0..n {
            map.insert(i, i);
        }

        for i in 0..6000 {
            assert!(map.remove(&i).is_some(), "remove {i} failed");
            map.insert(i + n, i + n);
        }

        assert_eq!(map.len(), n);
        // Verify all remaining keys are findable.
        for i in 6000..n {
            assert_eq!(map.get(&i), Some(&i), "original key {i} missing");
        }
        for i in 0..6000 {
            assert_eq!(
                map.get(&(i + n)),
                Some(&(i + n)),
                "new key {} missing",
                i + n
            );
        }
    }

    #[test]
    fn retain_does_not_trigger_mid_iter_resize_with_clustered_tombstones() {
        // `retain` cleans up only on iterator Drop, at the same capacity —
        // slot count must not change.
        let mut map: FunnelHashMap<i32, i32> = FunnelHashMap::with_capacity(1024);
        let max = i32::try_from(capacity::max_insertions(
            map.capacity(),
            DEFAULT_RESERVE_FRACTION,
        ))
        .expect("test capacity fits i32");
        for i in 0..max {
            map.insert(i, i);
        }
        let initial_capacity = map.capacity();
        map.retain(|k, _| k % 2 == 0);

        let expected_count = (0..max).filter(|i| i % 2 == 0).count();
        assert_eq!(map.len(), expected_count);
        for i in 0..max {
            if i % 2 == 0 {
                assert_eq!(map.get(&i), Some(&i), "kept key {i} missing");
            } else {
                assert!(map.get(&i).is_none(), "dropped key {i} survived");
            }
        }
        assert_eq!(
            map.capacity(),
            initial_capacity,
            "retain must not change the slot count, only rehash in place"
        );
    }

    #[test]
    fn bucket_overflow_promotes_max_populated_level() {
        // Paper §5: A_{i,j} overflow must spill into A_{i+1}, not skip to the
        // special array. Constant hasher pins every key to the same L0 bucket.
        let mut map: FunnelHashMap<i32, i32, ConstHashBuilder> =
            FunnelHashMap::with_capacity_and_hasher(2048, ConstHashBuilder);
        assert!(map.levels.len() > 1, "test requires multi-level layout");
        let l0_bucket_size = i32::try_from(1usize << map.levels[0].bucket_size_log2).unwrap();
        // bucket holds at most l0_bucket_size; one more forces a spill.
        for i in 0..=l0_bucket_size {
            map.insert(i, i);
        }
        assert_eq!(
            map.max_populated_level, 1,
            "first bucket overflow should land in A_1, not the special array"
        );
        for i in 0..=l0_bucket_size {
            assert_eq!(map.get(&i), Some(&i));
        }
    }

    #[test]
    fn reusing_level_tombstone_decrements_counter() {
        let mut map: FunnelHashMap<i32, i32, ConstHashBuilder> =
            FunnelHashMap::with_capacity_and_hasher(2048, ConstHashBuilder);
        let l0_bucket_size = 1usize << map.levels[0].bucket_size_log2;
        for i in 0..l0_bucket_size {
            let key = i32::try_from(i).unwrap();
            map.insert(key, key);
        }

        assert_eq!(map.levels[0].tombstones, 0);
        assert_eq!(map.remove(&0), Some(0));
        assert_eq!(map.levels[0].tombstones, 1);

        map.insert(10_000, 10_000);
        assert_eq!(map.levels[0].tombstones, 0);
        assert_eq!(map.get(&10_000), Some(&10_000));
    }

    #[test]
    fn reserve_fraction_clamped_to_funnel_max() {
        // Funnel's correctness proof requires reserve_fraction <= 1/8.
        let map: FunnelHashMap<i32, i32> =
            FunnelHashMap::with_capacity_and_reserve_fraction(256, 0.5);
        assert!(
            map.reserve_fraction <= MAX_FUNNEL_RESERVE_FRACTION,
            "reserve_fraction={} not clamped to {MAX_FUNNEL_RESERVE_FRACTION}",
            map.reserve_fraction
        );
    }
}
