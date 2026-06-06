use std::hash::{BuildHasher, Hash};
use std::mem::{self, MaybeUninit};
use std::ops::Range;
use std::slice;

use allocator_api2::alloc::{Allocator, Global, Layout};
use equivalent::Equivalent;

use crate::common::DefaultHashBuilder;
use crate::common::arena::{self, Arena, ArenaSlots, SlotEntry};
use crate::common::config::{GROUP_SIZE, INITIAL_CAPACITY};
use crate::common::control::{self, CTRL_EMPTY, CTRL_TOMBSTONE, ControlByte};
use crate::common::error::TryReserveError;
use crate::common::iter::RegionCursor;
use crate::common::math::{self, align, capacity, cast, probe};
use crate::common::simd;
use crate::map::{self, RawTable};
use crate::set;

/// Upper bound on `reserve_fraction`;
/// level capacities become unstable beyond this load factor.
pub(crate) const MAX_FUNNEL_RESERVE_FRACTION: f64 = 1.0 / 8.0;

/// One funnel level `A_i` (paper §5). Fixed grid of `β`-sized buckets `A_{i,j}`;
/// inserts hash to one bucket and probe within it. Overflow spills to `A_{i+1}`
/// (or the special array `A_{α+1}`).
struct BucketLevel<T> {
    ctrl_ptr: *mut u8,
    data_ptr: *mut MaybeUninit<T>,
    capacity: u32,
    bucket_count_mask: u32,
    bucket_size_log2: u32,
    salt: u32,
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
    fn data_ptr(&self) -> *mut MaybeUninit<T> {
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
        data_ptr: *mut MaybeUninit<T>,
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
    #[allow(clippy::cast_possible_truncation)]
    fn bucket_index(&self, key_hash: u64) -> usize {
        ((key_hash as u32) ^ self.salt) as usize & self.bucket_count_mask as usize
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
        unsafe { simd::free_mask_group(group_ptr) }
            .lowest()
            .map(|offset| bucket_range.start + offset)
    }

    /// Erase slot: become `CTRL_EMPTY` if the bucket has any EMPTY byte
    /// (probe chain terminates here), else `CTRL_TOMBSTONE`.
    /// Returns whether a tombstone was written.
    #[inline]
    fn erase(&mut self, idx: usize) -> bool {
        let group_idx = idx / GROUP_SIZE;
        let gp = unsafe { self.ctrl_ptr().add(group_idx * GROUP_SIZE) };
        if unsafe { simd::eq_mask_group(gp, CTRL_EMPTY).any() } {
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
        let match_mask = unsafe { simd::eq_mask_group(group_ptr, key_fingerprint) };
        for relative_idx in match_mask {
            let slot_idx = bucket_range.start + relative_idx;
            let entry = unsafe { self.get_ref(slot_idx) };
            if key.equivalent(&entry.key) {
                return LookupStep::Found(slot_idx);
            }
        }
        if wants_free {
            let free_mask = unsafe { simd::free_mask_group(group_ptr) };
            if let Some(o) = free_mask.lowest()
                && let Some(out) = slot_out
            {
                *out = Some(bucket_range.start + o);
            }
        }
        if unsafe { simd::eq_mask_group(group_ptr, CTRL_EMPTY).any() } {
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
    data_ptr: *mut MaybeUninit<T>,
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
    fn data_ptr(&self) -> *mut MaybeUninit<T> {
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
    fn new_at(
        cap: u32,
        group_count_mask: u32,
        ctrl_ptr: *mut u8,
        data_ptr: *mut MaybeUninit<T>,
    ) -> Self {
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
    fn erase(&mut self, idx: usize) -> bool {
        let group_idx = idx / GROUP_SIZE;
        let gp = unsafe { self.ctrl_ptr().add(group_idx * GROUP_SIZE) };
        if unsafe { simd::eq_mask_group(gp, CTRL_EMPTY).any() } {
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
    data_ptr: *mut MaybeUninit<T>,
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
    fn data_ptr(&self) -> *mut MaybeUninit<T> {
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
        data_ptr: *mut MaybeUninit<T>,
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
    fn erase(&mut self, idx: usize) -> bool {
        let group_idx = idx / GROUP_SIZE;
        let gp = unsafe { self.ctrl_ptr().add(group_idx * GROUP_SIZE) };
        if unsafe { simd::eq_mask_group(gp, CTRL_EMPTY).any() } {
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
    fn drain_occupied_with<F: FnMut(T)>(&mut self, mut f: F) {
        self.primary.drain_values_and_clear(&mut f);
        self.fallback.drain_values_and_clear(f);
    }
}

/// Where in the funnel structure a key/slot lives. Returned by lookups,
/// consumed by inserts / removes to avoid recomputing the location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotLocation {
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

/// Why a single-pass level probe missed, deciding whether overflow to the
/// special array is possible.
enum LevelMiss {
    /// An EMPTY byte ended the chain; no overflow to special possible.
    ChainClean,
    /// Levels exhausted without a clean stop; key may be in the special array.
    MayContinue,
}

/// Open-addressed funnel-hashing backend for the generic [`map::HashMap`]
/// shell. See [`FunnelHashMap`] for the public map type.
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
pub struct FunnelTable<K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
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
    for FunnelTable<K, V, S, A>
{
}
unsafe impl<K: Sync, V: Sync, S: Sync, A: Allocator + Clone + Sync> Sync
    for FunnelTable<K, V, S, A>
{
}

impl<K, V, S, A: Allocator + Clone> Drop for FunnelTable<K, V, S, A> {
    fn drop(&mut self) {
        let arena = mem::replace(&mut self.arena, Arena::empty());
        let guard = arena::DeallocGuard::new(arena, &self.alloc);
        for level in &mut self.levels {
            level.drop_values();
        }
        self.special.primary.drop_values();
        self.special.fallback.drop_values();
        drop(guard);
    }
}

// ---------------------------------------------------------------------------
// Public type aliases. The generic [`map::HashMap`] shell supplies the public
// API; these names keep `FunnelHashMap` and its iterator/entry types nameable
// (and re-exportable from `lib.rs` / `set.rs`).
// ---------------------------------------------------------------------------

/// Open-addressed hash map using funnel hashing.
pub type FunnelHashMap<K, V, S = DefaultHashBuilder, A = Global> =
    map::HashMap<K, V, FunnelTable<K, V, S, A>>;

/// A view into a single entry, occupied or vacant.
pub type Entry<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::Entry<'a, K, V, FunnelTable<K, V, S, A>>;
/// View of an occupied entry.
pub type OccupiedEntry<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::OccupiedEntry<'a, K, V, FunnelTable<K, V, S, A>>;
/// View of a vacant entry.
pub type VacantEntry<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::VacantEntry<'a, K, V, FunnelTable<K, V, S, A>>;
/// Error returned by `try_insert` on key collision.
pub type OccupiedError<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::OccupiedError<'a, K, V, FunnelTable<K, V, S, A>>;
/// Borrowing iterator over `(&K, &V)`.
pub type FunnelIter<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::Iter<'a, K, V, FunnelTable<K, V, S, A>>;
/// Borrowing iterator over `(&K, &mut V)`.
pub type FunnelIterMut<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::IterMut<'a, K, V, FunnelTable<K, V, S, A>>;
/// Consuming iterator over owned `(K, V)`.
pub type FunnelIntoIter<K, V, S = DefaultHashBuilder, A = Global> =
    map::IntoIter<K, V, FunnelTable<K, V, S, A>>;
/// `&K` iterator.
pub type Keys<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::Keys<'a, K, V, FunnelTable<K, V, S, A>>;
/// `&V` iterator.
pub type Values<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::Values<'a, K, V, FunnelTable<K, V, S, A>>;
/// `&mut V` iterator.
pub type FunnelValuesMut<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::ValuesMut<'a, K, V, FunnelTable<K, V, S, A>>;
/// Owned `K` iterator.
pub type FunnelIntoKeys<K, V, S = DefaultHashBuilder, A = Global> =
    map::IntoKeys<K, V, FunnelTable<K, V, S, A>>;
/// Owned `V` iterator.
pub type FunnelIntoValues<K, V, S = DefaultHashBuilder, A = Global> =
    map::IntoValues<K, V, FunnelTable<K, V, S, A>>;
/// Draining iterator that empties the map.
pub type Drain<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::Drain<'a, K, V, FunnelTable<K, V, S, A>>;
/// Iterator yielding entries removed by `extract_if`.
pub type ExtractIf<'a, K, V, F, S = DefaultHashBuilder, A = Global> =
    map::ExtractIf<'a, K, V, FunnelTable<K, V, S, A>, F>;

/// Hash set using funnel hashing.
pub type FunnelHashSet<T, S = DefaultHashBuilder, A = Global> =
    set::HashSet<T, FunnelTable<T, (), S, A>>;
/// Borrowing iterator over set values.
pub type FunnelSetIter<'a, T, S = DefaultHashBuilder, A = Global> =
    set::Iter<'a, T, FunnelTable<T, (), S, A>>;
/// Consuming iterator over set values.
pub type FunnelSetIntoIter<T, S = DefaultHashBuilder, A = Global> =
    set::IntoIter<T, FunnelTable<T, (), S, A>>;
/// Draining iterator that empties the set.
pub type FunnelSetDrain<'a, T, S = DefaultHashBuilder, A = Global> =
    set::Drain<'a, T, FunnelTable<T, (), S, A>>;
/// Iterator yielding values removed by set `extract_if`.
pub type FunnelSetExtractIf<'a, T, S = DefaultHashBuilder, A = Global> =
    set::ExtractIf<'a, T, FunnelTable<T, (), S, A>>;
/// Iterator over values present only in the first set.
pub type FunnelDifference<'a, T, S = DefaultHashBuilder, A = Global> =
    set::Difference<'a, T, FunnelTable<T, (), S, A>>;
/// Iterator over values present in both sets.
pub type FunnelIntersection<'a, T, S = DefaultHashBuilder, A = Global> =
    set::Intersection<'a, T, FunnelTable<T, (), S, A>>;
/// Iterator over values present in exactly one set.
pub type FunnelSymmetricDifference<'a, T, S = DefaultHashBuilder, A = Global> =
    set::SymmetricDifference<'a, T, FunnelTable<T, (), S, A>>;
/// Iterator over values present in either set.
pub type FunnelUnion<'a, T, S = DefaultHashBuilder, A = Global> =
    set::Union<'a, T, FunnelTable<T, (), S, A>>;
/// A view into a single set entry.
pub type FunnelSetEntry<'a, T, S = DefaultHashBuilder, A = Global> =
    set::Entry<'a, T, FunnelTable<T, (), S, A>>;
/// View of an occupied set entry.
pub type FunnelSetOccupiedEntry<'a, T, S = DefaultHashBuilder, A = Global> =
    set::OccupiedEntry<'a, T, FunnelTable<T, (), S, A>>;
/// View of a vacant set entry.
pub type FunnelSetVacantEntry<'a, T, S = DefaultHashBuilder, A = Global> =
    set::VacantEntry<'a, T, FunnelTable<T, (), S, A>>;

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
        let data_ptr = unsafe {
            arena_base
                .add(data_off as usize)
                .cast::<MaybeUninit<SlotEntry<K, V>>>()
        };
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
    let primary_data_ptr = unsafe {
        arena_base
            .add(data_off as usize)
            .cast::<MaybeUninit<SlotEntry<K, V>>>()
    };
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
    let fallback_data_ptr = unsafe {
        arena_base
            .add(data_off as usize)
            .cast::<MaybeUninit<SlotEntry<K, V>>>()
    };
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
            if let Some(mut levels) = self.levels.take() {
                for level in &mut levels {
                    level.drop_values();
                }
            }
            if let Some(mut special) = self.special.take() {
                special.primary.drop_values();
                special.fallback.drop_values();
            }
            arena.deallocate(&self.alloc);
        }
    }
}

impl<K, V, S, A> FunnelTable<K, V, S, A>
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

    /// Places a known-novel entry at `location`, resizing first if the table is
    /// full or no candidate was found. Single-pass insert's placement tail.
    fn insert_at_location_after_resize_check(
        &mut self,
        location: Option<SlotLocation>,
        key_hash: u64,
        key: K,
        value: V,
        key_fingerprint: u8,
    ) -> Option<V> {
        let final_location = match location {
            Some(loc) if self.len < self.max_insertions => loc,
            _ => {
                let new_capacity = if self.total_slots == 0 {
                    INITIAL_CAPACITY
                } else {
                    self.total_slots.saturating_mul(2)
                };
                self.resize(new_capacity);
                self.choose_slot_for_new_key(key_hash)
                    .expect("no free slot found after resize")
            }
        };

        self.place_new_entry(final_location, key, value, key_fingerprint);
        None
    }

    /// Raw pointer to the whole slot at `loc`. Projects through raw pointers
    /// from shared `&Region` (level / special primary / special fallback),
    /// forming no intermediate `&mut`, so distinct locations yield
    /// non-aliasing `*mut`.
    ///
    /// # Safety
    /// `loc` must reference a live slot in this table.
    #[inline]
    unsafe fn slot_ptr_at(&self, loc: SlotLocation) -> *mut SlotEntry<K, V> {
        match loc {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => {
                let levels_ptr: *const BucketLevel<SlotEntry<K, V>> = self.levels.as_ptr();
                // SAFETY: shared `&BucketLevel` only — never `&mut` — so no
                // aliasing tag.
                let level = unsafe { &*levels_ptr.add(level_idx) };
                level.slot_ptr(slot_idx)
            }
            SlotLocation::SpecialPrimary { slot_idx } => self.special.primary.slot_ptr(slot_idx),
            SlotLocation::SpecialFallback { slot_idx } => self.special.fallback.slot_ptr(slot_idx),
        }
    }

    /// Take + erase + decrement counters for the slot at `loc`. Shared by
    /// [`RawTable::remove`] and [`RawTable::extract_at`]; the former adds a
    /// resize pass, the latter consolidates tombstones lazily.
    fn take_and_tombstone(&mut self, location: SlotLocation) -> (K, V) {
        let removed = match location {
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
                removed
            }
            SlotLocation::SpecialPrimary { slot_idx } => {
                let primary = &mut self.special.primary;
                let removed = unsafe { primary.take(slot_idx) };
                if primary.erase(slot_idx) {
                    primary.tombstones += 1;
                }
                primary.len -= 1;
                self.special.total_len -= 1;
                removed
            }
            SlotLocation::SpecialFallback { slot_idx } => {
                let fallback = &mut self.special.fallback;
                let removed = unsafe { fallback.take(slot_idx) };
                if fallback.erase(slot_idx) {
                    fallback.tombstones += 1;
                }
                fallback.len -= 1;
                self.special.total_len -= 1;
                removed
            }
        };
        self.len -= 1;
        (removed.key, removed.value)
    }

    /// `true` if the region holding `loc` now has more tombstones than half
    /// its capacity, so [`RawTable::remove`] should rehash in place.
    fn region_needs_cleanup(&self, location: SlotLocation) -> bool {
        let (tombstones, cap) = match location {
            SlotLocation::Level { level_idx, .. } => {
                let level = &self.levels[level_idx];
                (level.tombstones, level.capacity())
            }
            SlotLocation::SpecialPrimary { .. } => {
                let primary = &self.special.primary;
                (primary.tombstones, primary.capacity())
            }
            SlotLocation::SpecialFallback { .. } => {
                let fallback = &self.special.fallback;
                (fallback.tombstones, fallback.capacity())
            }
        };
        tombstones as usize > cap / 2
    }

    /// Bulk-clears all control bytes and zeroes counters. Called by
    /// [`map::Drain::drop`] after the slots' values have been taken.
    fn wipe_all(&mut self) {
        for level in &mut self.levels {
            level.clear_all_controls();
            level.len = 0;
            level.tombstones = 0;
        }
        self.special.primary.clear_all_controls();
        self.special.primary.len = 0;
        self.special.primary.tombstones = 0;
        self.special.fallback.clear_all_controls();
        self.special.fallback.len = 0;
        self.special.fallback.tombstones = 0;
        self.special.total_len = 0;
        self.len = 0;
        self.max_populated_level = 0;
    }

    /// Removes all entries, keeping allocated capacity.
    fn clear(&mut self) {
        for level in &mut self.levels {
            level.drop_values_and_clear();
            level.len = 0;
            level.tombstones = 0;
        }
        self.special.primary.drop_values_and_clear();
        self.special.primary.len = 0;
        self.special.primary.tombstones = 0;
        self.special.fallback.drop_values_and_clear();
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
        for level in &mut self.levels {
            level.drain_values_and_clear(|entry| {
                out.push((entry.key, entry.value));
            });
        }
        self.special.drain_occupied_with(|entry| {
            out.push((entry.key, entry.value));
        });
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

    /// Single-pass level probe. Returns the match if any; with `Some(free_slot)`
    /// records the first free slot so an insert places there without re-probing.
    /// The [`LevelMiss`] reports whether the chain ended clean (no special overflow).
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
    fn place_new_entry(&mut self, location: SlotLocation, key: K, value: V, key_fingerprint: u8) {
        match location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => {
                let level = &mut self.levels[level_idx];
                level.write_with_control(slot_idx, SlotEntry { key, value }, key_fingerprint);
                level.len += 1;
                if level_idx > self.max_populated_level {
                    self.max_populated_level = level_idx;
                }
            }
            SlotLocation::SpecialPrimary { slot_idx } => {
                let primary = &mut self.special.primary;
                // Reusing a tombstone slot must decrement the counter;
                // otherwise resize triggers on stale-since-resize counts.
                let was_tombstone = primary.control_at(slot_idx) == CTRL_TOMBSTONE;
                primary.write_with_control(slot_idx, SlotEntry { key, value }, key_fingerprint);
                primary.len += 1;
                if was_tombstone {
                    primary.tombstones -= 1;
                }
                self.special.total_len += 1;
            }
            SlotLocation::SpecialFallback { slot_idx } => {
                let fallback = &mut self.special.fallback;
                fallback.write_with_control(slot_idx, SlotEntry { key, value }, key_fingerprint);
                fallback.len += 1;
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
        // SAFETY: `levels.len() == level_count >= 1` (fixed at construction), so
        // index 0 is always valid. Elides the hot-path bounds check + panic pad.
        let level0 = unsafe { self.levels.get_unchecked(0) };
        match level0.find_in_bucket(key_hash, key_fingerprint, key, None) {
            LookupStep::Found(slot_idx) => {
                return Some(SlotLocation::Level {
                    level_idx: 0,
                    slot_idx,
                });
            }
            LookupStep::Continue => {}
            LookupStep::StopSearch => return None,
        }

        if self.max_populated_level > 0 {
            let search_limit = (self.max_populated_level + 1).min(self.levels.len());
            // SAFETY: `search_limit <= levels.len()` by the `min` above, and
            // `1 <= search_limit` whenever `max_populated_level > 0`, so the
            // range is in bounds. Elides the slice bounds check.
            let tail = unsafe { self.levels.get_unchecked(1..search_limit) };
            for (offset, level) in tail.iter().enumerate() {
                match level.find_in_bucket(key_hash, key_fingerprint, key, None) {
                    LookupStep::Found(slot_idx) => {
                        return Some(SlotLocation::Level {
                            level_idx: offset + 1,
                            slot_idx,
                        });
                    }
                    LookupStep::Continue => {}
                    LookupStep::StopSearch => return None,
                }
            }
        }

        // Special tables are only populated under overflow.
        if self.special.total_len == 0 {
            return None;
        }
        self.find_in_special(key, key_hash, key_fingerprint, None)
    }

    fn shrink_max_populated_level(&mut self) {
        while self.max_populated_level > 0 && self.levels[self.max_populated_level].len == 0 {
            self.max_populated_level -= 1;
        }
    }
}

impl<K, V, S, A> FunnelTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    /// Cold path of [`RawTable::scan_next`]: first-call region prime and region
    /// crossings (levels → special primary → fallback). Kept out of line so the
    /// per-element hot path inlines.
    #[cold]
    fn scan_advance(&self, scan: &mut FunnelScan) -> Option<(*mut SlotEntry<K, V>, SlotLocation)> {
        if !scan.region.started() {
            // Prime the cursor on the first region. With no levels, jump
            // straight to the special primary.
            if self.levels.is_empty() {
                scan.phase = ScanPhase::Primary;
                scan.region.enter(&self.special.primary);
            } else {
                scan.region.enter(&self.levels[0]);
            }
        }
        loop {
            if let Some((ptr, slot_idx)) = scan.region.step::<SlotEntry<K, V>>() {
                return Some((ptr, scan.location_at(slot_idx)));
            }
            // Current region exhausted: advance, re-deriving the region pointer
            // from `&self`.
            match scan.phase {
                ScanPhase::Levels => {
                    scan.level_idx += 1;
                    if scan.level_idx < self.levels.len() {
                        scan.region.enter(&self.levels[scan.level_idx]);
                    } else {
                        scan.phase = ScanPhase::Primary;
                        scan.region.enter(&self.special.primary);
                    }
                }
                ScanPhase::Primary => {
                    scan.phase = ScanPhase::Fallback;
                    scan.region.enter(&self.special.fallback);
                }
                ScanPhase::Fallback => {
                    scan.phase = ScanPhase::Done;
                    return None;
                }
                ScanPhase::Done => return None,
            }
        }
    }
}

// `SlotEntry` is `pub(crate)`; the `RawTable` trait (in the private `map`
// module) exposes it in `slot_ref`/`slot_ptr`, so the impl mirrors the trait's
// private-interface lint exemption.
#[allow(private_interfaces)]
impl<K, V, S, A> RawTable<K, V> for FunnelTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Location = SlotLocation;
    type Hasher = S;
    type Alloc = A;
    type Scan = FunnelScan;

    #[inline]
    fn with_capacity_and_reserve_fraction_and_hasher_in(
        capacity: usize,
        reserve_fraction: f64,
        hash_builder: S,
        alloc: A,
    ) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            capacity,
            reserve_fraction,
            hash_builder,
            alloc,
        )
    }

    #[inline]
    fn hasher(&self) -> &S {
        &self.hash_builder
    }

    #[inline]
    fn allocator(&self) -> &A {
        &self.alloc
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    fn capacity(&self) -> usize {
        self.max_insertions
    }

    #[inline]
    fn total_slots(&self) -> usize {
        self.total_slots
    }

    #[inline]
    fn reserve_fraction(&self) -> f64 {
        self.reserve_fraction
    }

    #[inline]
    fn grow_capacity_for(&self, needed: usize) -> Option<usize> {
        self.grow_capacity_for(needed)
    }

    #[inline]
    fn resize(&mut self, new_capacity: usize) {
        self.resize(new_capacity);
    }

    #[inline]
    fn try_resize(&mut self, new_capacity: usize) -> Result<(), TryReserveError>
    where
        S: Clone,
    {
        self.try_resize(new_capacity)
    }

    #[inline]
    fn clear(&mut self) {
        self.clear();
    }

    #[inline]
    fn find<Q>(&self, key: &Q, hash: u64, fingerprint: u8) -> Option<SlotLocation>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find_slot_location_with_hash(key, hash, fingerprint)
    }

    #[inline]
    unsafe fn slot_ref(&self, loc: SlotLocation) -> &SlotEntry<K, V> {
        unsafe { self.slot_ref(loc) }
    }

    #[inline]
    unsafe fn slot_ptr(&self, loc: SlotLocation) -> *mut SlotEntry<K, V> {
        unsafe { self.slot_ptr_at(loc) }
    }

    #[inline]
    fn replace_value(&mut self, loc: SlotLocation, value: V) -> V {
        self.replace_existing_value(loc, value)
    }

    #[inline]
    fn insert_for_vacant(&mut self, key: K, value: V, hash: u64) -> SlotLocation {
        self.insert_for_vacant_entry(key, value, hash)
    }

    fn insert(&mut self, key: K, value: V, key_hash: u64) -> Option<V>
    where
        K: Hash + Eq,
    {
        let key_fingerprint = control::control_fingerprint(key_hash);

        // One pass over levels: on match replace; on miss keep the first free
        // slot as the insertion candidate.
        let mut candidate: Option<SlotLocation> = None;
        let (found, miss) =
            self.find_in_levels(&key, key_hash, key_fingerprint, Some(&mut candidate));
        if let Some(location) = found {
            return Some(self.replace_existing_value(location, value));
        }

        // Skip the special-array dedup when the chain ended clean (no overflow
        // possible) or special is empty — place at the level candidate.
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

        // Cold: key may have overflowed to special; probe it for a match.
        if let Some(location) =
            self.find_in_special(&key, key_hash, key_fingerprint, Some(&mut candidate))
        {
            return Some(self.replace_existing_value(location, value));
        }

        self.insert_at_location_after_resize_check(candidate, key_hash, key, value, key_fingerprint)
    }

    fn remove(&mut self, loc: SlotLocation) -> (K, V) {
        let kv = self.take_and_tombstone(loc);
        self.shrink_max_populated_level();
        if self.region_needs_cleanup(loc) {
            self.resize(self.total_slots);
        }
        kv
    }

    #[inline]
    fn tombstone_slot(&mut self, location: SlotLocation) {
        match location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => {
                self.levels[level_idx].erase(slot_idx);
            }
            SlotLocation::SpecialPrimary { slot_idx } => {
                self.special.primary.erase(slot_idx);
            }
            SlotLocation::SpecialFallback { slot_idx } => {
                self.special.fallback.erase(slot_idx);
            }
        }
    }

    #[inline]
    fn extract_finish(&mut self, location: SlotLocation) {
        match location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => {
                let level = &mut self.levels[level_idx];
                if level.erase(slot_idx) {
                    level.tombstones += 1;
                }
                level.len -= 1;
            }
            SlotLocation::SpecialPrimary { slot_idx } => {
                let primary = &mut self.special.primary;
                if primary.erase(slot_idx) {
                    primary.tombstones += 1;
                }
                primary.len -= 1;
                self.special.total_len -= 1;
            }
            SlotLocation::SpecialFallback { slot_idx } => {
                let fallback = &mut self.special.fallback;
                if fallback.erase(slot_idx) {
                    fallback.tombstones += 1;
                }
                fallback.len -= 1;
                self.special.total_len -= 1;
            }
        }
        self.len -= 1;
    }

    #[inline]
    fn scan(&self) -> FunnelScan {
        FunnelScan {
            phase: ScanPhase::Levels,
            level_idx: 0,
            region: RegionCursor::new(),
        }
    }

    #[inline]
    fn scan_next(&self, scan: &mut FunnelScan) -> Option<(*mut SlotEntry<K, V>, SlotLocation)> {
        // Hot path: another occupied slot in the region the cursor already holds.
        if scan.region.started()
            && let Some((ptr, slot_idx)) = scan.region.step::<SlotEntry<K, V>>()
        {
            return Some((ptr, scan.location_at(slot_idx)));
        }
        self.scan_advance(scan)
    }

    fn wipe_all(&mut self) {
        self.wipe_all();
    }

    fn clone_table(&self) -> Self
    where
        K: Clone,
        V: Clone,
        S: Clone,
    {
        self.clone_storage()
    }
}

/// Three-phase region of a [`FunnelScan`]: walk all bucket levels, then the
/// special primary, then the special fallback.
#[derive(Clone, Copy)]
enum ScanPhase {
    Levels,
    Primary,
    Fallback,
    Done,
}

/// Pointerless multi-region scan cursor for [`RawTable::scan`]. Holds only the
/// current phase + level index + a shared [`RegionCursor`]; the owning iterator
/// can move the table because no pointer into it is stored across calls.
/// Mirrors [`crate::elastic::ElasticScan`] but crosses three region kinds
/// (levels → special primary → special fallback).
#[derive(Clone)]
pub struct FunnelScan {
    phase: ScanPhase,
    level_idx: usize,
    region: RegionCursor,
}

impl FunnelScan {
    /// Maps `slot_idx` in the cursor's current region to its [`SlotLocation`].
    /// Shared by the hot and cold `scan_next` paths.
    #[inline]
    fn location_at(&self, slot_idx: usize) -> SlotLocation {
        match self.phase {
            ScanPhase::Levels => SlotLocation::Level {
                level_idx: self.level_idx,
                slot_idx,
            },
            ScanPhase::Primary => SlotLocation::SpecialPrimary { slot_idx },
            ScanPhase::Fallback => SlotLocation::SpecialFallback { slot_idx },
            // `step` returns `None` on an empty region, so the cursor never
            // yields once the phase machine reaches `Done`.
            ScanPhase::Done => unreachable!("cursor empty in Done phase"),
        }
    }
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

impl<K, V, S, A> FunnelTable<K, V, S, A>
where
    K: Clone,
    V: Clone,
    S: Clone,
    A: Allocator + Clone,
{
    /// Deep-clones storage + hasher + allocator. Backs the
    /// [`RawTable::clone_table`] impl; the [`map::HashMap`] shell provides the
    /// public [`Clone`].
    fn clone_storage(&self) -> Self {
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
}

/// Test-only direct drivers for [`FunnelTable`] internals. The public
/// insert/get/remove API now lives on the [`map::HashMap`] shell, but the
/// unit tests below inspect backend-private fields (`levels`, `special`,
/// `max_populated_level`, `reserve_fraction`), so they operate on the table
/// directly.
#[cfg(test)]
impl<K, V, S, A> FunnelTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    fn test_insert(&mut self, key: K, value: V) -> Option<V> {
        let hash = self.hash_key(&key);
        let fp = control::control_fingerprint(hash);
        if let Some(loc) = self.find_slot_location_with_hash(&key, hash, fp) {
            return Some(self.replace_existing_value(loc, value));
        }
        self.insert_for_vacant_entry(key, value, hash);
        None
    }

    fn test_get<Q>(&self, key: &Q) -> Option<&V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let hash = self.hash_key(key);
        let fp = control::control_fingerprint(hash);
        let loc = self.find_slot_location_with_hash(key, hash, fp)?;
        Some(unsafe { &self.slot_ref(loc).value })
    }

    fn test_remove<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let hash = self.hash_key(key);
        let fp = control::control_fingerprint(hash);
        let loc = self.find_slot_location_with_hash(key, hash, fp)?;
        Some(RawTable::remove(self, loc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::hash::{BuildHasher, Hasher};

    /// Builds a [`FunnelTable`] directly (bypassing the shell) so tests can
    /// reach backend-private fields.
    fn table_with_capacity<K, V>(capacity: usize) -> FunnelTable<K, V>
    where
        K: Eq + Hash,
    {
        FunnelTable::with_capacity_and_reserve_fraction_and_hasher_in(
            capacity,
            crate::common::config::DEFAULT_RESERVE_FRACTION,
            DefaultHashBuilder::default(),
            Global,
        )
    }

    #[test]
    fn funnel_layout_covers_capacity() {
        // `with_capacity(n)` interprets `n` as the insertion budget. Internal
        // slot allocation rounds up so `capacity() >= n` and total slots
        // (level + special) cover that budget.
        let requested = 257;
        let table: FunnelTable<i32, i32> = table_with_capacity(requested);
        assert!(
            table.capacity() >= requested,
            "capacity={} below requested={requested}",
            table.capacity()
        );
        let level_capacity: usize = table.levels.iter().map(BucketLevel::capacity).sum();
        let special_capacity = table.special.primary.capacity() + table.special.fallback.capacity();
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
        let mut table: FunnelTable<u64, u64> = table_with_capacity(1);
        assert_eq!(
            table.special.primary.group_count_mask, 0,
            "regression assumes a single-group special primary"
        );
        for i in 0..16 {
            table.test_insert(i, i * 3);
        }
        for i in 0..16 {
            assert_eq!(table.test_get(&i), Some(&(i * 3)));
        }
        for i in 0..8 {
            assert_eq!(table.test_remove(&i).map(|(_, v)| v), Some(i * 3));
        }
        for i in 0..8 {
            assert_eq!(table.test_get(&i), None);
        }
        for i in 8..16 {
            assert_eq!(table.test_get(&i), Some(&(i * 3)));
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
            crate::common::config::DEFAULT_RESERVE_FRACTION,
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

        let mut table: FunnelTable<i32, i32, ConstHashBuilder> =
            FunnelTable::with_capacity_and_reserve_fraction_and_hasher_in(
                2048,
                crate::common::config::DEFAULT_RESERVE_FRACTION,
                ConstHashBuilder,
                Global,
            );
        assert!(table.levels.len() > 1, "test requires multi-level layout");
        let l0_bucket_size = i32::try_from(1usize << table.levels[0].bucket_size_log2).unwrap();
        // bucket holds at most l0_bucket_size; one more forces a spill.
        for i in 0..=l0_bucket_size {
            table.test_insert(i, i);
        }
        assert_eq!(
            table.max_populated_level, 1,
            "first bucket overflow should land in A_1, not the special array"
        );
        for i in 0..=l0_bucket_size {
            assert_eq!(table.test_get(&i), Some(&i));
        }
    }

    #[test]
    fn reserve_fraction_clamped_to_funnel_max() {
        // Funnel's correctness proof requires reserve_fraction <= 1/8.
        let table: FunnelTable<i32, i32> =
            FunnelTable::with_capacity_and_reserve_fraction_and_hasher_in(
                256,
                0.5,
                DefaultHashBuilder::default(),
                Global,
            );
        assert!(
            table.reserve_fraction <= MAX_FUNNEL_RESERVE_FRACTION,
            "reserve_fraction={} not clamped to {MAX_FUNNEL_RESERVE_FRACTION}",
            table.reserve_fraction
        );
    }
}
