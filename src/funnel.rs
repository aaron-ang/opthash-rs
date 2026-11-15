//! Paper-exact Funnel placement with explicit dynamic-map epoch extensions.
use core::fmt;
use core::hash::{BuildHasher, Hash};
use core::mem::{self, MaybeUninit};

use alloc::boxed::Box;
use alloc::vec::Vec;
use allocator_api2::alloc::{Allocator, Global, Layout};
use equivalent::Equivalent;

use crate::ReserveFraction;
use crate::capacity;
use crate::epoch::{EpochSnapshot, EpochState, EpochTransition};
use crate::error::{TryBuildError, TryReserveError};
use crate::exact::geometry::{self, PaperConfig};
use crate::exact::probe::{
    self, FUNNEL_SPECIAL_FALLBACK_A_BASE, FUNNEL_SPECIAL_FALLBACK_B_BASE,
    FUNNEL_SPECIAL_PRIMARY_BASE, FunnelPrf, PreparedFastFunnelDomainProbe, PreparedFastFunnelProbe,
    PreparedProbeRange,
};
use crate::hasher::DefaultHashBuilder;
use crate::membership::{self, MembershipKey, MembershipRegion, MetadataWord};
use crate::raw::arena::{self, Arena, ArenaSlots, SlotEntry};
use crate::raw::bitmask::{BITMASK_SLOT_BIT, BITMASK_STRIDE};
use crate::raw::config::GROUP_SIZE;
use crate::raw::control::{self, CTRL_EMPTY, CTRL_TOMBSTONE};
use crate::raw::iter::OccupiedIndices;
use crate::raw::prefetch;
use crate::raw::rebuild::{self, Rebuildable};
use crate::raw::simd;
use crate::{macros, map};

/// Initial probe seed; each placement-recovery rebuild advances it by
/// [`FUNNEL_RESEED_STEP`].
const FUNNEL_PROBE_SEED: u64 = probe::WYHASH_DEFAULT_SECRET[3];
/// Added to the probe seed by each placement-recovery rebuild. The seed is
/// added to the key hash ahead of the fold, so a reseed translates every hash
/// by this step.
const FUNNEL_RESEED_STEP: u64 = probe::WYHASH_DEFAULT_SECRET[0];
/// Largest table whose lookups select between the first two recorded levels
/// instead of branching on the first. The second scan is a few instructions
/// while the control bytes, one per slot, stay in a core's private cache; past
/// that it is one more cache miss per lookup. The bound is a size such caches
/// commonly hold, not a measured crossover.
const SELECT_MAX_SLOTS: usize = 1 << 18;
/// Bits each key sets in its membership-filter word. A lookup whose bits are
/// not all set skips the probe walk, since the key cannot be present.
const MEMBERSHIP_BITS: usize = 2;

/// Pointerless scan progress through Funnel's flat storage.
#[derive(Clone, Debug)]
pub struct FunnelScan {
    mode: FunnelScanMode,
}

#[derive(Clone, Debug)]
enum FunnelScanMode {
    Dense(usize),
    Sparse(OccupiedIndices),
}

/// Entries of [`FunnelShape::head`]: the levels that own a level-bin bit plus
/// at least one absent entry, rounded up to a power of two so indexing masks
/// instead of bounds-checking.
const HEAD_LEVELS: usize = (OVERFLOW_LEVEL + 1).next_power_of_two();

// Declaration order is layout order: a draw reads the multiplier with the
// bucket count, and a tested draw the threshold with the offset.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LevelShape {
    /// See [`FunnelPrf::ordinary_multiplier`].
    multiplier: u64,
    bucket_range: PreparedProbeRange,
    offset: usize,
}

// Declaration order is layout order: the words every operation reads are
// adjacent at the front, and the large head array comes last.
#[repr(C)]
#[derive(Clone, Debug)]
struct FunnelShape {
    max_insertions: usize,
    /// One bit per lane of a bucket, selecting its lanes from a group's
    /// fingerprint matches. Zero when a bucket is wider than one group, or
    /// the shape is empty: such a table scans no bucket for first matches.
    bucket_lanes: u64,
    beta: usize,
    /// [`Self::bucket_lanes`] for lookups, with [`LOOKUP_SELECTS`] set when
    /// they select between the first two recorded levels; see
    /// [`SELECT_MAX_SLOTS`]. Next to `beta` so a lookup loads the pair.
    lookup_lanes: u64,
    n: usize,
    levels: Box<[LevelShape]>,
    loglog_ceiling: usize,
    primary_offset: usize,
    primary_range: PreparedProbeRange,
    fallback_offset: usize,
    fallback_bucket_width: usize,
    fallback_bucket_range: PreparedProbeRange,
    /// The levels that own a level-bin bit, copied inline so the hot paths
    /// index them without the pointer chase or a bounds check. Every other
    /// entry, the last one always among them, is [`LevelShape::ABSENT`], and
    /// so is every entry of a shape without [`Self::bucket_lanes`].
    head: [LevelShape; HEAD_LEVELS],
}

impl LevelShape {
    /// A level with no buckets, which rejects every probe word.
    const ABSENT: Self = Self {
        multiplier: 0,
        bucket_range: PreparedProbeRange::rejecting(),
        offset: 0,
    };
}

impl FunnelShape {
    /// Shape of ordinary level `level`, which owns a level-bin bit.
    #[inline]
    fn head_level(&self, level: u32) -> &LevelShape {
        &self.head[level as usize % HEAD_LEVELS]
    }

    fn empty() -> Self {
        Self {
            n: 0,
            max_insertions: 0,
            levels: Box::new([]),
            head: [LevelShape::ABSENT; HEAD_LEVELS],
            beta: 0,
            loglog_ceiling: 0,
            primary_offset: 0,
            primary_range: PreparedProbeRange::empty(),
            fallback_offset: 0,
            fallback_bucket_width: 0,
            fallback_bucket_range: PreparedProbeRange::empty(),
            bucket_lanes: 0,
            lookup_lanes: 0,
        }
    }

    #[inline]
    fn encode_logical_probe(&self, logical_probe: usize) -> u8 {
        debug_assert!(logical_probe < self.loglog_ceiling);
        #[allow(
            clippy::cast_possible_truncation,
            reason = "shape construction validates the counter lane"
        )]
        {
            logical_probe as u8
        }
    }

    fn from_slots(n: usize, reserve: ReserveFraction) -> Result<Self, TryReserveError> {
        if n == 0 {
            return Ok(Self::empty());
        }
        let config = PaperConfig::new(n, reserve.exponent())
            .map_err(|_| TryReserveError::CapacityOverflow)?;
        let plan = config
            .funnel_plan()
            .map_err(|_| TryReserveError::CapacityOverflow)?;
        let mut offset = 0_usize;
        let mut levels = Vec::new();
        levels
            .try_reserve_exact(plan.alpha())
            .map_err(|_| TryReserveError::AllocError)?;
        for (level_index, bucket_count) in plan.ordinary_bucket_counts().enumerate() {
            levels.push(LevelShape {
                multiplier: FunnelPrf::ordinary_multiplier(level_index as u64)
                    .ok_or(TryReserveError::CapacityOverflow)?,
                bucket_range: PreparedProbeRange::new(bucket_count)
                    .map_err(|_| TryReserveError::CapacityOverflow)?,
                offset,
            });
            offset = offset
                .checked_add(
                    bucket_count
                        .checked_mul(plan.beta())
                        .ok_or(TryReserveError::CapacityOverflow)?,
                )
                .ok_or(TryReserveError::CapacityOverflow)?;
        }
        let primary_offset = offset;
        let primary_len = plan.special_primary_len();
        let primary_range =
            PreparedProbeRange::new(primary_len).map_err(|_| TryReserveError::CapacityOverflow)?;
        let fallback_offset = primary_offset
            .checked_add(primary_len)
            .ok_or(TryReserveError::CapacityOverflow)?;
        let fallback_len = plan.special_fallback_len();
        if fallback_offset
            .checked_add(fallback_len)
            .ok_or(TryReserveError::CapacityOverflow)?
            != n
        {
            return Err(TryReserveError::CapacityOverflow);
        }
        let loglog_ceiling =
            u8::try_from(plan.loglog_ceiling()).map_err(|_| TryReserveError::CapacityOverflow)?;
        let bucket_lanes = bucket_lanes(plan.beta());
        let mut head = [LevelShape::ABSENT; HEAD_LEVELS];
        if bucket_lanes != 0 {
            for (slot, level) in head.iter_mut().zip(levels.iter().take(OVERFLOW_LEVEL)) {
                *slot = *level;
            }
        }
        Ok(Self {
            n,
            max_insertions: config.max_insertions(),
            levels: levels.into_boxed_slice(),
            head,
            beta: plan.beta(),
            loglog_ceiling: usize::from(loglog_ceiling),
            primary_offset,
            primary_range,
            fallback_offset,
            fallback_bucket_width: plan.fallback_bucket_width(),
            fallback_bucket_range: PreparedProbeRange::new(plan.fallback_bucket_count())
                .map_err(|_| TryReserveError::CapacityOverflow)?,
            bucket_lanes,
            lookup_lanes: if bucket_lanes != 0 && n <= SELECT_MAX_SLOTS {
                bucket_lanes | LOOKUP_SELECTS
            } else {
                bucket_lanes
            },
        })
    }

    fn for_insert_budget(
        requested: usize,
        reserve: ReserveFraction,
    ) -> Result<Self, TryReserveError> {
        if requested == 0 {
            return Ok(Self::empty());
        }
        let d = reserve.exponent();
        if !(3..usize::BITS).contains(&d) {
            return Err(TryReserveError::CapacityOverflow);
        }
        let mut n = capacity::exact_capacity_for(requested, reserve)
            .ok_or(TryReserveError::CapacityOverflow)?
            .max(2);

        let alpha = usize::try_from(u128::from(d) * 4 + 10)
            .map_err(|_| TryReserveError::CapacityOverflow)?;
        let beta =
            usize::try_from(u128::from(d) * 2).map_err(|_| TryReserveError::CapacityOverflow)?;
        n = n.max(
            alpha
                .checked_mul(beta)
                .and_then(|value| value.checked_add(2))
                .ok_or(TryReserveError::CapacityOverflow)?,
        );

        n = geometry::funnel_minimum_slots(d, n).ok_or(TryReserveError::CapacityOverflow)?;
        loop {
            if let Ok(shape) = Self::from_slots(n, reserve)
                && shape.max_insertions >= requested
            {
                return Ok(shape);
            }
            n = n.checked_add(1).ok_or(TryReserveError::CapacityOverflow)?;
        }
    }
}

/// Bit of [`FunnelShape::lookup_lanes`] that no lane owns.
const LOOKUP_SELECTS_BIT: u32 = u64::BITS - 1 - BITMASK_SLOT_BIT;
const LOOKUP_SELECTS: u64 = 1 << LOOKUP_SELECTS_BIT;
// The stride is one where a group mask holds one bit per slot.
#[allow(clippy::modulo_one)]
const _: () = assert!(
    LOOKUP_SELECTS_BIT % BITMASK_STRIDE != BITMASK_SLOT_BIT
        || LOOKUP_SELECTS_BIT as usize >= BITMASK_STRIDE as usize * GROUP_SIZE
);

/// See [`FunnelShape::bucket_lanes`].
fn bucket_lanes(beta: usize) -> u64 {
    if beta > GROUP_SIZE {
        return 0;
    }
    // One bit per lane, which every group mask sets for a matching lane. A
    // set of matches is then walked by clearing its lowest bit.
    (0..beta).fold(0, |lanes, lane| {
        lanes | 1 << (lane * BITMASK_STRIDE as usize + BITMASK_SLOT_BIT as usize)
    })
}

/// Lane of the lowest bit of `matches`.
///
/// # Safety
///
/// `matches` must be a non-empty subset of a [`bucket_lanes`] mask, which
/// sets one bit per lane, at `BITMASK_SLOT_BIT` of its stride.
#[inline]
// The stride is one where a group mask holds one bit per slot.
#[allow(clippy::modulo_one)]
unsafe fn lowest_lane(matches: u64) -> usize {
    debug_assert_ne!(matches, 0);
    let bit = matches.trailing_zeros();
    debug_assert_eq!(bit % BITMASK_STRIDE, BITMASK_SLOT_BIT);
    // SAFETY: the caller's contract. Stating it lets the division fold into
    // the slot's address scaling.
    unsafe { core::hint::assert_unchecked(bit % BITMASK_STRIDE == BITMASK_SLOT_BIT) };
    (bit / BITMASK_STRIDE) as usize
}

pub(crate) struct FlatStorage<T> {
    ctrl_ptr: *mut u8,
    data_ptr: *mut MaybeUninit<T>,
    capacity: usize,
}

// SAFETY: the raw pointers address slots owned solely by this descriptor's
// table, so sending or sharing it is sending or sharing the `T` values.
unsafe impl<T: Send> Send for FlatStorage<T> {}
// SAFETY: as for `Send`; `&FlatStorage` only exposes `&T` through the slots.
unsafe impl<T: Sync> Sync for FlatStorage<T> {}

// SAFETY: storage is only stamped at offsets carved from an arena laid out by
// `funnel_layout` with at least `capacity` ctrl bytes (plus group padding) and
// `capacity` slots, whose ctrl bytes `try_allocate_with_ctrl_zeroed` starts
// EMPTY, and is re-stamped before that arena is freed. The `GROUP_SIZE - 1`
// padding bytes are zeroed with the rest and never stamped, so they stay EMPTY.
unsafe impl<T> ArenaSlots<T> for FlatStorage<T> {
    const PADDED_TAIL: bool = true;

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
        self.capacity
    }
}

impl<T> arena::RegionSet for FlatStorage<T> {
    fn drop_all_values(&mut self) {
        arena::drop_values(core::slice::from_mut(self));
    }
}

/// Level-bin bit shared by every ordinary level from this index on and by both
/// special arrays. Shallower levels each own the bit at their index.
const OVERFLOW_LEVEL: usize = u16::BITS as usize - 1;
const OVERFLOW_LEVEL_BIT: u16 = 1 << OVERFLOW_LEVEL;

/// Level-bin bit of ordinary level `level`.
#[inline]
fn level_bit_of(level: usize) -> u16 {
    1 << level.min(OVERFLOW_LEVEL)
}

/// Level bin of a key. Bits 6 and 7 of the hash: disjoint from both membership
/// bit fields (bits 0..6 and 32..38), while the word index draws on the high
/// half.
#[inline]
const fn level_bin(key_hash: u64) -> usize {
    ((key_hash >> 6) & 3) as usize
}

/// One key's filter location: which word, which bits, and which level bin.
/// Computed once per operation and carried to the record step, so placement
/// never re-derives it.
#[derive(Clone, Copy)]
struct MembershipSlot {
    index: usize,
    bits: u64,
    bin: usize,
}

/// A loaded filter word paired with the key's bits, split from the test so the
/// load can be issued before the work that hides its latency. An absent tail
/// yields a gate that never passes, matching an empty table. It omits the
/// word index: a lookup never records, and carrying it costs the miss path on
/// every call.
#[derive(Clone, Copy)]
struct MembershipGate {
    word: u64,
    bits: u64,
    /// The key's level bin: a set bit marks a level some key sharing the bin
    /// was recorded at.
    levels: u16,
}

impl MembershipGate {
    /// `false` proves no insert ever recorded this key.
    #[inline]
    const fn passes(self) -> bool {
        self.word & self.bits == self.bits
    }
}

/// Where each region of one Funnel epoch's arena lives.
struct FunnelLayout {
    layout: Layout,
    data_offset: usize,
    control_bytes: usize,
    membership: MembershipRegion,
}

/// A table's filter tail: where it sits in the arena, and its base address.
#[derive(Clone, Copy)]
struct FilterTail {
    region: MembershipRegion,
    /// The gate is a lookup's first dependent load, so its base is cached
    /// rather than rebuilt from the arena base and region offset. An empty
    /// region points at [`NO_FILTER_WORD`], which rejects every key, so the
    /// gate needs no emptiness test; nothing writes through that pointer.
    base: *mut MetadataWord,
}

/// The word an empty table's gate reads: nothing recorded.
static NO_FILTER_WORD: MetadataWord = MetadataWord {
    membership: 0,
    level_bins: [0; 4],
};

impl FilterTail {
    /// # Safety
    ///
    /// `region` must have been laid out for the arena at `arena_base`.
    unsafe fn new(region: MembershipRegion, arena_base: *mut u8) -> Self {
        let base = if region.words == 0 {
            core::ptr::from_ref(&NO_FILTER_WORD).cast_mut()
        } else {
            // SAFETY: the caller's contract is `ptr`'s.
            unsafe { region.ptr::<MetadataWord>(arena_base) }
        };
        Self { region, base }
    }
}

type FunnelStorageBuild<K, V> = (Arena, FlatStorage<SlotEntry<K, V>>, FilterTail);

fn try_allocate_storage<K, V, A: Allocator>(
    n: usize,
    alloc: &A,
) -> Result<FunnelStorageBuild<K, V>, TryReserveError> {
    let shape = funnel_layout::<K, V>(n)?;
    let arena = Arena::try_allocate_with_ctrl_zeroed(shape.layout, shape.control_bytes, alloc)?;
    // The arena zeroes control bytes only; an empty filter must read as
    // "nothing recorded".
    // SAFETY: `shape.membership` was laid out for this arena by `funnel_layout`.
    unsafe { shape.membership.clear::<MetadataWord>(arena.as_ptr()) };
    let storage = FlatStorage {
        ctrl_ptr: arena.as_ptr(),
        // SAFETY: `data_offset` is the data section's offset within this
        // arena's layout, and is zero for the dangling empty arena.
        data_ptr: unsafe {
            arena
                .as_ptr()
                .add(shape.data_offset)
                .cast::<MaybeUninit<SlotEntry<K, V>>>()
        },
        capacity: n,
    };
    // SAFETY: as above.
    let membership = unsafe { FilterTail::new(shape.membership, arena.as_ptr()) };
    Ok((arena, storage, membership))
}

fn funnel_layout<K, V>(n: usize) -> Result<FunnelLayout, TryReserveError> {
    let control_bytes = if n == 0 {
        0
    } else {
        n.checked_add(GROUP_SIZE - 1)
            .ok_or(TryReserveError::CapacityOverflow)?
    };
    let (base_layout, data_offset) = arena::layout_for_extents::<K, V>(control_bytes, n)?;
    let (layout, membership) = MembershipRegion::extend::<MetadataWord>(base_layout, n)?;
    Ok(FunnelLayout {
        layout,
        data_offset,
        control_bytes,
        membership,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SearchResult {
    Hit(usize),
    Vacant(usize),
    Full,
    RangeFailure,
}

/// A free slot and the level-bin bit an entry placed there records. The
/// placement walk knows the level it stopped at; carrying the bit spares the
/// insert a slot-to-level search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Vacancy {
    slot: usize,
    level_bit: u16,
}

/// A live entry and the slot that holds it. Lookups return both, so a caller
/// that wants the entry need not re-derive its address from the slot.
struct Found<'a, K, V> {
    slot: usize,
    entry: &'a SlotEntry<K, V>,
}

impl<K, V> Clone for Found<'_, K, V> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K, V> Copy for Found<'_, K, V> {}

/// The part of a [`Found`] a lookup's caller wants. The out-of-line lookup is
/// instantiated per projection, so each returns one word and the hand-off to
/// the ordered walk stays a tail call.
trait FoundPart<'a, K, V> {
    type Part;

    fn of(found: Found<'a, K, V>) -> Self::Part;
}

struct FoundSlot;

impl<'a, K, V> FoundPart<'a, K, V> for FoundSlot {
    type Part = usize;

    #[inline]
    fn of(found: Found<'a, K, V>) -> usize {
        found.slot
    }
}

struct FoundEntry;

impl<'a, K: 'a, V: 'a> FoundPart<'a, K, V> for FoundEntry {
    type Part = &'a SlotEntry<K, V>;

    #[inline]
    fn of(found: Found<'a, K, V>) -> &'a SlotEntry<K, V> {
        found.entry
    }
}

/// A known-absent search, retained only while the entry borrows its map.
#[derive(Debug)]
pub struct FunnelVacant {
    hash: u64,
    // Allocated slot indices are below isize::MAX. Reserve the two largest
    // usize values for unsearched and exhausted walks, keeping the token to
    // a hash and one slot word instead of a prepared probe and enum payload.
    exact: usize,
}

impl FunnelVacant {
    const UNSEARCHED: usize = usize::MAX;
    const EXHAUSTED: usize = usize::MAX - 1;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BucketScanResult<T> {
    Hit(T),
    Empty(usize),
    Full,
}

/// Scans one masked SIMD group containing `logical_lanes` controls.
///
/// # Safety
///
/// `ctrl_ptr.add(start)` must be readable for `GROUP_SIZE` bytes,
/// `logical_lanes <= GROUP_SIZE`, and every slot passed to `inspect_match`
/// must be valid for the corresponding data arena.
#[inline]
unsafe fn scan_funnel_group<T>(
    ctrl_ptr: *const u8,
    start: usize,
    logical_lanes: usize,
    fingerprint: u8,
    first_tombstone: &mut Option<usize>,
    inspect_match: &mut impl FnMut(usize) -> Option<T>,
) -> BucketScanResult<T> {
    // SAFETY: caller guarantees `GROUP_SIZE` readable bytes at `start`.
    let group = unsafe { ctrl_ptr.add(start) };
    // SAFETY: as above, `group` is readable for one full group.
    let mut events = unsafe { simd::free_mask_group(group) };
    // SAFETY: as above.
    events.0 |= unsafe { simd::eq_mask_group(group, fingerprint) }.0;
    for lane in events {
        if lane >= logical_lanes {
            break;
        }
        let slot = start + lane;
        // SAFETY: `lane < logical_lanes <= GROUP_SIZE`, inside the readable group.
        let control = unsafe { *ctrl_ptr.add(slot) };
        if control == CTRL_TOMBSTONE {
            first_tombstone.get_or_insert(slot);
        } else if control == CTRL_EMPTY {
            return BucketScanResult::Empty(first_tombstone.unwrap_or(slot));
        } else if let Some(hit) = inspect_match(slot) {
            return BucketScanResult::Hit(hit);
        }
    }
    BucketScanResult::Full
}

/// Scans exactly `length` logical controls in order using masked SIMD groups.
///
/// # Safety
///
/// `ctrl_ptr.add(start)` must be readable through `length + GROUP_SIZE - 1`
/// bytes, and every slot passed to `inspect_match` must be a valid logical
/// slot for the corresponding data arena.
unsafe fn scan_funnel_bucket<T>(
    ctrl_ptr: *const u8,
    start: usize,
    length: usize,
    fingerprint: u8,
    first_tombstone: &mut Option<usize>,
    mut inspect_match: impl FnMut(usize) -> Option<T>,
) -> BucketScanResult<T> {
    if length <= GROUP_SIZE {
        // SAFETY: `length <= GROUP_SIZE`, so the caller's
        // `length + GROUP_SIZE - 1` readable bytes cover one full group.
        return unsafe {
            scan_funnel_group(
                ctrl_ptr,
                start,
                length,
                fingerprint,
                first_tombstone,
                &mut inspect_match,
            )
        };
    }
    // SAFETY: caller upholds this function's bounds, and `length > GROUP_SIZE`.
    unsafe {
        scan_funnel_bucket_multi_group(
            ctrl_ptr,
            start,
            length,
            fingerprint,
            first_tombstone,
            inspect_match,
        )
    }
}

/// Keeps the configurable multi-group case out of the default one-group path.
///
/// # Safety
///
/// The bounds requirements are identical to [`scan_funnel_bucket`], and
/// `length` must be greater than `GROUP_SIZE`.
#[inline(never)]
unsafe fn scan_funnel_bucket_multi_group<T>(
    ctrl_ptr: *const u8,
    start: usize,
    length: usize,
    fingerprint: u8,
    first_tombstone: &mut Option<usize>,
    mut inspect_match: impl FnMut(usize) -> Option<T>,
) -> BucketScanResult<T> {
    debug_assert!(length > GROUP_SIZE);
    let end = start + length;
    let mut position = start;
    while position < end {
        let logical_lanes = GROUP_SIZE.min(end - position);
        // SAFETY: `position < start + length`, so a full group from `position`
        // stays within the caller's `length + GROUP_SIZE - 1` readable bytes.
        match unsafe {
            scan_funnel_group(
                ctrl_ptr,
                position,
                logical_lanes,
                fingerprint,
                first_tombstone,
                &mut inspect_match,
            )
        } {
            BucketScanResult::Full => {}
            result => return result,
        }
        position += logical_lanes;
    }
    BucketScanResult::Full
}

/// Tombstone-blind scan of one group: stops at the first EMPTY lane and never
/// inspects tombstones. A lookup needs nothing more; without tombstones in the
/// group, the reported EMPTY is also the first free lane an insert wants.
///
/// # Safety
///
/// The bounds requirements are identical to [`scan_funnel_group`].
#[inline]
unsafe fn scan_clean_funnel_group<T>(
    ctrl_ptr: *const u8,
    start: usize,
    logical_lanes: usize,
    fingerprint: u8,
    inspect_match: &mut impl FnMut(usize) -> Option<T>,
) -> BucketScanResult<T> {
    // SAFETY: caller guarantees `GROUP_SIZE` readable bytes at `start`.
    let group = unsafe { ctrl_ptr.add(start) };
    // SAFETY: as above, `group` is readable for one full group.
    let matches = unsafe { simd::eq_mask_group(group, fingerprint) };
    // Iterator search on purpose: `BitMask::first_below` is the same test, but
    // here LLVM lowers it to a select chain instead of one test-and-branch.
    // SAFETY: as above.
    let first_empty = unsafe { simd::eq_mask_group(group, CTRL_EMPTY) }
        .into_iter()
        .find(|&lane| lane < logical_lanes);
    let semantic_lanes = first_empty.unwrap_or(logical_lanes);

    for lane in matches {
        if lane >= semantic_lanes {
            break;
        }
        let slot = start + lane;
        if let Some(hit) = inspect_match(slot) {
            return BucketScanResult::Hit(hit);
        }
    }
    if let Some(empty_lane) = first_empty {
        return BucketScanResult::Empty(start + empty_lane);
    }
    BucketScanResult::Full
}

/// Tombstone-blind scan over `length` logical controls; see
/// [`scan_clean_funnel_group`].
///
/// # Safety
///
/// The bounds requirements are identical to [`scan_funnel_bucket`].
unsafe fn scan_clean_funnel_bucket<T>(
    ctrl_ptr: *const u8,
    start: usize,
    length: usize,
    fingerprint: u8,
    mut inspect_match: impl FnMut(usize) -> Option<T>,
) -> BucketScanResult<T> {
    if length <= GROUP_SIZE {
        // SAFETY: `length <= GROUP_SIZE`, so the caller's readable span covers
        // one full group.
        return unsafe {
            scan_clean_funnel_group(ctrl_ptr, start, length, fingerprint, &mut inspect_match)
        };
    }
    let end = start + length;
    let mut position = start;
    while position < end {
        let logical_lanes = GROUP_SIZE.min(end - position);
        // SAFETY: `position < start + length`, so a full group from `position`
        // stays within the caller's readable span.
        match unsafe {
            scan_clean_funnel_group(
                ctrl_ptr,
                position,
                logical_lanes,
                fingerprint,
                &mut inspect_match,
            )
        } {
            BucketScanResult::Full => {}
            result => return result,
        }
        position += logical_lanes;
    }
    BucketScanResult::Full
}

/// First free (EMPTY or TOMBSTONE) slot among `length` logical controls: the
/// slot the general scan reports as `Vacant` for a key absent from the bucket,
/// without the fingerprint mask or key compares.
///
/// # Safety
///
/// The bounds requirements are identical to [`scan_funnel_bucket`].
#[inline]
unsafe fn first_free_in_bucket(ctrl_ptr: *const u8, start: usize, length: usize) -> Option<usize> {
    let end = start + length;
    let mut position = start;
    while position < end {
        let logical_lanes = GROUP_SIZE.min(end - position);
        // SAFETY: `position < start + length`, so a full group from `position`
        // stays within the caller's `length + GROUP_SIZE - 1` readable bytes.
        let free = unsafe { simd::free_mask_group(ctrl_ptr.add(position)) };
        if let Some(lane) = free.first_below(logical_lanes) {
            return Some(position + lane);
        }
        position += logical_lanes;
    }
    None
}

/// Paper-exact Funnel hashing within each table epoch. Deletion, growth, and
/// exceptional collision recovery are built-in dynamic-map behavior beyond
/// the paper's fixed-size insertion model.
// Declaration order is layout order; see [`FunnelShape`], which comes last
// for its head array.
#[repr(C)]
pub struct FunnelTable<K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    storage: FlatStorage<SlotEntry<K, V>>,
    /// Seeds every probe sequence. Starts at [`FUNNEL_PROBE_SEED`]; a
    /// placement-recovery rebuild advances it, because survivors of slot-order
    /// deletes are skewed toward the buckets the old seed left full.
    prf: FunnelPrf,
    /// Cached location of the membership filter tail. Lookups load one word
    /// from it before probing; see [`crate::membership`].
    membership: FilterTail,
    hash_builder: S,
    reserve_fraction: ReserveFraction,
    alloc: A,
    arena: Arena,
    epoch: EpochState,
    exceptional_placement: bool,
    /// Deletes since the filter last matched the live set; see
    /// [`membership::refresh_deletes`].
    stale_membership: usize,
    tombstones: usize,
    len: usize,
    shape: FunnelShape,
}

// SAFETY: the table uniquely owns its arena and every `K`/`V` in it; no
// shared or thread-local state escapes through the raw pointers.
unsafe impl<K: Send, V: Send, S: Send, A: Allocator + Clone + Send> Send
    for FunnelTable<K, V, S, A>
{
}
// SAFETY: `&FunnelTable` only hands out shared references to its contents
// and has no interior mutability.
unsafe impl<K: Sync, V: Sync, S: Sync, A: Allocator + Clone + Sync> Sync
    for FunnelTable<K, V, S, A>
{
}

impl<K, V, S, A: Allocator + Clone> fmt::Debug for FunnelTable<K, V, S, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FunnelTable").finish_non_exhaustive()
    }
}

impl<K, V, S, A: Allocator + Clone> Drop for FunnelTable<K, V, S, A> {
    fn drop(&mut self) {
        let storage = &mut self.storage;
        self.arena.drop_table(&self.alloc, || {
            arena::drop_values(core::slice::from_mut(storage));
        });
    }
}

macros::declare_backend_aliases! {
    table = FunnelTable,
    map_no_lifetime {
        /// Open-addressed hash map using funnel hashing.
        ///
        /// # Examples
        ///
        /// ```
        /// use opthash::FunnelHashMap;
        ///
        /// let mut lengths: FunnelHashMap<&str, usize> = ["alpha", "beta", "gamma"]
        ///     .into_iter()
        ///     .map(|word| (word, word.len()))
        ///     .collect();
        /// lengths.retain(|_, len| *len > 4);
        ///
        /// assert_eq!(lengths.len(), 2);
        /// assert!(!lengths.contains_key("beta"));
        /// ```
        FunnelHashMap => HashMap,
        /// Consuming iterator over owned `(K, V)`.
        FunnelIntoIter => IntoIter,
        /// Owned `K` iterator.
        FunnelIntoKeys => IntoKeys,
        /// Owned `V` iterator.
        FunnelIntoValues => IntoValues,
    },
    map_ref {
        /// A view into a single entry, occupied or vacant.
        FunnelEntry => Entry,
        /// View of an occupied entry.
        FunnelOccupiedEntry => OccupiedEntry,
        /// View of a vacant entry.
        FunnelVacantEntry => VacantEntry,
        /// Error returned by `try_insert` on key collision.
        FunnelOccupiedError => OccupiedError,
        /// Borrowing iterator over `(&K, &V)`.
        FunnelIter => Iter,
        /// Borrowing iterator over `(&K, &mut V)`.
        FunnelIterMut => IterMut,
        /// `&K` iterator.
        FunnelKeys => Keys,
        /// `&V` iterator.
        FunnelValues => Values,
        /// `&mut V` iterator.
        FunnelValuesMut => ValuesMut,
        /// Draining iterator that empties the map.
        FunnelDrain => Drain,
    },
    map_extract_if {
        /// Iterator yielding entries removed by `extract_if`.
        FunnelExtractIf
    },
    set_no_lifetime {
        /// Hash set using funnel hashing.
        ///
        /// # Examples
        ///
        /// ```
        /// use opthash::FunnelHashSet;
        ///
        /// let mut seen = FunnelHashSet::new();
        /// assert!(seen.insert("Paris"));
        /// assert!(!seen.insert("Paris"));
        /// assert!(seen.remove("Paris"));
        /// assert!(seen.is_empty());
        /// ```
        FunnelHashSet => HashSet,
        /// Consuming iterator over set values.
        FunnelSetIntoIter => IntoIter,
    },
    set_ref {
        /// Borrowing iterator over set values.
        FunnelSetIter => Iter,
        /// Draining iterator that empties the set.
        FunnelSetDrain => Drain,
        /// Iterator over values present only in the first set.
        FunnelDifference => Difference,
        /// Iterator over values present in both sets.
        FunnelIntersection => Intersection,
        /// Iterator over values present in exactly one set.
        FunnelSymmetricDifference => SymmetricDifference,
        /// Iterator over values present in either set.
        FunnelUnion => Union,
        /// A view into a single set entry.
        FunnelSetEntry => Entry,
        /// View of an occupied set entry.
        FunnelSetOccupiedEntry => OccupiedEntry,
        /// View of a vacant set entry.
        FunnelSetVacantEntry => VacantEntry,
    },
    set_extract_if {
        /// Iterator yielding values removed by set `extract_if`.
        FunnelSetExtractIf
    },
}

impl<K, V, S, A> FunnelTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    fn try_from_shape(
        shape: FunnelShape,
        reserve_fraction: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryReserveError> {
        let (arena, storage, membership) = try_allocate_storage(shape.n, &alloc)?;
        Ok(Self {
            shape,
            storage,
            len: 0,
            tombstones: 0,
            reserve_fraction,
            hash_builder,
            alloc,
            arena,
            epoch: EpochState::initial(),
            exceptional_placement: false,
            prf: FunnelPrf::new(FUNNEL_PROBE_SEED),
            membership,
            stale_membership: 0,
        })
    }

    fn try_with_insert_budget(
        capacity: usize,
        reserve_fraction: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryBuildError> {
        if reserve_fraction.exponent() < 3 {
            return Err(TryBuildError::FunnelExponentBelowMinimum {
                reserve_exponent: reserve_fraction.exponent(),
                minimum: 3,
            });
        }
        let shape = FunnelShape::for_insert_budget(capacity, reserve_fraction)?;
        Self::try_from_shape(shape, reserve_fraction, hash_builder, alloc).map_err(Into::into)
    }

    /// Bucket of the key in ordinary level `index`, whose shape is `level`.
    #[inline]
    fn sample_ordinary(
        probe: PreparedFastFunnelProbe,
        level: &LevelShape,
        index: usize,
    ) -> Option<usize> {
        probe::ordinary_funnel_first_index(probe, level.multiplier, level.bucket_range)
            .or_else(|| probe::ordinary_funnel_retry_index(probe, index, level.bucket_range))
    }

    #[inline]
    fn sample(
        prepared: &PreparedFastFunnelDomainProbe,
        logical_probe: u8,
        range: PreparedProbeRange,
    ) -> Option<usize> {
        probe::unbiased_prepared_funnel_probe_index_in_range(
            prepared,
            logical_probe,
            range,
            probe::RANGE_WORD_CAP,
        )
        .ok()
        .map(|probe| probe.index)
    }

    /// # Safety
    ///
    /// `slot < self.shape.n`.
    #[inline]
    unsafe fn inspect_slot<Q>(&self, slot: usize, key_fingerprint: u8, key: &Q) -> Option<bool>
    where
        Q: Equivalent<K> + ?Sized,
    {
        // SAFETY: caller keeps `slot` in bounds.
        let ctrl = unsafe { self.storage.control_at(slot) };
        if ctrl == CTRL_EMPTY {
            return Some(false);
        }
        if ctrl == key_fingerprint {
            // SAFETY: a fingerprint control is occupied, so the slot is initialized.
            let entry = unsafe { self.storage.get_ref(slot) };
            if key.equivalent(&entry.key) {
                return Some(true);
            }
        }
        None
    }

    #[cfg(test)]
    fn search_exact_for_insert<Q>(
        &self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
    ) -> SearchResult
    where
        Q: Equivalent<K> + ?Sized,
    {
        let probe = self.prf.prepare(key_hash);
        self.search_exact_prepared(key, probe, key_fingerprint)
    }

    /// Entry-side search over a probe the caller already prepared: the full
    /// walk, so a miss carries the vacancy an insert reuses.
    fn search_exact_prepared<Q>(
        &self,
        key: &Q,
        probe: PreparedFastFunnelProbe,
        key_fingerprint: u8,
    ) -> SearchResult
    where
        Q: Equivalent<K> + ?Sized,
    {
        if self.shape.n == 0 {
            return SearchResult::Full;
        }
        let mut first_tombstone = None;

        for (index, level) in self.shape.levels.iter().enumerate() {
            let Some(bucket) = Self::sample_ordinary(probe, level, index) else {
                return first_tombstone.map_or(SearchResult::RangeFailure, SearchResult::Vacant);
            };
            let start = level.offset + bucket * self.shape.beta;
            // SAFETY: an ordinary bucket ends at or before `n`, and the
            // control array pads `GROUP_SIZE - 1` bytes past `n`; matched
            // lanes carry the fingerprint, so they are occupied.
            let scan = unsafe {
                scan_funnel_bucket(
                    self.storage.ctrl_ptr(),
                    start,
                    self.shape.beta,
                    key_fingerprint,
                    &mut first_tombstone,
                    |slot| {
                        let entry = self.storage.get_ref(slot);
                        key.equivalent(&entry.key).then_some(slot)
                    },
                )
            };
            match scan {
                BucketScanResult::Hit(slot) => return SearchResult::Hit(slot),
                BucketScanResult::Empty(slot) => return SearchResult::Vacant(slot),
                BucketScanResult::Full => {}
            }
        }

        // The special-array tail stays inline. Outlining it as a `#[cold]` call
        // costs the ordinary walk more in call setup than it recovers in
        // register pressure, on hits and misses alike.
        let primary_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_PRIMARY_BASE);
        for logical_probe in 0..self.shape.loglog_ceiling {
            let Some(local) = Self::sample(
                &primary_probe,
                self.shape.encode_logical_probe(logical_probe),
                self.shape.primary_range,
            ) else {
                return first_tombstone.map_or(SearchResult::RangeFailure, SearchResult::Vacant);
            };
            let slot = self.shape.primary_offset + local;
            // SAFETY: a primary probe stays inside the primary range.
            if unsafe { self.storage.control_at(slot) } == CTRL_TOMBSTONE {
                first_tombstone.get_or_insert(slot);
                continue;
            }
            // SAFETY: a primary probe stays inside the primary range.
            match unsafe { self.inspect_slot(slot, key_fingerprint, key) } {
                Some(true) => return SearchResult::Hit(slot),
                Some(false) => return SearchResult::Vacant(first_tombstone.unwrap_or(slot)),
                None => {}
            }
        }

        let first_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_FALLBACK_A_BASE);
        let Some(first_bucket) = Self::sample(&first_probe, 0, self.shape.fallback_bucket_range)
        else {
            return first_tombstone.map_or(SearchResult::RangeFailure, SearchResult::Vacant);
        };
        let second_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_FALLBACK_B_BASE);
        let Some(second_bucket) = Self::sample(&second_probe, 0, self.shape.fallback_bucket_range)
        else {
            return first_tombstone.map_or(SearchResult::RangeFailure, SearchResult::Vacant);
        };
        for slot_in_bucket in 0..self.shape.fallback_bucket_width {
            for bucket in [first_bucket, second_bucket] {
                let slot = self.shape.fallback_offset
                    + bucket * self.shape.fallback_bucket_width
                    + slot_in_bucket;
                // SAFETY: both buckets lie inside the fallback range.
                if unsafe { self.storage.control_at(slot) } == CTRL_TOMBSTONE {
                    first_tombstone.get_or_insert(slot);
                    continue;
                }
                // SAFETY: both buckets lie inside the fallback range.
                match unsafe { self.inspect_slot(slot, key_fingerprint, key) } {
                    Some(true) => return SearchResult::Hit(slot),
                    Some(false) => {
                        return SearchResult::Vacant(first_tombstone.unwrap_or(slot));
                    }
                    None => {}
                }
            }
        }
        first_tombstone.map_or(SearchResult::Full, SearchResult::Vacant)
    }

    /// Read-only walk for `get`, `contains` and `remove`: the buckets of
    /// `search_exact_prepared` in the same order, restricted to the levels set in
    /// the key's bin `levels`, shallowest first. It stops only at a real EMPTY
    /// and skips tombstones without recording them, since a lookup never needs
    /// the vacancy an insert would take.
    ///
    /// An `EMPTY` lane in a visited bucket proves the key is not deeper: a
    /// slot returns to `EMPTY` only when the epoch is rebuilt, so that lane was
    /// free when the key was placed, and placement takes the first free slot
    /// of the walk. The level holding a live key always has its bit set, as
    /// bits only accumulate and a refresh re-records every live entry. Entries
    /// placed outside their funnel are the caller's full scan's concern.
    ///
    /// [`Self::find_unmatched`] hands every lookup it cannot settle to
    /// this walk, which therefore decides them all.
    fn lookup_recorded_levels<Q>(
        &self,
        key: &Q,
        probe: PreparedFastFunnelProbe,
        key_fingerprint: u8,
        levels: u16,
    ) -> Option<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let mut ordinary = levels & !OVERFLOW_LEVEL_BIT;
        while ordinary != 0 {
            let index = ordinary.trailing_zeros() as usize;
            ordinary &= ordinary - 1;
            // A range failure here ended the key's placement walk too.
            match self.lookup_level(key, probe, index, key_fingerprint)? {
                BucketScanResult::Hit(slot) => return Some(slot),
                BucketScanResult::Empty(_) => return None,
                BucketScanResult::Full => {}
            }
        }
        if levels & OVERFLOW_LEVEL_BIT == 0 {
            return None;
        }
        self.lookup_overflow_levels(key, probe, key_fingerprint)
    }

    /// Lookup over the ordinary levels the key's bin recorded, comparing the
    /// key against each bucket's fingerprint matches. `None` is not yet an
    /// answer: [`Self::unmatched_is_absent`] settles it or hands the lookup to
    /// the ordered walk.
    ///
    /// A level without the fingerprint cannot hold the key, so the walk moves
    /// on without the ordered walk's `EMPTY` test, which only shortens misses
    /// the filter let through.
    ///
    /// Each level is scanned at the bucket its first probe word selects,
    /// before that word is known to be accepted. A key found there is the
    /// answer either way, so only a lookup that finds nothing tests the
    /// words.
    ///
    /// Calls nothing but the key comparison, and keeps nothing for the lookup
    /// that finds nothing, so a caller that hands that lookup off by tail
    /// call keeps no frame.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn first_match<Q>(
        &self,
        key: &Q,
        probe: PreparedFastFunnelProbe,
        levels: u16,
    ) -> Option<Found<'_, K, V>>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let lookup_lanes = self.shape.lookup_lanes;
        let beta = self.shape.beta;
        let key_fingerprint = probe.fingerprint();
        // Fingerprint matches of the key's bucket in one level, with the
        // bucket's first slot.
        let scan = |level: u32, lanes: u64| -> (usize, u64) {
            debug_assert_ne!(lanes, 0);
            let level = self.shape.head_level(level);
            let (bucket, _) =
                probe::ordinary_funnel_first_draw(probe, level.multiplier, level.bucket_range);
            let start = level.offset + bucket * beta;
            // SAFETY: a first draw is below the level's bucket count whether
            // or not its word is accepted, an ordinary bucket ends at or
            // before `n`, and the control array pads `GROUP_SIZE - 1` bytes
            // past `n`. A level past the shape's last has no buckets and
            // draws slot zero, which a shape with lanes has.
            let matches =
                unsafe { simd::eq_mask_group(self.storage.ctrl_ptr().add(start), key_fingerprint) };
            (start, matches.0 & lanes)
        };
        // The entry at the lowest match of a bucket starting at `start`, if
        // it holds the key.
        let holding_key = |start: usize, matches: u64| -> Option<Found<'_, K, V>> {
            // SAFETY: every caller passes a non-empty set that `scan` masked
            // with the shape's lanes, less the bits cleared since.
            let slot = start + unsafe { lowest_lane(matches) };
            // SAFETY: a matched lane lies inside its bucket and carries the
            // fingerprint, so the slot is in bounds and occupied.
            let found = unsafe { self.found_at(slot) };
            key.equivalent(&found.entry.key).then_some(found)
        };
        // Widened so clearing the lowest set bit also tests for an empty set.
        let recorded = u32::from(levels & !OVERFLOW_LEVEL_BIT);
        // Compares every match of every level in a non-empty set.
        let walk = |mut pending: u32, lanes: u64| -> Option<Found<'_, K, V>> {
            loop {
                let (start, matches) = scan(pending.trailing_zeros(), lanes);
                let mut matches = matches;
                while matches != 0 {
                    if let Some(found) = holding_key(start, matches) {
                        return Some(found);
                    }
                    matches &= matches - 1;
                }
                pending &= pending - 1;
                if pending == 0 {
                    return None;
                }
            }
        };
        if recorded == 0 {
            return None;
        }
        if lookup_lanes & LOOKUP_SELECTS == 0 {
            // Without lanes no scan can match, and the head is absent.
            if lookup_lanes == 0 {
                return None;
            }
            return walk(recorded, lookup_lanes);
        }
        let lanes = lookup_lanes & !LOOKUP_SELECTS;
        // The first two recorded levels are scanned together and the
        // holder is selected, not branched on: which of them holds the
        // key is unpredictable.
        let mut pending = recorded;
        let first = pending.trailing_zeros();
        pending &= pending - 1;
        let second = if pending == 0 {
            first
        } else {
            pending.trailing_zeros()
        };
        pending &= pending.wrapping_sub(1);
        let (first_start, first_matches) = scan(first, lanes);
        let (second_start, second_matches) = scan(second, lanes);
        let in_first = first_matches != 0;
        let start = if in_first { first_start } else { second_start };
        let matches = if in_first {
            first_matches
        } else {
            second_matches
        };
        if matches != 0 {
            if let Some(found) = holding_key(start, matches) {
                return Some(found);
            }
            // Another key shares the fingerprint. Start over,
            // comparing every match of every recorded level.
            pending = recorded;
        }
        if pending == 0 {
            None
        } else {
            walk(pending, lanes)
        }
    }

    /// Whether a lookup [`Self::first_match`] found nothing for is absent.
    /// Otherwise the ordered walk decides: a probe word not accepted for
    /// certain, which is every word of a shape without lanes, or a key that
    /// may sit in the overflow levels or outside its funnel.
    #[inline]
    fn unmatched_is_absent(&self, probe: PreparedFastFunnelProbe, levels: u16) -> bool {
        if levels & OVERFLOW_LEVEL_BIT != 0 || self.exceptional_placement {
            return false;
        }
        let mut unchecked = u32::from(levels & !OVERFLOW_LEVEL_BIT);
        while unchecked != 0 {
            let level = self.shape.head_level(unchecked.trailing_zeros());
            unchecked &= unchecked - 1;
            let certain = probe::ordinary_funnel_first_certain_index(
                probe,
                level.multiplier,
                level.bucket_range,
            );
            if certain.is_none() {
                return false;
            }
        }
        true
    }

    /// Tombstone-blind scan of the key's bucket in ordinary level `index`;
    /// `None` is a range failure.
    ///
    /// Forced inline: with two callers LLVM outlines it, and the call per
    /// visited level costs more than the scan.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn lookup_level<Q>(
        &self,
        key: &Q,
        probe: PreparedFastFunnelProbe,
        index: usize,
        key_fingerprint: u8,
    ) -> Option<BucketScanResult<usize>>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let level = &self.shape.levels[index];
        let bucket = Self::sample_ordinary(probe, level, index)?;
        let start = level.offset + bucket * self.shape.beta;
        // SAFETY: an ordinary bucket ends at or before `n`, and the control
        // array pads `GROUP_SIZE - 1` bytes past `n`; matched lanes carry the
        // fingerprint, so they are occupied.
        Some(unsafe {
            scan_clean_funnel_bucket(
                self.storage.ctrl_ptr(),
                start,
                self.shape.beta,
                key_fingerprint,
                |slot| {
                    let entry = self.storage.get_ref(slot);
                    key.equivalent(&entry.key).then_some(slot)
                },
            )
        })
    }

    /// Overflow leg of [`Self::lookup_recorded_levels`]: every ordinary level
    /// from `OVERFLOW_LEVEL` on, then the special arrays, as the exact walk
    /// visits them.
    ///
    /// Out of line: most keys never record the overflow bit, and inlining
    /// this leg would give the hot walk a second copy of the level scan.
    #[inline(never)]
    fn lookup_overflow_levels<Q>(
        &self,
        key: &Q,
        probe: PreparedFastFunnelProbe,
        key_fingerprint: u8,
    ) -> Option<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        if self.shape.n == 0 {
            return None;
        }
        for index in OVERFLOW_LEVEL..self.shape.levels.len() {
            match self.lookup_level(key, probe, index, key_fingerprint)? {
                BucketScanResult::Hit(slot) => return Some(slot),
                BucketScanResult::Empty(_) => return None,
                BucketScanResult::Full => {}
            }
        }

        let primary_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_PRIMARY_BASE);
        for logical_probe in 0..self.shape.loglog_ceiling {
            let local = Self::sample(
                &primary_probe,
                self.shape.encode_logical_probe(logical_probe),
                self.shape.primary_range,
            )?;
            let slot = self.shape.primary_offset + local;
            // SAFETY: a primary probe stays inside the primary range.
            match unsafe { self.inspect_slot(slot, key_fingerprint, key) } {
                Some(true) => return Some(slot),
                Some(false) => return None,
                None => {}
            }
        }

        let first_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_FALLBACK_A_BASE);
        let first_bucket = Self::sample(&first_probe, 0, self.shape.fallback_bucket_range)?;
        let second_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_FALLBACK_B_BASE);
        let second_bucket = Self::sample(&second_probe, 0, self.shape.fallback_bucket_range)?;
        for slot_in_bucket in 0..self.shape.fallback_bucket_width {
            for bucket in [first_bucket, second_bucket] {
                let slot = self.shape.fallback_offset
                    + bucket * self.shape.fallback_bucket_width
                    + slot_in_bucket;
                // SAFETY: both buckets lie inside the fallback range.
                match unsafe { self.inspect_slot(slot, key_fingerprint, key) } {
                    Some(true) => return Some(slot),
                    Some(false) => return None,
                    None => {}
                }
            }
        }
        None
    }

    /// A vacancy at `slot`, found by a walk that did not track its level.
    #[inline]
    fn vacancy_at(&self, slot: usize) -> Vacancy {
        Vacancy {
            slot,
            level_bit: self.level_bit(slot),
        }
    }

    /// The vacancy an exact search reports, if any, with its level-bin bit.
    #[cfg(test)]
    fn vacancy_of(&self, exact: SearchResult) -> Option<Vacancy> {
        match exact {
            SearchResult::Vacant(slot) => Some(self.vacancy_at(slot)),
            SearchResult::Hit(_) => unreachable!("known-absent Funnel search found a key"),
            SearchResult::Full | SearchResult::RangeFailure => None,
        }
    }

    /// Placement walk for a key already known to be absent: the buckets of
    /// `search_exact_prepared` in the same order, returning the first free slot,
    /// which is the `Vacant` slot the exact search reports for an absent key.
    /// No fingerprint mask, no key compares. `None` is an exhausted walk.
    ///
    /// Forced inline: the loop keeps many registers live, so a call costs more
    /// in prologue and epilogue than the walk. The special-array tail stays out
    /// of line because almost every insert finds its slot in the funnel. It
    /// duplicates the exact search's special leg on purpose: a shared
    /// closure-driven walker slows the exact search's misses.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn search_vacancy(&self, probe: PreparedFastFunnelProbe) -> Option<Vacancy> {
        #[cfg(test)]
        tests::VACANCY_WALKS.with(|walks| walks.set(walks.get() + 1));
        if self.shape.n == 0 {
            return None;
        }
        let ctrl_ptr = self.storage.ctrl_ptr();
        for (index, level) in self.shape.levels.iter().enumerate() {
            let bucket = Self::sample_ordinary(probe, level, index)?;
            let start = level.offset + bucket * self.shape.beta;
            // SAFETY: an ordinary bucket ends at or before `n`, and the control
            // array pads `GROUP_SIZE - 1` bytes past `n`.
            if let Some(slot) = unsafe { first_free_in_bucket(ctrl_ptr, start, self.shape.beta) } {
                return Some(Vacancy {
                    slot,
                    level_bit: level_bit_of(index),
                });
            }
        }
        self.search_vacancy_special(probe).map(|slot| Vacancy {
            slot,
            level_bit: OVERFLOW_LEVEL_BIT,
        })
    }

    /// [`Self::search_vacancy`] for a table without tombstones, over the levels
    /// that own a level-bin bit: the first EMPTY lane of the walk, which is
    /// then its first free slot. `None` hands the insert to the general walk:
    /// a probe word not accepted for certain, which is every word of a shape
    /// without lanes, or no vacancy in those levels.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn first_empty_in_head(&self, probe: PreparedFastFunnelProbe) -> Option<Vacancy> {
        // One copy of the step per level, each with a constant index: the
        // walk then keeps no index and checks no bound.
        macro_rules! walk {
            ($($index:literal)*) => {
                const { assert!([$($index),*].len() == OVERFLOW_LEVEL) };
                $(
                    if let Some(vacancy) = self.first_empty_in_head_level(probe, $index).ok()? {
                        return Some(vacancy);
                    }
                )*
            };
        }
        walk!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14);
        None
    }

    /// One step of [`Self::first_empty_in_head`]: the first EMPTY lane of the
    /// key's bucket in head entry `index`, if it has one. `Err` is a probe
    /// word the exact test must decide.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn first_empty_in_head_level(
        &self,
        probe: PreparedFastFunnelProbe,
        index: usize,
    ) -> Result<Option<Vacancy>, ()> {
        let level = &self.shape.head[index];
        let bucket =
            probe::ordinary_funnel_first_certain_index(probe, level.multiplier, level.bucket_range)
                .ok_or(())?;
        let start = level.offset + bucket * self.shape.beta;
        // SAFETY: an ordinary bucket ends at or before `n`, and the control
        // array pads `GROUP_SIZE - 1` bytes past `n`.
        let empty = unsafe { simd::eq_mask_group(self.storage.ctrl_ptr().add(start), CTRL_EMPTY) }
            .0
            & self.shape.bucket_lanes;
        Ok((empty != 0).then(|| Vacancy {
            slot: start + (empty.trailing_zeros() / BITMASK_STRIDE) as usize,
            level_bit: level_bit_of(index),
        }))
    }

    /// Special-array leg of [`Self::search_vacancy`]: primary probes, then the
    /// two fallback buckets, in the exact search's order. Returns the bare
    /// slot: every special slot shares the overflow bit, and a slot alone
    /// returns in registers.
    #[inline(never)]
    fn search_vacancy_special(&self, probe: PreparedFastFunnelProbe) -> Option<usize> {
        let primary_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_PRIMARY_BASE);
        for logical_probe in 0..self.shape.loglog_ceiling {
            let local = Self::sample(
                &primary_probe,
                self.shape.encode_logical_probe(logical_probe),
                self.shape.primary_range,
            )?;
            let slot = self.shape.primary_offset + local;
            // SAFETY: a primary probe stays inside the primary range.
            if control::is_free(unsafe { self.storage.control_at(slot) }) {
                return Some(slot);
            }
        }

        let first_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_FALLBACK_A_BASE);
        let first_bucket = Self::sample(&first_probe, 0, self.shape.fallback_bucket_range)?;
        let second_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_FALLBACK_B_BASE);
        let second_bucket = Self::sample(&second_probe, 0, self.shape.fallback_bucket_range)?;
        for slot_in_bucket in 0..self.shape.fallback_bucket_width {
            for bucket in [first_bucket, second_bucket] {
                let slot = self.shape.fallback_offset
                    + bucket * self.shape.fallback_bucket_width
                    + slot_in_bucket;
                // SAFETY: both buckets lie inside the fallback range.
                if control::is_free(unsafe { self.storage.control_at(slot) }) {
                    return Some(slot);
                }
            }
        }
        None
    }

    /// Only epochs that placed a key outside its funnel reach this scan.
    #[cold]
    #[inline(never)]
    fn find_by_full_scan<Q>(&self, key: &Q, key_fingerprint: u8) -> Option<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        // SAFETY: `slot < n`, the storage capacity, and a fingerprint match
        // means the slot is occupied.
        (0..self.shape.n).find(|&slot| unsafe {
            self.storage.control_at(slot) == key_fingerprint
                && key.equivalent(&self.storage.get_ref(slot).key)
        })
    }

    #[inline]
    fn membership_ptr(&self) -> *mut MetadataWord {
        self.membership.base
    }

    /// `false` proves no insert ever recorded this key.
    #[cfg(test)]
    #[inline]
    fn membership_maybe_contains(&self, key_hash: u64) -> bool {
        let words = self.membership.region.words;
        if words == 0 {
            return false;
        }
        let bits = MembershipKey::from_signature::<MEMBERSHIP_BITS>(key_hash).bits();
        let word = MembershipKey::word(key_hash, words);
        // SAFETY: `word` is a multiply-high reduction below `words`, and the
        // arena's tail holds exactly that many zero-initialized words.
        unsafe { (*self.membership_ptr().add(word)).membership & bits == bits }
    }

    /// This key's filter word index and bits for the current epoch. Only an
    /// empty geometry has no words; its index is then zero, and the gate reads
    /// the shared all-zero word, which no key passes.
    #[inline]
    fn membership_slot(&self, key_hash: u64) -> MembershipSlot {
        MembershipSlot {
            index: MembershipKey::word(key_hash, self.membership.region.words),
            bits: MembershipKey::from_signature::<MEMBERSHIP_BITS>(key_hash).bits(),
            bin: level_bin(key_hash),
        }
    }

    /// Loads this key's filter word without testing it, so a lookup can
    /// prepare the probe while the load is in flight.
    #[inline]
    fn membership_gate(&self, key_hash: u64) -> MembershipGate {
        self.membership_gate_at(self.membership_slot(key_hash))
    }

    /// [`Self::membership_gate`] for a slot the caller keeps, so an insert can
    /// record at the same slot without re-deriving it after placement.
    #[inline]
    fn membership_gate_at(&self, slot: MembershipSlot) -> MembershipGate {
        // SAFETY: `slot.index` is a multiply-high reduction below `words`, and
        // the arena's tail holds exactly that many words; with no words it is
        // zero, and the base is the shared empty word. Two field loads, not a
        // copy of the whole word, so the bin needs no dynamic extraction.
        let (word, levels) = unsafe {
            let metadata = self.membership_ptr().add(slot.index);
            ((*metadata).membership, (*metadata).level_bins[slot.bin])
        };
        MembershipGate {
            word,
            bits: slot.bits,
            levels,
        }
    }

    /// Level-bin bit for an entry stored at `slot`. Levels are contiguous from
    /// slot zero, and the special arrays follow the last of them, so the slot
    /// alone names its level.
    #[inline]
    fn level_bit(&self, slot: usize) -> u16 {
        let levels = &self.shape.levels;
        let overflow_start = levels
            .get(OVERFLOW_LEVEL)
            .map_or(self.shape.primary_offset, |level| level.offset);
        if slot >= overflow_start {
            return OVERFLOW_LEVEL_BIT;
        }
        // Level zero starts at slot zero, so the later levels starting at or
        // before `slot` count up to its level. Most entries sit in the first
        // few levels, so the walk is short.
        level_bit_of(
            levels
                .iter()
                .skip(1)
                .take_while(|level| level.offset <= slot)
                .count(),
        )
    }

    /// Records a key under a filter location derived from this epoch, at the
    /// level-bin bit of the slot it is stored in, including entries
    /// exceptional recovery places outside their funnel.
    #[inline]
    fn record_membership(&mut self, membership: MembershipSlot, level_bit: u16) {
        debug_assert!(level_bit.is_power_of_two());
        if self.membership.region.words != 0 {
            // SAFETY: as in `membership_gate`; `&mut self` makes the borrow
            // exclusive.
            let metadata = unsafe { &mut *self.membership_ptr().add(membership.index) };
            metadata.membership |= membership.bits;
            metadata.level_bins[membership.bin] |= level_bit;
        }
    }

    fn clear_membership(&mut self) {
        // SAFETY: `region` was laid out for `self.arena`.
        unsafe {
            self.membership
                .region
                .clear::<MetadataWord>(self.arena.as_ptr());
        }
        self.stale_membership = 0;
    }

    /// Shared tail of `clear` and `wipe_all` once every slot is free.
    fn finish_clear(&mut self) {
        self.exceptional_placement = false;
        self.clear_membership();
        self.epoch.start(EpochTransition::Clear);
    }

    /// Re-record the filter from the live entries, dropping the bits departed
    /// keys left behind. Entries stay put; only the filter tail is rewritten.
    ///
    /// Every key is hashed before the filter is cleared, so a hasher that
    /// unwinds leaves it recording every live key. The hashes need scratch
    /// memory; without it the filter stays as it was. Either way the refresh
    /// stays owed to the next settling delete.
    #[cold]
    #[inline(never)]
    fn refresh_membership(&mut self) {
        let mut hashes = allocator_api2::vec::Vec::new_in(self.alloc.clone());
        if hashes.try_reserve_exact(self.len).is_err() {
            return;
        }
        let mut scan = OccupiedIndices::new();
        while let Some(slot) = scan.step(&self.storage) {
            // SAFETY: `step` yields occupied in-bounds slots.
            let entry = unsafe { self.storage.get_ref(slot) };
            hashes.push(self.hash_builder.hash_one(&entry.key));
        }
        debug_assert_eq!(hashes.len(), self.len);
        self.clear_membership();
        // The same scan order as above pairs each entry with its hash.
        let mut scan = OccupiedIndices::new();
        for hash in hashes {
            let Some(slot) = scan.step(&self.storage) else {
                break;
            };
            let membership = self.membership_slot(hash);
            self.record_membership(membership, self.level_bit(slot));
        }
    }

    /// Same-size cleanup once tombstones pass their threshold; otherwise a
    /// filter refresh once departed keys pass theirs. The cleanup rebuilds
    /// the filter too, so the two never stack.
    fn settle_after_deletes(&mut self) {
        if self.tombstones > capacity::tombstone_cleanup_threshold(self.shape.n) {
            self.resize_with_transition(self.shape.n, EpochTransition::TombstoneCleanup);
        } else if self.stale_membership > membership::refresh_deletes(self.shape.max_insertions) {
            self.refresh_membership();
        }
    }

    fn copy_membership_from(&mut self, source: &Self) {
        // SAFETY: each region belongs to its own table's arena; the source has
        // the same shape, so equal word counts; distinct arenas never overlap.
        unsafe {
            self.membership.region.copy_from::<MetadataWord>(
                self.arena.as_ptr(),
                source.membership.region,
                source.arena.as_ptr(),
            );
        };
    }

    /// Read-side counterpart of [`Self::locate`]: the same filter gate and
    /// exceptional full scan around the tombstone-blind lookup walk, which
    /// visits only the levels the key's bin has recorded.
    ///
    /// Only the filter test is inline: the walk keeps many registers live, and
    /// LLVM saves them all ahead of the test, so filter-rejected misses would
    /// pay for a walk they never run. The fingerprint is derived past the
    /// gate for the same reason.
    #[inline]
    fn find_live<'a, Q, P>(&'a self, key: &Q, key_hash: u64) -> Option<P::Part>
    where
        Q: Equivalent<K> + ?Sized,
        P: FoundPart<'a, K, V>,
    {
        let gate = self.membership_gate(key_hash);
        if !gate.passes() {
            return None;
        }
        self.find_after_gate::<Q, P>(key, key_hash, gate.levels)
    }

    #[inline]
    fn find_location<Q>(&self, key: &Q, key_hash: u64) -> Option<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        self.find_live::<Q, FoundSlot>(key, key_hash)
    }

    /// Out of line so a filter-rejected miss pays for no probe preparation.
    /// A lookup that finds its key returns from here without a frame.
    #[inline(never)]
    fn find_after_gate<'a, Q, P>(&'a self, key: &Q, key_hash: u64, levels: u16) -> Option<P::Part>
    where
        Q: Equivalent<K> + ?Sized,
        P: FoundPart<'a, K, V>,
    {
        let probe = self.prf.prepare(key_hash);
        match self.first_match(key, probe, levels) {
            Some(found) => Some(P::of(found)),
            None => self.find_unmatched::<Q, P>(key, key_hash, levels, probe),
        }
    }

    /// Out of line so the first-match scan keeps none of its state for the
    /// lookup that found nothing. The ordered walk sits in tail position, so
    /// its call needs no frame here.
    #[inline(never)]
    fn find_unmatched<'a, Q, P>(
        &'a self,
        key: &Q,
        key_hash: u64,
        levels: u16,
        probe: PreparedFastFunnelProbe,
    ) -> Option<P::Part>
    where
        Q: Equivalent<K> + ?Sized,
        P: FoundPart<'a, K, V>,
    {
        if self.unmatched_is_absent(probe, levels) {
            None
        } else {
            self.find_by_walk::<Q, P>(key, key_hash, levels)
        }
    }

    /// Probe preparation stays next to the walk so the prepared probe never
    /// crosses a call boundary.
    #[inline(never)]
    fn find_by_walk<'a, Q, P>(&'a self, key: &Q, key_hash: u64, levels: u16) -> Option<P::Part>
    where
        Q: Equivalent<K> + ?Sized,
        P: FoundPart<'a, K, V>,
    {
        let slot = self.find_location_by_walk(key, key_hash, levels)?;
        // SAFETY: the walk returns only occupied in-bounds slots.
        Some(P::of(unsafe { self.found_at(slot) }))
    }

    #[inline]
    fn find_location_by_walk<Q>(&self, key: &Q, key_hash: u64, levels: u16) -> Option<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let probe = self.prf.prepare(key_hash);
        let key_fingerprint = probe.fingerprint();
        match self.lookup_recorded_levels(key, probe, key_fingerprint, levels) {
            Some(slot) => Some(slot),
            None if self.exceptional_placement => self.find_by_full_scan(key, key_fingerprint),
            None => None,
        }
    }

    /// # Safety
    ///
    /// `slot` is in bounds and occupied.
    #[inline]
    unsafe fn found_at(&self, slot: usize) -> Found<'_, K, V> {
        Found {
            slot,
            // SAFETY: the caller's contract is `get_ref`'s.
            entry: unsafe { self.storage.get_ref(slot) },
        }
    }

    /// Where an absent key goes in a table without tombstones and below its
    /// insertion limit: the first EMPTY lane of the placement walk over the
    /// levels that own a level-bin bit. `None` leaves the placement to the
    /// general insert.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn head_vacancy(&self, probe: PreparedFastFunnelProbe) -> Option<Vacancy> {
        if self.tombstones != 0 || self.len >= self.shape.max_insertions {
            return None;
        }
        self.first_empty_in_head(probe)
    }

    /// Stores an absent key at the vacancy [`Self::head_vacancy`] reported
    /// and records it in the filter. Calls nothing.
    ///
    /// # Safety
    ///
    /// `vacancy` must come from [`Self::head_vacancy`] and `gate` from the
    /// filter word of `membership`, itself from [`Self::membership_slot`],
    /// with no write to the table since any of them was read.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    unsafe fn place_in_head(
        &mut self,
        key: K,
        value: V,
        membership: MembershipSlot,
        gate: MembershipGate,
        probe: PreparedFastFunnelProbe,
        vacancy: Vacancy,
    ) {
        debug_assert_eq!(vacancy.level_bit, self.level_bit(vacancy.slot));
        debug_assert_ne!(self.membership.region.words, 0);
        // Every table word this insert needs is read before its first
        // store, which could otherwise force each to be loaded again:
        // the length and the filter word's address here, the word itself
        // by the gate.
        let len = self.len;
        // SAFETY: a vacancy exists only in a table with slots, so its
        // filter has words and `membership.index` is below their count.
        let metadata = unsafe { self.membership_ptr().add(membership.index) };
        let key_fingerprint = probe.fingerprint();
        // SAFETY: the vacancy is an EMPTY lane of an ordinary bucket, and
        // `key_fingerprint` is an occupied control.
        unsafe {
            self.storage.write_with_control(
                vacancy.slot,
                SlotEntry { key, value },
                key_fingerprint,
            );
        }
        // SAFETY: `metadata` is this key's filter word, as above, and
        // `&mut self` makes the access exclusive.
        unsafe {
            (*metadata).membership = gate.word | membership.bits;
            (*metadata).level_bins[membership.bin] |= vacancy.level_bit;
        }
        self.len = len + 1;
    }

    /// The whole insert: duplicate search behind the filter gate, growth, then
    /// placement with its recovery paths. Out of line so the common insert in
    /// [`map::TableBackend::insert`] keeps no frame.
    #[inline(never)]
    fn insert_general(&mut self, key: K, value: V, hash: u64) -> Option<V> {
        // Same gate and, behind it, the same search as a lookup: a key the
        // filter never recorded is absent, and one it did is found by the
        // levels its bin recorded. Either way the placement walk then runs
        // on its own.
        let mut membership = self.membership_slot(hash);
        let gate = self.membership_gate_at(membership);
        if gate.passes()
            && let Some(slot) = self.find_after_gate::<K, FoundSlot>(&key, hash, gate.levels)
        {
            return Some(map::TableBackend::replace_value(self, slot, value));
        }
        let probe = self.prf.prepare(hash);
        if let Some(vacancy) = self.head_vacancy(probe) {
            // SAFETY: slot, gate and vacancy were read just above, with no
            // write since.
            unsafe { self.place_in_head(key, value, membership, gate, probe, vacancy) };
            return None;
        }
        if self.prepare_vacant_insert() {
            // Growth rebuilt the arena and its filter; the filter slot from
            // before it is stale.
            membership = self.membership_slot(hash);
        }
        let vacancy = self.search_vacancy(probe);
        self.place_absent_after_search(key, value, hash, membership, vacancy);
        None
    }

    /// Entry-side lookup, which keeps the exact walk's vacancy for the insert
    /// that may follow. `Err(None)` means the
    /// filter rejected the key before any walk; `Err(Some(_))` maps the exact
    /// walk's miss, which is never `Hit`, through `on_miss`.
    #[inline]
    fn locate<Q, R>(
        &self,
        key: &Q,
        key_hash: u64,
        on_miss: impl FnOnce(SearchResult) -> R,
    ) -> Result<usize, Option<R>>
    where
        Q: Equivalent<K> + ?Sized,
    {
        // Issue the filter load, then prepare the probe while it is in flight. A
        // key the filter never recorded was never inserted, so neither the walk
        // nor the exceptional full scan can find it.
        let gate = self.membership_gate(key_hash);
        let probe = self.prf.prepare(key_hash);
        if !gate.passes() {
            return Err(None);
        }
        let key_fingerprint = probe.fingerprint();
        match self.search_exact_prepared(key, probe, key_fingerprint) {
            SearchResult::Hit(slot) => Ok(slot),
            miss if self.exceptional_placement => self
                .find_by_full_scan(key, key_fingerprint)
                .ok_or_else(|| Some(on_miss(miss))),
            miss => Err(Some(on_miss(miss))),
        }
    }

    #[inline]
    fn find_entry_ref<'a, Q>(&'a self, key: &Q, key_hash: u64) -> Option<&'a SlotEntry<K, V>>
    where
        Q: Equivalent<K> + ?Sized,
    {
        self.find_live::<Q, FoundEntry>(key, key_hash)
    }

    /// Only an exhausted placement walk reaches this scan.
    #[cold]
    #[inline(never)]
    fn first_free_global(&self) -> Option<usize> {
        // SAFETY: `slot < n`, the storage capacity.
        (0..self.shape.n).find(|&slot| control::is_free(unsafe { self.storage.control_at(slot) }))
    }

    fn place_new_entry(
        &mut self,
        vacancy: Vacancy,
        key: K,
        value: V,
        membership: MembershipSlot,
        key_fingerprint: u8,
        exceptional: bool,
    ) {
        let Vacancy { slot, level_bit } = vacancy;
        // SAFETY: callers pass a free slot from a probe within the storage.
        let was_tombstone = unsafe { self.storage.control_at(slot) } == CTRL_TOMBSTONE;
        // SAFETY: as above, and `key_fingerprint` is an occupied control.
        unsafe {
            self.storage
                .write_with_control(slot, SlotEntry { key, value }, key_fingerprint);
        }
        debug_assert_eq!(level_bit, self.level_bit(slot), "level bit of slot {slot}");
        self.record_membership(membership, level_bit);
        self.len += 1;
        if was_tombstone {
            self.tombstones -= 1;
        }
        if exceptional {
            self.exceptional_placement = true;
        }
    }

    fn next_growth_slots(&self, needed: usize) -> Option<usize> {
        if needed >= isize::MAX as usize {
            return None;
        }
        let requested = needed.max(self.shape.max_insertions.saturating_mul(2));
        FunnelShape::for_insert_budget(requested, self.reserve_fraction)
            .ok()
            .map(|shape| shape.n)
    }

    /// Grows the table if the next insert would exceed the insertion limit.
    /// Returns `true` when a resize ran, so a search from before it is stale.
    #[inline]
    fn prepare_vacant_insert(&mut self) -> bool {
        if self.len >= self.shape.max_insertions {
            self.grow_for_next_insert();
            true
        } else {
            false
        }
    }

    #[cold]
    #[inline(never)]
    fn grow_for_next_insert(&mut self) {
        let slots = self
            .next_growth_slots(self.len.saturating_add(1))
            .expect("capacity overflow");
        self.resize_with_transition(slots, EpochTransition::Growth);
    }

    /// Places a known-absent key at its search's vacancy. An exhausted walk
    /// first rebuilds the table at the same size under a fresh probe seed,
    /// which clears tombstones and re-places every survivor, then walks
    /// again; only a second exhaustion places the key outside its funnel.
    fn place_absent_after_search(
        &mut self,
        key: K,
        value: V,
        key_hash: u64,
        mut membership: MembershipSlot,
        vacancy: Option<Vacancy>,
    ) -> usize {
        // An epoch that already placed outside its funnels was either rebuilt
        // for this reason or failed in its own rebuild; another would cost
        // O(n) per insert without helping.
        let rebuilt = vacancy.is_none() && !self.exceptional_placement;
        let vacancy = if rebuilt {
            let (recovered, slot) = self.rebuild_for_placement(key_hash);
            membership = slot;
            recovered
        } else {
            vacancy
        };
        let (vacancy, exceptional) = self.resolve_vacancy(vacancy);
        // Derived past the rebuild, whose fresh seed changes the fingerprint.
        let key_fingerprint = self.prf.prepare(key_hash).fingerprint();
        self.place_new_entry(
            vacancy,
            key,
            value,
            membership,
            key_fingerprint,
            exceptional,
        );
        if exceptional && rebuilt {
            self.epoch.note_placement_recovery();
        } else if exceptional {
            self.epoch
                .start_with_placement_recovery(EpochTransition::PlacementRecovery);
        }
        vacancy.slot
    }

    /// Rebuilds at the same size under a fresh probe seed and walks `key_hash`
    /// again, returning the new vacancy and filter slot. Out of line so the
    /// insert paths carry one inlined copy of the placement walk, not two.
    #[cold]
    #[inline(never)]
    fn rebuild_for_placement(&mut self, key_hash: u64) -> (Option<Vacancy>, MembershipSlot) {
        self.resize_with_transition(self.shape.n, EpochTransition::PlacementRecovery);
        let membership = self.membership_slot(key_hash);
        let vacancy = self.search_vacancy(self.prf.prepare(key_hash));
        (vacancy, membership)
    }

    /// Maps a known-absent search to `(vacancy, exceptional)`: its vacancy, or
    /// the first free slot anywhere once the walk is exhausted. Both callers
    /// run under the insertion limit, which reserves a free slot.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn resolve_vacancy(&self, vacancy: Option<Vacancy>) -> (Vacancy, bool) {
        if let Some(vacancy) = vacancy {
            debug_assert!(
                // SAFETY: a vacancy is a probed in-bounds slot.
                control::is_free(unsafe { self.storage.control_at(vacancy.slot) }),
                "stale Funnel vacancy at slot {}",
                vacancy.slot
            );
            (vacancy, false)
        } else {
            let slot = self
                .first_free_global()
                .expect("Funnel insertion limit reserves a free slot");
            (self.vacancy_at(slot), true)
        }
    }

    /// Inserts a key the caller has proven absent. Runs the placement walk
    /// only, which lands on the same slot the exact search would report.
    #[cfg(test)]
    fn insert_for_vacant_entry(&mut self, key: K, value: V, key_hash: u64) -> usize {
        let vacant = FunnelVacant {
            hash: key_hash,
            exact: FunnelVacant::UNSEARCHED,
        };
        map::TableBackend::insert_for_vacant(self, key, value, vacant)
    }

    fn resize_with_transition(&mut self, slots: usize, transition: EpochTransition) {
        let shape = FunnelShape::from_slots(slots, self.reserve_fraction)
            .expect("compatible Funnel resize geometry");
        let n = shape.n;
        if self.try_resize_to(shape, transition).is_err() {
            let layout = funnel_layout::<K, V>(n).expect("constructed Funnel layout");
            allocator_api2::alloc::handle_alloc_error(layout.layout)
        }
    }

    /// Moves every entry into fresh storage for `shape`. A placement-recovery
    /// rebuild also advances the probe seed. Each key is hashed in place
    /// before its entry is copied, and the old storage is freed only after
    /// the last copy, so `Err` or a panicking hasher leaves the table intact.
    fn try_resize_to(
        &mut self,
        shape: FunnelShape,
        transition: EpochTransition,
    ) -> Result<(), TryReserveError> {
        let (arena, storage, membership) = try_allocate_storage(shape.n, &self.alloc)?;
        let prf = if matches!(transition, EpochTransition::PlacementRecovery) {
            self.prf.reseeded(FUNNEL_RESEED_STEP)
        } else {
            self.prf
        };
        let recovered = rebuild::rebuild(
            self,
            FunnelGeneration {
                shape,
                storage,
                len: 0,
                tombstones: 0,
                arena,
                exceptional_placement: false,
                prf,
                membership,
                stale_membership: 0,
            },
        );
        self.epoch.start_epoch(transition, recovered);
        Ok(())
    }
}

/// The fields a resize replaces as a unit.
pub(crate) struct FunnelGeneration<K, V> {
    shape: FunnelShape,
    storage: FlatStorage<SlotEntry<K, V>>,
    len: usize,
    tombstones: usize,
    arena: Arena,
    exceptional_placement: bool,
    prf: FunnelPrf,
    membership: FilterTail,
    stale_membership: usize,
}

impl<K, V, S, A> Rebuildable for FunnelTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Key = K;
    type Value = V;
    type Region = FlatStorage<SlotEntry<K, V>>;
    type Generation = FunnelGeneration<K, V>;

    fn swap_generation(&mut self, other: &mut FunnelGeneration<K, V>) {
        mem::swap(&mut self.shape, &mut other.shape);
        mem::swap(&mut self.storage, &mut other.storage);
        mem::swap(&mut self.len, &mut other.len);
        mem::swap(&mut self.tombstones, &mut other.tombstones);
        mem::swap(&mut self.arena, &mut other.arena);
        mem::swap(
            &mut self.exceptional_placement,
            &mut other.exceptional_placement,
        );
        mem::swap(&mut self.prf, &mut other.prf);
        mem::swap(&mut self.membership, &mut other.membership);
        mem::swap(&mut self.stale_membership, &mut other.stale_membership);
    }

    fn regions(generation: &FunnelGeneration<K, V>) -> &[FlatStorage<SlotEntry<K, V>>] {
        core::slice::from_ref(&generation.storage)
    }

    fn release(&self, generation: FunnelGeneration<K, V>) {
        generation.arena.deallocate(&self.alloc);
    }

    fn hash_key(&self, key: &K) -> u64 {
        self.hash_builder.hash_one(key)
    }

    #[inline]
    fn prefetch_placement(&self, key_hash: u64) {
        let membership = self.membership_slot(key_hash);
        if self.membership.region.words != 0 {
            prefetch::prefetch_write(self.membership_ptr().wrapping_add(membership.index));
        }
        let Some(level) = self.shape.levels.first() else {
            return;
        };
        let probe = self.prf.prepare(key_hash);
        if let Some(bucket) = Self::sample_ordinary(probe, level, 0) {
            self.storage
                .prefetch_slot(level.offset + bucket * self.shape.beta);
        }
    }

    /// Inlined into both rebuild loops: outlining it costs a call per entry
    /// on the rebuild hot path.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn place_unique(&mut self, entry: SlotEntry<K, V>, key_hash: u64) -> bool {
        let probe = self.prf.prepare(key_hash);
        let key_fingerprint = probe.fingerprint();
        let (vacancy, exceptional) = self.resolve_vacancy(self.search_vacancy(probe));
        let membership = self.membership_slot(key_hash);
        self.place_new_entry(
            vacancy,
            entry.key,
            entry.value,
            membership,
            key_fingerprint,
            exceptional,
        );
        exceptional
    }
}

#[allow(private_interfaces)]
impl<K, V, S, A> map::TableBackend<K, V> for FunnelTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Location = usize;
    type Vacant = FunnelVacant;
    type Hasher = S;
    type Alloc = A;
    type Scan = FunnelScan;

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
        self.shape.max_insertions
    }

    #[inline]
    fn total_slots(&self) -> usize {
        self.shape.n
    }

    #[inline]
    fn reserve_config(&self) -> ReserveFraction {
        self.reserve_fraction
    }

    fn epoch_snapshot(&self) -> EpochSnapshot {
        self.epoch.snapshot(self.len)
    }

    #[inline]
    unsafe fn slot_ref(&self, slot: usize) -> &SlotEntry<K, V> {
        // SAFETY: caller passes a live location, so `slot` is occupied.
        unsafe { self.storage.get_ref(slot) }
    }

    #[inline]
    unsafe fn slot_ptr(&self, slot: usize) -> *mut SlotEntry<K, V> {
        // SAFETY: caller passes a live location, so `slot` is in bounds.
        unsafe { self.storage.slot_ptr(slot) }
    }

    #[inline]
    fn replace_value(&mut self, slot: usize, value: V) -> V {
        // SAFETY: a live location names an occupied in-bounds slot.
        let entry = unsafe { self.storage.get_mut(slot) };
        mem::replace(&mut entry.value, value)
    }

    #[inline]
    fn find<Q>(&self, key: &Q, hash: u64) -> Option<usize>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find_location(key, hash)
    }

    #[inline]
    fn find_entry<'a, Q>(&'a self, key: &Q, hash: u64) -> Option<&'a SlotEntry<K, V>>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find_entry_ref(key, hash)
    }

    #[inline]
    fn find_for_entry<Q>(&self, key: &Q, hash: u64) -> Result<usize, FunnelVacant>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let found = self.locate(key, hash, |miss| match miss {
            SearchResult::Vacant(slot) => slot,
            _ => FunnelVacant::EXHAUSTED,
        });
        let exact = match found {
            Ok(slot) => return Ok(slot),
            Err(exact) => exact.unwrap_or(FunnelVacant::UNSEARCHED),
        };
        Err(FunnelVacant { hash, exact })
    }

    #[inline]
    fn insert_for_vacant(&mut self, key: K, value: V, vacant: FunnelVacant) -> usize {
        let vacancy = if self.prepare_vacant_insert() || vacant.exact == FunnelVacant::UNSEARCHED {
            // Growth invalidates any recorded slot or exhaustion; an unsearched
            // token never had one.
            let probe = self.prf.prepare(vacant.hash);
            self.search_vacancy(probe)
        } else if vacant.exact == FunnelVacant::EXHAUSTED {
            // Both exhaustion reasons take the same recovery path.
            None
        } else {
            Some(self.vacancy_at(vacant.exact))
        };
        // Filter geometry may have changed during growth too.
        let membership = self.membership_slot(vacant.hash);
        self.place_absent_after_search(key, value, vacant.hash, membership, vacancy)
    }

    #[inline]
    fn insert(&mut self, key: K, value: V, hash: u64) -> Option<V>
    where
        K: Hash + Eq,
    {
        // A key the filter never recorded is absent, so it needs no duplicate
        // search. That common insert calls nothing and keeps no frame; every
        // other case is the general insert's.
        let membership = self.membership_slot(hash);
        let gate = self.membership_gate_at(membership);
        if !gate.passes() {
            let probe = self.prf.prepare(hash);
            if let Some(vacancy) = self.head_vacancy(probe) {
                // SAFETY: slot, gate and vacancy were read just above, with
                // no write since.
                unsafe { self.place_in_head(key, value, membership, gate, probe, vacancy) };
                return None;
            }
        }
        self.insert_general(key, value, hash)
    }

    fn remove(&mut self, slot: usize) -> (K, V) {
        // SAFETY: a live location names an occupied in-bounds slot;
        // `extract_finish` tombstones it so it is never read again.
        let entry = unsafe { self.storage.take(slot) };
        self.extract_finish(slot);
        self.settle_after_deletes();
        (entry.key, entry.value)
    }

    #[inline]
    fn tombstone_slot(&mut self, slot: usize) {
        // SAFETY: a live location names an in-bounds slot.
        unsafe { self.storage.mark_tombstone(slot) };
    }

    #[inline]
    fn extract_finish(&mut self, slot: usize) {
        // SAFETY: a live location names an in-bounds slot.
        unsafe { self.storage.mark_tombstone(slot) };
        self.len -= 1;
        self.tombstones += 1;
        self.stale_membership += 1;
        self.epoch.note_delete();
    }

    fn finish_deferred_removals(&mut self) {
        self.settle_after_deletes();
    }

    #[inline]
    fn scan(&self) -> FunnelScan {
        FunnelScan {
            // Dense scans avoid lane extraction for nearly every slot. Only
            // sparse tables amortize masks over enough empty controls; choose
            // once so draining cannot switch modes midway through a group.
            mode: if self.len <= self.shape.n / 4 {
                FunnelScanMode::Sparse(OccupiedIndices::new())
            } else {
                FunnelScanMode::Dense(0)
            },
        }
    }

    #[inline]
    fn scan_next(&self, scan: &mut FunnelScan) -> Option<(*mut SlotEntry<K, V>, usize)> {
        match &mut scan.mode {
            FunnelScanMode::Dense(next) => {
                while *next < self.shape.n {
                    let slot = *next;
                    *next += 1;
                    // SAFETY: `slot < n`, the storage capacity.
                    unsafe {
                        if control::is_occupied(self.storage.control_at(slot)) {
                            return Some((self.storage.slot_ptr(slot), slot));
                        }
                    }
                }
                None
            }
            FunnelScanMode::Sparse(cursor) => {
                let slot = cursor.step(&self.storage)?;
                // SAFETY: `step` yields in-bounds slots.
                Some((unsafe { self.storage.slot_ptr(slot) }, slot))
            }
        }
    }

    fn with_capacity_and_reserve_and_hasher_in(
        capacity: usize,
        reserve: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Self {
        Self::try_with_insert_budget(capacity, reserve, hash_builder, alloc)
            .expect("invalid Funnel construction")
    }

    fn try_with_capacity_and_reserve_and_hasher_in(
        capacity: usize,
        reserve: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryBuildError> {
        Self::try_with_insert_budget(capacity, reserve, hash_builder, alloc)
    }

    fn grow_capacity_for(&self, needed: usize) -> Option<usize> {
        self.next_growth_slots(needed)
    }

    fn resize(&mut self, new_capacity: usize) {
        self.resize_with_transition(new_capacity, EpochTransition::ExplicitResize);
    }

    fn try_resize(&mut self, new_capacity: usize) -> Result<(), TryReserveError> {
        let shape = FunnelShape::from_slots(new_capacity, self.reserve_fraction)?;
        self.try_resize_to(shape, EpochTransition::ExplicitResize)
    }

    fn shrink_to(&mut self, min_capacity: usize) {
        if self.len == 0 && min_capacity == 0 {
            if self.shape.n != 0 {
                self.resize_with_transition(0, EpochTransition::ExplicitResize);
            }
            return;
        }
        let requested = self.len.max(min_capacity);
        let Ok(shape) = FunnelShape::for_insert_budget(requested, self.reserve_fraction) else {
            panic!("capacity overflow");
        };
        if shape.n < self.shape.n {
            self.resize_with_transition(shape.n, EpochTransition::ExplicitResize);
        }
    }

    /// Lookups stop at `EMPTY`, so each value's slot becomes a tombstone
    /// before the value drops, and controls reset only after the last drop.
    /// A panicking `Drop` leaves every undropped entry reachable and counted,
    /// and a later `clear` finishes the job.
    fn clear(&mut self) {
        if mem::needs_drop::<SlotEntry<K, V>>() {
            let mut scan = OccupiedIndices::new();
            while let Some(slot) = scan.step(&self.storage) {
                // SAFETY: `step` yields occupied in-bounds slots; the slot is
                // marked a tombstone before `entry` drops, so it is never read
                // or dropped again.
                let entry = unsafe { self.storage.take(slot) };
                // SAFETY: `slot` is in bounds and its value was moved out.
                unsafe { self.storage.set_control(slot, CTRL_TOMBSTONE) };
                self.len -= 1;
                self.tombstones += 1;
                drop(entry);
            }
        }
        self.wipe_all();
    }

    fn wipe_all(&mut self) {
        self.storage.clear_all_controls();
        self.len = 0;
        self.tombstones = 0;
        self.finish_clear();
    }

    fn clone_table(&self) -> Self
    where
        K: Clone,
        V: Clone,
        S: Clone,
    {
        let mut cloned = Self::try_from_shape(
            self.shape.clone(),
            self.reserve_fraction,
            self.hash_builder.clone(),
            self.alloc.clone(),
        )
        .unwrap_or_else(|error| panic!("Funnel clone allocation failed: {error}"));
        cloned.storage.clone_region_from(&self.storage);
        cloned.len = self.len;
        cloned.tombstones = self.tombstones;
        cloned.epoch = self.epoch;
        cloned.exceptional_placement = self.exceptional_placement;
        cloned.prf = self.prf;
        // Slots are copied rather than reinserted, so the filter comes with them.
        cloned.copy_membership_from(self);
        cloned.stale_membership = self.stale_membership;
        cloned
    }
}

#[cfg(test)]
mod tests;
