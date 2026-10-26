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
use crate::exact::geometry::PaperConfig;
use crate::exact::probe::{self, CounterPrf, PreparedElasticProbe};
use crate::hasher::DefaultHashBuilder;
use crate::macros;
use crate::map;
use crate::membership::{self, MembershipKey, MembershipRegion};
use crate::raw::arena::{self, Arena, ArenaSlots, SlotEntry};
use crate::raw::config::INITIAL_CAPACITY;
use crate::raw::control::{self, CTRL_EMPTY, CTRL_TOMBSTONE};
use crate::raw::iter::OccupiedIndices;
use crate::raw::rebuild::{self, Rebuildable};

/// `(slot pointer, location)` yielded by the scan cursor: the pointer is read
/// by iterators, the `(level, slot)` location backs removal.
type ElasticScanItem<K, V> = (*mut SlotEntry<K, V>, (usize, usize));

// Fixed construction seed shared by placement, lookup, and membership.
const ELASTIC_PROBE_SEED: u64 = probe::WYHASH_DEFAULT_SECRET[0];
const ELASTIC_PROBE_BUDGET_C: usize = 8;
const UNIFORM_SEARCH_CAP: u64 = 4_096;
const QUERY_POSITION_CAP: u128 = 1_000_000;
const EXCEPTIONAL_PLACEMENT_FLAG: u32 = 1 << 31;
const QUERY_PROBE_LIMIT: usize = 384;
const MAX_ELASTIC_SLOTS: u64 = 1 << u32::BITS;
const ROUTE_SUMMARY_LEVELS: usize = u16::BITS as usize;
const H11_COUNTER_BASE: u32 = probe::elastic_counter_base(0, 0);

const _: () = assert!(u32::BITS as u64 <= probe::ELASTIC_LEVEL_LIMIT);
const _: () = assert!(UNIFORM_SEARCH_CAP <= probe::ELASTIC_LOGICAL_LIMIT);
const _: () = {
    let max_case1_logical_probes = ELASTIC_PROBE_BUDGET_C * (u32::BITS as usize - 1).pow(2);
    assert!(max_case1_logical_probes as u64 <= probe::ELASTIC_LOGICAL_LIMIT);
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExactPlacement {
    level: usize,
    slot: usize,
    /// Paper position of the chosen slot, `elastic_phi(level + 1, probe)`;
    /// the lookup schedule is extended to cover it.
    phi: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PhiRoute {
    /// Temporarily holds `phi` while a new suffix is sorted, then the exact
    /// level bound used by every lookup in the epoch.
    range_upper: u32,
    /// Packed retry-zero `(level, logical probe)` counter.
    counter_base: u32,
}

const _: () = assert!(mem::size_of::<PhiRoute>() == 8);

impl PhiRoute {
    #[inline]
    const fn level(self) -> usize {
        probe::elastic_counter_level(self.counter_base) as usize
    }
}

/// Descriptor for one sub-array `A_i`. Holds metadata + cached pointers
/// into the map-level arena; owns no allocation. The actual ctrl bytes and
/// [`SlotEntry`] data live contiguously in [`ElasticTable::arena`].
pub(crate) struct Level<T> {
    /// Cached `arena.as_ptr() + ctrl_offset`, stamped at construction.
    ctrl_ptr: *mut u8,
    /// Cached `arena.as_ptr() + data_offset`, stamped at construction.
    data_ptr: *mut MaybeUninit<T>,
    /// Exact logical slot count. Bounded by the arena layout, so the counters
    /// fit in `u32` too.
    capacity: u32,
    len: u32,
    tombstones: u32,
}

// SAFETY: the raw pointers address slots this descriptor's table owns
// exclusively, like `Box<[T]>`; no shared interior state outlives the borrow.
unsafe impl<T: Send> Send for Level<T> {}
// SAFETY: as above; `&Level` only permits reads of `T` through the pointers.
unsafe impl<T: Sync> Sync for Level<T> {}

// `Level` is read on every lookup — keep it within one 64-byte cache line.
const _: () = assert!(mem::size_of::<Level<SlotEntry<u64, u64>>>() <= 64);

// SAFETY: descriptors are only stamped at offsets carved from an arena
// allocated by `arena::layout_for` for exactly `capacity` ctrl bytes and
// slots, whose ctrl bytes `try_allocate_with_ctrl_zeroed` starts EMPTY, and
// are dropped or re-stamped before that arena is freed.
unsafe impl<T> ArenaSlots<T> for Level<T> {
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

impl<T> Level<T> {
    /// Stamps a fresh descriptor at the given arena ptrs.
    /// Caller advances the offset cursor.
    fn new_at(cap_u32: u32, ctrl_ptr: *mut u8, data_ptr: *mut MaybeUninit<T>) -> Self {
        Self {
            ctrl_ptr,
            data_ptr,
            capacity: cap_u32,
            len: 0,
            tombstones: 0,
        }
    }

    /// Slots minus live entries (includes tombstones, reusable on insert).
    #[inline]
    fn free_slots(&self) -> usize {
        self.capacity.saturating_sub(self.len) as usize
    }

    /// Tombstones exceed [`capacity::tombstone_cleanup_threshold`], so the
    /// table should begin a same-size cleanup epoch after the active scan.
    #[inline]
    fn needs_cleanup(&self) -> bool {
        self.tombstones as usize > capacity::tombstone_cleanup_threshold(self.capacity as usize)
    }

    /// Moves every live entry out through `visit` and resets the level to
    /// empty. Each slot's control and `len` are updated before `visit` runs,
    /// and tombstones are wiped only after the last entry, so a panic inside
    /// `visit` leaves the level consistent: the entries not yet visited stay
    /// live and counted, and the moved ones are `EMPTY`.
    fn drain_reset(&mut self, mut visit: impl FnMut(T)) {
        let mut scan = OccupiedIndices::new();
        while let Some(slot) = scan.step(self) {
            // SAFETY: `step` yields occupied in-bounds slots; the value is
            // moved out before the slot is marked empty.
            let entry = unsafe { self.take(slot) };
            // SAFETY: `slot` is in bounds, as above.
            unsafe { self.set_control(slot, CTRL_EMPTY) };
            self.len -= 1;
            visit(entry);
        }
        self.clear_all_controls();
        self.tombstones = 0;
    }
}

/// Open-addressed elastic-hashing backend for the generic [`map::HashMap`]
/// shell. See [`ElasticHashMap`] for the public map type.
///
/// Splits capacity across geometrically shrinking `levels` and routes inserts
/// through a `batch_plan`: early batches concentrate on level 0; later
/// batches push toward deeper levels. Lookups walk a precomputed probe
/// schedule, skipping levels the route summary rules out.
///
/// Placement uses the paper's exact level schedule and uniform per-level
/// probes. Query positions are compressed without changing their order.
pub struct ElasticTable<K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    levels: LevelSlice<K, V>,
    len: usize,
    total_slots: usize,
    max_insertions: usize,
    reserve_fraction: ReserveFraction,
    /// Schedule batch progression and epoch boundaries.
    scheduler: BatchScheduler,
    hash_builder: S,
    alloc: A,
    /// [`ctrl_L0|ctrl_L1|...`][pad][`slots_L0|slots_L1|...`].
    arena: Arena,
    epoch: EpochState,
    probe_high_water: u32,
    probe_schedule: Vec<PhiRoute>,
    /// Cached location of the metadata tail. See [`MembershipRegion`].
    membership: MembershipRegion,
    /// Deletes since the filter last matched the live set; see
    /// [`membership::refresh_deletes`].
    stale_membership: usize,
}

// SAFETY: the table uniquely owns its arena and every entry in it, like
// `Box<[SlotEntry<K, V>]>`; the raw pointers are never shared with another table.
unsafe impl<K: Send, V: Send, S: Send, A: Allocator + Clone + Send> Send
    for ElasticTable<K, V, S, A>
{
}
// SAFETY: as above; slots are mutated only under an exclusive borrow of the
// owning map, so `&ElasticTable` only reads.
unsafe impl<K: Sync, V: Sync, S: Sync, A: Allocator + Clone + Sync> Sync
    for ElasticTable<K, V, S, A>
{
}

impl<K, V, S, A: Allocator + Clone> fmt::Debug for ElasticTable<K, V, S, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ElasticTable").finish_non_exhaustive()
    }
}

impl<K, V, S, A: Allocator + Clone> Drop for ElasticTable<K, V, S, A> {
    fn drop(&mut self) {
        let levels = &mut self.levels;
        self.arena
            .drop_table(&self.alloc, || arena::RegionSet::drop_all_values(levels));
    }
}

macros::declare_backend_aliases! {
    table = ElasticTable,
    map_no_lifetime {
        /// Open-addressed hash map using elastic hashing.
        ///
        /// # Examples
        ///
        /// ```
        /// use opthash::ElasticHashMap;
        ///
        /// let mut stock = ElasticHashMap::with_capacity(16);
        /// stock.insert("apples", 3);
        /// *stock.entry("pears").or_insert(0) += 5;
        ///
        /// assert_eq!(stock.get("apples"), Some(&3));
        /// assert_eq!(stock.remove("pears"), Some(5));
        /// assert_eq!(stock.len(), 1);
        /// ```
        ElasticHashMap => HashMap,
        /// Consuming iterator over owned `(K, V)`.
        ElasticIntoIter => IntoIter,
        /// Owned `K` iterator.
        ElasticIntoKeys => IntoKeys,
        /// Owned `V` iterator.
        ElasticIntoValues => IntoValues,
    },
    map_ref {
        /// A view into a single entry, occupied or vacant.
        ElasticEntry => Entry,
        /// View of an occupied entry.
        ElasticOccupiedEntry => OccupiedEntry,
        /// View of a vacant entry.
        ElasticVacantEntry => VacantEntry,
        /// Error returned by `try_insert` on key collision.
        ElasticOccupiedError => OccupiedError,
        /// Borrowing iterator over `(&K, &V)`.
        ElasticIter => Iter,
        /// Borrowing iterator over `(&K, &mut V)`.
        ElasticIterMut => IterMut,
        /// `&K` iterator.
        ElasticKeys => Keys,
        /// `&V` iterator.
        ElasticValues => Values,
        /// `&mut V` iterator.
        ElasticValuesMut => ValuesMut,
        /// Draining iterator that empties the map.
        ElasticDrain => Drain,
    },
    map_extract_if {
        /// Iterator yielding entries removed by `extract_if`.
        ElasticExtractIf
    },
    set_no_lifetime {
        /// Hash set using elastic hashing.
        ///
        /// # Examples
        ///
        /// ```
        /// use opthash::ElasticHashSet;
        ///
        /// let evens: ElasticHashSet<u32> = (0..10).step_by(2).collect();
        /// let small: ElasticHashSet<u32> = (0..5).collect();
        ///
        /// let mut both: Vec<_> = evens.intersection(&small).copied().collect();
        /// both.sort_unstable();
        /// assert_eq!(both, [0, 2, 4]);
        /// ```
        ElasticHashSet => HashSet,
        /// Consuming iterator over set values.
        ElasticSetIntoIter => IntoIter,
    },
    set_ref {
        /// Borrowing iterator over set values.
        ElasticSetIter => Iter,
        /// Draining iterator that empties the set.
        ElasticSetDrain => Drain,
        /// Iterator over values present only in the first set.
        ElasticDifference => Difference,
        /// Iterator over values present in both sets.
        ElasticIntersection => Intersection,
        /// Iterator over values present in exactly one set.
        ElasticSymmetricDifference => SymmetricDifference,
        /// Iterator over values present in either set.
        ElasticUnion => Union,
        /// A view into a single set entry.
        ElasticSetEntry => Entry,
        /// View of an occupied set entry.
        ElasticSetOccupiedEntry => OccupiedEntry,
        /// View of a vacant set entry.
        ElasticSetVacantEntry => VacantEntry,
    },
    set_extract_if {
        /// Iterator yielding values removed by set `extract_if`.
        ElasticSetExtractIf
    },
}

/// Boxed slice of levels for one `(K, V)` parameterization.
type LevelSlice<K, V> = Box<[Level<SlotEntry<K, V>>]>;
/// A fresh arena, its level descriptors, and the metadata tail they share.
type ElasticArenaBuild<K, V> = (Arena, LevelSlice<K, V>, MembershipRegion);

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ElasticMetadataWord {
    membership: u64,
    route_bins: [u16; 4],
}

const _: () = assert!(mem::size_of::<ElasticMetadataWord>() == 16);

struct ElasticArenaLayout {
    layout: Layout,
    data_base_off: usize,
    membership: MembershipRegion,
}

fn elastic_arena_layout<K, V>(total_slots: usize) -> Result<ElasticArenaLayout, TryReserveError> {
    let (base_layout, data_base_off) = arena::layout_for::<K, V>(total_slots)?;
    let (layout, membership) =
        MembershipRegion::extend::<ElasticMetadataWord>(base_layout, total_slots)?;
    Ok(ElasticArenaLayout {
        layout,
        data_base_off,
        membership,
    })
}

#[derive(Clone, Copy)]
struct PreparedElasticRoute {
    probe: PreparedElasticProbe,
}

impl PreparedElasticRoute {
    #[inline]
    fn new(hash: u64) -> Self {
        Self {
            probe: CounterPrf::new(ELASTIC_PROBE_SEED).prepare_elastic(hash),
        }
    }

    #[inline]
    const fn signature(self) -> u64 {
        self.probe.routing_signature()
    }

    #[inline]
    fn summary_bin(self) -> usize {
        (self.signature() & 3) as usize
    }
}

#[derive(Clone, Copy)]
struct PreparedElasticKey {
    route: PreparedElasticRoute,
    membership: MembershipKey,
}

impl PreparedElasticKey {
    #[inline]
    fn new(hash: u64) -> Self {
        let route = PreparedElasticRoute::new(hash);
        Self {
            membership: MembershipKey::from_signature(route.signature()),
            route,
        }
    }
}

const _: () = assert!(mem::size_of::<PreparedElasticRoute>() == 8);
const _: () = assert!(mem::size_of::<PreparedElasticKey>() == 16);

/// Both metadata answers for one prepared key, read from one word.
#[derive(Clone, Copy)]
struct ElasticRouteFilter {
    /// `false` proves no insert ever recorded this key's route.
    maybe_present: bool,
    /// Summary bits of the levels this route bin has occupied. Bit `i` covers
    /// level `i` for `i < ROUTE_SUMMARY_LEVELS - 1`; the last bit is saturating
    /// and covers every deeper level.
    level_mask: u32,
}

impl ElasticRouteFilter {
    /// Widens the saturating last summary bit over every level index it stands
    /// for, so a lookup tests `1 << level` directly instead of clamping the
    /// level on each schedule step.
    #[inline]
    const fn expanded_level_mask(self) -> u32 {
        let saturated = (self.level_mask >> (ROUTE_SUMMARY_LEVELS - 1)) & 1;
        self.level_mask | (0_u32.wrapping_sub(saturated) << (ROUTE_SUMMARY_LEVELS - 1))
    }
}

/// Maps a level index onto its route-summary bit. Levels past the summary's
/// width share the last bit, so a wide geometry still narrows every shallow
/// level instead of disabling the summary outright.
#[inline]
const fn summary_level(level: usize) -> usize {
    if level < ROUTE_SUMMARY_LEVELS - 1 {
        level
    } else {
        ROUTE_SUMMARY_LEVELS - 1
    }
}

/// Walks `level`'s probes in paper order from `from_probe`, visiting each
/// `(paper_probe, phi)` with `phi <= position_cap` inside the uniform search
/// cap. Level 0's first probe is skipped: the H11 fast path covers it, so no
/// route is ever scheduled for it.
#[allow(clippy::inline_always)]
#[inline(always)]
fn for_each_phi_route(
    level: usize,
    from_probe: u128,
    position_cap: u128,
    mut visit: impl FnMut(u128, u128),
) {
    let paper_level = level as u128 + 1;
    let mut paper_probe = if level == 0 && from_probe == 1 {
        2
    } else {
        from_probe
    };
    while paper_probe <= u128::from(UNIFORM_SEARCH_CAP) {
        let phi =
            probe::elastic_phi(paper_level, paper_probe).expect("bounded Elastic query coordinate");
        if phi > position_cap {
            break;
        }
        visit(paper_probe, phi);
        paper_probe += 1;
    }
}

/// Full probe-schedule length per level count, computed at compile time so
/// construction, resize, and clone size the schedule without walking every
/// level's probes.
const PROBE_SCHEDULE_CAPACITY: [usize; MAX_LEVELS + 1] = {
    let mut capacities = [0; MAX_LEVELS + 1];
    let mut level = 0;
    while level < MAX_LEVELS {
        capacities[level + 1] = capacities[level] + level_route_count(level);
        level += 1;
    }
    capacities
};

/// Paper probes a lookup can reach in each level: those with
/// `phi <= QUERY_POSITION_CAP`, within `UNIFORM_SEARCH_CAP`. Placement stops
/// there, so a vacancy past the cap counts as a failed probe.
const LEVEL_PROBE_LIMIT: [u64; MAX_LEVELS] = {
    let mut limits = [0; MAX_LEVELS];
    let mut level = 0;
    while level < MAX_LEVELS {
        // `level_route_count` skips level 0's first probe, which the
        // direct-slot fast path covers.
        let first_probe_skipped = if level == 0 { 1 } else { 0 };
        limits[level] = (level_route_count(level) + first_probe_skipped) as u64;
        level += 1;
    }
    limits
};

/// Routes [`for_each_phi_route`] visits for `level` from its first probe up to
/// `QUERY_POSITION_CAP`, within `UNIFORM_SEARCH_CAP` probes.
const fn level_route_count(level: usize) -> usize {
    let paper_level = level as u128 + 1;
    let mut paper_probe = if level == 0 { 2 } else { 1 };
    let mut count = 0;
    while paper_probe <= UNIFORM_SEARCH_CAP as u128 {
        let Ok(phi) = probe::elastic_phi(paper_level, paper_probe) else {
            panic!("bounded Elastic query coordinate");
        };
        if phi > QUERY_POSITION_CAP {
            break;
        }
        count += 1;
        paper_probe += 1;
    }
    count
}

fn try_probe_schedule(level_count: usize) -> Result<Vec<PhiRoute>, TryReserveError> {
    let mut schedule = Vec::new();
    schedule
        .try_reserve_exact(PROBE_SCHEDULE_CAPACITY[level_count])
        .map_err(|_| TryReserveError::AllocError)?;
    Ok(schedule)
}

/// Schedule paper batches and allocation-epoch boundaries.
///
/// The active batch is a function of the live count alone: batch `i` covers
/// positions in `[batch_ends[i-1], batch_ends[i])`, the prefix-sum test the
/// scalar oracle applies, so under deletion it tracks occupancy rather than
/// an insert tally.
#[derive(Clone)]
pub(crate) struct BatchScheduler {
    /// Cumulative quota through each batch: the exclusive `len` bound at
    /// which the batch ends. Zero-quota batches repeat the previous end.
    batch_ends: Box<[usize]>,
    current_batch_index: usize,
    /// `batch_ends[current_batch_index - 1]`, or zero for the first batch.
    batch_start: usize,
    /// `batch_ends[current_batch_index]`, or `usize::MAX` for an empty plan.
    batch_end: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BatchTarget {
    Bootstrap,
    LevelPair(usize),
}

impl BatchScheduler {
    pub(crate) fn new(batch_plan: &[usize]) -> Self {
        let mut total = 0_usize;
        let batch_ends = batch_plan
            .iter()
            .map(|&quota| {
                total = total.saturating_add(quota);
                total
            })
            .collect::<Box<[usize]>>();
        let mut scheduler = Self {
            batch_ends,
            current_batch_index: 0,
            batch_start: 0,
            batch_end: usize::MAX,
        };
        scheduler.reset();
        scheduler
    }

    /// [`Self::target`] on a copy, for assertions through a shared borrow.
    #[cfg(test)]
    fn target_at(&self, len: usize) -> BatchTarget {
        self.clone().target(len)
    }

    /// Distinguish bootstrap placement from the level pair for later batches,
    /// for a table holding `len` live entries. Re-syncs the cached batch when
    /// `len` has left its window; the common case is two compares.
    #[inline]
    fn target(&mut self, len: usize) -> BatchTarget {
        if len >= self.batch_end || len < self.batch_start {
            self.sync(len);
        }
        if self.current_batch_index == 0 {
            BatchTarget::Bootstrap
        } else {
            BatchTarget::LevelPair(self.current_batch_index - 1)
        }
    }

    /// Move the cached window to the batch covering `len`. Zero-quota batches
    /// are never selected because their window is empty. Beyond the last end,
    /// the last batch stays active.
    #[cold]
    #[inline(never)]
    fn sync(&mut self, len: usize) {
        let ends = &self.batch_ends;
        if ends.is_empty() {
            return;
        }
        let index = ends.partition_point(|&end| end <= len).min(ends.len() - 1);
        self.current_batch_index = index;
        self.batch_start = if index == 0 { 0 } else { ends[index - 1] };
        self.batch_end = ends[index];
    }

    /// Reset batch progress after resize or clear.
    #[inline]
    pub(crate) fn reset(&mut self) {
        self.sync(0);
    }
}

/// Most levels, and most batch quotas, any Elastic geometry can have: a table
/// holds at most `MAX_ELASTIC_SLOTS = 2^32` slots and the paper uses
/// `ceil(log2(n))` levels with one quota each.
const MAX_LEVELS: usize = u32::BITS as usize;

/// A geometry's level lengths or batch quotas, held on the stack so building
/// or resizing a table allocates only what the table keeps.
#[derive(Clone, Copy)]
struct PlanBuffer {
    items: [usize; MAX_LEVELS],
    len: usize,
}

impl PlanBuffer {
    const EMPTY: Self = Self {
        items: [0; MAX_LEVELS],
        len: 0,
    };

    fn from_iter(items: impl ExactSizeIterator<Item = usize>) -> Self {
        let mut buffer = Self::EMPTY;
        assert!(
            items.len() <= MAX_LEVELS,
            "Elastic plan exceeds {MAX_LEVELS} levels"
        );
        for item in items {
            buffer.items[buffer.len] = item;
            buffer.len += 1;
        }
        buffer
    }
}

impl core::ops::Deref for PlanBuffer {
    type Target = [usize];

    fn deref(&self) -> &[usize] {
        &self.items[..self.len]
    }
}

/// Capacity shape and batch schedule for one elastic table allocation.
struct ElasticGeometry {
    total_slots: usize,
    max_insertions: usize,
    level_capacities: PlanBuffer,
    batch_plan: PlanBuffer,
}

impl ElasticGeometry {
    fn for_insert_budget(
        requested_insertions: usize,
        reserve_fraction: ReserveFraction,
    ) -> Option<Self> {
        let total_slots = if requested_insertions == 0 {
            0
        } else {
            capacity::capacity_for(INITIAL_CAPACITY, requested_insertions, reserve_fraction)?
        };
        Self::for_slots(total_slots, reserve_fraction)
    }

    /// `None` when `total_slots` exceeds `MAX_ELASTIC_SLOTS`.
    fn for_slots(total_slots: usize, reserve_fraction: ReserveFraction) -> Option<Self> {
        if !u64::try_from(total_slots).is_ok_and(|slots| slots <= MAX_ELASTIC_SLOTS) {
            return None;
        }
        if total_slots == 0 {
            return Some(Self {
                total_slots: 0,
                max_insertions: 0,
                level_capacities: PlanBuffer::EMPTY,
                batch_plan: PlanBuffer::EMPTY,
            });
        }

        // Public construction rounds positive maps up to INITIAL_CAPACITY, so
        // one slot is only an internal bootstrap shape outside the paper's
        // n >= 2 domain.
        if total_slots == 1 {
            let single = PlanBuffer::from_iter(core::iter::once(1));
            return Some(Self {
                total_slots: 1,
                max_insertions: 1,
                level_capacities: single,
                batch_plan: single,
            });
        }

        let config = PaperConfig::new(total_slots, reserve_fraction.exponent())
            .expect("validated Elastic library geometry");
        let plan = config.elastic_plan();
        Some(Self {
            total_slots,
            max_insertions: config.max_insertions(),
            level_capacities: PlanBuffer::from_iter(plan.level_lengths()),
            batch_plan: PlanBuffer::from_iter(plan.batch_quotas()),
        })
    }
}

/// Stamps level descriptors with arena-relative `(ctrl_ptr, data_ptr)`.
/// Split out so the alloc-then-deallocate-on-error wrapper stays shallow.
fn build_elastic_levels<K, V>(
    arena_base: *mut u8,
    data_base_off: usize,
    level_capacities: &[usize],
) -> Result<LevelSlice<K, V>, TryReserveError> {
    let mut cursor = arena::LayoutCursor::<SlotEntry<K, V>>::new(arena_base, data_base_off)?;
    let mut levels: Vec<Level<SlotEntry<K, V>>> = Vec::new();
    levels
        .try_reserve_exact(level_capacities.len())
        .map_err(|_| TryReserveError::AllocError)?;
    for &cap in level_capacities {
        let cap_u32 = u32::try_from(cap).map_err(|_| TryReserveError::CapacityOverflow)?;
        // SAFETY: the arena was allocated for the layout these caps sum to.
        let (ctrl_ptr, data_ptr) = unsafe { cursor.reserve(cap_u32)? };
        levels.push(Level::new_at(cap_u32, ctrl_ptr, data_ptr));
    }
    Ok(levels.into_boxed_slice())
}

fn total_ctrl(level_capacities: &[usize]) -> Option<usize> {
    level_capacities
        .iter()
        .try_fold(0_usize, |total, &capacity| total.checked_add(capacity))
}

#[allow(clippy::cast_ptr_alignment)]
fn try_alloc_elastic_arena<K, V, A: Allocator + Clone>(
    level_capacities: &[usize],
    alloc: &A,
) -> Result<ElasticArenaBuild<K, V>, TryReserveError> {
    let total_ctrl = total_ctrl(level_capacities).ok_or(TryReserveError::CapacityOverflow)?;
    let arena_layout = elastic_arena_layout::<K, V>(total_ctrl)?;
    let arena = Arena::try_allocate_with_ctrl_zeroed(arena_layout.layout, total_ctrl, alloc)?;
    let membership = arena_layout.membership;
    // The arena zeroes control bytes only; an empty filter must read as
    // "nothing recorded".
    // SAFETY: `membership` was laid out by `elastic_arena_layout` for this arena.
    unsafe { membership.clear::<ElasticMetadataWord>(arena.as_ptr()) };

    // `Arena` has no `Drop`: deallocate explicitly if level construction fails.
    match build_elastic_levels::<K, V>(arena.as_ptr(), arena_layout.data_base_off, level_capacities)
    {
        Ok(levels) => Ok((arena, levels, membership)),
        Err(e) => {
            arena.deallocate(alloc);
            Err(e)
        }
    }
}

fn alloc_elastic_arena<K, V, A: Allocator + Clone>(
    level_capacities: &[usize],
    alloc: &A,
) -> ElasticArenaBuild<K, V> {
    try_alloc_elastic_arena(level_capacities, alloc)
        .unwrap_or_else(|_| handle_elastic_alloc_error::<K, V>(level_capacities))
}

/// Reports the failed allocation for `level_capacities`, or a placeholder
/// layout when the geometry itself does not fit.
#[cold]
fn handle_elastic_alloc_error<K, V>(level_capacities: &[usize]) -> ! {
    let layout = total_ctrl(level_capacities)
        .and_then(|total_ctrl| {
            elastic_arena_layout::<K, V>(total_ctrl)
                .ok()
                .map(|layout| layout.layout)
        })
        .unwrap_or_else(Layout::new::<u8>);
    allocator_api2::alloc::handle_alloc_error(layout)
}

/// Drops every level's live values, backing [`arena::ArenaDropGuard`]'s
/// panic-safe rollback in `resize`/`clone`.
impl<K, V> arena::RegionSet for LevelSlice<K, V> {
    fn drop_all_values(&mut self) {
        arena::drop_values(self);
    }
}

impl<K, V, S, A> ElasticTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    /// Allocates an empty table for `geometry`. Every constructor ends here.
    fn try_from_geometry(
        geometry: &ElasticGeometry,
        reserve_fraction: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryReserveError> {
        let probe_schedule = try_probe_schedule(geometry.level_capacities.len())?;
        let (arena, levels, membership) =
            try_alloc_elastic_arena(&geometry.level_capacities, &alloc)?;

        Ok(Self {
            levels,
            len: 0,
            total_slots: geometry.total_slots,
            max_insertions: geometry.max_insertions,
            reserve_fraction,
            scheduler: BatchScheduler::new(&geometry.batch_plan),
            hash_builder,
            alloc,
            arena,
            epoch: EpochState::initial(),
            probe_high_water: 0,
            probe_schedule,
            membership,
            stale_membership: 0,
        })
    }

    /// Full constructor using an exact dyadic reserve.
    #[must_use]
    pub fn with_capacity_and_reserve_and_hasher_in(
        capacity: usize,
        reserve_fraction: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Self {
        let geometry = ElasticGeometry::for_insert_budget(capacity, reserve_fraction)
            .expect("capacity overflow");
        Self::try_from_geometry(&geometry, reserve_fraction, hash_builder, alloc)
            .unwrap_or_else(|_| handle_elastic_alloc_error::<K, V>(&geometry.level_capacities))
    }

    /// Fallible full constructor using an exact dyadic reserve.
    fn try_with_capacity_and_reserve_and_hasher_in(
        capacity: usize,
        reserve_fraction: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryBuildError> {
        let geometry = ElasticGeometry::for_insert_budget(capacity, reserve_fraction)
            .ok_or(TryBuildError::Reserve(TryReserveError::CapacityOverflow))?;
        Self::try_from_geometry(&geometry, reserve_fraction, hash_builder, alloc)
            .map_err(Into::into)
    }

    #[inline]
    fn membership_ptr(&self) -> *mut ElasticMetadataWord {
        // SAFETY: `self.membership` was laid out together with `self.arena`.
        unsafe {
            self.membership
                .ptr::<ElasticMetadataWord>(self.arena.as_ptr())
        }
    }

    /// Reads the membership scalar and selected route-summary bin directly:
    /// `maybe_present == false` proves the key was never recorded, and
    /// `level_mask` narrows the candidate levels. The two field loads avoid
    /// copying the whole metadata word for dynamic bin extraction.
    #[inline]
    fn route_filter(&self, prepared: PreparedElasticKey) -> ElasticRouteFilter {
        let words = self.membership.words;
        if words == 0 {
            return ElasticRouteFilter {
                maybe_present: false,
                level_mask: 0,
            };
        }
        let word = MembershipKey::word(prepared.route.signature(), words);
        let summary_bin = prepared.route.summary_bin();
        let bits = prepared.membership.bits();
        // SAFETY: `word` is a multiply-high reduction below `words`, and the
        // cached region covers exactly that many initialized, properly aligned
        // `ElasticMetadataWord`s.
        let (membership, route_bin) = unsafe {
            let metadata = self.membership_ptr().add(word);
            ((*metadata).membership, (*metadata).route_bins[summary_bin])
        };
        ElasticRouteFilter {
            maybe_present: membership & bits == bits,
            level_mask: u32::from(route_bin),
        }
    }

    #[cfg(test)]
    #[inline(never)]
    fn membership_maybe_contains(
        &self,
        route: PreparedElasticRoute,
        membership: MembershipKey,
    ) -> bool {
        let words = self.membership.words;
        if words == 0 {
            return false;
        }
        let word = MembershipKey::word(route.signature(), words);
        // SAFETY: `word < words`, and the region holds that many initialized words.
        unsafe {
            (*self.membership_ptr().add(word)).membership & membership.bits() == membership.bits()
        }
    }

    #[inline]
    fn record_membership(
        &mut self,
        route: PreparedElasticRoute,
        membership: MembershipKey,
        level: usize,
    ) {
        let words = self.membership.words;
        if words != 0 {
            let word = MembershipKey::word(route.signature(), words);
            // SAFETY: `word < words` indexes an initialized word; `&mut self`
            // makes the borrow exclusive.
            let metadata = unsafe { &mut *self.membership_ptr().add(word) };
            metadata.membership |= membership.bits();
            metadata.route_bins[route.summary_bin()] |= 1_u16 << summary_level(level);
        }
    }

    fn clear_membership(&mut self) {
        // SAFETY: `self.membership` was laid out together with `self.arena`.
        unsafe {
            self.membership
                .clear::<ElasticMetadataWord>(self.arena.as_ptr());
        }
        self.stale_membership = 0;
    }

    fn copy_membership_from(&mut self, source: &Self) {
        // SAFETY: each region was laid out for its own table's arena, so the two
        // never overlap; clones share geometry, so word counts match.
        unsafe {
            self.membership.copy_from::<ElasticMetadataWord>(
                self.arena.as_ptr(),
                source.membership,
                source.arena.as_ptr(),
            );
        };
    }

    fn clear(&mut self) {
        for level in &mut self.levels {
            level.drain_reset(|entry| {
                self.len -= 1;
                drop(entry);
            });
        }
        debug_assert_eq!(self.len, 0);
        self.reset_after_clear();
    }

    /// Resets placement, lookup, and filter state once every level is empty.
    fn reset_after_clear(&mut self) {
        self.scheduler.reset();
        self.probe_high_water = 0;
        self.probe_schedule.clear();
        self.clear_membership();
        self.epoch.start(EpochTransition::Clear);
    }

    /// Post-lookup insert for a key known to be absent. Returns the chosen
    /// slot so the caller can borrow into it without re-probing.
    fn insert_for_vacant_entry(&mut self, key: K, value: V, key_hash: u64) -> (usize, usize) {
        let prepared = PreparedElasticKey::new(key_hash);
        let key_fingerprint = control::control_fingerprint(key_hash);
        self.insert_for_vacant_entry_prepared(key, value, prepared, key_fingerprint)
    }

    fn insert_for_vacant_entry_prepared(
        &mut self,
        key: K,
        value: V,
        prepared: PreparedElasticKey,
        key_fingerprint: u8,
    ) -> (usize, usize) {
        if self.len >= self.max_insertions {
            let new_cap = if self.total_slots == 0 {
                INITIAL_CAPACITY
            } else {
                self.total_slots.saturating_mul(2)
            };
            self.resize_with_transition(new_cap, EpochTransition::Growth);
        }

        let target = self.scheduler.target(self.len);
        if let Some(placement) = self.choose_slot_for_new_key(prepared.route.probe, target) {
            return self.place_new_entry(key, value, prepared, key_fingerprint, placement);
        }
        self.place_after_target_failure(key, value, prepared, key_fingerprint, target)
    }

    /// Places a key whose active batch target has no slot: another target,
    /// then a same-size rebuild, then exceptional placement. Kept out of line
    /// so the common path inlines as a single target attempt.
    #[cold]
    #[inline(never)]
    fn place_after_target_failure(
        &mut self,
        key: K,
        value: V,
        prepared: PreparedElasticKey,
        key_fingerprint: u8,
        target: BatchTarget,
    ) -> (usize, usize) {
        if let Some(placement) = self.choose_slot_on_other_targets(prepared.route.probe, target) {
            return self.place_new_entry(key, value, prepared, key_fingerprint, placement);
        }
        // An epoch that already placed outside its probe routes failed its
        // own rebuild; another would cost O(n) per insert without helping.
        if self.probe_high_water & EXCEPTIONAL_PLACEMENT_FLAG != 0 {
            self.epoch.note_placement_recovery();
            return self.place_exceptional_entry(key, value, prepared, key_fingerprint);
        }
        self.resize_with_transition(self.total_slots, EpochTransition::PlacementRecovery);
        let target = self.scheduler.target(self.len);
        if let Some(placement) = self.choose_slot_for_new_key(prepared.route.probe, target) {
            self.place_new_entry(key, value, prepared, key_fingerprint, placement)
        } else {
            self.place_exceptional_entry(key, value, prepared, key_fingerprint)
        }
    }

    /// Write a new entry and update placement and batch metadata.
    #[inline]
    fn place_new_entry(
        &mut self,
        key: K,
        value: V,
        prepared: PreparedElasticKey,
        key_fingerprint: u8,
        placement: ExactPlacement,
    ) -> (usize, usize) {
        self.extend_probe_schedule(placement.phi);
        self.write_new_entry(
            key,
            value,
            prepared,
            key_fingerprint,
            placement.level,
            placement.slot,
        )
    }

    #[cold]
    fn place_exceptional_entry(
        &mut self,
        key: K,
        value: V,
        prepared: PreparedElasticKey,
        key_fingerprint: u8,
    ) -> (usize, usize) {
        let (level, slot) = self
            .first_free_slot()
            .expect("Elastic insertion limit must leave a free slot");
        self.probe_high_water |= EXCEPTIONAL_PLACEMENT_FLAG;
        self.write_new_entry(key, value, prepared, key_fingerprint, level, slot)
    }

    fn first_free_slot(&self) -> Option<(usize, usize)> {
        self.levels
            .iter()
            .enumerate()
            .find_map(|(level_index, level)| {
                (0..level.capacity())
                    // SAFETY: `slot` ranges over the level's capacity.
                    .find(|&slot| control::is_free(unsafe { level.control_at(slot) }))
                    .map(|slot| (level_index, slot))
            })
    }

    #[inline]
    fn write_new_entry(
        &mut self,
        key: K,
        value: V,
        prepared: PreparedElasticKey,
        key_fingerprint: u8,
        level_idx: usize,
        slot_idx: usize,
    ) -> (usize, usize) {
        {
            let level = &mut self.levels[level_idx];
            // SAFETY: callers pass a free slot found within this level.
            let prev_ctrl = unsafe { level.control_at(slot_idx) };
            // SAFETY: as above; `key_fingerprint` is an occupied control byte.
            unsafe {
                level.write_with_control(slot_idx, SlotEntry { key, value }, key_fingerprint);
            }
            level.len += 1;
            if prev_ctrl == CTRL_TOMBSTONE {
                level.tombstones -= 1;
            }
        }
        self.record_membership(prepared.route, prepared.membership, level_idx);
        self.len += 1;
        (level_idx, slot_idx)
    }

    fn extend_probe_schedule(&mut self, high_water: u128) {
        assert!(
            high_water <= QUERY_POSITION_CAP,
            "Elastic query-position convention exhausted"
        );
        let prior_high_water = self.probe_high_water & !EXCEPTIONAL_PLACEMENT_FLAG;
        if high_water <= u128::from(prior_high_water) {
            return;
        }
        let old_len = self.probe_schedule.len();
        for level in 0..self.levels.len() {
            let from_probe =
                first_paper_probe_after(level as u128 + 1, u128::from(prior_high_water));
            for_each_phi_route(level, from_probe, high_water, |paper_probe, phi| {
                let logical_probe_index =
                    u64::try_from(paper_probe - 1).expect("Elastic probe cap fits u64");
                assert!(
                    usize::try_from(logical_probe_index)
                        .is_ok_and(|index| index < QUERY_PROBE_LIMIT),
                    "Elastic query-probe convention exhausted"
                );
                let counter_base =
                    probe::try_pack_elastic_counter(level as u64, logical_probe_index, 0)
                        .expect("Elastic query tuple fits the production counter");
                self.probe_schedule.push(PhiRoute {
                    range_upper: u32::try_from(phi).expect("Elastic query cap fits u32"),
                    counter_base,
                });
            });
        }
        self.probe_schedule[old_len..].sort_unstable_by_key(|route| route.range_upper);
        for route in &mut self.probe_schedule[old_len..] {
            route.range_upper = self.levels[route.level()].capacity;
        }
        self.probe_high_water = (self.probe_high_water & EXCEPTIONAL_PLACEMENT_FLAG)
            | u32::try_from(high_water).expect("Elastic query cap fits u32");
    }
}

#[allow(private_interfaces)]
impl<K, V, S, A> map::TableBackend<K, V> for ElasticTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Location = (usize, usize);
    type Vacant = u64;
    type Hasher = S;
    type Alloc = A;

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
    fn reserve_config(&self) -> ReserveFraction {
        self.reserve_fraction
    }

    fn epoch_snapshot(&self) -> EpochSnapshot {
        self.epoch.snapshot(self.len)
    }

    #[inline]
    unsafe fn slot_ref(&self, (level_idx, slot_idx): (usize, usize)) -> &SlotEntry<K, V> {
        // SAFETY: caller passes a live location: occupied and in bounds.
        unsafe { self.levels[level_idx].get_ref(slot_idx) }
    }

    /// Projects through raw pointers from `&self.levels`, forming no
    /// intermediate `&mut Level`, so distinct locations yield non-aliasing
    /// `*mut`.
    #[inline]
    unsafe fn slot_ptr(&self, (level_idx, slot_idx): (usize, usize)) -> *mut SlotEntry<K, V> {
        let levels_ptr: *const Level<SlotEntry<K, V>> = self.levels.as_ptr();
        // SAFETY: shared `&Level` only — never `&mut` — so no aliasing tag.
        let level = unsafe { &*levels_ptr.add(level_idx) };
        // SAFETY: caller passes a live location, so `slot_idx` is in bounds.
        unsafe { level.slot_ptr(slot_idx) }
    }

    #[inline]
    fn replace_value(&mut self, (level_idx, slot_idx): (usize, usize), value: V) -> V {
        // SAFETY: `Location` contract: a valid location is occupied and in bounds.
        let slot = unsafe { self.levels[level_idx].get_mut(slot_idx) };
        mem::replace(&mut slot.value, value)
    }

    #[inline]
    fn find<Q>(&self, key: &Q, hash: u64) -> Option<(usize, usize)>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find_slot_indices_prepared(
            key,
            PreparedElasticKey::new(hash),
            control::control_fingerprint(hash),
        )
    }

    #[inline]
    fn find_entry<'a, Q>(&'a self, key: &Q, hash: u64) -> Option<&'a SlotEntry<K, V>>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find_entry_prepared(
            key,
            PreparedElasticKey::new(hash),
            control::control_fingerprint(hash),
        )
    }

    #[inline]
    fn find_for_entry<Q>(&self, key: &Q, hash: u64) -> Result<Self::Location, u64>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find(key, hash).ok_or(hash)
    }

    #[inline]
    fn insert_for_vacant(&mut self, key: K, value: V, hash: u64) -> (usize, usize) {
        self.insert_for_vacant_entry(key, value, hash)
    }

    #[inline]
    fn insert(&mut self, key: K, value: V, hash: u64) -> Option<V>
    where
        K: Hash + Eq,
    {
        let prepared = PreparedElasticKey::new(hash);
        let key_fingerprint = control::control_fingerprint(hash);
        // `find_slot_indices_prepared` applies the same filter from the metadata
        // word it already reads, so this path pays no separate pre-check load.
        if let Some(location) = self.find_slot_indices_prepared(&key, prepared, key_fingerprint) {
            return Some(self.replace_value(location, value));
        }
        self.insert_for_vacant_entry_prepared(key, value, prepared, key_fingerprint);
        None
    }

    fn remove(&mut self, (level_idx, slot_idx): (usize, usize)) -> (K, V) {
        // SAFETY: `TableBackend::Location` contract: a live location from
        // this table names an occupied in-bounds slot.
        let removed = unsafe { self.levels[level_idx].take(slot_idx) };
        self.extract_finish((level_idx, slot_idx));
        self.settle_after_deletes(self.levels[level_idx].needs_cleanup());
        (removed.key, removed.value)
    }

    #[inline]
    fn tombstone_slot(&mut self, (level_idx, slot_idx): (usize, usize)) {
        // SAFETY: a live location names an in-bounds slot.
        unsafe { self.levels[level_idx].mark_tombstone(slot_idx) };
    }

    #[inline]
    fn extract_finish(&mut self, (level_idx, slot_idx): (usize, usize)) {
        {
            let level = &mut self.levels[level_idx];
            // SAFETY: a live location names an in-bounds slot.
            unsafe { level.mark_tombstone(slot_idx) };
            level.len -= 1;
            level.tombstones += 1;
        }
        self.len -= 1;
        self.stale_membership += 1;
        self.epoch.note_delete();
    }

    fn finish_deferred_removals(&mut self) {
        self.settle_after_deletes(self.levels.iter().any(Level::needs_cleanup));
    }

    type Scan = ElasticScan;

    #[inline]
    fn scan(&self) -> ElasticScan {
        ElasticScan {
            level_idx: 0,
            slots: OccupiedIndices::new(),
        }
    }

    #[inline]
    fn scan_next(&self, scan: &mut ElasticScan) -> Option<ElasticScanItem<K, V>> {
        while let Some(level) = self.levels.get(scan.level_idx) {
            if let Some(slot_idx) = scan.slots.step(level) {
                // SAFETY: `step` yields in-bounds slots.
                let slot = unsafe { level.slot_ptr(slot_idx) };
                return Some((slot, (scan.level_idx, slot_idx)));
            }
            scan.level_idx += 1;
            scan.slots = OccupiedIndices::new();
        }
        None
    }

    #[inline]
    fn with_capacity_and_reserve_and_hasher_in(
        capacity: usize,
        reserve_fraction: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Self {
        Self::with_capacity_and_reserve_and_hasher_in(
            capacity,
            reserve_fraction,
            hash_builder,
            alloc,
        )
    }

    #[inline]
    fn try_with_capacity_and_reserve_and_hasher_in(
        capacity: usize,
        reserve_fraction: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryBuildError> {
        Self::try_with_capacity_and_reserve_and_hasher_in(
            capacity,
            reserve_fraction,
            hash_builder,
            alloc,
        )
    }

    #[inline]
    fn resize(&mut self, new_capacity: usize) {
        self.resize(new_capacity);
    }

    #[inline]
    fn try_resize(&mut self, new_capacity: usize) -> Result<(), TryReserveError> {
        self.try_resize(new_capacity)
    }

    #[inline]
    fn clear(&mut self) {
        self.clear();
    }

    fn wipe_all(&mut self) {
        for level in &mut self.levels {
            level.clear_all_controls();
            level.len = 0;
            level.tombstones = 0;
        }
        self.len = 0;
        self.reset_after_clear();
    }

    fn clone_table(&self) -> Self
    where
        K: Clone,
        V: Clone,
        S: Clone,
    {
        let scheduler = self.scheduler.clone();
        let hash_builder = self.hash_builder.clone();
        let alloc = self.alloc.clone();
        let mut probe_schedule = Vec::with_capacity(PROBE_SCHEDULE_CAPACITY[self.levels.len()]);
        probe_schedule.extend_from_slice(&self.probe_schedule);
        let level_capacities = PlanBuffer::from_iter(self.levels.iter().map(ArenaSlots::capacity));
        let (arena, levels, membership) = alloc_elastic_arena(&level_capacities, &self.alloc);

        // If a user `K::clone` / `V::clone` panics, the guard drops the
        // already-cloned values and frees the arena; see `ArenaDropGuard`.
        let mut guard = arena::ArenaDropGuard::new(arena, levels, self.alloc.clone());

        for (dst, src_lvl) in guard.regions_mut().iter_mut().zip(self.levels.iter()) {
            dst.clone_region_from(src_lvl);
            dst.len = src_lvl.len;
            dst.tombstones = src_lvl.tombstones;
        }

        // Success: reclaim arena + levels so the guard's Drop no-ops.
        let (arena, levels) = guard.disarm();

        let mut cloned = Self {
            levels,
            len: self.len,
            total_slots: self.total_slots,
            max_insertions: self.max_insertions,
            reserve_fraction: self.reserve_fraction,
            scheduler,
            hash_builder,
            alloc,
            arena,
            epoch: self.epoch,
            probe_high_water: self.probe_high_water,
            probe_schedule,
            membership,
            stale_membership: self.stale_membership,
        };
        cloned.copy_membership_from(self);
        cloned
    }
}

/// Track a pointerless scan across elastic levels.
#[derive(Clone, Debug)]
pub struct ElasticScan {
    level_idx: usize,
    slots: OccupiedIndices,
}

impl<K, V, S, A> ElasticTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    /// Same-size cleanup when a level passed its tombstone threshold; otherwise
    /// a filter refresh once departed keys passed theirs. The cleanup rebuilds
    /// the filter too, so the two never stack.
    fn settle_after_deletes(&mut self, needs_cleanup: bool) {
        if needs_cleanup {
            self.resize_with_transition(self.total_slots, EpochTransition::TombstoneCleanup);
        } else if self.stale_membership > membership::refresh_deletes(self.max_insertions) {
            self.refresh_membership();
        }
    }

    /// Re-record the filter from the live entries, dropping the bits departed
    /// keys left behind. Entries stay put; only the metadata tail is rewritten.
    #[cold]
    #[inline(never)]
    fn refresh_membership(&mut self) {
        self.clear_membership();
        for level_idx in 0..self.levels.len() {
            let mut scan = OccupiedIndices::new();
            while let Some(slot_idx) = scan.step(&self.levels[level_idx]) {
                let hash = {
                    // SAFETY: `step` yields occupied in-bounds slots.
                    let entry = unsafe { self.levels[level_idx].get_ref(slot_idx) };
                    self.hash_builder.hash_one(&entry.key)
                };
                let prepared = PreparedElasticKey::new(hash);
                self.record_membership(prepared.route, prepared.membership, level_idx);
            }
        }
    }

    /// Rebuilds levels at `new_capacity` and moves every live entry across.
    /// Passing the current capacity flushes tombstones without growing.
    fn resize(&mut self, new_capacity: usize) {
        self.resize_with_transition(new_capacity, EpochTransition::ExplicitResize);
    }

    fn resize_with_transition(&mut self, new_capacity: usize, transition: EpochTransition) {
        let geometry = ElasticGeometry::for_slots(new_capacity, self.reserve_fraction)
            .expect("capacity overflow");
        if self.try_resize_to(&geometry, transition).is_err() {
            handle_elastic_alloc_error::<K, V>(&geometry.level_capacities);
        }
    }

    /// Moves every entry into fresh levels for `geometry`. Each key is hashed
    /// in place before its entry is copied, and the old levels are freed only
    /// after the last copy, so `Err` or a panicking hasher leaves the table
    /// intact.
    fn try_resize_to(
        &mut self,
        geometry: &ElasticGeometry,
        transition: EpochTransition,
    ) -> Result<(), TryReserveError> {
        let probe_schedule = try_probe_schedule(geometry.level_capacities.len())?;
        let (arena, levels, membership) =
            try_alloc_elastic_arena(&geometry.level_capacities, &self.alloc)?;
        let used_exceptional_placement = rebuild::rebuild(
            self,
            ElasticGeneration {
                levels,
                len: 0,
                total_slots: geometry.total_slots,
                max_insertions: geometry.max_insertions,
                scheduler: BatchScheduler::new(&geometry.batch_plan),
                arena,
                probe_high_water: 0,
                probe_schedule,
                membership,
                stale_membership: 0,
            },
        );
        self.epoch.start_epoch(
            transition,
            transition == EpochTransition::PlacementRecovery || used_exceptional_placement,
        );
        Ok(())
    }

    /// Fallible counterpart to [`Self::resize`]; `Err` leaves the map intact.
    fn try_resize(&mut self, new_capacity: usize) -> Result<(), TryReserveError> {
        let geometry = ElasticGeometry::for_slots(new_capacity, self.reserve_fraction)
            .ok_or(TryReserveError::CapacityOverflow)?;
        self.try_resize_to(&geometry, EpochTransition::ExplicitResize)
    }

    /// Test constructor taking a raw slot count; public constructors take an
    /// insertion budget and inflate it via `capacity_for`.
    #[cfg(test)]
    fn try_with_slots_and_reserve_fraction_and_hasher_in(
        slots: usize,
        reserve_fraction: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryReserveError> {
        let geometry = ElasticGeometry::for_slots(slots, reserve_fraction)
            .ok_or(TryReserveError::CapacityOverflow)?;
        Self::try_from_geometry(&geometry, reserve_fraction, hash_builder, alloc)
    }

    /// Retries placement on every other batch target, shallowest first.
    /// Batches follow the live count, so after deletes the active pair can be
    /// one that earlier batches filled while other levels have room again.
    /// Insert-only traces never fail their active pair, so they never get here.
    fn choose_slot_on_other_targets(
        &self,
        probe: PreparedElasticProbe,
        target: BatchTarget,
    ) -> Option<ExactPlacement> {
        let has_room = |level: usize| self.levels.get(level).is_some_and(|l| l.free_slots() > 0);
        let pairs = self.levels.len().saturating_sub(1);
        core::iter::once(BatchTarget::Bootstrap)
            .chain((0..pairs).map(BatchTarget::LevelPair))
            .filter(|&candidate| candidate != target)
            .filter(|&candidate| match candidate {
                BatchTarget::Bootstrap => has_room(0),
                BatchTarget::LevelPair(current) => has_room(current) || has_room(current + 1),
            })
            .find_map(|candidate| self.choose_slot_for_new_key(probe, candidate))
    }

    fn choose_slot_for_new_key(
        &self,
        probe: PreparedElasticProbe,
        target: BatchTarget,
    ) -> Option<ExactPlacement> {
        if self.levels.is_empty() {
            return None;
        }
        // The paper's insertion cases, in order: Batch 0 fills level 0; then,
        // for the active pair, Case 2 (current nearly full) places in `next`,
        // Case 3 (next nearly full) in `current`, and Case 1 gives `current`
        // a bounded probe budget before falling back to `next`.
        let (level, slot, paper_probe) = match target {
            BatchTarget::Bootstrap => {
                let (slot, paper_probe) = self.uniform_vacancy(probe, 0)?;
                (0, slot, paper_probe)
            }
            BatchTarget::LevelPair(current) => {
                let next = current.checked_add(1)?;
                let current_level = self.levels.get(current)?;
                let next_level = self.levels.get(next)?;
                let free_current = current_level.free_slots();
                let free_next = next_level.free_slots();
                let current_low = free_current
                    <= self
                        .reserve_fraction
                        .floor_half_reserved(current_level.capacity());
                let next_low = free_next.saturating_mul(4) <= next_level.capacity();

                if current_low {
                    let (slot, paper_probe) = self.uniform_vacancy(probe, next)?;
                    (next, slot, paper_probe)
                } else if next_low {
                    let (slot, paper_probe) = self.uniform_vacancy(probe, current)?;
                    (current, slot, paper_probe)
                } else {
                    let budget = probe::elastic_dyadic_probe_budget(
                        free_current,
                        current_level.capacity(),
                        self.reserve_fraction.exponent(),
                        ELASTIC_PROBE_BUDGET_C,
                    )
                    .ok()?;
                    let budget = u64::try_from(budget)
                        .unwrap_or(u64::MAX)
                        .min(LEVEL_PROBE_LIMIT[current]);
                    if let Some((slot, probe)) = (0..budget).find_map(|logical_index| {
                        self.vacancy(current, probe, logical_index)
                            .map(|slot| (slot, logical_index + 1))
                    }) {
                        (current, slot, probe)
                    } else {
                        let (slot, paper_probe) = self.uniform_vacancy(probe, next)?;
                        (next, slot, paper_probe)
                    }
                }
            }
        };
        let paper_level = u32::try_from(level.checked_add(1)?).ok()?;
        let phi = u128::from(probe::elastic_phi_bounded(paper_level, paper_probe)?);
        if phi > QUERY_POSITION_CAP {
            return None;
        }
        Some(ExactPlacement { level, slot, phi })
    }

    fn uniform_vacancy(&self, probe: PreparedElasticProbe, level: usize) -> Option<(usize, u64)> {
        for logical_index in 0..LEVEL_PROBE_LIMIT[level] {
            if let Some(slot) = self.vacancy(level, probe, logical_index) {
                return Some((slot, logical_index + 1));
            }
        }
        None
    }

    fn vacancy(
        &self,
        level: usize,
        probe: PreparedElasticProbe,
        logical_index: u64,
    ) -> Option<usize> {
        let slot = self.route_prepared(level, probe, logical_index)?;
        // SAFETY: `route_prepared` maps into the level's capacity.
        control::is_free(unsafe { self.levels[level].control_at(slot) }).then_some(slot)
    }

    fn route_prepared(
        &self,
        level: usize,
        probe: PreparedElasticProbe,
        logical_index: u64,
    ) -> Option<usize> {
        let level = u32::try_from(level).ok()?;
        let counter_base = probe::elastic_counter_base(level, logical_index);
        self.route_prepared_counter(level as usize, probe, counter_base)
    }

    #[inline]
    fn route_prepared_counter(
        &self,
        level: usize,
        probe: PreparedElasticProbe,
        counter_base: u32,
    ) -> Option<usize> {
        let upper = self.levels.get(level)?.capacity();
        Self::route_prepared_counter_for_upper(probe, counter_base, upper)
    }

    #[inline]
    fn route_prepared_counter_for_upper(
        prepared: PreparedElasticProbe,
        counter_base: u32,
        upper: usize,
    ) -> Option<usize> {
        probe::unbiased_prepared_elastic_probe_index(
            prepared,
            counter_base,
            upper,
            probe::RANGE_WORD_CAP,
        )
        .ok()
        .map(|probe| probe.index)
    }

    #[inline]
    fn find_slot_indices_prepared<Q>(
        &self,
        key: &Q,
        prepared: PreparedElasticKey,
        key_fingerprint: u8,
    ) -> Option<(usize, usize)>
    where
        Q: Equivalent<K> + ?Sized,
    {
        self.find_by_exact_schedule(key, prepared, key_fingerprint, |level, slot, _entry| {
            (level, slot)
        })
    }

    #[inline]
    fn find_entry_prepared<'a, Q>(
        &'a self,
        key: &Q,
        prepared: PreparedElasticKey,
        key_fingerprint: u8,
    ) -> Option<&'a SlotEntry<K, V>>
    where
        Q: Equivalent<K> + ?Sized,
    {
        self.find_by_exact_schedule(key, prepared, key_fingerprint, |_level, _slot, entry| entry)
    }

    fn find_by_exact_schedule<'a, Q, R>(
        &'a self,
        key: &Q,
        prepared: PreparedElasticKey,
        key_fingerprint: u8,
        mut on_hit: impl FnMut(usize, usize, &'a SlotEntry<K, V>) -> R,
    ) -> Option<R>
    where
        Q: Equivalent<K> + ?Sized,
    {
        if self.len == 0 || self.levels.is_empty() {
            return None;
        }
        let Some(h11_slot) = Self::route_prepared_counter_for_upper(
            prepared.route.probe,
            H11_COUNTER_BASE,
            self.levels[0].capacity(),
        ) else {
            return self.find_by_full_scan(key, key_fingerprint, on_hit);
        };
        // The metadata load is issued while the level-zero control byte is still
        // in flight: neither depends on the other.
        let filter = self.route_filter(prepared);
        // SAFETY: the counter route maps into level zero's capacity.
        if let Some(entry) = unsafe { self.entry_if_match(0, h11_slot, key_fingerprint, key) } {
            return Some(on_hit(0, h11_slot, entry));
        }
        // A key the filter never recorded was never inserted, so neither the
        // remaining candidates nor the exceptional full scan can hold it.
        if !filter.maybe_present {
            return None;
        }

        let level_mask = filter.expanded_level_mask();
        for route in &self.probe_schedule {
            let level = route.level();
            if level_mask & (1_u32 << level) == 0 {
                continue;
            }
            let upper = route.range_upper as usize;
            let Some(slot) = Self::route_prepared_counter_for_upper(
                prepared.route.probe,
                route.counter_base,
                upper,
            ) else {
                return self.find_by_full_scan(key, key_fingerprint, on_hit);
            };
            // SAFETY: schedule routes name real levels and map below
            // `range_upper`, which is within that level's capacity.
            if let Some(entry) = unsafe { self.entry_if_match(level, slot, key_fingerprint, key) } {
                return Some(on_hit(level, slot, entry));
            }
        }
        if self.probe_high_water & EXCEPTIONAL_PLACEMENT_FLAG != 0 {
            self.find_by_full_scan(key, key_fingerprint, on_hit)
        } else {
            None
        }
    }

    fn find_by_full_scan<'a, Q, R>(
        &'a self,
        key: &Q,
        key_fingerprint: u8,
        mut on_hit: impl FnMut(usize, usize, &'a SlotEntry<K, V>) -> R,
    ) -> Option<R>
    where
        Q: Equivalent<K> + ?Sized,
    {
        for (level_index, level) in self.levels.iter().enumerate() {
            for slot in 0..level.capacity() {
                if let Some(entry) =
                    // SAFETY: both indices come from iterating the levels.
                    unsafe { self.entry_if_match(level_index, slot, key_fingerprint, key) }
                {
                    return Some(on_hit(level_index, slot, entry));
                }
            }
        }
        None
    }

    /// # Safety
    ///
    /// `level < self.levels.len()` and `slot` is within that level's capacity.
    #[inline]
    unsafe fn entry_if_match<'a, Q>(
        &'a self,
        level: usize,
        slot: usize,
        key_fingerprint: u8,
        key: &Q,
    ) -> Option<&'a SlotEntry<K, V>>
    where
        Q: Equivalent<K> + ?Sized,
    {
        debug_assert!(level < self.levels.len());
        // SAFETY: caller keeps `level` and `slot` in bounds; a fingerprint
        // match means the slot is occupied.
        unsafe {
            let level = self.levels.get_unchecked(level);
            if level.control_at(slot) != key_fingerprint {
                return None;
            }
            let entry = level.get_ref(slot);
            key.equivalent(&entry.key).then_some(entry)
        }
    }
}

fn first_paper_probe_after(paper_level: u128, position: u128) -> u128 {
    let mut lower = 1_u128;
    let mut upper = u128::from(UNIFORM_SEARCH_CAP) + 1;
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        let phi =
            probe::elastic_phi(paper_level, middle).expect("bounded Elastic query coordinate");
        if phi <= position {
            lower = middle + 1;
        } else {
            upper = middle;
        }
    }
    lower
}

#[cfg(test)]
impl<K, V, S, A> ElasticTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    fn route_exact(&self, level: usize, key_hash: u64, logical_index: u64) -> Option<usize> {
        let probe = CounterPrf::new(ELASTIC_PROBE_SEED).prepare_elastic(key_hash);
        self.levels.get(level)?;
        self.route_prepared(level, probe, logical_index)
    }
}

/// The fields a resize replaces as a unit.
pub(crate) struct ElasticGeneration<K, V> {
    levels: LevelSlice<K, V>,
    len: usize,
    total_slots: usize,
    max_insertions: usize,
    scheduler: BatchScheduler,
    arena: Arena,
    probe_high_water: u32,
    probe_schedule: Vec<PhiRoute>,
    membership: MembershipRegion,
    stale_membership: usize,
}

impl<K, V, S, A> Rebuildable for ElasticTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Key = K;
    type Value = V;
    type Region = Level<SlotEntry<K, V>>;
    type Generation = ElasticGeneration<K, V>;

    fn swap_generation(&mut self, other: &mut ElasticGeneration<K, V>) {
        mem::swap(&mut self.levels, &mut other.levels);
        mem::swap(&mut self.len, &mut other.len);
        mem::swap(&mut self.total_slots, &mut other.total_slots);
        mem::swap(&mut self.max_insertions, &mut other.max_insertions);
        mem::swap(&mut self.scheduler, &mut other.scheduler);
        mem::swap(&mut self.arena, &mut other.arena);
        mem::swap(&mut self.probe_high_water, &mut other.probe_high_water);
        mem::swap(&mut self.probe_schedule, &mut other.probe_schedule);
        mem::swap(&mut self.membership, &mut other.membership);
        mem::swap(&mut self.stale_membership, &mut other.stale_membership);
    }

    fn regions(generation: &ElasticGeneration<K, V>) -> &[Level<SlotEntry<K, V>>] {
        &generation.levels
    }

    fn release(&self, generation: ElasticGeneration<K, V>) {
        generation.arena.deallocate(&self.alloc);
    }

    fn hash_key(&self, key: &K) -> u64 {
        self.hash_builder.hash_one(key)
    }

    /// Skips the existence and capacity checks in `insert`: the new
    /// generation starts all-EMPTY, so neither can succeed.
    #[inline]
    fn place_unique(&mut self, entry: SlotEntry<K, V>, key_hash: u64) -> bool {
        let prepared = PreparedElasticKey::new(key_hash);
        let key_fingerprint = control::control_fingerprint(key_hash);
        let target = self.scheduler.target(self.len);
        if let Some(placement) = self.choose_slot_for_new_key(prepared.route.probe, target) {
            self.place_new_entry(entry.key, entry.value, prepared, key_fingerprint, placement);
            false
        } else {
            self.place_exceptional_entry(entry.key, entry.value, prepared, key_fingerprint);
            true
        }
    }
}

#[cfg(test)]
mod tests;
