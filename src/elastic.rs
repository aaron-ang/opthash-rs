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
use crate::membership::{self, MembershipKey, MembershipRegion, MetadataWord};
use crate::raw::arena::{self, Arena, ArenaSlots, SlotEntry};
use crate::raw::config::INITIAL_CAPACITY;
use crate::raw::control::{self, CTRL_EMPTY, CTRL_TOMBSTONE};
use crate::raw::iter::OccupiedIndices;
use crate::raw::prefetch;
use crate::raw::rebuild::{self, Rebuildable};

mod schedule;

use schedule::{ProbeSchedule, ProbeScheduleRoom, SENTINEL_LEVEL};

/// `(slot pointer, location)` yielded by the scan cursor: the pointer is read
/// by iterators, the `(level, slot)` location backs removal.
type ElasticScanItem<K, V> = (*mut SlotEntry<K, V>, (usize, usize));

/// Fixed construction seed shared by placement, lookup, and membership.
/// Zero keeps the routing signature the key's hash itself; the probe words
/// are keyed by their fold multiplier.
const ELASTIC_PROBE_SEED: u64 = 0;
/// The paper's constant `c` in the per-level probe budget
/// `c * min(log2(1/eps)^2, log2(1/delta))`; the paper only asks that it be
/// sufficiently large.
const ELASTIC_PROBE_BUDGET_C: usize = 8;
/// Most probe indices any level's search visits. The paper's fallback search
/// is unbounded; this caps it so the lookup schedule stays finite.
const UNIFORM_SEARCH_CAP: u64 = 4_096;
/// Largest paper query position a placement may take. The lookup schedule
/// covers every position up to it, so a vacancy past it counts as a failed
/// probe.
const QUERY_POSITION_CAP: u128 = 1_000_000;
/// Top bit of `probe_high_water`, set once this epoch placed an entry outside
/// its probe routes; lookups that miss the schedule then fall back to a full
/// scan.
const EXCEPTIONAL_PLACEMENT_FLAG: u32 = 1 << 31;
/// Bound on a level's probe index within `QUERY_POSITION_CAP`. Level one
/// reaches the most probes before its positions pass the cap.
const QUERY_PROBE_LIMIT: usize = 384;
/// Largest table: slot positions and schedule bounds are stored as `u32`.
const MAX_ELASTIC_SLOTS: u64 = 1 << u32::BITS;
/// Levels a key's route summary tracks, one `u16` bit each; the last bit
/// stands for every deeper level.
const ROUTE_SUMMARY_LEVELS: usize = u16::BITS as usize;
/// Bits each key sets in its membership-filter word. A lookup whose bits are
/// not all set skips the probe walk, since the key cannot be present. A false
/// positive walks every level's full schedule, so a third bit rejects enough
/// extra misses to outweigh its cost.
const MEMBERSHIP_BITS: usize = 3;
/// Counter base of level zero's first probe, which lookups route ahead of
/// the schedule.
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
    /// One-based probe of `level` that reached the slot.
    paper_probe: u64,
}

impl ExactPlacement {
    /// Paper position of the chosen slot, `elastic_phi(level + 1, probe)`;
    /// the lookup schedule is extended to cover it.
    fn phi(self) -> u128 {
        let paper_level = u32::try_from(self.level + 1).expect("Elastic level count fits u32");
        probe::elastic_phi_bounded(paper_level, self.paper_probe)
            .map(u128::from)
            .expect("bounded Elastic query coordinate")
    }
}

const _: () = assert!(GENERAL_REDUCTION <= u8::MAX as u32);
const _: () = assert!(UNIFORM_SEARCH_CAP <= u16::MAX as u64);
const _: () = assert!(MAX_LEVELS <= SENTINEL_LEVEL as usize);

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
    /// [`probe::elastic_index_shift`] of `capacity`, or [`GENERAL_REDUCTION`]
    /// when any level of the table has no such shift. A table's levels
    /// therefore reduce all by shift or all by the general reduction, and
    /// level zero answers which for the whole table.
    index_shift: u16,
    /// Leading paper probes of this level the lookup schedule covers: a
    /// placement within them needs no schedule extension. Zero for a level
    /// the schedule holds no routes for.
    scheduled_probes: u16,
}

/// [`Level::index_shift`] of every level in a table that has a level whose
/// probes need the general range reduction.
const GENERAL_REDUCTION: u32 = u64::BITS;

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
    fn new_at(
        cap_u32: u32,
        index_shift: u32,
        ctrl_ptr: *mut u8,
        data_ptr: *mut MaybeUninit<T>,
    ) -> Self {
        Self {
            ctrl_ptr,
            data_ptr,
            capacity: cap_u32,
            len: 0,
            tombstones: 0,
            index_shift: u16::try_from(index_shift).expect("Elastic index shift fits u16"),
            scheduled_probes: 0,
        }
    }

    #[inline]
    fn index_shift(&self) -> u32 {
        u32::from(self.index_shift)
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
    /// empty. Each moved slot becomes a counted tombstone before `visit`
    /// runs, and controls return to `EMPTY` only after the last entry, so a
    /// panic inside `visit` leaves the level as a run of removals would: the
    /// entries not yet visited stay live and counted, and no `EMPTY` slot
    /// appears ahead of one on its probe route.
    fn drain_reset(&mut self, mut visit: impl FnMut(T)) {
        let mut scan = OccupiedIndices::new();
        while let Some(slot) = scan.step(self) {
            // SAFETY: `step` yields occupied in-bounds slots; the value is
            // moved out before the slot is marked.
            let entry = unsafe { self.take(slot) };
            // SAFETY: `slot` is in bounds, as above.
            unsafe { self.mark_tombstone(slot) };
            self.len -= 1;
            self.tombstones += 1;
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
    /// Fixed for the allocation. The scheduler's settled limit is taken from
    /// it once, when the two are built ([`settled_limit`]).
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
    /// Levels the schedule holds routes for: every level up to the deepest
    /// one a placement of this epoch chose. A deeper level holds no entry, so
    /// lookups have nothing to visit there.
    scheduled_levels: u32,
    probe_schedule: ProbeSchedule,
    /// [`probe::ELASTIC_FOLD_MULTIPLIER`], kept in the table so the hot
    /// paths load it rather than build it.
    fold_multiplier: u64,
    /// Cached location of the metadata tail. See [`MembershipRegion`].
    membership: MembershipRegion,
    /// First word of the metadata tail, so the gate's address needs one load;
    /// [`NO_METADATA`] while `membership` has no words.
    metadata_words: *mut MetadataWord,
    /// Deletes since the filter last matched the live set; see
    /// [`membership::refresh_deletes`].
    stale_membership: usize,
}

// SAFETY: the table uniquely owns its arena and every entry in it, like
// `Box<[SlotEntry<K, V>]>`. Its raw pointers address that arena, except the
// schedule's sentinel route, which addresses an immutable static.
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

struct ElasticArenaLayout {
    layout: Layout,
    data_base_off: usize,
    membership: MembershipRegion,
}

fn elastic_arena_layout<K, V>(total_slots: usize) -> Result<ElasticArenaLayout, TryReserveError> {
    let (base_layout, data_base_off) = arena::layout_for::<K, V>(total_slots)?;
    let (layout, membership) = MembershipRegion::extend::<MetadataWord>(base_layout, total_slots)?;
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
            membership: MembershipKey::from_signature::<MEMBERSHIP_BITS>(route.signature()),
            route,
        }
    }
}

const _: () = assert!(mem::size_of::<PreparedElasticRoute>() == 8);
const _: () = assert!(mem::size_of::<PreparedElasticKey>() == 16);

/// Outcome of [`ElasticTable::search_schedule`].
enum ScheduleSearch<R> {
    Hit(R),
    Absent,
    /// The walk could not decide; carries the key's widened level mask for
    /// [`ElasticTable::find_by_general_schedule`].
    Unresolved(u32),
}

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
#[cfg(test)]
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

/// Routes a full schedule holds for `level`: its probes at positions up to
/// `QUERY_POSITION_CAP`, within `UNIFORM_SEARCH_CAP` probes, less level
/// zero's first, which is the direct slot.
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

/// [`BatchScheduler`]'s settled limit for a table of `levels` that takes
/// `max_insertions` entries.
fn settled_limit<T>(levels: &[Level<T>], max_insertions: usize) -> usize {
    match levels.first() {
        Some(level) if level.index_shift() != GENERAL_REDUCTION => max_insertions,
        _ => 0,
    }
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
    /// Live count below which [`ElasticTable::settled_placement`] can place: the
    /// table's insertion limit, or zero when its levels do not all reduce by
    /// shift.
    settled_limit: usize,
    /// Live counts from `batch_start` that are inside the cached batch and
    /// below `settled_limit`.
    settled_span: usize,
}

/// One of the paper's insertion cases, resolved against a table's levels.
struct PlacementCase<'a, K, V> {
    /// The level to search first.
    level: usize,
    region: &'a Level<SlotEntry<K, V>>,
    /// Probes of `level` to search.
    budget: u64,
    /// The level to search when the budget finds no slot.
    fallback: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BatchTarget {
    Bootstrap,
    LevelPair(usize),
}

impl BatchScheduler {
    pub(crate) fn new(batch_plan: &[usize], settled_limit: usize) -> Self {
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
            settled_limit,
            settled_span: settled_limit,
        };
        scheduler.reset();
        scheduler
    }

    /// The cached batch is current for `len` live entries and `len` is below
    /// the settled limit, in one compare: a `len` under `batch_start` wraps
    /// past any span.
    #[inline]
    fn settles(&self, len: usize) -> bool {
        len.wrapping_sub(self.batch_start) < self.settled_span
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
        if !self.covers(len) {
            self.sync(len);
        }
        self.cached_target()
    }

    /// The cached batch is the one a table holding `len` live entries is in.
    #[inline]
    fn covers(&self, len: usize) -> bool {
        len < self.batch_end && len >= self.batch_start
    }

    /// The target of the cached batch, which may trail `len` until the next
    /// [`Self::target`] re-syncs it.
    #[inline]
    fn cached_target(&self) -> BatchTarget {
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
        self.settled_span = self
            .batch_end
            .min(self.settled_limit)
            .saturating_sub(self.batch_start);
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
    let all_shift = level_capacities
        .iter()
        .all(|&cap| probe::elastic_index_shift(cap).is_some());
    for &cap in level_capacities {
        let cap_u32 = u32::try_from(cap).map_err(|_| TryReserveError::CapacityOverflow)?;
        let index_shift = match probe::elastic_index_shift(cap) {
            Some(shift) if all_shift => shift,
            _ => GENERAL_REDUCTION,
        };
        // SAFETY: the arena was allocated for the layout these caps sum to.
        let (ctrl_ptr, data_ptr) = unsafe { cursor.reserve(cap_u32)? };
        levels.push(Level::new_at(cap_u32, index_shift, ctrl_ptr, data_ptr));
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
    unsafe { membership.clear::<MetadataWord>(arena.as_ptr()) };

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

/// The word a table without a metadata tail reads: it records no key, so
/// the filter rejects every lookup without testing for the missing tail.
static NO_METADATA: MetadataWord = MetadataWord {
    level_bins: [0; 4],
    membership: 0,
};

/// First metadata word of `membership`'s tail inside `arena`, or
/// [`NO_METADATA`] when it has none. Only a tail with words is written to.
fn metadata_words(arena: &Arena, membership: MembershipRegion) -> *mut MetadataWord {
    if membership.words == 0 {
        return (&raw const NO_METADATA).cast_mut();
    }
    // SAFETY: `membership` was laid out together with `arena`.
    unsafe { membership.ptr::<MetadataWord>(arena.as_ptr()) }
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
        let schedule_room = ProbeScheduleRoom::try_with_capacity(
            PROBE_SCHEDULE_CAPACITY[geometry.level_capacities.len()],
        )?;
        let (arena, levels, membership) =
            try_alloc_elastic_arena(&geometry.level_capacities, &alloc)?;

        let settled_limit = settled_limit(&levels, geometry.max_insertions);
        let probe_schedule = schedule_room.schedule(&levels);
        Ok(Self {
            levels,
            len: 0,
            total_slots: geometry.total_slots,
            max_insertions: geometry.max_insertions,
            reserve_fraction,
            scheduler: BatchScheduler::new(&geometry.batch_plan, settled_limit),
            hash_builder,
            alloc,
            metadata_words: metadata_words(&arena, membership),
            arena,
            epoch: EpochState::initial(),
            probe_high_water: 0,
            scheduled_levels: 0,
            probe_schedule,
            fold_multiplier: probe::ELASTIC_FOLD_MULTIPLIER,
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
    fn membership_ptr(&self) -> *mut MetadataWord {
        self.metadata_words
    }

    /// Reads the membership scalar and selected route-summary bin directly:
    /// `maybe_present == false` proves the key was never recorded, and
    /// `level_mask` narrows the candidate levels. The two field loads avoid
    /// copying the whole metadata word for dynamic bin extraction.
    #[inline]
    fn route_filter(&self, prepared: PreparedElasticKey) -> ElasticRouteFilter {
        // Zero words reduce every signature to word zero, which is then
        // `NO_METADATA`: no bit is set there, so the filter rejects the key.
        let word = MembershipKey::word(prepared.route.signature(), self.membership.words);
        let summary_bin = prepared.route.summary_bin();
        let bits = prepared.membership.bits();
        debug_assert!(bits != 0);
        // SAFETY: `word` is a multiply-high reduction below the word count,
        // and the cached region covers exactly that many initialized,
        // properly aligned `MetadataWord`s; with no words it is zero and
        // `metadata_words` addresses the one word of `NO_METADATA`.
        let (membership, route_bin) = unsafe {
            let metadata = self.membership_ptr().add(word);
            ((*metadata).membership, (*metadata).level_bins[summary_bin])
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
            metadata.level_bins[route.summary_bin()] |= 1_u16 << summary_level(level);
        }
    }

    fn clear_membership(&mut self) {
        // SAFETY: `self.membership` was laid out together with `self.arena`.
        unsafe {
            self.membership.clear::<MetadataWord>(self.arena.as_ptr());
        }
        self.stale_membership = 0;
    }

    fn copy_membership_from(&mut self, source: &Self) {
        // SAFETY: each region was laid out for its own table's arena, so the two
        // never overlap; clones share geometry, so word counts match.
        unsafe {
            self.membership.copy_from::<MetadataWord>(
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
        self.scheduled_levels = 0;
        for level in &mut self.levels {
            level.scheduled_probes = 0;
        }
        self.probe_schedule.clear();
        self.clear_membership();
        self.epoch.start(EpochTransition::Clear);
    }

    /// Post-lookup insert for a key known to be absent. Returns the chosen
    /// slot so the caller can borrow into it without re-probing.
    #[inline]
    fn insert_for_vacant_entry(&mut self, key: K, value: V, key_hash: u64) -> (usize, usize) {
        let prepared = PreparedElasticKey::new(key_hash);
        let key_fingerprint = control::control_fingerprint(key_hash);
        self.insert_absent(key, value, prepared, key_fingerprint, |location| location)
    }

    /// Inserts a key known to be absent and hands its location to `finish`.
    /// The common insert searches its target level once, inline, among the
    /// probes the lookup schedule already covers. Growth, a batch change, the
    /// general range reduction, a search that finds no slot there, and with
    /// it every fallback and schedule extension, leave for the out-of-line
    /// path, which chooses the slot from the start.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn insert_absent<R>(
        &mut self,
        key: K,
        value: V,
        prepared: PreparedElasticKey,
        key_fingerprint: u8,
        finish: impl FnOnce((usize, usize)) -> R,
    ) -> R {
        let Some((level, slot, control)) = self.settled_slot(prepared.route.probe) else {
            return self.insert_absent_unsettled(key, value, prepared, key_fingerprint, finish);
        };
        finish(self.write_new_entry(key, value, prepared, key_fingerprint, level, slot, control))
    }

    /// The slot [`Self::choose_slot_for_new_key`] gives a new key, when the
    /// table needs no growth, the cached batch is current, its levels reduce
    /// by shift, and the batch's first choice of level has a free slot among
    /// its scheduled probes. `None` leaves the insert to
    /// [`Self::insert_for_vacant_entry_prepared`].
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn settled_slot(&self, probe: PreparedElasticProbe) -> Option<(usize, usize, u8)> {
        if !self.scheduler.settles(self.len) {
            return None;
        }
        debug_assert!(!self.levels.is_empty());
        // SAFETY: the scheduler settles only below the limit it was built
        // with, which `settled_limit` derives from the levels built beside
        // it and makes zero without a level zero. A clone copies both, and
        // a rebuild swaps both together.
        unsafe { core::hint::assert_unchecked(!self.levels.is_empty()) };
        // A level's scheduled probes all lie within its probe limit.
        let case = self.placement_case(self.scheduler.cached_target(), |region, budget| {
            let scheduled = u64::from(region.scheduled_probes);
            budget.map_or(scheduled, |budget| budget.min(scheduled))
        })?;
        let budget = case.budget;
        // SAFETY: a settled table's level zero reduces by shift, which
        // means every level does.
        let (slot, _, control) =
            unsafe { self.first_shifted_vacancy(probe, case.level, case.region, budget) }?;
        Some((case.level, slot, control))
    }

    #[inline(never)]
    fn insert_absent_unsettled<R>(
        &mut self,
        key: K,
        value: V,
        prepared: PreparedElasticKey,
        key_fingerprint: u8,
        finish: impl FnOnce((usize, usize)) -> R,
    ) -> R {
        finish(self.insert_for_vacant_entry_prepared(key, value, prepared, key_fingerprint))
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

    /// [`map::TableBackend::insert`] for a key
    /// [`Self::search_schedule`] left unresolved.
    #[inline(never)]
    fn insert_unresolved(
        &mut self,
        key: K,
        value: V,
        prepared: PreparedElasticKey,
        key_fingerprint: u8,
        level_mask: u32,
    ) -> Option<V> {
        let found = self.find_by_general_schedule(
            &key,
            prepared,
            key_fingerprint,
            level_mask,
            |level, slot, _| (level, slot),
        );
        if let Some(location) = found {
            return Some(map::TableBackend::replace_value(self, location, value));
        }
        self.insert_for_vacant_entry_prepared(key, value, prepared, key_fingerprint);
        None
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
        if placement.paper_probe > u64::from(self.levels[placement.level].scheduled_probes) {
            self.schedule_placement(placement);
        }
        // SAFETY: a placement names a slot of its level.
        let prev_ctrl = unsafe { self.levels[placement.level].control_at(placement.slot) };
        self.write_new_entry(
            key,
            value,
            prepared,
            key_fingerprint,
            placement.level,
            placement.slot,
            prev_ctrl,
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
        // SAFETY: the scan found `slot` within `level`.
        let prev_ctrl = unsafe { self.levels[level].control_at(slot) };
        self.write_new_entry(
            key,
            value,
            prepared,
            key_fingerprint,
            level,
            slot,
            prev_ctrl,
        )
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

    /// Writes a new entry into the free slot `slot_idx` of `level_idx`.
    /// `prev_ctrl` is the control byte the caller found the slot free by.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    fn write_new_entry(
        &mut self,
        key: K,
        value: V,
        prepared: PreparedElasticKey,
        key_fingerprint: u8,
        level_idx: usize,
        slot_idx: usize,
        prev_ctrl: u8,
    ) -> (usize, usize) {
        {
            debug_assert!(level_idx < self.levels.len());
            // SAFETY: callers pass a level they found a free slot in.
            let level = unsafe { self.levels.get_unchecked_mut(level_idx) };
            // SAFETY: callers pass a free slot found within this level.
            debug_assert_eq!(prev_ctrl, unsafe { level.control_at(slot_idx) });
            debug_assert!(control::is_free(prev_ctrl));
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

    /// Extends the schedule to cover a placement outside the scheduled levels
    /// or past the probes every scheduled level already holds.
    #[cold]
    #[inline(never)]
    fn schedule_placement(&mut self, placement: ExactPlacement) {
        if placement.level >= self.scheduled_levels as usize {
            self.schedule_levels_through(placement.level);
        }
        self.extend_probe_schedule(placement.phi());
    }

    /// Rebuilds the schedule to hold the routes of every level up to `level`,
    /// the first placement of this epoch past the levels scheduled so far.
    fn schedule_levels_through(&mut self, level: usize) {
        let high_water = self.probe_high_water & !EXCEPTIONAL_PLACEMENT_FLAG;
        self.probe_high_water &= EXCEPTIONAL_PLACEMENT_FLAG;
        self.probe_schedule.clear();
        self.scheduled_levels = u32::try_from(level + 1).expect("Elastic level count fits u32");
        for level in &mut self.levels {
            level.scheduled_probes = 0;
        }
        self.extend_probe_schedule(u128::from(high_water));
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
        // A level's positions grow with its probe, so each level offers its
        // next unscheduled probe and the lowest position among them is the
        // next route in position order.
        let position = |level: usize, paper_probe: u64| {
            if paper_probe > UNIFORM_SEARCH_CAP {
                return None;
            }
            let phi = probe::elastic_phi(level as u128 + 1, u128::from(paper_probe))
                .expect("bounded Elastic query coordinate");
            (phi <= high_water).then_some(phi)
        };
        let levels = &mut self.levels[..self.scheduled_levels as usize];
        let mut next = [None; MAX_LEVELS];
        for (level, region) in levels.iter().enumerate() {
            next[level] = position(level, u64::from(region.scheduled_probes) + 1);
        }
        while let Some((level, _)) = next[..levels.len()]
            .iter()
            .enumerate()
            .filter_map(|(level, phi)| phi.map(|phi| (level, phi)))
            .min_by_key(|&(_, phi)| phi)
        {
            let region = &mut levels[level];
            let logical_probe_index = u64::from(region.scheduled_probes);
            // Level zero's first probe is the direct slot, which every
            // lookup reads before it walks the schedule.
            if level != 0 || logical_probe_index != 0 {
                assert!(
                    usize::try_from(logical_probe_index)
                        .is_ok_and(|index| index < QUERY_PROBE_LIMIT),
                    "Elastic query-probe convention exhausted"
                );
                self.probe_schedule.push(level, region, logical_probe_index);
            }
            region.scheduled_probes += 1;
            next[level] = position(level, u64::from(region.scheduled_probes) + 1);
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
    fn find_value<'a, Q>(&'a self, key: &Q, hash: u64) -> Option<&'a V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
        K: 'a,
    {
        self.find_by_exact_schedule(
            key,
            PreparedElasticKey::new(hash),
            control::control_fingerprint(hash),
            |_level, _slot, entry| &entry.value,
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
        // The search applies the filter from the metadata word it already
        // reads, so this path pays no separate pre-check load.
        let search = self.search_schedule(&key, prepared, key_fingerprint, |level, slot, _| {
            (level, slot)
        });
        match search {
            ScheduleSearch::Hit(location) => Some(self.replace_value(location, value)),
            ScheduleSearch::Absent => {
                self.insert_absent(key, value, prepared, key_fingerprint, |_| None)
            }
            ScheduleSearch::Unresolved(level_mask) => {
                self.insert_unresolved(key, value, prepared, key_fingerprint, level_mask)
            }
        }
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
        let level_capacities = PlanBuffer::from_iter(self.levels.iter().map(ArenaSlots::capacity));
        let (arena, levels, membership) = alloc_elastic_arena(&level_capacities, &self.alloc);

        // If a user `K::clone` / `V::clone` panics, the guard drops the
        // already-cloned values and frees the arena; see `ArenaDropGuard`.
        let mut guard = arena::ArenaDropGuard::new(arena, levels, self.alloc.clone());

        for (dst, src_lvl) in guard.regions_mut().iter_mut().zip(self.levels.iter()) {
            dst.clone_region_from(src_lvl);
            dst.len = src_lvl.len;
            dst.tombstones = src_lvl.tombstones;
            dst.scheduled_probes = src_lvl.scheduled_probes;
        }

        let regions = guard.regions_mut();
        let probe_schedule = self
            .probe_schedule
            .clone_onto(PROBE_SCHEDULE_CAPACITY[regions.len()], regions);

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
            metadata_words: metadata_words(&arena, membership),
            arena,
            epoch: self.epoch,
            probe_high_water: self.probe_high_water,
            scheduled_levels: self.scheduled_levels,
            probe_schedule,
            fold_multiplier: probe::ELASTIC_FOLD_MULTIPLIER,
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
        let schedule_room = ProbeScheduleRoom::try_with_capacity(
            PROBE_SCHEDULE_CAPACITY[geometry.level_capacities.len()],
        )?;
        let (arena, levels, membership) =
            try_alloc_elastic_arena(&geometry.level_capacities, &self.alloc)?;
        let settled_limit = settled_limit(&levels, geometry.max_insertions);
        let probe_schedule = schedule_room.schedule(&levels);
        let used_exceptional_placement = rebuild::rebuild(
            self,
            ElasticGeneration {
                levels,
                len: 0,
                total_slots: geometry.total_slots,
                max_insertions: geometry.max_insertions,
                scheduler: BatchScheduler::new(&geometry.batch_plan, settled_limit),
                metadata_words: metadata_words(&arena, membership),
                arena,
                probe_high_water: 0,
                scheduled_levels: 0,
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
    /// A trace without deletes gets here only when a key's probes in its
    /// active pair all land on occupied slots.
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
        self.choose_slot_with(target, |level, budget| {
            self.first_vacancy(probe, level, budget)
        })
    }

    /// The paper's insertion case for `target`. `budget_of` turns the
    /// case's probe bound for its level, `None` when the case sets none,
    /// into the budget the caller searches with; resolving it per case
    /// lets an unbounded case skip the comparison against a bound.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn placement_case(
        &self,
        target: BatchTarget,
        budget_of: impl Fn(&Level<SlotEntry<K, V>>, Option<u64>) -> u64,
    ) -> Option<PlacementCase<'_, K, V>> {
        // The paper's insertion cases, in order: Batch 0 fills level 0; then,
        // for the active pair, Case 2 (current nearly full) places in `next`,
        // Case 3 (next nearly full) in `current`, and Case 1 gives `current`
        // a bounded probe budget before falling back to `next`.
        Some(match target {
            BatchTarget::Bootstrap => PlacementCase {
                level: 0,
                region: self.levels.first()?,
                budget: budget_of(self.levels.first()?, None),
                fallback: None,
            },
            BatchTarget::LevelPair(current) => {
                let next = current.checked_add(1)?;
                let [current_level, next_level] = self.levels.get(current..=next)? else {
                    return None;
                };
                let free_current = current_level.free_slots();
                let free_next = next_level.free_slots();
                let current_low = self.current_level_low(current_level);
                let next_low = free_next.saturating_mul(4) <= next_level.capacity();

                if current_low {
                    PlacementCase {
                        level: next,
                        region: next_level,
                        budget: budget_of(next_level, None),
                        fallback: None,
                    }
                } else if next_low {
                    PlacementCase {
                        level: current,
                        region: current_level,
                        budget: budget_of(current_level, None),
                        fallback: None,
                    }
                } else {
                    let budget = probe::elastic_dyadic_probe_budget(
                        free_current,
                        current_level.capacity(),
                        self.reserve_fraction.exponent(),
                        ELASTIC_PROBE_BUDGET_C,
                    )
                    .ok()?;
                    PlacementCase {
                        level: current,
                        region: current_level,
                        budget: budget_of(
                            current_level,
                            Some(u64::try_from(budget).unwrap_or(u64::MAX)),
                        ),
                        fallback: Some(next),
                    }
                }
            }
        })
    }

    /// Chooses `target`'s slot for a new key. `first_vacancy(level, budget)`
    /// yields the first free slot among `level`'s first `budget` probes and
    /// the one-based probe that reached it.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn choose_slot_with(
        &self,
        target: BatchTarget,
        first_vacancy: impl Fn(usize, u64) -> Option<(usize, u64)>,
    ) -> Option<ExactPlacement> {
        let PlacementCase {
            mut level,
            mut budget,
            mut fallback,
            ..
        } = self.placement_case(target, |_, budget| budget.unwrap_or(u64::MAX))?;
        // One search site serves every case, so the search inlines once.
        let (slot, paper_probe) = loop {
            let limit = *LEVEL_PROBE_LIMIT.get(level)?;
            if let Some(found) = first_vacancy(level, budget.min(limit)) {
                break found;
            }
            level = fallback.take()?;
            budget = u64::MAX;
        };
        // Every vacancy search stops within `LEVEL_PROBE_LIMIT`, whose probes
        // all sit at positions up to `QUERY_POSITION_CAP`.
        Some(ExactPlacement {
            level,
            slot,
            paper_probe,
        })
    }

    /// Case 2's test: the active pair's current level has at most half its
    /// reserve left, so new keys go to the next level.
    #[inline]
    fn current_level_low(&self, current_level: &Level<SlotEntry<K, V>>) -> bool {
        current_level.free_slots()
            <= self
                .reserve_fraction
                .floor_half_reserved(current_level.capacity())
    }

    /// The first free slot among `level`'s first `budget` probes, in probe
    /// order, with the one-based probe that reached it.
    fn first_vacancy(
        &self,
        probe: PreparedElasticProbe,
        level: usize,
        budget: u64,
    ) -> Option<(usize, u64)> {
        let region = self.levels.get(level)?;
        if region.index_shift() == GENERAL_REDUCTION {
            return self.first_vacancy_general(probe, level, budget);
        }
        // SAFETY: the level reduces by shift.
        unsafe { self.first_shifted_vacancy(probe, level, region, budget) }
            .map(|(slot, paper_probe, _)| (slot, paper_probe))
    }

    /// [`Self::first_vacancy`] for a level that reduces by shift.
    ///
    /// # Safety
    ///
    /// `region` must be this table's `level`, and must not be marked
    /// [`GENERAL_REDUCTION`].
    #[allow(clippy::inline_always)]
    #[inline(always)]
    unsafe fn first_shifted_vacancy(
        &self,
        probe: PreparedElasticProbe,
        level: usize,
        region: &Level<SlotEntry<K, V>>,
        budget: u64,
    ) -> Option<(usize, u64, u8)> {
        debug_assert!(core::ptr::eq(region, &raw const self.levels[level]));
        let index_shift = region.index_shift();
        debug_assert!(index_shift < u64::BITS);
        // SAFETY: a shift other than `GENERAL_REDUCTION` is
        // `probe::elastic_index_shift` of the capacity, below the word width.
        unsafe { core::hint::assert_unchecked(index_shift < u64::BITS) };
        let sequence = probe.sequence(self.fold_multiplier);
        let (mut word, word_step) = sequence.level_words(level);
        let mut remaining = budget;
        while remaining != 0 {
            let slot = probe::shifted_elastic_index(word, index_shift);
            // SAFETY: the caller's shift maps the index into the level's
            // capacity.
            let control = unsafe { region.control_at(slot) };
            if control::is_free(control) {
                return Some((slot, budget - remaining + 1, control));
            }
            word = word.wrapping_add(word_step);
            remaining -= 1;
        }
        None
    }

    /// [`Self::first_vacancy`] for a table whose levels need the general
    /// range reduction.
    #[inline(never)]
    fn first_vacancy_general(
        &self,
        probe: PreparedElasticProbe,
        level: usize,
        budget: u64,
    ) -> Option<(usize, u64)> {
        (0..budget).find_map(|logical_index| {
            self.vacancy(level, probe, logical_index)
                .map(|slot| (slot, logical_index + 1))
        })
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

    #[inline]
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
        match self.search_schedule(key, prepared, key_fingerprint, &mut on_hit) {
            ScheduleSearch::Hit(hit) => Some(hit),
            ScheduleSearch::Absent => None,
            ScheduleSearch::Unresolved(level_mask) => {
                self.find_by_general_schedule(key, prepared, key_fingerprint, level_mask, on_hit)
            }
        }
    }

    /// Walks the key's candidates in schedule order. A table that needs the
    /// general reduction has routes that probe nothing, so its walk ends
    /// unresolved. It calls nothing but the key comparison, so a caller that
    /// hands [`ScheduleSearch::Unresolved`] on in tail position keeps no
    /// stack frame.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn search_schedule<'a, Q, R>(
        &'a self,
        key: &Q,
        prepared: PreparedElasticKey,
        key_fingerprint: u8,
        mut on_hit: impl FnMut(usize, usize, &'a SlotEntry<K, V>) -> R,
    ) -> ScheduleSearch<R>
    where
        Q: Equivalent<K> + ?Sized,
    {
        // A key the filter never recorded was never inserted, so neither the
        // candidates nor the exceptional full scan can hold it.
        let filter = self.route_filter(prepared);
        if !filter.maybe_present {
            return ScheduleSearch::Absent;
        }
        let sequence = prepared.route.probe.sequence(self.fold_multiplier);
        let direct = self.probe_schedule.direct();
        // SAFETY: the schedule starts with its direct route and ends with
        // its sentinel, so the route after the direct one is in bounds.
        let (direct, mut next) = unsafe { (&*direct, direct.add(1)) };
        let h11_slot = probe::shifted_elastic_index(sequence.word(0), direct.index_shift());
        // SAFETY: the route's shifted index maps into the control bytes it
        // holds.
        if unsafe { *direct.control().add(h11_slot) } == key_fingerprint {
            // SAFETY: only level zero's own control bytes hold a
            // fingerprint, so the table has that level and the slot is one
            // of its occupied ones.
            let entry = unsafe { self.levels.get_unchecked(0).get_ref(h11_slot) };
            if key.equivalent(&entry.key) {
                return ScheduleSearch::Hit(on_hit(0, h11_slot, entry));
            }
        }

        let level_mask = filter.expanded_level_mask();
        let mut open_levels = u64::from(level_mask) | (1 << SENTINEL_LEVEL);
        loop {
            // SAFETY: the schedule ends with its sentinel, and the walk
            // cannot pass it: the sentinel's level stays open until its own
            // probe, which reads `EMPTY` and breaks below.
            let route = unsafe { &*next };
            // SAFETY: as above, `route` is at most the sentinel, the last
            // element, so this is at most one past the end.
            next = unsafe { next.add(1) };
            if (open_levels >> route.level()) & 1 == 0 {
                continue;
            }
            // The route holds a shift whichever reduction its level needs.
            let slot = probe::shifted_elastic_index(
                sequence.word(route.sequence_index()),
                route.index_shift(),
            );
            // SAFETY: the route holds its level's control base, and the
            // shifted index maps into that level's capacity.
            let control = unsafe { *route.control().add(slot) };
            if control == key_fingerprint {
                let level = route.level() as usize;
                // SAFETY: the sentinel's control bytes match no fingerprint,
                // so the route names a real level, and a fingerprint match
                // means the slot is occupied.
                let entry = unsafe { self.levels.get_unchecked(level).get_ref(slot) };
                if key.equivalent(&entry.key) {
                    return ScheduleSearch::Hit(on_hit(level, slot, entry));
                }
            } else if control == CTRL_EMPTY {
                // A key takes its level's first free probe, and a slot
                // returns to `EMPTY` only when its whole level is reset: a
                // removal leaves a tombstone, and so does a `clear` until its
                // last entry is out, even one a panicking drop interrupts. So
                // the key cannot sit at a later probe of this level.
                open_levels &= !(1 << route.level());
                // Either no real level is left open, or this was the
                // sentinel.
                if open_levels <= 1 << SENTINEL_LEVEL {
                    break;
                }
            }
        }
        // A table that needs the general reduction walked routes that probe
        // nothing.
        // SAFETY: the filter only passes when it has words, and those are laid
        // out for a non-zero slot count, which gives the table a level zero.
        let general = unsafe { self.levels.get_unchecked(0) }.index_shift() == GENERAL_REDUCTION;
        if general || self.probe_high_water & EXCEPTIONAL_PLACEMENT_FLAG != 0 {
            ScheduleSearch::Unresolved(level_mask)
        } else {
            ScheduleSearch::Absent
        }
    }

    /// The schedule walk from the first candidate, for a key that passed the
    /// filter and that [`Self::search_schedule`] left unresolved: the table
    /// needs the general range reduction or placed an entry outside its
    /// probe routes.
    #[inline(never)]
    fn find_by_general_schedule<'a, Q, R>(
        &'a self,
        key: &Q,
        prepared: PreparedElasticKey,
        key_fingerprint: u8,
        level_mask: u32,
        mut on_hit: impl FnMut(usize, usize, &'a SlotEntry<K, V>) -> R,
    ) -> Option<R>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let Some(h11_slot) = Self::route_prepared_counter_for_upper(
            prepared.route.probe,
            H11_COUNTER_BASE,
            self.levels[0].capacity(),
        ) else {
            return self.find_by_full_scan(key, key_fingerprint, on_hit);
        };
        // SAFETY: the counter route maps into level zero's capacity.
        if let Some(entry) = unsafe { self.entry_if_match(0, h11_slot, key_fingerprint, key) } {
            return Some(on_hit(0, h11_slot, entry));
        }

        for route in self.probe_schedule.routes() {
            let level = route.level() as usize;
            if level_mask & (1_u32 << level) == 0 {
                continue;
            }
            let Some(slot) =
                self.route_prepared_counter(level, prepared.route.probe, route.counter_base())
            else {
                return self.find_by_full_scan(key, key_fingerprint, on_hit);
            };
            // SAFETY: schedule routes name real levels and the counter route
            // maps into that level's capacity.
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
    scheduled_levels: u32,
    probe_schedule: ProbeSchedule,
    membership: MembershipRegion,
    metadata_words: *mut MetadataWord,
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
        mem::swap(&mut self.scheduled_levels, &mut other.scheduled_levels);
        mem::swap(&mut self.probe_schedule, &mut other.probe_schedule);
        mem::swap(&mut self.membership, &mut other.membership);
        mem::swap(&mut self.metadata_words, &mut other.metadata_words);
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

    #[inline]
    fn prefetch_placement(&self, key_hash: u64) {
        let prepared = PreparedElasticKey::new(key_hash);
        let words = self.membership.words;
        if words != 0 {
            let word = MembershipKey::word(prepared.route.signature(), words);
            prefetch::prefetch_write(self.membership_ptr().wrapping_add(word));
        }
        // The level whose first probe `choose_slot_for_new_key` reads, judged
        // from the cached batch; a stale batch only misdirects the hint.
        let level = match self.scheduler.cached_target() {
            BatchTarget::Bootstrap => 0,
            BatchTarget::LevelPair(current) => {
                let Some(current_level) = self.levels.get(current) else {
                    return;
                };
                if self.current_level_low(current_level) {
                    current + 1
                } else {
                    current
                }
            }
        };
        if let (Some(region), Some(slot)) = (
            self.levels.get(level),
            self.route_prepared(level, prepared.route.probe, 0),
        ) {
            region.prefetch_slot(slot);
        }
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
