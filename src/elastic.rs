use core::hash::{BuildHasher, Hash};
use core::mem::{self, MaybeUninit};

use alloc::{boxed::Box, vec::Vec};
use allocator_api2::alloc::{Allocator, Global, Layout};
use equivalent::Equivalent;

use crate::ReserveFraction;
use crate::common::DefaultHashBuilder;
use crate::common::arena::{self, Arena, ArenaSlots, SlotEntry};
use crate::common::config::INITIAL_CAPACITY;
use crate::common::control::{self, CTRL_EMPTY, CTRL_TOMBSTONE};
use crate::common::error::{TryBuildError, TryReserveError};
use crate::common::exact::geometry::PaperConfig;
use crate::common::exact::probe::{self, CounterPrf, PreparedElasticProbe};
use crate::common::iter::RegionCursor;
use crate::common::math::capacity;
use crate::common::membership::{self, MembershipKey, MembershipRegion};
use crate::epoch::{EpochSnapshot, EpochState, EpochTransition};
use crate::macros;
use crate::map;

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
const MAX_CASE1_LOGICAL_PROBES: usize =
    ELASTIC_PROBE_BUDGET_C * (u32::BITS as usize - 1) * (u32::BITS as usize - 1);
const MAX_ELASTIC_SLOTS: usize = match 1_usize.checked_shl(u32::BITS) {
    Some(slots) => slots,
    None => usize::MAX,
};
const ROUTE_SUMMARY_LEVELS: usize = u16::BITS as usize;
const H11_COUNTER_BASE: u32 = probe::elastic_counter_base(0, 0);

const _: () = assert!(u32::BITS as u64 <= probe::ELASTIC_LEVEL_LIMIT);
const _: () = assert!(UNIFORM_SEARCH_CAP <= probe::ELASTIC_LOGICAL_LIMIT);
const _: () = assert!(MAX_CASE1_LOGICAL_PROBES as u64 <= probe::ELASTIC_LOGICAL_LIMIT);

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
struct Level<T> {
    /// Cached `arena.as_ptr() + ctrl_offset`, stamped at construction.
    ctrl_ptr: *mut u8,
    /// Cached `arena.as_ptr() + data_offset`, stamped at construction.
    data_ptr: *mut MaybeUninit<T>,
    /// Exact logical slot count. Bounded by the arena layout, so the counters
    /// fit in `u32` too.
    capacity: u32,
    /// Live entry count.
    len: u32,
    /// Deleted-slot count.
    tombstones: u32,
}

unsafe impl<T: Send> Send for Level<T> {}
unsafe impl<T: Sync> Sync for Level<T> {}

// `Level` is read on every lookup — keep it within one 64-byte cache line.
const _: () = assert!(mem::size_of::<Level<SlotEntry<u64, u64>>>() <= 64);

impl<T> ArenaSlots<T> for Level<T> {
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
    /// empty. Each slot's control and the counters are updated before `visit`
    /// runs, so a panic inside it leaves the level consistent: the entries not
    /// yet visited stay live and counted, and the moved ones are `EMPTY`.
    fn drain_reset(&mut self, mut visit: impl FnMut(T)) {
        for slot in 0..self.capacity() {
            let control = self.control_at(slot);
            if control == CTRL_TOMBSTONE {
                self.set_control(slot, CTRL_EMPTY);
                self.tombstones -= 1;
            } else if control::is_occupied(control) {
                let entry = unsafe { self.take(slot) };
                self.set_control(slot, CTRL_EMPTY);
                self.len -= 1;
                visit(entry);
            }
        }
    }
}

/// Open-addressed elastic-hashing backend for the generic [`map::HashMap`]
/// shell. See [`ElasticHashMap`] for the public map type.
///
/// Splits capacity across geometrically shrinking `levels` and routes inserts
/// through a `batch_plan`: early batches concentrate on level 0; later
/// batches push toward deeper levels. Lookups probe every level whose
/// `len > 0`.
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

unsafe impl<K: Send, V: Send, S: Send, A: Allocator + Clone + Send> Send
    for ElasticTable<K, V, S, A>
{
}
unsafe impl<K: Sync, V: Sync, S: Sync, A: Allocator + Clone + Sync> Sync
    for ElasticTable<K, V, S, A>
{
}

impl<K, V, S, A: Allocator + Clone> Drop for ElasticTable<K, V, S, A> {
    fn drop(&mut self) {
        let levels = &mut self.levels;
        self.arena.drop_table(&self.alloc, || {
            for level in levels {
                level.drop_values();
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Public type aliases. The generic [`map::HashMap`] shell supplies the public
// API; these names keep `ElasticHashMap` and its iterator/entry types
// nameable (and re-exportable from `lib.rs` / `set.rs`). The generic-argument
// threading lives once in `declare_backend_aliases!`; each entry below is just
// `doc`, alias name, and the unprefixed shell type.
// ---------------------------------------------------------------------------

macros::declare_backend_aliases! {
    table = ElasticTable,
    map_no_lifetime {
        "Open-addressed hash map using elastic hashing." ElasticHashMap => HashMap,
        "Consuming iterator over owned `(K, V)`." ElasticIntoIter => IntoIter,
        "Owned `K` iterator." ElasticIntoKeys => IntoKeys,
        "Owned `V` iterator." ElasticIntoValues => IntoValues,
    },
    map_ref {
        "A view into a single entry, occupied or vacant." ElasticEntry => Entry,
        "View of an occupied entry." ElasticOccupiedEntry => OccupiedEntry,
        "View of a vacant entry." ElasticVacantEntry => VacantEntry,
        "Error returned by `try_insert` on key collision." ElasticOccupiedError => OccupiedError,
        "Borrowing iterator over `(&K, &V)`." ElasticIter => Iter,
        "Borrowing iterator over `(&K, &mut V)`." ElasticIterMut => IterMut,
        "`&K` iterator." ElasticKeys => Keys,
        "`&V` iterator." ElasticValues => Values,
        "`&mut V` iterator." ElasticValuesMut => ValuesMut,
        "Draining iterator that empties the map." ElasticDrain => Drain,
    },
    map_extract_if {
        "Iterator yielding entries removed by `extract_if`." ElasticExtractIf
    },
    set_no_lifetime {
        "Hash set using elastic hashing." ElasticHashSet => HashSet,
        "Consuming iterator over set values." ElasticSetIntoIter => IntoIter,
    },
    set_ref {
        "Borrowing iterator over set values." ElasticSetIter => Iter,
        "Draining iterator that empties the set." ElasticSetDrain => Drain,
        "Iterator yielding values removed by set `extract_if`." ElasticSetExtractIf => ExtractIf,
        "Iterator over values present only in the first set." ElasticDifference => Difference,
        "Iterator over values present in both sets." ElasticIntersection => Intersection,
        "Iterator over values present in exactly one set." ElasticSymmetricDifference => SymmetricDifference,
        "Iterator over values present in either set." ElasticUnion => Union,
        "A view into a single set entry." ElasticSetEntry => Entry,
        "View of an occupied set entry." ElasticSetOccupiedEntry => OccupiedEntry,
        "View of a vacant set entry." ElasticSetVacantEntry => VacantEntry,
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

fn probe_schedule_capacity(level_count: usize) -> usize {
    let mut count = 0;
    for level in 0..level_count {
        for_each_phi_route(level, 1, QUERY_POSITION_CAP, |_, _| count += 1);
    }
    count
}

fn try_probe_schedule(level_count: usize) -> Result<Vec<PhiRoute>, TryReserveError> {
    let mut schedule = Vec::new();
    schedule
        .try_reserve_exact(probe_schedule_capacity(level_count))
        .map_err(|_| TryReserveError::AllocError)?;
    Ok(schedule)
}

fn clone_probe_schedule(source: &[PhiRoute], level_count: usize) -> Vec<PhiRoute> {
    let mut schedule = Vec::with_capacity(probe_schedule_capacity(level_count));
    schedule.extend_from_slice(source);
    schedule
}

/// Schedule paper batches and allocation-epoch boundaries.
///
/// The active batch is a function of the live count alone: batch `i` covers
/// positions in `[batch_ends[i-1], batch_ends[i])`, the prefix-sum test the
/// scalar oracle applies, so under deletion it tracks occupancy rather than
/// an insert tally. The active window is cached: two compares per placement.
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

/// Direct the structural work required before insertion.
pub(crate) enum InsertAction {
    /// Resize to the specified slot count.
    Resize(usize),
    /// Continue without structural work.
    Continue,
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

    /// Select structural work for the next insert.
    #[inline]
    pub(crate) fn on_insert(
        current_len: usize,
        total_slots: usize,
        max_insertions: usize,
    ) -> InsertAction {
        if current_len >= max_insertions {
            let new_cap = if total_slots == 0 {
                INITIAL_CAPACITY
            } else {
                total_slots.saturating_mul(2)
            };
            return InsertAction::Resize(new_cap);
        }
        InsertAction::Continue
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
        if total_slots > MAX_ELASTIC_SLOTS {
            return None;
        }
        Some(Self::for_slots(total_slots, reserve_fraction))
    }

    fn for_slots(total_slots: usize, reserve_fraction: ReserveFraction) -> Self {
        assert!(total_slots <= MAX_ELASTIC_SLOTS, "capacity overflow");
        if total_slots == 0 {
            return Self {
                total_slots: 0,
                max_insertions: 0,
                level_capacities: PlanBuffer::EMPTY,
                batch_plan: PlanBuffer::EMPTY,
            };
        }

        // Public construction rounds positive maps up to INITIAL_CAPACITY, so
        // one slot is only an internal bootstrap shape outside the paper's
        // n >= 2 domain.
        if total_slots == 1 {
            let single = PlanBuffer::from_iter(core::iter::once(1));
            return Self {
                total_slots: 1,
                max_insertions: 1,
                level_capacities: single,
                batch_plan: single,
            };
        }

        let config = PaperConfig::new(total_slots, reserve_fraction.exponent())
            .expect("validated Elastic library geometry");
        let plan = config.elastic_plan();
        Self {
            total_slots,
            max_insertions: config.max_insertions(),
            level_capacities: PlanBuffer::from_iter(plan.level_lengths()),
            batch_plan: PlanBuffer::from_iter(plan.batch_quotas()),
        }
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

#[allow(clippy::cast_ptr_alignment)]
fn try_alloc_elastic_arena<K, V, A: Allocator + Clone>(
    level_capacities: &[usize],
    alloc: &A,
) -> Result<ElasticArenaBuild<K, V>, TryReserveError> {
    let total_ctrl = level_capacities
        .iter()
        .try_fold(0_usize, |total, &capacity| total.checked_add(capacity));
    let total_ctrl = total_ctrl.ok_or(TryReserveError::CapacityOverflow)?;
    let arena_layout = elastic_arena_layout::<K, V>(total_ctrl)?;
    let arena = Arena::try_allocate_with_ctrl_zeroed(arena_layout.layout, total_ctrl, alloc)?;
    let membership = arena_layout.membership;
    // The arena zeroes control bytes only; an empty filter must read as
    // "nothing recorded".
    unsafe { membership.clear::<ElasticMetadataWord>(arena.as_ptr()) };

    // `Arena` has no `Drop`, so a bare `?` would leak the allocation if
    // level construction fails. Deallocate explicitly on `Err`.
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
    let layout = level_capacities
        .iter()
        .try_fold(0_usize, |total, &capacity| total.checked_add(capacity))
        .and_then(|total_ctrl| {
            elastic_arena_layout::<K, V>(total_ctrl)
                .ok()
                .map(|layout| layout.layout)
        })
        .unwrap_or_else(|| Layout::from_size_align(1, 1).unwrap());
    allocator_api2::alloc::handle_alloc_error(layout)
}

/// Drops every level's live values, backing [`arena::ArenaDropGuard`]'s
/// panic-safe rollback in `resize`/`clone`.
impl<K, V> arena::RegionSet for LevelSlice<K, V> {
    fn drop_all_values(&mut self) {
        for level in self.iter_mut() {
            level.drop_values();
        }
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
        unsafe {
            self.membership
                .ptr::<ElasticMetadataWord>(self.arena.as_ptr())
        }
    }

    /// Both filter answers from one word: `maybe_present == false` proves the key
    /// was never recorded, and `level_mask` narrows the candidate levels. One
    /// dependent load for the pair.
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
        // SAFETY: `word` is a multiply-high reduction below `words`, and the
        // cached region covers exactly that many initialized words.
        let metadata = unsafe { &*self.membership_ptr().add(word) };
        let bits = prepared.membership.bits();
        ElasticRouteFilter {
            maybe_present: metadata.membership & bits == bits,
            level_mask: u32::from(metadata.route_bins[prepared.route.summary_bin()]),
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
            let metadata = unsafe { &mut *self.membership_ptr().add(word) };
            metadata.membership |= membership.bits();
            metadata.route_bins[route.summary_bin()] |= 1_u16 << summary_level(level);
        }
    }

    fn clear_membership(&mut self) {
        unsafe {
            self.membership
                .clear::<ElasticMetadataWord>(self.arena.as_ptr());
        }
        self.stale_membership = 0;
    }

    fn copy_membership_from(&mut self, source: &Self) {
        unsafe {
            self.membership.copy_from::<ElasticMetadataWord>(
                self.arena.as_ptr(),
                source.membership,
                source.arena.as_ptr(),
            );
        };
    }

    /// Removes all entries, keeping allocated capacity.
    fn clear(&mut self) {
        for level in &mut self.levels {
            level.drain_reset(|entry| {
                self.len -= 1;
                drop(entry);
            });
        }
        debug_assert_eq!(self.len, 0);
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
        if let InsertAction::Resize(cap) =
            BatchScheduler::on_insert(self.len, self.total_slots, self.max_insertions)
        {
            self.resize_with_transition(cap, EpochTransition::Growth);
        }

        let target = self.scheduler.target(self.len);
        if let Some(placement) = self.choose_slot_for_new_key(prepared.route.probe, target) {
            return self.place_new_entry(key, value, prepared, key_fingerprint, placement);
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
                    .find(|&slot| control::is_free(level.control_at(slot)))
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
            let prev_ctrl = level.control_at(slot_idx);
            level.write_with_control(slot_idx, SlotEntry { key, value }, key_fingerprint);
            level.len += 1;
            if prev_ctrl == CTRL_TOMBSTONE {
                level.tombstones -= 1;
            }
        }
        self.record_membership(prepared.route, prepared.membership, level_idx);
        self.len += 1;
        (level_idx, slot_idx)
    }

    /// Raw pointer to the whole slot at `(level_idx, slot_idx)`. Projects
    /// through raw pointers from `&self.levels`, forming no intermediate
    /// `&mut Level`, so distinct locations yield non-aliasing `*mut`.
    ///
    /// # Safety
    /// `level_idx` < `self.levels.len()` and `slot_idx` is a live slot there.
    #[inline]
    unsafe fn slot_ptr_at(&self, level_idx: usize, slot_idx: usize) -> *mut SlotEntry<K, V> {
        let levels_ptr: *const Level<SlotEntry<K, V>> = self.levels.as_ptr();
        // SAFETY: shared `&Level` only — never `&mut` — so no aliasing tag.
        let level = unsafe { &*levels_ptr.add(level_idx) };
        level.slot_ptr(slot_idx)
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
                    usize::try_from(logical_probe_index).unwrap() < QUERY_PROBE_LIMIT,
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

    /// Prime the scan and cross level boundaries off the hot path.
    #[cold]
    fn scan_advance(&self, scan: &mut ElasticScan) -> Option<ElasticScanItem<K, V>> {
        if !scan.region.started() {
            if self.levels.is_empty() {
                return None;
            }
            scan.region.enter(&self.levels[0]);
        }
        loop {
            if let Some((ptr, slot_idx)) = scan.region.step::<SlotEntry<K, V>>() {
                return Some((ptr, (scan.level_idx, slot_idx)));
            }
            scan.level_idx += 1;
            if scan.level_idx >= self.levels.len() {
                return None;
            }
            scan.region.enter(&self.levels[scan.level_idx]);
        }
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
        unsafe { self.slot_ref(level_idx, slot_idx) }
    }

    #[inline]
    unsafe fn slot_ptr(&self, (level_idx, slot_idx): (usize, usize)) -> *mut SlotEntry<K, V> {
        unsafe { self.slot_ptr_at(level_idx, slot_idx) }
    }

    #[inline]
    fn replace_value(&mut self, (level_idx, slot_idx): (usize, usize), value: V) -> V {
        let slot = unsafe { self.slot_mut(level_idx, slot_idx) };
        mem::replace(&mut slot.value, value)
    }

    // -- Lookup --

    #[inline]
    fn find<Q>(&self, key: &Q, hash: u64, fingerprint: u8) -> Option<(usize, usize)>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find_slot_indices_prepared(key, PreparedElasticKey::new(hash), fingerprint)
    }

    #[inline]
    fn find_entry<'a, Q>(
        &'a self,
        key: &Q,
        hash: u64,
        fingerprint: u8,
    ) -> Option<&'a SlotEntry<K, V>>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find_entry_prepared(key, PreparedElasticKey::new(hash), fingerprint)
    }

    // -- Insert / remove --

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
        let removed = unsafe { self.levels[level_idx].take(slot_idx) };
        self.extract_finish((level_idx, slot_idx));
        self.settle_after_deletes(self.levels[level_idx].needs_cleanup());
        (removed.key, removed.value)
    }

    #[inline]
    fn tombstone_slot(&mut self, (level_idx, slot_idx): (usize, usize)) {
        self.levels[level_idx].mark_tombstone(slot_idx);
    }

    #[inline]
    fn extract_finish(&mut self, (level_idx, slot_idx): (usize, usize)) {
        {
            let level = &mut self.levels[level_idx];
            level.mark_tombstone(slot_idx);
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

    // -- Iterate --

    type Scan = ElasticScan;

    #[inline]
    fn scan(&self) -> ElasticScan {
        ElasticScan {
            level_idx: 0,
            region: RegionCursor::new(),
        }
    }

    #[inline]
    fn scan_next(&self, scan: &mut ElasticScan) -> Option<ElasticScanItem<K, V>> {
        // Hot path: another occupied slot in the level the cursor already holds.
        if scan.region.started()
            && let Some((ptr, slot_idx)) = scan.region.step::<SlotEntry<K, V>>()
        {
            return Some((ptr, (scan.level_idx, slot_idx)));
        }
        self.scan_advance(scan)
    }

    // -- Lifecycle --

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

    fn wipe_all(&mut self) {
        for level in &mut self.levels {
            level.clear_all_controls();
            level.len = 0;
            level.tombstones = 0;
        }
        self.len = 0;
        self.scheduler.reset();
        self.probe_high_water = 0;
        self.probe_schedule.clear();
        self.clear_membership();
        self.epoch.start(EpochTransition::Clear);
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
        let probe_schedule = clone_probe_schedule(&self.probe_schedule, self.levels.len());
        let level_capacities: Vec<usize> =
            self.levels.iter().map(|l| l.capacity as usize).collect();
        let (arena, levels, membership) = alloc_elastic_arena(&level_capacities, &self.alloc);

        // Drop guard for the half-built clone: if any user `K::clone` /
        // `V::clone` panics, drop the already-cloned values (OCCUPIED on
        // `dst_arena`) and deallocate the partially-filled arena. `Arena`
        // has no `Drop`, so without this the whole allocation would leak.
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
#[derive(Clone)]
pub struct ElasticScan {
    level_idx: usize,
    region: RegionCursor,
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
            for slot_idx in 0..self.levels[level_idx].capacity() {
                if !control::is_occupied(self.levels[level_idx].control_at(slot_idx)) {
                    continue;
                }
                let hash = {
                    let entry = unsafe { self.levels[level_idx].get_ref(slot_idx) };
                    self.hash_builder.hash_one(&entry.key)
                };
                let prepared = PreparedElasticKey::new(hash);
                self.record_membership(prepared.route, prepared.membership, level_idx);
            }
        }
    }

    /// Insert `(key, value)` known to be new. Skips the existence check and
    /// capacity check in `insert`; resize loops drain old levels into fresh
    /// (all-EMPTY) ones, so neither check can succeed.
    ///
    #[inline]
    fn insert_unique(&mut self, key: K, value: V) -> bool {
        let key_hash = self.hash_builder.hash_one(&key);
        let prepared = PreparedElasticKey::new(key_hash);
        let key_fingerprint = control::control_fingerprint(key_hash);

        let target = self.scheduler.target(self.len);
        if let Some(placement) = self.choose_slot_for_new_key(prepared.route.probe, target) {
            self.place_new_entry(key, value, prepared, key_fingerprint, placement);
            false
        } else {
            self.place_exceptional_entry(key, value, prepared, key_fingerprint);
            true
        }
    }

    /// Drain all live entries into a temp Vec, rebuild levels at
    /// `new_capacity` in-place, reinsert. Passing the current capacity
    /// performs a no-grow rehash that flushes accumulated tombstones.
    fn resize(&mut self, new_capacity: usize) {
        self.resize_with_transition(new_capacity, EpochTransition::ExplicitResize);
    }

    fn resize_with_transition(&mut self, new_capacity: usize, transition: EpochTransition) {
        let geometry = ElasticGeometry::for_slots(new_capacity, self.reserve_fraction);
        let required_schedule_capacity = probe_schedule_capacity(geometry.level_capacities.len());
        if self.probe_schedule.capacity() < required_schedule_capacity {
            self.probe_schedule
                .reserve_exact(required_schedule_capacity - self.probe_schedule.len());
        }

        let (new_arena, new_levels, new_membership) =
            alloc_elastic_arena(&geometry.level_capacities, &self.alloc);

        // Swap in fresh arena; keep old one alive until drain completes.
        let old_arena = mem::replace(&mut self.arena, new_arena);
        let old_levels = mem::replace(&mut self.levels, new_levels);
        self.total_slots = geometry.total_slots;
        self.membership = new_membership;
        self.stale_membership = 0;
        self.max_insertions = geometry.max_insertions;
        self.scheduler = BatchScheduler::new(&geometry.batch_plan);
        self.len = 0;
        self.probe_high_water = 0;
        self.probe_schedule.clear();

        // Move every live entry from old arena into the new levels.
        //
        // Panic safety: clear each source ctrl before handing the moved entry
        // to `insert_unique`, so the guard's drop walks only un-moved slots.
        // If `insert_unique` panics, the guard unwinds: drops any survivors
        // then deallocates `old_arena` — `Arena` has no `Drop`, so without the
        // guard the backing allocation would leak.
        let mut guard = arena::ArenaDropGuard::new(old_arena, old_levels, self.alloc.clone());
        let mut used_exceptional_placement = false;
        for level in guard.regions_mut().iter_mut() {
            level.drain_values_and_clear(|entry| {
                used_exceptional_placement |= self.insert_unique(entry.key, entry.value);
            });
        }
        // guard drops at end of scope, deallocating old_arena. All slots
        // are CTRL_EMPTY so `drop_values` is a no-op on success.
        drop(guard);
        if transition == EpochTransition::PlacementRecovery || used_exceptional_placement {
            self.epoch.start_with_placement_recovery(transition);
        } else {
            self.epoch.start(transition);
        }
    }

    /// Fallible counterpart to [`Self::resize`]. Allocates the new backing
    /// storage before touching `self`, so `Err` leaves the map intact.
    fn try_resize(&mut self, new_capacity: usize) -> Result<(), TryReserveError>
    where
        S: Clone,
    {
        let prior_epoch = self.epoch;
        let hash_builder = self.hash_builder.clone();
        let mut new_map = Self::try_with_slots_and_reserve_fraction_and_hasher_in(
            new_capacity,
            self.reserve_fraction,
            hash_builder,
            self.alloc.clone(),
        )?;

        // Clear each source ctrl before handing the moved entry to
        // `insert_unique`. If that panics (e.g. via a user-provided `Hash`
        // impl), the un-iterated slots remain OCCUPIED on `self` and the
        // already-moved ones are EMPTY, so both `self.drop_values` and
        // `new_map.drop_values` are sound on unwind.
        let mut used_exceptional_placement = false;
        for level in &mut self.levels {
            level.drain_reset(|entry| {
                self.len -= 1;
                used_exceptional_placement |= new_map.insert_unique(entry.key, entry.value);
            });
        }
        debug_assert_eq!(self.len, 0);
        *self = new_map;
        self.epoch = prior_epoch;
        if used_exceptional_placement {
            self.epoch
                .start_with_placement_recovery(EpochTransition::ExplicitResize);
        } else {
            self.epoch.start(EpochTransition::ExplicitResize);
        }
        Ok(())
    }

    /// Internal fallible ctor for `try_resize`. `slots` is raw slot count
    /// (already inflated by the caller); public ctors take an insertion
    /// budget and inflate via `capacity_for` — this one skips that.
    fn try_with_slots_and_reserve_fraction_and_hasher_in(
        slots: usize,
        reserve_fraction: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryReserveError> {
        if slots > MAX_ELASTIC_SLOTS {
            return Err(TryReserveError::CapacityOverflow);
        }
        let geometry = ElasticGeometry::for_slots(slots, reserve_fraction);
        Self::try_from_geometry(&geometry, reserve_fraction, hash_builder, alloc)
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
                    if let Some((slot, probe)) = (0..budget).find_map(|logical_index| {
                        let logical_index = u64::try_from(logical_index).ok()?;
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
        for logical_index in 0..UNIFORM_SEARCH_CAP {
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
        control::is_free(self.levels[level].control_at(slot)).then_some(slot)
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

    /// SAFETY: `level_idx` < `self.levels.len()` and `slot_idx` references an
    /// occupied slot in that level.
    #[inline]
    unsafe fn slot_ref(&self, level_idx: usize, slot_idx: usize) -> &SlotEntry<K, V> {
        unsafe { self.levels[level_idx].get_ref(slot_idx) }
    }

    /// SAFETY: same as [`Self::slot_ref`] plus caller holds exclusive access.
    #[inline]
    unsafe fn slot_mut(&mut self, level_idx: usize, slot_idx: usize) -> &mut SlotEntry<K, V> {
        unsafe { self.levels[level_idx].get_mut(slot_idx) }
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
        if let Some(entry) = self.entry_if_match(0, h11_slot, key_fingerprint, key) {
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
            if let Some(entry) = self.entry_if_match(level, slot, key_fingerprint, key) {
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
                if let Some(entry) = self.entry_if_match(level_index, slot, key_fingerprint, key) {
                    return Some(on_hit(level_index, slot, entry));
                }
            }
        }
        None
    }

    #[inline]
    fn entry_if_match<'a, Q>(
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
        let level = unsafe { self.levels.get_unchecked(level) };
        if level.control_at(slot) != key_fingerprint {
            return None;
        }
        let entry = unsafe { level.get_ref(slot) };
        key.equivalent(&entry.key).then_some(entry)
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

#[cfg(test)]
mod tests {
    use super::*;

    use core::hash::{BuildHasher, Hasher};
    use core::mem::ManuallyDrop;
    use core::num::{NonZeroU32, NonZeroU64, NonZeroU128, NonZeroUsize};
    use core::ptr;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use crate::common::exact::reference::{ScalarElastic, ScalarElasticLimits};
    use crate::common::test_support::{
        self, CountDrop, IdentityBuildHasher, PanicHashKey, PanicOnFirstDrop, ToggleAllocator,
    };
    use alloc::sync::Arc;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    #[derive(Clone, Copy)]
    struct ConstHashBuilder;

    struct ConstHasher;

    impl Hasher for ConstHasher {
        fn finish(&self) -> u64 {
            0
        }

        fn write(&mut self, _: &[u8]) {}
    }

    impl BuildHasher for ConstHashBuilder {
        type Hasher = ConstHasher;

        fn build_hasher(&self) -> Self::Hasher {
            ConstHasher
        }
    }

    #[derive(Clone, Copy, Eq, Hash, PartialEq)]
    struct Zst;

    #[repr(align(256))]
    #[derive(Clone, Copy, Eq, Hash, PartialEq)]
    struct OverAligned(u64);

    fn assert_exact_trace(
        n: usize,
        reserve_exponent: u32,
        identities: impl IntoIterator<Item = u64>,
    ) {
        let reserve = ReserveFraction::from_exponent(reserve_exponent).unwrap();
        let config = PaperConfig::new(n, reserve_exponent).unwrap();
        let plan = config.elastic_plan();
        let mut table = ElasticTable::<u64, u64, IdentityBuildHasher>::
            try_with_slots_and_reserve_fraction_and_hasher_in(
                n,
                reserve,
                IdentityBuildHasher,
                Global,
            )
            .unwrap();
        assert_eq!(
            table
                .levels
                .iter()
                .map(ArenaSlots::capacity)
                .collect::<Vec<_>>(),
            plan.level_lengths().collect::<Vec<_>>()
        );
        assert_eq!(
            table.scheduler.batch_ends.as_ref(),
            plan.batch_quotas()
                .scan(0_usize, |total, quota| {
                    *total += quota;
                    Some(*total)
                })
                .collect::<Vec<_>>()
        );

        let limits = ScalarElasticLimits::new(
            NonZeroUsize::new(ELASTIC_PROBE_BUDGET_C).unwrap(),
            NonZeroU32::new(probe::RANGE_WORD_CAP).unwrap(),
            NonZeroU64::new(UNIFORM_SEARCH_CAP).unwrap(),
            NonZeroU128::new(QUERY_POSITION_CAP).unwrap(),
        );
        let mut scalar = ScalarElastic::new(config, CounterPrf::new(ELASTIC_PROBE_SEED), limits);

        for identity in identities {
            let prepared = PreparedElasticKey::new(identity);
            assert_eq!(table.hash_builder.hash_one(identity), identity);
            assert!(matches!(
                BatchScheduler::on_insert(table.len, table.total_slots, table.max_insertions),
                InsertAction::Continue
            ));
            let target = table.scheduler.target(table.len);
            let placement = table
                .choose_slot_for_new_key(prepared.route.probe, target)
                .unwrap();
            let expected = scalar.insert(identity);
            let global_slot = table.levels[..placement.level]
                .iter()
                .map(ArenaSlots::capacity)
                .sum::<usize>()
                + placement.slot;

            // The oracle's case label is not carried by the table; its
            // observable outcome (level, slot, and paper position) is.
            assert_eq!(placement.level, expected.location.level);
            assert_eq!(placement.slot, expected.location.slot_in_level);
            assert_eq!(global_slot, expected.location.global_slot);
            assert_eq!(placement.phi, expected.phi);
            assert_eq!(
                placement.phi,
                probe::elastic_phi(
                    expected.location.level as u128 + 1,
                    u128::from(expected.paper_probe)
                )
                .unwrap()
            );

            assert_eq!(
                table.place_new_entry(
                    identity,
                    identity,
                    prepared,
                    control::control_fingerprint(identity),
                    placement,
                ),
                (placement.level, placement.slot)
            );
            assert_eq!(
                table
                    .levels
                    .iter()
                    .map(|level| level.len as usize)
                    .collect::<Vec<_>>(),
                scalar.level_occupancy()
            );
            assert_eq!(
                table.find_slot_indices_prepared(
                    &identity,
                    prepared,
                    control::control_fingerprint(identity),
                ),
                Some((placement.level, placement.slot))
            );
            let query = scalar.query(identity);
            assert_eq!(query.global_slot, global_slot);
            assert!(
                query.found_position <= placement.phi,
                "lookup order visits phi={} no later than placement phi={}",
                query.found_position,
                placement.phi
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn elastic_placement_matches_the_scalar_paper_model() {
        assert_exact_trace(8, 3, [0, 1, 2, 1523, 2540, 2541, 2542]);
        for &(n, reserve_exponent) in &[(31, 4), (65, 6), (257, 8)] {
            let target = PaperConfig::new(n, reserve_exponent)
                .unwrap()
                .max_insertions();
            assert_exact_trace(
                n,
                reserve_exponent,
                (0..target).map(|identity| identity as u64),
            );
        }
    }

    #[test]
    fn compact_query_counters_cover_every_supported_geometry() {
        assert_eq!(MAX_CASE1_LOGICAL_PROBES, 7_688);
        assert_eq!(
            PaperConfig::new(MAX_ELASTIC_SLOTS, ReserveFraction::DEFAULT.exponent())
                .unwrap()
                .elastic_plan()
                .level_count(),
            u32::BITS as usize
        );
        #[cfg(target_pointer_width = "64")]
        {
            assert!(
                ElasticGeometry::for_insert_budget(MAX_ELASTIC_SLOTS, ReserveFraction::DEFAULT,)
                    .is_none()
            );
            let result = ElasticTable::<u64, u64, IdentityBuildHasher>::
                try_with_slots_and_reserve_fraction_and_hasher_in(
                    MAX_ELASTIC_SLOTS + 1,
                    ReserveFraction::DEFAULT,
                    IdentityBuildHasher,
                    Global,
                );
            assert!(matches!(result, Err(TryReserveError::CapacityOverflow)));
        }
        assert!(probe::elastic_phi(1, 383).unwrap() <= QUERY_POSITION_CAP);
        assert!(probe::elastic_phi(1, 384).unwrap() > QUERY_POSITION_CAP);
        for level in 0..u32::BITS as usize {
            for_each_phi_route(level, 1, QUERY_POSITION_CAP, |paper_probe, _| {
                assert!(usize::try_from(paper_probe - 1).unwrap() < QUERY_PROBE_LIMIT);
            });
        }

        let mut table = ElasticTable::<u64, u64, IdentityBuildHasher>::
            try_with_slots_and_reserve_fraction_and_hasher_in(
                31,
                ReserveFraction::from_exponent(4).unwrap(),
                IdentityBuildHasher,
                Global,
            )
            .unwrap();
        table.extend_probe_schedule(QUERY_POSITION_CAP);
        assert!(
            table
                .probe_schedule
                .iter()
                .all(|route| route.counter_base != H11_COUNTER_BASE)
        );
    }

    #[test]
    fn query_schedule_never_reallocates_within_an_epoch() {
        let mut table = ElasticTable::<u64, u64, IdentityBuildHasher>::
            try_with_slots_and_reserve_fraction_and_hasher_in(
                8_192,
                ReserveFraction::DEFAULT,
                IdentityBuildHasher,
                Global,
            )
            .unwrap();
        let initial_ptr = table.probe_schedule.as_ptr();
        let initial_capacity = table.probe_schedule.capacity();

        table.extend_probe_schedule(QUERY_POSITION_CAP);

        assert_eq!(table.probe_schedule.as_ptr(), initial_ptr);
        assert_eq!(table.probe_schedule.capacity(), initial_capacity);
        assert_eq!(table.probe_schedule.len(), initial_capacity);
    }

    #[test]
    fn query_schedule_caches_each_routes_exact_level_bound() {
        let mut table = ElasticTable::<u64, u64, IdentityBuildHasher>::
            try_with_slots_and_reserve_fraction_and_hasher_in(
                8_193,
                ReserveFraction::DEFAULT,
                IdentityBuildHasher,
                Global,
            )
            .unwrap();

        table.extend_probe_schedule(QUERY_POSITION_CAP);

        for route in &table.probe_schedule {
            assert_eq!(
                route.range_upper as usize,
                table.levels[route.level()].capacity()
            );
        }
    }

    #[test]
    fn elastic_geometry_carries_capacity_and_batch_state() {
        for &requested in &[0usize, 1, 127, 1_000, 10_000] {
            let reserve_fraction = ReserveFraction::DEFAULT;
            let geometry = ElasticGeometry::for_insert_budget(requested, reserve_fraction).unwrap();
            assert!(
                geometry.max_insertions >= requested,
                "requested={requested} max_insertions={}",
                geometry.max_insertions
            );
            assert_eq!(
                geometry.level_capacities.iter().sum::<usize>(),
                geometry.total_slots
            );
            assert_eq!(
                geometry.batch_plan.iter().sum::<usize>(),
                geometry.max_insertions
            );
            if geometry.total_slots >= 2 {
                let config =
                    PaperConfig::new(geometry.total_slots, reserve_fraction.exponent()).unwrap();
                let plan = config.elastic_plan();
                assert_eq!(
                    &*geometry.level_capacities,
                    plan.level_lengths().collect::<Vec<_>>()
                );
                assert_eq!(
                    &*geometry.batch_plan,
                    plan.batch_quotas().collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn clear_marks_each_slot_empty_before_dropping_its_value() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut map = ManuallyDrop::new(ElasticHashMap::<u64, PanicOnFirstDrop>::with_capacity(32));
        for key in 0..3 {
            map.insert(key, PanicOnFirstDrop(drops.clone()));
        }
        let first_occupied = map
            .table()
            .levels
            .iter()
            .enumerate()
            .find_map(|(level_index, level)| {
                (0..level.capacity())
                    .find(|&slot| control::is_occupied(level.control_at(slot)))
                    .map(|slot| (level_index, slot))
            })
            .unwrap();

        let result = catch_unwind(AssertUnwindSafe(|| map.clear()));
        assert!(result.is_err());
        assert_eq!(
            map.table().levels[first_occupied.0].control_at(first_occupied.1),
            CTRL_EMPTY
        );
        let live_controls = map
            .table()
            .levels
            .iter()
            .map(|level| {
                (0..level.capacity())
                    .filter(|&slot| control::is_occupied(level.control_at(slot)))
                    .count()
            })
            .sum::<usize>();
        assert_eq!(map.len(), live_controls);
        assert!(map.table().levels.iter().all(|level| {
            level.len as usize
                == (0..level.capacity())
                    .filter(|&slot| control::is_occupied(level.control_at(slot)))
                    .count()
        }));

        map.clear();
        assert!(map.is_empty());
        assert_eq!(drops.load(Ordering::SeqCst), 3);
        unsafe { ManuallyDrop::drop(&mut map) };
    }

    #[test]
    fn caught_hash_panic_during_try_resize_leaves_counters_valid() {
        let panic = Arc::new(AtomicBool::new(false));
        let drops = Arc::new(AtomicUsize::new(0));
        let key_drops = Arc::new(AtomicUsize::new(0));
        let key = |id: u64| PanicHashKey {
            id,
            armed: panic.clone(),
            drops: key_drops.clone(),
        };
        let mut map = ElasticHashMap::<PanicHashKey, CountDrop>::with_capacity(32);
        for id in 0..16_u64 {
            map.insert(key(id), CountDrop(drops.clone()));
        }

        panic.store(true, Ordering::SeqCst);
        let result = catch_unwind(AssertUnwindSafe(|| map.try_reserve(4_096)));
        assert!(result.is_err());
        panic.store(false, Ordering::SeqCst);

        let live_controls = map
            .table()
            .levels
            .iter()
            .map(|level| {
                (0..level.capacity())
                    .filter(|&slot| control::is_occupied(level.control_at(slot)))
                    .count()
            })
            .sum::<usize>();
        assert_eq!(map.len(), live_controls);
        assert!(map.table().levels.iter().all(|level| {
            level.len as usize
                == (0..level.capacity())
                    .filter(|&slot| control::is_occupied(level.control_at(slot)))
                    .count()
        }));
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        let live_keys = map.keys().map(|key| key.id).collect::<Vec<_>>();
        map.insert(key(100), CountDrop(drops.clone()));
        map.try_reserve(4_096).unwrap();
        for id in live_keys.into_iter().chain([100]) {
            assert!(map.contains_key(&key(id)));
        }
        drop(map);
        assert_eq!(drops.load(Ordering::SeqCst), 17);
    }

    #[test]
    fn elastic_metadata_is_appended_without_moving_control_or_data() {
        fn assert_layout<K, V>() {
            for &slots in &[0, 1, 7, 8, 31, 256] {
                let (base, data_offset) = arena::layout_for::<K, V>(slots).unwrap();
                let extended = elastic_arena_layout::<K, V>(slots).unwrap();
                assert_eq!(extended.data_base_off, data_offset);
                if slots == 0 {
                    assert_eq!(extended.layout.size(), 0);
                    assert_eq!(extended.membership.words, 0);
                } else {
                    assert_eq!(extended.membership.offset, base.size());
                    assert_eq!(
                        extended.membership.words,
                        slots.div_ceil(membership::SLOTS_PER_WORD)
                    );
                    assert!(extended.layout.size() > base.size());
                }
            }
        }

        assert_layout::<u64, u64>();
        assert_layout::<Zst, Zst>();
        assert_layout::<OverAligned, OverAligned>();
        assert!(mem::size_of::<ElasticMetadataWord>() <= 2 * membership::SLOTS_PER_WORD);

        let table =
            ElasticTable::<OverAligned, OverAligned>::with_capacity_and_reserve_and_hasher_in(
                64,
                ReserveFraction::DEFAULT,
                DefaultHashBuilder::default(),
                Global,
            );
        let layout = elastic_arena_layout::<OverAligned, OverAligned>(table.total_slots).unwrap();
        assert_eq!(
            table.membership_ptr().addr(),
            unsafe { table.arena.as_ptr().add(layout.membership.offset) }.addr()
        );
        assert_eq!(
            table.membership_ptr().addr() % mem::align_of::<ElasticMetadataWord>(),
            0
        );
        for word in 0..table.membership.words {
            let metadata = unsafe { &*table.membership_ptr().add(word) };
            assert_eq!(metadata.membership, 0);
            assert_eq!(metadata.route_bins, [0; 4]);
        }
        assert_eq!(
            table.levels[0].data_ptr().addr() % mem::align_of::<OverAligned>(),
            0
        );
    }

    #[test]
    fn normal_inserts_advance_batch_scheduler() {
        let mut map: ElasticHashMap<usize, usize> = ElasticHashMap::with_capacity(1024);
        let initial_quota = map.table().scheduler.batch_ends[0];
        assert!(
            initial_quota > 0,
            "test requires a non-empty bootstrap batch"
        );

        for key in 0..initial_quota {
            map.insert(key, key);
        }
        // Positions `0..quota` were bootstrap placements; position `quota`,
        // the next insert, opens the first level pair.
        assert_eq!(
            map.table().scheduler.target_at(initial_quota - 1),
            BatchTarget::Bootstrap
        );
        assert_eq!(map.table().scheduler.current_batch_index, 0);

        map.insert(initial_quota, initial_quota);
        let len = map.len();
        assert_eq!(
            map.table().scheduler.target_at(len),
            BatchTarget::LevelPair(0)
        );
        assert!(map.table().scheduler.current_batch_index > 0);
    }

    #[test]
    fn batch_target_follows_the_live_count_in_both_directions() {
        let mut map: ElasticHashMap<usize, usize> = ElasticHashMap::with_capacity(1024);
        let quota = map.table().scheduler.batch_ends[0];
        assert!(quota > 0);

        for key in 0..=quota {
            map.insert(key, key);
        }
        let len = map.len();
        assert_eq!(
            map.table().scheduler.target_at(len),
            BatchTarget::LevelPair(0)
        );

        // Two removals put the live count back inside the bootstrap window.
        assert_eq!(map.remove(&0), Some(0));
        assert_eq!(map.remove(&1), Some(1));
        let len = map.len();
        assert_eq!(map.table().scheduler.target_at(len), BatchTarget::Bootstrap);

        // The scalar oracle's prefix-sum rule, restated: batch `i` holds the
        // positions in `[ends[i-1], ends[i])`.
        let ends = map.table().scheduler.batch_ends.clone();
        let mut scheduler = map.table().scheduler.clone();
        for len in 0..*ends.last().unwrap() {
            let expected = ends.iter().position(|&end| len < end).unwrap();
            let target = scheduler.target(len);
            let index = match target {
                BatchTarget::Bootstrap => 0,
                BatchTarget::LevelPair(pair) => pair + 1,
            };
            assert_eq!(index, expected, "len {len}");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn deletes_past_the_threshold_refresh_the_membership_filter() {
        test_support::assert_deletes_past_threshold_refresh_filter::<ElasticTable<u64, u64>>(
            |table, key| {
                let prepared = PreparedElasticKey::new(table.hash_builder.hash_one(key));
                table.route_filter(prepared).maybe_present
            },
            |table| table.stale_membership,
        );
    }

    #[test]
    fn duplicate_insert_does_not_advance_the_paper_schedule() {
        let mut map: ElasticHashMap<u64, u64> = ElasticHashMap::with_capacity(64);
        assert_eq!(map.insert(7, 11), None);
        let batch = map.table().scheduler.current_batch_index;
        let len = map.len();
        let target = map.table().scheduler.target_at(len);

        assert_eq!(map.insert(7, 13), Some(11));
        assert_eq!(map.len(), 1);
        assert_eq!(map.table().scheduler.current_batch_index, batch);
        let len = map.len();
        assert_eq!(map.table().scheduler.target_at(len), target);
        assert_eq!(map.get(&7), Some(&13));
    }

    /// Independent restatement of the filter's bit pattern, kept here so a
    /// change to the shared derivation has to be deliberate.
    fn membership_bits_from_signature(signature: u64) -> u64 {
        let first = signature & 63;
        let second = (signature >> 32) & 63;
        (1_u64 << first) | (1_u64 << second)
    }

    fn membership_maybe_contains_prepared<K, V, S, A>(
        table: &ElasticTable<K, V, S, A>,
        prepared: PreparedElasticKey,
    ) -> bool
    where
        K: Eq + Hash,
        S: BuildHasher,
        A: Allocator + Clone,
    {
        table.membership_maybe_contains(prepared.route, prepared.membership)
    }

    #[test]
    fn compact_prepared_elastic_state_is_register_sized() {
        assert_eq!(mem::size_of::<PreparedElasticRoute>(), 8);
        assert_eq!(mem::align_of::<PreparedElasticRoute>(), 8);
        assert_eq!(mem::size_of::<PreparedElasticKey>(), 16);
        assert_eq!(mem::align_of::<PreparedElasticKey>(), 8);
    }

    #[test]
    fn route_summary_saturates_deep_levels_into_the_last_bit() {
        assert_eq!(summary_level(0), 0);
        assert_eq!(
            summary_level(ROUTE_SUMMARY_LEVELS - 2),
            ROUTE_SUMMARY_LEVELS - 2
        );
        assert_eq!(
            summary_level(ROUTE_SUMMARY_LEVELS - 1),
            ROUTE_SUMMARY_LEVELS - 1
        );
        assert_eq!(
            summary_level(ROUTE_SUMMARY_LEVELS),
            ROUTE_SUMMARY_LEVELS - 1
        );
        assert_eq!(summary_level(40), ROUTE_SUMMARY_LEVELS - 1);

        // Expansion is the inverse view: the saturating bit covers every level
        // index at or past it, and a clear bit widens to nothing.
        let filter = |level_mask| ElasticRouteFilter {
            maybe_present: true,
            level_mask,
        };
        assert_eq!(filter(0).expanded_level_mask(), 0);
        assert_eq!(filter(0b101).expanded_level_mask(), 0b101);
        assert_eq!(
            filter(1 << (ROUTE_SUMMARY_LEVELS - 1)).expanded_level_mask(),
            u32::MAX << (ROUTE_SUMMARY_LEVELS - 1)
        );
        let level_limit = usize::try_from(probe::ELASTIC_LEVEL_LIMIT).unwrap();
        for level in 0..level_limit {
            let recorded = filter(1 << summary_level(level)).expanded_level_mask();
            assert_ne!(recorded & (1 << level), 0, "level {level} lost its bit");
        }
    }

    #[test]
    fn route_summary_still_narrows_shallow_levels_on_wide_geometries() {
        // Enough levels that the old encoding fell back to an all-ones mask.
        let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
            ElasticHashMap::with_capacity_and_hasher(1 << 20, IdentityBuildHasher);
        assert!(
            map.table().levels.len() > ROUTE_SUMMARY_LEVELS,
            "fixture needs more levels than the summary width, got {}",
            map.table().levels.len()
        );
        let key_count = if cfg!(miri) { 64_u64 } else { 4_096_u64 };
        for key in 0..key_count {
            map.insert(key, key);
        }
        for key in 0..key_count {
            let prepared = PreparedElasticKey::new(key);
            let mask = map.table().route_filter(prepared).level_mask;
            assert!(mask != 0 && u16::try_from(mask).is_ok(), "mask {mask:#x}");
            assert!(
                mask.count_ones() < u32::try_from(ROUTE_SUMMARY_LEVELS).unwrap(),
                "key {key} mask {mask:#x} must exclude at least one level"
            );
            assert_eq!(map.get(&key), Some(&key));
        }
        assert_eq!(map.get(&(key_count + 1)), None);
    }

    #[test]
    fn prepared_route_keeps_the_geometry_independent_signature() {
        for hash in (0..65_536_u64).map(|value| value.wrapping_mul(0x9e37_79b9_7f4a_7c15)) {
            let route = PreparedElasticRoute::new(hash);
            let signature = route.signature();
            assert_eq!(signature, route.probe.routing_signature());
        }
    }

    #[test]
    fn compact_membership_matches_the_existing_signature_formula() {
        for hash in (0..16_384_u64).map(|value| value.rotate_left(19)) {
            let prepared = PreparedElasticKey::new(hash);
            let signature = prepared.route.signature();
            let expected = membership_bits_from_signature(signature);
            assert_eq!(prepared.membership.bits(), expected);
            for words in [1_usize, 3, 17, 257] {
                let product = u128::from(signature) * u128::try_from(words).unwrap();
                assert_eq!(
                    MembershipKey::word(signature, words),
                    usize::try_from(product >> 64).unwrap(),
                );
            }
        }
    }

    #[test]
    fn prepared_elastic_key_uses_the_exact_probe_signature() {
        let hash = 0xd1b5_4a32_d192_ed03;
        let prepared = PreparedElasticKey::new(hash);
        assert_eq!(
            prepared.route.signature(),
            prepared.route.probe.routing_signature()
        );
    }

    #[test]
    fn elastic_controls_keep_the_public_hash_fingerprint() {
        let hash = 1_u64;
        assert_ne!(
            control::control_fingerprint(hash),
            control::control_fingerprint(PreparedElasticRoute::new(hash).signature())
        );
        let prepared = PreparedElasticKey::new(hash);
        let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
            ElasticHashMap::with_capacity_and_hasher(64, IdentityBuildHasher);

        map.insert(hash, 7);
        let location = map
            .table()
            .find_slot_indices_prepared(&hash, prepared, control::control_fingerprint(hash))
            .unwrap();

        assert_eq!(
            map.table().levels[location.0].control_at(location.1),
            control::control_fingerprint(hash)
        );
    }

    #[test]
    fn route_summary_conservatively_records_every_live_level() {
        let (capacity, key_count, additional) = if cfg!(miri) {
            (128, 128_u64, 1_024)
        } else {
            (4_096, 4_096_u64, 20_000)
        };
        let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
            ElasticHashMap::with_capacity_and_hasher(capacity, IdentityBuildHasher);
        for key in 0..key_count {
            map.insert(key, key ^ 0x55);
        }

        for key in 0..key_count {
            let location = map
                .table()
                .levels
                .iter()
                .enumerate()
                .find_map(|(level_index, level)| {
                    (0..level.capacity()).find_map(|slot| {
                        (control::is_occupied(level.control_at(slot))
                            && unsafe { level.get_ref(slot) }.key == key)
                            .then_some((level_index, slot))
                    })
                })
                .unwrap();
            let prepared = PreparedElasticKey::new(key);
            assert_ne!(
                map.table().route_filter(prepared).level_mask
                    & (1_u32 << summary_level(location.0)),
                0,
                "key {key} at level {}",
                location.0
            );
            assert_eq!(map.get(&key), Some(&(key ^ 0x55)));
        }
        assert!(
            map.table()
                .levels
                .iter()
                .filter(|level| level.len != 0)
                .count()
                > 1,
            "route summary must cover more than one occupied level"
        );

        let cloned = map.clone();
        for key in 0..key_count {
            assert_eq!(cloned.get(&key), Some(&(key ^ 0x55)));
        }

        map.reserve(additional);
        for key in 0..key_count {
            assert_eq!(map.get(&key), Some(&(key ^ 0x55)));
        }

        map.clear();
        assert!(map.table().levels.len() <= ROUTE_SUMMARY_LEVELS);
        for word in 0..map.table().membership.words {
            assert_eq!(
                unsafe { (*map.table().membership_ptr().add(word)).route_bins },
                [0; 4]
            );
        }
    }

    #[test]
    fn prepared_elastic_key_remains_geometry_independent_across_growth() {
        let hash = 0x9e37_79b9_7f4a_7c15;
        let prepared = PreparedElasticKey::new(hash);
        let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
            ElasticHashMap::with_capacity_and_hasher(1, IdentityBuildHasher);
        map.insert(hash, 7);
        map.reserve(4_096);
        assert!(membership_maybe_contains_prepared(map.table(), prepared));
        assert_eq!(map.get(&hash), Some(&7));
    }

    #[test]
    fn membership_filter_never_forgets_live_or_deleted_hashes() {
        let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
            ElasticHashMap::with_capacity_and_hasher(64, IdentityBuildHasher);
        let inserted_hash = map.table().hash_builder.hash_one(7_u64);
        let prepared = PreparedElasticKey::new(inserted_hash);
        assert!(!membership_maybe_contains_prepared(map.table(), prepared));

        assert_eq!(map.insert(7, 11), None);
        assert!(membership_maybe_contains_prepared(map.table(), prepared));

        assert_eq!(map.insert(7, 13), Some(11));
        assert_eq!(map.len(), 1);
        assert!(membership_maybe_contains_prepared(map.table(), prepared));

        assert_eq!(map.remove(&7), Some(13));
        assert!(membership_maybe_contains_prepared(map.table(), prepared));
        assert_eq!(map.insert(7, 17), None);
        assert_eq!(map.get(&7), Some(&17));
    }

    #[test]
    fn blocked_membership_never_forgets_inserted_hashes() {
        let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
            ElasticHashMap::with_capacity_and_hasher(2_048, IdentityBuildHasher);
        for key in 0..1_024_u64 {
            map.insert(key, key);
        }
        for key in 0..1_024_u64 {
            assert!(membership_maybe_contains_prepared(
                map.table(),
                PreparedElasticKey::new(key)
            ));
        }
    }

    #[test]
    fn prepared_membership_remains_valid_across_growth() {
        let key = 0xD1B5_4A32_D192_ED03_u64;
        let prepared = PreparedElasticKey::new(key);
        let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
            ElasticHashMap::with_capacity_and_hasher(1, IdentityBuildHasher);

        map.insert(key, 7);
        assert!(membership_maybe_contains_prepared(map.table(), prepared));
        let old_slots = map.table().total_slots;

        map.reserve(1_024);
        assert!(map.table().total_slots > old_slots);
        assert!(membership_maybe_contains_prepared(map.table(), prepared));
        assert_eq!(map.get(&key), Some(&7));
    }

    #[test]
    fn membership_filter_resets_and_rebuilds_at_table_boundaries() {
        let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
            ElasticHashMap::with_capacity_and_hasher(128, IdentityBuildHasher);
        for key in 0_u64..96 {
            map.insert(key, key ^ 0x55);
        }

        let mut cloned = map.clone();
        for key in 0_u64..96 {
            let hash = cloned.table().hash_builder.hash_one(key);
            assert!(membership_maybe_contains_prepared(
                cloned.table(),
                PreparedElasticKey::new(hash),
            ));
            assert_eq!(cloned.get(&key), Some(&(key ^ 0x55)));
        }

        cloned.clear();
        for key in 0_u64..96 {
            let hash = cloned.table().hash_builder.hash_one(key);
            assert!(!membership_maybe_contains_prepared(
                cloned.table(),
                PreparedElasticKey::new(hash),
            ));
        }

        for key in 256_u64..384 {
            cloned.insert(key, key);
        }
        cloned.reserve(512);
        for key in 256_u64..384 {
            let hash = cloned.table().hash_builder.hash_one(key);
            assert!(membership_maybe_contains_prepared(
                cloned.table(),
                PreparedElasticKey::new(hash),
            ));
            assert_eq!(cloned.get(&key), Some(&key));
        }
    }

    #[test]
    fn all_vacant_entry_apis_record_membership() {
        let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
            ElasticHashMap::with_capacity_and_hasher(128, IdentityBuildHasher);

        map.try_insert(11, 1).unwrap();
        map.entry(22).or_insert(2);
        map.get_or_insert_key_with(&33_u64, 3, |key| *key);

        for key in [11_u64, 22, 33] {
            let hash = map.table().hash_builder.hash_one(key);
            assert!(membership_maybe_contains_prepared(
                map.table(),
                PreparedElasticKey::new(hash)
            ));
            assert!(map.contains_key(&key));
        }
    }

    #[test]
    fn drain_and_failed_reserve_preserve_membership_invariants() {
        let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
            ElasticHashMap::with_capacity_and_hasher(128, IdentityBuildHasher);
        for key in 0_u64..64 {
            map.insert(key, key);
        }
        assert!(map.try_reserve(usize::MAX).is_err());
        for key in 0_u64..64 {
            let hash = map.table().hash_builder.hash_one(key);
            assert!(membership_maybe_contains_prepared(
                map.table(),
                PreparedElasticKey::new(hash)
            ));
            assert_eq!(map.get(&key), Some(&key));
        }

        map.drain().for_each(drop);
        assert!(map.is_empty());
        for key in 0_u64..64 {
            let hash = map.table().hash_builder.hash_one(key);
            assert!(!membership_maybe_contains_prepared(
                map.table(),
                PreparedElasticKey::new(hash)
            ));
        }
    }

    #[test]
    fn allocator_failure_does_not_publish_or_forget_membership() {
        let fail = Arc::new(AtomicBool::new(true));
        let alloc = ToggleAllocator::new(Arc::clone(&fail));
        let failed = ElasticHashMap::<u64, u64, IdentityBuildHasher, ToggleAllocator>::
            try_with_capacity_and_reserve_and_hasher_in(
                128,
                ReserveFraction::DEFAULT,
                IdentityBuildHasher,
                alloc.clone(),
            );
        assert!(matches!(
            failed,
            Err(TryBuildError::Reserve(TryReserveError::AllocError))
        ));

        fail.store(false, Ordering::SeqCst);
        let mut map = ElasticHashMap::<u64, u64, IdentityBuildHasher, ToggleAllocator>::
            with_capacity_and_reserve_and_hasher_in(
                128,
                ReserveFraction::DEFAULT,
                IdentityBuildHasher,
                alloc,
            );
        for key in 0_u64..64 {
            map.insert(key, key ^ 0x5a);
        }

        fail.store(true, Ordering::SeqCst);
        assert_eq!(map.try_reserve(4_096), Err(TryReserveError::AllocError));
        for key in 0_u64..64 {
            let hash = map.table().hash_builder.hash_one(key);
            assert!(membership_maybe_contains_prepared(
                map.table(),
                PreparedElasticKey::new(hash)
            ));
            assert_eq!(map.get(&key), Some(&(key ^ 0x5a)));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn colliding_hashes_remain_distinguishable_through_delete_and_reuse() {
        let mut map: ElasticHashMap<u64, u64, ConstHashBuilder> =
            ElasticHashMap::with_capacity_and_hasher(512, ConstHashBuilder);
        let colliding_count = 64_u64;
        for key in 0..colliding_count {
            map.insert(key, key);
        }
        assert_eq!(map.remove(&0), Some(0));
        assert_eq!(map.insert(u64::MAX, 7), None);
        for key in 1..colliding_count {
            assert_eq!(map.get(&key), Some(&key));
        }
        assert_eq!(map.get(&u64::MAX), Some(&7));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn finite_probe_exhaustion_uses_observable_exceptional_recovery() {
        let reserve = ReserveFraction::DEFAULT;
        let mut table = ElasticTable::<u64, u64, ConstHashBuilder>::
            try_with_slots_and_reserve_fraction_and_hasher_in(
                8_192,
                reserve,
                ConstHashBuilder,
                Global,
            )
            .unwrap();
        let fingerprint = control::control_fingerprint(0);
        let prepared = PreparedElasticKey::new(0);
        let mut next_key = 0_u64;

        for logical_index in 0..UNIFORM_SEARCH_CAP {
            let paper_probe = u128::from(logical_index) + 1;
            if probe::elastic_phi(1, paper_probe).unwrap() > QUERY_POSITION_CAP {
                break;
            }
            let slot = table.route_exact(0, 0, logical_index).unwrap();
            if control::is_free(table.levels[0].control_at(slot)) {
                table.levels[0].write_with_control(
                    slot,
                    SlotEntry {
                        key: next_key,
                        value: next_key,
                    },
                    fingerprint,
                );
                table.levels[0].len += 1;
                table.len += 1;
                next_key += 1;
            }
        }
        assert!(
            table
                .choose_slot_for_new_key(prepared.route.probe, BatchTarget::Bootstrap)
                .is_none()
        );

        let before = table.epoch.snapshot(table.len);
        let location = table.insert_for_vacant_entry(u64::MAX, 7, 0);
        let after = table.epoch.snapshot(table.len);
        assert_eq!(after.generation, before.generation + 1);
        assert_eq!(after.placement_recoveries, before.placement_recoveries + 1);
        assert_eq!(after.transition, EpochTransition::PlacementRecovery);
        assert_ne!(table.probe_high_water & EXCEPTIONAL_PLACEMENT_FLAG, 0);
        assert!(membership_maybe_contains_prepared(&table, prepared));
        assert_eq!(
            table.find_slot_indices_prepared(&u64::MAX, prepared, fingerprint),
            Some(location)
        );
        for key in 0..next_key {
            assert!(
                table
                    .find_slot_indices_prepared(&key, prepared, fingerprint)
                    .is_some()
            );
        }
    }

    #[test]
    fn direct_lookup_returns_the_compared_slot_reference() {
        let mut table: ElasticTable<usize, usize> =
            ElasticTable::with_capacity_and_reserve_and_hasher_in(
                1024,
                ReserveFraction::DEFAULT,
                DefaultHashBuilder::default(),
                Global,
            );
        let mut insertion_count = 0;
        while insertion_count < table.max_insertions
            && !table.levels.iter().skip(1).any(|level| level.len > 0)
        {
            let key = insertion_count;
            table.insert_unique(key, key ^ 0xa5a5);
            insertion_count += 1;
        }
        assert!(
            table.levels.iter().skip(1).any(|level| level.len > 0),
            "test must exercise lookup beyond level 0"
        );

        for key in 0..insertion_count {
            let hash = table.hash_builder.hash_one(key);
            let prepared = PreparedElasticKey::new(hash);
            let fingerprint = control::control_fingerprint(hash);
            let location = table
                .find_slot_indices_prepared(&key, prepared, fingerprint)
                .expect("inserted key must have a location");
            let direct = table
                .find_entry_prepared(&key, prepared, fingerprint)
                .expect("inserted key must have an entry reference");
            let resolved = unsafe { table.slot_ref(location.0, location.1) };
            assert!(ptr::eq(direct, resolved), "key {key} returned a new slot");
        }

        let missing = usize::MAX;
        let hash = table.hash_builder.hash_one(missing);
        let prepared = PreparedElasticKey::new(hash);
        let fingerprint = control::control_fingerprint(hash);
        assert!(
            table
                .find_entry_prepared(&missing, prepared, fingerprint)
                .is_none()
        );
    }

    #[test]
    fn delete_below_cleanup_threshold_preserves_survivor_locations() {
        let mut map: ElasticHashMap<usize, usize> = ElasticHashMap::with_capacity(512);
        for key in 0..100 {
            map.insert(key, key);
        }
        let before: Vec<_> = (1..100)
            .map(|key| {
                let hash = map.table().hash_builder.hash_one(key);
                map.table()
                    .find_slot_indices_prepared(
                        &key,
                        PreparedElasticKey::new(hash),
                        control::control_fingerprint(hash),
                    )
                    .unwrap()
            })
            .collect();

        assert_eq!(map.remove(&0), Some(0));

        let after: Vec<_> = (1..100)
            .map(|key| {
                let hash = map.table().hash_builder.hash_one(key);
                map.table()
                    .find_slot_indices_prepared(
                        &key,
                        PreparedElasticKey::new(hash),
                        control::control_fingerprint(hash),
                    )
                    .unwrap()
            })
            .collect();
        assert_eq!(after, before);
    }

    #[test]
    fn rebuild_inserts_advance_batch_scheduler() {
        let mut table: ElasticTable<usize, usize> =
            ElasticTable::with_capacity_and_reserve_and_hasher_in(
                1024,
                ReserveFraction::DEFAULT,
                DefaultHashBuilder::default(),
                Global,
            );
        let initial_quota = table.scheduler.batch_ends[0];
        assert!(
            initial_quota > 0,
            "test requires a non-empty bootstrap batch"
        );

        for key in 0..=initial_quota {
            table.insert_unique(key, key);
        }

        let len = table.len;
        assert_eq!(table.scheduler.target(len), BatchTarget::LevelPair(0));
        assert!(table.scheduler.current_batch_index > 0);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn vacant_insert_uses_the_table_insertion_limit() {
        let mut table: ElasticTable<usize, usize> =
            ElasticTable::with_capacity_and_reserve_and_hasher_in(
                1024,
                ReserveFraction::DEFAULT,
                DefaultHashBuilder::default(),
                Global,
            );
        let rebuild_slots = table.total_slots * 2;
        let rebuild_geometry = ElasticGeometry::for_slots(rebuild_slots, table.reserve_fraction);
        let bootstrap_quota = rebuild_geometry.batch_plan[0];

        for key in 0..bootstrap_quota {
            table.insert_unique(key, key);
        }
        table.max_insertions = table.len;
        let previous_slots = table.total_slots;

        let key = bootstrap_quota;
        let hash = table.hash_builder.hash_one(key);
        table.insert_for_vacant_entry(key, key, hash);

        assert!(table.total_slots > previous_slots);
        let len = table.len;
        assert_eq!(table.scheduler.target(len), BatchTarget::LevelPair(0));
        assert!(table.scheduler.current_batch_index > 0);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn clone_and_clear_preserve_elastic_lookups() {
        let mut map: ElasticHashMap<u64, u64> = ElasticHashMap::with_capacity(512);
        for i in 0..384 {
            map.insert(i, i ^ 0xa5a5);
        }

        let cloned = map.clone();
        for i in 0..384 {
            assert_eq!(cloned.get(&i), Some(&(i ^ 0xa5a5)));
        }
        for i in 10_000..10_128 {
            assert_eq!(cloned.get(&i), None);
        }

        map.clear();
        for i in 512..896 {
            map.insert(i, i ^ 0x5a5a);
        }
        for i in 512..896 {
            assert_eq!(map.get(&i), Some(&(i ^ 0x5a5a)));
        }
        for i in 0..384 {
            assert_eq!(map.get(&i), None);
        }
    }

    #[test]
    fn retain_does_not_trigger_mid_iter_resize_with_clustered_tombstones() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(256);
        let cap = i32::try_from(map.capacity()).expect("test capacity fits i32");
        let n = cap * 2 / 3;
        for i in 0..n {
            map.insert(i, i);
        }
        let initial_capacity = map.capacity();
        map.retain(|k, _| k % 2 == 0);

        let expected_count = (0..n).filter(|i| i % 2 == 0).count();
        assert_eq!(map.len(), expected_count);
        for i in 0..n {
            if i % 2 == 0 {
                assert_eq!(map.get(&i), Some(&i), "kept key {i} missing");
            } else {
                assert!(map.get(&i).is_none(), "dropped key {i} survived");
            }
        }
        assert_eq!(
            map.capacity(),
            initial_capacity,
            "retain cannot resize while its scan is active"
        );
    }

    #[test]
    fn inserts_spill_to_deeper_levels_at_high_load() {
        // Paper §4: batches push later inserts into deeper levels.
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(512);
        assert!(
            map.table().levels.len() > 1,
            "test requires multi-level layout"
        );
        let max = i32::try_from(map.capacity()).expect("test capacity fits i32");
        for i in 0..max {
            map.insert(i, i);
        }
        assert!(
            map.table().levels.iter().skip(1).any(|level| level.len > 0),
            "expected the exact batch schedule to populate a deeper level"
        );
        for i in 0..max {
            assert_eq!(map.get(&i), Some(&i));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn removing_every_entry_empties_every_level() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(512);
        let max = i32::try_from(map.capacity()).expect("test capacity fits i32");
        for i in 0..max {
            map.insert(i, i);
        }
        for i in 0..max {
            map.remove(&i);
        }
        assert_eq!(map.len(), 0);
        assert!(map.table().levels.iter().all(|level| level.len == 0));
    }
}
