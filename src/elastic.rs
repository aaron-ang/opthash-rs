use core::hash::{BuildHasher, Hash};
use core::mem::{self, MaybeUninit};
use core::ptr;

use alloc::{boxed::Box, vec::Vec};
use allocator_api2::alloc::{Allocator, Global, Layout};
use equivalent::Equivalent;

use crate::ReserveFraction;
use crate::common::DefaultHashBuilder;
use crate::common::arena::{self, Arena, ArenaSlots, SlotEntry};
use crate::common::config::{CACHE_LINE, INITIAL_CAPACITY};
use crate::common::control::{self, CTRL_EMPTY, CTRL_TOMBSTONE, ControlByte};
use crate::common::error::{TryBuildError, TryReserveError};
use crate::common::exact::geometry::PaperConfig;
use crate::common::exact::probe::{self, CounterPrf, PreparedElasticProbe};
use crate::common::iter::RegionCursor;
use crate::common::math::capacity;
use crate::epoch::{EpochSnapshot, EpochState, EpochTransition};
use crate::macros;
use crate::map;

/// `(slot pointer, location)` yielded by the scan cursor: the pointer is read
/// by iterators, the `(level, slot)` location backs removal.
type ElasticScanItem<K, V> = (*mut SlotEntry<K, V>, (usize, usize));

// Fixed construction seed shared by placement, lookup, and membership.
const ELASTIC_PROBE_SEED: u64 = probe::WYHASH_DEFAULT_SECRET[0];
const ELASTIC_PROBE_BUDGET_C: usize = 8;
const RANGE_WORD_CAP: u32 = 8;
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
const MEMBERSHIP_SLOTS_PER_WORD: usize = 10;
const ROUTE_SUMMARY_LEVELS: usize = u16::BITS as usize;
const H11_COUNTER_BASE: u32 = probe::elastic_counter_base(0, 0);

const _: () = assert!(u32::BITS as u64 <= probe::ELASTIC_LEVEL_LIMIT);
const _: () = assert!(UNIFORM_SEARCH_CAP <= probe::ELASTIC_LOGICAL_LIMIT);
const _: () = assert!(MAX_CASE1_LOGICAL_PROBES as u64 <= probe::ELASTIC_LOGICAL_LIMIT);
const _: () = assert!(RANGE_WORD_CAP <= probe::ELASTIC_REJECTION_LIMIT);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExactInsertionCase {
    Batch0 {
        level: usize,
    },
    Case1 {
        batch: usize,
        current_level: usize,
        next_level: usize,
        free_current: usize,
        free_next: usize,
        budget: usize,
    },
    Case2 {
        batch: usize,
        current_level: usize,
        next_level: usize,
        free_current: usize,
        free_next: usize,
    },
    Case3 {
        batch: usize,
        current_level: usize,
        next_level: usize,
        free_current: usize,
        free_next: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExactPlacement {
    case: ExactInsertionCase,
    level: usize,
    slot: usize,
    paper_probe: u64,
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
type ElasticArenaBuild<K, V> = (Arena, LevelSlice<K, V>);

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
    membership_offset: usize,
    membership_words: usize,
}

#[inline]
fn membership_word_count(total_slots: usize) -> usize {
    total_slots.div_ceil(MEMBERSHIP_SLOTS_PER_WORD)
}

fn elastic_arena_layout<K, V>(total_slots: usize) -> Result<ElasticArenaLayout, TryReserveError> {
    let (base_layout, data_base_off) = arena::layout_for::<K, V>(total_slots)?;
    let membership_words = membership_word_count(total_slots);
    if membership_words == 0 {
        return Ok(ElasticArenaLayout {
            layout: base_layout,
            data_base_off,
            membership_offset: 0,
            membership_words: 0,
        });
    }
    let membership_layout = Layout::array::<ElasticMetadataWord>(membership_words)
        .map_err(|_| TryReserveError::AllocError)?;
    let (layout, membership_offset) = base_layout
        .extend(membership_layout)
        .map_err(|_| TryReserveError::AllocError)?;
    Ok(ElasticArenaLayout {
        layout: layout.pad_to_align(),
        data_base_off,
        membership_offset,
        membership_words,
    })
}

#[inline]
fn membership_tail_span<K, V>(total_slots: usize) -> usize {
    let bytes = membership_word_count(total_slots)
        .checked_mul(mem::size_of::<ElasticMetadataWord>())
        .expect("constructed Elastic membership size");
    if bytes == 0 {
        return 0;
    }
    let alignment = CACHE_LINE.max(mem::align_of::<SlotEntry<K, V>>());
    bytes
        .checked_add(alignment - 1)
        .expect("constructed Elastic membership padding")
        & !(alignment - 1)
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
struct PreparedMembership {
    bits: u64,
}

impl PreparedMembership {
    #[inline]
    fn from_signature(signature: u64) -> Self {
        let first = signature & 63;
        let step = ((signature >> 32) | 1) & 63;
        let second = first.wrapping_add(step) & 63;
        let third = second.wrapping_add(step) & 63;
        let fourth = third.wrapping_add(step) & 63;
        Self {
            bits: (1_u64 << first) | (1_u64 << second) | (1_u64 << third) | (1_u64 << fourth),
        }
    }

    #[inline]
    fn word(signature: u64, word_count: usize) -> usize {
        let product = u128::from(signature)
            * u128::try_from(word_count).expect("usize is representable as u128");
        usize::try_from(product >> 64).expect("multiply-high index is below word count")
    }
}

#[derive(Clone, Copy)]
struct PreparedElasticKey {
    route: PreparedElasticRoute,
    membership: PreparedMembership,
}

impl PreparedElasticKey {
    #[inline]
    fn new(hash: u64) -> Self {
        let route = PreparedElasticRoute::new(hash);
        Self {
            membership: PreparedMembership::from_signature(route.signature()),
            route,
        }
    }
}

const _: () = assert!(mem::size_of::<PreparedElasticRoute>() == 8);
const _: () = assert!(mem::size_of::<PreparedElasticKey>() == 16);

#[inline]
const fn expand_summary_level_mask(mask: u16, level_count: usize) -> u32 {
    if level_count > ROUTE_SUMMARY_LEVELS {
        u32::MAX
    } else {
        mask as u32
    }
}

fn probe_schedule_capacity(level_count: usize) -> usize {
    let mut count = 0;
    for level in 0..level_count {
        let paper_level = level as u128 + 1;
        for paper_probe in 1..=u128::from(UNIFORM_SEARCH_CAP) {
            let phi = probe::elastic_phi(paper_level, paper_probe)
                .expect("bounded Elastic query coordinate");
            if phi > QUERY_POSITION_CAP {
                break;
            }
            if level != 0 || paper_probe != 1 {
                count += 1;
            }
        }
    }
    count
}

fn probe_schedule(level_count: usize) -> Vec<PhiRoute> {
    Vec::with_capacity(probe_schedule_capacity(level_count))
}

fn try_probe_schedule(level_count: usize) -> Result<Vec<PhiRoute>, TryReserveError> {
    let mut schedule = Vec::new();
    schedule
        .try_reserve_exact(probe_schedule_capacity(level_count))
        .map_err(|_| TryReserveError::AllocError)?;
    Ok(schedule)
}

fn clone_probe_schedule(source: &[PhiRoute], level_count: usize) -> Vec<PhiRoute> {
    let mut schedule = probe_schedule(level_count);
    schedule.extend_from_slice(source);
    schedule
}

/// Schedule paper batches and allocation-epoch boundaries.
#[derive(Clone)]
pub(crate) struct BatchScheduler {
    batch_plan: Box<[usize]>,
    current_batch_index: usize,
    batch_remaining: usize,
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
    pub(crate) fn new(batch_plan: Box<[usize]>) -> Self {
        let initial_remaining = batch_plan.first().copied().unwrap_or(0);
        Self {
            batch_plan,
            current_batch_index: 0,
            batch_remaining: initial_remaining,
        }
    }

    /// Select structural work for the next insert.
    #[inline]
    pub(crate) fn on_insert(
        &mut self,
        current_len: usize,
        total_slots: usize,
        max_insertions: usize,
    ) -> InsertAction {
        let structural_action =
            Self::structural_action_for_next_insert(current_len, total_slots, max_insertions);
        if let Some(action) = structural_action {
            return action;
        }
        self.advance_batch_window();
        InsertAction::Continue
    }

    #[inline]
    fn structural_action_for_next_insert(
        current_len: usize,
        total_slots: usize,
        max_insertions: usize,
    ) -> Option<InsertAction> {
        if current_len >= max_insertions {
            let new_cap = if total_slots == 0 {
                INITIAL_CAPACITY
            } else {
                total_slots.saturating_mul(2)
            };
            return Some(InsertAction::Resize(new_cap));
        }
        None
    }

    /// Distinguish bootstrap placement from the level pair for later batches.
    #[inline]
    fn target(&self) -> BatchTarget {
        if self.current_batch_index == 0 {
            BatchTarget::Bootstrap
        } else {
            BatchTarget::LevelPair(self.current_batch_index - 1)
        }
    }

    /// Consume one insertion from the active batch.
    #[inline]
    fn complete_insert(&mut self) {
        self.batch_remaining = self.batch_remaining.saturating_sub(1);
    }

    /// Skip exhausted and zero-quota batches.
    #[inline]
    pub(crate) fn advance_batch_window(&mut self) {
        while self.batch_remaining == 0 && self.current_batch_index + 1 < self.batch_plan.len() {
            self.current_batch_index += 1;
            self.batch_remaining = self.batch_plan[self.current_batch_index];
        }
    }

    /// Reset batch progress after resize or clear.
    #[inline]
    pub(crate) fn reset(&mut self) {
        self.current_batch_index = 0;
        self.batch_remaining = self.batch_plan.first().copied().unwrap_or(0);
    }
}

/// Capacity shape and batch schedule for one elastic table allocation.
struct ElasticGeometry {
    total_slots: usize,
    max_insertions: usize,
    level_capacities: Vec<usize>,
    batch_plan: Box<[usize]>,
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
                level_capacities: Vec::new(),
                batch_plan: Box::new([]),
            };
        }

        // Public construction rounds positive maps up to INITIAL_CAPACITY, so
        // one slot is only an internal bootstrap shape outside the paper's
        // n >= 2 domain.
        if total_slots == 1 {
            return Self {
                total_slots: 1,
                max_insertions: 1,
                level_capacities: alloc::vec![1],
                batch_plan: Box::new([1]),
            };
        }

        let config = PaperConfig::new(total_slots, reserve_fraction.exponent())
            .expect("validated Elastic library geometry");
        let plan = config.elastic_plan();
        let level_capacities = plan.level_lengths().collect();
        let batch_plan = plan.batch_quotas().collect::<Vec<_>>().into_boxed_slice();
        Self {
            total_slots,
            max_insertions: config.target_insertions(),
            level_capacities,
            batch_plan,
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
    debug_assert_eq!(
        arena_layout.membership_offset,
        arena_layout.layout.size() - membership_tail_span::<K, V>(total_ctrl)
    );
    let arena = Arena::try_allocate_with_ctrl_zeroed(arena_layout.layout, total_ctrl, alloc)?;
    if arena_layout.membership_words != 0 {
        unsafe {
            ptr::write_bytes(
                arena
                    .as_ptr()
                    .add(arena_layout.membership_offset)
                    .cast::<ElasticMetadataWord>(),
                0,
                arena_layout.membership_words,
            );
        };
    }

    // `Arena` has no `Drop`, so a bare `?` would leak the allocation if
    // level construction fails. Deallocate explicitly on `Err`.
    match build_elastic_levels::<K, V>(arena.as_ptr(), arena_layout.data_base_off, level_capacities)
    {
        Ok(levels) => Ok((arena, levels)),
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
    try_alloc_elastic_arena(level_capacities, alloc).unwrap_or_else(|_| {
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
    })
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
    #[must_use]
    pub fn with_capacity_and_reserve_fraction_and_hasher_in(
        capacity: usize,
        reserve_fraction: f64,
        hash_builder: S,
        alloc: A,
    ) -> Self {
        let reserve_fraction = ReserveFraction::try_from(reserve_fraction)
            .unwrap_or_else(|error| panic!("invalid reserve fraction: {error}"));
        Self::with_capacity_and_reserve_and_hasher_in(
            capacity,
            reserve_fraction,
            hash_builder,
            alloc,
        )
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
        let probe_schedule = probe_schedule(geometry.level_capacities.len());
        let (arena, levels) = alloc_elastic_arena(&geometry.level_capacities, &alloc);

        Self {
            levels,
            len: 0,
            total_slots: geometry.total_slots,
            max_insertions: geometry.max_insertions,
            reserve_fraction,
            scheduler: BatchScheduler::new(geometry.batch_plan),
            hash_builder,
            alloc,
            arena,
            epoch: EpochState::initial(),
            probe_high_water: 0,
            probe_schedule,
        }
    }

    /// Fallible full constructor using an exact dyadic reserve.
    fn try_with_capacity_and_reserve_and_hasher_in(
        capacity: usize,
        reserve_fraction: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryBuildError> {
        let geometry = ElasticGeometry::for_insert_budget(capacity, reserve_fraction)
            .ok_or(TryBuildError::CapacityOverflow)?;
        let probe_schedule = try_probe_schedule(geometry.level_capacities.len())?;
        let (arena, levels) = try_alloc_elastic_arena(&geometry.level_capacities, &alloc)?;

        Ok(Self {
            levels,
            len: 0,
            total_slots: geometry.total_slots,
            max_insertions: geometry.max_insertions,
            reserve_fraction,
            scheduler: BatchScheduler::new(geometry.batch_plan),
            hash_builder,
            alloc,
            arena,
            epoch: EpochState::initial(),
            probe_high_water: 0,
            probe_schedule,
        })
    }

    #[inline]
    fn membership_words(&self) -> usize {
        membership_word_count(self.total_slots)
    }

    #[inline]
    #[allow(clippy::cast_ptr_alignment)]
    fn membership_ptr(&self) -> *mut ElasticMetadataWord {
        let tail_span = membership_tail_span::<K, V>(self.total_slots);
        debug_assert!(tail_span <= self.arena.layout_size());
        unsafe {
            self.arena
                .as_ptr()
                .add(self.arena.layout_size() - tail_span)
                .cast::<ElasticMetadataWord>()
        }
    }

    #[inline(never)]
    fn membership_maybe_contains(
        &self,
        route: PreparedElasticRoute,
        membership: PreparedMembership,
    ) -> bool {
        let words = self.membership_words();
        if words == 0 {
            return false;
        }
        let word = PreparedMembership::word(route.signature(), words);
        unsafe {
            (*self.membership_ptr().add(word)).membership & membership.bits == membership.bits
        }
    }

    #[inline(never)]
    fn record_membership(
        &mut self,
        route: PreparedElasticRoute,
        membership: PreparedMembership,
        level: usize,
    ) {
        let words = self.membership_words();
        if words != 0 {
            let word = PreparedMembership::word(route.signature(), words);
            let metadata = unsafe { &mut *self.membership_ptr().add(word) };
            metadata.membership |= membership.bits;
            if self.levels.len() <= ROUTE_SUMMARY_LEVELS {
                metadata.route_bins[route.summary_bin()] |= 1_u16 << level;
            }
        }
    }

    #[inline]
    fn summary_level_mask(&self, route: PreparedElasticRoute) -> u32 {
        let level_count = self.levels.len();
        if level_count > ROUTE_SUMMARY_LEVELS {
            return expand_summary_level_mask(0, level_count);
        }
        let words = self.membership_words();
        if words == 0 {
            return 0;
        }
        let word = PreparedMembership::word(route.signature(), words);
        let metadata = unsafe { &*self.membership_ptr().add(word) };
        expand_summary_level_mask(metadata.route_bins[route.summary_bin()], level_count)
    }

    fn clear_membership(&mut self) {
        let words = self.membership_words();
        if words != 0 {
            unsafe { ptr::write_bytes(self.membership_ptr(), 0, words) };
        }
    }

    fn copy_membership_from(&mut self, source: &Self) {
        let words = self.membership_words();
        debug_assert_eq!(words, source.membership_words());
        if words != 0 {
            unsafe {
                ptr::copy_nonoverlapping(source.membership_ptr(), self.membership_ptr(), words);
            };
        }
    }

    /// Removes all entries, keeping allocated capacity.
    fn clear(&mut self) {
        for level in &mut self.levels {
            for slot in 0..level.capacity() {
                let control = level.control_at(slot);
                if control == CTRL_TOMBSTONE {
                    level.set_control(slot, CTRL_EMPTY);
                    level.tombstones -= 1;
                    continue;
                }
                if !control.is_occupied() {
                    continue;
                }
                let entry = level.slot_ptr(slot);
                level.set_control(slot, CTRL_EMPTY);
                level.len -= 1;
                self.len -= 1;
                unsafe { ptr::drop_in_place(entry) };
            }
        }
        debug_assert_eq!(self.len, 0);
        self.scheduler.reset();
        self.probe_high_water = 0;
        self.probe_schedule.clear();
        self.clear_membership();
        self.epoch.start(EpochTransition::Clear, 0);
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
        match self
            .scheduler
            .on_insert(self.len, self.total_slots, self.max_insertions)
        {
            InsertAction::Resize(cap) => {
                self.resize_with_transition(cap, EpochTransition::Growth);
                self.scheduler.advance_batch_window();
            }
            InsertAction::Continue => {}
        }

        if let Some(placement) =
            self.choose_slot_for_new_key(prepared.route.probe, self.scheduler.target())
        {
            return self.place_new_entry(key, value, prepared, key_fingerprint, placement);
        }

        self.resize_with_transition(self.total_slots, EpochTransition::PlacementRecovery);
        self.scheduler.advance_batch_window();
        if let Some(placement) =
            self.choose_slot_for_new_key(prepared.route.probe, self.scheduler.target())
        {
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
                    .find(|&slot| level.control_at(slot).is_free())
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
        self.scheduler.complete_insert();
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

    /// Take + tombstone + decrement counters for the slot at `loc`. Backs
    /// [`map::TableBackend::remove`], which adds a resize pass.
    fn take_and_tombstone(&mut self, level_idx: usize, slot_idx: usize) -> (K, V) {
        let removed = {
            let level = &mut self.levels[level_idx];
            let removed = unsafe { level.take(slot_idx) };
            level.mark_tombstone(slot_idx);
            level.len -= 1;
            level.tombstones += 1;
            removed
        };
        self.len -= 1;
        self.epoch.note_delete();
        (removed.key, removed.value)
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
            let paper_level = level as u128 + 1;
            let mut paper_probe =
                first_paper_probe_after(paper_level, u128::from(prior_high_water));
            while paper_probe <= u128::from(UNIFORM_SEARCH_CAP) {
                let phi = probe::elastic_phi(paper_level, paper_probe)
                    .expect("bounded Elastic query coordinate");
                if phi > high_water {
                    break;
                }
                if level == 0 && paper_probe == 1 {
                    paper_probe += 1;
                    continue;
                }
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
                paper_probe += 1;
            }
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
        self.find_slot_indices_prepared(key, PreparedElasticRoute::new(hash), fingerprint)
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
        self.find_entry_prepared(key, PreparedElasticRoute::new(hash), fingerprint)
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
        if self.membership_maybe_contains(prepared.route, prepared.membership)
            && let Some(location) =
                self.find_slot_indices_prepared(&key, prepared.route, key_fingerprint)
        {
            return Some(self.replace_value(location, value));
        }
        self.insert_for_vacant_entry_prepared(key, value, prepared, key_fingerprint);
        None
    }

    fn remove(&mut self, (level_idx, slot_idx): (usize, usize)) -> (K, V) {
        let kv = self.take_and_tombstone(level_idx, slot_idx);
        let needs_resize = self.levels[level_idx].needs_cleanup();
        if needs_resize {
            self.resize_with_transition(self.total_slots, EpochTransition::TombstoneCleanup);
        }
        kv
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
        self.epoch.note_delete();
    }

    fn finish_deferred_removals(&mut self) {
        if self.levels.iter().any(Level::needs_cleanup) {
            self.resize_with_transition(self.total_slots, EpochTransition::TombstoneCleanup);
        }
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
        self.epoch.start(EpochTransition::Clear, 0);
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
        let (arena, levels) = alloc_elastic_arena(&level_capacities, &self.alloc);

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
    /// Insert `(key, value)` known to be new. Skips the existence check and
    /// capacity check in `insert`; resize loops drain old levels into fresh
    /// (all-EMPTY) ones, so neither check can succeed.
    ///
    #[inline]
    fn insert_unique(&mut self, key: K, value: V) -> bool {
        let key_hash = self.hash_key(&key);
        let prepared = PreparedElasticKey::new(key_hash);
        let key_fingerprint = control::control_fingerprint(key_hash);

        self.scheduler.advance_batch_window();
        let target = self.scheduler.target();
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

        let (new_arena, new_levels) = alloc_elastic_arena(&geometry.level_capacities, &self.alloc);

        // Swap in fresh arena; keep old one alive until drain completes.
        let old_arena = mem::replace(&mut self.arena, new_arena);
        let old_levels = mem::replace(&mut self.levels, new_levels);
        self.total_slots = geometry.total_slots;
        self.max_insertions = geometry.max_insertions;
        self.scheduler = BatchScheduler::new(geometry.batch_plan);
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
            self.epoch
                .start_with_placement_recovery(transition, self.len);
        } else {
            self.epoch.start(transition, self.len);
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
        for level_index in 0..self.levels.len() {
            let capacity = self.levels[level_index].capacity();
            for slot in 0..capacity {
                let control = self.levels[level_index].control_at(slot);
                if control == CTRL_TOMBSTONE {
                    self.levels[level_index].set_control(slot, CTRL_EMPTY);
                    self.levels[level_index].tombstones -= 1;
                    continue;
                }
                if !control.is_occupied() {
                    continue;
                }
                let entry = {
                    let level = &mut self.levels[level_index];
                    let entry = unsafe { level.take(slot) };
                    level.set_control(slot, CTRL_EMPTY);
                    level.len -= 1;
                    entry
                };
                self.len -= 1;
                used_exceptional_placement |= new_map.insert_unique(entry.key, entry.value);
            }
        }
        debug_assert_eq!(self.len, 0);
        *self = new_map;
        self.epoch = prior_epoch;
        if used_exceptional_placement {
            self.epoch
                .start_with_placement_recovery(EpochTransition::ExplicitResize, self.len);
        } else {
            self.epoch.start(EpochTransition::ExplicitResize, self.len);
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

        let probe_schedule = try_probe_schedule(geometry.level_capacities.len())?;
        let (arena, levels) = try_alloc_elastic_arena(&geometry.level_capacities, &alloc)?;

        Ok(Self {
            levels,
            len: 0,
            total_slots: geometry.total_slots,
            max_insertions: geometry.max_insertions,
            reserve_fraction,
            scheduler: BatchScheduler::new(geometry.batch_plan),
            hash_builder,
            alloc,
            arena,
            epoch: EpochState::initial(),
            probe_high_water: 0,
            probe_schedule,
        })
    }

    #[inline]
    fn hash_key<Q>(&self, key: &Q) -> u64
    where
        Q: Hash + ?Sized,
    {
        self.hash_builder.hash_one(key)
    }

    fn choose_slot_for_new_key(
        &self,
        probe: PreparedElasticProbe,
        target: BatchTarget,
    ) -> Option<ExactPlacement> {
        if self.levels.is_empty() {
            return None;
        }
        let (case, level, slot, paper_probe) = match target {
            BatchTarget::Bootstrap => {
                let (slot, paper_probe) = self.uniform_vacancy(probe, 0)?;
                (
                    ExactInsertionCase::Batch0 { level: 0 },
                    0,
                    slot,
                    paper_probe,
                )
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
                    (
                        ExactInsertionCase::Case2 {
                            batch: next,
                            current_level: current,
                            next_level: next,
                            free_current,
                            free_next,
                        },
                        next,
                        slot,
                        paper_probe,
                    )
                } else if next_low {
                    let (slot, paper_probe) = self.uniform_vacancy(probe, current)?;
                    (
                        ExactInsertionCase::Case3 {
                            batch: next,
                            current_level: current,
                            next_level: next,
                            free_current,
                            free_next,
                        },
                        current,
                        slot,
                        paper_probe,
                    )
                } else {
                    let budget = probe::elastic_dyadic_probe_budget(
                        free_current,
                        current_level.capacity(),
                        self.reserve_fraction.exponent(),
                        ELASTIC_PROBE_BUDGET_C,
                    )
                    .ok()?;
                    let case = ExactInsertionCase::Case1 {
                        batch: next,
                        current_level: current,
                        next_level: next,
                        free_current,
                        free_next,
                        budget,
                    };
                    if let Some((slot, probe)) = (0..budget).find_map(|logical_index| {
                        let logical_index = u64::try_from(logical_index).ok()?;
                        self.vacancy(current, probe, logical_index)
                            .map(|slot| (slot, logical_index + 1))
                    }) {
                        (case, current, slot, probe)
                    } else {
                        let (slot, paper_probe) = self.uniform_vacancy(probe, next)?;
                        (case, next, slot, paper_probe)
                    }
                }
            }
        };
        let paper_level = u32::try_from(level.checked_add(1)?).ok()?;
        let phi = u128::from(probe::elastic_phi_bounded(paper_level, paper_probe)?);
        if phi > QUERY_POSITION_CAP {
            return None;
        }
        Some(ExactPlacement {
            case,
            level,
            slot,
            paper_probe,
            phi,
        })
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
        self.levels[level]
            .control_at(slot)
            .is_free()
            .then_some(slot)
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

    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn route_prepared_counter(
        &self,
        level: usize,
        probe: PreparedElasticProbe,
        counter_base: u32,
    ) -> Option<usize> {
        let upper = self.levels.get(level)?.capacity();
        Self::route_prepared_counter_for_upper(probe, counter_base, upper)
    }

    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn route_prepared_counter_for_upper(
        prepared: PreparedElasticProbe,
        counter_base: u32,
        upper: usize,
    ) -> Option<usize> {
        probe::unbiased_prepared_elastic_probe_index(prepared, counter_base, upper, RANGE_WORD_CAP)
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
        prepared: PreparedElasticRoute,
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
        prepared: PreparedElasticRoute,
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
        prepared: PreparedElasticRoute,
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
            prepared.probe,
            H11_COUNTER_BASE,
            self.levels[0].capacity(),
        ) else {
            return self.find_by_full_scan(key, key_fingerprint, on_hit);
        };
        if let Some(entry) = self.entry_if_match(0, h11_slot, key_fingerprint, key) {
            return Some(on_hit(0, h11_slot, entry));
        }

        let summary_level_mask = self.summary_level_mask(prepared);
        for route in &self.probe_schedule {
            let level = route.level();
            let level_bit = 1_u32 << level;
            if summary_level_mask & level_bit == 0 {
                continue;
            }
            let upper = route.range_upper as usize;
            let Some(slot) =
                Self::route_prepared_counter_for_upper(prepared.probe, route.counter_base, upper)
            else {
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
    use core::ptr::NonNull;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use crate::common::exact::reference::{ScalarElastic, ScalarElasticCase, ScalarElasticLimits};
    use alloc::sync::Arc;
    use allocator_api2::alloc::AllocError as RawAllocError;
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

    #[derive(Clone, Copy)]
    struct IdentityBuildHasher;

    #[derive(Clone, Copy, Eq, Hash, PartialEq)]
    struct Zst;

    #[repr(align(256))]
    #[derive(Clone, Copy, Eq, Hash, PartialEq)]
    struct OverAligned(u64);

    #[derive(Clone)]
    struct ToggleAllocator {
        fail: Arc<AtomicBool>,
    }

    unsafe impl Allocator for ToggleAllocator {
        fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, RawAllocError> {
            if self.fail.load(Ordering::Relaxed) {
                Err(RawAllocError)
            } else {
                Global.allocate(layout)
            }
        }

        unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
            unsafe { Global.deallocate(ptr, layout) };
        }
    }

    #[derive(Default)]
    struct IdentityHasher(u64);

    impl Hasher for IdentityHasher {
        fn finish(&self) -> u64 {
            self.0
        }

        fn write(&mut self, bytes: &[u8]) {
            assert_eq!(bytes.len(), 8);
            let mut word = [0; 8];
            word.copy_from_slice(bytes);
            self.0 = u64::from_ne_bytes(word);
        }

        fn write_u64(&mut self, value: u64) {
            self.0 = value;
        }
    }

    impl BuildHasher for IdentityBuildHasher {
        type Hasher = IdentityHasher;

        fn build_hasher(&self) -> Self::Hasher {
            IdentityHasher::default()
        }
    }

    fn exact_case(case: ScalarElasticCase) -> ExactInsertionCase {
        match case {
            ScalarElasticCase::Batch0 { level } => ExactInsertionCase::Batch0 { level },
            ScalarElasticCase::Case1 {
                batch,
                current_level,
                next_level,
                free_current,
                free_next,
                budget,
            } => ExactInsertionCase::Case1 {
                batch,
                current_level,
                next_level,
                free_current,
                free_next,
                budget,
            },
            ScalarElasticCase::Case2 {
                batch,
                current_level,
                next_level,
                free_current,
                free_next,
            } => ExactInsertionCase::Case2 {
                batch,
                current_level,
                next_level,
                free_current,
                free_next,
            },
            ScalarElasticCase::Case3 {
                batch,
                current_level,
                next_level,
                free_current,
                free_next,
            } => ExactInsertionCase::Case3 {
                batch,
                current_level,
                next_level,
                free_current,
                free_next,
            },
        }
    }

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
            table.scheduler.batch_plan.as_ref(),
            plan.batch_quotas().collect::<Vec<_>>()
        );

        let limits = ScalarElasticLimits::new(
            NonZeroUsize::new(ELASTIC_PROBE_BUDGET_C).unwrap(),
            NonZeroU32::new(RANGE_WORD_CAP).unwrap(),
            NonZeroU64::new(UNIFORM_SEARCH_CAP).unwrap(),
            NonZeroU128::new(QUERY_POSITION_CAP).unwrap(),
        );
        let mut scalar = ScalarElastic::new(config, CounterPrf::new(ELASTIC_PROBE_SEED), limits);

        for identity in identities {
            let prepared = PreparedElasticKey::new(identity);
            assert_eq!(table.hash_key(&identity), identity);
            assert!(matches!(
                table
                    .scheduler
                    .on_insert(table.len, table.total_slots, table.max_insertions,),
                InsertAction::Continue
            ));
            let placement = table
                .choose_slot_for_new_key(prepared.route.probe, table.scheduler.target())
                .unwrap();
            let expected = scalar.insert(identity);
            let global_slot = table.levels[..placement.level]
                .iter()
                .map(ArenaSlots::capacity)
                .sum::<usize>()
                + placement.slot;

            assert_eq!(placement.case, exact_case(expected.case));
            assert_eq!(placement.level, expected.location.level);
            assert_eq!(placement.slot, expected.location.slot_in_level);
            assert_eq!(global_slot, expected.location.global_slot);
            assert_eq!(placement.paper_probe, expected.paper_probe);
            assert_eq!(placement.phi, expected.phi);

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
                    prepared.route,
                    control::control_fingerprint(identity),
                ),
                Some((placement.level, placement.slot))
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
                .target_insertions();
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
        for level in 1..=u128::from(u32::BITS) {
            let mut paper_probe = 1_u128;
            while probe::elastic_phi(level, paper_probe).unwrap() <= QUERY_POSITION_CAP {
                assert!(usize::try_from(paper_probe - 1).unwrap() < QUERY_PROBE_LIMIT);
                paper_probe += 1;
            }
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
                    geometry.level_capacities,
                    plan.level_lengths().collect::<Vec<_>>()
                );
                assert_eq!(
                    geometry.batch_plan.as_ref(),
                    plan.batch_quotas().collect::<Vec<_>>()
                );
            }
        }
    }

    struct ElasticPanicHashKey {
        value: u64,
        panic: Arc<AtomicBool>,
    }

    impl PartialEq for ElasticPanicHashKey {
        fn eq(&self, other: &Self) -> bool {
            self.value == other.value
        }
    }

    impl Eq for ElasticPanicHashKey {}

    impl Hash for ElasticPanicHashKey {
        fn hash<H: Hasher>(&self, state: &mut H) {
            assert!(
                !self.panic.load(Ordering::SeqCst),
                "Elastic test hash panic"
            );
            self.value.hash(state);
        }
    }

    struct ElasticCountDrop(Arc<AtomicUsize>);

    impl Drop for ElasticCountDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct ElasticPanicOnFirstDrop(Arc<AtomicUsize>);

    impl Drop for ElasticPanicOnFirstDrop {
        fn drop(&mut self) {
            assert!(
                self.0.fetch_add(1, Ordering::SeqCst) != 0,
                "first value drop"
            );
        }
    }

    #[test]
    fn clear_marks_each_slot_empty_before_dropping_its_value() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut map =
            ManuallyDrop::new(ElasticHashMap::<u64, ElasticPanicOnFirstDrop>::with_capacity(32));
        for key in 0..3 {
            map.insert(key, ElasticPanicOnFirstDrop(drops.clone()));
        }
        let first_occupied = map
            .table()
            .levels
            .iter()
            .enumerate()
            .find_map(|(level_index, level)| {
                (0..level.capacity())
                    .find(|&slot| level.control_at(slot).is_occupied())
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
                    .filter(|&slot| level.control_at(slot).is_occupied())
                    .count()
            })
            .sum::<usize>();
        assert_eq!(map.len(), live_controls);
        assert!(map.table().levels.iter().all(|level| {
            level.len as usize
                == (0..level.capacity())
                    .filter(|&slot| level.control_at(slot).is_occupied())
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
        let mut map = ElasticHashMap::<ElasticPanicHashKey, ElasticCountDrop>::with_capacity(32);
        for value in 0..16_u64 {
            map.insert(
                ElasticPanicHashKey {
                    value,
                    panic: panic.clone(),
                },
                ElasticCountDrop(drops.clone()),
            );
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
                    .filter(|&slot| level.control_at(slot).is_occupied())
                    .count()
            })
            .sum::<usize>();
        assert_eq!(map.len(), live_controls);
        assert!(map.table().levels.iter().all(|level| {
            level.len as usize
                == (0..level.capacity())
                    .filter(|&slot| level.control_at(slot).is_occupied())
                    .count()
        }));
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        let live_keys = map.keys().map(|key| key.value).collect::<Vec<_>>();
        map.insert(
            ElasticPanicHashKey {
                value: 100,
                panic: panic.clone(),
            },
            ElasticCountDrop(drops.clone()),
        );
        map.try_reserve(4_096).unwrap();
        for value in live_keys.into_iter().chain([100]) {
            assert!(map.contains_key(&ElasticPanicHashKey {
                value,
                panic: panic.clone(),
            }));
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
                    assert_eq!(extended.membership_words, 0);
                } else {
                    assert_eq!(extended.membership_offset, base.size());
                    assert_eq!(
                        extended.membership_words,
                        slots.div_ceil(MEMBERSHIP_SLOTS_PER_WORD)
                    );
                    assert!(extended.layout.size() > base.size());
                }
            }
        }

        assert_layout::<u64, u64>();
        assert_layout::<Zst, Zst>();
        assert_layout::<OverAligned, OverAligned>();
        assert!(mem::size_of::<ElasticMetadataWord>() <= 2 * MEMBERSHIP_SLOTS_PER_WORD);

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
            unsafe { table.arena.as_ptr().add(layout.membership_offset) }.addr()
        );
        assert_eq!(
            table.membership_ptr().addr() % mem::align_of::<ElasticMetadataWord>(),
            0
        );
        for word in 0..table.membership_words() {
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
        let initial_quota = map.table().scheduler.batch_remaining;
        assert!(
            initial_quota > 0,
            "test requires a non-empty bootstrap batch"
        );

        for key in 0..=initial_quota {
            map.insert(key, key);
        }

        assert!(map.table().scheduler.current_batch_index > 0);
        assert_eq!(map.table().scheduler.target(), BatchTarget::LevelPair(0));
    }

    #[test]
    fn duplicate_insert_does_not_advance_the_paper_schedule() {
        let mut map: ElasticHashMap<u64, u64> = ElasticHashMap::with_capacity(64);
        assert_eq!(map.insert(7, 11), None);
        let batch = map.table().scheduler.current_batch_index;
        let remaining = map.table().scheduler.batch_remaining;

        assert_eq!(map.insert(7, 13), Some(11));
        assert_eq!(map.len(), 1);
        assert_eq!(map.table().scheduler.current_batch_index, batch);
        assert_eq!(map.table().scheduler.batch_remaining, remaining);
        assert_eq!(map.get(&7), Some(&13));
    }

    fn membership_bits_from_signature(signature: u64) -> u64 {
        let first = signature & 63;
        let step = ((signature >> 32) | 1) & 63;
        let second = first.wrapping_add(step) & 63;
        let third = second.wrapping_add(step) & 63;
        let fourth = third.wrapping_add(step) & 63;
        (1_u64 << first) | (1_u64 << second) | (1_u64 << third) | (1_u64 << fourth)
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
    fn route_summary_filter_disables_above_its_sixteen_level_encoding() {
        assert_eq!(expand_summary_level_mask(0x1234, 16), 0x1234);
        assert_eq!(expand_summary_level_mask(0, 17), u32::MAX);
        assert_eq!(expand_summary_level_mask(0, 32), u32::MAX);
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
            assert_eq!(prepared.membership.bits, expected);
            for words in [1_usize, 3, 17, 257] {
                let product = u128::from(signature) * u128::try_from(words).unwrap();
                assert_eq!(
                    PreparedMembership::word(signature, words),
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
            .find_slot_indices_prepared(&hash, prepared.route, control::control_fingerprint(hash))
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
                        (level.control_at(slot).is_occupied()
                            && unsafe { level.get_ref(slot) }.key == key)
                            .then_some((level_index, slot))
                    })
                })
                .unwrap();
            let route = PreparedElasticRoute::new(key);
            assert_ne!(
                map.table().summary_level_mask(route) & (1_u32 << location.0),
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
        for word in 0..map.table().membership_words() {
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
        let inserted_hash = map.table().hash_key(&7_u64);
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
            let hash = cloned.table().hash_key(&key);
            assert!(membership_maybe_contains_prepared(
                cloned.table(),
                PreparedElasticKey::new(hash),
            ));
            assert_eq!(cloned.get(&key), Some(&(key ^ 0x55)));
        }

        cloned.clear();
        for key in 0_u64..96 {
            let hash = cloned.table().hash_key(&key);
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
            let hash = cloned.table().hash_key(&key);
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
            let hash = map.table().hash_key(&key);
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
            let hash = map.table().hash_key(&key);
            assert!(membership_maybe_contains_prepared(
                map.table(),
                PreparedElasticKey::new(hash)
            ));
            assert_eq!(map.get(&key), Some(&key));
        }

        map.drain().for_each(drop);
        assert!(map.is_empty());
        for key in 0_u64..64 {
            let hash = map.table().hash_key(&key);
            assert!(!membership_maybe_contains_prepared(
                map.table(),
                PreparedElasticKey::new(hash)
            ));
        }
    }

    #[test]
    fn allocator_failure_does_not_publish_or_forget_membership() {
        let fail = Arc::new(AtomicBool::new(true));
        let failed = ElasticHashMap::<u64, u64, IdentityBuildHasher, ToggleAllocator>::
            try_with_capacity_and_reserve_and_hasher_in(
                128,
                ReserveFraction::DEFAULT,
                IdentityBuildHasher,
                ToggleAllocator {
                    fail: Arc::clone(&fail),
                },
            );
        assert!(matches!(failed, Err(TryBuildError::AllocError)));

        fail.store(false, Ordering::Relaxed);
        let mut map = ElasticHashMap::<u64, u64, IdentityBuildHasher, ToggleAllocator>::
            with_capacity_and_reserve_and_hasher_in(
                128,
                ReserveFraction::DEFAULT,
                IdentityBuildHasher,
                ToggleAllocator {
                    fail: Arc::clone(&fail),
                },
            );
        for key in 0_u64..64 {
            map.insert(key, key ^ 0x5a);
        }

        fail.store(true, Ordering::Relaxed);
        assert_eq!(map.try_reserve(4_096), Err(TryReserveError::AllocError));
        for key in 0_u64..64 {
            let hash = map.table().hash_key(&key);
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
            if table.levels[0].control_at(slot).is_free() {
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
            table.find_slot_indices_prepared(&u64::MAX, prepared.route, fingerprint),
            Some(location)
        );
        for key in 0..next_key {
            assert!(
                table
                    .find_slot_indices_prepared(&key, prepared.route, fingerprint)
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
            let hash = table.hash_key(&key);
            let prepared = PreparedElasticKey::new(hash);
            let fingerprint = control::control_fingerprint(hash);
            let location = table
                .find_slot_indices_prepared(&key, prepared.route, fingerprint)
                .expect("inserted key must have a location");
            let direct = table
                .find_entry_prepared(&key, prepared.route, fingerprint)
                .expect("inserted key must have an entry reference");
            let resolved = unsafe { table.slot_ref(location.0, location.1) };
            assert!(ptr::eq(direct, resolved), "key {key} returned a new slot");
        }

        let missing = usize::MAX;
        let hash = table.hash_key(&missing);
        let prepared = PreparedElasticKey::new(hash);
        let fingerprint = control::control_fingerprint(hash);
        assert!(
            table
                .find_entry_prepared(&missing, prepared.route, fingerprint)
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
                let hash = map.table().hash_key(&key);
                map.table()
                    .find_slot_indices_prepared(
                        &key,
                        PreparedElasticRoute::new(hash),
                        control::control_fingerprint(hash),
                    )
                    .unwrap()
            })
            .collect();

        assert_eq!(map.remove(&0), Some(0));

        let after: Vec<_> = (1..100)
            .map(|key| {
                let hash = map.table().hash_key(&key);
                map.table()
                    .find_slot_indices_prepared(
                        &key,
                        PreparedElasticRoute::new(hash),
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
        let initial_quota = table.scheduler.batch_remaining;
        assert!(
            initial_quota > 0,
            "test requires a non-empty bootstrap batch"
        );

        for key in 0..=initial_quota {
            table.insert_unique(key, key);
        }

        assert!(table.scheduler.current_batch_index > 0);
        assert_eq!(table.scheduler.target(), BatchTarget::LevelPair(0));
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
        let hash = table.hash_key(&key);
        table.insert_for_vacant_entry(key, key, hash);

        assert!(table.total_slots > previous_slots);
        assert!(table.scheduler.current_batch_index > 0);
        assert_eq!(table.scheduler.target(), BatchTarget::LevelPair(0));
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
