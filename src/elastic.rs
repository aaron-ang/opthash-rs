use std::hash::{BuildHasher, Hash};
use std::mem::{self, MaybeUninit};

use allocator_api2::alloc::{Allocator, Global, Layout};
use equivalent::Equivalent;

use crate::common::DefaultHashBuilder;
use crate::common::arena::{self, Arena, ArenaSlots, SlotEntry};
use crate::common::config::{GROUP_SIZE, GROUP_SIZE_U32, INITIAL_CAPACITY};
use crate::common::control::{self, CTRL_EMPTY, CTRL_TOMBSTONE};
use crate::common::error::TryReserveError;
use crate::common::iter::RegionCursor;
use crate::common::math::{self, align, capacity, probe};
use crate::macros;
use crate::map;

/// `(slot pointer, location)` yielded by the scan cursor: the pointer is read
/// by iterators, the `(level, slot)` location backs removal.
type ElasticScanItem<K, V> = (*mut SlotEntry<K, V>, (usize, usize));

/// Defrag repacks fire at most once per `total_slots / DEFRAG_OPS_DIVISOR`
/// inserts, keeping them O(1) amortized so churn can't storm. Larger means more
/// frequent repacks: less probe drift, more repack work. 4 is the swept knee:
/// 2 inserts pay +16% from drift, 8+ erode the delete win with repack overhead.
const DEFRAG_OPS_DIVISOR: usize = 4;

/// A level is "drifted" once `max_probe_groups` exceeds this multiple of its
/// `f(ε)` budget. `>1` since the high-water max sits above the mean budget; 3
/// is delete-optimal in the sweep (2 over-repacks, 6 lets probes drift).
const DEFRAG_DRIFT_MULT: f64 = 3.0;

/// Descriptor for one sub-array `A_i`. Holds metadata + cached pointers
/// into the map-level arena; owns no allocation. The actual ctrl bytes and
/// [`SlotEntry`] data live contiguously in [`ElasticTable::arena`].
struct Level<T> {
    /// Cached `arena.as_ptr() + ctrl_offset`, stamped at construction.
    ctrl_ptr: *mut u8,
    /// Cached `arena.as_ptr() + data_offset`, stamped at construction.
    data_ptr: *mut MaybeUninit<T>,
    /// Slot capacity (= `group_count` * `GROUP_SIZE`). Bounded by `capacity`
    /// via the arena layout, so `len`/`tombstones` fit in `u32` too.
    capacity: u32,
    /// Number of SIMD groups.
    group_count: u32,
    /// `group_count - 1`; pow2 so probe wrap is `& mask`.
    group_count_mask: u32,
    /// `1 +` the largest probe distance any live key needed (high-water).
    /// Bounds the lookup scan; only grows until a resize resets it.
    max_probe_groups: u32,
    /// Live entry count.
    len: u32,
    /// Deleted-slot count.
    tombstones: u32,
    /// Cached `floor(reserve * cap / 2)`.
    half_reserve_slot_threshold: u32,
    /// Precomputed `DEFRAG_DRIFT_MULT * budget_cap`; keeps `probe_drifted` an
    /// integer compare.
    probe_drift_threshold: u32,
    /// Per-level salt mixed into key hashes.
    salt: u64,
    /// Paper §2 cap on `f(ε)`.
    budget_cap: f64,
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
    fn new_at(
        level_idx: usize,
        cap_u32: u32,
        reserve_fraction: f64,
        ctrl_ptr: *mut u8,
        data_ptr: *mut MaybeUninit<T>,
    ) -> Self {
        let cap = cap_u32 as usize;
        let gc = cap_u32 / GROUP_SIZE_U32;
        let budget_cap = compute_budget_cap(reserve_fraction, gc as usize);
        // `budget_cap >= 1.0`; `as u32` saturates and the value is tiny.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let probe_drift_threshold = (DEFRAG_DRIFT_MULT * budget_cap) as u32;
        Self {
            ctrl_ptr,
            data_ptr,
            capacity: cap_u32,
            group_count: gc,
            group_count_mask: gc.wrapping_sub(1),
            max_probe_groups: 0,
            salt: math::level_salt_wide(level_idx),
            len: 0,
            tombstones: 0,
            half_reserve_slot_threshold: u32::try_from(capacity::floor_half_reserve_slots(
                reserve_fraction,
                cap,
            ))
            .unwrap_or(u32::MAX),
            probe_drift_threshold,
            budget_cap,
        }
    }

    #[inline]
    fn group_count(&self) -> usize {
        self.group_count as usize
    }

    // ---------------------------------------------------------------- //
    // Probe helpers                                                      //
    // ---------------------------------------------------------------- //

    /// Slots minus live entries (includes tombstones, reusable on insert).
    #[inline]
    fn free_slots(&self) -> usize {
        self.capacity.saturating_sub(self.len) as usize
    }

    /// Paper §2 `f(ε)` probe budget.
    #[inline]
    #[allow(
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation
    )]
    fn limited_group_budget(&self) -> usize {
        let cap = self.capacity as usize;
        let free = self.free_slots();
        if cap == 0 || free == 0 {
            return 1;
        }
        let log_inv_eps = (cap as f64 / free as f64).log2();
        let raw = 1.0 + log_inv_eps;
        raw.min(self.budget_cap) as usize
    }

    /// Tombstones exceed [`capacity::tombstone_cleanup_threshold`], so `remove`
    /// should repack this level in place; the threshold's hysteresis keeps
    /// deletes amortized O(1).
    #[inline]
    fn needs_cleanup(&self) -> bool {
        self.tombstones as usize > capacity::tombstone_cleanup_threshold(self.capacity as usize)
    }

    /// `max_probe_groups` drifted past the healthy `f(ε)` budget; a repack pays.
    #[inline]
    fn probe_drifted(&self) -> bool {
        self.max_probe_groups > self.probe_drift_threshold
    }

    #[inline]
    fn triangular_group_start(&self, key_hash: u64) -> usize {
        let mixed = key_hash ^ self.salt;
        probe::hash_to_usize(mixed) & self.group_count_mask as usize
    }

    /// Extend `max_probe_groups` to cover a placement `group_dist` steps from its
    /// probe start, so a bounded lookup never stops short of a live key. The
    /// placing search already walked this distance.
    #[inline]
    fn note_probe_distance(&mut self, group_dist: u32) {
        let reached = group_dist + 1;
        if reached > self.max_probe_groups {
            self.max_probe_groups = reached;
        }
    }
}

impl<K, V> Level<SlotEntry<K, V>> {
    /// Triangular probe: fingerprint scan + key compare. Returns the slot on a
    /// hit, `None` on a miss. Scans at most `max_probe_groups` groups — every
    /// live key sits within that distance — or stops earlier at an EMPTY byte.
    #[inline]
    fn find_by_probe<Q>(&self, key_hash: u64, key_fingerprint: u8, key: &Q) -> Option<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        if self.len == 0 {
            return None;
        }
        let mask = self.group_count_mask as usize;
        let mut probe = probe::TriangularProbe::new(self.triangular_group_start(key_hash));
        for _ in 0..self.max_probe_groups as usize {
            let match_mask = self.group_match_mask(probe.pos, key_fingerprint);
            for relative_idx in match_mask {
                let slot_idx = probe.pos * GROUP_SIZE + relative_idx;
                let entry = unsafe { self.get_ref(slot_idx) };
                if key.equivalent(&entry.key) {
                    return Some(slot_idx);
                }
            }
            if self.group_match_mask(probe.pos, CTRL_EMPTY).any() {
                return None;
            }
            probe.advance(mask);
        }
        None
    }
}

/// Open-addressed elastic-hashing backend for the generic [`map::HashMap`]
/// shell. See [`ElasticHashMap`] for the public map type.
///
/// Splits capacity across geometrically shrinking `levels` and routes inserts
/// through a `batch_plan`: early batches concentrate on level 0; later
/// batches push toward deeper levels. Lookups probe every level whose
/// `len > 0`. Unlike standard open addressing, expected probe count stays
/// low even at high load.
///
/// **Probe sequence**: paper §2 assumes uniform random probes per level;
/// we use triangular probing with a per-level salt instead. Same
/// simplification as `SwissTable` / hashbrown — preserves coverage with
/// far better cache behavior than recomputing random positions.
pub struct ElasticTable<K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    levels: LevelSlice<K, V>,
    len: usize,
    total_slots: usize,
    max_insertions: usize,
    reserve_fraction: f64,
    /// Schedule batch progression, resizing, and defragmentation.
    scheduler: BatchScheduler,
    /// Bound lookups by the deepest populated level.
    max_populated_level: usize,
    hash_builder: S,
    alloc: A,
    /// [`ctrl_L0|ctrl_L1|...`][pad][`slots_L0|slots_L1|...`].
    arena: Arena,
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

/// Schedule resize, repack, and batch progression.
#[derive(Clone)]
pub struct BatchScheduler {
    batch_plan: Box<[usize]>,
    current_batch_index: usize,
    batch_remaining: usize,
    defrag_pending: bool,
    inserts_since_repack: usize,
    total_slots: usize,
    max_insertions: usize,
}

/// Direct the structural work required before insertion.
pub enum InsertAction {
    /// Resize to the specified slot count.
    Resize(usize),
    /// Repack at the current slot count.
    Defrag(usize),
    /// Continue without structural work.
    Continue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BatchTarget {
    Bootstrap,
    LevelPair(usize),
}

impl BatchScheduler {
    pub fn new(batch_plan: Box<[usize]>, total_slots: usize, max_insertions: usize) -> Self {
        let initial_remaining = batch_plan.first().copied().unwrap_or(0);
        Self {
            batch_plan,
            current_batch_index: 0,
            batch_remaining: initial_remaining,
            defrag_pending: false,
            inserts_since_repack: 0,
            total_slots,
            max_insertions,
        }
    }

    /// Select structural work for the next insert.
    #[inline]
    pub fn on_insert(&mut self, current_len: usize) -> InsertAction {
        self.inserts_since_repack += 1;
        if current_len >= self.max_insertions {
            // Bootstrap empty storage instead of doubling zero slots.
            let new_cap = if self.total_slots == 0 {
                INITIAL_CAPACITY
            } else {
                self.total_slots.saturating_mul(2)
            };
            return InsertAction::Resize(new_cap);
        }
        if self.defrag_pending
            && self.inserts_since_repack > (self.total_slots / DEFRAG_OPS_DIVISOR).max(1)
        {
            return InsertAction::Defrag(self.total_slots);
        }
        self.advance_batch_window();
        InsertAction::Continue
    }

    /// Request a repack after probe depth exceeds its budget.
    #[inline]
    pub fn report_drift(&mut self) {
        self.defrag_pending = true;
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
    pub fn advance_batch_window(&mut self) {
        while self.batch_remaining == 0 && self.current_batch_index + 1 < self.batch_plan.len() {
            self.current_batch_index += 1;
            self.batch_remaining = self.batch_plan[self.current_batch_index];
        }
    }

    /// Reset batch and repack progress after resize or clear.
    #[inline]
    pub fn reset(&mut self) {
        self.current_batch_index = 0;
        self.batch_remaining = self.batch_plan.first().copied().unwrap_or(0);
        self.defrag_pending = false;
        self.inserts_since_repack = 0;
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
    fn for_insert_budget(requested_insertions: usize, reserve_fraction: f64) -> Option<Self> {
        let total_slots = if requested_insertions == 0 {
            0
        } else {
            capacity::capacity_for(INITIAL_CAPACITY, requested_insertions, reserve_fraction)?
        };
        Some(Self::for_slots(total_slots, reserve_fraction))
    }

    fn for_slots(total_slots: usize, reserve_fraction: f64) -> Self {
        let max_insertions = capacity::max_insertions(total_slots, reserve_fraction);
        let level_capacities = partition_levels(total_slots);
        let batch_plan = build_batch_plan(&level_capacities, reserve_fraction, max_insertions);
        Self {
            total_slots,
            max_insertions,
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
    reserve_fraction: f64,
) -> Result<LevelSlice<K, V>, TryReserveError> {
    let mut cursor = arena::LayoutCursor::<SlotEntry<K, V>>::new(arena_base, data_base_off)?;
    let mut levels: Vec<Level<SlotEntry<K, V>>> = Vec::new();
    levels
        .try_reserve_exact(level_capacities.len())
        .map_err(|_| TryReserveError::AllocError)?;
    for (level_idx, &cap) in level_capacities.iter().enumerate() {
        let cap_u32 = u32::try_from(cap).map_err(|_| TryReserveError::CapacityOverflow)?;
        // SAFETY: the arena was allocated for the layout these caps sum to.
        let (ctrl_ptr, data_ptr) = unsafe { cursor.reserve(cap_u32)? };
        levels.push(Level::new_at(
            level_idx,
            cap_u32,
            reserve_fraction,
            ctrl_ptr,
            data_ptr,
        ));
    }
    Ok(levels.into_boxed_slice())
}

fn try_alloc_elastic_arena<K, V, A: Allocator + Clone>(
    level_capacities: &[usize],
    reserve_fraction: f64,
    alloc: &A,
) -> Result<ElasticArenaBuild<K, V>, TryReserveError> {
    let total_ctrl: usize = level_capacities.iter().sum();
    let (arena_layout, data_base_off) = arena::layout_for::<K, V>(total_ctrl)?;
    let arena = Arena::try_allocate_with_ctrl_zeroed(arena_layout, total_ctrl, alloc)?;

    // `Arena` has no `Drop`, so a bare `?` would leak the allocation if
    // level construction fails. Deallocate explicitly on `Err`.
    match build_elastic_levels::<K, V>(
        arena.as_ptr(),
        data_base_off,
        level_capacities,
        reserve_fraction,
    ) {
        Ok(levels) => Ok((arena, levels)),
        Err(e) => {
            arena.deallocate(alloc);
            Err(e)
        }
    }
}

fn alloc_elastic_arena<K, V, A: Allocator + Clone>(
    level_capacities: &[usize],
    reserve_fraction: f64,
    alloc: &A,
) -> ElasticArenaBuild<K, V> {
    try_alloc_elastic_arena(level_capacities, reserve_fraction, alloc).unwrap_or_else(|_| {
        let total_ctrl: usize = level_capacities.iter().sum();
        let layout = match arena::layout_for::<K, V>(total_ctrl) {
            Ok((l, _)) => l,
            Err(_) => Layout::from_size_align(1, 1).unwrap(),
        };
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
    /// Full constructor. `resize` also calls this with the existing
    /// `hash_builder` and allocator so all keys keep the same hash sequence
    /// across grows.
    ///
    /// # Load factor
    ///
    /// `reserve_fraction` is clamped to `[1e-6, 0.999999]`. Unlike funnel
    /// hashing (capped at δ ≤ 1/8), elastic stays sound at near-full load — the
    /// per-level `f(ε)` probe budget absorbs it.
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
        let reserve_fraction = capacity::sanitize_reserve_fraction(reserve_fraction);
        let geometry = ElasticGeometry::for_insert_budget(capacity, reserve_fraction)
            .expect("capacity overflow");
        let (arena, levels) =
            alloc_elastic_arena(&geometry.level_capacities, reserve_fraction, &alloc);

        Self {
            levels,
            len: 0,
            total_slots: geometry.total_slots,
            max_insertions: geometry.max_insertions,
            reserve_fraction,
            scheduler: BatchScheduler::new(
                geometry.batch_plan,
                geometry.total_slots,
                geometry.max_insertions,
            ),
            max_populated_level: 0,
            hash_builder,
            alloc,
            arena,
        }
    }

    /// Removes all entries, keeping allocated capacity.
    fn clear(&mut self) {
        for level in &mut self.levels {
            level.drop_values();
            level.clear_all_controls();
            level.len = 0;
            level.tombstones = 0;
            level.max_probe_groups = 0;
        }
        self.len = 0;
        self.max_populated_level = 0;
        self.scheduler.reset();
    }

    /// Post-lookup insert for a key known to be absent. Returns the chosen
    /// slot so the caller can borrow into it without re-probing.
    fn insert_for_vacant_entry(&mut self, key: K, value: V, key_hash: u64) -> (usize, usize) {
        let key_fingerprint = control::control_fingerprint(key_hash);

        match self.scheduler.on_insert(self.len) {
            InsertAction::Resize(cap) | InsertAction::Defrag(cap) => {
                self.resize(cap);
                // Post-resize the scheduler is fresh; skip leading zero-quota
                // batches. The `Continue` arm already advanced in `on_insert`.
                self.scheduler.advance_batch_window();
            }
            InsertAction::Continue => {}
        }

        let target = self.scheduler.target();
        let (level_idx, slot_idx, group_dist) = self
            .choose_slot_for_new_key(key_hash, target)
            .expect("no free slot found after resize");

        let level = &mut self.levels[level_idx];
        let prev_ctrl = level.control_at(slot_idx);
        level.write_with_control(slot_idx, SlotEntry { key, value }, key_fingerprint);
        level.note_probe_distance(group_dist);
        level.len += 1;
        if prev_ctrl == CTRL_TOMBSTONE {
            level.tombstones -= 1;
        }
        let drifted = level.probe_drifted();
        if drifted {
            self.scheduler.report_drift();
        }
        if level_idx > self.max_populated_level {
            self.max_populated_level = level_idx;
        }
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
        (removed.key, removed.value)
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
    fn reserve_fraction(&self) -> f64 {
        self.reserve_fraction
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
        self.find_slot_indices_with_hash(key, hash, fingerprint)
    }

    // -- Insert / remove --

    #[inline]
    fn insert_for_vacant(&mut self, key: K, value: V, hash: u64) -> (usize, usize) {
        self.insert_for_vacant_entry(key, value, hash)
    }

    fn remove(&mut self, (level_idx, slot_idx): (usize, usize)) -> (K, V) {
        let kv = self.take_and_tombstone(level_idx, slot_idx);
        let needs_resize = self.levels[level_idx].needs_cleanup();
        self.shrink_max_populated_level();
        if needs_resize {
            self.resize(self.total_slots);
        }
        kv
    }

    #[inline]
    fn tombstone_slot(&mut self, (level_idx, slot_idx): (usize, usize)) {
        self.levels[level_idx].mark_tombstone(slot_idx);
    }

    #[inline]
    fn extract_finish(&mut self, (level_idx, slot_idx): (usize, usize)) {
        let level = &mut self.levels[level_idx];
        level.mark_tombstone(slot_idx);
        level.len -= 1;
        level.tombstones += 1;
        self.len -= 1;
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
            level.max_probe_groups = 0;
        }
        self.len = 0;
        self.max_populated_level = 0;
        self.scheduler.reset();
    }

    fn clone_table(&self) -> Self
    where
        K: Clone,
        V: Clone,
        S: Clone,
    {
        let level_capacities: Vec<usize> =
            self.levels.iter().map(|l| l.capacity as usize).collect();
        let (arena, levels) =
            alloc_elastic_arena(&level_capacities, self.reserve_fraction, &self.alloc);

        // Drop guard for the half-built clone: if any user `K::clone` /
        // `V::clone` panics, drop the already-cloned values (OCCUPIED on
        // `dst_arena`) and deallocate the partially-filled arena. `Arena`
        // has no `Drop`, so without this the whole allocation would leak.
        let mut guard = arena::ArenaDropGuard::new(arena, levels, self.alloc.clone());

        for (dst, src_lvl) in guard.regions_mut().iter_mut().zip(self.levels.iter()) {
            dst.clone_region_from(src_lvl);
            dst.len = src_lvl.len;
            dst.tombstones = src_lvl.tombstones;
            dst.max_probe_groups = src_lvl.max_probe_groups;
        }

        // Success: reclaim arena + levels so the guard's Drop no-ops.
        let (arena, levels) = guard.disarm();

        Self {
            levels,
            len: self.len,
            total_slots: self.total_slots,
            max_insertions: self.max_insertions,
            reserve_fraction: self.reserve_fraction,
            scheduler: self.scheduler.clone(),
            max_populated_level: self.max_populated_level,
            hash_builder: self.hash_builder.clone(),
            alloc: self.alloc.clone(),
            arena,
        }
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
    /// # Panics
    ///
    /// Panics if `choose_slot_for_new_key` finds no slot — caller is
    /// responsible for sizing the new levels to fit every drained entry.
    #[inline]
    fn insert_unique(&mut self, key: K, value: V) {
        let key_hash = self.hash_key(&key);
        let key_fingerprint = control::control_fingerprint(key_hash);

        self.scheduler.advance_batch_window();
        let target = self.scheduler.target();
        let (level_idx, slot_idx, group_dist) = self
            .choose_slot_for_new_key(key_hash, target)
            .expect("no free slot found in freshly-allocated map");

        let level = &mut self.levels[level_idx];
        level.write_with_control(slot_idx, SlotEntry { key, value }, key_fingerprint);
        level.note_probe_distance(group_dist);
        level.len += 1;
        if level_idx > self.max_populated_level {
            self.max_populated_level = level_idx;
        }
        self.len += 1;
        self.scheduler.complete_insert();
    }

    /// Drain all live entries into a temp Vec, rebuild levels at
    /// `new_capacity` in-place, reinsert. Passing the current capacity
    /// performs a no-grow rehash that flushes accumulated tombstones.
    fn resize(&mut self, new_capacity: usize) {
        let geometry = ElasticGeometry::for_slots(new_capacity, self.reserve_fraction);

        let (new_arena, new_levels) = alloc_elastic_arena(
            &geometry.level_capacities,
            self.reserve_fraction,
            &self.alloc,
        );

        // Swap in fresh arena; keep old one alive until drain completes.
        let old_arena = mem::replace(&mut self.arena, new_arena);
        let old_levels = mem::replace(&mut self.levels, new_levels);
        self.total_slots = geometry.total_slots;
        self.max_insertions = geometry.max_insertions;
        self.scheduler = BatchScheduler::new(
            geometry.batch_plan,
            geometry.total_slots,
            geometry.max_insertions,
        );
        self.max_populated_level = 0;
        self.len = 0;

        // Move every live entry from old arena into the new levels.
        //
        // Panic safety: clear each source ctrl before handing the moved entry
        // to `insert_unique`, so the guard's drop walks only un-moved slots.
        // If `insert_unique` panics, the guard unwinds: drops any survivors
        // then deallocates `old_arena` — `Arena` has no `Drop`, so without the
        // guard the backing allocation would leak.
        let mut guard = arena::ArenaDropGuard::new(old_arena, old_levels, self.alloc.clone());
        for level in guard.regions_mut().iter_mut() {
            level.drain_values_and_clear(|entry| {
                self.insert_unique(entry.key, entry.value);
            });
        }
        // guard drops at end of scope, deallocating old_arena. All slots
        // are CTRL_EMPTY so `drop_values` is a no-op on success.
        drop(guard);
    }

    /// Fallible counterpart to [`Self::resize`]. Allocates the new backing
    /// storage before touching `self`, so `Err` leaves the map intact.
    fn try_resize(&mut self, new_capacity: usize) -> Result<(), TryReserveError>
    where
        S: Clone,
    {
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
        for level in &mut self.levels {
            level.drain_values_and_clear(|entry| {
                new_map.insert_unique(entry.key, entry.value);
            });
        }
        self.len = 0;
        self.max_populated_level = 0;
        *self = new_map;
        Ok(())
    }

    /// Internal fallible ctor for `try_resize`. `slots` is raw slot count
    /// (already inflated by the caller); public ctors take an insertion
    /// budget and inflate via `capacity_for` — this one skips that.
    fn try_with_slots_and_reserve_fraction_and_hasher_in(
        slots: usize,
        reserve_fraction: f64,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryReserveError> {
        let reserve_fraction = capacity::sanitize_reserve_fraction(reserve_fraction);
        let geometry = ElasticGeometry::for_slots(slots, reserve_fraction);

        let (arena, levels) =
            try_alloc_elastic_arena(&geometry.level_capacities, reserve_fraction, &alloc)?;

        Ok(Self {
            levels,
            len: 0,
            total_slots: geometry.total_slots,
            max_insertions: geometry.max_insertions,
            reserve_fraction,
            scheduler: BatchScheduler::new(
                geometry.batch_plan,
                geometry.total_slots,
                geometry.max_insertions,
            ),
            max_populated_level: 0,
            hash_builder,
            alloc,
            arena,
        })
    }

    #[inline]
    fn hash_key<Q>(&self, key: &Q) -> u64
    where
        Q: Hash + ?Sized,
    {
        self.hash_builder.hash_one(key)
    }

    /// Paper §4 places each insert in `A_i` or `A_{i+1}` per the current batch `B_i`;
    /// The full-sweep fallback covers the tombstone-reuse case the paper's analysis doesn't model.
    #[inline]
    fn choose_slot_for_new_key(
        &mut self,
        key_hash: u64,
        target: BatchTarget,
    ) -> Option<(usize, usize, u32)> {
        if self.levels.is_empty() {
            return None;
        }

        if let Some(found) = self.choose_slot_targeted(key_hash, target) {
            return Some(found);
        }

        for li in 0..self.levels.len() {
            if let Some((slot_idx, dist)) = self.first_free_uniform(key_hash, li) {
                return Some((li, slot_idx, dist));
            }
        }
        None
    }

    /// Batch-driven slot selection per paper §4 Cases 1/2/3 during batch `B_i`:
    /// - Case 1 (`ε₁ > δ/2` ∧ `ε₂ > 0.25`): limited probe in `A_i`, else uniform `A_{i+1}`.
    /// - Case 2 (`ε₁ ≤ δ/2`): uniform `A_{i+1}`.
    /// - Case 3 (`ε₂ ≤ 0.25`): uniform `A_i`.
    ///
    /// Cases 2 and 3 swap to the other level if the paper-mandated one is full.
    /// Paper proves success w.h.p. but not w.p. 1,
    /// so we avoid a hard insert failure on the rare bad event.
    #[inline]
    fn choose_slot_targeted(
        &self,
        key_hash: u64,
        target: BatchTarget,
    ) -> Option<(usize, usize, u32)> {
        let level_idx = match target {
            BatchTarget::Bootstrap => {
                return self
                    .first_free_uniform(key_hash, 0)
                    .map(|(slot_idx, dist)| (0, slot_idx, dist));
            }
            BatchTarget::LevelPair(level_idx) => level_idx,
        };
        if level_idx + 1 >= self.levels.len() {
            let last = self.levels.len() - 1;
            return self
                .first_free_uniform(key_hash, last)
                .map(|(slot_idx, dist)| (last, slot_idx, dist));
        }

        let current_level = &self.levels[level_idx];
        let next_level = &self.levels[level_idx + 1];
        let current_free_slots = current_level.free_slots();
        let next_free_slots = next_level.free_slots();

        if current_free_slots > current_level.half_reserve_slot_threshold as usize
            && next_free_slots.saturating_mul(4) > next_level.capacity()
        {
            let limited_budget = current_level.limited_group_budget();
            if let Some((slot_idx, dist)) =
                self.first_free_limited(key_hash, level_idx, limited_budget)
            {
                return Some((level_idx, slot_idx, dist));
            }
            if let Some((slot_idx, dist)) = self.first_free_uniform(key_hash, level_idx + 1) {
                return Some((level_idx + 1, slot_idx, dist));
            }
            return self
                .first_free_uniform(key_hash, level_idx)
                .map(|(slot_idx, dist)| (level_idx, slot_idx, dist));
        }

        if current_free_slots <= current_level.half_reserve_slot_threshold as usize {
            if let Some((slot_idx, dist)) = self.first_free_uniform(key_hash, level_idx + 1) {
                return Some((level_idx + 1, slot_idx, dist));
            }
            return self
                .first_free_uniform(key_hash, level_idx)
                .map(|(slot_idx, dist)| (level_idx, slot_idx, dist));
        }

        if let Some((slot_idx, dist)) = self.first_free_uniform(key_hash, level_idx) {
            return Some((level_idx, slot_idx, dist));
        }
        self.first_free_uniform(key_hash, level_idx + 1)
            .map(|(slot_idx, dist)| (level_idx + 1, slot_idx, dist))
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

    /// Paper §4 lookup: walk levels `A_1`, `A_2`, … in order using each
    /// level's probe sequence `h_{i,1}(x)`, `h_{i,2}(x)`, … until the key is
    /// found or all populated levels are exhausted.
    #[inline]
    fn find_slot_indices_with_hash<Q>(
        &self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
    ) -> Option<(usize, usize)>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let search_limit = (self.max_populated_level + 1).min(self.levels.len());
        for (level_idx, level) in self.levels[..search_limit].iter().enumerate() {
            if let Some(slot_idx) = level.find_by_probe(key_hash, key_fingerprint, key) {
                return Some((level_idx, slot_idx));
            }
        }
        None
    }

    /// Probe-bounded `first_free_uniform`: scans at most `max_groups` groups.
    /// Returns `(slot_idx, group_dist)`, the probe step where the slot was found,
    /// which the insert feeds to [`Level::note_probe_distance`].
    #[inline]
    #[allow(clippy::cast_possible_truncation)] // group_dist < group_count ≤ u32::MAX
    fn first_free_limited(
        &self,
        key_hash: u64,
        level_idx: usize,
        max_groups: usize,
    ) -> Option<(usize, u32)> {
        let level = &self.levels[level_idx];
        if level.len as usize >= level.capacity() {
            return None;
        }
        let group_count = level.group_count();
        let max_groups = max_groups.min(group_count.max(1));
        let mask = level.group_count_mask as usize;
        let mut probe = probe::TriangularProbe::new(level.triangular_group_start(key_hash));
        for step in 0..max_groups {
            if let Some(slot_idx) = level.first_free_in_group(probe.pos) {
                return Some((slot_idx, step as u32));
            }
            probe.advance(mask);
        }
        None
    }

    /// Triangular scan over all groups for the first FREE-or-TOMBSTONE slot.
    /// Returns `(slot_idx, group_dist)` (see [`Self::first_free_limited`]), or
    /// `None` only if the level is completely OCCUPIED.
    #[inline]
    #[allow(clippy::cast_possible_truncation)] // group_dist < group_count ≤ u32::MAX
    fn first_free_uniform(&self, key_hash: u64, level_idx: usize) -> Option<(usize, u32)> {
        let level = &self.levels[level_idx];
        if level.len as usize >= level.capacity() {
            return None;
        }
        let group_count = level.group_count();
        let mask = level.group_count_mask as usize;
        let mut probe = probe::TriangularProbe::new(level.triangular_group_start(key_hash));
        for step in 0..group_count {
            if let Some(slot_idx) = level.first_free_in_group(probe.pos) {
                return Some((slot_idx, step as u32));
            }
            probe.advance(mask);
        }
        None
    }

    /// After a remove, walk down `max_populated_level` past any now-empty
    /// trailing levels so subsequent lookups don't probe them.
    fn shrink_max_populated_level(&mut self) {
        while self.max_populated_level > 0
            && self.levels[self.max_populated_level].len == 0
            && self.levels[self.max_populated_level].tombstones == 0
        {
            self.max_populated_level -= 1;
        }
        if self.levels.is_empty() || (self.levels[0].len == 0 && self.levels[0].tombstones == 0) {
            self.max_populated_level = 0;
        }
    }
}

/// `min(1 + log δ⁻¹, group_count)` — paper §2 cap on `f(ε)` with `c = 1`.
fn compute_budget_cap(reserve_fraction: f64, group_count: usize) -> f64 {
    let log_cap = 1.0 + (1.0 / reserve_fraction).log2();
    let max_budget = math::cast::usize_to_f64(group_count.max(1));
    log_cap.min(max_budget).max(1.0)
}

/// Paper §4: split into `|A_{i+1}| = |A_i|/2 ± 1`, then round each up so
/// `group_count = size / GROUP_SIZE` is pow2 (triangular probe needs `(idx + delta) & mask` wrap).
/// Total slots may exceed `total_capacity` by up to ~2x.
/// Returns `[]` for capacity 0.
fn partition_levels(total_capacity: usize) -> Vec<usize> {
    if total_capacity == 0 {
        return Vec::new();
    }

    let mut sizes = Vec::new();
    let mut remaining = total_capacity;
    let mut next_size = total_capacity.div_ceil(2);

    while remaining > 0 {
        let size = next_size.min(remaining).max(1);
        sizes.push(size);
        remaining -= size;
        if remaining == 0 {
            break;
        }
        next_size = (size / 2).max(1);
    }

    sizes
        .into_iter()
        .map(align::round_up_to_pow2_groups)
        .collect()
}

/// Paper §4: batch `B_0` fills `A_1` to `⌈0.75|A_1|⌉`;
/// batch `B_i` (i ≥ 1) has `|A_i| - ⌊δ|A_i|/2⌋ - ⌈0.75|A_i|⌉ + ⌈0.75|A_{i+1}|⌉` insertions,
/// leaving `A_i` at `(1 - δ/2)` full and `A_{i+1}` at 3/4 full (eq. 1).
/// Total = `max_insertions`.
fn build_batch_plan(
    level_capacities: &[usize],
    reserve_fraction: f64,
    max_insertions: usize,
) -> Box<[usize]> {
    if level_capacities.is_empty() || max_insertions == 0 {
        return Box::new([]);
    }

    let mut plan = Vec::with_capacity(level_capacities.len() + 1);
    plan.push(capacity::ceil_three_quarters(level_capacities[0]));

    for level_index in 1..level_capacities.len() {
        let current_level_capacity = level_capacities[level_index - 1];
        let next_level_capacity = level_capacities[level_index];

        let target_current_level_occupancy = current_level_capacity.saturating_sub(
            capacity::floor_half_reserve_slots(reserve_fraction, current_level_capacity),
        );
        let initial_current_level_occupancy = capacity::ceil_three_quarters(current_level_capacity);
        let initial_next_level_occupancy = capacity::ceil_three_quarters(next_level_capacity);

        let batch_size = target_current_level_occupancy
            .saturating_sub(initial_current_level_occupancy)
            .saturating_add(initial_next_level_occupancy);
        plan.push(batch_size);
    }

    let mut inserted = 0;
    for size in &mut plan {
        if inserted >= max_insertions {
            *size = 0;
            continue;
        }
        let room = max_insertions - inserted;
        if *size > room {
            *size = room;
        }
        inserted += *size;
    }

    if inserted < max_insertions {
        plan.push(max_insertions - inserted);
    }

    plan.into_boxed_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ptr;

    use crate::common::config::DEFAULT_RESERVE_FRACTION;

    #[test]
    fn level_partition_inflates_to_pow2_groups_and_preserves_halving() {
        for &cap in &[127usize, 1_000, 10_000, 100_000] {
            let sizes = partition_levels(cap);
            assert!(!sizes.is_empty());
            // Each level's group_count must be pow2 (triangular precondition).
            for &s in &sizes {
                let g = s / GROUP_SIZE;
                assert!(
                    g.is_power_of_two(),
                    "cap={cap} level slots={s} groups={g} not pow2"
                );
            }
            // Slot total covers the requested capacity, bounded above by 2x.
            let total: usize = sizes.iter().sum();
            assert!(total >= cap, "cap={cap} total={total} below request");
            // The 2x space bound holds for the default 16-byte group. The
            // nightly wide layout rounds each geometric level up to a full
            // 64-slot group, so small capacities can fragment past 2x.
            #[cfg(not(opthash_wide_group))]
            assert!(total <= cap * 2, "cap={cap} total={total} exceeds 2x");
            // Each next level is at most the previous (non-increasing) and at
            // least half — the geometric halving shape, with pow2 rounding
            // tolerance.
            for w in sizes.windows(2) {
                assert!(w[1] <= w[0], "non-monotonic: {} → {}", w[0], w[1]);
                assert!(w[1] * 2 >= w[0], "shrinks too fast: {} → {}", w[0], w[1]);
            }
        }
    }

    #[test]
    fn limited_group_budget_uses_paper_linear_log() {
        // cap/free = 1024/12 = 85.3 (non-pow2): 1 + log2(85.3) = 7.42 floors to
        // 7 off any integer boundary, immune to libm's last-ULP wobble.
        const CAP: u32 = 1024;
        const FREE: u32 = 12;
        let mut level = Level::<SlotEntry<u64, u64>>::new_at(
            0,
            CAP,
            1.0 / 4096.0,
            ptr::null_mut(),
            ptr::null_mut(),
        );
        level.len = CAP - FREE;

        assert_eq!(level.limited_group_budget(), 7);
    }

    #[test]
    fn elastic_geometry_carries_capacity_and_batch_state() {
        for &requested in &[0usize, 1, 127, 1_000, 10_000] {
            let reserve_fraction = DEFAULT_RESERVE_FRACTION;
            let geometry = ElasticGeometry::for_insert_budget(requested, reserve_fraction).unwrap();
            assert!(
                geometry.max_insertions >= requested,
                "requested={requested} max_insertions={}",
                geometry.max_insertions
            );
            assert!(
                geometry.level_capacities.iter().sum::<usize>() >= geometry.total_slots,
                "rounded level capacities must cover total slots"
            );
            assert!(
                geometry.batch_plan.iter().sum::<usize>() >= geometry.max_insertions,
                "batch plan must cover the insertion budget"
            );
        }
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
    fn rebuild_inserts_advance_batch_scheduler() {
        let mut table: ElasticTable<usize, usize> =
            ElasticTable::with_capacity_and_reserve_fraction_and_hasher_in(
                1024,
                DEFAULT_RESERVE_FRACTION,
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
    fn insert_after_rebuild_advances_exhausted_batch() {
        let mut table: ElasticTable<usize, usize> =
            ElasticTable::with_capacity_and_reserve_fraction_and_hasher_in(
                1024,
                DEFAULT_RESERVE_FRACTION,
                DefaultHashBuilder::default(),
                Global,
            );
        let rebuild_slots = table.total_slots * 2;
        let rebuild_geometry = ElasticGeometry::for_slots(rebuild_slots, table.reserve_fraction);
        let bootstrap_quota = rebuild_geometry.batch_plan[0];

        for key in 0..bootstrap_quota {
            table.insert_unique(key, key);
        }
        table.scheduler.max_insertions = table.len;

        let key = bootstrap_quota;
        let hash = table.hash_key(&key);
        table.insert_for_vacant_entry(key, key, hash);

        assert!(table.scheduler.current_batch_index > 0);
        assert_eq!(table.scheduler.target(), BatchTarget::LevelPair(0));
    }

    #[test]
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
        // `retain` cleans up only on iterator Drop, at the same capacity —
        // slot count must not change.
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
            "retain must not change the slot count, only rehash in place"
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
            map.table().max_populated_level > 0,
            "expected spill into deeper level; max_populated_level = {}",
            map.table().max_populated_level
        );
        for i in 0..max {
            assert_eq!(map.get(&i), Some(&i));
        }
    }

    #[test]
    fn max_populated_level_shrinks_when_deepest_levels_emptied() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(512);
        let max = i32::try_from(map.capacity()).expect("test capacity fits i32");
        for i in 0..max {
            map.insert(i, i);
        }
        let high_water = map.table().max_populated_level;
        assert!(high_water > 0, "need a multi-level state to test shrinkage");
        for i in 0..max {
            map.remove(&i);
        }
        assert_eq!(map.len(), 0);
        assert_eq!(
            map.table().max_populated_level,
            0,
            "max_populated_level should walk back to 0 once every level empties"
        );
    }
}
