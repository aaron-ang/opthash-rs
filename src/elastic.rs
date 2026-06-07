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
use crate::map::{self, RawTable};
use crate::set;

/// `(slot pointer, location)` yielded by the scan cursor: the pointer is read
/// by iterators, the `(level, slot)` location backs removal.
type ElasticScanItem<K, V> = (*mut SlotEntry<K, V>, (usize, usize));

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
    /// Per-level salt mixed into key hashes.
    salt: u64,
    /// Paper §2 cap on `f(ε)`.
    budget_cap: f64,
}

unsafe impl<T: Send> Send for Level<T> {}
unsafe impl<T: Sync> Sync for Level<T> {}

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
            budget_cap: compute_budget_cap(reserve_fraction, gc as usize),
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
        let raw = 1.0 + log_inv_eps * log_inv_eps;
        raw.min(self.budget_cap) as usize
    }

    #[inline]
    fn needs_cleanup(&self) -> bool {
        self.tombstones > self.capacity / 2
    }

    #[inline]
    fn triangular_group_start(&self, key_hash: u64) -> usize {
        let mixed = key_hash ^ self.salt;
        probe::hash_to_usize(mixed) & self.group_count_mask as usize
    }

    /// Extends `max_probe_groups` to cover `slot_idx`'s probe distance. Run on
    /// every insert so a bounded lookup never stops short of a live key.
    #[inline]
    fn note_placement(&mut self, key_hash: u64, slot_idx: usize) {
        let target_group = slot_idx / GROUP_SIZE;
        let mask = self.group_count_mask as usize;
        let mut probe = probe::TriangularProbe::new(self.triangular_group_start(key_hash));
        let mut steps = 0u32;
        while probe.pos != target_group {
            probe.advance(mask);
            steps += 1;
        }
        if steps + 1 > self.max_probe_groups {
            self.max_probe_groups = steps + 1;
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
    /// Geometrically shrinking partition of capacity; length fixed at ctor.
    levels: LevelSlice<K, V>,
    /// Total live entries.
    len: usize,
    /// Total slot count across all levels.
    total_slots: usize,
    /// Insert count that triggers `resize(2x)`.
    max_insertions: usize,
    /// Slot reserve fraction per level. Set at construction.
    reserve_fraction: f64,
    /// Per-batch insert quota; drives `current_batch_index` advancement.
    batch_plan: Box<[usize]>,
    /// Index into `batch_plan`. Selects which level pair new keys target.
    current_batch_index: usize,
    /// Remaining inserts in the current batch before advancing.
    batch_remaining: usize,
    /// Highest level index ever written; bounds the lookup probe loop.
    max_populated_level: usize,
    /// Hash builder. Cloned across resizes to preserve probe sequences.
    hash_builder: S,
    /// Allocator used for all per-capacity allocations.
    alloc: A,
    /// One allocation holding all levels' ctrl bytes then all slot arrays.
    /// Layout: [`ctrl_L0` | `ctrl_L1` | ...] [pad] [`slots_L0` | `slots_L1` | ...]
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
        let arena = mem::replace(&mut self.arena, Arena::empty());
        let guard = arena::DeallocGuard::new(arena, &self.alloc);
        for level in &mut self.levels {
            level.drop_values();
        }
        drop(guard);
    }
}

// ---------------------------------------------------------------------------
// Public type aliases. The generic [`map::HashMap`] shell supplies the public
// API; these names keep `ElasticHashMap` and its iterator/entry types
// nameable (and re-exportable from `lib.rs` / `set.rs`).
// ---------------------------------------------------------------------------

/// Open-addressed hash map using elastic hashing.
pub type ElasticHashMap<K, V, S = DefaultHashBuilder, A = Global> =
    map::HashMap<K, V, ElasticTable<K, V, S, A>>;

/// A view into a single entry, occupied or vacant.
pub type ElasticEntry<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::Entry<'a, K, V, ElasticTable<K, V, S, A>>;
/// View of an occupied entry.
pub type ElasticOccupiedEntry<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::OccupiedEntry<'a, K, V, ElasticTable<K, V, S, A>>;
/// View of a vacant entry.
pub type ElasticVacantEntry<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::VacantEntry<'a, K, V, ElasticTable<K, V, S, A>>;
/// Error returned by `try_insert` on key collision.
pub type ElasticOccupiedError<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::OccupiedError<'a, K, V, ElasticTable<K, V, S, A>>;
/// Borrowing iterator over `(&K, &V)`.
pub type ElasticIter<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::Iter<'a, K, V, ElasticTable<K, V, S, A>>;
/// Borrowing iterator over `(&K, &mut V)`.
pub type ElasticIterMut<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::IterMut<'a, K, V, ElasticTable<K, V, S, A>>;
/// Consuming iterator over owned `(K, V)`.
pub type ElasticIntoIter<K, V, S = DefaultHashBuilder, A = Global> =
    map::IntoIter<K, V, ElasticTable<K, V, S, A>>;
/// `&K` iterator.
pub type ElasticKeys<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::Keys<'a, K, V, ElasticTable<K, V, S, A>>;
/// `&V` iterator.
pub type ElasticValues<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::Values<'a, K, V, ElasticTable<K, V, S, A>>;
/// `&mut V` iterator.
pub type ElasticValuesMut<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::ValuesMut<'a, K, V, ElasticTable<K, V, S, A>>;
/// Owned `K` iterator.
pub type ElasticIntoKeys<K, V, S = DefaultHashBuilder, A = Global> =
    map::IntoKeys<K, V, ElasticTable<K, V, S, A>>;
/// Owned `V` iterator.
pub type ElasticIntoValues<K, V, S = DefaultHashBuilder, A = Global> =
    map::IntoValues<K, V, ElasticTable<K, V, S, A>>;
/// Draining iterator that empties the map.
pub type ElasticDrain<'a, K, V, S = DefaultHashBuilder, A = Global> =
    map::Drain<'a, K, V, ElasticTable<K, V, S, A>>;
/// Iterator yielding entries removed by `extract_if`.
pub type ElasticExtractIf<'a, K, V, F, S = DefaultHashBuilder, A = Global> =
    map::ExtractIf<'a, K, V, ElasticTable<K, V, S, A>, F>;

/// Hash set using elastic hashing.
pub type ElasticHashSet<T, S = DefaultHashBuilder, A = Global> =
    set::HashSet<T, ElasticTable<T, (), S, A>>;
/// Borrowing iterator over set values.
pub type ElasticSetIter<'a, T, S = DefaultHashBuilder, A = Global> =
    set::Iter<'a, T, ElasticTable<T, (), S, A>>;
/// Consuming iterator over set values.
pub type ElasticSetIntoIter<T, S = DefaultHashBuilder, A = Global> =
    set::IntoIter<T, ElasticTable<T, (), S, A>>;
/// Draining iterator that empties the set.
pub type ElasticSetDrain<'a, T, S = DefaultHashBuilder, A = Global> =
    set::Drain<'a, T, ElasticTable<T, (), S, A>>;
/// Iterator yielding values removed by set `extract_if`.
pub type ElasticSetExtractIf<'a, T, S = DefaultHashBuilder, A = Global> =
    set::ExtractIf<'a, T, ElasticTable<T, (), S, A>>;
/// Iterator over values present only in the first set.
pub type ElasticDifference<'a, T, S = DefaultHashBuilder, A = Global> =
    set::Difference<'a, T, ElasticTable<T, (), S, A>>;
/// Iterator over values present in both sets.
pub type ElasticIntersection<'a, T, S = DefaultHashBuilder, A = Global> =
    set::Intersection<'a, T, ElasticTable<T, (), S, A>>;
/// Iterator over values present in exactly one set.
pub type ElasticSymmetricDifference<'a, T, S = DefaultHashBuilder, A = Global> =
    set::SymmetricDifference<'a, T, ElasticTable<T, (), S, A>>;
/// Iterator over values present in either set.
pub type ElasticUnion<'a, T, S = DefaultHashBuilder, A = Global> =
    set::Union<'a, T, ElasticTable<T, (), S, A>>;
/// A view into a single set entry.
pub type ElasticSetEntry<'a, T, S = DefaultHashBuilder, A = Global> =
    set::Entry<'a, T, ElasticTable<T, (), S, A>>;
/// View of an occupied set entry.
pub type ElasticSetOccupiedEntry<'a, T, S = DefaultHashBuilder, A = Global> =
    set::OccupiedEntry<'a, T, ElasticTable<T, (), S, A>>;
/// View of a vacant set entry.
pub type ElasticSetVacantEntry<'a, T, S = DefaultHashBuilder, A = Global> =
    set::VacantEntry<'a, T, ElasticTable<T, (), S, A>>;

/// Boxed slice of levels for one `(K, V)` parameterization.
type LevelSlice<K, V> = Box<[Level<SlotEntry<K, V>>]>;
type ElasticArenaBuild<K, V> = (Arena, LevelSlice<K, V>);

/// Stamps level descriptors with arena-relative `(ctrl_ptr, data_ptr)`.
/// Split out so the alloc-then-deallocate-on-error wrapper stays shallow.
fn build_elastic_levels<K, V>(
    arena_base: *mut u8,
    data_base_off: usize,
    level_capacities: &[usize],
    reserve_fraction: f64,
) -> Result<LevelSlice<K, V>, TryReserveError> {
    let slot_size = u32::try_from(mem::size_of::<SlotEntry<K, V>>())
        .map_err(|_| TryReserveError::CapacityOverflow)?;
    let mut ctrl_off: u32 = 0;
    let mut data_off: u32 =
        u32::try_from(data_base_off).map_err(|_| TryReserveError::CapacityOverflow)?;
    let mut levels: Vec<Level<SlotEntry<K, V>>> = Vec::new();
    levels
        .try_reserve_exact(level_capacities.len())
        .map_err(|_| TryReserveError::AllocError)?;
    for (level_idx, &cap) in level_capacities.iter().enumerate() {
        let cap_u32 = u32::try_from(cap).map_err(|_| TryReserveError::CapacityOverflow)?;
        let ctrl_ptr = unsafe { arena_base.add(ctrl_off as usize) };
        let data_ptr = unsafe {
            arena_base
                .add(data_off as usize)
                .cast::<MaybeUninit<SlotEntry<K, V>>>()
        };
        levels.push(Level::new_at(
            level_idx,
            cap_u32,
            reserve_fraction,
            ctrl_ptr,
            data_ptr,
        ));
        ctrl_off += cap_u32;
        data_off += cap_u32 * slot_size;
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

/// Drops values + deallocates an `Arena` if dropped before extraction.
/// Lets `resize`/`Clone` panic-safely roll back — `Arena` has no `Drop`.
/// Owns the level slice so mut-iteration borrows from `guard.levels`.
struct ArenaDropGuard<K, V, A: Allocator + Clone> {
    arena: Option<Arena>,
    levels: Option<LevelSlice<K, V>>,
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
            arena.deallocate(&self.alloc);
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
        let total_slots = if capacity == 0 {
            0
        } else {
            capacity::capacity_for(INITIAL_CAPACITY, capacity, reserve_fraction)
                .expect("capacity overflow")
        };
        let max_insertions = capacity::max_insertions(total_slots, reserve_fraction);

        let level_capacities = partition_levels(total_slots);
        let (arena, levels) = alloc_elastic_arena(&level_capacities, reserve_fraction, &alloc);
        let batch_plan = build_batch_plan(&level_capacities, reserve_fraction, max_insertions);
        let batch_remaining = batch_plan.first().copied().unwrap_or(0);

        Self {
            levels,
            len: 0,
            total_slots,
            max_insertions,
            reserve_fraction,
            batch_plan,
            current_batch_index: 0,
            batch_remaining,
            max_populated_level: 0,
            hash_builder,
            alloc,
            arena,
        }
    }

    /// Round up to the smallest capacity whose `max_insertions` accommodates
    /// `needed` live entries. Returns `None` if no representable capacity
    /// suffices. Used by `reserve` / `try_reserve`.
    fn grow_capacity_for(&self, needed: usize) -> Option<usize> {
        capacity::capacity_for(
            self.total_slots.max(INITIAL_CAPACITY),
            needed,
            self.reserve_fraction,
        )
    }

    /// Removes all entries, keeping allocated capacity.
    fn clear(&mut self) {
        for level in &mut self.levels {
            level.drop_values();
            level.clear_all_controls();
            level.len = 0;
            level.tombstones = 0;
        }
        self.len = 0;
        self.current_batch_index = 0;
        self.batch_remaining = self.batch_plan.first().copied().unwrap_or(0);
        self.max_populated_level = 0;
    }

    /// Post-lookup insert for a key known to be absent. Returns the chosen
    /// slot so the caller can borrow into it without re-probing.
    fn insert_for_vacant_entry(&mut self, key: K, value: V, key_hash: u64) -> (usize, usize) {
        let key_fingerprint = control::control_fingerprint(key_hash);

        if self.len >= self.max_insertions {
            let new_capacity = if self.total_slots == 0 {
                INITIAL_CAPACITY
            } else {
                self.total_slots.saturating_mul(2)
            };
            self.resize(new_capacity);
        }

        self.advance_batch_window();
        let (level_idx, slot_idx) = self
            .choose_slot_for_new_key(key_hash)
            .expect("no free slot found after resize");

        let level = &mut self.levels[level_idx];
        let prev_ctrl = level.control_at(slot_idx);
        level.write_with_control(slot_idx, SlotEntry { key, value }, key_fingerprint);
        level.note_placement(key_hash, slot_idx);
        level.len += 1;
        if prev_ctrl == CTRL_TOMBSTONE {
            level.tombstones -= 1;
        }
        if level_idx > self.max_populated_level {
            self.max_populated_level = level_idx;
        }
        self.len += 1;
        if self.batch_remaining > 0 {
            self.batch_remaining -= 1;
        }
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
    /// [`RawTable::remove`], which adds a resize pass.
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

    /// Cold path of [`RawTable::scan_next`]: first-call region prime and level
    /// crossings. Kept out of line so the per-element hot path inlines.
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

// `SlotEntry` is `pub(crate)`; the `RawTable` trait (in the private `map`
// module) exposes it in `slot_ref`/`slot_ptr`, so the impl mirrors the trait's
// private-interface lint exemption.
#[allow(private_interfaces)]
impl<K, V, S, A> RawTable<K, V> for ElasticTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Location = (usize, usize);
    type Hasher = S;
    type Alloc = A;
    type Scan = ElasticScan;

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
    fn find<Q>(&self, key: &Q, hash: u64, fingerprint: u8) -> Option<(usize, usize)>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find_slot_indices_with_hash(key, hash, fingerprint)
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

    fn wipe_all(&mut self) {
        for level in &mut self.levels {
            level.clear_all_controls();
            level.len = 0;
            level.tombstones = 0;
        }
        self.len = 0;
        self.max_populated_level = 0;
        self.current_batch_index = 0;
        self.batch_remaining = self.batch_plan.first().copied().unwrap_or(0);
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
        let mut guard = ArenaDropGuard {
            arena: Some(arena),
            levels: Some(levels),
            alloc: self.alloc.clone(),
        };

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
            dst.max_probe_groups = src_lvl.max_probe_groups;
        }

        // Success: extract arena + levels from the guard so its Drop becomes
        // a no-op. Both fields now live in `Self` below.
        let arena = guard.arena.take().unwrap();
        let levels = guard.levels.take().unwrap();
        drop(guard);

        Self {
            levels,
            len: self.len,
            total_slots: self.total_slots,
            max_insertions: self.max_insertions,
            reserve_fraction: self.reserve_fraction,
            batch_plan: self.batch_plan.clone(),
            current_batch_index: self.current_batch_index,
            batch_remaining: self.batch_remaining,
            max_populated_level: self.max_populated_level,
            hash_builder: self.hash_builder.clone(),
            alloc: self.alloc.clone(),
            arena,
        }
    }
}

/// Multi-level scan cursor for [`RawTable::scan`]. Holds the current level
/// index and a shared [`RegionCursor`]. `scan()` leaves it pointer-free; the
/// region pointer is populated only on the first `scan_next`, so a consumed
/// table can be moved before iteration begins.
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

        self.advance_batch_window();
        let (level_idx, slot_idx) = self
            .choose_slot_for_new_key(key_hash)
            .expect("no free slot found in freshly-allocated map");

        let level = &mut self.levels[level_idx];
        level.write_with_control(slot_idx, SlotEntry { key, value }, key_fingerprint);
        level.note_placement(key_hash, slot_idx);
        level.len += 1;
        if level_idx > self.max_populated_level {
            self.max_populated_level = level_idx;
        }
        self.len += 1;
        if self.batch_remaining > 0 {
            self.batch_remaining -= 1;
        }
    }

    /// Drain all live entries into a temp Vec, rebuild levels at
    /// `new_capacity` in-place, reinsert. Passing the current capacity
    /// performs a no-grow rehash that flushes accumulated tombstones.
    fn resize(&mut self, new_capacity: usize) {
        let level_capacities = partition_levels(new_capacity);
        let new_max_insertions = capacity::max_insertions(new_capacity, self.reserve_fraction);
        let new_batch_plan =
            build_batch_plan(&level_capacities, self.reserve_fraction, new_max_insertions);
        let new_batch_remaining = new_batch_plan.first().copied().unwrap_or(0);

        let (new_arena, new_levels) =
            alloc_elastic_arena(&level_capacities, self.reserve_fraction, &self.alloc);

        // Swap in fresh arena; keep old one alive until drain completes.
        let old_arena = mem::replace(&mut self.arena, new_arena);
        let old_levels = mem::replace(&mut self.levels, new_levels);
        self.total_slots = new_capacity;
        self.max_insertions = new_max_insertions;
        self.batch_plan = new_batch_plan;
        self.current_batch_index = 0;
        self.batch_remaining = new_batch_remaining;
        self.max_populated_level = 0;
        self.len = 0;

        // Move every live entry from old arena into the new levels.
        //
        // Panic safety: clear each source ctrl before handing the moved entry
        // to `insert_unique`, so the guard's drop walks only un-moved slots.
        // If `insert_unique` panics, the guard unwinds: drops any survivors
        // then deallocates `old_arena` — `Arena` has no `Drop`, so without the
        // guard the backing allocation would leak.
        let mut guard = ArenaDropGuard {
            arena: Some(old_arena),
            levels: Some(old_levels),
            alloc: self.alloc.clone(),
        };
        for level in guard.levels.as_deref_mut().unwrap() {
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
        let total_slots = slots;
        let reserve_fraction = capacity::sanitize_reserve_fraction(reserve_fraction);
        let max_insertions = capacity::max_insertions(total_slots, reserve_fraction);

        let level_capacities = partition_levels(total_slots);
        let (arena, levels) = try_alloc_elastic_arena(&level_capacities, reserve_fraction, &alloc)?;
        let batch_plan = build_batch_plan(&level_capacities, reserve_fraction, max_insertions);
        let batch_remaining = batch_plan.first().copied().unwrap_or(0);

        Ok(Self {
            levels,
            len: 0,
            total_slots,
            max_insertions,
            reserve_fraction,
            batch_plan,
            current_batch_index: 0,
            batch_remaining,
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

    /// Advance the batch state machine past any zero-quota batches so the
    /// next insert routes to the correct level pair.
    #[inline]
    fn advance_batch_window(&mut self) {
        while self.batch_remaining == 0 && self.current_batch_index + 1 < self.batch_plan.len() {
            self.current_batch_index += 1;
            self.batch_remaining = self.batch_plan[self.current_batch_index];
        }
    }

    /// Paper §4 places each insert in `A_i` or `A_{i+1}` per the current batch `B_i`;
    /// The full-sweep fallback covers the tombstone-reuse case the paper's analysis doesn't model.
    #[inline]
    fn choose_slot_for_new_key(&mut self, key_hash: u64) -> Option<(usize, usize)> {
        if self.levels.is_empty() {
            return None;
        }

        if let Some(pair) = self.choose_slot_targeted(key_hash) {
            return Some(pair);
        }

        for li in 0..self.levels.len() {
            if let Some(slot_idx) = self.first_free_uniform(key_hash, li) {
                return Some((li, slot_idx));
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
    fn choose_slot_targeted(&self, key_hash: u64) -> Option<(usize, usize)> {
        if self.current_batch_index == 0 {
            return self
                .first_free_uniform(key_hash, 0)
                .map(|slot_idx| (0, slot_idx));
        }

        let level_idx = self.current_batch_index.saturating_sub(1);
        if level_idx + 1 >= self.levels.len() {
            let last = self.levels.len() - 1;
            return self
                .first_free_uniform(key_hash, last)
                .map(|slot_idx| (last, slot_idx));
        }

        let current_level = &self.levels[level_idx];
        let next_level = &self.levels[level_idx + 1];
        let current_free_slots = current_level.free_slots();
        let next_free_slots = next_level.free_slots();

        if current_free_slots > current_level.half_reserve_slot_threshold as usize
            && next_free_slots.saturating_mul(4) > next_level.capacity()
        {
            let limited_budget = current_level.limited_group_budget();
            if let Some(slot_idx) = self.first_free_limited(key_hash, level_idx, limited_budget) {
                return Some((level_idx, slot_idx));
            }
            if let Some(slot_idx) = self.first_free_uniform(key_hash, level_idx + 1) {
                return Some((level_idx + 1, slot_idx));
            }
            return self
                .first_free_uniform(key_hash, level_idx)
                .map(|slot_idx| (level_idx, slot_idx));
        }

        if current_free_slots <= current_level.half_reserve_slot_threshold as usize {
            if let Some(slot_idx) = self.first_free_uniform(key_hash, level_idx + 1) {
                return Some((level_idx + 1, slot_idx));
            }
            return self
                .first_free_uniform(key_hash, level_idx)
                .map(|slot_idx| (level_idx, slot_idx));
        }

        if let Some(slot_idx) = self.first_free_uniform(key_hash, level_idx) {
            return Some((level_idx, slot_idx));
        }
        self.first_free_uniform(key_hash, level_idx + 1)
            .map(|slot_idx| (level_idx + 1, slot_idx))
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

    /// Probe-bounded variant of `first_free_uniform`: scans at most
    /// `max_groups` groups. Used by the elastic schedule when
    /// `current_level` still has reserve headroom.
    #[inline]
    fn first_free_limited(
        &self,
        key_hash: u64,
        level_idx: usize,
        max_groups: usize,
    ) -> Option<usize> {
        let level = &self.levels[level_idx];
        if level.len as usize >= level.capacity() {
            return None;
        }
        let group_count = level.group_count();
        let max_groups = max_groups.min(group_count.max(1));
        let mask = level.group_count_mask as usize;
        let mut probe = probe::TriangularProbe::new(level.triangular_group_start(key_hash));
        for _ in 0..max_groups {
            if let Some(slot_idx) = level.first_free_in_group(probe.pos) {
                return Some(slot_idx);
            }
            probe.advance(mask);
        }
        None
    }

    /// Triangular scan over all groups for the first FREE-or-TOMBSTONE slot.
    /// Returns `None` only if the level is completely OCCUPIED.
    #[inline]
    fn first_free_uniform(&self, key_hash: u64, level_idx: usize) -> Option<usize> {
        let level = &self.levels[level_idx];
        if level.len as usize >= level.capacity() {
            return None;
        }
        let group_count = level.group_count();
        let mask = level.group_count_mask as usize;
        let mut probe = probe::TriangularProbe::new(level.triangular_group_start(key_hash));
        for _ in 0..group_count {
            if let Some(slot_idx) = level.first_free_in_group(probe.pos) {
                return Some(slot_idx);
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
