use std::fmt;
use std::hash::{BuildHasher, Hash};
use std::iter::FusedIterator;
use std::marker::PhantomData;
use std::mem::{self, ManuallyDrop};
use std::ops::Index;
use std::ptr;

use allocator_api2::alloc::Layout;
use equivalent::Equivalent;

use crate::common::arena::{self, Arena, ArenaSlots, IterRange, SlotEntry};
use crate::common::bitmask::BitMask;
use crate::common::config::{
    DEFAULT_RESERVE_FRACTION, GROUP_SIZE, GROUP_SIZE_U32, INITIAL_CAPACITY,
};
use crate::common::control::{self, CTRL_EMPTY, CTRL_TOMBSTONE};
use crate::common::error::{EntryView, OccupiedError as CommonOccupiedError};
use crate::common::iter::{
    IntoKeys as CommonIntoKeys, IntoValues as CommonIntoValues, Keys as CommonKeys,
    Values as CommonValues,
};
use crate::common::math::{self, align, capacity, probe};
use crate::common::{Allocator, DefaultHashBuilder, Global, TryReserveError};

/// Descriptor for one sub-array `A_i`. Holds metadata + cached pointers
/// into the map-level arena; owns no allocation. The actual ctrl bytes and
/// [`SlotEntry`] data live contiguously in [`ElasticHashMap::arena`].
struct Level<T> {
    /// Cached `arena.as_ptr() + ctrl_offset`, stamped at construction.
    ctrl_ptr: *mut u8,
    /// Cached `arena.as_ptr() + data_offset`, stamped at construction.
    data_ptr: *mut T,
    /// Slot capacity (= `group_count` * `GROUP_SIZE`). Bounded by `capacity`
    /// via the arena layout, so `len`/`tombstones` fit in `u32` too.
    capacity: u32,
    /// Number of SIMD groups.
    group_count: u32,
    /// `group_count - 1`; pow2 so probe wrap is `& mask`.
    group_count_mask: u32,
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
    fn data_ptr(&self) -> *mut T {
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
        data_ptr: *mut T,
    ) -> Self {
        let cap = cap_u32 as usize;
        let gc = cap_u32 / GROUP_SIZE_U32;
        Self {
            ctrl_ptr,
            data_ptr,
            capacity: cap_u32,
            group_count: gc,
            group_count_mask: gc.wrapping_sub(1),
            salt: math::level_salt(level_idx),
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

    /// Triangular probe: fingerprint scan + caller-provided equality test.
    /// Returns slot index on hit, `None` on miss (stops at first EMPTY byte
    /// in the group sequence). Closure-driven so `Level<T>` stays K, V-free
    /// at the type level — caller binds `|entry| key.equivalent(&entry.key)`
    /// or set-style `|entry| key.equivalent(entry)`.
    #[inline]
    fn find_by_probe<F: FnMut(&T) -> bool>(
        &self,
        key_hash: u64,
        key_fingerprint: u8,
        mut eq: F,
    ) -> Option<usize> {
        if self.len == 0 {
            return None;
        }
        let mask = self.group_count_mask as usize;
        let mut probe = probe::TriangularProbe::new(self.triangular_group_start(key_hash));
        for _ in 0..self.group_count {
            let match_mask = self.group_match_mask(probe.pos, key_fingerprint);
            for relative_idx in match_mask {
                let slot_idx = probe.pos * GROUP_SIZE + relative_idx;
                let entry = unsafe { self.get_ref(slot_idx) };
                if eq(entry) {
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

/// Open-addressed hash map using elastic hashing.
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
pub struct ElasticHashMap<K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
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
    for ElasticHashMap<K, V, S, A>
{
}
unsafe impl<K: Sync, V: Sync, S: Sync, A: Allocator + Clone + Sync> Sync
    for ElasticHashMap<K, V, S, A>
{
}

impl<K, V, S, A: Allocator + Clone> Drop for ElasticHashMap<K, V, S, A> {
    fn drop(&mut self) {
        let arena = mem::replace(&mut self.arena, Arena::empty());
        let guard = arena::DeallocGuard::new(arena, &self.alloc);
        for level in &self.levels {
            level.drop_values();
        }
        drop(guard);
    }
}

impl<K, V, S, A> fmt::Debug for ElasticHashMap<K, V, S, A>
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

impl<K, V> Default for ElasticHashMap<K, V, DefaultHashBuilder, Global>
where
    K: Eq + Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

// Global allocator + default hasher constructors.
impl<K, V> ElasticHashMap<K, V, DefaultHashBuilder, Global>
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
impl<K, V, S> ElasticHashMap<K, V, S, Global>
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
impl<K, V, A> ElasticHashMap<K, V, DefaultHashBuilder, A>
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
        let data_ptr = unsafe { arena_base.add(data_off as usize).cast::<SlotEntry<K, V>>() };
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
            if let Some(levels) = self.levels.take() {
                for level in &levels {
                    level.drop_values();
                }
            }
            arena.deallocate(&self.alloc);
        }
    }
}

impl<K, V, S, A> ElasticHashMap<K, V, S, A>
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
    /// budget, not the raw slot count (see [`Self::total_slots`] field).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.max_insertions
    }

    /// Grow capacity so at least `additional` more inserts fit without
    /// triggering an internal resize. No-op if already large enough.
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
    /// the larger of `min_capacity` and [`Self::len`]. Mirrors
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
    /// suffices. Used by `reserve` / `try_reserve`.
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

        if let Some((level_idx, slot_idx)) =
            self.find_slot_indices_with_hash(&key, key_hash, key_fingerprint)
        {
            let entry = unsafe { self.levels[level_idx].get_mut(slot_idx) };
            let old = mem::replace(&mut entry.value, value);
            return Some(old);
        }

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
        None
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let key_hash = self.hash_key(key);
        let key_fingerprint = control::control_fingerprint(key_hash);
        let (level_idx, slot_idx) =
            self.find_slot_indices_with_hash(key, key_hash, key_fingerprint)?;
        Some(unsafe { &self.levels[level_idx].get_ref(slot_idx).value })
    }

    /// Like [`Self::get`] but returns the stored key alongside its value.
    pub fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let key_hash = self.hash_key(key);
        let key_fingerprint = control::control_fingerprint(key_hash);
        let (level_idx, slot_idx) =
            self.find_slot_indices_with_hash(key, key_hash, key_fingerprint)?;
        let entry = unsafe { self.levels[level_idx].get_ref(slot_idx) };
        Some((&entry.key, &entry.value))
    }

    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let key_hash = self.hash_key(key);
        let key_fingerprint = control::control_fingerprint(key_hash);
        let (level_idx, slot_idx) =
            self.find_slot_indices_with_hash(key, key_hash, key_fingerprint)?;
        Some(unsafe { &mut self.levels[level_idx].get_mut(slot_idx).value })
    }

    /// Returns `N` disjoint mutable references, mirroring
    /// [`std::collections::HashMap::get_disjoint_mut`]: per-key `Option` for
    /// each lookup, panic on aliasing among the hits.
    ///
    /// # Panics
    ///
    /// If two input keys resolve to the same `(level, slot)` pair.
    pub fn get_disjoint_mut<Q, const N: usize>(&mut self, keys: [&Q; N]) -> [Option<&mut V>; N]
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let locations = self.locate_disjoint(keys);
        arena::check_disjoint_aliasing(&locations);

        let levels_ptr: *const Level<SlotEntry<K, V>> = self.levels.as_ptr();
        std::array::from_fn(|i| {
            locations[i].map(|(level_idx, slot_idx)| {
                // SAFETY: locations are unique among Somes (asserted above).
                // `elastic_slot_value_ptr` projects via raw pointers — no
                // intermediate `&mut Level` / `&mut RawTable`, so two keys
                // hitting the same level can't alias under Stacked Borrows.
                let value_ptr = unsafe { elastic_slot_value_ptr(levels_ptr, level_idx, slot_idx) };
                unsafe { &mut *value_ptr }
            })
        })
    }

    /// Like [`Self::get_disjoint_mut`] but each yielded element is
    /// `(&K, &mut V)`. Mirrors `std`'s `get_disjoint_key_value_mut`.
    ///
    /// # Panics
    ///
    /// If two input keys resolve to the same `(level, slot)` pair.
    pub fn get_disjoint_key_value_mut<Q, const N: usize>(
        &mut self,
        keys: [&Q; N],
    ) -> [Option<(&K, &mut V)>; N]
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let locations = self.locate_disjoint(keys);
        arena::check_disjoint_aliasing(&locations);

        let levels_ptr: *const Level<SlotEntry<K, V>> = self.levels.as_ptr();
        std::array::from_fn(|i| {
            locations[i].map(|(level_idx, slot_idx)| {
                // SAFETY: as in `get_disjoint_mut`.
                let (k_ptr, v_ptr) =
                    unsafe { elastic_slot_kv_ptrs(levels_ptr, level_idx, slot_idx) };
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

        let levels_ptr: *const Level<SlotEntry<K, V>> = self.levels.as_ptr();
        std::array::from_fn(|i| {
            locations[i].map(|(level_idx, slot_idx)| {
                // SAFETY: caller guarantees the hits are pairwise distinct.
                let value_ptr = unsafe { elastic_slot_value_ptr(levels_ptr, level_idx, slot_idx) };
                unsafe { &mut *value_ptr }
            })
        })
    }

    #[inline]
    fn locate_disjoint<Q, const N: usize>(&self, keys: [&Q; N]) -> [Option<(usize, usize)>; N]
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        std::array::from_fn(|i| {
            let key = keys[i];
            let key_hash = self.hash_key(key);
            let key_fingerprint = control::control_fingerprint(key_hash);
            self.find_slot_indices_with_hash(key, key_hash, key_fingerprint)
        })
    }

    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let key_hash = self.hash_key(key);
        let key_fingerprint = control::control_fingerprint(key_hash);
        self.find_slot_indices_with_hash(key, key_hash, key_fingerprint)
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
        let (level_idx, slot_idx) =
            self.find_slot_indices_with_hash(key, key_hash, key_fingerprint)?;

        let removed_entry = {
            let level = &mut self.levels[level_idx];
            let removed = unsafe { level.take(slot_idx) };
            level.mark_tombstone(slot_idx);
            level.len -= 1;
            level.tombstones += 1;
            removed
        };

        self.len -= 1;
        let needs_resize = self.levels[level_idx].needs_cleanup();
        self.shrink_max_populated_level();
        if needs_resize {
            self.resize(self.total_slots);
        }
        Some((removed_entry.key, removed_entry.value))
    }

    pub fn clear(&mut self) {
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

    #[must_use]
    pub fn iter(&self) -> ElasticIter<'_, K, V, A> {
        ElasticIter {
            iter: IterRange::new_shared(&self.levels),
            remaining: self.len,
            _alloc: PhantomData,
        }
    }

    /// `&K` iterator. Order matches [`Self::iter`].
    #[must_use]
    pub fn keys(&self) -> Keys<'_, K, V, A> {
        Keys::new(self.iter())
    }

    /// `&V` iterator. Order matches [`Self::iter`].
    #[must_use]
    pub fn values(&self) -> Values<'_, K, V, A> {
        Values::new(self.iter())
    }

    /// Reference to the map's [`BuildHasher`].
    #[must_use]
    pub fn hasher(&self) -> &S {
        &self.hash_builder
    }

    /// `(&K, &mut V)` iterator. Mirrors `HashMap::iter_mut`.
    pub fn iter_mut(&mut self) -> ElasticIterMut<'_, K, V, A> {
        let remaining = self.len;
        let iter = IterRange::new_mut(&mut self.levels);
        ElasticIterMut {
            iter,
            remaining,
            _alloc: PhantomData,
        }
    }

    /// `&mut V` iterator. Mirrors `HashMap::values_mut`.
    pub fn values_mut(&mut self) -> ElasticValuesMut<'_, K, V, A> {
        ElasticValuesMut {
            inner: self.iter_mut(),
        }
    }

    /// Consuming iterator over owned keys. Mirrors `HashMap::into_keys`.
    #[must_use]
    pub fn into_keys(self) -> ElasticIntoKeys<K, V, S, A> {
        ElasticIntoKeys::new(self.into_iter())
    }

    /// Consuming iterator over owned values. Mirrors `HashMap::into_values`.
    #[must_use]
    pub fn into_values(self) -> ElasticIntoValues<K, V, S, A> {
        ElasticIntoValues::new(self.into_iter())
    }

    /// Returns an [`Entry`] for in-place manipulation of `key`'s slot.
    /// Mirrors [`std::collections::HashMap::entry`].
    pub fn entry(&mut self, key: K) -> Entry<'_, K, V, S, A> {
        let key_hash = self.hash_key(&key);
        let key_fingerprint = control::control_fingerprint(key_hash);
        if let Some((level_idx, slot_idx)) =
            self.find_slot_indices_with_hash(&key, key_hash, key_fingerprint)
        {
            Entry::Occupied(OccupiedEntry {
                map: self,
                level_idx,
                slot_idx,
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
        let iter = IterRange::new_mut(&mut self.levels);
        Drain {
            iter,
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
        let iter = IterRange::new_mut(&mut self.levels);
        ExtractIf {
            iter,
            map_ptr,
            pred: f,
            _marker: PhantomData,
        }
    }
}

/// A view into a single entry in an [`ElasticHashMap`], which may be either
/// vacant or occupied. Constructed via [`ElasticHashMap::entry`].
pub enum Entry<'a, K: 'a, V: 'a, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    /// Slot is occupied; key already lives in the map.
    Occupied(OccupiedEntry<'a, K, V, S, A>),
    /// Slot is vacant; the supplied key does not exist in the map yet.
    Vacant(VacantEntry<'a, K, V, S, A>),
}

/// View of an occupied entry in an [`ElasticHashMap`].
pub struct OccupiedEntry<'a, K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    map: &'a mut ElasticHashMap<K, V, S, A>,
    level_idx: usize,
    slot_idx: usize,
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
        unsafe { &self.map.slot_ref(self.level_idx, self.slot_idx).key }
    }

    /// Returns a reference to the entry's value.
    #[must_use]
    pub fn get(&self) -> &V {
        unsafe { &self.map.slot_ref(self.level_idx, self.slot_idx).value }
    }

    /// Returns `&mut V`. Borrow is tied to `self`; for the map's lifetime
    /// use [`OccupiedEntry::into_mut`].
    pub fn get_mut(&mut self) -> &mut V {
        unsafe { &mut self.map.slot_mut(self.level_idx, self.slot_idx).value }
    }

    /// Consumes the entry and returns `&mut V` borrowed from the map.
    #[must_use]
    pub fn into_mut(self) -> &'a mut V {
        unsafe { &mut self.map.slot_mut(self.level_idx, self.slot_idx).value }
    }

    /// Replaces the entry's value and returns the old one.
    pub fn insert(&mut self, value: V) -> V {
        let entry = unsafe { self.map.slot_mut(self.level_idx, self.slot_idx) };
        mem::replace(&mut entry.value, value)
    }

    /// Removes the entry and returns its value.
    #[must_use]
    pub fn remove(self) -> V {
        self.remove_entry().1
    }

    /// Removes the entry and returns the `(key, value)` pair.
    #[must_use]
    pub fn remove_entry(self) -> (K, V) {
        let level_idx = self.level_idx;
        let slot_idx = self.slot_idx;
        let removed = {
            let level = &mut self.map.levels[level_idx];
            let removed = unsafe { level.take(slot_idx) };
            level.mark_tombstone(slot_idx);
            level.len -= 1;
            level.tombstones += 1;
            removed
        };

        self.map.len -= 1;
        let needs_resize = self.map.levels[level_idx].needs_cleanup();
        self.map.shrink_max_populated_level();
        if needs_resize {
            self.map.resize(self.map.total_slots);
        }
        (removed.key, removed.value)
    }
}

/// View of a vacant entry in an [`ElasticHashMap`].
pub struct VacantEntry<'a, K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    map: &'a mut ElasticHashMap<K, V, S, A>,
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
        let (level_idx, slot_idx) =
            self.map
                .insert_for_vacant_entry(self.key, value, self.key_hash);
        unsafe { &mut self.map.slot_mut(level_idx, slot_idx).value }
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

/// Error returned by [`ElasticHashMap::try_insert`] on key collision.
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

/// Draining iterator. Yields and removes every `(K, V)` entry; the map is
/// empty once the iterator is consumed or dropped. Returned by
/// [`ElasticHashMap::drain`].
///
/// SAFETY: `iter` + `map_ptr` alias the same allocation, but each step
/// uses fresh temp `&mut`s only; `PhantomData` brands the `'a` borrow.
pub struct Drain<'a, K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    iter: IterRange<'a, SlotEntry<K, V>, Level<SlotEntry<K, V>>>,
    map_ptr: *mut ElasticHashMap<K, V, S, A>,
    _marker: PhantomData<&'a mut ElasticHashMap<K, V, S, A>>,
}

impl<K, V, S, A: Allocator + Clone> fmt::Debug for Drain<'_, K, V, S, A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Drain")
            .field("remaining", &unsafe { (*self.map_ptr).len })
            .finish_non_exhaustive()
    }
}

impl<K, V, S, A: Allocator + Clone> Iterator for Drain<'_, K, V, S, A> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        // Per-yield ctrl byte update is skipped: Drain::drop wipes all ctrls
        // via `clear_all_controls` regardless, and the scan only advances
        // forward so yielded slots are never re-read.
        let handle = self.iter.next_handle()?;
        let entry = unsafe { handle.read() };
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
        // All entries moved out via `next()`; wipe ctrl bytes + counters en bloc.
        let map = unsafe { &mut *self.map_ptr };
        for level in &mut map.levels {
            level.clear_all_controls();
            level.len = 0;
            level.tombstones = 0;
        }
        map.len = 0;
        map.max_populated_level = 0;
        map.current_batch_index = 0;
        map.batch_remaining = map.batch_plan.first().copied().unwrap_or(0);
    }
}

/// Filtering drain. Yields and removes entries for which the predicate
/// returns `true`; the rest stay in the map. Returned by
/// [`ElasticHashMap::extract_if`].
///
/// SAFETY: as [`Drain`] — `scanner` + `map_ptr` alias the same allocation;
/// each step uses fresh temporary `&mut`s only.
pub struct ExtractIf<'a, K, V, F, S = DefaultHashBuilder, A: Allocator + Clone = Global>
where
    K: Eq + Hash,
    S: BuildHasher,
    F: FnMut(&K, &mut V) -> bool,
{
    iter: IterRange<'a, SlotEntry<K, V>, Level<SlotEntry<K, V>>>,
    map_ptr: *mut ElasticHashMap<K, V, S, A>,
    pred: F,
    _marker: PhantomData<&'a mut ElasticHashMap<K, V, S, A>>,
}

impl<K, V, F, S, A: Allocator + Clone> fmt::Debug for ExtractIf<'_, K, V, F, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    F: FnMut(&K, &mut V) -> bool,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ExtractIf")
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
        while let Some(mut handle) = self.iter.next_handle() {
            // In-place borrow so predicate mutations stick on kept entries.
            let entry = unsafe { handle.as_mut() };
            if (self.pred)(&entry.key, &mut entry.value) {
                let level_ptr = handle.descriptor_ptr();
                // Tombstone before read so a panic between (none expected
                // here, but defensively) leaves no OCCUPIED to double-drop.
                unsafe {
                    handle.tombstone();
                    (*level_ptr).len -= 1;
                    (*level_ptr).tombstones += 1;
                    (*self.map_ptr).len -= 1;
                }
                let removed = unsafe { handle.read() };
                return Some((removed.key, removed.value));
            }
        }
        None
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

/// Borrowing iterator over occupied entries.
pub struct ElasticIter<'a, K, V, A: Allocator + Clone = Global> {
    iter: IterRange<'a, SlotEntry<K, V>, Level<SlotEntry<K, V>>>,
    remaining: usize,
    _alloc: PhantomData<&'a A>,
}

impl<K, V, A: Allocator + Clone> Clone for ElasticIter<'_, K, V, A> {
    fn clone(&self) -> Self {
        Self {
            iter: self.iter.clone(),
            remaining: self.remaining,
            _alloc: PhantomData,
        }
    }
}

impl<K: fmt::Debug, V: fmt::Debug, A: Allocator + Clone> fmt::Debug for ElasticIter<'_, K, V, A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

impl<'a, K, V, A: Allocator + Clone> Iterator for ElasticIter<'a, K, V, A> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let handle = self.iter.next_handle()?;
        // SAFETY: ElasticIter holds a shared borrow of the levels; only
        // `as_ref` is called on the handle.
        let entry = unsafe { handle.as_ref() };
        self.remaining -= 1;
        Some((&entry.key, &entry.value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K, V, A: Allocator + Clone> ExactSizeIterator for ElasticIter<'_, K, V, A> {}
impl<K, V, A: Allocator + Clone> FusedIterator for ElasticIter<'_, K, V, A> {}

impl<'a, K, V, S, A> IntoIterator for &'a ElasticHashMap<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Item = (&'a K, &'a V);
    type IntoIter = ElasticIter<'a, K, V, A>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// `&K` iterator returned by [`ElasticHashMap::keys`].
pub type Keys<'a, K, V, A = Global> = CommonKeys<ElasticIter<'a, K, V, A>>;
/// `&V` iterator returned by [`ElasticHashMap::values`].
pub type Values<'a, K, V, A = Global> = CommonValues<ElasticIter<'a, K, V, A>>;

/// `(&K, &mut V)` iterator. Walks levels in storage order, skipping FREE
/// and TOMBSTONE slots. Each `next()` yields a strictly newer slot ⇒
/// returned `&mut V`s are disjoint.
pub struct ElasticIterMut<'a, K, V, A: Allocator + Clone = Global> {
    iter: IterRange<'a, SlotEntry<K, V>, Level<SlotEntry<K, V>>>,
    remaining: usize,
    _alloc: PhantomData<A>,
}

impl<'a, K, V, A: Allocator + Clone> Iterator for ElasticIterMut<'a, K, V, A> {
    type Item = (&'a K, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        let mut handle = self.iter.next_handle()?;
        // SAFETY: scanner yielded a fresh handle; reborrow through raw
        // ptrs so refs outlive the handle's `&mut Level` borrow.
        let entry = unsafe { handle.as_mut() };
        let key: &'a K = unsafe { &*ptr::from_ref(&entry.key) };
        let val: &'a mut V = unsafe { &mut *ptr::from_mut(&mut entry.value) };
        self.remaining -= 1;
        Some((key, val))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K, V, A: Allocator + Clone> ExactSizeIterator for ElasticIterMut<'_, K, V, A> {}
impl<K, V, A: Allocator + Clone> FusedIterator for ElasticIterMut<'_, K, V, A> {}

impl<K, V, A: Allocator + Clone> fmt::Debug for ElasticIterMut<'_, K, V, A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ElasticIterMut")
            .field("remaining", &self.remaining)
            .finish_non_exhaustive()
    }
}

impl<'a, K, V, S, A> IntoIterator for &'a mut ElasticHashMap<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Item = (&'a K, &'a mut V);
    type IntoIter = ElasticIterMut<'a, K, V, A>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

/// `&mut V` iterator returned by [`ElasticHashMap::values_mut`].
pub struct ElasticValuesMut<'a, K, V, A: Allocator + Clone = Global> {
    inner: ElasticIterMut<'a, K, V, A>,
}

impl<'a, K, V, A: Allocator + Clone> Iterator for ElasticValuesMut<'a, K, V, A> {
    type Item = &'a mut V;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(_, v)| v)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<K, V, A: Allocator + Clone> ExactSizeIterator for ElasticValuesMut<'_, K, V, A> {}
impl<K, V, A: Allocator + Clone> FusedIterator for ElasticValuesMut<'_, K, V, A> {}

impl<K, V, A: Allocator + Clone> fmt::Debug for ElasticValuesMut<'_, K, V, A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ElasticValuesMut")
            .field("remaining", &self.inner.remaining)
            .finish_non_exhaustive()
    }
}

/// Consuming `(K, V)` iterator returned by `ElasticHashMap::into_iter`.
/// Holds levels + arena via `ManuallyDrop` so the inline scan ptr stays
/// valid without a self-borrow. `Drop` drains, then frees.
pub struct ElasticIntoIter<K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    /// Raw walker over `*self.levels`. Cursor state inline; no lifetime tie
    /// needed — the box is kept alive here via `ManuallyDrop`.
    levels_ptr: *mut Level<SlotEntry<K, V>>,
    levels_len: usize,
    level_idx: usize,
    next_group_slot: usize,
    current_group_slot: usize,
    current_mask: BitMask,
    levels: ManuallyDrop<LevelSlice<K, V>>,
    arena: ManuallyDrop<Arena>,
    alloc: A,
    remaining: usize,
    _marker: PhantomData<S>,
}

// SAFETY: raw pointers into owned `levels` / `arena`; Send/Sync match map.
unsafe impl<K: Send, V: Send, S: Send, A: Allocator + Clone + Send> Send
    for ElasticIntoIter<K, V, S, A>
{
}
unsafe impl<K: Sync, V: Sync, S: Sync, A: Allocator + Clone + Sync> Sync
    for ElasticIntoIter<K, V, S, A>
{
}

impl<K, V, S, A: Allocator + Clone> Iterator for ElasticIntoIter<K, V, S, A> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        while self.level_idx < self.levels_len {
            // SAFETY: `level_idx < levels_len`; `levels_ptr` points at the
            // box's data, kept alive by `self.levels: ManuallyDrop`.
            let level = unsafe { &mut *self.levels_ptr.add(self.level_idx) };
            if let Some(idx) = level.scan_next(
                &mut self.next_group_slot,
                &mut self.current_group_slot,
                &mut self.current_mask,
            ) {
                // SAFETY: scan only yields occupied slots. Tombstone-mark
                // prevents future revisits if `Drop` runs mid-iteration.
                let entry = unsafe { level.take(idx) };
                level.mark_tombstone(idx);
                self.remaining -= 1;
                return Some((entry.key, entry.value));
            }
            self.level_idx += 1;
            self.next_group_slot = 0;
            self.current_group_slot = 0;
            self.current_mask = BitMask(0);
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K, V, S, A: Allocator + Clone> ExactSizeIterator for ElasticIntoIter<K, V, S, A> {}
impl<K, V, S, A: Allocator + Clone> FusedIterator for ElasticIntoIter<K, V, S, A> {}

impl<K, V, S, A: Allocator + Clone> Drop for ElasticIntoIter<K, V, S, A> {
    fn drop(&mut self) {
        // Drain any unyielded entries so values run their Drop.
        for _ in self.by_ref() {}
        // SAFETY: scanner is no longer used past this point. Drop the
        // levels box (descriptors only, no remaining values), then free
        // the arena.
        unsafe {
            ManuallyDrop::drop(&mut self.levels);
            let arena = ManuallyDrop::take(&mut self.arena);
            arena.deallocate(&self.alloc);
        }
    }
}

impl<K, V, S, A: Allocator + Clone> fmt::Debug for ElasticIntoIter<K, V, S, A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ElasticIntoIter")
            .field("remaining", &self.remaining)
            .finish_non_exhaustive()
    }
}

impl<K, V, S, A> IntoIterator for ElasticHashMap<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Item = (K, V);
    type IntoIter = ElasticIntoIter<K, V, S, A>;

    fn into_iter(mut self) -> Self::IntoIter {
        let mut levels = mem::take(&mut self.levels);
        let arena = mem::replace(&mut self.arena, Arena::empty());
        let alloc = self.alloc.clone();
        let remaining = self.len;
        let levels_ptr = levels.as_mut_ptr();
        let levels_len = levels.len();
        // `self` drops below: empty levels + empty arena = no-op on the
        // arena/data side; hash_builder / batch_plan / etc. drop normally.
        ElasticIntoIter {
            levels_ptr,
            levels_len,
            level_idx: 0,
            next_group_slot: 0,
            current_group_slot: 0,
            current_mask: BitMask(0),
            levels: ManuallyDrop::new(levels),
            arena: ManuallyDrop::new(arena),
            alloc,
            remaining,
            _marker: PhantomData,
        }
    }
}

/// Owned `K` iterator returned by [`ElasticHashMap::into_keys`].
pub type ElasticIntoKeys<K, V, S = DefaultHashBuilder, A = Global> =
    CommonIntoKeys<ElasticIntoIter<K, V, S, A>>;
/// Owned `V` iterator returned by [`ElasticHashMap::into_values`].
pub type ElasticIntoValues<K, V, S = DefaultHashBuilder, A = Global> =
    CommonIntoValues<ElasticIntoIter<K, V, S, A>>;

impl<K, V, S, A> ElasticHashMap<K, V, S, A>
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
        // Panic safety: clear each source ctrl right after `read` so the
        // guard's drop walks only un-moved slots (no double-drop with
        // entries already in the new arena). If `insert_unique` panics
        // the guard unwinds: drops any survivors then deallocates
        // `old_arena` — `Arena` has no `Drop`, so without the guard the
        // backing allocation would leak.
        let guard = ArenaDropGuard {
            arena: Some(old_arena),
            levels: Some(old_levels),
            alloc: self.alloc.clone(),
        };
        for level in guard.levels.as_deref().unwrap() {
            for idx in level.occupied() {
                let entry = unsafe { level.take(idx) };
                level.set_control(idx, CTRL_EMPTY);
                self.insert_unique(entry.key, entry.value);
            }
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

        // Clear each source ctrl immediately after `take`. If `insert_unique`
        // panics (e.g. via a user-provided `Hash` impl), the un-iterated slots
        // remain OCCUPIED on `self` and the already-moved ones are EMPTY, so
        // both `self.drop_values` and `new_map.drop_values` are sound on
        // unwind (no double-drop).
        for level in &self.levels {
            for idx in level.occupied() {
                let entry = unsafe { level.take(idx) };
                level.set_control(idx, CTRL_EMPTY);
                new_map.insert_unique(entry.key, entry.value);
            }
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
            if let Some(slot_idx) = level.find_by_probe(key_hash, key_fingerprint, |entry| {
                key.equivalent(&entry.key)
            }) {
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

/// Raw-pointer projection from `(level_idx, slot_idx)` to `*mut V`.
/// Used by `get_disjoint_mut*` to hand out disjoint `&mut V` from multiple
/// slots without going through `&mut ElasticHashMap`.
///
/// # Safety
///
/// - `levels_ptr` must point to the map's live `[Level<SlotEntry<K, V>>]`.
/// - `slot_idx` must be an occupied slot in that level.
#[inline]
unsafe fn elastic_slot_value_ptr<K, V>(
    levels_ptr: *const Level<SlotEntry<K, V>>,
    level_idx: usize,
    slot_idx: usize,
) -> *mut V {
    let level = unsafe { &*levels_ptr.add(level_idx) };
    unsafe { &raw mut (*level.data_ptr().add(slot_idx)).value }
}

/// As [`elastic_slot_value_ptr`] but returns key + value pointers together.
#[inline]
unsafe fn elastic_slot_kv_ptrs<K, V>(
    levels_ptr: *const Level<SlotEntry<K, V>>,
    level_idx: usize,
    slot_idx: usize,
) -> (*const K, *mut V) {
    let level = unsafe { &*levels_ptr.add(level_idx) };
    let entry = unsafe { &mut *level.data_ptr().add(slot_idx) };
    (ptr::addr_of!(entry.key), ptr::addr_of_mut!(entry.value))
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

impl<K, V, S, A> Clone for ElasticHashMap<K, V, S, A>
where
    K: Clone,
    V: Clone,
    S: Clone,
    A: Allocator + Clone,
{
    fn clone(&self) -> Self {
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

    fn clone_from(&mut self, source: &Self) {
        // Reuse `self.arena` when the per-level layout matches — capacities
        // fully determine descriptor offsets, so we save one alloc + dealloc
        // per assignment. Falls back to full clone otherwise.
        let layouts_match = self.levels.len() == source.levels.len()
            && self
                .levels
                .iter()
                .zip(source.levels.iter())
                .all(|(a, b)| a.capacity == b.capacity);
        if !layouts_match {
            *self = source.clone();
            return;
        }

        for level in &self.levels {
            level.drop_values_and_clear();
        }

        // Panic-safe: `K::clone` / `V::clone` unwinding leaves `self`'s arena
        // with OCCUPIED ctrls only on slots that were fully written. `Drop`
        // walks ctrls, so the partial state cleans up correctly.
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

        self.len = source.len;
        self.total_slots = source.total_slots;
        self.max_insertions = source.max_insertions;
        self.reserve_fraction = source.reserve_fraction;
        self.batch_plan.clone_from(&source.batch_plan);
        self.current_batch_index = source.current_batch_index;
        self.batch_remaining = source.batch_remaining;
        self.max_populated_level = source.max_populated_level;
        self.hash_builder.clone_from(&source.hash_builder);
    }
}

impl<K, V, S, A> PartialEq for ElasticHashMap<K, V, S, A>
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

impl<K, V, S, A> Eq for ElasticHashMap<K, V, S, A>
where
    K: Eq + Hash,
    V: Eq,
    S: BuildHasher,
    A: Allocator + Clone,
{
}

impl<K, Q, V, S, A> Index<&Q> for ElasticHashMap<K, V, S, A>
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

impl<K, V, S, A> Extend<(K, V)> for ElasticHashMap<K, V, S, A>
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

impl<'a, K, V, S, A> Extend<(&'a K, &'a V)> for ElasticHashMap<K, V, S, A>
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

impl<'a, K, V, S, A> Extend<&'a (K, V)> for ElasticHashMap<K, V, S, A>
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

impl<K, V, S> FromIterator<(K, V)> for ElasticHashMap<K, V, S, Global>
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
        assert!(map.levels.len() > 1, "test requires multi-level layout");
        let max = i32::try_from(map.capacity()).expect("test capacity fits i32");
        for i in 0..max {
            map.insert(i, i);
        }
        assert!(
            map.max_populated_level > 0,
            "expected spill into deeper level; max_populated_level = {}",
            map.max_populated_level
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
        let high_water = map.max_populated_level;
        assert!(high_water > 0, "need a multi-level state to test shrinkage");
        for i in 0..max {
            map.remove(&i);
        }
        assert_eq!(map.len(), 0);
        assert_eq!(
            map.max_populated_level, 0,
            "max_populated_level should walk back to 0 once every level empties"
        );
    }
}
