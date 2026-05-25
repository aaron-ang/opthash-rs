use std::fmt;
use std::hash::{BuildHasher, Hash};
use std::iter::FusedIterator;
use std::marker::PhantomData;
use std::mem;
use std::ptr;

use equivalent::Equivalent;

use crate::common::config::{DEFAULT_RESERVE_FRACTION, GROUP_SIZE, INITIAL_CAPACITY};
use crate::common::control::{self, CTRL_EMPTY, CTRL_TOMBSTONE, ControlByte};
use crate::common::error::{EntryView, OccupiedError as CommonOccupiedError};
use crate::common::iter::{
    IntoKeys as CommonIntoKeys, IntoValues as CommonIntoValues, Keys as CommonKeys,
    Values as CommonValues,
};
use crate::common::math::{self, align, capacity, probe};
use crate::common::table::{OccupiedCursor, RawTable, SlotEntry};
use crate::common::{Allocator, DefaultHashBuilder, Global, TryReserveError};

/// One sub-array `A_i` in paper §4's partition `|A_{i+1}| = |A_i|/2 ± 1`.
/// Independent open-addressed table with its own probe sequence `h_{i,j}(x)`.
struct Level<K, V, A: Allocator + Clone = Global> {
    /// `SoA` control bytes + entries.
    table: RawTable<SlotEntry<K, V>, A>,
    /// Live entry count.
    len: usize,
    /// Per-level salt mixed into key hashes. Hot — read every lookup.
    salt: u64,
    /// `group_count - 1`. `group_count` is pow2 by construction (see
    /// `partition_levels`), so `(idx + delta) & mask` wraps in one op.
    group_count_mask: usize,
    /// Deleted-slot count.
    tombstones: usize,
    /// Cached `floor(reserve * cap / 2)` for the
    /// `current_free_slots > threshold` branch in slot selection.
    half_reserve_slot_threshold: usize,
    /// Paper §2 cap on `f(ε)` — `min(1 + log δ⁻¹, group_count)` with `c = 1`.
    budget_cap: f64,
}

impl<K, V, A: Allocator + Clone> Level<K, V, A> {
    fn with_capacity_in(
        capacity: usize,
        reserve_fraction: f64,
        level_idx: usize,
        alloc: A,
    ) -> Self {
        let table = RawTable::new_in(capacity, alloc);
        let group_count = table.group_count();
        debug_assert!(
            group_count == 0 || group_count.is_power_of_two(),
            "partition_levels must produce pow2 group_count",
        );
        let budget_cap = compute_budget_cap(reserve_fraction, group_count);
        Self {
            table,
            len: 0,
            salt: math::level_salt(level_idx),
            group_count_mask: group_count.wrapping_sub(1),
            tombstones: 0,
            half_reserve_slot_threshold: capacity::floor_half_reserve_slots(
                reserve_fraction,
                capacity,
            ),
            budget_cap,
        }
    }

    /// Fallible counterpart to [`Level::with_capacity_in`].
    fn try_with_capacity_in(
        capacity: usize,
        reserve_fraction: f64,
        level_idx: usize,
        alloc: A,
    ) -> Result<Self, TryReserveError> {
        let table =
            RawTable::try_new_in(capacity, alloc).map_err(|()| TryReserveError::AllocError)?;
        let group_count = table.group_count();
        let budget_cap = compute_budget_cap(reserve_fraction, group_count);
        Ok(Self {
            table,
            len: 0,
            salt: math::level_salt(level_idx),
            group_count_mask: group_count.wrapping_sub(1),
            tombstones: 0,
            half_reserve_slot_threshold: capacity::floor_half_reserve_slots(
                reserve_fraction,
                capacity,
            ),
            budget_cap,
        })
    }

    #[inline]
    fn capacity(&self) -> usize {
        self.table.capacity()
    }

    /// Slots minus live entries. Includes tombstones (reusable on insert).
    #[inline]
    fn free_slots(&self) -> usize {
        self.capacity().saturating_sub(self.len)
    }

    /// Paper §2 `f(ε) = c·min(log² ε⁻¹, log δ⁻¹)` with `ε = free_slots/capacity`.
    #[inline]
    #[allow(
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation
    )]
    fn limited_group_budget(&self) -> usize {
        let capacity = self.capacity();
        let free_slots = self.free_slots();
        if capacity == 0 || free_slots == 0 {
            return 1;
        }
        let log_inv_eps = (capacity as f64 / free_slots as f64).log2();
        let raw = 1.0 + log_inv_eps * log_inv_eps;
        raw.min(self.budget_cap) as usize
    }

    /// Triggers a no-grow rehash on remove when tombstones outnumber half
    /// the slots. Keeps probe sequences from degrading after delete-heavy
    /// workloads.
    #[inline]
    fn needs_cleanup(&self) -> bool {
        self.tombstones > self.capacity() / 2
    }

    /// Triangular-probing starting group: `(key_hash ^ salt) & (group_count - 1)`.
    /// `group_count` is pow2 by `partition_levels` construction.
    #[inline]
    fn triangular_group_start(&self, key_hash: u64) -> usize {
        let mixed = key_hash ^ self.salt;
        probe::hash_to_usize(mixed) & self.group_count_mask
    }

    /// Paper §4 search in this `A_i`: triangular probe of groups, SIMD
    /// fingerprint match, key compare. Stops on FREE byte (probe chain
    /// terminated naturally; key cannot be deeper in this level).
    #[inline]
    fn find_by_probe<Q>(&self, key_hash: u64, key_fingerprint: u8, key: &Q) -> Option<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        if self.len == 0 {
            return None;
        }

        let group_count = self.table.group_count();
        let mask = self.group_count_mask;
        let mut probe = probe::TriangularProbe::new(self.triangular_group_start(key_hash));

        for _ in 0..group_count {
            let match_mask = self.table.group_match_mask(probe.pos, key_fingerprint);
            for relative_idx in match_mask {
                let slot_idx = probe.pos * GROUP_SIZE + relative_idx;
                let entry = unsafe { self.table.get_ref(slot_idx) };
                if key.equivalent(&entry.key) {
                    return Some(slot_idx);
                }
            }
            if self.table.group_match_mask(probe.pos, CTRL_EMPTY).any() {
                return None;
            }
            probe.advance(mask);
        }
        None
    }
}

impl<K: Clone, V: Clone, A: Allocator + Clone> Clone for Level<K, V, A> {
    fn clone(&self) -> Self {
        Self {
            table: self.table.clone(),
            len: self.len,
            salt: self.salt,
            group_count_mask: self.group_count_mask,
            tombstones: self.tombstones,
            half_reserve_slot_threshold: self.half_reserve_slot_threshold,
            budget_cap: self.budget_cap,
        }
    }

    fn clone_from(&mut self, source: &Self) {
        self.table.clone_from(&source.table);
        self.len = source.len;
        self.salt = source.salt;
        self.group_count_mask = source.group_count_mask;
        self.tombstones = source.tombstones;
        self.half_reserve_slot_threshold = source.half_reserve_slot_threshold;
        self.budget_cap = source.budget_cap;
    }
}

/// Open-addressed hash map using elastic hashing.
///
/// Splits capacity across geometrically shrinking `levels` and routes inserts
/// through a `batch_plan`: early batches concentrate on level 0; later
/// batches push toward deeper levels. Lookups probe every level whose
/// `len > 0`. Unlike standard open addressing, expected probe count stays
/// low even at high load.
pub struct ElasticHashMap<K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    /// Geometrically shrinking partition of capacity; length fixed at ctor.
    levels: Box<[Level<K, V, A>]>,
    /// Total live entries.
    len: usize,
    /// Total slot count across all levels.
    capacity: usize,
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
    /// Allocator used for all per-capacity allocations (tables, probe budgets).
    alloc: A,
}

impl<K: fmt::Debug, V: fmt::Debug, S, A: Allocator + Clone> fmt::Debug
    for ElasticHashMap<K, V, S, A>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ElasticHashMap")
            .field("len", &self.len)
            .field("capacity", &self.capacity)
            .field("max_populated_level", &self.max_populated_level)
            .finish_non_exhaustive()
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
        let capacity = if capacity == 0 {
            0
        } else {
            capacity::capacity_for(INITIAL_CAPACITY, capacity, reserve_fraction)
                .expect("capacity overflow")
        };
        let max_insertions = capacity::max_insertions(capacity, reserve_fraction);

        let level_capacities = partition_levels(capacity);
        let levels: Box<[Level<K, V, A>]> = level_capacities
            .iter()
            .enumerate()
            .map(|(level_idx, &cap)| {
                Level::with_capacity_in(cap, reserve_fraction, level_idx, alloc.clone())
            })
            .collect();

        let batch_plan = build_batch_plan(&level_capacities, reserve_fraction, max_insertions);
        let batch_remaining = batch_plan.first().copied().unwrap_or(0);

        Self {
            levels,
            len: 0,
            capacity,
            max_insertions,
            reserve_fraction,
            batch_plan,
            current_batch_index: 0,
            batch_remaining,
            max_populated_level: 0,
            hash_builder,
            alloc,
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
    /// Mirrors [`std::collections::HashMap::capacity`]. Returns
    /// `max_insertions` (the budget), not the raw slot count.
    #[must_use]
    #[allow(clippy::misnamed_getters)]
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
    /// the larger of `min_capacity` and `self.len`. Mirrors
    /// [`std::collections::HashMap::shrink_to`].
    ///
    /// # Panics
    ///
    /// Panics if no representable capacity satisfies
    /// `capacity::max_insertions(cap) >= min_capacity`.
    pub fn shrink_to(&mut self, min_capacity: usize) {
        if self.len == 0 && min_capacity == 0 {
            if self.capacity > 0 {
                self.resize(0);
            }
            return;
        }
        let lower = self.len.max(min_capacity).max(INITIAL_CAPACITY);
        let new_capacity = capacity::capacity_for(INITIAL_CAPACITY, lower, self.reserve_fraction)
            .expect("capacity overflow");
        if new_capacity >= self.capacity {
            return;
        }
        self.resize(new_capacity);
    }

    /// Round up to the smallest capacity whose `max_insertions` accommodates
    /// `needed` live entries. Returns `None` if no representable capacity
    /// suffices. Used by `reserve` / `try_reserve`.
    fn grow_capacity_for(&self, needed: usize) -> Option<usize> {
        capacity::capacity_for(
            self.capacity.max(INITIAL_CAPACITY),
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
            let entry = unsafe { self.levels[level_idx].table.get_mut(slot_idx) };
            let old = mem::replace(&mut entry.value, value);
            return Some(old);
        }

        if self.len >= self.max_insertions {
            let new_capacity = if self.capacity == 0 {
                INITIAL_CAPACITY
            } else {
                self.capacity.saturating_mul(2)
            };
            self.resize(new_capacity);
        }

        self.advance_batch_window();
        let (level_idx, slot_idx) = self
            .choose_slot_for_new_key(key_hash)
            .expect("no free slot found after resize");

        let level = &mut self.levels[level_idx];
        let prev_ctrl = level.table.control_at(slot_idx);
        level
            .table
            .write_with_control(slot_idx, SlotEntry { key, value }, key_fingerprint);
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
        Some(unsafe { &self.levels[level_idx].table.get_ref(slot_idx).value })
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
        let entry = unsafe { self.levels[level_idx].table.get_ref(slot_idx) };
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
        Some(unsafe { &mut self.levels[level_idx].table.get_mut(slot_idx).value })
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
        check_disjoint_aliasing(&locations);

        let levels_ptr: *mut Level<K, V, A> = self.levels.as_mut_ptr();
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
        check_disjoint_aliasing(&locations);

        let levels_ptr: *mut Level<K, V, A> = self.levels.as_mut_ptr();
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

        let levels_ptr: *mut Level<K, V, A> = self.levels.as_mut_ptr();
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
            let removed = unsafe { level.table.take(slot_idx) };
            level.table.mark_tombstone(slot_idx);
            level.len -= 1;
            level.tombstones += 1;
            removed
        };

        self.len -= 1;
        let needs_resize = self.levels[level_idx].needs_cleanup();
        self.shrink_max_populated_level();
        if needs_resize {
            self.resize(self.capacity);
        }
        Some((removed_entry.key, removed_entry.value))
    }

    pub fn clear(&mut self) {
        for level in &mut self.levels {
            for idx in 0..level.table.capacity() {
                if level.table.control_at(idx).is_occupied() {
                    unsafe { level.table.drop_in_place(idx) };
                }
            }
            level.table.clear_all_controls();
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
            tables: self.levels.iter(),
            current: None,
            cursor: OccupiedCursor::new(),
            remaining: self.len,
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
        let levels_len = self.levels.len();
        let levels = self.levels.as_mut_ptr();
        let remaining = self.len;
        ElasticIterMut {
            levels,
            levels_len,
            level_idx: 0,
            cursor: OccupiedCursor::new(),
            remaining,
            _marker: PhantomData,
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
            let new_capacity = if self.capacity == 0 {
                INITIAL_CAPACITY
            } else {
                self.capacity.saturating_mul(2)
            };
            self.resize(new_capacity);
        }

        self.advance_batch_window();
        let (level_idx, slot_idx) = self
            .choose_slot_for_new_key(key_hash)
            .expect("no free slot found after resize");

        let level = &mut self.levels[level_idx];
        let prev_ctrl = level.table.control_at(slot_idx);
        level
            .table
            .write_with_control(slot_idx, SlotEntry { key, value }, key_fingerprint);
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
        Drain {
            map: self,
            level_idx: 0,
            cursor: OccupiedCursor::new(),
        }
    }

    /// Yields and removes `(K, V)` pairs where `f` returned `true`; kept
    /// entries remain in the map. Mirrors
    /// [`std::collections::HashMap::extract_if`].
    pub fn extract_if<F>(&mut self, f: F) -> ExtractIf<'_, K, V, F, S, A>
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        ExtractIf {
            map: self,
            pred: f,
            level_idx: 0,
            cursor: OccupiedCursor::new(),
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
        unsafe {
            &self.map.levels[self.level_idx]
                .table
                .get_ref(self.slot_idx)
                .key
        }
    }

    /// Returns a reference to the entry's value.
    #[must_use]
    pub fn get(&self) -> &V {
        unsafe {
            &self.map.levels[self.level_idx]
                .table
                .get_ref(self.slot_idx)
                .value
        }
    }

    /// Returns `&mut V`. Borrow is tied to `self`; for the map's lifetime
    /// use [`OccupiedEntry::into_mut`].
    pub fn get_mut(&mut self) -> &mut V {
        unsafe {
            &mut self.map.levels[self.level_idx]
                .table
                .get_mut(self.slot_idx)
                .value
        }
    }

    /// Consumes the entry and returns `&mut V` borrowed from the map.
    #[must_use]
    pub fn into_mut(self) -> &'a mut V {
        unsafe {
            &mut self.map.levels[self.level_idx]
                .table
                .get_mut(self.slot_idx)
                .value
        }
    }

    /// Replaces the entry's value and returns the old one.
    pub fn insert(&mut self, value: V) -> V {
        let entry = unsafe { self.map.levels[self.level_idx].table.get_mut(self.slot_idx) };
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
            let removed = unsafe { level.table.take(slot_idx) };
            level.table.mark_tombstone(slot_idx);
            level.len -= 1;
            level.tombstones += 1;
            removed
        };

        self.map.len -= 1;
        let needs_resize = self.map.levels[level_idx].needs_cleanup();
        self.map.shrink_max_populated_level();
        if needs_resize {
            let capacity = self.map.capacity;
            self.map.resize(capacity);
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
        unsafe { &mut self.map.levels[level_idx].table.get_mut(slot_idx).value }
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
pub struct Drain<'a, K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    map: &'a mut ElasticHashMap<K, V, S, A>,
    level_idx: usize,
    cursor: OccupiedCursor,
}

impl<K: fmt::Debug, V: fmt::Debug, S, A: Allocator + Clone> fmt::Debug for Drain<'_, K, V, S, A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Drain").finish_non_exhaustive()
    }
}

impl<K, V, S, A: Allocator + Clone> Iterator for Drain<'_, K, V, S, A> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        // Per-yield ctrl byte update is skipped: Drain::drop wipes all ctrls
        // via `clear_all_controls` regardless, and the scan only advances
        // forward so yielded slots are never re-read.
        while self.level_idx < self.map.levels.len() {
            let level = &mut self.map.levels[self.level_idx];
            if let Some(idx) = level.table.scan_next(&mut self.cursor) {
                let entry = unsafe { level.table.take(idx) };
                self.map.len -= 1;
                return Some((entry.key, entry.value));
            }
            self.level_idx += 1;
            self.cursor = OccupiedCursor::new();
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.map.len, Some(self.map.len))
    }
}

impl<K, V, S, A: Allocator + Clone> ExactSizeIterator for Drain<'_, K, V, S, A> {}
impl<K, V, S, A: Allocator + Clone> FusedIterator for Drain<'_, K, V, S, A> {}

impl<K, V, S, A: Allocator + Clone> Drop for Drain<'_, K, V, S, A> {
    fn drop(&mut self) {
        // Drain any unyielded entries so values run their `Drop`.
        for _ in &mut *self {}
        // All entries moved out via `next()`; wipe ctrl bytes + counters en bloc.
        for level in &mut self.map.levels {
            level.table.clear_all_controls();
            level.len = 0;
            level.tombstones = 0;
        }
        self.map.len = 0;
        self.map.max_populated_level = 0;
        self.map.current_batch_index = 0;
        self.map.batch_remaining = self.map.batch_plan.first().copied().unwrap_or(0);
    }
}

/// Filtering drain. Yields and removes entries for which the predicate
/// returns `true`; the rest stay in the map. Returned by
/// [`ElasticHashMap::extract_if`].
pub struct ExtractIf<'a, K, V, F, S = DefaultHashBuilder, A: Allocator + Clone = Global>
where
    K: Eq + Hash,
    S: BuildHasher,
    F: FnMut(&K, &mut V) -> bool,
{
    map: &'a mut ElasticHashMap<K, V, S, A>,
    pred: F,
    level_idx: usize,
    cursor: OccupiedCursor,
}

impl<K, V, F, S, A: Allocator + Clone> fmt::Debug for ExtractIf<'_, K, V, F, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    F: FnMut(&K, &mut V) -> bool,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ExtractIf").finish_non_exhaustive()
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
        while self.level_idx < self.map.levels.len() {
            let level = &mut self.map.levels[self.level_idx];
            while let Some(idx) = level.table.scan_next(&mut self.cursor) {
                // In-place borrow so predicate mutations stick on kept entries.
                let entry = unsafe { level.table.get_mut(idx) };
                if (self.pred)(&entry.key, &mut entry.value) {
                    let removed = unsafe { level.table.take(idx) };
                    level.table.mark_tombstone(idx);
                    level.len -= 1;
                    level.tombstones += 1;
                    self.map.len -= 1;
                    return Some((removed.key, removed.value));
                }
            }
            self.level_idx += 1;
            self.cursor = OccupiedCursor::new();
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.map.len))
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

/// Borrowing iterator over occupied entries. Walks levels in order via
/// [`OccupiedCursor`]; skips FREE and TOMBSTONE.
#[derive(Clone)]
pub struct ElasticIter<'a, K, V, A: Allocator + Clone = Global> {
    tables: std::slice::Iter<'a, Level<K, V, A>>,
    current: Option<&'a RawTable<SlotEntry<K, V>, A>>,
    cursor: OccupiedCursor,
    remaining: usize,
}

impl<K, V, A: Allocator + Clone> fmt::Debug for ElasticIter<'_, K, V, A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ElasticIter").finish_non_exhaustive()
    }
}

impl<'a, K, V, A: Allocator + Clone> Iterator for ElasticIter<'a, K, V, A> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let Some(table) = self.current else {
                self.current = Some(&self.tables.next()?.table);
                self.cursor = OccupiedCursor::new();
                continue;
            };
            if let Some(slot_idx) = table.scan_next(&mut self.cursor) {
                let entry = unsafe { table.get_ref(slot_idx) };
                self.remaining -= 1;
                return Some((&entry.key, &entry.value));
            }
            self.current = None;
        }
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
/// and TOMBSTONE slots.
///
/// SAFETY: raw pointer + `PhantomData<&'a mut [Level<K, V, A>]>` ties the
/// iterator to the exclusive borrow of the map. Each `next()` returns a
/// borrow of a strictly newer slot, so produced references are disjoint.
pub struct ElasticIterMut<'a, K, V, A: Allocator + Clone = Global> {
    levels: *mut Level<K, V, A>,
    levels_len: usize,
    level_idx: usize,
    cursor: OccupiedCursor,
    remaining: usize,
    _marker: PhantomData<&'a mut [Level<K, V, A>]>,
}

// SAFETY: behaves as `&mut [Level<K, V, A>]` for its lifetime.
unsafe impl<K: Send, V: Send, A: Allocator + Clone + Send> Send for ElasticIterMut<'_, K, V, A> {}
unsafe impl<K: Sync, V: Sync, A: Allocator + Clone + Sync> Sync for ElasticIterMut<'_, K, V, A> {}

impl<'a, K, V, A: Allocator + Clone> Iterator for ElasticIterMut<'a, K, V, A> {
    type Item = (&'a K, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        while self.level_idx < self.levels_len {
            // SAFETY: `level_idx < levels_len`; `self.levels` points at an
            // owned slice of initialized `Level`s. Fresh `&mut` each iter.
            let level = unsafe { &mut *self.levels.add(self.level_idx) };
            if let Some(idx) = level.table.scan_next(&mut self.cursor) {
                // SAFETY: scan only yields occupied slots; reborrow through
                // raw ptr so refs outlive the per-iter `level` reborrow.
                let entry = unsafe { level.table.get_mut(idx) };
                let key: &'a K = unsafe { &*ptr::from_ref(&entry.key) };
                let val: &'a mut V = unsafe { &mut *ptr::from_mut(&mut entry.value) };
                self.remaining -= 1;
                return Some((key, val));
            }
            self.level_idx += 1;
            self.cursor = OccupiedCursor::new();
        }
        None
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
            .field("level_idx", &self.level_idx)
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
            .field("level_idx", &self.inner.level_idx)
            .finish_non_exhaustive()
    }
}

/// Consuming `(K, V)` iterator returned by `ElasticHashMap::into_iter`.
pub struct ElasticIntoIter<K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    map: ElasticHashMap<K, V, S, A>,
    level_idx: usize,
    cursor: OccupiedCursor,
}

impl<K, V, S, A: Allocator + Clone> Iterator for ElasticIntoIter<K, V, S, A> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        while self.level_idx < self.map.levels.len() {
            let table = &mut self.map.levels[self.level_idx].table;
            if let Some(idx) = table.scan_next(&mut self.cursor) {
                // SAFETY: scan only yields occupied slots. Tombstone-mark
                // prevents map's Drop and future next() from revisiting.
                let entry = unsafe { table.take(idx) };
                table.mark_tombstone(idx);
                self.map.len -= 1;
                return Some((entry.key, entry.value));
            }
            self.level_idx += 1;
            self.cursor = OccupiedCursor::new();
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.map.len, Some(self.map.len))
    }
}

impl<K, V, S, A: Allocator + Clone> ExactSizeIterator for ElasticIntoIter<K, V, S, A> {}
impl<K, V, S, A: Allocator + Clone> FusedIterator for ElasticIntoIter<K, V, S, A> {}

impl<K, V, S, A: Allocator + Clone> Drop for ElasticIntoIter<K, V, S, A> {
    fn drop(&mut self) {
        // Drain remaining entries so each runs its Drop; map's Drop then
        // sees only tombstones.
        for _ in self.by_ref() {}
    }
}

impl<K, V, S, A: Allocator + Clone> fmt::Debug for ElasticIntoIter<K, V, S, A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ElasticIntoIter")
            .field("level_idx", &self.level_idx)
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

    fn into_iter(self) -> Self::IntoIter {
        ElasticIntoIter {
            map: self,
            level_idx: 0,
            cursor: OccupiedCursor::new(),
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
        level
            .table
            .write_with_control(slot_idx, SlotEntry { key, value }, key_fingerprint);
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
        let new_levels: Box<[Level<K, V, A>]> = level_capacities
            .iter()
            .enumerate()
            .map(|(level_idx, &cap)| {
                Level::with_capacity_in(cap, self.reserve_fraction, level_idx, self.alloc.clone())
            })
            .collect();
        let new_max_insertions = capacity::max_insertions(new_capacity, self.reserve_fraction);
        let new_batch_plan =
            build_batch_plan(&level_capacities, self.reserve_fraction, new_max_insertions);
        let new_batch_remaining = new_batch_plan.first().copied().unwrap_or(0);

        // Swap new levels in; old move local for draining.
        let old_levels = std::mem::replace(&mut self.levels, new_levels);
        self.capacity = new_capacity;
        self.max_insertions = new_max_insertions;
        self.batch_plan = new_batch_plan;
        self.current_batch_index = 0;
        self.batch_remaining = new_batch_remaining;
        self.max_populated_level = 0;
        self.len = 0;

        // `take` leaves ctrl stale; clear so Drop doesn't double-drop.
        for mut level in old_levels {
            level.table.for_each_occupied_mut(|table, idx| {
                let entry = unsafe { table.take(idx) };
                self.insert_unique(entry.key, entry.value);
            });
            level.table.clear_all_controls();
        }
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

        for level in &mut self.levels {
            level.table.for_each_occupied_mut(|table, idx| {
                let entry = unsafe { table.take(idx) };
                new_map.insert_unique(entry.key, entry.value);
            });
            level.table.clear_all_controls();
            level.len = 0;
            level.tombstones = 0;
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
        let capacity = slots;
        let reserve_fraction = capacity::sanitize_reserve_fraction(reserve_fraction);
        let max_insertions = capacity::max_insertions(capacity, reserve_fraction);

        let level_capacities = partition_levels(capacity);
        let mut levels: Vec<Level<K, V, A>> = Vec::new();
        levels
            .try_reserve_exact(level_capacities.len())
            .map_err(|_| TryReserveError::AllocError)?;
        for (level_idx, &cap) in level_capacities.iter().enumerate() {
            levels.push(Level::try_with_capacity_in(
                cap,
                reserve_fraction,
                level_idx,
                alloc.clone(),
            )?);
        }
        let levels = levels.into_boxed_slice();

        let batch_plan = build_batch_plan(&level_capacities, reserve_fraction, max_insertions);
        let batch_remaining = batch_plan.first().copied().unwrap_or(0);

        Ok(Self {
            levels,
            len: 0,
            capacity,
            max_insertions,
            reserve_fraction,
            batch_plan,
            current_batch_index: 0,
            batch_remaining,
            max_populated_level: 0,
            hash_builder,
            alloc,
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

        if current_free_slots > current_level.half_reserve_slot_threshold
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

        if current_free_slots <= current_level.half_reserve_slot_threshold {
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
        if level.len >= level.capacity() {
            return None;
        }

        let group_count = level.table.group_count();
        let max_groups = max_groups.min(group_count.max(1));
        let mask = level.group_count_mask;
        let mut probe = probe::TriangularProbe::new(level.triangular_group_start(key_hash));
        for _ in 0..max_groups {
            if let Some(slot_idx) = level.table.first_free_in_group(probe.pos) {
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
        if level.len >= level.capacity() {
            return None;
        }

        let group_count = level.table.group_count();
        let mask = level.group_count_mask;
        let mut probe = probe::TriangularProbe::new(level.triangular_group_start(key_hash));
        for _ in 0..group_count {
            if let Some(slot_idx) = level.table.first_free_in_group(probe.pos) {
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

/// Raw-pointer projection from `(level_idx, slot_idx)` to `*mut V`, without
/// forming an intermediate `&mut Level` / `&mut RawTable`. Used by
/// `get_disjoint_mut*` to hand out disjoint `&mut V` even when multiple keys
/// live in the same level.
///
/// # Safety
///
/// - `levels_ptr` must point to a live `[Level<K, V, A>]` whose `level_idx`
///   slot exists.
/// - `slot_idx` must reference an occupied slot in that level's table.
#[inline]
unsafe fn elastic_slot_value_ptr<K, V, A: Allocator + Clone>(
    levels_ptr: *mut Level<K, V, A>,
    level_idx: usize,
    slot_idx: usize,
) -> *mut V {
    let lvl_ptr = unsafe { levels_ptr.add(level_idx) };
    let table_ptr: *mut RawTable<SlotEntry<K, V>, A> = unsafe { &raw mut (*lvl_ptr).table };
    let entry_ptr: *mut SlotEntry<K, V> = unsafe { RawTable::slot_ptr_raw(table_ptr, slot_idx) };
    unsafe { &raw mut (*entry_ptr).value }
}

/// As [`elastic_slot_value_ptr`] but returns key + value pointers together.
#[inline]
unsafe fn elastic_slot_kv_ptrs<K, V, A: Allocator + Clone>(
    levels_ptr: *mut Level<K, V, A>,
    level_idx: usize,
    slot_idx: usize,
) -> (*const K, *mut V) {
    let lvl_ptr = unsafe { levels_ptr.add(level_idx) };
    let table_ptr: *mut RawTable<SlotEntry<K, V>, A> = unsafe { &raw mut (*lvl_ptr).table };
    let entry_ptr: *mut SlotEntry<K, V> = unsafe { RawTable::slot_ptr_raw(table_ptr, slot_idx) };
    let k_ptr: *const K = unsafe { &raw const (*entry_ptr).key };
    let v_ptr: *mut V = unsafe { &raw mut (*entry_ptr).value };
    (k_ptr, v_ptr)
}

/// O(N^2) alias check shared by `get_disjoint_mut` and
/// `get_disjoint_key_value_mut`. Panics if two `Some` locations collide.
#[inline]
fn check_disjoint_aliasing<const N: usize>(locations: &[Option<(usize, usize)>; N]) {
    for (i, li) in locations.iter().enumerate() {
        let Some(li) = li else { continue };
        for other in &locations[i + 1..] {
            assert!(
                other.as_ref() != Some(li),
                "get_disjoint_mut: duplicate keys resolve to the same entry",
            );
        }
    }
}

/// `min(1 + log δ⁻¹, group_count)` — paper §2 cap on `f(ε)` with `c = 1`.
#[allow(clippy::cast_precision_loss)]
fn compute_budget_cap(reserve_fraction: f64, group_count: usize) -> f64 {
    let log_cap = 1.0 + (1.0 / reserve_fraction).log2();
    let max_budget = group_count.max(1) as f64;
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
        Self {
            levels: self.levels.clone(),
            len: self.len,
            capacity: self.capacity,
            max_insertions: self.max_insertions,
            reserve_fraction: self.reserve_fraction,
            batch_plan: self.batch_plan.clone(),
            current_batch_index: self.current_batch_index,
            batch_remaining: self.batch_remaining,
            max_populated_level: self.max_populated_level,
            hash_builder: self.hash_builder.clone(),
            alloc: self.alloc.clone(),
        }
    }

    fn clone_from(&mut self, source: &Self) {
        // Fast path: reuse every per-level allocation when shapes match.
        let shape_matches = self.capacity == source.capacity
            && self
                .levels
                .iter()
                .zip(source.levels.iter())
                .all(|(a, b)| a.table.capacity() == b.table.capacity());
        if !shape_matches {
            *self = source.clone();
            return;
        }
        for (dst, src) in self.levels.iter_mut().zip(source.levels.iter()) {
            dst.clone_from(src);
        }
        self.len = source.len;
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

impl<K, Q, V, S, A> std::ops::Index<&Q> for ElasticHashMap<K, V, S, A>
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
