use std::borrow::Borrow;
use std::fmt;
use std::hash::{BuildHasher, Hash};
use std::iter::FusedIterator;
use std::marker::PhantomData;
use std::mem;
use std::ptr;

use allocator_api2::boxed::Box as ABox;
use allocator_api2::vec::Vec as AVec;

use crate::common::config::{DEFAULT_RESERVE_FRACTION, GROUP_SIZE, INITIAL_CAPACITY};
use crate::common::control::{CTRL_EMPTY, CTRL_TOMBSTONE, ControlByte, ControlOps};
use crate::common::entry::{EntryView, OccupiedError as CommonOccupiedError};
use crate::common::iter::{
    IntoKeys as CommonIntoKeys, IntoValues as CommonIntoValues, Keys as CommonKeys,
    OccupiedScanner, Values as CommonValues,
};
use crate::common::layout::{Entry as SlotEntry, RawTable};
use crate::common::math::{
    capacity_for, ceil_three_quarters, floor_half_reserve_slots, level_salt, max_insertions,
    round_up_to_pow2_groups, sanitize_reserve_fraction, usize_to_f64,
};
use crate::common::simd::ProbeOps;
use crate::common::{Allocator, DefaultHashBuilder, Global, TryReserveError};

const DEFAULT_PROBE_SCALE: f64 = 16.0;

/// Construction-time tuning for `ElasticHashMap`.
#[derive(Debug, Clone, Copy)]
pub struct ElasticOptions {
    /// Target initial capacity. The map sizes its level partition so
    /// `capacity * (1 - reserve_fraction)` inserts fit before the next resize.
    capacity: usize,
    /// Fraction of slots kept free as headroom. Lower means higher load
    /// factor but more probing on collisions.
    reserve_fraction: f64,
    /// Multiplier on per-level probe budgets. Higher means more thorough
    /// probing within a level before falling through to the next.
    probe_scale: f64,
}

impl Default for ElasticOptions {
    fn default() -> Self {
        Self {
            capacity: 0,
            reserve_fraction: DEFAULT_RESERVE_FRACTION,
            probe_scale: DEFAULT_PROBE_SCALE,
        }
    }
}

impl ElasticOptions {
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    #[must_use]
    pub fn reserve_fraction(mut self, reserve_fraction: f64) -> Self {
        self.reserve_fraction = reserve_fraction;
        self
    }

    #[must_use]
    pub fn probe_scale(mut self, probe_scale: f64) -> Self {
        self.probe_scale = probe_scale;
        self
    }
}

/// One level in elastic hashing's geometric partition: an independent
/// open-addressed table roughly half the previous level's capacity.
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
    /// Probe budget indexed by `free_slots()`.
    limited_probe_budgets: ABox<[usize], A>,
}

impl<K, V, A: Allocator + Clone> Level<K, V, A> {
    fn with_capacity_in(
        capacity: usize,
        reserve_fraction: f64,
        probe_scale: f64,
        level_idx: usize,
        alloc: A,
    ) -> Self {
        let table = RawTable::new_in(capacity, alloc.clone());
        let group_count = table.group_count();
        debug_assert!(
            group_count == 0 || group_count.is_power_of_two(),
            "partition_levels must produce pow2 group_count",
        );
        let limited_probe_budgets =
            build_probe_budgets_in(capacity, group_count, reserve_fraction, probe_scale, alloc);
        Self {
            table,
            len: 0,
            salt: level_salt(level_idx),
            group_count_mask: group_count.wrapping_sub(1),
            tombstones: 0,
            half_reserve_slot_threshold: floor_half_reserve_slots(reserve_fraction, capacity),
            limited_probe_budgets,
        }
    }

    /// Fallible counterpart to [`Level::with_capacity_in`].
    fn try_with_capacity_in(
        capacity: usize,
        reserve_fraction: f64,
        probe_scale: f64,
        level_idx: usize,
        alloc: A,
    ) -> Result<Self, TryReserveError> {
        let table = RawTable::try_new_in(capacity, alloc.clone())
            .map_err(|()| TryReserveError::AllocError)?;
        let group_count = table.group_count();
        let limited_probe_budgets = try_build_probe_budgets_in(
            capacity,
            group_count,
            reserve_fraction,
            probe_scale,
            alloc,
        )?;
        Ok(Self {
            table,
            len: 0,
            salt: level_salt(level_idx),
            group_count_mask: group_count.wrapping_sub(1),
            tombstones: 0,
            half_reserve_slot_threshold: floor_half_reserve_slots(reserve_fraction, capacity),
            limited_probe_budgets,
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

    /// Per-fill-level probe budget (tighter as the level fills).
    #[inline]
    fn limited_group_budget(&self) -> usize {
        self.limited_probe_budgets[self.free_slots()]
    }

    /// Triggers a no-grow rehash on remove when tombstones outnumber half
    /// the slots. Keeps probe sequences from degrading after delete-heavy
    /// workloads.
    #[inline]
    fn needs_cleanup(&self) -> bool {
        self.tombstones > self.capacity() / 2
    }
}

impl<K, V, A: Allocator + Clone> Drop for Level<K, V, A> {
    fn drop(&mut self) {
        for idx in 0..self.table.capacity() {
            if self.table.control_at(idx).is_occupied() {
                unsafe { self.table.drop_in_place(idx) };
            }
        }
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
    /// Geometrically shrinking partition of capacity.
    levels: Vec<Level<K, V, A>>,
    /// Total live entries.
    len: usize,
    /// Total slot count across all levels.
    capacity: usize,
    /// Insert count that triggers `resize(2x)`.
    max_insertions: usize,
    /// Slot reserve fraction per level. See `ElasticOptions`.
    reserve_fraction: f64,
    /// Probe-budget multiplier. See `ElasticOptions`.
    probe_scale: f64,
    /// Per-batch insert quota; drives `current_batch_index` advancement.
    batch_plan: Vec<usize>,
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
        Self::with_options(ElasticOptions::default())
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_options(ElasticOptions::with_capacity(capacity))
    }

    #[must_use]
    pub fn with_options(options: ElasticOptions) -> Self {
        Self::with_options_and_hasher_in(options, DefaultHashBuilder::default(), Global)
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
        Self::with_options_and_hasher_in(ElasticOptions::default(), hash_builder, Global)
    }

    #[must_use]
    pub fn with_capacity_and_hasher(capacity: usize, hash_builder: S) -> Self {
        Self::with_options_and_hasher_in(
            ElasticOptions::with_capacity(capacity),
            hash_builder,
            Global,
        )
    }

    #[must_use]
    pub fn with_options_and_hasher(options: ElasticOptions, hash_builder: S) -> Self {
        Self::with_options_and_hasher_in(options, hash_builder, Global)
    }
}

// Custom allocator + default hasher constructors.
impl<K, V, A> ElasticHashMap<K, V, DefaultHashBuilder, A>
where
    K: Eq + Hash,
    A: Allocator + Clone,
{
    #[must_use]
    pub fn new_in(alloc: A) -> Self {
        Self::with_options_and_hasher_in(
            ElasticOptions::default(),
            DefaultHashBuilder::default(),
            alloc,
        )
    }

    #[must_use]
    pub fn with_capacity_in(capacity: usize, alloc: A) -> Self {
        Self::with_options_and_hasher_in(
            ElasticOptions::with_capacity(capacity),
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
    #[must_use]
    pub fn with_hasher_in(hash_builder: S, alloc: A) -> Self {
        Self::with_options_and_hasher_in(ElasticOptions::default(), hash_builder, alloc)
    }

    #[must_use]
    pub fn with_capacity_and_hasher_in(capacity: usize, hash_builder: S, alloc: A) -> Self {
        Self::with_options_and_hasher_in(
            ElasticOptions::with_capacity(capacity),
            hash_builder,
            alloc,
        )
    }

    /// Full constructor. `resize` also calls this with the existing
    /// `hash_builder` and allocator so all keys keep the same hash sequence
    /// across grows.
    #[must_use]
    pub fn with_options_and_hasher_in(options: ElasticOptions, hash_builder: S, alloc: A) -> Self {
        let reserve_fraction = sanitize_reserve_fraction(options.reserve_fraction);
        let probe_scale = sanitize_probe_scale(options.probe_scale);
        let capacity = options.capacity;
        let max_insertions = max_insertions(capacity, reserve_fraction);

        let level_capacities = partition_levels(capacity);
        let levels = level_capacities
            .iter()
            .enumerate()
            .map(|(level_idx, &cap)| {
                Level::with_capacity_in(
                    cap,
                    reserve_fraction,
                    probe_scale,
                    level_idx,
                    alloc.clone(),
                )
            })
            .collect::<Vec<_>>();

        let batch_plan = build_batch_plan(&level_capacities, reserve_fraction, max_insertions);
        let batch_remaining = batch_plan.first().copied().unwrap_or(0);

        Self {
            levels,
            len: 0,
            capacity,
            max_insertions,
            reserve_fraction,
            probe_scale,
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

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
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
    /// `max_insertions(cap) >= min_capacity`.
    pub fn shrink_to(&mut self, min_capacity: usize) {
        if self.len == 0 && min_capacity == 0 {
            if self.capacity > 0 {
                self.resize(0);
            }
            return;
        }
        let lower = self.len.max(min_capacity).max(INITIAL_CAPACITY);
        let new_capacity = capacity_for(INITIAL_CAPACITY, lower, self.reserve_fraction)
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
        capacity_for(
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
        let key_fingerprint = ControlOps::control_fingerprint(key_hash);

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
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let key_hash = self.hash_key(key);
        let key_fingerprint = ControlOps::control_fingerprint(key_hash);
        let (level_idx, slot_idx) =
            self.find_slot_indices_with_hash(key, key_hash, key_fingerprint)?;
        Some(unsafe { &self.levels[level_idx].table.get_ref(slot_idx).value })
    }

    /// Like [`Self::get`] but returns the stored key alongside its value.
    pub fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let key_hash = self.hash_key(key);
        let key_fingerprint = ControlOps::control_fingerprint(key_hash);
        let (level_idx, slot_idx) =
            self.find_slot_indices_with_hash(key, key_hash, key_fingerprint)?;
        let entry = unsafe { self.levels[level_idx].table.get_ref(slot_idx) };
        Some((&entry.key, &entry.value))
    }

    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let key_hash = self.hash_key(key);
        let key_fingerprint = ControlOps::control_fingerprint(key_hash);
        let (level_idx, slot_idx) =
            self.find_slot_indices_with_hash(key, key_hash, key_fingerprint)?;
        Some(unsafe { &mut self.levels[level_idx].table.get_mut(slot_idx).value })
    }

    /// Returns `N` disjoint mutable references, mirroring
    /// [`std::collections::HashMap::get_disjoint_mut`]: `None` if any key
    /// misses, panic on aliasing.
    ///
    /// # Panics
    ///
    /// If two input keys resolve to the same `(level, slot)` pair.
    pub fn get_disjoint_mut<Q, const N: usize>(&mut self, keys: [&Q; N]) -> Option<[&mut V; N]>
    where
        K: Borrow<Q> + Eq,
        Q: Hash + Eq + ?Sized,
    {
        let mut locations: [(usize, usize); N] = [(0, 0); N];
        for (i, key) in keys.iter().enumerate() {
            let key_hash = self.hash_key(*key);
            let key_fingerprint = ControlOps::control_fingerprint(key_hash);
            locations[i] = self.find_slot_indices_with_hash(*key, key_hash, key_fingerprint)?;
        }

        // O(N^2) alias check; cheaper than a HashSet for the small N
        // (typically <= 16) std::get_disjoint_mut targets.
        for i in 0..N {
            for j in (i + 1)..N {
                assert!(
                    locations[i] != locations[j],
                    "get_disjoint_mut: duplicate keys resolve to the same entry",
                );
            }
        }

        // SAFETY: locations are unique (checked above). `elastic_slot_value_ptr`
        // projects to each value via raw pointers — no intermediate
        // `&mut Level` / `&mut RawTable` — so two keys hitting the same level
        // can't alias under Stacked Borrows.
        let levels_ptr: *mut Level<K, V, A> = self.levels.as_mut_ptr();
        let mut out: core::mem::MaybeUninit<[&mut V; N]> = core::mem::MaybeUninit::uninit();
        let out_ptr = out.as_mut_ptr().cast::<&mut V>();
        for (i, (level_idx, slot_idx)) in locations.into_iter().enumerate() {
            let value_ptr = unsafe { elastic_slot_value_ptr(levels_ptr, level_idx, slot_idx) };
            unsafe { out_ptr.add(i).write(&mut *value_ptr) };
        }
        Some(unsafe { out.assume_init() })
    }

    /// Unsafe variant of [`Self::get_disjoint_mut`] that skips the
    /// alias check. Mirrors [`std::collections::HashMap::get_disjoint_unchecked_mut`].
    ///
    /// # Safety
    ///
    /// All input keys must resolve to distinct entries; otherwise the
    /// returned references alias and behavior is undefined.
    pub unsafe fn get_disjoint_unchecked_mut<Q, const N: usize>(
        &mut self,
        keys: [&Q; N],
    ) -> Option<[&mut V; N]>
    where
        K: Borrow<Q> + Eq,
        Q: Hash + Eq + ?Sized,
    {
        let mut locations: [(usize, usize); N] = [(0, 0); N];
        for (i, key) in keys.iter().enumerate() {
            let key_hash = self.hash_key(*key);
            let key_fingerprint = ControlOps::control_fingerprint(key_hash);
            locations[i] = self.find_slot_indices_with_hash(*key, key_hash, key_fingerprint)?;
        }

        // SAFETY: caller guarantees distinct locations; same raw-pointer
        // chain as the checked variant.
        let levels_ptr: *mut Level<K, V, A> = self.levels.as_mut_ptr();
        let mut out: core::mem::MaybeUninit<[&mut V; N]> = core::mem::MaybeUninit::uninit();
        let out_ptr = out.as_mut_ptr().cast::<&mut V>();
        for (i, (level_idx, slot_idx)) in locations.into_iter().enumerate() {
            let value_ptr = unsafe { elastic_slot_value_ptr(levels_ptr, level_idx, slot_idx) };
            unsafe { out_ptr.add(i).write(&mut *value_ptr) };
        }
        Some(unsafe { out.assume_init() })
    }

    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let key_hash = self.hash_key(key);
        let key_fingerprint = ControlOps::control_fingerprint(key_hash);
        self.find_slot_indices_with_hash(key, key_hash, key_fingerprint)
            .is_some()
    }

    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.remove_inner(key).map(|(_, v)| v)
    }

    /// Like [`Self::remove`] but returns the stored key alongside its value.
    pub fn remove_entry<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.remove_inner(key)
    }

    fn remove_inner<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let key_hash = self.hash_key(key);
        let key_fingerprint = ControlOps::control_fingerprint(key_hash);
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
            levels: &self.levels,
            level_idx: 0,
            scanner: OccupiedScanner::new(),
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
        ElasticIterMut {
            levels,
            levels_len,
            level_idx: 0,
            scanner: OccupiedScanner::new(),
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
        let key_fingerprint = ControlOps::control_fingerprint(key_hash);
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
        let key_fingerprint = ControlOps::control_fingerprint(key_hash);

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
            scanner: OccupiedScanner::new(),
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
            scanner: OccupiedScanner::new(),
        }
    }

    /// Walk every level and rehash if any crossed the cleanup threshold while
    /// resize was suppressed. Called once from each bulk-op iterator's `Drop`.
    fn resize_if_needed(&mut self) {
        if self.levels.iter().any(Level::needs_cleanup) {
            self.resize(self.capacity);
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
    scanner: OccupiedScanner,
}

impl<K: fmt::Debug, V: fmt::Debug, S, A: Allocator + Clone> fmt::Debug for Drain<'_, K, V, S, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Drain").finish_non_exhaustive()
    }
}

impl<K, V, S, A: Allocator + Clone> Iterator for Drain<'_, K, V, S, A> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        // Per-yield ctrl byte update is skipped: Drain::drop wipes all ctrls
        // via `clear_all_controls` regardless, and the scanner only advances
        // forward so yielded slots are never re-read.
        while self.level_idx < self.map.levels.len() {
            let level = &mut self.map.levels[self.level_idx];
            if let Some(idx) = self.scanner.next_in(&level.table) {
                let entry = unsafe { level.table.take(idx) };
                self.map.len -= 1;
                return Some((entry.key, entry.value));
            }
            self.level_idx += 1;
            self.scanner.reset();
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
    scanner: OccupiedScanner,
}

impl<K, V, F, S, A: Allocator + Clone> fmt::Debug for ExtractIf<'_, K, V, F, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    F: FnMut(&K, &mut V) -> bool,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
            while let Some(idx) = self.scanner.next_in(&level.table) {
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
            self.scanner.reset();
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
        // Dropping `extract_if` early leaves unvisited entries in the map.
        // Only consolidate any tombstone backlog from already-removed entries.
        self.map.resize_if_needed();
    }
}

/// Borrowing iterator over occupied entries. Walks levels in order via
/// [`OccupiedScanner`]; skips FREE and TOMBSTONE.
#[derive(Clone)]
pub struct ElasticIter<'a, K, V, A: Allocator + Clone = Global> {
    levels: &'a [Level<K, V, A>],
    level_idx: usize,
    scanner: OccupiedScanner,
}

impl<K, V, A: Allocator + Clone> fmt::Debug for ElasticIter<'_, K, V, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ElasticIter")
            .field("level_idx", &self.level_idx)
            .finish_non_exhaustive()
    }
}

impl<'a, K, V, A: Allocator + Clone> Iterator for ElasticIter<'a, K, V, A> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        while self.level_idx < self.levels.len() {
            let table = &self.levels[self.level_idx].table;
            if let Some(slot_idx) = self.scanner.next_in(table) {
                let entry = unsafe { table.get_ref(slot_idx) };
                return Some((&entry.key, &entry.value));
            }
            self.level_idx += 1;
            self.scanner.reset();
        }
        None
    }
}

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
    scanner: OccupiedScanner,
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
            if let Some(idx) = self.scanner.next_in(&level.table) {
                // SAFETY: scanner only yields occupied slots; reborrow through
                // raw ptr so refs outlive the per-iter `level` reborrow.
                let entry = unsafe { level.table.get_mut(idx) };
                let key: &'a K = unsafe { &*ptr::from_ref(&entry.key) };
                let val: &'a mut V = unsafe { &mut *ptr::from_mut(&mut entry.value) };
                return Some((key, val));
            }
            self.level_idx += 1;
            self.scanner.reset();
        }
        None
    }
}

impl<K, V, A: Allocator + Clone> fmt::Debug for ElasticIterMut<'_, K, V, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
}

impl<K, V, A: Allocator + Clone> fmt::Debug for ElasticValuesMut<'_, K, V, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ElasticValuesMut")
            .field("level_idx", &self.inner.level_idx)
            .finish_non_exhaustive()
    }
}

/// Consuming `(K, V)` iterator returned by `ElasticHashMap::into_iter`.
pub struct ElasticIntoIter<K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    map: ElasticHashMap<K, V, S, A>,
    level_idx: usize,
    scanner: OccupiedScanner,
}

impl<K, V, S, A: Allocator + Clone> Iterator for ElasticIntoIter<K, V, S, A> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        while self.level_idx < self.map.levels.len() {
            let table = &mut self.map.levels[self.level_idx].table;
            if let Some(idx) = self.scanner.next_in(table) {
                // SAFETY: scanner only yields occupied slots. Tombstone-mark
                // prevents map's Drop and future next() from revisiting.
                let entry = unsafe { table.take(idx) };
                table.mark_tombstone(idx);
                return Some((entry.key, entry.value));
            }
            self.level_idx += 1;
            self.scanner.reset();
        }
        None
    }
}

impl<K, V, S, A: Allocator + Clone> FusedIterator for ElasticIntoIter<K, V, S, A> {}

impl<K, V, S, A: Allocator + Clone> Drop for ElasticIntoIter<K, V, S, A> {
    fn drop(&mut self) {
        // Drain remaining entries so each runs its Drop; map's Drop then
        // sees only tombstones.
        for _ in self.by_ref() {}
    }
}

impl<K, V, S, A: Allocator + Clone> fmt::Debug for ElasticIntoIter<K, V, S, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
            scanner: OccupiedScanner::new(),
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
    /// Drain all live entries into a temp Vec, rebuild levels at
    /// `new_capacity` in-place, reinsert. Passing the current capacity
    /// performs a no-grow rehash that flushes accumulated tombstones.
    fn resize(&mut self, new_capacity: usize) {
        let mut entries = Vec::with_capacity(self.len);
        for level in &mut self.levels {
            for idx in 0..level.table.capacity() {
                if level.table.control_at(idx).is_occupied() {
                    let entry = unsafe { level.table.take(idx) };
                    entries.push((entry.key, entry.value));
                }
            }
            level.table.clear_all_controls();
            level.len = 0;
            level.tombstones = 0;
        }

        let level_capacities = partition_levels(new_capacity);
        let new_levels = level_capacities
            .iter()
            .enumerate()
            .map(|(level_idx, &cap)| {
                Level::with_capacity_in(
                    cap,
                    self.reserve_fraction,
                    self.probe_scale,
                    level_idx,
                    self.alloc.clone(),
                )
            })
            .collect::<Vec<_>>();
        let new_max_insertions = max_insertions(new_capacity, self.reserve_fraction);
        let new_batch_plan =
            build_batch_plan(&level_capacities, self.reserve_fraction, new_max_insertions);
        let new_batch_remaining = new_batch_plan.first().copied().unwrap_or(0);

        self.levels = new_levels;
        self.capacity = new_capacity;
        self.max_insertions = new_max_insertions;
        self.batch_plan = new_batch_plan;
        self.current_batch_index = 0;
        self.batch_remaining = new_batch_remaining;
        self.max_populated_level = 0;
        self.len = 0;

        for (key, value) in entries {
            self.insert(key, value);
        }
    }

    /// Fallible counterpart to [`Self::resize`]. Allocates the new backing
    /// storage before touching `self`, so `Err` leaves the map intact.
    fn try_resize(&mut self, new_capacity: usize) -> Result<(), TryReserveError>
    where
        S: Clone,
    {
        let hash_builder = self.hash_builder.clone();
        let mut new_map = Self::try_with_options_and_hasher_in(
            ElasticOptions {
                capacity: new_capacity,
                reserve_fraction: self.reserve_fraction,
                probe_scale: self.probe_scale,
            },
            hash_builder,
            self.alloc.clone(),
        )?;

        for level in &mut self.levels {
            for idx in 0..level.table.capacity() {
                if level.table.control_at(idx).is_occupied() {
                    let entry = unsafe { level.table.take(idx) };
                    new_map.insert(entry.key, entry.value);
                }
            }
            level.table.clear_all_controls();
            level.len = 0;
            level.tombstones = 0;
        }

        self.len = 0;
        self.max_populated_level = 0;
        *self = new_map;
        Ok(())
    }

    /// Fallible counterpart to [`Self::with_options_and_hasher_in`]. Returns
    /// `Err(TryReserveError::AllocError)` if any backing allocation fails.
    fn try_with_options_and_hasher_in(
        options: ElasticOptions,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryReserveError> {
        let reserve_fraction = sanitize_reserve_fraction(options.reserve_fraction);
        let probe_scale = sanitize_probe_scale(options.probe_scale);
        let capacity = options.capacity;
        let max_insertions = max_insertions(capacity, reserve_fraction);

        let level_capacities = partition_levels(capacity);
        let mut levels: Vec<Level<K, V, A>> = Vec::new();
        levels
            .try_reserve_exact(level_capacities.len())
            .map_err(|_| TryReserveError::AllocError)?;
        for (level_idx, &cap) in level_capacities.iter().enumerate() {
            levels.push(Level::try_with_capacity_in(
                cap,
                reserve_fraction,
                probe_scale,
                level_idx,
                alloc.clone(),
            )?);
        }

        let batch_plan = build_batch_plan(&level_capacities, reserve_fraction, max_insertions);
        let batch_remaining = batch_plan.first().copied().unwrap_or(0);

        Ok(Self {
            levels,
            len: 0,
            capacity,
            max_insertions,
            reserve_fraction,
            probe_scale,
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

    /// Pick the (level, slot) pair to write a new key into. Tries the
    /// batch-targeted level pair first (`choose_slot_targeted`); falls back
    /// to a full sweep across all levels when the targeted slot is full
    /// (e.g. tombstones in earlier levels are the only reusable slots).
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

    /// Batch-driven slot selection. Reads `current_batch_index` to pick the
    /// level pair `(li, li+1)`, then steers between them based on
    /// `current_free_slots > half_reserve_threshold` and `next_free_slots`
    /// thresholds. Per the elastic-hashing schedule, this is what keeps
    /// expected probe count low at high load.
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

    /// Locate `key` across all populated levels. Returns `(level, slot)` on
    /// hit. Bounded by `max_populated_level + 1` so empty trailing levels
    /// don't get probed.
    #[inline]
    fn find_slot_indices_with_hash<Q>(
        &self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
    ) -> Option<(usize, usize)>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        let search_limit = (self.max_populated_level + 1).min(self.levels.len());
        for (level_idx, level) in self.levels[..search_limit].iter().enumerate() {
            if let Some(slot_idx) =
                Self::find_in_level_by_probe(key_hash, key_fingerprint, key, level)
            {
                return Some((level_idx, slot_idx));
            }
        }
        None
    }

    /// Probe one level for `key`. Walks groups via the level's intra-level
    /// probe sequence (triangular for power-of-2 group counts, double-hash
    /// step otherwise), SIMD-matches the fingerprint byte, then key-compares
    /// only the matched slots. Stops on FREE byte (group has space) when no
    /// tombstones exist.
    #[inline]
    fn find_in_level_by_probe<Q>(
        key_hash: u64,
        key_fingerprint: u8,
        key: &Q,
        level: &Level<K, V, A>,
    ) -> Option<usize>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        if level.len == 0 {
            return None;
        }

        let group_count = level.table.group_count();
        let mask = level.group_count_mask;
        let mut group_idx = Self::triangular_group_start(level, key_hash);
        let mut delta: usize = 0;

        for _ in 0..group_count {
            // Warm the slot region for this group while the SIMD scan runs.
            // SAFETY: `level.len > 0` guarded above ⇒ `capacity > 0`;
            // `group_idx < group_count` ⇒ `group_idx * GROUP_SIZE < capacity`.
            unsafe { level.table.prefetch_slot(group_idx * GROUP_SIZE) };
            let match_mask = level.table.group_match_mask(group_idx, key_fingerprint);
            for relative_idx in match_mask {
                let slot_idx = group_idx * GROUP_SIZE + relative_idx;
                let entry = unsafe { level.table.get_ref(slot_idx) };
                if entry.key.borrow() == key {
                    return Some(slot_idx);
                }
            }
            if level.table.group_match_mask(group_idx, CTRL_EMPTY).any() {
                return None;
            }
            delta += 1;
            group_idx = (group_idx + delta) & mask;
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
        let mut group_idx = Self::triangular_group_start(level, key_hash);
        let mut delta: usize = 0;
        for _ in 0..max_groups {
            if let Some(slot_idx) = level.table.first_free_in_group(group_idx) {
                return Some(slot_idx);
            }
            delta += 1;
            group_idx = (group_idx + delta) & mask;
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
        let mut group_idx = Self::triangular_group_start(level, key_hash);
        let mut delta: usize = 0;
        for _ in 0..group_count {
            if let Some(slot_idx) = level.table.first_free_in_group(group_idx) {
                return Some(slot_idx);
            }
            delta += 1;
            group_idx = (group_idx + delta) & mask;
        }
        None
    }

    /// Triangular-probing starting group: `(key_hash ^ salt) & (group_count - 1)`.
    /// `group_count` is pow2 by `partition_levels` construction.
    #[inline]
    fn triangular_group_start(level: &Level<K, V, A>, key_hash: u64) -> usize {
        let mixed = key_hash ^ level.salt;
        ProbeOps::hash_to_usize(mixed) & level.group_count_mask
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

fn sanitize_probe_scale(probe_scale: f64) -> f64 {
    if probe_scale.is_finite() && probe_scale > 0.0 {
        probe_scale
    } else {
        DEFAULT_PROBE_SCALE
    }
}

/// Fallible counterpart to [`build_probe_budgets_in`]. Returns
/// `Err(TryReserveError::AllocError)` on allocation failure.
fn try_build_probe_budgets_in<A: Allocator>(
    capacity: usize,
    group_count: usize,
    reserve_fraction: f64,
    probe_scale: f64,
    alloc: A,
) -> Result<ABox<[usize], A>, TryReserveError> {
    let mut budgets: AVec<usize, A> = AVec::new_in(alloc);
    budgets
        .try_reserve_exact(capacity.saturating_add(1))
        .map_err(|_| TryReserveError::AllocError)?;
    budgets.resize(capacity.saturating_add(1), 1);
    if capacity == 0 {
        return Ok(budgets.into_boxed_slice());
    }
    fill_probe_budgets(
        &mut budgets,
        capacity,
        group_count,
        reserve_fraction,
        probe_scale,
    );
    Ok(budgets.into_boxed_slice())
}

fn build_probe_budgets_in<A: Allocator>(
    capacity: usize,
    group_count: usize,
    reserve_fraction: f64,
    probe_scale: f64,
    alloc: A,
) -> ABox<[usize], A> {
    let mut budgets: AVec<usize, A> = AVec::new_in(alloc);
    budgets.resize(capacity.saturating_add(1), 1);
    if capacity == 0 {
        return budgets.into_boxed_slice();
    }
    fill_probe_budgets(
        &mut budgets,
        capacity,
        group_count,
        reserve_fraction,
        probe_scale,
    );
    budgets.into_boxed_slice()
}

#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn fill_probe_budgets(
    budgets: &mut [usize],
    capacity: usize,
    group_count: usize,
    reserve_fraction: f64,
    probe_scale: f64,
) {
    let max_budget = group_count.max(1);
    let cap_f = usize_to_f64(capacity);
    let log_cap = (1.0 / reserve_fraction).log2();

    // Budget(fs) is a non-increasing staircase function of free_slots.
    // Instead of computing log2/ceil per slot, find the threshold free_slots
    // where each budget level transitions, then fill segments.
    //
    // Budget >= b when: fs < capacity / 2^sqrt((b-1)*GROUP_SIZE / probe_scale)
    let mut thresholds: Vec<(usize, usize)> = Vec::new();
    for b in 2..=max_budget {
        let ratio = ((b - 1) * GROUP_SIZE) as f64 / probe_scale;
        if ratio >= log_cap {
            break;
        }
        let exact = cap_f / f64::exp2(ratio.sqrt());
        let threshold = (exact.ceil() as usize).saturating_sub(1).min(capacity);
        if threshold == 0 {
            break;
        }
        thresholds.push((b, threshold));
    }

    // Fill from highest budget inward (thresholds decrease with increasing b).
    let mut prev_end = 0;
    for &(b, threshold) in thresholds.iter().rev() {
        if threshold > prev_end {
            budgets[(prev_end + 1)..=threshold].fill(b);
            prev_end = threshold;
        }
    }
}

/// Split `total_capacity` into geometrically halving level sizes, then round
/// each up so `group_count = size / GROUP_SIZE` is pow2 — required for the
/// triangular probe path's `(idx + delta) & mask` wrap. Total slots may
/// exceed `total_capacity` by up to ~2x. Returns `[]` for capacity 0.
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

    sizes.into_iter().map(round_up_to_pow2_groups).collect()
}

/// Build the per-batch insertion quota that drives `current_batch_index`.
/// Batch 0 fills level 0 to ~3/4 occupancy. Each subsequent batch tops up
/// the previous level toward its reserve threshold while priming the next
/// level. Total quota equals `max_insertions`.
fn build_batch_plan(
    level_capacities: &[usize],
    reserve_fraction: f64,
    max_insertions: usize,
) -> Vec<usize> {
    if level_capacities.is_empty() || max_insertions == 0 {
        return Vec::new();
    }

    let mut plan = Vec::with_capacity(level_capacities.len() + 1);
    plan.push(ceil_three_quarters(level_capacities[0]));

    for level_index in 1..level_capacities.len() {
        let current_level_capacity = level_capacities[level_index - 1];
        let next_level_capacity = level_capacities[level_index];

        let target_current_level_occupancy = current_level_capacity.saturating_sub(
            floor_half_reserve_slots(reserve_fraction, current_level_capacity),
        );
        let initial_current_level_occupancy = ceil_three_quarters(current_level_capacity);
        let initial_next_level_occupancy = ceil_three_quarters(next_level_capacity);

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

    plan
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
    fn insert_get_and_update_work() {
        let mut map = ElasticHashMap::with_capacity(64);

        for key in 0..20 {
            assert_eq!(map.insert(key, key * 10), None);
        }
        for key in 0..20 {
            assert_eq!(map.get(&key), Some(&(key * 10)));
        }

        let replaced = map.insert(7, 777).expect("update should succeed");
        assert_eq!(replaced, 70);
        assert_eq!(map.get(&7), Some(&777));
    }

    #[test]
    fn get_mut_and_contains_key_work() {
        let mut map = ElasticHashMap::new();
        assert_eq!(map.insert("alpha", 1), None);
        assert!(map.contains_key("alpha"));

        if let Some(v) = map.get_mut("alpha") {
            *v = 2;
        }
        assert_eq!(map.get("alpha"), Some(&2));
    }

    #[test]
    fn remove_supports_borrowed_key_and_updates_len() {
        let mut map: ElasticHashMap<String, i32> = ElasticHashMap::new();
        assert_eq!(map.insert("alpha".to_string(), 1), None);
        assert_eq!(map.insert("beta".to_string(), 2), None);

        assert_eq!(map.remove("alpha"), Some(1));
        assert_eq!(map.remove("alpha"), None);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("beta"), Some(&2));
    }

    #[test]
    fn clear_removes_all_entries_and_resets_map() {
        let mut map = ElasticHashMap::with_capacity(64);
        for key in 0..10 {
            assert_eq!(map.insert(key, key * 10), None);
        }

        map.clear();
        assert!(map.is_empty());
        for key in 0..10 {
            assert_eq!(map.get(&key), None);
        }

        assert_eq!(map.insert(99, 990), None);
        assert_eq!(map.get(&99), Some(&990));
    }

    #[test]
    fn new_starts_with_zero_capacity() {
        let map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        assert_eq!(map.capacity(), 0);
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn insert_resizes_when_threshold_is_reached() {
        let capacity = 40;
        let mut map = ElasticHashMap::with_capacity(capacity);
        let max_insertions = max_insertions(capacity, DEFAULT_RESERVE_FRACTION);

        for key in 0..max_insertions + 10 {
            assert_eq!(map.insert(key, key), None);
        }

        for key in 0..max_insertions + 10 {
            assert_eq!(map.get(&key), Some(&key));
        }

        assert!(map.capacity() > capacity);
    }

    #[test]
    fn insert_resizes_from_zero_capacity() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        map.insert(1, 10);
        assert_eq!(map.get(&1), Some(&10));
        assert!(map.capacity() > 0);
    }

    #[test]
    fn options_constructor_preserves_capacity() {
        let map: ElasticHashMap<i32, i32> = ElasticHashMap::with_options(ElasticOptions {
            capacity: 96,
            reserve_fraction: DEFAULT_RESERVE_FRACTION,
            probe_scale: 8.0,
        });
        assert_eq!(map.capacity(), 96);
    }

    #[test]
    fn delete_heavy_preserves_correctness() {
        let n = 10_000;
        let cutoff = (n * 4) / 5;
        for trial in 0..50 {
            let mut map = ElasticHashMap::new();
            for i in 0..n {
                map.insert(i, i * 10);
            }
            // Delete the first 80% of keys.
            for i in 0..cutoff {
                assert_eq!(
                    map.remove(&i),
                    Some(i * 10),
                    "trial {trial}: missing key {i} during delete"
                );
            }
            // Lookup remaining keys (post-tombstone state).
            for i in cutoff..n {
                assert_eq!(
                    map.get(&i),
                    Some(&(i * 10)),
                    "trial {trial}: key {i} missing after deletes"
                );
            }
            assert_eq!(map.len(), (n - cutoff) as usize);
            // Re-insert into tombstone-heavy map.
            for i in n..(n + n / 5) {
                assert_eq!(map.insert(i, i), None);
            }
            for i in n..(n + n / 5) {
                assert_eq!(
                    map.get(&i),
                    Some(&i),
                    "trial {trial}: key {i} missing after re-insert"
                );
            }
        }
    }

    #[test]
    fn large_map_correctness() {
        let n = 10_000;
        let mut map = ElasticHashMap::with_capacity(n * 2);
        for i in 0..n {
            assert_eq!(map.insert(i, i), None);
        }
        for i in 0..n {
            assert_eq!(map.get(&i), Some(&i), "key {i} missing");
        }
        assert_eq!(map.len(), n);
    }

    #[test]
    fn partial_group_capacity_works() {
        // Capacity 18 creates a partial last group (2 valid slots out of 16).
        let mut map = ElasticHashMap::with_capacity(18);
        for i in 0..15 {
            assert_eq!(map.insert(i, i), None);
        }
        for i in 0..15 {
            assert_eq!(map.get(&i), Some(&i));
        }
    }

    #[test]
    fn iter_yields_every_inserted_pair_once() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(64);
        for i in 0..50 {
            map.insert(i, i * 10);
        }
        let mut collected: Vec<(i32, i32)> = map.iter().map(|(&k, &v)| (k, v)).collect();
        collected.sort();
        let expected: Vec<(i32, i32)> = (0..50).map(|i| (i, i * 10)).collect();
        assert_eq!(collected, expected);
    }

    #[test]
    fn iter_skips_tombstones_after_remove() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(32);
        for i in 0..20 {
            map.insert(i, i);
        }
        for i in (0..20).step_by(2) {
            map.remove(&i);
        }
        let keys: Vec<i32> = map.iter().map(|(&k, _)| k).collect();
        assert_eq!(keys.len(), 10);
        let mut sorted = keys;
        sorted.sort();
        assert_eq!(sorted, (1..20).step_by(2).collect::<Vec<_>>());
    }

    #[test]
    fn iter_empty_map_is_empty() {
        let map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        assert_eq!(map.iter().count(), 0);
    }

    #[test]
    fn get_disjoint_mut_returns_all_refs_on_hits() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(64);
        for i in 0..16 {
            map.insert(i, i * 10);
        }

        let got = map.get_disjoint_mut([&1, &3, &7, &15]).expect("all hits");
        assert_eq!(*got[0], 10);
        assert_eq!(*got[1], 30);
        assert_eq!(*got[2], 70);
        assert_eq!(*got[3], 150);
    }

    #[test]
    fn get_disjoint_mut_returns_none_if_any_missing() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(32);
        for i in 0..8 {
            map.insert(i, i);
        }

        assert!(map.get_disjoint_mut([&0, &1, &99]).is_none());
    }

    #[test]
    #[should_panic(expected = "duplicate keys")]
    fn get_disjoint_mut_panics_on_duplicate_keys() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(32);
        map.insert(1, 100);
        map.insert(2, 200);
        let _ = map.get_disjoint_mut([&1, &1]);
    }

    #[test]
    fn get_disjoint_unchecked_mut_returns_all_refs_on_hits() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(64);
        for i in 0..16 {
            map.insert(i, i * 10);
        }

        // SAFETY: keys are distinct.
        let got = unsafe { map.get_disjoint_unchecked_mut([&1, &3, &7, &15]) }.expect("all hits");
        assert_eq!(*got[0], 10);
        assert_eq!(*got[1], 30);
        assert_eq!(*got[2], 70);
        assert_eq!(*got[3], 150);
    }

    #[test]
    fn get_disjoint_unchecked_mut_returns_none_if_any_missing() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(32);
        for i in 0..8 {
            map.insert(i, i);
        }

        // SAFETY: keys are distinct (and one misses, returning None).
        assert!(unsafe { map.get_disjoint_unchecked_mut([&0, &1, &99]) }.is_none());
    }

    #[test]
    fn get_disjoint_mut_zero_keys_is_some_empty() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(16);
        map.insert(1, 1);
        let got: [&mut i32; 0] = map
            .get_disjoint_mut::<i32, 0>([])
            .expect("zero-key returns Some");
        assert_eq!(got.len(), 0);
    }

    #[test]
    fn get_disjoint_mut_mutation_propagates() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(32);
        for i in 0..8 {
            map.insert(i, i);
        }
        {
            let got = map.get_disjoint_mut([&2, &5]).expect("hit");
            *got[0] = 222;
            *got[1] = 555;
        }
        assert_eq!(map.get(&2), Some(&222));
        assert_eq!(map.get(&5), Some(&555));
    }

    #[test]
    fn keys_yields_inserted_keys_only() {
        use std::collections::HashSet;
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(64);
        for i in 0..30 {
            map.insert(i, i * 10);
        }
        let got: HashSet<i32> = map.keys().copied().collect();
        let expected: HashSet<i32> = (0..30).collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn values_yields_inserted_values_only() {
        use std::collections::HashSet;
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(64);
        for i in 0..30 {
            map.insert(i, i * 10);
        }
        let got: HashSet<i32> = map.values().copied().collect();
        let expected: HashSet<i32> = (0..30).map(|i| i * 10).collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn hasher_returns_consistent_handle() {
        let map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        let a: *const _ = map.hasher();
        let b: *const _ = map.hasher();
        assert!(std::ptr::eq(a, b));
    }

    #[test]
    fn get_key_value_returns_both_on_hit_none_on_miss() {
        let mut map: ElasticHashMap<String, i32> = ElasticHashMap::with_capacity(16);
        map.insert("alpha".to_string(), 1);
        map.insert("beta".to_string(), 2);

        let (k, v) = map.get_key_value("alpha").expect("hit");
        assert_eq!(k, "alpha");
        assert_eq!(*v, 1);

        assert!(map.get_key_value("missing").is_none());
    }

    #[test]
    fn remove_entry_returns_both_and_actually_removes() {
        let mut map: ElasticHashMap<String, i32> = ElasticHashMap::with_capacity(16);
        map.insert("alpha".to_string(), 1);
        map.insert("beta".to_string(), 2);

        let (k, v) = map.remove_entry("alpha").expect("hit");
        assert_eq!(k, "alpha");
        assert_eq!(v, 1);
        assert_eq!(map.len(), 1);
        assert!(map.get("alpha").is_none());

        assert!(map.remove_entry("alpha").is_none());
    }

    #[test]
    fn try_reserve_grows_when_needed() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        assert_eq!(map.capacity(), 0);
        map.try_reserve(1024).expect("alloc should succeed");
        let cap = map.capacity();
        assert!(cap >= 1024, "reserve under-allocated: cap={cap}");
        for i in 0..1024 {
            map.insert(i, i * 2);
        }
        for i in 0..1024 {
            assert_eq!(map.get(&i), Some(&(i * 2)));
        }
        assert_eq!(map.len(), 1024);
    }

    #[test]
    fn try_reserve_zero_additional_is_noop() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(64);
        let cap_before = map.capacity();
        map.try_reserve(0).expect("noop");
        assert_eq!(map.capacity(), cap_before);
    }

    #[test]
    fn try_reserve_overflow_returns_error() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        map.insert(1, 1);
        assert_eq!(
            map.try_reserve(usize::MAX),
            Err(TryReserveError::CapacityOverflow)
        );
    }

    #[test]
    fn shrink_to_below_len_clamps_to_len() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(2048);
        for i in 0..100 {
            map.insert(i, i);
        }
        let cap_before = map.capacity();
        map.shrink_to(0);
        let cap_after = map.capacity();
        // Capacity dropped but all entries still queryable.
        assert!(cap_after < cap_before);
        assert!(cap_after >= map.len());
        for i in 0..100 {
            assert_eq!(map.get(&i), Some(&i));
        }
    }

    #[test]
    fn shrink_to_above_capacity_is_noop() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(64);
        for i in 0..10 {
            map.insert(i, i);
        }
        let cap = map.capacity();
        map.shrink_to(cap * 4);
        assert_eq!(map.capacity(), cap);
    }

    #[test]
    fn shrink_to_fit_reduces_capacity_when_sparse() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(2048);
        for i in 0..1000 {
            map.insert(i, i);
        }
        for i in 0..900 {
            map.remove(&i);
        }
        let cap_before = map.capacity();
        map.shrink_to_fit();
        assert!(map.capacity() < cap_before);
        for i in 900..1000 {
            assert_eq!(map.get(&i), Some(&i));
        }
    }

    #[test]
    fn iter_mut_yields_each_entry_exactly_once() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(64);
        for i in 0..50 {
            map.insert(i, i * 3);
        }
        let mut collected: Vec<(i32, i32)> = map.iter_mut().map(|(&k, v)| (k, *v)).collect();
        collected.sort_unstable();
        let expected: Vec<(i32, i32)> = (0..50).map(|i| (i, i * 3)).collect();
        assert_eq!(collected, expected);
    }

    #[test]
    fn iter_mut_skips_tombstones() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(32);
        for i in 0..20 {
            map.insert(i, i);
        }
        for i in (0..20).step_by(2) {
            map.remove(&i);
        }
        let count = map.iter_mut().count();
        assert_eq!(count, 10);
    }

    #[test]
    fn iter_mut_empty_map_is_empty() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        assert_eq!(map.iter_mut().count(), 0);
    }

    #[test]
    fn values_mut_mutates_in_place() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(32);
        for i in 0..16 {
            map.insert(i, i);
        }
        for v in map.values_mut() {
            *v += 100;
        }
        for i in 0..16 {
            assert_eq!(map.get(&i), Some(&(i + 100)));
        }
    }

    #[test]
    fn retain_with_empty_map_is_noop() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        let mut called = false;
        map.retain(|_, _| {
            called = true;
            true
        });
        assert!(!called);
        assert!(map.is_empty());
    }

    #[test]
    fn retain_can_mutate_values_in_place() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(64);
        for i in 0..20 {
            map.insert(i, i);
        }
        map.retain(|k, v| {
            *v += 100;
            k % 2 == 0
        });
        assert_eq!(map.len(), 10);
        for i in (0..20).step_by(2) {
            // Mutations only stick on surviving entries — the extracted ones
            // never make it back into the map.
            assert_eq!(map.get(&i), Some(&(i + 100)));
        }
    }

    #[test]
    fn into_iter_yields_all_entries() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(64);
        for i in 0..30 {
            map.insert(i, i * 11);
        }
        let mut collected: Vec<(i32, i32)> = map.into_iter().collect();
        collected.sort_unstable();
        let expected: Vec<(i32, i32)> = (0..30).map(|i| (i, i * 11)).collect();
        assert_eq!(collected, expected);
    }

    #[test]
    fn into_iter_skips_tombstones() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(64);
        for i in 0..40 {
            map.insert(i, i);
        }
        for i in (0..40).step_by(3) {
            map.remove(&i);
        }
        let expected_len = map.len();
        let collected: Vec<(i32, i32)> = map.into_iter().collect();
        assert_eq!(collected.len(), expected_len);
    }

    #[test]
    fn into_keys_yields_all_keys() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(64);
        for i in 0..20 {
            map.insert(i, i);
        }
        let mut keys: Vec<i32> = map.into_keys().collect();
        keys.sort_unstable();
        assert_eq!(keys, (0..20).collect::<Vec<_>>());
    }

    #[test]
    fn into_values_yields_all_values() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(64);
        for i in 0..20 {
            map.insert(i, i * 5);
        }
        let mut vals: Vec<i32> = map.into_values().collect();
        vals.sort_unstable();
        let expected: Vec<i32> = (0..20).map(|i| i * 5).collect();
        assert_eq!(vals, expected);
    }

    #[test]
    fn into_keys_drops_values() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct DropCounter {
            counter: Arc<AtomicUsize>,
        }
        impl Drop for DropCounter {
            fn drop(&mut self) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }
        }

        let counter = Arc::new(AtomicUsize::new(0));
        let n: usize = 25;
        let mut map: ElasticHashMap<usize, DropCounter> = ElasticHashMap::with_capacity(64);
        for i in 0..n {
            map.insert(
                i,
                DropCounter {
                    counter: Arc::clone(&counter),
                },
            );
        }
        let keys: Vec<usize> = map.into_keys().collect();
        assert_eq!(keys.len(), n);
        assert_eq!(counter.load(Ordering::SeqCst), n);
    }

    #[test]
    fn into_values_drops_keys() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct DropKey {
            id: usize,
            counter: Arc<AtomicUsize>,
        }
        impl std::hash::Hash for DropKey {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.id.hash(state);
            }
        }
        impl PartialEq for DropKey {
            fn eq(&self, other: &Self) -> bool {
                self.id == other.id
            }
        }
        impl Eq for DropKey {}
        impl Drop for DropKey {
            fn drop(&mut self) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }
        }

        let counter = Arc::new(AtomicUsize::new(0));
        let n: usize = 25;
        let mut map: ElasticHashMap<DropKey, usize> = ElasticHashMap::with_capacity(64);
        for i in 0..n {
            map.insert(
                DropKey {
                    id: i,
                    counter: Arc::clone(&counter),
                },
                i,
            );
        }
        let vals: Vec<usize> = map.into_values().collect();
        assert_eq!(vals.len(), n);
        assert_eq!(counter.load(Ordering::SeqCst), n);
    }

    #[test]
    fn iter_mut_partial_consume_then_drop() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(64);
        for i in 0..30 {
            map.insert(i, i);
        }
        {
            let mut it = map.iter_mut();
            for _ in 0..5 {
                if let Some((_, v)) = it.next() {
                    *v += 1000;
                }
            }
            // it drops here; map is still consistent.
        }
        assert_eq!(map.len(), 30);
        // Every original key is still present.
        for i in 0..30 {
            assert!(map.get(&i).is_some(), "key {i} disappeared");
        }
    }

    #[test]
    fn drain_yields_all_entries_then_empties_map() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(64);
        for i in 0..30 {
            map.insert(i, i * 7);
        }
        let mut collected: Vec<(i32, i32)> = map.drain().collect();
        collected.sort_unstable();
        let expected: Vec<(i32, i32)> = (0..30).map(|i| (i, i * 7)).collect();
        assert_eq!(collected, expected);
        assert!(map.is_empty());
        assert_eq!(map.iter().count(), 0);
        // Reuse after drain.
        map.insert(999, 999);
        assert_eq!(map.get(&999), Some(&999));
    }

    #[test]
    fn drain_partial_consume_then_drop_still_empties_map() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(64);
        for i in 0..30 {
            map.insert(i, i);
        }
        {
            let mut drain = map.drain();
            let _first = drain.next();
            let _second = drain.next();
            // Drop here without exhausting; remaining entries must still be
            // freed and the map emptied (std semantics).
        }
        assert!(map.is_empty());
        assert_eq!(map.iter().count(), 0);
    }

    #[test]
    fn into_iter_partial_drop_drops_remaining() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct DropCounter {
            counter: Arc<AtomicUsize>,
        }
        impl Drop for DropCounter {
            fn drop(&mut self) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }
        }

        let counter = Arc::new(AtomicUsize::new(0));
        let n: usize = 40;
        let mut map: ElasticHashMap<usize, DropCounter> = ElasticHashMap::with_capacity(64);
        for i in 0..n {
            map.insert(
                i,
                DropCounter {
                    counter: Arc::clone(&counter),
                },
            );
        }
        let take = 10;
        let mut it = map.into_iter();
        let mut taken: Vec<(usize, DropCounter)> = Vec::with_capacity(take);
        for _ in 0..take {
            taken.push(it.next().expect("element"));
        }
        // `taken` is alive; only the remaining `n - take` entries are dropped
        // when the iterator's Drop runs.
        drop(it);
        assert_eq!(counter.load(Ordering::SeqCst), n - take);
        drop(taken);
        assert_eq!(counter.load(Ordering::SeqCst), n);
    }

    #[test]
    fn entry_or_insert_creates_when_missing() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        let value = map.entry(1).or_insert(10);
        assert_eq!(*value, 10);
        assert_eq!(map.get(&1), Some(&10));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn entry_or_insert_returns_existing() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        map.insert(1, 10);
        let value = map.entry(1).or_insert(99);
        assert_eq!(*value, 10);
        assert_eq!(map.get(&1), Some(&10));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn entry_or_insert_with_lazy_default_not_called_on_hit() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        map.insert(1, 10);
        let mut called = false;
        let value = map.entry(1).or_insert_with(|| {
            called = true;
            42
        });
        assert_eq!(*value, 10);
        assert!(!called, "default closure must not run on occupied entry");
    }

    #[test]
    fn entry_or_insert_with_key_uses_key_in_default() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        let value = map.entry(7).or_insert_with_key(|k| k * 100);
        assert_eq!(*value, 700);
        assert_eq!(map.get(&7), Some(&700));
    }

    #[test]
    fn entry_and_modify_runs_on_occupied() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        map.insert(1, 10);
        let value = map.entry(1).and_modify(|v| *v += 5).or_insert(0);
        assert_eq!(*value, 15);
        assert_eq!(map.get(&1), Some(&15));
    }

    #[test]
    fn entry_and_modify_skips_on_vacant() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        let mut touched = false;
        let value = map.entry(1).and_modify(|_| touched = true).or_insert(42);
        assert_eq!(*value, 42);
        assert!(!touched);
        assert_eq!(map.get(&1), Some(&42));
    }

    #[test]
    fn entry_occupied_get_mut_mutates() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        map.insert(1, 10);
        if let Entry::Occupied(mut occ) = map.entry(1) {
            *occ.get_mut() = 99;
            assert_eq!(*occ.get(), 99);
        } else {
            panic!("expected occupied");
        }
        assert_eq!(map.get(&1), Some(&99));
    }

    #[test]
    fn entry_occupied_into_mut_outlives_entry_borrow() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        map.insert(1, 10);
        let value: &mut i32 = match map.entry(1) {
            Entry::Occupied(occ) => occ.into_mut(),
            Entry::Vacant(_) => panic!("expected occupied"),
        };
        *value = 123;
        assert_eq!(map.get(&1), Some(&123));
    }

    #[test]
    fn entry_occupied_insert_returns_old_and_replaces() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        map.insert(1, 10);
        if let Entry::Occupied(mut occ) = map.entry(1) {
            let old = occ.insert(99);
            assert_eq!(old, 10);
        } else {
            panic!("expected occupied");
        }
        assert_eq!(map.get(&1), Some(&99));
    }

    #[test]
    fn entry_occupied_remove_returns_value() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        map.insert(1, 10);
        map.insert(2, 20);
        if let Entry::Occupied(occ) = map.entry(1) {
            assert_eq!(occ.remove(), 10);
        } else {
            panic!("expected occupied");
        }
        assert!(map.get(&1).is_none());
        assert_eq!(map.get(&2), Some(&20));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn entry_vacant_insert_returns_mut_ref() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        let value: &mut i32 = match map.entry(5) {
            Entry::Vacant(vac) => vac.insert(50),
            Entry::Occupied(_) => panic!("expected vacant"),
        };
        *value += 1;
        assert_eq!(map.get(&5), Some(&51));
    }

    #[test]
    fn try_insert_succeeds_when_missing() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        let value = map.try_insert(1, 10).expect("vacant should succeed");
        assert_eq!(*value, 10);
        assert_eq!(map.get(&1), Some(&10));
    }

    #[test]
    fn try_insert_fails_with_occupied_error_when_present() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        map.insert(1, 10);
        let err = map.try_insert(1, 99).expect_err("occupied must error");
        assert_eq!(err.entry.key(), &1);
        assert_eq!(err.entry.get(), &10);
        assert_eq!(map.get(&1), Some(&10));
    }

    #[test]
    fn try_insert_occupied_error_carries_rejected_value() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::new();
        map.insert(1, 10);
        let err = map.try_insert(1, 99).expect_err("occupied must error");
        assert_eq!(err.value, 99);
    }

    #[test]
    fn extract_if_yields_only_matching_and_leaves_rest() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(64);
        for i in 0..40 {
            map.insert(i, i);
        }
        let mut extracted: Vec<(i32, i32)> = map.extract_if(|k, _| k % 3 == 0).collect();
        extracted.sort_unstable();
        let expected: Vec<(i32, i32)> = (0..40).filter(|i| i % 3 == 0).map(|i| (i, i)).collect();
        assert_eq!(extracted, expected);
        assert_eq!(map.len(), 40 - expected.len());
        for i in 0..40 {
            if i % 3 == 0 {
                assert!(map.get(&i).is_none());
            } else {
                assert_eq!(map.get(&i), Some(&i));
            }
        }
    }

    #[test]
    fn extract_if_partial_consume_then_drop_keeps_remaining_in_map() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(64);
        for i in 0..30 {
            map.insert(i, i);
        }
        let original_len = map.len();
        let extracted_count;
        {
            let mut it = map.extract_if(|_, _| true);
            // Pull two; abandon the rest.
            assert!(it.next().is_some());
            assert!(it.next().is_some());
            extracted_count = 2;
        }
        assert_eq!(map.len(), original_len - extracted_count);
        // Remaining keys are still all findable via iter().
        let remaining: Vec<i32> = map.iter().map(|(&k, _)| k).collect();
        assert_eq!(remaining.len(), original_len - extracted_count);
    }

    #[test]
    fn retain_does_not_trigger_mid_iter_resize_with_clustered_tombstones() {
        // Build a small map past the cleanup threshold and retain half. The
        // bulk-op iterators bypass `remove`, so the per-remove resize check
        // can't fire mid-walk; this test guards that invariant.
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(256);
        let cap = i32::try_from(map.capacity()).expect("test capacity fits i32");
        let n = cap * 2 / 3;
        for i in 0..n {
            map.insert(i, i);
        }
        let initial_capacity = map.capacity();
        map.retain(|k, _| k % 2 == 0);

        // Every surviving key must still resolve.
        let expected_count = (0..n).filter(|i| i % 2 == 0).count();
        assert_eq!(map.len(), expected_count);
        for i in 0..n {
            if i % 2 == 0 {
                assert_eq!(map.get(&i), Some(&i), "kept key {i} missing");
            } else {
                assert!(map.get(&i).is_none(), "dropped key {i} survived");
            }
        }
        // No regress in capacity (we may have rehashed but never grew).
        assert!(map.capacity() <= initial_capacity * 2);
    }

    #[test]
    fn shrink_then_insert_works() {
        let mut map: ElasticHashMap<i32, i32> = ElasticHashMap::with_capacity(1024);
        for i in 0..200 {
            map.insert(i, i * 3);
        }
        for i in 0..150 {
            map.remove(&i);
        }
        map.shrink_to_fit();
        // Reinserting into a freshly-shrunk map should land cleanly.
        for i in 0..50 {
            assert_eq!(map.insert(i, i * 5), None);
        }
        for i in 0..50 {
            assert_eq!(map.get(&i), Some(&(i * 5)));
        }
        for i in 150..200 {
            assert_eq!(map.get(&i), Some(&(i * 3)));
        }
    }
}
