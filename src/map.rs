use core::error::Error;
use core::fmt;
use core::hash::{BuildHasher, Hash};
use core::iter::FusedIterator;
use core::marker::PhantomData;
use core::ops::Index;

use allocator_api2::alloc::{Allocator, Global};
use equivalent::Equivalent;

use crate::ReserveFraction;
#[cfg(feature = "default-hasher")]
use crate::common::DefaultHashBuilder;
use crate::common::arena::{self, SlotEntry};
use crate::common::config::INITIAL_CAPACITY;
use crate::common::control;
use crate::common::error::{TryBuildError, TryReserveError};
use crate::common::iter::{
    IntoKeys as CommonIntoKeys, IntoValues as CommonIntoValues, Keys as CommonKeys,
    Values as CommonValues,
};
use crate::common::math::capacity;
use crate::epoch::EpochSnapshot;

/// The backend contract behind [`HashMap`]: storage, lookup, insert, iteration,
/// and lifecycle, grouped into sections below.
// This crate-private contract intentionally exposes `SlotEntry`.
#[allow(private_interfaces)]
pub trait TableBackend<K, V>: Sized {
    // -- Storage: metadata + direct slot access --

    /// Identify an occupied slot in this table.
    ///
    /// Valid only until the next structural mutation of the same table (a
    /// resize/repack from `insert`/`remove`, or `resize`/`clear`/`shrink_to`).
    /// Every method taking a `Location` requires one from the same table, still
    /// valid; a stale or foreign location reads or writes the wrong slot.
    /// Consume it before the next mutation; never store it across one.
    type Location: Copy + PartialEq;
    /// Build hashes for stored keys.
    type Hasher: BuildHasher;
    /// Allocate backing storage.
    type Alloc: Allocator + Clone;
    /// Return the hash builder.
    fn hasher(&self) -> &Self::Hasher;

    /// Hash `key` with the table's hash builder.
    fn hash<Q: Hash + ?Sized>(&self, key: &Q) -> u64 {
        self.hasher().hash_one(key)
    }

    /// Return the allocator.
    fn allocator(&self) -> &Self::Alloc;

    /// Return the number of live entries.
    fn len(&self) -> usize;

    /// Return the live-entry limit before resizing.
    fn capacity(&self) -> usize;

    /// Return the backing slot count, including reserved slots.
    fn total_slots(&self) -> usize;

    /// Return the exact reserve fraction fixed for this allocation epoch.
    fn reserve_config(&self) -> ReserveFraction;

    /// Return the current allocation epoch.
    fn epoch_snapshot(&self) -> EpochSnapshot;

    /// Borrow the slot at `loc`.
    ///
    /// # Safety
    /// `loc` must be a live location from this table.
    unsafe fn slot_ref(&self, loc: Self::Location) -> &SlotEntry<K, V>;

    /// Return a raw slot pointer without forming an intermediate `&mut`.
    ///
    /// # Safety
    /// `loc` must be a live location from this table.
    unsafe fn slot_ptr(&self, loc: Self::Location) -> *mut SlotEntry<K, V>;

    /// Replace the value at `loc` (valid per [`Location`](TableBackend::Location))
    /// and return the previous.
    fn replace_value(&mut self, loc: Self::Location, value: V) -> V;

    // -- Lookup --

    /// Find the slot for `key` by precomputed hash and fingerprint; the
    /// location is valid per [`Location`](TableBackend::Location).
    fn find<Q>(&self, key: &Q, hash: u64, fingerprint: u8) -> Option<Self::Location>
    where
        Q: Hash + Equivalent<K> + ?Sized;

    /// Find and borrow the occupied slot for `key` by precomputed hash and
    /// fingerprint. This interface lets backends retain the slot reference
    /// formed while comparing the key, avoiding a second location-to-slot
    /// dispatch on hot read hits. The reference is tied to `self`; its shared
    /// borrow prevents the structural mutation that could otherwise invalidate
    /// the backing allocation.
    fn find_entry<'a, Q>(
        &'a self,
        key: &Q,
        hash: u64,
        fingerprint: u8,
    ) -> Option<&'a SlotEntry<K, V>>
    where
        Q: Hash + Equivalent<K> + ?Sized;

    // -- Insert / remove --

    /// Insert a known-absent key, resize as needed, and return its location
    /// (valid per [`Location`](TableBackend::Location)).
    fn insert_for_vacant(&mut self, key: K, value: V, hash: u64) -> Self::Location;

    /// Insert `key` → `value` and return the previous value. Backends may
    /// override this two-probe default with single-pass insertion.
    fn insert(&mut self, key: K, value: V, hash: u64) -> Option<V>
    where
        K: Hash + Eq,
    {
        let fp = fingerprint(hash);
        if let Some(loc) = self.find(&key, hash, fp) {
            return Some(self.replace_value(loc, value));
        }
        self.insert_for_vacant(key, value, hash);
        None
    }

    /// Remove the entry at `loc` (valid per [`Location`](TableBackend::Location)),
    /// update bookkeeping, and resize if needed.
    fn remove(&mut self, loc: Self::Location) -> (K, V);

    /// Mark `loc` (valid per [`Location`](TableBackend::Location)) as a tombstone
    /// without updating counters — draining iterators use it after moving the
    /// value out to avoid a double drop.
    fn tombstone_slot(&mut self, loc: Self::Location);

    /// Mark a moved-out `loc` (valid per [`Location`](TableBackend::Location)) as
    /// a tombstone and update counters without resizing.
    fn extract_finish(&mut self, loc: Self::Location);

    /// Complete maintenance deferred while a bulk-removal scan was active.
    fn finish_deferred_removals(&mut self);

    // -- Iterate: scan occupied slots without retaining pointers --

    /// Track scan progress by index so a consumed table can move safely.
    type Scan;

    /// Create a cursor positioned before the first occupied slot.
    fn scan(&self) -> Self::Scan;

    /// Advance `scan` and return the next occupied slot. The cursor stays
    /// pointerless between calls so a consumed table can move safely.
    ///
    /// Yield each occupied slot exactly once per traversal, with distinct
    /// pointers: `IterMut`/`Drain` lift each to a `&mut`, so a repeat aliases (UB).
    fn scan_next(&self, scan: &mut Self::Scan) -> Option<(*mut SlotEntry<K, V>, Self::Location)>;

    // -- Lifecycle: construct, resize, clean up, clone --

    /// Construct storage for the public exact-reserve constructor family.
    fn with_capacity_and_reserve_and_hasher_in(
        capacity: usize,
        reserve: ReserveFraction,
        hash_builder: Self::Hasher,
        alloc: Self::Alloc,
    ) -> Self;

    /// Fallible construction for the public exact-reserve constructor family.
    fn try_with_capacity_and_reserve_and_hasher_in(
        capacity: usize,
        reserve: ReserveFraction,
        hash_builder: Self::Hasher,
        alloc: Self::Alloc,
    ) -> Result<Self, TryBuildError>;

    /// Compute the slot count for `needed` live entries, or `None` if none is
    /// representable. Round up from `total_slots()` (min `INITIAL_CAPACITY`) by
    /// the current exact reserve.
    fn grow_capacity_for(&self, needed: usize) -> Option<usize> {
        capacity::capacity_for(
            self.total_slots().max(INITIAL_CAPACITY),
            needed,
            self.reserve_config(),
        )
    }

    /// Reallocate to `new_capacity` slots and reinsert every entry.
    fn resize(&mut self, new_capacity: usize);

    /// Attempt to resize while leaving the table intact on `Err`.
    fn try_resize(&mut self, new_capacity: usize) -> Result<(), TryReserveError>
    where
        Self::Hasher: Clone;

    /// Ensure room for `additional` entries.
    fn reserve(&mut self, additional: usize) {
        let needed = self.len().saturating_add(additional);
        if needed <= self.capacity() {
            return;
        }
        let new_capacity = self.grow_capacity_for(needed).expect("capacity overflow");
        self.resize(new_capacity);
    }

    /// Attempt to reserve room for `additional` entries.
    fn try_reserve(&mut self, additional: usize) -> Result<(), TryReserveError>
    where
        Self::Hasher: Clone,
    {
        let needed = self
            .len()
            .checked_add(additional)
            .ok_or(TryReserveError::CapacityOverflow)?;
        if needed <= self.capacity() {
            return Ok(());
        }
        let new_capacity = self
            .grow_capacity_for(needed)
            .ok_or(TryReserveError::CapacityOverflow)?;
        self.try_resize(new_capacity)
    }

    /// Shrink capacity toward `min_capacity` without dropping entries.
    fn shrink_to(&mut self, min_capacity: usize) {
        if self.len() == 0 && min_capacity == 0 {
            if self.total_slots() > 0 {
                self.resize(0);
            }
            return;
        }
        let lower = self.len().max(min_capacity).max(INITIAL_CAPACITY);
        let new_capacity = capacity::capacity_for(INITIAL_CAPACITY, lower, self.reserve_config())
            .expect("capacity overflow");
        if new_capacity >= self.total_slots() {
            return;
        }
        self.resize(new_capacity);
    }

    /// Drop all entries while retaining the allocation.
    fn clear(&mut self);

    /// Clear control bytes and counters after [`Drain::drop`] moves out values.
    fn wipe_all(&mut self);

    /// Clone storage, hash builder, allocator, and entries.
    fn clone_table(&self) -> Self
    where
        K: Clone,
        V: Clone,
        Self::Hasher: Clone;
}

/// Computes the control-byte fingerprint the backends scan on.
#[inline]
fn fingerprint(hash: u64) -> u8 {
    control::control_fingerprint(hash)
}

/// Use a [`TableBackend`] backend to store key-value pairs.
pub struct HashMap<K, V, P: TableBackend<K, V>> {
    table: P,
    _marker: PhantomData<(K, V)>,
}

impl<K, V, P: TableBackend<K, V>> HashMap<K, V, P> {
    #[inline]
    fn from_table(table: P) -> Self {
        Self {
            table,
            _marker: PhantomData,
        }
    }

    /// Full exact constructor: capacity, reserve, hasher, and allocator.
    ///
    /// # Panics
    /// Panics if the backend rejects the reserve/capacity or allocation fails.
    #[must_use]
    pub fn with_capacity_and_reserve_and_hasher_in(
        capacity: usize,
        reserve: ReserveFraction,
        hash_builder: P::Hasher,
        alloc: P::Alloc,
    ) -> Self {
        Self::from_table(P::with_capacity_and_reserve_and_hasher_in(
            capacity,
            reserve,
            hash_builder,
            alloc,
        ))
    }

    /// Fallible full exact constructor.
    ///
    /// # Errors
    ///
    /// Returns [`TryBuildError`] for an unsupported reserve, capacity
    /// overflow, or allocator failure.
    pub fn try_with_capacity_and_reserve_and_hasher_in(
        capacity: usize,
        reserve: ReserveFraction,
        hash_builder: P::Hasher,
        alloc: P::Alloc,
    ) -> Result<Self, TryBuildError> {
        P::try_with_capacity_and_reserve_and_hasher_in(capacity, reserve, hash_builder, alloc)
            .map(Self::from_table)
    }

    /// Compatibility constructor accepting an exact dyadic `f64` reserve.
    ///
    /// # Panics
    ///
    /// Panics when `reserve_fraction` is not exactly `1 / 2^d` for positive
    /// `d`, or when construction otherwise fails.
    #[must_use]
    pub fn with_capacity_and_reserve_fraction_and_hasher_in(
        capacity: usize,
        reserve_fraction: f64,
        hash_builder: P::Hasher,
        alloc: P::Alloc,
    ) -> Self {
        Self::try_with_capacity_and_reserve_fraction_and_hasher_in(
            capacity,
            reserve_fraction,
            hash_builder,
            alloc,
        )
        .unwrap_or_else(|error| panic!("invalid map construction: {error}"))
    }

    /// Fallible compatibility constructor accepting an exact dyadic `f64`.
    ///
    /// # Errors
    ///
    /// Returns [`TryBuildError::InvalidReserveFraction`] for non-dyadic input,
    /// or the backend construction error.
    pub fn try_with_capacity_and_reserve_fraction_and_hasher_in(
        capacity: usize,
        reserve_fraction: f64,
        hash_builder: P::Hasher,
        alloc: P::Alloc,
    ) -> Result<Self, TryBuildError> {
        let reserve = ReserveFraction::try_from(reserve_fraction)
            .map_err(TryBuildError::InvalidReserveFraction)?;
        Self::try_with_capacity_and_reserve_and_hasher_in(capacity, reserve, hash_builder, alloc)
    }

    /// Reference to the map's allocator.
    pub fn allocator(&self) -> &P::Alloc {
        self.table.allocator()
    }

    /// Reference to the map's [`BuildHasher`].
    pub fn hasher(&self) -> &P::Hasher {
        self.table.hasher()
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Returns `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.table.len() == 0
    }

    /// Maximum entries before the next automatic resize.
    pub fn capacity(&self) -> usize {
        self.table.capacity()
    }

    /// Returns the exact reserve fraction fixed for the current epoch.
    #[must_use]
    pub fn reserve_fraction(&self) -> ReserveFraction {
        self.table.reserve_config()
    }

    /// Returns the current allocation epoch.
    #[must_use]
    pub fn epoch(&self) -> EpochSnapshot {
        self.table.epoch_snapshot()
    }

    /// Reserves room for at least `additional` more entries.
    pub fn reserve(&mut self, additional: usize) {
        self.table.reserve(additional);
    }

    /// Fallible [`reserve`](Self::reserve).
    ///
    /// # Errors
    /// Returns [`TryReserveError`] on capacity overflow or allocator failure.
    pub fn try_reserve(&mut self, additional: usize) -> Result<(), TryReserveError>
    where
        P::Hasher: Clone,
    {
        self.table.try_reserve(additional)
    }

    /// Shrinks capacity to fit the current length.
    pub fn shrink_to_fit(&mut self) {
        self.table.shrink_to(0);
    }

    /// Shrinks capacity toward `min_capacity`.
    pub fn shrink_to(&mut self, min_capacity: usize) {
        self.table.shrink_to(min_capacity);
    }

    /// Removes all entries, keeping allocated capacity.
    pub fn clear(&mut self) {
        self.table.clear();
    }
}

#[cfg(test)]
impl<K, V, P: TableBackend<K, V>> HashMap<K, V, P> {
    pub(crate) fn table(&self) -> &P {
        &self.table
    }
}

impl<K, V, P> HashMap<K, V, P>
where
    K: Eq + Hash,
    P: TableBackend<K, V>,
{
    #[inline]
    fn find_location<Q>(&self, key: &Q) -> Option<P::Location>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let hash = self.table.hash(key);
        self.table.find(key, hash, fingerprint(hash))
    }

    /// Shared reference to the slot at `loc`.
    ///
    /// # Safety
    /// `loc` must be a live location from this table.
    #[inline]
    unsafe fn slot_entry(&self, loc: P::Location) -> &SlotEntry<K, V> {
        unsafe { self.table.slot_ref(loc) }
    }

    /// Mutable reference to the slot at `loc`.
    ///
    /// # Safety
    /// `loc` must be live in this table, and the caller must uphold mutable
    /// aliasing rules for the returned slot.
    #[inline]
    #[allow(clippy::mut_from_ref)]
    unsafe fn slot_entry_mut(&self, loc: P::Location) -> &mut SlotEntry<K, V> {
        unsafe { &mut *self.table.slot_ptr(loc) }
    }

    #[inline]
    fn lookup_entry<Q>(&self, key: &Q) -> Option<&SlotEntry<K, V>>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let hash = self.table.hash(key);
        self.table.find_entry(key, hash, fingerprint(hash))
    }

    /// Inserts `key`/`value`. Returns the previous value for `key`, if any.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let hash = self.table.hash(&key);
        self.table.insert(key, value, hash)
    }

    /// Returns a reference to the value for `key`.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.lookup_entry(key).map(|entry| &entry.value)
    }

    /// Returns the stored `(key, value)` pair for `key`.
    pub fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let entry = self.lookup_entry(key)?;
        Some((&entry.key, &entry.value))
    }

    /// Returns the stored key equal to `key`, inserting `f(key)` (with `value`)
    /// if absent, in one hit-path probe. The `Copy` location from
    /// [`TableBackend::find`] frees the borrow before the key ref is re-derived —
    /// the naive `get`-then-insert needs Polonius. Backs set `get_or_insert_with`.
    pub(crate) fn get_or_insert_key_with<Q, F>(&mut self, key: &Q, value: V, f: F) -> &K
    where
        Q: Hash + Equivalent<K> + ?Sized,
        F: FnOnce(&Q) -> K,
    {
        let hash = self.table.hash(key);
        if let Some(loc) = self.table.find(key, hash, fingerprint(hash)) {
            // SAFETY: `find` returned a live location from this table.
            return unsafe { &self.slot_entry(loc).key };
        }
        let loc = self.table.insert_for_vacant(f(key), value, hash);
        // SAFETY: `loc` was just inserted into this table.
        unsafe { &self.slot_entry(loc).key }
    }

    /// Returns a mutable reference to the value for `key`.
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let loc = self.find_location(key)?;
        // SAFETY: `find_location` returned a live location; `&mut self` proves exclusivity.
        Some(unsafe { &mut self.slot_entry_mut(loc).value })
    }

    /// Returns `true` if `key` is present.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find_location(key).is_some()
    }

    /// Removes `key`, returning its value.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.remove_entry(key).map(|(_, v)| v)
    }

    /// Removes `key`, returning the stored `(key, value)` pair.
    pub fn remove_entry<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let loc = self.find_location(key)?;
        Some(self.table.remove(loc))
    }

    /// Returns `N` disjoint mutable references; per-key `Option`, panics on
    /// aliasing among the hits.
    ///
    /// # Panics
    /// If two input keys resolve to the same slot.
    pub fn get_disjoint_mut<Q, const N: usize>(&mut self, keys: [&Q; N]) -> [Option<&mut V>; N]
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let locations = self.locate_disjoint(keys);
        arena::check_disjoint_aliasing(&locations);
        core::array::from_fn(|i| {
            locations[i].map(|loc| {
                // SAFETY: locations are live and unique among the hits (asserted above).
                unsafe { &mut self.slot_entry_mut(loc).value }
            })
        })
    }

    /// Like [`get_disjoint_mut`](Self::get_disjoint_mut) but yields `(&K, &mut V)`.
    ///
    /// # Panics
    /// If two input keys resolve to the same slot.
    pub fn get_disjoint_key_value_mut<Q, const N: usize>(
        &mut self,
        keys: [&Q; N],
    ) -> [Option<(&K, &mut V)>; N]
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let locations = self.locate_disjoint(keys);
        arena::check_disjoint_aliasing(&locations);
        core::array::from_fn(|i| {
            locations[i].map(|loc| {
                // SAFETY: locations are live and unique among the hits (asserted above).
                let slot = unsafe { self.slot_entry_mut(loc) };
                (&slot.key, &mut slot.value)
            })
        })
    }

    /// Unchecked [`get_disjoint_mut`](Self::get_disjoint_mut).
    ///
    /// # Safety
    /// The keys that resolve to occupied slots must be pairwise distinct.
    pub unsafe fn get_disjoint_unchecked_mut<Q, const N: usize>(
        &mut self,
        keys: [&Q; N],
    ) -> [Option<&mut V>; N]
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let locations = self.locate_disjoint(keys);
        core::array::from_fn(|i| {
            locations[i].map(|loc|
                // SAFETY: caller guarantees the hits are pairwise distinct.
                unsafe { &mut self.slot_entry_mut(loc).value })
        })
    }

    #[inline]
    fn locate_disjoint<Q, const N: usize>(&self, keys: [&Q; N]) -> [Option<P::Location>; N]
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        core::array::from_fn(|i| self.find_location(keys[i]))
    }

    /// Inserts `key`/`value` only if absent; otherwise returns an
    /// [`OccupiedError`] carrying the rejected value.
    ///
    /// # Errors
    /// [`OccupiedError`] when `key` is already present.
    pub fn try_insert(&mut self, key: K, value: V) -> Result<&mut V, OccupiedError<'_, K, V, P>> {
        let hash = self.table.hash(&key);
        let fp = fingerprint(hash);
        if let Some(loc) = self.table.find(&key, hash, fp) {
            return Err(OccupiedError {
                entry: OccupiedEntry {
                    map: self,
                    loc,
                    _marker: PhantomData,
                },
                value,
            });
        }
        let loc = self.table.insert_for_vacant(key, value, hash);
        // SAFETY: `loc` was just inserted into this table.
        Ok(unsafe { &mut self.slot_entry_mut(loc).value })
    }

    /// Gets the [`Entry`] for `key` for in-place manipulation.
    pub fn entry(&mut self, key: K) -> Entry<'_, K, V, P> {
        let hash = self.table.hash(&key);
        match self.table.find(&key, hash, fingerprint(hash)) {
            Some(loc) => Entry::Occupied(OccupiedEntry {
                map: self,
                loc,
                _marker: PhantomData,
            }),
            None => Entry::Vacant(VacantEntry {
                map: self,
                key,
                hash,
            }),
        }
    }

    /// Drops every entry for which `f(&K, &mut V)` returns `false`.
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        self.extract_if(|k, v| !f(k, v)).for_each(drop);
    }
}

// ---------------------------------------------------------------------------
// Entry API
// ---------------------------------------------------------------------------

/// A view into a single map entry, occupied or vacant.
pub enum Entry<'a, K, V, P: TableBackend<K, V>> {
    /// Key present.
    Occupied(OccupiedEntry<'a, K, V, P>),
    /// Key absent.
    Vacant(VacantEntry<'a, K, V, P>),
}

/// View of an occupied entry.
pub struct OccupiedEntry<'a, K, V, P: TableBackend<K, V>> {
    map: &'a mut HashMap<K, V, P>,
    loc: P::Location,
    _marker: PhantomData<K>,
}

/// View of a vacant entry.
pub struct VacantEntry<'a, K, V, P: TableBackend<K, V>> {
    map: &'a mut HashMap<K, V, P>,
    key: K,
    hash: u64,
}

/// Error returned by [`HashMap::try_insert`] on key collision. Holds the
/// occupied entry that blocked the insert plus the rejected value.
pub struct OccupiedError<'a, K, V, P: TableBackend<K, V>> {
    /// The entry whose key was already present.
    pub entry: OccupiedEntry<'a, K, V, P>,
    /// The value that could not be inserted.
    pub value: V,
}

impl<K, V, P> fmt::Debug for OccupiedError<'_, K, V, P>
where
    K: Eq + Hash + fmt::Debug,
    V: fmt::Debug,
    P: TableBackend<K, V>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OccupiedError")
            .field("key", self.entry.key())
            .field("value", &self.value)
            .finish()
    }
}

impl<K, V, P> fmt::Display for OccupiedError<'_, K, V, P>
where
    K: Eq + Hash + fmt::Debug,
    V: fmt::Debug,
    P: TableBackend<K, V>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "tried to insert {:?}, but key {:?} was already present with {:?}",
            self.value,
            self.entry.key(),
            self.entry.get(),
        )
    }
}

impl<K, V, P> Error for OccupiedError<'_, K, V, P>
where
    K: Eq + Hash + fmt::Debug,
    V: fmt::Debug,
    P: TableBackend<K, V>,
{
}

impl<'a, K, V, P> OccupiedEntry<'a, K, V, P>
where
    K: Eq + Hash,
    P: TableBackend<K, V>,
{
    /// Reference to the entry's key.
    #[must_use]
    pub fn key(&self) -> &K {
        // SAFETY: occupied entries store a live location from this table.
        unsafe { &self.map.slot_entry(self.loc).key }
    }

    /// Reference to the entry's value.
    #[must_use]
    pub fn get(&self) -> &V {
        // SAFETY: occupied entries store a live location from this table.
        unsafe { &self.map.slot_entry(self.loc).value }
    }

    /// Mutable reference to the value, tied to `self`.
    pub fn get_mut(&mut self) -> &mut V {
        // SAFETY: occupied entries store a live location; `&mut self` proves exclusivity.
        unsafe { &mut self.map.slot_entry_mut(self.loc).value }
    }

    /// Consumes the entry, returning `&mut V` for the map's lifetime.
    #[must_use]
    pub fn into_mut(self) -> &'a mut V {
        // SAFETY: occupied entries store a live location; consuming the entry
        // preserves the original exclusive map borrow for `'a`.
        unsafe { &mut self.map.slot_entry_mut(self.loc).value }
    }

    /// Consumes the entry, returning `&K` for the map's lifetime.
    pub(crate) fn into_key(self) -> &'a K {
        // SAFETY: occupied entries store a live location from this table.
        unsafe { &self.map.slot_entry(self.loc).key }
    }

    /// Replaces the value, returning the old one.
    pub fn insert(&mut self, value: V) -> V {
        self.map.table.replace_value(self.loc, value)
    }

    /// Removes the entry and returns its value.
    #[must_use]
    pub fn remove(self) -> V {
        self.remove_entry().1
    }

    /// Removes the entry and returns the `(key, value)` pair.
    #[must_use]
    pub fn remove_entry(self) -> (K, V) {
        self.map.table.remove(self.loc)
    }
}

impl<'a, K, V, P> VacantEntry<'a, K, V, P>
where
    K: Eq + Hash,
    P: TableBackend<K, V>,
{
    /// Reference to the key that would be inserted.
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
        let loc = self.map.table.insert_for_vacant(self.key, value, self.hash);
        // SAFETY: `loc` was just inserted into this table.
        unsafe { &mut self.map.slot_entry_mut(loc).value }
    }

    /// Inserts `value` and returns the resulting [`OccupiedEntry`].
    pub(crate) fn insert_entry(self, value: V) -> OccupiedEntry<'a, K, V, P> {
        let loc = self.map.table.insert_for_vacant(self.key, value, self.hash);
        OccupiedEntry {
            map: self.map,
            loc,
            _marker: PhantomData,
        }
    }
}

impl<'a, K, V, P> Entry<'a, K, V, P>
where
    K: Eq + Hash,
    P: TableBackend<K, V>,
{
    /// Returns `&mut V`, inserting `default` if vacant.
    pub fn or_insert(self, default: V) -> &'a mut V {
        match self {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(default),
        }
    }

    /// Like [`or_insert`](Self::or_insert) with a lazily-computed default.
    pub fn or_insert_with<F: FnOnce() -> V>(self, default: F) -> &'a mut V {
        match self {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(default()),
        }
    }

    /// Like [`or_insert_with`](Self::or_insert_with); the closure gets the key.
    pub fn or_insert_with_key<F: FnOnce(&K) -> V>(self, default: F) -> &'a mut V {
        match self {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                let value = default(e.key());
                e.insert(value)
            }
        }
    }

    /// Reference to this entry's key.
    pub fn key(&self) -> &K {
        match self {
            Entry::Occupied(e) => e.key(),
            Entry::Vacant(e) => e.key(),
        }
    }

    /// Runs `f` on the value if occupied, then returns the entry.
    #[must_use]
    pub fn and_modify<F: FnOnce(&mut V)>(self, f: F) -> Self {
        match self {
            Entry::Occupied(mut e) => {
                f(e.get_mut());
                Entry::Occupied(e)
            }
            Entry::Vacant(e) => Entry::Vacant(e),
        }
    }
}

impl<'a, K, V, P> Entry<'a, K, V, P>
where
    K: Eq + Hash,
    P: TableBackend<K, V>,
    V: Default,
{
    /// Returns `&mut V`, inserting `V::default()` if vacant.
    pub fn or_default(self) -> &'a mut V {
        match self {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(V::default()),
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience constructors (reproduced generically from the full constructor)
// ---------------------------------------------------------------------------

#[cfg(feature = "default-hasher")]
impl<K, V, P> HashMap<K, V, P>
where
    P: TableBackend<K, V, Hasher = DefaultHashBuilder, Alloc = Global>,
{
    /// Creates an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    /// Creates an empty map with at least `capacity` slots.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_capacity_and_reserve_and_hasher_in(
            capacity,
            ReserveFraction::DEFAULT,
            DefaultHashBuilder::default(),
            Global,
        )
    }

    /// Creates an empty map with the exact dyadic `reserve`.
    ///
    /// # Panics
    /// Panics if the backend rejects `reserve` or allocation fails.
    #[must_use]
    pub fn with_reserve(reserve: ReserveFraction) -> Self {
        Self::with_capacity_and_reserve(0, reserve)
    }

    /// Creates an empty map with `capacity` and the exact dyadic `reserve`.
    ///
    /// # Panics
    /// Panics if the backend rejects the inputs or allocation fails.
    #[must_use]
    pub fn with_capacity_and_reserve(capacity: usize, reserve: ReserveFraction) -> Self {
        Self::try_with_capacity_and_reserve(capacity, reserve)
            .unwrap_or_else(|error| panic!("invalid map construction: {error}"))
    }

    /// Fallible exact-reserve constructor.
    ///
    /// # Errors
    ///
    /// Returns [`TryBuildError`] for backend policy, capacity, or allocation
    /// failures.
    pub fn try_with_capacity_and_reserve(
        capacity: usize,
        reserve: ReserveFraction,
    ) -> Result<Self, TryBuildError> {
        Self::try_with_capacity_and_reserve_and_hasher_in(
            capacity,
            reserve,
            DefaultHashBuilder::default(),
            Global,
        )
    }

    /// Compatibility constructor for an exact dyadic `f64` reserve.
    ///
    /// # Panics
    /// Panics for non-dyadic input, unsupported reserve, or allocation failure.
    #[must_use]
    pub fn with_reserve_fraction(reserve_fraction: f64) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            0,
            reserve_fraction,
            DefaultHashBuilder::default(),
            Global,
        )
    }

    /// Compatibility constructor for capacity and an exact dyadic `f64` reserve.
    ///
    /// # Panics
    /// Panics for non-dyadic input, unsupported reserve, or construction failure.
    #[must_use]
    pub fn with_capacity_and_reserve_fraction(capacity: usize, reserve_fraction: f64) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            capacity,
            reserve_fraction,
            DefaultHashBuilder::default(),
            Global,
        )
    }

    /// Fallible compatibility constructor for an exact dyadic `f64` reserve.
    ///
    /// # Errors
    ///
    /// Returns [`TryBuildError`] for invalid input or construction failure.
    pub fn try_with_capacity_and_reserve_fraction(
        capacity: usize,
        reserve_fraction: f64,
    ) -> Result<Self, TryBuildError> {
        Self::try_with_capacity_and_reserve_fraction_and_hasher_in(
            capacity,
            reserve_fraction,
            DefaultHashBuilder::default(),
            Global,
        )
    }
}

impl<K, V, P> HashMap<K, V, P>
where
    P: TableBackend<K, V, Alloc = Global>,
{
    /// Creates an empty map that uses `hash_builder`.
    #[must_use]
    pub fn with_hasher(hash_builder: P::Hasher) -> Self {
        Self::with_capacity_and_reserve_and_hasher_in(
            0,
            ReserveFraction::DEFAULT,
            hash_builder,
            Global,
        )
    }

    /// Creates an empty map with the given capacity and hasher.
    #[must_use]
    pub fn with_capacity_and_hasher(capacity: usize, hash_builder: P::Hasher) -> Self {
        Self::with_capacity_and_reserve_and_hasher_in(
            capacity,
            ReserveFraction::DEFAULT,
            hash_builder,
            Global,
        )
    }

    /// Creates an empty map with an exact reserve and custom hasher.
    ///
    /// # Panics
    /// Panics if the backend rejects the inputs or allocation fails.
    #[must_use]
    pub fn with_capacity_and_reserve_and_hasher(
        capacity: usize,
        reserve: ReserveFraction,
        hash_builder: P::Hasher,
    ) -> Self {
        Self::with_capacity_and_reserve_and_hasher_in(capacity, reserve, hash_builder, Global)
    }

    /// Compatibility constructor for an exact dyadic `f64` reserve and hasher.
    ///
    /// # Panics
    /// Panics for non-dyadic input, unsupported reserve, or construction failure.
    #[must_use]
    pub fn with_reserve_fraction_and_hasher(
        reserve_fraction: f64,
        hash_builder: P::Hasher,
    ) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            0,
            reserve_fraction,
            hash_builder,
            Global,
        )
    }

    /// Compatibility constructor for capacity, exact dyadic reserve, and hasher.
    ///
    /// # Panics
    /// Panics for non-dyadic input, unsupported reserve, or construction failure.
    #[must_use]
    pub fn with_capacity_and_reserve_fraction_and_hasher(
        capacity: usize,
        reserve_fraction: f64,
        hash_builder: P::Hasher,
    ) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            capacity,
            reserve_fraction,
            hash_builder,
            Global,
        )
    }
}

#[cfg(feature = "default-hasher")]
impl<K, V, P> HashMap<K, V, P>
where
    P: TableBackend<K, V, Hasher = DefaultHashBuilder>,
{
    /// Creates an empty map in the given allocator.
    #[must_use]
    pub fn new_in(alloc: P::Alloc) -> Self {
        Self::with_capacity_and_reserve_and_hasher_in(
            0,
            ReserveFraction::DEFAULT,
            DefaultHashBuilder::default(),
            alloc,
        )
    }

    /// Creates an empty map with the given capacity in the given allocator.
    #[must_use]
    pub fn with_capacity_in(capacity: usize, alloc: P::Alloc) -> Self {
        Self::with_capacity_and_reserve_and_hasher_in(
            capacity,
            ReserveFraction::DEFAULT,
            DefaultHashBuilder::default(),
            alloc,
        )
    }
}

// ---------------------------------------------------------------------------
// Iteration accessors
// ---------------------------------------------------------------------------

impl<K, V, P: TableBackend<K, V>> HashMap<K, V, P> {
    /// Borrowing iterator over `(&K, &V)`, in arbitrary order.
    pub fn iter(&self) -> Iter<'_, K, V, P> {
        Iter {
            table: &self.table,
            scan: self.table.scan(),
            remaining: self.table.len(),
            _marker: PhantomData,
        }
    }

    /// Borrowing iterator over `(&K, &mut V)`.
    pub fn iter_mut(&mut self) -> IterMut<'_, K, V, P> {
        let scan = self.table.scan();
        let remaining = self.table.len();
        IterMut {
            table: core::ptr::from_mut(&mut self.table),
            scan,
            remaining,
            _marker: PhantomData,
        }
    }

    /// Iterator over `&K`.
    pub fn keys(&self) -> Keys<'_, K, V, P> {
        CommonKeys::new(self.iter())
    }

    /// Iterator over `&V`.
    pub fn values(&self) -> Values<'_, K, V, P> {
        CommonValues::new(self.iter())
    }

    /// Iterator over `&mut V`.
    pub fn values_mut(&mut self) -> ValuesMut<'_, K, V, P> {
        CommonValues::new(self.iter_mut())
    }

    /// Consuming iterator over owned keys.
    pub fn into_keys(self) -> IntoKeys<K, V, P> {
        CommonIntoKeys::new(self.into_iter())
    }

    /// Consuming iterator over owned values.
    pub fn into_values(self) -> IntoValues<K, V, P> {
        CommonIntoValues::new(self.into_iter())
    }

    /// Draining iterator that empties the map.
    pub fn drain(&mut self) -> Drain<'_, K, V, P> {
        let scan = self.table.scan();
        let remaining = self.table.len();
        Drain {
            table: core::ptr::from_mut(&mut self.table),
            scan,
            remaining,
            _marker: PhantomData,
        }
    }

    /// Removes and yields the entries for which `f` returns `true`.
    pub fn extract_if<F>(&mut self, f: F) -> ExtractIf<'_, K, V, P, F>
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        let scan = self.table.scan();
        ExtractIf {
            table: core::ptr::from_mut(&mut self.table),
            scan,
            pred: f,
            finished: false,
            _marker: PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// Iterators
// ---------------------------------------------------------------------------

/// Borrowing iterator over `(&K, &V)`.
pub struct Iter<'a, K, V, P: TableBackend<K, V>> {
    table: &'a P,
    scan: P::Scan,
    remaining: usize,
    _marker: PhantomData<(&'a K, &'a V)>,
}

impl<'a, K, V, P: TableBackend<K, V>> Iterator for Iter<'a, K, V, P> {
    type Item = (&'a K, &'a V);
    fn next(&mut self) -> Option<(&'a K, &'a V)> {
        let (ptr, _loc) = self.table.scan_next(&mut self.scan)?;
        self.remaining -= 1;
        // SAFETY: `ptr` is a live slot from this table's scan; the `&'a P`
        // borrow keeps it alive for `'a`.
        let slot: &'a SlotEntry<K, V> = unsafe { &*ptr };
        Some((&slot.key, &slot.value))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K, V, P: TableBackend<K, V>> ExactSizeIterator for Iter<'_, K, V, P> {
    fn len(&self) -> usize {
        self.remaining
    }
}
impl<K, V, P: TableBackend<K, V>> FusedIterator for Iter<'_, K, V, P> {}

impl<K, V, P> Clone for Iter<'_, K, V, P>
where
    P: TableBackend<K, V>,
    P::Scan: Clone,
{
    fn clone(&self) -> Self {
        Self {
            table: self.table,
            scan: self.scan.clone(),
            remaining: self.remaining,
            _marker: PhantomData,
        }
    }
}

impl<K: fmt::Debug, V: fmt::Debug, P> fmt::Debug for Iter<'_, K, V, P>
where
    P: TableBackend<K, V>,
    P::Scan: Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// Borrowing iterator over `(&K, &mut V)`.
pub struct IterMut<'a, K, V, P: TableBackend<K, V>> {
    table: *mut P,
    scan: P::Scan,
    remaining: usize,
    _marker: PhantomData<(&'a K, &'a mut V)>,
}

impl<'a, K, V, P: TableBackend<K, V>> Iterator for IterMut<'a, K, V, P> {
    type Item = (&'a K, &'a mut V);
    fn next(&mut self) -> Option<(&'a K, &'a mut V)> {
        // SAFETY: `table` points to the borrowed map; `scan_next` yields each
        // location at most once, so the `&'a mut` references are disjoint.
        let table = unsafe { &*self.table };
        let (ptr, _loc) = table.scan_next(&mut self.scan)?;
        self.remaining -= 1;
        let slot: &'a mut SlotEntry<K, V> = unsafe { &mut *ptr };
        Some((&slot.key, &mut slot.value))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K, V, P: TableBackend<K, V>> ExactSizeIterator for IterMut<'_, K, V, P> {
    fn len(&self) -> usize {
        self.remaining
    }
}
impl<K, V, P: TableBackend<K, V>> FusedIterator for IterMut<'_, K, V, P> {}

/// Consuming iterator over owned `(K, V)`.
pub struct IntoIter<K, V, P: TableBackend<K, V>> {
    table: P,
    scan: P::Scan,
    remaining: usize,
}

impl<K, V, P: TableBackend<K, V>> Iterator for IntoIter<K, V, P> {
    type Item = (K, V);
    fn next(&mut self) -> Option<(K, V)> {
        let (ptr, loc) = self.table.scan_next(&mut self.scan)?;
        self.remaining -= 1;
        // SAFETY: `ptr` is a live slot; read the entry out, then tombstone so
        // the consumed table's `Drop` won't re-drop the moved-out slot.
        let entry = unsafe { core::ptr::read(ptr) };
        self.table.tombstone_slot(loc);
        Some((entry.key, entry.value))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K, V, P: TableBackend<K, V>> ExactSizeIterator for IntoIter<K, V, P> {
    fn len(&self) -> usize {
        self.remaining
    }
}
impl<K, V, P: TableBackend<K, V>> FusedIterator for IntoIter<K, V, P> {}

/// Draining iterator; empties the map on consumption or drop.
pub struct Drain<'a, K, V, P: TableBackend<K, V>> {
    table: *mut P,
    scan: P::Scan,
    remaining: usize,
    _marker: PhantomData<&'a mut P>,
}

impl<K, V, P: TableBackend<K, V>> Iterator for Drain<'_, K, V, P> {
    type Item = (K, V);
    fn next(&mut self) -> Option<(K, V)> {
        // SAFETY: `table` points to the borrowed map for the drain's lifetime.
        let (ptr, loc) = unsafe { (*self.table).scan_next(&mut self.scan) }?;
        self.remaining -= 1;
        // SAFETY: live slot; read the entry out and mark a tombstone (counters
        // are reset wholesale by `wipe_all` on drop).
        let entry = unsafe { core::ptr::read(ptr) };
        unsafe { (*self.table).tombstone_slot(loc) };
        Some((entry.key, entry.value))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K, V, P: TableBackend<K, V>> ExactSizeIterator for Drain<'_, K, V, P> {
    fn len(&self) -> usize {
        self.remaining
    }
}
impl<K, V, P: TableBackend<K, V>> FusedIterator for Drain<'_, K, V, P> {}

impl<K, V, P: TableBackend<K, V>> Drop for Drain<'_, K, V, P> {
    fn drop(&mut self) {
        // Drain any unyielded entries so values run their `Drop`, then wipe.
        for _ in &mut *self {}
        unsafe { (*self.table).wipe_all() };
    }
}

/// Iterator yielding entries removed by [`HashMap::extract_if`]. Unyielded
/// non-matching entries are retained. Exhausting the iterator may clean
/// accumulated tombstones after the scan is finished.
pub struct ExtractIf<'a, K, V, P: TableBackend<K, V>, F> {
    table: *mut P,
    scan: P::Scan,
    pred: F,
    finished: bool,
    _marker: PhantomData<&'a mut P>,
}

impl<K, V, P, F> Iterator for ExtractIf<'_, K, V, P, F>
where
    P: TableBackend<K, V>,
    F: FnMut(&K, &mut V) -> bool,
{
    type Item = (K, V);
    fn next(&mut self) -> Option<(K, V)> {
        if self.finished {
            return None;
        }
        loop {
            // SAFETY: `table` points to the borrowed map for the iterator's life.
            let Some((ptr, loc)) = (unsafe { (*self.table).scan_next(&mut self.scan) }) else {
                self.finished = true;
                // SAFETY: the scan is exhausted and the iterator still owns the
                // map's exclusive borrow, so a same-size cleanup is now safe.
                unsafe { (*self.table).finish_deferred_removals() };
                return None;
            };
            // SAFETY: live slot; exclusive via the `&mut` map borrow.
            let slot = unsafe { &mut *ptr };
            if (self.pred)(&slot.key, &mut slot.value) {
                // SAFETY: matched — read the entry out, then finalize removal
                // (tombstone + counters; the map keeps being used).
                let entry = unsafe { core::ptr::read(ptr) };
                unsafe { (*self.table).extract_finish(loc) };
                return Some((entry.key, entry.value));
            }
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}

impl<K, V, P, F> FusedIterator for ExtractIf<'_, K, V, P, F>
where
    P: TableBackend<K, V>,
    F: FnMut(&K, &mut V) -> bool,
{
}

impl<K, V, P: TableBackend<K, V>, F> Drop for ExtractIf<'_, K, V, P, F> {
    fn drop(&mut self) {
        if !self.finished {
            // SAFETY: the iterator still owns the map's exclusive borrow.
            unsafe { (*self.table).finish_deferred_removals() };
        }
    }
}

/// Iterator over `&K`.
pub(crate) type Keys<'a, K, V, P> = CommonKeys<Iter<'a, K, V, P>>;
/// Iterator over `&V`.
pub(crate) type Values<'a, K, V, P> = CommonValues<Iter<'a, K, V, P>>;
/// Iterator over `&mut V`.
pub(crate) type ValuesMut<'a, K, V, P> = CommonValues<IterMut<'a, K, V, P>>;
/// Consuming iterator over owned keys.
pub(crate) type IntoKeys<K, V, P> = CommonIntoKeys<IntoIter<K, V, P>>;
/// Consuming iterator over owned values.
pub(crate) type IntoValues<K, V, P> = CommonIntoValues<IntoIter<K, V, P>>;

// ---------------------------------------------------------------------------
// Trait impls
// ---------------------------------------------------------------------------

#[cfg(feature = "default-hasher")]
impl<K, V, P> Default for HashMap<K, V, P>
where
    P: TableBackend<K, V, Hasher = DefaultHashBuilder, Alloc = Global>,
{
    fn default() -> Self {
        Self::with_capacity(0)
    }
}

impl<K, V, P> Clone for HashMap<K, V, P>
where
    K: Clone,
    V: Clone,
    P: TableBackend<K, V>,
    P::Hasher: Clone,
{
    fn clone(&self) -> Self {
        Self::from_table(self.table.clone_table())
    }
}

impl<K, V, P> fmt::Debug for HashMap<K, V, P>
where
    K: fmt::Debug,
    V: fmt::Debug,
    P: TableBackend<K, V>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<K, V, P> PartialEq for HashMap<K, V, P>
where
    K: Eq + Hash,
    V: PartialEq,
    P: TableBackend<K, V>,
{
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len()
            && self
                .iter()
                .all(|(k, v)| other.get(k).is_some_and(|ov| *v == *ov))
    }
}

impl<K, V, P> Eq for HashMap<K, V, P>
where
    K: Eq + Hash,
    V: Eq,
    P: TableBackend<K, V>,
{
}

impl<K, Q, V, P> Index<&Q> for HashMap<K, V, P>
where
    K: Eq + Hash,
    Q: Hash + Equivalent<K> + ?Sized,
    P: TableBackend<K, V>,
{
    type Output = V;
    fn index(&self, key: &Q) -> &V {
        self.get(key).expect("no entry found for key")
    }
}

impl<K, V, P> Extend<(K, V)> for HashMap<K, V, P>
where
    K: Eq + Hash,
    P: TableBackend<K, V>,
{
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        let iter = iter.into_iter();
        self.reserve(iter.size_hint().0);
        for (k, v) in iter {
            self.insert(k, v);
        }
    }
}

impl<'a, K, V, P> Extend<(&'a K, &'a V)> for HashMap<K, V, P>
where
    K: Eq + Hash + Copy,
    V: Copy,
    P: TableBackend<K, V>,
{
    fn extend<I: IntoIterator<Item = (&'a K, &'a V)>>(&mut self, iter: I) {
        self.extend(iter.into_iter().map(|(k, v)| (*k, *v)));
    }
}

impl<'a, K, V, P> Extend<&'a (K, V)> for HashMap<K, V, P>
where
    K: Eq + Hash + Copy,
    V: Copy,
    P: TableBackend<K, V>,
{
    fn extend<I: IntoIterator<Item = &'a (K, V)>>(&mut self, iter: I) {
        self.extend(iter.into_iter().map(|(k, v)| (*k, *v)));
    }
}

#[cfg(feature = "default-hasher")]
impl<K, V, P> FromIterator<(K, V)> for HashMap<K, V, P>
where
    K: Eq + Hash,
    P: TableBackend<K, V, Hasher = DefaultHashBuilder, Alloc = Global>,
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let iter = iter.into_iter();
        let mut map = Self::with_capacity(iter.size_hint().0);
        map.extend(iter);
        map
    }
}

impl<'a, K, V, P: TableBackend<K, V>> IntoIterator for &'a HashMap<K, V, P> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V, P>;
    fn into_iter(self) -> Iter<'a, K, V, P> {
        self.iter()
    }
}

impl<'a, K, V, P: TableBackend<K, V>> IntoIterator for &'a mut HashMap<K, V, P> {
    type Item = (&'a K, &'a mut V);
    type IntoIter = IterMut<'a, K, V, P>;
    fn into_iter(self) -> IterMut<'a, K, V, P> {
        self.iter_mut()
    }
}

impl<K, V, P: TableBackend<K, V>> IntoIterator for HashMap<K, V, P> {
    type Item = (K, V);
    type IntoIter = IntoIter<K, V, P>;
    fn into_iter(self) -> IntoIter<K, V, P> {
        let scan = self.table.scan();
        let remaining = self.table.len();
        IntoIter {
            table: self.table,
            scan,
            remaining,
        }
    }
}
