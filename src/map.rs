use core::error::Error;
use core::fmt;
use core::hash::{BuildHasher, Hash};
use core::iter::FusedIterator;
use core::marker::PhantomData;
use core::mem;
use core::ops::Index;

use allocator_api2::alloc::{Allocator, Global};
use equivalent::Equivalent;

use crate::ReserveFraction;
use crate::capacity;
use crate::epoch::EpochSnapshot;
use crate::error::{TryBuildError, TryReserveError};
#[cfg(feature = "default-hasher")]
use crate::hasher::DefaultHashBuilder;
use crate::raw::arena::{self, SlotEntry};
use crate::raw::config::INITIAL_CAPACITY;

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
    /// State from an absent entry search. Only pass it back to the same table
    /// for the same key/hash, with no intervening structural mutation. The
    /// entry's exclusive borrow enforces this; insertion must invalidate any
    /// geometry-dependent state if it grows the table itself.
    type Vacant;
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

    /// Find the slot for `key` by precomputed hash; the
    /// location is valid per [`Location`](TableBackend::Location).
    fn find<Q>(&self, key: &Q, hash: u64) -> Option<Self::Location>
    where
        Q: Hash + Equivalent<K> + ?Sized;

    /// Find and borrow the occupied slot for `key` by precomputed hash.
    /// Returning the slot reference formed during key comparison
    /// avoids a second location-to-slot dispatch on read hits. The shared
    /// borrow of `self` blocks structural mutation while the reference lives.
    fn find_entry<'a, Q>(&'a self, key: &Q, hash: u64) -> Option<&'a SlotEntry<K, V>>
    where
        Q: Hash + Equivalent<K> + ?Sized;

    // -- Insert / remove --

    /// Find an entry, preserving reusable insertion state on absence.
    fn find_for_entry<Q>(&self, key: &Q, hash: u64) -> Result<Self::Location, Self::Vacant>
    where
        Q: Hash + Equivalent<K> + ?Sized;

    /// Insert a known-absent key using its search state, resize as needed, and
    /// return its location (valid per [`Location`](TableBackend::Location)).
    fn insert_for_vacant(&mut self, key: K, value: V, vacant: Self::Vacant) -> Self::Location;

    /// Insert `key` → `value` and return the previous value.
    fn insert(&mut self, key: K, value: V, hash: u64) -> Option<V>
    where
        K: Hash + Eq;

    /// Remove the entry at `loc` (valid per [`Location`](TableBackend::Location)),
    /// update bookkeeping, and resize if needed.
    fn remove(&mut self, loc: Self::Location) -> (K, V);

    /// Move the next entry `scan` reaches out of the table and mark its slot
    /// a tombstone without updating counters, which leaves the table fit only
    /// for dropping. [`IntoIter`] uses it on a table it owns, so the table's
    /// `Drop` skips the slot.
    ///
    /// # Safety
    ///
    /// `scan` came from [`scan`](TableBackend::scan) on this table and has
    /// stepped only this table, which has seen no insertion or resize since.
    unsafe fn take_next(&mut self, scan: &mut Self::Scan) -> Option<SlotEntry<K, V>>;

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

    // -- Drain: detach the storage, move entries out, put it back empty --

    /// The entries and their allocation, apart from the hash builder and the
    /// allocator. Dropping it frees nothing; only
    /// [`restore_storage`](TableBackend::restore_storage) gives the allocation
    /// back to a table. The default owns no allocation.
    type Storage: Default;

    /// Detach the storage and start a `Clear` epoch, leaving a valid empty
    /// table that owns no allocation. A [`Scan`](TableBackend::Scan) created
    /// just before, and the locations it yields, carry over to the storage.
    fn take_storage(&mut self) -> Self::Storage;

    /// [`scan_next`](TableBackend::scan_next) over detached storage.
    fn storage_scan_next(
        storage: &Self::Storage,
        scan: &mut Self::Scan,
    ) -> Option<(*mut SlotEntry<K, V>, Self::Location)>;

    /// [`take_next`](TableBackend::take_next) over detached storage, so
    /// [`drop_storage_values`](TableBackend::drop_storage_values) skips the
    /// slot.
    ///
    /// # Safety
    ///
    /// `scan` carried over to `storage` per
    /// [`take_storage`](TableBackend::take_storage) and has stepped only it.
    unsafe fn storage_take_next(
        storage: &mut Self::Storage,
        scan: &mut Self::Scan,
    ) -> Option<SlotEntry<K, V>>;

    /// Folds the entries [`storage_take_next`](TableBackend::storage_take_next)
    /// would yield from here on, leaving `scan` exhausted. A backend
    /// overrides it where one pass beats repeated single steps.
    ///
    /// # Safety
    ///
    /// As for [`storage_take_next`](TableBackend::storage_take_next).
    #[inline]
    unsafe fn storage_take_fold<B>(
        storage: &mut Self::Storage,
        scan: &mut Self::Scan,
        init: B,
        mut f: impl FnMut(B, (K, V)) -> B,
    ) -> B {
        let mut acc = init;
        // SAFETY: the caller's contract is this call's.
        while let Some(entry) = unsafe { Self::storage_take_next(storage, scan) } {
            acc = f(acc, (entry.key, entry.value));
        }
        acc
    }

    /// Drop every entry still in `storage`. Like dropping a slice, a panicking
    /// `Drop` does not stop the walk; a second panic aborts.
    fn drop_storage_values(storage: &mut Self::Storage);

    /// Put back the storage [`take_storage`](TableBackend::take_storage)
    /// detached from this table, reset to empty with its allocation kept. No
    /// entry is dropped, so the caller must have moved out or dropped them
    /// all. `storage` receives the empty storage the table held meanwhile.
    /// Runs no user code and cannot panic.
    fn restore_storage(&mut self, storage: &mut Self::Storage);

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
    fn try_resize(&mut self, new_capacity: usize) -> Result<(), TryReserveError>;

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
    fn try_reserve(&mut self, additional: usize) -> Result<(), TryReserveError> {
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

    /// Clone storage, hash builder, allocator, and entries.
    fn clone_table(&self) -> Self
    where
        K: Clone,
        V: Clone,
        Self::Hasher: Clone;
}

/// Use a table backend to store key-value pairs.
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
    #[deprecated(
        since = "0.12.0",
        note = "convert with `ReserveFraction::try_from` and call `with_capacity_and_reserve_and_hasher_in`"
    )]
    #[allow(deprecated)]
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
        .expect("invalid map construction")
    }

    /// Fallible compatibility constructor accepting an exact dyadic `f64`.
    ///
    /// # Errors
    ///
    /// Returns [`TryBuildError::InvalidReserveFraction`] for non-dyadic input,
    /// or the backend construction error.
    #[deprecated(
        since = "0.12.0",
        note = "convert with `ReserveFraction::try_from` and call `try_with_capacity_and_reserve_and_hasher_in`"
    )]
    #[allow(deprecated)]
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
    #[must_use]
    pub fn allocator(&self) -> &P::Alloc {
        self.table.allocator()
    }

    /// Reference to the map's [`BuildHasher`].
    #[must_use]
    pub fn hasher(&self) -> &P::Hasher {
        self.table.hasher()
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.table.len() == 0
    }

    /// Maximum entries before the next automatic resize.
    #[must_use]
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
    ///
    /// # Panics
    ///
    /// Panics if the new capacity overflows `usize`.
    pub fn reserve(&mut self, additional: usize) {
        self.table.reserve(additional);
    }

    /// Fallible [`reserve`](Self::reserve).
    ///
    /// # Errors
    /// Returns [`TryReserveError`] on capacity overflow or allocator failure.
    pub fn try_reserve(&mut self, additional: usize) -> Result<(), TryReserveError> {
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
        self.table.find(key, hash)
    }

    /// Mutable reference to the slot at `loc`.
    ///
    /// # Safety
    /// `loc` must be live in this table, and the caller must uphold mutable
    /// aliasing rules for the returned slot.
    #[inline]
    #[allow(clippy::mut_from_ref)]
    unsafe fn slot_entry_mut(&self, loc: P::Location) -> &mut SlotEntry<K, V> {
        // SAFETY: caller passes a live `loc` and guarantees exclusive access.
        unsafe { &mut *self.table.slot_ptr(loc) }
    }

    #[inline]
    fn lookup_entry<Q>(&self, key: &Q) -> Option<&SlotEntry<K, V>>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let hash = self.table.hash(key);
        self.table.find_entry(key, hash)
    }

    /// Inserts `key`/`value`. Returns the previous value for `key`, if any.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let hash = self.table.hash(&key);
        self.table.insert(key, value, hash)
    }

    /// Returns a reference to the value for `key`.
    #[must_use]
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.lookup_entry(key).map(|entry| &entry.value)
    }

    /// Returns the stored `(key, value)` pair for `key`.
    #[must_use]
    pub fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let entry = self.lookup_entry(key)?;
        Some((&entry.key, &entry.value))
    }

    /// Returns the stored key equal to `key`, inserting `f(key)` (with `value`)
    /// if absent, in one hit-path probe. The `Copy` location from
    /// [`TableBackend::find_for_entry`] frees the borrow before the key ref is re-derived —
    /// the naive `get`-then-insert needs Polonius. Backs set `get_or_insert_with`.
    pub(crate) fn get_or_insert_key_with<Q, F>(&mut self, key: &Q, value: V, f: F) -> &K
    where
        Q: Hash + Equivalent<K> + ?Sized,
        F: FnOnce(&Q) -> K,
    {
        let hash = self.table.hash(key);
        let vacant = match self.table.find_for_entry(key, hash) {
            Ok(loc) => {
                // SAFETY: the search returned a live location from this table.
                return unsafe { &self.table.slot_ref(loc).key };
            }
            Err(vacant) => vacant,
        };
        let loc = self.table.insert_for_vacant(f(key), value, vacant);
        // SAFETY: `loc` was just inserted into this table.
        unsafe { &self.table.slot_ref(loc).key }
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
    #[must_use]
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

    /// Returns `N` disjoint mutable references, `None` for absent keys.
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
        let vacant = match self.table.find_for_entry(&key, hash) {
            Ok(loc) => {
                return Err(OccupiedError {
                    entry: OccupiedEntry { map: self, loc },
                    value,
                });
            }
            Err(vacant) => vacant,
        };
        let loc = self.table.insert_for_vacant(key, value, vacant);
        // SAFETY: `loc` was just inserted into this table.
        Ok(unsafe { &mut self.slot_entry_mut(loc).value })
    }

    /// Gets the [`Entry`] for `key` for in-place manipulation.
    pub fn entry(&mut self, key: K) -> Entry<'_, K, V, P> {
        let hash = self.table.hash(&key);
        match self.table.find_for_entry(&key, hash) {
            Ok(loc) => Entry::Occupied(OccupiedEntry { map: self, loc }),
            Err(vacant) => Entry::Vacant(VacantEntry {
                map: self,
                key,
                vacant,
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
}

/// View of a vacant entry.
pub struct VacantEntry<'a, K, V, P: TableBackend<K, V>> {
    map: &'a mut HashMap<K, V, P>,
    key: K,
    vacant: P::Vacant,
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

impl<K, V, P> fmt::Debug for OccupiedEntry<'_, K, V, P>
where
    K: Eq + Hash + fmt::Debug,
    V: fmt::Debug,
    P: TableBackend<K, V>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OccupiedEntry")
            .field("key", self.key())
            .field("value", self.get())
            .finish()
    }
}

impl<K, V, P> fmt::Debug for VacantEntry<'_, K, V, P>
where
    K: Eq + Hash + fmt::Debug,
    P: TableBackend<K, V>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("VacantEntry").field(self.key()).finish()
    }
}

impl<K, V, P> fmt::Debug for Entry<'_, K, V, P>
where
    K: Eq + Hash + fmt::Debug,
    V: fmt::Debug,
    P: TableBackend<K, V>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Entry::Occupied(entry) => f.debug_tuple("Entry").field(entry).finish(),
            Entry::Vacant(entry) => f.debug_tuple("Entry").field(entry).finish(),
        }
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
        unsafe { &self.map.table.slot_ref(self.loc).key }
    }

    /// Reference to the entry's value.
    #[must_use]
    pub fn get(&self) -> &V {
        // SAFETY: occupied entries store a live location from this table.
        unsafe { &self.map.table.slot_ref(self.loc).value }
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
        unsafe { &self.map.table.slot_ref(self.loc).key }
    }

    /// Replaces the value, returning the old one.
    pub fn insert(&mut self, value: V) -> V {
        self.map.table.replace_value(self.loc, value)
    }

    /// Removes the entry and returns its value.
    pub fn remove(self) -> V {
        self.remove_entry().1
    }

    /// Removes the entry and returns the `(key, value)` pair.
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
    #[must_use]
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
        self.insert_entry(value).into_mut()
    }

    /// Inserts `value` and returns the resulting [`OccupiedEntry`].
    pub fn insert_entry(self, value: V) -> OccupiedEntry<'a, K, V, P> {
        let loc = self
            .map
            .table
            .insert_for_vacant(self.key, value, self.vacant);
        OccupiedEntry { map: self.map, loc }
    }
}

impl<'a, K, V, P> Entry<'a, K, V, P>
where
    K: Eq + Hash,
    P: TableBackend<K, V>,
{
    /// Returns `&mut V`, inserting `default` if vacant.
    pub fn or_insert(self, default: V) -> &'a mut V {
        self.or_insert_with_key(|_| default)
    }

    /// Like [`or_insert`](Self::or_insert) with a lazily-computed default.
    pub fn or_insert_with<F: FnOnce() -> V>(self, default: F) -> &'a mut V {
        self.or_insert_with_key(|_| default())
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
    #[must_use]
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
        self.or_insert_with_key(|_| V::default())
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
        Self::with_capacity_and_hasher(capacity, DefaultHashBuilder::default())
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
        Self::try_with_capacity_and_reserve(capacity, reserve).expect("invalid map construction")
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
    #[deprecated(
        since = "0.12.0",
        note = "convert with `ReserveFraction::try_from` and call `with_reserve`"
    )]
    #[allow(deprecated)]
    pub fn with_reserve_fraction(reserve_fraction: f64) -> Self {
        Self::with_capacity_and_reserve_fraction(0, reserve_fraction)
    }

    /// Compatibility constructor for capacity and an exact dyadic `f64` reserve.
    ///
    /// # Panics
    /// Panics for non-dyadic input, unsupported reserve, or construction failure.
    #[must_use]
    #[deprecated(
        since = "0.12.0",
        note = "convert with `ReserveFraction::try_from` and call `with_capacity_and_reserve`"
    )]
    #[allow(deprecated)]
    pub fn with_capacity_and_reserve_fraction(capacity: usize, reserve_fraction: f64) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher(
            capacity,
            reserve_fraction,
            DefaultHashBuilder::default(),
        )
    }

    /// Fallible compatibility constructor for an exact dyadic `f64` reserve.
    ///
    /// # Errors
    ///
    /// Returns [`TryBuildError`] for invalid input or construction failure.
    #[deprecated(
        since = "0.12.0",
        note = "convert with `ReserveFraction::try_from` and call `try_with_capacity_and_reserve`"
    )]
    #[allow(deprecated)]
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
        Self::with_capacity_and_hasher(0, hash_builder)
    }

    /// Creates an empty map with the given capacity and hasher.
    #[must_use]
    pub fn with_capacity_and_hasher(capacity: usize, hash_builder: P::Hasher) -> Self {
        Self::with_capacity_and_reserve_and_hasher(capacity, ReserveFraction::DEFAULT, hash_builder)
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
    #[deprecated(
        since = "0.12.0",
        note = "convert with `ReserveFraction::try_from` and call `with_capacity_and_reserve_and_hasher`"
    )]
    #[allow(deprecated)]
    pub fn with_reserve_fraction_and_hasher(
        reserve_fraction: f64,
        hash_builder: P::Hasher,
    ) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher(0, reserve_fraction, hash_builder)
    }

    /// Compatibility constructor for capacity, exact dyadic reserve, and hasher.
    ///
    /// # Panics
    /// Panics for non-dyadic input, unsupported reserve, or construction failure.
    #[must_use]
    #[deprecated(
        since = "0.12.0",
        note = "convert with `ReserveFraction::try_from` and call `with_capacity_and_reserve_and_hasher`"
    )]
    #[allow(deprecated)]
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
        Self::with_capacity_in(0, alloc)
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
            table: TableBorrow::new(&mut self.table),
            scan,
            remaining,
            _marker: PhantomData,
        }
    }

    /// Iterator over `&K`.
    pub fn keys(&self) -> Keys<'_, K, V, P> {
        Keys { inner: self.iter() }
    }

    /// Iterator over `&V`.
    pub fn values(&self) -> Values<'_, K, V, P> {
        Values { inner: self.iter() }
    }

    /// Iterator over `&mut V`.
    pub fn values_mut(&mut self) -> ValuesMut<'_, K, V, P> {
        ValuesMut {
            inner: self.iter_mut(),
        }
    }

    /// Consuming iterator over owned keys.
    pub fn into_keys(self) -> IntoKeys<K, V, P> {
        IntoKeys {
            inner: self.into_iter(),
        }
    }

    /// Consuming iterator over owned values.
    pub fn into_values(self) -> IntoValues<K, V, P> {
        IntoValues {
            inner: self.into_iter(),
        }
    }

    /// Clears the map, returning every entry as an iterator. Keeps the
    /// allocated memory for reuse.
    ///
    /// The map is empty as soon as this returns. Dropping the iterator drops
    /// the entries it has not yielded and gives the allocation back to the
    /// map. Leaking the iterator (for example with
    /// [`mem::forget`](core::mem::forget)) leaks those entries and the
    /// allocation, and leaves the map empty and usable.
    pub fn drain(&mut self) -> Drain<'_, K, V, P> {
        let scan = self.table.scan();
        let remaining = self.table.len();
        let storage = self.table.take_storage();
        Drain {
            table: &mut self.table,
            storage,
            scan,
            remaining,
        }
    }

    /// Removes and yields the entries for which `f` returns `true`.
    pub fn extract_if<F>(&mut self, f: F) -> ExtractIf<'_, K, V, P, F>
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        ExtractIf {
            scan: ExtractScan::new(self),
            pred: f,
        }
    }
}

// ---------------------------------------------------------------------------
// Iterators
// ---------------------------------------------------------------------------

/// Implement `ExactSizeIterator` (from the `remaining` counter) and
/// `FusedIterator` for scanning iterators whose `next` decrements `remaining`
/// once per yielded entry.
macro_rules! exact_scan_iters {
    ($($name:ident<$($gen:tt),*>),* $(,)?) => {
        $(
            impl<K, V, P: TableBackend<K, V>> ExactSizeIterator for $name<$($gen),*> {
                fn len(&self) -> usize {
                    self.remaining
                }
            }
            impl<K, V, P: TableBackend<K, V>> FusedIterator for $name<$($gen),*> {}
        )*
    };
}

exact_scan_iters! {
    Iter<'_, K, V, P>,
    IterMut<'_, K, V, P>,
    IntoIter<K, V, P>,
    Drain<'_, K, V, P>,
}

/// Borrowing iterator over `(&K, &V)`.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Iter<'a, K, V, P: TableBackend<K, V>> {
    table: &'a P,
    scan: P::Scan,
    remaining: usize,
    _marker: PhantomData<(&'a K, &'a V)>,
}

impl<'a, K, V, P> Iter<'a, K, V, P>
where
    P: TableBackend<K, V>,
    P::Scan: Clone,
{
    fn view(&self) -> Self {
        self.clone()
    }

    /// Shared view of the entries another iterator has yet to yield.
    fn remaining(table: &'a P, scan: &P::Scan, remaining: usize) -> Self {
        Self {
            table,
            scan: scan.clone(),
            remaining,
            _marker: PhantomData,
        }
    }
}

/// Exclusive table borrow kept as a raw pointer, so an iterator can hand out
/// `&mut` slots while `&self` methods still read the table.
struct TableBorrow<'a, P> {
    ptr: *mut P,
    _marker: PhantomData<&'a mut P>,
}

impl<'a, P> TableBorrow<'a, P> {
    fn new(table: &'a mut P) -> Self {
        Self {
            ptr: core::ptr::from_mut(table),
            _marker: PhantomData,
        }
    }

    fn as_ptr(&self) -> *mut P {
        self.ptr
    }
}

// SAFETY: built only from a `&'a mut P` and used in its place, so it may be
// sent exactly when that borrow may.
unsafe impl<P: Send> Send for TableBorrow<'_, P> {}

// SAFETY: as above, for sharing.
unsafe impl<P: Sync> Sync for TableBorrow<'_, P> {}

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
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct IterMut<'a, K, V, P: TableBackend<K, V>> {
    table: TableBorrow<'a, P>,
    scan: P::Scan,
    remaining: usize,
    _marker: PhantomData<(&'a K, &'a mut V)>,
}

impl<'a, K, V, P: TableBackend<K, V>> Iterator for IterMut<'a, K, V, P> {
    type Item = (&'a K, &'a mut V);
    fn next(&mut self) -> Option<(&'a K, &'a mut V)> {
        // SAFETY: `table` points to the borrowed map; `scan_next` yields each
        // location at most once, so the `&'a mut` references are disjoint.
        let table = unsafe { &*self.table.as_ptr() };
        let (ptr, _loc) = table.scan_next(&mut self.scan)?;
        self.remaining -= 1;
        // SAFETY: as above; `ptr` is a live slot yielded once under the `&'a mut`
        // map borrow.
        let slot: &'a mut SlotEntry<K, V> = unsafe { &mut *ptr };
        Some((&slot.key, &mut slot.value))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K: fmt::Debug, V: fmt::Debug, P> fmt::Debug for IterMut<'_, K, V, P>
where
    P: TableBackend<K, V>,
    P::Scan: Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.view()).finish()
    }
}

impl<K, V, P> IterMut<'_, K, V, P>
where
    P: TableBackend<K, V>,
    P::Scan: Clone,
{
    /// Shared view of the entries not yet yielded.
    pub(crate) fn view(&self) -> Iter<'_, K, V, P> {
        // SAFETY: `&self` blocks `next`, and the cloned scan visits only
        // slots not yet yielded, so these shared borrows alias no handed-out
        // `&mut V`.
        let table = unsafe { &*self.table.as_ptr() };
        Iter::remaining(table, &self.scan, self.remaining)
    }
}

/// Consuming iterator over owned `(K, V)`.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct IntoIter<K, V, P: TableBackend<K, V>> {
    table: P,
    scan: P::Scan,
    remaining: usize,
}

impl<K, V, P: TableBackend<K, V>> Iterator for IntoIter<K, V, P> {
    type Item = (K, V);
    fn next(&mut self) -> Option<(K, V)> {
        // SAFETY: `scan` was made from `table` when this iterator took
        // ownership of it, and nothing else steps the scan or touches the
        // table.
        let entry = unsafe { self.table.take_next(&mut self.scan) }?;
        self.remaining -= 1;
        Some((entry.key, entry.value))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K: fmt::Debug, V: fmt::Debug, P> fmt::Debug for IntoIter<K, V, P>
where
    P: TableBackend<K, V>,
    P::Scan: Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.view()).finish()
    }
}

impl<K, V, P> IntoIter<K, V, P>
where
    P: TableBackend<K, V>,
    P::Scan: Clone,
{
    /// Shared view of the entries not yet yielded.
    pub(crate) fn view(&self) -> Iter<'_, K, V, P> {
        Iter::remaining(&self.table, &self.scan, self.remaining)
    }
}

/// Draining iterator over owned `(K, V)`. Owns the storage it took from the
/// map, which stays empty until the iterator is dropped and hands the
/// allocation back.
pub struct Drain<'a, K, V, P: TableBackend<K, V>> {
    table: &'a mut P,
    storage: P::Storage,
    scan: P::Scan,
    remaining: usize,
}

impl<K, V, P: TableBackend<K, V>> Iterator for Drain<'_, K, V, P> {
    type Item = (K, V);
    fn next(&mut self) -> Option<(K, V)> {
        // SAFETY: `drain` made `scan` just before detaching `storage`, and
        // both are private to this iterator.
        let entry = unsafe { P::storage_take_next(&mut self.storage, &mut self.scan) }?;
        self.remaining -= 1;
        Some((entry.key, entry.value))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
    fn fold<B, F>(mut self, init: B, f: F) -> B
    where
        F: FnMut(B, (K, V)) -> B,
    {
        // SAFETY: as in `next`.
        let acc = unsafe { P::storage_take_fold(&mut self.storage, &mut self.scan, init, f) };
        // Reached only when `f` did not unwind, so no value is left to drop.
        self.remaining = 0;
        acc
    }
}

impl<K, V, P: TableBackend<K, V>> Drop for Drain<'_, K, V, P> {
    fn drop(&mut self) {
        /// Puts the storage back when dropped, so the map regains its
        /// allocation even if a value's `Drop` unwinds.
        struct Restore<'a, K, V, P: TableBackend<K, V>> {
            table: &'a mut P,
            storage: &'a mut P::Storage,
        }

        impl<K, V, P: TableBackend<K, V>> Drop for Restore<'_, K, V, P> {
            fn drop(&mut self) {
                // Moved to a slot of its own first: a pointer into the
                // `Drain` would expose every field to the call and keep the
                // scan state in memory throughout the caller's loop.
                let mut storage = mem::take(self.storage);
                restore(self.table, &mut storage);
            }
        }

        /// Out of line so the drop glue stays small enough to inline into
        /// the caller's loop.
        #[inline(never)]
        fn restore<K, V, P: TableBackend<K, V>>(table: &mut P, storage: &mut P::Storage) {
            table.restore_storage(storage);
        }

        let restore = Restore {
            table: &mut *self.table,
            storage: &mut self.storage,
        };
        if self.remaining != 0 {
            P::drop_storage_values(restore.storage);
        }
    }
}

impl<K: fmt::Debug, V: fmt::Debug, P> fmt::Debug for Drain<'_, K, V, P>
where
    P: TableBackend<K, V>,
    P::Scan: Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.view()).finish()
    }
}

impl<K, V, P> Drain<'_, K, V, P>
where
    P: TableBackend<K, V>,
    P::Scan: Clone,
{
    /// Shared view of the entries not yet moved out.
    pub(crate) fn view(&self) -> impl Iterator<Item = (&K, &V)> {
        let mut scan = self.scan.clone();
        core::iter::from_fn(move || {
            let (ptr, _loc) = P::storage_scan_next(&self.storage, &mut scan)?;
            // SAFETY: `ptr` is a live slot of the storage `&self` borrows; the
            // cloned scan visits only slots not yet moved out.
            let slot = unsafe { &*ptr };
            Some((&slot.key, &slot.value))
        })
    }
}

/// Iterator yielding entries removed by [`HashMap::extract_if`]. Unyielded
/// non-matching entries are retained. Exhausting or dropping the iterator may
/// clean accumulated tombstones.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct ExtractIf<'a, K, V, P: TableBackend<K, V>, F> {
    scan: ExtractScan<'a, K, V, P>,
    pred: F,
}

impl<K, V, P, F> Iterator for ExtractIf<'_, K, V, P, F>
where
    P: TableBackend<K, V>,
    F: FnMut(&K, &mut V) -> bool,
{
    type Item = (K, V);
    fn next(&mut self) -> Option<(K, V)> {
        self.scan.next_matching(&mut self.pred)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}

/// Removal scan behind map and set `ExtractIf`. Holds the map's exclusive
/// borrow and finishes deferred cleanup once exhausted or dropped.
///
/// Every removal is counted as it happens; the deferred cleanup only reclaims
/// tombstones, so the map is consistent without it. Cleanup may hash keys and
/// allocate, so a scan the predicate is unwinding out of skips it rather than
/// risk a second panic.
pub(crate) struct ExtractScan<'a, K, V, P: TableBackend<K, V>> {
    table: TableBorrow<'a, P>,
    scan: P::Scan,
    state: ExtractState,
    _marker: PhantomData<&'a mut HashMap<K, V, P>>,
}

/// Where an [`ExtractScan`] stands. One field, so dropping the scan decides
/// on cleanup with a single comparison.
#[derive(Clone, Copy, Eq, PartialEq)]
enum ExtractState {
    /// Between predicate calls, with cleanup still owed.
    Scanning,
    /// Inside a predicate call. A scan dropped in this state is being
    /// unwound by the predicate; the next call that returns leaves it.
    InPredicate,
    /// Exhausted; cleanup has run.
    Finished,
}

impl<'a, K, V, P: TableBackend<K, V>> ExtractScan<'a, K, V, P> {
    pub(crate) fn new(map: &'a mut HashMap<K, V, P>) -> Self {
        let scan = map.table.scan();
        Self {
            table: TableBorrow::new(&mut map.table),
            scan,
            state: ExtractState::Scanning,
            _marker: PhantomData,
        }
    }

    /// Removes and returns the next entry `pred` accepts.
    #[inline]
    pub(crate) fn next_matching(
        &mut self,
        mut pred: impl FnMut(&K, &mut V) -> bool,
    ) -> Option<(K, V)> {
        if self.state == ExtractState::Finished {
            return None;
        }
        loop {
            // SAFETY: `table` points to the borrowed map for the iterator's life.
            let Some((ptr, loc)) = (unsafe { (*self.table.as_ptr()).scan_next(&mut self.scan) })
            else {
                self.state = ExtractState::Finished;
                // SAFETY: the scan is exhausted and the iterator still owns the
                // map's exclusive borrow, so a same-size cleanup is now safe.
                unsafe { (*self.table.as_ptr()).finish_deferred_removals() };
                return None;
            };
            // SAFETY: live slot; exclusive via the `&mut` map borrow.
            let slot = unsafe { &mut *ptr };
            self.state = ExtractState::InPredicate;
            let matched = pred(&slot.key, &mut slot.value);
            self.state = ExtractState::Scanning;
            if matched {
                // SAFETY: matched — read the entry out, then finalize removal
                // (tombstone + counters; the map keeps being used).
                let entry = unsafe { core::ptr::read(ptr) };
                // SAFETY: `table` is exclusively borrowed; `slot` is dead, and `loc`
                // is still valid since the predicate cannot mutate the map.
                unsafe { (*self.table.as_ptr()).extract_finish(loc) };
                return Some((entry.key, entry.value));
            }
        }
    }
}

impl<K, V, P: TableBackend<K, V>, F> fmt::Debug for ExtractIf<'_, K, V, P, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtractIf").finish_non_exhaustive()
    }
}

impl<K, V, P, F> FusedIterator for ExtractIf<'_, K, V, P, F>
where
    P: TableBackend<K, V>,
    F: FnMut(&K, &mut V) -> bool,
{
}

impl<K, V, P: TableBackend<K, V>> Drop for ExtractScan<'_, K, V, P> {
    fn drop(&mut self) {
        if self.state == ExtractState::Scanning {
            // SAFETY: the iterator still owns the map's exclusive borrow.
            unsafe { (*self.table.as_ptr()).finish_deferred_removals() };
        }
    }
}

/// Generate a projection iterator over one of the `(K, V)` scanning iterators.
///
/// Each type maps every inner item through `$project`, forwards `size_hint`,
/// and inherits the inner `ExactSizeIterator` and `FusedIterator`. `Debug`
/// lists the projection of the not-yet-yielded entries. A trailing `clone`
/// derives `Clone` from the inner borrowing iterator.
macro_rules! project_iter {
    (
        $(#[$attr:meta])*
        $name:ident$(<$lt:lifetime>)?($inner:ident) => $item:ty, debug($shown:ident),
        |($k:pat_param, $v:pat_param)| $project:expr $(, $flag:ident)?
    ) => {
        $(#[$attr])*
        #[must_use = "iterators are lazy and do nothing unless consumed"]
        pub struct $name<$($lt,)? K, V, P: TableBackend<K, V>> {
            inner: $inner<$($lt,)? K, V, P>,
        }

        impl<$($lt,)? K, V, P: TableBackend<K, V>> Iterator for $name<$($lt,)? K, V, P> {
            type Item = $item;
            #[inline]
            fn next(&mut self) -> Option<$item> {
                self.inner.next().map(|($k, $v)| $project)
            }
            #[inline]
            fn size_hint(&self) -> (usize, Option<usize>) {
                self.inner.size_hint()
            }
        }

        impl<$($lt,)? K, V, P: TableBackend<K, V>> ExactSizeIterator for $name<$($lt,)? K, V, P> {
            fn len(&self) -> usize {
                self.inner.len()
            }
        }

        impl<$($lt,)? K, V, P: TableBackend<K, V>> FusedIterator for $name<$($lt,)? K, V, P> {}

        impl<$($lt,)? K, V, P> fmt::Debug for $name<$($lt,)? K, V, P>
        where
            $shown: fmt::Debug,
            P: TableBackend<K, V>,
            P::Scan: Clone,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list()
                    .entries(self.inner.view().map(|($k, $v)| $project))
                    .finish()
            }
        }

        $(project_iter!(@$flag $name);)?
    };
    (@clone $name:ident) => {
        impl<K, V, P> Clone for $name<'_, K, V, P>
        where
            P: TableBackend<K, V>,
            P::Scan: Clone,
        {
            fn clone(&self) -> Self {
                Self {
                    inner: self.inner.clone(),
                }
            }
        }
    };
}

project_iter! {
    /// Iterator over `&K`.
    Keys<'a>(Iter) => &'a K, debug(K), |(k, _)| k, clone
}

project_iter! {
    /// Iterator over `&V`.
    Values<'a>(Iter) => &'a V, debug(V), |(_, v)| v, clone
}

project_iter! {
    /// Iterator over `&mut V`.
    ValuesMut<'a>(IterMut) => &'a mut V, debug(V), |(_, v)| v
}

project_iter! {
    /// Consuming iterator over owned keys.
    IntoKeys(IntoIter) => K, debug(K), |(k, _)| k
}

project_iter! {
    /// Consuming iterator over owned values.
    IntoValues(IntoIter) => V, debug(V), |(_, v)| v
}

// ---------------------------------------------------------------------------
// Trait impls
// ---------------------------------------------------------------------------

impl<K, V, P> Default for HashMap<K, V, P>
where
    P: TableBackend<K, V, Alloc = Global>,
    P::Hasher: Default,
{
    fn default() -> Self {
        Self::with_hasher(P::Hasher::default())
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

    /// Returns the value for `key`.
    ///
    /// # Panics
    ///
    /// Panics if `key` is not present.
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

impl<K, V, P> FromIterator<(K, V)> for HashMap<K, V, P>
where
    K: Eq + Hash,
    P: TableBackend<K, V, Alloc = Global>,
    P::Hasher: Default,
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let iter = iter.into_iter();
        let mut map = Self::with_capacity_and_hasher(iter.size_hint().0, P::Hasher::default());
        map.extend(iter);
        map
    }
}

impl<K, V, P, const N: usize> From<[(K, V); N]> for HashMap<K, V, P>
where
    K: Eq + Hash,
    P: TableBackend<K, V, Alloc = Global>,
    P::Hasher: Default,
{
    fn from(arr: [(K, V); N]) -> Self {
        arr.into_iter().collect()
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
