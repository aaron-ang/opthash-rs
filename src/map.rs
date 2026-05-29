//! Generic hash-map shell shared by the [`ElasticHashMap`](crate::ElasticHashMap)
//! and [`FunnelHashMap`](crate::FunnelHashMap) backends.
//!
//! [`HashMap`] is a thin wrapper that owns a [`RawTable`] implementation and
//! layers the public map API — lookup/insert/remove, the entry API, iterators,
//! and trait impls — on top of a small set of backend primitives. The backends
//! ([`crate::elastic`], [`crate::funnel`]) own all storage, hashing, and the
//! probing algorithm; this module owns everything that is identical between them.

use std::fmt;
use std::hash::{BuildHasher, Hash};
use std::iter::FusedIterator;
use std::marker::PhantomData;
use std::ops::Index;

use allocator_api2::alloc::{Allocator, Global};
use equivalent::Equivalent;

use crate::common::DefaultHashBuilder;
use crate::common::arena::SlotEntry;
use crate::common::config::DEFAULT_RESERVE_FRACTION;
use crate::common::control;
use crate::common::error::{EntryView, OccupiedError as CommonOccupiedError, TryReserveError};
use crate::common::iter::{
    IntoKeys as CommonIntoKeys, IntoValues as CommonIntoValues, Keys as CommonKeys,
    Values as CommonValues,
};

/// Backend storage + probing primitives that [`HashMap`] builds its public API
/// on. Each implementor owns the slot storage, the hasher, and the allocator;
/// the map shell never touches raw slots except through these methods.
///
/// All `unsafe` accessors take a [`Location`](RawTable::Location) previously
/// returned by [`find`](RawTable::find) or an insert primitive; passing a stale
/// or out-of-range location is undefined behavior.
// `slot_ref`/`slot_ptr` traffic in the crate-private `SlotEntry`; this trait is
// an internal contract (the `map` module is private), so the leak is intended.
#[allow(private_interfaces)]
pub trait RawTable<K, V>: Sized {
    /// Opaque handle to an occupied slot (e.g. `(level, slot)` or a region enum).
    type Location: Copy + PartialEq;
    /// Hash builder type.
    type Hasher: BuildHasher;
    /// Allocator type.
    type Alloc: Allocator + Clone;
    /// Pointerless cursor over occupied slots in storage order. Holds only
    /// indices so the owning [`IntoIter`] can move the table without dangling.
    type Scan;

    /// Full constructor mirroring the public `with_capacity_*` family.
    fn with_capacity_and_reserve_fraction_and_hasher_in(
        capacity: usize,
        reserve_fraction: f64,
        hash_builder: Self::Hasher,
        alloc: Self::Alloc,
    ) -> Self;

    /// Reference to the hash builder.
    fn hasher(&self) -> &Self::Hasher;

    /// Hashes `key` with the table's hasher.
    fn hash<Q: Hash + ?Sized>(&self, key: &Q) -> u64 {
        self.hasher().hash_one(key)
    }

    /// Reference to the allocator.
    fn allocator(&self) -> &Self::Alloc;

    /// Number of live entries.
    fn len(&self) -> usize;

    /// Maximum entries before the next automatic resize (the public `capacity`).
    fn capacity(&self) -> usize;

    /// Ensures room for `additional` more entries.
    fn reserve(&mut self, additional: usize);

    /// Fallible [`reserve`](RawTable::reserve).
    fn try_reserve(&mut self, additional: usize) -> Result<(), TryReserveError>
    where
        Self::Hasher: Clone;

    /// Shrinks capacity toward `min_capacity`.
    fn shrink_to(&mut self, min_capacity: usize);

    /// Drops all entries, keeping allocation.
    fn clear(&mut self);

    /// Finds the slot for `key` (hash + fingerprint precomputed by the shell).
    fn find<Q>(&self, key: &Q, hash: u64, fingerprint: u8) -> Option<Self::Location>
    where
        Q: Hash + Equivalent<K> + ?Sized;

    /// Shared reference to the slot at `loc`.
    ///
    /// # Safety
    /// `loc` must be a live location from this table.
    unsafe fn slot_ref(&self, loc: Self::Location) -> &SlotEntry<K, V>;

    /// Raw pointer to the slot at `loc`. Takes `&self` (not `&mut`) and forms no
    /// intermediate reference to the owning region, so callers may derive
    /// disjoint `&mut` from distinct locations without aliasing.
    ///
    /// # Safety
    /// `loc` must be a live location from this table.
    unsafe fn slot_ptr(&self, loc: Self::Location) -> *mut SlotEntry<K, V>;

    /// Replaces the value at `loc`, returning the old one.
    fn replace_value(&mut self, loc: Self::Location, value: V) -> V;

    /// Inserts a known-absent key, resizing as needed. Returns its location.
    fn insert_for_vacant(&mut self, key: K, value: V, hash: u64) -> Self::Location;

    /// Removes the entry at `loc` (tombstone + bookkeeping + maybe resize).
    fn remove(&mut self, loc: Self::Location) -> (K, V);

    /// Removes the entry at `loc` without triggering a resize. Used by
    /// draining iterators that consolidate tombstones lazily.
    fn extract_at(&mut self, loc: Self::Location) -> (K, V);

    /// Fresh cursor positioned before the first occupied slot.
    fn scan(&self) -> Self::Scan;

    /// Advances `scan`, returning the next occupied location in storage order.
    /// Re-derives storage pointers from `&self` so `scan` stays pointerless.
    fn scan_next(&self, scan: &mut Self::Scan) -> Option<Self::Location>;

    /// Bulk-clears all control bytes and zeroes counters. Called by
    /// [`Drain::drop`] after the slots' values have been taken.
    fn wipe_all(&mut self);

    /// Deep-clones the table (storage + hasher + allocator).
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

/// A hash map backed by a [`RawTable`] implementation `R`.
pub struct HashMap<K, V, R: RawTable<K, V>> {
    table: R,
    _marker: PhantomData<(K, V)>,
}

impl<K, V, R: RawTable<K, V>> HashMap<K, V, R> {
    #[inline]
    fn from_table(table: R) -> Self {
        Self {
            table,
            _marker: PhantomData,
        }
    }

    /// Full constructor: capacity, reserve fraction, hasher, and allocator.
    #[must_use]
    pub fn with_capacity_and_reserve_fraction_and_hasher_in(
        capacity: usize,
        reserve_fraction: f64,
        hash_builder: R::Hasher,
        alloc: R::Alloc,
    ) -> Self {
        Self::from_table(R::with_capacity_and_reserve_fraction_and_hasher_in(
            capacity,
            reserve_fraction,
            hash_builder,
            alloc,
        ))
    }

    /// Reference to the map's allocator.
    pub fn allocator(&self) -> &R::Alloc {
        self.table.allocator()
    }

    /// Reference to the map's [`BuildHasher`].
    pub fn hasher(&self) -> &R::Hasher {
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
        R::Hasher: Clone,
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

impl<K, V, R> HashMap<K, V, R>
where
    K: Eq + Hash,
    R: RawTable<K, V>,
{
    /// Inserts `key`/`value`. Returns the previous value for `key`, if any.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let hash = self.table.hash(&key);
        let fp = fingerprint(hash);
        if let Some(loc) = self.table.find(&key, hash, fp) {
            return Some(self.table.replace_value(loc, value));
        }
        self.table.insert_for_vacant(key, value, hash);
        None
    }

    /// Returns a reference to the value for `key`.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let hash = self.table.hash(key);
        let loc = self.table.find(key, hash, fingerprint(hash))?;
        Some(unsafe { &self.table.slot_ref(loc).value })
    }

    /// Returns the stored `(key, value)` pair for `key`.
    pub fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let hash = self.table.hash(key);
        let loc = self.table.find(key, hash, fingerprint(hash))?;
        let entry = unsafe { self.table.slot_ref(loc) };
        Some((&entry.key, &entry.value))
    }

    /// Returns a mutable reference to the value for `key`.
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let hash = self.table.hash(key);
        let loc = self.table.find(key, hash, fingerprint(hash))?;
        // SAFETY: `loc` is live; `&mut self` proves exclusivity.
        Some(unsafe { &mut (*self.table.slot_ptr(loc)).value })
    }

    /// Returns `true` if `key` is present.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let hash = self.table.hash(key);
        self.table.find(key, hash, fingerprint(hash)).is_some()
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
        let hash = self.table.hash(key);
        let loc = self.table.find(key, hash, fingerprint(hash))?;
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
        crate::common::arena::check_disjoint_aliasing(&locations);
        std::array::from_fn(|i| {
            locations[i].map(|loc| {
                // SAFETY: locations are unique among the hits (asserted above),
                // and `slot_ptr` forms no intermediate region reference.
                unsafe { &mut (*self.table.slot_ptr(loc)).value }
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
        crate::common::arena::check_disjoint_aliasing(&locations);
        std::array::from_fn(|i| {
            locations[i].map(|loc| {
                // SAFETY: as in `get_disjoint_mut`.
                let slot = unsafe { &mut *self.table.slot_ptr(loc) };
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
        std::array::from_fn(|i| {
            locations[i].map(|loc|
                // SAFETY: caller guarantees the hits are pairwise distinct.
                unsafe { &mut (*self.table.slot_ptr(loc)).value })
        })
    }

    #[inline]
    fn locate_disjoint<Q, const N: usize>(&self, keys: [&Q; N]) -> [Option<R::Location>; N]
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        std::array::from_fn(|i| {
            let hash = self.table.hash(keys[i]);
            self.table.find(keys[i], hash, fingerprint(hash))
        })
    }

    /// Inserts `key`/`value` only if absent; otherwise returns an
    /// [`OccupiedError`] carrying the rejected value.
    ///
    /// # Errors
    /// [`OccupiedError`] when `key` is already present.
    pub fn try_insert(&mut self, key: K, value: V) -> Result<&mut V, OccupiedError<'_, K, V, R>> {
        let hash = self.table.hash(&key);
        let fp = fingerprint(hash);
        if let Some(loc) = self.table.find(&key, hash, fp) {
            return Err(CommonOccupiedError {
                entry: OccupiedEntry {
                    map: self,
                    loc,
                    _marker: PhantomData,
                },
                value,
            });
        }
        let loc = self.table.insert_for_vacant(key, value, hash);
        // SAFETY: just inserted; `&mut self` proves exclusivity.
        Ok(unsafe { &mut (*self.table.slot_ptr(loc)).value })
    }

    /// Gets the [`Entry`] for `key` for in-place manipulation.
    pub fn entry(&mut self, key: K) -> Entry<'_, K, V, R> {
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
pub enum Entry<'a, K, V, R: RawTable<K, V>> {
    /// Key present.
    Occupied(OccupiedEntry<'a, K, V, R>),
    /// Key absent.
    Vacant(VacantEntry<'a, K, V, R>),
}

/// View of an occupied entry.
pub struct OccupiedEntry<'a, K, V, R: RawTable<K, V>> {
    map: &'a mut HashMap<K, V, R>,
    loc: R::Location,
    _marker: PhantomData<K>,
}

/// View of a vacant entry.
pub struct VacantEntry<'a, K, V, R: RawTable<K, V>> {
    map: &'a mut HashMap<K, V, R>,
    key: K,
    hash: u64,
}

/// Error returned by [`HashMap::try_insert`] on key collision.
pub type OccupiedError<'a, K, V, R> = CommonOccupiedError<OccupiedEntry<'a, K, V, R>, V>;

impl<'a, K, V, R> OccupiedEntry<'a, K, V, R>
where
    K: Eq + Hash,
    R: RawTable<K, V>,
{
    /// Reference to the entry's key.
    #[must_use]
    pub fn key(&self) -> &K {
        unsafe { &self.map.table.slot_ref(self.loc).key }
    }

    /// Reference to the entry's value.
    #[must_use]
    pub fn get(&self) -> &V {
        unsafe { &self.map.table.slot_ref(self.loc).value }
    }

    /// Mutable reference to the value, tied to `self`.
    pub fn get_mut(&mut self) -> &mut V {
        // SAFETY: `loc` live; `&mut self` proves exclusivity.
        unsafe { &mut (*self.map.table.slot_ptr(self.loc)).value }
    }

    /// Consumes the entry, returning `&mut V` for the map's lifetime.
    #[must_use]
    pub fn into_mut(self) -> &'a mut V {
        // SAFETY: `loc` live; the consumed `&'a mut` map borrow proves exclusivity.
        unsafe { &mut (*self.map.table.slot_ptr(self.loc)).value }
    }

    /// Consumes the entry, returning `&K` for the map's lifetime.
    pub(crate) fn into_key(self) -> &'a K {
        // SAFETY: as in `into_mut`.
        unsafe { &(*self.map.table.slot_ptr(self.loc)).key }
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

impl<K, V, R> EntryView for OccupiedEntry<'_, K, V, R>
where
    K: Eq + Hash,
    R: RawTable<K, V>,
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

impl<'a, K, V, R> VacantEntry<'a, K, V, R>
where
    K: Eq + Hash,
    R: RawTable<K, V>,
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
        // SAFETY: just inserted; consumed `&'a mut` map borrow proves exclusivity.
        unsafe { &mut (*self.map.table.slot_ptr(loc)).value }
    }

    /// Inserts `value` and returns the resulting [`OccupiedEntry`].
    pub(crate) fn insert_entry(self, value: V) -> OccupiedEntry<'a, K, V, R> {
        let loc = self.map.table.insert_for_vacant(self.key, value, self.hash);
        OccupiedEntry {
            map: self.map,
            loc,
            _marker: PhantomData,
        }
    }
}

impl<'a, K, V, R> Entry<'a, K, V, R>
where
    K: Eq + Hash,
    R: RawTable<K, V>,
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

impl<'a, K, V, R> Entry<'a, K, V, R>
where
    K: Eq + Hash,
    R: RawTable<K, V>,
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

impl<K, V, R> HashMap<K, V, R>
where
    R: RawTable<K, V, Hasher = DefaultHashBuilder, Alloc = Global>,
{
    /// Creates an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    /// Creates an empty map with at least `capacity` slots.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            capacity,
            DEFAULT_RESERVE_FRACTION,
            DefaultHashBuilder::default(),
            Global,
        )
    }

    /// Creates an empty map with the given reserve fraction.
    #[must_use]
    pub fn with_reserve_fraction(reserve_fraction: f64) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            0,
            reserve_fraction,
            DefaultHashBuilder::default(),
            Global,
        )
    }

    /// Creates an empty map with the given capacity and reserve fraction.
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

impl<K, V, R> HashMap<K, V, R>
where
    R: RawTable<K, V, Alloc = Global>,
{
    /// Creates an empty map that uses `hash_builder`.
    #[must_use]
    pub fn with_hasher(hash_builder: R::Hasher) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            0,
            DEFAULT_RESERVE_FRACTION,
            hash_builder,
            Global,
        )
    }

    /// Creates an empty map with the given capacity and hasher.
    #[must_use]
    pub fn with_capacity_and_hasher(capacity: usize, hash_builder: R::Hasher) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            capacity,
            DEFAULT_RESERVE_FRACTION,
            hash_builder,
            Global,
        )
    }

    /// Creates an empty map with the given reserve fraction and hasher.
    #[must_use]
    pub fn with_reserve_fraction_and_hasher(
        reserve_fraction: f64,
        hash_builder: R::Hasher,
    ) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            0,
            reserve_fraction,
            hash_builder,
            Global,
        )
    }

    /// Creates an empty map with the given capacity, reserve fraction, and hasher.
    #[must_use]
    pub fn with_capacity_and_reserve_fraction_and_hasher(
        capacity: usize,
        reserve_fraction: f64,
        hash_builder: R::Hasher,
    ) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            capacity,
            reserve_fraction,
            hash_builder,
            Global,
        )
    }
}

impl<K, V, R> HashMap<K, V, R>
where
    R: RawTable<K, V, Hasher = DefaultHashBuilder>,
{
    /// Creates an empty map in the given allocator.
    #[must_use]
    pub fn new_in(alloc: R::Alloc) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            0,
            DEFAULT_RESERVE_FRACTION,
            DefaultHashBuilder::default(),
            alloc,
        )
    }

    /// Creates an empty map with the given capacity in the given allocator.
    #[must_use]
    pub fn with_capacity_in(capacity: usize, alloc: R::Alloc) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            capacity,
            DEFAULT_RESERVE_FRACTION,
            DefaultHashBuilder::default(),
            alloc,
        )
    }
}

// ---------------------------------------------------------------------------
// Iteration accessors
// ---------------------------------------------------------------------------

impl<K, V, R: RawTable<K, V>> HashMap<K, V, R> {
    /// Borrowing iterator over `(&K, &V)`, in arbitrary order.
    pub fn iter(&self) -> Iter<'_, K, V, R> {
        Iter {
            table: &self.table,
            scan: self.table.scan(),
            remaining: self.table.len(),
            _marker: PhantomData,
        }
    }

    /// Borrowing iterator over `(&K, &mut V)`.
    pub fn iter_mut(&mut self) -> IterMut<'_, K, V, R> {
        let scan = self.table.scan();
        let remaining = self.table.len();
        IterMut {
            table: std::ptr::from_mut(&mut self.table),
            scan,
            remaining,
            _marker: PhantomData,
        }
    }

    /// Iterator over `&K`.
    pub fn keys(&self) -> Keys<'_, K, V, R> {
        CommonKeys::new(self.iter())
    }

    /// Iterator over `&V`.
    pub fn values(&self) -> Values<'_, K, V, R> {
        CommonValues::new(self.iter())
    }

    /// Iterator over `&mut V`.
    pub fn values_mut(&mut self) -> ValuesMut<'_, K, V, R> {
        CommonValues::new(self.iter_mut())
    }

    /// Consuming iterator over owned keys.
    pub fn into_keys(self) -> IntoKeys<K, V, R> {
        CommonIntoKeys::new(self.into_iter())
    }

    /// Consuming iterator over owned values.
    pub fn into_values(self) -> IntoValues<K, V, R> {
        CommonIntoValues::new(self.into_iter())
    }

    /// Draining iterator that empties the map.
    pub fn drain(&mut self) -> Drain<'_, K, V, R> {
        let scan = self.table.scan();
        let remaining = self.table.len();
        Drain {
            table: std::ptr::from_mut(&mut self.table),
            scan,
            remaining,
            _marker: PhantomData,
        }
    }

    /// Removes and yields the entries for which `f` returns `true`.
    pub fn extract_if<F>(&mut self, f: F) -> ExtractIf<'_, K, V, R, F>
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        let scan = self.table.scan();
        ExtractIf {
            table: std::ptr::from_mut(&mut self.table),
            scan,
            pred: f,
            _marker: PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// Iterators
// ---------------------------------------------------------------------------

/// Borrowing iterator over `(&K, &V)`.
pub struct Iter<'a, K, V, R: RawTable<K, V>> {
    table: &'a R,
    scan: R::Scan,
    remaining: usize,
    _marker: PhantomData<(&'a K, &'a V)>,
}

impl<'a, K, V, R: RawTable<K, V>> Iterator for Iter<'a, K, V, R> {
    type Item = (&'a K, &'a V);
    fn next(&mut self) -> Option<(&'a K, &'a V)> {
        let loc = self.table.scan_next(&mut self.scan)?;
        self.remaining -= 1;
        // SAFETY: `loc` came from this table's scan; the `&'a R` borrow keeps
        // the slot alive for `'a`.
        let slot: &'a SlotEntry<K, V> = unsafe { &*self.table.slot_ptr(loc) };
        Some((&slot.key, &slot.value))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K, V, R: RawTable<K, V>> ExactSizeIterator for Iter<'_, K, V, R> {
    fn len(&self) -> usize {
        self.remaining
    }
}
impl<K, V, R: RawTable<K, V>> FusedIterator for Iter<'_, K, V, R> {}

impl<K, V, R> Clone for Iter<'_, K, V, R>
where
    R: RawTable<K, V>,
    R::Scan: Clone,
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

impl<K: fmt::Debug, V: fmt::Debug, R> fmt::Debug for Iter<'_, K, V, R>
where
    R: RawTable<K, V>,
    R::Scan: Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// Borrowing iterator over `(&K, &mut V)`.
pub struct IterMut<'a, K, V, R: RawTable<K, V>> {
    table: *mut R,
    scan: R::Scan,
    remaining: usize,
    _marker: PhantomData<(&'a K, &'a mut V)>,
}

impl<'a, K, V, R: RawTable<K, V>> Iterator for IterMut<'a, K, V, R> {
    type Item = (&'a K, &'a mut V);
    fn next(&mut self) -> Option<(&'a K, &'a mut V)> {
        // SAFETY: `table` points to the borrowed map; `scan_next` yields each
        // location at most once, so the `&'a mut` references are disjoint.
        let table = unsafe { &*self.table };
        let loc = table.scan_next(&mut self.scan)?;
        self.remaining -= 1;
        let slot: &'a mut SlotEntry<K, V> = unsafe { &mut *table.slot_ptr(loc) };
        Some((&slot.key, &mut slot.value))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K, V, R: RawTable<K, V>> ExactSizeIterator for IterMut<'_, K, V, R> {
    fn len(&self) -> usize {
        self.remaining
    }
}
impl<K, V, R: RawTable<K, V>> FusedIterator for IterMut<'_, K, V, R> {}

/// Consuming iterator over owned `(K, V)`.
pub struct IntoIter<K, V, R: RawTable<K, V>> {
    table: R,
    scan: R::Scan,
    remaining: usize,
}

impl<K, V, R: RawTable<K, V>> Iterator for IntoIter<K, V, R> {
    type Item = (K, V);
    fn next(&mut self) -> Option<(K, V)> {
        let loc = self.table.scan_next(&mut self.scan)?;
        self.remaining -= 1;
        Some(self.table.extract_at(loc))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K, V, R: RawTable<K, V>> ExactSizeIterator for IntoIter<K, V, R> {
    fn len(&self) -> usize {
        self.remaining
    }
}
impl<K, V, R: RawTable<K, V>> FusedIterator for IntoIter<K, V, R> {}

/// Draining iterator; empties the map on consumption or drop.
pub struct Drain<'a, K, V, R: RawTable<K, V>> {
    table: *mut R,
    scan: R::Scan,
    remaining: usize,
    _marker: PhantomData<&'a mut R>,
}

impl<K, V, R: RawTable<K, V>> Iterator for Drain<'_, K, V, R> {
    type Item = (K, V);
    fn next(&mut self) -> Option<(K, V)> {
        // SAFETY: `table` points to the borrowed map for the drain's lifetime.
        let loc = unsafe { (*self.table).scan_next(&mut self.scan) }?;
        self.remaining -= 1;
        Some(unsafe { (*self.table).extract_at(loc) })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K, V, R: RawTable<K, V>> ExactSizeIterator for Drain<'_, K, V, R> {
    fn len(&self) -> usize {
        self.remaining
    }
}
impl<K, V, R: RawTable<K, V>> FusedIterator for Drain<'_, K, V, R> {}

impl<K, V, R: RawTable<K, V>> Drop for Drain<'_, K, V, R> {
    fn drop(&mut self) {
        // Drain any unyielded entries so values run their `Drop`, then wipe.
        for _ in &mut *self {}
        unsafe { (*self.table).wipe_all() };
    }
}

/// Iterator yielding entries removed by [`HashMap::extract_if`]. Unyielded
/// non-matching entries are retained; its `Drop` is a no-op.
pub struct ExtractIf<'a, K, V, R: RawTable<K, V>, F> {
    table: *mut R,
    scan: R::Scan,
    pred: F,
    _marker: PhantomData<&'a mut R>,
}

impl<K, V, R, F> Iterator for ExtractIf<'_, K, V, R, F>
where
    R: RawTable<K, V>,
    F: FnMut(&K, &mut V) -> bool,
{
    type Item = (K, V);
    fn next(&mut self) -> Option<(K, V)> {
        loop {
            // SAFETY: `table` points to the borrowed map for the iterator's life.
            let loc = unsafe { (*self.table).scan_next(&mut self.scan) }?;
            let slot = unsafe { &mut *(*self.table).slot_ptr(loc) };
            if (self.pred)(&slot.key, &mut slot.value) {
                return Some(unsafe { (*self.table).extract_at(loc) });
            }
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}

impl<K, V, R, F> FusedIterator for ExtractIf<'_, K, V, R, F>
where
    R: RawTable<K, V>,
    F: FnMut(&K, &mut V) -> bool,
{
}

/// Iterator over `&K`.
pub type Keys<'a, K, V, R> = CommonKeys<Iter<'a, K, V, R>>;
/// Iterator over `&V`.
pub type Values<'a, K, V, R> = CommonValues<Iter<'a, K, V, R>>;
/// Iterator over `&mut V`.
pub type ValuesMut<'a, K, V, R> = CommonValues<IterMut<'a, K, V, R>>;
/// Consuming iterator over owned keys.
pub type IntoKeys<K, V, R> = CommonIntoKeys<IntoIter<K, V, R>>;
/// Consuming iterator over owned values.
pub type IntoValues<K, V, R> = CommonIntoValues<IntoIter<K, V, R>>;

// ---------------------------------------------------------------------------
// Trait impls
// ---------------------------------------------------------------------------

impl<K, V, R> Default for HashMap<K, V, R>
where
    R: RawTable<K, V, Hasher = DefaultHashBuilder, Alloc = Global>,
{
    fn default() -> Self {
        Self::with_capacity(0)
    }
}

impl<K, V, R> Clone for HashMap<K, V, R>
where
    K: Clone,
    V: Clone,
    R: RawTable<K, V>,
    R::Hasher: Clone,
{
    fn clone(&self) -> Self {
        Self::from_table(self.table.clone_table())
    }
}

impl<K, V, R> fmt::Debug for HashMap<K, V, R>
where
    K: fmt::Debug,
    V: fmt::Debug,
    R: RawTable<K, V>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<K, V, R> PartialEq for HashMap<K, V, R>
where
    K: Eq + Hash,
    V: PartialEq,
    R: RawTable<K, V>,
{
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len()
            && self
                .iter()
                .all(|(k, v)| other.get(k).is_some_and(|ov| *v == *ov))
    }
}

impl<K, V, R> Eq for HashMap<K, V, R>
where
    K: Eq + Hash,
    V: Eq,
    R: RawTable<K, V>,
{
}

impl<K, Q, V, R> Index<&Q> for HashMap<K, V, R>
where
    K: Eq + Hash,
    Q: Hash + Equivalent<K> + ?Sized,
    R: RawTable<K, V>,
{
    type Output = V;
    fn index(&self, key: &Q) -> &V {
        self.get(key).expect("no entry found for key")
    }
}

impl<K, V, R> Extend<(K, V)> for HashMap<K, V, R>
where
    K: Eq + Hash,
    R: RawTable<K, V>,
{
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        let iter = iter.into_iter();
        self.reserve(iter.size_hint().0);
        for (k, v) in iter {
            self.insert(k, v);
        }
    }
}

impl<'a, K, V, R> Extend<(&'a K, &'a V)> for HashMap<K, V, R>
where
    K: Eq + Hash + Copy,
    V: Copy,
    R: RawTable<K, V>,
{
    fn extend<I: IntoIterator<Item = (&'a K, &'a V)>>(&mut self, iter: I) {
        self.extend(iter.into_iter().map(|(k, v)| (*k, *v)));
    }
}

impl<'a, K, V, R> Extend<&'a (K, V)> for HashMap<K, V, R>
where
    K: Eq + Hash + Copy,
    V: Copy,
    R: RawTable<K, V>,
{
    fn extend<I: IntoIterator<Item = &'a (K, V)>>(&mut self, iter: I) {
        self.extend(iter.into_iter().map(|(k, v)| (*k, *v)));
    }
}

impl<K, V, R> FromIterator<(K, V)> for HashMap<K, V, R>
where
    K: Eq + Hash,
    R: RawTable<K, V, Hasher = DefaultHashBuilder, Alloc = Global>,
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let iter = iter.into_iter();
        let mut map = Self::with_capacity(iter.size_hint().0);
        map.extend(iter);
        map
    }
}

impl<'a, K, V, R: RawTable<K, V>> IntoIterator for &'a HashMap<K, V, R> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V, R>;
    fn into_iter(self) -> Iter<'a, K, V, R> {
        self.iter()
    }
}

impl<'a, K, V, R: RawTable<K, V>> IntoIterator for &'a mut HashMap<K, V, R> {
    type Item = (&'a K, &'a mut V);
    type IntoIter = IterMut<'a, K, V, R>;
    fn into_iter(self) -> IterMut<'a, K, V, R> {
        self.iter_mut()
    }
}

impl<K, V, R: RawTable<K, V>> IntoIterator for HashMap<K, V, R> {
    type Item = (K, V);
    type IntoIter = IntoIter<K, V, R>;
    fn into_iter(self) -> IntoIter<K, V, R> {
        let scan = self.table.scan();
        let remaining = self.table.len();
        IntoIter {
            table: self.table,
            scan,
            remaining,
        }
    }
}
