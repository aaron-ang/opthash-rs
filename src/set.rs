use std::fmt;
use std::hash::Hash;
use std::iter::{Chain, FusedIterator};
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Sub, SubAssign};

use allocator_api2::alloc::Global;
use equivalent::Equivalent;

use crate::common::DefaultHashBuilder;
use crate::common::error::TryReserveError;
use crate::map::{self, RawTable};

/// Boxed predicate adapting a set-level `FnMut(&T) -> bool` to the map's
/// `FnMut(&K, &mut V) -> bool`. Boxing keeps the public `ExtractIf` type
/// nameable; the allocation is once per `extract_if` call, off the hot path.
type SetExtractPred<'a, T> = Box<dyn FnMut(&T, &mut ()) -> bool + 'a>;

/// A hash set backed by a [`RawTable`] implementation.
pub struct HashSet<T, R: RawTable<T, ()>>
where
    T: Eq + Hash,
{
    map: map::HashMap<T, (), R>,
}

impl<T, R> HashSet<T, R>
where
    T: Eq + Hash,
    R: RawTable<T, (), Hasher = DefaultHashBuilder, Alloc = Global>,
{
    /// Creates an empty set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: map::HashMap::new(),
        }
    }

    /// Creates an empty set with at least `capacity` slots.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            map: map::HashMap::with_capacity(capacity),
        }
    }

    /// Creates an empty set with the given reserve fraction.
    #[must_use]
    pub fn with_reserve_fraction(reserve_fraction: f64) -> Self {
        Self {
            map: map::HashMap::with_reserve_fraction(reserve_fraction),
        }
    }

    /// Creates an empty set with the given capacity and reserve fraction.
    #[must_use]
    pub fn with_capacity_and_reserve_fraction(capacity: usize, reserve_fraction: f64) -> Self {
        Self {
            map: map::HashMap::with_capacity_and_reserve_fraction(capacity, reserve_fraction),
        }
    }
}

impl<T, R> HashSet<T, R>
where
    T: Eq + Hash,
    R: RawTable<T, (), Alloc = Global>,
{
    /// Creates an empty set that uses `hash_builder` to hash values.
    #[must_use]
    pub fn with_hasher(hash_builder: R::Hasher) -> Self {
        Self {
            map: map::HashMap::with_hasher(hash_builder),
        }
    }

    /// Creates an empty set with the given capacity and hasher.
    #[must_use]
    pub fn with_capacity_and_hasher(capacity: usize, hash_builder: R::Hasher) -> Self {
        Self {
            map: map::HashMap::with_capacity_and_hasher(capacity, hash_builder),
        }
    }

    /// Creates an empty set with the given reserve fraction and hasher.
    #[must_use]
    pub fn with_reserve_fraction_and_hasher(
        reserve_fraction: f64,
        hash_builder: R::Hasher,
    ) -> Self {
        Self {
            map: map::HashMap::with_reserve_fraction_and_hasher(reserve_fraction, hash_builder),
        }
    }

    /// Creates an empty set with the given capacity, reserve fraction, and hasher.
    #[must_use]
    pub fn with_capacity_and_reserve_fraction_and_hasher(
        capacity: usize,
        reserve_fraction: f64,
        hash_builder: R::Hasher,
    ) -> Self {
        Self {
            map: map::HashMap::with_capacity_and_reserve_fraction_and_hasher(
                capacity,
                reserve_fraction,
                hash_builder,
            ),
        }
    }
}

impl<T, R> HashSet<T, R>
where
    T: Eq + Hash,
    R: RawTable<T, (), Hasher = DefaultHashBuilder>,
{
    /// Creates an empty set in the given allocator.
    #[must_use]
    pub fn new_in(alloc: R::Alloc) -> Self {
        Self {
            map: map::HashMap::new_in(alloc),
        }
    }

    /// Creates an empty set with the given capacity in the given allocator.
    #[must_use]
    pub fn with_capacity_in(capacity: usize, alloc: R::Alloc) -> Self {
        Self {
            map: map::HashMap::with_capacity_in(capacity, alloc),
        }
    }
}

impl<T, R> HashSet<T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
    /// Full constructor: capacity, reserve fraction, hasher, and allocator.
    #[must_use]
    pub fn with_capacity_and_reserve_fraction_and_hasher_in(
        capacity: usize,
        reserve_fraction: f64,
        hash_builder: R::Hasher,
        alloc: R::Alloc,
    ) -> Self {
        Self {
            map: map::HashMap::with_capacity_and_reserve_fraction_and_hasher_in(
                capacity,
                reserve_fraction,
                hash_builder,
                alloc,
            ),
        }
    }

    /// Reference to the set's allocator.
    pub fn allocator(&self) -> &R::Alloc {
        self.map.allocator()
    }

    /// Reference to the set's [`std::hash::BuildHasher`].
    pub fn hasher(&self) -> &R::Hasher {
        self.map.hasher()
    }

    /// Number of values in the set.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns `true` if the set contains no values.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Current slot capacity.
    pub fn capacity(&self) -> usize {
        self.map.capacity()
    }

    /// Reserves room for at least `additional` more values.
    pub fn reserve(&mut self, additional: usize) {
        self.map.reserve(additional);
    }

    /// Fallible [`reserve`](Self::reserve).
    ///
    /// # Errors
    ///
    /// Returns [`TryReserveError`] on capacity overflow or allocator failure.
    pub fn try_reserve(&mut self, additional: usize) -> Result<(), TryReserveError>
    where
        R::Hasher: Clone,
    {
        self.map.try_reserve(additional)
    }

    /// Shrinks capacity to fit the current length.
    pub fn shrink_to_fit(&mut self) {
        self.map.shrink_to_fit();
    }

    /// Shrinks capacity toward `min_capacity`.
    pub fn shrink_to(&mut self, min_capacity: usize) {
        self.map.shrink_to(min_capacity);
    }

    /// Returns `true` if the set contains a value equal to `value`.
    pub fn contains<Q>(&self, value: &Q) -> bool
    where
        Q: Hash + Equivalent<T> + ?Sized,
    {
        self.map.contains_key(value)
    }

    /// Returns a reference to the value equal to `value`, if any.
    pub fn get<Q>(&self, value: &Q) -> Option<&T>
    where
        Q: Hash + Equivalent<T> + ?Sized,
    {
        self.map.get_key_value(value).map(|(k, ())| k)
    }

    /// Inserts `value` if absent, then returns a reference to the stored value.
    pub fn get_or_insert(&mut self, value: T) -> &T {
        match self.map.entry(value) {
            map::Entry::Occupied(entry) => entry.into_key(),
            map::Entry::Vacant(entry) => entry.insert_entry(()).into_key(),
        }
    }

    /// Returns the stored value equal to `value`, inserting `f(value)`
    /// first if absent.
    pub fn get_or_insert_with<Q, F>(&mut self, value: &Q, f: F) -> &T
    where
        Q: Hash + Equivalent<T> + ?Sized,
        F: FnOnce(&Q) -> T,
    {
        self.map.get_or_insert_key_with(value, (), f)
    }

    /// Inserts `value`. Returns `true` if it was newly added.
    pub fn insert(&mut self, value: T) -> bool {
        self.map.insert(value, ()).is_none()
    }

    /// Inserts `value`, replacing and returning any equal existing value.
    pub fn replace(&mut self, value: T) -> Option<T> {
        let replaced = self.map.remove_entry(&value).map(|(k, ())| k);
        self.map.insert(value, ());
        replaced
    }

    /// Removes the value equal to `value`. Returns whether it was present.
    pub fn remove<Q>(&mut self, value: &Q) -> bool
    where
        Q: Hash + Equivalent<T> + ?Sized,
    {
        self.map.remove(value).is_some()
    }

    /// Removes and returns the value equal to `value`, if any.
    pub fn take<Q>(&mut self, value: &Q) -> Option<T>
    where
        Q: Hash + Equivalent<T> + ?Sized,
    {
        self.map.remove_entry(value).map(|(k, ())| k)
    }

    /// Removes all values, keeping allocated capacity.
    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Borrowing iterator over the set's values, in arbitrary order.
    pub fn iter(&self) -> Iter<'_, T, R> {
        Iter {
            inner: self.map.keys(),
        }
    }

    /// Draining iterator. Removes and yields every value.
    pub fn drain(&mut self) -> Drain<'_, T, R> {
        Drain {
            inner: self.map.drain(),
        }
    }

    /// Removes and yields values for which `f` returns `true`. Retains the
    /// rest, and retains any unvisited values if the iterator is dropped early.
    pub fn extract_if<'s, F>(&'s mut self, mut f: F) -> ExtractIf<'s, T, R>
    where
        T: 's,
        F: FnMut(&T) -> bool + 's,
    {
        let pred: SetExtractPred<'s, T> = Box::new(move |value, ()| f(value));
        ExtractIf {
            inner: self.map.extract_if(pred),
        }
    }

    /// Retains only the values for which `f` returns `true`.
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&T) -> bool,
    {
        self.map.retain(|value, ()| f(value));
    }

    /// Gets the [`Entry`] for `value` for in-place manipulation.
    pub fn entry(&mut self, value: T) -> Entry<'_, T, R> {
        match self.map.entry(value) {
            map::Entry::Occupied(entry) => Entry::Occupied(OccupiedEntry { inner: entry }),
            map::Entry::Vacant(entry) => Entry::Vacant(VacantEntry { inner: entry }),
        }
    }

    /// Visits the values present in `self` but not in `other`.
    pub fn difference<'a>(&'a self, other: &'a Self) -> Difference<'a, T, R> {
        Difference {
            iter: self.iter(),
            other,
        }
    }

    /// Visits the values present in either `self` or `other` but not both.
    pub fn symmetric_difference<'a>(&'a self, other: &'a Self) -> SymmetricDifference<'a, T, R> {
        SymmetricDifference {
            iter: self.difference(other).chain(other.difference(self)),
        }
    }

    /// Visits the values present in both `self` and `other`.
    pub fn intersection<'a>(&'a self, other: &'a Self) -> Intersection<'a, T, R> {
        // Iterate the smaller set and probe the larger, minimizing membership
        // lookups when sizes differ.
        let (smaller, larger) = if self.len() <= other.len() {
            (self, other)
        } else {
            (other, self)
        };
        Intersection {
            iter: smaller.iter(),
            other: larger,
        }
    }

    /// Visits the values present in either `self` or `other`.
    pub fn union<'a>(&'a self, other: &'a Self) -> Union<'a, T, R> {
        // Iterate the larger set in full and only the difference of the
        // smaller one, minimizing membership lookups.
        let (smaller, larger) = if self.len() <= other.len() {
            (self, other)
        } else {
            (other, self)
        };
        Union {
            iter: larger.iter().chain(smaller.difference(larger)),
        }
    }

    /// Returns `true` if `self` and `other` share no values.
    pub fn is_disjoint(&self, other: &Self) -> bool {
        self.intersection(other).next().is_none()
    }

    /// Returns `true` if every value in `self` is also in `other`.
    pub fn is_subset(&self, other: &Self) -> bool {
        self.len() <= other.len() && self.iter().all(|value| other.contains(value))
    }

    /// Returns `true` if every value in `other` is also in `self`.
    pub fn is_superset(&self, other: &Self) -> bool {
        other.is_subset(self)
    }
}

impl<T, R> Default for HashSet<T, R>
where
    T: Eq + Hash,
    R: RawTable<T, (), Hasher = DefaultHashBuilder, Alloc = Global>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T, R> Clone for HashSet<T, R>
where
    T: Clone + Eq + Hash,
    R: RawTable<T, ()>,
    R::Hasher: Clone,
{
    fn clone(&self) -> Self {
        Self {
            map: self.map.clone(),
        }
    }
}

impl<T, R> fmt::Debug for HashSet<T, R>
where
    T: fmt::Debug + Eq + Hash,
    R: RawTable<T, ()>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

impl<T, R> PartialEq for HashSet<T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().all(|value| other.contains(value))
    }
}

impl<T, R> Eq for HashSet<T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
}

impl<T, R> FromIterator<T> for HashSet<T, R>
where
    T: Eq + Hash,
    R: RawTable<T, (), Alloc = Global>,
    R::Hasher: Default,
{
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut set = Self::with_hasher(R::Hasher::default());
        set.extend(iter);
        set
    }
}

impl<T, R, const N: usize> From<[T; N]> for HashSet<T, R>
where
    T: Eq + Hash,
    R: RawTable<T, (), Hasher = DefaultHashBuilder, Alloc = Global>,
{
    fn from(arr: [T; N]) -> Self {
        arr.into_iter().collect()
    }
}

impl<T, R> Extend<T> for HashSet<T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.map.extend(iter.into_iter().map(|value| (value, ())));
    }
}

impl<'a, T, R> Extend<&'a T> for HashSet<T, R>
where
    T: 'a + Eq + Hash + Copy,
    R: RawTable<T, ()>,
{
    fn extend<I: IntoIterator<Item = &'a T>>(&mut self, iter: I) {
        self.extend(iter.into_iter().copied());
    }
}

impl<'a, T, R> IntoIterator for &'a HashSet<T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
    type Item = &'a T;
    type IntoIter = Iter<'a, T, R>;
    fn into_iter(self) -> Iter<'a, T, R> {
        self.iter()
    }
}

impl<T, R> IntoIterator for HashSet<T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
    type Item = T;
    type IntoIter = IntoIter<T, R>;
    fn into_iter(self) -> IntoIter<T, R> {
        IntoIter {
            inner: self.map.into_keys(),
        }
    }
}

impl<T, R> BitOr<&HashSet<T, R>> for &HashSet<T, R>
where
    T: Eq + Hash + Clone,
    R: RawTable<T, (), Alloc = Global>,
    R::Hasher: Default,
{
    type Output = HashSet<T, R>;
    fn bitor(self, rhs: &HashSet<T, R>) -> HashSet<T, R> {
        self.union(rhs).cloned().collect()
    }
}

impl<T, R> BitAnd<&HashSet<T, R>> for &HashSet<T, R>
where
    T: Eq + Hash + Clone,
    R: RawTable<T, (), Alloc = Global>,
    R::Hasher: Default,
{
    type Output = HashSet<T, R>;
    fn bitand(self, rhs: &HashSet<T, R>) -> HashSet<T, R> {
        self.intersection(rhs).cloned().collect()
    }
}

impl<T, R> BitXor<&HashSet<T, R>> for &HashSet<T, R>
where
    T: Eq + Hash + Clone,
    R: RawTable<T, (), Alloc = Global>,
    R::Hasher: Default,
{
    type Output = HashSet<T, R>;
    fn bitxor(self, rhs: &HashSet<T, R>) -> HashSet<T, R> {
        self.symmetric_difference(rhs).cloned().collect()
    }
}

impl<T, R> Sub<&HashSet<T, R>> for &HashSet<T, R>
where
    T: Eq + Hash + Clone,
    R: RawTable<T, (), Alloc = Global>,
    R::Hasher: Default,
{
    type Output = HashSet<T, R>;
    fn sub(self, rhs: &HashSet<T, R>) -> HashSet<T, R> {
        self.difference(rhs).cloned().collect()
    }
}

impl<T, R> BitOrAssign<&HashSet<T, R>> for HashSet<T, R>
where
    T: Eq + Hash + Clone,
    R: RawTable<T, ()>,
{
    fn bitor_assign(&mut self, rhs: &HashSet<T, R>) {
        for value in rhs {
            if !self.contains(value) {
                self.insert(value.clone());
            }
        }
    }
}

impl<T, R> BitAndAssign<&HashSet<T, R>> for HashSet<T, R>
where
    T: Eq + Hash + Clone,
    R: RawTable<T, ()>,
{
    fn bitand_assign(&mut self, rhs: &HashSet<T, R>) {
        self.retain(|value| rhs.contains(value));
    }
}

impl<T, R> BitXorAssign<&HashSet<T, R>> for HashSet<T, R>
where
    T: Eq + Hash + Clone,
    R: RawTable<T, ()>,
{
    fn bitxor_assign(&mut self, rhs: &HashSet<T, R>) {
        for value in rhs {
            if self.contains(value) {
                self.remove(value);
            } else {
                self.insert(value.clone());
            }
        }
    }
}

impl<T, R> SubAssign<&HashSet<T, R>> for HashSet<T, R>
where
    T: Eq + Hash + Clone,
    R: RawTable<T, ()>,
{
    fn sub_assign(&mut self, rhs: &HashSet<T, R>) {
        if rhs.len() < self.len() {
            for value in rhs {
                self.remove(value);
            }
        } else {
            self.retain(|value| !rhs.contains(value));
        }
    }
}

/// Borrowing iterator over [`HashSet`] values.
pub struct Iter<'a, T, R: RawTable<T, ()>>
where
    T: Eq + Hash,
{
    inner: map::Keys<'a, T, (), R>,
}

impl<T, R> Clone for Iter<'_, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
    R::Scan: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<'a, T, R> Iterator for Iter<'a, T, R>
where
    T: 'a + Eq + Hash,
    R: RawTable<T, ()>,
{
    type Item = &'a T;
    fn next(&mut self) -> Option<&'a T> {
        self.inner.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<'a, T, R> ExactSizeIterator for Iter<'a, T, R>
where
    T: 'a + Eq + Hash,
    R: RawTable<T, ()>,
{
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<'a, T, R> FusedIterator for Iter<'a, T, R>
where
    T: 'a + Eq + Hash,
    R: RawTable<T, ()>,
{
}

impl<T, R> fmt::Debug for Iter<'_, T, R>
where
    T: fmt::Debug + Eq + Hash,
    R: RawTable<T, ()>,
    R::Scan: Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// Consuming iterator over [`HashSet`] values.
pub struct IntoIter<T, R: RawTable<T, ()>>
where
    T: Eq + Hash,
{
    inner: map::IntoKeys<T, (), R>,
}

impl<T, R> Iterator for IntoIter<T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
    type Item = T;
    fn next(&mut self) -> Option<T> {
        self.inner.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<T, R> ExactSizeIterator for IntoIter<T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<T, R> FusedIterator for IntoIter<T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
}

impl<T, R> fmt::Debug for IntoIter<T, R>
where
    T: fmt::Debug + Eq + Hash,
    R: RawTable<T, ()>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntoIter").finish_non_exhaustive()
    }
}

/// Draining iterator over [`HashSet`] values.
pub struct Drain<'a, T, R: RawTable<T, ()>>
where
    T: Eq + Hash,
{
    inner: map::Drain<'a, T, (), R>,
}

impl<T, R> Iterator for Drain<'_, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
    type Item = T;
    fn next(&mut self) -> Option<T> {
        self.inner.next().map(|(value, ())| value)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<T, R> ExactSizeIterator for Drain<'_, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<T, R> FusedIterator for Drain<'_, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
}

impl<T, R> fmt::Debug for Drain<'_, T, R>
where
    T: fmt::Debug + Eq + Hash,
    R: RawTable<T, ()>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Drain").finish_non_exhaustive()
    }
}

/// Iterator yielding the extracted values of a [`HashSet`].
pub struct ExtractIf<'a, T, R: RawTable<T, ()>>
where
    T: Eq + Hash,
{
    inner: map::ExtractIf<'a, T, (), R, SetExtractPred<'a, T>>,
}

impl<T, R> Iterator for ExtractIf<'_, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
    type Item = T;
    fn next(&mut self) -> Option<T> {
        self.inner.next().map(|(value, ())| value)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, self.inner.size_hint().1)
    }
}

impl<T, R> FusedIterator for ExtractIf<'_, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
}

impl<T, R> fmt::Debug for ExtractIf<'_, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtractIf").finish_non_exhaustive()
    }
}

/// Iterator over the difference of two [`HashSet`]s.
pub struct Difference<'a, T, R: RawTable<T, ()>>
where
    T: Eq + Hash,
{
    iter: Iter<'a, T, R>,
    other: &'a HashSet<T, R>,
}

impl<T, R> Clone for Difference<'_, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
    R::Scan: Clone,
{
    fn clone(&self) -> Self {
        Self {
            iter: self.iter.clone(),
            other: self.other,
        }
    }
}

impl<'a, T, R> Iterator for Difference<'a, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
    type Item = &'a T;
    fn next(&mut self) -> Option<&'a T> {
        loop {
            let value = self.iter.next()?;
            if !self.other.contains(value) {
                return Some(value);
            }
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let (_, upper) = self.iter.size_hint();
        (0, upper)
    }
}

impl<T, R> FusedIterator for Difference<'_, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
}

impl<T, R> fmt::Debug for Difference<'_, T, R>
where
    T: fmt::Debug + Eq + Hash,
    R: RawTable<T, ()>,
    R::Scan: Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// Iterator over the intersection of two [`HashSet`]s.
pub struct Intersection<'a, T, R: RawTable<T, ()>>
where
    T: Eq + Hash,
{
    iter: Iter<'a, T, R>,
    other: &'a HashSet<T, R>,
}

impl<T, R> Clone for Intersection<'_, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
    R::Scan: Clone,
{
    fn clone(&self) -> Self {
        Self {
            iter: self.iter.clone(),
            other: self.other,
        }
    }
}

impl<'a, T, R> Iterator for Intersection<'a, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
    type Item = &'a T;
    fn next(&mut self) -> Option<&'a T> {
        loop {
            let value = self.iter.next()?;
            if self.other.contains(value) {
                return Some(value);
            }
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let (_, upper) = self.iter.size_hint();
        (0, upper)
    }
}

impl<T, R> FusedIterator for Intersection<'_, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
}

impl<T, R> fmt::Debug for Intersection<'_, T, R>
where
    T: fmt::Debug + Eq + Hash,
    R: RawTable<T, ()>,
    R::Scan: Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// Iterator over the symmetric difference of two [`HashSet`]s.
pub struct SymmetricDifference<'a, T, R: RawTable<T, ()>>
where
    T: Eq + Hash,
{
    iter: Chain<Difference<'a, T, R>, Difference<'a, T, R>>,
}

impl<T, R> Clone for SymmetricDifference<'_, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
    R::Scan: Clone,
{
    fn clone(&self) -> Self {
        Self {
            iter: self.iter.clone(),
        }
    }
}

impl<'a, T, R> Iterator for SymmetricDifference<'a, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
    type Item = &'a T;
    fn next(&mut self) -> Option<&'a T> {
        self.iter.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<T, R> FusedIterator for SymmetricDifference<'_, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
}

impl<T, R> fmt::Debug for SymmetricDifference<'_, T, R>
where
    T: fmt::Debug + Eq + Hash,
    R: RawTable<T, ()>,
    R::Scan: Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// Iterator over the union of two [`HashSet`]s.
pub struct Union<'a, T, R: RawTable<T, ()>>
where
    T: Eq + Hash,
{
    iter: Chain<Iter<'a, T, R>, Difference<'a, T, R>>,
}

impl<T, R> Clone for Union<'_, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
    R::Scan: Clone,
{
    fn clone(&self) -> Self {
        Self {
            iter: self.iter.clone(),
        }
    }
}

impl<'a, T, R> Iterator for Union<'a, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
    type Item = &'a T;
    fn next(&mut self) -> Option<&'a T> {
        self.iter.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<T, R> FusedIterator for Union<'_, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
}

impl<T, R> fmt::Debug for Union<'_, T, R>
where
    T: fmt::Debug + Eq + Hash,
    R: RawTable<T, ()>,
    R::Scan: Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// A view into a single [`HashSet`] entry.
pub enum Entry<'a, T, R: RawTable<T, ()>>
where
    T: Eq + Hash,
{
    /// Value already present.
    Occupied(OccupiedEntry<'a, T, R>),
    /// Value absent.
    Vacant(VacantEntry<'a, T, R>),
}

/// View of an occupied [`HashSet`] entry.
pub struct OccupiedEntry<'a, T, R: RawTable<T, ()>>
where
    T: Eq + Hash,
{
    inner: map::OccupiedEntry<'a, T, (), R>,
}

/// View of a vacant [`HashSet`] entry.
pub struct VacantEntry<'a, T, R: RawTable<T, ()>>
where
    T: Eq + Hash,
{
    inner: map::VacantEntry<'a, T, (), R>,
}

impl<'a, T, R> Entry<'a, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
    /// Ensures the value is present, returning the occupied entry.
    pub fn insert(self) -> OccupiedEntry<'a, T, R> {
        match self {
            Entry::Occupied(entry) => entry,
            Entry::Vacant(entry) => entry.insert(),
        }
    }

    /// Ensures the value is present.
    pub fn or_insert(self) {
        if let Entry::Vacant(entry) = self {
            entry.insert();
        }
    }

    /// Reference to the entry's value.
    pub fn get(&self) -> &T {
        match self {
            Entry::Occupied(entry) => entry.get(),
            Entry::Vacant(entry) => entry.get(),
        }
    }
}

impl<T, R> OccupiedEntry<'_, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
    /// Reference to the value in the entry.
    pub fn get(&self) -> &T {
        self.inner.key()
    }

    /// Removes the value from the set and returns it.
    pub fn remove(self) -> T {
        self.inner.remove_entry().0
    }
}

impl<'a, T, R> VacantEntry<'a, T, R>
where
    T: Eq + Hash,
    R: RawTable<T, ()>,
{
    /// Reference to the value that would be inserted.
    pub fn get(&self) -> &T {
        self.inner.key()
    }

    /// Takes ownership of the value without inserting it.
    pub fn into_value(self) -> T {
        self.inner.into_key()
    }

    /// Inserts the value and returns the resulting occupied entry.
    pub fn insert(self) -> OccupiedEntry<'a, T, R> {
        OccupiedEntry {
            inner: self.inner.insert_entry(()),
        }
    }
}

impl<T, R> fmt::Debug for OccupiedEntry<'_, T, R>
where
    T: fmt::Debug + Eq + Hash,
    R: RawTable<T, ()>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OccupiedEntry")
            .field("value", self.get())
            .finish()
    }
}

impl<T, R> fmt::Debug for VacantEntry<'_, T, R>
where
    T: fmt::Debug + Eq + Hash,
    R: RawTable<T, ()>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("VacantEntry").field(self.get()).finish()
    }
}

impl<T, R> fmt::Debug for Entry<'_, T, R>
where
    T: fmt::Debug + Eq + Hash,
    R: RawTable<T, ()>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Entry::Occupied(entry) => f.debug_tuple("Entry").field(entry).finish(),
            Entry::Vacant(entry) => f.debug_tuple("Entry").field(entry).finish(),
        }
    }
}
