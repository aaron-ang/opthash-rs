use std::fmt;
use std::hash::{BuildHasher, Hash};
use std::iter::{Chain, FusedIterator};
use std::marker::PhantomData;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Sub, SubAssign};

use allocator_api2::alloc::{Allocator, Global};
use equivalent::Equivalent;

use crate::common::DefaultHashBuilder;
use crate::common::error::TryReserveError;
use crate::elastic::{
    Drain as ElasticMapDrain, ElasticHashMap, ElasticIntoKeys, Entry as ElasticMapEntry,
    ExtractIf as ElasticMapExtractIf, Keys as ElasticMapKeys, OccupiedEntry as ElasticMapOccupied,
    VacantEntry as ElasticMapVacant,
};
use crate::funnel::{
    Drain as FunnelMapDrain, Entry as FunnelMapEntry, ExtractIf as FunnelMapExtractIf,
    FunnelHashMap, FunnelIntoKeys, Keys as FunnelMapKeys, OccupiedEntry as FunnelMapOccupied,
    VacantEntry as FunnelMapVacant,
};

/// Boxed predicate adapting a set-level `FnMut(&T) -> bool` to the map's
/// `FnMut(&K, &mut V) -> bool`. Boxing keeps the public `ExtractIf` type
/// nameable; the allocation is once per `extract_if` call, off the hot path.
type SetExtractPred<'a, T> = Box<dyn FnMut(&T, &mut ()) -> bool + 'a>;

macro_rules! define_hash_set {
    (
        set = $Set:ident,
        map = $Map:ident,
        iter = $Iter:ident,
        into_iter = $IntoIter:ident,
        drain = $Drain:ident,
        extract_if = $ExtractIf:ident,
        difference = $Difference:ident,
        intersection = $Intersection:ident,
        symmetric_difference = $SymmetricDifference:ident,
        union = $Union:ident,
        entry = $Entry:ident,
        occupied_entry = $OccupiedEntry:ident,
        vacant_entry = $VacantEntry:ident,
        map_keys = $MapKeys:ident,
        // Type args (after `'a, T, ()`) for the map's borrowing-keys iterator.
        // The generic-shell backend bakes the hasher `S` into the iterator
        // type (`S, A`); the standalone funnel backend erases it (`A`). The
        // set's borrowing iterators always carry `S` and tie it off with
        // `PhantomData` so the macro body stays single-shaped.
        map_keys_tail = ($($MapKeysTail:tt)*),
        map_into_keys = $MapIntoKeys:ident,
        map_drain = $MapDrain:ident,
        map_extract_if = $MapExtractIf:ident,
        map_entry = $MapEntry:ident,
        map_occupied = $MapOccupied:ident,
        map_vacant = $MapVacant:ident,
    ) => {
        #[doc = concat!("A hash set backed by [`", stringify!($Map), "`].")]
        pub struct $Set<T, S = DefaultHashBuilder, A: Allocator + Clone = Global>
        where
            T: Eq + Hash,
            S: BuildHasher,
        {
            map: $Map<T, (), S, A>,
        }

        impl<T> $Set<T, DefaultHashBuilder, Global>
        where
            T: Eq + Hash,
        {
            /// Creates an empty set.
            #[must_use]
            pub fn new() -> Self {
                Self { map: $Map::new() }
            }

            /// Creates an empty set with at least `capacity` slots.
            #[must_use]
            pub fn with_capacity(capacity: usize) -> Self {
                Self {
                    map: $Map::with_capacity(capacity),
                }
            }

            /// Creates an empty set with the given reserve fraction.
            #[must_use]
            pub fn with_reserve_fraction(reserve_fraction: f64) -> Self {
                Self {
                    map: $Map::with_reserve_fraction(reserve_fraction),
                }
            }

            /// Creates an empty set with the given capacity and reserve fraction.
            #[must_use]
            pub fn with_capacity_and_reserve_fraction(
                capacity: usize,
                reserve_fraction: f64,
            ) -> Self {
                Self {
                    map: $Map::with_capacity_and_reserve_fraction(capacity, reserve_fraction),
                }
            }
        }

        impl<T, S> $Set<T, S, Global>
        where
            T: Eq + Hash,
            S: BuildHasher,
        {
            /// Creates an empty set that uses `hash_builder` to hash values.
            #[must_use]
            pub fn with_hasher(hash_builder: S) -> Self {
                Self {
                    map: $Map::with_hasher(hash_builder),
                }
            }

            /// Creates an empty set with the given capacity and hasher.
            #[must_use]
            pub fn with_capacity_and_hasher(capacity: usize, hash_builder: S) -> Self {
                Self {
                    map: $Map::with_capacity_and_hasher(capacity, hash_builder),
                }
            }

            /// Creates an empty set with the given reserve fraction and hasher.
            #[must_use]
            pub fn with_reserve_fraction_and_hasher(reserve_fraction: f64, hash_builder: S) -> Self {
                Self {
                    map: $Map::with_reserve_fraction_and_hasher(reserve_fraction, hash_builder),
                }
            }

            /// Creates an empty set with the given capacity, reserve fraction, and hasher.
            #[must_use]
            pub fn with_capacity_and_reserve_fraction_and_hasher(
                capacity: usize,
                reserve_fraction: f64,
                hash_builder: S,
            ) -> Self {
                Self {
                    map: $Map::with_capacity_and_reserve_fraction_and_hasher(
                        capacity,
                        reserve_fraction,
                        hash_builder,
                    ),
                }
            }
        }

        impl<T, A> $Set<T, DefaultHashBuilder, A>
        where
            T: Eq + Hash,
            A: Allocator + Clone,
        {
            /// Creates an empty set in the given allocator.
            #[must_use]
            pub fn new_in(alloc: A) -> Self {
                Self {
                    map: $Map::new_in(alloc),
                }
            }

            /// Creates an empty set with the given capacity in the given allocator.
            #[must_use]
            pub fn with_capacity_in(capacity: usize, alloc: A) -> Self {
                Self {
                    map: $Map::with_capacity_in(capacity, alloc),
                }
            }
        }

        impl<T, S, A> $Set<T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            /// Full constructor: capacity, reserve fraction, hasher, and allocator.
            #[must_use]
            pub fn with_capacity_and_reserve_fraction_and_hasher_in(
                capacity: usize,
                reserve_fraction: f64,
                hash_builder: S,
                alloc: A,
            ) -> Self {
                Self {
                    map: $Map::with_capacity_and_reserve_fraction_and_hasher_in(
                        capacity,
                        reserve_fraction,
                        hash_builder,
                        alloc,
                    ),
                }
            }

            /// Reference to the set's allocator.
            pub fn allocator(&self) -> &A {
                self.map.allocator()
            }

            /// Reference to the set's [`BuildHasher`].
            pub fn hasher(&self) -> &S {
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
                S: Clone,
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
                    $MapEntry::Occupied(entry) => entry.into_key(),
                    $MapEntry::Vacant(entry) => entry.insert_entry(()).into_key(),
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
                let replaced = match self.map.remove_entry(&value) {
                    Some((k, ())) => Some(k),
                    None => None,
                };
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
                match self.map.remove_entry(value) {
                    Some((k, ())) => Some(k),
                    None => None,
                }
            }

            /// Removes all values, keeping allocated capacity.
            pub fn clear(&mut self) {
                self.map.clear();
            }

            /// Borrowing iterator over the set's values, in arbitrary order.
            pub fn iter(&self) -> $Iter<'_, T, S, A> {
                $Iter {
                    inner: self.map.keys(),
                    _marker: PhantomData,
                }
            }

            /// Draining iterator. Removes and yields every value.
            pub fn drain(&mut self) -> $Drain<'_, T, S, A> {
                $Drain {
                    inner: self.map.drain(),
                }
            }

            /// Removes and yields values for which `f` returns `true`. Retains
            /// the rest; unconsumed matches are still removed on drop.
            pub fn extract_if<'s, F>(&'s mut self, mut f: F) -> $ExtractIf<'s, T, S, A>
            where
                T: 's,
                F: FnMut(&T) -> bool + 's,
            {
                let pred: SetExtractPred<'s, T> = Box::new(move |value, ()| f(value));
                $ExtractIf {
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

            /// Gets the [`Entry`](`$Entry`) for `value` for in-place manipulation.
            pub fn entry(&mut self, value: T) -> $Entry<'_, T, S, A> {
                match self.map.entry(value) {
                    $MapEntry::Occupied(entry) => $Entry::Occupied($OccupiedEntry { inner: entry }),
                    $MapEntry::Vacant(entry) => $Entry::Vacant($VacantEntry { inner: entry }),
                }
            }

            /// Visits the values present in `self` but not in `other`.
            pub fn difference<'a>(&'a self, other: &'a Self) -> $Difference<'a, T, S, A> {
                $Difference {
                    iter: self.iter(),
                    other,
                }
            }

            /// Visits the values present in either `self` or `other` but not both.
            pub fn symmetric_difference<'a>(
                &'a self,
                other: &'a Self,
            ) -> $SymmetricDifference<'a, T, S, A> {
                $SymmetricDifference {
                    iter: self.difference(other).chain(other.difference(self)),
                }
            }

            /// Visits the values present in both `self` and `other`.
            pub fn intersection<'a>(&'a self, other: &'a Self) -> $Intersection<'a, T, S, A> {
                // Iterate the smaller set and probe the larger, minimizing
                // membership lookups when sizes differ.
                let (smaller, larger) = if self.len() <= other.len() {
                    (self, other)
                } else {
                    (other, self)
                };
                $Intersection {
                    iter: smaller.iter(),
                    other: larger,
                }
            }

            /// Visits the values present in either `self` or `other`.
            pub fn union<'a>(&'a self, other: &'a Self) -> $Union<'a, T, S, A> {
                // Iterate the larger set in full and only the difference of the
                // smaller one, minimizing membership lookups.
                let (smaller, larger) = if self.len() <= other.len() {
                    (self, other)
                } else {
                    (other, self)
                };
                $Union {
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

        impl<T> Default for $Set<T, DefaultHashBuilder, Global>
        where
            T: Eq + Hash,
        {
            fn default() -> Self {
                Self::new()
            }
        }

        impl<T, S, A> Clone for $Set<T, S, A>
        where
            T: Clone + Eq + Hash,
            S: Clone + BuildHasher,
            A: Allocator + Clone,
        {
            fn clone(&self) -> Self {
                Self {
                    map: self.map.clone(),
                }
            }
        }

        impl<T, S, A> fmt::Debug for $Set<T, S, A>
        where
            T: fmt::Debug + Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_set().entries(self.iter()).finish()
            }
        }

        impl<T, S, A> PartialEq for $Set<T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn eq(&self, other: &Self) -> bool {
                self.len() == other.len() && self.iter().all(|value| other.contains(value))
            }
        }

        impl<T, S, A> Eq for $Set<T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
        }

        impl<T, S> FromIterator<T> for $Set<T, S, Global>
        where
            T: Eq + Hash,
            S: BuildHasher + Default,
        {
            fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
                let mut set = Self {
                    map: $Map::with_hasher(S::default()),
                };
                set.extend(iter);
                set
            }
        }

        impl<T, const N: usize> From<[T; N]> for $Set<T, DefaultHashBuilder, Global>
        where
            T: Eq + Hash,
        {
            fn from(arr: [T; N]) -> Self {
                arr.into_iter().collect()
            }
        }

        impl<T, S, A> Extend<T> for $Set<T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
                self.map.extend(iter.into_iter().map(|value| (value, ())));
            }
        }

        impl<'a, T, S, A> Extend<&'a T> for $Set<T, S, A>
        where
            T: 'a + Eq + Hash + Copy,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn extend<I: IntoIterator<Item = &'a T>>(&mut self, iter: I) {
                self.extend(iter.into_iter().copied());
            }
        }

        impl<'a, T, S, A> IntoIterator for &'a $Set<T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            type Item = &'a T;
            type IntoIter = $Iter<'a, T, S, A>;
            fn into_iter(self) -> $Iter<'a, T, S, A> {
                self.iter()
            }
        }

        impl<T, S, A> IntoIterator for $Set<T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            type Item = T;
            type IntoIter = $IntoIter<T, S, A>;
            fn into_iter(self) -> $IntoIter<T, S, A> {
                $IntoIter {
                    inner: self.map.into_keys(),
                }
            }
        }

        impl<T, S> BitOr<&$Set<T, S>> for &$Set<T, S>
        where
            T: Eq + Hash + Clone,
            S: BuildHasher + Default,
        {
            type Output = $Set<T, S>;
            fn bitor(self, rhs: &$Set<T, S>) -> $Set<T, S> {
                self.union(rhs).cloned().collect()
            }
        }

        impl<T, S> BitAnd<&$Set<T, S>> for &$Set<T, S>
        where
            T: Eq + Hash + Clone,
            S: BuildHasher + Default,
        {
            type Output = $Set<T, S>;
            fn bitand(self, rhs: &$Set<T, S>) -> $Set<T, S> {
                self.intersection(rhs).cloned().collect()
            }
        }

        impl<T, S> BitXor<&$Set<T, S>> for &$Set<T, S>
        where
            T: Eq + Hash + Clone,
            S: BuildHasher + Default,
        {
            type Output = $Set<T, S>;
            fn bitxor(self, rhs: &$Set<T, S>) -> $Set<T, S> {
                self.symmetric_difference(rhs).cloned().collect()
            }
        }

        impl<T, S> Sub<&$Set<T, S>> for &$Set<T, S>
        where
            T: Eq + Hash + Clone,
            S: BuildHasher + Default,
        {
            type Output = $Set<T, S>;
            fn sub(self, rhs: &$Set<T, S>) -> $Set<T, S> {
                self.difference(rhs).cloned().collect()
            }
        }

        impl<T, S, A> BitOrAssign<&$Set<T, S, A>> for $Set<T, S, A>
        where
            T: Eq + Hash + Clone,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn bitor_assign(&mut self, rhs: &$Set<T, S, A>) {
                for value in rhs {
                    if !self.contains(value) {
                        self.insert(value.clone());
                    }
                }
            }
        }

        impl<T, S, A> BitAndAssign<&$Set<T, S, A>> for $Set<T, S, A>
        where
            T: Eq + Hash + Clone,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn bitand_assign(&mut self, rhs: &$Set<T, S, A>) {
                self.retain(|value| rhs.contains(value));
            }
        }

        impl<T, S, A> BitXorAssign<&$Set<T, S, A>> for $Set<T, S, A>
        where
            T: Eq + Hash + Clone,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn bitxor_assign(&mut self, rhs: &$Set<T, S, A>) {
                for value in rhs {
                    if self.contains(value) {
                        self.remove(value);
                    } else {
                        self.insert(value.clone());
                    }
                }
            }
        }

        impl<T, S, A> SubAssign<&$Set<T, S, A>> for $Set<T, S, A>
        where
            T: Eq + Hash + Clone,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn sub_assign(&mut self, rhs: &$Set<T, S, A>) {
                if rhs.len() < self.len() {
                    for value in rhs {
                        self.remove(value);
                    }
                } else {
                    self.retain(|value| !rhs.contains(value));
                }
            }
        }

        #[doc = concat!("Borrowing iterator over [`", stringify!($Set), "`] values.")]
        pub struct $Iter<'a, T, S = DefaultHashBuilder, A: Allocator + Clone = Global>
        where
            T: Eq + Hash,
            S: BuildHasher,
        {
            inner: $MapKeys<'a, T, (), $($MapKeysTail)*>,
            _marker: PhantomData<S>,
        }

        impl<T, S, A> Clone for $Iter<'_, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn clone(&self) -> Self {
                Self {
                    inner: self.inner.clone(),
                    _marker: PhantomData,
                }
            }
        }

        impl<'a, T, S, A> Iterator for $Iter<'a, T, S, A>
        where
            T: 'a + Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            type Item = &'a T;
            fn next(&mut self) -> Option<&'a T> {
                self.inner.next()
            }
            fn size_hint(&self) -> (usize, Option<usize>) {
                self.inner.size_hint()
            }
        }

        impl<'a, T, S, A> ExactSizeIterator for $Iter<'a, T, S, A>
        where
            T: 'a + Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn len(&self) -> usize {
                self.inner.len()
            }
        }

        impl<'a, T, S, A> FusedIterator for $Iter<'a, T, S, A>
        where
            T: 'a + Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
        }

        impl<T, S, A> fmt::Debug for $Iter<'_, T, S, A>
        where
            T: fmt::Debug + Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list().entries(self.clone()).finish()
            }
        }

        #[doc = concat!("Consuming iterator over [`", stringify!($Set), "`] values.")]
        pub struct $IntoIter<T, S = DefaultHashBuilder, A: Allocator + Clone = Global>
        where
            T: Eq + Hash,
            S: BuildHasher,
        {
            inner: $MapIntoKeys<T, (), S, A>,
        }

        impl<T, S, A> Iterator for $IntoIter<T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            type Item = T;
            fn next(&mut self) -> Option<T> {
                self.inner.next()
            }
            fn size_hint(&self) -> (usize, Option<usize>) {
                self.inner.size_hint()
            }
        }

        impl<T, S, A> ExactSizeIterator for $IntoIter<T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn len(&self) -> usize {
                self.inner.len()
            }
        }

        impl<T, S, A> FusedIterator for $IntoIter<T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
        }

        impl<T, S, A> fmt::Debug for $IntoIter<T, S, A>
        where
            T: fmt::Debug + Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($IntoIter)).finish_non_exhaustive()
            }
        }

        #[doc = concat!("Draining iterator over [`", stringify!($Set), "`] values.")]
        pub struct $Drain<'a, T, S = DefaultHashBuilder, A: Allocator + Clone = Global>
        where
            T: Eq + Hash,
            S: BuildHasher,
        {
            inner: $MapDrain<'a, T, (), S, A>,
        }

        impl<T, S, A> Iterator for $Drain<'_, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            type Item = T;
            fn next(&mut self) -> Option<T> {
                match self.inner.next() {
                    Some((value, ())) => Some(value),
                    None => None,
                }
            }
            fn size_hint(&self) -> (usize, Option<usize>) {
                self.inner.size_hint()
            }
        }

        impl<T, S, A> ExactSizeIterator for $Drain<'_, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn len(&self) -> usize {
                self.inner.len()
            }
        }

        impl<T, S, A> FusedIterator for $Drain<'_, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
        }

        impl<T, S, A> fmt::Debug for $Drain<'_, T, S, A>
        where
            T: fmt::Debug + Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($Drain)).finish_non_exhaustive()
            }
        }

        #[doc = concat!("Iterator yielding the extracted values of a [`", stringify!($Set), "`].")]
        pub struct $ExtractIf<'a, T, S = DefaultHashBuilder, A: Allocator + Clone = Global>
        where
            T: Eq + Hash,
            S: BuildHasher,
        {
            inner: $MapExtractIf<'a, T, (), SetExtractPred<'a, T>, S, A>,
        }

        impl<T, S, A> Iterator for $ExtractIf<'_, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            type Item = T;
            fn next(&mut self) -> Option<T> {
                match self.inner.next() {
                    Some((value, ())) => Some(value),
                    None => None,
                }
            }
            fn size_hint(&self) -> (usize, Option<usize>) {
                (0, self.inner.size_hint().1)
            }
        }

        impl<T, S, A> FusedIterator for $ExtractIf<'_, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
        }

        impl<T, S, A> fmt::Debug for $ExtractIf<'_, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($ExtractIf)).finish_non_exhaustive()
            }
        }

        #[doc = concat!("Iterator over the difference of two [`", stringify!($Set), "`]s.")]
        pub struct $Difference<'a, T, S = DefaultHashBuilder, A: Allocator + Clone = Global>
        where
            T: Eq + Hash,
            S: BuildHasher,
        {
            iter: $Iter<'a, T, S, A>,
            other: &'a $Set<T, S, A>,
        }

        impl<T, S, A> Clone for $Difference<'_, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn clone(&self) -> Self {
                Self {
                    iter: self.iter.clone(),
                    other: self.other,
                }
            }
        }

        impl<'a, T, S, A> Iterator for $Difference<'a, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
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

        impl<T, S, A> FusedIterator for $Difference<'_, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
        }

        impl<T, S, A> fmt::Debug for $Difference<'_, T, S, A>
        where
            T: fmt::Debug + Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list().entries(self.clone()).finish()
            }
        }

        #[doc = concat!("Iterator over the intersection of two [`", stringify!($Set), "`]s.")]
        pub struct $Intersection<'a, T, S = DefaultHashBuilder, A: Allocator + Clone = Global>
        where
            T: Eq + Hash,
            S: BuildHasher,
        {
            iter: $Iter<'a, T, S, A>,
            other: &'a $Set<T, S, A>,
        }

        impl<T, S, A> Clone for $Intersection<'_, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn clone(&self) -> Self {
                Self {
                    iter: self.iter.clone(),
                    other: self.other,
                }
            }
        }

        impl<'a, T, S, A> Iterator for $Intersection<'a, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
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

        impl<T, S, A> FusedIterator for $Intersection<'_, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
        }

        impl<T, S, A> fmt::Debug for $Intersection<'_, T, S, A>
        where
            T: fmt::Debug + Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list().entries(self.clone()).finish()
            }
        }

        #[doc = concat!("Iterator over the symmetric difference of two [`", stringify!($Set), "`]s.")]
        pub struct $SymmetricDifference<'a, T, S = DefaultHashBuilder, A: Allocator + Clone = Global>
        where
            T: Eq + Hash,
            S: BuildHasher,
        {
            iter: Chain<$Difference<'a, T, S, A>, $Difference<'a, T, S, A>>,
        }

        impl<T, S, A> Clone for $SymmetricDifference<'_, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn clone(&self) -> Self {
                Self {
                    iter: self.iter.clone(),
                }
            }
        }

        impl<'a, T, S, A> Iterator for $SymmetricDifference<'a, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            type Item = &'a T;
            fn next(&mut self) -> Option<&'a T> {
                self.iter.next()
            }
            fn size_hint(&self) -> (usize, Option<usize>) {
                self.iter.size_hint()
            }
        }

        impl<T, S, A> FusedIterator for $SymmetricDifference<'_, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
        }

        impl<T, S, A> fmt::Debug for $SymmetricDifference<'_, T, S, A>
        where
            T: fmt::Debug + Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list().entries(self.clone()).finish()
            }
        }

        #[doc = concat!("Iterator over the union of two [`", stringify!($Set), "`]s.")]
        pub struct $Union<'a, T, S = DefaultHashBuilder, A: Allocator + Clone = Global>
        where
            T: Eq + Hash,
            S: BuildHasher,
        {
            iter: Chain<$Iter<'a, T, S, A>, $Difference<'a, T, S, A>>,
        }

        impl<T, S, A> Clone for $Union<'_, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn clone(&self) -> Self {
                Self {
                    iter: self.iter.clone(),
                }
            }
        }

        impl<'a, T, S, A> Iterator for $Union<'a, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            type Item = &'a T;
            fn next(&mut self) -> Option<&'a T> {
                self.iter.next()
            }
            fn size_hint(&self) -> (usize, Option<usize>) {
                self.iter.size_hint()
            }
        }

        impl<T, S, A> FusedIterator for $Union<'_, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
        }

        impl<T, S, A> fmt::Debug for $Union<'_, T, S, A>
        where
            T: fmt::Debug + Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list().entries(self.clone()).finish()
            }
        }

        #[doc = concat!("A view into a single [`", stringify!($Set), "`] entry.")]
        pub enum $Entry<'a, T, S = DefaultHashBuilder, A: Allocator + Clone = Global>
        where
            T: Eq + Hash,
            S: BuildHasher,
        {
            /// Value already present.
            Occupied($OccupiedEntry<'a, T, S, A>),
            /// Value absent.
            Vacant($VacantEntry<'a, T, S, A>),
        }

        #[doc = concat!("View of an occupied [`", stringify!($Set), "`] entry.")]
        pub struct $OccupiedEntry<'a, T, S = DefaultHashBuilder, A: Allocator + Clone = Global>
        where
            T: Eq + Hash,
            S: BuildHasher,
        {
            inner: $MapOccupied<'a, T, (), S, A>,
        }

        #[doc = concat!("View of a vacant [`", stringify!($Set), "`] entry.")]
        pub struct $VacantEntry<'a, T, S = DefaultHashBuilder, A: Allocator + Clone = Global>
        where
            T: Eq + Hash,
            S: BuildHasher,
        {
            inner: $MapVacant<'a, T, (), S, A>,
        }

        impl<'a, T, S, A> $Entry<'a, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            /// Ensures the value is present, returning the occupied entry.
            pub fn insert(self) -> $OccupiedEntry<'a, T, S, A> {
                match self {
                    $Entry::Occupied(entry) => entry,
                    $Entry::Vacant(entry) => entry.insert(),
                }
            }

            /// Ensures the value is present.
            pub fn or_insert(self) {
                if let $Entry::Vacant(entry) = self {
                    entry.insert();
                }
            }

            /// Reference to the entry's value.
            pub fn get(&self) -> &T {
                match self {
                    $Entry::Occupied(entry) => entry.get(),
                    $Entry::Vacant(entry) => entry.get(),
                }
            }
        }

        impl<'a, T, S, A> $OccupiedEntry<'a, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
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

        impl<'a, T, S, A> $VacantEntry<'a, T, S, A>
        where
            T: Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
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
            pub fn insert(self) -> $OccupiedEntry<'a, T, S, A> {
                $OccupiedEntry {
                    inner: self.inner.insert_entry(()),
                }
            }
        }

        impl<T, S, A> fmt::Debug for $OccupiedEntry<'_, T, S, A>
        where
            T: fmt::Debug + Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($OccupiedEntry))
                    .field("value", self.get())
                    .finish()
            }
        }

        impl<T, S, A> fmt::Debug for $VacantEntry<'_, T, S, A>
        where
            T: fmt::Debug + Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($VacantEntry))
                    .field(self.get())
                    .finish()
            }
        }

        impl<T, S, A> fmt::Debug for $Entry<'_, T, S, A>
        where
            T: fmt::Debug + Eq + Hash,
            S: BuildHasher,
            A: Allocator + Clone,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $Entry::Occupied(entry) => {
                        f.debug_tuple("Entry").field(entry).finish()
                    }
                    $Entry::Vacant(entry) => f.debug_tuple("Entry").field(entry).finish(),
                }
            }
        }
    };
}

define_hash_set! {
    set = ElasticHashSet,
    map = ElasticHashMap,
    iter = ElasticSetIter,
    into_iter = ElasticSetIntoIter,
    drain = ElasticSetDrain,
    extract_if = ElasticSetExtractIf,
    difference = ElasticDifference,
    intersection = ElasticIntersection,
    symmetric_difference = ElasticSymmetricDifference,
    union = ElasticUnion,
    entry = ElasticSetEntry,
    occupied_entry = ElasticSetOccupiedEntry,
    vacant_entry = ElasticSetVacantEntry,
    map_keys = ElasticMapKeys,
    map_keys_tail = (S, A),
    map_into_keys = ElasticIntoKeys,
    map_drain = ElasticMapDrain,
    map_extract_if = ElasticMapExtractIf,
    map_entry = ElasticMapEntry,
    map_occupied = ElasticMapOccupied,
    map_vacant = ElasticMapVacant,
}

define_hash_set! {
    set = FunnelHashSet,
    map = FunnelHashMap,
    iter = FunnelSetIter,
    into_iter = FunnelSetIntoIter,
    drain = FunnelSetDrain,
    extract_if = FunnelSetExtractIf,
    difference = FunnelDifference,
    intersection = FunnelIntersection,
    symmetric_difference = FunnelSymmetricDifference,
    union = FunnelUnion,
    entry = FunnelSetEntry,
    occupied_entry = FunnelSetOccupiedEntry,
    vacant_entry = FunnelSetVacantEntry,
    map_keys = FunnelMapKeys,
    map_keys_tail = (S, A),
    map_into_keys = FunnelIntoKeys,
    map_drain = FunnelMapDrain,
    map_extract_if = FunnelMapExtractIf,
    map_entry = FunnelMapEntry,
    map_occupied = FunnelMapOccupied,
    map_vacant = FunnelMapVacant,
}
