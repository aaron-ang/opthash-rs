use std::fmt;
use std::iter::FusedIterator;

use crate::common::bitmask::BitMask;
use crate::common::config::GROUP_SIZE;
use crate::common::layout::RawTable;
use crate::common::simd::occupied_mask_16;

/// SIMD scanner: yields one occupied slot at a time, refilling its mask one
/// group at a time. Call [`Self::reset`] between tables.
#[derive(Clone, Copy)]
pub(crate) struct OccupiedScanner {
    next_group_slot: usize,
    current_group_slot: usize,
    current_mask: BitMask,
}

impl OccupiedScanner {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            next_group_slot: 0,
            current_group_slot: 0,
            current_mask: BitMask(0),
        }
    }

    #[inline]
    pub(crate) fn reset(&mut self) {
        self.next_group_slot = 0;
        self.current_group_slot = 0;
        self.current_mask = BitMask(0);
    }

    /// Next occupied slot in `table`, or `None` when exhausted.
    #[inline]
    pub(crate) fn next_in<T, A: allocator_api2::alloc::Allocator>(
        &mut self,
        table: &RawTable<T, A>,
    ) -> Option<usize> {
        loop {
            if let Some(bit) = self.current_mask.next() {
                return Some(self.current_group_slot + bit);
            }
            if self.next_group_slot >= table.capacity() {
                return None;
            }
            let group_idx = self.next_group_slot / GROUP_SIZE;
            let group_ptr = table.group_data_ptr(group_idx);
            let mut mask = unsafe { occupied_mask_16(group_ptr) };
            let group_end = self.next_group_slot + GROUP_SIZE;
            if group_end > table.capacity() {
                mask = mask.truncate_to(table.capacity() - self.next_group_slot);
            }
            self.current_mask = mask;
            self.current_group_slot = self.next_group_slot;
            self.next_group_slot = group_end;
        }
    }
}

/// Projects the `K` from a borrowing `(&K, &V)` iterator.
pub struct Keys<I> {
    inner: I,
}

impl<I> Keys<I> {
    pub(crate) fn new(inner: I) -> Self {
        Self { inner }
    }
}

impl<I: Clone> Clone for Keys<I> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<I, K, V> Iterator for Keys<I>
where
    I: Iterator<Item = (K, V)>,
{
    type Item = K;
    #[inline]
    fn next(&mut self) -> Option<K> {
        self.inner.next().map(|(k, _)| k)
    }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
    #[inline]
    fn fold<B, F: FnMut(B, K) -> B>(self, init: B, mut f: F) -> B {
        self.inner.fold(init, move |acc, (k, _)| f(acc, k))
    }
    #[inline]
    fn for_each<F: FnMut(K)>(self, mut f: F) {
        self.inner.for_each(move |(k, _)| f(k));
    }
}

impl<I, K, V> FusedIterator for Keys<I> where I: FusedIterator<Item = (K, V)> {}

impl<I> fmt::Debug for Keys<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keys").finish_non_exhaustive()
    }
}

/// Projects the `V` from a borrowing `(&K, &V)` iterator.
pub struct Values<I> {
    inner: I,
}

impl<I> Values<I> {
    pub(crate) fn new(inner: I) -> Self {
        Self { inner }
    }
}

impl<I: Clone> Clone for Values<I> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<I, K, V> Iterator for Values<I>
where
    I: Iterator<Item = (K, V)>,
{
    type Item = V;
    #[inline]
    fn next(&mut self) -> Option<V> {
        self.inner.next().map(|(_, v)| v)
    }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
    #[inline]
    fn fold<B, F: FnMut(B, V) -> B>(self, init: B, mut f: F) -> B {
        self.inner.fold(init, move |acc, (_, v)| f(acc, v))
    }
    #[inline]
    fn for_each<F: FnMut(V)>(self, mut f: F) {
        self.inner.for_each(move |(_, v)| f(v));
    }
}

impl<I, K, V> FusedIterator for Values<I> where I: FusedIterator<Item = (K, V)> {}

impl<I> fmt::Debug for Values<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Values").finish_non_exhaustive()
    }
}

/// Projects the owned `K` from a consuming `(K, V)` iterator.
pub struct IntoKeys<I> {
    inner: I,
}

impl<I> IntoKeys<I> {
    pub(crate) fn new(inner: I) -> Self {
        Self { inner }
    }
}

impl<I, K, V> Iterator for IntoKeys<I>
where
    I: Iterator<Item = (K, V)>,
{
    type Item = K;
    #[inline]
    fn next(&mut self) -> Option<K> {
        self.inner.next().map(|(k, _)| k)
    }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
    #[inline]
    fn fold<B, F: FnMut(B, K) -> B>(self, init: B, mut f: F) -> B {
        self.inner.fold(init, move |acc, (k, _)| f(acc, k))
    }
    #[inline]
    fn for_each<F: FnMut(K)>(self, mut f: F) {
        self.inner.for_each(move |(k, _)| f(k));
    }
}

impl<I, K, V> FusedIterator for IntoKeys<I> where I: FusedIterator<Item = (K, V)> {}

impl<I> fmt::Debug for IntoKeys<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntoKeys").finish_non_exhaustive()
    }
}

/// Projects the owned `V` from a consuming `(K, V)` iterator.
pub struct IntoValues<I> {
    inner: I,
}

impl<I> IntoValues<I> {
    pub(crate) fn new(inner: I) -> Self {
        Self { inner }
    }
}

impl<I, K, V> Iterator for IntoValues<I>
where
    I: Iterator<Item = (K, V)>,
{
    type Item = V;
    #[inline]
    fn next(&mut self) -> Option<V> {
        self.inner.next().map(|(_, v)| v)
    }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
    #[inline]
    fn fold<B, F: FnMut(B, V) -> B>(self, init: B, mut f: F) -> B {
        self.inner.fold(init, move |acc, (_, v)| f(acc, v))
    }
    #[inline]
    fn for_each<F: FnMut(V)>(self, mut f: F) {
        self.inner.for_each(move |(_, v)| f(v));
    }
}

impl<I, K, V> FusedIterator for IntoValues<I> where I: FusedIterator<Item = (K, V)> {}

impl<I> fmt::Debug for IntoValues<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntoValues").finish_non_exhaustive()
    }
}
