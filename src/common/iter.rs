use std::fmt;
use std::iter::FusedIterator;

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
