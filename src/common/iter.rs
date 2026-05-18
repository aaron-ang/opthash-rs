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
    fn next(&mut self) -> Option<K> {
        self.inner.next().map(|(k, _)| k)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<I> std::fmt::Debug for Keys<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    fn next(&mut self) -> Option<V> {
        self.inner.next().map(|(_, v)| v)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<I> std::fmt::Debug for Values<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    fn next(&mut self) -> Option<K> {
        self.inner.next().map(|(k, _)| k)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<I> std::fmt::Debug for IntoKeys<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    fn next(&mut self) -> Option<V> {
        self.inner.next().map(|(_, v)| v)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<I> std::fmt::Debug for IntoValues<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntoValues").finish_non_exhaustive()
    }
}
