/// Default `BuildHasher` for the maps' `S` type parameter.
///
/// Always exists so the `S = DefaultHashBuilder` defaults on the public type
/// aliases stay valid, but only implements [`core::hash::BuildHasher`] when the
/// `default-hasher` feature is enabled (wrapping [`foldhash::fast::RandomState`]).
/// With the feature off it is an empty placeholder and callers must supply an
/// explicit hasher `S`.
#[derive(Clone, Debug, Default)]
pub struct DefaultHashBuilder {
    #[cfg(feature = "default-hasher")]
    inner: foldhash::fast::RandomState,
}

#[cfg(feature = "default-hasher")]
impl core::hash::BuildHasher for DefaultHashBuilder {
    type Hasher = <foldhash::fast::RandomState as core::hash::BuildHasher>::Hasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        self.inner.build_hasher()
    }
}
