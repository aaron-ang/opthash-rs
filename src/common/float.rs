//! `no_std` fallbacks for the `std`-only [`prim@f64`] methods the cold layout
//! math uses (`log2`, `powi`, `floor`, `ceil`, `round`). Compiled only when
//! `std` is off; with `std` on the inherent methods are used unchanged, so the
//! default build is untouched. (`max`/`min`/`clamp` are in `core` — no fallback.)

/// Extension trait re-supplying the `std`-only [`prim@f64`] methods used by the
/// layout math when the `std` feature is disabled.
pub(crate) trait FloatExt {
    /// Base-2 logarithm; see [`f64::log2`].
    fn log2(self) -> Self;
    /// Raise to an integer power; see [`f64::powi`].
    fn powi(self, n: i32) -> Self;
    /// Round toward negative infinity; see [`f64::floor`].
    fn floor(self) -> Self;
    /// Round toward positive infinity; see [`f64::ceil`].
    fn ceil(self) -> Self;
    /// Round to the nearest integer; see [`f64::round`].
    fn round(self) -> Self;
}

impl FloatExt for f64 {
    #[inline]
    fn log2(self) -> Self {
        libm::log2(self)
    }
    #[inline]
    fn powi(self, n: i32) -> Self {
        // Exponentiation by squaring — mirrors `f64::powi`'s repeated-multiply
        // semantics, so `no_std` layout math matches the `std` build. (`pow`'s
        // exp/log path would round differently and could diverge by an ULP.)
        let mut acc = 1.0_f64;
        let mut base = self;
        let mut exp = n.unsigned_abs();
        while exp > 0 {
            if exp & 1 == 1 {
                acc *= base;
            }
            exp >>= 1;
            if exp > 0 {
                base *= base;
            }
        }
        if n < 0 { 1.0 / acc } else { acc }
    }
    #[inline]
    fn floor(self) -> Self {
        libm::floor(self)
    }
    #[inline]
    fn ceil(self) -> Self {
        libm::ceil(self)
    }
    #[inline]
    fn round(self) -> Self {
        libm::round(self)
    }
}
