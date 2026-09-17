use core::error::Error;
use core::fmt;

use crate::common::exact::geometry;

/// An exact dyadic reserve fraction `delta = 1 / 2^d`.
///
/// The exponent is stored directly so capacity calculations never depend on
/// floating-point rounding.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReserveFraction {
    exponent: u32,
}

/// Binary64 exponent bias: `2^-d` for `d < F64_EXPONENT_BIAS` is a normal
/// value with biased exponent `F64_EXPONENT_BIAS - d`.
const F64_EXPONENT_BIAS: u32 = (f64::MAX_EXP - 1) as u32;
/// Fraction bits below the binary64 exponent field.
const F64_MANTISSA_BITS: u32 = f64::MANTISSA_DIGITS - 1;
/// `2^-1074` is the smallest binary64 subnormal; larger `d` has no representation.
const F64_MIN_SUBNORMAL_EXPONENT: u32 = F64_EXPONENT_BIAS + F64_MANTISSA_BITS - 1;

impl ReserveFraction {
    /// The default reserve fraction `1/8`.
    pub const DEFAULT: Self = Self { exponent: 3 };

    /// Creates `delta = 1 / 2^exponent`.
    ///
    /// # Errors
    ///
    /// Returns [`ReserveFractionError::ExponentZero`] for `exponent == 0`,
    /// which would represent `delta = 1` rather than a fraction below one.
    pub const fn from_exponent(exponent: u32) -> Result<Self, ReserveFractionError> {
        if exponent == 0 {
            return Err(ReserveFractionError::ExponentZero);
        }
        Ok(Self { exponent })
    }

    /// Returns `d` from the exact representation `delta = 1 / 2^d`.
    #[must_use]
    pub const fn exponent(self) -> u32 {
        self.exponent
    }

    /// Returns `floor(delta * n)` using exact integer arithmetic.
    #[must_use]
    pub const fn floor_reserved(self, n: usize) -> usize {
        geometry::floor_div_pow2(n, self.exponent as u64)
    }

    /// Returns `floor(delta * n / 2)` using exact integer arithmetic.
    #[must_use]
    pub const fn floor_half_reserved(self, n: usize) -> usize {
        geometry::floor_div_pow2(n, self.exponent as u64 + 1)
    }

    /// Returns the exact `f64` representation when one exists.
    ///
    /// Binary64 represents inverse powers of two through `2^-1074`; larger
    /// exponents return `None` rather than underflowing to zero.
    #[must_use]
    pub const fn as_f64(self) -> Option<f64> {
        match self.exponent {
            1..F64_EXPONENT_BIAS => {
                let biased_exponent = (F64_EXPONENT_BIAS - self.exponent) as u64;
                Some(f64::from_bits(biased_exponent << F64_MANTISSA_BITS))
            }
            F64_EXPONENT_BIAS..=F64_MIN_SUBNORMAL_EXPONENT => {
                let significand_bit = F64_MIN_SUBNORMAL_EXPONENT - self.exponent;
                Some(f64::from_bits(1_u64 << significand_bit))
            }
            _ => None,
        }
    }
}

impl TryFrom<f64> for ReserveFraction {
    type Error = ReserveFractionError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        if !value.is_finite() {
            return Err(ReserveFractionError::NonFinite);
        }
        if value <= 0.0 {
            return Err(ReserveFractionError::NonPositive);
        }
        if value >= 1.0 {
            return Err(ReserveFractionError::NotBelowOne);
        }

        let bits = value.to_bits();
        let biased_exponent = ((bits >> F64_MANTISSA_BITS) & 0x7ff) as u32;
        let significand = bits & ((1_u64 << F64_MANTISSA_BITS) - 1);

        let exponent = if biased_exponent == 0 {
            if !significand.is_power_of_two() {
                return Err(ReserveFractionError::NotInversePowerOfTwo);
            }
            F64_MIN_SUBNORMAL_EXPONENT - significand.trailing_zeros()
        } else {
            if significand != 0 {
                return Err(ReserveFractionError::NotInversePowerOfTwo);
            }
            F64_EXPONENT_BIAS - biased_exponent
        };

        Self::from_exponent(exponent)
    }
}

/// A reserve fraction cannot be represented by the exact dyadic model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReserveFractionError {
    /// Exponent zero would represent one, outside the open unit interval.
    ExponentZero,
    /// A floating-point input was NaN or infinite.
    NonFinite,
    /// A floating-point input was zero or negative.
    NonPositive,
    /// A floating-point input was at least one.
    NotBelowOne,
    /// A floating-point input was not exactly `1 / 2^d`.
    NotInversePowerOfTwo,
}

impl fmt::Display for ReserveFractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExponentZero => f.write_str("reserve exponent must be positive"),
            Self::NonFinite => f.write_str("reserve fraction must be finite"),
            Self::NonPositive => f.write_str("reserve fraction must be positive"),
            Self::NotBelowOne => f.write_str("reserve fraction must be less than one"),
            Self::NotInversePowerOfTwo => {
                f.write_str("reserve fraction must be an exact inverse power of two")
            }
        }
    }
}

impl Error for ReserveFractionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_exactly_one_eighth() {
        assert_eq!(ReserveFraction::DEFAULT.exponent(), 3);
        assert_eq!(ReserveFraction::DEFAULT.as_f64(), Some(0.125));
        assert_eq!(
            ReserveFraction::try_from(0.125),
            Ok(ReserveFraction::DEFAULT)
        );
    }
}
