use core::error::Error;
use core::fmt;

/// An exact dyadic reserve fraction `delta = 1 / 2^d`.
///
/// The exponent is stored directly so capacity calculations never depend on
/// floating-point rounding.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReserveFraction {
    delta_log2: u32,
}

impl ReserveFraction {
    /// The default reserve fraction `1/8`.
    pub const DEFAULT: Self = Self { delta_log2: 3 };

    /// Creates `delta = 1 / 2^delta_log2`.
    ///
    /// # Errors
    ///
    /// Returns [`ReserveFractionError::DeltaLog2Zero`] for `delta_log2 == 0`,
    /// which would represent `delta = 1` rather than a fraction below one.
    pub const fn from_delta_log2(delta_log2: u32) -> Result<Self, ReserveFractionError> {
        if delta_log2 == 0 {
            return Err(ReserveFractionError::DeltaLog2Zero);
        }
        Ok(Self { delta_log2 })
    }

    /// Returns `d` from the exact representation `delta = 1 / 2^d`.
    #[must_use]
    pub const fn delta_log2(self) -> u32 {
        self.delta_log2
    }

    /// Returns `floor(delta * n)` using exact integer arithmetic.
    #[must_use]
    pub const fn floor_reserved(self, n: usize) -> usize {
        floor_div_pow2(n, self.delta_log2 as u64)
    }

    /// Returns `floor(delta * n / 2)` using exact integer arithmetic.
    #[must_use]
    pub const fn floor_half_reserved(self, n: usize) -> usize {
        floor_div_pow2(n, self.delta_log2 as u64 + 1)
    }

    /// Returns the exact `f64` representation when one exists.
    ///
    /// Binary64 represents inverse powers of two through `2^-1074`; larger
    /// exponents return `None` rather than underflowing to zero.
    #[must_use]
    pub const fn as_f64(self) -> Option<f64> {
        match self.delta_log2 {
            1..=1_022 => {
                let biased_exponent = 1_023_u64 - self.delta_log2 as u64;
                Some(f64::from_bits(biased_exponent << 52))
            }
            1_023..=1_074 => {
                let significand_bit = 1_074_u32 - self.delta_log2;
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
        let biased_exponent = ((bits >> 52) & 0x7ff) as u32;
        let significand = bits & ((1_u64 << 52) - 1);

        let delta_log2 = if biased_exponent == 0 {
            if !significand.is_power_of_two() {
                return Err(ReserveFractionError::NotInversePowerOfTwo);
            }
            1_074 - significand.trailing_zeros()
        } else {
            if significand != 0 {
                return Err(ReserveFractionError::NotInversePowerOfTwo);
            }
            1_023 - biased_exponent
        };

        Self::from_delta_log2(delta_log2)
    }
}

/// A reserve fraction cannot be represented by the exact dyadic model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReserveFractionError {
    /// Exponent zero would represent one, outside the open unit interval.
    DeltaLog2Zero,
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
            Self::DeltaLog2Zero => f.write_str("reserve exponent must be positive"),
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

const fn floor_div_pow2(value: usize, exponent: u64) -> usize {
    if exponent >= usize::BITS as u64 {
        0
    } else {
        value >> exponent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_exactly_one_eighth() {
        assert_eq!(ReserveFraction::DEFAULT.delta_log2(), 3);
        assert_eq!(ReserveFraction::DEFAULT.as_f64(), Some(0.125));
        assert_eq!(
            ReserveFraction::try_from(0.125),
            Ok(ReserveFraction::DEFAULT)
        );
    }
}
