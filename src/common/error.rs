use core::error::Error;
use core::fmt;

use crate::common::reserve::ReserveFractionError;

/// Error returned by fallible map and set constructors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TryBuildError {
    /// A floating-point compatibility input was not an exact dyadic fraction.
    InvalidReserveFraction(ReserveFractionError),
    /// Funnel Hashing requires `delta <= 1/8`.
    FunnelDeltaLog2BelowMinimum {
        /// Rejected exponent in `delta = 1 / 2^d`.
        delta_log2: u32,
        /// Smallest exponent supported by Funnel Hashing.
        minimum: u32,
    },
    /// Capacity computation overflowed `usize`.
    CapacityOverflow,
    /// Allocator failed.
    AllocError,
}

impl fmt::Display for TryBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidReserveFraction(error) => error.fmt(f),
            Self::FunnelDeltaLog2BelowMinimum {
                delta_log2,
                minimum,
            } => write!(
                f,
                "Funnel reserve exponent {delta_log2} is below the minimum {minimum}"
            ),
            Self::CapacityOverflow => f.write_str("capacity overflow"),
            Self::AllocError => f.write_str("memory allocation failed"),
        }
    }
}

impl Error for TryBuildError {}

impl From<ReserveFractionError> for TryBuildError {
    fn from(error: ReserveFractionError) -> Self {
        Self::InvalidReserveFraction(error)
    }
}

impl From<TryReserveError> for TryBuildError {
    fn from(error: TryReserveError) -> Self {
        match error {
            TryReserveError::CapacityOverflow => Self::CapacityOverflow,
            TryReserveError::AllocError => Self::AllocError,
        }
    }
}

/// Error returned by `try_reserve` when the map can't grow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TryReserveError {
    /// Capacity computation overflowed `usize`.
    CapacityOverflow,
    /// Allocator failed.
    AllocError,
}

impl fmt::Display for TryReserveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityOverflow => f.write_str("capacity overflow"),
            Self::AllocError => f.write_str("memory allocation failed"),
        }
    }
}

impl Error for TryReserveError {}
