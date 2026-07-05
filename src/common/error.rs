use core::error::Error;
use core::fmt;

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
