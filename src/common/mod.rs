pub(crate) mod bitmask;
pub(crate) mod config;
pub(crate) mod control;
pub(crate) mod error;
pub(crate) mod iter;
pub(crate) mod math;
pub(crate) mod simd;
pub(crate) mod table;

pub use allocator_api2::alloc::{Allocator, Global};

pub use error::TryReserveError;

pub type DefaultHashBuilder = foldhash::fast::RandomState;
