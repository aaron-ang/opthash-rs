//! Open-addressing hash maps and sets built on Elastic Hashing and Funnel
//! Hashing, sharing a `SwissTable`-style control-byte core.
//!
//! The crate is `no_std` (needs `alloc`); the default features `std` and
//! `default-hasher` are on for the usual std-backed, `foldhash`-seeded setup.
//! Disable them for a `core`-only build where callers supply their own hasher.
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "nightly", feature(allocator_api))]
// Library-API lints, scoped here rather than in `Cargo.toml [lints]` so they
// govern only the library and not benches/tests/build-script.
#![warn(missing_docs)]
#![warn(unreachable_pub)]

extern crate alloc;

mod common;
mod elastic;
mod epoch;
mod funnel;
mod macros;
mod map;
mod set;

#[cfg(feature = "python")]
mod python;

pub use equivalent::Equivalent;

pub use common::DefaultHashBuilder;
pub use common::error::{TryBuildError, TryReserveError};
pub use common::reserve::{ReserveFraction, ReserveFractionError};
pub use epoch::{EpochSnapshot, EpochTransition};

pub use elastic::{
    ElasticDifference, ElasticDrain, ElasticEntry, ElasticExtractIf, ElasticHashMap,
    ElasticHashSet, ElasticIntersection, ElasticIntoIter, ElasticIntoKeys, ElasticIntoValues,
    ElasticIter, ElasticIterMut, ElasticKeys, ElasticOccupiedEntry, ElasticOccupiedError,
    ElasticSetDrain, ElasticSetEntry, ElasticSetExtractIf, ElasticSetIntoIter, ElasticSetIter,
    ElasticSetOccupiedEntry, ElasticSetVacantEntry, ElasticSymmetricDifference, ElasticUnion,
    ElasticVacantEntry, ElasticValues, ElasticValuesMut,
};
pub use funnel::{
    FunnelDifference, FunnelDrain, FunnelEntry, FunnelExtractIf, FunnelHashMap, FunnelHashSet,
    FunnelIntersection, FunnelIntoIter, FunnelIntoKeys, FunnelIntoValues, FunnelIter,
    FunnelIterMut, FunnelKeys, FunnelOccupiedEntry, FunnelOccupiedError, FunnelSetDrain,
    FunnelSetEntry, FunnelSetExtractIf, FunnelSetIntoIter, FunnelSetIter, FunnelSetOccupiedEntry,
    FunnelSetVacantEntry, FunnelSymmetricDifference, FunnelUnion, FunnelVacantEntry, FunnelValues,
    FunnelValuesMut,
};
