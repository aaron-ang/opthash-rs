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
#![warn(missing_debug_implementations)]

extern crate alloc;

mod capacity;
mod elastic;
mod epoch;
mod error;
mod exact;
mod funnel;
mod hasher;
mod macros;
mod map;
mod membership;
mod raw;
mod reserve;
mod set;
#[cfg(test)]
mod test_support;

#[cfg(feature = "python")]
mod python;

/// Compiles and runs the README's Rust snippets as doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

pub use equivalent::Equivalent;

pub use epoch::{EpochSnapshot, EpochTransition};
pub use error::{TryBuildError, TryReserveError};
pub use hasher::DefaultHashBuilder;
pub use reserve::{ReserveFraction, ReserveFractionError};

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

/// The generic map shell behind [`ElasticHashMap`] and [`FunnelHashMap`],
/// with its entry and iterator types.
///
/// Name these through the backend aliases; this module exists so their
/// methods and trait impls are documented in one place.
pub mod hash_map {
    pub use crate::map::{
        Drain, Entry, ExtractIf, HashMap, IntoIter, IntoKeys, IntoValues, Iter, IterMut, Keys,
        OccupiedEntry, OccupiedError, VacantEntry, Values, ValuesMut,
    };
}

/// The generic set shell behind [`ElasticHashSet`] and [`FunnelHashSet`],
/// with its entry and iterator types.
///
/// Name these through the backend aliases; this module exists so their
/// methods and trait impls are documented in one place.
pub mod hash_set {
    pub use crate::set::{
        Difference, Drain, Entry, ExtractIf, HashSet, Intersection, IntoIter, Iter, OccupiedEntry,
        SymmetricDifference, Union, VacantEntry,
    };
}
