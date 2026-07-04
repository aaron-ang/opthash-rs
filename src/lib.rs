#![cfg_attr(feature = "nightly", feature(allocator_api))]

mod common;
mod elastic;
mod funnel;
mod macros;
mod map;
mod set;

#[cfg(feature = "python")]
mod python;

pub use equivalent::Equivalent;

pub use common::DefaultHashBuilder;
pub use common::error::TryReserveError;

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
