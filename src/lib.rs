#![cfg_attr(feature = "nightly", feature(allocator_api))]

mod common;
mod elastic;
mod funnel;
mod map;
mod set;

#[cfg(feature = "python")]
mod python;

pub use equivalent::Equivalent;

pub use common::DefaultHashBuilder;
pub use common::error::TryReserveError;

pub use elastic::{
    Drain as ElasticDrain, ElasticDifference, ElasticHashMap, ElasticHashSet, ElasticIntersection,
    ElasticIntoIter, ElasticIntoKeys, ElasticIntoValues, ElasticIter, ElasticIterMut,
    ElasticSetDrain, ElasticSetEntry, ElasticSetExtractIf, ElasticSetIntoIter, ElasticSetIter,
    ElasticSetOccupiedEntry, ElasticSetVacantEntry, ElasticSymmetricDifference, ElasticUnion,
    ElasticValuesMut, Entry as ElasticEntry, ExtractIf as ElasticExtractIf, Keys as ElasticKeys,
    OccupiedEntry as ElasticOccupiedEntry, OccupiedError as ElasticOccupiedError,
    VacantEntry as ElasticVacantEntry, Values as ElasticValues,
};
pub use funnel::{
    Drain as FunnelDrain, Entry as FunnelEntry, ExtractIf as FunnelExtractIf, FunnelDifference,
    FunnelHashMap, FunnelHashSet, FunnelIntersection, FunnelIntoIter, FunnelIntoKeys,
    FunnelIntoValues, FunnelIter, FunnelIterMut, FunnelSetDrain, FunnelSetEntry,
    FunnelSetExtractIf, FunnelSetIntoIter, FunnelSetIter, FunnelSetOccupiedEntry,
    FunnelSetVacantEntry, FunnelSymmetricDifference, FunnelUnion, FunnelValuesMut,
    Keys as FunnelKeys, OccupiedEntry as FunnelOccupiedEntry, OccupiedError as FunnelOccupiedError,
    VacantEntry as FunnelVacantEntry, Values as FunnelValues,
};
