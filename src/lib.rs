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
    ElasticSetDrain, ElasticSetExtractIf, ElasticSetIntoIter, ElasticSetIter,
    ElasticSymmetricDifference, ElasticUnion, ElasticValuesMut, ExtractIf as ElasticExtractIf,
    Keys as ElasticKeys, OccupiedError as ElasticOccupiedError, Values as ElasticValues,
};
pub use funnel::{
    Drain as FunnelDrain, ExtractIf as FunnelExtractIf, FunnelDifference, FunnelHashMap,
    FunnelHashSet, FunnelIntersection, FunnelIntoIter, FunnelIntoKeys, FunnelIntoValues,
    FunnelIter, FunnelIterMut, FunnelSetDrain, FunnelSetExtractIf, FunnelSetIntoIter,
    FunnelSetIter, FunnelSymmetricDifference, FunnelUnion, FunnelValuesMut, Keys as FunnelKeys,
    OccupiedError as FunnelOccupiedError, Values as FunnelValues,
};

pub use map::{
    Entry as ElasticEntry, Entry as FunnelEntry, OccupiedEntry as ElasticOccupiedEntry,
    OccupiedEntry as FunnelOccupiedEntry, VacantEntry as ElasticVacantEntry,
    VacantEntry as FunnelVacantEntry,
};
pub use set::{
    Entry as ElasticSetEntry, Entry as FunnelSetEntry, OccupiedEntry as ElasticSetOccupiedEntry,
    OccupiedEntry as FunnelSetOccupiedEntry, VacantEntry as ElasticSetVacantEntry,
    VacantEntry as FunnelSetVacantEntry,
};
