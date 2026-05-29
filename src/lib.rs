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
    Drain as ElasticDrain, ElasticHashMap, ElasticIntoIter, ElasticIntoKeys, ElasticIntoValues,
    ElasticIter, ElasticIterMut, ElasticValuesMut, ExtractIf as ElasticExtractIf,
    Keys as ElasticKeys, OccupiedError as ElasticOccupiedError, Values as ElasticValues,
};
pub use funnel::{
    Drain as FunnelDrain, ExtractIf as FunnelExtractIf, FunnelHashMap, FunnelIntoIter,
    FunnelIntoKeys, FunnelIntoValues, FunnelIter, FunnelIterMut, FunnelValuesMut,
    Keys as FunnelKeys, OccupiedError as FunnelOccupiedError, Values as FunnelValues,
};
// The entry types are the generic shell's enum/structs (the backend-side names
// are thin aliases). Re-exporting the real enum keeps
// `use ElasticEntry::{Occupied, Vacant}` / `use FunnelEntry::{Occupied, Vacant}`
// working, which a bare alias forbids.
pub use map::{
    Entry as ElasticEntry, Entry as FunnelEntry, OccupiedEntry as ElasticOccupiedEntry,
    OccupiedEntry as FunnelOccupiedEntry, VacantEntry as ElasticVacantEntry,
    VacantEntry as FunnelVacantEntry,
};
pub use set::{
    ElasticDifference, ElasticHashSet, ElasticIntersection, ElasticSetDrain, ElasticSetEntry,
    ElasticSetExtractIf, ElasticSetIntoIter, ElasticSetIter, ElasticSetOccupiedEntry,
    ElasticSetVacantEntry, ElasticSymmetricDifference, ElasticUnion, FunnelDifference,
    FunnelHashSet, FunnelIntersection, FunnelSetDrain, FunnelSetEntry, FunnelSetExtractIf,
    FunnelSetIntoIter, FunnelSetIter, FunnelSetOccupiedEntry, FunnelSetVacantEntry,
    FunnelSymmetricDifference, FunnelUnion,
};
