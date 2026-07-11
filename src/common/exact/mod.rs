//! Exact finite geometry and probe primitives used by the production maps.

mod geometry;
mod probe;
#[cfg(test)]
pub(crate) mod reference;

#[cfg(test)]
pub(crate) use geometry::FunnelPlan;
pub(crate) use geometry::PaperConfig;
pub(crate) use probe::{
    CounterPrf, FunnelPrf, PreparedElasticLevelProbe, PreparedElasticProbe,
    PreparedFastFunnelDomainProbe, PreparedProbeRange, ProbeDomain, elastic_dyadic_probe_budget,
    elastic_phi, unbiased_prepared_elastic_probe_index,
    unbiased_prepared_funnel_probe_index_in_range,
};
#[cfg(test)]
pub(crate) use probe::{
    ProbeOracle, RangeReductionError, elastic_phi_inverse, unbiased_probe_index,
};
