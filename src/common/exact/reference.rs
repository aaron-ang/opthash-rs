use alloc::vec;
use alloc::vec::Vec;
use core::num::{NonZeroU32, NonZeroU64, NonZeroU128, NonZeroUsize};

use super::geometry::{FunnelPlan, PaperConfig};
use super::probe::{self, ProbeDomain, ProbeOracle, RangeReductionError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScalarElasticLimits {
    probe_budget_c: NonZeroUsize,
    range_word_cap: NonZeroU32,
    uniform_search_probe_cap: NonZeroU64,
    hit_query_position_cap: NonZeroU128,
}

impl ScalarElasticLimits {
    pub(crate) const fn new(
        probe_budget_c: NonZeroUsize,
        range_word_cap: NonZeroU32,
        uniform_search_probe_cap: NonZeroU64,
        hit_query_position_cap: NonZeroU128,
    ) -> Self {
        Self {
            probe_budget_c,
            range_word_cap,
            uniform_search_probe_cap,
            hit_query_position_cap,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScalarElasticCase {
    Batch0 {
        level: usize,
    },
    Case1 {
        batch: usize,
        current_level: usize,
        next_level: usize,
        free_current: usize,
        free_next: usize,
        budget: usize,
    },
    Case2 {
        batch: usize,
        current_level: usize,
        next_level: usize,
        free_current: usize,
        free_next: usize,
    },
    Case3 {
        batch: usize,
        current_level: usize,
        next_level: usize,
        free_current: usize,
        free_next: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScalarElasticLocation {
    pub(crate) level: usize,
    pub(crate) slot_in_level: usize,
    pub(crate) global_slot: usize,
}

impl ScalarElasticLocation {
    const fn new(level: usize, slot_in_level: usize, global_slot: usize) -> Self {
        Self {
            level,
            slot_in_level,
            global_slot,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScalarElasticInsertion {
    pub(crate) case: ScalarElasticCase,
    pub(crate) location: ScalarElasticLocation,
    pub(crate) paper_probe: u64,
    pub(crate) phi: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScalarElasticQuery {
    found_position: u128,
    global_slot: usize,
    logical_positions: u128,
    mapped_positions: u128,
    gap_positions: u128,
    scalar_inspections: u128,
    random_words: u128,
}

pub(crate) struct ScalarElastic<O> {
    config: PaperConfig,
    oracle: O,
    limits: ScalarElasticLimits,
    levels: Vec<usize>,
    offsets: Vec<usize>,
    quotas: Vec<usize>,
    occupancy: Vec<usize>,
    slots: Vec<Option<u64>>,
    len: usize,
}

impl<O: ProbeOracle> ScalarElastic<O> {
    pub(crate) fn new(config: PaperConfig, oracle: O, limits: ScalarElasticLimits) -> Self {
        let plan = config.elastic_plan();
        let levels = plan.level_lengths().collect::<Vec<_>>();
        let mut offsets = Vec::with_capacity(levels.len());
        let mut offset = 0;
        for &length in &levels {
            offsets.push(offset);
            offset += length;
        }
        assert_eq!(offset, config.n());
        Self {
            config,
            oracle,
            limits,
            quotas: plan.batch_quotas().collect(),
            occupancy: vec![0; levels.len()],
            slots: vec![None; config.n()],
            levels,
            offsets,
            len: 0,
        }
    }

    pub(crate) fn insert(&mut self, identity: u64) -> ScalarElasticInsertion {
        assert!(
            !self.slots.contains(&Some(identity)),
            "scalar Elastic insertion identities must be distinct"
        );
        let batch = self
            .active_batch()
            .expect("scalar Elastic insertion exceeded the exact target");
        let (case, level, slot_in_level, paper_probe) = if batch == 0 {
            let (slot, probe) = self.uniform_vacancy(0, identity);
            (ScalarElasticCase::Batch0 { level: 0 }, 0, slot, probe)
        } else {
            let current = batch - 1;
            let next = batch;
            let free_current = self.levels[current] - self.occupancy[current];
            let free_next = self.levels[next] - self.occupancy[next];
            let current_threshold = scalar_floor_div_pow2(
                self.levels[current],
                self.config.reserve_exponent().saturating_add(1),
            );
            let next_threshold = self.levels[next] / 4;
            let current_low = free_current <= current_threshold;
            let next_low = free_next <= next_threshold;
            assert!(
                !(current_low && next_low),
                "scalar Elastic schedule exhausted both active levels"
            );
            if current_low {
                let (slot, probe) = self.uniform_vacancy(next, identity);
                (
                    ScalarElasticCase::Case2 {
                        batch,
                        current_level: current,
                        next_level: next,
                        free_current,
                        free_next,
                    },
                    next,
                    slot,
                    probe,
                )
            } else if next_low {
                let (slot, probe) = self.uniform_vacancy(current, identity);
                (
                    ScalarElasticCase::Case3 {
                        batch,
                        current_level: current,
                        next_level: next,
                        free_current,
                        free_next,
                    },
                    current,
                    slot,
                    probe,
                )
            } else {
                let budget = probe::elastic_dyadic_probe_budget(
                    free_current,
                    self.levels[current],
                    self.config.reserve_exponent(),
                    self.limits.probe_budget_c.get(),
                )
                .expect("scalar Elastic probe budget must be representable");
                let case = ScalarElasticCase::Case1 {
                    batch,
                    current_level: current,
                    next_level: next,
                    free_current,
                    free_next,
                    budget,
                };
                let bounded = (0..budget).find_map(|logical_index| {
                    let logical_index = u64::try_from(logical_index).ok()?;
                    self.vacancy(current, identity, logical_index)
                        .map(|slot| (slot, logical_index + 1))
                });
                let (level, slot, probe) = if let Some((slot, probe)) = bounded {
                    (current, slot, probe)
                } else {
                    let (slot, probe) = self.uniform_vacancy(next, identity);
                    (next, slot, probe)
                };
                (case, level, slot, probe)
            }
        };

        let global_slot = self.offsets[level] + slot_in_level;
        assert!(self.slots[global_slot].is_none());
        let phi = probe::elastic_phi(level as u128 + 1, u128::from(paper_probe))
            .expect("scalar Elastic selection must have a representable phi");
        assert!(phi <= self.limits.hit_query_position_cap.get());
        self.slots[global_slot] = Some(identity);
        self.occupancy[level] += 1;
        self.len += 1;
        ScalarElasticInsertion {
            case,
            location: ScalarElasticLocation::new(level, slot_in_level, global_slot),
            paper_probe,
            phi,
        }
    }

    fn query(&self, identity: u64) -> ScalarElasticQuery {
        let mut h11 = None;
        let mut random_words = 0_u128;
        let mut mapped_positions = 0_u128;
        let mut gap_positions = 0_u128;
        for position in 1..=self.limits.hit_query_position_cap.get() {
            let (level, logical_index, is_h11) = match probe::elastic_phi_inverse(position) {
                Some((paper_i, paper_j)) if paper_i <= self.levels.len() as u128 => {
                    mapped_positions += 1;
                    let level = usize::try_from(paper_i - 1).unwrap();
                    let logical_index = u64::try_from(paper_j - 1).unwrap();
                    (level, logical_index, level == 0 && logical_index == 0)
                }
                _ => {
                    gap_positions += 1;
                    (0, 0, true)
                }
            };
            let global_slot = if is_h11 {
                if let Some(global_slot) = h11 {
                    global_slot
                } else {
                    let (global_slot, words) = self.route(level, identity, logical_index);
                    random_words += u128::from(words);
                    h11 = Some(global_slot);
                    global_slot
                }
            } else {
                let (global_slot, words) = self.route(level, identity, logical_index);
                random_words += u128::from(words);
                global_slot
            };
            if self.slots[global_slot] == Some(identity) {
                return ScalarElasticQuery {
                    found_position: position,
                    global_slot,
                    logical_positions: position,
                    mapped_positions,
                    gap_positions,
                    scalar_inspections: position,
                    random_words,
                };
            }
        }
        panic!("scalar Elastic query failed to find its promised identity")
    }

    pub(crate) fn level_occupancy(&self) -> &[usize] {
        &self.occupancy
    }

    fn active_batch(&self) -> Option<usize> {
        let mut prefix = 0;
        for (batch, &quota) in self.quotas.iter().enumerate() {
            prefix += quota;
            if self.len < prefix {
                return Some(batch);
            }
        }
        None
    }

    fn uniform_vacancy(&self, level: usize, identity: u64) -> (usize, u64) {
        for logical_index in 0..self.limits.uniform_search_probe_cap.get() {
            if let Some(slot) = self.vacancy(level, identity, logical_index) {
                return (slot, logical_index + 1);
            }
        }
        panic!("scalar Elastic exhausted its finite uniform-search cap")
    }

    fn vacancy(&self, level: usize, identity: u64, logical_index: u64) -> Option<usize> {
        let (global_slot, _) = self.route(level, identity, logical_index);
        self.slots[global_slot]
            .is_none()
            .then_some(global_slot - self.offsets[level])
    }

    fn route(&self, level: usize, identity: u64, logical_index: u64) -> (usize, u32) {
        let sampled = probe::unbiased_probe_index(
            &self.oracle,
            identity,
            ProbeDomain::ElasticOrdinary {
                level: level as u64,
            },
            logical_index,
            self.levels[level],
            self.limits.range_word_cap.get(),
        )
        .expect("scalar Elastic range reduction must succeed");
        (
            self.offsets[level] + sampled.index,
            sampled.random_word_count,
        )
    }
}

fn scalar_floor_div_pow2(value: usize, exponent: u32) -> usize {
    value.checked_shr(exponent).unwrap_or(0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScalarFunnelLocation {
    Ordinary {
        level: usize,
        bucket: usize,
        slot_in_bucket: usize,
        global_slot: usize,
    },
    SpecialPrimary {
        slot: usize,
        global_slot: usize,
    },
    SpecialFallback {
        bucket: usize,
        slot_in_bucket: usize,
        global_slot: usize,
    },
}

impl ScalarFunnelLocation {
    pub(crate) const fn global_slot(self) -> usize {
        match self {
            Self::Ordinary { global_slot, .. }
            | Self::SpecialPrimary { global_slot, .. }
            | Self::SpecialFallback { global_slot, .. } => global_slot,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScalarFunnelSearch {
    Hit(ScalarFunnelLocation),
    Vacant(ScalarFunnelLocation),
    Full,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScalarFunnelInsert {
    Inserted(ScalarFunnelLocation),
    Duplicate(ScalarFunnelLocation),
    TargetExhausted,
    FallbackFull,
}

pub(crate) struct ScalarFunnel<O> {
    plan: FunnelPlan,
    oracle: O,
    range_word_cap: u32,
    slots: Vec<Option<u64>>,
    levels: Vec<(usize, usize)>,
    primary_offset: usize,
    fallback_offset: usize,
    len: usize,
}

impl<O: ProbeOracle> ScalarFunnel<O> {
    pub(crate) fn new(config: PaperConfig, oracle: O, range_word_cap: NonZeroU32) -> Self {
        let plan = config.funnel_plan().unwrap();
        let mut offset = 0;
        let levels = plan
            .ordinary_bucket_counts()
            .map(|bucket_count| {
                let level = (offset, bucket_count);
                offset += bucket_count * plan.beta();
                level
            })
            .collect();
        let primary_offset = offset;
        let fallback_offset = primary_offset + plan.special_primary_len();
        Self {
            plan,
            oracle,
            range_word_cap: range_word_cap.get(),
            slots: vec![None; config.n()],
            levels,
            primary_offset,
            fallback_offset,
            len: 0,
        }
    }

    fn sample(
        &self,
        identity: u64,
        domain: ProbeDomain,
        logical_index: u64,
        upper: usize,
    ) -> Result<usize, RangeReductionError> {
        probe::unbiased_probe_index(
            &self.oracle,
            identity,
            domain,
            logical_index,
            upper,
            self.range_word_cap,
        )
        .map(|probe| probe.index)
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn search(
        &self,
        identity: u64,
    ) -> Result<(ScalarFunnelSearch, u128), RangeReductionError> {
        let mut logical_probes = 0_u128;
        for (level, &(offset, bucket_count)) in self.levels.iter().enumerate() {
            let bucket = self.sample(
                identity,
                ProbeDomain::FunnelOrdinary {
                    level: level as u64,
                },
                0,
                bucket_count,
            )?;
            for slot_in_bucket in 0..self.plan.beta() {
                logical_probes += 1;
                let global_slot = offset + bucket * self.plan.beta() + slot_in_bucket;
                match self.slots[global_slot] {
                    Some(stored) if stored == identity => {
                        return Ok((
                            ScalarFunnelSearch::Hit(ScalarFunnelLocation::Ordinary {
                                level,
                                bucket,
                                slot_in_bucket,
                                global_slot,
                            }),
                            logical_probes,
                        ));
                    }
                    Some(_) => {}
                    None => {
                        return Ok((
                            ScalarFunnelSearch::Vacant(ScalarFunnelLocation::Ordinary {
                                level,
                                bucket,
                                slot_in_bucket,
                                global_slot,
                            }),
                            logical_probes,
                        ));
                    }
                }
            }
        }

        for logical_index in 0..self.plan.loglog_ceiling() {
            let slot = self.sample(
                identity,
                ProbeDomain::FunnelSpecialPrimary,
                logical_index as u64,
                self.plan.special_primary_len(),
            )?;
            logical_probes += 1;
            let global_slot = self.primary_offset + slot;
            match self.slots[global_slot] {
                Some(stored) if stored == identity => {
                    return Ok((
                        ScalarFunnelSearch::Hit(ScalarFunnelLocation::SpecialPrimary {
                            slot,
                            global_slot,
                        }),
                        logical_probes,
                    ));
                }
                Some(_) => {}
                None => {
                    return Ok((
                        ScalarFunnelSearch::Vacant(ScalarFunnelLocation::SpecialPrimary {
                            slot,
                            global_slot,
                        }),
                        logical_probes,
                    ));
                }
            }
        }

        let bucket_a = self.sample(
            identity,
            ProbeDomain::FunnelSpecialFallbackChoiceA,
            0,
            self.plan.fallback_bucket_count(),
        )?;
        let bucket_b = self.sample(
            identity,
            ProbeDomain::FunnelSpecialFallbackChoiceB,
            0,
            self.plan.fallback_bucket_count(),
        )?;
        for slot_in_bucket in 0..self.plan.fallback_bucket_width() {
            for bucket in [bucket_a, bucket_b] {
                logical_probes += 1;
                let global_slot = self.fallback_offset
                    + bucket * self.plan.fallback_bucket_width()
                    + slot_in_bucket;
                match self.slots[global_slot] {
                    Some(stored) if stored == identity => {
                        return Ok((
                            ScalarFunnelSearch::Hit(ScalarFunnelLocation::SpecialFallback {
                                bucket,
                                slot_in_bucket,
                                global_slot,
                            }),
                            logical_probes,
                        ));
                    }
                    Some(_) => {}
                    None => {
                        return Ok((
                            ScalarFunnelSearch::Vacant(ScalarFunnelLocation::SpecialFallback {
                                bucket,
                                slot_in_bucket,
                                global_slot,
                            }),
                            logical_probes,
                        ));
                    }
                }
            }
        }
        Ok((ScalarFunnelSearch::Full, logical_probes))
    }

    pub(crate) fn insert(
        &mut self,
        identity: u64,
    ) -> Result<(ScalarFunnelInsert, u128), RangeReductionError> {
        let (search, probes) = self.search(identity)?;
        let result = match search {
            ScalarFunnelSearch::Hit(location) => ScalarFunnelInsert::Duplicate(location),
            ScalarFunnelSearch::Vacant(_) | ScalarFunnelSearch::Full
                if self.len >= self.plan.config().target_insertions() =>
            {
                ScalarFunnelInsert::TargetExhausted
            }
            ScalarFunnelSearch::Vacant(location) => {
                self.slots[location.global_slot()] = Some(identity);
                self.len += 1;
                ScalarFunnelInsert::Inserted(location)
            }
            ScalarFunnelSearch::Full => ScalarFunnelInsert::FallbackFull,
        };
        Ok((result, probes))
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn locations(&self) -> impl Iterator<Item = (ScalarFunnelLocation, u64)> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter_map(move |(global_slot, identity)| {
                let identity = (*identity)?;
                Some((self.location_at_global_slot(global_slot), identity))
            })
    }

    fn location_at_global_slot(&self, global_slot: usize) -> ScalarFunnelLocation {
        assert!(global_slot < self.slots.len());
        if global_slot < self.primary_offset {
            for (level, &(offset, bucket_count)) in self.levels.iter().enumerate() {
                let level_len = bucket_count * self.plan.beta();
                if global_slot < offset + level_len {
                    let slot_in_level = global_slot - offset;
                    return ScalarFunnelLocation::Ordinary {
                        level,
                        bucket: slot_in_level / self.plan.beta(),
                        slot_in_bucket: slot_in_level % self.plan.beta(),
                        global_slot,
                    };
                }
            }
            unreachable!("ordinary scalar Funnel slot must belong to a level");
        }
        if global_slot < self.fallback_offset {
            return ScalarFunnelLocation::SpecialPrimary {
                slot: global_slot - self.primary_offset,
                global_slot,
            };
        }
        let slot_in_fallback = global_slot - self.fallback_offset;
        ScalarFunnelLocation::SpecialFallback {
            bucket: slot_in_fallback / self.plan.fallback_bucket_width(),
            slot_in_bucket: slot_in_fallback % self.plan.fallback_bucket_width(),
            global_slot,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;
    use core::num::{NonZeroU32, NonZeroU64, NonZeroU128, NonZeroUsize};

    use super::{
        ScalarElastic, ScalarElasticCase, ScalarElasticInsertion, ScalarElasticLimits,
        ScalarElasticLocation, ScalarElasticQuery, ScalarFunnel, ScalarFunnelInsert,
        ScalarFunnelLocation, ScalarFunnelSearch,
    };
    use crate::common::exact::geometry::PaperConfig;
    use crate::common::exact::probe::{ProbeDomain, ProbeOracle};

    #[derive(Debug)]
    struct ElasticCycleOracle {
        level_lengths: Vec<usize>,
    }

    impl ElasticCycleOracle {
        fn new(config: PaperConfig) -> Self {
            Self {
                level_lengths: config.elastic_plan().level_lengths().collect(),
            }
        }
    }

    impl ProbeOracle for ElasticCycleOracle {
        fn word(
            &self,
            _identity: u64,
            domain: ProbeDomain,
            logical_probe_index: u64,
            _rejection_index: u32,
        ) -> u64 {
            let ProbeDomain::ElasticOrdinary { level } = domain else {
                panic!("unexpected Funnel domain")
            };
            let level = usize::try_from(level).expect("test level must fit usize");
            let logical_probe_index =
                usize::try_from(logical_probe_index).expect("test probe index must fit usize");
            let upper = self.level_lengths[level];
            accepted_word_for_index(logical_probe_index % upper, upper)
        }
    }

    #[derive(Debug)]
    struct FunnelFirstBucketOracle {
        ordinary_bucket_counts: Vec<usize>,
        primary_len: usize,
        fallback_bucket_count: usize,
    }

    impl FunnelFirstBucketOracle {
        fn new(config: PaperConfig) -> Self {
            let plan = config.funnel_plan().unwrap();
            Self {
                ordinary_bucket_counts: plan.ordinary_bucket_counts().collect(),
                primary_len: plan.special_primary_len(),
                fallback_bucket_count: plan.fallback_bucket_count(),
            }
        }
    }

    impl ProbeOracle for FunnelFirstBucketOracle {
        fn word(
            &self,
            _identity: u64,
            domain: ProbeDomain,
            _logical_probe_index: u64,
            _rejection_index: u32,
        ) -> u64 {
            let upper = match domain {
                ProbeDomain::FunnelOrdinary { level } => {
                    let level = usize::try_from(level).expect("test level must fit usize");
                    self.ordinary_bucket_counts[level]
                }
                ProbeDomain::FunnelSpecialPrimary => self.primary_len,
                ProbeDomain::FunnelSpecialFallbackChoiceA
                | ProbeDomain::FunnelSpecialFallbackChoiceB => self.fallback_bucket_count,
                ProbeDomain::ElasticOrdinary { .. } => panic!("unexpected Elastic domain"),
            };
            accepted_word_for_index(0, upper)
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn elastic_reference_has_a_hand_checked_batch_and_query_trace() {
        let config = PaperConfig::new(8, 3).unwrap();
        let limits = ScalarElasticLimits::new(
            NonZeroUsize::new(1).unwrap(),
            NonZeroU32::new(1).unwrap(),
            NonZeroU64::new(8).unwrap(),
            NonZeroU128::new(256).unwrap(),
        );
        let mut scalar = ScalarElastic::new(config, ElasticCycleOracle::new(config), limits);

        let insertions: Vec<_> = (10..=16).map(|identity| scalar.insert(identity)).collect();
        assert_eq!(
            insertions,
            vec![
                ScalarElasticInsertion {
                    case: ScalarElasticCase::Batch0 { level: 0 },
                    location: ScalarElasticLocation::new(0, 0, 0),
                    paper_probe: 1,
                    phi: 13,
                },
                ScalarElasticInsertion {
                    case: ScalarElasticCase::Batch0 { level: 0 },
                    location: ScalarElasticLocation::new(0, 1, 1),
                    paper_probe: 2,
                    phi: 57,
                },
                ScalarElasticInsertion {
                    case: ScalarElasticCase::Batch0 { level: 0 },
                    location: ScalarElasticLocation::new(0, 2, 2),
                    paper_probe: 3,
                    phi: 61,
                },
                ScalarElasticInsertion {
                    case: ScalarElasticCase::Case1 {
                        batch: 1,
                        current_level: 0,
                        next_level: 1,
                        free_current: 1,
                        free_next: 2,
                        budget: 3,
                    },
                    location: ScalarElasticLocation::new(1, 0, 4),
                    paper_probe: 1,
                    phi: 26,
                },
                ScalarElasticInsertion {
                    case: ScalarElasticCase::Case1 {
                        batch: 1,
                        current_level: 0,
                        next_level: 1,
                        free_current: 1,
                        free_next: 1,
                        budget: 3,
                    },
                    location: ScalarElasticLocation::new(1, 1, 5),
                    paper_probe: 2,
                    phi: 114,
                },
                ScalarElasticInsertion {
                    case: ScalarElasticCase::Case3 {
                        batch: 1,
                        current_level: 0,
                        next_level: 1,
                        free_current: 1,
                        free_next: 0,
                    },
                    location: ScalarElasticLocation::new(0, 3, 3),
                    paper_probe: 4,
                    phi: 233,
                },
                ScalarElasticInsertion {
                    case: ScalarElasticCase::Case2 {
                        batch: 2,
                        current_level: 1,
                        next_level: 2,
                        free_current: 0,
                        free_next: 2,
                    },
                    location: ScalarElasticLocation::new(2, 0, 6),
                    paper_probe: 1,
                    phi: 27,
                },
            ]
        );
        assert_eq!(scalar.level_occupancy(), &[4, 2, 1]);
        assert_eq!(
            scalar.query(10),
            ScalarElasticQuery {
                found_position: 1,
                global_slot: 0,
                logical_positions: 1,
                mapped_positions: 0,
                gap_positions: 1,
                scalar_inspections: 1,
                random_words: 1,
            }
        );
        assert_eq!(
            scalar.query(13),
            ScalarElasticQuery {
                found_position: 26,
                global_slot: 4,
                logical_positions: 26,
                mapped_positions: 2,
                gap_positions: 24,
                scalar_inspections: 26,
                random_words: 2,
            }
        );
    }

    #[test]
    fn funnel_reference_has_a_hand_checked_level_transition() {
        let config = PaperConfig::new(32_768, 3).unwrap();
        let mut scalar = ScalarFunnel::new(
            config,
            FunnelFirstBucketOracle::new(config),
            NonZeroU32::new(1).unwrap(),
        );

        for (identity, slot_in_bucket) in (0_u64..6).zip(0_usize..6) {
            assert_eq!(
                scalar.insert(identity).unwrap(),
                (
                    ScalarFunnelInsert::Inserted(ScalarFunnelLocation::Ordinary {
                        level: 0,
                        bucket: 0,
                        slot_in_bucket,
                        global_slot: slot_in_bucket,
                    }),
                    slot_in_bucket as u128 + 1,
                )
            );
        }
        assert_eq!(
            scalar.insert(6).unwrap(),
            (
                ScalarFunnelInsert::Inserted(ScalarFunnelLocation::Ordinary {
                    level: 1,
                    bucket: 0,
                    slot_in_bucket: 0,
                    global_slot: 7_428,
                }),
                7,
            )
        );
        assert_eq!(
            scalar.insert(6).unwrap(),
            (
                ScalarFunnelInsert::Duplicate(ScalarFunnelLocation::Ordinary {
                    level: 1,
                    bucket: 0,
                    slot_in_bucket: 0,
                    global_slot: 7_428,
                }),
                7,
            )
        );
        assert_eq!(
            scalar.search(99).unwrap(),
            (
                ScalarFunnelSearch::Vacant(ScalarFunnelLocation::Ordinary {
                    level: 1,
                    bucket: 0,
                    slot_in_bucket: 1,
                    global_slot: 7_429,
                }),
                8,
            )
        );
    }

    #[test]
    fn funnel_reference_reports_len_and_occupied_locations() {
        let config = PaperConfig::new(32_768, 3).unwrap();
        let mut scalar = ScalarFunnel::new(
            config,
            FunnelFirstBucketOracle::new(config),
            NonZeroU32::new(1).unwrap(),
        );

        scalar.insert(10).unwrap();
        scalar.insert(20).unwrap();

        assert_eq!(scalar.len(), 2);
        assert_eq!(
            scalar.locations().collect::<Vec<_>>(),
            vec![
                (
                    ScalarFunnelLocation::Ordinary {
                        level: 0,
                        bucket: 0,
                        slot_in_bucket: 0,
                        global_slot: 0,
                    },
                    10,
                ),
                (
                    ScalarFunnelLocation::Ordinary {
                        level: 0,
                        bucket: 0,
                        slot_in_bucket: 1,
                        global_slot: 1,
                    },
                    20,
                ),
            ]
        );
    }

    #[allow(clippy::cast_possible_truncation)]
    fn accepted_word_for_index(index: usize, upper: usize) -> u64 {
        assert!(index < upper);
        let upper = upper as u128;
        let scale = 1_u128 << 64;
        let mut word = ((index as u128) * scale).div_ceil(upper);
        let threshold = (upper as u64).wrapping_neg() % upper as u64;
        loop {
            let product = word * upper;
            if (product >> 64) as usize == index && product as u64 >= threshold {
                return word as u64;
            }
            word += 1;
        }
    }
}
