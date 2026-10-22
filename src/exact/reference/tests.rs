use alloc::vec;
use alloc::vec::Vec;
use core::num::{NonZeroU32, NonZeroU64, NonZeroU128, NonZeroUsize};

use super::{
    ElasticCase, ScalarElastic, ScalarElasticInsertion, ScalarElasticLimits, ScalarElasticLocation,
    ScalarElasticQuery, ScalarFunnel, ScalarFunnelInsert, ScalarFunnelLocation, ScalarFunnelSearch,
};
use crate::exact::geometry::PaperConfig;
use crate::exact::probe::{ProbeDomain, ProbeOracle};

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
                case: ElasticCase::Batch0 { level: 0 },
                location: ScalarElasticLocation::new(0, 0, 0),
                paper_probe: 1,
                phi: 13,
            },
            ScalarElasticInsertion {
                case: ElasticCase::Batch0 { level: 0 },
                location: ScalarElasticLocation::new(0, 1, 1),
                paper_probe: 2,
                phi: 57,
            },
            ScalarElasticInsertion {
                case: ElasticCase::Batch0 { level: 0 },
                location: ScalarElasticLocation::new(0, 2, 2),
                paper_probe: 3,
                phi: 61,
            },
            ScalarElasticInsertion {
                case: ElasticCase::Case1 {
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
                case: ElasticCase::Case1 {
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
                case: ElasticCase::Case3 {
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
                case: ElasticCase::Case2 {
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
