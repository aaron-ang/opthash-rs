use super::*;

#[test]
#[cfg_attr(
    miri,
    ignore = "exhaustive integer packing is covered by native debug and release tests"
)]
fn elastic_counter_pack_is_injective_and_checked() {
    let mut expected = 0_u32;
    for level in 0..ELASTIC_LEVEL_LIMIT {
        for logical_probe in 0..ELASTIC_LOGICAL_LIMIT {
            for rejection in 0..ELASTIC_REJECTION_LIMIT {
                let counter = try_pack_elastic_counter(level, logical_probe, rejection).unwrap();
                assert_eq!(counter, expected);
                assert_eq!(
                    elastic_counter_level(counter),
                    u32::try_from(level).unwrap()
                );
                expected += 1;
            }
        }
    }
    assert_eq!(expected, 1 << 21);

    assert!(try_pack_elastic_counter(ELASTIC_LEVEL_LIMIT, 0, 0).is_none());
    assert!(try_pack_elastic_counter(0, ELASTIC_LOGICAL_LIMIT, 0).is_none());
    assert!(try_pack_elastic_counter(0, 0, ELASTIC_REJECTION_LIMIT).is_none());
}

#[test]
#[cfg_attr(
    miri,
    ignore = "exhaustive integer parity is covered by native debug and release tests"
)]
fn bounded_elastic_phi_matches_checked_encoder_for_every_hot_coordinate() {
    for i in 1..=u32::BITS {
        for j in 1..=4_096_u64 {
            let expected = u64::try_from(elastic_phi(u128::from(i), u128::from(j)).unwrap()).ok();
            assert_eq!(elastic_phi_bounded(i, j), expected, "i={i}, j={j}");
        }
    }
}

#[test]
fn bounded_elastic_phi_rejects_zero_and_unrepresentable_coordinates() {
    assert_eq!(elastic_phi_bounded(0, 1), None);
    assert_eq!(elastic_phi_bounded(1, 0), None);
    assert_eq!(elastic_phi_bounded(u32::MAX, u64::from(u16::MAX)), None);
    assert_eq!(elastic_phi_bounded(1, u64::from(u16::MAX) + 1), None);
}

#[test]
fn prepared_elastic_probe_is_bit_identical_to_the_full_counter_prf() {
    let oracle = CounterPrf::new(0x1234_5678_9abc_def0);
    for key in [0, 1, u64::MAX, 0xd1b5_4a32_d192_ed03] {
        let prepared = oracle.prepare_elastic(key);
        for level in [0, 1, 17, ELASTIC_LEVEL_LIMIT - 1] {
            let domain = ProbeDomain::ElasticOrdinary { level };
            for logical_probe in [0, 1, 383, ELASTIC_LOGICAL_LIMIT - 1] {
                for rejection in [0, 1, 7, ELASTIC_REJECTION_LIMIT - 1] {
                    assert_eq!(
                        prepared.word(0, domain, logical_probe, rejection),
                        oracle.word(key, domain, logical_probe, rejection)
                    );
                }
            }
        }
    }
}

#[test]
fn prepared_power_of_two_reduction_is_bit_identical_to_generic_reduction() {
    let oracle = CounterPrf::new(0x1234_5678_9abc_def0);
    for key in [0, 1, u64::MAX, 0xd1b5_4a32_d192_ed03] {
        let prepared = oracle.prepare_elastic(key);
        for level in [0, 1, 17, ELASTIC_LEVEL_LIMIT - 1] {
            let domain = ProbeDomain::ElasticOrdinary { level };
            for logical_probe in [0, 1, 383, 4_095] {
                let counter_base = try_pack_elastic_counter(level, logical_probe, 0).unwrap();
                for upper in [1, 2, 3, 4, 16, 191, 1_237, 1 << 20] {
                    assert_eq!(
                        unbiased_prepared_elastic_probe_index(prepared, counter_base, upper, 8,),
                        unbiased_probe_index(&oracle, key, domain, logical_probe, upper, 8,)
                    );
                }
            }
        }
    }
}

#[test]
fn elastic_counter_permutation_has_fixed_golden_vectors() {
    let oracle = CounterPrf::new(0x1234_5678_9abc_def0);
    let cases = [
        (0, 0, 0, 0, 0x0000_0000, 0xa672_f2f4_5fc9_0bed),
        (1, 31, 8_191, 7, 0x001f_ffff, 0x728c_b5c3_2967_b861),
        (u64::MAX, 17, 383, 7, 0x0011_0bff, 0x3472_0d88_ba17_9868),
        (
            0xd1b5_4a32_d192_ed03,
            7,
            7_687,
            0,
            0x0007_f038,
            0x8778_e64f_a636_f5ca,
        ),
    ];
    for (key, level, logical_probe, rejection, counter, word) in cases {
        assert_eq!(
            try_pack_elastic_counter(level, logical_probe, rejection),
            Some(counter)
        );
        let domain = ProbeDomain::ElasticOrdinary { level };
        assert_eq!(oracle.word(key, domain, logical_probe, rejection), word);
        assert_eq!(
            oracle
                .prepare_elastic(key)
                .word(key, domain, logical_probe, rejection),
            word
        );
    }
}

const FIXED_SEED: u64 = 0x1234_5678_9abc_def0;
const DISTRIBUTION_SAMPLES: u64 = 1 << 18;
const EXPECTED_PER_BUCKET: usize = 512;

/// Checks `word(key, level)` over `DISTRIBUTION_SAMPLES` keys for balanced
/// bits, single-bit avalanche, and level independence. Every key is also
/// handed to `per_key` so a caller can tally backend-specific statistics
/// over the same sample.
fn assert_fixed_seed_word_distribution(
    word: impl Fn(u64, u64) -> u64,
    mut per_key: impl FnMut(u64),
) {
    const SAMPLES: u64 = DISTRIBUTION_SAMPLES;
    let mut one_counts = [0_u64; u64::BITS as usize];
    let mut avalanche_bits = 0_u64;
    let mut cross_level_equal_bits = 0_u64;

    for key in 0..SAMPLES {
        let ordinary = word(key, 7);
        for bit in 0..u64::BITS {
            one_counts[bit as usize] += (ordinary >> bit) & 1;
        }
        let flipped_key = key ^ (1_u64 << (key % u64::from(u64::BITS)));
        avalanche_bits += u64::from((ordinary ^ word(flipped_key, 7)).count_ones());
        cross_level_equal_bits += u64::from((!(ordinary ^ word(key, 8))).count_ones());
        per_key(key);
    }

    for count in one_counts {
        assert!((SAMPLES * 48 / 100..=SAMPLES * 52 / 100).contains(&count));
    }
    assert!((SAMPLES * 30..=SAMPLES * 34).contains(&avalanche_bits));
    assert!((SAMPLES * 30..=SAMPLES * 34).contains(&cross_level_equal_bits));
}

/// Draws `upper * EXPECTED_PER_BUCKET` samples through `sample(key, upper)`
/// for awkward non-power-of-two ranges and rejects any bucket that lands
/// more than a quarter off its expectation.
fn assert_awkward_ranges_have_no_large_skew(sample: impl Fn(u64, usize) -> usize) {
    for upper in [3, 191, 1_237] {
        let mut counts = alloc::vec![0_u32; upper];
        for key in 0..(upper * EXPECTED_PER_BUCKET) as u64 {
            counts[sample(key, upper)] += 1;
        }
        for count in counts {
            assert!(
                (EXPECTED_PER_BUCKET - 128..=EXPECTED_PER_BUCKET + 128).contains(&(count as usize)),
                "upper={upper} count={count}"
            );
        }
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn elastic_fixed_seed_distribution_smoke() {
    let oracle = CounterPrf::new(FIXED_SEED);
    let word = |key, level| oracle.word(key, ProbeDomain::ElasticOrdinary { level }, 3, 0);
    let mut cross_probe_equal_bits = 0_u64;
    assert_fixed_seed_word_distribution(word, |key| {
        let next_probe = oracle.word(key, ProbeDomain::ElasticOrdinary { level: 7 }, 4, 0);
        cross_probe_equal_bits += u64::from((!(word(key, 7) ^ next_probe)).count_ones());
    });
    assert!(
        (DISTRIBUTION_SAMPLES * 30..=DISTRIBUTION_SAMPLES * 34).contains(&cross_probe_equal_bits)
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn elastic_awkward_ranges_have_no_large_fixed_seed_skew() {
    let oracle = CounterPrf::new(FIXED_SEED);
    let counter_base = try_pack_elastic_counter(7, 3, 0).unwrap();
    assert_awkward_ranges_have_no_large_skew(|key, upper| {
        unbiased_prepared_elastic_probe_index(oracle.prepare_elastic(key), counter_base, upper, 8)
            .unwrap()
            .index
    });
}

#[test]
fn fast_funnel_counter_pack_is_injective_and_checked() {
    let mut counters = alloc::collections::BTreeSet::new();
    for domain in [
        ProbeDomain::FunnelOrdinary { level: 0 },
        ProbeDomain::FunnelOrdinary { level: 262 },
        ProbeDomain::FunnelSpecialPrimary,
        ProbeDomain::FunnelSpecialFallbackChoiceA,
        ProbeDomain::FunnelSpecialFallbackChoiceB,
    ] {
        for logical in 0..8 {
            for retry in 0..8 {
                let counter = try_pack_funnel_counter(domain, logical, retry).unwrap();
                assert!(counters.insert(counter));
            }
        }
    }
    assert!(
        try_pack_funnel_counter(ProbeDomain::FunnelOrdinary { level: 1 << 46 }, 0, 0,).is_none()
    );
    assert!(try_pack_funnel_counter(ProbeDomain::FunnelSpecialPrimary, 256, 0).is_none());
    assert!(try_pack_funnel_counter(ProbeDomain::FunnelSpecialPrimary, 0, 256).is_none());
    assert!(try_pack_funnel_counter(ProbeDomain::ElasticOrdinary { level: 0 }, 0, 0).is_none());
}

#[test]
fn fast_funnel_narrow_indices_match_checked_counter_encoding() {
    let oracle = FunnelPrf::new(0x1234_5678_9abc_def0);
    let key = 0xd1b5_4a32_d192_ed03;
    let domain = ProbeDomain::FunnelSpecialPrimary;
    let prepared = oracle.prepare(key).prepare_domain(domain).unwrap();

    for (logical, rejection) in [(0_u8, 0_u8), (u8::MAX, u8::MAX)] {
        assert_eq!(
            prepared.word_from_indices(logical, rejection),
            oracle.word(key, domain, u64::from(logical), u32::from(rejection))
        );
    }
}

#[test]
fn fast_funnel_prepared_words_and_reductions_match_the_generic_oracle() {
    let oracle = FunnelPrf::new(0x1234_5678_9abc_def0);
    for key in [0, 1, u64::MAX, 0xd1b5_4a32_d192_ed03] {
        let prepared = oracle.prepare(key);
        for domain in [
            ProbeDomain::FunnelOrdinary { level: 0 },
            ProbeDomain::FunnelOrdinary { level: 17 },
            ProbeDomain::FunnelSpecialPrimary,
            ProbeDomain::FunnelSpecialFallbackChoiceA,
            ProbeDomain::FunnelSpecialFallbackChoiceB,
        ] {
            let prepared_domain = prepared.prepare_domain(domain).unwrap();
            for logical in [0_u8, 1, 7, u8::MAX] {
                for retry in [0_u8, 1, 7, u8::MAX] {
                    assert_eq!(
                        prepared_domain.word(u64::from(logical), u32::from(retry)),
                        oracle.word(key, domain, u64::from(logical), u32::from(retry))
                    );
                }
                for upper in [1, 2, 3, 16, 191, 1_237, 1 << 20] {
                    let range = PreparedProbeRange::new(upper).unwrap();
                    assert_eq!(
                        unbiased_prepared_funnel_probe_index_in_range(
                            &prepared_domain,
                            logical,
                            range,
                            8,
                        ),
                        unbiased_probe_index(&oracle, key, domain, u64::from(logical), upper, 8,)
                    );
                }
            }
        }
    }
}

#[test]
fn fast_funnel_counter_permutation_has_fixed_golden_vectors() {
    let oracle = FunnelPrf::new(0x1234_5678_9abc_def0);
    let cases = [
        (
            0,
            ProbeDomain::FunnelOrdinary { level: 0 },
            0,
            0,
            0x0000_0000_0000_0000,
            0x0ef8_0bc3_2b4b_4b8b,
        ),
        (
            1,
            ProbeDomain::FunnelOrdinary {
                level: (1 << 46) - 1,
            },
            255,
            255,
            0x3fff_ffff_ffff_ffff,
            0xe12e_db4c_7253_f889,
        ),
        (
            u64::MAX,
            ProbeDomain::FunnelSpecialPrimary,
            255,
            255,
            0x4000_0000_0000_ffff,
            0x0381_edbb_81aa_baf9,
        ),
        (
            0xd1b5_4a32_d192_ed03,
            ProbeDomain::FunnelSpecialFallbackChoiceA,
            7,
            1,
            0x8000_0000_0000_0701,
            0xaae3_de68_9f97_85e8,
        ),
        (
            0x0123_4567_89ab_cdef,
            ProbeDomain::FunnelSpecialFallbackChoiceB,
            0,
            0,
            0xc000_0000_0000_0000,
            0xf046_a747_c536_c435,
        ),
    ];
    for (key, domain, logical, retry, counter, word) in cases {
        assert_eq!(
            try_pack_funnel_counter(domain, logical, retry),
            Some(counter)
        );
        assert_eq!(oracle.word(key, domain, logical, retry), word);
        assert_eq!(
            oracle
                .prepare(key)
                .prepare_domain(domain)
                .unwrap()
                .word(logical, retry),
            word
        );
    }
}

#[cfg(target_pointer_width = "64")]
#[test]
#[allow(clippy::cast_possible_truncation)]
fn fast_funnel_retries_and_exhaustion_use_distinct_checked_counters() {
    let oracle = FunnelPrf::new(0x1234_5678_9abc_def0);
    let range = PreparedProbeRange::new((1_usize << 63) + 1).unwrap();
    let accepts = |word: u64| {
        let product = u128::from(word) * u128::from(range.upper as u64);
        product as u64 >= range.rejection_threshold
    };
    let mut reject_then_accept = None;
    let mut three_rejections = None;
    for key in 0..1_024 {
        let prepared = oracle
            .prepare(key)
            .prepare_domain(ProbeDomain::FunnelSpecialPrimary)
            .unwrap();
        let accepted = [0, 1, 2].map(|retry| accepts(prepared.word(9, retry)));
        if !accepted[0] && accepted[1] && reject_then_accept.is_none() {
            reject_then_accept = Some(prepared);
        }
        if accepted == [false; 3] && three_rejections.is_none() {
            three_rejections = Some(prepared);
        }
    }

    let retry = reject_then_accept.expect("fixed seed must exercise one exact retry");
    assert_eq!(
        unbiased_prepared_funnel_probe_index_in_range(&retry, 9, range, 1),
        Err(RangeReductionError::RejectionLimitExceeded {
            random_word_count: 1
        })
    );
    assert_eq!(
        unbiased_prepared_funnel_probe_index_in_range(&retry, 9, range, 2)
            .unwrap()
            .random_word_count,
        2
    );

    let exhausted = three_rejections.expect("fixed seed must exercise bounded exhaustion");
    assert_eq!(
        unbiased_prepared_funnel_probe_index_in_range(&exhausted, 9, range, 3),
        Err(RangeReductionError::RejectionLimitExceeded {
            random_word_count: 3
        })
    );
}

#[test]
#[allow(clippy::cast_possible_truncation)]
fn fast_funnel_reducer_accepts_the_full_rejection_index_lane() {
    const KEY: u64 = 0x55;
    const LOGICAL_PROBE_INDEX: u8 = u8::MAX;
    const UPPER: usize = 2;
    const REJECTION_THRESHOLD: u64 = 0xfef8_8af3_37e1_1307;
    let prepared = FunnelPrf::new(0x1234_5678_9abc_def0)
        .prepare(KEY)
        .prepare_domain(ProbeDomain::FunnelSpecialPrimary)
        .unwrap();
    let upper_word = u64::try_from(UPPER).unwrap();

    for rejection_index in 0..u8::MAX {
        let product = u128::from(prepared.word_from_indices(LOGICAL_PROBE_INDEX, rejection_index))
            * u128::from(upper_word);
        assert!(
            (product as u64) < REJECTION_THRESHOLD,
            "rejection index {rejection_index} must reject"
        );
    }
    let endpoint_product = u128::from(prepared.word_from_indices(LOGICAL_PROBE_INDEX, u8::MAX))
        * u128::from(upper_word);
    assert!((endpoint_product as u64) >= REJECTION_THRESHOLD);
    let expected_index = usize::try_from(endpoint_product >> u64::BITS).unwrap();

    assert_eq!(
        unbiased_prepared_funnel_probe_index_in_range(
            &prepared,
            LOGICAL_PROBE_INDEX,
            PreparedProbeRange {
                upper: UPPER,
                rejection_threshold: REJECTION_THRESHOLD,
            },
            256,
        ),
        Ok(ProbeIndex {
            index: expected_index,
            random_word_count: 256
        })
    );
}

#[test]
fn fast_funnel_reducer_rejects_counts_above_its_counter_encoding() {
    let prepared = FunnelPrf::new(0x1234_5678_9abc_def0)
        .prepare(0xd1b5_4a32_d192_ed03)
        .prepare_domain(ProbeDomain::FunnelSpecialPrimary)
        .unwrap();

    assert_eq!(
        unbiased_prepared_funnel_probe_index_in_range(
            &prepared,
            0,
            PreparedProbeRange::new(2).unwrap(),
            257,
        ),
        Err(RangeReductionError::RejectionLimitExceeded {
            random_word_count: 0
        })
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn fast_funnel_fixed_seed_distribution_smoke() {
    let oracle = FunnelPrf::new(FIXED_SEED);
    let fallback_range = PreparedProbeRange::new(257).unwrap();
    let mut fallback_same_bucket = 0_u64;
    let mut first_fallback_counts = alloc::vec![0_u32; fallback_range.upper()];
    let mut second_fallback_counts = alloc::vec![0_u32; fallback_range.upper()];
    let fallback_index = |key: u64, domain: ProbeDomain| {
        let prepared = oracle.prepare(key).prepare_domain(domain).unwrap();
        unbiased_prepared_funnel_probe_index_in_range(&prepared, 0, fallback_range, 8)
            .unwrap()
            .index
    };

    assert_fixed_seed_word_distribution(
        |key, level| oracle.word(key, ProbeDomain::FunnelOrdinary { level }, 0, 0),
        |key| {
            let a = fallback_index(key, ProbeDomain::FunnelSpecialFallbackChoiceA);
            let b = fallback_index(key, ProbeDomain::FunnelSpecialFallbackChoiceB);
            first_fallback_counts[a] += 1;
            second_fallback_counts[b] += 1;
            fallback_same_bucket += u64::from(a == b);
        },
    );

    let expected_bucket_count = DISTRIBUTION_SAMPLES / fallback_range.upper() as u64;
    let bucket_min = expected_bucket_count * 3 / 4;
    let bucket_max = expected_bucket_count * 5 / 4;
    assert!((bucket_min..=bucket_max).contains(&fallback_same_bucket));
    for count in first_fallback_counts
        .into_iter()
        .chain(second_fallback_counts)
    {
        assert!((bucket_min..=bucket_max).contains(&u64::from(count)));
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn fast_funnel_awkward_ranges_have_no_large_fixed_seed_skew() {
    let oracle = FunnelPrf::new(FIXED_SEED);
    assert_awkward_ranges_have_no_large_skew(|key, upper| {
        let range = PreparedProbeRange::new(upper).unwrap();
        let prepared = oracle
            .prepare(key)
            .prepare_domain(ProbeDomain::FunnelSpecialPrimary)
            .unwrap();
        unbiased_prepared_funnel_probe_index_in_range(&prepared, 3, range, 8)
            .unwrap()
            .index
    });
}
