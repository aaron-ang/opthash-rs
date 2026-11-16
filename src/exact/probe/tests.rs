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
fn elastic_level_runs_never_share_or_wrap_a_sequence_index() {
    let last_probe = ELASTIC_LOGICAL_LIMIT - 1;
    let levels = u32::try_from(ELASTIC_LEVEL_LIMIT).unwrap();
    assert_eq!(elastic_level_run(0).0, 0);
    let mut steps = alloc::collections::BTreeSet::new();
    for level in 0..levels {
        let (first, step) = elastic_level_run(level as usize);
        // The level sits in the bits no step reaches, so two levels' runs
        // are disjoint, and a positive step keeps one level's probes apart.
        assert_eq!(first % levels, level);
        assert_eq!(step % levels, 0);
        assert_eq!((step / levels) % 2, 1);
        assert!(steps.insert(step), "two levels share a step");
        assert!(u32::try_from(u64::from(first) + last_probe * u64::from(step)).is_ok());
        for logical in [0, 1, 2, 63, 64, 4_095, 4_096, last_probe] {
            let index = elastic_sequence_index(level, logical);
            assert_eq!(elastic_sequence_coordinates(index), (level, logical));
        }
    }
}

#[test]
fn elastic_level_words_step_through_the_levels_sequence_indices() {
    let oracle = CounterPrf::new(FIXED_SEED);
    for key in [0, 1, u64::MAX, FIXED_SEED, ELASTIC_FOLD_MULTIPLIER] {
        let sequence = oracle
            .prepare_elastic(key)
            .sequence(ELASTIC_FOLD_MULTIPLIER);
        for level in 0..u32::try_from(ELASTIC_LEVEL_LIMIT).unwrap() {
            let (mut word, step) = sequence.run_words(elastic_level_run(level as usize));
            for logical in 0..512 {
                assert_eq!(
                    word,
                    sequence.word(elastic_sequence_index(level, logical)),
                    "key {key:#x} level {level} probe {logical}"
                );
                assert_eq!(
                    word,
                    oracle.specified_word(key, u64::from(level), logical, 0)
                );
                word = word.wrapping_add(step);
            }
        }
    }
}

/// Distinct slots among a key's first 64 probes of a level of 1024 slots.
fn distinct_slots(oracle: CounterPrf, key: u64, level: u64) -> usize {
    let prepared = oracle.prepare_elastic(key);
    let domain = ProbeDomain::ElasticOrdinary { level };
    (0..64)
        .map(|logical| prepared.word(0, domain, logical, 0) >> (u64::BITS - 10))
        .collect::<alloc::collections::BTreeSet<_>>()
        .len()
}

#[test]
fn all_zero_and_all_one_signatures_probe_many_slots() {
    // The construction's seed leaves the signature equal to the hash, which
    // an identity hasher makes the key.
    let oracle = CounterPrf::new(0);
    for key in [0, u64::MAX] {
        for level in 0..ELASTIC_LEVEL_LIMIT {
            assert!(
                distinct_slots(oracle, key, level) >= 48,
                "key {key:#x} level {level}"
            );
        }
    }
}

#[test]
fn elastic_counter_permutation_has_fixed_golden_vectors() {
    let oracle = CounterPrf::new(0x1234_5678_9abc_def0);
    let cases = [
        (0, 0, 0, 0, 0x0000_0000, 0x03dc_8f3b_0012_13da),
        (1, 31, 8_191, 7, 0x001f_ffff, 0x077e_7748_26d1_cae4),
        (u64::MAX, 17, 383, 7, 0x0011_0bff, 0xd466_8029_2118_daf5),
        (
            0xd1b5_4a32_d192_ed03,
            7,
            7_687,
            0,
            0x0007_f038,
            0xe8be_5676_db52_3aea,
        ),
        (
            0xd1b5_4a32_d192_ed03,
            0,
            1,
            0,
            0x0000_0008,
            0xf8b9_ef2e_58a2_6c67,
        ),
        (
            0xd1b5_4a32_d192_ed03,
            1,
            0,
            0,
            0x0001_0000,
            0xf987_7ac4_310b_9b4c,
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
    // Consecutive probes of a level are a multiple of the level count apart
    // in the sequence, so their words share the lowest bits. A slot index is
    // drawn from the top of the word; the high half is what must differ.
    let high_half = |word: u64| word >> u32::BITS;
    let mut cross_probe_equal_bits = 0_u64;
    assert_fixed_seed_word_distribution(word, |key| {
        let next_probe = oracle.word(key, ProbeDomain::ElasticOrdinary { level: 7 }, 4, 0);
        let differing = high_half(word(key, 7) ^ next_probe).count_ones();
        cross_probe_equal_bits += u64::from(u32::BITS - differing);
    });
    assert!(
        (DISTRIBUTION_SAMPLES * 15..=DISTRIBUTION_SAMPLES * 17).contains(&cross_probe_equal_bits)
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
            // An ordinary level draws its first word from the level multiplier
            // and only its retries from the counter permutation.
            let ordinary_level = match domain {
                ProbeDomain::FunnelOrdinary { level } => Some(level),
                _ => None,
            };
            for logical in [0_u8, 1, 7, u8::MAX] {
                let first_word_level = ordinary_level.filter(|_| logical == 0);
                for retry in [0_u8, 1, 7, u8::MAX] {
                    let word = match first_word_level {
                        Some(level) if retry == 0 => prepared
                            .ordinary_first_word(FunnelPrf::ordinary_multiplier(level).unwrap()),
                        _ => prepared_domain.word(u64::from(logical), u32::from(retry)),
                    };
                    assert_eq!(
                        word,
                        oracle.word(key, domain, u64::from(logical), u32::from(retry))
                    );
                }
                for upper in [1, 2, 3, 16, 191, 1_237, 1 << 20] {
                    let range = PreparedProbeRange::new(upper).unwrap();
                    let expected =
                        unbiased_probe_index(&oracle, key, domain, u64::from(logical), upper, 8);
                    if let Some(level) = first_word_level {
                        // An ordinary level reduces its word without a
                        // rejection test.
                        let multiplier = FunnelPrf::ordinary_multiplier(level).unwrap();
                        let word = oracle.word(key, domain, 0, 0);
                        assert_eq!(
                            ordinary_funnel_bucket(prepared, multiplier, upper) as u128,
                            (u128::from(word) * upper as u128) >> u64::BITS
                        );
                    } else {
                        assert_eq!(
                            unbiased_prepared_funnel_probe_index_in_range(
                                &prepared_domain,
                                logical,
                                range,
                                8,
                            ),
                            expected
                        );
                    }
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
            0x1900_49ec_e9b9_4124,
        ),
        (
            1,
            ProbeDomain::FunnelOrdinary {
                level: (1 << 46) - 1,
            },
            255,
            255,
            0x3fff_ffff_ffff_ffff,
            0x0610_a668_27e7_3b4b,
        ),
        (
            u64::MAX,
            ProbeDomain::FunnelSpecialPrimary,
            255,
            255,
            0x4000_0000_0000_ffff,
            0xc018_4e05_44d6_1b67,
        ),
        (
            0xd1b5_4a32_d192_ed03,
            ProbeDomain::FunnelSpecialFallbackChoiceA,
            7,
            1,
            0x8000_0000_0000_0701,
            0x16c9_2271_400d_9fc0,
        ),
        (
            0x0123_4567_89ab_cdef,
            ProbeDomain::FunnelSpecialFallbackChoiceB,
            0,
            0,
            0xc000_0000_0000_0000,
            0xee3b_835b_d981_5793,
        ),
    ];
    for (key, domain, logical, retry, counter, word) in cases {
        assert_eq!(
            try_pack_funnel_counter(domain, logical, retry),
            Some(counter)
        );
        assert_eq!(
            oracle
                .prepare(key)
                .prepare_domain(domain)
                .unwrap()
                .word(logical, retry),
            word
        );
        // The oracle serves an ordinary level's first word from the level
        // multiplier, pinned below.
        if !matches!(domain, ProbeDomain::FunnelOrdinary { .. }) || (logical, retry) != (0, 0) {
            assert_eq!(oracle.word(key, domain, logical, retry), word);
        }
    }
    assert_eq!(
        oracle.word(0, ProbeDomain::FunnelOrdinary { level: 0 }, 0, 0),
        0xe2a7_e887_3647_55d8
    );
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
    const KEY: u64 = 0x1c7;
    const LOGICAL_PROBE_INDEX: u8 = u8::MAX;
    const UPPER: usize = 2;
    const REJECTION_THRESHOLD: u64 = 0xfe17_cfc8_112e_3a20;
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

/// A walk over consecutive levels multiplies its running word by the step
/// where a lookup of one level multiplies the folded word by that level's
/// multiplier, and both must draw the same bucket.
#[test]
fn stepping_a_level_word_reaches_the_next_level_multiplier() {
    let oracle = FunnelPrf::new(FIXED_SEED);
    for key in [0, 1, u64::MAX, 0x0123_4567_89ab_cdef] {
        let probe = oracle.prepare(key);
        let mut word = probe.ordinary_first_word(oracle.level_step());
        for level in 0..4_096_u64 {
            let multiplier = FunnelPrf::ordinary_multiplier(level).unwrap();
            assert_eq!(word, probe.ordinary_first_word(multiplier), "level {level}");
            word = word.wrapping_mul(oracle.level_step());
        }
    }
}

/// Two levels sharing a multiplier would send every key to correlated
/// buckets in both.
#[test]
fn ordinary_level_multipliers_are_odd_and_distinct() {
    let levels = 0..4_096_u64;
    let multipliers = levels
        .clone()
        .map(|level| FunnelPrf::ordinary_multiplier(level).unwrap())
        .collect::<alloc::collections::BTreeSet<_>>();
    assert_eq!(multipliers.len() as u64, levels.end);
    assert!(multipliers.iter().all(|multiplier| multiplier % 2 == 1));
}

/// The fingerprint tells apart the keys sharing a bucket, so two keys of one
/// bucket must share it about once in its number of values, in every level a
/// shape can have.
///
/// A family that does not know the seed stays within an eighth of that rate
/// in each level: a mixing hasher, and the key families an identity hasher
/// passes through unmixed. A family built around the seed, whose folded
/// words are small multiples of a power of two, lines up with single levels;
/// it stays within an eighth over the levels of a walk taken together, and
/// in no level does it lose more than one bit of the fingerprint.
fn assert_fingerprints_stay_spread_within_a_bucket(buckets: usize) {
    use core::hash::BuildHasher;
    const KEYS: u64 = 1 << 17;
    const VALUES: usize = 128;
    // One past the last level of the plan with the largest reserve exponent.
    const LEVELS: u64 = 4 * (u64::BITS as u64 - 1) + 10;
    type Family = (&'static str, fn(u64) -> u64);
    let oracle = FunnelPrf::new(FIXED_SEED);
    let zero = oracle.zero_word_hash();
    let seedless: [Family; 6] = [
        ("mixed", |index| {
            crate::test_support::fixed_hasher().hash_one(index)
        }),
        ("sequential", |index| index),
        ("multiplicative", |index| {
            index.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        }),
        ("shifted", |index| index << 32),
        ("stepped", |index| index * VALUES as u64),
        ("thousands", |index| index * 1_000),
    ];
    let seedless = seedless.map(|(family, key_of)| {
        let probes = (0..KEYS).map(|index| oracle.prepare(key_of(index)));
        (family, false, probes.collect::<alloc::vec::Vec<_>>())
    });
    let seed_centred = [0_u32, 7, 18, 19, 20, 21].map(|shift| {
        let probes = (0..KEYS).map(|index| oracle.prepare((index << shift).wrapping_add(zero)));
        ("seed-centred", true, probes.collect::<alloc::vec::Vec<_>>())
    });
    for (_, _, probes) in seedless.iter().chain(&seed_centred) {
        for probe in probes {
            assert!(crate::raw::control::is_occupied(probe.fingerprint()));
        }
    }
    // Pairs of keys sharing a bucket, and those of them sharing a
    // fingerprint as well.
    let pairs = |count: u64| count * count.saturating_sub(1) / 2;
    {
        let mut counts = alloc::vec![[0_u64; VALUES]; buckets];
        for (family, centred, probes) in seedless.iter().chain(&seed_centred) {
            let (mut walk_bucket, mut walk_both) = (0, 0);
            for level in 0..LEVELS {
                let multiplier = FunnelPrf::ordinary_multiplier(level).unwrap();
                counts.fill([0; VALUES]);
                for &probe in probes {
                    let bucket = ordinary_funnel_bucket(probe, multiplier, buckets);
                    counts[bucket][usize::from(probe.fingerprint()) % VALUES] += 1;
                }
                let sharing_bucket: u64 =
                    counts.iter().map(|bucket| pairs(bucket.iter().sum())).sum();
                let sharing_both: u64 = counts.iter().flatten().copied().map(pairs).sum();
                let even = sharing_bucket / VALUES as u64;
                let allowed = if *centred {
                    0..=2 * even
                } else {
                    even - even / 8..=even + even / 8
                };
                assert!(
                    allowed.contains(&sharing_both),
                    "{family} level {level} buckets {buckets}: {sharing_both} of {sharing_bucket}"
                );
                walk_bucket += sharing_bucket;
                walk_both += sharing_both;
            }
            let even = walk_bucket / VALUES as u64;
            assert!(
                (even - even / 8..=even + even / 8).contains(&walk_both),
                "{family} buckets {buckets}: {walk_both} of {walk_bucket}"
            );
        }
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "counts fingerprints over hundreds of thousands of keys"
)]
fn fingerprints_stay_spread_within_a_bucket_of_few() {
    assert_fingerprints_stay_spread_within_a_bucket(8);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "counts fingerprints over hundreds of thousands of keys"
)]
fn fingerprints_stay_spread_within_a_bucket_of_a_ragged_count() {
    assert_fingerprints_stay_spread_within_a_bucket(1_000);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "counts fingerprints over hundreds of thousands of keys"
)]
fn fingerprints_stay_spread_within_a_bucket_of_a_power_of_two() {
    assert_fingerprints_stay_spread_within_a_bucket(4_096);
}

/// The ordinary draw gives each bucket one run of consecutive words, the
/// runs in bucket order from the first word to the last, and no two runs
/// differ in length by more than one word. A level with no buckets draws
/// bucket zero.
#[test]
fn ordinary_draw_gives_every_bucket_one_even_run_of_words() {
    // Inverse of an odd word modulo 2^64, by Newton's iteration.
    fn inverse(odd: u64) -> u64 {
        let mut inverse = odd;
        for _ in 0..6 {
            inverse = inverse.wrapping_mul(2_u64.wrapping_sub(odd.wrapping_mul(inverse)));
        }
        assert_eq!(odd.wrapping_mul(inverse), 1);
        inverse
    }
    const WORDS: u128 = 1 << u64::BITS;
    let multiplier = FunnelPrf::ordinary_multiplier(3).unwrap();
    // A probe whose word in the level is `word`.
    let probe_drawing = |word: u64| PreparedFastFunnelProbe {
        keyed: 0,
        key_out: word.wrapping_mul(inverse(multiplier)),
    };
    for upper in [1_usize, 2, 3, 7, 1_000, (1 << 20) + 1, (1 << 31) - 1] {
        let draw = |word: u64| ordinary_funnel_bucket(probe_drawing(word), multiplier, upper);
        // The word that starts a bucket's run, or the count of words for
        // the bucket past the last.
        let run_start = |bucket: usize| (bucket as u128 * WORDS).div_ceil(upper as u128);
        assert_eq!(draw(0), 0);
        assert_eq!(draw(u64::MAX), upper - 1);
        let even = WORDS / upper as u128;
        let near_ends = (0..upper.min(64)).chain(upper.saturating_sub(64)..upper);
        let spread = (0..1_024_usize).map(|index| index.wrapping_mul(0x9E37_79B9) % upper);
        for bucket in near_ends.chain(spread) {
            let start = run_start(bucket);
            let end = run_start(bucket + 1);
            // Its first and last words draw the bucket, and the words on
            // either side of the run draw its neighbours.
            let first = u64::try_from(start).unwrap();
            let last = u64::try_from(end - 1).unwrap();
            assert_eq!(draw(first), bucket, "upper {upper}");
            assert_eq!(draw(last), bucket, "upper {upper}");
            if bucket != 0 {
                assert_eq!(draw(first - 1), bucket - 1, "upper {upper}");
            }
            if bucket + 1 != upper {
                assert_eq!(draw(last + 1), bucket + 1, "upper {upper}");
            }
            assert!(
                end - start == even || end - start == even + 1,
                "upper {upper} bucket {bucket}"
            );
        }
        // A larger word never draws a lower bucket, so the runs are whole.
        let mut words: Vec<u64> = (0..4_096_u64)
            .map(|index| index.wrapping_mul(0x9E37_79B9_7F4A_7C15))
            .collect();
        words.sort_unstable();
        assert!(words.windows(2).all(|pair| draw(pair[0]) <= draw(pair[1])));
    }
    for word in [0, 1, u64::MAX, 0x9E37_79B9_7F4A_7C15] {
        assert_eq!(
            ordinary_funnel_bucket(probe_drawing(word), multiplier, 0),
            0
        );
    }
}

/// Keys spread over an ordinary level's buckets as evenly as uniform draws
/// would: for a mixing hasher, for the key families an identity hasher passes
/// through unmixed, and for bucket counts on both sides of a power of two.
#[test]
#[cfg_attr(miri, ignore = "draws hundreds of thousands of buckets")]
fn ordinary_draws_fill_buckets_evenly_for_every_key_family() {
    use core::hash::BuildHasher;

    const KEYS: u64 = 1 << 17;
    type Family = (&'static str, fn(u64) -> u64);
    let oracle = FunnelPrf::new(FIXED_SEED);
    let families: [Family; 6] = [
        ("mixed", |index| {
            crate::test_support::fixed_hasher().hash_one(index)
        }),
        ("sequential", |index| index),
        ("multiplicative", |index| {
            index.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        }),
        ("shifted", |index| index << 32),
        ("reversed", u64::reverse_bits),
        ("around the zero word", |index| {
            FunnelPrf::new(FIXED_SEED)
                .zero_word_hash()
                .wrapping_add(index)
        }),
    ];
    for buckets in [8_usize, 1_000, 4_096] {
        for (family, key_of) in families {
            for level in [0, 1, 7] {
                let multiplier = FunnelPrf::ordinary_multiplier(level).unwrap();
                let mut counts = alloc::vec![0_u64; buckets];
                for index in 0..KEYS {
                    let probe = oracle.prepare(key_of(index));
                    counts[ordinary_funnel_bucket(probe, multiplier, buckets)] += 1;
                }
                // Pearson's statistic, scaled by the expected count to stay
                // in integers: uniform draws put it near the bucket count
                // less one, with a deviation of the root of twice that.
                let scaled: u64 = counts
                    .iter()
                    .map(|&count| (count * buckets as u64).abs_diff(KEYS).pow(2))
                    .sum();
                let statistic = scaled / (KEYS * buckets as u64);
                let freedom = buckets as u64 - 1;
                let slack = 6 * (2 * freedom).isqrt().max(1);
                assert!(
                    statistic <= freedom + slack,
                    "{family} level {level} buckets {buckets}: {statistic}"
                );
            }
        }
    }
}

#[test]
fn elastic_probe_budget_matches_the_ceiling_quotient_form() {
    let by_quotient = |free: usize, level: usize, exponent: u32, c: usize| {
        let ratio_ceiling = level.div_ceil(free);
        let log_ceiling = (usize::BITS - (ratio_ceiling - 1).leading_zeros()) as usize;
        c * (log_ceiling * log_ceiling).min(exponent as usize)
    };
    let check = |free: usize, level: usize| {
        for exponent in [1, 3, 4, 64, u32::MAX] {
            for c in [8_u32, 3] {
                let expected = by_quotient(free, level, exponent, c as usize);
                assert_eq!(
                    elastic_dyadic_probe_budget(free, level, exponent, c as usize),
                    Ok(expected),
                    "free {free} of {level}"
                );
                if let (Ok(free), Ok(level)) = (u32::try_from(free), u32::try_from(level)) {
                    assert_eq!(
                        elastic_level_probe_budget(free, level, exponent, c),
                        expected as u64,
                        "free {free} of {level}"
                    );
                }
            }
        }
    };
    let exhaustive_levels: usize = if cfg!(miri) { 70 } else { 600 };
    for level in 1..=exhaustive_levels {
        for free in 1..=level {
            check(free, level);
        }
    }
    for shift in [15, 31, usize::BITS - 2, usize::BITS - 1] {
        let power = 1_usize << shift;
        // `u32::MAX` is the widest level the `u32` form takes.
        for level in [power - 1, power, power + 1, u32::MAX as usize, usize::MAX] {
            for free in [
                1,
                2,
                3,
                level / 3,
                level / 2,
                level / 2 + 1,
                level - 1,
                level,
            ] {
                check(free, level);
            }
        }
    }

    assert!(elastic_dyadic_probe_budget(0, 8, 3, 8).is_err());
    assert!(elastic_dyadic_probe_budget(9, 8, 3, 8).is_err());
    assert!(elastic_dyadic_probe_budget(1, 8, 3, 0).is_err());
}
