use super::{ConfigError, FunnelPlanError, FunnelPlanParameter, PaperConfig, floor_div_pow2};

#[test]
fn rejects_invalid_configuration_inputs() {
    assert_eq!(PaperConfig::new(1, 3), Err(ConfigError::NTooSmall { n: 1 }));
    assert_eq!(PaperConfig::new(2, 0), Err(ConfigError::ExponentZero));
}

#[test]
fn computes_exact_reserved_slots_and_insertion_target() {
    let config = PaperConfig::new(32_768, 3).unwrap();

    assert_eq!(config.n(), 32_768);
    assert_eq!(config.reserve_exponent(), 3);
    assert_eq!(config.floor_delta_n(), 4_096);
    assert_eq!(config.max_insertions(), 28_672);
}

#[test]
fn exponents_at_least_as_wide_as_usize_reserve_no_slots() {
    for reserve_exponent in [usize::BITS, usize::BITS.saturating_add(1), u32::MAX] {
        let config = PaperConfig::new(32_768, reserve_exponent).unwrap();

        assert_eq!(config.floor_delta_n(), 0);
        assert_eq!(config.max_insertions(), 32_768);
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn elastic_level_geometry_obeys_paper_invariants() {
    for n in 2..=4_096 {
        let plan = PaperConfig::new(n, 3).unwrap().elastic_plan();
        let lengths: Vec<_> = plan.level_lengths().collect();
        let expected_level_count = (usize::BITS - (n - 1).leading_zeros()) as usize;

        assert_eq!(lengths.len(), expected_level_count, "n={n}");
        assert!(lengths.iter().all(|&length| length > 0), "n={n}");
        assert_eq!(lengths.iter().sum::<usize>(), n, "n={n}");
        for adjacent in lengths.windows(2) {
            assert!(
                adjacent[1].saturating_mul(2).abs_diff(adjacent[0]) <= 2,
                "n={n}, current={}, next={}",
                adjacent[0],
                adjacent[1]
            );
        }
    }
}

#[test]
fn elastic_batches_use_exact_formula_and_cap_at_target() {
    const RESERVE_EXPONENT_VALUES: [u32; 4] = [3, 4, 6, 8];
    const NON_POWER_OF_TWO_N_VALUES: [usize; 10] = [3, 5, 6, 7, 10, 17, 31, 33, 1_001, 4_095];

    for reserve_exponent in RESERVE_EXPONENT_VALUES {
        for n in NON_POWER_OF_TWO_N_VALUES {
            let config = PaperConfig::new(n, reserve_exponent).unwrap();
            let plan = config.elastic_plan();
            let levels: Vec<_> = plan.level_lengths().collect();
            let actual: Vec<_> = plan.batch_quotas().collect();
            let mut raw = Vec::with_capacity(levels.len());
            raw.push(ceil_three_quarters(levels[0]));
            for adjacent in levels.windows(2) {
                let current = adjacent[0];
                let next = adjacent[1];
                raw.push(
                    current
                        - floor_div_pow2(current, u64::from(reserve_exponent) + 1)
                        - ceil_three_quarters(current)
                        + ceil_three_quarters(next),
                );
            }

            let mut remaining = config.max_insertions();
            let expected: Vec<_> = raw
                .into_iter()
                .map(|quota| {
                    let capped = quota.min(remaining);
                    remaining -= capped;
                    capped
                })
                .collect();

            assert_eq!(
                actual, expected,
                "n={n}, reserve_exponent={reserve_exponent}"
            );
            assert_eq!(
                actual.iter().sum::<usize>(),
                config.max_insertions(),
                "n={n}, reserve_exponent={reserve_exponent}"
            );
        }
    }
}

#[test]
fn funnel_canonical_plan_uses_exact_paper_geometry() {
    let config = PaperConfig::new(32_768, 3).unwrap();
    let plan = config.funnel_plan().unwrap();
    let counts: Vec<_> = plan.ordinary_bucket_counts().collect();
    let lengths: Vec<_> = plan.ordinary_level_lengths().collect();

    assert_eq!(plan.config(), config);
    assert_eq!(plan.alpha(), 22);
    assert_eq!(plan.beta(), 6);
    assert_eq!(plan.loglog_ceiling(), 4);
    assert_eq!(plan.fallback_bucket_width(), 8);
    assert_eq!(plan.special_len(), 3_056);
    assert_eq!(plan.special_primary_len(), 1_528);
    assert_eq!(plan.special_fallback_len(), 1_528);
    assert_eq!(plan.fallback_bucket_count(), 191);
    assert_eq!(config.max_insertions(), 28_672);
    assert_eq!(counts.len(), 22);
    assert_eq!(counts[0], 1_238);
    assert_eq!(
        counts,
        [
            1_238, 929, 697, 523, 393, 295, 222, 167, 126, 95, 72, 55, 41, 30, 22, 16, 12, 8, 5, 3,
            2, 1,
        ]
    );
    assert_eq!(counts.iter().sum::<usize>(), (32_768 - 3_056) / 6);
    assert_eq!(lengths.iter().sum::<usize>() + plan.special_len(), 32_768);
}

#[test]
fn funnel_geometry_obeys_exact_formulas_across_a_grid() {
    const RESERVE_EXPONENT_VALUES: [u32; 4] = [3, 4, 6, 8];
    const N_VALUES: [usize; 4] = [32_768, 65_537, 100_000, 131_072];

    for reserve_exponent in RESERVE_EXPONENT_VALUES {
        for n in N_VALUES {
            assert_funnel_invariants(n, reserve_exponent);
        }
    }
}

#[test]
fn funnel_special_length_is_the_largest_compatible_choice() {
    for (n, reserve_exponent) in [(32_768, 3), (50_000, 4), (131_072, 8)] {
        let plan = PaperConfig::new(n, reserve_exponent)
            .unwrap()
            .funnel_plan()
            .unwrap();
        let (_, upper) = independent_special_bounds(n, reserve_exponent);
        let alpha = usize::try_from(4_u128 * u128::from(reserve_exponent) + 10).unwrap();

        assert!((plan.special_len() + 1..=upper).all(|candidate| {
            !independent_special_is_compatible(
                n,
                candidate,
                plan.beta(),
                plan.fallback_bucket_width(),
                alpha,
            )
        }));
    }
}

#[test]
fn funnel_rejects_a_finite_special_array_that_cannot_be_tiled() {
    assert_eq!(
        PaperConfig::new(50_003, 4).unwrap().funnel_plan(),
        Err(FunnelPlanError::NoCompatibleSpecialLayout {
            lower: 1_563,
            upper: 2_343,
            beta: 8,
            loglog_ceiling: 4,
            fallback_bucket_width: 8,
        })
    );
}

#[test]
fn funnel_plan_rejects_delta_above_the_concrete_domain() {
    let config = PaperConfig::new(32_768, 2).unwrap();

    assert_eq!(
        config.funnel_plan(),
        Err(FunnelPlanError::ExponentBelowMinimum {
            reserve_exponent: 2,
            minimum: 3,
        })
    );
}

#[test]
fn funnel_plan_reports_small_and_infeasible_geometry() {
    assert_eq!(
        PaperConfig::new(2, 3).unwrap().funnel_plan(),
        Err(FunnelPlanError::NoCompatibleSpecialLayout {
            lower: 1,
            upper: 0,
            beta: 6,
            loglog_ceiling: 1,
            fallback_bucket_width: 2,
        })
    );
    assert_eq!(
        PaperConfig::new(128, 3).unwrap().funnel_plan(),
        Err(FunnelPlanError::NoCompatibleSpecialLayout {
            lower: 8,
            upper: 12,
            beta: 6,
            loglog_ceiling: 3,
            fallback_bucket_width: 6,
        })
    );
}

#[test]
fn funnel_plan_handles_extreme_inputs_without_overflow() {
    let extreme_exponent = PaperConfig::new(usize::MAX, u32::MAX)
        .unwrap()
        .funnel_plan();
    if usize::BITS >= 64 {
        assert_eq!(
            extreme_exponent,
            Err(FunnelPlanError::NoCompatibleSpecialLayout {
                lower: 1,
                upper: 0,
                beta: usize::try_from(2_u128 * u128::from(u32::MAX)).unwrap(),
                loglog_ceiling: 6,
                fallback_bucket_width: 12,
            })
        );
    } else {
        assert_eq!(
            extreme_exponent,
            Err(FunnelPlanError::DerivedParameterOverflow {
                parameter: FunnelPlanParameter::Alpha,
                reserve_exponent: u32::MAX,
            })
        );
    }

    let plan = PaperConfig::new(usize::MAX - 2, 3)
        .unwrap()
        .funnel_plan()
        .unwrap();
    let ordinary_slots: u128 = plan
        .ordinary_level_lengths()
        .map(|length| length as u128)
        .sum();
    assert_eq!(
        ordinary_slots + plan.special_len() as u128,
        (usize::MAX - 2) as u128
    );
}

#[cfg(target_pointer_width = "64")]
#[test]
fn funnel_plan_rejects_zero_bucket_fallback_even_when_zero_is_divisible() {
    assert_eq!(
        PaperConfig::new(12_297_829_382_473_034_485, 63)
            .unwrap()
            .funnel_plan(),
        Err(FunnelPlanError::NoCompatibleSpecialLayout {
            lower: 1,
            upper: 1,
            beta: 126,
            loglog_ceiling: 6,
            fallback_bucket_width: 12,
        })
    );
}

#[test]
fn funnel_loglog_ceiling_changes_at_exact_base_two_boundaries() {
    let mut k = 0_u32;
    loop {
        let exponent = 1_u32 << k;
        if exponent >= usize::BITS {
            break;
        }
        let boundary = 1_usize << exponent;

        assert_result_loglog(boundary, usize::try_from(k).unwrap().max(1));
        assert_result_loglog(boundary + 1, usize::try_from(k + 1).unwrap().max(1));
        k += 1;
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn funnel_special_selector_matches_an_exhaustive_small_reference() {
    const MAX_TOTAL_BUCKETS: usize = 400;

    for reserve_exponent in 3..=6 {
        let alpha = 4 * reserve_exponent as usize + 10;
        let beta = 2 * reserve_exponent as usize;
        let reachable = independent_reachable_totals(alpha, MAX_TOTAL_BUCKETS);

        for n in 2..=2_000 {
            let expected = brute_force_special_len(n, reserve_exponent, beta, &reachable);
            match (
                PaperConfig::new(n, reserve_exponent).unwrap().funnel_plan(),
                expected,
            ) {
                (Ok(plan), Some(special_len)) => {
                    assert_eq!(
                        plan.special_len(),
                        special_len,
                        "n={n}, d={reserve_exponent}"
                    );
                }
                (Err(FunnelPlanError::NoCompatibleSpecialLayout { .. }), None) => {}
                (actual, expected) => {
                    panic!("n={n}, d={reserve_exponent}, actual={actual:?}, expected={expected:?}")
                }
            }
        }
    }
}

#[test]
fn funnel_ordinary_iterators_preserve_exact_size_and_fused_contracts() {
    let plan = PaperConfig::new(32_768, 3).unwrap().funnel_plan().unwrap();
    let mut counts = plan.ordinary_bucket_counts();
    let mut lengths = plan.ordinary_level_lengths();

    for remaining in (1..=plan.alpha()).rev() {
        assert_eq!(counts.len(), remaining);
        assert_eq!(lengths.len(), remaining);
        assert_eq!(
            lengths.next(),
            counts.next().map(|count| count * plan.beta())
        );
    }
    assert_eq!(counts.len(), 0);
    assert_eq!(lengths.len(), 0);
    assert_eq!(counts.next(), None);
    assert_eq!(counts.next(), None);
    assert_eq!(lengths.next(), None);
    assert_eq!(lengths.next(), None);
}

#[test]
#[cfg_attr(miri, ignore)]
fn funnel_reachable_path_sums_are_contiguous_in_a_small_reference_model() {
    for first in 1_usize..=64 {
        let mut states = std::collections::BTreeSet::from([(first, first)]);
        for level_count in 1..=24 {
            let sums: std::collections::BTreeSet<_> = states.iter().map(|&(_, sum)| sum).collect();
            let minimum = *sums.first().unwrap();
            let maximum = *sums.last().unwrap();
            assert_eq!(
                sums.len(),
                maximum - minimum + 1,
                "first={first}, level_count={level_count}"
            );

            let mut next_states = std::collections::BTreeSet::new();
            for &(current, sum) in &states {
                for next in 1..=current {
                    if (4_u128 * next as u128).abs_diff(3_u128 * current as u128) <= 4 {
                        next_states.insert((next, sum + next));
                    }
                }
            }
            states = next_states;
        }
    }
}

#[allow(clippy::too_many_lines)]
fn assert_funnel_invariants(n: usize, reserve_exponent: u32) {
    let config = PaperConfig::new(n, reserve_exponent).unwrap();
    let plan = config.funnel_plan().unwrap();
    let counts: Vec<_> = plan.ordinary_bucket_counts().collect();
    let lengths: Vec<_> = plan.ordinary_level_lengths().collect();
    let (lower, upper) = independent_special_bounds(n, reserve_exponent);
    let expected_alpha = usize::try_from(4_u128 * u128::from(reserve_exponent) + 10).unwrap();
    let expected_beta = usize::try_from(2_u128 * u128::from(reserve_exponent)).unwrap();
    let expected_loglog_ceiling = independent_loglog_ceiling(n);
    let expected_fallback_width = 2 * expected_loglog_ceiling;
    let expected_target = n - n / usize::try_from(1_u128 << reserve_exponent).unwrap();

    assert_eq!(
        plan.config(),
        config,
        "n={n}, reserve_exponent={reserve_exponent}"
    );
    assert_eq!(
        plan.alpha(),
        expected_alpha,
        "n={n}, reserve_exponent={reserve_exponent}"
    );
    assert_eq!(
        plan.beta(),
        expected_beta,
        "n={n}, reserve_exponent={reserve_exponent}"
    );
    assert_eq!(
        plan.loglog_ceiling(),
        expected_loglog_ceiling,
        "n={n}, reserve_exponent={reserve_exponent}"
    );
    assert_eq!(
        plan.fallback_bucket_width(),
        expected_fallback_width,
        "n={n}, reserve_exponent={reserve_exponent}"
    );
    assert_eq!(
        config.max_insertions(),
        expected_target,
        "n={n}, reserve_exponent={reserve_exponent}"
    );
    assert!(
        (lower..=upper).contains(&plan.special_len()),
        "n={n}, reserve_exponent={reserve_exponent}"
    );
    assert_eq!(
        (n - plan.special_len()) % expected_beta,
        0,
        "n={n}, reserve_exponent={reserve_exponent}"
    );
    assert_eq!(
        counts.len(),
        expected_alpha,
        "n={n}, reserve_exponent={reserve_exponent}"
    );
    assert!(
        counts.iter().all(|&count| count > 0),
        "n={n}, reserve_exponent={reserve_exponent}"
    );
    assert_eq!(
        counts.iter().sum::<usize>(),
        (n - plan.special_len()) / expected_beta,
        "n={n}, reserve_exponent={reserve_exponent}"
    );
    assert_eq!(
        lengths,
        counts
            .iter()
            .map(|&count| count * expected_beta)
            .collect::<Vec<_>>(),
        "n={n}, reserve_exponent={reserve_exponent}"
    );
    assert_eq!(
        lengths.iter().sum::<usize>() + plan.special_len(),
        n,
        "n={n}, reserve_exponent={reserve_exponent}"
    );
    for adjacent in counts.windows(2) {
        let current = adjacent[0] as u128;
        let next = adjacent[1] as u128;
        assert!(
            next <= current,
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        assert!(
            (4_u128 * next).abs_diff(3_u128 * current) <= 4,
            "n={n}, reserve_exponent={reserve_exponent}, current={current}, next={next}"
        );
    }
    assert_eq!(
        plan.special_primary_len() + plan.special_fallback_len(),
        plan.special_len(),
        "n={n}, reserve_exponent={reserve_exponent}"
    );
    assert!(
        plan.special_primary_len() >= plan.special_fallback_len(),
        "n={n}, reserve_exponent={reserve_exponent}"
    );
    assert!(
        plan.special_primary_len()
            .abs_diff(plan.special_fallback_len())
            <= 1,
        "n={n}, reserve_exponent={reserve_exponent}"
    );
    assert!(
        plan.special_fallback_len() >= expected_fallback_width,
        "n={n}, reserve_exponent={reserve_exponent}"
    );
    assert_eq!(
        plan.special_fallback_len() % expected_fallback_width,
        0,
        "n={n}, reserve_exponent={reserve_exponent}"
    );
    assert_eq!(
        plan.fallback_bucket_count() * expected_fallback_width,
        plan.special_fallback_len(),
        "n={n}, reserve_exponent={reserve_exponent}"
    );
    assert!(
        plan.fallback_bucket_count() > 0,
        "n={n}, reserve_exponent={reserve_exponent}"
    );
}

fn assert_result_loglog(n: usize, expected: usize) {
    match PaperConfig::new(n, 3).unwrap().funnel_plan() {
        Ok(plan) => {
            assert_eq!(plan.loglog_ceiling(), expected, "n={n}");
            assert_eq!(plan.fallback_bucket_width(), 2 * expected, "n={n}");
        }
        Err(FunnelPlanError::NoCompatibleSpecialLayout {
            loglog_ceiling,
            fallback_bucket_width,
            ..
        }) => {
            assert_eq!(loglog_ceiling, expected, "n={n}");
            assert_eq!(fallback_bucket_width, 2 * expected, "n={n}");
        }
        Err(error) => panic!("n={n}, unexpected error={error:?}"),
    }
}

fn brute_force_special_len(
    n: usize,
    reserve_exponent: u32,
    beta: usize,
    reachable_totals: &std::collections::BTreeSet<usize>,
) -> Option<usize> {
    let (lower, upper) = independent_special_bounds(n, reserve_exponent);
    if lower > upper {
        return None;
    }
    let fallback_width = 2 * independent_loglog_ceiling(n);

    (lower..=upper).rev().find(|&special_len| {
        let main_len = n - special_len;
        let fallback_len = special_len / 2;
        main_len.is_multiple_of(beta)
            && fallback_len >= fallback_width
            && fallback_len.is_multiple_of(fallback_width)
            && reachable_totals.contains(&(main_len / beta))
    })
}

fn independent_special_is_compatible(
    n: usize,
    special_len: usize,
    beta: usize,
    fallback_width: usize,
    alpha: usize,
) -> bool {
    let main_len = n - special_len;
    let fallback_len = special_len / 2;
    main_len.is_multiple_of(beta)
        && fallback_len >= fallback_width
        && fallback_len.is_multiple_of(fallback_width)
        && main_len / beta >= alpha
}

fn independent_reachable_totals(
    level_count: usize,
    maximum_total: usize,
) -> std::collections::BTreeSet<usize> {
    let mut states: std::collections::BTreeSet<_> =
        (1..=maximum_total).map(|first| (first, first)).collect();
    for _ in 1..level_count {
        let mut next_states = std::collections::BTreeSet::new();
        for &(current, sum) in &states {
            for next in 1..=current {
                if (4_u128 * next as u128).abs_diff(3_u128 * current as u128) <= 4
                    && sum + next <= maximum_total
                {
                    next_states.insert((next, sum + next));
                }
            }
        }
        states = next_states;
    }
    states.into_iter().map(|(_, sum)| sum).collect()
}

fn independent_loglog_ceiling(n: usize) -> usize {
    independent_ceil_log2(independent_ceil_log2(n)).max(1)
}

fn independent_ceil_log2(value: usize) -> usize {
    let mut exponent = 0;
    let mut power = 1_u128;
    while power < value as u128 {
        power *= 2;
        exponent += 1;
    }
    exponent
}

fn independent_special_bounds(n: usize, reserve_exponent: u32) -> (usize, usize) {
    let lower_denominator = 1_u128 << (reserve_exponent + 1);
    let upper_denominator = 1_u128 << (reserve_exponent + 2);
    let n = n as u128;
    let lower = n / lower_denominator + u128::from(!n.is_multiple_of(lower_denominator));
    let upper = (3 * n) / upper_denominator;
    (
        usize::try_from(lower).unwrap(),
        usize::try_from(upper).unwrap(),
    )
}

fn ceil_three_quarters(value: usize) -> usize {
    usize::try_from(((value as u128) * 3).div_ceil(4)).unwrap()
}
