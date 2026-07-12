#[path = "../benches/support/fixtures.rs"]
mod fixtures;

use std::collections::HashSet;

use fixtures::{
    DEFAULT_HIT_QUERY_SEED, exact_size_label, parse_positive_sizes, scaled_insert_sample_size,
    sequential_hit_keys, shuffled_hit_keys, shuffled_hit_keys_with_seed,
};

fn pairs(count: usize) -> Vec<(u64, u64)> {
    (0..count)
        .map(|index| {
            let key = index as u64 * 17 + 3;
            (key, !key)
        })
        .collect()
}

#[test]
fn shuffled_cycle_starts_with_a_true_permutation() {
    let pairs = pairs(16);
    let queries = shuffled_hit_keys(&pairs, pairs.len() * 2 + 3);
    let mut first_cycle = queries[..pairs.len()].to_vec();
    let mut expected = pairs.iter().map(|&(key, _)| key).collect::<Vec<_>>();
    first_cycle.sort_unstable();
    expected.sort_unstable();

    assert_eq!(first_cycle, expected);
    assert_eq!(
        &queries[..pairs.len()],
        &queries[pairs.len()..pairs.len() * 2]
    );
}

#[test]
fn shuffled_order_is_seeded_and_reproducible() {
    let pairs = pairs(64);
    let default_order = shuffled_hit_keys(&pairs, pairs.len());

    assert_eq!(
        default_order,
        shuffled_hit_keys_with_seed(&pairs, pairs.len(), DEFAULT_HIT_QUERY_SEED)
    );
    assert_eq!(default_order, shuffled_hit_keys(&pairs, pairs.len()));
    assert_ne!(
        default_order,
        shuffled_hit_keys_with_seed(&pairs, pairs.len(), DEFAULT_HIT_QUERY_SEED ^ 1)
    );
}

#[test]
fn default_seed_has_a_golden_permutation() {
    assert_eq!(
        shuffled_hit_keys(&pairs(8), 8),
        [88, 20, 3, 105, 71, 54, 122, 37]
    );
}

#[test]
fn hit_helpers_return_exactly_the_requested_hit_keys() {
    let pairs = pairs(7);
    let hits = pairs.iter().map(|&(key, _)| key).collect::<HashSet<_>>();

    for queries in [
        shuffled_hit_keys(&pairs, 31),
        sequential_hit_keys(&pairs, 31),
    ] {
        assert_eq!(queries.len(), 31);
        assert!(queries.iter().all(|key| hits.contains(key)));
    }
}

#[test]
fn sequential_hits_match_the_former_modulo_trace() {
    let pairs = pairs(5);
    let expected = (0..13)
        .map(|index| pairs[index % pairs.len()].0)
        .collect::<Vec<_>>();

    assert_eq!(sequential_hit_keys(&pairs, 13), expected);
}

#[test]
fn empty_pair_inputs_are_safe() {
    assert!(shuffled_hit_keys(&[], 10).is_empty());
    assert!(shuffled_hit_keys_with_seed(&[], 10, DEFAULT_HIT_QUERY_SEED).is_empty());
    assert!(sequential_hit_keys(&[], 10).is_empty());
}

#[test]
fn positive_size_parser_accepts_trimmed_values() {
    assert_eq!(
        parse_positive_sizes("SCALED_INSERT_SIZES", "1, 100,10000").unwrap(),
        vec![1, 100, 10_000]
    );
}

#[test]
fn positive_size_parser_rejects_every_invalid_class() {
    for raw in ["", "   ", "0", "100,0", "ten", "100,,200", ",100", "100,"] {
        let error = parse_positive_sizes("SCALED_INSERT_SIZES", raw).unwrap_err();
        assert!(error.contains("SCALED_INSERT_SIZES"), "{raw:?}: {error}");
    }
}

#[test]
fn positive_size_parser_rejects_duplicate_benchmark_ids() {
    let error = parse_positive_sizes("SCALED_INSERT_SIZES", "1000,1000").unwrap_err();
    assert!(error.contains("SCALED_INSERT_SIZES"), "{error}");
    assert!(error.contains("duplicate"), "{error}");
    assert!(error.contains("1000"), "{error}");
}

#[test]
fn scaled_size_labels_are_exact_and_unambiguous() {
    assert_eq!(exact_size_label(100_000), "100K");
    assert_eq!(exact_size_label(1_000_000), "1M");
    assert_eq!(exact_size_label(10_000_000), "10M");
    assert_eq!(exact_size_label(1_500), "1500");
}

#[test]
fn scaled_insert_uses_minimum_samples_only_for_the_10m_tier() {
    assert_eq!(scaled_insert_sample_size(100_000), 100);
    assert_eq!(scaled_insert_sample_size(1_000_000), 100);
    assert_eq!(scaled_insert_sample_size(9_999_999), 100);
    assert_eq!(scaled_insert_sample_size(10_000_000), 10);
    assert_eq!(scaled_insert_sample_size(20_000_000), 10);
}

#[test]
fn mean_latency_builds_each_map_once_per_size_not_once_per_sample() {
    let source = include_str!("../benches/mean_latency.rs");
    assert!(
        source.contains("let maps = LatencyMaps::new(&pairs);")
            && source.contains("bench_latency_group(c, &workload, &maps"),
        "latency maps must be constructed outside Criterion routines and reused by both traces"
    );
    assert!(
        !source.contains("let map = $build(&pairs);")
            && !source.contains("latency_arm!(\"std\", common::build_std_map)"),
        "a builder inside bench_function is repeated for every Criterion sample"
    );
}
