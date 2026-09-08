#[path = "../benches/harness/mod.rs"]
mod harness;
#[path = "../benches/harness/memory.rs"]
mod memory;

use std::alloc::{GlobalAlloc, Layout};
use std::collections::HashSet;

use harness::{
    DEFAULT_HIT_QUERY_SEED, LATENCY_SIZES, exact_size_label, parse_positive_sizes,
    scaled_insert_sample_size, sequential_hit_keys, shuffled_hit_keys, shuffled_hit_keys_with_seed,
};
use memory::{AllocationCounters, AllocationMeasurement, AllocationSnapshot, CountingAllocator};

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
fn latency_sizes_keep_their_round_labels() {
    let labels: Vec<String> = LATENCY_SIZES.iter().map(|&n| exact_size_label(n)).collect();
    assert_eq!(labels, ["1K", "10K", "100K", "1M", "10M"]);
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
fn allocation_measurement_reports_map_delta_per_live_entry() {
    let before = AllocationSnapshot {
        live_bytes: 1_000,
        peak_live_bytes: 1_000,
        live_allocations: 10,
        allocation_calls: 40,
        allocated_bytes: 8_000,
    };
    let after = AllocationSnapshot {
        live_bytes: 1_400,
        peak_live_bytes: 1_900,
        live_allocations: 12,
        allocation_calls: 45,
        allocated_bytes: 8_600,
    };

    let measured = AllocationMeasurement::between(before, after, 4);

    assert_eq!(measured.live_entries, 4);
    assert_eq!(measured.live_bytes, 400);
    assert_eq!(measured.peak_live_bytes, 900);
    assert_eq!(measured.live_allocations, 2);
    assert_eq!(measured.allocation_calls, 5);
    assert_eq!(measured.allocated_bytes, 600);
    assert!((measured.per_entry(measured.live_bytes) - 100.0).abs() < f64::EPSILON);
    assert!((measured.per_entry(measured.peak_live_bytes) - 225.0).abs() < f64::EPSILON);
    assert!((measured.per_entry(measured.allocated_bytes) - 150.0).abs() < f64::EPSILON);
}

#[test]
fn counting_allocator_tracks_successful_allocation_and_deallocation() {
    static COUNTERS: AllocationCounters = AllocationCounters::new();
    let allocator = CountingAllocator::new(&COUNTERS);
    let layout = Layout::from_size_align(64, 8).unwrap();
    let before = allocator.snapshot();

    let ptr = unsafe { allocator.alloc(layout) };
    assert!(!ptr.is_null());
    let allocated = allocator.snapshot();

    assert_eq!(allocated.live_bytes - before.live_bytes, 64);
    assert_eq!(allocated.live_allocations - before.live_allocations, 1);
    assert_eq!(allocated.allocation_calls - before.allocation_calls, 1);
    assert_eq!(allocated.allocated_bytes - before.allocated_bytes, 64);

    unsafe { allocator.dealloc(ptr, layout) };
    let deallocated = allocator.snapshot();
    assert_eq!(deallocated.live_bytes, before.live_bytes);
    assert_eq!(deallocated.live_allocations, before.live_allocations);
}

#[test]
fn counting_allocator_tracks_zeroed_and_reallocated_memory() {
    static COUNTERS: AllocationCounters = AllocationCounters::new();
    let allocator = CountingAllocator::new(&COUNTERS);
    let initial_layout = Layout::from_size_align(32, 8).unwrap();
    allocator.reset_peak();
    let before = allocator.snapshot();

    let ptr = unsafe { allocator.alloc_zeroed(initial_layout) };
    assert!(!ptr.is_null());
    assert!(
        unsafe { std::slice::from_raw_parts(ptr, 32) }
            .iter()
            .all(|&byte| byte == 0)
    );

    let grown = unsafe { allocator.realloc(ptr, initial_layout, 96) };
    assert!(!grown.is_null());
    let grown_snapshot = allocator.snapshot();
    assert_eq!(grown_snapshot.live_bytes - before.live_bytes, 96);
    assert_eq!(grown_snapshot.live_allocations - before.live_allocations, 1);
    // The default realloc allocates the new block before freeing the old one,
    // so the peak holds both.
    assert_eq!(grown_snapshot.peak_live_bytes - before.live_bytes, 32 + 96);

    let grown_layout = Layout::from_size_align(96, 8).unwrap();
    let shrunk = unsafe { allocator.realloc(grown, grown_layout, 16) };
    assert!(!shrunk.is_null());
    let shrunk_snapshot = allocator.snapshot();
    assert_eq!(shrunk_snapshot.live_bytes - before.live_bytes, 16);
    assert_eq!(
        shrunk_snapshot.live_allocations - before.live_allocations,
        1
    );

    let shrunk_layout = Layout::from_size_align(16, 8).unwrap();
    unsafe { allocator.dealloc(shrunk, shrunk_layout) };
    let after = allocator.snapshot();
    assert_eq!(after.live_bytes, before.live_bytes);
    assert_eq!(after.live_allocations, before.live_allocations);
}

#[test]
fn mean_latency_builds_each_map_once_per_size_not_once_per_sample() {
    let source = include_str!("../benches/mean_latency.rs");
    assert!(
        source.contains("let maps = harness::MapQuad::new(&pairs);")
            && source.contains("bench_latency_group(c, &workload, &maps"),
        "latency maps must be constructed outside Criterion routines and reused by both traces"
    );
    assert!(
        !source.contains("let map = $build(&pairs);")
            && !source.contains("latency_arm!(\"std\", harness::build_std_map)"),
        "a builder inside bench_function is repeated for every Criterion sample"
    );
}
