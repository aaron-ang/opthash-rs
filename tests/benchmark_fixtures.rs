use std::alloc::{GlobalAlloc, Layout};
use std::collections::HashSet;

use harness::memory::{
    AllocationCounters, AllocationMeasurement, AllocationSnapshot, CountingAllocator,
};
use harness::{
    DEFAULT_HIT_QUERY_SEED, GroupProbeMap, HIGH_LOAD_EXPONENTS, HIGH_LOAD_SLOTS, LATENCY_SIZES,
    LoadPoint, MAP_SIZE, MAP_SLOTS, MapQuad, OP_COUNT, exact_size_label, parse_positive_sizes,
    scaled_insert_sample_size, sequential_hit_keys, shuffled_hit_keys, shuffled_hit_keys_with_seed,
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
    assert_eq!(shuffled_hit_keys(&[], 10), [0_u64; 0]);
    assert_eq!(
        shuffled_hit_keys_with_seed(&[], 10, DEFAULT_HIT_QUERY_SEED),
        [0_u64; 0]
    );
    assert_eq!(sequential_hit_keys(&[], 10), [0_u64; 0]);
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
#[cfg_attr(miri, ignore = "full-size bench fixture is too slow")]
fn throughput_maps_sit_at_their_full_insert_budget() {
    let maps = MapQuad::new(&pairs(MAP_SIZE));
    for (name, capacity) in [
        ("std", maps.std.capacity()),
        ("hashbrown", maps.hashbrown.capacity()),
        ("elastic", maps.elastic.capacity()),
        ("funnel", maps.funnel.capacity()),
    ] {
        assert_eq!(capacity, MAP_SIZE, "{name} has slack above MAP_SIZE");
    }
    assert!(
        MAP_SLOTS.is_power_of_two(),
        "power-of-two maps only land exactly on MAP_SIZE from a power-of-two slot count"
    );
}

#[test]
#[cfg_attr(miri, ignore = "full-size bench fixture is too slow")]
fn entry_reinsert_fixture_preserves_capacity_and_funnel_epoch() {
    let pairs = harness::make_pairs(harness::ENTRY_REINSERT_FILL);
    let mut maps = MapQuad {
        std: harness::std_map_cap(MAP_SIZE),
        hashbrown: harness::hashbrown_map_cap(MAP_SIZE),
        elastic: harness::elastic_map_cap(MAP_SIZE),
        funnel: harness::funnel_map_cap(MAP_SIZE),
    };
    for &(key, value) in &pairs {
        maps.std.insert(key, value);
        maps.hashbrown.insert(key, value);
        maps.elastic.insert(key, value);
        maps.funnel.insert(key, value);
    }
    let epoch = maps.funnel.epoch();
    let removed = &pairs[..harness::ENTRY_REINSERT_COUNT];
    for &(key, value) in removed {
        assert_eq!(maps.std.remove(&key), Some(value));
        assert_eq!(maps.hashbrown.remove(&key), Some(value));
        assert_eq!(maps.elastic.remove(&key), Some(value));
        assert_eq!(maps.funnel.remove(&key), Some(value));
    }
    assert_eq!(maps.funnel.epoch().generation, epoch.generation);
    assert_eq!(maps.funnel.len(), pairs.len() - removed.len());
    for &(key, value) in removed {
        assert!(!maps.funnel.contains_key(&key));
        assert_eq!(*maps.std.entry(key).or_insert(value), value);
        assert_eq!(*maps.hashbrown.entry(key).or_insert(value), value);
        assert_eq!(*maps.elastic.entry(key).or_insert(value), value);
        assert_eq!(*maps.funnel.entry(key).or_insert(value), value);
    }
    for (name, len, capacity) in [
        ("std", maps.std.len(), maps.std.capacity()),
        ("hashbrown", maps.hashbrown.len(), maps.hashbrown.capacity()),
        ("elastic", maps.elastic.len(), maps.elastic.capacity()),
        ("funnel", maps.funnel.len(), maps.funnel.capacity()),
    ] {
        assert_eq!(len, pairs.len());
        assert_eq!(capacity, MAP_SIZE, "{name}");
    }
    assert_eq!(maps.funnel.epoch().generation, epoch.generation);
    for &(key, value) in &pairs {
        assert_eq!(maps.funnel.get(&key), Some(&value));
    }
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

    // SAFETY: `layout` has nonzero size.
    let ptr = unsafe { allocator.alloc(layout) };
    assert!(!ptr.is_null());
    let allocated = allocator.snapshot();

    assert_eq!(allocated.live_bytes - before.live_bytes, 64);
    assert_eq!(allocated.live_allocations - before.live_allocations, 1);
    assert_eq!(allocated.allocation_calls - before.allocation_calls, 1);
    assert_eq!(allocated.allocated_bytes - before.allocated_bytes, 64);

    // SAFETY: `ptr` came from `alloc` with `layout` and is freed once.
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

    // SAFETY: `initial_layout` has nonzero size.
    let ptr = unsafe { allocator.alloc_zeroed(initial_layout) };
    assert!(!ptr.is_null());
    assert!(
        // SAFETY: `ptr` is a live, zero-initialized 32-byte allocation.
        unsafe { std::slice::from_raw_parts(ptr, 32) }
            .iter()
            .all(|&byte| byte == 0)
    );

    // SAFETY: `ptr` is live with `initial_layout`; 96 is nonzero and fits `isize`.
    let grown = unsafe { allocator.realloc(ptr, initial_layout, 96) };
    assert!(!grown.is_null());
    let grown_snapshot = allocator.snapshot();
    assert_eq!(grown_snapshot.live_bytes - before.live_bytes, 96);
    assert_eq!(grown_snapshot.live_allocations - before.live_allocations, 1);
    // The default realloc allocates the new block before freeing the old one,
    // so the peak holds both.
    assert_eq!(grown_snapshot.peak_live_bytes - before.live_bytes, 32 + 96);

    let grown_layout = Layout::from_size_align(96, 8).unwrap();
    // SAFETY: `grown` is live with `grown_layout`; 16 is nonzero.
    let shrunk = unsafe { allocator.realloc(grown, grown_layout, 16) };
    assert!(!shrunk.is_null());
    let shrunk_snapshot = allocator.snapshot();
    assert_eq!(shrunk_snapshot.live_bytes - before.live_bytes, 16);
    assert_eq!(
        shrunk_snapshot.live_allocations - before.live_allocations,
        1
    );

    let shrunk_layout = Layout::from_size_align(16, 8).unwrap();
    // SAFETY: `shrunk` is live with `shrunk_layout` and freed once.
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

#[test]
fn group_probe_matches_std_at_high_load() {
    let slots = if cfg!(miri) { 1 << 10 } else { 1 << 16 };
    let point = LoadPoint::new(slots, 10);
    let pairs = harness::make_pairs(point.entries());
    let mut map = point.group_probe();
    let mut model = harness::std_map_cap(point.entries());
    assert!(map.is_empty());

    for &(key, value) in &pairs {
        assert_eq!(map.insert(key, value), model.insert(key, value));
    }
    for &(key, value) in pairs.iter().step_by(7) {
        assert_eq!(map.insert(key, !value), model.insert(key, !value));
    }
    assert_eq!(map.len(), model.len());
    for &(key, _) in &pairs {
        assert_eq!(map.get(&key), model.get(&key));
    }
    let misses = if cfg!(miri) { 64 } else { OP_COUNT };
    for key in harness::miss_keys(misses) {
        assert_eq!(map.get(&key), None);
    }
}

/// Small tables filled to one empty slot put many keys in groups that wrap
/// past the last slot, so lookups depend on the mirrored control bytes.
#[test]
fn group_probe_finds_keys_in_wrapping_groups() {
    let key_sets = if cfg!(miri) { 8 } else { 512 };
    for slots in [32, 64] {
        for set in 0..key_sets {
            let keys: Vec<u64> = (0..slots - 1)
                .map(|index| harness::key_at(set * slots + index))
                .collect();
            let mut map = GroupProbeMap::with_slots(slots, slots - 1);
            for (value, &key) in (0..).zip(&keys) {
                assert_eq!(map.insert(key, value), None);
            }
            assert_eq!(map.len(), slots - 1);
            for (value, key) in (0..).zip(&keys) {
                assert_eq!(map.get(key), Some(&value), "slots {slots}, set {set}");
            }
        }
    }
}

#[test]
fn group_probe_places_keys_where_hashbrown_does() {
    let point = LoadPoint::new(1 << 10, 3);
    let mut group_probe = point.group_probe();
    let mut hashbrown = point.hashbrown().expect("hashbrown runs at 7/8 load");
    for (key, value) in harness::make_pairs(point.entries()) {
        group_probe.insert(key, value);
        hashbrown.insert(key, value);
    }
    assert!(group_probe.keys().eq(hashbrown.keys()));
}

#[test]
#[should_panic(expected = "max_len must leave an empty slot")]
fn group_probe_rejects_a_budget_that_fills_every_slot() {
    let _ = GroupProbeMap::with_slots(64, 64);
}

#[test]
#[should_panic(expected = "GroupProbeMap is full")]
fn group_probe_rejects_inserts_past_its_budget() {
    let mut map = GroupProbeMap::with_slots(64, 1);
    map.insert(1, 1);
    map.insert(2, 2);
}

#[test]
fn high_load_groups_name_size_and_load() {
    let names: Vec<String> = HIGH_LOAD_SLOTS
        .iter()
        .flat_map(|&slots| {
            HIGH_LOAD_EXPONENTS
                .iter()
                .map(move |&exponent| LoadPoint::new(slots, exponent).group("get_miss"))
        })
        .collect();
    assert_eq!(
        names,
        [
            "get_miss_64Ki_87_5",
            "get_miss_64Ki_96_9",
            "get_miss_64Ki_99_2",
            "get_miss_64Ki_99_9",
            "get_miss_1Mi_87_5",
            "get_miss_1Mi_96_9",
            "get_miss_1Mi_99_2",
            "get_miss_1Mi_99_9",
        ]
    );
}

#[test]
fn high_load_tail_is_one_sixty_fourth_of_the_entries() {
    let point = LoadPoint::new(1 << 16, 10);
    assert_eq!(point.entries(), 65_472);
    assert_eq!(point.tail(), 1_023);
}

#[test]
#[cfg_attr(miri, ignore = "full-size bench fixture is too slow")]
fn high_load_arms_run_at_the_point_load() {
    for slots in HIGH_LOAD_SLOTS {
        for exponent in HIGH_LOAD_EXPONENTS {
            let point = LoadPoint::new(slots, exponent);
            // The constructors assert their own capacities.
            let _ = (point.elastic(), point.funnel(), point.group_probe());
            assert_eq!(point.hashbrown().is_some(), exponent == 3);
        }
    }
}

#[test]
#[should_panic(expected = "sweep exponents")]
fn high_load_rejects_exponents_the_load_label_cannot_tell_apart() {
    let _ = LoadPoint::new(1 << 16, 11);
}
