// This package intentionally has no `opthash` path or registry dependency.
use std::collections::HashMap as StdHashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::BuildHasherDefault;
use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use foldhash::fast::FixedState;
use hashbrown::HashMap as HashbrownMap;

const OP_COUNT: usize = 100_000;
const GOLDEN_RATIO_U64: u64 = 0x9E37_79B9_7F4A_7C15;
const VALUE_XOR_MIX: u64 = 0xA5A5_A5A5_A5A5_A5A5;

fn pairs() -> Vec<(u64, u64)> {
    (0..OP_COUNT)
        .map(|index| {
            let key = (index as u64).wrapping_mul(GOLDEN_RATIO_U64);
            (key, key ^ VALUE_XOR_MIX)
        })
        .collect()
}

macro_rules! control_arm {
    ($group:expr, $name:literal, $map:expr, $pairs:expr) => {{
        let pairs = $pairs.clone();
        let mut map = $map;
        let expected_capacity = map.capacity();
        for &(key, value) in &pairs {
            assert_eq!(map.insert(key, value), None);
        }
        assert_eq!(map.len(), pairs.len());
        assert_eq!(map.capacity(), expected_capacity);
        for &(key, value) in &pairs {
            assert_eq!(map.get(&key), Some(&value));
        }
        map.clear();
        $group.bench_function($name, move |b| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    map.clear();
                    assert_eq!(map.capacity(), expected_capacity);
                    let start = std::time::Instant::now();
                    for &(key, value) in &pairs {
                        black_box(map.insert(black_box(key), black_box(value)));
                    }
                    total += start.elapsed();
                    assert_eq!(map.len(), pairs.len());
                }
                total
            });
        });
    }};
}

fn fixed_controls(c: &mut Criterion) {
    let pairs = pairs();
    let mut group = c.benchmark_group("cache_gate_insert");
    group.throughput(Throughput::Elements(OP_COUNT as u64));
    control_arm!(
        group,
        "cache_gate_insert_std",
        StdHashMap::<u64, u64, BuildHasherDefault<DefaultHasher>>::with_capacity_and_hasher(
            OP_COUNT * 2,
            BuildHasherDefault::default()
        ),
        pairs
    );
    control_arm!(
        group,
        "cache_gate_insert_hashbrown",
        HashbrownMap::<u64, u64, FixedState>::with_capacity_and_hasher(
            OP_COUNT * 2,
            FixedState::default()
        ),
        pairs
    );
    group.finish();
}

criterion_group!(benches, fixed_controls);
criterion_main!(benches);
