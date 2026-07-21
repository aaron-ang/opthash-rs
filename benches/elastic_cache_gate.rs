mod harness;

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

#[inline(never)]
fn elastic_cache_gate_insert_kernel(
    map: &mut harness::ElasticHashMap<u64, u64>,
    pairs: &[(u64, u64)],
) -> Duration {
    let start = Instant::now();
    for &(key, value) in pairs {
        black_box(map.insert(black_box(key), black_box(value)));
    }
    start.elapsed()
}

#[inline(never)]
fn elastic_cache_gate_get_kernel(map: &harness::ElasticHashMap<u64, u64>, key: u64) -> Option<u64> {
    map.get(black_box(&key)).copied()
}

fn cache_gate_insert(c: &mut Criterion) {
    let pairs = harness::cache_gate_pairs();
    let mut map = harness::elastic_cache_gate_map();
    harness::validate_cache_gate_fill(&mut map, &pairs);
    map.clear();
    let expected_capacity = map.capacity();
    let mut group = c.benchmark_group("cache_gate_insert");
    group.throughput(Throughput::Elements(pairs.len() as u64));
    group.bench_function("cache_gate_insert_elastic", move |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                map.clear();
                assert_eq!(map.capacity(), expected_capacity);
                total += elastic_cache_gate_insert_kernel(&mut map, &pairs);
                assert_eq!(map.len(), pairs.len());
            }
            total
        });
    });
    group.finish();
}

fn cache_gate_get_hit(c: &mut Criterion) {
    let pairs = harness::cache_gate_pairs();
    let mut map = harness::elastic_cache_gate_map();
    harness::validate_cache_gate_fill(&mut map, &pairs);
    let keys = pairs.iter().map(|pair| pair.0).collect::<Vec<_>>();
    c.bench_function("cache_gate_get_hit_elastic", move |b| {
        let mut keys = keys.iter().cycle();
        b.iter(|| black_box(elastic_cache_gate_get_kernel(&map, *keys.next().unwrap())));
    });
}

criterion_group!(benches, cache_gate_insert, cache_gate_get_hit);
criterion_main!(benches);
