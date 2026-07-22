mod harness;

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

include!("../tests/fixtures/cache_gate_layout_adversary.rs");

// SAFETY: Linux cache-gate links this function through the checked RX-only
// target-specific augmentation and validates the final ELF.
#[cfg_attr(
    target_os = "linux",
    unsafe(link_section = ".text.opthash.cache_gate.funnel.insert")
)]
#[inline(never)]
fn funnel_cache_gate_insert_kernel(
    map: &mut harness::FunnelHashMap<u64, u64>,
    pairs: &[(u64, u64)],
) -> Duration {
    let start = Instant::now();
    for &(key, value) in pairs {
        black_box(map.insert(black_box(key), black_box(value)));
    }
    start.elapsed()
}

// SAFETY: Linux cache-gate links this function through the checked RX-only
// target-specific augmentation and validates the final ELF.
#[cfg_attr(
    target_os = "linux",
    unsafe(link_section = ".text.opthash.cache_gate.funnel.get")
)]
#[inline(never)]
fn funnel_cache_gate_get_kernel(map: &harness::FunnelHashMap<u64, u64>, key: u64) -> Option<u64> {
    map.get(black_box(&key)).copied()
}

fn cache_gate_insert(c: &mut Criterion) {
    exercise_cache_gate_layout_adversary();
    let pairs = harness::cache_gate_pairs();
    let mut map = harness::funnel_cache_gate_map();
    harness::validate_funnel_cache_gate_fill(&mut map, &pairs);
    map.clear();
    let expected_capacity = map.capacity();
    let mut group = c.benchmark_group("cache_gate_insert");
    group.throughput(Throughput::Elements(pairs.len() as u64));
    group.bench_function("cache_gate_insert_funnel", move |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                map.clear();
                assert_eq!(map.capacity(), expected_capacity);
                total += funnel_cache_gate_insert_kernel(&mut map, &pairs);
                assert_eq!(map.len(), pairs.len());
            }
            total
        });
    });
    group.finish();
}

fn cache_gate_get_hit(c: &mut Criterion) {
    let pairs = harness::cache_gate_pairs();
    let mut map = harness::funnel_cache_gate_map();
    harness::validate_funnel_cache_gate_fill(&mut map, &pairs);
    let keys = pairs.iter().map(|pair| pair.0).collect::<Vec<_>>();
    c.bench_function("cache_gate_get_hit_funnel", move |b| {
        let mut keys = keys.iter().cycle();
        b.iter(|| black_box(funnel_cache_gate_get_kernel(&map, *keys.next().unwrap())));
    });
}

criterion_group!(benches, cache_gate_insert, cache_gate_get_hit);
criterion_main!(benches);
