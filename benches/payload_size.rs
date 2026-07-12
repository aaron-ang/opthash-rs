#[macro_use]
mod harness;

use std::hint::black_box;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use harness::{MAP_SIZE, OP_COUNT};

/// [`bench_insert`] equivalent with `BigVal` payload (32B).
fn bench_insert_big(c: &mut Criterion) {
    let pairs = harness::make_big_pairs(OP_COUNT);
    let mut group = c.benchmark_group("insert_big");
    group.throughput(Throughput::Elements(OP_COUNT as u64));
    bench_insert_reuse!(group, "insert_big", OP_COUNT, &pairs);
    group.finish();
}

fn bench_get_hit_big(c: &mut Criterion) {
    let pairs = harness::make_big_pairs(MAP_SIZE);
    let hit_keys: Vec<u64> = (0..OP_COUNT).map(|idx| pairs[idx % MAP_SIZE].0).collect();

    let mut group = c.benchmark_group("get_hit_big");
    group.throughput(Throughput::Elements(hit_keys.len() as u64));

    bench_populated_big!(group, "get_hit_big", BatchSize::LargeInput, &pairs, |map| {
        for key in &hit_keys {
            black_box(map.get(black_box(key)));
        }
    },);

    group.finish();
}

fn bench_drain_big(c: &mut Criterion) {
    let pairs = harness::make_big_pairs(MAP_SIZE);
    let mut group = c.benchmark_group("drain_big");
    group.throughput(Throughput::Elements(MAP_SIZE as u64));

    bench_populated_big!(group, "drain_big", BatchSize::PerIteration, &pairs, |map| {
        black_box(map.drain().fold(0u64, |a, (k, v)| a ^ k ^ v[0] ^ v[3]))
    },);

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = bench_insert_big, bench_get_hit_big, bench_drain_big
);
criterion_main!(benches);
