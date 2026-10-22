use criterion::{Criterion, Throughput, criterion_group, criterion_main};

use harness::bench_insert_reuse;

const DEFAULT_SIZES: &[usize] = &[100_000, 1_000_000, 10_000_000];

fn bench_scaled_insert(c: &mut Criterion) {
    for size in harness::sizes_from_env("SCALED_INSERT_SIZES", DEFAULT_SIZES) {
        let pairs = harness::make_pairs(size);
        let label = harness::exact_size_label(size);
        let workload = format!("insert_scale_{label}");
        let mut group = c.benchmark_group(&workload);
        group.sample_size(harness::scaled_insert_sample_size(size));
        group.throughput(Throughput::Elements(size as u64));
        bench_insert_reuse!(group, &workload, size, &pairs);
        group.finish();
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = bench_scaled_insert
);
criterion_main!(benches);
