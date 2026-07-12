#[path = "support/common.rs"]
mod common;
#[path = "support/fixtures.rs"]
mod fixtures;
#[macro_use]
#[path = "support/throughput.rs"]
mod throughput;

use std::env;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

const DEFAULT_SIZES: &[usize] = &[100_000, 1_000_000, 10_000_000];

fn configured_sizes() -> Vec<usize> {
    match env::var("SCALED_INSERT_SIZES") {
        Ok(raw) => fixtures::parse_positive_sizes("SCALED_INSERT_SIZES", &raw)
            .unwrap_or_else(|error| panic!("{error}")),
        Err(env::VarError::NotPresent) => DEFAULT_SIZES.to_vec(),
        Err(env::VarError::NotUnicode(_)) => {
            panic!("SCALED_INSERT_SIZES must contain valid Unicode")
        }
    }
}

fn bench_scaled_insert(c: &mut Criterion) {
    for size in configured_sizes() {
        let pairs = common::make_pairs(size);
        let label = fixtures::exact_size_label(size);
        let workload = format!("insert_scale_{label}");
        let mut group = c.benchmark_group(&workload);
        group.sample_size(fixtures::scaled_insert_sample_size(size));
        group.throughput(Throughput::Elements(size as u64));
        bench_insert_reuse_named!(group, &workload, size, &pairs);
        group.finish();
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = bench_scaled_insert
);
criterion_main!(benches);
