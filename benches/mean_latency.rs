//! Mean per-lookup latency across `LATENCY_SIZES`. Feeds the
//! cache-hierarchy chart at `assets/benchmark-latency.svg` via
//! `scripts/generate_latency_chart.py`.
//!
//! ```sh
//! cargo bench --bench mean_latency
//! uv run scripts/generate_latency_chart.py
//! ```

#[path = "support/common.rs"]
mod common;

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

fn bench_get_hit_latency(c: &mut Criterion) {
    for &size in common::LATENCY_SIZES {
        let pairs = common::make_pairs(size);
        let query_keys: Vec<u64> = (0..size).map(|idx| pairs[idx].0).collect();

        let label = common::size_label(size);
        let workload = format!("get_hit_latency_{label}");
        let mut group = c.benchmark_group(&workload);

        // Bench id `<workload>_<impl>`, matching speedup.rs (see benches/README.md).
        macro_rules! latency_arm {
            ($impl:literal, $build:expr) => {
                group.bench_function(format!("{workload}_{}", $impl), |b| {
                    let map = $build(&pairs);
                    let mut keys = query_keys.iter().cycle();
                    b.iter(|| black_box(map.get(black_box(keys.next().unwrap()))));
                });
            };
        }

        latency_arm!("std", common::build_std_map);
        latency_arm!("hashbrown", common::build_hashbrown_map);
        latency_arm!("elastic", common::build_elastic_map);
        latency_arm!("funnel", common::build_funnel_map);

        group.finish();
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = bench_get_hit_latency
);
criterion_main!(benches);
