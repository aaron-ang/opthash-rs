//! Mean per-lookup latency across `LATENCY_SIZES`. Feeds the
//! cache-hierarchy chart at `assets/benchmark-latency.svg` via
//! `scripts/generate_latency_chart.py`.
//!
//! ```sh
//! cargo bench --bench mean_latency
//! uv run --group charts scripts/generate_latency_chart.py
//! ```

mod common;

use std::hint::black_box;
use std::time::Duration;

use common::{
    LATENCY_SIZES, build_elastic_map, build_funnel_map, build_hashbrown_map, build_std_map,
    make_pairs, size_label,
};
use criterion::{Criterion, criterion_group, criterion_main};

fn bench_get_hit_latency(c: &mut Criterion) {
    for &size in LATENCY_SIZES {
        let pairs = make_pairs(size);
        let query_keys: Vec<u64> = (0..size).map(|idx| pairs[idx].0).collect();

        let label = size_label(size);
        let mut group = c.benchmark_group(format!("get_hit_latency_{label}"));

        macro_rules! latency_arm {
            ($name:literal, $build:expr) => {
                group.bench_function($name, |b| {
                    let map = $build(&pairs);
                    let mut i = 0;
                    b.iter(|| {
                        let key = &query_keys[i % size];
                        i = i.wrapping_add(1);
                        black_box(map.get(black_box(key)))
                    });
                });
            };
        }

        latency_arm!("std", build_std_map);
        latency_arm!("hashbrown", build_hashbrown_map);
        latency_arm!("elastic", build_elastic_map);
        latency_arm!("funnel", build_funnel_map);

        group.finish();
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2));
    targets = bench_get_hit_latency
);
criterion_main!(benches);
