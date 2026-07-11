//! Mean per-lookup latency across `LATENCY_SIZES`. Feeds the
//! cache-hierarchy chart at `assets/benchmark-latency.svg` via
//! `scripts/generate_latency_chart.py`.
//!
//! ```sh
//! SAVE=ref BENCH=mean_latency scripts/bench.sh
//! uv run scripts/generate_latency_chart.py --baseline ref
//! ```

#[path = "support/common.rs"]
mod common;
#[path = "support/fixtures.rs"]
mod fixtures;

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

struct LatencyMaps {
    std: common::StdHashMap<u64, u64>,
    hashbrown: common::HashbrownMap<u64, u64>,
    elastic: common::ElasticHashMap<u64, u64>,
    funnel: common::FunnelHashMap<u64, u64>,
}

impl LatencyMaps {
    fn new(pairs: &[(u64, u64)]) -> Self {
        Self {
            std: common::build_std_map(pairs),
            hashbrown: common::build_hashbrown_map(pairs),
            elastic: common::build_elastic_map(pairs),
            funnel: common::build_funnel_map(pairs),
        }
    }
}

fn bench_get_hit_latency(c: &mut Criterion) {
    for &size in common::LATENCY_SIZES {
        let pairs = common::make_pairs(size);
        let query_keys = fixtures::shuffled_hit_keys(&pairs, size);
        let sequential_query_keys = fixtures::sequential_hit_keys(&pairs, size);
        let maps = LatencyMaps::new(&pairs);

        let label = common::size_label(size);
        let workload = format!("get_hit_latency_{label}");
        bench_latency_group(c, &workload, &maps, &query_keys);

        let sequential_workload = format!("get_hit_sequential_latency_{label}");
        bench_latency_group(c, &sequential_workload, &maps, &sequential_query_keys);
    }
}

fn bench_latency_group(c: &mut Criterion, workload: &str, maps: &LatencyMaps, query_keys: &[u64]) {
    let mut group = c.benchmark_group(workload);

    // Bench id `<workload>_<impl>`, matching speedup.rs (see benches/README.md).
    macro_rules! latency_arm {
        ($impl:literal, $map:expr) => {
            group.bench_function(format!("{workload}_{}", $impl), |b| {
                let mut keys = query_keys.iter().cycle();
                b.iter(|| black_box($map.get(black_box(keys.next().unwrap()))));
            });
        };
    }

    latency_arm!("std", maps.std);
    latency_arm!("hashbrown", maps.hashbrown);
    latency_arm!("elastic", maps.elastic);
    latency_arm!("funnel", maps.funnel);

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = bench_get_hit_latency
);
criterion_main!(benches);
