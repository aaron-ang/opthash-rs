//! Mean per-lookup latency across `LATENCY_SIZES`.
//!
//! ```sh
//! SAVE=ref BENCH=mean_latency scripts/bench.sh
//! ```
//!
//! The pinned run stores named Criterion estimates under `target/criterion/`.

mod harness;

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

fn bench_get_hit_latency(c: &mut Criterion) {
    for &size in harness::LATENCY_SIZES {
        let pairs = harness::make_pairs(size);
        let query_keys = harness::shuffled_hit_keys(&pairs, size);
        let sequential_query_keys = harness::sequential_hit_keys(&pairs, size);
        let maps = harness::MapQuad::new(&pairs);

        let label = harness::exact_size_label(size);
        let workload = format!("get_hit_latency_{label}");
        bench_latency_group(c, &workload, &maps, &query_keys);

        let sequential_workload = format!("get_hit_sequential_latency_{label}");
        bench_latency_group(c, &sequential_workload, &maps, &sequential_query_keys);
    }
}

fn bench_latency_group(
    c: &mut Criterion,
    workload: &str,
    maps: &harness::MapQuad,
    query_keys: &[u64],
) {
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
