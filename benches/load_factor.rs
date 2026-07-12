mod harness;

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

/// `with_capacity` request shared by every arm; sized to the 100K cache regime
/// where elastic's high-load spike first appears.
const CAP_HINT: usize = 100_000;

/// Fill targets as a fraction of each map's resize threshold (`capacity()`).
const LOAD_FRACTIONS: &[f64] = &[0.45, 0.55, 0.65, 0.75, 0.85];

#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn bench_load_factor(c: &mut Criterion) {
    use hashbrown::HashMap as HashbrownMap;
    use opthash::{ElasticHashMap, FunnelHashMap};

    // Generous pool: the largest fill is the top fraction of the largest
    // `capacity()`, which stays well under this even at high reserve fractions.
    let pairs = harness::make_pairs(CAP_HINT * 2);

    for &frac in LOAD_FRACTIONS {
        let pct = (frac * 100.0).round() as u32;
        let workload = format!("load_factor_{pct}");
        let mut group = c.benchmark_group(&workload);

        // Bench id `<workload>_<impl>`, matching speedup.rs / mean_latency.rs.
        macro_rules! arm {
            ($impl:literal, $Map:ty) => {
                group.bench_function(format!("{workload}_{}", $impl), |b| {
                    let mut map = <$Map>::with_capacity(CAP_HINT);
                    // Fill to `frac` of this map's resize threshold so the load
                    // axis is stable across reserve-policy changes.
                    // `frac < 1`, so no arm rehashes mid-fill.
                    let fill = ((map.capacity() as f64 * frac) as usize).min(pairs.len());
                    for &(key, value) in &pairs[..fill] {
                        map.insert(key, value);
                    }
                    let query_keys: Vec<u64> = pairs[..fill].iter().map(|&(k, _)| k).collect();
                    let mut keys = query_keys.iter().cycle();
                    b.iter(|| black_box(map.get(black_box(keys.next().unwrap()))));
                });
            };
        }

        arm!("hashbrown", HashbrownMap<u64, u64>);
        arm!("elastic", ElasticHashMap<u64, u64>);
        arm!("funnel", FunnelHashMap<u64, u64>);

        group.finish();
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = bench_load_factor
);
criterion_main!(benches);
