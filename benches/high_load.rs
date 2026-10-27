//! Elastic and Funnel from 7/8 to 1023/1024 load against `group_probe`, a
//! `SwissTable`-layout table that accepts the same loads.
//!
//! ```sh
//! BENCH=high_load SAVE=<name> scripts/bench.sh
//! ```

use std::hint::black_box;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use harness::{HIGH_LOAD_EXPONENTS, HIGH_LOAD_SLOTS, LoadPoint, OP_COUNT};

/// Invokes `$arm!(impl_name, empty_map)` once per arm at `$point`; hashbrown
/// joins only the points its load cap admits. Each arm builds and drops its map
/// inside its own `$arm!` block, so no arm's map stays resident while another
/// arm is timed.
macro_rules! for_each_arm {
    ($point:expr, $arm:ident) => {
        $arm!("elastic", $point.elastic());
        $arm!("funnel", $point.funnel());
        $arm!("group_probe", $point.group_probe());
        if let Some(map) = $point.hashbrown() {
            $arm!("hashbrown", map);
        }
    };
}

/// Inserts `$pairs` into `$map`, then asserts it holds `$len` pairs at its
/// starting capacity: a map that grew would run below the point's load.
macro_rules! fill {
    ($impl:literal, $map:ident, $pairs:expr, $len:expr) => {{
        let capacity = $map.capacity();
        for &(key, value) in $pairs {
            $map.insert(key, value);
        }
        assert_eq!(
            ($map.len(), $map.capacity()),
            ($len, capacity),
            "{} left its point while filling",
            $impl
        );
    }};
}

fn bench_high_load(c: &mut Criterion) {
    let miss_keys = harness::miss_keys(OP_COUNT);
    for slots in HIGH_LOAD_SLOTS {
        for exponent in HIGH_LOAD_EXPONENTS {
            let point = LoadPoint::new(slots, exponent);
            let pairs = harness::make_pairs(point.entries());
            bench_tail_insert(c, point, &pairs);
            let hit_keys = harness::shuffled_hit_keys(&pairs, OP_COUNT);
            bench_lookup(c, &point.group("get_hit"), point, &pairs, &hit_keys);
            bench_lookup(c, &point.group("get_miss"), point, &pairs, &miss_keys);
        }
    }
}

/// Times the last `point.tail()` inserts into a clone of a template holding
/// every earlier pair, so each sample starts at the same load. One untimed
/// preflight clone checks the tail ends at the point. Per-iteration batches
/// keep at most one clone alive and drop it outside the timing.
fn bench_tail_insert(c: &mut Criterion, point: LoadPoint, pairs: &[(u64, u64)]) {
    let (prefix, tail) = pairs.split_at(point.entries() - point.tail());
    let group_name = point.group("tail_insert");
    let mut group = c.benchmark_group(&group_name);
    group.throughput(Throughput::Elements(tail.len() as u64));

    macro_rules! arm {
        ($impl:literal, $empty:expr) => {{
            let mut template = $empty;
            fill!($impl, template, prefix, prefix.len());
            let mut full = template.clone();
            fill!($impl, full, tail, point.entries());
            drop(full);
            group.bench_function(format!("{group_name}_{}", $impl), |b| {
                b.iter_batched_ref(
                    || template.clone(),
                    |map| {
                        for &(key, value) in tail {
                            black_box(map.insert(black_box(key), black_box(value)));
                        }
                    },
                    BatchSize::PerIteration,
                );
            });
        }};
    }
    for_each_arm!(point, arm);

    group.finish();
}

fn bench_lookup(
    c: &mut Criterion,
    group_name: &str,
    point: LoadPoint,
    pairs: &[(u64, u64)],
    keys: &[u64],
) {
    let mut group = c.benchmark_group(group_name);
    group.throughput(Throughput::Elements(keys.len() as u64));

    macro_rules! arm {
        ($impl:literal, $empty:expr) => {{
            let mut map = $empty;
            fill!($impl, map, pairs, point.entries());
            group.bench_function(format!("{group_name}_{}", $impl), |b| {
                b.iter(|| {
                    for key in keys {
                        black_box(map.get(black_box(key)));
                    }
                });
            });
        }};
    }
    for_each_arm!(point, arm);

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = bench_high_load
);
criterion_main!(benches);
