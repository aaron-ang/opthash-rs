//! Speedup bench suite. Each group runs std / hashbrown / elastic / funnel
//! over the same workload so CodSpeed can chart deltas per-PR.
//!
//! ## LLVM elision pitfalls
//!
//! - `.count()` over `Copy`+no-op-`Drop` iterators is hoisted out. Fold
//!   xor over `(k, v)` instead.
//! - Bulk drops over `(u64, u64)` payload look side-effect-free to LLVM;
//!   use `DropU64` for clear/drain (`drop_throughput` groups).
//! - Wrap `.get(k)` results in `black_box` to keep loop-invariant lookups
//!   from being hoisted.
//!
//! ## BatchSize
//!
//! `LargeInput` for non-destructive ops (`iter`, `iter_mut`, lookups).
//! `PerIteration` for destructive ops (`drain`, `extract_if`, `clear`,
//! `grow_insert`, `entry_or_insert`).

mod common;

use std::collections::HashMap as StdHashMap;
use std::hint::black_box;
use std::path::Path;
use std::time::Duration;

use common::{
    BigVal, LATENCY_SIZES, VALUE_XOR_MIX_ALT, build_elastic_big_map, build_elastic_drop_map,
    build_elastic_map, build_funnel_big_map, build_funnel_drop_map, build_funnel_map,
    build_hashbrown_big_map, build_hashbrown_drop_map, build_hashbrown_map, build_std_big_map,
    build_std_drop_map, build_std_map, drop_sink_value, key_at, make_big_pairs, make_pairs,
    size_label,
};
use criterion::{
    BatchSize, Criterion, Throughput, criterion_group, criterion_main, profiler::Profiler,
};
use hashbrown::HashMap as HashbrownMap;
use opthash::{ElasticHashMap, FunnelHashMap};
use pprof::{ProfilerGuard, flamegraph::Options as FlamegraphOptions};

struct FlamegraphProfiler {
    frequency: i32,
    active: Option<ProfilerGuard<'static>>,
}

impl FlamegraphProfiler {
    fn new() -> Self {
        Self {
            frequency: 997,
            active: None,
        }
    }
}

impl Profiler for FlamegraphProfiler {
    fn start_profiling(&mut self, _benchmark_id: &str, _benchmark_dir: &Path) {
        self.active = Some(ProfilerGuard::new(self.frequency).unwrap());
    }

    fn stop_profiling(&mut self, _benchmark_id: &str, benchmark_dir: &Path) {
        if let Some(guard) = self.active.take() {
            let report = guard.report().build().unwrap();
            let mut opts = FlamegraphOptions::default();
            opts.deterministic = true;
            std::fs::create_dir_all(benchmark_dir).unwrap();
            let path = benchmark_dir.join("flamegraph.svg");
            let file = std::fs::File::create(&path).unwrap();
            report.flamegraph_with_options(file, &mut opts).unwrap();
        }
    }
}

/// Pre-populated map size for the throughput benches.
const MAP_SIZE: usize = 20_000;
/// Ops per iteration for throughput benches.
const OP_COUNT: usize = 100_000;
/// Tiny map size — fits comfortably in L1.
const TINY_MAP_SIZE: usize = 32;
///  Tiny map bench lookups per iteration.
const TINY_OP_COUNT: usize = 500_000;
/// Inserts per iteration of `resize_heavy_throughput`; triggers multiple resizes.
const RESIZE_INSERT_COUNT: usize = 8_000;

/// Emits per-impl `bench_function` blocks for a given op.
macro_rules! bench_all_impls {
    ($group:expr, $op:literal, $batch:expr, $std_setup:expr, $hb_setup:expr, $el_setup:expr, $fn_setup:expr, $body:expr $(,)?) => {{
        let group = &mut $group;
        group.bench_function(concat!($op, "_std"), |b| {
            b.iter_batched_ref($std_setup, $body, $batch)
        });
        group.bench_function(concat!($op, "_hashbrown"), |b| {
            b.iter_batched_ref($hb_setup, $body, $batch)
        });
        group.bench_function(concat!($op, "_elastic"), |b| {
            b.iter_batched_ref($el_setup, $body, $batch)
        });
        group.bench_function(concat!($op, "_funnel"), |b| {
            b.iter_batched_ref($fn_setup, $body, $batch)
        });
    }};
}

fn bench_insert_throughput(c: &mut Criterion) {
    let pairs = make_pairs(OP_COUNT);
    let mut group = c.benchmark_group("insert_throughput");
    group.throughput(Throughput::Elements(OP_COUNT as u64));

    bench_all_impls!(
        group,
        "insert",
        BatchSize::PerIteration,
        || StdHashMap::with_capacity(OP_COUNT * 2),
        || HashbrownMap::with_capacity(OP_COUNT * 2),
        || ElasticHashMap::with_capacity(OP_COUNT * 2),
        || FunnelHashMap::with_capacity(OP_COUNT * 2),
        |map| {
            for &(key, value) in &pairs {
                map.insert(black_box(key), black_box(value));
            }
            black_box(map.len())
        },
    );

    group.finish();
}

fn bench_one_lookup_group(
    c: &mut Criterion,
    group_name: &str,
    op_tag: &str,
    query_keys: &[u64],
    std_map: &StdHashMap<u64, u64>,
    hb_map: &HashbrownMap<u64, u64>,
    el_map: &ElasticHashMap<u64, u64>,
    fn_map: &FunnelHashMap<u64, u64>,
) {
    let mut group = c.benchmark_group(group_name);
    group.throughput(Throughput::Elements(query_keys.len() as u64));
    group.bench_function(format!("{op_tag}_std"), |b| {
        b.iter(|| {
            for key in query_keys {
                black_box(std_map.get(black_box(key)));
            }
        });
    });
    group.bench_function(format!("{op_tag}_hashbrown"), |b| {
        b.iter(|| {
            for key in query_keys {
                black_box(hb_map.get(black_box(key)));
            }
        });
    });
    group.bench_function(format!("{op_tag}_elastic"), |b| {
        b.iter(|| {
            for key in query_keys {
                black_box(el_map.get(black_box(key)));
            }
        });
    });
    group.bench_function(format!("{op_tag}_funnel"), |b| {
        b.iter(|| {
            for key in query_keys {
                black_box(fn_map.get(black_box(key)));
            }
        });
    });
    group.finish();
}

fn bench_lookups(c: &mut Criterion) {
    let pairs = make_pairs(MAP_SIZE);
    let std_map = build_std_map(&pairs);
    let hb_map = build_hashbrown_map(&pairs);
    let el_map = build_elastic_map(&pairs);
    let fn_map = build_funnel_map(&pairs);

    let hit_keys: Vec<u64> = (0..OP_COUNT).map(|idx| pairs[idx % MAP_SIZE].0).collect();
    let miss_keys: Vec<u64> = (0..OP_COUNT)
        .map(|idx| key_at(idx + MAP_SIZE + 10_000_000))
        .collect();

    bench_one_lookup_group(
        c,
        "get_hit_throughput",
        "get_hit",
        &hit_keys,
        &std_map,
        &hb_map,
        &el_map,
        &fn_map,
    );
    bench_one_lookup_group(
        c,
        "get_miss_throughput",
        "get_miss",
        &miss_keys,
        &std_map,
        &hb_map,
        &el_map,
        &fn_map,
    );
}

fn bench_tiny_lookup_throughput(c: &mut Criterion) {
    let pairs = make_pairs(TINY_MAP_SIZE);
    let query_keys: Vec<u64> = (0..TINY_OP_COUNT)
        .map(|idx| {
            if idx % 2 == 0 {
                pairs[idx % TINY_MAP_SIZE].0
            } else {
                key_at(idx + 5_000_000)
            }
        })
        .collect();
    let std_map = build_std_map(&pairs);
    let hb_map = build_hashbrown_map(&pairs);
    let el_map = build_elastic_map(&pairs);
    let fn_map = build_funnel_map(&pairs);
    bench_one_lookup_group(
        c,
        "tiny_lookup_throughput",
        "tiny_lookup",
        &query_keys,
        &std_map,
        &hb_map,
        &el_map,
        &fn_map,
    );
}

fn bench_delete_heavy_throughput(c: &mut Criterion) {
    let initial_pairs = make_pairs(MAP_SIZE);
    let replacement_pairs: Vec<(u64, u64)> = (0..OP_COUNT)
        .map(|idx| {
            let key = key_at(idx + 20_000_000);
            (key, key ^ VALUE_XOR_MIX_ALT)
        })
        .collect();

    let mut group = c.benchmark_group("delete_heavy_throughput");
    group.throughput(Throughput::Elements((OP_COUNT * 2) as u64));

    bench_all_impls!(
        group,
        "delete",
        BatchSize::PerIteration,
        || build_std_map(&initial_pairs),
        || build_hashbrown_map(&initial_pairs),
        || build_elastic_map(&initial_pairs),
        || build_funnel_map(&initial_pairs),
        |map| {
            for idx in 0..OP_COUNT {
                black_box(map.remove(black_box(&initial_pairs[idx % MAP_SIZE].0)));
                let (key, value) = replacement_pairs[idx];
                black_box(map.insert(black_box(key), black_box(value)));
            }
        },
    );

    group.finish();
}

fn bench_mixed_throughput(c: &mut Criterion) {
    let pairs = make_pairs(MAP_SIZE);
    let ops: Vec<(usize, bool)> = (0..OP_COUNT)
        .map(|i| {
            let idx = ((i as u32).wrapping_mul(2_654_435_761) as usize) % MAP_SIZE;
            (idx, i & 1 == 0)
        })
        .collect();

    let mut group = c.benchmark_group("mixed_throughput");
    group.throughput(Throughput::Elements(OP_COUNT as u64));

    bench_all_impls!(
        group,
        "mixed",
        BatchSize::LargeInput,
        || build_std_map(&pairs),
        || build_hashbrown_map(&pairs),
        || build_elastic_map(&pairs),
        || build_funnel_map(&pairs),
        |map| {
            for &(idx, is_read) in &ops {
                let key = pairs[idx].0;
                if is_read {
                    black_box(map.get(black_box(&key)));
                } else {
                    black_box(map.insert(black_box(key), black_box(idx as u64)));
                }
            }
        },
    );

    group.finish();
}

fn bench_resize_heavy_throughput(c: &mut Criterion) {
    let pairs = make_pairs(RESIZE_INSERT_COUNT);
    let mut group = c.benchmark_group("resize_heavy_throughput");
    group.throughput(Throughput::Elements(RESIZE_INSERT_COUNT as u64));

    bench_all_impls!(
        group,
        "resize",
        BatchSize::PerIteration,
        StdHashMap::new,
        HashbrownMap::new,
        ElasticHashMap::new,
        FunnelHashMap::new,
        |map| {
            for &(key, value) in &pairs {
                black_box(map.insert(black_box(key), black_box(value)));
            }
            black_box(map.len())
        },
    );

    group.finish();
}

fn bench_iter_throughput(c: &mut Criterion) {
    let pairs = make_pairs(MAP_SIZE);
    let mut group = c.benchmark_group("iter_throughput");
    group.throughput(Throughput::Elements(MAP_SIZE as u64));

    // xor-fold the yielded pairs so LLVM can't elide the walk; `.count()`
    // alone is hoisted out when the map is loop-invariant.
    bench_all_impls!(
        group,
        "iter",
        BatchSize::LargeInput,
        || build_std_map(&pairs),
        || build_hashbrown_map(&pairs),
        || build_elastic_map(&pairs),
        || build_funnel_map(&pairs),
        |map| black_box(map.iter().fold(0u64, |a, (k, v)| a ^ k ^ v)),
    );

    group.finish();
}

fn bench_iter_mut_throughput(c: &mut Criterion) {
    let pairs = make_pairs(MAP_SIZE);
    let mut group = c.benchmark_group("iter_mut_throughput");
    group.throughput(Throughput::Elements(MAP_SIZE as u64));

    bench_all_impls!(
        group,
        "iter_mut",
        BatchSize::LargeInput,
        || build_std_map(&pairs),
        || build_hashbrown_map(&pairs),
        || build_elastic_map(&pairs),
        || build_funnel_map(&pairs),
        |map| {
            for (_, v) in map.iter_mut() {
                *v = black_box(*v).wrapping_add(1);
            }
        },
    );

    group.finish();
}

fn bench_drain_throughput(c: &mut Criterion) {
    let pairs = make_pairs(MAP_SIZE);
    let mut group = c.benchmark_group("drain_throughput");
    group.throughput(Throughput::Elements(MAP_SIZE as u64));

    // xor-fold pulls every yielded `(K, V)` out — defeats `.count()` elision
    // when both `K` and `V` are `Copy` with no-op `Drop`.
    bench_all_impls!(
        group,
        "drain",
        BatchSize::PerIteration,
        || build_std_map(&pairs),
        || build_hashbrown_map(&pairs),
        || build_elastic_map(&pairs),
        || build_funnel_map(&pairs),
        |map| black_box(map.drain().fold(0u64, |a, (k, v)| a ^ k ^ v)),
    );

    group.finish();
}

fn bench_extract_if_throughput(c: &mut Criterion) {
    let pairs = make_pairs(MAP_SIZE);
    let mut group = c.benchmark_group("extract_if_throughput");
    group.throughput(Throughput::Elements(MAP_SIZE as u64));

    bench_all_impls!(
        group,
        "extract_if",
        BatchSize::PerIteration,
        || build_std_map(&pairs),
        || build_hashbrown_map(&pairs),
        || build_elastic_map(&pairs),
        || build_funnel_map(&pairs),
        |map| {
            black_box(
                map.extract_if(|k, _v| *k % 2 == 0)
                    .fold(0u64, |a, (k, v)| a ^ k ^ v),
            )
        },
    );

    group.finish();
}

fn bench_clear_drop_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("clear_drop_throughput");
    group.throughput(Throughput::Elements(MAP_SIZE as u64));

    bench_all_impls!(
        group,
        "clear",
        BatchSize::PerIteration,
        || build_std_drop_map(MAP_SIZE),
        || build_hashbrown_drop_map(MAP_SIZE),
        || build_elastic_drop_map(MAP_SIZE),
        || build_funnel_drop_map(MAP_SIZE),
        |map| map.clear(),
    );
    // Touch the sink so the drop side-effects can't be optimized out at
    // module scope.
    black_box(drop_sink_value());

    group.finish();
}

fn bench_entry_or_insert_throughput(c: &mut Criterion) {
    let pairs = make_pairs(MAP_SIZE);
    let mut group = c.benchmark_group("entry_or_insert_throughput");
    group.throughput(Throughput::Elements(MAP_SIZE as u64));

    bench_all_impls!(
        group,
        "entry",
        BatchSize::PerIteration,
        || StdHashMap::with_capacity(MAP_SIZE),
        || HashbrownMap::with_capacity(MAP_SIZE),
        || ElasticHashMap::with_capacity(MAP_SIZE),
        || FunnelHashMap::with_capacity(MAP_SIZE),
        |map| {
            for &(key, value) in &pairs {
                *map.entry(black_box(key)).or_insert(black_box(value)) ^= 1;
            }
            black_box(map.len())
        },
    );

    group.finish();
}

fn bench_grow_insert_throughput(c: &mut Criterion) {
    let pairs = make_pairs(MAP_SIZE);
    let mut group = c.benchmark_group("grow_insert_throughput");
    group.throughput(Throughput::Elements(MAP_SIZE as u64));

    // Same op as `insert_throughput` but constructed via `Default::default()`
    // — no capacity hint, so each impl pays its growth-through-rehash cost.
    bench_all_impls!(
        group,
        "grow_insert",
        BatchSize::PerIteration,
        StdHashMap::new,
        HashbrownMap::new,
        ElasticHashMap::new,
        FunnelHashMap::new,
        |map| {
            for &(key, value) in &pairs {
                map.insert(black_box(key), black_box(value));
            }
            black_box(map.len())
        },
    );

    group.finish();
}

/// Sweep `get_hit_throughput` across load factors. Elastic's pitch is
/// graceful behavior near capacity; this measures it directly against the
/// other impls at the same operating points.
fn bench_get_hit_load_factor(c: &mut Criterion) {
    const LOAD_PCTS: &[u32] = &[50, 75, 90];
    let pairs = make_pairs(MAP_SIZE);
    let hit_keys: Vec<u64> = (0..OP_COUNT).map(|idx| pairs[idx % MAP_SIZE].0).collect();

    for &load_pct in LOAD_PCTS {
        let cap = MAP_SIZE * 100 / load_pct as usize;
        let mut std_map = StdHashMap::with_capacity(cap);
        let mut hb_map = HashbrownMap::with_capacity(cap);
        let mut el_map = ElasticHashMap::with_capacity(cap);
        let mut fn_map = FunnelHashMap::with_capacity(cap);
        for &(key, value) in &pairs {
            std_map.insert(key, value);
            hb_map.insert(key, value);
            el_map.insert(key, value);
            fn_map.insert(key, value);
        }
        bench_one_lookup_group(
            c,
            &format!("get_hit_load_{load_pct}"),
            "get_hit",
            &hit_keys,
            &std_map,
            &hb_map,
            &el_map,
            &fn_map,
        );
    }
}

// ---------------------------------------------------------------------------
// Large-value (memcpy axis) variants. 32-byte `BigVal` payload exercises
// memcpy on insert-rehash, move-out on drain, and cache-line footprint
// on get. Pair with the equivalent `(u64, u64)` group to attribute deltas.
// ---------------------------------------------------------------------------

fn bench_insert_big_throughput(c: &mut Criterion) {
    let pairs = make_big_pairs(OP_COUNT);
    let mut group = c.benchmark_group("insert_big_throughput");
    group.throughput(Throughput::Elements(OP_COUNT as u64));

    bench_all_impls!(
        group,
        "insert_big",
        BatchSize::PerIteration,
        || StdHashMap::<u64, BigVal>::with_capacity(OP_COUNT),
        || HashbrownMap::<u64, BigVal>::with_capacity(OP_COUNT),
        || ElasticHashMap::<u64, BigVal>::with_capacity(OP_COUNT),
        || FunnelHashMap::<u64, BigVal>::with_capacity(OP_COUNT),
        |map| {
            for &(key, value) in &pairs {
                map.insert(black_box(key), black_box(value));
            }
            black_box(map.len())
        },
    );

    group.finish();
}

fn bench_get_hit_big_throughput(c: &mut Criterion) {
    let pairs = make_big_pairs(MAP_SIZE);
    let hit_keys: Vec<u64> = (0..OP_COUNT).map(|idx| pairs[idx % MAP_SIZE].0).collect();

    let mut group = c.benchmark_group("get_hit_big_throughput");
    group.throughput(Throughput::Elements(hit_keys.len() as u64));

    bench_all_impls!(
        group,
        "get_hit_big",
        BatchSize::LargeInput,
        || build_std_big_map(&pairs),
        || build_hashbrown_big_map(&pairs),
        || build_elastic_big_map(&pairs),
        || build_funnel_big_map(&pairs),
        |map| {
            for key in &hit_keys {
                black_box(map.get(black_box(key)));
            }
        },
    );

    group.finish();
}

fn bench_drain_big_throughput(c: &mut Criterion) {
    let pairs = make_big_pairs(MAP_SIZE);
    let mut group = c.benchmark_group("drain_big_throughput");
    group.throughput(Throughput::Elements(MAP_SIZE as u64));

    bench_all_impls!(
        group,
        "drain_big",
        BatchSize::PerIteration,
        || build_std_big_map(&pairs),
        || build_hashbrown_big_map(&pairs),
        || build_elastic_big_map(&pairs),
        || build_funnel_big_map(&pairs),
        |map| { black_box(map.drain().fold(0u64, |a, (k, v)| a ^ k ^ v[0] ^ v[3])) },
    );

    group.finish();
}

// ---------------------------------------------------------------------------
// Follow-ups to the iter / drop / memcpy axis: shrink_to_fit (capacity
// reduction after removals), replace (insert with existing keys —
// update-path codegen, distinct from vacant-slot insert), and extend
// (bulk reserve+insert via `Iterator`).
// ---------------------------------------------------------------------------

fn bench_shrink_to_fit_throughput(c: &mut Criterion) {
    let pairs = make_pairs(MAP_SIZE);
    let keep: usize = MAP_SIZE / 10; // keep 10% — large gap to reclaim
    let mut group = c.benchmark_group("shrink_to_fit_throughput");
    group.throughput(Throughput::Elements((MAP_SIZE - keep) as u64));

    bench_all_impls!(
        group,
        "shrink_to_fit",
        BatchSize::PerIteration,
        || {
            let mut m = build_std_map(&pairs);
            for (k, _) in pairs.iter().skip(keep) {
                m.remove(k);
            }
            m
        },
        || {
            let mut m = build_hashbrown_map(&pairs);
            for (k, _) in pairs.iter().skip(keep) {
                m.remove(k);
            }
            m
        },
        || {
            let mut m = build_elastic_map(&pairs);
            for (k, _) in pairs.iter().skip(keep) {
                m.remove(k);
            }
            m
        },
        || {
            let mut m = build_funnel_map(&pairs);
            for (k, _) in pairs.iter().skip(keep) {
                m.remove(k);
            }
            m
        },
        |map| {
            map.shrink_to_fit();
            black_box(map.capacity())
        },
    );

    group.finish();
}

fn bench_replace_throughput(c: &mut Criterion) {
    let pairs = make_pairs(MAP_SIZE);
    let mut group = c.benchmark_group("replace_throughput");
    group.throughput(Throughput::Elements(MAP_SIZE as u64));

    // Re-insert all keys with new values. Hits the update-existing-value
    // branch in `insert` codegen — distinct from `insert_throughput` which
    // only exercises vacant-slot inserts.
    bench_all_impls!(
        group,
        "replace",
        BatchSize::LargeInput,
        || build_std_map(&pairs),
        || build_hashbrown_map(&pairs),
        || build_elastic_map(&pairs),
        || build_funnel_map(&pairs),
        |map| {
            for &(key, value) in &pairs {
                black_box(map.insert(black_box(key), black_box(value.wrapping_add(1))));
            }
            black_box(map.len())
        },
    );

    group.finish();
}

fn bench_extend_throughput(c: &mut Criterion) {
    let pairs = make_pairs(MAP_SIZE);
    let mut group = c.benchmark_group("extend_throughput");
    group.throughput(Throughput::Elements(MAP_SIZE as u64));

    bench_all_impls!(
        group,
        "extend",
        BatchSize::PerIteration,
        StdHashMap::new,
        HashbrownMap::new,
        ElasticHashMap::new,
        FunnelHashMap::new,
        |map| {
            map.extend(pairs.iter().copied());
            black_box(map.len())
        },
    );

    group.finish();
}

fn bench_get_hit_latency(c: &mut Criterion) {
    for &size in LATENCY_SIZES {
        let pairs = make_pairs(size);
        let query_keys: Vec<u64> = (0..size).map(|idx| pairs[idx].0).collect();

        let label = size_label(size);
        let mut group = c.benchmark_group(format!("get_hit_latency_{label}"));

        macro_rules! latency_arm {
            ($name:literal, $build:expr) => {
                group.bench_function(concat!("get_hit_", $name), |b| {
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
        .with_profiler(FlamegraphProfiler::new())
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2));
    targets =
        bench_insert_throughput,
        bench_grow_insert_throughput,
        bench_lookups,
        bench_get_hit_load_factor,
        bench_tiny_lookup_throughput,
        bench_mixed_throughput,
        bench_delete_heavy_throughput,
        bench_resize_heavy_throughput,
        bench_iter_throughput,
        bench_iter_mut_throughput,
        bench_drain_throughput,
        bench_extract_if_throughput,
        bench_clear_drop_throughput,
        bench_entry_or_insert_throughput,
        bench_replace_throughput,
        bench_extend_throughput,
        bench_shrink_to_fit_throughput,
        bench_insert_big_throughput,
        bench_get_hit_big_throughput,
        bench_drain_big_throughput,
        bench_get_hit_latency
);
criterion_main!(benches);
