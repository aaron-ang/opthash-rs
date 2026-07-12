#[macro_use]
mod harness;

use std::hint::black_box;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};

use harness::{MAP_SIZE, OP_COUNT, RESIZE_INSERT_COUNT, TINY_MAP_SIZE, TINY_OP_COUNT};

/// Steady-state insert into a reused map (cap = `2 * OP_COUNT`).
/// Reflects what a long-lived map pays per insert; excludes allocation cost.
fn bench_insert(c: &mut Criterion) {
    let pairs = harness::make_pairs(OP_COUNT);
    let mut group = c.benchmark_group("insert");
    group.throughput(Throughput::Elements(OP_COUNT as u64));
    bench_insert_reuse!(group, "insert", OP_COUNT * 2, &pairs);
    group.finish();
}

fn bench_lookups(c: &mut Criterion) {
    let pairs = harness::make_pairs(MAP_SIZE);
    let std_map = harness::build_std_map(&pairs);
    let hb_map = harness::build_hashbrown_map(&pairs);
    let el_map = harness::build_elastic_map(&pairs);
    let fn_map = harness::build_funnel_map(&pairs);

    let hit_keys = harness::shuffled_hit_keys(&pairs, OP_COUNT);
    let sequential_hit_keys = harness::sequential_hit_keys(&pairs, OP_COUNT);
    let miss_keys: Vec<u64> = (0..OP_COUNT)
        .map(|idx| harness::key_at(idx + MAP_SIZE + 10_000_000))
        .collect();

    harness::bench_one_lookup_group(c, "get_hit", &hit_keys, &std_map, &hb_map, &el_map, &fn_map);
    harness::bench_one_lookup_group(
        c,
        "get_hit_sequential",
        &sequential_hit_keys,
        &std_map,
        &hb_map,
        &el_map,
        &fn_map,
    );
    harness::bench_one_lookup_group(
        c, "get_miss", &miss_keys, &std_map, &hb_map, &el_map, &fn_map,
    );
}

fn bench_tiny_lookup(c: &mut Criterion) {
    let pairs = harness::make_pairs(TINY_MAP_SIZE);
    let query_keys: Vec<u64> = (0..TINY_OP_COUNT)
        .map(|idx| {
            if idx % 2 == 0 {
                pairs[idx % TINY_MAP_SIZE].0
            } else {
                harness::key_at(idx + 5_000_000)
            }
        })
        .collect();
    let std_map = harness::build_std_map(&pairs);
    let hb_map = harness::build_hashbrown_map(&pairs);
    let el_map = harness::build_elastic_map(&pairs);
    let fn_map = harness::build_funnel_map(&pairs);
    harness::bench_one_lookup_group(
        c,
        "tiny_lookup",
        &query_keys,
        &std_map,
        &hb_map,
        &el_map,
        &fn_map,
    );
}

fn bench_mixed(c: &mut Criterion) {
    let pairs = harness::make_pairs(MAP_SIZE);
    let ops: Vec<(usize, bool)> = (0..OP_COUNT)
        .map(|i| {
            let mixed = u32::try_from(i).unwrap().wrapping_mul(2_654_435_761);
            let idx = mixed as usize % MAP_SIZE;
            (idx, i & 1 == 0)
        })
        .collect();

    let mut group = c.benchmark_group("mixed");
    group.throughput(Throughput::Elements(OP_COUNT as u64));

    bench_populated!(group, "mixed", BatchSize::LargeInput, &pairs, |map| {
        for &(idx, is_read) in &ops {
            let key = pairs[idx].0;
            if is_read {
                black_box(map.get(black_box(&key)));
            } else {
                black_box(map.insert(black_box(key), black_box(idx as u64)));
            }
        }
    },);

    group.finish();
}

fn bench_delete_heavy(c: &mut Criterion) {
    let initial_pairs = harness::make_pairs(MAP_SIZE);
    let churn_keys: Vec<u64> = (0..OP_COUNT + MAP_SIZE).map(harness::key_at).collect();

    let mut group = c.benchmark_group("delete_heavy");
    group.throughput(Throughput::Elements((OP_COUNT * 2) as u64));

    bench_populated!(
        group,
        "delete_heavy",
        BatchSize::PerIteration,
        &initial_pairs,
        |map| {
            for idx in 0..OP_COUNT {
                black_box(map.remove(black_box(&churn_keys[idx])));
                let key = churn_keys[idx + MAP_SIZE];
                black_box(map.insert(black_box(key), black_box(key ^ harness::VALUE_XOR_MIX_ALT)));
            }
        },
    );

    group.finish();
}

fn bench_resize_heavy(c: &mut Criterion) {
    let pairs = harness::make_pairs(RESIZE_INSERT_COUNT);
    let mut group = c.benchmark_group("resize_heavy");
    group.throughput(Throughput::Elements(RESIZE_INSERT_COUNT as u64));

    bench_empty!(group, "resize_heavy", BatchSize::PerIteration, |map| {
        for &(key, value) in &pairs {
            black_box(map.insert(black_box(key), black_box(value)));
        }
        black_box(map.len())
    },);

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets =
        bench_insert,
        bench_lookups,
        bench_tiny_lookup,
        bench_mixed,
        bench_delete_heavy,
        bench_resize_heavy
);
criterion_main!(benches);
