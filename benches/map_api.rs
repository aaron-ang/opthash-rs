#[path = "support/common.rs"]
mod common;
#[macro_use]
#[path = "support/throughput.rs"]
mod throughput;

use std::hint::black_box;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use throughput::MAP_SIZE;

fn bench_iter(c: &mut Criterion) {
    let pairs = common::make_pairs(MAP_SIZE);
    let mut group = c.benchmark_group("iter");
    group.throughput(Throughput::Elements(MAP_SIZE as u64));

    // xor-fold the yielded pairs so LLVM can't elide the walk; `.count()`
    // alone is hoisted out when the map is loop-invariant.
    bench_populated!(group, "iter", BatchSize::LargeInput, &pairs, |map| {
        black_box(map.iter().fold(0u64, |a, (k, v)| a ^ k ^ v))
    },);

    group.finish();
}

fn bench_iter_mut(c: &mut Criterion) {
    let pairs = common::make_pairs(MAP_SIZE);
    let mut group = c.benchmark_group("iter_mut");
    group.throughput(Throughput::Elements(MAP_SIZE as u64));

    bench_populated!(group, "iter_mut", BatchSize::LargeInput, &pairs, |map| {
        for (_, v) in map.iter_mut() {
            *v = black_box(*v).wrapping_add(1);
        }
    },);

    group.finish();
}

fn bench_drain(c: &mut Criterion) {
    let pairs = common::make_pairs(MAP_SIZE);
    let mut group = c.benchmark_group("drain");
    group.throughput(Throughput::Elements(MAP_SIZE as u64));

    // xor-fold pulls every yielded `(K, V)` out - defeats `.count()` elision
    // when both `K` and `V` are `Copy` with no-op `Drop`.
    bench_populated!(group, "drain", BatchSize::PerIteration, &pairs, |map| {
        black_box(map.drain().fold(0u64, |a, (k, v)| a ^ k ^ v))
    },);

    group.finish();
}

fn bench_extract_if(c: &mut Criterion) {
    let pairs = common::make_pairs(MAP_SIZE);
    let mut group = c.benchmark_group("extract_if");
    group.throughput(Throughput::Elements(MAP_SIZE as u64));

    bench_populated!(
        group,
        "extract_if",
        BatchSize::PerIteration,
        &pairs,
        |map| {
            black_box(
                map.extract_if(|k, _v| *k % 2 == 0)
                    .fold(0u64, |a, (k, v)| a ^ k ^ v),
            )
        },
    );

    group.finish();
}

#[allow(clippy::redundant_closure_for_method_calls)]
fn bench_clear_drop(c: &mut Criterion) {
    let mut group = c.benchmark_group("clear_drop");
    group.throughput(Throughput::Elements(MAP_SIZE as u64));

    bench_all_impls!(
        group,
        "clear",
        BatchSize::PerIteration,
        || common::build_std_drop_map(MAP_SIZE),
        || common::build_hashbrown_drop_map(MAP_SIZE),
        || common::build_elastic_drop_map(MAP_SIZE),
        || common::build_funnel_drop_map(MAP_SIZE),
        |map| map.clear(),
    );
    // Touch the sink so the drop side-effects can't be optimized out at
    // module scope.
    black_box(common::drop_sink_value());

    group.finish();
}

fn bench_entry_or_insert(c: &mut Criterion) {
    let pairs = common::make_pairs(MAP_SIZE);
    let mut group = c.benchmark_group("entry_or_insert");
    group.throughput(Throughput::Elements(MAP_SIZE as u64));

    bench_with_cap!(group, "entry", BatchSize::PerIteration, MAP_SIZE, |map| {
        for &(key, value) in &pairs {
            *map.entry(black_box(key)).or_insert(black_box(value)) ^= 1;
        }
        black_box(map.len())
    },);

    group.finish();
}

/// Build a populated map then remove all but the first `keep` entries -
/// the realistic precondition for `shrink_to_fit` (post-bulk-delete state).
macro_rules! sparse_setup {
    ($builder:expr, $pairs:expr, $keep:expr) => {
        || {
            let mut m = $builder($pairs);
            for (k, _) in $pairs.iter().skip($keep) {
                m.remove(k);
            }
            m
        }
    };
}

fn bench_shrink_to_fit(c: &mut Criterion) {
    let pairs = common::make_pairs(MAP_SIZE);
    let keep: usize = MAP_SIZE / 10;
    let mut group = c.benchmark_group("shrink_to_fit");
    group.throughput(Throughput::Elements(keep as u64));

    bench_all_impls!(
        group,
        "shrink_to_fit",
        BatchSize::PerIteration,
        sparse_setup!(common::build_std_map, &pairs, keep),
        sparse_setup!(common::build_hashbrown_map, &pairs, keep),
        sparse_setup!(common::build_elastic_map, &pairs, keep),
        sparse_setup!(common::build_funnel_map, &pairs, keep),
        |map| {
            map.shrink_to_fit();
            black_box(map.capacity())
        },
    );

    group.finish();
}

/// Re-insert all keys with new values - hits the update-existing branch
/// in `insert` codegen, distinct from the vacant-slot path covered by `insert`.
fn bench_replace(c: &mut Criterion) {
    let pairs = common::make_pairs(MAP_SIZE);
    let mut group = c.benchmark_group("replace");
    group.throughput(Throughput::Elements(MAP_SIZE as u64));

    bench_populated!(group, "replace", BatchSize::LargeInput, &pairs, |map| {
        for &(key, value) in &pairs {
            black_box(map.insert(black_box(key), black_box(value.wrapping_add(1))));
        }
        black_box(map.len())
    },);

    group.finish();
}

fn bench_extend(c: &mut Criterion) {
    let pairs = common::make_pairs(MAP_SIZE);
    let mut group = c.benchmark_group("extend");
    group.throughput(Throughput::Elements(MAP_SIZE as u64));

    bench_empty!(group, "extend", BatchSize::PerIteration, |map| {
        map.extend(pairs.iter().copied());
        black_box(map.len())
    },);

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets =
        bench_iter,
        bench_iter_mut,
        bench_drain,
        bench_extract_if,
        bench_clear_drop,
        bench_entry_or_insert,
        bench_shrink_to_fit,
        bench_replace,
        bench_extend
);
criterion_main!(benches);
