//! Set-wrapper regression benches: `extract_if` + set algebra (`union` /
//! `intersection` / `difference` / `symmetric_difference`).
//!
//! These exercise the set-specific code that is NOT shared with the map
//! backends — the boxed `extract_if` predicate and the algebra iterators
//! (`Union`/`Intersection`/`Difference`/`SymmetricDifference`). The map
//! `speedup` suite already covers the shared probing path (set `insert`/
//! `contains` delegate straight to it), so this target guards only the wrapper.
//! Each group runs std / hashbrown / elastic / funnel side-by-side.

mod common;

use std::collections::HashSet as StdHashSet;
use std::hint::black_box;
use std::time::Duration;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use hashbrown::HashSet as HashbrownHashSet;
use opthash::{ElasticHashSet, FunnelHashSet};

/// Elements per set.
const N: usize = 20_000;

/// `count` distinct keys from `common::key_at`, starting at `offset`.
fn keys(count: usize, offset: usize) -> Vec<u64> {
    (offset..offset + count).map(common::key_at).collect()
}

/// Builds a set of `$ty` pre-sized to `$keys`.
macro_rules! build_set {
    ($ty:ty, $keys:expr) => {{
        let mut set = <$ty>::with_capacity($keys.len());
        for &k in $keys {
            set.insert(k);
        }
        set
    }};
}

/// Rebuilds a fresh set each iteration, then extracts the even keys — the
/// boxed-predicate path on the opthash sets. xor-fold defeats elision.
fn bench_set_extract_if(c: &mut Criterion) {
    let ks = keys(N, 0);
    let mut group = c.benchmark_group("set_extract_if_throughput");
    group.throughput(Throughput::Elements(N as u64));

    macro_rules! one {
        ($name:literal, $ty:ty) => {
            group.bench_function($name, |b| {
                b.iter_batched_ref(
                    || build_set!($ty, &ks),
                    |set| black_box(set.extract_if(|&x| x % 2 == 0).fold(0u64, |a, x| a ^ x)),
                    BatchSize::PerIteration,
                );
            });
        };
    }
    one!("set_extract_if_std", StdHashSet<u64>);
    one!("set_extract_if_hashbrown", HashbrownHashSet<u64>);
    one!("set_extract_if_elastic", ElasticHashSet<u64>);
    one!("set_extract_if_funnel", FunnelHashSet<u64>);

    group.finish();
}

/// Benches one set-algebra method (`union`/`intersection`/…) across the four
/// impls over two 50%-overlapping sets. The operands are built once (the
/// algebra iterators are read-only); xor-fold consumes the lazy iterator so
/// the wrapper's per-element work is actually timed.
macro_rules! algebra_group {
    ($c:expr, $tag:literal, $method:ident) => {{
        let ka = keys(N, 0);
        let kb = keys(N, N / 2);
        let sa = build_set!(StdHashSet<u64>, &ka);
        let sb = build_set!(StdHashSet<u64>, &kb);
        let ha = build_set!(HashbrownHashSet<u64>, &ka);
        let hb = build_set!(HashbrownHashSet<u64>, &kb);
        let ea = build_set!(ElasticHashSet<u64>, &ka);
        let eb = build_set!(ElasticHashSet<u64>, &kb);
        let fa = build_set!(FunnelHashSet<u64>, &ka);
        let fb = build_set!(FunnelHashSet<u64>, &kb);

        let mut group = $c.benchmark_group(concat!($tag, "_throughput"));
        group.throughput(Throughput::Elements(N as u64));
        group.bench_function(concat!($tag, "_std"), |b| {
            b.iter(|| black_box(sa.$method(&sb).fold(0u64, |a, &x| a ^ x)));
        });
        group.bench_function(concat!($tag, "_hashbrown"), |b| {
            b.iter(|| black_box(ha.$method(&hb).fold(0u64, |a, &x| a ^ x)));
        });
        group.bench_function(concat!($tag, "_elastic"), |b| {
            b.iter(|| black_box(ea.$method(&eb).fold(0u64, |a, &x| a ^ x)));
        });
        group.bench_function(concat!($tag, "_funnel"), |b| {
            b.iter(|| black_box(fa.$method(&fb).fold(0u64, |a, &x| a ^ x)));
        });
        group.finish();
    }};
}

fn bench_set_algebra(c: &mut Criterion) {
    algebra_group!(c, "set_union", union);
    algebra_group!(c, "set_intersection", intersection);
    algebra_group!(c, "set_difference", difference);
    algebra_group!(c, "set_symmetric_difference", symmetric_difference);
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2));
    targets = bench_set_extract_if, bench_set_algebra
);
criterion_main!(benches);
