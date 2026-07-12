#![allow(dead_code, unused_macros)]

use criterion::{Criterion, Throughput};

use super::{ElasticHashMap, FunnelHashMap, HashbrownMap, StdHashMap};

#[allow(clippy::too_many_arguments)]
pub fn bench_one_lookup_group(
    c: &mut Criterion,
    group_name: &str,
    query_keys: &[u64],
    std_map: &StdHashMap<u64, u64>,
    hb_map: &HashbrownMap<u64, u64>,
    el_map: &ElasticHashMap<u64, u64>,
    fn_map: &FunnelHashMap<u64, u64>,
) {
    let mut group = c.benchmark_group(group_name);
    group.throughput(Throughput::Elements(query_keys.len() as u64));
    group.bench_function(format!("{group_name}_std"), |b| {
        b.iter(|| {
            for key in query_keys {
                std::hint::black_box(std_map.get(std::hint::black_box(key)));
            }
        });
    });
    group.bench_function(format!("{group_name}_hashbrown"), |b| {
        b.iter(|| {
            for key in query_keys {
                std::hint::black_box(hb_map.get(std::hint::black_box(key)));
            }
        });
    });
    group.bench_function(format!("{group_name}_elastic"), |b| {
        b.iter(|| {
            for key in query_keys {
                std::hint::black_box(el_map.get(std::hint::black_box(key)));
            }
        });
    });
    group.bench_function(format!("{group_name}_funnel"), |b| {
        b.iter(|| {
            for key in query_keys {
                std::hint::black_box(fn_map.get(std::hint::black_box(key)));
            }
        });
    });
    group.finish();
}

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

/// [`bench_all_impls!`] with `build_*_map($pairs)` for each impl.
macro_rules! bench_populated {
    ($group:expr, $op:literal, $batch:expr, $pairs:expr, $body:expr $(,)?) => {
        bench_all_impls!(
            $group,
            $op,
            $batch,
            || $crate::harness::build_std_map($pairs),
            || $crate::harness::build_hashbrown_map($pairs),
            || $crate::harness::build_elastic_map($pairs),
            || $crate::harness::build_funnel_map($pairs),
            $body,
        )
    };
}

/// Like [`bench_populated`] but using the `(u64, BigVal)` builders.
macro_rules! bench_populated_big {
    ($group:expr, $op:literal, $batch:expr, $pairs:expr, $body:expr $(,)?) => {
        bench_all_impls!(
            $group,
            $op,
            $batch,
            || $crate::harness::build_std_big_map($pairs),
            || $crate::harness::build_hashbrown_big_map($pairs),
            || $crate::harness::build_elastic_big_map($pairs),
            || $crate::harness::build_funnel_big_map($pairs),
            $body,
        )
    };
}

/// [`bench_all_impls!`] with empty-map constructors. For growth / extend.
macro_rules! bench_empty {
    ($group:expr, $op:literal, $batch:expr, $body:expr $(,)?) => {
        bench_all_impls!(
            $group,
            $op,
            $batch,
            || $crate::harness::std_map_cap(0),
            || $crate::harness::hashbrown_map_cap(0),
            || $crate::harness::elastic_map_cap(0),
            || $crate::harness::funnel_map_cap(0),
            $body,
        )
    };
}

/// [`bench_all_impls!`] with `with_capacity($cap)` constructors.
macro_rules! bench_with_cap {
    ($group:expr, $op:literal, $batch:expr, $cap:expr, $body:expr $(,)?) => {
        bench_all_impls!(
            $group,
            $op,
            $batch,
            || $crate::harness::std_map_cap($cap),
            || $crate::harness::hashbrown_map_cap($cap),
            || $crate::harness::elastic_map_cap($cap),
            || $crate::harness::funnel_map_cap($cap),
            $body,
        )
    };
}

/// Per-impl insert bench using `iter_custom` + map reuse via `clear()`.
/// Timed region excludes setup so allocation-induced cache pollution
/// doesn't bleed into the measurement (unlike [`bench_with_cap!`]).
macro_rules! bench_insert_reuse {
    ($group:expr, $op:literal, $cap:expr, $pairs:expr $(,)?) => {{
        bench_insert_reuse_one!(
            $group,
            concat!($op, "_std"),
            $crate::harness::std_map_cap($cap),
            $pairs
        );
        bench_insert_reuse_one!(
            $group,
            concat!($op, "_hashbrown"),
            $crate::harness::hashbrown_map_cap($cap),
            $pairs
        );
        bench_insert_reuse_one!(
            $group,
            concat!($op, "_elastic"),
            $crate::harness::elastic_map_cap($cap),
            $pairs
        );
        bench_insert_reuse_one!(
            $group,
            concat!($op, "_funnel"),
            $crate::harness::funnel_map_cap($cap),
            $pairs
        );
    }};
}

/// Dynamic-name variant of [`bench_insert_reuse`] for size-labelled groups.
macro_rules! bench_insert_reuse_named {
    ($group:expr, $op:expr, $cap:expr, $pairs:expr $(,)?) => {{
        bench_insert_reuse_one!(
            $group,
            format!("{}_std", $op),
            $crate::harness::std_map_cap($cap),
            $pairs
        );
        bench_insert_reuse_one!(
            $group,
            format!("{}_hashbrown", $op),
            $crate::harness::hashbrown_map_cap($cap),
            $pairs
        );
        bench_insert_reuse_one!(
            $group,
            format!("{}_elastic", $op),
            $crate::harness::elastic_map_cap($cap),
            $pairs
        );
        bench_insert_reuse_one!(
            $group,
            format!("{}_funnel", $op),
            $crate::harness::funnel_map_cap($cap),
            $pairs
        );
    }};
}

/// Validate the reused-map fixture once before Criterion starts sampling.
macro_rules! preflight_insert_reuse_map {
    ($map:expr, $pairs:expr $(,)?) => {{
        let expected_capacity = $map.capacity();
        for &(key, value) in $pairs {
            assert_eq!(
                $map.insert(key, value),
                None,
                "scaled-insert fixtures must contain distinct keys"
            );
        }
        assert_eq!($map.len(), $pairs.len(), "preflight inserted length");
        assert_eq!(
            $map.capacity(),
            expected_capacity,
            "preallocated map grew during preflight"
        );
        for &(key, value) in $pairs {
            assert_eq!($map.get(&key), Some(&value), "preflight key/value");
        }
        $map.clear();
        assert_eq!($map.len(), 0, "preflight clear length");
        assert_eq!(
            $map.capacity(),
            expected_capacity,
            "clear changed preallocated capacity"
        );
        expected_capacity
    }};
}

/// One impl variant of [`bench_insert_reuse`]. Native: `iter_custom` so
/// only the insert loop is timed (no per-iter alloc pollution). Under
/// `cfg(codspeed)` falls back to `iter_batched_ref` (codspeed-criterion-
/// compat skips `iter_custom`); accept the realloc cost - instruction
/// counts under callgrind are insensitive to cache state anyway.
macro_rules! bench_insert_reuse_one {
    ($group:expr, $name:expr, $setup:expr, $pairs:expr $(,)?) => {{
        #[cfg(not(codspeed))]
        {
            let pairs = $pairs;
            let mut map = $setup;
            let expected_capacity = preflight_insert_reuse_map!(map, pairs);
            $group.bench_function($name, move |b| {
                b.iter_custom(|iters| {
                    let mut total = std::time::Duration::ZERO;
                    for _ in 0..iters {
                        map.clear();
                        assert_eq!(map.len(), 0, "timed-fill clear length");
                        assert_eq!(
                            map.capacity(),
                            expected_capacity,
                            "timed-fill clear changed capacity"
                        );
                        let t0 = std::time::Instant::now();
                        for &(key, value) in pairs {
                            map.insert(std::hint::black_box(key), std::hint::black_box(value));
                        }
                        let elapsed = t0.elapsed();
                        assert_eq!(map.len(), pairs.len(), "timed-fill inserted length");
                        assert_eq!(
                            map.capacity(),
                            expected_capacity,
                            "preallocated map grew during timed fill"
                        );
                        total += elapsed;
                    }
                    total
                });
            });
        }
        #[cfg(codspeed)]
        {
            let pairs = $pairs;
            let mut preflight = $setup;
            let _ = preflight_insert_reuse_map!(preflight, pairs);
            drop(preflight);
            $group.bench_function($name, move |b| {
                b.iter_batched_ref(
                    || $setup,
                    |map| {
                        for &(key, value) in pairs {
                            map.insert(std::hint::black_box(key), std::hint::black_box(value));
                        }
                        std::hint::black_box(map.len())
                    },
                    criterion::BatchSize::PerIteration,
                );
            });
        }
    }};
}
