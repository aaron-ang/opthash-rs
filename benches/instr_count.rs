//! Deterministic instruction-count benches via callgrind.
//!
//! Runs under valgrind, so each iteration is ~1000× slower than wall-clock —
//! intended for CI gating, not interactive tuning. Counts are stable across
//! runs (no CPU jitter), so a regression of even 10 instructions is signal.
//!
//! Run: `cargo bench --bench instr_count` (requires `valgrind` on PATH and
//! the `iai-callgrind-runner` cargo binary: `cargo install iai-callgrind-runner`).
mod common;

use std::collections::HashMap as StdHashMap;
use std::hint::black_box;

use hashbrown::HashMap as HbMap;
use iai_callgrind::{
    Callgrind, LibraryBenchmarkConfig, library_benchmark, library_benchmark_group, main,
};
use opthash::{ElasticHashMap, FunnelHashMap};

use common::{
    build_elastic_map, build_funnel_map, build_hashbrown_map, build_std_map, key_at, make_pairs,
};

const N: usize = 1_024;

/// Emits one `#[library_benchmark]` per impl (std/hashbrown/elastic/funnel)
/// + the `library_benchmark_group!`. `$body` re-expands per impl so its
/// `map` parameter's type can differ across arms.
macro_rules! op_group {
    (
        $group:ident,
        $ret:ty,
        std = $std:ident,
        hashbrown = $hashbrown:ident,
        elastic = $elastic:ident,
        funnel = $funnel:ident,
        |$map:ident| $body:expr $(,)?
    ) => {
        #[library_benchmark]
        fn $std() -> $ret {
            #[allow(unused_mut)]
            let mut $map = build_std_map(&make_pairs(N));
            $body
        }

        #[library_benchmark]
        fn $hashbrown() -> $ret {
            #[allow(unused_mut)]
            let mut $map = build_hashbrown_map(&make_pairs(N));
            $body
        }

        #[library_benchmark]
        fn $elastic() -> $ret {
            #[allow(unused_mut)]
            let mut $map = build_elastic_map(&make_pairs(N));
            $body
        }

        #[library_benchmark]
        fn $funnel() -> $ret {
            #[allow(unused_mut)]
            let mut $map = build_funnel_map(&make_pairs(N));
            $body
        }

        library_benchmark_group!(
            name = $group;
            benchmarks = $std, $hashbrown, $elastic, $funnel
        );
    };
}

// ---------------------------------------------------------------------------
// get_hit
// ---------------------------------------------------------------------------

op_group!(
    get_hit,
    u64,
    std = get_hit_std,
    hashbrown = get_hit_hashbrown,
    elastic = get_hit_elastic,
    funnel = get_hit_funnel,
    |map| {
        let mut acc = 0u64;
        for idx in 0..N {
            acc = acc.wrapping_add(*map.get(&key_at(idx)).unwrap());
        }
        black_box(acc)
    }
);

// ---------------------------------------------------------------------------
// insert (fresh map)
// ---------------------------------------------------------------------------

macro_rules! insert_arm {
    ($name:ident, $ty:ty) => {
        #[library_benchmark]
        fn $name() {
            let mut map = <$ty>::with_capacity(N * 2);
            for idx in 0..N {
                let k = key_at(idx);
                black_box(map.insert(k, k));
            }
            black_box(map);
        }
    };
}

insert_arm!(insert_std, StdHashMap<u64, u64>);
insert_arm!(insert_hashbrown, HbMap<u64, u64>);
insert_arm!(insert_elastic, ElasticHashMap<u64, u64>);
insert_arm!(insert_funnel, FunnelHashMap<u64, u64>);

library_benchmark_group!(
    name = insert;
    benchmarks = insert_std, insert_hashbrown, insert_elastic, insert_funnel
);

// ---------------------------------------------------------------------------
// remove
// ---------------------------------------------------------------------------

op_group!(
    remove,
    (),
    std = remove_std,
    hashbrown = remove_hashbrown,
    elastic = remove_elastic,
    funnel = remove_funnel,
    |map| {
        for idx in 0..N {
            black_box(map.remove(&key_at(idx)));
        }
        black_box(map);
    }
);

// ---------------------------------------------------------------------------
// iter().count() — exercises the OccupiedScanner path
// ---------------------------------------------------------------------------

op_group!(
    iter,
    usize,
    std = iter_std,
    hashbrown = iter_hashbrown,
    elastic = iter_elastic,
    funnel = iter_funnel,
    |map| black_box(map.iter().count())
);

// ---------------------------------------------------------------------------
// drain().count() — full-table teardown
// ---------------------------------------------------------------------------

op_group!(
    drain,
    usize,
    std = drain_std,
    hashbrown = drain_hashbrown,
    elastic = drain_elastic,
    funnel = drain_funnel,
    |map| black_box(map.drain().count())
);

// ---------------------------------------------------------------------------
// extract_if with non-trivial predicate (no LLVM elision of closure body).
// `std::HashMap::extract_if` is stable since Rust 1.88; opthash's edition
// 2024 toolchain has it.
// ---------------------------------------------------------------------------

op_group!(
    extract_if,
    usize,
    std = extract_if_std,
    hashbrown = extract_if_hashbrown,
    elastic = extract_if_elastic,
    funnel = extract_if_funnel,
    |map| black_box(map.extract_if(|k, v| (k ^ *v) & 1 == 0).count())
);

main!(
    config = LibraryBenchmarkConfig::default()
        .tool(
            // `--cache-sim=yes` enables L1d/L1i + LLd/LLi simulation.
            // `--branch-sim=yes` enables branch predictor simulation.
            // Both ride on top of instruction counting at no measurement noise cost.
            Callgrind::default().args(["--cache-sim=yes", "--branch-sim=yes"]),
        );
    library_benchmark_groups = get_hit, insert, remove, iter, drain, extract_if
);
