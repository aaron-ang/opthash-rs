//! Deterministic instruction-count benches via callgrind.
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

// ---------------------------------------------------------------------------
// Setup helpers — run via iai-callgrind `setup =`, NOT in the measured region.
// ---------------------------------------------------------------------------

fn populated_std() -> StdHashMap<u64, u64> {
    build_std_map(&make_pairs(N))
}
fn populated_hashbrown() -> HbMap<u64, u64> {
    build_hashbrown_map(&make_pairs(N))
}
fn populated_elastic() -> ElasticHashMap<u64, u64> {
    build_elastic_map(&make_pairs(N))
}
fn populated_funnel() -> FunnelHashMap<u64, u64> {
    build_funnel_map(&make_pairs(N))
}

fn empty_std() -> StdHashMap<u64, u64> {
    StdHashMap::with_capacity(N * 2)
}
fn empty_hashbrown() -> HbMap<u64, u64> {
    HbMap::with_capacity(N * 2)
}
fn empty_elastic() -> ElasticHashMap<u64, u64> {
    ElasticHashMap::with_capacity(N * 2)
}
fn empty_funnel() -> FunnelHashMap<u64, u64> {
    FunnelHashMap::with_capacity(N * 2)
}

/// Emits one `#[library_benchmark]` per impl + the `library_benchmark_group!`.
/// Each fn receives a pre-built map from its `setup` hook; that map's
/// construction cost is excluded from the measured instruction count.
macro_rules! op_group {
    (
        $group:ident,
        $ret:ty,
        std = $std:ident (setup = $std_setup:ident),
        hashbrown = $hashbrown:ident (setup = $hb_setup:ident),
        elastic = $elastic:ident (setup = $el_setup:ident),
        funnel = $funnel:ident (setup = $fn_setup:ident),
        |$map:ident| $body:expr $(,)?
    ) => {
        #[library_benchmark]
        #[bench::run(setup = $std_setup)]
        fn $std($map: StdHashMap<u64, u64>) -> $ret {
            $body
        }
        #[library_benchmark]
        #[bench::run(setup = $hb_setup)]
        fn $hashbrown($map: HbMap<u64, u64>) -> $ret {
            $body
        }
        #[library_benchmark]
        #[bench::run(setup = $el_setup)]
        fn $elastic($map: ElasticHashMap<u64, u64>) -> $ret {
            $body
        }
        #[library_benchmark]
        #[bench::run(setup = $fn_setup)]
        fn $funnel($map: FunnelHashMap<u64, u64>) -> $ret {
            $body
        }
        library_benchmark_group!(
            name = $group;
            benchmarks = $std, $hashbrown, $elastic, $funnel
        );
    };
}

macro_rules! mut_op_group {
    (
        $group:ident,
        $ret:ty,
        std = $std:ident (setup = $std_setup:ident),
        hashbrown = $hashbrown:ident (setup = $hb_setup:ident),
        elastic = $elastic:ident (setup = $el_setup:ident),
        funnel = $funnel:ident (setup = $fn_setup:ident),
        |$map:ident| $body:expr $(,)?
    ) => {
        #[library_benchmark]
        #[bench::run(setup = $std_setup)]
        fn $std(mut $map: StdHashMap<u64, u64>) -> $ret {
            $body
        }
        #[library_benchmark]
        #[bench::run(setup = $hb_setup)]
        fn $hashbrown(mut $map: HbMap<u64, u64>) -> $ret {
            $body
        }
        #[library_benchmark]
        #[bench::run(setup = $el_setup)]
        fn $elastic(mut $map: ElasticHashMap<u64, u64>) -> $ret {
            $body
        }
        #[library_benchmark]
        #[bench::run(setup = $fn_setup)]
        fn $funnel(mut $map: FunnelHashMap<u64, u64>) -> $ret {
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
    std = get_hit_std(setup = populated_std),
    hashbrown = get_hit_hashbrown(setup = populated_hashbrown),
    elastic = get_hit_elastic(setup = populated_elastic),
    funnel = get_hit_funnel(setup = populated_funnel),
    |map| {
        let mut acc = 0u64;
        for idx in 0..N {
            acc = acc.wrapping_add(*map.get(&key_at(idx)).unwrap());
        }
        black_box(acc)
    }
);

// ---------------------------------------------------------------------------
// insert (into a freshly-allocated empty map)
// ---------------------------------------------------------------------------

mut_op_group!(
    insert,
    (),
    std = insert_std(setup = empty_std),
    hashbrown = insert_hashbrown(setup = empty_hashbrown),
    elastic = insert_elastic(setup = empty_elastic),
    funnel = insert_funnel(setup = empty_funnel),
    |map| {
        for idx in 0..N {
            let k = key_at(idx);
            black_box(map.insert(k, k));
        }
    }
);

// ---------------------------------------------------------------------------
// remove
// ---------------------------------------------------------------------------

mut_op_group!(
    remove,
    (),
    std = remove_std(setup = populated_std),
    hashbrown = remove_hashbrown(setup = populated_hashbrown),
    elastic = remove_elastic(setup = populated_elastic),
    funnel = remove_funnel(setup = populated_funnel),
    |map| {
        for idx in 0..N {
            black_box(map.remove(&key_at(idx)));
        }
    }
);

// ---------------------------------------------------------------------------
// iter().count() — exercises the OccupiedScanner path
// ---------------------------------------------------------------------------

op_group!(
    iter,
    usize,
    std = iter_std(setup = populated_std),
    hashbrown = iter_hashbrown(setup = populated_hashbrown),
    elastic = iter_elastic(setup = populated_elastic),
    funnel = iter_funnel(setup = populated_funnel),
    |map| black_box(map.iter().count())
);

// ---------------------------------------------------------------------------
// drain().count() — full-table teardown
// ---------------------------------------------------------------------------

mut_op_group!(
    drain,
    usize,
    std = drain_std(setup = populated_std),
    hashbrown = drain_hashbrown(setup = populated_hashbrown),
    elastic = drain_elastic(setup = populated_elastic),
    funnel = drain_funnel(setup = populated_funnel),
    |map| black_box(map.drain().count())
);

// ---------------------------------------------------------------------------
// extract_if with non-trivial predicate (no LLVM elision of closure body).
// ---------------------------------------------------------------------------

mut_op_group!(
    extract_if,
    usize,
    std = extract_if_std(setup = populated_std),
    hashbrown = extract_if_hashbrown(setup = populated_hashbrown),
    elastic = extract_if_elastic(setup = populated_elastic),
    funnel = extract_if_funnel(setup = populated_funnel),
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
