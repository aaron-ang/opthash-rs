# Benchmarks

Use [`scripts/bench.sh`](../scripts/bench.sh) for evidence. It pins and locks
one CPU, disables ASLR on Linux, records compact metadata sidecars for every
explicit Criterion target, and rejects incompatible stored comparisons. Raw
`cargo bench` is for smoke iteration only.

## Named runs

```bash
SAVE=anchor scripts/bench.sh
SAVE=candidate scripts/bench.sh
LOAD=candidate BASELINE=anchor scripts/bench.sh
```

`BENCH=all` runs `speedup` followed by `mean_latency`. Select one target with
`BENCH=speedup`, `BENCH=mean_latency`, or `BENCH=scaled_insert`. Pass Criterion
filters and options after `--`. Each named run keeps raw Criterion estimates and
compact metadata; `scaled_insert` remains outside `BENCH=all`.

Criterion IDs use `<workload>_<implementation>`, where implementation is one
of `std`, `hashbrown`, `elastic`, or `funnel`. Renaming an ID resets CodSpeed
history. The registered headline workloads live in
[`speedup.rs`](speedup.rs).

## Hit-query methodology

Randomized `get_hit` workloads cycle a full Fisher-Yates permutation generated
by local SplitMix64 with seed `0xD1B54A32D192ED03`. Ordered controls use the
same populated keys in input order and have `get_hit_sequential` in their IDs.
Old baselines from before this fixture change are incompatible even though the
headline IDs did not change.

`mean_latency` covers 1K, 10K, 100K, 1M, and 10M entries. Maps are built once
per size outside Criterion's sampled callback. Results are batch mean
nanoseconds per lookup, not single-operation tail percentiles.

## Scaled insert

The local-only scaled target measures reused, preallocated maps at 100K, 1M,
and 10M entries:

```bash
BENCH=scaled_insert scripts/bench.sh
```

One preflight fill verifies all keys, values, length, and unchanged capacity.
Timed samples exclude `clear()` and post-fill assertions. The 100K and 1M
groups use 100 samples; 10M uses Criterion's minimum 10 because exact Elastic
fills take seconds. The policy is fixed in source and fixture-tested.

For smoke runs only:

```bash
SCALED_INSERT_SIZES=1000 cargo bench --bench scaled_insert -- insert_scale_1K
```

## Raw results

Inspect the named Criterion estimates directly:

```bash
cat target/criterion/get_hit/get_hit_funnel/ref/estimates.json
cat target/criterion/get_hit/get_hit_funnel/change/estimates.json
```

The `ref/estimates.json` file contains the saved absolute estimates. The
`change/estimates.json` file is created by a named comparison and contains the
fractional change from its selected baseline.

## Python

Python-side operations cross the GIL, `HashedAny::hash()`, and Python bytecode.
Write a fresh pytest-benchmark result for direct inspection:

```bash
pytest benches/python/throughput.py --benchmark-json=.benchmarks/python.json
```

Python pytest-benchmark JSON is not covered by the Rust metadata sidecars.
