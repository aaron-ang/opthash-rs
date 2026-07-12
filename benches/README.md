# Benchmarks

Use [`scripts/bench.sh`](../scripts/bench.sh) for evidence. On Linux it pins and
locks one CPU and disables ASLR; non-Linux keeps the plain-Cargo fallback. Raw
`cargo bench` is for smoke iteration only.

## Named runs

```bash
# On each clean commit, save under its 12-character commit hash.
scripts/bench.sh

# Compare two stored commits without rerunning.
LOAD=<candidate-hash> BASELINE=<baseline-hash> scripts/bench.sh
```

Commit hashes are the reproducible default. The script rejects an unnamed run
from a dirty tree because its results would not identify the measured source.
Use an explicit name for dirty experiments or multiple variants of one commit:

```bash
SAVE=membership-v2 scripts/bench.sh
```

An explicit name is also required when rerunning one commit with different
Criterion options; otherwise the shared commit-hash baseline would be replaced.

`BENCH=all` runs `speedup` followed by `mean_latency`. Select one target with
`BENCH=speedup`, `BENCH=mean_latency`, `BENCH=map_api`, or
`BENCH=scaled_insert`. Pass Criterion filters and options after `--`.
`map_api` and `scaled_insert` remain outside `BENCH=all`.

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

## Deletion maintenance

The explicit `map_api` target includes three deletion-maintenance controls at
20K entries: `remove_burst` removes three fifths of a populated map,
`post_delete_lookup` queries a deterministic shuffle of all original keys after that burst, and
`post_delete_insert` reinserts the removed keys. Criterion setup constructs the
post-delete state outside the timed region. Run only these groups with:

```bash
BENCH=map_api scripts/bench.sh -- 'remove_burst|post_delete'
```

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
