# Benchmarks

Use [`scripts/bench.sh`](../scripts/bench.sh) for evidence. On Linux it pins and
locks one CPU, disables ASLR, and turns on glibc's transparent huge pages for
large allocations; non-Linux keeps the plain-Cargo fallback. Raw `cargo bench`
is for smoke iteration only. The pin does not keep other processes off the core,
so run evidence on an otherwise idle machine.

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

`BENCH=all` runs `speedup` followed by `mean_latency`; only those two are in
`all`. Select any other `[[bench]]` target with `BENCH=<name>`. Pass Criterion
filters and options after `--`.

`map_api` also includes `entry_reinsert`: allocate for `MAP_SIZE`, fill to
`3 * MAP_SIZE / 4`, remove the first `MAP_SIZE / 32` keys during setup, then
time their `entry().or_insert()` calls. Spare capacity keeps all controls from growing.
The small delete burst stays below Funnel cleanup and filter-refresh thresholds,
so every removed key remains filter-positive and exercises vacant-search reuse.
Measure its baseline using the same fixture on the comparison revision.

Criterion IDs use `<workload>_<implementation>`, where implementation is one
of `std`, `hashbrown`, `elastic`, `funnel`, or `group_probe` (high-load sweep
only). Renaming an ID resets CodSpeed
history. The registered headline workloads live in
[`speedup.rs`](speedup.rs).

## Interpreting comparisons

- `hashbrown` shares the fixed foldhash fixture with Elastic and Funnel and is
  the SIMD SwissTable throughput ceiling, not a claim that paper-faithful probe
  algorithms should match its constant factors.
- `std` uses its own fixed `DefaultHasher`; Funnel parity with `std` is a useful
  engineering target but is not a same-table-design comparison.
- `MAP_SIZE` is `7/8 * 2^15`, so every map sits at its full insert budget:
  Funnel sizes exactly, and Elastic and `hashbrown` round to 32,768 slots whose
  budget is exactly that. `load_factor` fills every map to the same lower
  fraction of its own threshold; use it when the question is load, not size.
- `get_hit` is the benchmark closest to the paper's positive-query objective.
- `get_miss` measures a different regime: Funnel negatives follow insertion-like
  routing, while ordinary Elastic negatives exhaust the paper-derived exact
  schedule.
- `delete_heavy`, `remove_burst`, and `post_delete_*` measure the library's
  tombstone and epoch extensions, not the paper's insertion-only theorem.

## Hit-query methodology

Randomized `get_hit` workloads cycle a full Fisher-Yates permutation generated
by local SplitMix64 with seed `0xD1B54A32D192ED03`. Ordered controls use the
same populated keys in input order and have `get_hit_sequential` in their IDs.

## Deletion maintenance

The explicit `map_api` target includes three deletion-maintenance controls at
`MAP_SIZE` entries: `remove_burst` removes three fifths of a populated map,
`post_delete_lookup` queries a deterministic shuffle of all original keys after that burst, and
`post_delete_insert` reinserts the removed keys. Criterion setup constructs the
post-delete state outside the timed region. Run only these groups with:

```bash
BENCH=map_api scripts/bench.sh -- 'remove_burst|post_delete'
```

`iter_sparse` and `drain_sparse` start from the same allocated maps as the
dense `iter` and `drain` groups, then delete all but the first `MAP_SIZE / 10`
keys without shrinking. Deletions and any automatic maintenance happen in
untimed setup. Throughput counts the surviving entries; the timed fold visits
every surviving key/value pair.

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

## High-load sweep

`high_load` measures Elastic and Funnel where the paper's bounds separate from
greedy probing: tables filled to 87.5%, 96.9%, 99.2%, and 99.9% of their slots
(reserve exponents 3, 5, 7, and 10), at 2^16 slots (cache-resident) and 2^20
slots (past one L3 cluster).

```bash
BENCH=high_load SAVE=<name> scripts/bench.sh
BENCH=high_load SAVE=<name> scripts/bench.sh -- '_64K_'   # one size
```

Groups are `{workload}_{size}_{load}`, for example `get_miss_1M_99_9`:

- `tail_insert` times the last 1/64 of the inserts into a clone of a map
  holding the rest, so each sample ends at the point's load.
- `get_hit` and `get_miss` time the same shuffled hit and offset miss queries
  as `speedup`.

hashbrown caps load at 7/8, so it cannot run above the first point.
`group_probe` is the greedy control instead: a harness table with hashbrown's
control-byte layout, 8-lane SWAR groups, and triangular probing, but no load
cap and no removal. hashbrown joins only the 87.5% groups, to calibrate it.

**Calibration rule.** At 87.5%, at both sizes, `group_probe` must be within
1.5x of `hashbrown` on every workload in the same run. A run that misses it
does not count as evidence until `group_probe` is tuned.

Each arm builds its map just before its own benchmark and drops it right
after, so arm order and other backends' allocation sizes cannot move it.

## Memory footprint

`benches/memory.rs` reports heap bytes per entry, peak bytes while building,
and allocation counts for all four maps. Counts are deterministic, so it uses
the release profile rather than the bench profile:

```bash
cargo bench --profile release --bench memory
MEMORY_SIZES=1000,10000 cargo bench --profile release --bench memory
```

`prealloc` fills a `with_capacity(n)` map; `grow` fills an empty one; `shrink`
is `grow` followed by `shrink_to_fit`. Default sizes straddle hashbrown's 7/8 · 2^20 capacity step to show the power-of-two
sawtooth. Bytes are requested layouts, not RSS.

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
