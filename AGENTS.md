# AGENTS.md

Use this file as the local operating guide for code changes in this repo.

## Commands

For code refactors, run:

```bash
cargo test                                  # Run all tests
pre-commit run --all-files                  # Runs formatters, clippy, ruff, mypy stub checks
```

For performance-sensitive changes, run the relevant benchmark A/B workflow in [Benchmarks](#benchmarks) and read the JSON results.

One-time setup (after cloning):

```bash
uv tool install pre-commit
pre-commit install
```

## Benchmarks

Criterion suite comparing `ElasticHashMap`, `FunnelHashMap`, `std::HashMap`, `hashbrown::HashMap` (SwissTable + foldhash — absolute ceiling).

Use `scripts/bench.sh` for benchmark results you will act on. Raw `cargo bench` is unpinned; wall-clock noise can swing and flip the sign of real changes. Use raw cargo only for smoke runs or single-filter iteration.

For A/B comparisons, save a known anchor, save each changed tree as a named variant, then compare stored runs offline with `LOAD` and `BASELINE`. Refresh `ref` when intentionally updating the default anchor after environment or benchmark-fixture changes.

```bash
SAVE=anchor scripts/bench.sh                # measure known baseline
SAVE=opt1 scripts/bench.sh                  # measure changed tree
LOAD=opt1 BASELINE=anchor scripts/bench.sh  # opt1 vs anchor (no rerun)
SAVE=ref scripts/bench.sh                   # intentionally refresh the default anchor
```

For many variants against the same anchor, save the anchor once (`SAVE=anchor`), save each variant (`SAVE=optN`), then compare with `LOAD=optN BASELINE=anchor`. Stored baselines persist in `target/criterion/`.

- `target/criterion/<group>/<variant>/new/estimates.json` — absolute ns (`mean.point_estimate`)
- `target/criterion/<group>/<variant>/change/estimates.json` — fractional change vs the selected baseline (`+0.05` = 5% slower)
- Variants are `<op>_<impl>` per [benches/speedup.rs](benches/speedup.rs), for example `get_hit_funnel` or `insert_elastic`.
- Example change file: `target/criterion/get_hit_throughput/get_hit_funnel/change/estimates.json`.

Run shape and options:

- Wraps `cargo bench` with `taskset` (core pin), `setarch -R` (ASLR off), `chrt -b` (scheduler batch), and `numactl` (NUMA bind, multi-node only) — no privileges. `sudo` adds `nice -20`, `prlimit` memlock; drops back to invoking user for cargo.
- `BENCH=all` (default) runs `speedup`, then `mean_latency`; set `BENCH=speedup|mean_latency` for one target.
- Pass through Criterion flags with `--`: `SAVE=opt1 scripts/bench.sh -- --measurement-time 10`.
- Filter by Criterion name: `SAVE=opt1 scripts/bench.sh -- "get_hit_latency"`. The script strips a leading `--`, so both forms work.

### Latency-chart harness

- `BENCH=mean_latency scripts/bench.sh` — Criterion sweep of `get_hit` over `LATENCY_SIZES` (1K → 10M); feeds the cache-cliff line chart. Output: `target/criterion/get_hit_latency_<size>/get_hit_latency_<size>_<impl>/`.

### Python-side benchmarks

`benches/python/throughput.py` — pytest-benchmark suite comparing `dict`, `ElasticHashMap`, and `FunnelHashMap` from Python across insert / get_hit / get_miss / mixed / delete workloads at N = 10K. Each opthash op crosses the GIL → `HashedAny::hash()` → Python bytecode.

```bash
pytest benches/python/throughput.py --benchmark-json=.benchmarks/python.json

uv run scripts/generate_python_chart.py
```

### CodSpeed CI

`.github/workflows/codspeed.yml` runs Callgrind sim on every PR. Two jobs:

- **rust** — `cargo codspeed run --bench speedup`. The `criterion` dev-dep is a package rename to `codspeed-criterion-compat`; don't revert.
- **python** — `pytest benches/python/throughput.py --codspeed`. `pytest-codspeed` is drop-in for `pytest-benchmark`.

`mean_latency.rs` is local-only. Sim counts instructions, not wallclock — `scripts/bench.sh` stays the local ground truth.

### Charts

- `uv run scripts/generate_speedup_chart.py` — throughput speedup bar chart
- `uv run scripts/generate_latency_chart.py` — Criterion mean-latency line (`target/criterion/get_hit_latency_<size>`; sizes from `LATENCY_SIZES` in `benches/common.rs`).
- `uv run scripts/generate_all_charts.py` — regenerate everything
- `uv run scripts/generate_python_chart.py` — Python-side dict-vs-opthash speedup (reads `.benchmarks/python.json`)

Charts are saved in `assets/`. Shared plotting helpers (`IMPLEMENTATIONS`, loaders, axis styling) live in `scripts/_plot_common.py`.

### Methodology

- Re-save the anchor whenever a fixture constant changes (`OP_COUNT`, `MAP_SIZE`, `LATENCY_SIZES`). Comparing across different workloads makes `change/` deltas meaningless.
- Treat unchanged controls (`std`, `hashbrown`) as the run's noise floor. Large movement in controls weakens any conclusion about `elastic` or `funnel`.
- Rebuild before reading `callgrind`/CodSpeed output — stale binaries silently report pre-change asm. Check binary mtime against the commit you intend to measure.

## Project Structure

- `src/elastic.rs` — `ElasticHashMap` (tests inline)
- `src/funnel.rs` — `FunnelHashMap` (tests inline)
- `src/common/` — shared internals used by library and benches: control-byte SIMD, bitmask, layout math, config
- `benches/common.rs` — bench fixtures

Don't duplicate primitives across `src/` and `benches/`.

## Worktree Naming

When spawning a worktree, name its branch after the work (e.g. `feat/std-parity-mut-iters`) and pass the same name to `git worktree add`.

## Refactoring Guidelines

### Design Priorities

- Prefer layout and locality wins before adding more metadata. Keep hot metadata contiguous — if fields are read together, store them together.
- Cache routing state that's reused in hot paths; never recompute it per probe.
- Preserve SIMD-friendly control-byte scans: contiguous groups, cheap bitmask iteration, early rejection before touching payloads.
- Treat values that are constant by construction as constants. Storing them as runtime fields costs a load + mul per probe that LLVM can't fold away.

### Reject

- Metadata that costs work on every insert/delete unless benchmarks prove a net win.
- Optimizations that improve a narrow microbenchmark but regress the public `speedup` suite. `target/criterion/` is the final gate — if the relevant benchmark regresses, the change does not stay.

### Verification

- Read the asm (`objdump -d`) on hot functions before factoring shared SIMD or arithmetic primitives. LLVM already CSEs same-pointer control-byte loads and folds duplicate masks; a "cleaner" abstraction may save nothing.
- Confirm hot-path wins with `perf stat` (cycles, instructions, cache-misses, branch-misses) on a pinned run; a real win moves the matching counter, not just wallclock.
- Adding a field to a hot struct (`RawTable`, `Level`) is a layout change. Downstream fields can shift across cache lines and regress lookups with no semantic change. Measure offsets _and_ bench.
- Pure refactors (rename, extract, no logic change) can swing 5–50% from icache and branch-predictor layout shifts. A no-op refactor should leave CodSpeed sim instr-count at ±0.
