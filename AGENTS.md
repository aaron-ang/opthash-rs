# AGENTS.md

Run all of these after every refactor. Check benchmark results in `target/criterion/` for performance regressions.

## Commands

```bash
cargo fmt                                   # Format Rust code
cargo clippy --all-targets --features python -- -W clippy::pedantic   # Lint with pedantic warnings
cargo test                                  # Run all tests
scripts/bench.sh                            # Run all benchmarks (noise-controlled — see Benchmarks)
uvx ruff format                             # Format Python code (scripts/, tests/)
pre-commit run --all-files                  # Run formatters on the whole tree
```

One-time setup (after cloning):

```bash
uv tool install pre-commit
pre-commit install
```

## Benchmarks

Criterion suite comparing `ElasticHashMap`, `FunnelHashMap`, `std::HashMap`, `hashbrown::HashMap` (SwissTable + foldhash — absolute ceiling).

**Always use `scripts/bench.sh` for results you'll act on.** Raw `cargo bench` is unpinned — wall-clock noise can swing ±10% and flip the sign of real ±5% changes. Use raw cargo only for smoke runs / single-filter iteration.

```bash
scripts/bench.sh                            # measure + save as "ref"
SAVE=opt1 scripts/bench.sh                  # measure + save as "opt1"
LOAD=opt1 scripts/bench.sh                  # opt1 vs ref (no rerun)
LOAD=opt1 BASELINE=opt2 scripts/bench.sh    # opt1 vs opt2 (no rerun)
```

For A/B many optimizations against the same anchor: `SAVE=optN` each variant, then `LOAD=optN` to compare offline. Stored baselines persist in `target/criterion/`.

- Wraps `cargo bench` with `taskset` (core pin), `setarch -R` (ASLR off), `chrt -b` (scheduler batch), and `numactl` (NUMA bind, multi-node only) — no privileges. `sudo` adds `nice -20`, `prlimit` memlock; drops back to invoking user for cargo.
- `BENCH=all` (default) runs `speedup` then `latency`; set `BENCH=speedup|latency` for single-target.
- Re-save `ref` when env changes (sudo vs not, core pin) — baselines are wall-clock.
- Pass through flags (no leading `--`): `SAVE=ref scripts/bench.sh --measurement-time 10`. Criterion name filter: `scripts/bench.sh "get_hit_latency"`.
- `latency` bench writes histograms to `target/latency/` and ignores `--baseline`.

**Read results from JSON, not stdout** (stdout truncates + mixes runs):

- `target/criterion/<group>/<variant>/new/estimates.json` — absolute ns (`mean.point_estimate`)
- `target/criterion/<group>/<variant>/change/estimates.json` — fractional change vs the baseline this run compared against (e.g. +0.05 = 5% slower)

Variants are `<op>_<impl>` per [benches/speedup.rs](benches/speedup.rs) (e.g. `get_hit_funnel`, `insert_elastic`). Example: `target/criterion/get_hit_throughput/get_hit_funnel/change/estimates.json`.

### Latency-chart harnesses

- **`cargo bench --bench mean_latency`** — Criterion sweep of `get_hit` over `LATENCY_SIZES` (1K → 10M); feeds the cache-cliff line chart. Output: `target/criterion/get_hit_latency_<size>/<impl>/`.
- **`cargo bench --bench tail_latency`** — HDR get-hit distribution at SIZE=10M (1M samples × 4 maps × 10K warmup). Output: `target/latency/<map>/<size>/<op>.json` (serde_json) — percentiles + histogram buckets + `clock_overhead_ns`.

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

`mean_latency.rs` and `tail_latency.rs` are local-only. Sim counts instructions, not wallclock — `scripts/bench.sh` stays the local ground truth.

### Charts

- `uv run scripts/generate_speedup_chart.py` — throughput speedup bar chart
- `uv run scripts/generate_latency_chart.py` — Criterion mean-latency line (`target/criterion/get_hit_latency_<size>`; sizes from `LATENCY_SIZES` in `benches/common.rs`) + HDR get-hit tail CDF @ 10M (`target/latency/`).
- `uv run scripts/generate_all_charts.py` — regenerate everything
- `uv run scripts/generate_python_chart.py` — Python-side dict-vs-opthash speedup (reads `.benchmarks/python.json`)

Charts are saved in `assets/`. Shared plotting helpers (`IMPLEMENTATIONS`, loaders, axis styling) live in `scripts/plot_common.py`. The tail plotter subtracts `clock_overhead_ns` so percentiles reflect per-op latency, not per-(op + `Instant::now()`).

## Project structure

- `src/elastic.rs` — `ElasticHashMap` (tests inline)
- `src/funnel.rs` — `FunnelHashMap` (tests inline)
- `src/common/` — shared internals: control-byte SIMD ops, layout math, config

## Worktree naming

When spawning a worktree, name its branch after the work (e.g. `feat/std-parity-mut-iters`) and pass the same name to `git worktree add`.

## Refactoring guidelines

### Where things live

- Low-level helpers used by both the library and benchmarks live in `src/common/` (bitmask, simd, layout, math). Benches pull fixtures from `benches/common.rs`. Don't duplicate primitives across `src/` and `benches/`.

### Design priorities

- Prefer layout and locality wins before adding more metadata. Keep hot metadata contiguous — if fields are read together, store them together.
- Cache routing state that's reused in hot paths; never recompute it per probe.
- Preserve SIMD-friendly control-byte scans: contiguous groups, cheap bitmask iteration, early rejection before touching payloads.
- Treat values that are constant by construction as constants. Storing them as runtime fields costs a load + mul per probe that LLVM can't fold away.

### Reject

- Metadata that costs work on every insert/delete unless benchmarks prove a net win.
- Optimizations that improve a microbenchmark but regress the public `throughput` suite. `target/criterion/` is the final gate — if the relevant benchmark regresses, the change does not stay.

### Bench methodology

- Re-save `ref` whenever a fixture constant changes (`HIT_LOOKUP_COUNT`, `MIXED_OP_COUNT`, etc.). Comparing across different workloads makes the `change/` deltas meaningless.
- Rebuild before reading callgrind output. Stale binaries silently report pre-change asm — check binary mtime against the commit you intend to measure.

### Verify before refactor

- Read the asm (`objdump -d`) on hot functions before factoring shared SIMD or arithmetic primitives. LLVM already CSEs same-pointer control-byte loads and folds duplicate masks; a "cleaner" abstraction may save nothing.
- Adding a field to a hot struct (`RawTable`, `Level`) is a layout change. Downstream fields can shift across cache lines and regress lookups 15–20% with no semantic change. Measure offsets _and_ bench.
- Pure refactors (rename, extract, no logic change) can swing 5–50% from icache and branch-predictor layout shifts. A no-op refactor should leave CodSpeed sim instr-count at ±0.
