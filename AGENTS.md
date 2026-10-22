# AGENTS.md

## Commands

For code refactors, run:

```bash
cargo test                                  # Run all tests
pre-commit run --all-files                  # Runs formatters, clippy, ruff, mypy stub checks
```

For performance-sensitive changes, run the relevant benchmark A/B workflow in [Benchmarks](#benchmarks) and read the JSON results.

Do not edit `CHANGELOG.md`. release-plz generates it from conventional commit
messages on release. Put user-facing detail in the commit body and mark
breaking changes with `!` on the type (`refactor!: ...`) so they land in the
right changelog section and version bump.

One-time setup: `uv tool install pre-commit && pre-commit install`.

## Tests

Tests are deterministic. Build maps from the fixed-seed aliases with the
`Deterministic` trait in scope (`test_support` in `src/`, `tests/support` in
integration tests) so `HashMap::new()` / `with_capacity(n)` seed foldhash
identically on every run; never use the random-seeded default except in
constructor-surface tests that hash no key. Treat a flaky test as a
determinism bug to fix, not a run to repeat.

## Benchmarks

Criterion suite comparing `ElasticHashMap`, `FunnelHashMap`, `std::HashMap`, `hashbrown::HashMap` (SwissTable + foldhash — absolute ceiling).

Use `scripts/bench.sh` for benchmark results you will act on. Raw `cargo bench` is unpinned; wall-clock noise can swing and flip the sign of real changes. Use raw cargo only for smoke runs or single-filter iteration.

For A/B comparisons, save a known anchor, save each changed tree as a named
variant, then compare stored runs offline with `LOAD` and `BASELINE`. Refresh
`ref` when intentionally updating the default anchor after environment or
benchmark-fixture changes. Stored baselines persist in `target/criterion/`.

With no mode selected, the harness requires a clean tree and saves HEAD under
its 12-character commit hash. Use an explicit `SAVE` name for exploratory runs.

```bash
SAVE=anchor scripts/bench.sh                # measure known baseline
SAVE=opt1 scripts/bench.sh                  # measure changed tree
LOAD=opt1 BASELINE=anchor scripts/bench.sh  # opt1 vs anchor (no rerun)
SAVE=ref scripts/bench.sh                   # intentionally refresh the default anchor
```

- `target/criterion/<group>/<variant>/<baseline>/estimates.json` — absolute ns (`mean.point_estimate`)
- `target/criterion/<group>/<variant>/change/estimates.json` — fractional change vs the selected baseline (`+0.05` = 5% slower)
- Example (id convention in [benches/README.md](benches/README.md)): `target/criterion/get_hit/get_hit_funnel/change/estimates.json`.

Run shape and options:

- Pins the core, disables ASLR, and uses the batch scheduler without privileges; `sudo` adds `nice` and memlock, then drops back to the invoking user for cargo.
- Linux runs lock the pinned core and the Criterion output root, so concurrent
  runs serialize. With `CORE` unset the script picks a max-frequency core; an
  explicit `CORE=<n>` skips that selection but is still locked.
- `BENCH=all` (default) runs `speedup`, then `mean_latency`; set `BENCH=speedup|mean_latency` for one target.
- Other `[[bench]]` targets are not in `all`; run explicitly via
  `BENCH=<name>`: `set_ops`, `map_api`, `load_factor`, `payload_size`, and
  `scaled_insert` (reused-map insert sweep). `SCALED_INSERT_SIZES` overrides
  are for smoke runs only; evidence uses the default sizes.
- `memory` is a plain-`main` footprint report (TSV, deterministic counts), not
  Criterion: `cargo bench --profile release --bench memory`.
- Pass through Criterion flags with `--`: `SAVE=opt1 scripts/bench.sh -- --measurement-time 10`.
- Filter by Criterion name: `SAVE=opt1 scripts/bench.sh -- "get_hit_latency"`. The script strips a leading `--`, so both forms work.
- Python: `benches/python/throughput.py` (pytest-benchmark); see [benches/README.md](benches/README.md#python).

### CodSpeed CI

`.github/workflows/codspeed.yml` runs `cargo codspeed build --bench speedup` then `cargo codspeed run`, plus `pytest benches/python/throughput.py --codspeed`, on every PR. The `criterion` dev-dep is a package rename to `codspeed-criterion-compat`; don't revert. It counts simulated instructions, not wallclock; `scripts/bench.sh` stays the local ground truth.

### Methodology

- Re-save the anchor whenever a fixture constant changes (`OP_COUNT`, `MAP_SIZE`, `LATENCY_SIZES`). Comparing across different workloads makes `change/` deltas meaningless.
- Treat unchanged controls (`std`, `hashbrown`) as the run's noise floor. Large movement in controls weakens any conclusion about `elastic` or `funnel`.
- Rebuild before reading `callgrind`/CodSpeed output — stale binaries silently report pre-change asm. Check binary mtime against the commit you intend to measure.

## Project Structure

- `src/map.rs` — generic public `HashMap` shell and the single `TableBackend` contract both backends implement.
- `benches/harness/` — unpublished `opthash-bench-harness` workspace crate (dev-dep `harness`) with shared fixtures and Criterion helpers.

Modules with children use `foo.rs` + `foo/` (no `mod.rs`; `clippy::mod_module_files` enforces it). `tests/support/mod.rs` is the exception: a `tests/support.rs` would build as its own test crate.
Large modules keep unit tests in a sibling `<module>/tests.rs` (`mod tests;`); small ones keep them inline.

Don't duplicate primitives across `src/` and `benches/`.

## Comments and Docs

- Every item earns its place: no dead code, self-explanatory comments, or docs restating the signature. Keep SAFETY, invariants, and non-obvious "why".
- No raw numbers, benchmark results, or experiment history in comments or docs; put them in commit bodies and PR descriptions.

## Worktree Naming

When spawning a worktree, name its branch after the work (e.g. `feat/std-parity-mut-iters`) and pass the same name to `git worktree add`.

## Refactoring Guidelines

### Design Priorities

- Import types and traits, but call free functions through their owning module
  (for example, `probe::elastic_phi`). Do not flatten internal functions through
  `mod.rs`; keep crate-root re-exports limited to the curated public interface.
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
- Adding a field to a hot struct (`ElasticTable`/`FunnelTable`, Elastic's `Level`, Funnel's `FunnelShape`/`LevelShape`) is a layout change. Downstream fields can shift across cache lines and regress lookups with no semantic change. Measure offsets _and_ bench.
- Pure refactors (rename, extract, no logic change) can swing results from icache and branch-predictor layout shifts. A no-op refactor should leave CodSpeed sim instr-count at ±0.
