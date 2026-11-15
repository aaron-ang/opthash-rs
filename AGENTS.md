# AGENTS.md

`opthash` implements the Elastic and Funnel hash tables of
[arXiv 2501.02305](https://arxiv.org/abs/2501.02305) behind one `HashMap`
shell. The paper fixes where a key may go ([Paper Bounds](#paper-bounds));
everything about how fast the table gets there is open to measurement.

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

## Paper Bounds

The paper ([arXiv 2501.02305](https://arxiv.org/abs/2501.02305)) proves its
probe bounds for an idealised table. A refactor or optimization may change
whatever those proofs do not use. They use structure, which the code keeps
exactly, and randomness, which no implementation has and the code
approximates.

Structure is a hard limit, and the test oracle checks it:

- Elastic: the level sizes, the batches and their fill thresholds, the three
  insertion cases with their probe budget, first-free placement along a
  level's probe sequence, and the lookup order over `(level, probe)` pairs.
- Funnel: the level and bucket geometry, one bucket per key in each level,
  levels tried in order, and the special array's bounded probing half and
  two-choice half.
- Both: no reordering. A placed entry moves only in a rebuild.

Randomness is a matter of evidence. The proofs take every probe as a uniform
draw from its level, independent across keys, across one key's probes in a
level, and across levels. One 64-bit hash cannot supply that, so every
probe-word construction relates a key's probes somehow. A construction stays
when its PR does all of this:

- Shows each probe is uniform over its range, or states and bounds the bias.
- Names the relation it introduces between a key's probe words and the keys
  that relation would hurt, then measures how often the key families below
  produce such keys and what each occurrence costs.
- Compares per-level occupancy and probe lengths (mean and tail) with the
  construction it replaces, at partial and full load, for a mixing hasher and
  for an identity hasher over sequential, multiplicative, and shifted keys.
- Shows no special-array use and no exceptional placement in any of those
  runs.

A construction that fails any of these does not stay, whatever it saves.

Everything else is outside the paper and free to change: deletion and
tombstones, resizing, the membership filter, control bytes, and any path
that only reaches the same answer sooner. The paper bounds lookups of
present keys only, so how fast an absent key is rejected is this crate's own
design. Such a path must return what the
ordered walk returns and place where the placement walk places, and a
differential test against that walk shows it.

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
- Sets `GLIBC_TUNABLES=glibc.malloc.hugetlb=1` for the measured run, so large
  fixtures get transparent huge pages and DRAM-bound groups stop shifting with
  physical page placement. A caller-set value wins; an empty one opts out.
- Keep heavy work (VMs, builds) off the machine during evidence runs. The
  core pin keeps the bench on one core but does not keep other processes off
  it, and the L3, DRAM bandwidth, and power budget stay shared.
- Linux runs lock the pinned core and the Criterion output root, so concurrent
  runs serialize. With `CORE` unset the script picks a max-frequency core; an
  explicit `CORE=<n>` skips that selection but is still locked.
- `BENCH=all` (default) runs `speedup`, then `mean_latency`; set `BENCH=speedup|mean_latency` for one target.
- Other `[[bench]]` targets are not in `all`; run explicitly via
  `BENCH=<name>`: `set_ops`, `map_api`, `load_factor`, `payload_size`,
  `scaled_insert` (reused-map insert sweep), and `high_load` (87.5–99.9% load
  vs the `group_probe` baseline). `SCALED_INSERT_SIZES` overrides
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

Import types and traits, but call free functions through their owning module
(for example, `probe::elastic_phi`). Do not re-export internal functions from
a parent module; keep crate-root re-exports limited to the curated public
interface.

## Comments and Docs

- Every item earns its place: no dead code, self-explanatory comments, or docs restating the signature. Keep SAFETY, invariants, and non-obvious "why".
- No raw numbers, benchmark results, or experiment history in comments or docs; put them in commit bodies and PR descriptions.

## Worktree Naming

When spawning a worktree, name its branch after the work (e.g. `feat/std-parity-mut-iters`) and pass the same name to `git worktree add`.

## Performance Work

### Design Priorities

These priorities are defaults, not limits. When a measurement disagrees with
one, build the variant and let instruction counts and `scripts/bench.sh`
decide; name the default it departs from in the PR.

- Prefer layout and locality wins before adding more metadata. Keep hot metadata contiguous — if fields are read together, store them together.
- Cache routing state that's reused in hot paths instead of recomputing it per probe.
- Preserve SIMD-friendly control-byte scans: contiguous groups, cheap bitmask iteration, early rejection before touching payloads.
- Keep values the compiler can fold (geometry, shifts, strides) as constants. A runtime field costs a load per probe and stops the compiler from turning a multiply or divide into a shift.
- Measure wide constants instead of assuming. Building a 64-bit immediate can take more instructions than one load from a hot struct, and the answer differs by target.
- Prefer a change that removes work from every operation over a fast path for one case. A fast path has to pay for its lines, its extra state, and the differential test that pins it to the general path.

### Reject

- Metadata that costs work on every insert/delete unless benchmarks prove a net win.
- Size or load thresholds taken from a sweep on one machine. Derive a threshold from a mechanism that holds on other hardware, set it to a conservative bound documented as one, or choose the variant that needs none; say in the PR which machines were measured.
- Optimizations that improve a narrow microbenchmark but regress the public `speedup` suite. `target/criterion/` is the final gate — if the relevant benchmark regresses, the change does not stay.

### Verification

- Read the asm (`objdump -d`) on hot functions before factoring shared SIMD or arithmetic primitives. LLVM already CSEs same-pointer control-byte loads and folds duplicate masks; a "cleaner" abstraction may save nothing.
- Compare instruction counts first: they do not move with machine load, so they settle an A/B that cycles cannot. Cycles and `scripts/bench.sh` then decide whether the saved instructions were on the critical path.
- Confirm hot-path wins with `perf stat` (cycles, instructions, cache-misses, branch-misses) on a pinned run; a real win moves the matching counter, not just wallclock.
- Adding a field to a hot struct (`ElasticTable`/`FunnelTable`, Elastic's `Level`, Funnel's `FunnelShape`/`LevelShape`) is a layout change. Downstream fields can shift across cache lines and regress lookups with no semantic change. Measure offsets _and_ bench.
- Pure refactors (rename, extract, no logic change) can swing results from icache and branch-predictor layout shifts. A no-op refactor should leave CodSpeed sim instr-count at ±0.
