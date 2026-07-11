# Exact-Probe Performance Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reach control-normalized `main` performance with the exact Elastic and Funnel algorithms, or produce conclusive evidence that trace-preserving machine optimizations cannot close a remaining gap.

**Architecture:** Scalar exact probing remains the oracle. Fixed-width batch APIs generate bit-identical probe indices, architecture-specific arithmetic accelerates those APIs, and map hot paths consume batched candidates strictly in logical order. Every optimization is isolated, trace-tested, benchmarked, and either committed or removed.

**Tech Stack:** Stable Rust 1.88+, `core::arch` NEON/SSE/AVX intrinsics, Criterion, perf, objdump, Python/maturin.

## Global Constraints

- Execute the benchmark metadata simplification plan first.
- Preserve `phi`, Case 1/2/3, `f(epsilon)`, `c=8`, `alpha`, `beta`, reserve defaults, retry caps, and first-success order.
- Do not add triangular probing, additional Funnel buckets, or a hash-to-slot lookup index.
- Scalar and optimized probe outputs must be bit-identical for every tested tuple and retry.
- Reject changes that regress any headline workload beyond stable-control noise.
- Final parity means no more than 5% slower than the control-normalized `main` implementation on identical current fixtures.
- Adding metadata is allowed, but field offsets, heap cost, and cache counters must be reported.

---

### Task 1: Build trustworthy `main` and exact anchors

**Files:**
- Modify only in disposable worktree: current `benches/`, `scripts/`, `Cargo.toml`, and `Cargo.lock` applied over `main` implementation sources.
- Evidence: external Criterion root `/tmp/opthash-parity-criterion`.

**Interfaces:**
- Produces named baselines `main-current-fixtures` and `exact-anchor` with identical methodology metadata.

- [ ] **Step 1: Create isolated baseline worktrees**

```bash
git worktree add /tmp/opthash-perf-main -b perf/main-current-fixtures main
git worktree add /tmp/opthash-perf-exact -b perf/exact-anchor HEAD
```

- [ ] **Step 2: Apply only the current benchmark harness to the main worktree**

```bash
git -C /tmp/opthash-perf-main restore --source=perf/exact-anchor -- \
  benches scripts Cargo.toml Cargo.lock build.rs pyproject.toml uv.lock AGENTS.md
git -C /tmp/opthash-perf-main diff -- src
```

Expected: the second command has no output; `main` library sources remain
unchanged while fixtures and runner match the exact branch.

Commit the disposable harness so its metadata reports a clean source:

```bash
git -C /tmp/opthash-perf-main add benches scripts Cargo.toml Cargo.lock \
  build.rs pyproject.toml uv.lock AGENTS.md
git -C /tmp/opthash-perf-main commit -m "bench: apply current fixtures to main"
```

- [ ] **Step 3: Run clean pinned primitive anchors serially**

```bash
OPTHASH_CRITERION_ROOT=/tmp/opthash-parity-criterion \
SAVE=main-current-fixtures BENCH=speedup /tmp/opthash-perf-main/scripts/bench.sh -- \
'^(insert|get_hit|get_hit_sequential|get_miss)/'
```

```bash
OPTHASH_CRITERION_ROOT=/tmp/opthash-parity-criterion \
SAVE=exact-anchor BENCH=speedup /tmp/opthash-perf-exact/scripts/bench.sh -- \
'^(insert|get_hit|get_hit_sequential|get_miss)/'
```

Expected: both metadata sidecars report identical methodology, filter, core,
hardware, rustc, and registration IDs; source fingerprints differ.

- [ ] **Step 4: Capture baseline structure sizes and native module paths**

Run the existing layout tests and record `size_of`/offset output for
`ElasticTable`, `FunnelTable`, `Level`, `FunnelShape`, and `LevelShape` in the
task report. Build both Python extensions in separate `.venv` directories and
verify `opthash.opthash.__file__` points into the intended worktree.

- [ ] **Step 5: Commit only reusable fixture corrections, not disposable worktree state**

If no fixture correction is needed, create no commit. Delete any invalid anchor
and rerun rather than editing its metadata.

### Task 2: Add scalar pair APIs as the equivalence seam

**Files:**
- Modify: `src/common/exact/probe.rs`
- Modify: `src/common/exact/mod.rs`

**Interfaces:**
- Produces: `unbiased_prepared_elastic_probe_index_pair(...) -> [Result<ProbeIndex, RangeReductionError>; 2]`
- Produces: `unbiased_prepared_funnel_probe_index_pair_in_ranges(...) -> [Result<ProbeIndex, RangeReductionError>; 2]`

- [ ] **Step 1: Write failing pair-equivalence tests**

```rust
#[test]
fn elastic_pair_matches_two_scalar_reductions() {
    let prepared = CounterPrf::new(7).prepare_elastic(11);
    for level in 0..8_u64 {
        let probe = prepared.prepare_level_lane(PreparedElasticProbe::level_lane(level));
        for logical in 0..128_u64 {
            for upper in [1, 2, 3, 7, 8, 31, 32, 257] {
                let lanes = [
                    PreparedElasticProbe::logical_probe_lane(logical),
                    PreparedElasticProbe::logical_probe_lane(logical + 1),
                ];
                let pair = unbiased_prepared_elastic_probe_index_pair(
                    [probe, probe], lanes, [upper, upper], 8,
                );
                assert_eq!(
                    pair,
                    lanes.map(|lane| unbiased_prepared_elastic_probe_index(&probe, lane, upper, 8))
                );
            }
        }
    }
}
```

Add the analogous Funnel test over every domain, logical index `0..32`, and
ranges `[1, 3, 6, 17, 257]`.

```rust
#[test]
fn funnel_pair_matches_two_scalar_reductions() {
    let prepared = FunnelPrf::new(7).prepare(11);
    for domain in [
        ProbeDomain::FunnelOrdinary { level: 0 },
        ProbeDomain::FunnelOrdinary { level: 31 },
        ProbeDomain::FunnelSpecialPrimary,
        ProbeDomain::FunnelSpecialFallbackChoiceA,
        ProbeDomain::FunnelSpecialFallbackChoiceB,
    ] {
        let probe = prepared.prepare_domain(domain).unwrap();
        for logical in 0..32_u64 {
            for upper in [1, 3, 6, 17, 257] {
                let logicals = [logical, logical + 1];
                let range = PreparedProbeRange::new(upper).unwrap();
                let pair = unbiased_prepared_funnel_probe_index_pair_in_ranges(
                    [probe, probe], logicals, [range, range], 8,
                );
                assert_eq!(pair, core::array::from_fn(|lane| {
                    unbiased_prepared_funnel_probe_index_in_range(
                        &probe, logicals[lane], range, 8,
                    )
                }));
            }
        }
    }
}
```

- [ ] **Step 2: Run tests and verify missing-function failures**

Run: `cargo test common::exact::probe::tests::elastic_pair_matches_two_scalar_reductions`

Expected: compile failure because the pair API does not exist.

- [ ] **Step 3: Implement scalar pair APIs**

```rust
pub(crate) fn unbiased_prepared_elastic_probe_index_pair(
    probes: [PreparedElasticLevelProbe; 2],
    lanes: [u64; 2],
    uppers: [usize; 2],
    max_random_words: u32,
) -> [Result<ProbeIndex, RangeReductionError>; 2] {
    core::array::from_fn(|index| {
        unbiased_prepared_elastic_probe_index(
            &probes[index], lanes[index], uppers[index], max_random_words,
        )
    })
}
```

Implement the Funnel function with the same `array::from_fn` pattern and its
single-lane prepared range reducer.

- [ ] **Step 4: Run equivalence and full exact tests**

Run: `cargo test common::exact::probe::tests`

Expected: all probe tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/common/exact/probe.rs src/common/exact/mod.rs
git commit -m "refactor: add exact probe pair seams"
```

### Task 3: Add AArch64 NEON pair arithmetic

**Files:**
- Modify: `src/common/exact/probe.rs`
- Modify: `build.rs`

**Interfaces:**
- Produces private `mix64_pair([u64; 2]) -> [u64; 2]` under `opthash_neon_group`.
- Scalar builds retain `values.map(mix64)`.

- [ ] **Step 1: Write exhaustive mixer equivalence tests**

```rust
#[test]
fn pair_mixer_matches_scalar_golden_values() {
    for left in [0, 1, u64::MAX, INITIAL_LANE, KEY_LANE] {
        for right in [0, 1, u64::MAX, PROBE_LANE, REJECTION_LANE] {
            assert_eq!(mix64_pair([left, right]), [mix64(left), mix64(right)]);
        }
    }
}
```

- [ ] **Step 2: Run and verify failure**

Run: `cargo test pair_mixer_matches_scalar_golden_values`

Expected: compile failure because `mix64_pair` is undefined.

- [ ] **Step 3: Implement NEON and scalar mixer pairs**

For AArch64, perform the exact two SplitMix finalizer rounds lane-wise:

```rust
#[cfg(opthash_neon_group)]
#[inline(always)]
fn mix64_pair(values: [u64; 2]) -> [u64; 2] {
    use core::arch::aarch64::{
        vdupq_n_u64, veorq_u64, vld1q_u64, vmulq_u64, vshrq_n_u64, vst1q_u64,
    };

    unsafe {
        let mut lanes = vld1q_u64(values.as_ptr());
        lanes = veorq_u64(lanes, vshrq_n_u64::<30>(lanes));
        lanes = vmulq_u64(lanes, vdupq_n_u64(0xbf58_476d_1ce4_e5b9));
        lanes = veorq_u64(lanes, vshrq_n_u64::<27>(lanes));
        lanes = vmulq_u64(lanes, vdupq_n_u64(0x94d0_49bb_1331_11eb));
        lanes = veorq_u64(lanes, vshrq_n_u64::<31>(lanes));
        let mut output = [0; 2];
        vst1q_u64(output.as_mut_ptr(), lanes);
        output
    }
}
```

For other targets, use:

```rust
#[inline(always)]
fn mix64_pair(values: [u64; 2]) -> [u64; 2] {
    values.map(mix64)
}
```

Do not enable a runtime feature or change control-group width. Reuse the
existing `opthash_neon_group`; `build.rs` needs no new cfg unless compilation
proves the arithmetic and control-scan capabilities must be separated.

- [ ] **Step 4: Use pair arithmetic only inside pair APIs**

For Elastic, vectorize both lanes of
`mix64(level_state + logical_probe_lane)` and the final mix after adding the
unchanged rejection-zero lane. For Funnel, vectorize
`mix64(counter ^ key_in)` and xor each result with its original `key_out`.
Perform exact range reduction per lane in array order. Any non-power-of-two
rejection falls back to the existing scalar retry function for only that lane.

- [ ] **Step 5: Verify outputs and assembly**

Run: `cargo test common::exact::probe::tests`

Expected: every golden and equivalence test passes.

Run: `cargo rustc --release --lib -- --emit=obj`

Run: `find target/release/deps -name 'opthash-*.o' -print0 | xargs -0 objdump -d | rg -n "mul|eor|ushr"`

Expected: the pair path contains vector `mul`/shift/xor instructions on AArch64.

- [ ] **Step 6: Benchmark the seam in isolation**

Add a temporary Criterion filter or callgrind harness that consumes pair
outputs. Retain the NEON implementation only if instruction count and cycles
improve over two scalar calls. Remove the temporary harness afterward.

- [ ] **Step 7: Commit accepted code**

```bash
git add build.rs src/common/exact/probe.rs
git commit -m "perf: vectorize exact probe pairs on aarch64"
```

### Task 4: Batch Elastic insertion probes

**Files:**
- Modify: `src/elastic.rs:1431-1585`
- Modify: `src/common/exact/reference.rs` only for test-visible trace data
- Test: inline `src/elastic.rs` tests

**Interfaces:**
- Consumes: Elastic pair reducer from Task 2.
- Produces: private `first_vacancy_in_range(..., logical_start: u64, logical_end: u64)` that checks pair results in logical order.

- [ ] **Step 1: Add scalar-vs-batched placement trace tests at pair boundaries**

Extend the existing `assert_exact_trace` fixture to collect every
`ExactPlacement`. Add a test-only scalar candidate consumer that uses the
single-lane reducer and a batched consumer that uses the pair reducer. Test
budgets `1, 2, 3, 7, 8, 31, 32`, free slots at each first/second lane,
duplicate candidate indices, and rejection fallback. Assert the candidate
prefixes and complete `ExactPlacement` values equal the scalar oracle.

- [ ] **Step 2: Run tests against the scalar implementation**

Run: `cargo test elastic::tests::batched_insertion_preserves_every_pair_boundary`

Expected: compile failure because the batched helper is undefined.

- [ ] **Step 3: Implement ordered pair consumption**

```rust
let mut logical = logical_start;
while logical + 1 < logical_end {
    let lanes = [
        PreparedElasticProbe::logical_probe_lane(logical),
        PreparedElasticProbe::logical_probe_lane(logical + 1),
    ];
    let reduced = unbiased_prepared_elastic_probe_index_pair(
        [*probe, *probe], lanes, [upper, upper], RANGE_WORD_CAP,
    );
    for (offset, result) in reduced.into_iter().enumerate() {
        let slot = result.ok()?.index;
        if self.levels[level].control_at(slot).is_free() {
            return Some((slot, logical + offset as u64 + 1));
        }
    }
    logical += 2;
}
```

Handle the remaining lane with the existing scalar function. Use this helper
for Case 1 budgets and uniform vacancy without changing their limits.

- [ ] **Step 4: Run trace and correctness suites**

Run: `cargo test elastic::tests`

Run: `cargo test common::exact::reference::tests`

Expected: all tests pass.

- [ ] **Step 5: Run pinned insert A/B**

Save the variant as `elastic-insert-pair` against `exact-anchor`. Read JSON and
controls. Keep it only if Elastic insert improves and no other speedup group
regresses beyond controls.

- [ ] **Step 6: Inspect counters**

Run pinned `perf stat` for insert with cycles, instructions, cache misses, and
branch misses. Confirm the measured win corresponds to lower instructions or
cycles.

- [ ] **Step 7: Commit or remove**

If accepted:

```bash
git add src/elastic.rs
git commit -m "perf: batch exact elastic insertion probes"
```

If rejected, remove only this task's diff with `apply_patch` and retain the
benchmark report outside the final tree.

### Task 5: Batch Elastic query routes

**Files:**
- Modify: `src/elastic.rs:1645-1712`
- Modify: `src/common/exact/reference.rs` for a test-only public trace snapshot
- Modify: inline Elastic tests

**Interfaces:**
- Consumes: exact probe pair reducer.
- Preserves: the existing `PhiRoute` layout unless measured offsets justify a change.

- [ ] **Step 1: Write pair-boundary query trace tests**

Add `#[cfg(test)] pub(crate) struct ScalarElasticQueryTrace` containing the
found location plus the ordered global-slot inspections, and expose
`ScalarElastic::query_trace`. For hits at route ranks `0, 1, 2, 7, 8, 31, 32`,
assert that batched lookup returns the same slot and records the same
compared-route prefix as the scalar oracle. Include complete misses and
exceptional full-scan fallback.

- [ ] **Step 2: Run and verify failure**

Run: `cargo test elastic::tests::batched_query_preserves_phi_prefixes`

Expected: failure because the batched query path is not implemented.

- [ ] **Step 3: Consume route pairs in `phi` order**

Use `probe_schedule.chunks_exact(2)`. Prepare both level states, reduce both
indices with their exact `range_upper`, inspect the first candidate, and inspect
the second only when the first is not a hit. Process `chunks.remainder()` with
the scalar path. Keep `h(1,1)` first and unchanged.

- [ ] **Step 4: Run fidelity and map parity suites**

Run: `cargo test elastic::tests::batched_query_preserves_phi_prefixes`

Run: `cargo test --test map_parity elastic_parity`

Expected: all tests pass.

- [ ] **Step 5: Run pinned random and ordered hit A/B**

Save `elastic-query-pair`, compare with `exact-anchor`, and inspect JSON. Keep
only if both random and ordered Elastic hits improve with stable controls and
insert/miss do not regress.

- [ ] **Step 6: Test prefetch as a separate single-variable experiment**

Add `simd::prefetch_read(ptr)` using AArch64 `prfm pldl1keep`, x86 `_mm_prefetch`,
and a scalar no-op. Prefetch only the second valid control pointer before
checking the first. Run the same A/B; retain prefetch only if both scale and
headline hits improve.

- [ ] **Step 7: Commit accepted changes**

```bash
git add src/common/simd.rs src/elastic.rs
git commit -m "perf: pipeline exact elastic query routes"
```

### Task 6: Add a delayed Elastic negative checkpoint

**Files:**
- Modify: `src/elastic.rs` membership and query path
- Modify: inline Elastic tests

**Interfaces:**
- Preserves every positive query prefix.
- Negative early return is permitted only after a fixed exact-route prefix.

- [ ] **Step 1: Write membership and hit-prefix tests**

Assert no false negatives after insert, delete, clone, clear, growth, cleanup,
and recovery. Instrument tests to prove hits before the checkpoint never call
the membership predicate and later hits return the same exact location.

- [ ] **Step 2: Optimize power-of-two membership indexing**

Use a mask when `membership_words().is_power_of_two()` and retain exact
multiply-high indexing for arbitrary internal geometries. Run all membership
tests before changing query behavior.

- [ ] **Step 3: Sweep fixed checkpoints**

Test checkpoints after `h(1,1)` and after exact route counts `2, 8, 32`. Each
variant is a separate A/B against the same anchor. Record random hit, ordered
hit, miss, mixed, and insert.

- [ ] **Step 4: Apply the acceptance rule**

Select the earliest checkpoint whose hit and insert deltas stay within stable
control noise and whose miss result is best. If none qualifies, retain only the
membership arithmetic change when it independently improves insert.

- [ ] **Step 5: Commit accepted code**

```bash
git add src/elastic.rs
git commit -m "perf: reject elastic misses after an exact prefix"
```

### Task 7: Pipeline Funnel exact choices

**Files:**
- Modify: `src/common/exact/probe.rs`
- Modify: `src/common/exact/reference.rs` for test-only ordered inspection traces
- Modify: `src/funnel.rs:478-610`
- Modify: inline Funnel tests

**Interfaces:**
- Consumes: Funnel pair reducer.
- Preserves: one bucket per ordinary level, ordered `beta` scan, B cap, and alternating C order.

- [ ] **Step 1: Write scalar-vs-pipelined Funnel trace tests**

Add a `#[cfg(test)] ScalarFunnelSearchTrace` snapshot to the retained scalar
oracle. Cover hits and first empties in both lanes of paired levels, full
buckets, tombstones, B logical probes, C-A/C-B ties, and range-reduction
retries. Assert complete ordered global-slot sequences equal the scalar oracle.

- [ ] **Step 2: Pair ordinary bucket choices**

Generate bucket indices for two consecutive levels, prefetch both bucket control
starts, scan the first bucket, and scan the second only if the first is full.
Process an odd final level with the scalar path.

- [ ] **Step 3: Pair B and C choice generation**

Generate B logical probes in pairs but inspect in order. Generate C bucket A
and B together, then retain exact A0, B0, A1, B1 ordering and tie behavior.

- [ ] **Step 4: Run Funnel fidelity tests**

Run: `cargo test funnel::tests`

Run: `cargo test common::exact::reference::tests`

Expected: all tests pass.

- [ ] **Step 5: Run pinned Funnel A/B**

Measure insert, random/ordered hits, miss, mixed, and delete-heavy. Retain each
pairing/prefetch stage only when the public speedup suite improves without a
headline regression.

- [ ] **Step 6: Evaluate a Funnel negative filter separately**

Reuse a shared arena-tail membership primitive only after its layout and insert
cost are measured. Sweep the same delayed checkpoints; do not add per-operation
metadata work unless miss improvement survives hit and insert gates.

- [ ] **Step 7: Commit accepted changes**

```bash
git add src/common/exact/probe.rs src/funnel.rs
git commit -m "perf: pipeline exact funnel choices"
```

### Task 8: Close parity gaps without changing the algorithm

**Files:**
- Modify only files implicated by measured hot counters.
- Evidence outside final tree.

**Interfaces:** None beyond existing exact batch APIs.

- [ ] **Step 1: Compare accepted branch with `main-current-fixtures`**

Run full `speedup`, `mean_latency`, and `scaled_insert` baselines serially on the
same core. Compute raw and `std`/`hashbrown`-normalized ratios from JSON.

- [ ] **Step 2: Profile every remaining gap above 5%**

For each gap, record `perf stat`, `perf record`, annotated assembly, and hot
structure offsets. State one root-cause hypothesis before making one change.

- [ ] **Step 3: Test only trace-preserving hypotheses**

Allowed categories are cached epoch constants, reduced dependent loads,
instruction scheduling, cold-path extraction, prefetch distance, batch width,
and metadata locality. Each hypothesis receives its own saved variant and is
removed if rejected.

- [ ] **Step 4: Stop at the architectural boundary**

If every remaining gap requires triangular probing, an auxiliary lookup index,
different probe randomness, changed constants, or changed placement/query
order, do not implement it. Record the smallest stable gap and the counter that
demonstrates the boundary.

- [ ] **Step 5: Commit each accepted independent optimization**

Use one `perf:` commit per measured cause; never combine rejected experiments
with accepted code.

### Task 9: Final evidence and verification

**Files:**
- Update: `assets/benchmark-speedup.svg`
- Update: `assets/benchmark-latency.svg`
- Update: `assets/benchmark-python-speedup.svg`
- Update: `benches/README.md` only for final source identifiers or methodology.

- [ ] **Step 1: Run full clean evidence baselines**

Run full pinned Rust suites with a clean source and strict metadata. Rebuild the
Python extension, verify its native path, and run all Python benchmarks.

- [ ] **Step 2: Regenerate every chart twice**

Expected: each second generation has the same SHA-256 as the first.

- [ ] **Step 3: Run all correctness and publication gates**

Run: `cargo test`

Run: `uv run pytest -q`

Run: `pre-commit run --all-files`

Run: `cargo clippy --all-targets --features=python -- -W clippy::pedantic -D warnings`

Run: `cargo rustc --no-default-features --lib --crate-type rlib`

Run: `cargo package --allow-dirty`

Expected: every command succeeds.

- [ ] **Step 4: Remove diagnostic worktrees and branches**

Remove `/tmp/opthash-perf-main` and `/tmp/opthash-perf-exact`, then delete the
`perf/main-current-fixtures` and `perf/exact-anchor` branches. Preserve named
external evidence until final ratios are recorded.

- [ ] **Step 5: Commit final evidence**

```bash
git add assets benches/README.md
git commit -m "docs: publish paper-faithful parity evidence"
```
