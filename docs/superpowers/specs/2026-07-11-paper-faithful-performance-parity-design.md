# Paper-Faithful Performance Parity Design

## Context

The exact-default implementation preserves the finite Elastic and Funnel
placement algorithms, but controlled comparisons against `main` exposed large
performance regressions. With stable `std` controls, ordered Elastic insert,
hit, and miss were approximately 11.5x, 8.4x, and 67x slower; Funnel was 2.0x,
2.9x, and 6.1x slower. Higher-level operations compound those primitive costs.

The objective is to reach or exceed `main` throughput and latency without
changing the paper's logical algorithms, constants, geometry, probe order, or
guarantees. Triangular group probing and lookup indexes that bypass the paper
query are outside the allowed design.

## Goals

- Reach control-normalized performance parity with `main` for insert, random
  and ordered hit lookup, miss lookup, and scaled insert.
- Preserve the exact scalar placement and query traces.
- Retain no-reordering behavior within a paper-comparable allocation epoch.
- Use architecture-aware SIMD, batching, prefetch, and cached invariant state
  where they do not alter logical results.
- Keep auxiliary metadata when it provides a measured net benefit. There is no
  fixed memory cap, but heap use and hot-structure layout are benchmark inputs.
- Restore a concise, accurate library README with layout diagrams and technical
  references.
- Replace the oversized Criterion manifest subsystem with a small compatibility
  sidecar while retaining protection against invalid comparisons.
- Remove the test-only floating duplicate of the default reserve fraction.

## Non-goals

- Reintroducing SwissTable triangular probing as an Elastic probe sequence.
- Probing additional Funnel buckets within an ordinary level.
- Adding a hash-to-slot index or location cache that skips earlier paper probes.
- Changing `phi`, `f(epsilon)`, `c=8`, `alpha`, `beta`, reserve defaults, range
  reduction, retry caps, or exceptional-recovery conditions.
- Claiming parity when unchanged controls or fixture provenance make an A/B
  comparison inconclusive.

## Logical invariants

For every key, table state, and supported geometry:

- Scalar and optimized code generate the same probe words and reduced indices,
  including rejection retries.
- Elastic insertion examines the same logical `h(i,j)` sequence and selects the
  same first permitted free slot in Cases 1, 2, and 3.
- Elastic lookup consumes candidates in exact `phi` order and returns the same
  first matching location.
- Funnel selects one identical bucket per ordinary level, scans its `beta`
  logical slots in order, applies the same B limit, and alternates C-A/C-B with
  the same tie rule.
- Vector loads may fetch later valid control bytes speculatively, but later
  lanes cannot influence the result before all earlier logical lanes fail.
- SIMD padding is readable but never selectable.

The independent scalar oracle remains test-only and is the trace authority.

## Benchmark provenance simplification

Criterion continues to own named baseline directories. `scripts/bench.sh`
retains pinning, locking, NUMA policy, and named `SAVE`/`LOAD` workflows, but the
prepare/publish/hydrate/discard transaction protocol is removed.

After a successful named run, the runner atomically writes one JSON sidecar
containing:

- target, baseline, filter, Criterion arguments, and timestamp;
- Git commit and dirty state;
- a source fingerprint, plus a separate deterministic methodology hash over
  benchmark, fixture, Cargo configuration, and runner files;
- CPU identity, selected core, operating system, and `rustc -vV`;
- the measured Criterion registration IDs.

The source fingerprint is checked before and after measurement so a source
change during a run prevents publication. Before `LOAD` or `BASELINE`, the
runner rejects missing metadata, differing
methodology, fixture, hardware/core, filters, or registration sets. Source
hashes are recorded but may differ between baseline and candidate by design.
A final evidence run must also report a clean source tree. A failed or
interrupted run has no sidecar and therefore cannot be used as evidence.
Artifact copying, per-artifact hashes, hard-coded fixture values,
hard-coded registration schemas, and transaction directories are removed.

Filtered runs are comparable only with runs using the same filter and resulting
registration set. All Criterion targets may use the same sidecar mechanism;
charts still require complete headline targets.

## Exact-probe acceleration

### Shared probe layer

`src/common/exact/probe.rs` keeps scalar functions as the reference and adds
architecture-specific batch implementations behind the existing compile-time
SIMD selection. Batch APIs accept consecutive logical probe descriptors and
produce bit-identical words or indices. Rejected lanes remain active until
their exact retry succeeds or reaches the existing cap.

The implementation starts with arithmetic-only vectorization. Control-byte
gathering is introduced separately so its cache effect can be measured.
Portable scalar behavior remains available for `no_std` and unsupported CPUs.

### Elastic

Optimization proceeds in independently measured stages:

1. Cache epoch-constant level lanes, range state, and query route state without
   enlarging hot structures until offsets and heap cost are measured.
2. Generate Case 1 and uniform-vacancy candidate indices in batches; select the
   earliest free logical probe.
3. Batch consecutive query routes in `phi` order, pipeline their control-byte
   reads, and compare candidate entries in order.
4. Test software prefetch and supported gather implementations independently.
5. Test a cheaper membership calculation and delayed negative checkpoint after
   a prefix that contains most successful hits. The checkpoint is accepted only
   when misses improve and hit latency remains within the control noise floor.

No batch changes the logical probe budget. Duplicate candidate positions remain
duplicate logical probes.

### Funnel

The existing ordered SIMD bucket scans remain. Additional stages are:

1. Batch or pipeline exact per-level bucket-index generation.
2. Prefetch later level controls while consuming levels in order.
3. Batch B candidates and C bucket choices while retaining their exact logical
   order and limits.
4. Evaluate an epoch membership filter for negative queries, with the same
   no-hit-regression gate as Elastic.

## Performance workflow and acceptance

The baseline is the `main` implementation compiled against the current fixture
and benchmark sources in an isolated worktree. This provides identical random
and ordered traces for both implementations. Python extensions are rebuilt in
release mode in separate environments and their native module paths are
verified before measurement.

For each experiment:

1. Save one clean pinned anchor.
2. Save the single changed variant on the same core.
3. Read `mean.point_estimate` and confidence intervals from JSON.
4. Normalize against unchanged `std` and `hashbrown` controls.
5. Reject the run as inconclusive when either control moves by more than 5%.
6. Inspect instructions, cycles, cache misses, and branch misses for accepted
   wall-clock changes.
7. Remove the experiment if any headline workload regresses beyond the control
   noise floor.

Final parity requires each primitive and scaled workload to be no more than 5%
slower than the control-normalized `main` result, with overlapping uncertainty
or a confirming rerun. Higher-level Rust and Python workloads must not regress.
Parity is a target, not a license to substitute an unproven algorithm: if all
trace-preserving approaches are exhausted without parity, the measured limit is
reported explicitly.

## Tests and verification

- Golden vectors for scalar and every SIMD batch width.
- Exhaustive small-range and awkward-range retry equivalence.
- Scalar-oracle placement and query trace equivalence across geometry grids.
- First-success tests with empty, occupied, tombstoned, duplicate, and padded
  lanes at every batch boundary.
- Structure size, field offset, arena alignment, and heap-accounting tests for
  new metadata.
- Benchmark-runner tests for atomic sidecars, interrupted runs, dirty sources,
  filters, incompatible methodology/hardware, and matching comparisons.
- `cargo test`, all Python tests, pre-commit, strict Clippy, `no_std`, benchmark
  smoke builds, package verification, and deterministic chart generation.

## Library hygiene and README

`src/common/config.rs` retains architecture constants only. Its test-only
`DEFAULT_RESERVE_FRACTION` is removed, and the three Elastic tests use
`ReserveFraction::DEFAULT` with the exact reserve constructor.

The README replaces the long fidelity discussion with a compact scope note and
restores an accurate text layout:

- one arena with control regions, aligned entry regions, and Elastic membership
  metadata;
- Elastic arrays `A_1..A_k` with exact `h(i,j)` and `phi` query order;
- Funnel ordinary `beta`-slot buckets followed by B and C.

References cover the paper, its hashing model, SwissTable control-byte SIMD,
hashbrown as the performance ceiling, and foldhash as the default hasher. The
diagram must not mention triangular probing as part of the exact defaults.

## Review and delivery

Work is split into reviewable commits: benchmark metadata simplification,
reserve/config hygiene, shared exact-probe batches, Elastic acceleration,
Funnel acceleration, and README/final evidence. Disposable experiments remain
outside the final history. Generated results are retained only when they are
fresh, source-identified, and reproducible from the documented workflow.
