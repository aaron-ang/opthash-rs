# Library Hygiene and README Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove legacy implementation terminology and duplicated configuration, then restore a concise and accurate library README and fresh Python chart.

**Architecture:** `ReserveFraction::DEFAULT` is the sole reserve default. The exact optimized code is called the library implementation; the independent scalar oracle remains test-only. Documentation explains physical layout and algorithm shape without describing removed triangular behavior.

**Tech Stack:** Rust, Markdown, pytest-benchmark, Matplotlib SVG, Cargo packaging.

## Global Constraints

- Execute Tasks 1-3 after the benchmark metadata plan, then execute the exact
  performance plan. Return for Tasks 4-6 only after its final evidence task.
- Preserve the `#[cfg(test)]` scalar oracle as fidelity evidence.
- Remove every use of “production” as an implementation-mode distinction.
- Do not add public APIs or change runtime behavior in this plan.
- Keep the README concise and library-oriented.
- Retain only fresh generated benchmark assets and exclude workflow documents from the published crate.

---

### Task 1: Make `ReserveFraction::DEFAULT` the only default

**Files:**
- Modify: `src/common/config.rs:14-17`
- Modify: `src/elastic.rs` test module and three constructors
- Modify: `src/common/reserve.rs` tests

**Interfaces:**
- Consumes: `ReserveFraction::DEFAULT` and `with_capacity_and_reserve_and_hasher_in`.
- Removes: `common::config::DEFAULT_RESERVE_FRACTION`.

- [ ] **Step 1: Add a default round-trip test**

```rust
#[test]
fn default_is_exactly_one_eighth() {
    assert_eq!(ReserveFraction::DEFAULT.delta_log2(), 3);
    assert_eq!(ReserveFraction::DEFAULT.as_f64(), Some(0.125));
    assert_eq!(
        ReserveFraction::try_from(0.125),
        Ok(ReserveFraction::DEFAULT)
    );
}
```

- [ ] **Step 2: Run the reserve test**

Run: `cargo test common::reserve::tests::default_is_exactly_one_eighth`

Expected: pass, proving the exact type already owns the default.

- [ ] **Step 3: Convert Elastic tests to the exact constructor**

Replace each test call with:

```rust
ElasticTable::with_capacity_and_reserve_and_hasher_in(
    1024,
    ReserveFraction::DEFAULT,
    DefaultHashBuilder::default(),
    Global,
)
```

Remove the `DEFAULT_RESERVE_FRACTION` import and constant from `config.rs`.

- [ ] **Step 4: Run focused tests and absence check**

Run these commands separately:

```bash
cargo test elastic::tests::direct_lookup_returns_the_compared_slot_reference
cargo test elastic::tests::rebuild_inserts_advance_batch_scheduler
cargo test elastic::tests::insert_after_rebuild_advances_exhausted_batch
```

Expected: each test passes.

Run: `rg -n "DEFAULT_RESERVE_FRACTION" src`

Expected: no matches.

- [ ] **Step 5: Commit**

```bash
git add src/common/config.rs src/common/reserve.rs src/elastic.rs
git commit -m "refactor: centralize the default reserve"
```

### Task 2: Remove legacy “production” terminology

**Files:**
- Modify: `README.md`
- Modify: `src/elastic.rs`
- Modify: `src/funnel.rs`
- Modify: `src/common/exact/geometry.rs`
- Modify: `src/common/exact/probe.rs`
- Modify: `benches/support/common.rs`

**Interfaces:**
- Renames private test helper `production_case` to `exact_case`.
- Renames tests to `elastic_placement_matches_the_scalar_paper_model`, `funnel_locations_match_the_independent_scalar_oracle`, and `funnel_search_reaches_primary_and_alternating_fallback_in_order`.

- [ ] **Step 1: Establish the terminology gate**

Run: `rg -n -i "production" README.md src benches scripts tests`

Expected: the known legacy matches identify every edit in this task.

- [ ] **Step 2: Rename helpers, tests, comments, and diagnostics**

Use these exact replacements:

```text
production_case                                      -> exact_case
production_placement_matches_the_scalar_paper_model -> elastic_placement_matches_the_scalar_paper_model
production_locations_match_the_independent_scalar_oracle -> funnel_locations_match_the_independent_scalar_oracle
production_search_reaches_primary_and_alternating_fallback_in_order -> funnel_search_reaches_primary_and_alternating_fallback_in_order
production geometry                                 -> library geometry
production counter                                  -> library counter
production encoding                                 -> checked library encoding
production extensions                               -> library API extensions
production hasher                                   -> default hasher
```

- [ ] **Step 3: Run renamed fidelity tests**

Run: `cargo test elastic_placement_matches_the_scalar_paper_model`

Expected: pass.

Run: `cargo test funnel_locations_match_the_independent_scalar_oracle`

Expected: pass.

Run: `cargo test funnel_search_reaches_primary_and_alternating_fallback_in_order`

Expected: pass.

- [ ] **Step 4: Verify terminology is gone**

Run: `rg -n -i "production" README.md src benches scripts tests`

Expected: no matches.

- [ ] **Step 5: Commit**

```bash
git add README.md src benches/support/common.rs
git commit -m "refactor: name the exact path as the library implementation"
```

### Task 3: Restore a concise, accurate README layout

**Files:**
- Modify: `README.md:11-130`

**Interfaces:** None.

- [ ] **Step 1: Replace the long fidelity section with a compact scope paragraph**

The paragraph must state: exact finite geometry and placement apply within a
fixed allocation epoch; deletion, growth, and cleanup are library API
extensions; deterministic mixers instantiate but do not prove the paper's
randomness assumptions.

- [ ] **Step 2: Add the accurate layout sketch**

```text
Arena (one allocation)
  [control regions A1..Ak | SIMD padding | alignment | entries A1..Ak | Elastic membership]

ElasticHashMap
  A1 [################]  h(1,j)
  A2 [########]          h(2,j)     query order: phi(i,j)
  A3 [####]              h(3,j)

FunnelHashMap
  A1 [beta-slot buckets] -> A2 [beta-slot buckets] -> ... -> B -> C(a,b)
       one bucket/level       first empty in order       alternating choices
```

The surrounding text must say padding is readable but never selectable and
must not mention triangular probing.

- [ ] **Step 3: Restore concise references**

Include bullets for:

- Farach-Colton, Krapivin, and Kuszmaul with repository paper source and arXiv.
- Carter and Wegman for universal hashing context, without claiming the mixer
  is a universal family.
- Abseil SwissTable notes for control-byte SIMD only.
- hashbrown as the benchmark ceiling.
- foldhash as the default `BuildHasher`.

- [ ] **Step 4: Check README size and links**

Run: `wc -l README.md`

Expected: no more than 170 lines.

Run: `pre-commit run check-vcs-permalinks --files README.md`

Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: restore concise layout and references"
```

### Task 4: Clean the package after final performance evidence

**Files:**
- Delete: `CHANGELOG.md`
- Modify: `benches/README.md`
- Create or update: `assets/benchmark-python-speedup.svg`
- Modify: `Cargo.toml`

**Interfaces:** None.

- [ ] **Step 1: Ensure workflow documents are excluded from packaging**

Add to the existing `exclude` list:

```toml
    "/docs/",
```

- [ ] **Step 2: Verify final evidence was generated from the accepted library**

Inspect the clean-source identifiers recorded by the exact performance plan,
then run:

```bash
test -s assets/benchmark-python-speedup.svg
rg -n "benchmark-python-speedup.svg" benches/README.md
```

Expected: the final Python chart exists and its benchmark README link resolves.
Do not regenerate it here; the exact performance plan already benchmarks and
hash-checks the accepted implementation.

- [ ] **Step 3: Keep one README reference and remove stale warnings**

`benches/README.md` must contain:

```markdown
![Python speedup chart](../assets/benchmark-python-speedup.svg)
```

It must state that a fresh benchmark run is required after implementation or
fixture changes.

- [ ] **Step 4: Verify package contents**

Run: `cargo package --allow-dirty --list`

Expected: no `CHANGELOG.md`, `docs/`, `assets/`, benches, scripts, or tests; the
remaining package consists only of library sources and crate metadata.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml benches/README.md assets/benchmark-python-speedup.svg
git rm CHANGELOG.md
git commit -m "docs: retain current reproducible evidence"
```

### Task 5: Remove workflow documents after implementation completes

**Files:**
- Delete: `docs/superpowers/specs/2026-07-11-paper-faithful-performance-parity-design.md`
- Delete: `docs/superpowers/plans/2026-07-11-benchmark-metadata-simplification.md`
- Delete: `docs/superpowers/plans/2026-07-11-library-hygiene-readme.md`
- Delete: `docs/superpowers/plans/2026-07-11-exact-probe-performance-parity.md`

**Interfaces:** None.

- [ ] **Step 1: Confirm implementation and evidence gates are complete**

Review the commits produced by the metadata, hygiene, and exact-performance
plans. Confirm every accepted optimization has its recorded pinned A/B result,
every rejected experiment is absent from the tree, and Task 9 of the exact
performance plan has passed. Do not delete the plans while any gate remains.

- [ ] **Step 2: Remove workflow-only documents**

```bash
git rm -r docs/superpowers
```

- [ ] **Step 3: Verify the repository contains no generated planning tree**

Run: `test ! -e docs/superpowers && git status --short`

Expected: the planning tree is absent; only its staged deletion and intended
implementation changes are shown.

- [ ] **Step 4: Commit**

```bash
git commit -m "chore: remove completed workflow documents"
```

### Task 6: Final verification

**Files:** None.

- [ ] **Step 1: Run repository gates**

Run: `cargo test`

Expected: all Rust tests pass.

Run: `uv run pytest -q`

Expected: all Python tests pass.

Run: `pre-commit run --all-files`

Expected: all hooks pass.

- [ ] **Step 2: Run publication gates**

Run: `cargo clippy --all-targets --features=python -- -W clippy::pedantic -D warnings`

Expected: no warnings or errors.

Run: `cargo rustc --no-default-features --lib --crate-type rlib`

Expected: `no_std` library build succeeds.

Run: `cargo package --allow-dirty`

Expected: packaging and verification succeed.

- [ ] **Step 3: Verify the working tree scope**

Run: `git status --short`

Expected: clean after the final commit.
