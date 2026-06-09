# Get-Hit Prefetch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut large-N get-hit latency for `ElasticTable` and `FunnelTable` by prefetching deeper levels' ctrl groups up front, turning serial cross-level cache misses into parallel (MLP) ones.

**Architecture:** Each level's ctrl-group address is a pure function of `key_hash` (`triangular_group_start` / `bucket_index`), independent across levels. Today the lookup loop serializes those misses (L0 load → branch → L1 load → …). We add a `prefetch_read` hint helper and, before scanning L0, issue read-prefetches for levels `1..=max_populated_level`. The prefetch loop is empty when only L0 is populated, so the small-N regime (where opthash already beats hashbrown) gains zero instructions. Prefetch is semantically a no-op, so correctness is unchanged; the **benchmark A/B is the acceptance test**.

**Tech Stack:** Rust (stable; `nightly` is an opt-in cargo feature), inline `asm!` `prfm` (aarch64) / `_mm_prefetch` (x86_64), Criterion via `scripts/bench.sh`.

**Branch:** Do this work on a fresh branch `perf/get-hit-prefetch` (isolation skill handles the worktree). The spec lives at `docs/superpowers/specs/2026-06-08-get-hit-scaling-design.md`.

**Note on TDD shape:** A prefetch hint has no observable behavior, so the lookup-wiring tasks have no new functional unit test — their gate is "full `cargo test` still green" (correctness preserved) plus the benchmark gate in Task 6. Only the helper (Task 2) has a real unit test, because "is a non-faulting safe hint" is a testable contract.

---

### Task 1: Capture the anchor baseline (measurement only, no code change)

Anchor must be measured at HEAD before any hot-path change, per AGENTS.md.

**Files:** none (reads/writes `target/criterion/`).

- [ ] **Step 1: Confirm clean tree at HEAD**

Run: `git status --short`
Expected: empty (the spec commits are already in; no uncommitted changes).

- [ ] **Step 2: Measure and save the anchor (speedup + mean_latency)**

Run: `SAVE=anchor scripts/bench.sh`
Expected: completes both `speedup` and `mean_latency`; populates `target/criterion/.../anchor/`.

- [ ] **Step 3: Record the absolute large-N numbers for later comparison**

Run:
```bash
for sz in 1K 10K 100K 1M 10M; do
  for impl in elastic funnel std hashbrown; do
    f="target/criterion/get_hit_latency_${sz}/get_hit_latency_${sz}_${impl}/new/estimates.json"
    [ -f "$f" ] && printf "%s %-10s %s\n" "$sz" "$impl" \
      "$(python3 -c "import json;print(f\"{json.load(open('$f'))['mean']['point_estimate']:.2f}\")")"
  done
done
```
Expected: a table near elastic 1K≈4.9 / 10M≈36, funnel 1K≈4.3 / 10M≈28, hashbrown 10M≈21. Paste it into the PR/notes as the anchor of record.

- [ ] **Step 4: No commit** (measurement only).

---

### Task 2: Add the `prefetch_read` hint helper (stable path) + unit test

**Files:**
- Create: `src/common/prefetch.rs`
- Modify: `src/common/mod.rs` (register module)
- Test: inline `#[cfg(test)] mod tests` in `src/common/prefetch.rs`

- [ ] **Step 1: Register the module**

In `src/common/mod.rs`, add the module line in alphabetical position (after `iter`, before `simd`):

```rust
pub(crate) mod iter;
pub(crate) mod math;
pub(crate) mod prefetch;
pub(crate) mod simd;
```

- [ ] **Step 2: Write the failing test (helper does not exist yet)**

Create `src/common/prefetch.rs` with ONLY the test module first:

```rust
#[cfg(test)]
mod tests {
    use super::prefetch_read;

    #[test]
    fn prefetch_is_a_safe_noop_hint() {
        // Prefetching valid memory must not fault and must leave data readable.
        let v: Vec<u64> = (0..64).collect();
        for x in &v {
            prefetch_read(x as *const u64);
        }
        assert_eq!(v[63], 63);

        // A zero-length Vec yields a dangling-but-aligned pointer. Architectural
        // prefetch never faults, so this must be a silent no-op.
        let empty: Vec<u64> = Vec::new();
        prefetch_read(empty.as_ptr());
    }
}
```

- [ ] **Step 3: Run the test — verify it fails to compile**

Run: `cargo test -p opthash --lib prefetch 2>&1 | head -20`
Expected: FAIL — `cannot find function `prefetch_read` in this scope` (or unresolved import `super::prefetch_read`).

- [ ] **Step 4: Implement the helper (stable asm / intrinsic per arch)**

Prepend above the test module in `src/common/prefetch.rs`:

```rust
//! Read-prefetch hint. A pure performance hint with no observable effect:
//! architectural prefetch instructions never fault, so any pointer value is
//! safe to pass. Callers use it to overlap a soon-to-be-needed cache-line miss
//! with independent work already in flight.

/// Hint that `*ptr`'s cache line will be read soon (temporal, L1 locality).
#[inline(always)]
pub(crate) fn prefetch_read<T>(ptr: *const T) {
    #[cfg(target_arch = "aarch64")]
    // SAFETY: `prfm` is a non-faulting hint; it reads no memory and writes no
    // registers. `readonly`/`nostack`/`preserves_flags` are all upheld.
    unsafe {
        core::arch::asm!(
            "prfm pldl1keep, [{0}]",
            in(reg) ptr,
            options(nostack, preserves_flags, readonly),
        );
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: `_mm_prefetch` is a non-faulting hint over any address.
    unsafe {
        core::arch::x86_64::_mm_prefetch::<{ core::arch::x86_64::_MM_HINT_T0 }>(ptr.cast());
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let _ = ptr; // no-op fallback on other targets
    }
}
```

- [ ] **Step 5: Run the test — verify it passes**

Run: `cargo test -p opthash --lib prefetch 2>&1 | tail -5`
Expected: PASS — `test common::prefetch::tests::prefetch_is_a_safe_noop_hint ... ok`.

- [ ] **Step 6: Commit**

```bash
git add src/common/prefetch.rs src/common/mod.rs
git commit -m "feat(common): add prefetch_read hint helper (stable asm path)"
```

---

### Task 3: Add `prefetch_lookup_ctrl` to elastic `Level` and wire into lookup

**Files:**
- Modify: `src/elastic.rs` (add import; add method near `triangular_group_start` ~line 167; edit `find_slot_indices_with_hash` ~lines 1156-1172)

- [ ] **Step 1: Add the prefetch import**

In `src/elastic.rs`, after the existing `use crate::common::math::...` line (line 13), add:

```rust
use crate::common::prefetch;
```

- [ ] **Step 2: Add `prefetch_lookup_ctrl` on `Level<T>`**

In `impl<T> Level<T>`, immediately after `triangular_group_start` (the method ending around line 170), add:

```rust
    /// Prefetch the first probe group's ctrl line for `key_hash`, so a
    /// deeper-level lookup miss overlaps the L0 scan. Pure hint; callers gate
    /// this to populated levels.
    #[inline]
    fn prefetch_lookup_ctrl(&self, key_hash: u64) {
        let group_idx = self.triangular_group_start(key_hash);
        prefetch::prefetch_read(self.group_ctrl(group_idx));
    }
```

- [ ] **Step 3: Wire prefetch into `find_slot_indices_with_hash`**

Replace the body of `find_slot_indices_with_hash` (lines 1165-1171) — the part from `let search_limit` through `None` — with:

```rust
        let search_limit = (self.max_populated_level + 1).min(self.levels.len());
        // Issue deeper levels' ctrl prefetches before scanning L0 so their
        // cache misses overlap (MLP) instead of serializing behind each
        // level's branch. Empty range when only L0 is populated => zero cost.
        for level in &self.levels[1..search_limit] {
            level.prefetch_lookup_ctrl(key_hash);
        }
        for (level_idx, level) in self.levels[..search_limit].iter().enumerate() {
            if let Some(slot_idx) = level.find_by_probe(key_hash, key_fingerprint, key) {
                return Some((level_idx, slot_idx));
            }
        }
        None
```

(`search_limit >= 1` always, so `1..search_limit` is a valid range — empty when `search_limit == 1`.)

- [ ] **Step 4: Verify it compiles and all tests pass (correctness unchanged)**

Run: `cargo test -p opthash 2>&1 | tail -15`
Expected: builds clean; all elastic tests PASS (prefetch is semantically invisible).

- [ ] **Step 5: Commit**

```bash
git add src/elastic.rs
git commit -m "perf(elastic): prefetch deeper-level ctrl groups before L0 scan"
```

---

### Task 4: Add `prefetch_lookup_ctrl` to funnel `BucketLevel` and wire into lookup

**Files:**
- Modify: `src/funnel.rs` (add import; add method near `bucket_index` ~line 81; edit `find_slot_location_with_hash` ~lines 1700-1748)

- [ ] **Step 1: Add the prefetch import**

In `src/funnel.rs`, after `use crate::common::math::...` (the math import line near 13-15), add:

```rust
use crate::common::prefetch;
```

- [ ] **Step 2: Add `prefetch_lookup_ctrl` on `BucketLevel<T>`**

In `impl<T> BucketLevel<T>`, immediately after `bucket_range` (ending ~line 91), add:

```rust
    /// Prefetch the ctrl group this `key_hash` would scan, so a deeper-level
    /// lookup miss overlaps the L0 scan. Pure hint; callers gate this to
    /// populated levels. `find_in_bucket` scans only this one group, so one
    /// prefetch covers the whole level's lookup.
    #[inline]
    fn prefetch_lookup_ctrl(&self, key_hash: u64) {
        let bucket_idx = self.bucket_index(key_hash);
        let group_idx = (bucket_idx << self.bucket_size_log2) / GROUP_SIZE;
        prefetch::prefetch_read(self.group_ctrl(group_idx));
    }
```

(`GROUP_SIZE` is already imported in `funnel.rs` at line 11. `bucket_idx << bucket_size_log2` is `bucket_range.start`, a multiple of `GROUP_SIZE`, so the division is exact.)

- [ ] **Step 3: Wire prefetch into `find_slot_location_with_hash`**

Replace the whole body of `find_slot_location_with_hash` (lines 1709-1747, from the `let level0` line through the final `self.find_in_special(...)`) with:

```rust
        let search_limit = (self.max_populated_level + 1).min(self.levels.len());
        // Issue deeper levels' ctrl prefetches before scanning L0 so their
        // misses overlap (MLP). Empty range when only L0 is populated.
        // SAFETY: `1 <= search_limit <= levels.len()`, so `1..search_limit` is
        // an in-bounds (possibly empty) subslice.
        for level in unsafe { self.levels.get_unchecked(1..search_limit) } {
            level.prefetch_lookup_ctrl(key_hash);
        }

        // SAFETY: `levels.len() >= 1` (fixed at construction), so index 0 is
        // always valid. Elides the hot-path bounds check + panic pad.
        let level0 = unsafe { self.levels.get_unchecked(0) };
        match level0.find_in_bucket(key_hash, key_fingerprint, key, None) {
            LookupStep::Found(slot_idx) => {
                return Some(SlotLocation::Level {
                    level_idx: 0,
                    slot_idx,
                });
            }
            LookupStep::Continue => {}
            LookupStep::StopSearch => return None,
        }

        if search_limit > 1 {
            // SAFETY: `1 < search_limit <= levels.len()` here, so the range is
            // in bounds. Elides the slice bounds check.
            let tail = unsafe { self.levels.get_unchecked(1..search_limit) };
            for (offset, level) in tail.iter().enumerate() {
                match level.find_in_bucket(key_hash, key_fingerprint, key, None) {
                    LookupStep::Found(slot_idx) => {
                        return Some(SlotLocation::Level {
                            level_idx: offset + 1,
                            slot_idx,
                        });
                    }
                    LookupStep::Continue => {}
                    LookupStep::StopSearch => return None,
                }
            }
        }

        // Special tables are only populated under overflow.
        if self.special.total_len == 0 {
            return None;
        }
        self.find_in_special(key, key_hash, key_fingerprint, None)
```

(This hoists `search_limit` to the top and replaces the old `if self.max_populated_level > 0` tail guard with the equivalent `search_limit > 1`. Behavior is identical; the only addition is the prefetch loop.)

- [ ] **Step 4: Verify it compiles and all tests pass (correctness unchanged)**

Run: `cargo test -p opthash 2>&1 | tail -15`
Expected: builds clean; all funnel tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/funnel.rs
git commit -m "perf(funnel): prefetch deeper-level ctrl groups before L0 scan"
```

---

### Task 5: Pre-commit gate (formatters, clippy, asm sanity)

**Files:** none.

- [ ] **Step 1: Run the full pre-commit suite**

Run: `pre-commit run --all-files 2>&1 | tail -30`
Expected: all hooks Pass (notably `cargo clippy`, `cargo fmt`). Fix any clippy lint inline (e.g. if clippy flags the shift/division, keep the existing `#[allow]` style used nearby) and re-run.

- [ ] **Step 2: Commit any formatting fixups (if the hooks changed files)**

```bash
git add -A && git commit -m "style: pre-commit fixups for prefetch wiring" || echo "nothing to commit"
```

---

### Task 6: Measure the variant and evaluate the gates (decision point)

**Files:** none (reads `target/criterion/`).

- [ ] **Step 1: Measure and save the variant**

Run: `SAVE=prefetch scripts/bench.sh`
Expected: completes speedup + mean_latency, populating `target/criterion/.../prefetch/`.

- [ ] **Step 2: Compute the change vs anchor (offline, no rerun)**

Run: `LOAD=prefetch BASELINE=anchor scripts/bench.sh`
Then read the deltas:
```bash
echo "== speedup get_hit (20K) change =="
for impl in elastic funnel std hashbrown; do
  f="target/criterion/get_hit/get_hit_${impl}/change/estimates.json"
  [ -f "$f" ] && printf "%-10s %s\n" "$impl" \
    "$(python3 -c "import json;print(f\"{json.load(open('$f'))['mean']['point_estimate']*100:+.1f}%\")")"
done
echo "== mean_latency get_hit change by size =="
for sz in 1K 10K 100K 1M 10M; do
  for impl in elastic funnel std hashbrown; do
    f="target/criterion/get_hit_latency_${sz}/get_hit_latency_${sz}_${impl}/change/estimates.json"
    [ -f "$f" ] && printf "%s %-10s %s\n" "$sz" "$impl" \
      "$(python3 -c "import json;print(f\"{json.load(open('$f'))['mean']['point_estimate']*100:+.1f}%\")")"
  done
done
```

- [ ] **Step 2b: Confirm the binary is fresh (not stale asm)**

Run: `ls -l --time-style=+%s target/release/deps/speedup-* 2>/dev/null | tail -1`
Expected: mtime is newer than the last `src/` edit. If stale, rerun Step 1.

- [ ] **Step 3: Evaluate against the spec's success gates**

Pass requires ALL of:
- get_hit @1M and @10M: **≤ -5%** (faster) for elastic AND funnel.
- get_hit @1K and @10K: within **±2%** (no small-N regression).
- get_hit @100K: not slower (≤ +2%).
- speedup suite get/insert/delete: within **±2%**.
- controls std/hashbrown: within **±2%** at every size (else the run is noisy — rerun).

Record the decision in the PR/notes:
- **All gates pass** → keep the lever; proceed to Task 7.
- **Gates fail** → revert Tasks 2-5 (`git revert` the prefetch commits) and stop. The lever does not ship. Note which gate failed.

- [ ] **Step 4: No commit** (decision/measurement only).

---

### Task 7 (CONDITIONAL — only if Task 6 gates PASS): nightly `core::intrinsics` prefetch path

Per the directive "if prefetch works, include `intrinsics::prefetch_*` in the nightly feature." Skip this task entirely if Task 6 failed.

**Files:**
- Modify: `src/lib.rs:1` (add the feature gate)
- Modify: `src/common/prefetch.rs` (nightly branch)

- [ ] **Step 1: Enable the `core_intrinsics` feature under `nightly`**

In `src/lib.rs`, line 1 currently reads:
```rust
#![cfg_attr(feature = "nightly", feature(allocator_api))]
```
Change it to add `core_intrinsics`:
```rust
#![cfg_attr(feature = "nightly", feature(allocator_api, core_intrinsics))]
```

- [ ] **Step 2: Add the nightly intrinsic branch to `prefetch_read`**

In `src/common/prefetch.rs`, restructure `prefetch_read` so the `nightly` feature uses the compiler intrinsic and the stable arch paths only apply when `nightly` is off:

```rust
/// Hint that `*ptr`'s cache line will be read soon (temporal, L1 locality).
#[inline(always)]
pub(crate) fn prefetch_read<T>(ptr: *const T) {
    #[cfg(feature = "nightly")]
    // SAFETY: prefetch intrinsics are non-faulting hints over any address.
    unsafe {
        core::intrinsics::prefetch_read_data(ptr, 3); // locality 3 = L1
    }
    #[cfg(all(not(feature = "nightly"), target_arch = "aarch64"))]
    // SAFETY: `prfm` is a non-faulting hint; reads no memory, writes no regs.
    unsafe {
        core::arch::asm!(
            "prfm pldl1keep, [{0}]",
            in(reg) ptr,
            options(nostack, preserves_flags, readonly),
        );
    }
    #[cfg(all(not(feature = "nightly"), target_arch = "x86_64"))]
    // SAFETY: `_mm_prefetch` is a non-faulting hint over any address.
    unsafe {
        core::arch::x86_64::_mm_prefetch::<{ core::arch::x86_64::_MM_HINT_T0 }>(ptr.cast());
    }
    #[cfg(all(
        not(feature = "nightly"),
        not(any(target_arch = "aarch64", target_arch = "x86_64"))
    ))]
    {
        let _ = ptr;
    }
}
```

- [ ] **Step 3: Verify both feature configurations build and test**

Run (stable path):
```bash
cargo test -p opthash --lib prefetch 2>&1 | tail -3
```
Expected: PASS.

Run (nightly path — only if a nightly toolchain is installed):
```bash
cargo +nightly test -p opthash --features nightly --lib prefetch 2>&1 | tail -3
```
Expected: PASS. If no nightly toolchain is available, note that the nightly branch is compile-checked in CI instead and skip locally.

- [ ] **Step 4: Commit**

```bash
git add src/lib.rs src/common/prefetch.rs
git commit -m "feat(common): use core::intrinsics prefetch under nightly feature"
```

---

## Self-Review

- **Spec coverage:** Lever 1 (prefetch, both maps) → Tasks 2-4. A/B protocol + gates → Tasks 1, 6. Nightly-intrinsic directive → Task 7. Lever 2 (load knob) is explicitly deferred in the spec → no task, correct.
- **Type/name consistency:** helper `prefetch_read` (Task 2) is called by `prefetch_lookup_ctrl` in both `Level` (Task 3) and `BucketLevel` (Task 4); both reach `group_ctrl` via the `ArenaSlots` trait already imported in each file. `search_limit` computed identically in both maps.
- **No-field-add invariant:** neither method adds a struct field, so the `Level<...> <= 64` byte assertion (elastic.rs:69) and funnel layout are untouched — no cache-line shift.
- **Placeholder scan:** no TBD/TODO; every code step shows full code; every run step shows the command + expected output.
