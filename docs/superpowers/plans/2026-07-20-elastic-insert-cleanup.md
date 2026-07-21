# Elastic Insert Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce Elastic insert cost without changing its paper-visible probe trace by returning placement in registers and reusing one sidecar metadata calculation/load.

**Architecture:** Keep the public map and `ElasticTable` layout unchanged. Replace the release placement result with a 12-byte checked payload while compiling branch diagnostics only for tests; separately prepare one sidecar word snapshot for duplicate detection, pass its derived route mask into lookup, retain only its integer index across placement, and recompute that index after every resize.

**Tech Stack:** Rust 2024, `no_std` + `alloc`, Criterion/CodSpeed, Linux `perf`, GNU `objdump`, existing `scripts/bench.sh` harness.

## Global Constraints

- Preserve the exact Elastic target selection, candidate order, range reduction, `phi`, exceptional-placement behavior, and lookup schedule.
- Keep `ElasticTable`, `Level`, and the arena layout byte-for-byte unchanged.
- Store no pointer, reference, or metadata snapshot across growth, same-size placement recovery, or any other arena change.
- Keep `ExactInsertionCase` and `paper_probe` diagnostics in test builds only; the release return payload is exactly 12 bytes.
- Use checked conversions at the placement boundary: level, slot, and bounded `phi` must fit `u32` before returning.
- Recompute the sidecar word index unconditionally after every resize, including same-size placement recovery.
- Add no production dependency and preserve Rust 1.88 and `no_std` builds.
- Retain a change only when the pinned Criterion run improves Elastic insert and does not regress randomized or ordered get beyond the approved gates.
- Before any empirical retain/revert decision, consult a fresh reviewer subagent; its approval is the user's delegated approval.

---

### Task 1: Save the Merged-Main Performance and Assembly Anchor

**Files:**
- Read: `scripts/bench.sh`
- Read: `benches/speedup.rs`
- Read: `target/criterion/`

**Interfaces:**
- Consumes: clean branch whose only code difference from merged main is documentation.
- Produces: stored Criterion baseline `cleanup-anchor`, baseline instruction/counter output, and a baseline disassembly of the concrete Elastic insert path.

- [ ] **Step 1: Confirm the benchmark tree has no code changes**

Run:

```bash
git status --short
git diff 4fe61a2 -- src benches scripts Cargo.toml Cargo.lock
```

Expected: `git status --short` is empty and the code/benchmark diff against merged PR #130 is empty.

- [ ] **Step 2: Save a fresh pinned anchor**

Run:

```bash
SAVE=cleanup-anchor scripts/bench.sh
BENCH=scaled_insert SAVE=cleanup-anchor-scale scripts/bench.sh
```

Expected: Criterion completes `speedup`, `mean_latency`, and the default 100K/1M/10M scaled-insert groups; JSON appears below `target/criterion/*/cleanup-anchor/` and `target/criterion/*/cleanup-anchor-scale/`.

- [ ] **Step 3: Record the baseline hardware counters for Elastic insert**

Run on the pinned AArch64 host:

```bash
perf stat -r 3 -e cycles,instructions,cache-misses,branch-misses -- scripts/bench.sh "insert/insert_elastic"
```

Expected: three completed counter samples with no unsupported-event or permission error. Save the terminal output with the task notes; do not compare an unpinned raw `cargo bench` run.

- [ ] **Step 4: Capture the exact concrete baseline assembly**

Run:

```bash
cargo bench --bench speedup --no-run --message-format=json > target/cleanup-anchor-cargo.json
jq -r 'select(.reason == "compiler-artifact" and .target.name == "speedup" and .executable != null) | .executable' target/cleanup-anchor-cargo.json | sort -u > target/cleanup-anchor-executables.txt
test "$(wc -l < target/cleanup-anchor-executables.txt)" -eq 1
speedup_bin=$(sed -n '1p' target/cleanup-anchor-executables.txt)
test -n "$speedup_bin"
test -x "$speedup_bin"
test "$(stat -c %Y "$speedup_bin")" -ge "$(git show -s --format=%ct HEAD)"
objdump -d -C "$speedup_bin" > target/cleanup-anchor-speedup.asm
rg -n "choose_slot_for_new_key|insert_for_vacant_entry_prepared" target/cleanup-anchor-speedup.asm
```

Expected: Cargo identifies one freshly rebuilt `speedup` executable belonging
to the checked-out commit; the symbols or their inlined call sites are present.
Record the exact executable path, commit ID, binary mtime, function stack
adjustment, and whether a hidden result pointer or stack copies are visible.

### Task 2: Return a Compact Placement Payload in Release Builds

**Files:**
- Modify: `src/elastic.rs:46-92`
- Modify: `src/elastic.rs:907-965`
- Modify: `src/elastic.rs:1560-1680`
- Test: `src/elastic.rs:2030-2160`

**Interfaces:**
- Consumes: current `BatchTarget`, `PreparedElasticProbe`, `elastic_phi_bounded`, `QUERY_POSITION_CAP`.
- Produces: `ExactPlacement { level: u32, slot: u32, phi: u32 }`, test-only `ExactPlacementDiagnostics`, and `PlacementChoice` returned by `choose_slot_for_new_key`.

- [ ] **Step 1: Add a failing compact-layout test**

Add beside `compact_prepared_elastic_state_is_register_sized`:

```rust
#[test]
fn exact_placement_release_payload_is_three_words() {
    assert_eq!(mem::size_of::<ExactPlacement>(), 12);
    assert_eq!(mem::align_of::<ExactPlacement>(), mem::align_of::<u32>());
}
```

Run:

```bash
cargo test elastic::tests::exact_placement_release_payload_is_three_words -- --exact
```

Expected: FAIL because the existing `ExactPlacement` contains the large case enum, two `usize` values, `u64`, and `u128`.

- [ ] **Step 2: Split the production payload from test diagnostics**

Replace the current placement declarations with:

```rust
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExactInsertionCase {
    Batch0 {
        level: usize,
    },
    Case1 {
        batch: usize,
        current_level: usize,
        next_level: usize,
        free_current: usize,
        free_next: usize,
        budget: usize,
    },
    Case2 {
        batch: usize,
        current_level: usize,
        next_level: usize,
        free_current: usize,
        free_next: usize,
    },
    Case3 {
        batch: usize,
        current_level: usize,
        next_level: usize,
        free_current: usize,
        free_next: usize,
    },
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExactPlacement {
    level: u32,
    slot: u32,
    phi: u32,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExactPlacementDiagnostics {
    case: ExactInsertionCase,
    paper_probe: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PlacementChoice {
    placement: ExactPlacement,
    #[cfg(test)]
    diagnostics: ExactPlacementDiagnostics,
}

const _: () = assert!(mem::size_of::<ExactPlacement>() == 12);
#[cfg(not(test))]
const _: () = assert!(mem::size_of::<PlacementChoice>() == 12);

#[cfg(test)]
macro_rules! record_exact_insertion_case {
    ($slot:ident, $case:expr) => {
        $slot = Some($case);
    };
}

#[cfg(not(test))]
macro_rules! record_exact_insertion_case {
    ($slot:ident, $case:expr) => {};
}
```

Expected: `ExactInsertionCase` cannot contribute to release layout and `PlacementChoice` is register-return-sized on 64-bit targets.

- [ ] **Step 3: Stop carrying the case enum through the production match**

Change `choose_slot_for_new_key` to return `Option<PlacementChoice>`, initialize test diagnostics only under `cfg(test)`, and make the match return only `(level, slot, paper_probe)`:

```rust
fn choose_slot_for_new_key(
    &self,
    probe: PreparedElasticProbe,
    target: BatchTarget,
) -> Option<PlacementChoice> {
    if self.levels.is_empty() {
        return None;
    }
    #[cfg(test)]
    let mut diagnostics_case = None;

    let (level, slot, paper_probe) = match target {
        BatchTarget::Bootstrap => {
            let level_probe = probe.prepare_level_lane(ELASTIC_LEVEL_LANES[0]);
            let (slot, paper_probe) = self.uniform_vacancy(level_probe, 0)?;
            record_exact_insertion_case!(
                diagnostics_case,
                ExactInsertionCase::Batch0 { level: 0 }
            );
            (0, slot, paper_probe)
        }
        BatchTarget::LevelPair(current) => {
            let next = current.checked_add(1)?;
            let current_level = self.levels.get(current)?;
            let next_level = self.levels.get(next)?;
            let free_current = current_level.free_slots();
            let free_next = next_level.free_slots();
            let current_low = free_current
                <= self
                    .reserve_fraction
                    .floor_half_reserved(current_level.capacity());
            let next_low = free_next.saturating_mul(4) <= next_level.capacity();

            if current_low {
                record_exact_insertion_case!(
                    diagnostics_case,
                    ExactInsertionCase::Case2 {
                        batch: next,
                        current_level: current,
                        next_level: next,
                        free_current,
                        free_next,
                    }
                );
                let level_probe = probe.prepare_level_lane(ELASTIC_LEVEL_LANES[next]);
                let (slot, paper_probe) = self.uniform_vacancy(level_probe, next)?;
                (next, slot, paper_probe)
            } else if next_low {
                record_exact_insertion_case!(
                    diagnostics_case,
                    ExactInsertionCase::Case3 {
                        batch: next,
                        current_level: current,
                        next_level: next,
                        free_current,
                        free_next,
                    }
                );
                let level_probe = probe.prepare_level_lane(ELASTIC_LEVEL_LANES[current]);
                let (slot, paper_probe) = self.uniform_vacancy(level_probe, current)?;
                (current, slot, paper_probe)
            } else {
                let budget = probe::elastic_dyadic_probe_budget(
                    free_current,
                    current_level.capacity(),
                    self.reserve_fraction.exponent(),
                    ELASTIC_PROBE_BUDGET_C,
                )
                .ok()?;
                record_exact_insertion_case!(
                    diagnostics_case,
                    ExactInsertionCase::Case1 {
                        batch: next,
                        current_level: current,
                        next_level: next,
                        free_current,
                        free_next,
                        budget,
                    }
                );
                let current_probe = probe.prepare_level_lane(ELASTIC_LEVEL_LANES[current]);
                if let Some((slot, paper_probe)) = (0..budget).find_map(|logical_index| {
                    let logical_index = u64::try_from(logical_index).ok()?;
                    self.vacancy(current, current_probe, logical_index)
                        .map(|slot| (slot, logical_index + 1))
                }) {
                    (current, slot, paper_probe)
                } else {
                    let next_probe = probe.prepare_level_lane(ELASTIC_LEVEL_LANES[next]);
                    let (slot, paper_probe) = self.uniform_vacancy(next_probe, next)?;
                    (next, slot, paper_probe)
                }
            }
        }
    };

    let paper_level = u32::try_from(level.checked_add(1)?).ok()?;
    let phi = probe::elastic_phi_bounded(paper_level, paper_probe)?;
    if u128::from(phi) > QUERY_POSITION_CAP {
        return None;
    }
    Some(PlacementChoice {
        placement: ExactPlacement {
            level: u32::try_from(level).ok()?,
            slot: u32::try_from(slot).ok()?,
            phi: u32::try_from(phi).ok()?,
        },
        #[cfg(test)]
        diagnostics: ExactPlacementDiagnostics {
            case: diagnostics_case.expect("every placement branch records its case"),
            paper_probe,
        },
    })
}
```

Expected: all release branches compute the same target, slot, probe count, and `phi`, but do not construct `ExactInsertionCase`.

- [ ] **Step 4: Convert the compact fields only at the mutation boundary**

At the start of `place_new_entry`, replace direct placement field use with:

```rust
let ExactPlacement { level, slot, phi } = placement.placement;
let level = usize::try_from(level).expect("checked Elastic level fits usize");
let slot = usize::try_from(slot).expect("checked Elastic slot fits usize");
self.extend_probe_schedule(u128::from(phi));
self.write_new_entry(key, value, prepared, key_fingerprint, level, slot)
```

Update scalar parity assertions to read:

```rust
let actual = placement.placement;
assert_eq!(placement.diagnostics.case, exact_case(expected.case));
assert_eq!(usize::try_from(actual.level).unwrap(), expected.location.level);
assert_eq!(usize::try_from(actual.slot).unwrap(), expected.location.slot_in_level);
assert_eq!(placement.diagnostics.paper_probe, expected.paper_probe);
assert_eq!(u128::from(actual.phi), expected.phi);
```

Expected: mutation uses the same physical indices; test diagnostics remain as detailed as before.

- [ ] **Step 5: Run focused and full correctness tests**

Run:

```bash
cargo test elastic::tests::exact_placement_release_payload_is_three_words -- --exact
cargo test elastic::tests::elastic_placement_matches_the_scalar_paper_model -- --exact
cargo test elastic::tests::finite_probe_exhaustion_uses_observable_exceptional_recovery -- --exact
cargo test
```

Expected: all commands PASS.

- [ ] **Step 6: Verify release ABI/assembly before committing**

Run:

```bash
cargo bench --bench speedup --no-run
cargo bench --bench speedup --no-run --message-format=json > target/compact-placement-cargo.json
jq -r 'select(.reason == "compiler-artifact" and .target.name == "speedup" and .executable != null) | .executable' target/compact-placement-cargo.json | sort -u > target/compact-placement-executables.txt
test "$(wc -l < target/compact-placement-executables.txt)" -eq 1
speedup_bin=$(sed -n '1p' target/compact-placement-executables.txt)
test -n "$speedup_bin"
test -x "$speedup_bin"
test "$(stat -c %Y "$speedup_bin")" -ge "$(git show -s --format=%ct HEAD)"
objdump -d -C "$speedup_bin" > target/compact-placement-speedup.asm
rg -n "choose_slot_for_new_key|insert_for_vacant_entry_prepared" target/compact-placement-speedup.asm
```

Expected: the placement result is returned in registers with no 208-byte diagnostic payload, hidden result buffer, or copies of `ExactInsertionCase` in the release path.

- [ ] **Step 7: Commit the independently testable placement change**

```bash
git add src/elastic.rs
git commit -m "perf: compact elastic placement result"
```

### Task 3: Reuse the Elastic Metadata Index and Snapshot

**Files:**
- Modify: `src/elastic.rs:344-410`
- Modify: `src/elastic.rs:785-855`
- Modify: `src/elastic.rs:897-1015`
- Modify: `src/elastic.rs:1745-1845`
- Modify: `src/elastic.rs:1195-1220`
- Test: `src/elastic.rs:2530-2825`

**Interfaces:**
- Consumes: `PreparedElasticRoute`, `ElasticMetadataWord`, and `PlacementChoice` from Task 2.
- Produces: 8-byte `PreparedElasticKey`, niche-optimized `MetadataWordIndex`, `PreparedMetadataWrite`, `PreparedInsertMetadata`, one-shot signature preparation, cached-summary lookup, and signature-preserving resize reindexing.

- [ ] **Step 1: Add failing preparation and growth-safety tests**

Add beside the existing membership tests:

```rust
#[test]
fn prepared_insert_metadata_matches_the_sidecar_word() {
    let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(256, IdentityBuildHasher);
    for key in 0..128_u64 {
        map.insert(key, key);
    }
    for key in 0..128_u64 {
        let route = PreparedElasticRoute::new(key);
        let write = map.table().prepare_metadata_write(route);
        let actual = map.table().prepare_insert_metadata(write);
        let index = write.index.unwrap().get();
        let word = unsafe { *map.table().membership_ptr().add(index) };
        let membership = PreparedMembership::from_signature(write.signature);
        assert_eq!(
            actual.membership_maybe_contains,
            word.membership & membership.bits == membership.bits
        );
        assert_eq!(
            actual.summary_level_mask,
            expand_summary_level_mask(
                word.route_bins[(write.signature & 3) as usize],
                map.table().levels.len(),
            )
        );
    }
}

#[test]
fn metadata_index_is_recomputed_after_growth() {
    let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(16, IdentityBuildHasher);
    let old_words = map.table().membership_words();
    map.reserve(4_096);
    let new_words = map.table().membership_words();
    assert_ne!(old_words, new_words);
    let key = (0_u64..u64::MAX)
        .find(|&candidate| {
            let route = PreparedElasticRoute::new(candidate);
            let old = PreparedMembership::word(route.signature(), old_words);
            let new = PreparedMembership::word(route.signature(), new_words);
            old != new
        })
        .unwrap();
    let route = PreparedElasticRoute::new(key);
    let signature = route.signature();
    let stale = PreparedMetadataWrite {
        signature,
        index: MetadataWordIndex::new(PreparedMembership::word(signature, old_words)),
    };
    let fresh = map.table().reindex_metadata_write(stale);
    assert_eq!(fresh.signature, stale.signature);
    assert_ne!(stale.index, fresh.index);
    assert_eq!(map.insert(key, 7), None);
    let write = map.table().prepare_metadata_write(route);
    assert!(map.table().prepare_insert_metadata(write).membership_maybe_contains);
    assert_eq!(map.get(&key), Some(&7));
}
```

Run:

```bash
cargo test elastic::tests::prepared_insert_metadata_matches_the_sidecar_word -- --exact
cargo test elastic::tests::metadata_index_is_recomputed_after_growth -- --exact
```

Expected: FAIL because the metadata preparation types and methods do not exist.

- [ ] **Step 2: Add pointerless, signature-caching metadata types**

Replace `PreparedElasticKey` so it retains only the route root, then add:

```rust
#[derive(Clone, Copy)]
struct PreparedElasticKey {
    route: PreparedElasticRoute,
}

impl PreparedElasticKey {
    #[inline]
    fn new(hash: u64) -> Self {
        Self { route: PreparedElasticRoute::new(hash) }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MetadataWordIndex(core::num::NonZeroUsize);

impl MetadataWordIndex {
    #[inline]
    fn new(index: usize) -> Option<Self> {
        index.checked_add(1).and_then(core::num::NonZeroUsize::new).map(Self)
    }

    #[inline]
    const fn get(self) -> usize {
        self.0.get() - 1
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreparedMetadataWrite {
    signature: u64,
    index: Option<MetadataWordIndex>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreparedInsertMetadata {
    summary_level_mask: u32,
    membership_maybe_contains: bool,
}

const _: () = assert!(mem::size_of::<PreparedElasticKey>() == 8);
const _: () = assert!(mem::size_of::<MetadataWordIndex>() == mem::size_of::<usize>());
const _: () = assert!(mem::size_of::<PreparedMetadataWrite>() <= 16);
const _: () = assert!(mem::size_of::<PreparedInsertMetadata>() == 8);
```

Expected: one mixed signature is retained with a niche-optimized integer index; no pointer, reference, or word snapshot crosses placement or resize.

- [ ] **Step 3: Compute the index once and derive both lookup decisions from one word copy**

Replace `membership_maybe_contains` for the insert path with these methods; keep `summary_level_mask` for ordinary get calls:

```rust
#[inline]
fn metadata_word_index_from_signature(
    &self,
    signature: u64,
) -> Option<MetadataWordIndex> {
    let words = self.membership_words();
    if words == 0 {
        None
    } else {
        MetadataWordIndex::new(PreparedMembership::word(signature, words))
    }
}

#[inline]
fn prepare_metadata_write(&self, route: PreparedElasticRoute) -> PreparedMetadataWrite {
    let signature = route.signature();
    PreparedMetadataWrite {
        signature,
        index: self.metadata_word_index_from_signature(signature),
    }
}

#[inline]
fn reindex_metadata_write(&self, write: PreparedMetadataWrite) -> PreparedMetadataWrite {
    PreparedMetadataWrite {
        signature: write.signature,
        index: self.metadata_word_index_from_signature(write.signature),
    }
}

#[inline]
fn prepare_insert_metadata(&self, write: PreparedMetadataWrite) -> PreparedInsertMetadata {
    let Some(index) = write.index else {
        return PreparedInsertMetadata {
            summary_level_mask: 0,
            membership_maybe_contains: false,
        };
    };
    let metadata = unsafe { *self.membership_ptr().add(index.get()) };
    let membership = PreparedMembership::from_signature(write.signature);
    PreparedInsertMetadata {
        summary_level_mask: expand_summary_level_mask(
            metadata.route_bins[(write.signature & 3) as usize],
            self.levels.len(),
        ),
        membership_maybe_contains: metadata.membership & membership.bits == membership.bits,
    }
}

#[inline]
fn record_metadata_at(
    &mut self,
    write: PreparedMetadataWrite,
    level: usize,
) {
    debug_assert_eq!(write.index, self.metadata_word_index_from_signature(write.signature));
    let Some(index) = write.index else { return };
    let membership = PreparedMembership::from_signature(write.signature);
    let metadata = unsafe { &mut *self.membership_ptr().add(index.get()) };
    metadata.membership |= membership.bits;
    if self.levels.len() <= ROUTE_SUMMARY_LEVELS {
        metadata.route_bins[(write.signature & 3) as usize] |= 1_u16 << level;
    }
}
```

Also rewrite `summary_level_mask` to assign `let signature = route.signature();`
once, then derive both `PreparedMembership::word(signature, words)` and
`(signature & 3) as usize` from that local. Step 4 supplies this method lazily,
after the first H(1,1) probe misses. Remove `PreparedElasticRoute::summary_bin`
after its two callers use the cached signature; do not leave a helper that
silently recomputes the signature.

Expected: each insert computes the mixed signature once, and each get computes
it at most once after H(1,1); the insert precheck performs one multiply-high
index calculation and one 16-byte metadata copy. `prepare_metadata_write`
returns two machine words and `prepare_insert_metadata` returns one 8-byte
aggregate, so neither crosses AArch64's indirect-result boundary. Release
assembly must contain no hidden result pointer or aggregate stack copy.

- [ ] **Step 4: Pass the cached route mask into duplicate lookup**

Add the specialized wrapper:

```rust
#[inline]
fn find_slot_indices_prepared_with_summary<Q>(
    &self,
    key: &Q,
    prepared: PreparedElasticRoute,
    key_fingerprint: u8,
    summary_level_mask: u32,
) -> Option<(usize, usize)>
where
    Q: Equivalent<K> + ?Sized,
{
    self.find_by_exact_schedule(
        key,
        prepared,
        key_fingerprint,
        || summary_level_mask,
        |level, slot, _entry| (level, slot),
    )
}
```

Change `find_by_exact_schedule` to accept a generic `S: FnOnce() -> u32`. It
must execute the existing H(1,1) probe first and return immediately on a hit;
only after that miss may it call `let summary_level_mask =
summary_level_mask();`. Existing `find_slot_indices_prepared` and
`find_entry_prepared` pass `|| self.summary_level_mask(prepared)`. The insert
wrapper above passes the already cached value through `|| summary_level_mask`.
Keep the helper `#[inline]` and confirm assembly contains no closure object,
indirect call, or early signature calculation.

Expected: public get behavior is unchanged; H(1,1) hits do not compute the
signature or touch sidecar metadata, while insert duplicate lookup cannot
calculate or load the sidecar word a second time.

- [ ] **Step 5: Thread only the index through insertion and invalidate it on resize**

Change the prepared insertion signature to:

```rust
fn insert_for_vacant_entry_prepared(
    &mut self,
    key: K,
    value: V,
    prepared: PreparedElasticKey,
    key_fingerprint: u8,
    mut metadata_write: PreparedMetadataWrite,
) -> (usize, usize)
```

Use this exact invalidation rule around arena-changing calls:

```rust
match self
    .scheduler
    .on_insert(self.len, self.total_slots, self.max_insertions)
{
    InsertAction::Resize(cap) => {
        self.resize_with_transition(cap, EpochTransition::Growth);
        self.scheduler.advance_batch_window();
        metadata_write = self.reindex_metadata_write(metadata_write);
    }
    InsertAction::Continue => {}
}
```

After placement failure, recompute after same-size recovery:

```rust
self.resize_with_transition(self.total_slots, EpochTransition::PlacementRecovery);
self.scheduler.advance_batch_window();
metadata_write = self.reindex_metadata_write(metadata_write);
```

Pass `metadata_write` through `place_new_entry`, `place_exceptional_entry`, and `write_new_entry`. In `write_new_entry`, before mutating the slot, assert provenance and then record with the cached signature/index:

```rust
debug_assert_eq!(
    metadata_write.index,
    self.metadata_word_index_from_signature(metadata_write.signature),
);
// Existing slot write and level counter updates remain in their current order.
self.record_metadata_at(metadata_write, level_idx);
```

Every caller must supply the current index:

```rust
let metadata_write = self.prepare_metadata_write(prepared.route);
self.insert_for_vacant_entry_prepared(
    key,
    value,
    prepared,
    key_fingerprint,
    metadata_write,
)
```

Expected: no stale arena-derived pointer exists; every resize overwrites the old integer provenance before record.

- [ ] **Step 6: Make the ordinary insert use the prepared snapshot**

Replace the insert precheck with:

```rust
let prepared = PreparedElasticKey::new(hash);
let key_fingerprint = control::control_fingerprint(hash);
let metadata_write = self.prepare_metadata_write(prepared.route);
let metadata = self.prepare_insert_metadata(metadata_write);
if metadata.membership_maybe_contains
    && let Some(location) = self.find_slot_indices_prepared_with_summary(
        &key,
        prepared.route,
        key_fingerprint,
        metadata.summary_level_mask,
    )
{
    return Some(self.replace_value(location, value));
}
self.insert_for_vacant_entry_prepared(
    key,
    value,
    prepared,
    key_fingerprint,
    metadata_write,
);
None
```

Expected: a likely-absent insert mixes the signature once and loads one sidecar
word; a possible duplicate reuses its route mask; a no-growth miss reuses its
signature/index for the final record; resize changes only the index.

- [ ] **Step 7: Run focused invariant tests, Miri, and full verification**

Run:

```bash
cargo test elastic::tests::prepared_insert_metadata_matches_the_sidecar_word -- --exact
cargo test elastic::tests::metadata_index_is_recomputed_after_growth -- --exact
cargo test elastic::tests::membership_filter_never_forgets_live_or_deleted_hashes -- --exact
cargo test elastic::tests::all_vacant_entry_apis_record_membership -- --exact
cargo test elastic::tests::drain_and_failed_reserve_preserve_membership_invariants -- --exact
cargo test
cargo +nightly miri test elastic::tests::metadata_index_is_recomputed_after_growth -- --exact
pre-commit run --all-files
```

Expected: all commands PASS and strict-provenance Miri reports no invalid pointer use.

- [ ] **Step 8: Commit the independently testable metadata change**

```bash
git add src/elastic.rs
git commit -m "perf: reuse elastic insert metadata"
```

### Task 4: Attribute, Gate, and Retain the Trace-Neutral Changes

**Files:**
- Read: `target/criterion/*/*/{new,change}/estimates.json`
- Read: `target/compact-placement-speedup.asm`
- Create: `docs/performance/2026-07-20-elastic-insert-cleanup.md`

**Interfaces:**
- Consumes: the Task 1 anchor, Task 2 commit, and Task 3 commit.
- Produces: separate A/B evidence for compact placement and metadata reuse, cross-architecture evidence, and a retained or reverted cleanup series.

- [ ] **Step 1: Resolve immutable commits and create three measurement worktrees**

Invoke `superpowers:using-git-worktrees`. Resolve each commit by its exact
message, reject missing or ambiguous matches, and create detached worktrees so
that every measured command actually executes the intended tree:

```bash
cleanup_anchor_commit=4fe61a25f7ba29afad3e19bb46a03fc475748543
test "$(git rev-list --all --count --grep='^perf: compact elastic placement result$')" -eq 1
test "$(git rev-list --all --count --grep='^perf: reuse elastic insert metadata$')" -eq 1
cleanup_compact_commit=$(git rev-list --all --grep='^perf: compact elastic placement result$' -1)
cleanup_final_commit=$(git rev-list --all --grep='^perf: reuse elastic insert metadata$' -1)
git merge-base --is-ancestor "$cleanup_anchor_commit" "$cleanup_compact_commit"
git merge-base --is-ancestor "$cleanup_compact_commit" "$cleanup_final_commit"
git worktree add --detach /home/aang/projects/opthash/.worktrees/perf/cleanup-anchor "$cleanup_anchor_commit"
git worktree add --detach /home/aang/projects/opthash/.worktrees/perf/cleanup-compact "$cleanup_compact_commit"
git worktree add --detach /home/aang/projects/opthash/.worktrees/perf/cleanup-final "$cleanup_final_commit"
```

In each worktree, assert `git rev-parse HEAD` equals the resolved commit and
`git status --porcelain -- src benches scripts Cargo.toml Cargo.lock` is empty.
Use this one shared result root on a given host:

```bash
cleanup_criterion_root=/home/aang/projects/opthash/.worktrees/perf/counter-prf-insert/target/criterion
cleanup_arch=$(uname -m)
```

Expected: anchor, compact, and final are physically separate clean trees; all
runs on one host write named variants to one Criterion root.

- [ ] **Step 2: Collect three alternating adjacent A/B triplets per architecture**

Run the following literal sequence. The central compact run is adjacent to
both comparisons; the second triplet reverses order to expose thermal/order
bias:

```bash
(cd /home/aang/projects/opthash/.worktrees/perf/cleanup-anchor && OPTHASH_CRITERION_ROOT="$cleanup_criterion_root" SAVE="$cleanup_arch-cleanup-anchor-a1" scripts/bench.sh)
(cd /home/aang/projects/opthash/.worktrees/perf/cleanup-compact && OPTHASH_CRITERION_ROOT="$cleanup_criterion_root" SAVE="$cleanup_arch-cleanup-compact-c1" scripts/bench.sh)
(cd /home/aang/projects/opthash/.worktrees/perf/cleanup-final && OPTHASH_CRITERION_ROOT="$cleanup_criterion_root" SAVE="$cleanup_arch-cleanup-final-f1" scripts/bench.sh)

(cd /home/aang/projects/opthash/.worktrees/perf/cleanup-final && OPTHASH_CRITERION_ROOT="$cleanup_criterion_root" SAVE="$cleanup_arch-cleanup-final-f2" scripts/bench.sh)
(cd /home/aang/projects/opthash/.worktrees/perf/cleanup-compact && OPTHASH_CRITERION_ROOT="$cleanup_criterion_root" SAVE="$cleanup_arch-cleanup-compact-c2" scripts/bench.sh)
(cd /home/aang/projects/opthash/.worktrees/perf/cleanup-anchor && OPTHASH_CRITERION_ROOT="$cleanup_criterion_root" SAVE="$cleanup_arch-cleanup-anchor-a2" scripts/bench.sh)

(cd /home/aang/projects/opthash/.worktrees/perf/cleanup-anchor && OPTHASH_CRITERION_ROOT="$cleanup_criterion_root" SAVE="$cleanup_arch-cleanup-anchor-a3" scripts/bench.sh)
(cd /home/aang/projects/opthash/.worktrees/perf/cleanup-compact && OPTHASH_CRITERION_ROOT="$cleanup_criterion_root" SAVE="$cleanup_arch-cleanup-compact-c3" scripts/bench.sh)
(cd /home/aang/projects/opthash/.worktrees/perf/cleanup-final && OPTHASH_CRITERION_ROOT="$cleanup_criterion_root" SAVE="$cleanup_arch-cleanup-final-f3" scripts/bench.sh)
```

For `i=1,2,3`, run offline comparisons from the anchor worktree with the same
`OPTHASH_CRITERION_ROOT`: compact `ci` against anchor `ai`, final `fi` against
anchor `ai`, and final `fi` against compact `ci`. The first two are acceptance
gates; the adjacent final-vs-compact comparison attributes the metadata delta
and catches an independently regressing second commit. Finally, on the final
tree only, run:

```bash
(cd /home/aang/projects/opthash/.worktrees/perf/cleanup-final && OPTHASH_CRITERION_ROOT="$cleanup_criterion_root" BENCH=scaled_insert SAVE="$cleanup_arch-cleanup-final-scale" scripts/bench.sh)
```

Expected: three compact-vs-anchor, three combined-final-vs-anchor, and three
adjacent metadata-vs-compact pairs exist, plus final 100K/1M/10M scaled runs.

- [ ] **Step 3: Inspect and preserve every raw pair**

For each comparison read `mean.point_estimate` and the full 95% confidence
interval directly from both `new/estimates.json` and
`change/estimates.json`. Record the literal run names for `insert_elastic`,
randomized `get_hit_elastic`, ordered `get_hit_sequential_elastic`, all other
public-suite Elastic operations, and all randomized/ordered mean-latency groups
at `1K`, `10K`, `100K`, `1M`, and `10M`, with matching std/hashbrown controls.
Discard and rerun a whole adjacent triplet when either control changes by more
than 5%; never subtract control drift or replace raw pairs with console medians.

Expected: three usable raw pairs, with point estimate and interval, remain for
each independently attributable change on each architecture.

- [ ] **Step 4: Rebuild and collect counters, actual Callgrind, and exact assembly**

In each of the three worktrees on AArch64, run pinned hardware counters for
`insert/insert_elastic`. In each worktree on x86-64, force a fresh benchmark
build and collect actual CodSpeed/Callgrind instruction counts:

```bash
cargo clean -p opthash
CARGO_INCREMENTAL=0 cargo codspeed build --bench speedup
cargo codspeed run --bench speedup 2>&1 | tee target/cleanup-callgrind.txt
cargo bench --bench speedup --no-run --message-format=json > target/cleanup-cargo.json
jq -r 'select(.reason == "compiler-artifact" and .target.name == "speedup" and .executable != null) | .executable' target/cleanup-cargo.json | sort -u > target/cleanup-executables.txt
test "$(wc -l < target/cleanup-executables.txt)" -eq 1
speedup_bin=$(sed -n '1p' target/cleanup-executables.txt)
test -n "$speedup_bin"
test -x "$speedup_bin"
test "$(stat -c %Y "$speedup_bin")" -ge "$(git show -s --format=%ct HEAD)"
objdump -d -C "$speedup_bin" > target/cleanup-speedup.asm
rg -n "choose_slot_for_new_key|insert_for_vacant_entry_prepared" target/cleanup-speedup.asm
cargo test elastic::tests::compact_prepared_elastic_state_is_register_sized -- --exact
```

Run the snippet separately in anchor, compact, and final, saving the exact
commit ID and executable path beside each output. Extract and record exact
per-operation Callgrind instruction counts for Elastic insert, randomized and
ordered get, and std/hashbrown controls; do not record only an aggregate count.

Expected: counter and instruction direction corroborates Criterion; no hidden
placement result buffer, closure call, early get signature, selector branch,
or stale benchmark binary is present; hot table/level sizes stay unchanged.

- [ ] **Step 5: Repeat Steps 1-4 on the pinned x86-64 host**

Transfer commits, not build artifacts. Use the same three detached trees and
let `cleanup_arch=$(uname -m)` produce architecture-qualified run names. Repeat
the exact alternating sequence, raw JSON inspection, scaled final run,
Callgrind collection, and exact-binary disassembly.

Expected for compact-vs-anchor and combined-final-vs-anchor: all three Elastic
insert point estimates improve; at least two 95% change intervals exclude zero;
the median raw insert change is at most -10%. Randomized
and ordered get median plus the upper confidence bound in at least two pairs
are at or below +2%. Apply that same +2% median/two-upper-bound gate separately
to every randomized and sequential `get_hit_*_latency_{1K,10K,100K,1M,10M}`
trace. Any public-suite or latency-size regression outside the approved gates
rejects that variant. Use final-vs-compact only for attribution: metadata must
not independently regress Elastic insert, any public operation, or any latency
size outside its confidence/noise bounds. If compact fails but combined final
passes, retain both commits because the passing variant depends on both; if
compact passes but combined final fails, reject metadata; if both fail, reject
both.

- [ ] **Step 6: Write the evidence record**

Create `docs/performance/2026-07-20-elastic-insert-cleanup.md`. Populate every numeric cell directly from the named JSON files and saved counter output; do not enter estimates or console-rounded values. The document must contain this schema:

```markdown
# Elastic Insert Cleanup Evidence

1. A raw-pairs table headed `Architecture`, `Change`, `Pair`, `Baseline run`,
   `Candidate run`, `Operation`, `Baseline ns`, `Candidate ns`, `Change point`,
   `95% low`, `95% high`, `std movement`, and `hashbrown movement`. Include all
   three pairs for insert, randomized get, ordered get, and every gate-bearing
   public operation, plus randomized and sequential latency at 1K, 10K, 100K,
   1M, and 10M; do not collapse this table to medians.
2. A decision table headed `Architecture`, `Change`, `insert median`, `get-hit
   median`, `ordered-get median`, `worst latency-size result`, `Callgrind
   instructions`, `perf counters`, and `decision`, with rows for
   compact-vs-anchor and combined-final-vs-anchor on both architectures, plus
   final-vs-compact attribution rows for metadata.
3. A `Discarded controls` section naming every discarded run pair and its exact
   std/hashbrown point estimate and confidence interval, or literal `None`.
4. A `Callgrind` section listing exact per-operation instruction counts and
   source commit for anchor, compact, and final on x86-64.
5. An `Assembly` section listing commit, exact executable, mtime, return ABI,
   stack-frame change, signature timing, and multiply/load changes per tree and
   architecture.
6. A `Scaled insert` section recording the final tree's 100K, 1M, and 10M
   point estimates and run names.
```

Expected: every decision is traceable to named stored runs; no result is inferred from Criterion console summaries alone.

- [ ] **Step 7: Revert any independently failing change and verify the retained tree**

Before acting, give every raw JSON pair—including all ten latency traces—each
control interval, exact Callgrind count, hardware counter, and assembly record
to a fresh reviewer subagent. It
must classify compact-vs-anchor and combined-final-vs-anchor independently,
then apply these four cases literally:

1. Compact PASS, combined PASS: retain both only when final-vs-compact does not
   independently regress a public operation; otherwise revert metadata only.
2. Compact PASS, combined FAIL: revert metadata; retain compact.
3. Compact FAIL, combined PASS: retain both because the accepted combined tree
   depends on both commits.
4. Compact FAIL, combined FAIL: revert metadata first, then revert compact.

Whenever the combined variant is rejected (cases 2 and 4), resolve and revert
the metadata commit unconditionally, even if its adjacent delta improved a
failing compact tree:

```bash
metadata_commit=$(git log --format=%H --grep='^perf: reuse elastic insert metadata$' -1)
test -n "$metadata_commit"
git revert "$metadata_commit" --no-edit
```

In case 4, after metadata is absent, resolve and revert the placement commit
rather than reverting the metadata-revert commit. In case 1 with an independent
metadata regression, use only the first revert command. In case 3, run neither:

```bash
placement_commit=$(git log --format=%H --grep='^perf: compact elastic placement result$' -1)
test -n "$placement_commit"
git revert "$placement_commit" --no-edit
```

For the retained tree, run:

```bash
cargo test
pre-commit run --all-files
test "$(git status --short)" = "?? docs/performance/2026-07-20-elastic-insert-cleanup.md"
```

Expected: tests and hooks PASS; the only untracked path is the evidence document
created in Step 6; only accepted trace-neutral code changes remain.

- [ ] **Step 8: Commit the evidence record**

```bash
pre-commit run --files docs/performance/2026-07-20-elastic-insert-cleanup.md
git add docs/performance/2026-07-20-elastic-insert-cleanup.md
git commit -m "docs: record elastic insert cleanup evidence"
```
