# Counter PRF Bakeoff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Evaluate current, guarded-wyhash64, Philox2x64-6, and Philox2x64-10 in the real Elastic and Funnel hot paths, then ship only backend choices that materially improve insert without harming get or paper fidelity.

**Architecture:** Put core-only checked encoders and candidate primitives behind temporary compile-time module aliases, with `probe.rs` retaining the map-facing wrappers. An excluded standalone quality package imports those exact source modules for deterministic statistics and raw PractRand/TestU01 streams; candidate worktrees change only compile-time aliases, and the final tree deletes selectors and losing implementations.

**Tech Stack:** Rust 2024/core-only production primitives, standalone Cargo quality tool with `statrs 0.18`, Criterion/CodSpeed, PractRand 0.95+, TestU01 1.2.3, Linux `perf`, GNU `objdump`.

## Global Constraints

- Preserve the paper algorithm's candidate order, exact range reducer, rejection accounting, scheduler, placement cases, and exceptional recovery.
- Distinct supported tuples for one key must never reuse an encoded counter.
- Funnel encoding remains four domains + 46-bit level + 8-bit logical + 8-bit retry.
- Elastic encoding is 5-bit level + 13-bit logical + 3-bit retry; Case 1 is bounded at 8192 probes by `MAX_ELASTIC_SLOTS`, the dyadic square, and `ELASTIC_PROBE_BUDGET_C = 8`.
- The power-of-two high-bit reducer and non-power-of-two multiply-high/rejection reducer remain unchanged.
- `guarded-wyhash64` uses the exact approved ordinary formula, the approved `a == 0` permutation fallback, and no unexplained constants.
- Philox uses multiplier `0xD2B74407B1CE6E93`, Weyl increment `0x9E3779B97F4A7C15`, counter `(encoded_counter, 0)`, and output lane zero.
- Elastic metadata signature uses guarded counter `S2`, or Philox counter `(0, 1)`; insert computes and caches it exactly once, while ordinary get computes it lazily only after H(1,1) misses. Raw `a` and the legacy signature are not allowed substitutions.
- No production dependency, public API, shipped feature flag, dynamic dispatch,
  runtime candidate branch, or new field in `ElasticTable`, `FunnelTable`,
  `Level`, or the existing Funnel shape/storage types. Current source has no
  `BucketLevel`; introducing one is a separately gated layout change.
- Keep root Elastic key state separate from level cache: current cache entries are 8 bytes; guarded and Philox cache entries are zero-sized; no 16-byte prepared-level value is allowed.
- Every candidate formula, constant, lane mapping, round count, and traversal is fixed in source before its result is generated.
- Keep only candidates that pass deterministic, statistical, cross-architecture, full-suite, and assembly/counter gates; otherwise production remains on the current PRF.
- Preserve Rust 1.88, `no_std`, little-endian, and big-endian correctness.
- Hard precondition: Phase 1's table-dependent metadata cache remains rejected
  and reverted, and the accepted compile-time candidate signature-cache
  evidence commit from
  `docs/superpowers/plans/2026-07-21-elastic-candidate-signature-cache.md` is an
  ancestor of this tree. Its evidence must record native AArch64 and x86-64
  acceptance, immutable `cache-off-current`, codegen-neutral
  `cache-policy-current`, and passing forced `cache-on-current` gates. Every
  candidate and final tree is compared directly with `cache-off-current`.
- Before selecting a statistical survivor, benchmark survivor, backend winner, or revert, consult a fresh reviewer subagent; its approval is the user's delegated approval.

---

### Task 1: Add Checked Counter Encodings

**Files:**
- Create: `src/common/exact/prf/mod.rs`
- Create: `src/common/exact/prf/encoding.rs`
- Modify: `src/common/exact/mod.rs`
- Modify: `src/common/exact/probe.rs:1-330`
- Test: `src/common/exact/prf/encoding.rs`

**Interfaces:**
- Consumes: current `ProbeDomain` and Funnel packing behavior.
- Produces: `FunnelDomain`, `try_pack_elastic_counter`, `try_pack_funnel_counter`, and exact boundary tests used by every candidate.

- [ ] **Preflight: Prove the candidate signature-cache evidence was accepted**

```bash
test "$(git rev-list --all --count --grep='^docs: accept elastic candidate signature cache$')" -eq 1
signature_cache_evidence_commit=$(git rev-list --all --grep='^docs: accept elastic candidate signature cache$' -1)
git merge-base --is-ancestor "$signature_cache_evidence_commit" HEAD
signature_cache_evidence_path=docs/performance/2026-07-21-elastic-candidate-signature-cache.md
signature_cache_blob=$(mktemp)
trap 'rm -f "$signature_cache_blob"' EXIT
git show "$signature_cache_evidence_commit:$signature_cache_evidence_path" > "$signature_cache_blob"
test "$(git hash-object "$signature_cache_evidence_path")" = "$(git rev-parse "$signature_cache_evidence_commit:$signature_cache_evidence_path")"
test "$(rg -c '^- Original source commit: `[0-9a-f]{40}`$|^- Cache-off commit: `[0-9a-f]{40}`$|^- Cache-policy commit: `[0-9a-f]{40}`$|^- Cache-on commit: `[0-9a-f]{40}`$|^- Cache-on production diff SHA-256: `[0-9a-f]{64}`$|^- Decision: `ACCEPT`$' "$signature_cache_blob")" -eq 6
cache_source_commit=$(sed -n 's/^- Original source commit: `\([0-9a-f]\{40\}\)`$/\1/p' "$signature_cache_blob")
cache_off_current_commit=$(sed -n 's/^- Cache-off commit: `\([0-9a-f]\{40\}\)`$/\1/p' "$signature_cache_blob")
cache_policy_current_commit=$(sed -n 's/^- Cache-policy commit: `\([0-9a-f]\{40\}\)`$/\1/p' "$signature_cache_blob")
cache_on_current_commit=$(sed -n 's/^- Cache-on commit: `\([0-9a-f]\{40\}\)`$/\1/p' "$signature_cache_blob")
cache_on_diff_sha=$(sed -n 's/^- Cache-on production diff SHA-256: `\([0-9a-f]\{64\}\)`$/\1/p' "$signature_cache_blob")
for commit in "$cache_source_commit" "$cache_off_current_commit" "$cache_policy_current_commit" "$cache_on_current_commit"; do git cat-file -e "$commit^{commit}"; done
git merge-base --is-ancestor "$cache_source_commit" "$cache_off_current_commit"
git merge-base --is-ancestor "$cache_off_current_commit" "$cache_policy_current_commit"
git merge-base --is-ancestor "$cache_policy_current_commit" "$cache_on_current_commit"
git merge-base --is-ancestor "$cache_policy_current_commit" "$signature_cache_evidence_commit"
git diff --quiet "$cache_source_commit" "$cache_off_current_commit" -- src
git diff --quiet "$cache_policy_current_commit" "$signature_cache_evidence_commit" -- src
test "$(git diff --name-only "$cache_policy_current_commit" "$cache_on_current_commit" -- src)" = "src/common/exact/probe.rs"
test "$(git diff --binary "$cache_policy_current_commit" "$cache_on_current_commit" -- src | sha256sum | cut -d' ' -f1)" = "$cache_on_diff_sha"
git show "$cache_policy_current_commit:src/common/exact/probe.rs" | rg "const CACHE_ELASTIC_INSERT_SIGNATURE: bool = false"
git show "$cache_on_current_commit:src/common/exact/probe.rs" | rg "const CACHE_ELASTIC_INSERT_SIGNATURE: bool = true"
rg -n "const CACHE_ELASTIC_INSERT_SIGNATURE: bool = false" src/common/exact/probe.rs
rg -n "insert_metadata|fn signature\(|fn membership\(" src/elastic.rs
cargo test elastic::tests::insert_growth_reindexes_cached_signature_in_production_path -- --exact
cargo test elastic::tests::finite_probe_exhaustion_uses_observable_exceptional_recovery -- --exact
```

Expected: accepted blob equals checked-out blob; every referenced commit exists;
source→off→policy and policy→on/evidence graph is exact; cache-off production
equals recorded original; accepted production equals policy false; cache-on has
only the recorded force-true source diff; both production-path tests PASS.
Otherwise stop; do not add encoders or resurrect `PreparedMetadataWrite`.

- [ ] **Step 1: Write failing boundary and uniqueness tests**

Create `prf/mod.rs` with `pub(crate) mod encoding;`, add `pub(crate) mod prf;`
to `exact/mod.rs`, and create `encoding.rs` containing only this test module.
This makes the red test discoverable while leaving its required API undefined:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn elastic_counter_boundaries_are_checked_and_unique() {
        assert_eq!(try_pack_elastic_counter(0, 0, 0), Some(0));
        assert_eq!(try_pack_elastic_counter(0, 4_095, 7), Some((4_095 << 3) | 7));
        assert_eq!(try_pack_elastic_counter(0, 4_096, 0), Some(4_096 << 3));
        assert_eq!(try_pack_elastic_counter(31, 8_191, 7), Some((31 << 16) | (8_191 << 3) | 7));
        assert_eq!(try_pack_elastic_counter(32, 0, 0), None);
        assert_eq!(try_pack_elastic_counter(0, 8_192, 0), None);
        assert_eq!(try_pack_elastic_counter(0, 0, 8), None);

        let mut seen = BTreeSet::new();
        for level in 0..32 {
            for logical in 0..8_192 {
                for retry in 0..8 {
                    assert!(seen.insert(try_pack_elastic_counter(level, logical, retry).unwrap()));
                }
            }
        }
        assert_eq!(seen.len(), 32 * 8_192 * 8);
    }

    #[test]
    fn funnel_counter_boundaries_remain_exact() {
        assert_eq!(try_pack_funnel_counter(FunnelDomain::Ordinary(0), 0, 0), Some(0));
        assert_eq!(
            try_pack_funnel_counter(FunnelDomain::Ordinary((1 << 46) - 1), 255, 255),
            Some(0x3fff_ffff_ffff_ffff),
        );
        assert_eq!(
            try_pack_funnel_counter(FunnelDomain::Primary, 255, 255),
            Some(0x4000_0000_0000_ffff),
        );
        assert_eq!(try_pack_funnel_counter(FunnelDomain::Ordinary(1 << 46), 0, 0), None);
        assert_eq!(try_pack_funnel_counter(FunnelDomain::Primary, 256, 0), None);
        assert_eq!(try_pack_funnel_counter(FunnelDomain::Primary, 0, 256), None);
    }
}
```

Run:

```bash
if cargo test common::exact::prf::encoding::tests > target/encoding-red.txt 2>&1; then
    echo "error: encoding red test unexpectedly passed" >&2
    exit 1
fi
rg -n "cannot find (function|type).*try_pack|cannot find type.*FunnelDomain" target/encoding-red.txt
```

Expected: nonzero compile/test status and the captured diagnostics name the
undefined checked encoders/domain. Zero discovered tests or a successful run is
not an acceptable red state.

- [ ] **Step 2: Implement the exact core-only encoders**

Add this implementation above the retained tests in `encoding.rs`:

```rust
const ELASTIC_LEVEL_LIMIT: u32 = 1 << 5;
const ELASTIC_LOGICAL_LIMIT: u64 = 1 << 13;
const ELASTIC_RETRY_LIMIT: u32 = 1 << 3;
const FUNNEL_LEVEL_LIMIT: u64 = 1 << 46;
const FUNNEL_LOGICAL_LIMIT: u64 = 1 << 8;
const FUNNEL_RETRY_LIMIT: u32 = 1 << 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FunnelDomain {
    Ordinary(u64),
    Primary,
    FallbackA,
    FallbackB,
}

pub(crate) const fn try_pack_elastic_counter(
    level: u32,
    logical: u64,
    retry: u32,
) -> Option<u64> {
    if level >= ELASTIC_LEVEL_LIMIT
        || logical >= ELASTIC_LOGICAL_LIMIT
        || retry >= ELASTIC_RETRY_LIMIT
    {
        return None;
    }
    Some((level as u64) << 16 | logical << 3 | retry as u64)
}

pub(crate) const fn try_pack_funnel_counter(
    domain: FunnelDomain,
    logical: u64,
    retry: u32,
) -> Option<u64> {
    if logical >= FUNNEL_LOGICAL_LIMIT || retry >= FUNNEL_RETRY_LIMIT {
        return None;
    }
    let (tag, level) = match domain {
        FunnelDomain::Ordinary(level) if level < FUNNEL_LEVEL_LIMIT => (0_u64, level),
        FunnelDomain::Primary => (1, 0),
        FunnelDomain::FallbackA => (2, 0),
        FunnelDomain::FallbackB => (3, 0),
        FunnelDomain::Ordinary(_) => return None,
    };
    Some((tag << 62) | (level << 16) | (logical << 8) | retry as u64)
}
```

The module wiring already exists from Step 1. Keep
`probe::try_pack_funnel_counter` as a wrapper that maps `ProbeDomain` to
`FunnelDomain`, so callers continue to use `probe::...`.

- [ ] **Step 3: Add compile-time layout and secret exclusions**

Define `WYHASH_DEFAULT_SECRET` once in `prf/mod.rs`, have `probe.rs` expose its
existing constant as an alias to that one source, and in `encoding.rs` add:

```rust
use super::WYHASH_DEFAULT_SECRET;

const S1: u64 = WYHASH_DEFAULT_SECRET[1];
const S2: u64 = WYHASH_DEFAULT_SECRET[2];
const _: () = assert!(S1 >> 21 != 0);
const _: () = assert!(S2 >> 21 != 0);
const _: () = assert!((S1 >> 62) != 0 && ((S1 >> 16) & ((1_u64 << 46) - 1)) != 0);
const _: () = assert!((S2 >> 62) != 0 && ((S2 >> 16) & ((1_u64 << 46) - 1)) != 0);
const _: () = assert!(S1 != S2);
```

Expected: changes to secrets or layouts that make `S1`/`S2` valid counters fail compilation.

- [ ] **Step 4: Run encoding and existing oracle tests**

```bash
cargo test common::exact::prf::encoding::tests
cargo test common::exact::probe::tests::fast_funnel_counter_pack_is_injective_and_checked -- --exact
cargo test common::exact::probe::tests::prepared_elastic_probe_is_bit_identical_to_the_full_counter_prf -- --exact
```

Expected: all tests PASS.

- [ ] **Step 5: Commit the encoding boundary**

```bash
git add src/common/exact/mod.rs src/common/exact/prf/mod.rs src/common/exact/prf/encoding.rs src/common/exact/probe.rs
git commit -m "refactor: define checked probe counters"
```

### Task 2: Add a Trace-Neutral Compile-Time Current-PRF Module

**Files:**
- Create: `src/common/exact/prf/current.rs`
- Modify: `src/common/exact/prf/mod.rs`
- Modify: `src/common/exact/probe.rs:60-320`
- Modify: `src/elastic.rs`
- Test: `src/common/exact/probe.rs:820-1165`

**Interfaces:**
- Consumes: checked encoders from Task 1, current golden vectors, and the accepted policy-false signature-cache scaffold.
- Produces: identical inherent candidate API in `current`, including `CACHE_ELASTIC_INSERT_SIGNATURE`, temporary aliases `active_elastic`/`active_funnel`, and thin map-facing wrappers in `probe.rs`.

- [ ] **Step 1: Pin unchanged current vectors and sizes**

Extend existing golden tests to assert:

```rust
assert_eq!(core::mem::size_of::<PreparedElasticProbe>(), 8);
assert_eq!(core::mem::size_of::<PreparedElasticLevelProbe>(), 8);
assert_eq!(core::mem::size_of::<PreparedFastFunnelProbe>(), 16);
assert_eq!(core::mem::size_of::<PreparedFastFunnelDomainProbe>(), 24);
```

Run the current vector tests and save their output:

```bash
cargo test common::exact::probe::tests::prepared_elastic_probe_is_bit_identical_to_the_full_counter_prf -- --exact
cargo test common::exact::probe::tests::fast_funnel_counter_permutation_has_fixed_golden_vectors -- --exact
```

Then force a rebuild, collect the accepted signature-cache tree's actual
CodSpeed/Callgrind counts, and capture its exact benchmark executable:

```bash
cargo clean -p opthash
CARGO_INCREMENTAL=0 cargo codspeed build --bench speedup
cargo codspeed run --bench speedup 2>&1 | tee target/pre-scaffold-callgrind.txt
cargo bench --bench speedup --no-run --message-format=json > target/pre-scaffold-cargo.json
jq -r 'select(.reason == "compiler-artifact" and .target.name == "speedup" and .executable != null) | .executable' target/pre-scaffold-cargo.json | sort -u > target/pre-scaffold-executables.txt
test "$(wc -l < target/pre-scaffold-executables.txt)" -eq 1
speedup_bin=$(sed -n '1p' target/pre-scaffold-executables.txt)
test -n "$speedup_bin"
test -x "$speedup_bin"
test "$(stat -c %Y "$speedup_bin")" -ge "$(git show -s --format=%ct HEAD)"
objdump -d -C "$speedup_bin" > target/pre-scaffold-speedup.asm
git rev-parse HEAD > target/pre-scaffold-commit.txt
```

Expected: tests PASS before the refactor. The evidence records the exact
per-operation instruction counts, benchmark executable, mtime, and accepted
cleanup commit.

- [ ] **Step 2: Implement the current candidate with the existing formulas**

In `current.rs`, define the existing constants, `mix64`, and `absorb` byte-for-byte, then expose these types and functions:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedElastic { domain_state: u64 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ElasticLevelCache(u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedFunnel { key_in: u64, key_out: u64 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedFunnelDomain { key_in: u64, key_out: u64, counter_base: u64 }

#[inline]
pub(crate) fn prepare_elastic(seed: u64, hash: u64) -> PreparedElastic {
    let state = mix64(seed.wrapping_add(INITIAL_LANE));
    let state = absorb(state, hash, S0);
    PreparedElastic { domain_state: absorb(state, 1, S1) }
}

pub(crate) const fn elastic_level_address(level: u32) -> Option<u64> {
    if level < 32 {
        Some(mix64((level as u64).wrapping_add(S2)))
    } else {
        None
    }
}

pub(crate) const fn elastic_logical_address(logical: u64) -> Option<u64> {
    if logical < 8_192 {
        Some(mix64(logical.wrapping_add(S3)))
    } else {
        None
    }
}

pub(crate) const CACHE_ELASTIC_LEVELS: bool = true;
pub(crate) const CACHE_ELASTIC_INSERT_SIGNATURE: bool = false;

pub(crate) fn prepare_elastic_level(
    root: PreparedElastic,
    level_address: u64,
) -> ElasticLevelCache {
    ElasticLevelCache(mix64(root.domain_state.wrapping_add(level_address)))
}

#[inline(always)]
pub(crate) fn elastic_word(
    _root: PreparedElastic,
    level_cache: ElasticLevelCache,
    _level_address: u64,
    logical_address: u64,
    retry: u8,
) -> u64 {
    let state = mix64(level_cache.0.wrapping_add(logical_address));
    let retry_lane = if retry == 0 {
        mix64(RETRY_LANE)
    } else {
        mix64(u64::from(retry).wrapping_add(RETRY_LANE))
    };
    mix64(state.wrapping_add(retry_lane))
}

#[inline]
pub(crate) const fn elastic_signature(prepared: PreparedElastic) -> u64 {
    prepared.domain_state
}
```

Implement Funnel with the current equations:

```rust
#[inline]
pub(crate) fn prepare_funnel(seed: u64, hash: u64) -> PreparedFunnel {
    let keyed = hash.wrapping_add(seed);
    PreparedFunnel {
        key_in: mix64(keyed.wrapping_add(S0)),
        key_out: mix64(keyed.wrapping_add(S1)),
    }
}

#[inline(always)]
pub(crate) const fn prepare_funnel_domain(
    prepared: PreparedFunnel,
    counter_base: u64,
) -> PreparedFunnelDomain {
    PreparedFunnelDomain { key_in: prepared.key_in, key_out: prepared.key_out, counter_base }
}

#[inline(always)]
pub(crate) fn funnel_word(prepared: PreparedFunnelDomain, logical: u8, retry: u8) -> u64 {
    let counter = prepared.counter_base | (u64::from(logical) << 8) | u64::from(retry);
    mix64(counter ^ prepared.key_in) ^ prepared.key_out
}
```

Add checked `elastic_word_for_tuple` and `funnel_word_for_tuple` compositions
that call these same address, preparation, and word functions. They return
`None` when the Task 1 encoder rejects a field and are the only current-formula
entry points used by the quality tool.

- [ ] **Step 3: Add compile-time aliases and thin wrappers**

In `prf/mod.rs`:

```rust
pub(crate) mod current;
pub(crate) use current as active_elastic;
pub(crate) use current as active_funnel;
```

Make `PreparedElasticProbe` wrap the active root and
`PreparedElasticLevelProbe` wrap only `active_elastic::ElasticLevelCache`.
Move the accepted current property from its temporary owner in `probe.rs` to
`current::CACHE_ELASTIC_INSERT_SIGNATURE`, and make `PreparedElasticKey` select
through `active_elastic::CACHE_ELASTIC_INSERT_SIGNATURE`. Do not duplicate or
leave a fallback constant in `probe.rs`.
Change the internal reducer/route call shape to carry root and addresses
separately:

```rust
fn unbiased_prepared_elastic_probe_index(
    root: PreparedElasticProbe,
    level_cache: PreparedElasticLevelProbe,
    level_address: u64,
    logical_address: u64,
    upper: usize,
    max_words: u32,
) -> Result<ProbeIndex, RangeReductionError>;
```

The current module ignores the extra root/address arguments in `elastic_word`.
Keep the existing 32×8-byte current level cache and prepared-level bitmask.
Have existing `elastic.rs` call sites pass the same precomputed level/logical
addresses they already use.

Expected: aliases resolve at compile time; no enum, trait, function pointer, or runtime branch exists.

- [ ] **Step 4: Verify semantics and commit the scaffold**

Run:

```bash
cargo test common::exact::probe::tests
cargo test
git add src/common/exact/prf/current.rs src/common/exact/prf/mod.rs src/common/exact/probe.rs src/elastic.rs
git commit -m "refactor: isolate current counter prf"
```

Expected: tests PASS and the trace-neutral scaffold is one independently revertible commit.

- [ ] **Step 5: Verify code-generation identity and hard-stop on any non-neutral scaffold**

Run:

```bash
cargo clean -p opthash
CARGO_INCREMENTAL=0 cargo codspeed build --bench speedup
cargo codspeed run --bench speedup 2>&1 | tee target/current-module-callgrind.txt
cargo bench --bench speedup --no-run --message-format=json > target/current-module-cargo.json
jq -r 'select(.reason == "compiler-artifact" and .target.name == "speedup" and .executable != null) | .executable' target/current-module-cargo.json | sort -u > target/current-module-executables.txt
test "$(wc -l < target/current-module-executables.txt)" -eq 1
speedup_bin=$(sed -n '1p' target/current-module-executables.txt)
test -n "$speedup_bin"
test -x "$speedup_bin"
test "$(stat -c %Y "$speedup_bin")" -ge "$(git show -s --format=%ct HEAD)"
objdump -d -C "$speedup_bin" > target/current-module-speedup.asm
```

Compare against both the exact-binary assembly/rebuilt CodSpeed output captured
for the accepted signature-cache commit immediately before Step 2 and the
immutable `cache-off-current` original recorded in its evidence. Record
exact per-operation instruction counts for Elastic/Funnel insert, randomized
get, ordered get, and controls. Whole binaries may differ in symbol ordering,
so compare the corresponding hot symbol bodies; demand byte identity there and
exactly ±0 Callgrind instructions for every named operation. Also require the
fixed-control executable SHA-256 and stable-layout preflight from the signature
cache plan to remain valid. Current policy must be false in both comparisons.

If any hot body or named Callgrind count differs, revert only the scaffold
commit and stop this plan:

```bash
git revert HEAD --no-edit
```

Do not create candidate branches or substitute candidate formulas after a
non-neutral result. Revise this task, restore byte-identical hot codegen, obtain
fresh reviewer approval, and repeat the identity gate before continuing. If
the hot bodies and counts are identical, retain the scaffold and continue.

### Task 3: Implement Guarded-Wyhash and Philox Candidates

**Files:**
- Create: `src/common/exact/prf/guarded_wyhash.rs`
- Create: `src/common/exact/prf/philox_core.rs`
- Create: `src/common/exact/prf/philox6.rs`
- Create: `src/common/exact/prf/philox10.rs`
- Modify: `src/common/exact/prf/mod.rs`
- Test: each candidate module inline

**Interfaces:**
- Consumes: `encoding::{FunnelDomain, try_pack_elastic_counter, try_pack_funnel_counter}`.
- Produces: identical prepared/address/word/signature APIs plus checked `elastic_word_for_tuple` and `funnel_word_for_tuple` for the quality tool.

- [ ] **Step 1: Write guarded-wyhash algebraic and golden tests**

Add `pub(crate) mod guarded_wyhash;` to `prf/mod.rs`, create
`guarded_wyhash.rs` containing only these tests, and run the targeted test to
obtain a discoverable red compile before adding any implementation. Tests must
cover normal and exceptional keys, invalid counters, secrets, and boundaries:

```rust
#[cfg(test)]
mod tests {
use super::*;
use alloc::collections::BTreeSet;

#[test]
fn guarded_word_never_collapses_the_zero_factor_key() {
    let seed = S0;
    let prepared = prepare_elastic(seed, 0);
    let words = [0_u64, 1, 4_095, 4_096, 8_191]
        .map(|logical| elastic_word_for_tuple(seed, 0, 0, logical, 0).unwrap());
    assert_eq!(prepared.a, 0);
    assert_eq!(words.into_iter().collect::<BTreeSet<_>>().len(), words.len());
    assert_eq!(words, [
        0xa3a5_e03e_e742_3204,
        0xdaf7_88b4_1c6b_02b7,
        0x538a_418c_ff1c_c7d8,
        0xaf4e_c084_c6d0_d276,
        0x007a_8182_24e7_ddee,
    ]);
}

#[test]
fn guarded_boundaries_and_signature_have_fixed_vectors() {
    let vectors = [
        (0_u64, 0_u64, 0_u32, 0_u64, 0_u32, 0xfa30_3abc_2b1d_7630, 0x3bc4_db7a_9d46_38e9),
        (u64::MAX, u64::MAX, 31, 8_191, 7, 0x1bbd_74cd_2959_0d91, 0x3bc4_db7a_9d46_38e9),
        (S0, S1, 0, 4_096, 1, 0x0356_8db1_8b73_1def, 0xc04a_c104_2005_c161),
    ];
    for (seed, hash, level, logical, retry, word, signature) in vectors {
        assert_eq!(elastic_word_for_tuple(seed, hash, level, logical, retry), Some(word));
        assert_eq!(elastic_signature(prepare_elastic(seed, hash)), signature);
    }
    assert!(elastic_word_for_tuple(0, 0, 32, 0, 0).is_none());
    assert!(elastic_word_for_tuple(0, 0, 0, 8_192, 0).is_none());
    assert!(elastic_word_for_tuple(0, 0, 0, 0, 8).is_none());
}

#[test]
fn guarded_algebraic_keys_and_nearby_counters_do_not_form_constant_streams() {
    let values = [0, u64::MAX, S0, S1, S2, S3];
    let mut keys = values.to_vec();
    for left in values {
        for right in values {
            keys.push(left ^ right);
        }
    }
    keys.sort_unstable();
    keys.dedup();
    for seed in values {
        for hash in keys.iter().copied() {
            let words = [0_u64, 1, 4_095, 4_096, 8_191]
                .map(|logical| elastic_word_for_tuple(seed, hash, 0, logical, 0).unwrap());
            assert!(words.windows(2).any(|pair| pair[0] != pair[1]), "seed={seed:#x} hash={hash:#x}");
        }
    }
}
}
```

Run and require a nonzero status whose diagnostics name the undefined guarded
functions/types; a successful or zero-test run is invalid:

```bash
if cargo test common::exact::prf::guarded_wyhash::tests > target/guarded-red.txt 2>&1; then
    echo "error: guarded red tests unexpectedly passed" >&2
    exit 1
fi
rg -n "cannot find (function|type).*guarded|cannot find function.*elastic_word_for_tuple|cannot find function.*prepare_elastic" target/guarded-red.txt
```

- [ ] **Step 2: Implement guarded-wyhash exactly**

The shared word function is:

```rust
#[inline(always)]
const fn guarded_word_from_counter(a: u64, counter: u64) -> u64 {
    if a == 0 {
        return mix64(counter ^ S2) ^ S3;
    }
    let first = (a as u128) * ((counter ^ S1) as u128);
    let lo = first as u64;
    let hi = (first >> 64) as u64;
    let second = ((lo ^ S0) as u128) * ((hi ^ S1) as u128);
    second as u64 ^ (second >> 64) as u64
}
```

Use 8-byte prepared states and the approved lazy signature:

```rust
const ELASTIC_METADATA_COUNTER: u64 = S2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedElastic { a: u64 }
pub(crate) type ElasticLevelCache = ();
pub(crate) const CACHE_ELASTIC_LEVELS: bool = false;
pub(crate) const CACHE_ELASTIC_INSERT_SIGNATURE: bool = true;

#[inline]
pub(crate) const fn prepare_elastic(seed: u64, hash: u64) -> PreparedElastic {
    PreparedElastic { a: (hash ^ seed) ^ S0 }
}

#[inline]
pub(crate) const fn elastic_signature(prepared: PreparedElastic) -> u64 {
    guarded_word_from_counter(prepared.a, ELASTIC_METADATA_COUNTER)
}

#[inline]
pub(crate) fn prepare_elastic_level(
    _root: PreparedElastic,
    _level_address: u64,
) -> ElasticLevelCache {}

#[inline(always)]
pub(crate) fn elastic_word(
    root: PreparedElastic,
    _level_cache: ElasticLevelCache,
    level_address: u64,
    logical_address: u64,
    retry: u8,
) -> u64 {
    guarded_word_from_counter(
        root.a,
        level_address | logical_address | u64::from(retry),
    )
}
```

Elastic addresses are `level << 16` and `logical << 3`; Funnel uses its checked counter base. `elastic_word` ORs base, logical address, and retry before calling the guarded word. `funnel_word` ORs its base, `logical << 8`, and retry. Checked tool functions must call these same preparation and word functions rather than duplicate the formula.

Run `cargo test common::exact::prf::guarded_wyhash::tests` and require PASS
before writing Philox tests.

- [ ] **Step 3: Write published Philox known-answer and domain tests**

Add `pub(crate) mod philox_core;`, `pub(crate) mod philox6;`, and `pub(crate) mod
philox10;` to `prf/mod.rs`. Create those three files with test modules only:
put the core Random123 vectors in `philox_core.rs` and each wrapper's checked
tuple/metadata tests in its own file. Add tests for both round counts and
metadata separation:

```rust
#[test]
fn metadata_lane_is_disjoint_from_regular_probe_lanes() {
    for encoded in [0, 1, (31 << 16) | (8_191 << 3) | 7, u64::MAX] {
        assert_ne!((encoded, 0), (0, 1));
    }
}

#[test]
fn six_and_ten_round_variants_are_distinct_and_deterministic() {
    assert_eq!(
        philox2x64::<6>(0, 0, 0),
        (0x7ee2_7967_82e4_de12, 0x6921_e1f4_eea1_2943),
    );
    assert_eq!(
        philox2x64::<10>(0, 0, 0),
        (0xca00_a045_9843_d731, 0x66c2_4222_c9a8_45b5),
    );
    assert_eq!(
        philox2x64::<6>(u64::MAX, u64::MAX, u64::MAX),
        (0x62cb_7fa1_1e10_1713, 0x4074_1ef3_d337_be5d),
    );
    assert_eq!(
        philox2x64::<10>(u64::MAX, u64::MAX, u64::MAX),
        (0x65b0_21d6_0cd8_310f, 0x4d02_f322_2f86_df20),
    );
}
```

Verify these literal vectors against the Random123 reference implementation before the task is committed.

Before implementation, require discoverable red failures:

```bash
if cargo test common::exact::prf::philox_core::tests > target/philox-core-red.txt 2>&1; then
    echo "error: Philox core red tests unexpectedly passed" >&2
    exit 1
fi
if cargo test common::exact::prf::philox6::tests > target/philox6-red.txt 2>&1; then
    echo "error: Philox6 red tests unexpectedly passed" >&2
    exit 1
fi
if cargo test common::exact::prf::philox10::tests > target/philox10-red.txt 2>&1; then
    echo "error: Philox10 red tests unexpectedly passed" >&2
    exit 1
fi
rg -n "cannot find function.*philox|cannot find (function|type).*prepare" target/philox-core-red.txt target/philox6-red.txt target/philox10-red.txt
```

- [ ] **Step 4: Implement Philox core and fixed-round wrappers**

In `philox_core.rs`:

```rust
const MULTIPLIER: u64 = 0xD2B7_4407_B1CE_6E93;
const WEYL: u64 = 0x9E37_79B9_7F4A_7C15;

#[inline(always)]
pub(crate) const fn philox2x64<const ROUNDS: usize>(
    mut lane0: u64,
    mut lane1: u64,
    mut key: u64,
) -> (u64, u64) {
    let mut round = 0;
    while round < ROUNDS {
        let product = (MULTIPLIER as u128) * (lane0 as u128);
        let lo = product as u64;
        let hi = (product >> 64) as u64;
        lane0 = hi ^ key ^ lane1;
        lane1 = lo;
        key = key.wrapping_add(WEYL);
        round += 1;
    }
    (lane0, lane1)
}
```

`philox6.rs` and `philox10.rs` expose the identical candidate API, calling `philox2x64::<6>` and `::<10>`. Every prepared state in guarded and Philox derives `Clone, Copy, Debug, Eq, PartialEq` so the existing map-facing wrapper derives remain valid. Prepared Elastic stores only `key_hash ^ backend_seed`; `ElasticLevelCache = ()`, `CACHE_ELASTIC_LEVELS = false`, and `CACHE_ELASTIC_INSERT_SIGNATURE = true`; regular probes call `(encoded_counter, 0)` and `elastic_signature` calls `(0, 1)`. Funnel uses the same regular mapping. `current.rs` alone sets `CACHE_ELASTIC_INSERT_SIGNATURE = false`.

Add size assertions:

```rust
const _: () = assert!(core::mem::size_of::<current::ElasticLevelCache>() == 8);
const _: () = assert!(core::mem::size_of::<guarded_wyhash::ElasticLevelCache>() == 0);
const _: () = assert!(core::mem::size_of::<philox6::ElasticLevelCache>() == 0);
const _: () = assert!(core::mem::size_of::<philox10::ElasticLevelCache>() == 0);
const _: () = assert!(!current::CACHE_ELASTIC_INSERT_SIGNATURE);
const _: () = assert!(guarded_wyhash::CACHE_ELASTIC_INSERT_SIGNATURE);
const _: () = assert!(philox6::CACHE_ELASTIC_INSERT_SIGNATURE);
const _: () = assert!(philox10::CACHE_ELASTIC_INSERT_SIGNATURE);
```

In `find_by_exact_schedule`, branch only on the compile-time
`active_elastic::CACHE_ELASTIC_LEVELS`. Current retains the existing cache and
bitmask. Guarded/Philox prepare `()` and LLVM must remove the cache array,
bitmask, and branch entirely. If it does not, use a source-selected packed
helper in candidate worktrees; never carry root key state inside cache entries.

In `PreparedElasticKey`, select the accepted insert union word only through
`active_elastic::CACHE_ELASTIC_INSERT_SIGNATURE`. Guarded/Philox insert must
evaluate `elastic_signature` exactly once and retain that full word through
placement; precheck and record may each derive Bloom bits but must derive their
word index from current geometry. Ordinary lookup remains `PreparedElasticRoute`
only and must return an H(1,1) hit before guarded `S2` or Philox `(0,1)` work.
Release assembly must contain no surviving branch for either candidate
property.

Run the three targeted module test filters and require PASS before proceeding
to the cross-platform aggregate in Step 5.

- [ ] **Step 5: Run all candidate vectors, algebraic cases, and endian checks**

```bash
cargo test common::exact::prf
cargo test common::exact::probe::tests
```

Run the same known-answer tests natively on the pinned AArch64 and x86-64
hosts. The repository has an s390x wheel cross-build but no configured
big-endian test runner, so use `cross`'s s390x QEMU image on the Docker-enabled
x86-64 host:

```bash
cargo install cross --version 0.2.5 --locked
cross --version
docker info
cross test --target s390x-unknown-linux-gnu common::exact::prf
cross test --target s390x-unknown-linux-gnu common::exact::probe::tests
```

Record the `cross`, Docker, QEMU image digest, Rust, and target versions. Every
vector test must also round-trip `word.to_le_bytes()`/`u64::from_le_bytes` and
`word.to_be_bytes()`/`u64::from_be_bytes`.

Expected: all native tests PASS and literal integer words are identical on
little- and big-endian runners.

- [ ] **Step 6: Commit candidate primitives**

```bash
git add src/common/exact/prf
git commit -m "feat: add counter prf candidates"
```

### Task 4: Build the Exact-Source Statistical and Stream Tool

**Files:**
- Modify: `Cargo.toml:10-27`
- Create: `src/common/exact/reduce.rs`
- Modify: `src/common/exact/mod.rs`
- Modify: `src/common/exact/probe.rs`
- Create: `tools/prf-quality/Cargo.toml`
- Create: `tools/prf-quality/Cargo.lock`
- Create: `tools/prf-quality/src/main.rs`
- Create: `tools/prf-quality/src/traversal.rs`
- Create: `tools/prf-quality/src/stats.rs`
- Create: `tools/prf-quality/testu01/driver.c`
- Create: `scripts/prf-quality.sh`
- Test: `tools/prf-quality/src/*.rs`

**Interfaces:**
- Consumes: exact candidate and production reducer modules via path modules, fixed SplitMix seed `0xD1B54A32D192ED03`, and the approved five traversals.
- Produces: `quality`, `stream`, and `vectors` commands; raw `u64le`/`u32le` stdout streams; deterministic rejection reports.

- [ ] **Step 1: Extract the exact word reducers and hard-gate codegen neutrality**

First write failing parity tests covering `upper` values `1`, every power of
two representable by `usize`, every range family used below, words `0`, `1`,
`u64::MAX`, each rejection boundary, and `2^20` deterministic SplitMix words.
Then create `src/common/exact/reduce.rs` with only the production arithmetic:

```rust
#[inline]
pub(crate) fn rejection_threshold(upper: usize) -> u64 {
    let upper_word = upper as u64;
    upper_word.wrapping_neg() % upper_word
}

#[inline(always)]
pub(crate) fn power_of_two_index(word: u64, upper: usize) -> usize {
    if upper == 1 {
        0
    } else {
        let index_bits = upper.trailing_zeros();
        (word >> (u64::BITS - index_bits)) as usize
    }
}

#[allow(clippy::cast_possible_truncation)]
#[inline(always)]
pub(crate) fn multiply_high_if_accepted(
    word: u64,
    upper: usize,
    threshold: u64,
) -> Option<usize> {
    let product = (word as u128) * (upper as u128);
    (product as u64 >= threshold).then_some((product >> u64::BITS) as usize)
}
```

Make `exact/mod.rs` declare `pub(crate) mod reduce;`. Replace the duplicated
power-of-two shift, rejection-threshold calculation, and multiply-high
acceptance bodies in `probe.rs` with calls through `reduce::...`. Preserve the
existing outer control flow exactly: Elastic alone uses the power-of-two fast
path, Funnel continues to use multiply-high for every prepared range, and
retry/error accounting stays in `probe.rs`.

Before editing, force-build and save exact hot assembly plus actual
CodSpeed/Callgrind per-operation counts using the JSON executable-resolution
recipe from Task 2. After editing, repeat the rebuild and compare corresponding
Elastic/Funnel insert/get hot bodies byte-for-byte and every named instruction
count at ±0. Run:

```bash
cargo test common::exact::reduce::tests
cargo test common::exact::probe::tests
cargo test
```

If codegen or any Callgrind count changes, revert the extraction and stop the
plan; revise it and obtain fresh reviewer approval. Continue only after exact
neutrality, then commit:

```bash
git add src/common/exact/mod.rs src/common/exact/reduce.rs src/common/exact/probe.rs
git commit -m "refactor: share exact probe word reducer"
```

- [ ] **Step 2: Exclude the tool and create its isolated manifest**

Add `"/tools/"` to the root package `exclude`. Create:

```toml
[package]
name = "opthash-prf-quality"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
statrs = { version = "0.18.0", default-features = false }
```

Expected: production `Cargo.lock` and dependency graph remain unchanged when the tool is not invoked.

- [ ] **Step 3: Define fixed CLI enums and exact-source imports**

First add parser table tests for every accepted form below, missing termination
mode, both termination modes, zero/over-limit words, unknown candidate,
unknown traversal, unknown format, and unknown flag. Run them and observe FAIL
because the parser is absent. Then put these imports and enums at the top of
tool `main.rs`:

```rust
#[path = "../../../src/common/exact/prf/mod.rs"]
mod prf;
#[path = "../../../src/common/exact/reduce.rs"]
mod exact_reduce;
mod stats;
mod traversal;

extern crate alloc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Candidate { Current, Guarded, Philox6, Philox10 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Traversal { KeyMajor, CounterMajor, DomainInterleaved, Strided, Adversarial }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamFormat { U64Le, U32Le }
```

Parse exactly these forms and reject every unknown/missing argument with exit status 2:

```text
quality --candidate current|guarded|philox6|philox10
stream --elastic-candidate current|guarded|philox6|philox10 --funnel-candidate current|guarded|philox6|philox10 --traversal key-major|counter-major|domain-interleaved|strided|adversarial --format u64le|u32le (--words POSITIVE_U64 | --until-broken-pipe)
vectors --candidate current|guarded|philox6|philox10
```

`stream` dispatches an Elastic tuple to `elastic_candidate` and a Funnel tuple
to `funnel_candidate`, so a mixed production composition is tested exactly.
For single-candidate screening, pass the same candidate to both flags. Only
stream bytes go to stdout; all labels and errors use stderr. Require exactly
one termination mode. `--words` must not exceed `STREAM_WORD_LIMIT` and writes
exactly that many words; `--until-broken-pipe` treats EPIPE as success but
errors if the injective stream limit is exhausted first.

- [ ] **Step 4: Fix traversal families and first-word vectors in source**

First write the first-32 golden, restart, acceptance, uniqueness, period-edge,
and limit tests described below and observe FAIL. Then in `traversal.rs`,
define:

```rust
pub(crate) const SPLITMIX_SEED: u64 = 0xD1B5_4A32_D192_ED03;
pub(crate) const BASE_COUNT: usize = 1 << 14;
pub(crate) const STREAM_WORDS: usize = 1 << 20;
pub(crate) const ODD_STRIDE: u64 = 0x9E37_79B9_7F4A_7C15;
pub(crate) const BOUNDARY_KEYS: &[u64] = &[
    0,
    u64::MAX,
    0x2D35_8DCC_AA6C_78A5,
    0x8BB8_4B93_962E_ACC9,
    0x4B33_A62E_D433_D4A3,
    0x4D5A_2DA5_1DE1_AA47,
];
pub(crate) const ELASTIC_LOGICAL_BOUNDARIES: &[u64] = &[0, 1, 383, 384, 4_095, 4_096, 8_190, 8_191];
pub(crate) const FUNNEL_LEVEL_BOUNDARIES: &[u64] = &[0, 1, (1 << 46) - 2, (1 << 46) - 1];
```

Implement two deliberately separate APIs:

- `quality_tuples()` is the finite deterministic Cartesian fixture used by
  avalanche, collision, correlation, metadata, and reducer checks. It retains
  the exact boundary keys and classes below.
- `stream_tuple(index: u64) -> Option<BackendTuple>` is the long-running raw
  stream mapping. Set `STREAM_WORD_LIMIT = 1_u64 << 40`, 128 times
  the `2^33` `u64` words consumed by a 64-GiB PractRand run. It must be
  injective in the complete `(backend, key, domain, logical, retry)` tuple for
  every index below that limit.

For every traversal, split `index` into a bounded schedule ordinal and an epoch.
Put a class tag in the high eight key bits and map the epoch through a fixed
invertible 56-bit xorshift/odd-multiply permutation in the low bits. Distinct
class tags occupy disjoint key spaces; within a class, the permutation makes
epochs unique; within an epoch, schedule ordinals must have distinct backend
coordinates. Document this injectivity argument next to the code.

Implement the five approved finite orders and their stream schedules:

1. `key-major`: for key index `i`, cycle sequential `i`, SplitMix(`i`),
   `1 << (i % 64)`, `i & 0xffff`, `(i & 0xffff) << 48`, and
   `(i & 0xff) * 0x0101010101010101`; for each key, visit the declared
   Elastic boundary counters followed by every Funnel domain boundary.
2. `counter-major`: advance Elastic logical fields and Funnel ordinary levels
   in numeric order, visiting keys `0`, `u64::MAX`, every secret, and every
   pairwise secret XOR at each counter.
3. `domain-interleaved`: for each SplitMix key, emit Elastic ordinary, Funnel
   ordinary, primary, fallback-A, and fallback-B in that exact order.
4. `strided`: set key to `index * ODD_STRIDE`, Elastic logical to the low 13
   bits, Funnel level to the low 46 bits, and alternate backend/domain by
   `index % 5`.
5. `adversarial`: the finite fixture takes the Cartesian product of `BOUNDARY_KEYS`, every pairwise
   secret XOR, their one-bit neighbors, `ELASTIC_LOGICAL_BOUNDARIES`,
   `FUNNEL_LEVEL_BOUNDARIES`, and retry boundaries in lexicographic order. Its
   stream schedule repeats those boundary coordinate classes only after
   advancing to a new injectively encoded key epoch.

Add tests for the first 32 tuples of every traversal, deterministic restart,
checked-encoder acceptance, and no complete-tuple duplicate in a `HashSet` for
the first `2^20` stream indices of each traversal. Test indices surrounding
every schedule-period boundary and the final valid index; assert the first
invalid index returns `None`. A proof comment and these tests are both required.

- [ ] **Step 5: Implement calibrated statistical gates**

First write failing golden tests for Holm stop behavior, exact two-sided
binomial endpoints/center, chi-square upper tails, collision thresholds, and
positive/negative correlation boundaries. Then in `stats.rs`, use exact
binomial and chi-square distributions. The Holm gate is:

```rust
fn holm_rejections(mut tests: Vec<NamedPValue>, family_alpha: f64) -> Vec<NamedPValue> {
    tests.sort_by(|left, right| left.p.total_cmp(&right.p));
    let family_size = tests.len();
    let mut rejected = Vec::new();
    for (rank, test) in tests.into_iter().enumerate() {
        let threshold = family_alpha / (family_size - rank) as f64;
        if test.p > threshold {
            break;
        }
        rejected.push(test);
    }
    rejected
}
```

For each avalanche cell with `successes` out of `BASE_COUNT`:

```rust
let null = Binomial::new(0.5, BASE_COUNT as u64).unwrap();
let lower = null.cdf(successes as u64);
let upper = if successes == 0 {
    1.0
} else {
    1.0 - null.cdf(successes as u64 - 1)
};
let p = (2.0 * lower.min(upper)).min(1.0);
```

Put all key/counter cells for all declared classes into one `1e-6` Holm family. Put all upper-tail range chi-square p-values into a second `1e-6` Holm family. Also reject more than two full-width collisions per `2^20` traversal or absolute serial/cross-stream Pearson correlation at or above `0.005`.

Generate key-avalanche cells from `2^14` fixed SplitMix bases: for each of 64
input bits, compare every base with the same base XOR that bit and tally all 64
output bits, per declared domain/counter class. Generate counter-avalanche cells
the same way for every bit in each encoded field, retaining only flips for which
both decoded tuples are valid. Collision and serial/cross-stream calculations
consume exactly `2^20` raw words from each fixed traversal.

- [ ] **Step 6: Test the actual reducer and Elastic metadata derivation**

Write the production-adapter parity test and metadata-distribution tests first;
run them and observe FAIL before adding their drivers. Use these fixed
representative upper-bound families for both backend tuple streams:

```rust
const RANGE_1K: &[usize] = &[1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 125, 250, 500, 1_000];
const RANGE_100K: &[usize] = &[97, 195, 391, 781, 1_562, 3_125, 6_250, 12_500, 25_000, 50_000, 100_000];
const RANGE_10M: &[usize] = &[9_765, 19_531, 39_062, 78_125, 156_250, 312_500, 625_000, 1_250_000, 2_500_000, 5_000_000, 10_000_000];
```

Coalesce adjacent output values into at most 4096 contiguous bins, keep exact represented-output counts, and require expected count at least 32.

The quality tool must call `exact_reduce::power_of_two_index` for Elastic
power-of-two ranges and `exact_reduce::multiply_high_if_accepted` plus
`exact_reduce::rejection_threshold` for all other Elastic ranges and every
Funnel range. It must consume subsequent checked retry tuples after a rejection
and preserve the production retry bound. Do not duplicate any reducer formula
inside `stats.rs`. Add a test that feeds identical candidate words through the
tool driver and production `probe.rs` test adapter and compares accepted index,
word count, and rejection-limit result for every declared range.

For Elastic signatures, test sequential, low-bit, high-bit, and SplitMix keys. Derive the sidecar word with multiply-high, the four Bloom bits with the production formula, and the two-bit route bin. Reject a candidate when its metadata chi-square family fails or any Bloom bit is constant for a declared class.

Expected: this catches raw-`a` clustering independently of raw PRF tests.

- [ ] **Step 7: Implement nonrepeating binary streaming and its tests**

First write the exact-length, over-limit, byte-order, early-close, and
direct-evaluation tests described below and observe FAIL. Then implement this
stream loop:

```rust
let stdout = std::io::stdout();
let mut output = std::io::BufWriter::new(stdout.lock());
let mut word_index = 0_u64;
loop {
    if word_limit == Some(word_index) {
        return output.flush();
    }
    let tuple = traversal
        .stream_tuple(word_index)
        .ok_or_else(|| std::io::Error::other("injective stream limit exhausted"))?;
    let candidate = match tuple.backend() {
        Backend::Elastic => elastic_candidate,
        Backend::Funnel => funnel_candidate,
    };
    let word = candidate.word(tuple).expect("traversal emits only checked tuples");
    let write_result = match format {
        StreamFormat::U64Le => output.write_all(&word.to_le_bytes()),
        StreamFormat::U32Le => {
            output
                .write_all(&(word as u32).to_le_bytes())
                .and_then(|()| output.write_all(&((word >> 32) as u32).to_le_bytes()))
        }
    };
    if let Err(error) = write_result {
        if until_broken_pipe && error.kind() == std::io::ErrorKind::BrokenPipe {
            return Ok(());
        }
        return Err(error);
    }
    word_index = word_index.checked_add(1).expect("stream index exhausted");
}
```

Unit tests stream the first 4096 words to a `Vec<u8>`, decode explicitly as
little-endian, and compare with direct tuple evaluation. Assert bounded mode
writes exactly the requested byte count and rejects zero/over-limit counts. An
integration test pipes every format into a reader that closes early: bounded
mode must fail, while `--until-broken-pipe` must exit successfully. EPIPE is
intentional only for an unbounded TestU01 consumer.

- [ ] **Step 8: Add the TestU01 stdin driver**

Create `driver.c`:

```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "bbattery.h"
#include "unif01.h"

static unsigned long next_bits(void) {
    unsigned char bytes[4];
    if (fread(bytes, 1, 4, stdin) != 4) {
        fputs("opthash TestU01 stream ended early\n", stderr);
        exit(2);
    }
    return (unsigned long)bytes[0]
        | ((unsigned long)bytes[1] << 8)
        | ((unsigned long)bytes[2] << 16)
        | ((unsigned long)bytes[3] << 24);
}

int main(void) {
    unif01_Gen *generator = unif01_CreateExternGenBits("opthash-prf", next_bits);
    bbattery_BigCrush(generator);
    unif01_DeleteExternGenBits(generator);
    return 0;
}
```

- [ ] **Step 9: Add one reproducible quality runner**

`scripts/prf-quality.sh` accepts Elastic candidate, Funnel candidate, and mode,
uses the standalone manifest, and runs these exact pipelines:

```bash
cargo run --release --manifest-path tools/prf-quality/Cargo.toml -- quality --candidate "$elastic_candidate"
cargo run --release --manifest-path tools/prf-quality/Cargo.toml -- stream --elastic-candidate "$elastic_candidate" --funnel-candidate "$funnel_candidate" --traversal "$traversal" --format u64le --words 8589934592 | RNG_test stdin64 -tlmax 64GB
cc -std=c99 -Wall -Wextra -O3 tools/prf-quality/testu01/driver.c -ltestu01 -lprobdist -lmylib -lm -o target/opthash-testu01
cargo run --release --manifest-path tools/prf-quality/Cargo.toml -- stream --elastic-candidate "$elastic_candidate" --funnel-candidate "$funnel_candidate" --traversal "$traversal" --format u32le --until-broken-pipe | target/opthash-testu01
```

The script runs PractRand for all five traversals with the same statistical
survivor selected for both backends. After performance selects backend winners,
it runs BigCrush on key-major, counter-major, and domain-interleaved streams
with that exact Elastic/Funnel pair. It records tool versions, both candidates,
traversal, command, exit status, and complete output below
`target/prf-quality/`.

The runner uses Bash `set -euo pipefail`, temporarily disables `errexit`
around each two-process pipeline, captures both `PIPESTATUS` values
immediately, and requires producer `0` plus consumer `0`. Thus an intentional
BigCrush EPIPE is translated to producer success by the tool, while generator
faults and battery failures remain distinct nonzero failures. Record both
statuses.

- [ ] **Step 10: Run tool tests and commit**

```bash
cargo test --manifest-path tools/prf-quality/Cargo.toml
cargo fmt --manifest-path tools/prf-quality/Cargo.toml -- --check
cargo clippy --manifest-path tools/prf-quality/Cargo.toml --all-targets -- -D warnings
cargo run --release --manifest-path tools/prf-quality/Cargo.toml -- vectors --candidate guarded
cargo run --release --manifest-path tools/prf-quality/Cargo.toml -- quality --candidate guarded
pre-commit run --files Cargo.toml scripts/prf-quality.sh tools/prf-quality/Cargo.toml tools/prf-quality/src/main.rs tools/prf-quality/src/traversal.rs tools/prf-quality/src/stats.rs tools/prf-quality/testu01/driver.c
git add Cargo.toml scripts/prf-quality.sh tools/prf-quality
git commit -m "test: add counter prf quality harness"
```

Expected: unit tests PASS, deterministic quality report passes or explicitly rejects the candidate, and the root production lockfile has no tool dependency additions.

### Task 5: Run Candidate Quality Gates Before Map Benchmarks

**Files:**
- Read: `target/prf-quality/`
- Create: `docs/performance/2026-07-20-counter-prf-quality.md`

**Interfaces:**
- Consumes: exact-source quality tool and four candidate compositions.
- Produces: a fixed deterministic/PractRand pass/reject list; rejected candidates do not consume map benchmark time.

- [ ] **Step 1: Run deterministic gates for every candidate**

```bash
scripts/prf-quality.sh current current quality
scripts/prf-quality.sh guarded guarded quality
scripts/prf-quality.sh philox6 philox6 quality
scripts/prf-quality.sh philox10 philox10 quality
```

Expected: each report names every tested family and contains no undeclared traversal. A rejection names exact cells/tests and p-values.

- [ ] **Step 2: Run PractRand for every deterministic survivor**

For every survivor, including current, run all five literal traversal names.
For guarded, the commands are:

```bash
scripts/prf-quality.sh guarded guarded practrand-key-major
scripts/prf-quality.sh guarded guarded practrand-counter-major
scripts/prf-quality.sh guarded guarded practrand-domain-interleaved
scripts/prf-quality.sh guarded guarded practrand-strided
scripts/prf-quality.sh guarded guarded practrand-adversarial
```

Repeat with `current`, `philox6`, and `philox10` only when their deterministic
reports pass. Expected: every survivor stream reaches at least 64 GiB without a
PractRand failure.

- [ ] **Step 3: Obtain delegated review of the survivor list**

Give the complete deterministic and PractRand reports to a fresh reviewer
subagent. Benchmark only candidates it confirms passed every predeclared gate.

- [ ] **Step 4: Record exact pre-benchmark quality evidence**

Create `docs/performance/2026-07-20-counter-prf-quality.md` with:

1. Candidate formula commit and source file hash.
2. Deterministic family sizes, corrected thresholds, worst p-values, collision counts, and maximum absolute correlations.
3. Metadata-distribution results.
4. PractRand version and ending byte count for each of five traversals per survivor.
5. Explicit survivor/rejection decision for current, guarded, Philox6, and Philox10.
6. Statement that statistical evidence is an engineering PRF model, not proof of the paper's independence assumption.

- [ ] **Step 5: Commit the evidence**

```bash
pre-commit run --files docs/performance/2026-07-20-counter-prf-quality.md
git add docs/performance/2026-07-20-counter-prf-quality.md
git commit -m "docs: record counter prf quality evidence"
```

### Task 6: Benchmark Survivors in Real Backend Worktrees

**Files:**
- Modify per worktree: `src/common/exact/prf/mod.rs`
- Read: `scripts/bench.sh`
- Read: `scripts/cache-gate.sh`
- Read: `docs/performance/2026-07-21-elastic-candidate-signature-cache.md`
- Read: `target/criterion/`

**Interfaces:**
- Consumes: accepted signature-cache evidence, immutable cache-off original current, codegen-neutral current scaffold, and statistical survivors.
- Produces: fixed-control-valid current/guarded/Philox real-map runs, including mixed-backend isolation variants, all compared directly with original current.

- [ ] **Step 1: Freeze original current and the accepted current-PRF scaffold**

Resolve `cache_off_current_commit` from the accepted signature-cache evidence,
then freeze both it and the clean current-PRF composition after Task 5. The
former is the only acceptance baseline; the latter is an attribution control
containing codegen-neutral scaffolding and inactive candidates:

```bash
prf_criterion_root=/home/aang/projects/opthash/.worktrees/perf/counter-prf-insert/target/criterion
cache_off_current_commit=$(sed -n 's/^- Cache-off commit: `\([0-9a-f]\{40\}\)`$/\1/p' docs/performance/2026-07-21-elastic-candidate-signature-cache.md)
test -n "$cache_off_current_commit"
git cat-file -e "$cache_off_current_commit^{commit}"
prf_current_commit=$(git rev-parse HEAD)
git worktree add --detach /home/aang/projects/opthash/.worktrees/perf/prf-original-current "$cache_off_current_commit"
git worktree add --detach /home/aang/projects/opthash/.worktrees/perf/prf-current-anchor "$prf_current_commit"
(cd /home/aang/projects/opthash/.worktrees/perf/prf-original-current && test "$(git rev-parse HEAD)" = "$cache_off_current_commit" && test -z "$(git status --porcelain -- src benches scripts Cargo.toml Cargo.lock)")
(cd /home/aang/projects/opthash/.worktrees/perf/prf-current-anchor && test "$(git rev-parse HEAD)" = "$prf_current_commit" && test -z "$(git status --porcelain -- src benches scripts Cargo.toml Cargo.lock)")
(cd /home/aang/projects/opthash/.worktrees/perf/prf-original-current && OPTHASH_CRITERION_ROOT="$prf_criterion_root" SAVE=prf-original-current scripts/bench.sh)
(cd /home/aang/projects/opthash/.worktrees/perf/prf-original-current && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert SAVE=prf-original-current-scale scripts/bench.sh)
(cd /home/aang/projects/opthash/.worktrees/perf/prf-original-current && BUILD_CONTROL=1 scripts/cache-gate.sh)
CACHE_GATE_CONTROL_BIN=$(sed -n '1p' /home/aang/projects/opthash/.worktrees/perf/prf-original-current/target/cache-gate-control-bin.txt)
test -x "$CACHE_GATE_CONTROL_BIN"
(cd /home/aang/projects/opthash/.worktrees/perf/prf-original-current && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" CONTROL=1 SAVE=prf-original-fixed-control scripts/cache-gate.sh)
(cd /home/aang/projects/opthash/.worktrees/perf/prf-original-current && CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" MANIFEST=1 CACHE_GATE_VARIANT=prf-original-current scripts/cache-gate.sh)
(cd /home/aang/projects/opthash/.worktrees/perf/prf-current-anchor && CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" MANIFEST=1 CACHE_GATE_VARIANT=prf-scaffold-current scripts/cache-gate.sh)
(cd /home/aang/projects/opthash/.worktrees/perf/prf-current-anchor && OPTHASH_CRITERION_ROOT="$prf_criterion_root" SAVE=prf-scaffold-current scripts/bench.sh)
(cd /home/aang/projects/opthash/.worktrees/perf/prf-current-anchor && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert SAVE=prf-scaffold-current-scale scripts/bench.sh)
```

Expected: original-current and scaffold-current JSON exists. Before any
candidate run, corresponding current hot bodies must be byte-identical and
named Callgrind counts exactly equal; their stable Elastic/Funnel kernel
addresses, `start % 4096`, alignment, link-map predecessors, and target-aware
layout snapshots must also match. Any scaffold timing is diagnostic only.

- [ ] **Step 2: Create one isolated worktree per statistical survivor**

Use `superpowers:using-git-worktrees`. For the three new candidates:

```bash
git worktree add /home/aang/projects/opthash/.worktrees/perf/prf-guarded -b perf/prf-guarded
git worktree add /home/aang/projects/opthash/.worktrees/perf/prf-philox6 -b perf/prf-philox6
git worktree add /home/aang/projects/opthash/.worktrees/perf/prf-philox10 -b perf/prf-philox10
```

Skip creation only for a candidate already rejected by Task 5.

- [ ] **Step 3: Make selector-only candidate commits**

In each worktree, change only:

```rust
pub(crate) use guarded_wyhash as active_elastic;
pub(crate) use guarded_wyhash as active_funnel;
```

Use `philox6` or `philox10` in its corresponding worktree. Commit the
selector, then, in that clean immutable candidate tree, run and retain the
complete production-path cache lifecycle gate with the candidate actually
active:

```bash
cargo test elastic::tests::insert_growth_reindexes_cached_signature_in_production_path -- --exact
cargo test elastic::tests::finite_probe_exhaustion_uses_observable_exceptional_recovery -- --exact
cargo test elastic::tests::membership_filter_never_forgets_live_or_deleted_hashes -- --exact
cargo test elastic::tests::membership_filter_resets_and_rebuilds_at_table_boundaries -- --exact
cargo test elastic::tests::all_vacant_entry_apis_record_membership -- --exact
cargo test elastic::tests::drain_and_failed_reserve_preserve_membership_invariants -- --exact
cargo test elastic::tests::allocator_failure_does_not_publish_or_forget_membership -- --exact
cargo test elastic::tests::colliding_hashes_remain_distinguishable_through_delete_and_reuse -- --exact
cargo test elastic::tests::route_summary_conservatively_records_every_live_level -- --exact
cargo test
cargo +nightly miri test elastic::tests::insert_growth_reindexes_cached_signature_in_production_path -- --exact
cargo +nightly miri test elastic::tests::finite_probe_exhaustion_uses_observable_exceptional_recovery -- --exact
```

Use commit subjects `perf: select guarded counter prf`, `perf: select philox6
counter prf`, or `perf: select philox10 counter prf`. Candidate vector tests
and generic forced-policy helpers do not substitute for these production
growth, same-size recovery, allocator-failure, lifecycle, full-suite, and Miri
runs. A failure rejects that selector before any diagnostic or acceptance
benchmark.

- [ ] **Step 4: Run one diagnostic suite for worktree/isolation planning only**

Point all worktrees at the anchor's Criterion root. Treat each candidate's
four-command paragraph as an independent block and run it only when Task 5
created that candidate worktree:

For each survivor, assign `prf_candidate` and execute this block; repeat with
`guarded`, `philox6`, and `philox10` only when that candidate survived:

```bash
prf_candidate=guarded
prf_candidate_tree=/home/aang/projects/opthash/.worktrees/perf/prf-$prf_candidate
prf_scaffold_tree=/home/aang/projects/opthash/.worktrees/perf/prf-current-anchor
prf_arch=$(uname -m)
prf_candidate_commit=$(git -C "$prf_candidate_tree" rev-parse HEAD)
prf_scaffold_commit=$(git -C "$prf_scaffold_tree" rev-parse HEAD)
(cd "$prf_candidate_tree" && CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" MANIFEST=1 CACHE_GATE_VARIANT="prf-$prf_candidate-diagnostic" scripts/cache-gate.sh)
prf_candidate_manifest="$prf_candidate_tree/target/cache-gate/$prf_arch/prf-$prf_candidate-diagnostic/manifest.json"
prf_scaffold_manifest="$prf_scaffold_tree/target/cache-gate/$prf_arch/prf-scaffold-current/manifest.json"

(cd "$prf_candidate_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" SAVE="prf-$prf_candidate" scripts/bench.sh)
(cd "$prf_scaffold_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" LOAD="prf-$prf_candidate" BASELINE=prf-scaffold-current scripts/bench.sh)
(cd "$prf_scaffold_tree" && scripts/snapshot-criterion-pair.sh --criterion-root "$prf_criterion_root" --snapshot-root target/cache-gate-evidence --arch "$prf_arch" --comparison "prf-$prf_candidate-diagnostic-full" --pair 1 --target all --anchor-run prf-scaffold-current --candidate-run "prf-$prf_candidate" --anchor-commit "$prf_scaffold_commit" --candidate-commit "$prf_candidate_commit" --anchor-manifest "$prf_scaffold_manifest" --candidate-manifest "$prf_candidate_manifest")

(cd "$prf_candidate_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert SAVE="prf-$prf_candidate-scale" scripts/bench.sh)
(cd "$prf_scaffold_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert LOAD="prf-$prf_candidate-scale" BASELINE=prf-scaffold-current-scale scripts/bench.sh)
(cd "$prf_scaffold_tree" && scripts/snapshot-criterion-pair.sh --criterion-root "$prf_criterion_root" --snapshot-root target/cache-gate-evidence --arch "$prf_arch" --comparison "prf-$prf_candidate-diagnostic-scale" --pair 1 --target scaled_insert --anchor-run prf-scaffold-current-scale --candidate-run "prf-$prf_candidate-scale" --anchor-commit "$prf_scaffold_commit" --candidate-commit "$prf_candidate_commit" --anchor-manifest "$prf_scaffold_manifest" --candidate-manifest "$prf_candidate_manifest")
```

These results are diagnostic only: use them to detect broken selectors and
estimate run time. They cannot decide isolation, accept, or exclude a quality
survivor regardless of point estimate.

- [ ] **Step 5: Create both backend-isolated compositions for every survivor**

Do not use the one diagnostic run to predict backend divergence. For every
non-current quality survivor, unconditionally create two selector-only
worktrees/commits from `prf_current_commit`: one changes Elastic only and one
changes Funnel only. For guarded, the selectors are:

```rust
pub(crate) use guarded_wyhash as active_elastic;
pub(crate) use current as active_funnel;
```

and:

```rust
pub(crate) use current as active_elastic;
pub(crate) use guarded_wyhash as active_funnel;
```

Use paths/names `prf-guarded-elastic-only` and
`prf-guarded-funnel-only`; create the corresponding two paths for Philox6 and
Philox10 whenever they survived Task 5. Run correctness tests and commit every
selector. After each selector commit, run the exact production-path lifecycle,
full-suite, and two focused Miri command block from Step 3 with that isolated
composition active; reject before measurement on any failure. Thus each
quality survivor enters Step 6 as three measured
compositions—combined, Elastic-only, and Funnel-only—and later split results
cannot create an unmeasured branch.

- [ ] **Step 6: Collect three interleaved pairs on AArch64 and x86-64**

For every non-current Task 5 quality survivor's combined composition plus both
isolated compositions from Step 5, set its literal name and clean selector
worktree. Build manifests with the one canonical fixed-control binary from
`prf-original-current`; never rebuild or infer a control executable in a
candidate tree:

```bash
prf_arch=$(uname -m)
prf_candidate=guarded
prf_candidate_tree=/home/aang/projects/opthash/.worktrees/perf/prf-guarded
prf_anchor_tree=/home/aang/projects/opthash/.worktrees/perf/prf-original-current
CACHE_GATE_CONTROL_BIN=$(sed -n '1p' "$prf_anchor_tree/target/cache-gate-control-bin.txt")
test -x "$CACHE_GATE_CONTROL_BIN"
prf_anchor_commit=$(git -C "$prf_anchor_tree" rev-parse HEAD)
prf_candidate_commit=$(git -C "$prf_candidate_tree" rev-parse HEAD)
test -z "$(git -C "$prf_anchor_tree" status --porcelain)"
test -z "$(git -C "$prf_candidate_tree" status --porcelain)"

(cd "$prf_anchor_tree" && CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" MANIFEST=1 CACHE_GATE_VARIANT=prf-original-current scripts/cache-gate.sh)
(cd "$prf_candidate_tree" && CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" MANIFEST=1 CACHE_GATE_VARIANT="prf-$prf_candidate" scripts/cache-gate.sh)
prf_anchor_manifest="$prf_anchor_tree/target/cache-gate/$prf_arch/prf-original-current/manifest.json"
prf_candidate_manifest="$prf_candidate_tree/target/cache-gate/$prf_arch/prf-$prf_candidate/manifest.json"
test -f "$prf_anchor_manifest"
test -f "$prf_candidate_manifest"
```

Before timing, compare the two manifests and module-local hot-layout snapshots.
For both stable targets, the corresponding anchor/candidate insert and get
kernel address, `start % 4096`, alignment, and link-map predecessor must be
identical. Every recorded size/alignment/field offset for `ElasticTable`,
`Level`, `ElasticMetadataWord`, `FunnelTable`, `FunnelShape`, `LevelShape`, and
`FlatStorage` must match. `BucketLevel` must remain absent, or, if introduced by
an independently approved change, have a complete exact snapshot. Any drift is
a hard layout rejection before timing; a favorable timing result cannot waive
it.

Run and immediately snapshot all three preflight comparisons, including the
stable Funnel target even for a combined or Funnel-only selector:

```bash
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" CONTROL=1 SAVE="$prf_arch-prf-$prf_candidate-preflight-original-control" scripts/cache-gate.sh)
(cd "$prf_candidate_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" CONTROL=1 SAVE="$prf_arch-prf-$prf_candidate-preflight-candidate-control" scripts/cache-gate.sh)
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" CONTROL=1 LOAD="$prf_arch-prf-$prf_candidate-preflight-candidate-control" BASELINE="$prf_arch-prf-$prf_candidate-preflight-original-control" scripts/cache-gate.sh)
(cd "$prf_anchor_tree" && scripts/snapshot-criterion-pair.sh --criterion-root "$prf_criterion_root" --snapshot-root target/cache-gate-evidence --arch "$prf_arch" --comparison "prf-$prf_candidate-preflight-control" --pair 1 --target control --anchor-run "$prf_arch-prf-$prf_candidate-preflight-original-control" --candidate-run "$prf_arch-prf-$prf_candidate-preflight-candidate-control" --anchor-commit "$prf_anchor_commit" --candidate-commit "$prf_candidate_commit" --anchor-manifest "$prf_anchor_manifest" --candidate-manifest "$prf_candidate_manifest")

(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" ELASTIC=1 SAVE="$prf_arch-prf-$prf_candidate-preflight-original-elastic" scripts/cache-gate.sh)
(cd "$prf_candidate_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" ELASTIC=1 SAVE="$prf_arch-prf-$prf_candidate-preflight-candidate-elastic" scripts/cache-gate.sh)
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" ELASTIC=1 LOAD="$prf_arch-prf-$prf_candidate-preflight-candidate-elastic" BASELINE="$prf_arch-prf-$prf_candidate-preflight-original-elastic" scripts/cache-gate.sh)
(cd "$prf_anchor_tree" && scripts/snapshot-criterion-pair.sh --criterion-root "$prf_criterion_root" --snapshot-root target/cache-gate-evidence --arch "$prf_arch" --comparison "prf-$prf_candidate-preflight-elastic" --pair 1 --target elastic_cache_gate --anchor-run "$prf_arch-prf-$prf_candidate-preflight-original-elastic" --candidate-run "$prf_arch-prf-$prf_candidate-preflight-candidate-elastic" --anchor-commit "$prf_anchor_commit" --candidate-commit "$prf_candidate_commit" --anchor-manifest "$prf_anchor_manifest" --candidate-manifest "$prf_candidate_manifest")

(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" FUNNEL=1 SAVE="$prf_arch-prf-$prf_candidate-preflight-original-funnel" scripts/cache-gate.sh)
(cd "$prf_candidate_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" FUNNEL=1 SAVE="$prf_arch-prf-$prf_candidate-preflight-candidate-funnel" scripts/cache-gate.sh)
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" FUNNEL=1 LOAD="$prf_arch-prf-$prf_candidate-preflight-candidate-funnel" BASELINE="$prf_arch-prf-$prf_candidate-preflight-original-funnel" scripts/cache-gate.sh)
(cd "$prf_anchor_tree" && scripts/snapshot-criterion-pair.sh --criterion-root "$prf_criterion_root" --snapshot-root target/cache-gate-evidence --arch "$prf_arch" --comparison "prf-$prf_candidate-preflight-funnel" --pair 1 --target funnel_cache_gate --anchor-run "$prf_arch-prf-$prf_candidate-preflight-original-funnel" --candidate-run "$prf_arch-prf-$prf_candidate-preflight-candidate-funnel" --anchor-commit "$prf_anchor_commit" --candidate-commit "$prf_candidate_commit" --anchor-manifest "$prf_anchor_manifest" --candidate-manifest "$prf_candidate_manifest")
```

Require the fixed-control executable hashes to be byte-identical and every
preflight std/hashbrown point to remain within 5%. For each of the three full
pairs and three scaled pairs, run a fresh adjacent fixed-control pair first,
execute its explicit `LOAD=<candidate> BASELINE=<anchor>` comparison, and call
`snapshot-criterion-pair.sh` immediately. Then run the benchmark pair and
immediately compare and snapshot it. This helper is the mandatory protocol;
its caller supplies unique `full-1` through `full-3` or `scale-1` through
`scale-3` labels, and the benchmark SAVE order is `anchor,candidate`,
`candidate,anchor`, `anchor,candidate`:

```bash
snapshot_control_pair() {
    pair_label=$1 pair=$2
    anchor_control="$prf_arch-prf-$prf_candidate-$pair_label-original-control"
    candidate_control="$prf_arch-prf-$prf_candidate-$pair_label-candidate-control"
    (cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" CONTROL=1 SAVE="$anchor_control" scripts/cache-gate.sh)
    (cd "$prf_candidate_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" CONTROL=1 SAVE="$candidate_control" scripts/cache-gate.sh)
    (cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" CONTROL=1 LOAD="$candidate_control" BASELINE="$anchor_control" scripts/cache-gate.sh)
    (cd "$prf_anchor_tree" && scripts/snapshot-criterion-pair.sh --criterion-root "$prf_criterion_root" --snapshot-root target/cache-gate-evidence --arch "$prf_arch" --comparison "prf-$prf_candidate-$pair_label-control" --pair "$pair" --target control --anchor-run "$anchor_control" --candidate-run "$candidate_control" --anchor-commit "$prf_anchor_commit" --candidate-commit "$prf_candidate_commit" --anchor-manifest "$prf_anchor_manifest" --candidate-manifest "$prf_candidate_manifest")
}

snapshot_full_pair() {
    pair=$1 anchor_run=$2 candidate_run=$3
    (cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" LOAD="$candidate_run" BASELINE="$anchor_run" scripts/bench.sh)
    (cd "$prf_anchor_tree" && scripts/snapshot-criterion-pair.sh --criterion-root "$prf_criterion_root" --snapshot-root target/cache-gate-evidence --arch "$prf_arch" --comparison "prf-$prf_candidate-full" --pair "$pair" --target all --anchor-run "$anchor_run" --candidate-run "$candidate_run" --anchor-commit "$prf_anchor_commit" --candidate-commit "$prf_candidate_commit" --anchor-manifest "$prf_anchor_manifest" --candidate-manifest "$prf_candidate_manifest")
}

snapshot_scale_pair() {
    pair=$1 anchor_run=$2 candidate_run=$3
    (cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert LOAD="$candidate_run" BASELINE="$anchor_run" scripts/bench.sh)
    (cd "$prf_anchor_tree" && scripts/snapshot-criterion-pair.sh --criterion-root "$prf_criterion_root" --snapshot-root target/cache-gate-evidence --arch "$prf_arch" --comparison "prf-$prf_candidate-scale" --pair "$pair" --target scaled_insert --anchor-run "$anchor_run" --candidate-run "$candidate_run" --anchor-commit "$prf_anchor_commit" --candidate-commit "$prf_candidate_commit" --anchor-manifest "$prf_anchor_manifest" --candidate-manifest "$prf_candidate_manifest")
}

snapshot_control_pair full-1 1
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" SAVE="$prf_arch-prf-original-$prf_candidate-a1" scripts/bench.sh)
(cd "$prf_candidate_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" SAVE="$prf_arch-prf-$prf_candidate-c1" scripts/bench.sh)
snapshot_full_pair 1 "$prf_arch-prf-original-$prf_candidate-a1" "$prf_arch-prf-$prf_candidate-c1"
snapshot_control_pair full-2 2
(cd "$prf_candidate_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" SAVE="$prf_arch-prf-$prf_candidate-c2" scripts/bench.sh)
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" SAVE="$prf_arch-prf-original-$prf_candidate-a2" scripts/bench.sh)
snapshot_full_pair 2 "$prf_arch-prf-original-$prf_candidate-a2" "$prf_arch-prf-$prf_candidate-c2"
snapshot_control_pair full-3 3
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" SAVE="$prf_arch-prf-original-$prf_candidate-a3" scripts/bench.sh)
(cd "$prf_candidate_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" SAVE="$prf_arch-prf-$prf_candidate-c3" scripts/bench.sh)
snapshot_full_pair 3 "$prf_arch-prf-original-$prf_candidate-a3" "$prf_arch-prf-$prf_candidate-c3"

snapshot_control_pair scale-1 1
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert SAVE="$prf_arch-prf-original-$prf_candidate-scale-a1" scripts/bench.sh)
(cd "$prf_candidate_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert SAVE="$prf_arch-prf-$prf_candidate-scale-c1" scripts/bench.sh)
snapshot_scale_pair 1 "$prf_arch-prf-original-$prf_candidate-scale-a1" "$prf_arch-prf-$prf_candidate-scale-c1"
snapshot_control_pair scale-2 2
(cd "$prf_candidate_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert SAVE="$prf_arch-prf-$prf_candidate-scale-c2" scripts/bench.sh)
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert SAVE="$prf_arch-prf-original-$prf_candidate-scale-a2" scripts/bench.sh)
snapshot_scale_pair 2 "$prf_arch-prf-original-$prf_candidate-scale-a2" "$prf_arch-prf-$prf_candidate-scale-c2"
snapshot_control_pair scale-3 3
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert SAVE="$prf_arch-prf-original-$prf_candidate-scale-a3" scripts/bench.sh)
(cd "$prf_candidate_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert SAVE="$prf_arch-prf-$prf_candidate-scale-c3" scripts/bench.sh)
snapshot_scale_pair 3 "$prf_arch-prf-original-$prf_candidate-scale-a3" "$prf_arch-prf-$prf_candidate-scale-c3"
```

The fresh control pair uses the same immediate `CONTROL=1 LOAD/BASELINE` plus
snapshot sequence shown in preflight, with comparison names containing the
matching `full-N` or `scale-N`. Do not begin the next SAVE until the current
snapshot has atomically captured every `change/estimates.json`, both named
absolute `estimates.json` trees, both manifests/link maps, commit/run/target
metadata, and verified SHA-256 inventory. If either control moves by more than
5%, preserve the rejected snapshot, discard that benchmark pair, and rerun it
under a new run/pair name; never overwrite or subtract control movement.

These direct original-current comparisons—not candidate-vs-scaffold or
candidate-vs-cache-on comparisons—decide acceptance. Use distinct names and
snapshot directories for combined and backend-isolated compositions. Read
only immutable snapshots, never live Criterion `change/`, and record every raw
point estimate and 95% interval plus controls for every `speedup` operation and
every randomized and sequential mean-latency group at 1K, 10K, 100K, 1M, and
10M.

Declare each composition's `changed_backends` from its selector before reading
results. On each architecture, apply the improvement gate only to a changed
backend: all three headline insert points improve, at least two 95% intervals
exclude zero, and median raw change is at most -10% Elastic or -5% Funnel.
Apply that backend's same all-three/two-interval/median threshold independently
at scaled 100K, 1M, and 10M. Randomized and ordered get median and the upper
confidence bound in at least two pairs remain at or below +2%, and every raw
point estimate must be `<= +0.02`. For every other
public `speedup` group—`get_miss`, `tiny_lookup`, `mixed`, `delete_heavy`, and
`resize_heavy`—every point is `<= +0.02`, the median is `<= +0.02`, and at
least two upper confidence bounds are `<= +0.02` for each changed backend.
Apply the same point/median/two-upper-bound
gate independently to all ten `get_hit_latency_*` and
`get_hit_sequential_latency_*` size traces.

For a backend whose selector remains `current`, do not demand an impossible
insert improvement. Instead, every headline insert, scaled insert, public get,
all ten latency traces, and other public-operation point must be `<= +0.02`,
each three-pair median must be `<= +0.01`, and at least two corresponding 95%
upper bounds must be `<= +0.02`. Never reject a favorable negative lower
bound. Its exact named Callgrind counts must be ±0 and corresponding stable
insert/get hot bodies byte-identical to `prf-original-current`. This unchanged
gate applies in particular to every Funnel public operation, latency size, and
scaled insert in Elastic-only compositions. Any changed-backend failure or
retained-current regression rejects the composition.

- [ ] **Step 7: Corroborate with assembly and operation-specific counters**

On AArch64, take each tree's `cache_gate_profile` absolute path only from its
accepted manifest. Run the no-build launcher separately for all four operations
and retain three raw repetitions per operation/tree:

```bash
for tree in "$prf_anchor_tree" "$prf_candidate_tree"; do
    manifest="$tree/target/cache-gate/$prf_arch/$(test "$tree" = "$prf_anchor_tree" && echo prf-original-current || echo prf-$prf_candidate)/manifest.json"
    profile_bin=$(jq -er '.executables.cache_gate_profile.absolute_path' "$manifest")
    test -x "$profile_bin"
    for operation in elastic-insert elastic-get funnel-insert funnel-get; do
        for repetition in 1 2 3; do
            (cd "$tree" && CACHE_GATE_PERF_BIN="$profile_bin" scripts/cache-gate-perf.sh --manifest "$manifest" --operation "$operation" --iterations 100 --repetition "$repetition")
        done
    done
done
```

`cache-gate-perf.sh` verifies the manifested binary hash, performs all setup
before `READY`, enables `perf stat -x,` counters only around the one named
fixed-iteration kernel, and writes a raw CSV plus command/PID/iteration
manifest. No Cargo, linker, Criterion, fixture setup, or second operation may
run while counters are enabled. Compare per-operation medians only.

On x86-64, rebuild and collect actual Callgrind plus the exact benchmark
executable separately in those same trees:

```bash
cargo clean -p opthash
CARGO_INCREMENTAL=0 cargo codspeed build --bench speedup
cargo codspeed run --bench speedup 2>&1 | tee target/prf-callgrind.txt
cargo bench --bench speedup --no-run --message-format=json > target/prf-cargo.json
jq -r 'select(.reason == "compiler-artifact" and .target.name == "speedup" and .executable != null) | .executable' target/prf-cargo.json | sort -u > target/prf-executables.txt
test "$(wc -l < target/prf-executables.txt)" -eq 1
speedup_bin=$(sed -n '1p' target/prf-executables.txt)
test -n "$speedup_bin"
test -x "$speedup_bin"
test "$(stat -c %Y "$speedup_bin")" -ge "$(git show -s --format=%ct HEAD)"
objdump -d -C "$speedup_bin" > target/prf-candidate-speedup.asm
rg -n "elastic_word|funnel_word|philox2x64|guarded_word" target/prf-candidate-speedup.asm
```

Record commit ID, exact executable path/mtime, and exact per-operation
Callgrind counts for Elastic/Funnel insert, randomized/ordered get, and
std/hashbrown controls. Expected: AArch64 counters and x86-64 Callgrind
direction agree with wall clock; direct inlining has no trait calls,
function-pointer calls, selector branch, unexpected spill, unexpected helper
call, or stale/dependency executable. For guarded/Philox Elastic specifically,
require exactly one inlined metadata evaluation (`S2` or `(0,1)`) per prepared
insert key; none may occur in membership precheck, final record,
`write_new_entry`, or post-resize record code. Require H(1,1) get return before
all candidate metadata-signature instructions, no hidden return pointer or
aggregate copy for the 16-byte key, and no policy branch after compile-time
selection. Compare stack frames, register saves, spills, and call sites directly
with `prf-original-current`, not only `prf-current-anchor`.

For a retained-current backend, require exact named Callgrind counts and
byte-identical normalized stable-kernel bodies. For every changed backend,
operation-specific AArch64 cycle and instruction direction must corroborate
the accepted wall-clock direction; an adverse cache- or branch-miss direction
requires an explicit raw-repetition explanation and reviewer approval.

Give every survivor's three normal pairs, three scaled pairs, all public-suite
operations, all ten latency-size traces, controls, counters, Callgrind counts,
and assembly to a fresh reviewer subagent. Only now may a composition be
excluded or named a provisional backend winner. Record explicit pass/reject
reasons for every quality survivor.

### Task 7: Run BigCrush, Ship Only Backend Winners, and Remove the Bakeoff Surface

**Files:**
- Modify: `src/common/exact/prf/mod.rs`
- Delete: every losing candidate module
- Modify: `tools/prf-quality/src/main.rs`
- Modify when a PRF changes: `README.md`
- Modify when a PRF changes: `CHANGELOG.md`
- Modify: `docs/performance/2026-07-20-counter-prf-quality.md`
- Create: `docs/performance/2026-07-20-counter-prf-performance.md`

**Interfaces:**
- Consumes: Task 5 quality survivors, Task 6 cross-architecture evidence, and immutable cache-off original current.
- Produces: direct production modules for each backend, no selector machinery, and final verification evidence.

- [ ] **Step 1: Run BigCrush on each provisional backend winner**

Set the two names to the provisional independently selected winners and run the
actual mixed production composition:

```bash
prf_elastic_winner=guarded
prf_funnel_winner=current
scripts/prf-quality.sh "$prf_elastic_winner" "$prf_funnel_winner" bigcrush-key-major
scripts/prf-quality.sh "$prf_elastic_winner" "$prf_funnel_winner" bigcrush-counter-major
scripts/prf-quality.sh "$prf_elastic_winner" "$prf_funnel_winner" bigcrush-domain-interleaved
```

Replace the two example assignments with Task 6's actual choices. Expected:
TestU01 completes all three BigCrush runs with no reported failure. Append the
TestU01 version, full summary, traversal, both source hashes, and exact backend
composition to the quality evidence document. A failing composition falls back
one backend at a time to the next independently eligible Task 5/Task 6 choice,
then reruns all three streams; if attribution is ambiguous, fall back both
backends together. No untested composition ships.

- [ ] **Step 2: Obtain delegated approval of final backend winners**

Give the complete quality, BigCrush, Criterion, controls, counters, and assembly
evidence to a fresh reviewer subagent. Its approved Elastic and Funnel choices
are the production choices.

- [ ] **Step 3: Select independently passing backend implementations**

Do not create a final alias or flatten functions through `prf/mod.rs`. If
guarded passes Elastic but current wins Funnel, make `probe.rs` call these
owning modules directly:

```rust
prf::guarded_wyhash::prepare_elastic(seed, hash);
prf::current::prepare_funnel(seed, hash);
```

Use the measured winner names instead when results differ. If no candidate passes a backend's full gate, that backend must use `current`.

- [ ] **Step 4: Delete selector aliases and losing code**

Remove `active_elastic` and `active_funnel`. Change `probe.rs` wrappers to call
the approved owning candidate modules directly, as in Step 3. Delete all losing
candidate files; keep Philox core only if a retained backend uses it. The final
quality CLI exposes only the formula module or modules used by the two shipped
backends. If `current` loses both backends, delete `current.rs` and remove it
from the final CLI; if one backend retains it, keep it only for that production
use. Earlier quality evidence remains archived by its committed source IDs and
hashes, so experimental losers need not remain in the source tree.

Expected: no source grep match for `active_elastic`, `active_funnel`, or a rejected candidate name.

- [ ] **Step 5: Update user-facing randomness documentation when production changes**

If either backend no longer uses the merged-main formula, update the README
randomness table/section to name the actual Elastic and Funnel implementations,
their domain/counter separation, and the fact that statistical validation is
an engineering PRF model rather than proof of an ideal independent oracle. Add
an `[Unreleased]` `### Changed` entry to `CHANGELOG.md` naming the internal PRF
replacement and stating that public API and paper geometry are unchanged. If
both backends retain `current`, make no README/CHANGELOG edit and state that in
the performance evidence.

- [ ] **Step 6: Verify and commit the exact final production tree**

```bash
rustup toolchain install 1.88.0
cargo test
cargo test --no-default-features
cargo +1.88.0 test --no-default-features
cargo +nightly test --features nightly
cargo +nightly miri test
pre-commit run --all-files
cargo test --manifest-path tools/prf-quality/Cargo.toml
cargo fmt --manifest-path tools/prf-quality/Cargo.toml -- --check
cargo clippy --manifest-path tools/prf-quality/Cargo.toml --all-targets -- -D warnings
```

Expected: all commands PASS.

Commit the selected direct modules, deleted experiments, final quality CLI,
BigCrush evidence, and conditional user documentation before measuring, so
every binary and result has one immutable source ID:

```bash
git add src/common/exact/prf src/common/exact/probe.rs src/elastic.rs tools/prf-quality README.md CHANGELOG.md docs/performance/2026-07-20-counter-prf-quality.md
git commit -m "perf: select validated counter prf backends"
prf_final_commit=$(git rev-parse HEAD)
test -z "$(git status --porcelain)"
```

- [ ] **Step 7: Pass fixed-control preflight and run three fresh final-vs-original pairs**

The acceptance anchor remains immutable `prf-original-current` from Task 6;
`prf-current-anchor` is diagnostic only. The final tree is the clean
`counter-prf-insert` worktree at `prf_final_commit`. On each pinned host first
run adjacent independent fixed controls and both stable-layout backend targets.
Require byte-identical control executables and every std/hashbrown movement
within 5%. Re-declare Task 6 Step 6's exact `snapshot_control_pair` helper with
`prf_candidate=final`, `prf_candidate_tree="$prf_final_tree"`,
`prf_candidate_commit="$prf_final_commit"`, and
`prf_candidate_manifest="$prf_final_manifest"`; invoke it at each marked
position below. Then run this exact alternating sequence:

```bash
prf_arch=$(uname -m)
prf_anchor_tree=/home/aang/projects/opthash/.worktrees/perf/prf-original-current
prf_final_tree=/home/aang/projects/opthash/.worktrees/perf/counter-prf-insert
CACHE_GATE_CONTROL_BIN=$(sed -n '1p' "$prf_anchor_tree/target/cache-gate-control-bin.txt")
test -x "$CACHE_GATE_CONTROL_BIN"
prf_anchor_commit=$(git -C "$prf_anchor_tree" rev-parse HEAD)
test "$prf_anchor_commit" = "$cache_off_current_commit"
test "$(git -C "$prf_final_tree" rev-parse HEAD)" = "$prf_final_commit"
test -z "$(git -C "$prf_anchor_tree" status --porcelain)"
test -z "$(git -C "$prf_final_tree" status --porcelain)"

(cd "$prf_anchor_tree" && CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" MANIFEST=1 CACHE_GATE_VARIANT=prf-original-current scripts/cache-gate.sh)
(cd "$prf_final_tree" && CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" MANIFEST=1 CACHE_GATE_VARIANT=prf-final scripts/cache-gate.sh)
prf_anchor_manifest="$prf_anchor_tree/target/cache-gate/$prf_arch/prf-original-current/manifest.json"
prf_final_manifest="$prf_final_tree/target/cache-gate/$prf_arch/prf-final/manifest.json"

(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" CONTROL=1 SAVE="$prf_arch-prf-final-preflight-original-control" scripts/cache-gate.sh)
(cd "$prf_final_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" CONTROL=1 SAVE="$prf_arch-prf-final-preflight-final-control" scripts/cache-gate.sh)
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" CONTROL=1 LOAD="$prf_arch-prf-final-preflight-final-control" BASELINE="$prf_arch-prf-final-preflight-original-control" scripts/cache-gate.sh)
(cd "$prf_anchor_tree" && scripts/snapshot-criterion-pair.sh --criterion-root "$prf_criterion_root" --snapshot-root target/cache-gate-evidence --arch "$prf_arch" --comparison prf-final-preflight-control --pair 1 --target control --anchor-run "$prf_arch-prf-final-preflight-original-control" --candidate-run "$prf_arch-prf-final-preflight-final-control" --anchor-commit "$prf_anchor_commit" --candidate-commit "$prf_final_commit" --anchor-manifest "$prf_anchor_manifest" --candidate-manifest "$prf_final_manifest")

(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" ELASTIC=1 SAVE="$prf_arch-prf-final-preflight-original-elastic" scripts/cache-gate.sh)
(cd "$prf_final_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" ELASTIC=1 SAVE="$prf_arch-prf-final-preflight-final-elastic" scripts/cache-gate.sh)
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" ELASTIC=1 LOAD="$prf_arch-prf-final-preflight-final-elastic" BASELINE="$prf_arch-prf-final-preflight-original-elastic" scripts/cache-gate.sh)
(cd "$prf_anchor_tree" && scripts/snapshot-criterion-pair.sh --criterion-root "$prf_criterion_root" --snapshot-root target/cache-gate-evidence --arch "$prf_arch" --comparison prf-final-preflight-elastic --pair 1 --target elastic_cache_gate --anchor-run "$prf_arch-prf-final-preflight-original-elastic" --candidate-run "$prf_arch-prf-final-preflight-final-elastic" --anchor-commit "$prf_anchor_commit" --candidate-commit "$prf_final_commit" --anchor-manifest "$prf_anchor_manifest" --candidate-manifest "$prf_final_manifest")

(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" FUNNEL=1 SAVE="$prf_arch-prf-final-preflight-original-funnel" scripts/cache-gate.sh)
(cd "$prf_final_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" FUNNEL=1 SAVE="$prf_arch-prf-final-preflight-final-funnel" scripts/cache-gate.sh)
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" FUNNEL=1 LOAD="$prf_arch-prf-final-preflight-final-funnel" BASELINE="$prf_arch-prf-final-preflight-original-funnel" scripts/cache-gate.sh)
(cd "$prf_anchor_tree" && scripts/snapshot-criterion-pair.sh --criterion-root "$prf_criterion_root" --snapshot-root target/cache-gate-evidence --arch "$prf_arch" --comparison prf-final-preflight-funnel --pair 1 --target funnel_cache_gate --anchor-run "$prf_arch-prf-final-preflight-original-funnel" --candidate-run "$prf_arch-prf-final-preflight-final-funnel" --anchor-commit "$prf_anchor_commit" --candidate-commit "$prf_final_commit" --anchor-manifest "$prf_anchor_manifest" --candidate-manifest "$prf_final_manifest")

snapshot_control_pair final-full-1 1
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" SAVE="$prf_arch-prf-final-original-a1" scripts/bench.sh)
(cd "$prf_final_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" SAVE="$prf_arch-prf-final-f1" scripts/bench.sh)
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" LOAD="$prf_arch-prf-final-f1" BASELINE="$prf_arch-prf-final-original-a1" scripts/bench.sh)
(cd "$prf_anchor_tree" && scripts/snapshot-criterion-pair.sh --criterion-root "$prf_criterion_root" --snapshot-root target/cache-gate-evidence --arch "$prf_arch" --comparison prf-final-full --pair 1 --target all --anchor-run "$prf_arch-prf-final-original-a1" --candidate-run "$prf_arch-prf-final-f1" --anchor-commit "$prf_anchor_commit" --candidate-commit "$prf_final_commit" --anchor-manifest "$prf_anchor_manifest" --candidate-manifest "$prf_final_manifest")
snapshot_control_pair final-full-2 2
(cd "$prf_final_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" SAVE="$prf_arch-prf-final-f2" scripts/bench.sh)
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" SAVE="$prf_arch-prf-final-original-a2" scripts/bench.sh)
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" LOAD="$prf_arch-prf-final-f2" BASELINE="$prf_arch-prf-final-original-a2" scripts/bench.sh)
(cd "$prf_anchor_tree" && scripts/snapshot-criterion-pair.sh --criterion-root "$prf_criterion_root" --snapshot-root target/cache-gate-evidence --arch "$prf_arch" --comparison prf-final-full --pair 2 --target all --anchor-run "$prf_arch-prf-final-original-a2" --candidate-run "$prf_arch-prf-final-f2" --anchor-commit "$prf_anchor_commit" --candidate-commit "$prf_final_commit" --anchor-manifest "$prf_anchor_manifest" --candidate-manifest "$prf_final_manifest")
snapshot_control_pair final-full-3 3
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" SAVE="$prf_arch-prf-final-original-a3" scripts/bench.sh)
(cd "$prf_final_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" SAVE="$prf_arch-prf-final-f3" scripts/bench.sh)
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" LOAD="$prf_arch-prf-final-f3" BASELINE="$prf_arch-prf-final-original-a3" scripts/bench.sh)
(cd "$prf_anchor_tree" && scripts/snapshot-criterion-pair.sh --criterion-root "$prf_criterion_root" --snapshot-root target/cache-gate-evidence --arch "$prf_arch" --comparison prf-final-full --pair 3 --target all --anchor-run "$prf_arch-prf-final-original-a3" --candidate-run "$prf_arch-prf-final-f3" --anchor-commit "$prf_anchor_commit" --candidate-commit "$prf_final_commit" --anchor-manifest "$prf_anchor_manifest" --candidate-manifest "$prf_final_manifest")

snapshot_control_pair final-scale-1 1
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert SAVE="$prf_arch-prf-final-original-scale-a1" scripts/bench.sh)
(cd "$prf_final_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert SAVE="$prf_arch-prf-final-scale-f1" scripts/bench.sh)
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert LOAD="$prf_arch-prf-final-scale-f1" BASELINE="$prf_arch-prf-final-original-scale-a1" scripts/bench.sh)
(cd "$prf_anchor_tree" && scripts/snapshot-criterion-pair.sh --criterion-root "$prf_criterion_root" --snapshot-root target/cache-gate-evidence --arch "$prf_arch" --comparison prf-final-scale --pair 1 --target scaled_insert --anchor-run "$prf_arch-prf-final-original-scale-a1" --candidate-run "$prf_arch-prf-final-scale-f1" --anchor-commit "$prf_anchor_commit" --candidate-commit "$prf_final_commit" --anchor-manifest "$prf_anchor_manifest" --candidate-manifest "$prf_final_manifest")
snapshot_control_pair final-scale-2 2
(cd "$prf_final_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert SAVE="$prf_arch-prf-final-scale-f2" scripts/bench.sh)
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert SAVE="$prf_arch-prf-final-original-scale-a2" scripts/bench.sh)
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert LOAD="$prf_arch-prf-final-scale-f2" BASELINE="$prf_arch-prf-final-original-scale-a2" scripts/bench.sh)
(cd "$prf_anchor_tree" && scripts/snapshot-criterion-pair.sh --criterion-root "$prf_criterion_root" --snapshot-root target/cache-gate-evidence --arch "$prf_arch" --comparison prf-final-scale --pair 2 --target scaled_insert --anchor-run "$prf_arch-prf-final-original-scale-a2" --candidate-run "$prf_arch-prf-final-scale-f2" --anchor-commit "$prf_anchor_commit" --candidate-commit "$prf_final_commit" --anchor-manifest "$prf_anchor_manifest" --candidate-manifest "$prf_final_manifest")
snapshot_control_pair final-scale-3 3
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert SAVE="$prf_arch-prf-final-original-scale-a3" scripts/bench.sh)
(cd "$prf_final_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert SAVE="$prf_arch-prf-final-scale-f3" scripts/bench.sh)
(cd "$prf_anchor_tree" && OPTHASH_CRITERION_ROOT="$prf_criterion_root" BENCH=scaled_insert LOAD="$prf_arch-prf-final-scale-f3" BASELINE="$prf_arch-prf-final-original-scale-a3" scripts/bench.sh)
(cd "$prf_anchor_tree" && scripts/snapshot-criterion-pair.sh --criterion-root "$prf_criterion_root" --snapshot-root target/cache-gate-evidence --arch "$prf_arch" --comparison prf-final-scale --pair 3 --target scaled_insert --anchor-run "$prf_arch-prf-final-original-scale-a3" --candidate-run "$prf_arch-prf-final-scale-f3" --anchor-commit "$prf_anchor_commit" --candidate-commit "$prf_final_commit" --anchor-manifest "$prf_anchor_manifest" --candidate-manifest "$prf_final_manifest")
```

The `LOAD/BASELINE` and atomic snapshot must occur at the exact positions shown,
before another comparison can overwrite live `change/`. Each snapshot contains
all changes, both absolute trees, both manifests/link maps, commits, run names,
target, and verified hashes. Repeat the adjacent fixed-control comparison and
snapshot immediately before each full and scaled pair, using unique names;
discard/rerun any pair whose std or hashbrown control exceeds 5%, preserving
the rejected snapshot. Read raw point estimates, intervals, and controls only
from immutable snapshots. Apply every
Task 6 gate to the actual mixed tree: headline insert, randomized/ordered get,
all five other public `speedup` groups, and each 100K/1M/10M scaled-insert
group, plus all randomized/sequential latency traces at 1K, 10K, 100K, 1M,
and 10M. No operation, scale, or latency size is exempt because its provisional
components passed separately. Derive `changed_backends` from the final direct module calls:
apply -10%/-5% only to changed Elastic/Funnel backends, and apply Task 6's +2%
plus byte-identical hot-body/±0-Callgrind gate to any backend that still calls
`current`. Candidate-vs-scaffold or candidate-vs-cache-on comparisons cannot
substitute for these direct original-current gates.

Before accepting timing, require the final manifest to match original current
for the stable Elastic and Funnel kernels' address, `start % 4096`, alignment,
and link-map predecessor, and require every target-aware layout snapshot to
match. Reject unexplained drift. If Funnel remains `current`, every Funnel
public/latency/scaled point is `<= +0.02`, its median is `<= +0.01`, at least
two upper bounds are `<= +0.02`, and its named Callgrind counts and normalized
stable hot bodies are exactly unchanged. Never gate a favorable negative lower
bound.

- [ ] **Step 8: Capture final counters, Callgrind, and exact assembly**

On AArch64 run only the manifested no-build profile binary in both immutable
trees. Invoke `scripts/cache-gate-perf.sh` with the matching manifest for each
of `elastic-insert`, `elastic-get`, `funnel-insert`, and `funnel-get`, with
identical iterations and three separately retained repetitions, exactly as in
Task 6 Step 7. Counters are enabled only after the profile process reports
`READY`; preserve every raw `perf stat -x,` CSV and compute per-operation
medians. Cargo, Criterion, linking, fixture setup, and another operation are
outside the enabled interval.

On x86-64 run the following separately in both trees, using distinct output
names:

```bash
cargo clean -p opthash
CARGO_INCREMENTAL=0 cargo codspeed build --bench speedup
cargo codspeed run --bench speedup 2>&1 | tee target/prf-final-callgrind.txt
cargo bench --bench speedup --no-run --message-format=json > target/prf-final-cargo.json
jq -r 'select(.reason == "compiler-artifact" and .target.name == "speedup" and .executable != null) | .executable' target/prf-final-cargo.json | sort -u > target/prf-final-executables.txt
test "$(wc -l < target/prf-final-executables.txt)" -eq 1
speedup_bin=$(sed -n '1p' target/prf-final-executables.txt)
test -n "$speedup_bin"
test -x "$speedup_bin"
test "$(stat -c %Y "$speedup_bin")" -ge "$(git show -s --format=%ct HEAD)"
objdump -d -C "$speedup_bin" > target/prf-final-speedup.asm
rg -n "elastic_word|funnel_word|philox2x64|guarded_word|insert_for_vacant_entry_prepared|find_by_exact_schedule" target/prf-final-speedup.asm
```

Record each tree's commit, exact executable/mtime, and per-operation Callgrind
counts. Expected: the final mixed tree reproduces accepted wall-clock and
instruction/counter direction, directly inlines its two winner formulas, and
contains no selector, hidden aggregate result, spill regression, stale binary,
or rejected-candidate call. Elastic insert contains exactly one retained
candidate metadata-signature evaluation; get remains lazy after H(1,1). All
ABI, stack, spill, call-site, and instruction comparisons use
`prf-original-current`.

Give the three raw final pairs—with point estimates, 95% intervals, run names,
and controls for `insert`, `get_hit`, `get_hit_sequential`, `get_miss`,
`tiny_lookup`, `mixed`, `delete_heavy`, and `resize_heavy`—plus all three
100K/1M/10M scaled pairs and all ten randomized/sequential 1K→10M latency
traces, counters, Callgrind, and exact assembly to a fresh reviewer subagent
before proceeding. If it rejects the mixed tree, choose only
a previously eligible fallback, rerun the actual mixed
BigCrush streams, and return to Steps 3-6: rewire/delete modules, update the
final CLI/docs, rerun the entire test/no-std/nightly/Miri/pre-commit gate, and
make a new immutable production commit. Only then repeat Steps 7-8. Do not
document or ship a final composition until the reviewer approves it.

- [ ] **Step 9: Record final performance evidence**

Create `docs/performance/2026-07-20-counter-prf-performance.md` containing:

1. Exact cache-off original, scaffold-current, and candidate commit IDs plus host architecture/CPU/kernel/toolchain.
2. All three raw pairs, point estimates, 95% intervals, controls, and decisions
   per architecture/backend for `insert`, `get_hit`, `get_hit_sequential`,
   `get_miss`, `tiny_lookup`, `mixed`, `delete_heavy`, and `resize_heavy`.
3. All three raw pairs, intervals, controls, and +2% decisions for randomized
   and sequential latency at 1K, 10K, 100K, 1M, and 10M.
4. Fixed-control executable hashes/addresses, stable-layout preflight, and every discarded control run/movement.
5. All three 100K/1M/10M scaled-insert pairs, intervals, controls, and gate decisions.
6. Callgrind and `perf stat` cycle/instruction/cache/branch changes.
7. Struct sizes, stack-frame sizes, one-signature/lazy-get proof, and multiply lowering from final assembly.
8. Independent winner decision for Elastic and Funnel, including `current` where no new candidate passed.

- [ ] **Step 10: Commit the final performance evidence**

```bash
pre-commit run --files docs/performance/2026-07-20-counter-prf-performance.md
git add docs/performance/2026-07-20-counter-prf-performance.md
git commit -m "docs: record counter prf performance evidence"
git status --short
```

Expected: commit succeeds, worktree is clean, and the tree contains no runtime or feature-selectable PRF experiment.
