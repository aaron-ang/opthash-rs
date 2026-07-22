# Elastic Candidate Signature Cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add and validate a compile-time candidate policy that caches one full Elastic metadata signature for guarded-wyhash64 and Philox inserts while preserving original current-PRF code generation when the policy is false.

**Architecture:** First repair the rejected v1 measurement harness with
Linux-ELF-only input sections and an augmenting linker script that gives every
stable/profile kernel a page-isolated reservation and checked exported
sentinels. Manifest once, then execute those exact hash-verified Criterion and
profile binaries without Cargo or relinking. Only after cache-off-v2 passes on
native AArch64 and x86-64, replay the policy source patch: ordinary lookup stays
on the 8-byte `PreparedElasticRoute`, while only the insert-only 16-byte
`PreparedElasticKey` changes its second-word meaning by compile-time policy.

**Tech Stack:** Rust 2024 (`core`/`alloc`, MSRV 1.88), Criterion/CodSpeed,
Linux ELF/PIE, GNU ld or LLD augmenting linker scripts, `readelf`, GNU
`objdump`, Linux `perf`, `sha256sum`, existing pinned benchmark launcher.

## Global Constraints

- Preserve candidate enumeration, paper placement, scheduler state, exact reducer, retry accounting, lookup schedule, exceptional recovery, slot/control/counter mutation order, and public API.
- `PreparedElasticRoute` remains exactly 8 bytes and `PreparedElasticKey`
  exactly 16 bytes; on each target, both retain the cache-off alignment of
  `u64` rather than assuming an eight-byte alignment on every supported ABI.
- `ElasticTable`, `FunnelTable`, `Level`, Funnel shape/storage types, and
  metadata-word size/offsets remain byte-for-byte unchanged; current
  `BucketLevel` absence is recorded rather than inventing a snapshot for a type
  that does not exist.
- Add no table field, sidecar field, third prepared-key word, metadata pointer/reference, loaded metadata snapshot, or cached geometry-dependent word index.
- Current policy is `false`; guarded-wyhash64, Philox2x64-6, and Philox2x64-10 policies are `true` when those candidate modules are introduced.
- Policy `false` stores the existing prepared membership bits and must reproduce original current insert/get hot-symbol bytes and exact named Callgrind instruction counts.
- Policy `true` stores the full `routing_signature()`, derives membership bits when prechecking and recording, and evaluates the metadata signature exactly once per prepared insert key.
- Ordinary `get`, `get_mut`, `contains_key`, remove lookup, and entry lookup construct only `PreparedElasticRoute`; an H(1,1) hit returns before candidate metadata-signature work.
- Word index is always multiply-high of the logical signature and the table's current `membership_words()`; summary bin is `signature & 3`.
- Cache-off, cache-policy, and cache-on measurements use immutable commits. Every final candidate is compared directly with cache-off original current, never only with cache-policy or cache-on current.
- The original `1080c18` harness and `b1cabb6`/`f4a0d35` policy manifests are
  rejected diagnostics. Preserve them and the recoverable `5fb56a5` revert,
  but never relabel or copy their results into acceptance evidence.
- Task 2 remains `HOLD` until a fresh harness-only cache-off-v2 descendant of
  source-original `47fc953` passes the repaired layout gate on native AArch64
  and x86-64 and receives fresh review. This is `REJECT-HARNESS`, not
  `REJECT-CARRIER`; current policy semantics are not rejected.
- Before any v2 worktree is created, commit exactly this standalone plan, the
  counter-PRF bakeoff plan, and the counter-PRF design spec as one docs-only
  remediation commit whose exact parent is `f4a0d35`. Record its commit, patch
  SHA-256, file list, and three Git blob IDs; replay that edge after the v1
  harness edge and require every v2 descendant to retain those blobs.
- A fixed-control executable must be byte-identical across measured commits.
  Stable Elastic/Funnel and profile kernels use unique constant ELF input
  sections, page-isolated executable output reservations inserted before
  `.text`, exact exported reservation-start/reservation-end sentinels, and a
  structurally valid body-end sentinel whose address may move only for a
  declared changed kernel. Kernel Rust
  ABI stays internal; do not add `no_mangle` or `export_name` merely for order.
- Stable Criterion and profile runs execute the exact absolute binaries named
  and hashed by the accepted manifest. No Cargo invocation, rebuild, or relink
  may occur between manifest construction and a stable/profile evidence run.
- Unsupported linker augmentation, non-ELF hosts, bad PIE/RX layout, veneers,
  or missing native architecture produce `HOLD`; no orphan-section fallback or
  weakened address gate is permitted.
- Run the three-pair full-suite, default scaled-insert, assembly, Callgrind, and hardware-counter gates on pinned native AArch64 and x86-64 hosts.
- Add no production dependency and preserve `no_std`, allocator, Miri, little-endian, big-endian, and Rust 1.88 behavior.
- Before retaining or reverting the cache scaffold, obtain a fresh reviewer decision over raw evidence. Reviewer approval is the delegated acceptance gate.

## File Map

- `tools/cache-gate-control/Cargo.toml` and `tools/cache-gate-control/src/main.rs` — fixed std/hashbrown control executable with no `opthash` dependency.
- `tools/cache-gate-control/Cargo.lock` — pinned independent control dependencies.
- `benches/elastic_cache_gate.rs` — one-implementation stable-layout Elastic insert/get target.
- `benches/funnel_cache_gate.rs` — one-implementation stable-layout Funnel insert/get target used for unchanged-backend and later PRF gates.
- `benches/cache_gate_profile.rs` — deterministic operation-specific profiling binary with setup outside enabled counters.
- `benches/harness/cache_gate.rs` and `benches/harness/mod.rs` — shared deterministic fixture and validation used by the stable Elastic target without duplicating workload primitives.
- `tests/elastic_cache_gate_fixture.rs` — real libtest integration target for fixture RED/GREEN discovery.
- `tests/test_extract_hot_symbols.py` — normalization/extractor fixtures for x86-64 and AArch64 disassembly.
- `Cargo.toml` — declares stable/profile targets and excludes `/tools/` from the published crate; fixed controls remain an independent manifest.
- `scripts/cache-gate.sh` — applies the repository's pin/ASLR/scheduler/NUMA rules to fixed-control and stable-Elastic targets and writes a manifest of binary hashes and symbol addresses.
- `benches/cache-gate-elastic-layout.ld` — checked 2-kernel Elastic GNU ld/LLD
  augmentation using `INSERT BEFORE .text`.
- `benches/cache-gate-funnel-layout.ld` — checked 2-kernel Funnel augmentation.
- `benches/cache-gate-profile-layout.ld` — checked 4-kernel profile
  augmentation. No link receives an empty reservation for another executable.
- `scripts/cache-gate-linker-capability.sh` — probes the actual Cargo-configured
  linker with the augmentation and records linker path/flavor/version, ELF
  identity, three fragment hashes/set hash, and fail-closed result.
- `scripts/cache-gate-elf-layout.py` — parses ELF sections/program headers,
  linker maps, symbol tables, sentinels, veneers, and manifest-to-binary hashes;
  validates and compares structural placement.
- `tests/test_cache_gate_elf_layout.py` — GNU ld/LLD map/ELF fixtures for
  section, sentinel, overflow, flags/segments, overlap, veneer, and hash gates.
- `tests/fixtures/cache_gate_layout_adversary.rs` — private generic emission
  perturbation used only to prove 16-CGU partition changes cannot move reserved
  kernels.
- `scripts/cache-gate-perf.sh` — no-build, manifested-binary, operation-specific `perf stat` collection.
- `scripts/extract-hot-symbols.py` — exact-one-symbol resolution, checked instruction normalization, and symbol metadata/hashing.
- `scripts/snapshot-criterion-pair.sh` — atomic immutable snapshot of change JSON, both absolute JSON trees, manifests, and SHA-256 inventory after each offline comparison.
- `src/common/exact/probe.rs` — owns the current compile-time candidate property until the counter-PRF bakeoff moves it into identical candidate modules.
- `src/elastic.rs` — insert-only union word, logical accessors, current-geometry metadata derivation, lifecycle tests, and layout assertions.
- `docs/performance/2026-07-21-elastic-candidate-signature-cache.md` — immutable commits, raw pairs, codegen/counter evidence, reviewer verdict, and retain/revert record.

## Current Execution State and Canonical Graph

The v1 work was executed far enough to diagnose the harness, but no policy or
carrier decision is accepted:

```text
47fc953  source-original documentation commit
  └─1080c18  v1 harness; retained, layout evidence rejected
      └─b1cabb6  first policy diagnostic; source semantics pass
          └─5fb56a5  recoverable revert to source-original production
              └─f4a0d35  revised policy diagnostic; same layout failure
```

The canonical continuation includes the docs edge under review:

```text
f4a0d35
  └─<docs-remediation-v2>    exact three-doc amendment; parent is f4a0d35
      └─<policy-revert-v2>   revert f4a0d35 source; retain amended docs

47fc953
  └─<replayed-harness-v1>    replay 1080c18 harness files only
      └─<replayed-docs-v2>   cherry-pick exact docs-remediation edge
          └─<cache-off-v2>   ELF placement repair; src equals 47fc953
              └─<policy-replay-v2> exact production patch after test-only RED
                  └─<cache-policy-v2> lifecycle-tested policy-false tip
                      └─<cache-on-v2> force-true attribution branch
```

Only the second graph's reviewed `cache-off-v2`, `cache-policy-v2`, and
`cache-on-v2` commits may appear in accepted evidence. Task 1 below documents
the implemented v1 harness and remains useful as source history; its v1
manifest/timing commands are superseded by Task 2 and must not be used for
acceptance.

---

### Task 1: Build the Initial Harness (Historical v1; Layout Evidence Rejected)

**Execution status:** Implemented at `1080c188a47f02202b6a0878830dbf2947629992`.
Its fixture, independent controls, snapshot tooling, and no-build profile path
remain inputs to Task 2, but its stable Elastic placement failed. The v1
manifest/timing steps below are historical diagnostics, not acceptance gates.
Do not rerun Task 2 policy acceptance from this anchor.

**Files:**
- Create: `tools/cache-gate-control/Cargo.toml`
- Create: `tools/cache-gate-control/Cargo.lock`
- Create: `tools/cache-gate-control/src/main.rs`
- Create: `benches/elastic_cache_gate.rs`
- Create: `benches/harness/cache_gate.rs`
- Modify: `benches/harness/mod.rs`
- Create: `tests/elastic_cache_gate_fixture.rs`
- Create: `benches/funnel_cache_gate.rs`
- Create: `benches/cache_gate_profile.rs`
- Modify: `Cargo.toml`
- Create: `scripts/cache-gate.sh`
- Create: `scripts/cache-gate-perf.sh`
- Create: `scripts/extract-hot-symbols.py`
- Create: `scripts/snapshot-criterion-pair.sh`
- Create: `tests/test_extract_hot_symbols.py`
- Test: `benches/harness/cache_gate.rs`

**Interfaces:**
- Consumes: fixed `OP_COUNT`, `make_pairs`, `BenchHasher`, existing pinned-host rules in `scripts/bench.sh`.
- Produces: discoverable fixture tests; independent fixed controls; named stable Elastic/Funnel kernels; operation-specific profiling kernels; checked symbol metadata; and `target/cache-gate/<arch>/<variant>/manifest.json` containing commit, executable/link-map hashes, symbol addresses/alignment/sizes, and normalized hashes.

- [ ] **Step 1: Freeze original production identity before adding harness files**

Run:

```bash
test -z "$(git status --porcelain)"
cache_off_source_commit=$(git rev-parse HEAD)
git diff --quiet 849b8b3 -- src
git rev-parse "$cache_off_source_commit^{tree}" > target/cache-off-source-tree.txt
git diff 849b8b3.."$cache_off_source_commit" -- src benches scripts Cargo.toml Cargo.lock > target/cache-off-source.diff
test ! -s target/cache-off-source.diff
```

Expected: clean tree; production and benchmark sources still match the post-design/pre-Phase-1 source tree. Record the full commit in task notes. If the source diff is nonempty, stop and have a reviewer identify the new original before continuing.

- [ ] **Step 2: Write failing harness fixture tests**

Declare the `elastic_cache_gate` target in `Cargo.toml`, create a temporary
`benches/elastic_cache_gate.rs` containing `mod harness; fn main() {}`, and add
`mod cache_gate;` to `benches/harness/mod.rs`. Create
`benches/harness/cache_gate.rs` with the tests first and no implementation:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_gate_fixture_is_fixed_and_distinct() {
        let pairs = cache_gate_pairs();
        assert_eq!(pairs.len(), CACHE_GATE_OP_COUNT);
        assert_eq!(pairs[0], (0, 0xA5A5_A5A5_A5A5_A5A5));
        assert_eq!(pairs[1].0, 0x9E37_79B9_7F4A_7C15);
        let mut keys = pairs.iter().map(|pair| pair.0).collect::<Vec<_>>();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), pairs.len());
    }

    #[test]
    fn cache_gate_preflight_requires_exact_fill_without_growth() {
        let pairs = cache_gate_pairs();
        let mut map = elastic_cache_gate_map();
        let capacity = map.capacity();
        validate_cache_gate_fill(&mut map, &pairs);
        assert_eq!(map.len(), CACHE_GATE_OP_COUNT);
        assert_eq!(map.capacity(), capacity);
    }
}
```

Create a real libtest integration target at
`tests/elastic_cache_gate_fixture.rs`:

```rust
#[path = "../benches/harness/mod.rs"]
mod harness;
```

The integration crate is compiled with `cfg(test)` and discovers nested tests;
the Criterion target remains `harness = false` and is never used as libtest.

Run:

```bash
if cargo test --test elastic_cache_gate_fixture cache_gate::tests > target/cache-gate-harness-red.txt 2>&1; then
    echo "error: cache-gate harness red unexpectedly passed" >&2
    exit 1
fi
rg -n "cache_gate_pairs|elastic_cache_gate_map|validate_cache_gate_fill" target/cache-gate-harness-red.txt
```

Expected: nonzero compile status naming the missing fixture functions from the
integration target. A Criterion main invocation or zero discovered tests is not
acceptable.

- [ ] **Step 3: Implement one shared deterministic Elastic fixture**

Implement in `benches/harness/cache_gate.rs`:

```rust
use std::hash::BuildHasher;

use super::{BenchHasher, ElasticHashMap, OP_COUNT, make_pairs};

pub const CACHE_GATE_OP_COUNT: usize = OP_COUNT;

pub fn cache_gate_pairs() -> Vec<(u64, u64)> {
    make_pairs(CACHE_GATE_OP_COUNT)
}

pub fn elastic_cache_gate_map() -> ElasticHashMap<u64, u64> {
    ElasticHashMap::with_capacity_and_hasher(CACHE_GATE_OP_COUNT * 2, BenchHasher::default())
}

pub fn validate_cache_gate_fill<S>(
    map: &mut opthash::ElasticHashMap<u64, u64, S>,
    pairs: &[(u64, u64)],
) where
    S: BuildHasher,
{
    let capacity = map.capacity();
    for &(key, value) in pairs {
        assert_eq!(map.insert(key, value), None);
    }
    assert_eq!(map.len(), pairs.len());
    assert_eq!(map.capacity(), capacity);
    for &(key, value) in pairs {
        assert_eq!(map.get(&key), Some(&value));
    }
}
```

Re-export only the needed names from `benches/harness/mod.rs`. Do not copy `make_pairs`, map constructors, or timing macros.

- [ ] **Step 4: Complete the stable-layout Elastic target**

Retain the target declaration added for RED:

```toml
[[bench]]
name = "elastic_cache_gate"
harness = false
```

Replace the temporary `benches/elastic_cache_gate.rs` with exactly two Elastic monomorphizations and no std/hashbrown/Funnel timing arms:

```rust
mod harness;

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

#[inline(never)]
fn elastic_cache_gate_insert_kernel(
    map: &mut harness::ElasticHashMap<u64, u64>,
    pairs: &[(u64, u64)],
) -> Duration {
    let start = Instant::now();
    for &(key, value) in pairs {
        black_box(map.insert(black_box(key), black_box(value)));
    }
    start.elapsed()
}

#[inline(never)]
fn elastic_cache_gate_get_kernel(
    map: &harness::ElasticHashMap<u64, u64>,
    key: u64,
) -> Option<u64> {
    map.get(black_box(&key)).copied()
}

fn cache_gate_insert(c: &mut Criterion) {
    let pairs = harness::cache_gate_pairs();
    let mut map = harness::elastic_cache_gate_map();
    harness::validate_cache_gate_fill(&mut map, &pairs);
    map.clear();
    let expected_capacity = map.capacity();
    let mut group = c.benchmark_group("cache_gate_insert");
    group.throughput(Throughput::Elements(pairs.len() as u64));
    group.bench_function("cache_gate_insert_elastic", move |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                map.clear();
                assert_eq!(map.capacity(), expected_capacity);
                total += elastic_cache_gate_insert_kernel(&mut map, &pairs);
                assert_eq!(map.len(), pairs.len());
            }
            total
        });
    });
    group.finish();
}

fn cache_gate_get_hit(c: &mut Criterion) {
    let pairs = harness::cache_gate_pairs();
    let mut map = harness::elastic_cache_gate_map();
    harness::validate_cache_gate_fill(&mut map, &pairs);
    let keys = pairs.iter().map(|pair| pair.0).collect::<Vec<_>>();
    c.bench_function("cache_gate_get_hit_elastic", move |b| {
        let mut keys = keys.iter().cycle();
        b.iter(|| black_box(elastic_cache_gate_get_kernel(&map, *keys.next().unwrap())));
    });
}

criterion_group!(benches, cache_gate_insert, cache_gate_get_hit);
criterion_main!(benches);
```

Run:

```bash
cargo test --test elastic_cache_gate_fixture cache_gate::tests -- --nocapture | tee target/cache-gate-harness-green.txt
rg -n "test result: ok\. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" target/cache-gate-harness-green.txt
```

Expected: exactly two discovered fixture tests PASS under libtest.

- [ ] **Step 5: Add the stable Funnel target and named kernels**

Add `funnel_cache_gate_map()` and `validate_funnel_cache_gate_fill()` to
`benches/harness/cache_gate.rs`, using `FunnelHashMap<u64, u64>` with the same
capacity, pairs, exact-fill, capacity, and lookup assertions as the Elastic
fixture. Declare:

```toml
[[bench]]
name = "funnel_cache_gate"
harness = false
```

Create `benches/funnel_cache_gate.rs` with concrete, unique kernels:

```rust
mod harness;

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

#[inline(never)]
fn funnel_cache_gate_insert_kernel(
    map: &mut harness::FunnelHashMap<u64, u64>,
    pairs: &[(u64, u64)],
) -> Duration {
    let start = Instant::now();
    for &(key, value) in pairs {
        black_box(map.insert(black_box(key), black_box(value)));
    }
    start.elapsed()
}

#[inline(never)]
fn funnel_cache_gate_get_kernel(
    map: &harness::FunnelHashMap<u64, u64>,
    key: u64,
) -> Option<u64> {
    map.get(black_box(&key)).copied()
}

fn cache_gate_insert(c: &mut Criterion) {
    let pairs = harness::cache_gate_pairs();
    let mut map = harness::funnel_cache_gate_map();
    harness::validate_funnel_cache_gate_fill(&mut map, &pairs);
    map.clear();
    let expected_capacity = map.capacity();
    let mut group = c.benchmark_group("cache_gate_insert");
    group.throughput(Throughput::Elements(pairs.len() as u64));
    group.bench_function("cache_gate_insert_funnel", move |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                map.clear();
                assert_eq!(map.capacity(), expected_capacity);
                total += funnel_cache_gate_insert_kernel(&mut map, &pairs);
                assert_eq!(map.len(), pairs.len());
            }
            total
        });
    });
    group.finish();
}

fn cache_gate_get_hit(c: &mut Criterion) {
    let pairs = harness::cache_gate_pairs();
    let mut map = harness::funnel_cache_gate_map();
    harness::validate_funnel_cache_gate_fill(&mut map, &pairs);
    let keys = pairs.iter().map(|pair| pair.0).collect::<Vec<_>>();
    c.bench_function("cache_gate_get_hit_funnel", move |b| {
        let mut keys = keys.iter().cycle();
        b.iter(|| black_box(funnel_cache_gate_get_kernel(&map, *keys.next().unwrap())));
    });
}

criterion_group!(benches, cache_gate_insert, cache_gate_get_hit);
criterion_main!(benches);
```

Both Criterion callbacks call named kernels; no map operation remains only in
an anonymous closure.

Run `cargo bench --bench elastic_cache_gate --no-run` and
`cargo bench --bench funnel_cache_gate --no-run`. Expected: each executable
contains exactly one demangled insert kernel and one get kernel.

- [ ] **Step 6: Add a truly independent fixed-control package**

Create `tools/cache-gate-control/Cargo.toml`:

```toml
[package]
name = "opthash-cache-gate-control"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
criterion = { version = "4", package = "codspeed-criterion-compat", default-features = false, features = ["cargo_bench_support"] }
foldhash = { version = "0.2", default-features = false, features = ["std"] }
hashbrown = "0.17"
```

Create `src/main.rs` with std/hashbrown only:

```rust
// This package intentionally has no `opthash` path or registry dependency.
use std::collections::HashMap as StdHashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::BuildHasherDefault;
use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use foldhash::fast::FixedState;
use hashbrown::HashMap as HashbrownMap;

const OP_COUNT: usize = 100_000;
const GOLDEN_RATIO_U64: u64 = 0x9E37_79B9_7F4A_7C15;
const VALUE_XOR_MIX: u64 = 0xA5A5_A5A5_A5A5_A5A5;

fn pairs() -> Vec<(u64, u64)> {
    (0..OP_COUNT)
        .map(|index| {
            let key = (index as u64).wrapping_mul(GOLDEN_RATIO_U64);
            (key, key ^ VALUE_XOR_MIX)
        })
        .collect()
}

macro_rules! control_arm {
    ($group:expr, $name:literal, $map:expr, $pairs:expr) => {{
        let pairs = $pairs.clone();
        let mut map = $map;
        let expected_capacity = map.capacity();
        for &(key, value) in &pairs {
            assert_eq!(map.insert(key, value), None);
        }
        assert_eq!(map.len(), pairs.len());
        assert_eq!(map.capacity(), expected_capacity);
        for &(key, value) in &pairs {
            assert_eq!(map.get(&key), Some(&value));
        }
        map.clear();
        $group.bench_function($name, move |b| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    map.clear();
                    assert_eq!(map.capacity(), expected_capacity);
                    let start = std::time::Instant::now();
                    for &(key, value) in &pairs {
                        black_box(map.insert(black_box(key), black_box(value)));
                    }
                    total += start.elapsed();
                    assert_eq!(map.len(), pairs.len());
                }
                total
            });
        });
    }};
}

fn fixed_controls(c: &mut Criterion) {
    let pairs = pairs();
    let mut group = c.benchmark_group("cache_gate_insert");
    group.throughput(Throughput::Elements(OP_COUNT as u64));
    control_arm!(
        group,
        "cache_gate_insert_std",
        StdHashMap::<u64, u64, BuildHasherDefault<DefaultHasher>>::
            with_capacity_and_hasher(OP_COUNT * 2, BuildHasherDefault::default()),
        pairs
    );
    control_arm!(
        group,
        "cache_gate_insert_hashbrown",
        HashbrownMap::<u64, u64, FixedState>::
            with_capacity_and_hasher(OP_COUNT * 2, FixedState::default()),
        pairs
    );
    group.finish();
}

criterion_group!(benches, fixed_controls);
criterion_main!(benches);
```

Add `"/tools/"` to root `Cargo.toml`'s package `exclude` list. Generate and
retain the nested lockfile, then verify independence and the non-workspace tool
directly:

```bash
cargo generate-lockfile --manifest-path tools/cache-gate-control/Cargo.toml
if cargo metadata --locked --manifest-path tools/cache-gate-control/Cargo.toml --format-version 1 --no-deps | rg '"name":"opthash"'; then
    echo "error: fixed controls depend on opthash" >&2
    exit 1
fi
cargo fmt --manifest-path tools/cache-gate-control/Cargo.toml -- --check
cargo clippy --locked --manifest-path tools/cache-gate-control/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path tools/cache-gate-control/Cargo.toml
cargo build --release --locked --manifest-path tools/cache-gate-control/Cargo.toml
sha256sum tools/cache-gate-control/Cargo.toml tools/cache-gate-control/Cargo.lock > target/cache-gate-control-inputs.sha256
```

Expected: no `opthash` package in metadata; format, lint, test, and locked
release build pass; manifest and lockfile hashes are retained in every control
manifest.

- [ ] **Step 7: Add checked symbol extraction and manifest integrity**

Create `scripts/extract-hot-symbols.py`. Its CLI is:

```text
scripts/extract-hot-symbols.py --binary ABS --arch aarch64|x86_64 \
  --symbol REGEX [--symbol REGEX ...] --output ABS.json
```

For each requested demangled regex it must run `nm -S -n --defined-only -C`,
require exactly one text symbol, validate nonzero size and in-file start/end,
then run `objdump -drwC` over that exact range. Its JSON records binary hash,
symbol name/start/end/size, `start % 4096`, declared alignment, raw-byte hash,
normalized-instruction hash, direct calls, frame adjustment, and detected
spills. Normalization removes instruction addresses and raw-byte columns;
replaces numeric PC/RIP-relative displacements and branch targets with
`<pc-rel>` while retaining relocation/demangled target names; preserves opcode,
registers, immediates, memory width, and non-PC-relative offsets. Unknown line
forms, overlapping ranges, zero/multiple symbols, or architecture mismatch are
fatal—never silently drop a line.

Create `tests/test_extract_hot_symbols.py` with fixed AArch64 and x86-64
`objdump` snippets proving address-only and relocation-only changes normalize
identically, while opcode/register/stack-offset changes hash differently; add
zero/multiple/unknown-line failure cases. Run `pytest -q
tests/test_extract_hot_symbols.py`; expected: all extractor tests PASS.

- [ ] **Step 8: Add pinned launcher and clean-commit manifests**

Create `scripts/cache-gate.sh` by factoring the same Linux core lock,
Criterion-root lock, `taskset`, `setarch -R`, `chrt -b`, and NUMA behavior used
by `scripts/bench.sh`. Supported run modes are exactly `CONTROL=1`, `ELASTIC=1`,
and `FUNNEL=1`; all honor `SAVE`, `LOAD`, and `BASELINE`. `CONTROL=1` requires
an already-built absolute `CACHE_GATE_CONTROL_BIN` for every evidence run and
performs no Cargo/build activity. A separate `BUILD_CONTROL=1` mode is allowed
only in immutable cache-off and writes its resolved path plus Cargo/lock hashes.

`MANIFEST=1` requires `CACHE_GATE_CONTROL_BIN`, a clean worktree, and a named
`CACHE_GATE_VARIANT`; it refuses dirty/untracked production or harness files.
It uses a fresh variant-specific `CARGO_TARGET_DIR`, `CARGO_INCREMENTAL=0`, and
linker `-Map` output; builds Elastic, Funnel, and profile executables once;
rejects zero/multiple Cargo JSON paths or artifacts older than HEAD; calls the
checked extractor for these exact kernel regexes:

```text
::elastic_cache_gate_insert_kernel$
::elastic_cache_gate_get_kernel$
::funnel_cache_gate_insert_kernel$
::funnel_cache_gate_get_kernel$
::elastic_profile_insert_kernel$
::elastic_profile_get_kernel$
::funnel_profile_insert_kernel$
::funnel_profile_get_kernel$
```

It writes `target/cache-gate/<arch>/<variant>/manifest.json` containing HEAD,
tree hash, empty-diff assertion, rustc/linker flags, absolute executables,
executable/link-map/control-manifest/control-lock hashes, and the extractor JSON.
No manifest may label a dirty tree with HEAD; dirty diagnostics use explicit
`tree=<git-write-tree>` plus diff hash and are excluded from acceptance.

Run:

```bash
pre-commit run --files Cargo.toml benches/elastic_cache_gate.rs benches/funnel_cache_gate.rs benches/cache_gate_profile.rs benches/harness/cache_gate.rs benches/harness/mod.rs tests/elastic_cache_gate_fixture.rs tests/test_extract_hot_symbols.py scripts/cache-gate.sh scripts/cache-gate-perf.sh scripts/extract-hot-symbols.py scripts/snapshot-criterion-pair.sh tools/cache-gate-control/Cargo.toml tools/cache-gate-control/Cargo.lock tools/cache-gate-control/src/main.rs
BUILD_CONTROL=1 scripts/cache-gate.sh
CACHE_GATE_CONTROL_BIN=$(sed -n '1p' target/cache-gate-control-bin.txt)
test -x "$CACHE_GATE_CONTROL_BIN"
CONTROL=1 SAVE=harness-self CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" scripts/cache-gate.sh
ELASTIC=1 SAVE=harness-self CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" scripts/cache-gate.sh
FUNNEL=1 SAVE=harness-self CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" scripts/cache-gate.sh
MANIFEST=1 CACHE_GATE_VARIANT=harness-self CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" scripts/cache-gate.sh
```

Expected: hooks and extractor tests PASS; three timing modes complete; manifest
resolves exactly eight named kernels and contains every required hash.

- [ ] **Step 9: Add atomic pair snapshot tooling**

Create `scripts/snapshot-criterion-pair.sh` with required arguments
`--runner-root`, `--criterion-root`, `--snapshot-root`, `--arch`, `--comparison`, `--pair`,
`--target`, `--anchor-run`, `--candidate-run`, `--anchor-commit`,
`--candidate-commit`, `--anchor-manifest`, and `--candidate-manifest`. It must:

1. refuse an existing destination and write through `mktemp -d`;
2. acquire the Criterion-root lock, require `--runner-root` to equal the
   candidate manifest's authenticated runner root, authenticate the absolute
   executor from that root, execute exactly one offline `LOAD=<candidate>
   BASELINE=<anchor>` comparison itself, and copy every target-matching
   `change/estimates.json` before releasing the lock;
3. copy both `<anchor-run>/estimates.json` and
   `<candidate-run>/estimates.json` as `absolute/anchor/...` and
   `absolute/candidate/...` preserving group/benchmark paths;
4. copy both build manifests/link maps and record run names, commits, target,
   host, executor absolute path/hash, exact argv, and
   `offline_execution_count: 1` in `pair-manifest.json`;
5. generate `SHA256SUMS`, verify it with `sha256sum -c`, fsync files, then
   atomically rename the temporary directory;
6. fail when any expected change/absolute JSON is missing, when manifests do
   not name the supplied commits, when a hash changes, or when a caller-side
   comparison would make execution non-unique.

All gates read only `target/cache-gate-evidence/<arch>/<comparison>/pair-N/`;
live Criterion `change/` files are never evidence after another comparison.

- [ ] **Step 10: Add no-build operation-specific profiling**

Declare `cache_gate_profile` (`harness = false`). It accepts exactly
`--operation elastic-insert|elastic-get|funnel-insert|funnel-get`,
`--iterations N`, `--ready-fd`, and `--go-fd`. It constructs and validates the
map/key fixture before writing `READY`, waits for `GO`, then calls one matching
`#[inline(never)]` fixed-iteration kernel and exits. Insert clears outside the
enabled kernel and profiles one exact preallocated fill per iteration; get
profiles an exact cycling hit count. The four kernel names are those required
by Step 8.

Create `scripts/cache-gate-perf.sh`. It accepts only an already-manifested
absolute `CACHE_GATE_PERF_BIN` plus required `--runner-root ABS`, applies the
same realpath/exact-worktree/root-containment checks as `cache-gate.sh`, and
requires the manifest's runner root/commit/tree to equal that root. It verifies
the binary SHA-256 against `manifest.json` and runs one operation per invocation.
Every CSV/command manifest is written below the supplied root and records its
resolved root, commit, tree, perf-launcher absolute path, Git blob, and SHA-256.
Use `perf stat -x,` with control/ack
FIFOs and initially-disabled counters: launch profile binary, wait `READY`,
start `perf stat -D -1 --control=fifo:<ctl>,<ack> -p <pid>`, enable, send `GO`,
wait for kernel completion, disable, and preserve one raw CSV plus command/PID/
iteration manifest. No Cargo, linker, Criterion, setup, or another operation is
inside enabled counters. Require identical iterations across trees and three
separate repetitions for every operation.

- [ ] **Step 11: Commit the harness-only cache-off anchor**

```bash
git add Cargo.toml benches/elastic_cache_gate.rs benches/funnel_cache_gate.rs benches/cache_gate_profile.rs benches/harness/cache_gate.rs benches/harness/mod.rs tests/elastic_cache_gate_fixture.rs tests/test_extract_hot_symbols.py scripts/cache-gate.sh scripts/cache-gate-perf.sh scripts/extract-hot-symbols.py scripts/snapshot-criterion-pair.sh tools/cache-gate-control
git commit -m "bench: isolate elastic signature cache gate"
cache_off_v1_commit=$(git rev-parse HEAD)
git diff --quiet "$cache_off_source_commit".."$cache_off_v1_commit" -- src
```

Expected: immutable diagnostic `cache-off-v1` commit differs from original only
in benchmark/harness files; production source is byte-identical. Task 2 must
replace its uncontrolled layout before acceptance.

### Task 2: Repair and Prove the Stable-Layout Harness Before Policy Replay

**Files:**
- Modify: `benches/elastic_cache_gate.rs`
- Modify: `benches/funnel_cache_gate.rs`
- Modify: `benches/cache_gate_profile.rs`
- Create: `benches/cache-gate-elastic-layout.ld`
- Create: `benches/cache-gate-funnel-layout.ld`
- Create: `benches/cache-gate-profile-layout.ld`
- Create: `tools/cache-gate-link-probe/Cargo.toml`
- Create: `tools/cache-gate-link-probe/Cargo.lock`
- Create: `tools/cache-gate-link-probe/src/main.rs`
- Modify: `scripts/cache-gate.sh`
- Create: `scripts/cache-gate-linker-capability.sh`
- Create: `scripts/cache-gate-elf-layout.py`
- Modify: `scripts/extract-hot-symbols.py`
- Modify: `scripts/snapshot-criterion-pair.sh`
- Create: `tests/test_cache_gate_elf_layout.py`
- Create: `tests/fixtures/cache_gate_layout_adversary.rs`
- Modify: `tests/test_extract_hot_symbols.py`
- Modify: `tests/test_snapshot_criterion_pair.py`

**Interfaces:**
- Consumes: source-original `47fc953`, rejected v1 harness `1080c18`, the
  actual Cargo-configured native linker, and the existing fixed-control,
  extractor, snapshot, and profile launchers.
- Produces: immutable `cache_off_current_v2_commit`; three script-hashed GNU
  ld/LLD augmentations with exact 2/2/4 executable shapes; exact ELF/link-map
  records for eight reserved kernels across three binaries;
  hash-authenticated no-build stable Criterion/profile execution; and native
  AArch64/x86-64 approval to replay policy.

- [ ] **Step 1: Pin amended docs, preserve diagnostics, and recover source-original production**

First make the three amended documents durable. The docs commit is a declared
edge, not incidental working-tree state. Then archive v1 diagnostics and create
a recoverable source revert that retains the amended docs:

```bash
test "$(git rev-parse 1080c18)" = 1080c188a47f02202b6a0878830dbf2947629992
test "$(git rev-parse b1cabb6)" = b1cabb653cebc5922e84a26cb24db8b58903245d
test "$(git rev-parse 5fb56a5)" = 5fb56a5e0e55cc093b5ac7035746178bcf023066
test "$(git rev-parse f4a0d35)" = f4a0d354239a8cf669bb240fcb17474693d7b56f
test "$(git rev-parse 47fc953)" = 47fc953b8b429cfdac29c13c313c28a21eb0ee4a
test "$(git rev-parse HEAD)" = f4a0d354239a8cf669bb240fcb17474693d7b56f
docs_remediation_files=(
  docs/superpowers/plans/2026-07-20-counter-prf-bakeoff.md
  docs/superpowers/plans/2026-07-21-elastic-candidate-signature-cache.md
  docs/superpowers/specs/2026-07-20-counter-prf-insert-design.md
)
docs_remediation_file_list=$(printf '%s\n' "${docs_remediation_files[@]}")
test "$(git diff --name-only)" = "$docs_remediation_file_list"
pre-commit run --files "${docs_remediation_files[@]}"
git add "${docs_remediation_files[@]}"
git commit -m "docs: repair signature cache layout plan"
docs_remediation_v2_commit=$(git rev-parse HEAD)
test "$(git rev-parse "$docs_remediation_v2_commit^")" = f4a0d354239a8cf669bb240fcb17474693d7b56f
test "$(git diff --name-only "$docs_remediation_v2_commit^" "$docs_remediation_v2_commit")" = "$docs_remediation_file_list"
docs_remediation_patch_sha=$(git diff --binary "$docs_remediation_v2_commit^" "$docs_remediation_v2_commit" -- "${docs_remediation_files[@]}" | sha256sum | cut -d' ' -f1)
test "${#docs_remediation_patch_sha}" -eq 64
for file in "${docs_remediation_files[@]}"; do
  git rev-parse "$docs_remediation_v2_commit:$file"
  git show "$docs_remediation_v2_commit:$file" | sha256sum
done
docs_bakeoff_blob=$(git rev-parse "$docs_remediation_v2_commit:docs/superpowers/plans/2026-07-20-counter-prf-bakeoff.md")
docs_signature_cache_blob=$(git rev-parse "$docs_remediation_v2_commit:docs/superpowers/plans/2026-07-21-elastic-candidate-signature-cache.md")
docs_counter_prf_spec_blob=$(git rev-parse "$docs_remediation_v2_commit:docs/superpowers/specs/2026-07-20-counter-prf-insert-design.md")
docs_bakeoff_sha=$(git show "$docs_remediation_v2_commit:docs/superpowers/plans/2026-07-20-counter-prf-bakeoff.md" | sha256sum | cut -d' ' -f1)
docs_signature_cache_sha=$(git show "$docs_remediation_v2_commit:docs/superpowers/plans/2026-07-21-elastic-candidate-signature-cache.md" | sha256sum | cut -d' ' -f1)
docs_counter_prf_spec_sha=$(git show "$docs_remediation_v2_commit:docs/superpowers/specs/2026-07-20-counter-prf-insert-design.md" | sha256sum | cut -d' ' -f1)
mkdir -p target/cache-gate-rejected/task-2-layout-v1
find target/cache-gate -type f \( -name manifest.json -o -name '*.map' -o -name '*.cargo.json' \) -print0 \
  | sort -z | xargs -0 -r sha256sum > target/cache-gate-rejected/task-2-layout-v1/SHA256SUMS
policy_revert_v2_tree=/home/aang/projects/opthash/.worktrees/audit/cache-policy-revert-v2
git worktree add "$policy_revert_v2_tree" -b audit/cache-policy-revert-v2 "$docs_remediation_v2_commit"
git -C "$policy_revert_v2_tree" revert --no-edit f4a0d354239a8cf669bb240fcb17474693d7b56f
layout_repair_policy_revert_commit=$(git -C "$policy_revert_v2_tree" rev-parse HEAD)
test "$(git -C "$policy_revert_v2_tree" rev-parse HEAD^)" = "$docs_remediation_v2_commit"
test -z "$(git -C "$policy_revert_v2_tree" status --porcelain)"
git diff --quiet 47fc953b8b429cfdac29c13c313c28a21eb0ee4a "$layout_repair_policy_revert_commit" -- src
git diff --quiet 5fb56a5e0e55cc093b5ac7035746178bcf023066 "$layout_repair_policy_revert_commit" -- src
```

Expected: the unique docs commit has exact parent `f4a0d35`, exactly three
files, one recorded patch hash, and three recorded Git blob/content hashes. The
revert's exact parent is that docs commit; it removes only the current policy
source diff, keeps all three blobs exact, and makes `src/` source-original. Old
commits/manifests remain immutable diagnostics. Do not delete them or run timing.

- [ ] **Step 2: Create the repair branch from source-original and replay only the harness**

Use `superpowers:using-git-worktrees`. Create the branch/worktree from the exact
source commit, then replay v1 harness files without either policy commit:

```bash
layout_v2_tree=/home/aang/projects/opthash/.worktrees/bench/cache-gate-layout-v2
test "$(git rev-parse 1080c188a47f02202b6a0878830dbf2947629992^)" = 47fc953b8b429cfdac29c13c313c28a21eb0ee4a
test "$(git rev-parse b1cabb653cebc5922e84a26cb24db8b58903245d^)" = 1080c188a47f02202b6a0878830dbf2947629992
test "$(git rev-parse 5fb56a5e0e55cc093b5ac7035746178bcf023066^)" = b1cabb653cebc5922e84a26cb24db8b58903245d
test "$(git rev-parse f4a0d354239a8cf669bb240fcb17474693d7b56f^)" = 5fb56a5e0e55cc093b5ac7035746178bcf023066
git worktree add "$layout_v2_tree" -b bench/cache-gate-layout-v2 47fc953b8b429cfdac29c13c313c28a21eb0ee4a
git -C "$layout_v2_tree" cherry-pick 1080c188a47f02202b6a0878830dbf2947629992
replayed_harness_v1_commit=$(git -C "$layout_v2_tree" rev-parse HEAD)
test "$(git -C "$layout_v2_tree" rev-parse HEAD^)" = 47fc953b8b429cfdac29c13c313c28a21eb0ee4a
harness_v1_files=(
  Cargo.toml
  benches/cache_gate_profile.rs
  benches/elastic_cache_gate.rs
  benches/funnel_cache_gate.rs
  benches/harness/cache_gate.rs
  benches/harness/mod.rs
  docs/superpowers/plans/2026-07-20-counter-prf-bakeoff.md
  docs/superpowers/plans/2026-07-21-elastic-candidate-signature-cache.md
  scripts/cache-gate-perf-support.py
  scripts/cache-gate-perf.sh
  scripts/cache-gate.sh
  scripts/extract-hot-symbols.py
  scripts/snapshot-criterion-pair.sh
  tests/elastic_cache_gate_fixture.rs
  tests/test_cache_gate_perf_support.py
  tests/test_extract_hot_symbols.py
  tests/test_snapshot_criterion_pair.py
  tools/cache-gate-control/.gitignore
  tools/cache-gate-control/Cargo.lock
  tools/cache-gate-control/Cargo.toml
  tools/cache-gate-control/src/main.rs
)
test "$(git -C "$layout_v2_tree" diff --name-only HEAD^ HEAD)" = "$(printf '%s\n' "${harness_v1_files[@]}")"
test "$(git -C "$layout_v2_tree" diff --binary HEAD^ HEAD | sha256sum | cut -d' ' -f1)" = 2e82ea3092bc1585c0845620b3748fb15fa12d97d53b9e14f71f0bf1e95231d1
git -C "$layout_v2_tree" diff --quiet 47fc953b8b429cfdac29c13c313c28a21eb0ee4a "$replayed_harness_v1_commit" -- src
git -C "$layout_v2_tree" cherry-pick "$docs_remediation_v2_commit"
replayed_docs_v2_commit=$(git -C "$layout_v2_tree" rev-parse HEAD)
test "$(git -C "$layout_v2_tree" rev-parse HEAD^)" = "$replayed_harness_v1_commit"
test "$(git -C "$layout_v2_tree" diff --name-only HEAD^ HEAD)" = "$docs_remediation_file_list"
test "$(git -C "$layout_v2_tree" diff --binary HEAD^ HEAD | sha256sum | cut -d' ' -f1)" = "$docs_remediation_patch_sha"
test "$(git -C "$layout_v2_tree" rev-parse HEAD:docs/superpowers/plans/2026-07-20-counter-prf-bakeoff.md)" = "$docs_bakeoff_blob"
test "$(git -C "$layout_v2_tree" rev-parse HEAD:docs/superpowers/plans/2026-07-21-elastic-candidate-signature-cache.md)" = "$docs_signature_cache_blob"
test "$(git -C "$layout_v2_tree" rev-parse HEAD:docs/superpowers/specs/2026-07-20-counter-prf-insert-design.md)" = "$docs_counter_prf_spec_blob"
test "$(git -C "$layout_v2_tree" show HEAD:docs/superpowers/plans/2026-07-20-counter-prf-bakeoff.md | sha256sum | cut -d' ' -f1)" = "$docs_bakeoff_sha"
test "$(git -C "$layout_v2_tree" show HEAD:docs/superpowers/plans/2026-07-21-elastic-candidate-signature-cache.md | sha256sum | cut -d' ' -f1)" = "$docs_signature_cache_sha"
test "$(git -C "$layout_v2_tree" show HEAD:docs/superpowers/specs/2026-07-20-counter-prf-insert-design.md | sha256sum | cut -d' ' -f1)" = "$docs_counter_prf_spec_sha"
! git -C "$layout_v2_tree" merge-base --is-ancestor b1cabb653cebc5922e84a26cb24db8b58903245d HEAD
! git -C "$layout_v2_tree" merge-base --is-ancestor f4a0d354239a8cf669bb240fcb17474693d7b56f HEAD
```

Expected: clean harness-plus-exact-docs worktree; no policy source. Both replay
edges have the asserted exact parent, literal file list, and patch SHA-256; the
three replayed documentation blobs equal the remediation source blobs. Any
cherry-pick conflict is a hard failure because it changes an authenticated
edge. Run Steps 3–10 with
`$layout_v2_tree` as the working directory; no repair file is edited in a
policy or audit worktree.

- [ ] **Step 3: Write failing ELF-layout, capability, and no-build tests**

Create `tests/test_cache_gate_elf_layout.py` first. Its fixture table must cover
all eight literal kernel/input/output/sentinel tuples:

```python
KERNELS = {
    "elastic_cache_gate_insert_kernel": {
        "target": "elastic", "input": ".text.opthash.cache_gate.elastic.insert", "output": ".opthash.cache_gate.elastic.insert",
        "reservation_start": "__opthash_cache_gate_elastic_insert_reservation_start", "body_end": "__opthash_cache_gate_elastic_insert_body_end", "reservation_end": "__opthash_cache_gate_elastic_insert_reservation_end",
    },
    "elastic_cache_gate_get_kernel": {
        "target": "elastic", "input": ".text.opthash.cache_gate.elastic.get", "output": ".opthash.cache_gate.elastic.get",
        "reservation_start": "__opthash_cache_gate_elastic_get_reservation_start", "body_end": "__opthash_cache_gate_elastic_get_body_end", "reservation_end": "__opthash_cache_gate_elastic_get_reservation_end",
    },
    "funnel_cache_gate_insert_kernel": {
        "target": "funnel", "input": ".text.opthash.cache_gate.funnel.insert", "output": ".opthash.cache_gate.funnel.insert",
        "reservation_start": "__opthash_cache_gate_funnel_insert_reservation_start", "body_end": "__opthash_cache_gate_funnel_insert_body_end", "reservation_end": "__opthash_cache_gate_funnel_insert_reservation_end",
    },
    "funnel_cache_gate_get_kernel": {
        "target": "funnel", "input": ".text.opthash.cache_gate.funnel.get", "output": ".opthash.cache_gate.funnel.get",
        "reservation_start": "__opthash_cache_gate_funnel_get_reservation_start", "body_end": "__opthash_cache_gate_funnel_get_body_end", "reservation_end": "__opthash_cache_gate_funnel_get_reservation_end",
    },
    "elastic_profile_insert_kernel": {
        "target": "profile", "input": ".text.opthash.cache_gate.profile.elastic.insert", "output": ".opthash.cache_gate.profile.elastic.insert",
        "reservation_start": "__opthash_cache_gate_profile_elastic_insert_reservation_start", "body_end": "__opthash_cache_gate_profile_elastic_insert_body_end", "reservation_end": "__opthash_cache_gate_profile_elastic_insert_reservation_end",
    },
    "elastic_profile_get_kernel": {
        "target": "profile", "input": ".text.opthash.cache_gate.profile.elastic.get", "output": ".opthash.cache_gate.profile.elastic.get",
        "reservation_start": "__opthash_cache_gate_profile_elastic_get_reservation_start", "body_end": "__opthash_cache_gate_profile_elastic_get_body_end", "reservation_end": "__opthash_cache_gate_profile_elastic_get_reservation_end",
    },
    "funnel_profile_insert_kernel": {
        "target": "profile", "input": ".text.opthash.cache_gate.profile.funnel.insert", "output": ".opthash.cache_gate.profile.funnel.insert",
        "reservation_start": "__opthash_cache_gate_profile_funnel_insert_reservation_start", "body_end": "__opthash_cache_gate_profile_funnel_insert_body_end", "reservation_end": "__opthash_cache_gate_profile_funnel_insert_reservation_end",
    },
    "funnel_profile_get_kernel": {
        "target": "profile", "input": ".text.opthash.cache_gate.profile.funnel.get", "output": ".opthash.cache_gate.profile.funnel.get",
        "reservation_start": "__opthash_cache_gate_profile_funnel_get_reservation_start", "body_end": "__opthash_cache_gate_profile_funnel_get_body_end", "reservation_end": "__opthash_cache_gate_profile_funnel_get_reservation_end",
    },
}

TARGET_KERNELS = {
    "elastic": tuple(name for name, spec in KERNELS.items() if spec["target"] == "elastic"),
    "funnel": tuple(name for name, spec in KERNELS.items() if spec["target"] == "funnel"),
    "profile": tuple(name for name, spec in KERNELS.items() if spec["target"] == "profile"),
}
assert tuple(map(len, TARGET_KERNELS.values())) == (2, 2, 4)
```

Add named tests for: missing/duplicate input section, wrong output section,
missing/duplicate/non-global reservation-start, body-end, or reservation-end
sentinel, reservation overflow, wrong
`ALLOC|EXECINSTR` flags, kernel split across `PT_LOAD`s, non-RX or RWX segment,
overlap, non-PIE `ET_EXEC`, reservation start not aligned to the capability record's
`MAXPAGESIZE`, actual `sh_addralign` mismatch, target-fragment/set hash mismatch,
binary hash mismatch, link-map sentinel mismatch, and a `veneer|thunk` in a
reserved region or a kernel call targeting `.plt`. Add a comparison test where
only trailing-zero-derived
alignment appears equal but ELF `sh_addralign` differs; it must fail.
Add exact-shape fixtures proving each executable contains only its 2, 2, or 4
declared reservations; an empty cross-target reservation or absent expected
reservation must fail.

Extend `tests/test_snapshot_criterion_pair.py` so stable comparison fixtures
contain absolute manifested binaries. Assert stable offline comparison invokes
that exact path, refuses a hash mismatch, and never invokes `cargo`. Add a
launcher test proving `ELASTIC=1` and `FUNNEL=1` reject missing
`CACHE_GATE_MANIFEST`. Add subprocess fixtures for `cache-gate.sh` and
`cache-gate-perf.sh`: each rejects an omitted/non-absolute/non-worktree
`--runner-root`; accepts an absolute fixture root; resolves symlinks; records
the root's commit/tree; and writes only below that root's `target/`. The
snapshot fixture must assert its nested launcher argv contains the same
authenticated `--runner-root`, and must reject a root that differs from the
candidate manifest's recorded root.

Run RED:

```bash
if pytest -q tests/test_cache_gate_elf_layout.py tests/test_extract_hot_symbols.py tests/test_snapshot_criterion_pair.py > target/cache-gate-layout-red.txt 2>&1; then
    echo "error: ELF layout red unexpectedly passed" >&2
    exit 1
fi
rg -n "cache-gate-elf-layout|output_section|reservation_start|body_end|reservation_end|PT_LOAD|CACHE_GATE_MANIFEST|cargo" target/cache-gate-layout-red.txt
```

Expected: nonzero status naming missing parser/fields/no-build behavior; zero
discovered tests is failure.

- [ ] **Step 4: Put every kernel in one constant Linux-ELF input section**

Keep every kernel `#[inline(never)]`. Add one target-gated unsafe attribute and
an adjacent safety comment to each existing function. For example:

```rust
// SAFETY: Linux cache-gate links this function through the checked RX-only
// target-specific augmentation and validates the final ELF.
#[cfg_attr(target_os = "linux", unsafe(link_section = ".text.opthash.cache_gate.elastic.insert"))]
#[inline(never)]
fn elastic_cache_gate_insert_kernel(/* unchanged arguments */) -> Duration {
    // unchanged body
}
```

Use exactly the eight input-section names in Step 3. Apply the same form to
Elastic stable get, Funnel stable insert/get, and all four profile kernels.
Names are constant and independent of Rust symbol hashes, crate paths, CGUs,
and object filenames. Do not change signatures/bodies, add `no_mangle`, add
`export_name`, or expose a new Rust ABI. Exported stability comes from the
linker-defined sentinel symbols in Step 5.

Add `tests/fixtures/cache_gate_layout_adversary.rs` as a private generic
emission included only under `--cfg cache_gate_layout_adversary`. Call a
cfg-gated `#[inline(never)]` monomorphization once during untimed benchmark
registration/setup, consume its result with `black_box`, and give it a unique
ordinary-text symbol/section identity. This makes the perturbation linked and
observable while keeping it outside every reserved section and timed kernel.
The launcher accepts `CACHE_GATE_LAYOUT_ADVERSARY=1` only
for manifest proof builds and appends both
`--cfg cache_gate_layout_adversary` and
`--check-cfg=cfg(cache_gate_layout_adversary)`. It records the complete rustc
argv including `-C codegen-units`, every emitted object/archive member, the
ordered linker-input list, each object's CGU membership, and the input owner of
each reserved section. Clean-a and clean-b must have identical
`cgu_partition_fingerprint`, object/member, and link-order fingerprints. The
adversary must have different predeclared CGU-partition and link-order
fingerprints, and the named adversary
symbol/section must occur exactly once outside every reservation; equality or
absence is a vacuous proof and fails before layout comparison.

- [ ] **Step 5: Add three target-specific page-reservation fragments**

Create three augmenting fragments. Each link sees only reservations backed by
that executable: Elastic 2, Funnel 2, profile 4. None uses an absolute address
or replacement `SECTIONS` layout.

`benches/cache-gate-elastic-layout.ld`:

```ld
SECTIONS
{
  .opthash.cache_gate.elastic.insert ALIGN(CONSTANT(MAXPAGESIZE)) :
  { __opthash_cache_gate_elastic_insert_reservation_start = .; KEEP(*(.text.opthash.cache_gate.elastic.insert)) __opthash_cache_gate_elastic_insert_body_end = .; ASSERT((__opthash_cache_gate_elastic_insert_body_end - __opthash_cache_gate_elastic_insert_reservation_start) <= CONSTANT(MAXPAGESIZE), "elastic insert cache-gate reservation overflow"); . = __opthash_cache_gate_elastic_insert_reservation_start + CONSTANT(MAXPAGESIZE); __opthash_cache_gate_elastic_insert_reservation_end = .; }
  .opthash.cache_gate.elastic.get ALIGN(CONSTANT(MAXPAGESIZE)) :
  { __opthash_cache_gate_elastic_get_reservation_start = .; KEEP(*(.text.opthash.cache_gate.elastic.get)) __opthash_cache_gate_elastic_get_body_end = .; ASSERT((__opthash_cache_gate_elastic_get_body_end - __opthash_cache_gate_elastic_get_reservation_start) <= CONSTANT(MAXPAGESIZE), "elastic get cache-gate reservation overflow"); . = __opthash_cache_gate_elastic_get_reservation_start + CONSTANT(MAXPAGESIZE); __opthash_cache_gate_elastic_get_reservation_end = .; }
}
INSERT BEFORE .text;
```

`benches/cache-gate-funnel-layout.ld`:

```ld
SECTIONS
{
  .opthash.cache_gate.funnel.insert ALIGN(CONSTANT(MAXPAGESIZE)) :
  { __opthash_cache_gate_funnel_insert_reservation_start = .; KEEP(*(.text.opthash.cache_gate.funnel.insert)) __opthash_cache_gate_funnel_insert_body_end = .; ASSERT((__opthash_cache_gate_funnel_insert_body_end - __opthash_cache_gate_funnel_insert_reservation_start) <= CONSTANT(MAXPAGESIZE), "funnel insert cache-gate reservation overflow"); . = __opthash_cache_gate_funnel_insert_reservation_start + CONSTANT(MAXPAGESIZE); __opthash_cache_gate_funnel_insert_reservation_end = .; }
  .opthash.cache_gate.funnel.get ALIGN(CONSTANT(MAXPAGESIZE)) :
  { __opthash_cache_gate_funnel_get_reservation_start = .; KEEP(*(.text.opthash.cache_gate.funnel.get)) __opthash_cache_gate_funnel_get_body_end = .; ASSERT((__opthash_cache_gate_funnel_get_body_end - __opthash_cache_gate_funnel_get_reservation_start) <= CONSTANT(MAXPAGESIZE), "funnel get cache-gate reservation overflow"); . = __opthash_cache_gate_funnel_get_reservation_start + CONSTANT(MAXPAGESIZE); __opthash_cache_gate_funnel_get_reservation_end = .; }
}
INSERT BEFORE .text;
```

`benches/cache-gate-profile-layout.ld`:

```ld
SECTIONS
{
  .opthash.cache_gate.profile.elastic.insert ALIGN(CONSTANT(MAXPAGESIZE)) :
  { __opthash_cache_gate_profile_elastic_insert_reservation_start = .; KEEP(*(.text.opthash.cache_gate.profile.elastic.insert)) __opthash_cache_gate_profile_elastic_insert_body_end = .; ASSERT((__opthash_cache_gate_profile_elastic_insert_body_end - __opthash_cache_gate_profile_elastic_insert_reservation_start) <= CONSTANT(MAXPAGESIZE), "profile elastic insert reservation overflow"); . = __opthash_cache_gate_profile_elastic_insert_reservation_start + CONSTANT(MAXPAGESIZE); __opthash_cache_gate_profile_elastic_insert_reservation_end = .; }
  .opthash.cache_gate.profile.elastic.get ALIGN(CONSTANT(MAXPAGESIZE)) :
  { __opthash_cache_gate_profile_elastic_get_reservation_start = .; KEEP(*(.text.opthash.cache_gate.profile.elastic.get)) __opthash_cache_gate_profile_elastic_get_body_end = .; ASSERT((__opthash_cache_gate_profile_elastic_get_body_end - __opthash_cache_gate_profile_elastic_get_reservation_start) <= CONSTANT(MAXPAGESIZE), "profile elastic get reservation overflow"); . = __opthash_cache_gate_profile_elastic_get_reservation_start + CONSTANT(MAXPAGESIZE); __opthash_cache_gate_profile_elastic_get_reservation_end = .; }
  .opthash.cache_gate.profile.funnel.insert ALIGN(CONSTANT(MAXPAGESIZE)) :
  { __opthash_cache_gate_profile_funnel_insert_reservation_start = .; KEEP(*(.text.opthash.cache_gate.profile.funnel.insert)) __opthash_cache_gate_profile_funnel_insert_body_end = .; ASSERT((__opthash_cache_gate_profile_funnel_insert_body_end - __opthash_cache_gate_profile_funnel_insert_reservation_start) <= CONSTANT(MAXPAGESIZE), "profile funnel insert reservation overflow"); . = __opthash_cache_gate_profile_funnel_insert_reservation_start + CONSTANT(MAXPAGESIZE); __opthash_cache_gate_profile_funnel_insert_reservation_end = .; }
  .opthash.cache_gate.profile.funnel.get ALIGN(CONSTANT(MAXPAGESIZE)) :
  { __opthash_cache_gate_profile_funnel_get_reservation_start = .; KEEP(*(.text.opthash.cache_gate.profile.funnel.get)) __opthash_cache_gate_profile_funnel_get_body_end = .; ASSERT((__opthash_cache_gate_profile_funnel_get_body_end - __opthash_cache_gate_profile_funnel_get_reservation_start) <= CONSTANT(MAXPAGESIZE), "profile funnel get reservation overflow"); . = __opthash_cache_gate_profile_funnel_get_reservation_start + CONSTANT(MAXPAGESIZE); __opthash_cache_gate_profile_funnel_get_reservation_end = .; }
}
INSERT BEFORE .text;
```

`CONSTANT(MAXPAGESIZE)` is linker/target derived; it is not a hard-coded VMA.
Each output section begins on its own maximum-page boundary and occupies one
fixed reservation. `reservation_start` is the aligned address, `body_end` is
immediately after `KEEP`, and `reservation_end` is exactly
`reservation_start + CONSTANT(MAXPAGESIZE)` after padding. Thus a body-size
change cannot move the next kernel. `KEEP` makes
placement survive `--gc-sections`. Do not use `--section-start`, a copied full
default script, post-link VMA mutation, or absolute padding addresses.

- [ ] **Step 6: Probe the actual linker and fail closed**

Create the dependency-free `tools/cache-gate-link-probe` package with three
explicit binaries: `elastic` has exactly the two Elastic input sections,
`funnel` exactly the two Funnel sections, and `profile` exactly the four
profile sections. Each has one ordinary `.text` caller, and each is linked with
only its matching fragment. `scripts/cache-gate-linker-capability.sh` must:

1. require native Linux `aarch64|x86_64` and an ELF target;
2. run `cargo rustc --release --locked --manifest-path
   tools/cache-gate-link-probe/Cargo.toml --bin elastic|funnel|profile --
   --print link-args` separately with the exact matching augmentation and map
   flags used by the corresponding real executable, thereby exercising
   Cargo's configured linker rather than a guessed `ld`;
3. parse the emitted absolute linker command, resolve the linker path, and
   accept only GNU ld or LLD with documented `INSERT BEFORE`/`KEEP` support;
4. resolve explicit native GNU `ld.bfd` and `ld.lld`, then execute all three
   2/2/4 probe shapes with each; absence or failure of either flavor is `HOLD`,
   never a skipped compatibility test;
5. record each absolute linker path, flavor, `--version`, target triple, page
   constants, rustc/Cargo versions, three full link argvs, and all three
   linker-fragment SHA-256 values plus a canonical set hash;
6. call `cache-gate-elf-layout.py validate` on all three probe ELF/map pairs
   for the actual Cargo linker and for every installed claimed GNU ld/LLD
   flavor, rejecting extra or missing reservations;
7. atomically write `target/cache-gate-linker/<arch>/capability.json`.

Unsupported linker flavor, missing `--print link-args`, non-ELF output, or any
structural validation failure exits with a distinct `HOLD:` diagnostic and
status 3. `scripts/cache-gate.sh MANIFEST=1` requires this accepted capability
record, verifies its target-fragment/set hashes and linker identity against the actual build, and
never falls back to orphan placement.

- [ ] **Step 7: Make ELF and manifest validation structural**

Implement `scripts/cache-gate-elf-layout.py` with:

```text
validate --binary ABS --link-map ABS --script ABS --symbols ABS.json --arch aarch64|x86_64 --output ABS.json
compare --anchor ABS/manifest.json --candidate ABS/manifest.json [--allow-body-change KERNEL]...
```

For each target, `validate` first requires its exact 2/2/4 kernel set and no
cross-target output reservation. For each kernel it requires exactly one
function symbol and one named input section in the exact output section; parses
`reservation_start`, `body_end`, `reservation_end`, body and reservation sizes,
`reservation_start % capability.MAXPAGESIZE`, `reservation_start % 4096`, ELF
`sh_addralign`, all three sentinel names/addresses, raw and normalized hashes,
calls, frame, and spills. All three sentinels must be unique defined `GLOBAL
DEFAULT` symbols; `body_end` must immediately follow the kept input body;
`reservation_end - reservation_start` must equal the capability-derived
maximum page; and the maximum-page remainder must be zero. It rejects
any veneer/thunk in a reserved region or call graph and any kernel call through
PLT. Unrelated process-runtime PLT entries are inventoried but do not fail the
gate. `readelf -hSWlWs` and the link map must agree. Every reserved section must be `ALLOC|EXECINSTR`, lie
wholly in one RX `PT_LOAD`, avoid every writable segment, and not overlap
another section. The binary must be PIE `ET_DYN`; no program header may be RWX.

`compare` always requires the same linker flavor/version, three-script set
hash, target-specific output/input section, `reservation_start`,
`reservation_end`, page offsets, actual alignment, reservation size,
capability-derived maximum-page size/remainder, and reservation-start/end
sentinel names and addresses for all eight kernels. It parses and validates
`body_end`, body size, raw/normalized hashes, calls, frame, and spills for every
kernel. By default those body fields must also be exact.
Repeatable `--allow-body-change KERNEL` is accepted only for a literal Step-3
kernel name; it relaxes equality only for that kernel's `body_end`, body size,
raw/normalized hashes, calls, frame, and spills. It never relaxes
`reservation_start`, `reservation_end`, reservation size, section placement,
or reservation sentinel identity/address. The caller must declare the complete expected
potentially changed-kernel set before measurement; missing body fields or a
body change outside that set is fatal. Do not compute a field called
`declared_alignment` from address trailing zeros.

Extend `scripts/extract-hot-symbols.py` to include section index/name and
linker-generated veneer/thunk inventory. Extend `MANIFEST=1` to pass
`-Wl,-T,<absolute target-specific-fragment>` plus the existing map flag, copy
capability, the applicable fragment, and layout JSON into the manifest
directory, and record all three fragment hashes/set hash plus the used
fragment under `linker_capability` and `elf_layout`. Record the manifest-local
capability copy as `.linker_capability.copy.absolute_path` and
`.linker_capability.copy.sha256`; later phases read that exact authenticated
copy rather than reconstructing a variant directory.

- [ ] **Step 8: Authenticate stable timing to the manifested executable**

Change the launcher interface for every mode and the execution path for stable
modes in `scripts/cache-gate.sh`:

```bash
CACHE_GATE_MANIFEST=/absolute/manifest.json ELASTIC=1 SAVE=name \
  scripts/cache-gate.sh --runner-root /absolute/worktree
CACHE_GATE_MANIFEST=/absolute/manifest.json FUNNEL=1 SAVE=name \
  scripts/cache-gate.sh --runner-root /absolute/worktree
```

Every launcher mode, including `BUILD_CONTROL=1`, `MANIFEST=1`, `CONTROL=1`,
`ELASTIC=1`, and `FUNNEL=1`, requires `--runner-root ABS`. Resolve it once with
`realpath -e`, require it to be the exact Git worktree top level, and use it as
`REPO_ROOT`; caller cwd and the launcher's own `BASH_SOURCE` directory never
select the subject tree. Record resolved runner root, HEAD, tree, and mode in
every build/run manifest. All target/build/map/run outputs are rooted below
`$runner_root/target`; reject a manifest, target directory, or output path
outside that root. The sole exception is an explicitly absolute shared
`OPTHASH_CRITERION_ROOT` used by an A/B pair; its run manifest must bind both
that evidence root and the authenticated subject runner root, and it may not
contain build, map, or executable artifacts. For immutable modes, authenticate the root HEAD/tree against
the supplied manifest before work.

Both modes require an absolute accepted manifest, verify commit/tree,
capability/script/layout hashes, select the exact absolute Elastic or Funnel
executable, verify its SHA-256 again immediately before `exec`, and run it
directly with `--bench` plus Criterion arguments under the unchanged pin/ASLR/
scheduler/NUMA wrappers. They must contain no `cargo`, compiler, or linker
command. Record the executable path/hash in run metadata.

For proof builds, `MANIFEST=1` accepts a required-by-the-caller unique
`CACHE_GATE_MANIFEST_INSTANCE`, maps it to
`target/cache-gate-build/<instance>`, and rejects an existing instance root.
It sets `CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16`, rejects conflicting Cargo or
rustc codegen-unit configuration, and requires the captured rustc argv for all
three executables to contain `-C codegen-units=16`.
Task 2 Step 9 always supplies it, making clean-a/clean-b/adversary links
genuinely independent; ordinary named variant manifests retain their existing
fresh-build behavior.

Make `scripts/snapshot-criterion-pair.sh` the sole offline-comparison executor,
not a copier invoked after a separate comparison. Add required `--runner-root
ABS`. While holding the Criterion-root lock, it verifies both manifests and the
absolute authenticated snapshot-helper/launcher/ELF-validator paths and hashes,
runs exactly one `LOAD=<candidate> BASELINE=<anchor>` comparison, snapshots the
result before releasing the lock, and records `offline_execution_count: 1`,
executor path/hash, and exact argv. For stable targets it must select the
candidate manifest's exact hash-verified binary for the offline
`--load-baseline/--baseline` pass; using the anchor binary is fatal. It never
invokes Cargo for `elastic_cache_gate` or `funnel_cache_gate`. For control it
uses the fixed-control candidate manifest binary. Full `speedup`, latency, and
scaled targets execute the canonical runner under `--runner-root` once inside
the helper. Every nested `cache-gate.sh` invocation explicitly receives the
same resolved `--runner-root`; the pair manifest records and authenticates it.
Resolve a relative `--snapshot-root` beneath that runner root and reject any
absolute or normalized snapshot destination outside `$runner_root/target`.
Callers run only the two `SAVE` measurements and then invoke this
helper; a caller-side offline comparison or duplicate execution is fatal.

The cache-off manifest records the Git blob ID and SHA-256 of
`scripts/cache-gate-elf-layout.py`, `scripts/snapshot-criterion-pair.sh`, and
`scripts/cache-gate.sh`, and `scripts/cache-gate-perf.sh`. Every later evidence command binds each to an absolute
path under the reviewed immutable cache-off tree, verifies its hash against the
manifest immediately before execution, and calls that path. `PATH` lookup or a
same-named script from a candidate tree is forbidden.

- [ ] **Step 9: Pass tests, commit cache-off-v2, and prove it twice on both native hosts**

Run before committing:

```bash
pytest -q tests/test_cache_gate_elf_layout.py tests/test_extract_hot_symbols.py tests/test_snapshot_criterion_pair.py
cargo test --test elastic_cache_gate_fixture cache_gate::tests
cargo fmt --all -- --check
pre-commit run --files Cargo.toml benches/elastic_cache_gate.rs benches/funnel_cache_gate.rs benches/cache_gate_profile.rs benches/cache-gate-elastic-layout.ld benches/cache-gate-funnel-layout.ld benches/cache-gate-profile-layout.ld scripts/cache-gate.sh scripts/cache-gate-linker-capability.sh scripts/cache-gate-elf-layout.py scripts/extract-hot-symbols.py scripts/snapshot-criterion-pair.sh tests/test_cache_gate_elf_layout.py tests/fixtures/cache_gate_layout_adversary.rs tests/test_extract_hot_symbols.py tests/test_snapshot_criterion_pair.py tools/cache-gate-link-probe/Cargo.toml tools/cache-gate-link-probe/Cargo.lock tools/cache-gate-link-probe/src/main.rs
git diff --check
git diff --quiet 47fc953b8b429cfdac29c13c313c28a21eb0ee4a -- src
git add Cargo.toml benches scripts tests tools/cache-gate-link-probe
git commit -m "bench: stabilize cache gate ELF layout"
cache_off_current_v2_commit=$(git rev-parse HEAD)
test "$(git rev-parse "$cache_off_current_v2_commit^")" = "$replayed_docs_v2_commit"
test -z "$(git status --porcelain)"
git diff --quiet 47fc953b8b429cfdac29c13c313c28a21eb0ee4a "$cache_off_current_v2_commit" -- src
test "$(git rev-parse "$cache_off_current_v2_commit:docs/superpowers/plans/2026-07-20-counter-prf-bakeoff.md")" = "$docs_bakeoff_blob"
test "$(git rev-parse "$cache_off_current_v2_commit:docs/superpowers/plans/2026-07-21-elastic-candidate-signature-cache.md")" = "$docs_signature_cache_blob"
test "$(git rev-parse "$cache_off_current_v2_commit:docs/superpowers/specs/2026-07-20-counter-prf-insert-design.md")" = "$docs_counter_prf_spec_blob"
```

On each native AArch64 and x86-64 host, run the linker capability probe and
build the same immutable commit twice in fresh roots plus one adversarial
manifest. `CACHE_GATE_MANIFEST_INSTANCE` maps to a dedicated Cargo target root
under `target/cache-gate-build/<instance>`; manifest mode rejects a pre-existing
instance root. Require an operator-supplied positive `CACHE_GATE_ATTEMPT` and
derive every proof instance/variant from architecture, immutable commit, and
attempt. Preserve every failed attempt root; a repair commit or rerun uses a new
commit/attempt ID and never overwrites it:

```bash
cache_arch=$(uname -m)
test "${CACHE_GATE_ATTEMPT:?set positive repair/proof attempt}" -gt 0
cache_off_attempt_id="$cache_arch-${cache_off_current_v2_commit:0:12}-attempt-$CACHE_GATE_ATTEMPT"
cache_off_clean_a="$cache_off_attempt_id-clean-a"
cache_off_clean_b="$cache_off_attempt_id-clean-b"
cache_off_adversary="$cache_off_attempt_id-adversary"
scripts/cache-gate-linker-capability.sh
CACHE_GATE_LAUNCHER="$layout_v2_tree/scripts/cache-gate.sh"
BUILD_CONTROL=1 "$CACHE_GATE_LAUNCHER" --runner-root "$layout_v2_tree"
CACHE_GATE_CONTROL_BIN=$(sed -n '1p' "$layout_v2_tree/target/cache-gate-control-bin.txt")
CACHE_GATE_LINKER_CAPABILITY="$layout_v2_tree/target/cache-gate-linker/$cache_arch/capability.json"
CACHE_GATE_ELF_LAYOUT_TOOL="$layout_v2_tree/scripts/cache-gate-elf-layout.py"
CACHE_GATE_SNAPSHOT_TOOL="$layout_v2_tree/scripts/snapshot-criterion-pair.sh"
test "${CACHE_GATE_ELF_LAYOUT_TOOL#/}" != "$CACHE_GATE_ELF_LAYOUT_TOOL"
test "${CACHE_GATE_SNAPSHOT_TOOL#/}" != "$CACHE_GATE_SNAPSHOT_TOOL"
CACHE_GATE_MANIFEST_INSTANCE="$cache_off_clean_a" CACHE_GATE_LINKER_CAPABILITY="$CACHE_GATE_LINKER_CAPABILITY" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" MANIFEST=1 CACHE_GATE_VARIANT="$cache_off_clean_a" "$CACHE_GATE_LAUNCHER" --runner-root "$layout_v2_tree"
CACHE_GATE_MANIFEST_INSTANCE="$cache_off_clean_b" CACHE_GATE_LINKER_CAPABILITY="$CACHE_GATE_LINKER_CAPABILITY" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" MANIFEST=1 CACHE_GATE_VARIANT="$cache_off_clean_b" "$CACHE_GATE_LAUNCHER" --runner-root "$layout_v2_tree"
CACHE_GATE_LAYOUT_ADVERSARY=1 CACHE_GATE_MANIFEST_INSTANCE="$cache_off_adversary" CACHE_GATE_LINKER_CAPABILITY="$CACHE_GATE_LINKER_CAPABILITY" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" MANIFEST=1 CACHE_GATE_VARIANT="$cache_off_adversary" "$CACHE_GATE_LAUNCHER" --runner-root "$layout_v2_tree"
cache_off_clean_a_manifest="$layout_v2_tree/target/cache-gate/$cache_arch/$cache_off_clean_a/manifest.json"
cache_off_clean_b_manifest="$layout_v2_tree/target/cache-gate/$cache_arch/$cache_off_clean_b/manifest.json"
cache_off_adversary_manifest="$layout_v2_tree/target/cache-gate/$cache_arch/$cache_off_adversary/manifest.json"
test "$(jq -r '.runner_root' "$cache_off_clean_a_manifest")" = "$layout_v2_tree"
test "$(sha256sum "$CACHE_GATE_ELF_LAYOUT_TOOL" | cut -d' ' -f1)" = "$(jq -r '.tools.elf_layout.sha256' "$cache_off_clean_a_manifest")"
test "$(sha256sum "$CACHE_GATE_SNAPSHOT_TOOL" | cut -d' ' -f1)" = "$(jq -r '.tools.snapshot.sha256' "$cache_off_clean_a_manifest")"
"$CACHE_GATE_ELF_LAYOUT_TOOL" compare --anchor "$cache_off_clean_a_manifest" --candidate "$cache_off_clean_b_manifest"
"$CACHE_GATE_ELF_LAYOUT_TOOL" compare --anchor "$cache_off_clean_a_manifest" --candidate "$cache_off_adversary_manifest"
```

Require exact placement/body fields for all eight kernels across clean-a,
clean-b, and adversary. Require clean-a/clean-b rustc argv to contain the same
explicit default release `-C codegen-units=16`, with identical object/member,
`cgu_partition_fingerprint`, link-order, and reserved-input-owner fingerprints.
Require the adversary CGU-partition/object/member and link-order fingerprints
to differ; its named symbol/section
must appear exactly once, be linked, and lie outside all reservations. Compare
placed cache-off-v2 bodies with rejected
`1080c18` manifests only for normalized body hash, body size, calls, frame, and
spills; those must match. Do not require or reuse v1 placement/raw hashes. Use
`readelf` evidence to record PIE `ET_DYN`, RX containment, no RWX, no overlap,
and no veneers/thunks. Do not run Criterion or `perf` yet.

- [ ] **Step 10: Obtain fresh harness approval before policy replay**

Give a fresh reviewer: the layout decision; exact old/new commit graph; v1
diagnostics; revert commit; source-identity diff; linker capability records;
three fragment hashes/set hash; all three manifests from both architectures; ELF/program-header/
map/layout JSON; clean-repeat/adversary comparisons; v1 body-only comparison;
and test output. The only outcomes are:

- `APPROVE POLICY REPLAY`: both native architectures pass and cache-off-v2 is
  an immutable harness-only anchor;
- `REPAIR HARNESS`: preserve evidence and make another harness-only commit from
  cache-off-v2, increment `CACHE_GATE_ATTEMPT`, derive fresh
  `<arch>-<new-commit>-attempt-N` capability/proof/variant/evidence names, and
  repeat Steps 6–10 without deleting any failed root;
- `HOLD`: unsupported linker/ELF host, missing architecture, veneer, invalid
  segment, or inability to preserve exact bodies/placement.

Record the review path/verdict and `cache_off_current_v2_commit`. No policy
patch may be applied before `APPROVE POLICY REPLAY`; no timing is authorized in
this task.

### Task 3: Replay the Compile-Time Candidate Policy Without Changing Current Codegen

**Files:**
- Modify: `src/common/exact/probe.rs`
- Modify: `src/elastic.rs:341-409,803-849,899-1008,1200-1214`
- Test: `src/elastic.rs:2540-2625`

**Interfaces:**
- Consumes: reviewer-approved `cache_off_current_v2_commit`, current
  `PreparedElasticProbe::routing_signature`, and the exact source-only diff
  from `5fb56a5` to diagnostic `f4a0d35`.
- Produces: fresh `cache_policy_current_v2_commit`,
  `probe::CACHE_ELASTIC_INSERT_SIGNATURE: bool`, insert-only
  `PreparedElasticKey { route, insert_metadata }`, logical
  `signature()`/`membership()` accessors, and exact repaired-harness identity.
  Counter-PRF Task 2 later moves the constant unchanged into every candidate
  module.

- [ ] **Step 1: Split the historical edge and prove test-only RED on cache-off-v2**

Create immutable off/policy worktrees from the approved anchor. Pin the full
historical source edge, then deterministically split it at the first test hunk.
The test-only patch must be applied and fail to compile before any production
hunk is present:

```bash
cache_off_v2_tree=/home/aang/projects/opthash/.worktrees/perf/cache-off-v2
cache_policy_v2_tree=/home/aang/projects/opthash/.worktrees/perf/cache-policy-v2
git worktree add --detach "$cache_off_v2_tree" "$cache_off_current_v2_commit"
git worktree add "$cache_policy_v2_tree" -b perf/cache-policy-v2 "$cache_off_current_v2_commit"
historical_policy_diff="$cache_policy_v2_tree/target/cache-policy-f4a0d35-full.patch"
cache_policy_tests_patch="$cache_policy_v2_tree/target/cache-policy-f4a0d35-tests.patch"
cache_policy_production_patch="$cache_policy_v2_tree/target/cache-policy-f4a0d35-production.patch"
git diff --binary 5fb56a5e0e55cc093b5ac7035746178bcf023066 f4a0d354239a8cf669bb240fcb17474693d7b56f -- src > "$historical_policy_diff"
awk '
  /^diff --git a\/src\/elastic.rs b\/src\/elastic.rs$/ { elastic = 1; header = 1 }
  !elastic { next }
  header { print; if (/^\+\+\+ /) header = 0; next }
  /^@@ -2537,6 \+2591,76 @@ mod tests \{$/ { tests = 1 }
  tests { print }
' "$historical_policy_diff" > "$cache_policy_tests_patch"
awk '
  BEGIN { keep = 1 }
  /^@@ -2537,6 \+2591,76 @@ mod tests \{$/ { keep = 0 }
  keep != 0 { print }
' "$historical_policy_diff" > "$cache_policy_production_patch"
test "$(sha256sum "$historical_policy_diff" | cut -d' ' -f1)" = 7e91eb3cad49651dd7d28aef45de17024143aa9104b82cba29615ea2b50fe472
test "$(sha256sum "$cache_policy_tests_patch" | cut -d' ' -f1)" = 783c0f86b2dd2ee14d0e0a01b62dffa81d160e641def439eaf495448f0294aaf
test "$(sha256sum "$cache_policy_production_patch" | cut -d' ' -f1)" = dd8e41055edb6055c8f1006a3bb32ae98b39091dc4f90af54fa4fb5b69ae60f9
test "$(git diff --name-only 5fb56a5e0e55cc093b5ac7035746178bcf023066 f4a0d354239a8cf669bb240fcb17474693d7b56f -- src)" = $'src/common/exact/probe.rs\nsrc/elastic.rs'
test "$(git apply --numstat "$cache_policy_tests_patch" | cut -f3-)" = src/elastic.rs
test "$(git apply --numstat "$cache_policy_production_patch" | cut -f3-)" = $'src/common/exact/probe.rs\nsrc/elastic.rs'
git -C "$cache_policy_v2_tree" diff --quiet 47fc953b8b429cfdac29c13c313c28a21eb0ee4a -- src
git -C "$cache_policy_v2_tree" apply --check "$cache_policy_tests_patch"
git -C "$cache_policy_v2_tree" apply "$cache_policy_tests_patch"
```

First prove source discovery independently of the compiler. Exactly one copy of
each named `#[test]` must now exist in `src/elastic.rs`; a missing name or
duplicate is fatal. Then run compile-only test construction and require a
missing-production-API error. A successful build, a zero-test report, or an
unrelated failure is not RED:

```bash
test "$(rg -n '^    fn current_insert_metadata_keeps_prepared_membership_bits\(\)' "$cache_policy_v2_tree/src/elastic.rs" | wc -l)" -eq 1
test "$(rg -n '^    fn forced_candidate_signature_is_full_and_sixteen_bytes\(\)' "$cache_policy_v2_tree/src/elastic.rs" | wc -l)" -eq 1
test "$(rg -n '^    #\[test\]$' "$cache_policy_v2_tree/src/elastic.rs" -B1 -A1 | rg -c 'current_insert_metadata_keeps_prepared_membership_bits|forced_candidate_signature_is_full_and_sixteen_bytes')" -eq 2
if (cd "$cache_policy_v2_tree" && cargo test --no-run elastic::tests::current_insert_metadata_keeps_prepared_membership_bits > target/cache-policy-v2-red.txt 2>&1); then
    echo "error: policy-v2 red unexpectedly passed" >&2
    exit 1
fi
! rg -F "running 0 tests" "$cache_policy_v2_tree/target/cache-policy-v2-red.txt"
rg -n "CACHE_ELASTIC_INSERT_SIGNATURE|insert_metadata|new_for_policy|signature_for_policy|membership_for_policy" "$cache_policy_v2_tree/target/cache-policy-v2-red.txt"
```

Expected: the fresh anchor still has source-original production, and the exact
test-only patch is discovered in source but cannot compile because production
APIs are absent. Preserve the RED log and all three literal hashes/file lists.
The `b1cabb6` patch and every v1 manifest remain diagnostic only.

- [ ] **Step 2: Audit the replayed property and union-word contract**

The source patch must contain these tests before production changes:

```rust
#[test]
fn current_insert_metadata_keeps_prepared_membership_bits() {
    assert!(!probe::CACHE_ELASTIC_INSERT_SIGNATURE);
    for hash in signature_test_hashes() {
        let prepared = PreparedElasticKey::new(hash);
        let signature = prepared.route.signature();
        assert_eq!(prepared.insert_metadata, membership_bits_from_signature(signature));
        assert_eq!(prepared.signature(), signature);
        assert_eq!(prepared.membership().bits, membership_bits_from_signature(signature));
    }
}

#[test]
fn forced_candidate_signature_is_full_and_sixteen_bytes() {
    assert_eq!(mem::size_of::<PreparedElasticRoute>(), 8);
    assert_eq!(mem::align_of::<PreparedElasticRoute>(), mem::align_of::<u64>());
    assert_eq!(mem::size_of::<PreparedElasticKey>(), 16);
    assert_eq!(mem::align_of::<PreparedElasticKey>(), mem::align_of::<u64>());
    for hash in signature_test_hashes() {
        let prepared = PreparedElasticKey::new_for_policy::<true>(hash);
        assert_eq!(prepared.insert_metadata, prepared.route.signature());
        assert_eq!(prepared.signature_for_policy::<true>(), prepared.route.signature());
        assert_eq!(
            prepared.membership_for_policy::<true>().bits,
            membership_bits_from_signature(prepared.route.signature()),
        );
    }
}
```

`signature_test_hashes()` must return zero, `u64::MAX`, `ELASTIC_PROBE_SEED`, the four pinned secrets, every pairwise XOR, every one-hot bit, and 4,096 fixed SplitMix64 outputs.

- [ ] **Step 3: Audit and apply the exact reviewed implementation patch**

In `src/common/exact/probe.rs`, beside the current Elastic prepared-state API, add:

```rust
pub(crate) const CACHE_ELASTIC_INSERT_SIGNATURE: bool = false;
```

In `src/elastic.rs`, replace only the insert-key representation:

```rust
#[derive(Clone, Copy)]
struct PreparedElasticKey {
    route: PreparedElasticRoute,
    insert_metadata: u64,
}

impl PreparedElasticKey {
    #[inline]
    fn new(hash: u64) -> Self {
        Self::new_for_policy::<{ probe::CACHE_ELASTIC_INSERT_SIGNATURE }>(hash)
    }

    #[inline]
    fn new_for_policy<const CACHE_SIGNATURE: bool>(hash: u64) -> Self {
        let route = PreparedElasticRoute::new(hash);
        let insert_metadata = if CACHE_SIGNATURE {
            route.signature()
        } else {
            PreparedMembership::from_signature(route.signature()).bits
        };
        Self { route, insert_metadata }
    }

    #[inline]
    fn signature(self) -> u64 {
        self.signature_for_policy::<{ probe::CACHE_ELASTIC_INSERT_SIGNATURE }>()
    }

    #[inline]
    fn signature_for_policy<const CACHE_SIGNATURE: bool>(self) -> u64 {
        if CACHE_SIGNATURE {
            self.insert_metadata
        } else {
            self.route.signature()
        }
    }

    #[inline]
    fn membership(self) -> PreparedMembership {
        self.membership_for_policy::<{ probe::CACHE_ELASTIC_INSERT_SIGNATURE }>()
    }

    #[inline]
    fn membership_for_policy<const CACHE_SIGNATURE: bool>(self) -> PreparedMembership {
        if CACHE_SIGNATURE {
            PreparedMembership::from_signature(self.insert_metadata)
        } else {
            PreparedMembership { bits: self.insert_metadata }
        }
    }
}

const _: () = assert!(mem::size_of::<PreparedElasticRoute>() == 8);
const _: () = assert!(mem::align_of::<PreparedElasticRoute>() == mem::align_of::<u64>());
const _: () = assert!(mem::size_of::<PreparedElasticKey>() == 16);
const _: () = assert!(mem::align_of::<PreparedElasticKey>() == mem::align_of::<u64>());
```

Keep policy knowledge inside this type. Do not expose `insert_metadata` to metadata callers.

- [ ] **Step 4: Audit route precheck/record and apply the reviewed patch**

Change `membership_maybe_contains` and `record_membership` to consume a logical signature and `PreparedMembership`. Both derive word index from `self.membership_words()` at invocation time. Route summary uses the same signature's low two bits. At insert precheck and final record, call:

```rust
let signature = prepared.signature();
let membership = prepared.membership();
if self.membership_maybe_contains(signature, membership)
    && let Some(location) =
        self.find_slot_indices_prepared(&key, prepared.route, key_fingerprint)
{
    return Some(self.replace_value(location, value));
}
```

and:

```rust
self.record_membership(prepared.signature(), prepared.membership(), level_idx);
```

Do not change `summary_level_mask(PreparedElasticRoute)`: ordinary lookup remains route-only and computes a candidate signature lazily only after H(1,1) misses.

After confirming the production patch contains exactly the Step-2
representation and this logical-value routing, apply it after the recorded RED
without hand editing. The union of the two applied patches must reproduce the
full historical edge byte-for-byte:

```bash
git -C "$cache_policy_v2_tree" apply --check "$cache_policy_production_patch"
git -C "$cache_policy_v2_tree" apply "$cache_policy_production_patch"
test "$(git -C "$cache_policy_v2_tree" diff --name-only -- src)" = $'src/common/exact/probe.rs\nsrc/elastic.rs'
test "$(git -C "$cache_policy_v2_tree" diff --binary -- src | sha256sum | cut -d' ' -f1)" = 7e91eb3cad49651dd7d28aef45de17024143aa9104b82cba29615ea2b50fe472
git -C "$cache_policy_v2_tree" diff --quiet f4a0d354239a8cf669bb240fcb17474693d7b56f -- src
```

- [ ] **Step 5: Run focused semantics and current layout tests**

```bash
(cd "$cache_policy_v2_tree" && cargo test elastic::tests::current_insert_metadata_keeps_prepared_membership_bits -- --exact)
(cd "$cache_policy_v2_tree" && cargo test elastic::tests::forced_candidate_signature_is_full_and_sixteen_bytes -- --exact)
(cd "$cache_policy_v2_tree" && cargo test elastic::tests::compact_membership_matches_the_existing_signature_formula -- --exact)
(cd "$cache_policy_v2_tree" && cargo test elastic::tests::compact_prepared_elastic_state_is_register_sized -- --exact)
(cd "$cache_policy_v2_tree" && cargo test common::exact::probe::tests::prepared_elastic_probe_is_bit_identical_to_the_full_counter_prf -- --exact)
```

Expected: PASS; current property is false and all old vectors/layouts remain exact.

- [ ] **Step 6: Commit the neutral policy scaffold before evidence builds**

After semantic tests pass, commit before creating any acceptance manifest:

```bash
git -C "$cache_policy_v2_tree" add src/common/exact/probe.rs src/elastic.rs
git -C "$cache_policy_v2_tree" commit -m "refactor: add elastic insert signature policy"
policy_replay_v2_commit=$(git -C "$cache_policy_v2_tree" rev-parse HEAD)
cache_policy_current_v2_commit=$policy_replay_v2_commit
test "$(git -C "$cache_policy_v2_tree" rev-parse "$policy_replay_v2_commit^")" = "$cache_off_current_v2_commit"
test -z "$(git -C "$cache_policy_v2_tree" status --porcelain)"
git -C "$cache_policy_v2_tree" diff --quiet f4a0d354239a8cf669bb240fcb17474693d7b56f "$cache_policy_current_v2_commit" -- src
test "$(git -C "$cache_policy_v2_tree" rev-parse "$policy_replay_v2_commit:docs/superpowers/plans/2026-07-20-counter-prf-bakeoff.md")" = "$docs_bakeoff_blob"
test "$(git -C "$cache_policy_v2_tree" rev-parse "$policy_replay_v2_commit:docs/superpowers/plans/2026-07-21-elastic-candidate-signature-cache.md")" = "$docs_signature_cache_blob"
test "$(git -C "$cache_policy_v2_tree" rev-parse "$policy_replay_v2_commit:docs/superpowers/specs/2026-07-20-counter-prf-insert-design.md")" = "$docs_counter_prf_spec_blob"
```

Expected: immutable clean scaffold exists; no dirty-tree manifest is acceptance
evidence.

- [ ] **Step 7: Prove clean policy-false codegen and repaired-layout identity**

Use the already-created immutable v2 worktrees and one cache-off-built control.
Pass the exact accepted linker capability record and build fresh manifests:

```bash
CACHE_GATE_LAUNCHER="$cache_off_v2_tree/scripts/cache-gate.sh"
test "$(git hash-object "$CACHE_GATE_LAUNCHER")" = "$(git -C "$cache_off_v2_tree" rev-parse HEAD:scripts/cache-gate.sh)"
BUILD_CONTROL=1 "$CACHE_GATE_LAUNCHER" --runner-root "$cache_off_v2_tree"
CACHE_GATE_CONTROL_BIN=$(sed -n '1p' "$cache_off_v2_tree/target/cache-gate-control-bin.txt")
test -x "$CACHE_GATE_CONTROL_BIN"
layout_v2_tree=/home/aang/projects/opthash/.worktrees/bench/cache-gate-layout-v2
CACHE_GATE_LINKER_CAPABILITY="$layout_v2_tree/target/cache-gate-linker/$(uname -m)/capability.json"
test -f "$CACHE_GATE_LINKER_CAPABILITY"
cache_arch=$(uname -m)
cache_off_policy_variant="$cache_arch-${cache_off_current_v2_commit:0:12}-policy-proof"
cache_policy_variant="$cache_arch-${cache_policy_current_v2_commit:0:12}-policy-proof"
CACHE_GATE_LINKER_CAPABILITY="$CACHE_GATE_LINKER_CAPABILITY" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" MANIFEST=1 CACHE_GATE_VARIANT="$cache_off_policy_variant" "$CACHE_GATE_LAUNCHER" --runner-root "$cache_off_v2_tree"
CACHE_GATE_LINKER_CAPABILITY="$CACHE_GATE_LINKER_CAPABILITY" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" MANIFEST=1 CACHE_GATE_VARIANT="$cache_policy_variant" "$CACHE_GATE_LAUNCHER" --runner-root "$cache_policy_v2_tree"
cache_off_v2_manifest="$cache_off_v2_tree/target/cache-gate/$cache_arch/$cache_off_policy_variant/manifest.json"
cache_policy_v2_manifest="$cache_policy_v2_tree/target/cache-gate/$cache_arch/$cache_policy_variant/manifest.json"
CACHE_GATE_ELF_LAYOUT_TOOL="$cache_off_v2_tree/scripts/cache-gate-elf-layout.py"
test "$(sha256sum "$CACHE_GATE_ELF_LAYOUT_TOOL" | cut -d' ' -f1)" = "$(jq -r '.tools.elf_layout.sha256' "$cache_off_v2_manifest")"
"$CACHE_GATE_ELF_LAYOUT_TOOL" compare --anchor "$cache_off_v2_manifest" --candidate "$cache_policy_v2_manifest"
```

Use extractor JSON and fresh CodSpeed output to compare stable Elastic/Funnel
kernels plus concrete insert, H(1,1), summary, membership-precheck, record, and
write symbols. Expected: policy-current current hot bodies have equal normalized
hashes, calls, frames, spills, and exact named Callgrind counts versus cache-off;
fixed control path/hash and linker capability/fragment hashes are identical.
All eight kernels must match exact output/input section, reservation start/end,
reservation, page offset, actual alignment, all three reservation sentinels,
raw/normalized hashes, calls, frames, and spills; binaries remain PIE/RX with no
veneers. Run on native AArch64 and x86-64.

Give both native manifest pairs plus production identity/Callgrind evidence to
a fresh reviewer. Only `APPROVE LIFECYCLE` releases Task 4. If policy production
identity fails, recoverably revert exact `cache_policy_current_v2_commit` and
revise source shape from cache-off-v2. If the ELF mechanism or placement fails,
return to Task 2 or `HOLD`; do not blame/relabel policy and do not run timing.

### Task 4: Prove Exact Derivation, Growth, Recovery, and Lifecycle Semantics

**Files:**
- Modify: `src/elastic.rs:2540-3010`
- Test: `src/elastic.rs`

**Interfaces:**
- Consumes: Task 3 logical signature/membership methods and current production insertion/rebuild paths.
- Produces: independent scalar-oracle coverage and production-path regression tests that fail if cached signature, current geometry, membership bits, or route bin diverge.

- [ ] **Step 1: Write the independent derivation oracle test**

Add `cached_signature_derives_existing_membership_bits_word_and_bin`. Its oracle must implement multiply-high and four Bloom placements locally, without calling `PreparedMembership::{from_signature,word}`. Cover `0`, `u64::MAX`, every one-hot bit, and 4,096 fixed SplitMix values against word counts `1,2,3,17,257`, `usize::MAX / size_of::<ElasticMetadataWord>()`, and the maximum count admitted by `elastic_arena_layout` on the target. Assert bin equals `(signature & 3) as usize`.

Run the exact test before adding any shared test helper. Expected RED if production helpers are deliberately perturbed; record the mutation/revert in task notes, then run against unmodified production and require PASS. This is a characterization TDD red: the intentional one-line mutation proves the oracle detects a wrong word or Bloom step, and the mutation must not be committed.

- [ ] **Step 2: Prove precheck and record use identical derivation**

Add `candidate_membership_precheck_and_record_use_identical_derivation`. Construct a zeroed table with at least three metadata words, choose a signature whose target word has distinct neighbors, create a forced-policy prepared key, and invoke production `membership_maybe_contains` then `record_membership`. Assert false before record, true after, exact target bits, exact inserted-level route-bin bit, and byte equality for every non-target metadata word. Permit multiple Bloom placements colliding within the target membership word; permit no neighboring-word/bin mutation.

Run exact test; expected PASS only after Task 3 routes both operations through the same logical signature.

- [ ] **Step 3: Add the production growth regression missed by Phase 1**

Add `insert_growth_reindexes_cached_signature_in_production_path` using a cloned `BatchScheduler` preview:

1. Build a small identity-hashed map and fill until cloned `scheduler.on_insert(...)` returns `InsertAction::Resize(new_slots)` for the next insert.
2. Search fixed hashes until independent multiply-high produces different indices for old and predicted new membership-word counts.
3. Snapshot old word count and epoch.
4. Call public `map.insert(hash, value)`; do not invoke a reindex helper or resize directly.
5. Assert growth transition occurred, lookup succeeds, new target word contains exact bits/bin, and—when still in range—the stale old index does not receive the pending key's uniquely attributable route-bin bit.

First add the test with a temporary test-only mutation that records using pre-growth word count; require failure at the target-word assertion. Revert mutation and require:

```bash
cargo test elastic::tests::insert_growth_reindexes_cached_signature_in_production_path -- --exact
cargo +nightly miri test elastic::tests::insert_growth_reindexes_cached_signature_in_production_path -- --exact
```

Expected: native and Miri PASS through actual scheduler growth.

- [ ] **Step 4: Extend same-size exceptional recovery assertions**

In `finite_probe_exhaustion_uses_observable_exceptional_recovery`, snapshot the forced-policy key's full signature before insertion. After production recovery, independently derive the current word, membership bits, and bin; assert the pending entry's membership bits and inserted-level summary bit are present in the rebuilt sidecar, lookup succeeds, and epoch reports exactly one `PlacementRecovery`.

Run:

```bash
cargo test elastic::tests::finite_probe_exhaustion_uses_observable_exceptional_recovery -- --exact
```

Expected: PASS; no index, pointer, reference, or sidecar snapshot crossed recovery.

- [ ] **Step 5: Run the complete metadata lifecycle matrix**

Run focused tests covering duplicate replacement, vacant entry APIs, clear, clone, conservative delete/tombstone, drain, explicit reserve, failed `try_reserve`, allocator failure, explicit `resize`, `try_resize`, tombstone cleanup, rebuild, and collision reuse:

```bash
cargo test elastic::tests::membership_filter_never_forgets_live_or_deleted_hashes -- --exact
cargo test elastic::tests::membership_filter_resets_and_rebuilds_at_table_boundaries -- --exact
cargo test elastic::tests::all_vacant_entry_apis_record_membership -- --exact
cargo test elastic::tests::drain_and_failed_reserve_preserve_membership_invariants -- --exact
cargo test elastic::tests::allocator_failure_does_not_publish_or_forget_membership -- --exact
cargo test elastic::tests::colliding_hashes_remain_distinguishable_through_delete_and_reuse -- --exact
cargo test elastic::tests::route_summary_conservatively_records_every_live_level -- --exact
cargo test elastic::tests::prepared_elastic_key_remains_geometry_independent_across_growth -- --exact
cargo test elastic::tests::prepared_membership_remains_valid_across_growth -- --exact
cargo test caught_hash_panic_during_try_resize_leaves_counters_valid
```

Expected: every test PASS. Add explicit assertions to the existing boundary tests if any named lifecycle only checks lookup and not membership/summary state; do not create a test-only reindex path.

- [ ] **Step 6: Add target-aware hot-layout snapshots**

Add module-local `hot_layout_snapshot` tests in `src/elastic.rs` and
`src/funnel.rs`, using `core::mem::{size_of, align_of, offset_of}`. Emit one
stable `key=value` line for size/alignment and every listed field offset:

- Elastic: `PreparedElasticRoute`, `PreparedElasticKey`,
  `ElasticMetadataWord::{membership,route_bins}`,
  `Level::{ctrl_ptr,data_ptr,capacity,len,tombstones}`, and every
  `ElasticTable` field;
- Funnel: `LevelShape`, every `FunnelShape` field,
  `FlatStorage::{ctrl_ptr,data_ptr,n}`, and every `FunnelTable` field.

Current source has no `BucketLevel`; require `! rg -n 'struct BucketLevel' src`
and record `BucketLevel=absent` in the baseline. Introduction of that type is a
layout change and fails the gate until it receives its own complete snapshot.
Do not invent an assertion for a nonexistent type.

Capture cache-off output separately for native AArch64, native x86-64, and the
32-bit compile target. Every policy/on/candidate native snapshot must match its
same-target cache-off file exactly. Carrier alignment is target-aware:
`align_of::<PreparedElastic{Route,Key}>() == align_of::<u64>()`; native assembly
records actual ABI lowering instead of assuming 8-byte alignment everywhere.

Run the MSRV 32-bit gates:

```bash
rustup target add --toolchain 1.88.0 i686-unknown-linux-gnu
cargo +1.88.0 check --target i686-unknown-linux-gnu --lib --no-default-features
cargo +1.88.0 test --target i686-unknown-linux-gnu --lib --no-run
```

Expected: 32-bit check and test-build PASS. If the host lacks a compatible
linker/sysroot, the gate is `HOLD`; do not infer support from native tests.

- [ ] **Step 7: Run full portability verification and commit tests**

```bash
cargo test
cargo rustc --lib --no-default-features --crate-type rlib
cargo +1.88.0 rustc --lib --no-default-features --crate-type rlib
cargo +nightly test --features nightly
cargo +nightly miri test elastic::tests::insert_growth_reindexes_cached_signature_in_production_path -- --exact
pre-commit run --all-files
git diff --check
```

Expected: all supported commands PASS. Commit lifecycle coverage separately:

```bash
git add src/elastic.rs
git commit -m "test: cover elastic signature cache lifecycle"
cache_policy_current_v2_commit=$(git rev-parse HEAD)
test "$(git rev-parse "$cache_policy_current_v2_commit^")" = "$policy_replay_v2_commit"
test "$(git rev-parse "$cache_policy_current_v2_commit:docs/superpowers/plans/2026-07-20-counter-prf-bakeoff.md")" = "$docs_bakeoff_blob"
test "$(git rev-parse "$cache_policy_current_v2_commit:docs/superpowers/plans/2026-07-21-elastic-candidate-signature-cache.md")" = "$docs_signature_cache_blob"
test "$(git rev-parse "$cache_policy_current_v2_commit:docs/superpowers/specs/2026-07-20-counter-prf-insert-design.md")" = "$docs_counter_prf_spec_blob"
```

The updated policy commit remains default-false and codegen-neutral; create a
fresh immutable worktree/manifest and re-run Task 3 Step 7 after test-only
changes to confirm release symbols and layouts remain identical.

### Task 5: Freeze Cache-On Current and Pass Static/Assembly Gates

**Files:**
- Modify in variant only: `src/common/exact/probe.rs`
- Read: `target/cache-gate/`
- Create as build artifacts only: `target/cache-*-speedup.asm`, `target/cache-*-callgrind.txt`

**Interfaces:**
- Consumes: immutable cache-off-v2 and cache-policy-v2 commits.
- Produces: immutable cache-on current commit plus per-architecture ABI, one-signature, and lazy-get evidence.

- [ ] **Step 1: Verify off/policy worktrees and create immutable cache-on**

Invoke `superpowers:using-git-worktrees`. Use matching branch/worktree names:

Task 3 already created off/policy worktrees. Verify their clean HEADs; if Task 4
advanced policy with lifecycle tests, remove only the stale detached policy
worktree and recreate it at the new exact commit. Then create
`perf/cache-on-v2` from that exact policy commit.

In cache-on only, change `CACHE_ELASTIC_INSERT_SIGNATURE` from `false` to `true`
and commit before evidence tests:

```bash
cache_on_v2_tree=/home/aang/projects/opthash/.worktrees/perf/cache-on-v2
git worktree add "$cache_on_v2_tree" -b perf/cache-on-v2 "$cache_policy_current_v2_commit"
git -C "$cache_on_v2_tree" add src/common/exact/probe.rs
git -C "$cache_on_v2_tree" commit -m "perf: force current elastic signature cache"
cache_on_current_v2_commit=$(git -C "$cache_on_v2_tree" rev-parse HEAD)
test "$(git -C "$cache_on_v2_tree" rev-parse "$cache_on_current_v2_commit^")" = "$cache_policy_current_v2_commit"
test -z "$(git -C "$cache_on_v2_tree" status --porcelain)"
test "$(git -C "$cache_on_v2_tree" rev-parse "$cache_on_current_v2_commit:docs/superpowers/plans/2026-07-20-counter-prf-bakeoff.md")" = "$docs_bakeoff_blob"
test "$(git -C "$cache_on_v2_tree" rev-parse "$cache_on_current_v2_commit:docs/superpowers/plans/2026-07-21-elastic-candidate-signature-cache.md")" = "$docs_signature_cache_blob"
test "$(git -C "$cache_on_v2_tree" rev-parse "$cache_on_current_v2_commit:docs/superpowers/specs/2026-07-20-counter-prf-insert-design.md")" = "$docs_counter_prf_spec_blob"
```

Expected: each tree clean and each HEAD equals its recorded immutable commit.

- [ ] **Step 2: Run forced-true production lifecycle and Miri gates**

In immutable cache-on, retain exact output from:

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

Expected: every command runs with active production policy true and PASS.
Generic forced helpers from policy-false do not satisfy this gate.

- [ ] **Step 3: Prove fixed controls, stable layout, and policy-false identity on both architectures**

On each native host, build the independent control executable exactly once from
`cache-off-v2`, save its absolute path as `CACHE_GATE_CONTROL_BIN`, and
pass that same path to every `MANIFEST=1` in all three trees. Do not rebuild
controls from candidate worktree paths. Build new manifests and run the
structural comparator before inspecting production bodies. Carry the literal
`cache_off_static_variant`, `cache_off_static_manifest`,
`cache_off_static_manifest_sha`, `cache_off_static_capability`, and
`cache_off_static_capability_sha` selected here into Tasks 6 and 7; later steps
must not reconstruct a cache-off variant or capability path:

```bash
layout_v2_tree=/home/aang/projects/opthash/.worktrees/bench/cache-gate-layout-v2
CACHE_GATE_LINKER_CAPABILITY="$layout_v2_tree/target/cache-gate-linker/$(uname -m)/capability.json"
cache_arch=$(uname -m)
CACHE_GATE_LAUNCHER="$cache_off_v2_tree/scripts/cache-gate.sh"
cache_off_static_variant="$cache_arch-${cache_off_current_v2_commit:0:12}-static"
cache_policy_static_variant="$cache_arch-${cache_policy_current_v2_commit:0:12}-static"
cache_on_static_variant="$cache_arch-${cache_on_current_v2_commit:0:12}-static"
CACHE_GATE_LINKER_CAPABILITY="$CACHE_GATE_LINKER_CAPABILITY" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" MANIFEST=1 CACHE_GATE_VARIANT="$cache_off_static_variant" "$CACHE_GATE_LAUNCHER" --runner-root "$cache_off_v2_tree"
CACHE_GATE_LINKER_CAPABILITY="$CACHE_GATE_LINKER_CAPABILITY" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" MANIFEST=1 CACHE_GATE_VARIANT="$cache_policy_static_variant" "$CACHE_GATE_LAUNCHER" --runner-root "$cache_policy_v2_tree"
CACHE_GATE_LINKER_CAPABILITY="$CACHE_GATE_LINKER_CAPABILITY" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" MANIFEST=1 CACHE_GATE_VARIANT="$cache_on_static_variant" "$CACHE_GATE_LAUNCHER" --runner-root "$cache_on_v2_tree"
cache_off_v2_manifest="$cache_off_v2_tree/target/cache-gate/$cache_arch/$cache_off_static_variant/manifest.json"
cache_policy_v2_manifest="$cache_policy_v2_tree/target/cache-gate/$cache_arch/$cache_policy_static_variant/manifest.json"
cache_on_v2_manifest="$cache_on_v2_tree/target/cache-gate/$cache_arch/$cache_on_static_variant/manifest.json"
cache_off_static_manifest="$cache_off_v2_manifest"
cache_policy_static_manifest="$cache_policy_v2_manifest"
cache_on_static_manifest="$cache_on_v2_manifest"
cache_off_static_manifest_sha=$(sha256sum "$cache_off_static_manifest" | cut -d' ' -f1)
cache_off_static_capability=$(jq -er '.linker_capability.copy.absolute_path' "$cache_off_static_manifest")
cache_off_static_capability_sha=$(jq -er '.linker_capability.copy.sha256' "$cache_off_static_manifest")
test "$(realpath -e "$cache_off_static_capability")" = "$(dirname "$cache_off_static_manifest")/linker-capability.json"
test "$(sha256sum "$cache_off_static_capability" | cut -d' ' -f1)" = "$cache_off_static_capability_sha"
CACHE_GATE_ELF_LAYOUT_TOOL="$cache_off_v2_tree/scripts/cache-gate-elf-layout.py"
test "$(sha256sum "$CACHE_GATE_ELF_LAYOUT_TOOL" | cut -d' ' -f1)" = "$(jq -r '.tools.elf_layout.sha256' "$cache_off_v2_manifest")"
"$CACHE_GATE_ELF_LAYOUT_TOOL" compare --anchor "$cache_off_v2_manifest" --candidate "$cache_policy_v2_manifest"
"$CACHE_GATE_ELF_LAYOUT_TOOL" compare --anchor "$cache_off_v2_manifest" --candidate "$cache_on_v2_manifest" \
  --allow-body-change elastic_cache_gate_insert_kernel \
  --allow-body-change elastic_profile_insert_kernel
```

Require:

- identical fixed-control executable SHA-256 in all trees;
- cache-off and cache-policy stable Elastic/Funnel insert/get normalized hashes identical;
- for cache-off-v2, cache-policy-v2, and cache-on-v2, all eight corresponding
  stable/profile kernels have identical output/input sections, starts, page
  offsets, zero capability-derived maximum-page remainders, actual ELF
  alignments, reservation sizes, and reservation-start/reservation-end sentinel
  names/addresses; every `body_end` name/address is structurally valid, but its
  address is exact only for unchanged kernels;
- cache-policy-v2 has exact `body_end`/body size, raw/normalized hash, calls, frame,
  and spills for all eight kernels; cache-on-v2 permits body-field changes only
  for the declared stable/profile Elastic insert kernels, requires every body
  record to be structurally valid, and keeps the other six body records exact;
  any missing field, unexpected change, or placement drift rejects before timing;
- identical accepted linker capability, actual linker path/flavor/version,
  three-fragment set hash, PIE/RX segment proof, and zero veneers/thunks;
- exact cache-off/cache-policy named Callgrind counts on x86-64;
- exact same-target hot-layout snapshots for all named existing types/fields;
  `BucketLevel=absent` remains exact.

Any source-identity failure blocks timing and sends Task 3 back for a fresh
policy replay/revision. Any capability/section/segment/placement failure sends
the harness to Task 2 or `HOLD`; do not conflate it with policy.

- [ ] **Step 4: Inspect cache-on insert ABI and one-signature lowering**

Fresh-build `speedup` for production inspection, but take
`elastic_cache_gate` only from each accepted manifest; never rebuild that stable
binary. Dump concrete hot bodies with `objdump -d -C` and record caller/callee
register and stack use. Require:

- `PreparedElasticKey` travels as two scalar 64-bit words on 64-bit targets; no hidden result pointer or aggregate copy;
- no new stack slot/spill whose only purpose is preserving cached signature across placement;
- one current `routing_signature()` materialization while constructing a prepared insert key;
- no signature materialization in `membership_maybe_contains`, `record_membership`, `write_new_entry`, or post-resize record code;
- two fixed Bloom derivations are allowed (precheck and record); no third 64-bit carrier word;
- no selector helper, indirect call, function pointer, or surviving policy branch.

Current's `routing_signature()` is a field projection, so this gate proves the carrier/dataflow. Counter-PRF candidate assembly later must separately prove exactly one guarded `S2` evaluation or Philox `(0,1)` round block.

- [ ] **Step 5: Prove get laziness and exact get identity**

Compare cache-off, cache-policy, and cache-on concrete bodies for `get`, `get_mut`, contains, remove lookup, and entry lookup. Require byte identity for the stable H(1,1) get body and exact named Callgrind counts. In candidate-ready source and assembly, H(1,1) match/return must precede summary signature/index work. Grep/review must show no `PreparedElasticKey::new` on ordinary lookup paths.

Expected: forcing insert policy changes no ordinary get body or instruction count.

- [ ] **Step 6: Obtain a static-gate review before timing**

Give the three commits, source diff, layout output, fixed-control hashes, normalized symbol dumps, Callgrind counts, stack frames, spill/call-site audit, one-signature trace, and get-laziness trace to a fresh reviewer. Record `APPROVE TIMING` or `REJECT` in task notes. Do not run the expensive campaign after rejection.

### Task 6: Run Fixed-Control Preflight and Three-Pair Cross-Architecture Gate

**Files:**
- Read: `scripts/bench.sh`
- Read: `scripts/cache-gate.sh`
- Read: `target/criterion/`
- Read: `target/cache-gate/`

**Interfaces:**
- Consumes: reviewer-approved immutable cache-off-v2/cache-policy-v2/cache-on-v2 trees.
- Produces: fixed-control-valid AArch64 and x86-64 raw comparisons for full speedup, both latency orders/sizes, default scaled insert, Callgrind, and `perf stat`.

- [ ] **Step 1: Run one adjacent fixed-control/stable-layout preflight pair per architecture**

Use one shared Criterion root per host. Run cache-off controls + stable Elastic
and Funnel targets immediately adjacent to cache-on equivalents, then invoke
the authenticated atomic helper. It alone runs one offline comparison and
snapshots it under the same lock:

```bash
cache_arch=$(uname -m)
cache_root=/home/aang/projects/opthash/.worktrees/perf/counter-prf-insert/target/criterion-cache
cache_off_tree=/home/aang/projects/opthash/.worktrees/perf/cache-off-v2
cache_on_tree=/home/aang/projects/opthash/.worktrees/perf/cache-on-v2
CACHE_GATE_CONTROL_BIN=$(sed -n '1p' "$cache_off_tree/target/cache-gate-control-bin.txt")
test -x "$CACHE_GATE_CONTROL_BIN"
test -n "${cache_off_static_variant:?carry exact Task 5 cache-off static variant}"
test -n "${cache_off_static_manifest:?carry exact Task 5 cache-off manifest}"
test -n "${cache_off_static_manifest_sha:?carry exact Task 5 cache-off manifest hash}"
test -n "${cache_off_static_capability:?carry exact Task 5 cache-off capability copy}"
test -n "${cache_off_static_capability_sha:?carry exact Task 5 cache-off capability hash}"
test -n "${cache_policy_static_manifest:?carry exact Task 5 cache-policy manifest}"
test -n "${cache_on_static_manifest:?carry exact Task 5 cache-on manifest}"
cache_off_manifest="$cache_off_static_manifest"
cache_on_manifest="$cache_on_static_manifest"
test "${CACHE_TIMING_ATTEMPT:?set positive timing attempt}" -gt 0
cache_preflight_id="$cache_arch-${cache_on_current_v2_commit:0:12}-attempt-$CACHE_TIMING_ATTEMPT-preflight"
test -f "$cache_off_manifest"
test -f "$cache_on_manifest"
CACHE_GATE_LINKER_CAPABILITY="$cache_off_static_capability"
test "$(sha256sum "$cache_off_manifest" | cut -d' ' -f1)" = "$cache_off_static_manifest_sha"
test "$(realpath -e "$CACHE_GATE_LINKER_CAPABILITY")" = "$(dirname "$cache_off_manifest")/linker-capability.json"
test "$(sha256sum "$CACHE_GATE_LINKER_CAPABILITY" | cut -d' ' -f1)" = "$cache_off_static_capability_sha"
test "$cache_off_static_capability_sha" = "$(jq -er '.linker_capability.copy.sha256' "$cache_off_manifest")"
CACHE_GATE_ELF_LAYOUT_TOOL="$cache_off_tree/scripts/cache-gate-elf-layout.py"
CACHE_GATE_SNAPSHOT_TOOL="$cache_off_tree/scripts/snapshot-criterion-pair.sh"
CACHE_GATE_LAUNCHER="$cache_off_tree/scripts/cache-gate.sh"
test "$(sha256sum "$CACHE_GATE_ELF_LAYOUT_TOOL" | cut -d' ' -f1)" = "$(jq -r '.tools.elf_layout.sha256' "$cache_off_manifest")"
test "$(sha256sum "$CACHE_GATE_SNAPSHOT_TOOL" | cut -d' ' -f1)" = "$(jq -r '.tools.snapshot.sha256' "$cache_off_manifest")"
test "$(sha256sum "$CACHE_GATE_LAUNCHER" | cut -d' ' -f1)" = "$(jq -r '.tools.launcher.sha256' "$cache_off_manifest")"
"$CACHE_GATE_ELF_LAYOUT_TOOL" compare --anchor "$cache_off_manifest" --candidate "$cache_on_manifest" \
  --allow-body-change elastic_cache_gate_insert_kernel \
  --allow-body-change elastic_profile_insert_kernel

OPTHASH_CRITERION_ROOT="$cache_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" CONTROL=1 SAVE="$cache_preflight_id-off-control" "$CACHE_GATE_LAUNCHER" --runner-root "$cache_off_tree"
OPTHASH_CRITERION_ROOT="$cache_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" CONTROL=1 SAVE="$cache_preflight_id-on-control" "$CACHE_GATE_LAUNCHER" --runner-root "$cache_on_tree"
"$CACHE_GATE_SNAPSHOT_TOOL" --runner-root "$cache_on_tree" --criterion-root "$cache_root" --snapshot-root target/cache-gate-evidence --arch "$cache_arch" --comparison "$cache_preflight_id-control" --pair 1 --target control --anchor-run "$cache_preflight_id-off-control" --candidate-run "$cache_preflight_id-on-control" --anchor-commit "$cache_off_current_v2_commit" --candidate-commit "$cache_on_current_v2_commit" --anchor-manifest "$cache_off_manifest" --candidate-manifest "$cache_on_manifest"

OPTHASH_CRITERION_ROOT="$cache_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" CACHE_GATE_MANIFEST="$cache_off_manifest" ELASTIC=1 SAVE="$cache_preflight_id-off-elastic" "$CACHE_GATE_LAUNCHER" --runner-root "$cache_off_tree"
OPTHASH_CRITERION_ROOT="$cache_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" CACHE_GATE_MANIFEST="$cache_on_manifest" ELASTIC=1 SAVE="$cache_preflight_id-on-elastic" "$CACHE_GATE_LAUNCHER" --runner-root "$cache_on_tree"
"$CACHE_GATE_SNAPSHOT_TOOL" --runner-root "$cache_on_tree" --criterion-root "$cache_root" --snapshot-root target/cache-gate-evidence --arch "$cache_arch" --comparison "$cache_preflight_id-elastic" --pair 1 --target elastic_cache_gate --anchor-run "$cache_preflight_id-off-elastic" --candidate-run "$cache_preflight_id-on-elastic" --anchor-commit "$cache_off_current_v2_commit" --candidate-commit "$cache_on_current_v2_commit" --anchor-manifest "$cache_off_manifest" --candidate-manifest "$cache_on_manifest"

OPTHASH_CRITERION_ROOT="$cache_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" CACHE_GATE_MANIFEST="$cache_off_manifest" FUNNEL=1 SAVE="$cache_preflight_id-off-funnel" "$CACHE_GATE_LAUNCHER" --runner-root "$cache_off_tree"
OPTHASH_CRITERION_ROOT="$cache_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" CACHE_GATE_MANIFEST="$cache_on_manifest" FUNNEL=1 SAVE="$cache_preflight_id-on-funnel" "$CACHE_GATE_LAUNCHER" --runner-root "$cache_on_tree"
"$CACHE_GATE_SNAPSHOT_TOOL" --runner-root "$cache_on_tree" --criterion-root "$cache_root" --snapshot-root target/cache-gate-evidence --arch "$cache_arch" --comparison "$cache_preflight_id-funnel" --pair 1 --target funnel_cache_gate --anchor-run "$cache_preflight_id-off-funnel" --candidate-run "$cache_preflight_id-on-funnel" --anchor-commit "$cache_off_current_v2_commit" --candidate-commit "$cache_on_current_v2_commit" --anchor-manifest "$cache_off_manifest" --candidate-manifest "$cache_on_manifest"
```

Expected: fixed-control SHA-256 remains identical; every std/hashbrown control point movement is within ±5%; repeated layout-linked control shift from Phase 1 is absent; cache-off stable Elastic absolute means are repeatable. Any control breach stops the campaign for harness/host investigation. Rerun only after identifying a host or harness cause; never rerun until favorable and never normalize candidate results by controls.

- [ ] **Step 2: Collect three interleaved full-suite pairs for policy and cache-on**

For each candidate tree (`cache-policy-v2`, then `cache-on-v2`) run
this sequence independently on both architectures. After each adjacent pair,
run the shown offline comparison and snapshot immediately:

```bash
candidate_name=cache-on-v2
candidate_tree=/home/aang/projects/opthash/.worktrees/perf/cache-on-v2
candidate_commit=$(git -C "$candidate_tree" rev-parse HEAD)
test "${CACHE_TIMING_ATTEMPT:?set positive timing attempt}" -gt 0
candidate_campaign_id="$cache_arch-${candidate_commit:0:12}-attempt-$CACHE_TIMING_ATTEMPT"
case "$candidate_name" in
  cache-policy-v2) candidate_manifest="$cache_policy_static_manifest" ;;
  cache-on-v2) candidate_manifest="$cache_on_static_manifest" ;;
  *) echo "error: undeclared cache timing candidate $candidate_name" >&2; exit 1 ;;
esac
test -f "$candidate_manifest"
candidate_layout_args=()
if test "$candidate_name" = cache-on-v2; then
  candidate_layout_args=(
    --allow-body-change elastic_cache_gate_insert_kernel
    --allow-body-change elastic_profile_insert_kernel
  )
fi
"$CACHE_GATE_ELF_LAYOUT_TOOL" compare --anchor "$cache_off_manifest" --candidate "$candidate_manifest" "${candidate_layout_args[@]}"

(cd "$cache_off_tree" && OPTHASH_CRITERION_ROOT="$cache_root" SAVE="$candidate_campaign_id-off-a1" scripts/bench.sh)
(cd "$candidate_tree" && OPTHASH_CRITERION_ROOT="$cache_root" SAVE="$candidate_campaign_id-c1" scripts/bench.sh)
"$CACHE_GATE_SNAPSHOT_TOOL" --runner-root "$candidate_tree" --criterion-root "$cache_root" --snapshot-root target/cache-gate-evidence --arch "$cache_arch" --comparison "$candidate_campaign_id-full" --pair 1 --target all --anchor-run "$candidate_campaign_id-off-a1" --candidate-run "$candidate_campaign_id-c1" --anchor-commit "$cache_off_current_v2_commit" --candidate-commit "$candidate_commit" --anchor-manifest "$cache_off_manifest" --candidate-manifest "$candidate_manifest"

(cd "$candidate_tree" && OPTHASH_CRITERION_ROOT="$cache_root" SAVE="$candidate_campaign_id-c2" scripts/bench.sh)
(cd "$cache_off_tree" && OPTHASH_CRITERION_ROOT="$cache_root" SAVE="$candidate_campaign_id-off-a2" scripts/bench.sh)
"$CACHE_GATE_SNAPSHOT_TOOL" --runner-root "$candidate_tree" --criterion-root "$cache_root" --snapshot-root target/cache-gate-evidence --arch "$cache_arch" --comparison "$candidate_campaign_id-full" --pair 2 --target all --anchor-run "$candidate_campaign_id-off-a2" --candidate-run "$candidate_campaign_id-c2" --anchor-commit "$cache_off_current_v2_commit" --candidate-commit "$candidate_commit" --anchor-manifest "$cache_off_manifest" --candidate-manifest "$candidate_manifest"

(cd "$cache_off_tree" && OPTHASH_CRITERION_ROOT="$cache_root" SAVE="$candidate_campaign_id-off-a3" scripts/bench.sh)
(cd "$candidate_tree" && OPTHASH_CRITERION_ROOT="$cache_root" SAVE="$candidate_campaign_id-c3" scripts/bench.sh)
"$CACHE_GATE_SNAPSHOT_TOOL" --runner-root "$candidate_tree" --criterion-root "$cache_root" --snapshot-root target/cache-gate-evidence --arch "$cache_arch" --comparison "$candidate_campaign_id-full" --pair 3 --target all --anchor-run "$candidate_campaign_id-off-a3" --candidate-run "$candidate_campaign_id-c3" --anchor-commit "$cache_off_current_v2_commit" --candidate-commit "$candidate_commit" --anchor-manifest "$cache_off_manifest" --candidate-manifest "$candidate_manifest"
```

Repeat the Step-1 control, Elastic, and Funnel two-`SAVE` → atomic-helper block
around each `ai/ci` pair with unique
comparison/pair names. Instantiate its candidate half with
`$candidate_tree`, `$candidate_manifest`, and `$candidate_name`; never reuse
the hard-coded cache-on values while measuring cache-policy-v2. Every stable
candidate invocation receives `CACHE_GATE_MANIFEST="$candidate_manifest"` and
every stable anchor invocation receives `CACHE_GATE_MANIFEST="$cache_off_manifest"`.
Discard/rerun the whole pair if either fixed control
exceeds 5%; preserve rejected snapshots under `discarded/`, do not overwrite
them, substitute full-suite controls, or normalize.

- [ ] **Step 3: Collect three default scaled-insert pairs**

Use the same alternating pattern with `BENCH=scaled_insert` for 100K, 1M, and
10M in both policy and cache-on trees. Immediately after each adjacent pair
invoke the authenticated helper once with exactly
`--runner-root "$candidate_tree" --target scaled_insert` and the matching run
names/pair/manifests; the helper
sets `BENCH=scaled_insert`, performs the only offline execution, and snapshots
before releasing its lock. Do not use
`SCALED_INSERT_SIZES` overrides as evidence. Pair every candidate directly with
cache-off original. Around each scaled pair, repeat the Step-1 control,
Elastic, and Funnel two-`SAVE` → atomic-helper immutable snapshot
blocks with unique names; a preflight snapshot cannot substitute for these
pair-adjacent controls.

- [ ] **Step 4: Apply the predeclared Criterion gates**

For cache-policy current, require byte-identical hot bodies, exact zero
Callgrind-instruction delta, each of three regression points
`point_estimate <= +0.02`, median of three points `<= +0.01`, and at least two
of three `confidence_interval.upper_bound <= +0.02` versus cache-off. Never
gate a favorable negative lower bound. For cache-on current, separately on each
architecture require:

- all three Elastic headline insert and each scaled-insert point estimates at most +2%;
- median at most +1%;
- at least two 95% upper bounds at most +2%;
- every randomized/ordered get trace and every other public Elastic operation
  has all three point estimates `<= +0.02`, median `<= +0.02`, and at least two
  95% upper bounds `<= +0.02`;
- every unchanged Funnel headline/public/latency/scale point is `<= +0.02`, its
  three-point median is `<= +0.01`, at least two upper bounds are `<= +0.02`,
  and named Funnel Callgrind counts/hot bodies equal cache-off exactly.

Read only immutable snapshots. Record baseline/candidate absolute means, raw
fractional point, 95% low/high, pair manifest and hashes, and fixed-control
movement for every pair. A cache-on failure rejects this carrier before
candidate PRF work; later candidate speed cannot excuse it.

- [ ] **Step 5: Collect x86-64 Callgrind corroboration**

Fresh-build each immutable tree with `CARGO_INCREMENTAL=0`, record exact per-operation counts, and require:

- cache-policy insert/get counts exactly equal cache-off;
- cache-on Elastic insert instructions increase by at most 1%;
- cache-on get counts exactly equal cache-off;
- no stale executable, selector branch, helper/indirect call, hidden sret, aggregate copy, or signature-preservation spill.

- [ ] **Step 6: Collect operation-specific AArch64 hardware counters**

For each immutable tree, take `CACHE_GATE_PERF_BIN` only from its accepted
manifest and run four separate, no-build fixed-iteration operations, three raw
repetitions each:

```bash
test "${CACHE_TIMING_ATTEMPT:?set positive timing attempt}" -gt 0
cache_perf_campaign="$cache_arch-${cache_off_current_v2_commit:0:12}-${cache_on_current_v2_commit:0:12}-attempt-$CACHE_TIMING_ATTEMPT"
CACHE_GATE_CAMPAIGN_KEY="elastic-signature-cache-$cache_perf_campaign"
CACHE_GATE_PERF_TOOL="$cache_off_tree/scripts/cache-gate-perf.sh"
test "$(sha256sum "$CACHE_GATE_PERF_TOOL" | cut -d' ' -f1)" = "$(jq -r '.tools.perf_launcher.sha256' "$cache_off_manifest")"
perf_trees=("$cache_off_tree" "$cache_on_tree")
perf_manifests=("$cache_off_manifest" "$cache_on_manifest")
for index in 0 1; do
    tree=${perf_trees[$index]}
    manifest=${perf_manifests[$index]}
    test "$(jq -r '.runner_root' "$manifest")" = "$tree"
    CACHE_GATE_CAMPAIGN_ROOT="$tree/target/cache-gate-campaigns/$cache_perf_campaign"
    profile_bin=$(jq -er '.executables.cache_gate_profile.absolute_path' "$manifest")
    for op in elastic-insert elastic-get funnel-insert funnel-get; do
        for repetition in 1 2 3; do
            CACHE_GATE_PERF_BIN="$profile_bin" \
            CACHE_GATE_CAMPAIGN_ROOT="$CACHE_GATE_CAMPAIGN_ROOT" \
            CACHE_GATE_CAMPAIGN_KEY="$CACHE_GATE_CAMPAIGN_KEY" \
                "$CACHE_GATE_PERF_TOOL" --runner-root "$tree" \
                --manifest "$manifest" --operation "$op" --iterations 100 \
                --repetition "$repetition"
        done
    done
done
```

Use the same campaign key under each authenticated runner root; every output is
contained by that root and records it. A different comparison campaign requires
a new architecture/commit/attempt key and preserves both prior roots.

Require cache-on Elastic median cycles and instructions `<= +0.02` versus
cache-off and unchanged Funnel exact direction/count gates; no adverse cache-/
branch-miss direction may be unexplained by raw repetition noise. Preserve each
`perf stat -x,` CSV and compute medians from operation-specific files only.

- [ ] **Step 7: Audit completeness before making any decision**

Expected evidence set per architecture: immutable control/Elastic/Funnel
preflight snapshots; three policy-vs-off and three on-vs-off full snapshots;
three matching scaled snapshots; both absolute JSON trees; pair manifests and
verified hashes; actual linker capability/version and three fragment hashes;
manifested stable/profile executable paths/hashes; all eight output/input
sections, sentinel/address/page/alignment/reservation/link-map records;
PIE/RX/no-veneer proof; assembly manifests; x86 Callgrind; operation-specific
AArch64 counters. Missing architecture, Funnel, capability, exact binary,
snapshot, manifest, or hash keeps decision `HOLD`, not `PASS`.

### Task 7: Fresh Review, Retain/Revert, and Evidence Commit

**Files:**
- Create: `docs/performance/2026-07-21-elastic-candidate-signature-cache.md`
- Modify on rejection: `src/common/exact/probe.rs`, `src/elastic.rs`, harness files as directed by reviewer

**Interfaces:**
- Consumes: complete Task 6 raw evidence and immutable v2 commit graph.
- Produces: one fresh reviewer decision, retained policy-false scaffold or ordered reverts, and the exact accepted evidence commit consumed by the counter-PRF bakeoff.

- [ ] **Step 1: Write the evidence record from raw files**

Create the document with these literal top-level fields:

```markdown
# Elastic Candidate Signature Cache Evidence

- Original source commit: `<40-hex>`
- Rejected v1 harness commit: `1080c188a47f02202b6a0878830dbf2947629992`
- Rejected policy diagnostic commits: `b1cabb653cebc5922e84a26cb24db8b58903245d,f4a0d354239a8cf669bb240fcb17474693d7b56f`
- Historical policy revert commit: `5fb56a5e0e55cc093b5ac7035746178bcf023066`
- Docs-remediation-v2 commit: `<40-hex>`
- Docs-remediation-v2 patch SHA-256: `<64-hex>`
- Docs-remediation-v2 files: `docs/superpowers/plans/2026-07-20-counter-prf-bakeoff.md,docs/superpowers/plans/2026-07-21-elastic-candidate-signature-cache.md,docs/superpowers/specs/2026-07-20-counter-prf-insert-design.md`
- Docs bakeoff Git blob: `<40-hex>`
- Docs bakeoff content SHA-256: `<64-hex>`
- Docs signature-cache Git blob: `<40-hex>`
- Docs signature-cache content SHA-256: `<64-hex>`
- Docs counter-PRF spec Git blob: `<40-hex>`
- Docs counter-PRF spec content SHA-256: `<64-hex>`
- Policy-revert-v2 commit: `<40-hex>`
- Replayed harness-v1 commit: `<40-hex>`
- Replayed harness-v1 patch SHA-256: `2e82ea3092bc1585c0845620b3748fb15fa12d97d53b9e14f71f0bf1e95231d1`
- Replayed harness-v1 files: `Cargo.toml,benches/cache_gate_profile.rs,benches/elastic_cache_gate.rs,benches/funnel_cache_gate.rs,benches/harness/cache_gate.rs,benches/harness/mod.rs,docs/superpowers/plans/2026-07-20-counter-prf-bakeoff.md,docs/superpowers/plans/2026-07-21-elastic-candidate-signature-cache.md,scripts/cache-gate-perf-support.py,scripts/cache-gate-perf.sh,scripts/cache-gate.sh,scripts/extract-hot-symbols.py,scripts/snapshot-criterion-pair.sh,tests/elastic_cache_gate_fixture.rs,tests/test_cache_gate_perf_support.py,tests/test_extract_hot_symbols.py,tests/test_snapshot_criterion_pair.py,tools/cache-gate-control/.gitignore,tools/cache-gate-control/Cargo.lock,tools/cache-gate-control/Cargo.toml,tools/cache-gate-control/src/main.rs`
- Replayed-docs-v2 commit: `<40-hex>`
- Cache-off-v2 commit: `<40-hex>`
- Policy-replay-v2 commit: `<40-hex>`
- Policy full patch SHA-256: `7e91eb3cad49651dd7d28aef45de17024143aa9104b82cba29615ea2b50fe472`
- Policy test-only patch SHA-256: `783c0f86b2dd2ee14d0e0a01b62dffa81d160e641def439eaf495448f0294aaf`
- Policy test-only files: `src/elastic.rs`
- Policy production patch SHA-256: `dd8e41055edb6055c8f1006a3bb32ae98b39091dc4f90af54fa4fb5b69ae60f9`
- Policy production files: `src/common/exact/probe.rs,src/elastic.rs`
- Cache-policy-v2 commit: `<40-hex>`
- Cache-on-v2 commit: `<40-hex>`
- Cache-on-v2 production diff SHA-256: `<64-hex>`
- Elastic linker-fragment SHA-256: `<64-hex>`
- Funnel linker-fragment SHA-256: `<64-hex>`
- Profile linker-fragment SHA-256: `<64-hex>`
- Linker-fragment set SHA-256: `<64-hex>`
- ELF layout validator Git blob: `<40-hex>`
- ELF layout validator SHA-256: `<64-hex>`
- Snapshot helper Git blob: `<40-hex>`
- Snapshot helper SHA-256: `<64-hex>`
- Cache-gate launcher Git blob: `<40-hex>`
- Cache-gate launcher SHA-256: `<64-hex>`
- Cache-gate perf launcher Git blob: `<40-hex>`
- Cache-gate perf launcher SHA-256: `<64-hex>`
- AArch64 linker capability SHA-256: `<64-hex>`
- x86-64 linker capability SHA-256: `<64-hex>`
- AArch64 cache-off-v2 static variant: `aarch64-<12-char-cache-off-commit>-static`
- x86-64 cache-off-v2 static variant: `x86_64-<12-char-cache-off-commit>-static`
- AArch64 cache-off-v2 manifest SHA-256: `<64-hex>`
- x86-64 cache-off-v2 manifest SHA-256: `<64-hex>`
- Stable timing mode: `manifested-no-build`
- Decision: `HOLD|ACCEPT|REJECT`
```

Then include:

1. Host/CPU/kernel/rustc/Criterion/CodSpeed/perf identity for both architectures.
2. Fixed-control executable paths, Cargo/lock hashes, both native linker
   capability records, linker path/flavor/version, fragment hashes/set hash, stable/profile
   `output_section`/`input_section`, addresses/page offsets/actual alignments,
   literal `reservation_start`, `body_end`, and `reservation_end` sentinels,
   PIE `ET_DYN`,
   `ALLOC|EXECINSTR`, wholly RX
   `PT_LOAD`, no RWX/overlap, and no-veneer proof, preflight snapshots, and every
   discarded adjacency.
3. Three immutable full-suite snapshot paths per comparison/architecture with
   run names, commits, manifest hashes, baseline/candidate ns, point, 95%
   low/high, and control movements.
4. Three immutable 100K/1M/10M scaled snapshot paths per comparison/architecture.
5. Layout sizes/offsets; raw and normalized hot-body hashes; return ABI; stack
   frames; spills; calls; clean-repeat/adversary results including literal
   `codegen-units`, `cgu_partition_fingerprint`, `object_fingerprint`,
   `link_order_fingerprint`, reserved
   input owners, and exact-one linked adversary identity; exact manifested
   timing-binary hashes; one-signature and lazy-get findings.
6. Exact per-operation x86-64 Callgrind counts and AArch64 cycles/instructions/cache/branch counters.
7. A gate table with one row per required threshold and literal pass/fail evidence.
8. Limitations and missing evidence; never infer a passing cell.

- [ ] **Step 2: Obtain a fresh reviewer decision**

Give reviewer the original design, layout decision, complete old/repaired v2
commit graph, source patches/diffs, linker capability and ELF records, all raw
JSON/manifests/snapshots, evidence draft, and exact gates. Reviewer returns one
of:

- `ACCEPT`: policy-false codegen is original, cache-on carrier passes both architectures, one-signature/get/ABI/lifecycle gates pass;
- `REJECT-CARRIER`: cache-on fails correctness, ABI, or performance; revert carrier/policy production changes;
- `REJECT-HARNESS`: control/stable-layout evidence is invalid; preserve v2 evidence and restart Task 2 from the last source-original harness-only anchor;
- `HOLD`: evidence is incomplete, including either missing native architecture.

Record reviewer path and verdict verbatim in the evidence document. No author self-approval.

- [ ] **Step 3: Retain only on ACCEPT**

On `ACCEPT`, keep the repaired harness, policy-false scaffold, and lifecycle
tests; do not merge the forced-true commit. Set document `Decision: ACCEPT`.
Verify current production constant remains false and source diff against
cache-policy-v2 is exact. The accepted tree must contain no runtime selector or
forced candidate policy. V1 manifests remain labeled rejected diagnostics.

- [ ] **Step 4: Revert on rejection in dependency order**

On `REJECT-CARRIER`, revert lifecycle-test commit only if tests depend on removed interface, then revert `refactor: add elastic insert signature policy`; retain the fixed-control/stable-layout harness unless reviewer rejects it independently. Use `git revert <exact-commit>`—never reset—and report recoverability. Set `Decision: REJECT` and name every revert commit.

On `REJECT-HARNESS`, make no carrier decision from invalid timing and do not
repair underneath policy descendants. Preserve all old commits/snapshots for
audit, then create a new branch/worktree from exact source-original `47fc953` or
the latest reviewer-approved source-original harness-only anchor. Build and
approve a new harness-only cache-off-v3 commit there first; only then
replay or reimplement policy/lifecycle commits and rerun every static/timing
gate. Alternatively create explicit lifecycle-then-policy reverts before
harness repair. A tree containing policy source is never named
`cache-off-v2`/`cache-off-v3`. On `HOLD`, make no retain/revert claim.

- [ ] **Step 5: Run final verification and commit accepted/rejected evidence**

```bash
cargo test
cargo rustc --lib --no-default-features --crate-type rlib
pre-commit run --all-files
git diff --check
```

Expected: PASS. If accepted:

```bash
git add docs/performance/2026-07-21-elastic-candidate-signature-cache.md
git commit -m "docs: accept elastic candidate signature cache"
signature_cache_evidence_commit=$(git rev-parse HEAD)
test "$(git rev-parse "$signature_cache_evidence_commit^")" = "$cache_policy_current_v2_commit"
test "$(git rev-parse "$signature_cache_evidence_commit:docs/superpowers/plans/2026-07-20-counter-prf-bakeoff.md")" = "$docs_bakeoff_blob"
test "$(git rev-parse "$signature_cache_evidence_commit:docs/superpowers/plans/2026-07-21-elastic-candidate-signature-cache.md")" = "$docs_signature_cache_blob"
test "$(git rev-parse "$signature_cache_evidence_commit:docs/superpowers/specs/2026-07-20-counter-prf-insert-design.md")" = "$docs_counter_prf_spec_blob"
```

If rejected, use `docs: reject elastic candidate signature cache`. Only the exact accepted message releases the counter-PRF plan's precondition.

- [ ] **Step 6: Hand off immutable anchors to the counter-PRF bakeoff**

Record both full IDs in the evidence doc and task handoff:

- `cache_off_current_v2_commit`: repaired harness-only commit whose production
  `src/` equals `47fc953` and whose linker capability/layout passed both native
  architectures;
- `signature_cache_evidence_commit`: accepted policy-false tree and evidence.

Every guarded/Philox survivor and final mixed tree must be compared directly to
`cache_off_current_v2_commit`, using its exact linker script/capability and
manifested stable Elastic/Funnel binaries. `cache-policy-v2` and `cache-on-v2`
remain attribution controls only.
