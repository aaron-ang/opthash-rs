# Elastic Candidate Signature Cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add and validate a compile-time candidate policy that caches one full Elastic metadata signature for guarded-wyhash64 and Philox inserts while preserving original current-PRF code generation when the policy is false.

**Architecture:** Keep ordinary lookup on the existing 8-byte `PreparedElasticRoute`. Change only the insert-only 16-byte `PreparedElasticKey`: its second word is prepared Bloom bits when `CACHE_ELASTIC_INSERT_SIGNATURE` is false and the full geometry-independent metadata signature when true. Callers obtain logical signature and membership values through small methods; every sidecar index is derived from the current table geometry at the point of use, so no pointer, loaded word, or index survives growth or same-size placement recovery.

**Tech Stack:** Rust 2024 (`core`/`alloc`, MSRV 1.88), Criterion/CodSpeed, Linux `perf`, GNU `objdump`, `sha256sum`, existing pinned benchmark launcher.

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
- A fixed-control executable must be byte-identical across measured commits. A dedicated Elastic target must isolate stable benchmark layout. One adjacent preflight pair must keep every fixed std/hashbrown control within 5% before full measurement.
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
- `scripts/cache-gate-perf.sh` — no-build, manifested-binary, operation-specific `perf stat` collection.
- `scripts/extract-hot-symbols.py` — exact-one-symbol resolution, checked instruction normalization, and symbol metadata/hashing.
- `scripts/snapshot-criterion-pair.sh` — atomic immutable snapshot of change JSON, both absolute JSON trees, manifests, and SHA-256 inventory after each offline comparison.
- `src/common/exact/probe.rs` — owns the current compile-time candidate property until the counter-PRF bakeoff moves it into identical candidate modules.
- `src/elastic.rs` — insert-only union word, logical accessors, current-geometry metadata derivation, lifecycle tests, and layout assertions.
- `docs/performance/2026-07-21-elastic-candidate-signature-cache.md` — immutable commits, raw pairs, codegen/counter evidence, reviewer verdict, and retain/revert record.

---

### Task 1: Build and Prove the Fixed-Control/Stable-Layout Harness

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
`--criterion-root`, `--snapshot-root`, `--arch`, `--comparison`, `--pair`,
`--target`, `--anchor-run`, `--candidate-run`, `--anchor-commit`,
`--candidate-commit`, `--anchor-manifest`, and `--candidate-manifest`. It must:

1. refuse an existing destination and write through `mktemp -d`;
2. copy every target-matching `change/estimates.json` immediately after the
   corresponding `LOAD/BASELINE` command;
3. copy both `<anchor-run>/estimates.json` and
   `<candidate-run>/estimates.json` as `absolute/anchor/...` and
   `absolute/candidate/...` preserving group/benchmark paths;
4. copy both build manifests/link maps and record run names, commits, target,
   host, executable hashes, and command line in `pair-manifest.json`;
5. generate `SHA256SUMS`, verify it with `sha256sum -c`, fsync files, then
   atomically rename the temporary directory;
6. fail when any expected change/absolute JSON is missing, when manifests do
   not name the supplied commits, or when a hash changes.

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
absolute `CACHE_GATE_PERF_BIN`, verifies its SHA-256 against `manifest.json`,
and runs one operation per invocation. Use `perf stat -x,` with control/ack
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
cache_off_current_commit=$(git rev-parse HEAD)
git diff --quiet "$cache_off_source_commit".."$cache_off_current_commit" -- src
```

Expected: immutable `cache-off-current` commit differs from original only in benchmark/harness files; production source is byte-identical.

### Task 2: Add the Compile-Time Candidate Policy Without Changing Current Codegen

**Files:**
- Modify: `src/common/exact/probe.rs`
- Modify: `src/elastic.rs:341-409,803-849,899-1008,1200-1214`
- Test: `src/elastic.rs:2540-2625`

**Interfaces:**
- Consumes: current `PreparedElasticProbe::routing_signature`, `PreparedMembership` formula, current insert flow.
- Produces: `probe::CACHE_ELASTIC_INSERT_SIGNATURE: bool`, insert-only `PreparedElasticKey { route, insert_metadata }`, and logical `signature()`/`membership()` accessors. Counter-PRF Task 2 later moves the constant unchanged into every candidate module.

- [ ] **Step 1: Write failing representation and exact-derivation tests**

Add tests before production changes:

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

Run:

```bash
if cargo test elastic::tests::current_insert_metadata_keeps_prepared_membership_bits -- --exact > target/cache-policy-red.txt 2>&1; then
    echo "error: policy red unexpectedly passed" >&2
    exit 1
fi
rg -n "CACHE_ELASTIC_INSERT_SIGNATURE|insert_metadata|new_for_policy" target/cache-policy-red.txt
```

Expected: compile failure names missing policy/field/helpers.

- [ ] **Step 2: Add the current candidate property and union-word interface**

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

- [ ] **Step 3: Route precheck and record through logical values**

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

- [ ] **Step 4: Run focused semantics and current layout tests**

```bash
cargo test elastic::tests::current_insert_metadata_keeps_prepared_membership_bits -- --exact
cargo test elastic::tests::forced_candidate_signature_is_full_and_sixteen_bytes -- --exact
cargo test elastic::tests::compact_membership_matches_the_existing_signature_formula -- --exact
cargo test elastic::tests::compact_prepared_elastic_state_is_register_sized -- --exact
cargo test common::exact::probe::tests::prepared_elastic_probe_is_bit_identical_to_the_full_counter_prf -- --exact
```

Expected: PASS; current property is false and all old vectors/layouts remain exact.

- [ ] **Step 5: Commit the neutral policy scaffold before evidence builds**

After semantic tests pass, commit before creating any acceptance manifest:

```bash
git add src/common/exact/probe.rs src/elastic.rs
git commit -m "refactor: add elastic insert signature policy"
cache_policy_current_commit=$(git rev-parse HEAD)
test -z "$(git status --porcelain)"
```

Expected: immutable clean scaffold exists; no dirty-tree manifest is acceptance
evidence.

- [ ] **Step 6: Prove clean policy-false codegen identity**

Create detached `cache-off-current` and `cache-policy-current` worktrees from
their recorded commits, each with a fresh target directory. Build the fixed
control once from cache-off and always pass its absolute path:

```bash
git worktree add --detach /home/aang/projects/opthash/.worktrees/perf/cache-off-current "$cache_off_current_commit"
git worktree add --detach /home/aang/projects/opthash/.worktrees/perf/cache-policy-current "$cache_policy_current_commit"
(cd /home/aang/projects/opthash/.worktrees/perf/cache-off-current && BUILD_CONTROL=1 scripts/cache-gate.sh)
CACHE_GATE_CONTROL_BIN=$(sed -n '1p' /home/aang/projects/opthash/.worktrees/perf/cache-off-current/target/cache-gate-control-bin.txt)
test -x "$CACHE_GATE_CONTROL_BIN"
(cd /home/aang/projects/opthash/.worktrees/perf/cache-off-current && CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" MANIFEST=1 CACHE_GATE_VARIANT=cache-off-current scripts/cache-gate.sh)
(cd /home/aang/projects/opthash/.worktrees/perf/cache-policy-current && CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" MANIFEST=1 CACHE_GATE_VARIANT=cache-policy-current scripts/cache-gate.sh)
```

Use extractor JSON and fresh CodSpeed output to compare stable Elastic/Funnel
kernels plus concrete insert, H(1,1), summary, membership-precheck, record, and
write symbols. Expected: policy-current current hot bodies have equal normalized
hashes, calls, frames, spills, and exact named Callgrind counts versus cache-off;
fixed control path/hash is identical. Stable kernel start address, alignment,
and link-map predecessor must also equal cache-off. If any identity gate fails,
revert exact `cache_policy_current_commit`, revise source shape in a fresh child,
and repeat; do not measure or relabel a dirty working tree.

### Task 3: Prove Exact Derivation, Growth, Recovery, and Lifecycle Semantics

**Files:**
- Modify: `src/elastic.rs:2540-3010`
- Test: `src/elastic.rs`

**Interfaces:**
- Consumes: Task 2 logical signature/membership methods and current production insertion/rebuild paths.
- Produces: independent scalar-oracle coverage and production-path regression tests that fail if cached signature, current geometry, membership bits, or route bin diverge.

- [ ] **Step 1: Write the independent derivation oracle test**

Add `cached_signature_derives_existing_membership_bits_word_and_bin`. Its oracle must implement multiply-high and four Bloom placements locally, without calling `PreparedMembership::{from_signature,word}`. Cover `0`, `u64::MAX`, every one-hot bit, and 4,096 fixed SplitMix values against word counts `1,2,3,17,257`, `usize::MAX / size_of::<ElasticMetadataWord>()`, and the maximum count admitted by `elastic_arena_layout` on the target. Assert bin equals `(signature & 3) as usize`.

Run the exact test before adding any shared test helper. Expected RED if production helpers are deliberately perturbed; record the mutation/revert in task notes, then run against unmodified production and require PASS. This is a characterization TDD red: the intentional one-line mutation proves the oracle detects a wrong word or Bloom step, and the mutation must not be committed.

- [ ] **Step 2: Prove precheck and record use identical derivation**

Add `candidate_membership_precheck_and_record_use_identical_derivation`. Construct a zeroed table with at least three metadata words, choose a signature whose target word has distinct neighbors, create a forced-policy prepared key, and invoke production `membership_maybe_contains` then `record_membership`. Assert false before record, true after, exact target bits, exact inserted-level route-bin bit, and byte equality for every non-target metadata word. Permit multiple Bloom placements colliding within the target membership word; permit no neighboring-word/bin mutation.

Run exact test; expected PASS only after Task 2 routes both operations through the same logical signature.

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
cache_policy_current_commit=$(git rev-parse HEAD)
```

The updated policy commit remains default-false and codegen-neutral; create a
fresh immutable worktree/manifest and re-run Task 2 Step 6 after test-only
changes to confirm release symbols and layouts remain identical.

### Task 4: Freeze Cache-On Current and Pass Static/Assembly Gates

**Files:**
- Modify in variant only: `src/common/exact/probe.rs`
- Read: `target/cache-gate/`
- Create as build artifacts only: `target/cache-*-speedup.asm`, `target/cache-*-callgrind.txt`

**Interfaces:**
- Consumes: immutable cache-off and cache-policy commits.
- Produces: immutable cache-on current commit plus per-architecture ABI, one-signature, and lazy-get evidence.

- [ ] **Step 1: Verify off/policy worktrees and create immutable cache-on**

Invoke `superpowers:using-git-worktrees`. Use matching branch/worktree names:

Task 2 already created off/policy worktrees. Verify their clean HEADs; if Task 3
advanced policy with lifecycle tests, remove only the stale detached policy
worktree and recreate it at the new exact commit. Then create
`perf/cache-on-current` from that exact policy commit.

In cache-on only, change `CACHE_ELASTIC_INSERT_SIGNATURE` from `false` to `true`
and commit before evidence tests:

```bash
git add src/common/exact/probe.rs
git commit -m "perf: force current elastic signature cache"
cache_on_current_commit=$(git rev-parse HEAD)
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
`cache-off-current`, save its absolute path as `CACHE_GATE_CONTROL_BIN`, and
pass that same path to every `MANIFEST=1` in all three trees. Do not rebuild
controls from candidate worktree paths. Require:

- identical fixed-control executable SHA-256 in all trees;
- cache-off and cache-policy stable Elastic/Funnel insert/get normalized hashes identical;
- for cache-off, cache-policy, and cache-on, each corresponding Elastic and
  Funnel stable kernel has identical start address, `start % 4096`, declared
  alignment, and link-map predecessor; any drift rejects before timing;
- exact cache-off/cache-policy named Callgrind counts on x86-64;
- exact same-target hot-layout snapshots for all named existing types/fields;
  `BucketLevel=absent` remains exact.

Any failure blocks timing and sends Task 2 back for source-shape revision.

- [ ] **Step 4: Inspect cache-on insert ABI and one-signature lowering**

Fresh-build `speedup` and `elastic_cache_gate`, dump concrete hot bodies with `objdump -d -C`, and record caller/callee register and stack use. Require:

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

### Task 5: Run Fixed-Control Preflight and Three-Pair Cross-Architecture Gate

**Files:**
- Read: `scripts/bench.sh`
- Read: `scripts/cache-gate.sh`
- Read: `target/criterion/`
- Read: `target/cache-gate/`

**Interfaces:**
- Consumes: reviewer-approved immutable cache-off/cache-policy/cache-on trees.
- Produces: fixed-control-valid AArch64 and x86-64 raw comparisons for full speedup, both latency orders/sizes, default scaled insert, Callgrind, and `perf stat`.

- [ ] **Step 1: Run one adjacent fixed-control/stable-layout preflight pair per architecture**

Use one shared Criterion root per host. Run cache-off controls + stable Elastic
and Funnel targets immediately adjacent to cache-on equivalents, run explicit
offline comparisons, then snapshot before any later `LOAD/BASELINE` overwrites
live `change/` files:

```bash
cache_arch=$(uname -m)
cache_root=/home/aang/projects/opthash/.worktrees/perf/counter-prf-insert/target/criterion-cache
cache_off_tree=/home/aang/projects/opthash/.worktrees/perf/cache-off-current
cache_on_tree=/home/aang/projects/opthash/.worktrees/perf/cache-on-current
CACHE_GATE_CONTROL_BIN=$(sed -n '1p' "$cache_off_tree/target/cache-gate-control-bin.txt")
test -x "$CACHE_GATE_CONTROL_BIN"

(cd "$cache_off_tree" && OPTHASH_CRITERION_ROOT="$cache_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" CONTROL=1 SAVE="$cache_arch-cache-preflight-off-control" scripts/cache-gate.sh)
(cd "$cache_on_tree" && OPTHASH_CRITERION_ROOT="$cache_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" CONTROL=1 SAVE="$cache_arch-cache-preflight-on-control" scripts/cache-gate.sh)
(cd "$cache_off_tree" && OPTHASH_CRITERION_ROOT="$cache_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" CONTROL=1 LOAD="$cache_arch-cache-preflight-on-control" BASELINE="$cache_arch-cache-preflight-off-control" scripts/cache-gate.sh)
scripts/snapshot-criterion-pair.sh --criterion-root "$cache_root" --snapshot-root target/cache-gate-evidence --arch "$cache_arch" --comparison preflight-control --pair 1 --target control --anchor-run "$cache_arch-cache-preflight-off-control" --candidate-run "$cache_arch-cache-preflight-on-control" --anchor-commit "$cache_off_current_commit" --candidate-commit "$cache_on_current_commit" --anchor-manifest "$cache_off_tree/target/cache-gate/$cache_arch/cache-off-current/manifest.json" --candidate-manifest "$cache_on_tree/target/cache-gate/$cache_arch/cache-on-current/manifest.json"

(cd "$cache_off_tree" && OPTHASH_CRITERION_ROOT="$cache_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" ELASTIC=1 SAVE="$cache_arch-cache-preflight-off-elastic" scripts/cache-gate.sh)
(cd "$cache_on_tree" && OPTHASH_CRITERION_ROOT="$cache_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" ELASTIC=1 SAVE="$cache_arch-cache-preflight-on-elastic" scripts/cache-gate.sh)
(cd "$cache_off_tree" && OPTHASH_CRITERION_ROOT="$cache_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" ELASTIC=1 LOAD="$cache_arch-cache-preflight-on-elastic" BASELINE="$cache_arch-cache-preflight-off-elastic" scripts/cache-gate.sh)
scripts/snapshot-criterion-pair.sh --criterion-root "$cache_root" --snapshot-root target/cache-gate-evidence --arch "$cache_arch" --comparison preflight-elastic --pair 1 --target elastic_cache_gate --anchor-run "$cache_arch-cache-preflight-off-elastic" --candidate-run "$cache_arch-cache-preflight-on-elastic" --anchor-commit "$cache_off_current_commit" --candidate-commit "$cache_on_current_commit" --anchor-manifest "$cache_off_tree/target/cache-gate/$cache_arch/cache-off-current/manifest.json" --candidate-manifest "$cache_on_tree/target/cache-gate/$cache_arch/cache-on-current/manifest.json"

(cd "$cache_off_tree" && OPTHASH_CRITERION_ROOT="$cache_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" FUNNEL=1 SAVE="$cache_arch-cache-preflight-off-funnel" scripts/cache-gate.sh)
(cd "$cache_on_tree" && OPTHASH_CRITERION_ROOT="$cache_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" FUNNEL=1 SAVE="$cache_arch-cache-preflight-on-funnel" scripts/cache-gate.sh)
(cd "$cache_off_tree" && OPTHASH_CRITERION_ROOT="$cache_root" CACHE_GATE_CONTROL_BIN="$CACHE_GATE_CONTROL_BIN" FUNNEL=1 LOAD="$cache_arch-cache-preflight-on-funnel" BASELINE="$cache_arch-cache-preflight-off-funnel" scripts/cache-gate.sh)
scripts/snapshot-criterion-pair.sh --criterion-root "$cache_root" --snapshot-root target/cache-gate-evidence --arch "$cache_arch" --comparison preflight-funnel --pair 1 --target funnel_cache_gate --anchor-run "$cache_arch-cache-preflight-off-funnel" --candidate-run "$cache_arch-cache-preflight-on-funnel" --anchor-commit "$cache_off_current_commit" --candidate-commit "$cache_on_current_commit" --anchor-manifest "$cache_off_tree/target/cache-gate/$cache_arch/cache-off-current/manifest.json" --candidate-manifest "$cache_on_tree/target/cache-gate/$cache_arch/cache-on-current/manifest.json"
```

Expected: fixed-control SHA-256 remains identical; every std/hashbrown control point movement is within ±5%; repeated layout-linked control shift from Phase 1 is absent; cache-off stable Elastic absolute means are repeatable. Any control breach stops the campaign for harness/host investigation. Rerun only after identifying a host or harness cause; never rerun until favorable and never normalize candidate results by controls.

- [ ] **Step 2: Collect three interleaved full-suite pairs for policy and cache-on**

For each candidate tree (`cache-policy-current`, then `cache-on-current`) run
this sequence independently on both architectures. After each adjacent pair,
run the shown offline comparison and snapshot immediately:

```bash
candidate_name=cache-on-current
candidate_tree=/home/aang/projects/opthash/.worktrees/perf/cache-on-current

(cd "$cache_off_tree" && OPTHASH_CRITERION_ROOT="$cache_root" SAVE="$cache_arch-$candidate_name-off-a1" scripts/bench.sh)
(cd "$candidate_tree" && OPTHASH_CRITERION_ROOT="$cache_root" SAVE="$cache_arch-$candidate_name-c1" scripts/bench.sh)
(cd "$cache_off_tree" && OPTHASH_CRITERION_ROOT="$cache_root" LOAD="$cache_arch-$candidate_name-c1" BASELINE="$cache_arch-$candidate_name-off-a1" scripts/bench.sh)
scripts/snapshot-criterion-pair.sh --criterion-root "$cache_root" --snapshot-root target/cache-gate-evidence --arch "$cache_arch" --comparison "$candidate_name-full" --pair 1 --target all --anchor-run "$cache_arch-$candidate_name-off-a1" --candidate-run "$cache_arch-$candidate_name-c1" --anchor-commit "$cache_off_current_commit" --candidate-commit "$(git -C "$candidate_tree" rev-parse HEAD)" --anchor-manifest "$cache_off_tree/target/cache-gate/$cache_arch/cache-off-current/manifest.json" --candidate-manifest "$candidate_tree/target/cache-gate/$cache_arch/$candidate_name/manifest.json"

(cd "$candidate_tree" && OPTHASH_CRITERION_ROOT="$cache_root" SAVE="$cache_arch-$candidate_name-c2" scripts/bench.sh)
(cd "$cache_off_tree" && OPTHASH_CRITERION_ROOT="$cache_root" SAVE="$cache_arch-$candidate_name-off-a2" scripts/bench.sh)
(cd "$cache_off_tree" && OPTHASH_CRITERION_ROOT="$cache_root" LOAD="$cache_arch-$candidate_name-c2" BASELINE="$cache_arch-$candidate_name-off-a2" scripts/bench.sh)
scripts/snapshot-criterion-pair.sh --criterion-root "$cache_root" --snapshot-root target/cache-gate-evidence --arch "$cache_arch" --comparison "$candidate_name-full" --pair 2 --target all --anchor-run "$cache_arch-$candidate_name-off-a2" --candidate-run "$cache_arch-$candidate_name-c2" --anchor-commit "$cache_off_current_commit" --candidate-commit "$(git -C "$candidate_tree" rev-parse HEAD)" --anchor-manifest "$cache_off_tree/target/cache-gate/$cache_arch/cache-off-current/manifest.json" --candidate-manifest "$candidate_tree/target/cache-gate/$cache_arch/$candidate_name/manifest.json"

(cd "$cache_off_tree" && OPTHASH_CRITERION_ROOT="$cache_root" SAVE="$cache_arch-$candidate_name-off-a3" scripts/bench.sh)
(cd "$candidate_tree" && OPTHASH_CRITERION_ROOT="$cache_root" SAVE="$cache_arch-$candidate_name-c3" scripts/bench.sh)
(cd "$cache_off_tree" && OPTHASH_CRITERION_ROOT="$cache_root" LOAD="$cache_arch-$candidate_name-c3" BASELINE="$cache_arch-$candidate_name-off-a3" scripts/bench.sh)
scripts/snapshot-criterion-pair.sh --criterion-root "$cache_root" --snapshot-root target/cache-gate-evidence --arch "$cache_arch" --comparison "$candidate_name-full" --pair 3 --target all --anchor-run "$cache_arch-$candidate_name-off-a3" --candidate-run "$cache_arch-$candidate_name-c3" --anchor-commit "$cache_off_current_commit" --candidate-commit "$(git -C "$candidate_tree" rev-parse HEAD)" --anchor-manifest "$cache_off_tree/target/cache-gate/$cache_arch/cache-off-current/manifest.json" --candidate-manifest "$candidate_tree/target/cache-gate/$cache_arch/$candidate_name/manifest.json"
```

Repeat the Step-1 control, Elastic, and Funnel `SAVE` → explicit
`LOAD/BASELINE` → snapshot block around each `ai/ci` pair with unique
comparison/pair names. Discard/rerun the whole pair if either fixed control
exceeds 5%; preserve rejected snapshots under `discarded/`, do not overwrite
them, substitute full-suite controls, or normalize.

- [ ] **Step 3: Collect three default scaled-insert pairs**

Use the same alternating pattern with `BENCH=scaled_insert` for 100K, 1M, and
10M in both policy and cache-on trees. Immediately after each adjacent pair run
`BENCH=scaled_insert LOAD="$candidate_run" BASELINE="$anchor_run"
scripts/bench.sh`, then invoke `snapshot-criterion-pair.sh --target
scaled_insert` with the matching pair number/manifests. Do not use
`SCALED_INSERT_SIZES` overrides as evidence. Pair every candidate directly with
cache-off original. Around each scaled pair, repeat the Step-1 control,
Elastic, and Funnel `SAVE` → explicit `LOAD/BASELINE` → immutable snapshot
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
CACHE_GATE_PERF_BIN=/absolute/path/from/manifest
CACHE_GATE_CAMPAIGN_ROOT=/absolute/shared/cache-gate-campaign-contracts
CACHE_GATE_CAMPAIGN_KEY=elastic-signature-cache-cache-off-vs-on
for op in elastic-insert elastic-get funnel-insert funnel-get; do
    for repetition in 1 2 3; do
        CACHE_GATE_PERF_BIN="$CACHE_GATE_PERF_BIN" \
        CACHE_GATE_CAMPAIGN_ROOT="$CACHE_GATE_CAMPAIGN_ROOT" \
        CACHE_GATE_CAMPAIGN_KEY="$CACHE_GATE_CAMPAIGN_KEY" \
            scripts/cache-gate-perf.sh --manifest /absolute/manifest.json \
            --operation "$op" --iterations 100 --repetition "$repetition"
    done
done
```

Use this one absolute campaign root and key unchanged in both immutable
anchor/candidate worktrees; a different comparison campaign requires a new key.

Require cache-on Elastic median cycles and instructions `<= +0.02` versus
cache-off and unchanged Funnel exact direction/count gates; no adverse cache-/
branch-miss direction may be unexplained by raw repetition noise. Preserve each
`perf stat -x,` CSV and compute medians from operation-specific files only.

- [ ] **Step 7: Audit completeness before making any decision**

Expected evidence set per architecture: immutable control/Elastic/Funnel
preflight snapshots; three policy-vs-off and three on-vs-off full snapshots;
three matching scaled snapshots; both absolute JSON trees; pair manifests and
verified hashes; stable address/alignment/link maps; assembly manifests; x86
Callgrind; operation-specific AArch64 counters. Missing architecture, Funnel,
snapshot, manifest, or hash keeps decision `HOLD`, not `PASS`.

### Task 6: Fresh Review, Retain/Revert, and Evidence Commit

**Files:**
- Create: `docs/performance/2026-07-21-elastic-candidate-signature-cache.md`
- Modify on rejection: `src/common/exact/probe.rs`, `src/elastic.rs`, harness files as directed by reviewer

**Interfaces:**
- Consumes: complete Task 5 raw evidence and immutable commit graph.
- Produces: one fresh reviewer decision, retained policy-false scaffold or ordered reverts, and the exact accepted evidence commit consumed by the counter-PRF bakeoff.

- [ ] **Step 1: Write the evidence record from raw files**

Create the document with these literal top-level fields:

```markdown
# Elastic Candidate Signature Cache Evidence

- Original source commit: `<40-hex>`
- Cache-off commit: `<40-hex>`
- Cache-policy commit: `<40-hex>`
- Cache-on commit: `<40-hex>`
- Cache-on production diff SHA-256: `<64-hex>`
- Decision: `HOLD|ACCEPT|REJECT`
```

Then include:

1. Host/CPU/kernel/rustc/Criterion/CodSpeed/perf identity for both architectures.
2. Fixed-control executable paths, Cargo/lock hashes, stable Elastic/Funnel
   addresses/alignment/link maps, preflight snapshot paths, and every discarded
   adjacency.
3. Three immutable full-suite snapshot paths per comparison/architecture with
   run names, commits, manifest hashes, baseline/candidate ns, point, 95%
   low/high, and control movements.
4. Three immutable 100K/1M/10M scaled snapshot paths per comparison/architecture.
5. Layout sizes/offsets; normalized hot-body hashes; return ABI; stack frames; spills; calls; one-signature and lazy-get findings.
6. Exact per-operation x86-64 Callgrind counts and AArch64 cycles/instructions/cache/branch counters.
7. A gate table with one row per required threshold and literal pass/fail evidence.
8. Limitations and missing evidence; never infer a passing cell.

- [ ] **Step 2: Obtain a fresh reviewer decision**

Give reviewer original design, three commits, source diffs, all raw JSON/manifests, evidence draft, and exact gates. Reviewer returns one of:

- `ACCEPT`: policy-false codegen is original, cache-on carrier passes both architectures, one-signature/get/ABI/lifecycle gates pass;
- `REJECT-CARRIER`: cache-on fails correctness, ABI, or performance; revert carrier/policy production changes;
- `REJECT-HARNESS`: control/stable-layout evidence is invalid; repair harness and restart Task 1;
- `HOLD`: evidence is incomplete, including either missing native architecture.

Record reviewer path and verdict verbatim in the evidence document. No author self-approval.

- [ ] **Step 3: Retain only on ACCEPT**

On `ACCEPT`, keep the policy-false scaffold and lifecycle tests; do not merge the forced-true commit. Set document `Decision: ACCEPT`. Verify current production constant remains false and source diff against cache-policy commit is exact. The accepted tree must contain no runtime selector and no forced candidate policy.

- [ ] **Step 4: Revert on rejection in dependency order**

On `REJECT-CARRIER`, revert lifecycle-test commit only if tests depend on removed interface, then revert `refactor: add elastic insert signature policy`; retain the fixed-control/stable-layout harness unless reviewer rejects it independently. Use `git revert <exact-commit>`—never reset—and report recoverability. Set `Decision: REJECT` and name every revert commit.

On `REJECT-HARNESS`, make no carrier decision from invalid timing and do not
repair underneath policy descendants. Preserve all old commits/snapshots for
audit, then create a new branch/worktree from exact `cache_off_source_commit`.
Build and approve a new harness-only cache-off commit there first; only then
replay or reimplement policy/lifecycle commits and rerun every static/timing
gate. Alternatively create explicit lifecycle-then-policy reverts before
harness repair. A tree containing policy source is never named
`cache-off-current`. On `HOLD`, make no retain/revert claim.

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
```

If rejected, use `docs: reject elastic candidate signature cache`. Only the exact accepted message releases the counter-PRF plan's precondition.

- [ ] **Step 6: Hand off immutable anchors to the counter-PRF bakeoff**

Record both full IDs in the evidence doc and task handoff:

- `cache_off_current_commit`: harness-only commit whose production `src/` equals original current;
- `signature_cache_evidence_commit`: accepted policy-false tree and evidence.

Every guarded/Philox survivor and final mixed tree must be compared directly to `cache_off_current_commit`. `cache-policy-current` and `cache-on-current` remain attribution controls only.
