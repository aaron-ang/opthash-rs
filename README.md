# opthash

[![Crates.io](https://img.shields.io/crates/v/opthash?logo=rust&label=crates.io)](https://crates.io/crates/opthash)
[![PyPI](https://img.shields.io/pypi/v/opthash?logo=pypi&logoColor=white&label=pypi)](https://pypi.org/project/opthash/)
[![MSRV](https://img.shields.io/crates/msrv/opthash?logo=rust)](https://crates.io/crates/opthash)
[![Python](https://img.shields.io/pypi/pyversions/opthash?logo=python&logoColor=white)](https://pypi.org/project/opthash/)
[![CI](https://github.com/aaron-ang/opthash-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/aaron-ang/opthash-rs/actions/workflows/ci.yml)
[![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://codspeed.io/aaron-ang/opthash-rs?utm_source=badge)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Rust hash maps and sets implementing the finite Elastic Hashing and Funnel
Hashing placement algorithms from *Optimal Bounds for Open Addressing Without
Reordering* (Farach-Colton, Krapivin, and Kuszmaul, 2025).

## Fidelity and scope

Within a recovery-free, deletion-free paper-comparable prefix of a fixed
allocation epoch, the default maps use the paper's logical geometry, constants,
probe order, and placement rules where the paper fixes them.
There are exactly `n` selectable slots, and at most
`n - floor(delta*n)` distinct insertions; SIMD padding is initialized but never
selectable. Successful insertion in that regime does not move an existing
entry.

The public `HashMap` API also supports updates, negative lookup, deletion,
tombstone reuse and cleanup, growth, and rare placement recovery. Cleanup,
growth, and recovery begin a new observable epoch and may reinsert entries.
Those behaviors, the finite `c=8` Elastic convention, finite caps, and the
concrete deterministic probe generators are library API extensions, so the
crate does not claim that its concrete runs prove the paper's expected or
high-probability bounds.

Probe words are stable and domain-separated, with rejection-based range
reduction that is bias-free conditional on uniform probe words. Elastic uses a
deterministic counter mixer. Funnel uses a cheaper deterministic counter
permutation with separate ordinary, B,
C-A, C-B, and retry counters. Neither construction is a cryptographic PRF, a
universal family, or evidence of independent random words. Unequal keys that
collide under a caller-supplied `BuildHasher` share a probe stream. Correctness
is preserved by exceptional placement and a cold full scan, but constant or
adversarial hashers can reduce operations to linear time.

## Data structures

Both maps use one arena allocation for control bytes and key-value slots,
7-bit fingerprints, SIMD control scans, direct-entry lookup, and tombstones.
The default hasher is [`foldhash`](https://crates.io/crates/foldhash).

- `ElasticHashMap<K, V>` uses exact geometrically halving levels, paper batches
  and Case 1/2/3 insertion, the disclosed squared finite probe budget with
  `c=8`, and the paper's injective `phi` ordering. An epoch-scoped membership
  filter accelerates definite-negative duplicate checks without changing a
  positive query or placement trace.
- `FunnelHashMap<K, V>` uses `alpha=4d+10` ordinary levels and `beta=2d`
  logical slots per bucket for `delta=1/2^d`. It scans an ordinary bucket to
  the first empty or all `beta` slots, samples special array B with
  replacement, then alternates the two C choices with the emptier bucket
  winning and ties going to A.

`capacity()` is the live insertion limit for the current epoch, not the number
of arena slots or allocated bytes. Reserve is an exact dyadic fraction, fixed
within an epoch; the default is `1/8`. Funnel requires a reserve of at most
`1/8` (`d >= 3`). Float compatibility constructors accept only exact inverse
powers of two and never clamp.

## Rust usage

```bash
cargo add opthash
```

```rust
use opthash::{ElasticHashMap, FunnelHashMap, ReserveFraction};

let mut elastic = ElasticHashMap::new();
elastic.insert("key", 42);
assert_eq!(elastic.get("key"), Some(&42));

let reserve = ReserveFraction::from_delta_log2(4).unwrap(); // delta = 1/16
let mut funnel = FunnelHashMap::with_capacity_and_reserve(1024, reserve);
funnel.insert("key", 42);
assert_eq!(funnel.remove("key"), Some(42));
```

The crate supports `no_std` with `alloc`; disable default features and supply a
`BuildHasher` for that configuration.

## Python usage

```bash
pip install opthash
```

```python
from opthash import ElasticHashMap, FunnelHashMap

m = ElasticHashMap.with_options(capacity=1024, delta_log2=4)
m["key"] = 42
assert m["key"] == 42

f = FunnelHashMap.with_options(capacity=1024, delta_log2=4)
f["key"] = 42
```

## Benchmarks

Use `scripts/bench.sh` for pinned, serialized wall-clock evidence; raw
`cargo bench` is intended only for smoke iteration. The harness locks its CPU,
writes compact metadata sidecars for every explicit Criterion target, and keeps
randomized hit traces separate from sequential locality controls. Charts require
clean, complete `speedup` and `mean_latency` metadata. `scaled_insert` is
sidecar-tracked but remains outside `BENCH=all`.

See the [benchmark guide](https://github.com/aaron-ang/opthash-rs/blob/main/benches/README.md)
for the throughput, latency, and scaled-insert workflows.

The source-bound charts report both randomized hits and sequential locality
controls. Their gap shows the cache cost of the paper-faithful scattered probe
order at scale; these host-specific results do not claim parity with
SwissTable.

## References

- Martín Farach-Colton, Andrew Krapivin, and William Kuszmaul. *Optimal Bounds
  for Open Addressing Without Reordering* (2025).
  [Repository source](https://github.com/aaron-ang/opthash-rs/blob/main/paper/main.tex),
  [arXiv](https://arxiv.org/abs/2501.02305).
- Abseil. [SwissTable design notes](https://abseil.io/about/design/swisstables).
- [`hashbrown`](https://github.com/rust-lang/hashbrown), used as the benchmark
  ceiling.
