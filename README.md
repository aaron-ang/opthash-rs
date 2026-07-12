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
Reordering* (Farach-Colton, Krapivin, and Kuszmaul, 2025).[^fkk2025]

## Scope

Within a fixed allocation epoch, the maps use the paper's exact finite geometry
and placement rules.[^fkk2025] Deletion, growth, tombstone cleanup, and rare
placement recovery are library API extensions around those epochs. The
deterministic mixers instantiate the construction but do not prove the paper's
randomness assumptions.[^cw1979]

## Layout

Both maps keep key-value entries and 7-bit fingerprint control bytes in one
arena allocation. Full-width SIMD scans follow the SwissTable control-byte
pattern.[^swisstable] Their padding is readable but never selectable as a slot.

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

Elastic uses geometrically halving arrays, paper batches and Case 1/2/3
placement, and the paper's `phi` query order. Its arena tail holds an
epoch-scoped membership filter for definite-negative checks. The filter applies
the SplitMix64 finalizer as a stateless avalanche mixer; it does not instantiate
the stateful generator.[^splitmix64] Funnel scans one ordinary bucket per level
to its first empty slot, then tries B in order and alternates the two C
choices.[^fkk2025]

`capacity()` is the live insertion limit for the current epoch, not the number
of arena slots or allocated bytes. Reserve is configured exactly as
`delta = 2^-d` with `ReserveFraction::from_exponent(d)` in Rust or
`reserve_exponent=d` in Python; the default is `d=3`. Funnel requires `d >= 3`.
Rust float compatibility inputs accept only exact inverse powers of two; all
other values are rejected rather than clamped.

## Rust usage

```bash
cargo add opthash
```

```rust
use opthash::{ElasticHashMap, FunnelHashMap, ReserveFraction};

let mut elastic = ElasticHashMap::new();
elastic.insert("key", 42);
assert_eq!(elastic.get("key"), Some(&42));

let reserve = ReserveFraction::from_exponent(4).unwrap(); // delta = 1/16
let mut funnel = FunnelHashMap::with_capacity_and_reserve(1024, reserve);
funnel.insert("key", 42);
assert_eq!(funnel.remove("key"), Some(42));
```

The default `BuildHasher` wraps `foldhash`.[^foldhash] The crate supports
`no_std` with `alloc`; disable default features and supply a `BuildHasher` for
that configuration.

## Python usage

```bash
pip install opthash
```

```python
from opthash import ElasticHashMap, FunnelHashMap

m = ElasticHashMap.with_options(capacity=1024, reserve_exponent=4)
m["key"] = 42
assert m["key"] == 42

f = FunnelHashMap.with_options(capacity=1024, reserve_exponent=4)
f["key"] = 42
```

## Benchmarks

Benchmarks compare both maps with `std` and use `hashbrown` as the throughput
ceiling.[^hashbrown]

See [benches/README.md](benches/README.md) for the benchmark methodology.

## References

[^fkk2025]: Martín Farach-Colton, Andrew Krapivin, and William Kuszmaul.
    *Optimal Bounds for Open Addressing Without Reordering* (2025):
    [repository paper source](https://github.com/aaron-ang/opthash-rs/blob/2090d09dfa8f4cabc5a65a856a0468a661680cff/paper/main.tex),
    [arXiv](https://arxiv.org/abs/2501.02305).

[^cw1979]: J. Lawrence Carter and Mark N. Wegman. [*Universal Classes of Hash
    Functions*](https://doi.org/10.1016/0022-0000(79)90044-8), for universal
    hashing context; the deterministic mixers here are not claimed to form a
    universal family.

[^swisstable]: Abseil. [SwissTable design
    notes](https://abseil.io/about/design/swisstables), background for the
    control-byte SIMD scans only.

[^hashbrown]: [`hashbrown`](https://docs.rs/hashbrown/0.17.1/hashbrown/), used
    as the benchmark ceiling.

[^foldhash]: [`foldhash`](https://docs.rs/foldhash/0.2.0/foldhash/), wrapped by
    the default `BuildHasher` when the `default-hasher` feature is enabled.

[^splitmix64]: Guy L. Steele Jr., Doug Lea, and Christine H. Flood. [*Fast
    Splittable Pseudorandom Number
    Generators*](https://doi.org/10.1145/2660193.2660195) (2014). The finalizer
    constants follow Sebastiano Vigna's public-domain [`splitmix64.c` reference
    implementation](https://prng.di.unimi.it/splitmix64.c).
