# opthash

[![Crates.io](https://img.shields.io/crates/v/opthash?logo=rust&label=crates.io)](https://crates.io/crates/opthash)
[![PyPI](https://img.shields.io/pypi/v/opthash?logo=pypi&logoColor=white&label=pypi)](https://pypi.org/project/opthash/)
[![MSRV](https://img.shields.io/crates/msrv/opthash?logo=rust)](https://crates.io/crates/opthash)
[![Python](https://img.shields.io/pypi/pyversions/opthash?logo=python&logoColor=white)](https://pypi.org/project/opthash/)
[![CI](https://github.com/aaron-ang/opthash-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/aaron-ang/opthash-rs/actions/workflows/ci.yml)
[![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://codspeed.io/aaron-ang/opthash-rs?utm_source=badge)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Rust hash maps and sets implementing the finite Elastic Hashing and Funnel
Hashing placement algorithms from _Optimal Bounds for Open Addressing Without
Reordering_ (Farach-Colton, Krapivin, and Kuszmaul, 2025).[^fkk2025]

## Scope

Within a fixed table epoch, both maps use the paper's finite geometry and
placement rules.[^fkk2025] The paper considers a fixed-size, insertion-only
table; opthash adds deletion, growth, tombstone cleanup, and clearing, with each
rebuild or reset beginning a new observable epoch.

The paper's amortized probe-complexity objective concerns successful queries for
stored keys.[^fkk2025] Funnel's greedy negative query follows its insertion path,
but Elastic negative lookup is not the paper's primary optimized quantity.
Deletion over an unbounded update history is a separate model; tombstones and
cleanup epochs here are correctness-preserving library extensions rather than
claims of the insertion-only bounds.[^fkk2025]

Placement recovery handles the unusual case where the prescribed candidates
are full while the map is still below its insertion limit. Elastic first
rebuilds at the same size; if needed, either map can use another free slot and
a broader lookup fallback. This preserves correctness beyond the paper's model.
Likewise, deterministic mixing instantiates the paper's ideal random choices
but does not prove its randomness assumptions.[^cw1979]

## Layout

Both maps keep control bytes and key-value entries in one arena allocation:

```text
Shared   [control bytes | SIMD padding | alignment | key-value entries]
Elastic  [... shared arena ... | membership filter]
```

Each control byte stores slot state and, when occupied, a 7-bit hash
fingerprint. Queries scan them in SIMD-sized groups before inspecting possible
key matches.[^swisstable] Padding makes the final scan safe but is not usable
space; the membership filter is an Elastic-only tail.

```text
ElasticHashMap
  A1 [################] -> A2 [########] -> A3 [####]

FunnelHashMap
  A1 [buckets] -> A2 [buckets] -> ... -> B [individual choices] -> C [two buckets]
```

Elastic batches insertions over geometrically smaller levels, normally choosing
between the current level and the next. Elastic's membership filter avoids exact
duplicate-search work when an inserted hash is definitely new; ordinary queries
follow the paper-derived exact probe schedule.

Funnel tries one key-selected bucket per ordinary level. If they are full, `B`
offers a short sequence of individual slots; `C` alternates between matching
positions in two selected buckets, tending to use the less-filled one.[^fkk2025]

### Capacity and reserve

`capacity()` is the live insertion limit, not the physical slot or byte count.
For `n` slots, the map reserves `floor(delta * n)`, where `delta = 2^-d` is set
with `ReserveFraction::from_exponent(d)` in Rust or `reserve_exponent=d` in
Python.

Both maps default to `d=3` (one-eighth target reserve). This is a library
default, not a paper optimum. Funnel requires `d >= 3`, matching the paper's
`delta <= 1/8` assumption; Elastic accepts any positive representable value.
Larger `d` means less headroom, a higher load limit, and generally more probing.
Float inputs must be exact inverse powers of two and are never clamped.

### Implementation fidelity

opthash derives domain-separated placement streams from fixed wyhash parameters
and maps them into finite ranges without modulo bias.[^wyrand][^lemire2019]
Elastic's membership filter uses a separate SplitMix64-derived mix.[^splitmix64]

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

elastic = ElasticHashMap.with_options(capacity=1024, reserve_exponent=4)
elastic["key"] = 42
assert elastic["key"] == 42

funnel = FunnelHashMap.with_options(capacity=1024, reserve_exponent=4)
funnel["key"] = 42
```

## Benchmarks

Benchmarks compare both maps with `std` and use `hashbrown` as the throughput
ceiling.[^hashbrown]

See [benches/README.md](benches/README.md) for the benchmark methodology.

## References

[^fkk2025]:
    Martín Farach-Colton, Andrew Krapivin, and William Kuszmaul.
    _Optimal Bounds for Open Addressing Without Reordering_ (2025):
    [repository paper source](https://github.com/aaron-ang/opthash-rs/blob/2090d09dfa8f4cabc5a65a856a0468a661680cff/paper/main.tex),
    [arXiv](https://arxiv.org/abs/2501.02305).

[^cw1979]:
    J. Lawrence Carter and Mark N. Wegman. [_Universal Classes of Hash
    Functions_](<https://doi.org/10.1016/0022-0000(79)90044-8>), for universal
    hashing context; the deterministic mixers here are not claimed to form a
    universal family.

[^wyrand]:
    Yi Wang, Diego Barrios Romero, Daniel Lemire, and Li Jin. [_Modern
    Non-Cryptographic Hash Function and Pseudorandom Number
    Generator_](https://github.com/wangyi-fudan/wyhash/blob/e4764a0b637d34d3421a7760affada9288b625a8/Modern%20Non-Cryptographic%20Hash%20Function%20and%20Pseudorandom%20Number%20Generator.pdf).
    The construction seeds, fixed lanes, and membership salt pin the [wyhash 4.3
    defaults and current wyrand/w1rand
    increments](https://github.com/wangyi-fudan/wyhash/blob/e4764a0b637d34d3421a7760affada9288b625a8/wyhash.h#L145-L153).
    Elastic's construction and membership paths reuse one value under separate
    mixers; opthash otherwise uses these only as constants and does not implement
    those algorithms.

[^lemire2019]:
    Daniel Lemire. [_Fast Random Integer Generation in an
    Interval_](https://doi.org/10.1145/3230636), _ACM Transactions on Modeling
    and Computer Simulation_ 29(1), 2019.

[^swisstable]:
    Abseil. [SwissTable design
    notes](https://abseil.io/about/design/swisstables), background for the
    control-byte SIMD scans only.

[^hashbrown]:
    [`hashbrown`](https://docs.rs/hashbrown/0.17.1/hashbrown/), used
    as the benchmark ceiling.

[^foldhash]:
    [`foldhash`](https://docs.rs/foldhash/0.2.0/foldhash/), wrapped by
    the default `BuildHasher` when the `default-hasher` feature is enabled.

[^splitmix64]:
    Guy L. Steele Jr., Doug Lea, and Christine H. Flood. [_Fast
    Splittable Pseudorandom Number
    Generators_](https://doi.org/10.1145/2660193.2660195) (2014). The finalizer
    constants follow Sebastiano Vigna's public-domain [`splitmix64.c` reference
    implementation](https://prng.di.unimi.it/splitmix64.c).
