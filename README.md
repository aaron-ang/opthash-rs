# opthash

[![Crates.io](https://img.shields.io/crates/v/opthash?logo=rust&label=crates.io)](https://crates.io/crates/opthash)
[![PyPI](https://img.shields.io/pypi/v/opthash?logo=pypi&logoColor=white&label=pypi)](https://pypi.org/project/opthash/)
[![MSRV](https://img.shields.io/crates/msrv/opthash?logo=rust)](https://crates.io/crates/opthash)
[![Python](https://img.shields.io/pypi/pyversions/opthash?logo=python&logoColor=white)](https://pypi.org/project/opthash/)
[![CI](https://github.com/aaron-ang/opthash-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/aaron-ang/opthash-rs/actions/workflows/ci.yml)
[![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://codspeed.io/aaron-ang/opthash-rs?utm_source=badge)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

opthash provides Rust hash maps and sets based on **Elastic Hashing** and
**Funnel Hashing**, two open-addressing algorithms introduced in
[_Optimal Bounds for Open Addressing Without Reordering_](https://arxiv.org/abs/2501.02305).
It turns the paper's fixed-table constructions into familiar collection APIs
that can be used in real programs.

> [!IMPORTANT]
> opthash is experimental. It is intended for evaluating and improving these
> algorithms, not as a drop-in performance replacement for `std::HashMap` or
> `hashbrown`. Benchmark and test it against your own workload before adopting
> it in production.

## Features

- `ElasticHashMap`, `ElasticHashSet`, `FunnelHashMap`, and `FunnelHashSet`
- Familiar map, set, entry, iterator, and collection APIs
- Paper-faithful placement during normal fixed-size operation
- Configurable spare capacity, hashers, and allocators
- `no_std` support with `alloc`
- Optional Python bindings with typed map and set APIs

## Quick start

Add opthash to a Rust project:

```bash
cargo add opthash
```

Both algorithms expose the same core collection APIs:

```rust
use opthash::{ElasticHashMap, FunnelHashSet};

let mut scores = ElasticHashMap::new();
scores.insert("Ada", 42);
scores.entry("Linus").or_insert(37);

assert_eq!(scores.get("Ada"), Some(&42));

let mut visited = FunnelHashSet::new();
visited.insert("Paris");

assert!(visited.contains("Paris"));
```

The default configuration uses `foldhash` and keeps one-eighth of the table
available as spare capacity. Most users should start with these defaults.
Advanced users can tune the reserve with `ReserveFraction`, provide another
`BuildHasher`, or use a custom allocator.

To use opthash without `std`, disable default features and provide a hasher:

```bash
cargo add opthash --no-default-features
```

## Choosing an algorithm

Elastic and Funnel use different placement strategies but share the same core
API. Choose the construction you want to explore; switching between them is
straightforward. For current performance results, see the
[benchmark guide](benches/README.md).

Near full load, Funnel answers lookups for absent keys faster than a greedy
group-probing table, and the gap widens as the table fills. Greedy probing
still wins hits and most inserts. See the
[high-load sweep](benches/README.md#high-load-sweep).

## Compared with the paper

opthash preserves the paper's finite geometry, placement rules, and probe order
during normal operation between table rebuilds. A usable dynamic collection
also needs behavior outside the paper's model:

| Topic | Paper | opthash |
| --- | --- | --- |
| Table lifetime | Fixed size | Grows and rebuilds as needed |
| Updates | Insertions only | Also replaces, deletes, clears, and cleans up tombstones |
| Placement | Uses the prescribed candidates | Follows them normally; rare exhaustion can trigger a broader correctness fallback |
| Randomness | Analyzes ideal random choices | Uses concrete deterministic mixing |
| Bounds | Analyzes probe complexity in a fixed-size, insertion-only model | The paper's bounds do not cover deletion, growth, Elastic misses, or wall-clock performance |

These differences preserve normal paper-faithful traces while making the maps
usable as general collections. They also mean the paper's theoretical bounds
should not be read as guarantees for every library operation. See the
[paper source used by this project](https://github.com/aaron-ang/opthash-rs/blob/main/paper/main.tex)
for the exact construction.

## Python

Python bindings expose the same four map and set families:

```bash
pip install opthash
```

```python
from opthash import FunnelHashMap

scores = FunnelHashMap({"Ada": 42})
scores["Linus"] = 37

assert scores["Ada"] == 42
```

Python 3.10 or newer is supported.

## Project resources

- [Rust API documentation](https://docs.rs/opthash)
- [Research paper](https://arxiv.org/abs/2501.02305)
- [Benchmark methodology](benches/README.md)
- [Changelog](CHANGELOG.md)
- [Issue tracker](https://github.com/aaron-ang/opthash-rs/issues)

## License

Licensed under the [Apache License 2.0](LICENSE).
