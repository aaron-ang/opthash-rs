# opthash

[![Crates.io](https://img.shields.io/crates/v/opthash?logo=rust&label=crates.io)](https://crates.io/crates/opthash)
[![PyPI](https://img.shields.io/pypi/v/opthash?logo=pypi&logoColor=white&label=pypi)](https://pypi.org/project/opthash/)
[![MSRV](https://img.shields.io/crates/msrv/opthash?logo=rust)](https://crates.io/crates/opthash)
[![Python](https://img.shields.io/pypi/pyversions/opthash?logo=python&logoColor=white)](https://pypi.org/project/opthash/)
[![CI](https://github.com/aaron-ang/opthash-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/aaron-ang/opthash-rs/actions/workflows/ci.yml)
[![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://codspeed.io/aaron-ang/opthash-rs?utm_source=badge)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Rust implementations of **Elastic Hashing** and **Funnel Hashing** from _Optimal Bounds for Open Addressing Without Reordering_ (Farach-Colton, Krapivin, Kuszmaul, 2025) — see [References](#references) [^fkk2025].

Both are open-addressing hash maps that achieve optimal expected probe complexity without reordering elements after insertion.

## Data Structures

Both maps share a common core: a single-`Arena` allocation per map indexed by per-level descriptors, 7-bit fingerprint control bytes, SIMD control-byte scans for occupancy + lookup, and tombstone accounting [^swisstable] [^cppcon2017] [^hashbrown]. Per-level salt re-randomization [^cw1979] decorrelates probe paths across levels. The default `BuildHasher` is [`foldhash`](https://crates.io/crates/foldhash) [^foldhash]. The two maps differ in how they probe within a level:

- **`ElasticHashMap<K, V>`** — Levels with geometrically halving capacities, each probed by a SwissTable-style triangular sequence (`(idx + delta) & mask`); inserts follow a per-level probe budget.
- **`FunnelHashMap<K, V>`** — Bucketed levels (paper §5): a key maps to one bucket per level; overflow spills to the next level, not other buckets. Plus a split special array: `primary` (odd-step group probe) and `fallback` (two-choice buckets).

Both maps mirror the `std::collections::HashMap` API. Each starts with zero allocation (`new()`) and grows on demand; the `reserve_fraction` headroom knob is exposed via dedicated constructors.

## Usage

### Rust

```bash
cargo add opthash
```

```rust
use opthash::{ElasticHashMap, FunnelHashMap};

let mut map = ElasticHashMap::new();
map.insert("key", 42);
assert_eq!(map.get("key"), Some(&42));

let mut map = ElasticHashMap::with_capacity_and_reserve_fraction(1024, 0.10);
map.insert("key", 42);
assert_eq!(map.get("key"), Some(&42));

let mut map = FunnelHashMap::with_capacity_and_reserve_fraction(1024, 0.10);
map.insert("key", 42);
assert_eq!(map.get("key"), Some(&42));
```

### Python

```bash
pip install opthash
```

```python
from opthash import ElasticHashMap, FunnelHashMap

m = ElasticHashMap()
m["key"] = 42
assert m["key"] == 42
assert "key" in m and len(m) == 1

m = ElasticHashMap.with_options(capacity=1024, reserve_fraction=0.10)

m = FunnelHashMap.with_options(capacity=1024, reserve_fraction=0.10)
```

## Layout Sketch

```text
Arena (one allocation per map)
==============================

  fp = fingerprint (7-bit control byte)   kv = key-value entry
  __ = empty (CTRL_EMPTY 0x00)            xx = tombstone (CTRL_TOMBSTONE 0x80)
  a tombstoned kv may still sit in its slot physically, but is logically uninit

  Control bytes pack first, then alignment padding so the slot region starts
  at align_of::<SlotEntry<K, V>>(), then the slots:

  arena::ptr ► [fp fp xx __ ... ][fp xx fp __ ...][fp fp ...][  pad  ][kv kv kv ...][kv ... ]
               └─── ctrl L0 ────┘└─── ctrl L1 ───┘└── ... ──┘         └─ slots L0 ─┘└─ ... ─┘
               ▲ each level descriptor caches ctrl_ptr + data_ptr into the arena.

  All slot/ctrl/SIMD ops live on the ArenaSlots trait (src/common/arena.rs).


ElasticHashMap — geometrically halving levels
=============================================

  Box<[Level]> over the arena; each level ~half the previous, probed by a
  SwissTable triangular sequence (idx → idx+1 → idx+3 ... & mask). A full
  level sends the key down to the next:

    L0  [################################]  ~half of all slots
    L1  [################]
    L2  [########]
    L3  [####]
    ...


FunnelHashMap — fixed-width buckets, overflow down the funnel
=============================================================

  Box<[BucketLevel]>; each level is a grid of β-wide buckets. A key hashes
  to one bucket per level (levels salt independently); a full bucket spills
  the key to the next level. β is fixed, so levels differ only in bucket count:

    key
     │  hashed independently to one β-wide bucket per level
     ▼
    L0  [b0][b1][b2][b3][b4][b5] ┐ bucket full?
    L1  [b0][b1][b2]             ▼ rehash to next level
    L2  [b0]
    special ─► primary (group-probed · paper B) → fallback (two-choice · paper C)

  within one level (buckets sit side by side in the ctrl/slot regions):

    ctrl  fp xx fp __ ... fp fp xx __ ...
    slot  kv kv kv __ ... kv kv kv __ ...
          └── bucket 0 ──┘└── bucket 1 ──┘
```

## Benchmarks

See [benches/README.md](benches/README.md) for comparison charts.

## References

[^fkk2025]: Martín Farach-Colton, Andrew Krapivin, William Kuszmaul. _Optimal Bounds for Open Addressing Without Reordering_ (2025). arXiv: <https://arxiv.org/abs/2501.02305>. Establishes the elastic and funnel hashing schemes implemented in [`src/elastic.rs`](https://github.com/aaron-ang/opthash-rs/blob/main/src/elastic.rs) and [`src/funnel.rs`](https://github.com/aaron-ang/opthash-rs/blob/main/src/funnel.rs); the funnel "special array" split into `primary` (group-probed, paper B) and `fallback` (two-choice, paper C) follows the paper's construction directly.

[^cw1979]: J. Lawrence Carter, Mark N. Wegman. _Universal Classes of Hash Functions_ (STOC 1977 / JCSS 1979). DOI: <https://doi.org/10.1016/0022-0000(79)90044-8>. Foundational hash-based probing model the FKK bounds rely on; the per-level `salt` re-randomization in `Level`/`BucketLevel` (see `level_salt` in [`src/common/math.rs`](https://github.com/aaron-ang/opthash-rs/blob/main/src/common/math.rs)) follows the universal-hashing assumption.

[^swisstable]: Abseil. _SwissTable design notes_. <https://abseil.io/about/design/swisstables>. Source of the 7-bit fingerprint control-byte layout + SIMD group scans used by the shared `ArenaSlots` trait (see [`src/common/arena.rs`](https://github.com/aaron-ang/opthash-rs/blob/main/src/common/arena.rs), [`src/common/control.rs`](https://github.com/aaron-ang/opthash-rs/blob/main/src/common/control.rs), [`src/common/simd.rs`](https://github.com/aaron-ang/opthash-rs/blob/main/src/common/simd.rs)) and the triangular `(idx + delta) & mask` probe sequence used in `Level::triangular_group_start`.

[^cppcon2017]: Matt Kulukundis. _Designing a Fast, Efficient, Cache-friendly Hash Table, Step by Step_ (CppCon 2017). <https://www.youtube.com/watch?v=ncHmEUmJZf4>. Talk introducing the SwissTable design referenced above.

[^hashbrown]: `hashbrown` — Rust port of SwissTable. <https://github.com/rust-lang/hashbrown>. Used as the absolute throughput ceiling in the Criterion benches (see [benches/README.md](benches/README.md)).

[^foldhash]: `foldhash` crate. <https://crates.io/crates/foldhash>. Default `BuildHasher` (`foldhash::fast::RandomState`) wired up in [`src/common/mod.rs`](https://github.com/aaron-ang/opthash-rs/blob/main/src/common/mod.rs).
