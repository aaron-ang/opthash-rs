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

Both maps share a common core: a single-`Arena` allocation per map indexed by per-level descriptors, 7-bit fingerprint control bytes, SIMD control-byte scans for occupancy + lookup, tombstone accounting, and SwissTable-style triangular probing within every level [^swisstable] [^cppcon2017] [^hashbrown]. Per-level salt re-randomization [^cw1979] decorrelates probe paths across levels. The default `BuildHasher` is [`foldhash`](https://crates.io/crates/foldhash) [^foldhash].

- **`ElasticHashMap<K, V>`** — Flat group-probed level with geometrically halving capacities; insertion uses per-level probe budgets.
- **`FunnelHashMap<K, V>`** — Bucketed levels plus a split special array: `primary` (group-probed) and `fallback` (two-choice buckets).

Both maps mirror `std::collections::HashMap`'s API and support the same operations. Each map starts with zero allocation (`new()`) and grows dynamically on demand. The `reserve_fraction` headroom knob is exposed via dedicated constructors.

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

  fp = fingerprint (7-bit control byte)
  kv = key-value entry, __ = empty, xx = tombstone

  All control bytes pack first, then per-K/V-aligned padding, then all slots:

  arena::ptr ► [fp fp fp ...][fp fp fp ...][fp fp ...][  pad  ][kv kv kv ...][kv ... ]
               └─ ctrl L0 ──┘└─ ctrl L1 ──┘└── ... ──┘         └─ slots L0 ─┘└─ ... ─┘
               ▲ each ctrl region starts at u32 offset stamped in its descriptor.

  Each descriptor is a view of: ctrl_offset, data_offset, capacity,
  plus per-shape metadata (salt, mask, etc). All slot/ctrl/SIMD ops live on
  the `ArenaSlots` trait (`src/common/arena.rs`) which implements pointer arithmetic.


ElasticHashMap
==============

  levels: Box<[Level]> (descriptors only)

    Level 0    ctrl_offset, data_offset, capacity (~half of total slots)
    Level 1    geometrically halved
    Level 2    ...

    per-level  group_count, group_count_mask, salt, len, tombstones,
               half_reserve_slot_threshold, budget_cap

  arena:       Arena (the single allocation backing every level above)

  map-wide     len, total_slots, max_insertions, reserve_fraction,
               batch_plan, current_batch_index, batch_remaining,
               max_populated_level, hash_builder, alloc


FunnelHashMap
=============

  levels: Box<[BucketLevel]> (descriptors)

    Level 0
      ctrl region   fp fp __ __ ... fp fp __ __ ... fp ...
      slot region   kv kv __ __ ... kv kv __ __ ... kv ...
                    └── bucket 0 ──┘└── bucket 1 ──┘

    Level 1    (same layout, smaller buckets)

    per-level  bucket_count_mask, bucket_size_log2, salt, len, tombstones

  special: SpecialArray

    primary    group-probed (paper B)
               group_count_mask, len, tombstones

    fallback   two-choice bucketed (paper C)
               bucket_count, bucket_size_log2, len, tombstones

  arena:       Arena (covers every level + both special regions)

  map-wide     len, total_slots, max_insertions, reserve_fraction,
               primary_probe_limit, max_populated_level, hash_builder, alloc
```

## Benchmarks

See [benches/README.md](benches/README.md) for bench target layout, charts, CLI flags, chart regeneration, and flamegraph profiling.

## References

[^fkk2025]: Martín Farach-Colton, Andrew Krapivin, William Kuszmaul. _Optimal Bounds for Open Addressing Without Reordering_ (2025). arXiv: <https://arxiv.org/abs/2501.02305>. Establishes the elastic and funnel hashing schemes implemented in [`src/elastic.rs`](https://github.com/aaron-ang/opthash-rs/blob/main/src/elastic.rs) and [`src/funnel.rs`](https://github.com/aaron-ang/opthash-rs/blob/main/src/funnel.rs); the funnel "special array" split into `primary` (group-probed, paper B) and `fallback` (two-choice, paper C) follows the paper's construction directly.

[^cw1979]: J. Lawrence Carter, Mark N. Wegman. _Universal Classes of Hash Functions_ (STOC 1977 / JCSS 1979). DOI: <https://doi.org/10.1016/0022-0000(79)90044-8>. Foundational hash-based probing model the FKK bounds rely on; the per-level `salt` re-randomization in `Level`/`BucketLevel` (see `level_salt` in [`src/common/math.rs`](https://github.com/aaron-ang/opthash-rs/blob/main/src/common/math.rs)) follows the universal-hashing assumption.

[^swisstable]: Abseil. _SwissTable design notes_. <https://abseil.io/about/design/swisstables>. Source of the 7-bit fingerprint control-byte layout + SIMD group scans used by the shared `ArenaSlots` trait (see [`src/common/arena.rs`](https://github.com/aaron-ang/opthash-rs/blob/main/src/common/arena.rs), [`src/common/control.rs`](https://github.com/aaron-ang/opthash-rs/blob/main/src/common/control.rs), [`src/common/simd.rs`](https://github.com/aaron-ang/opthash-rs/blob/main/src/common/simd.rs)) and the triangular `(idx + delta) & mask` probe sequence used in `Level::triangular_group_start`.

[^cppcon2017]: Matt Kulukundis. _Designing a Fast, Efficient, Cache-friendly Hash Table, Step by Step_ (CppCon 2017). <https://www.youtube.com/watch?v=ncHmEUmJZf4>. Talk introducing the SwissTable design referenced above.

[^hashbrown]: `hashbrown` — Rust port of SwissTable. <https://github.com/rust-lang/hashbrown>. Used as the absolute throughput ceiling in the Criterion benches (see [benches/README.md](benches/README.md)).

[^foldhash]: `foldhash` crate. <https://crates.io/crates/foldhash>. Default `BuildHasher` (`foldhash::fast::RandomState`) wired up in [`src/common/mod.rs`](https://github.com/aaron-ang/opthash-rs/blob/main/src/common/mod.rs).

[^prefetch2007]: Shimin Chen, Anastassia Ailamaki, Phillip B. Gibbons, Todd C. Mowry. _Improving Hash Join Performance through Prefetching_ (ACM TODS 2007). PDF: <https://www.cs.cmu.edu/~chensm/papers/hashjoin_tods_preliminary.pdf>. Motivates the intra-probe issued one group ahead (see [`src/funnel.rs`](https://github.com/aaron-ang/opthash-rs/blob/main/src/funnel.rs)).
