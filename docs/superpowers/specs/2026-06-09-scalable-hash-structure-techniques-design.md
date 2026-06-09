# Scalable Hash-Structure Techniques - Design

Date: 2026-06-09
Scope: `ElasticTable`, `FunnelTable`, and optional storage-layout variants.
Status: draft for review.

## Problem

The current maps already use the usual practical hash-table wins: compact control
bytes, 7-bit fingerprints, SIMD group scans, contiguous metadata, per-level hash
salts, and one backing arena. The remaining scalability problem is not basic
collision filtering. It is that elastic and funnel lookups often touch multiple
independent level regions before reaching the payload slot.

Stored local Criterion results at HEAD show the shape:

| workload | hashbrown | elastic | funnel |
|----------|-----------|---------|--------|
| get_hit @ 10M | 18.0 ns | 41.6 ns | 61.7 ns |
| get_hit @ 100K | 3.49 ns | 7.15 ns | 12.58 ns |
| load factor 85%, 100K | 4.08 ns | 11.24 ns | 9.45 ns |

The research takeaway is consistent across SwissTable, F14, cuckoo hashing,
cache-efficient filters, and cache-oblivious structures: scalable data
structures reduce unpredictable memory accesses, scan compact metadata first,
and group the data needed by one query into as few cache lines as possible.

Unconditional cross-level prefetch has already been tried and reverted. It
regressed because it fetched deeper-level cache lines speculatively, often for
hits that resolved earlier, increasing memory bandwidth pressure. Future work
must reduce the number of authoritative probes or make each probe more likely to
fetch useful data.

## References

- Abseil SwissTable design notes: 7-bit metadata, SIMD candidate filtering,
  and probing through metadata before payload comparison.
  <https://abseil.io/about/design/swisstables>
- Folly F14: chunked SIMD search, high-load chunk probing, overflow counts, and
  separate value-vector storage for larger entries.
  <https://github.com/facebook/folly/blob/main/folly/container/F14.md>
- Farach-Colton, Krapivin, Kuszmaul: elastic and funnel hashing foundations.
  <https://arxiv.org/abs/2501.02305>
- Pagh and Rodler cuckoo hashing: two independent lookup locations can be issued
  in parallel, but the design relies on relocation.
  <https://courses.cs.umbc.edu/undergraduate/341/spring08/projects/proj4/pagh01cuckoo.pdf>
- Herlihy, Shavit, Tzafrir hopscotch hashing: bounded neighborhood displacement
  preserves locality at high load, but also relies on relocation.
  <https://people.csail.mit.edu/shanir/publications/disc2008_submission_98.pdf>
- Bender, Kuszmaul, Kuszmaul graveyard hashing: tombstone policy can materially
  change high-load behavior.
  <https://arxiv.org/abs/2107.01250>
- Bender, Kuszmaul, Zhou rainbow hashing: classical open addressing can support
  high load with improved query/update bounds, but as a new design family.
  <https://arxiv.org/abs/2409.11280>
- Cache-efficient filters and quotient filters: compact filters win by limiting
  each query to one or two nearby cache lines.
  <https://arxiv.org/abs/1911.08374>

## Design Goals

- Improve large-N `get_hit` and `get_miss` by reducing cache-line touches per
  lookup.
- Keep every idea independently benchmarkable. No combined landing until the
  individual counter movement is understood.
- Preserve the public API unless a variant is explicitly documented as opt-in.
- Prefer data-structure changes with measurable cache-miss or instruction-count
  movement over cosmetic refactors.
- Avoid unconditional prefetch and other bandwidth-increasing tricks unless a
  benchmark proves they reduce total misses.

## Candidate A: Per-Level Routing Filters

### Idea

Add compact per-level membership filters that answer: "Could this key be in this
level?" A negative answer skips the authoritative control-byte probe for that
level. A positive answer falls through to the existing level lookup. The filter
never answers the public query; it only routes around level probes.

This is most useful for `ElasticTable`, whose lookup probes every populated
level in order. It can also help `FunnelTable` once a bucket overflows and the
lookup must descend, but funnel's exact bucket-stop semantics make Candidate B
the first funnel target.

### Shape

- Add a compact filter region per level, built and cleared with the existing
  arena or as a separate allocation during the spike.
- Use one hash already available from the map lookup. Derive filter positions by
  bit mixing, not by invoking the hasher again.
- Target a cache-resident or cache-line-blocked layout. A filter that causes one
  random DRAM load per skipped level is not useful.
- Start with `ElasticTable` only. If it cannot win there, it is unlikely to win
  for funnel.

### Correctness

- Insert sets the level's filter bits after the slot is chosen.
- Remove may either leave stale bits or use a counting filter. A stale-bit
  filter is simpler and cannot cause false negatives, but it degrades under
  churn and after many removals.
- Resize/repack rebuilds filters from live entries, restoring quality.
- A filter false positive costs the current lookup path. A false negative is a
  correctness bug and must be impossible.

### Benchmark Gate

Spike gate:

- `get_hit_latency` @ 1M and 10M: elastic improves by at least 10%.
- `get_miss` speedup suite: elastic improves by at least 10%.
- `insert`, `delete_heavy`, and `mixed`: no regression beyond the control noise
  floor unless the filter is explicitly opt-in.
- `std` and `hashbrown` controls stay flat in the A/B comparison.

If stale filters win initially, add a delete-churn benchmark before shipping.

## Candidate B: Funnel Bucket Overflow Counters

### Idea

F14 tracks overflow counts per chunk. A lookup can stop when the current chunk
has no active overflow, even if local metadata would otherwise force probing to
continue. Funnel levels are naturally bucketed, so a per-bucket overflow counter
is a direct fit.

Today, a full funnel bucket has only local control bytes. If no empty byte is
present, lookup must continue because a key might have spilled to a deeper level.
An exact `overflow_count == 0` allows a clean stop after the current bucket.

### Shape

- Add one counter per funnel bucket, initially `u8` with saturating overflow to a
  fallback "unknown" value if needed.
- On insert, when an attempted bucket is full and the key spills deeper,
  increment that bucket's counter.
- On remove, for the removed key's prior spill path, decrement the counters for
  buckets it depended on.
- On resize/repack, rebuild counters exactly by reinserting live entries.

### Correctness

An overflow counter means "there exists at least one live key that tried this
bucket and was stored later." Lookup may stop at a full bucket only when the
counter is zero. Tombstones remain separate: a bucket with tombstones may still
need existing control-byte behavior for local search correctness.

The main risk is decrement correctness on remove. The implementation must know
which previous buckets the removed key failed before reaching its actual
location. This is derivable from the key hash and the removed `SlotLocation`.

### Benchmark Gate

- `get_miss`: funnel improves by at least 15%.
- `mixed` and `delete_heavy`: funnel improves or stays within noise.
- `get_hit_latency` @ 100K, 1M, 10M: no regression; any win is additive.
- Counter memory overhead is reported as bytes per live key at default load.

This candidate is a practical first funnel change because it is much smaller
than a layout rewrite and has exact semantics.

## Candidate C: Cache-Line Interleaved Funnel Metadata

### Idea

Instead of laying out `ctrl_L0 | ctrl_L1 | ...`, place control bytes for related
funnel buckets near each other so a lookup's likely descent path fetches adjacent
metadata. This applies the cache-aware and cache-oblivious principle: physical
layout should match the query path, not just the logical level order.

### Shape

The spike starts with a metadata-only layout:

- Keep slot storage unchanged.
- Remap control storage so a level-0 bucket's control group and one or more
  descendant bucket control groups are in the same cache-line neighborhood.
- Preserve existing `BucketLevel` APIs by changing pointer/index translation
  behind helpers, not by duplicating lookup code.

The full version may need to change funnel bucket partitioning so child buckets
are deterministic descendants of parent buckets. That is a deeper algorithmic
change and must not be mixed with the metadata-only spike.

### Correctness

This is a layout-preserving transformation: same candidate buckets, same
slot ownership, same insert and lookup rules. The first spike must prove that
address translation and iteration remain correct before changing hashing.

### Benchmark Gate

- `get_hit_latency` @ 1M and 10M: funnel improves by at least 15%.
- `get_miss`: funnel improves or stays flat.
- `insert`: no regression beyond 5%, because inserts also scan buckets in order.
- `iter`, `drain`, `extract_if`: no meaningful regression from less-linear
  control layout.

If metadata-only interleaving does not move cache misses, do not proceed to the
hash/layout rewrite.

## Candidate D: Split Key/Value Storage for Large Entries

### Idea

F14 switches between inline storage and value-vector storage. For larger entries,
the hash table stores compact indexes while values live packed elsewhere. opthash
currently stores `SlotEntry<K, V>` inline; probing a candidate slot can pull a
large value into cache just to compare the key.

### Shape

Add an opt-in storage policy or a new backend variant, not a default behavior:

- Control bytes remain in the table.
- Slot table stores key plus value index, or full key plus compact value handle.
- Values are packed in a separate vector/arena.
- Remove must either maintain a freelist or swap-remove and update the owning
  slot's index.

### Correctness

The public API returns references into the value storage, so moving values during
remove or rehash must respect Rust aliasing rules and existing iterator behavior.
This is the highest API-risk candidate. It starts with benchmarks and a
prototype for `K = u64, V = [u64; 4]`, not by refactoring the generic map shell.

### Benchmark Gate

- `get_hit_big`: improves by at least 20% for both maps.
- `insert_big`: no regression beyond 10%, or the variant is documented as
  read-heavy only.
- `drain_big` and iteration costs are reported explicitly, because packed value
  order may help or hurt.
- `get_hit` for `u64,u64`: unchanged if this is opt-in.

## Candidate E: Lower-Load Presets

### Idea

Lower load factors reduce the probability of deeper-level hits and long probe
paths. This is not a novel data structure, but it is a direct, measurable
space/time tradeoff and is evaluated before deeper rewrites.

### Shape

- Elastic already exposes `with_reserve_fraction`.
- Funnel clamps `reserve_fraction` to `1/8` for the paper-backed default. Add an
  explicitly named experimental constructor or internal benchmark-only mode if a
  looser funnel load is needed.
- Do not change defaults without benchmark evidence across the full public
  suite.

### Benchmark Gate

- Extend `load_factor.rs` to include named reserve fractions for elastic and
  funnel, not only fill fraction of `capacity()`.
- Report speedup per extra byte/key.
- Ship only documentation or an opt-in constructor unless all default workloads
  improve.

## Candidate F: New Reordering Families

Robin Hood, hopscotch, cuckoo, and rainbow hashing are applicable research ideas
in the broad sense, but they are not incremental improvements to elastic/funnel.
They rely on relocation, multiple homes, or a substantially different insertion
discipline. Treat them as potential new map families only.

Recommended action: do not mix these into the current optimization track. If the
goal becomes "fastest practical map" rather than "practical elastic/funnel
implementation," create a separate design for a third backend.

## Staging

1. Candidate E benchmark sweep: cheapest way to quantify the memory/time frontier.
2. Candidate B for funnel: exact counters, small implementation surface, likely
   wins for misses and churn.
3. Candidate A for elastic: best direct attack on multi-level successful lookups.
4. Candidate C for funnel: high-upside layout work after counters establish a
   cleaner funnel baseline.
5. Candidate D as an opt-in large-payload track.
6. Candidate F only if a new backend is explicitly desired.

## Measurement Protocol

Use the repository A/B harness, not raw `cargo bench`, for any conclusion:

```bash
SAVE=anchor scripts/bench.sh
SAVE=<variant> scripts/bench.sh
LOAD=<variant> BASELINE=anchor scripts/bench.sh
BENCH=mean_latency SAVE=<variant>-lat scripts/bench.sh
```

For each candidate, read:

- `target/criterion/<workload>/<workload>_<impl>/change/estimates.json`
- `target/criterion/get_hit_latency_<size>/get_hit_latency_<size>_<impl>/new/estimates.json`
- Control deltas for `std` and `hashbrown`.

Also run:

```bash
cargo test
pre-commit run --all-files
```

For shipped performance claims, add `perf stat` on a pinned run:

```bash
perf stat -e cycles,instructions,cache-misses,branch-misses scripts/bench.sh -- "get_hit"
```

The expected winning counter is fewer cache misses or fewer loaded bytes per
lookup. A wall-clock improvement without a matching counter movement is suspect.

## Non-Goals

- Retrying unconditional cross-level prefetch.
- Combining multiple candidates before each one has a clean A/B result.
- Changing default load factor or public behavior before measuring the full
  speedup suite.
- Refactoring shared SIMD/control helpers without assembly and benchmark proof.
