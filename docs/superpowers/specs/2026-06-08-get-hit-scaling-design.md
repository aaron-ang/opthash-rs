# Get-Hit Latency Scaling — Design

Date: 2026-06-08
Scope: `ElasticTable` and `FunnelTable` lookup hot paths.
Status: design approved, pending spec review.

## Problem

Get-hit latency for both maps grows faster with map size than the SwissTable
ceiling (hashbrown). Measured from the `mean_latency` Criterion sweep at HEAD
(`target/criterion/get_hit_latency_<size>`), u64 keys, foldhash, aarch64
(NEON, GROUP_SIZE=16):

| size | elastic | funnel | hashbrown | std   |
|------|---------|--------|-----------|-------|
| 1K   | 4.90    | 4.30   | 5.26      | 8.96  |
| 10K  | 4.90    | 4.72   | 5.01      | 9.30  |
| 100K | 6.40    | 9.71   | 5.44      | 11.83 |
| 1M   | 18.18   | 16.20  | 11.69     | 35.19 |
| 10M  | 36.24   | 27.95  | 21.29     | 62.65 |

Growth 10K→10M: elastic **7.4×**, funnel **5.9×**, hashbrown **4.3×**. At small
N (in-cache) opthash *beats* hashbrown; at large N (cache-bound) it loses. So the
regression is large-N specific.

## Diagnosis

Large-N get cost is dominated by distinct cache lines touched per hit (each
≈ a DRAM miss at 10M). Counts:

- **hashbrown** ≈ 2 lines (1 ctrl group + 1 slot); flat in N — most hits resolve
  in the first group.
- **funnel** ≈ 2 × ~1.78 levels ≈ **3.6** — only ~41% of hits resolve at L0; the
  rest cascade to L1/L2.
- **elastic** ≈ more — probes *every* populated level; triangular probe drift
  adds groups within a level.

Corroborating signal: funnel's knee at 100K (9.71ns, worse than elastic 6.40)
lands exactly at the L2-spill point. The multi-level structure hurts the moment
the working set exceeds L2.

Key structural fact (from the code): each level's bucket/group index is a **pure
function of `key_hash`** — `bucket_index(key_hash)` (funnel),
`triangular_group_start(key_hash)` (elastic) — independent across levels. But the
lookup loop serializes them: L0 ctrl load → match → branch → *then* L1 ctrl load.
The level ctrl misses run **serial**, not parallel; control dependencies stop the
CPU from running ahead.

## Lever 1 — up-front multi-level ctrl prefetch (primary, transparent, both maps)

Since every level's ctrl address is computable from `key_hash` before any load,
issue prefetches for the deeper levels' ctrl groups *before* scanning L0,
converting serial misses into MLP-parallel ones.

- **Funnel** (`find_slot_location_with_hash`): before scanning L0, loop levels
  `1..=search_limit`, compute each level's ctrl group ptr from
  `bucket_index(key_hash)`, issue a read prefetch. Then run the existing scan.
- **Elastic** (`find_slot_indices_with_hash`): before the level loop, prefetch
  the first probe group ctrl ptr (`triangular_group_start(key_hash)`) of levels
  `1..=max_populated_level`. Then run the existing loop.

**Small-N protection (load-bearing design point):** the prefetch loop iterates
levels `1..=max_populated_level` only. At small N, `max_populated_level == 0` →
loop empty → **zero added instructions**. Prefetch cost is paid only when deeper
levels exist, which correlates with large N. This protects the small-N regime
where opthash already beats hashbrown.

**Honest ceiling:** only the *ctrl* cascade parallelizes. The final slot load
(after fingerprint match) stays serial-dependent and cannot be prefetched ahead.
Expect modest gains (~5–15% @10M), ~0 at small N. Funnel @10M is already 28ns,
far below 1.78 × ~90ns serial — meaningful overlap already exists; the headroom
is the uncovered serial fraction.

**Implementation notes:**
- Portable intrinsic `core::intrinsics::prefetch_read_data` (or stable
  `core::arch::aarch64::_prefetch` behind cfg). Prefer the portable path.
- Gate behind a cargo feature / cfg during the spike so the A/B is clean.

## Lever 2 — get-optimized load knob (secondary, opt-in, both maps)

Lower load factor → more hits resolve at L0 → fewer lines touched.

- **Elastic**: `with_reserve_fraction` already exists (default 0.45). Document /
  surface a get-heavy preset; no new mechanism needed.
- **Funnel**: δ clamps to 1/8 (~87% L0 load). Add a looser-clamp constructor so
  L0 load drops and the L0 hit share rises above ~41%.

Opt-in preset only. Not a default change. Costs slots/key.

## Verification — A/B protocol (gates the whole thing)

Per AGENTS.md methodology, prefetch behind a cfg so it is a clean A/B:

1. `SAVE=anchor scripts/bench.sh` — HEAD baseline.
2. Implement prefetch. `SAVE=prefetch scripts/bench.sh`.
3. `LOAD=prefetch BASELINE=anchor scripts/bench.sh` — read `change/estimates.json`.
4. `BENCH=mean_latency scripts/bench.sh` — the real signal is at 1M/10M, not the
   20K speedup suite. Read `get_hit_latency_<size>` mean estimates for both maps.

**Success gates (all must hold to ship Lever 1):**
- get_hit @1M and @10M: ≥5% improvement for elastic *and* funnel.
- get_hit @1K / @10K: ±0 (no small-N regression).
- speedup suite (20K): get / insert / delete ±0.
- @100K: no regression (guard against the instruction-bound mid-N case).
- controls (std / hashbrown): flat — confirms the run is trustworthy.

If gates fail, Lever 1 is dropped — no ship. Lever 2 stands independently
regardless of Lever 1's outcome.

## Risks

- Prefetch is pure added instructions; if the box is instruction-bound at mid-N
  (100K), it could regress there. Mitigated by gating + the explicit @100K gate.
- aarch64/NEON box only; no AVX2/AVX512 wide-group path. Findings may not
  transfer to x86 — note this in any result writeup.
- Pure-refactor icache/branch-layout swings of 5–50% can masquerade as wins.
  Trust deltas only on the benched path and confirm controls stayed flat.

## Out of scope

- Batch / pipelined `get_many` API (user excluded it this round).
- Default load-factor changes (Lever 2 is opt-in only).
- Layout rework toward a single-region SwissTable-exact structure (defeats the
  elastic/funnel designs).
