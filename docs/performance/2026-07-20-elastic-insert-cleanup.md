# Elastic Insert Cleanup Evidence

## Result

Phase 1 compact placement and metadata reuse were rejected at the AArch64
control gate and reverted. This is a measurement-validity rejection, not an
attribution of any observed timing movement to either Elastic change. Every
triplet violated the predeclared rule that unchanged `std` or `hashbrown`
controls must remain within 5%. Therefore zero usable raw pairs exist and no
median, performance, or retention claim is made.

Measured immutable commits were anchor
`4fe61a25f7ba29afad3e19bb46a03fc475748543`, compact
`23ce90c7fd36bfdb9db54cce1b6fa2b10b9dcc62`, and final
`ba3beef70bb363c97440917edfab77f5aa86664e`. Each full suite used the shared
Criterion root and `scripts/bench.sh` on native AArch64. Run order was
`a1,c1,f1 / f2,c2,a2 / a3,c3,f3`.

## Raw pairs and discarded controls

Each pair below has 72 preserved raw `change/estimates.json` files under
`target/task4-evidence-logs/raw-change/<pair>/target/criterion/`. Point and
interval values are fractional time changes directly from those files; for
example `+0.050` is +5.0%. Every listed pair is invalid for acceptance or
attribution because at least one unchanged control crosses the ±5% rule.

| Architecture | Change | Pair | Baseline run | Candidate run | Controls beyond 5% | Decisive control evidence (point; 95% low, high) |
| --- | --- | --- | --- | --- | ---: | --- |
| aarch64 | compact-vs-anchor | 1 | `aarch64-cleanup-anchor-a1` | `aarch64-cleanup-compact-c1` | 3 | `insert_std` +0.698864; +0.647766, +0.754065. `get_hit_sequential_latency_1K_std` +0.122728; +0.121505, +0.124134. `mixed_hashbrown` +0.050270; +0.044841, +0.055490. |
| aarch64 | compact-vs-anchor | 2 | `aarch64-cleanup-anchor-a2` | `aarch64-cleanup-compact-c2` | 3 | `mixed_std` -0.069648; -0.074040, -0.064857. `mixed_hashbrown` -0.090989; -0.097702, -0.084837. `get_hit_sequential_latency_1K_std` +0.121540; +0.120333, +0.122688. |
| aarch64 | compact-vs-anchor | 3 | `aarch64-cleanup-anchor-a3` | `aarch64-cleanup-compact-c3` | 5 | `mixed_std` +0.093723; +0.086299, +0.100628. `mixed_hashbrown` +0.175476; +0.165333, +0.185594. `get_hit_sequential_latency_1K_std` +0.118475; +0.114670, +0.120829. 10M randomized std/hashbrown: -0.077788/-0.070914. |
| aarch64 | combined-final-vs-anchor | 1 | `aarch64-cleanup-anchor-a1` | `aarch64-cleanup-final-f1` | 12 | `get_hit_sequential_latency_1K_std` +0.370769; +0.370164, +0.371545. |
| aarch64 | combined-final-vs-anchor | 2 | `aarch64-cleanup-anchor-a2` | `aarch64-cleanup-final-f2` | 13 | `get_hit_sequential_latency_1K_std` +0.370915; +0.370287, +0.371693. |
| aarch64 | combined-final-vs-anchor | 3 | `aarch64-cleanup-anchor-a3` | `aarch64-cleanup-final-f3` | 13 | `get_hit_sequential_latency_1K_std` +0.368677; +0.364254, +0.371230. |
| aarch64 | metadata-vs-compact attribution | 1 | `aarch64-cleanup-compact-c1` | `aarch64-cleanup-final-f1` | 13 | `get_hit_sequential_latency_1K_std` +0.220927; +0.219436, +0.222366. |
| aarch64 | metadata-vs-compact attribution | 2 | `aarch64-cleanup-compact-c2` | `aarch64-cleanup-final-f2` | 12 | `get_hit_sequential_latency_1K_std` +0.222351; +0.220974, +0.223655. |
| aarch64 | metadata-vs-compact attribution | 3 | `aarch64-cleanup-compact-c3` | `aarch64-cleanup-final-f3` | 11 | `get_hit_sequential_latency_1K_std` +0.223699; +0.222555, +0.224832. |

This table deliberately does not collapse invalid pairs into medians. Raw
candidate means remain in the named Criterion baseline directories; raw change
intervals are in the preserved pair snapshots above.

## Reviewer rationale and decision

`task-4-control-review.md` rejected the variants without a fourth timing
campaign. The decisive 1K ordered-control trace is stable within a commit
family but shifts by binary identity:

| Tree | Absolute means (ns) | Across-run range |
| --- | --- | --- |
| anchor | 6.243146, 6.243192, 6.253730 | 0.17% of mean |
| compact | 7.009354, 7.001987, 6.994640 | 0.21% of mean |
| final | 8.557909, 8.558888, 8.559337 | 0.017% of mean |

The compact shift is about +12% and the metadata delta about +22%, both far
outside the control gate and their intervals. Reversing the middle triplet did
not remove the shift. The reviewer found no label, commit, lock, or harness
integrity error; binary/layout sensitivity is the leading explanation, not a
proven mechanism. Accepting a favorable rebuild would break attribution.

Task-4 case 4 therefore applies: reject combined final, revert metadata first,
then revert original compact placement commit (not the metadata-revert commit).
Reverts are `07d83d51c7a99601414cd670ba3a16ed963e47c9` and
`ff07edfbda5135582c8b121a082b83d1bd6d4003`.

## Decision table

| Architecture | Change | insert median | get-hit median | ordered-get median | worst latency-size result | Callgrind instructions | perf counters | decision |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| aarch64 | compact-vs-anchor | invalid controls | invalid controls | invalid controls | invalid controls | not run | not run | reject and revert placement |
| aarch64 | combined-final-vs-anchor | invalid controls | invalid controls | invalid controls | invalid controls | not run | not run | reject and revert metadata and placement |
| aarch64 | metadata-vs-compact | invalid controls | invalid controls | invalid controls | invalid controls | not run | not run | no independent attribution accepted |
| x86-64 | all | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | no pinned executable x86-64 host discovered |

## Discarded controls

All nine AArch64 comparisons are discarded. Their exact raw control evidence
is the preceding table and the 648 preserved JSON snapshots. No arithmetic
normalization or subtraction of control drift was applied.

## Scaled insert

The final-tree scale run completed before control rejection; it is retained as
raw, non-decision evidence only. Values are `mean.point_estimate` nanoseconds
from the named JSON files:

| Run | Operation | Point estimate ns | 95% low ns | 95% high ns |
| --- | --- | ---: | ---: | ---: |
| `aarch64-cleanup-final-scale` | `insert_scale_100K_elastic` | 3286314.097333334 | 3285300.4014500002 | 3287360.0595333325 |
| `aarch64-cleanup-final-scale` | `insert_scale_1M_elastic` | 47167500.38 | 47134652.146125 | 47200356.90125 |
| `aarch64-cleanup-final-scale` | `insert_scale_10M_elastic` | 1587717277.9 | 1586325166.0 | 1589276135.4275 |

## Counters, Callgrind, and assembly

Not run. The control gate rejected both variants before corroboration could be
meaningful. No counter, Callgrind, or assembly cells are inferred.

## Cross-architecture limitation

Only native AArch64 was available. An installed Rust `x86_64` target is not an
executable pinned x86-64 host. Project configuration and environment exposed
no pinned x86-64 endpoint, so no x86 transfer, timing, Callgrind, or assembly
substitution occurred.
