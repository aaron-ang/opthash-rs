# Paper-Faithful Insert and Counter-PRF Optimization

Status: approved design, pending implementation plan

## Context

PR #130 materially reduced `get` and `insert` costs without changing the
paper-exact placement rules. Its pinned 100K-operation steady-state insert run
measured approximately 28.3 ns/op for Elastic, 12.5 ns/op for Funnel, and
3.7 ns/op for hashbrown. The remaining gap is partly algorithmic: Elastic
intentionally looks ahead across candidate slots, and Funnel may attempt a
bucket in several levels. The paper proves asymptotic probe bounds; it does not
make the current instruction sequence or deterministic pseudorandom function
optimal.

Release assembly also exposes work unrelated to the paper. Elastic's
`choose_slot_for_new_key` currently returns test-only case diagnostics in a
roughly 96-byte result and creates a 208-byte stack frame on the measured
AArch64 build. Production placement needs only the selected level, slot, and
bounded `phi`. Elastic also recomputes the same sidecar metadata-word index on
the membership-check and record paths.

The current probe generator expands a 64-bit key hash with several dependent
two-multiply `mix64` rounds. The paper requires separately addressed random
choices and uniform slot selection, but it does not require that particular
mixer or stable physical destinations between library versions.

## Goals

- Improve ordinary `insert` by at least 10% for Elastic and 5% for Funnel in
  the pinned headline workload.
- Preserve the paper's geometry, batch-transition rules, logical tuple
  enumeration order, first-vacant rules, and exact unbiased range reduction.
- Keep randomized and ordered `get` within 2% of the baseline after accounting
  for unchanged-control noise.
- Add no table metadata and no public API.
- Preserve `no_std`, allocator, MSRV, Miri, and supported-target behavior.
- Make the finite randomness model and its limitations explicit.

## Non-goals

- Matching hashbrown's insert throughput at any cost.
- Changing reserve fractions, level sizes, Funnel bucket sizes, or the paper
  insertion strategy.
- Adding a caller-promised unique-insert or bulk-only API.
- Providing cryptographic randomness or denial-of-service resistance beyond
  the selected `BuildHasher`'s contract.
- Stabilizing iteration order or physical placement across library versions.
- Optimizing deletion, cleanup, or resizing except where a cold split is needed
  to keep ordinary insert compact.

## Paper-Faithful Randomness Contract

The paper models each logical probe as an independent uniform random slot. No
finite deterministic implementation over a 64-bit key hash can literally
instantiate that random oracle. The current implementation already uses an
engineering approximation. A replacement must preserve the same finite
contract:

1. Every supported `(backend, domain, level, logical_probe, rejection_retry)`
   tuple has a checked, non-truncating encoding.
2. Distinct supported tuples within one key stream never reuse an encoded
   counter.
3. A fixed construction seed and key hash deterministically select a full-width
   pseudorandom word for each counter.
4. Backend and special-array domains remain separated.
5. The existing exact reducer remains unchanged: power-of-two ranges use the
   appropriate high word bits, while other ranges use multiply-high plus
   rejection. Conditional on uniform PRF words, neither path introduces
   additional range bias. No modulo-biased recovery is allowed.
6. Rejection exhaustion continues through the existing explicit failure and
   placement-recovery paths.
7. A collision in the caller's 64-bit hash may share a probe stream, as it does
   today. The implementation does not claim collision-free identity over an
   unbounded key universe.

Changing deterministic destinations is permitted. Changing the placement
decision rules or logical tuple enumeration order is not.

## Considered Approaches

### 1. Trace-neutral cleanup only

Compact Elastic's production placement result and reuse prepared metadata
indices while retaining the current PRF. This is the safest option and provides
a clean attribution baseline, but it leaves the dominant routing arithmetic in
both backends unchanged.

### 2. Folded-multiply counter PRF

Prepare an injective backend-key value, encode each logical request as a
counter, and pass the two values through a guarded `wyhash64` two-input mixer.
The ordinary branch is bit-for-bit upstream `wyhash64`; the one key whose first
factor would be zero uses a documented permutation fallback. The
folded-multiply primitive maps well to `mul`/`umulh` on AArch64 and a single
full-width multiply on common x86-64 implementations. Upstream reports
BigCrush and PractRand success for unguarded `wyhash64`.

This removes the current nested lane mixers and has the best expected hot-path
cost among candidates without an ad-hoc one-round construction. Its limitation
is that the backend's structured key/counter stream is not the same stream that
upstream tested, so it still needs its own quality gates.

### 3. Philox2x64 counter PRF

Philox gives a well-studied keyed counter construction. Published Random123
results identify six rounds as the minimum Crush-resistant Philox2x64 variant.
It is the strongest reference design considered here, but its repeated
full-width multiplies are unlikely to beat the current single-insert path.
It remains useful as a statistical and performance control.

### Decision

The original decision was to implement trace-neutral cleanup first, then run an
internal bakeoff between the current PRF, guarded `wyhash64`, Philox2x64-6, and
Philox2x64-10. Exact upstream `wyhash64` and ad-hoc single-fold compositions
remain rejected because valid key values can produce a zero first factor and a
constant stream. Only a candidate that passes correctness, quality, and
performance gates may replace the current PRF. Do not ship runtime PRF
selection or experimental feature flags.

Phase 1 was implemented, reviewed, measured, rejected at its predeclared
unchanged-control gate, and reverted. All nine AArch64 comparisons were invalid
for attribution because candidate-dependent binary layout moved fixed
std/hashbrown controls by more than 5%; no Phase-1 speed or regression claim was
accepted. The retained production tree is the original current implementation.

The first candidate-signature harness at `1080c188a47f02202b6a0878830dbf2947629992`
and its policy diagnostics `b1cabb653cebc5922e84a26cb24db8b58903245d`
and `f4a0d354239a8cf669bb240fcb17474693d7b56f` are also rejected for
attribution. Their stable Elastic wrappers moved because private generic changes
altered the default 16-CGU linker input order. The historical source revert
`5fb56a5e0e55cc093b5ac7035746178bcf023066` and a new explicit revert of
`f4a0d35` remain recoverable audit evidence. This is a harness rejection, not a
carrier-policy rejection; preserve the diagnostic manifests and do not time or
accept their results.

Before PRF candidate work, repair the stable-layout mechanism on a fresh
source-original branch, approve an immutable harness-only `cache-off-v2`, and
then replay the exact policy patch in a fresh commit/worktree. The repaired
graph first pins a three-file docs-remediation commit whose exact parent is
`f4a0d35`; the main line is source-original → replayed harness → replayed exact
docs-remediation edge → cache-off-v2 → policy-replay-v2 → lifecycle-tested
cache-policy-v2, with forced cache-on-v2 as the policy child's attribution
control. The audit revert's exact parent is the docs-remediation commit. Current
policy stores its existing prepared Bloom bits, while guarded/Philox policy
stores one full geometry-independent metadata signature in the same 16-byte
insert-only carrier. Phase 2 stays `HOLD` until the repaired harness, replayed
policy, lifecycle, assembly, and pinned native AArch64/x86-64 gates pass fresh
review.

## Design

### Phase 1: compact Elastic placement (historical, rejected and reverted)

The production placement value will contain only:

- physical level;
- slot within that level;
- bounded `phi` needed to extend the lookup schedule.

`phi` is capped by `QUERY_POSITION_CAP = 1_000_000`, so production stores the
checked value as `u32` rather than `u128`.
`paper_probe` and the detailed `ExactInsertionCase` remain available only to
test builds or are reconstructed by a test-only oracle wrapper. Scalar parity
tests must retain their current diagnostic quality.

The normal no-growth path will remain visibly separate from cold growth and
placement recovery. This keeps resize error handling and panic safety
unchanged while allowing the compiler to keep the compact placement in
registers.

### Phase 1: prepare Elastic metadata once (historical, rejected and reverted)

For one table shape, derive the metadata word index, membership bits, and route
bin from the prepared routing signature once. The insert path may retain an
index or value snapshot across immutable work, but never a pointer or reference
across possible resize. If growth or placement recovery changes the arena or
word count, recompute from the same routing signature before recording.

A single metadata load should provide both the membership result and, when an
exact duplicate search is required, the route-summary mask. The final record
uses the prepared index on the no-growth path. This preserves conservative
false-positive behavior and all clear, clone, delete, and rebuild semantics.

This table-dependent `PreparedMetadataWrite` design is no longer a Phase-2
precondition. Its focused unit and assembly checks passed, but its timing
campaign failed the measurement-validity gate and the code was reverted. The
candidate-specific replacement stores no sidecar index or snapshot: a
compile-time policy selects whether the second word of `PreparedElasticKey`
contains current prepared Bloom bits or a candidate's full metadata signature.
Precheck and record derive the word index from current geometry independently;
ordinary get remains route-only and lazy after H(1,1).

### Phase 2: checked counter encoding

Keep backend-specific encoders so a shared abstraction does not reduce existing
limits or enlarge hot structs.

Funnel retains its existing 64-bit layout:

```text
bits 63..62  domain: ordinary=0, primary=1, fallback-A=2, fallback-B=3
bits 61..16  ordinary level, range 0..2^46-1; zero for special domains
bits 15..8   logical probe, range 0..255
bits 7..0    rejection retry, range 0..255
```

Elastic uses this checked 21-bit layout inside a `u64`:

```text
bits 20..16  ordinary level, range 0..31
bits 15..3   logical probe, range 0..8191
bits 2..0    rejection retry, range 0..7
bits 63..21  zero
counter = (level << 16) | (logical_probe << 3) | rejection_retry
```

For every supported shape, `level_slots <= MAX_ELASTIC_SLOTS <= 2^32` and
`free_slots >= 1`, so the dyadic budget has `ceil(log2(level_slots /
free_slots)) <= 32`. Squaring gives at most 1024 and
`ELASTIC_PROBE_BUDGET_C = 8` therefore bounds a Case 1 budget at 8192. Its
zero-based logical indices end at 8191. Uniform searches are separately capped
by `UNIFORM_SEARCH_CAP = 4096`. Both paths can generate indices beyond the
384-entry query-lane table and later reject the resulting `phi` when it exceeds
`QUERY_POSITION_CAP`; that table remains sufficient only for retained schedule
entries. The retry field covers all words admitted by `RANGE_WORD_CAP = 8`.

Every field boundary and one-past-the-boundary value is covered by exact tests.
Unsupported values return failure; they are never masked or truncated. The
distinct fixed backend seeds separate Elastic's implicit ordinary domain from
Funnel's encoded domains.

Free functions remain owned by `common::exact::probe`; callers use qualified
module paths in accordance with the repository's internal API conventions.

### Phase 2: PRF candidates

Each candidate exposes the existing prepare-then-sample shape:

1. Prepare backend-specific key state from the construction seed and 64-bit key
   hash.
2. Accept a checked encoded counter.
3. Return one deterministic 64-bit word.
4. Feed the word to the unchanged exact range reducer.

The folded-multiply candidate is named `guarded-wyhash64`. Define `mul128(a,
b)` as the low and high halves of the full product and `fold64(a, b)` as those
halves XORed. Let `S0` through `S3` be the pinned upstream secrets already in
the crate. The exact mapping is:

```text
prepared_key = key_hash ^ backend_seed             # injective for fixed seed
a = prepared_key ^ S0                              # retained in prepared state
b = encoded_counter ^ S1
if a == 0:
    word = mix64(encoded_counter ^ S2) ^ S3        # exceptional permutation
else:
    (lo, hi) = mul128(a, b)
    word = fold64(lo ^ S0, hi ^ S1)                # exact upstream branch
```

`mix64` is the crate's current bijective SplitMix64 finalizer, making the
exceptional branch a permutation of the valid counter set rather than a
constant stream. `S1` is not a valid counter in either checked backend layout:
its high bits exclude Elastic, while its Funnel special-domain tag is paired
with nonzero reserved level bits. Compile-time assertions and boundary tests
pin that invariant. Thus neither product factor is zero on the ordinary branch.

The key remains a separate mixer input rather than serving only as the phase of
a Weyl counter stream. Known-answer and algebraic tests cover zero, `u64::MAX`,
every pinned seed and secret, every pairwise XOR of those values, the exact key
that selects the exceptional branch, raw counters equal to each secret, and the
nearest valid encoded counters around those raw patterns. The prepared-key XOR
is a permutation, so distinct key hashes never collapse before branch
selection. Tests at logical indices 4095, 4096, 8191, and the rejected boundary
8192 pin the Elastic budget proof.

Philox candidates use the exact Random123 Philox2x64 construction. Counter lane
zero is `encoded_counter`, counter lane one is zero, the 64-bit Philox key is
`key_hash ^ backend_seed`, and the returned word is output lane zero. The round
multiplier is `0xD2B74407B1CE6E93`; the key schedule uses the upstream
`0x9E3779B97F4A7C15` Weyl increment. Six rounds are the paper's reported minimum
Crush-resistant configuration and are the performance candidate. Ten rounds
are the published extra-safety-margin control; the design does not conflate the
six-round candidate with that stronger setting.

If a candidate formula, lane mapping, round count, or constant changes after
quality testing, that change creates a new named benchmark and quality variant;
results cannot be attributed across formulas.

Constants must come from published upstream constructions or be generated and
documented by a reproducible search. No unexplained magic constants may enter
the hot path. A folded-multiply helper is shared only if release assembly shows
that the abstraction disappears on all representative targets.

The winning prepared state must not enlarge `ElasticTable`, `FunnelTable`,
`Level`, or `BucketLevel`. Temporary key-local state is acceptable only after
checking size, register pressure, and generated code.

## Data Flow

For a normal insert:

1. The public map hashes the key once.
2. The backend prepares routing state once.
3. Elastic prepares candidate-selected key-local insert metadata, derives the
   sidecar location from current geometry for duplicate precheck, and derives
   it again after any growth/recovery for record; Funnel performs its combined
   hit/vacancy bucket scan.
4. The scheduler selects the same paper target as before.
5. The PRF maps each required logical tuple to a word.
6. The unchanged range reducer introduces no additional range bias,
   conditional on the PRF word being uniform.
7. The backend chooses the first vacant candidate required by the paper.
8. The slot, controls, counters, and conservative metadata are updated in their
   existing panic-safe order.

Growth, rejection exhaustion, and exceptional placement stay on their current
cold recovery paths.

## Correctness and Quality Gates

### Deterministic correctness

- Known-answer vectors for every PRF candidate on little- and big-endian
  supported targets.
- Algebraic seed/secret vectors prove injective prepared-key mapping and guard
  against zero-factor, constant-stream, and shifted-stream degeneracies.
- Exhaustive tuple-encoding uniqueness over all library-supported Elastic
  bounds and boundary-focused Funnel tests over its much larger level range.
- Existing scalar-oracle parity for candidate destinations and placement cases.
- Existing exact range-reduction and rejection accounting tests unchanged.
- Map/set parity, entry APIs, clone, clear, resize, tombstones, exceptional
  placement, and panic-safety tests.
- For every guarded/Philox selector composition, the active production path
  must pass the named growth transition, same-size exceptional recovery,
  allocator-failure, complete metadata/summary lifecycle matrix, full
  `cargo test`, and focused growth/recovery Miri tests before benchmarking.
  Candidate vectors or generic forced-policy helpers are insufficient.
- Target-aware module-local snapshots use `size_of`, `align_of`, and
  `offset_of!` for every field of `ElasticTable`, `Level`,
  `ElasticMetadataWord`, `FunnelTable`, `FunnelShape`, `LevelShape`, and
  `FlatStorage`, plus both prepared carriers. Carrier alignment is compared
  with `align_of::<u64>()`, not assumed to be eight on every target.
  `BucketLevel` is explicitly absent in the current tree; if later introduced,
  it receives the same complete snapshot gate.
- Native AArch64/x86-64 tests and ABI evidence are supplemented by Rust 1.88
  `i686-unknown-linux-gnu` `cargo check --lib --no-default-features` and
  test-build (`cargo test --lib --no-run`) evidence. Missing required target
  infrastructure produces `HOLD`, not an inferred pass.
- `cargo test`, Miri, and `pre-commit run --all-files`.

### Statistical quality

Use five fixed-seed serialized traversals:

1. key-major: sequential, random, single-bit, low-bit-only, high-bit-only, and
   repeated-pattern keys at fixed representative counters;
2. counter-major: logical field progressions exercised by representative
   geometries, plus exact boundary progressions, for fixed random and
   algebraic keys;
3. domain-interleaved: ordinary and special domains alternated for each key;
4. strided: valid logical probes and keys visited with fixed odd strides;
5. adversarial: zero, all-ones, seeds, secrets, pairwise secret XORs, and their
   one-bit neighbors crossed with boundary tuples.

For key avalanche, use `2^14` fixed SplitMix-generated bases for each of 64
input bits and compare each base with its one-bit-flipped pair, giving `2^20`
pairs per domain/counter class. Counter avalanche uses the same paired method
for every bit of each encoded field, retaining only pairs for which both tuples
are valid. Raw-word collision and serial/cross-stream tests consume `2^20`
outputs per traversal.

For every input/output-bit avalanche cell, use a two-sided exact binomial test
against `p = 0.5`. Combine all key- and counter-avalanche cells for all declared
classes into one predeclared Holm-Bonferroni family with family-wise rejection
level `1e-6`. This controls false rejection instead of applying an unjustified
fixed interval to only `2^14` trials per cell. Also require no more than two
full-width collisions per `2^20`-word stream and absolute serial or cross-stream
Pearson correlation below `0.005`.

Bucket tests use the actual exact reducer and representative 1K, 100K, and 10M
Elastic/Funnel range sets, coalescing outputs into at most 4096 contiguous bins
whose exact expected counts are proportional to the number of represented
outputs, with every expected count at least 32. Upper-tail chi-square tests form
a second predeclared Holm-Bonferroni family with family-wise rejection level
`1e-6`; both full ordered test families are fixed in source before candidate
results are generated.

Run PractRand through at least 64 GiB on each of the five serialized traversals
for every surviving composition. Run TestU01 BigCrush on key-major,
counter-major, and domain-interleaved streams for the final candidate. Upstream
results for a primitive alone are insufficient. Statistical tests do not prove
paper independence, so documentation must continue to describe the result as
an engineering PRF model.

## Performance Evaluation

Save a fresh pinned original-current anchor only after the stable-layout repair.
Phase-1 compact-placement/table-dependent metadata variants and the
`1080c18`/`b1cabb6`/`f4a0d35` harness-policy manifests remain archived as
rejected/reverted diagnostics, not candidate foundations. Before PRF variants,
measure independently:

1. harness-only `cache-off-v2`, whose production source is byte-identical to
   source-original;
2. freshly replayed, codegen-neutral `cache-policy-v2`, with current policy
   false;
3. forced `cache-on-v2`, isolating the 16-byte full-signature carrier and
   second Bloom derivation;
4. each PRF candidate on the accepted policy scaffold, compared directly with
   `cache-off-v2`.

The fixed std/hashbrown control executable must be independent of the candidate
crate, built once from immutable cache-off original, and byte-identical across
commits. Its absolute path is passed explicitly to every manifest and timing
command. On native Linux ELF only, separate stable-layout Elastic and Funnel
targets plus the profile target expose eight unique `#[inline(never)]` kernels
in constant, target-gated input sections. Rust kernel symbols remain internal;
the checked exported identities are linker-defined reservation-start,
body-end, and reservation-end sentinels,
so the measurement harness adds no Rust `no_mangle`/`export_name` ABI.

A checked GNU ld/LLD scheme uses three target-specific augmenting fragments:
two Elastic reservations, two Funnel reservations, and four profile
reservations. No executable receives empty reservations owned by another
target. Each fragment uses `KEEP`, one page-isolated RX reservation per kernel,
target-derived `CONSTANT(MAXPAGESIZE)`, and `INSERT BEFORE .text`. It uses no hard-coded VMA, replacement default script,
`--section-start`, or post-link address rewriting. A capability probe exercises
the actual Cargo-configured linker and records its path/flavor/version, target,
link arguments, page constants, toolchain, each fragment hash, and a canonical
set hash. Capability tests exercise the exact 2/2/4 shapes with the actual
Cargo linker plus explicit native GNU ld and LLD. Missing or unsupported
linkers, non-ELF hosts, missing native AArch64/x86-64 evidence, invalid PIE/RX
segments, overlaps, or veneers produce `HOLD`; this Linux-only evidence harness
does not narrow the library's supported targets.

Repeat-build proof records the complete rustc argv, explicit default release
`-C codegen-units=16`, emitted object/archive-member inventory, ordered linker
inputs, a CGU-partition fingerprint, and the input owner of every reserved
body. Clean builds must match.
The CGU adversary is a linked, `#[inline(never)]` generic called once during
untimed registration/setup; its unique symbol/section must appear exactly once
outside all reservations, and its object/link-order fingerprints must differ
from clean. An absent or fingerprint-identical adversary is vacuous and fails.

The structural validator requires exactly one body and all three sentinels per
reservation and parses the ELF plus linker map. `reservation_start` is aligned,
`body_end` immediately follows the kept input body, and `reservation_end` is
exactly one capability-derived maximum page after the start. Across every
variant it enforces exact output/input section, reservation start/end and page
offset, actual alignment, zero maximum-page remainder, exact reservation-start
and reservation-end names/addresses, reservation size, and empty veneer/thunk
inventories. It always requires a present, structurally valid `body_end` name,
but its address is exact only for an unchanged kernel.
It parses and structurally validates body end/size, raw and normalized hashes,
direct calls, frame, and spills in every variant: policy-false and unchanged
backend bodies must be exact, while a caller-declared changed backend permits
body-field differences only for its four stable/profile kernels; relaxation
never covers reservation start/end, size, or placement. It also proves
PIE `ET_DYN`, wholly RX `PT_LOAD` ownership, and no RWX or overlap. Stable
Criterion and profile modes accept only an absolute manifest, hash-check its
recorded executable, and execute that binary directly; Cargo, compilation, and
relinking are forbidden between manifest creation and timing. Every build,
manifest, stable SAVE, control SAVE, snapshot, and profile invocation requires
an explicit `--runner-root ABS`; the launcher resolves it to the exact Git
worktree root, authenticates its commit/tree against the manifest where
applicable, roots its outputs there, and records that root in every result.
Caller cwd and the authenticated launcher's own source directory never select
the subject tree. An explicitly absolute shared Criterion evidence root is the
only exception: its result metadata also binds the authenticated subject root,
and it contains no build/map/executable artifacts. The accepted manifest binds absolute ELF-validator,
snapshot-helper, cache-gate launcher, and perf launcher paths to their Git
blobs and SHA-256 hashes; every later call reauthenticates them. Both stable
targets run for combined candidates, and Funnel is mandatory for Funnel-only
compositions. Do not reuse either rejected binary-layout-sensitive A/B shape or
use cache-on-v2 as an acceptance baseline.
Later phases carry each architecture's literal accepted cache-off static
variant, manifest path/hash, and manifest-recorded capability-copy path/hash;
they never synthesize a generic cache-off static directory. Every full-suite and
scaled-insert snapshot runs the canonical helper with the candidate tree as
`--runner-root`, matching the candidate manifest; cache-off appears only as
the anchor manifest, commit, and run.

For each retained variant:

- run the full `speedup` suite;
- inspect exact Callgrind instruction counts for Elastic and Funnel insert/get;
- run pinned `perf stat -x,` through already-manifested no-build profiling
  binaries, separately for Elastic insert/get and Funnel insert/get, with
  identical fixed iteration counts and all setup before counters are enabled;
- inspect hot-function assembly and struct sizes;
- run randomized and ordered mean-latency sweeps from 1K through 10M;
- run the default 100K, 1M, and 10M scaled-insert suite for the final candidate.

Run three interleaved anchor/candidate pairs on pinned AArch64 and x86-64 hosts.
After every adjacent pair—fixed control, stable Elastic, stable Funnel, full
suite, and scaled insert—invoke the authenticated atomic snapshot helper once.
While holding the Criterion-root lock it is the sole executor of one
`LOAD=<candidate> BASELINE=<anchor>` comparison and snapshots before release.
The caller protocol is exactly two SAVE measurements followed by one helper
invocation; no separate caller-side offline comparison is permitted. Every
nested launcher call receives the same authenticated `--runner-root`, which
must equal the candidate manifest's recorded root.
Stable/control comparison execution uses the candidate manifest's exact binary,
never the anchor binary; full/scaled uses the canonical authenticated runner.
The pair manifest records executor path/hash/argv and
`offline_execution_count=1`. Atomically preserve all matching
`change/estimates.json`, both named absolute `estimates.json` trees, both build
manifests/link maps, commit and run names, target, command, executable hashes,
and a verified SHA-256 inventory into a unique architecture/composition/pair
directory. Acceptance reads only these immutable snapshots. Discard and rerun
a pair under a new name if either independent fixed std or hashbrown control
moves by more than 5%; preserve the rejected snapshot and never subtract
control movement from a candidate result.

Every survivor and final campaign requires a positive, never-reused attempt
number and derives one campaign ID from architecture + exact immutable
candidate commit + attempt + literal composition. Its diagnostic/static proof
instances and manifest variants, every SAVE run, comparison, snapshot
destination, and perf campaign use that same ID. Failed roots are preserved;
a retry increments the attempt (and uses its new immutable commit where source
changed), then repeats the whole campaign rather than overwriting or renaming
only one pair.

On each architecture, all three changed-backend insert point estimates must
improve, at least two Criterion 95% change intervals must exclude zero, and the
median raw change must be at most -10% for Elastic and -5% for Funnel. For every
regression gate, each point estimate must be `<= +0.02`, the declared median
must be `<= +0.02` (or the stricter `<= +0.01` for an unchanged backend), and
at least two 95% upper bounds must be `<= +0.02`; a favorable negative lower
bound is never grounds for rejection. Apply those gates independently to
randomized/ordered get, every other public operation, every latency size, and
each scaled size. If a backend remains current—especially Funnel in an
Elastic-only composition—also require exact named Callgrind counts and
byte-identical normalized stable insert/get bodies against original current.

Callgrind instruction counts on x86-64 and pinned hardware counters on AArch64
must corroborate the wall-clock direction. Inspect release assembly on both
architectures for spills, helper calls, and multiply lowering. Any public suite
regression outside these predeclared gates rejects the candidate. If no PRF
candidate passes on both architectures, retain the accepted policy-false
signature-cache scaffold and leave the current PRF in production; the rejected
Phase-1 cleanup remains reverted.

Before Phase 2 starts, the checked-out signature-cache evidence blob must equal
the uniquely accepted evidence commit's blob. Parse exactly one original source,
rejected v1 harness, rejected policy diagnostics, historical revert,
docs-remediation commit/patch/three blobs, policy-revert-v2, replayed harness,
replayed docs, cache-off-v2, policy-replay-v2, cache-policy-v2, cache-on-v2,
literal harness/test-only/production patch hashes and file lists,
cache-on-v2 production-diff hash, three linker-fragment hashes/set hash,
authenticated validator/helper/cache-gate/perf-launcher hashes, both native capability hashes,
both native cache-off-v2 manifest hashes, manifested-no-build mode, and
`ACCEPT` field from that committed blob. Verify every commit exists; the
exact-parent source→replayed-harness→replayed-docs→off→policy-replay→policy and
policy→on/evidence graph; the separate
f4a0d35→docs-remediation→policy-revert-v2 audit line;
source/replay/off/revert production
identity; false policy in the accepted tree; and a true-policy cache-on-v2 tree
differing only by the declared force-true source diff. Require both native ELF
records to contain every structural field above. A string match in a mutable
working-tree document is not evidence.
The preflight exact-counts every schema label, strictly parses every field, and
rejects a missing, malformed, or duplicate field. It compares the rejected-v1
harness, both rejected diagnostics, historical revert, full/test-only/
production policy patch hashes and file lists, and every remaining literal or
authenticated hash/ID against the pinned repository facts; graph/hash checks
alone do not authenticate what the evidence document claims.
Before any source work, the authenticated committed blob must contain exactly
one literal `- Decision: \`ACCEPT\`` line and exactly one literal
`- Stable timing mode: \`manifested-no-build\`` line; narrative substring
matches do not release Phase 2.

## Documentation and Compatibility

Update the hashing documentation and changelog with the new finite PRF model,
its fixed seeds, quality evidence, and the fact that physical placement and
iteration order changed. Public map semantics and source compatibility do not
change. No promise of cryptographic security, adversarial collision resistance,
or stable layout is added. The target-specific page-reservation linker
fragments and ELF
sentinels belong only to the Linux performance targets; production library
builds, non-ELF targets, public symbols, and supported-target policy are
unchanged. Failure to run that evidence harness is a performance-decision
`HOLD`, not a library incompatibility.

## Rollout

1. Preserve Phase-1 and `1080c18`/`b1cabb6`/`5fb56a5`/`f4a0d35`
   diagnostic/reversion evidence and recoverably revert the current policy line
   to source-original.
2. Commit the exact three amended docs on `f4a0d35`; from source-original,
   replay the harness and docs edges, add the checked ELF
   section/sentinel/page-reservation mechanism, and approve immutable
   cache-off-v2 only after native AArch64/x86-64 capability, adversarial,
   repeat-build, PIE/RX/no-veneer, and exact-manifest no-build proof.
3. Replay the exact policy patch in a fresh commit/worktree; prove policy-false
   identity against cache-off-v2, then run forced cache-on-v2 lifecycle,
   assembly, counter, and timing gates. Proceed only after fresh approval.
4. Implement PRF candidates as short-lived internal variants.
5. Run correctness and statistical gates before expensive full benchmarks.
6. Run the full pinned performance gate on surviving candidates, comparing
   each directly with original current.
7. Delete losing variants and all runtime selection machinery.
8. Re-run complete verification and independent review on the single final
   implementation.

## Primary References

- Farach-Colton, Krapivin, and Kuszmaul, *Optimal Bounds for Open Addressing
  Without Reordering*: https://arxiv.org/abs/2501.02305
- wyhash reference implementation: https://github.com/wangyi-fudan/wyhash/blob/master/wyhash.h
- Salmon et al., *Parallel Random Numbers: As Easy as 1, 2, 3*:
  https://www.thesalmons.org/john/random123/papers/random123sc11.pdf
