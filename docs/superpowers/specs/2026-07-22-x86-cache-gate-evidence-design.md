# Native x86-64 Cache-Gate Evidence

Status: approved design, pending implementation plan

## Context

The repaired cache-gate harness is locally approved on native AArch64 at
`061d13da22b89208c801308efd578444c8e9caba` (tree
`24921a941f8c3c26467465b99d6b45ee5912b2da`). Its accepted capability covers
the actual Cargo linker, GNU ld, and LLD for the exact Elastic/Funnel/profile
2/2/4 shapes. Attempt 5 also proves clean-repeat identity, a non-vacuous layout
adversary, and semantic equality with the rejected v1 bodies.

Phase 2 remains on `HOLD` because the same proof is absent on native x86-64.
The local host is AArch64, no native x86-64 Docker or self-hosted runner is
available, and emulation or cross-linking does not satisfy the plan. The
repository can use a GitHub-hosted Ubuntu x86-64 runner, but the immutable
subject commit is not remote and no existing workflow runs or preserves the
Task 2 evidence.

## Goals

- Run Task 2 Step 9 on a genuinely native x86-64 Linux host.
- Keep `061d13d` as the exact subject; the CI-only descendant must not alter its
  tree, binaries, scripts, or manifests.
- Exercise the actual Cargo linker plus native GNU ld and LLD for all 2/2/4
  shapes.
- Produce fresh clean-a, clean-b, and adversary manifests and run both strict
  comparisons.
- Compare the new v2 bodies with the replayed v1 harness using the current
  normalizer and only body size, normalized instructions, calls, frame, and
  spills.
- Preserve sufficient files, hidden probe roots, permissions, logs, hashes,
  and tool versions for an independent local review after the hosted runner is
  gone.

## Non-goals

- Running Criterion, `perf`, or any performance timing.
- Replaying or accepting the candidate signature-cache policy.
- Modifying production source, benchmark bodies, layout fragments, or the
  reviewed cache-gate harness.
- Treating QEMU, cross-compilation, or a container on the AArch64 host as
  native x86-64 evidence.
- Opening a performance PR or deleting remote evidence branches before the
  downloaded artifact receives final review.

## Considered Approaches

### 1. GitHub-hosted evidence workflow (selected)

Push the immutable subject and a separate CI-only descendant. A branch-scoped
`push` workflow runs on `ubuntu-24.04`, checks out the exact subject and v1
replay into separate directories, installs native LLD, runs the proof, then
uploads a tar archive and checksum.

This is the smallest available native path. The workflow commit cannot
contaminate the subject because every proof command runs in the exact subject
checkout and asserts its commit, tree, and cleanliness.

### 2. User-provided x86-64 Linux host

This avoids repository CI changes, but no such host is currently available.
It remains the fallback if hosted Actions cannot supply both native linker
flavors or cannot retain the required evidence.

### 3. Cross-build or emulation

Rejected. It cannot prove native linker discovery, native executable shape, or
the required host contract.

## Design

### Branch and checkout isolation

The orchestration branch is `ci/x86-cache-gate-evidence`, descended from
`061d13d`. Its workflow triggers only on a push to that branch and has
`contents: read` permission. Every referenced Action is pinned by full commit
SHA, checkout disables persisted credentials, and no step receives repository
write permission.

The job creates three independent directories:

- `orchestrator`: the CI descendant containing only design/plan and workflow
  support;
- `subject`: exact `061d13da22b89208c801308efd578444c8e9caba`;
- `v1`: exact replayed v1 harness
  `b0d53234dc051af91fe0321450b3e8312a84e635`.

Before building, the runner must report `x86_64`; `subject` must have the exact
commit and tree above; both subject and v1 checkouts must be clean. Rust is
pinned to 1.95.0, matching the reviewed AArch64 toolchain. The workflow
installs the distribution's native `lld`, then uses a minimal explicit `PATH`
containing the pinned Rust toolchain and system directories. It requires
`command -v ld.lld` to resolve to `/usr/bin/ld.lld`, verifies the owning `lld`
packages with `dpkg-query` and `dpkg -V`, and records their versions. The
linker's exact invocation path, payload hash, symlink chain, `argv0`, and
version are also captured by the capability record.

The reviewed orchestration commit is the exact push target. The job requires
`GITHUB_SHA` to equal its checked-out orchestration commit and records the
orchestration tree plus SHA-256 values for the workflow, runner, and portable
archive verifier. Run provenance contains only an allowlisted set of GitHub
identifiers and tool/package versions; it never dumps the ambient environment
or credentials.

### Proof execution

A small orchestration script accepts absolute subject, v1, and evidence roots.
It never copies code into either checkout.

In `subject` it:

1. runs `scripts/cache-gate-linker-capability.sh`;
2. builds the authenticated fixed-control binary;
3. validates `run_id <= 9223372036854774` and `1 <= run_attempt <= 999`, derives
   the injective signed-64-bit value
   `CACHE_GATE_ATTEMPT = run_id * 1000 + run_attempt`, then builds fresh
   `x86_64-061d13da22b8-attempt-<id>-clean-a`, `clean-b`, and `adversary`
   instances;
4. validates every manifest;
5. runs strict clean-a-to-clean-b and clean-a-to-adversary comparisons;
6. verifies the actual/GNU/LLD 2/2/4 shape matrix, linker traces, clean proof
   equality, and non-vacuous adversary evidence.

In `v1` it builds a new diagnostic manifest from the exact replayed v1 harness.
The current subject extractor then re-extracts the hash-authenticated v1
binaries. A canonical comparison requires equality across all eight kernels
for body size, current normalized-instruction hash, direct and indirect calls,
frame size, and spills. It never compares v1 placement or raw hashes.

Every attempt name is immutable. A failed hosted run is retained in an artifact
named with both `run_id` and `run_attempt`; a workflow rerun or orchestration
repair therefore derives a different positive attempt and artifact name.
Manifest/build roots must not pre-exist, and artifact upload uses
`overwrite: false`.

### Evidence packaging

The proof step writes allowlisted run provenance, tool/package versions,
validation, comparison, and canonical body-comparison logs beneath a dedicated
evidence root. It creates a SHA-256 inventory covering the capability record,
producer probe files, three v2 manifests and every referenced artifact, v1
manifest and binaries, control provenance, workflow/support files, and logs.

Packaging names whole directories in a tar archive so hidden `.probe.*` files,
executable bits, and symlinks are retained. `actions/upload-artifact` uploads
only the tar archive and its SHA-256 file. It does not upload loose trees whose
hidden files or modes could be lost.

The proof step captures its exit status without converting it to success.
Packaging and upload run under `if: always()`. Upload uses
`if-no-files-found: error` and `overwrite: false`. After upload, a final step
exits with the captured proof status, so diagnostics are preserved without
turning a failed gate green.

The Actions artifact is externally bound to the run. The controller records
the reviewed `GITHUB_SHA`, run ID/attempt, artifact ID/name/size, and the digest
reported by the GitHub Actions artifact API. It downloads the raw artifact
archive through the API and verifies that digest before trusting the co-uploaded
cache-gate tar checksum.

### Portable archive verification

Original manifests and capability records remain byte-for-byte immutable; no
post-download rewrite is allowed. They contain hosted-runner absolute paths,
so ordinary `validate-manifest` cannot be rerun after relocation and the local
AArch64 host cannot execute the archived x86-64 linkers.

A separate reviewed portable verifier consumes an extracted archive plus an
allowlisted mapping from the recorded hosted workspace roots to archive roots.
Exact system linker paths and symlink-chain members are copied into an
inventoried `system-root` mirror and listed individually in run provenance;
they do not authorize arbitrary `/usr` traversal. The verifier requires every
recorded absolute path to be either under an allowed workspace root or one of
those exact mirrored system paths. It maps paths without changing the JSON,
verifies every referenced byte and SHA-256, rechecks capability/manifests'
exact schemas and cross-document relationships, repeats clean/adversary
comparisons over embedded semantic fields, and verifies the canonical v1/v2
body proof. Live linker identity and ELF validation remain the hosted runner's
responsibility; their exact command, status, records, and logs are inventoried
for review. The portable verifier does not claim to rerun native x86 execution
on AArch64.

Before extracting, the verifier inventories the tar and rejects absolute or
parent-traversing member names, device/FIFO/socket entries, duplicate paths,
and symlink or hardlink targets that escape the archive root. Extraction uses
`--no-same-owner`; the verifier then checks types, modes, link targets, and the
internal SHA-256 inventory before following mapped records.

### Verification and acceptance

Local checks before push must cover workflow syntax, shell/static checks, and
orchestration-script tests using the existing AArch64 manifests as fixtures.
A fresh reviewer must report zero Critical or Important findings before push.

After download, local review must verify the external Actions artifact digest,
the cache-gate tar checksum, safe archive structure, internal inventory,
portable mapped records/comparisons, hosted validation logs, and native x86-64
ELF/linker records. Only a fresh reviewer may then choose
`APPROVE POLICY REPLAY`, `REPAIR HARNESS`, or `HOLD` under Task 2 Step 10.

The remote orchestration branch remains until that review completes. Cleanup
is a separate explicit action; it is not part of this evidence run.

## Failure Handling

- Wrong architecture, subject commit/tree drift, dirty checkout, missing GNU
  ld/LLD, incomplete 2/2/4 shapes, manifest failure, comparison failure, or v1
  body mismatch fails the job.
- Orchestration SHA/tree/hash drift, an unexpected LLD package/path, unsafe
  archive member, mapped-path escape, inventory mismatch, or external artifact
  digest mismatch also fails the gate.
- Partial evidence is still packaged and uploaded when possible.
- No failure permits timing, policy replay, or a synthetic native claim.
- If GitHub-hosted Ubuntu cannot satisfy the native linker contract, the result
  is `HOLD` until a native x86-64 Linux host is supplied.
