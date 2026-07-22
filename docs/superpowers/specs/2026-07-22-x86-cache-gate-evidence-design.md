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
`contents: read` permission.

The job creates three independent directories:

- `orchestrator`: the CI descendant containing only design/plan and workflow
  support;
- `subject`: exact `061d13da22b89208c801308efd578444c8e9caba`;
- `v1`: exact replayed v1 harness
  `b0d53234dc051af91fe0321450b3e8312a84e635`.

Before building, the runner must report `x86_64`; `subject` must have the exact
commit and tree above; both subject and v1 checkouts must be clean. Rust is
pinned to 1.95.0, matching the reviewed AArch64 toolchain. The workflow
installs the distribution's native `lld`; its exact path, payload hash,
symlink chain, `argv0`, and version are captured by the capability record.

### Proof execution

A small orchestration script accepts absolute subject, v1, and evidence roots.
It never copies code into either checkout.

In `subject` it:

1. runs `scripts/cache-gate-linker-capability.sh`;
2. builds the authenticated fixed-control binary;
3. derives a positive, unique `CACHE_GATE_ATTEMPT` from the GitHub run ID and
   run-attempt number, then builds fresh
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

Every attempt name is immutable. A failed hosted run is retained in its
artifact; a workflow rerun or orchestration repair derives a different positive
attempt ID and never overwrites earlier evidence.

### Evidence packaging

The proof step writes environment, tool-version, validation, comparison, and
canonical body-comparison logs beneath a dedicated evidence root. It creates a
SHA-256 inventory covering the capability record, producer probe files, three
v2 manifests and their referenced artifacts, v1 manifest and binaries,
control provenance, and logs.

Packaging names whole directories in a tar archive so hidden `.probe.*` files,
executable bits, and symlinks are retained. `actions/upload-artifact` uploads
only the tar archive and its SHA-256 file. It does not upload loose trees whose
hidden files or modes could be lost.

The proof command is allowed to fail without skipping packaging. After the
artifact upload, a final workflow step re-emits the proof failure so diagnostics
are preserved without turning a failed gate green.

### Verification and acceptance

Local checks before push must cover workflow syntax, shell/static checks, and
orchestration-script tests using the existing AArch64 manifests as fixtures.
A fresh reviewer must report zero Critical or Important findings before push.

After download, local review must verify the outer archive checksum, safely
inspect archive paths before extraction, verify the internal inventory, rerun
manifest validation and comparisons against the extracted files, and inspect
the native x86-64 ELF/linker records. Only a fresh reviewer may then choose
`APPROVE POLICY REPLAY`, `REPAIR HARNESS`, or `HOLD` under Task 2 Step 10.

The remote orchestration branch remains until that review completes. Cleanup
is a separate explicit action; it is not part of this evidence run.

## Failure Handling

- Wrong architecture, subject commit/tree drift, dirty checkout, missing GNU
  ld/LLD, incomplete 2/2/4 shapes, manifest failure, comparison failure, or v1
  body mismatch fails the job.
- Partial evidence is still packaged and uploaded when possible.
- No failure permits timing, policy replay, or a synthetic native claim.
- If GitHub-hosted Ubuntu cannot satisfy the native linker contract, the result
  is `HOLD` until a native x86-64 Linux host is supplied.
