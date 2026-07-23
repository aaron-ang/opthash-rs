# Native x86-64 Cache-Gate Evidence

Status: approved design, implementation plan complete

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
packages with `dpkg-query` and `dpkg -V`, and records their versions. After the
capability is accepted, the runner enumerates every actual/GNU/LLD record across
all required target shapes. From each recorded invocation path it walks the
complete absolute- or parent-relative symlink chain through its terminal regular
file, rejecting missing members, cycles, and escapes. It deduplicates exact
source/raw-target pairs while retaining record associations, then mirrors and
individually allowlists every invocation and chain member with raw link text,
mode, hash, package record, `argv0`, and version. This complete inventory is not
limited to `/usr/bin/ld.lld`.

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
3. requires `run_id` and `run_attempt` to be canonical positive decimals
   matching `^[1-9][0-9]*$`, validates `run_id <= 9223372036854774` and
   `run_attempt <= 999`, derives the injective signed-64-bit value
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
producer probe files, three v2 manifests and every hash-bearing referenced
artifact, v1 manifest and binaries, control provenance, workflow/support files,
logs, the pinned Rust toolchain root, and exact mirrored system files.

Packaging names whole directories in a tar archive so hidden `.probe.*` files,
executable bits, and symlinks are retained. `actions/upload-artifact` uploads
only the tar archive and its SHA-256 file. It does not upload loose trees whose
hidden files or modes could be lost.

The proof wrapper captures its exit status without converting the proof to
success and atomically writes the canonical decimal value to the fixed direct
child `proof.status` of a freshly created private evidence root before exiting
with that value. Before trap installation, raw path validation rejects any
arbitrary basename, outside or traversing path, normalization alias, symlink,
hardlink alias, or pre-existing destination. Status writing uses an
`O_EXCL|O_NOFOLLOW` same-directory temporary file, followed by a
directory-FD-relative atomic rename without following either path. The one-shot
`EXIT` handler disables its trap before work, bounds the captured proof code,
attempts that durable write, forces status 125 and retries the failure value if
writing fails, then explicitly exits without recursion. A successful exit is
impossible unless durable canonical status zero was written and validated. Packaging,
upload, and the final status step each explicitly run under `if: always()`;
default success gating therefore cannot skip any of them after an earlier
failure. Upload uses `if-no-files-found: error` and `overwrite: false`. After
upload, the final step reads, strictly validates, and exits with the durable
proof status as a canonical decimal in the range 0 through 255. A missing,
non-canonical, or out-of-range status file exits 125 instead of being treated as
success.

The Actions artifact is externally bound to the run. The controller records
the reviewed `GITHUB_SHA`, run ID/attempt, artifact ID/name/size, and the digest
reported by the GitHub Actions artifact API. That API download is an outer ZIP,
whose independently reported digest is verified before any member is inspected.
The controller then parses the ZIP without general-purpose extraction. It
inspects raw slash-separated name components before constructing or normalizing
a POSIX path, rejecting absolute names and empty, dot, or parent components;
canonical names must then be unique. Directories, links, and every non-regular
ZIP member fail.
Exactly the expected cache-gate tar and checksum regular members must exist,
with no extras, and their bytes are read directly for the next verification
stage.

### Portable archive verification

Original manifests and capability records remain byte-for-byte immutable; no
post-download rewrite is allowed. They contain hosted-runner absolute paths,
so ordinary `validate-manifest` cannot be rerun after relocation and the local
AArch64 host cannot execute the archived x86-64 linkers.

A separate reviewed portable verifier takes only the inner cache-gate tar
archive and its expected SHA-256, obtained after the controller's safe outer-ZIP
handling, as inputs. It verifies the checksum before parsing any tar member and
owns the complete inspect/extract/verify lifecycle; it never trusts a
caller-extracted tree.

Before extraction it inspects every raw slash-separated member-name component,
rejects absolute names and empty, dot, or parent components, and only then
constructs a POSIX path and rejects duplicate canonical names.
Only directories, regular files, symlinks, and hardlinks are permitted;
devices, FIFOs, sockets, and unknown types fail. Before extraction, the verifier
builds and validates the complete link graph. Every symlink within
`system-root` requires an individually allowlisted source/raw-target pair,
whether its raw target is relative or absolute. A dedicated symlink resolver
still resolves relative targets from their containing member. Absolute symlink
targets outside `system-root` fail; allowlisted absolute system targets preserve
their raw absolute link text as evidence, while
verifier-internal resolution treats the leading `/` as the root of the archived
`system-root` namespace, never the host filesystem. Every member in such a
chain must be mirrored and individually allowlisted through its terminal
regular file. A separate hardlink resolver resolves targets from the archive
root, and every hardlink chain must terminate at a regular-file member; a
symlink or directory terminal fails. Every resolved target must be an existing
canonical member without escaping or cycling. Any archive member under a
link-valued ancestor is rejected, regardless of its own type. Only after the
whole graph passes does the verifier extract into a newly created private root
using dirfd-relative no-follow operations, create link objects without
following them, never restore ownership, and perform all link resolution
internally rather than through filesystem traversal. It then checks exact
types, modes, raw link targets, and the internal SHA-256 inventory.

Portable verification first applies exact, complete allowed-key schemas to every
accepted version of the capability, v2 manifest, v1 manifest, provenance,
inventory, transcript, body-comparison, and `portable-paths.json` documents.
`portable-paths.json` itself has an exact versioned recursive schema: its
top-level version, roots, system-link pairs, and routing records, plus every
nested entry, have fixed complete key sets and scalar/container types. Every
object at every nesting level, including array elements, must have exactly its
required keys and types; any unknown or missing key fails regardless of its
name. No root, allowlist pair, or routing record is trusted, and no typed path
routing occurs, until all documents pass this structural gate.

Portable path validation then uses a closed, schema-aware routing table. It
enumerates every known path-bearing field and command-token position; any known
path field without a route or any unclassified path-valued command token fails
closed rather than falling back to string substitution. Routing includes:

- hash-bearing file records must map to archived bytes under the subject, v1,
  evidence, or pinned Rust toolchain roots, or to an individually allowlisted
  file/symlink in the `system-root` mirror;
- root fields and duplicate path fields are classified explicitly, mapped once,
  and required to retain their declared equality or alias relationship;
- every element of each captured `PATH` list is parsed separately, with empty or
  unclassified elements rejected and ordering preserved;
- Cargo registry, pinned Rust toolchain, and allowlisted system paths route to
  distinct archived namespaces and cannot cross-map;
- every accepted actual/GNU/LLD capability invocation and complete symlink-chain
  member across all target shapes is mirrored exactly and listed individually
  with its expected raw link text and terminal file, never treated as permission
  to traverse arbitrary host `/usr` or `/etc` paths;
- `rlib(member)` archive-owner values are semantic pairs: the archived rlib is
  mapped separately and the named member is checked against its archive index;
- rustc flags and command transcripts are parsed by their captured command
  grammar, including path-valued output, search-path, `--extern`, linker,
  link-argument, response-file, and input positions; each discovered path is
  routed by its field/token class;
- linker argv, map ownership, rustc temporary inputs, and other classified
  transient link inputs without a hash-bearing file-record contract remain
  semantic evidence. They must use allowed recorded roots and preserve grammar,
  ordering, duplicate relationships, and agreement with the hosted
  trace/validation output, but are not falsely required to survive after the
  link.

The verifier maps paths without changing original JSON bytes, verifies every
hash-bearing record, rechecks capability/manifests' exact schemas and
cross-document relationships, repeats clean/adversary comparisons over
embedded semantic fields, and verifies the canonical v1/v2 body proof. Live
linker identity and ELF validation remain the hosted runner's responsibility;
their exact command, status, records, and logs are inventoried for review. The
portable verifier does not claim to rerun native x86 execution on AArch64.

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
