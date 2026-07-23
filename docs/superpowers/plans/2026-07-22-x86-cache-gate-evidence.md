# Native x86-64 Cache-Gate Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a branch-scoped GitHub Actions workflow that runs the accepted cache-gate harness on native x86-64, preserves independently verifiable evidence, and yields a reviewed cross-architecture gate decision without running timings or replaying policy.

**Architecture:** A hosted-only shell runner checks immutable inputs and drives the existing capability, manifest, comparison, and v1-replay CLIs. Three small standard-library Python programs package the closed evidence tree, safely unwrap the GitHub artifact ZIP, and checksum-first verify the inner tar with schema-aware path routing. The workflow only orchestrates exact commits and always uploads diagnostics before propagating the durable proof status.

**Tech Stack:** Bash 5, Python 3 standard library, pytest, GitHub Actions `ubuntu-24.04`, Rust 1.95.0, native GNU ld and Ubuntu `lld`, existing cache-gate Python/shell tools.

## Global Constraints

- Exact subject: `061d13da22b89208c801308efd578444c8e9caba`, tree `24921a941f8c3c26467465b99d6b45ee5912b2da`.
- Exact v1 replay: `b0d53234dc051af91fe0321450b3e8312a84e635`.
- Orchestration branch: `ci/x86-cache-gate-evidence`; workflow triggers only on a push to that branch.
- Runner must be native Linux `x86_64`; QEMU, cross-compilation, and AArch64 containers are invalid.
- Rust is exactly `1.95.0`; `ld.lld` must resolve to `/usr/bin/ld.lld` from an intact Ubuntu `lld` package under a minimal explicit `PATH`.
- Actions are full-SHA pinned: checkout `11d5960a326750d5838078e36cf38b85af677262`, upload-artifact `ea165f8d65b6e75b540449e92b4886f43607fa02`, rust-toolchain `2c7215f132e9ebf062739d9130488b56d53c060c`.
- Checkout always uses `persist-credentials: false`; workflow permission is only `contents: read`.
- `run_id` and `run_attempt` are canonical positive decimals; `run_id <= 9223372036854774`, `run_attempt <= 999`, and `CACHE_GATE_ATTEMPT = run_id * 1000 + run_attempt`.
- Every manifest/build/evidence/artifact name includes both GitHub run ID and run attempt, refuses pre-existing roots, and uses upload `overwrite: false`.
- Build actual/GNU/LLD capability shapes, fixed control, clean-a, clean-b, adversary, strict comparisons, and fresh v1 body proof. Compare v1/v2 only on size, normalized instructions SHA-256, direct calls, indirect calls, frame adjustment, and spills for all eight kernels.
- Never mutate original manifest/capability JSON. Never claim portable replay of native linker or ELF execution.
- Outer ZIP digest is independently checked before ZIP parsing; inner tar digest is checked before tar parsing.
- Tar extraction is verifier-owned, private, no-follow, and occurs only after complete member/link-graph validation.
- Path-bearing schema validation is exhaustive and fail-closed; no unclassified field or command token receives generic string substitution.
- No Criterion, `perf`, wall-clock timing, policy replay, production-source change, benchmark-body change, or performance PR.
- Retain the remote evidence branch until downloaded evidence receives fresh Step 10 review.

## File Map

- `scripts/verify-x86-cache-gate-artifact.py` — independently bind and safely unwrap the two-file GitHub Actions outer ZIP.
- `tests/test_verify_x86_cache_gate_artifact.py` — digest, ZIP member, duplicate, traversal, link/type, and exact-name tests.
- `scripts/package-x86-cache-gate-evidence.py` — inventory one closed staging root and create deterministic inner tar plus checksum without following links.
- `scripts/verify-x86-cache-gate-evidence.py` — checksum-first tar inspection, safe extraction, inventory/schema/path/semantic verification.
- `tests/test_verify_x86_cache_gate_evidence.py` — malicious tar, link graph, mode, inventory, typed-path, and v1/v2 semantic fixtures.
- `scripts/run-x86-cache-gate-evidence.sh` — native hosted assertions and exact Task 2 Step 9 proof lifecycle; writes durable status and evidence contracts.
- `tests/test_x86_cache_gate_evidence.py` — runner source contracts and hermetic fake-tool lifecycle tests.
- `.github/workflows/x86-cache-gate-evidence.yml` — exact immutable checkouts, toolchain/LLD setup, proof, always-package/upload/final-status flow.

---

### Task 1: Safely Bind the Downloaded Actions Artifact

**Files:**
- Create: `scripts/verify-x86-cache-gate-artifact.py`
- Create: `tests/test_verify_x86_cache_gate_artifact.py`

**Interfaces:**
- Consumes: raw Actions API ZIP, expected API digest matching `sha256:[0-9a-f]{64}`, exact expected inner tar/checksum basenames, fresh output directory.
- Produces: `verify_artifact(zip_path: Path, expected_digest: str, tar_name: str, checksum_name: str, output: Path) -> tuple[Path, Path]` and an equivalent CLI.

- [ ] **Step 1: Write failing digest and exact-member tests**

Create tests that import the script through `importlib.util.spec_from_file_location` and use this helper:

```python
def make_zip(path: Path, entries: list[tuple[str, bytes]]) -> str:
    with zipfile.ZipFile(path, "w") as archive:
        for name, body in entries:
            archive.writestr(name, body)
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
```

Cover one accepted ZIP containing exactly `cache-gate-7-2.tar` and `cache-gate-7-2.tar.sha256`, including ordinary `writestr` members whose Unix mode has permission bits but zero file-type bits. Also cover rejection of wrong digest, extra member, missing member, absolute name, `../`, `a/../b`, raw `a/./b`, raw `a//b`, duplicate canonical name, a directory member, and a Unix symlink encoded in `ZipInfo.external_attr`.

Run:

```bash
pytest -q tests/test_verify_x86_cache_gate_artifact.py
```

Expected: collection fails because the script does not exist.

- [ ] **Step 2: Implement strict ZIP parsing without general extraction**

Implement these exact validation boundaries:

```python
DIGEST_RE = re.compile(r"sha256:([0-9a-f]{64})\Z")

def canonical_member(name: str) -> PurePosixPath:
    if not name or name.startswith("/"):
        raise EvidenceError("unsafe ZIP member name")
    raw_parts = name.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise EvidenceError("unsafe ZIP member name")
    path = PurePosixPath(*raw_parts)
    if path.is_absolute():
        raise EvidenceError("unsafe ZIP member name")
    return path

def is_regular(info: zipfile.ZipInfo) -> bool:
    unix_mode = info.external_attr >> 16
    file_type = stat.S_IFMT(unix_mode)
    return not info.is_dir() and file_type in {0, stat.S_IFREG}
```

Hash the raw ZIP before opening it. Inspect raw slash-separated components before constructing `PurePosixPath`, so normalization cannot hide empty or dot components. Require unique canonical names equal to the exact two-name set. Treat zero file-type bits as an ordinary member even when permission bits are present; accept only file-type bits zero or `S_IFREG`. Reject encrypted entries, non-regulars, directories, and links. Refuse an existing output directory, create it mode `0o700`, and write each body with `os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)` rather than `ZipFile.extract`.

CLI:

```text
verify-x86-cache-gate-artifact.py --zip PATH --api-digest sha256:HEX \
  --tar-name NAME --checksum-name NAME --output DIR
```

- [ ] **Step 3: Run focused tests and commit**

```bash
pytest -q tests/test_verify_x86_cache_gate_artifact.py
pre-commit run --files scripts/verify-x86-cache-gate-artifact.py tests/test_verify_x86_cache_gate_artifact.py
git add scripts/verify-x86-cache-gate-artifact.py tests/test_verify_x86_cache_gate_artifact.py
git commit -m "ci: safely unwrap cache-gate artifacts"
```

Expected: all focused tests and hooks pass.

---

### Task 2: Package and Verify the Inner Evidence Archive

**Files:**
- Create: `scripts/package-x86-cache-gate-evidence.py`
- Create: `scripts/verify-x86-cache-gate-evidence.py`
- Create: `tests/test_verify_x86_cache_gate_evidence.py`

**Interfaces:**
- Consumes: closed staging directory with top-level `bundle/`, output tar path, output checksum path.
- Produces: deterministic uncompressed POSIX tar, checksum file formatted as `64-lowercase-hex + two spaces + archive basename + newline`, and `verify_archive(archive: Path, expected_sha256: str) -> VerificationReport`.
- Archive contract: `bundle/provenance.json`, `bundle/inventory.json`, `bundle/portable-paths.json`, `bundle/body-comparison.json`, plus inventoried `orchestrator/`, `subject/`, `v1/`, `evidence/`, `toolchain/`, and `system-root/` roots.

- [ ] **Step 1: Write failing package round-trip and malicious-tar tests**

Build tar fixtures directly with `tarfile.TarInfo`. Test accepted hidden regular files, executable modes, ordinary relative symlinks, individually allowlisted absolute and relative system-root symlinks, and regular-file hardlinks. Include a hardlink at `bundle/sub/copy` whose raw target `bundle/original` succeeds only when resolved from the archive root, not from the hardlink's parent. Reject checksum mismatch before `tarfile.open` is called, absolute names, raw `a/./b`, raw `a//b`, parent components, duplicate names, devices/FIFO, missing target, link cycle, hardlink to symlink or directory, any member under a link-valued ancestor, an unallowlisted absolute symlink, an unallowlisted relative system-root symlink, a missing actual-linker chain member, a missing GNU-linker chain member, inventory mismatch, and a pre-existing extraction root.

The checksum-first regression must monkeypatch `tarfile.open` to raise if invoked and assert a bad digest reports `archive SHA-256 mismatch` first.

Run:

```bash
pytest -q tests/test_verify_x86_cache_gate_evidence.py -k 'archive or link or inventory'
```

Expected: FAIL because package/verifier modules do not exist.

- [ ] **Step 2: Implement deterministic no-follow packaging**

Walk with `os.scandir` and `follow_symlinks=False`. Require a real directory staging root and exactly one top-level `bundle` directory. Sort paths by POSIX bytes. Inventory each entry as:

```json
{"path":"bundle/evidence/logs/proof.log","type":"file","mode":420,"size":12,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}
{"path":"bundle/system-root/usr/bin/cc","type":"symlink","mode":511,"target":"/etc/alternatives/cc"}
```

Reject sockets, devices, FIFOs, and hardlinks not explicitly described by `bundle/provenance.json`. Write regular files via `TarInfo` with fixed `mtime=0`, `uid=gid=0`, empty owner/group names, preserved permission bits, and no dereference. Atomically write `inventory.json`, tar, then checksum.

CLI:

```text
package-x86-cache-gate-evidence.py --staging-root ABS \
  --archive ABS/cache-gate-RUN-ATTEMPT.tar \
  --checksum ABS/cache-gate-RUN-ATTEMPT.tar.sha256
```

- [ ] **Step 3: Implement complete pre-extraction tar/link validation**

Use `tarfile.open(archive, mode="r:")` only after raw checksum equality. Inspect each member's raw slash-separated components before constructing `PurePosixPath`; reject empty, dot, and parent components so values such as `a/./b` and `a//b` cannot normalize into accepted names. Build `dict[path, TarInfo]`, rejecting duplicate canonical paths and unsupported types. Build the entire link graph before writing anything, using distinct resolvers for the two tar semantics:

```python
def symlink_target(member: PurePosixPath, raw: str, system_pairs: set[tuple[str, str]]) -> PurePosixPath:
    system_prefix = PurePosixPath("bundle/system-root")
    if member.is_relative_to(system_prefix):
        source = "/" + str(member.relative_to(system_prefix))
        if (source, raw) not in system_pairs:
            raise EvidenceError("unallowlisted system link")
    if raw.startswith("/"):
        if not member.is_relative_to(system_prefix):
            raise EvidenceError("unallowlisted absolute system link")
        return canonical_member("bundle/system-root" + raw)
    return resolve_target(member.parent, raw)

def hardlink_target(raw: str) -> PurePosixPath:
    if raw.startswith("/"):
        raise EvidenceError("absolute hardlink target")
    return resolve_target(PurePosixPath(), raw)
```

`resolve_target` performs component-wise verifier-internal resolution and rejects empty targets or archive-root escape. Every system-root symlink requires an exact individually allowlisted `(source, raw_target)` pair before resolution, whether its raw target is absolute or relative. Symlinks remain parent-relative; hardlinks are archive-root-relative. Resolve every symlink/hardlink chain with a three-color DFS. Hardlinks must terminate at a regular member. Every member whose ancestor is a symlink or hardlink fails. Require allowlisted system chains to terminate at a mirrored regular file. Preserve and compare raw targets.

Extract only after graph success into `tempfile.mkdtemp`, mode `0o700`, beneath a verifier-owned parent. Open/create every directory or file relative to directory FDs using `O_DIRECTORY|O_NOFOLLOW`, `O_CREAT|O_EXCL|O_NOFOLLOW`; create links as objects but never resolve them through host filesystem traversal. Never restore uid/gid.

- [ ] **Step 4: Write failing closed-schema and semantic-proof tests**

Fixture `portable-paths.json` version 1 with exact hosted/archive roots, individually allowlisted system links, and typed records. Its top-level key set is exactly `version`, `roots`, `system_links`, and `routing_records`; `version` is integer 1. Each `roots` item has exactly string keys `name`, `hosted`, and `archive`; each `system_links` item has exactly string keys `source` and `raw_target`; each `routing_records` item has exactly string keys `document` and `field_kind` plus `key_path`, a nonempty list of strings. Test:

```python
assert classify(("manifest", "runner_root")) == "root"
assert classify(("manifest", "executables", "*", "absolute_path")) == "hashed-file"
assert classify(("manifest", "executables", "*", "rustc_argv")) == "rustc-command"
assert classify(("manifest", "environment", "PATH")) == "path-list"
```

For every capability, v2 manifest, v1 manifest, provenance, inventory,
transcript, body-comparison, and `portable-paths.json` fixture, inject unknown
ordinary keys such as `binary`, `owner`, and `source` at both top-level and
nested objects, and delete one required key at each nesting shape. For
`portable-paths.json`, cover unknown and missing keys at the top level and in
each root, system-link, and routing-record item. Every case must fail exact
schema validation before typed path routing begins; spy on the classifier to
prove it was not called. Also reject wrong scalar/container types, an empty
`key_path`, empty/unclassified `PATH` elements, root alias mismatch, Cargo
registry path mapped to toolchain, malformed `rlib(member)`, missing rlib index
member, unclassified rustc path-valued flags/response files, a transient input
outside declared roots, changed ordering/duplicates, and any original JSON byte
mutation.

Create eight body rows and verify only this exact tuple is compared:

```python
BODY_FIELDS = (
    "size", "normalized_instructions_sha256", "direct_calls",
    "indirect_calls", "frame_adjustment", "spills",
)
```

Changing `raw_sha256` or placement must not fail body equality; changing any `BODY_FIELDS` item must fail.

- [ ] **Step 5: Implement fail-closed schema/path and semantic verification**

First define literal recursive allowed-key schemas for every accepted version of
the capability, v2 manifest, v1 manifest, provenance, inventory, transcript,
body-comparison, and `portable-paths.json` documents. For `portable-paths.json`
version 1, enforce the exact top-level and nested root/system-link/routing-record
key sets and types above before trusting any root, allowlist pair, or routing
record. Validate exact key-set equality at every object and nesting level,
including every object inside arrays: any unknown or missing key fails regardless
of its spelling, and scalar/list/object types must match. Do not call path
classification until every document, including the routing document itself,
passes this complete structural gate.

Only then apply a literal
`(document_kind, key_path_pattern) -> field_kind` table to every known
path-bearing field and command-token position. Parse command arrays token by
token for `-o`, `-L`, `--extern`, `-C linker=`, `-C link-arg=`, response-file,
and positional input forms. Reject any known path field without a routing entry
or any unclassified path-valued command position.

Map hosted roots only through exact provenance entries, without rewriting source JSON. Verify all hash-bearing records against extracted bytes; map `rlib(member)` owner then validate the member through `ar t`; validate semantic/transient strings for grammar, roots, order, duplicates, and hosted-log agreement without requiring them to exist. Recheck exact capability/manifest schema versions, accepted 2/2/4 actual/GNU/LLD shapes, clean aggregate equality, non-vacuous adversary differences with semantic equality, and all eight v1/v2 body tuples.

CLI:

```text
verify-x86-cache-gate-evidence.py --archive PATH --expected-sha256 HEX
```

Print one stable JSON report containing archive SHA, subject commit/tree, run ID/attempt, three manifest SHAs, capability SHA, eight-body canonical SHA, and `status: "READY"`.

- [ ] **Step 6: Run focused/full Python tests and commit**

```bash
pytest -q tests/test_verify_x86_cache_gate_evidence.py
pytest -q tests/test_verify_x86_cache_gate_artifact.py tests/test_verify_x86_cache_gate_evidence.py
pre-commit run --files \
  scripts/package-x86-cache-gate-evidence.py \
  scripts/verify-x86-cache-gate-evidence.py \
  tests/test_verify_x86_cache_gate_evidence.py
git add scripts/package-x86-cache-gate-evidence.py scripts/verify-x86-cache-gate-evidence.py tests/test_verify_x86_cache_gate_evidence.py
git commit -m "ci: preserve portable cache-gate evidence"
```

Expected: all tests and hooks pass.

---

### Task 3: Drive Exact Hosted Task 2 Step 9

**Files:**
- Create: `scripts/run-x86-cache-gate-evidence.sh`
- Create: `tests/test_x86_cache_gate_evidence.py`

**Interfaces:**
- Consumes: `--orchestrator ABS --subject ABS --v1 ABS --evidence ABS --run-id DECIMAL --run-attempt DECIMAL --status-file ABS`, where the final argument must be the canonical fixed direct child `ABS_EVIDENCE/proof.status`.
- Produces: hosted validation logs, immutable JSON contracts under evidence root, closed bundle staging tree, and atomic canonical status file; exits the actual proof status.

- [ ] **Step 1: Write failing source-contract and fake lifecycle tests**

Assert the runner rejects noncanonical/zero/too-large IDs, wrong architecture, dirty/wrong subject or v1, existing evidence/manifest roots, non-`/usr/bin/ld.lld`, failed `dpkg -V`, or unexpected orchestrator SHA. Feed accepted multi-shape capability fixtures, then remove one member from an actual-linker chain and, separately, one member from a GNU-linker chain; both must fail before manifests are built or evidence is staged. Test status paths outside the evidence root, with traversal or noncanonical aliases such as `/./`, with a name other than `proof.status`, or through a symlink; each must fail before trap installation and create no status or temporary file. Use fake `git`, `uname`, `dpkg-query`, `dpkg`, `cargo`, and harness scripts on `PATH` to prove later failures still atomically write the fixed direct-child status in `0..255`, leave no temporary file, and never invoke timing modes. Inject temporary-file creation and rename failures: the runner must disable the trap, exit 125 without recursion, and leave either a durable canonical 125 or a missing/invalid status that the workflow converts to 125, never a successful final result. Source-contract tests require `O_EXCL`, `O_NOFOLLOW`, a directory-FD-relative rename, `trap - EXIT`, explicit bounded final exit, and the fixed `proof.status` basename.

Source-contract assertions must require literal subject/v1/tree constants, `CACHE_GATE_ATTEMPT=$((run_id * 1000 + run_attempt))`, `BUILD_CONTROL=1`, three `MANIFEST=1` calls, `CACHE_GATE_LAYOUT_ADVERSARY=1`, two `compare` calls, three `validate-manifest` calls, current extractor use for v1, and absence of `cargo bench`, `criterion`, `perf stat`, `ELASTIC=1`, and `FUNNEL=1`.

Run:

```bash
pytest -q tests/test_x86_cache_gate_evidence.py
```

Expected: FAIL because runner does not exist.

- [ ] **Step 2: Implement immutable host, checkout, linker, and attempt gates**

Start with `set -Eeuo pipefail` and parse only the named flags. Before installing an `EXIT` trap, validate raw path components so traversal and normalization aliases are rejected rather than erased by `realpath`; require a non-existing evidence root whose existing parent chain contains no symlink, create it as a private mode-`0o700` directory, and require `status_file` to equal its canonical fixed direct child `proof.status`. Reject any arbitrary basename, outside path, pre-existing destination, symlink, hardlink alias, or noncanonical spelling before the trap can write.

Install the trap only after those checks. `write_status` opens the evidence directory with `O_DIRECTORY|O_NOFOLLOW`, creates an unpredictable same-directory temporary file with `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW` and mode `0o600`, writes and fsyncs the canonical status, then performs a directory-FD-relative atomic rename to `proof.status` and fsyncs the directory. It never follows either path. Its failure cleanup cannot leave a newly written success value authoritative: it restores a durable 125 when possible, otherwise removes or invalidates the destination so the workflow's missing/invalid fallback remains 125.

Use a one-shot finalizer that disables its own `EXIT` trap first, bounds the captured proof code, attempts the durable atomic write, forces final status 125 and retries that failure value if the first write fails, then explicitly exits without recursion:

```bash
proof_status=125
write_status() {
  STATUS_VALUE="${1:?}" python3 - "$evidence" proof.status <<'PY'
# Embedded standard-library helper: validate STATUS_VALUE, open root with
# O_DIRECTORY|O_NOFOLLOW, create unpredictable same-directory temporary with
# O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, write+fsync, dirfd-relative rename to the
# fixed name, fsync directory, and unlink any leftover temporary on failure.
PY
}
finish() {
  local code=$? final_status=125
  trap - EXIT
  if [[ "$code" =~ ^[0-9]+$ ]] && (( code <= 255 )); then
    final_status=$code
  fi
  if ! write_status "$final_status"; then
    final_status=125
    write_status 125 || true
  fi
  exit "$final_status"
}
trap finish EXIT
```

The embedded helper accepts only the root, fixed basename, and status value,
revalidates the fixed basename and canonical private root, and implements the
no-follow dirfd operations above. Any helper failure leaves the proof failed; it
cannot redirect output outside the evidence root. No runner path may exit zero
unless writing and validating durable `proof.status` value zero succeeded.

Require canonical IDs using `[[ $value =~ ^[1-9][0-9]*$ ]]`, explicit bounds, native `/usr/bin/uname -m == x86_64`, `/proc/sys/kernel/ostype == Linux`, exact clean commits/trees, and exact `GITHUB_SHA == orchestrator HEAD`. Record only allowlisted GitHub fields.

Set minimal `PATH="$RUSTUP_HOME/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin:/usr/local/bin:/usr/bin:/bin"`. Require rustc 1.95.0. Before capability execution, require `/usr/bin/ld.lld` and verify its owning Ubuntu `lld` package with `dpkg-query`, package versions, and clean `dpkg -V`; this availability check is not the complete linker-chain inventory.

- [ ] **Step 3: Implement the exact v2 capability/control/manifests proof**

Run capability once, require its stdout path, and validate the record before
using it. Enumerate every accepted actual/GNU/LLD record across every required
target shape. Starting at each recorded invocation path, walk the complete
symlink chain with `lstat`/`readlink`: resolve absolute raw targets from the
virtual system root and relative raw targets from their source parent, reject
cycles, escapes, missing members, and non-regular terminals, and record hashes,
modes, package ownership/verification, and raw target text. Dedupe only exact
`(source, raw_target)` pairs while retaining each capability-record association.
Mirror and individually allowlist every invocation path and chain member through
its terminal regular file; do this for actual and GNU records as well as LLD.
Only after this complete inventory succeeds, build control:

```bash
BUILD_CONTROL=1 "$subject/scripts/cache-gate.sh" --runner-root "$subject"
readarray -t control <"$subject/target/cache-gate-control-bin.txt"
```

For `clean-a`, `clean-b`, and `adversary`, derive names `x86_64-061d13da22b8-attempt-${CACHE_GATE_ATTEMPT}-${kind}` and unique instances with the same suffix. Invoke:

```bash
CACHE_GATE_CONTROL_BIN="${control[0]}" \
CACHE_GATE_CONTROL_PROVENANCE="${control[1]}" \
CACHE_GATE_LINKER_CAPABILITY="$capability" \
CACHE_GATE_VARIANT="$variant" CACHE_GATE_MANIFEST_INSTANCE="$instance" \
CACHE_GATE_LAYOUT_ADVERSARY="$adversary" MANIFEST=1 \
  "$subject/scripts/cache-gate.sh" --runner-root "$subject"
```

Validate each manifest. Compare clean-a to clean-b, then clean-a to adversary. Parse records to require all nine accepted capability entries with exact target shapes 2/2/4, identical clean aggregate fingerprints, differing adversary CGU/object/link fingerprints, and exactly one adversary symbol plus section per executable outside reservations.

- [ ] **Step 4: Implement fresh v1 diagnostic and current-normalizer body proof**

Build v1 control with its own launcher, then build variant `x86_64-v1-replay-run-${run_id}-attempt-${run_attempt}` using v1 `MANIFEST=1`. Authenticate the v1 manifest and its three binary hashes before invoking the current subject `extract-hot-symbols.py` for the exact eight symbols listed by the v1 manifest.

Write `body-comparison.json` with sorted kernel rows and `BODY_FIELDS`. Require every v1 tuple equals clean-a's tuple. Compute a canonical JSON SHA-256 over the eight rows. Do not read or compare raw body hashes, addresses, sections, or placement.

- [ ] **Step 5: Stage closed evidence and provenance contracts**

Copy, never rewrite, capability, three v2 manifests and every hash-bearing referenced file, v1 manifest/binaries/re-extractions, control records, proof logs, reviewed workflow/runner/verifier sources, pinned toolchain files actually referenced, every deduplicated actual/GNU/LLD invocation and complete chain from all accepted target-shape records, package records, and body comparison under `bundle/`.

Write sorted JSON `provenance.json` containing exact commits/trees, orchestration script/workflow hashes, run ID/attempt/derived attempt, allowed GitHub identifiers, Rust and package versions, hosted roots, archive roots, system link pairs, and proof result. Write `portable-paths.json` version 1 with explicit typed routing records. Run the package script only in the workflow's always step, not inside the proof interval.

- [ ] **Step 6: Run runner tests and commit**

```bash
pytest -q tests/test_x86_cache_gate_evidence.py
bash -n scripts/run-x86-cache-gate-evidence.sh
pre-commit run --files scripts/run-x86-cache-gate-evidence.sh tests/test_x86_cache_gate_evidence.py
git add scripts/run-x86-cache-gate-evidence.sh tests/test_x86_cache_gate_evidence.py
git commit -m "ci: run native x86 cache-gate proof"
```

Expected: focused tests, syntax check, and hooks pass.

---

### Task 4: Add the Branch-Scoped Native x86 Workflow

**Files:**
- Create: `.github/workflows/x86-cache-gate-evidence.yml`
- Modify: `tests/test_x86_cache_gate_evidence.py`

**Interfaces:**
- Consumes: push of reviewed orchestration commit to `ci/x86-cache-gate-evidence` and remote availability of exact subject/v1 commits.
- Produces: uniquely named Actions artifact containing only inner tar and checksum; job conclusion equals durable proof status after upload.

- [ ] **Step 1: Add failing workflow contract tests**

Parse YAML through `ruby -e 'require "yaml"; YAML.load_file(ARGV[0], aliases: true)'` when available and assert text contracts in pytest. Require:

```yaml
on:
  push:
    branches: [ci/x86-cache-gate-evidence]
permissions:
  contents: read
jobs:
  x86-cache-gate-evidence:
    runs-on: ubuntu-24.04
```

Require all `uses:` values end in 40 hex characters, checkout has `persist-credentials: false`, and package/upload/final-status steps each use `if: ${{ always() }}`. Upload must set `if-no-files-found: error`, `overwrite: false`, and a name containing both `${{ github.run_id }}` and `${{ github.run_attempt }}`.

- [ ] **Step 2: Implement exact checkouts and native tool setup**

Checkout orchestration, subject, and v1 into sibling paths with the pinned checkout SHA. Subject ref is `061d13da22b89208c801308efd578444c8e9caba`; v1 ref is `b0d53234dc051af91fe0321450b3e8312a84e635`; every checkout disables persisted credentials.

Install Rust with:

```yaml
- uses: dtolnay/rust-toolchain@2c7215f132e9ebf062739d9130488b56d53c060c
  with:
    toolchain: 1.95.0
```

Install Ubuntu `lld` through `apt-get`, then let the runner perform exact path/package/hash gates. Do not use a container, matrix, cache action, or sudo beyond package installation.

- [ ] **Step 3: Implement proof, always-package/upload, and final status**

Run the proof step directly so a nonzero proof is visible. Give it a stable `id: proof` and `continue-on-error: true`; its durable status remains authoritative. Package under `${{ always() }}`, even if checkout/setup/proof failed, using a fallback diagnostic bundle and status 125 when the canonical status file is missing.

Upload only the tar and checksum under `${{ always() }}` with pinned upload-artifact. The final step also uses `${{ always() }}`, validates canonical `0..255`, and executes `exit "$status"`; missing/invalid status exits 125. If the proof step's recorded outcome is failure while the status file says zero, the final step treats that as a failed status write and exits 125. This final step is never conditioned on prior success, so neither the runner nor workflow can finish successfully without a durable valid zero status.

- [ ] **Step 4: Validate workflow and commit**

```bash
pytest -q tests/test_x86_cache_gate_evidence.py
ruby -e 'require "yaml"; YAML.load_file(ARGV[0], aliases: true)' .github/workflows/x86-cache-gate-evidence.yml
pre-commit run --files .github/workflows/x86-cache-gate-evidence.yml tests/test_x86_cache_gate_evidence.py
git add .github/workflows/x86-cache-gate-evidence.yml tests/test_x86_cache_gate_evidence.py
git commit -m "ci: collect native x86 cache-gate evidence"
```

Expected: workflow parses, focused tests and hooks pass.

---

### Task 5: Full Local Gate, Independent Review, Hosted Run, and Download Verification

**Files:**
- Modify only if a test/reviewer exposes a defect in Task 1-4 files.
- Record operational evidence outside Git-tracked source under `target/cache-gate-evidence-controller/`.

**Interfaces:**
- Consumes: reviewed local branch, exact subject branch, GitHub Actions run/artifact API.
- Produces: clean local code review, externally digest-bound downloaded artifact, portable `READY` report, and final Step 10 reviewer verdict.

- [ ] **Step 1: Run the complete local verification gate**

```bash
pytest -q \
  tests/test_x86_cache_gate_evidence.py \
  tests/test_verify_x86_cache_gate_evidence.py \
  tests/test_verify_x86_cache_gate_artifact.py \
  tests/test_cache_gate_elf_layout.py \
  tests/test_extract_hot_symbols.py
cargo test --test elastic_cache_gate_fixture cache_gate::tests
cargo test
pre-commit run --all-files
git diff --check
test -z "$(git status --porcelain)"
git diff --quiet 061d13da22b89208c801308efd578444c8e9caba -- src benches tools
```

Expected: all tests/hooks pass, worktree clean, and production/benchmark/tool trees exactly match the approved subject.

- [ ] **Step 2: Obtain fresh code review before external mutation**

Give a fresh reviewer the complete diff from `061d13d`, approved design/spec, this plan, and local outputs. Require zero Critical and Important findings; repair and re-review until C0/I0. Reviewer must explicitly confirm no timing/policy path and approve the exact commits to push.

- [ ] **Step 3: Push exact reviewed commits and monitor one workflow run**

Push subject commit to `origin/bench/cache-gate-layout-v2` and the reviewed orchestration tip to `origin/ci/x86-cache-gate-evidence`. Confirm the workflow `headSha` equals the reviewed orchestration SHA and monitor to terminal state. Do not rerun under the same attempt; a repair is a new orchestration commit or GitHub rerun attempt and therefore a new namespace.

- [ ] **Step 4: Independently bind and verify the downloaded artifact**

Use the GitHub Actions artifact API to record run ID/attempt, artifact ID/name/size, and reported digest. Export those exact recorded values as `EVIDENCE_RUN_ID`, `EVIDENCE_RUN_ATTEMPT`, and `EVIDENCE_API_DIGEST`; read the selected checksum file's first field into `EVIDENCE_TAR_SHA256`. Download raw outer ZIP, then run:

```bash
artifact_base="cache-gate-${EVIDENCE_RUN_ID}-${EVIDENCE_RUN_ATTEMPT}"
python3 scripts/verify-x86-cache-gate-artifact.py \
  --zip target/cache-gate-evidence-controller/actions-artifact.zip \
  --api-digest "$EVIDENCE_API_DIGEST" \
  --tar-name "${artifact_base}.tar" \
  --checksum-name "${artifact_base}.tar.sha256" \
  --output target/cache-gate-evidence-controller/unwrapped
EVIDENCE_TAR_SHA256=$(awk 'NR == 1 { print $1 }' \
  "target/cache-gate-evidence-controller/unwrapped/${artifact_base}.tar.sha256")
python3 scripts/verify-x86-cache-gate-evidence.py \
  --archive "target/cache-gate-evidence-controller/unwrapped/${artifact_base}.tar" \
  --expected-sha256 "$EVIDENCE_TAR_SHA256"
```

Expected: outer digest/member gate passes and portable report says `status: "READY"` with exact subject/tree and eight-body proof. Environment values come directly from the recorded API response and selected checksum file; never infer or edit them.

- [ ] **Step 5: Obtain final Step 10 reviewer verdict**

Give a fresh reviewer the API provenance, raw ZIP digest, tar checksum, portable report, hosted validation logs, exact native x86 linker/ELF records, and existing AArch64 attempt-5 evidence. Reviewer returns exactly one of `APPROVE POLICY REPLAY`, `REPAIR HARNESS`, or `HOLD`. Do not time or replay policy unless the verdict is `APPROVE POLICY REPLAY`.
