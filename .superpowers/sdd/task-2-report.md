# Task 2 report: inner x86 cache-gate evidence archive

Status: `DONE`

## Implemented

- Deterministic uncompressed PAX/POSIX tar packaging with fixed ownership and
  timestamps, byte-sorted member names, preserved permission bits, atomic
  inventory/archive/checksum writes, no-follow regular-file and provenance
  opens, and explicit hardlink declarations.
- Checksum-first verifier using a verifier-owned snapshot file descriptor: the
  SHA-256 is checked before `tarfile.open(fileobj=..., mode="r:")`.
- Raw member-name component validation before `PurePosixPath`, duplicate/type
  rejection, whole-archive link graph validation, root-relative hardlink
  semantics, parent-relative symlink semantics, individual system-link pairs,
  cycle/missing-target/linked-ancestor checks, and hardlink regular terminals.
- Dirfd-relative extraction using `O_DIRECTORY|O_NOFOLLOW` and
  `O_CREAT|O_EXCL|O_NOFOLLOW`; link objects are created without host
  resolution and ownership is never restored.
- Exact inventory verification of path/type/mode/size/hash/raw-target.
- Literal recursive schemas for the test evidence documents and
  `portable-paths.json`, schema-before-routing ordering, closed route table,
  hosted-to-archive root mapping, command token parsing, stable report output,
  2/2/4 shape checks, clean/adversary checks, and exact six-field eight-body
  comparison.

## TDD evidence

Initial focused RED:

```text
uv run pytest -q tests/test_verify_x86_cache_gate_evidence.py -k 'archive or link or inventory'
22 errors: package/verifier modules did not exist
```

Archive GREEN:

```text
22 passed, 3 deselected in 0.09s
```

Semantic RED:

```text
41 failed, 25 deselected
```

Semantic GREEN:

```text
41 passed, 25 deselected in 0.11s
```

End-to-end RED failed at the intentional
`semantic evidence verification is not implemented` boundary, then passed
after implementation.

## Fresh final verification

```text
python3 -m py_compile scripts/package-x86-cache-gate-evidence.py \
  scripts/verify-x86-cache-gate-evidence.py \
  tests/test_verify_x86_cache_gate_evidence.py
# exit 0

uv run pytest -q tests/test_verify_x86_cache_gate_evidence.py
67 passed in 0.25s

uv run pytest -q tests/test_verify_x86_cache_gate_artifact.py \
  tests/test_verify_x86_cache_gate_evidence.py
82 passed in 0.24s

pre-commit run --files \
  scripts/package-x86-cache-gate-evidence.py \
  scripts/verify-x86-cache-gate-evidence.py \
  tests/test_verify_x86_cache_gate_evidence.py
# all hooks passed

git diff --check
# exit 0
```

## Release Review Round 3 remediation

All eight Round 3 findings were closed with regression-first tests:

1. Manifest and capability layouts now run the complete hosted ET_DYN,
   non-RWX, exact-section/count/flag, RX-segment, overlap, alignment,
   veneer/thunk, and PLT contract. MAXPAGESIZE, target-keyed fragment hashes,
   fragment-set hashes, linker flavor, executable bytes, and link-map bytes are
   cross-bound to their independent records.
2. Every manifest link command is regenerated from the held trace and exact
   capability driver, target-keyed fragment, per-executable map, output, and
   object/archive/library inputs. The independently regenerated nine-command
   map is the transcript authority.
3. Every shape, manifest, and transcript trace record is schema- and
   route-validated. Final-link producers are recomputed from output arguments,
   and exactly one producer is required rather than trusting recorded counts.
4. Every extracted file and symlink read now requires an exact tar member and
   traverses all ancestors with dirfd-relative `O_NOFOLLOW` opens. Rlib index
   checks consume bytes read through that authority, not an extracted pathname.
5. Packaging holds the exact provenance descriptor, identity, bytes, and hash
   through both walks and archive creation. Verification requires provenance,
   tar, and inventory hardlink sets to be exactly equal.
6. The mandatory fixture now drives full concrete routing, all nine authentic
   manifest link commands, and all trace records. Shape CWD/output roots and
   extracted-linker bare `argv0` grammar are explicit. Nine original hosted
   command/trace pairs were added; the fixture README records the sole safety
   normalization applied to captured rustc environments.
7. Clean and adversary occurrence proofs are recomputed from layout sections,
   exact nonempty constants, symbol name/start/size, and reservation intervals.
8. Empty `LD_LIBRARY_PATH` elements are rejected.

Initial Round 3 RED selection:

```text
33 failed, 4 passed, 142 deselected
```

Focused GREEN groups covered all eight findings, followed by full verification:

```text
uv run pytest -q tests/test_verify_x86_cache_gate_evidence.py
180 passed

uv run pytest -q \
  tests/test_verify_x86_cache_gate_artifact.py \
  tests/test_verify_x86_cache_gate_evidence.py
195 passed

uv run python -m py_compile \
  scripts/package-x86-cache-gate-evidence.py \
  scripts/verify-x86-cache-gate-evidence.py \
  tests/test_verify_x86_cache_gate_evidence.py
# exit 0

pre-commit run --files \
  scripts/package-x86-cache-gate-evidence.py \
  scripts/verify-x86-cache-gate-evidence.py \
  tests/test_verify_x86_cache_gate_evidence.py \
  tests/fixtures/x86_cache_gate_evidence/README.md \
  tests/fixtures/x86_cache_gate_evidence/aarch64-attempt-5-records.tar.xz
# all applicable hooks passed

git diff --check
# exit 0
```

No known Task 2 gaps remain.

## Re-review round 2 remediation

Status: DONE

The round-2 verifier review is fully resolved:

1. Authenticated command routing now resolves every positional or path-valued
   token against the recorded cwd and declared roots. The real reviewed
   transcript exercises all 92 rustc invocations (76 compiler plus 16 build
   scripts). The only `/tmp` exception is GNU's exact
   `/tmp/cc[A-Za-z0-9]{6}.res` resolution-file grammar.
2. Every manifest and capability-shape symbol/layout pair is cross-bound.
   Native x86 architecture, target triple, keyed actual/GNU/LLD flavors,
   kernel sets, all body fields, raw hashes, structural ranges, exact sentinel
   names and metadata, link-map sentinels, reservation arithmetic, and
   non-overlap are enforced before READY.
3. Clean layout comparison includes all raw/body/sentinel fields. Adversary raw
   relocation remains allowed only when that adversary layout and its own
   symbol record agree; all other body, placement, and sentinel fields remain
   fixed.
4. All seven verifier tools are pinned to exact subject paths, reviewed
   commit/tree, Git blob IDs, SHA-256 values, and archived bytes. Both controls
   are locked, use exact source identities and output namespaces, bind to the
   capability's exact Rust/Cargo identity, and require the pinned x86 Rust
   1.95.0 toolchain. The v1 control root is bound to the declared portable v1
   root rather than inferred as authority from the control itself.

Round-2 RED included the 17-failure reported gap reproduction, followed by an
expanded 34-failure adversarial matrix. The final three independent-review
probes first failed for variable-length GCC resolution names, coherent
non-arithmetic layout sizes/forged sentinel names, and self-authenticated
control versions/root.

Fresh final verification on the formatted tree:

```text
uv run pytest -q tests/test_verify_x86_cache_gate_evidence.py
143 passed in 2.71s

uv run pytest -q \
  tests/test_verify_x86_cache_gate_artifact.py \
  tests/test_verify_x86_cache_gate_evidence.py
158 passed in 2.50s

uv run python -m py_compile \
  scripts/package-x86-cache-gate-evidence.py \
  scripts/verify-x86-cache-gate-evidence.py \
  tests/test_verify_x86_cache_gate_evidence.py
# exit 0

pre-commit run --files \
  scripts/package-x86-cache-gate-evidence.py \
  scripts/verify-x86-cache-gate-evidence.py \
  tests/test_verify_x86_cache_gate_evidence.py \
  tests/fixtures/x86_cache_gate_evidence/README.md
# all applicable hooks passed

git diff --check
# exit 0
```

Fresh independent re-review: Critical 0, Important 0. No known Task 2 gaps
remain. No Task 1 files were modified.

Bare `pytest` was unavailable in this environment; the repository `.venv` was
used through `uv run pytest`.

## Review-finding remediation

All four former self-review concerns and all seven blocking Task 2 review
findings are resolved:

1. The verifier now carries the complete recursive real capability, v2, and v1
   schemas. It expands the closed route table over concrete documents, validates
   command positions and transcript environments, authenticates
   `portable-paths.json` through provenance, and requires hosted `system-root`
   to be exactly `/`.
2. Every actual/GNU/LLD × elastic/funnel/profile shape is parsed from its
   authenticated symbol, layout, link-argument, execution, and trace bytes.
   The verifier enforces the exact 2/2/4 kernel sets, driver/linker identities,
   controls, sessions, raw outputs, chain adjacency, raw symlink targets,
   `argv0`, extraction roots, and terminal payload hashes. The nine hosted
   manifest transcripts remain cross-bound to their exact link proofs.
3. Subject commit/tree, capability producer, all v2 manifests and controls, the
   selected v1 replay commit/tree and control, embedded capability objects, and
   copied capability byte hashes are exact immutable identities before READY.
   Body-comparison and portable-path documents are also byte-authenticated by
   provenance.
4. Clean/adversary proof validation now recomputes every per-executable and
   aggregate fingerprint from ordered arrays (preserving duplicates), checks
   exact build vectors and kernel names, compares clean/adversary semantic and
   placement contracts, and validates exact adversary occurrences.
5. Every `rlib(member)` occurrence in both owner lists, input-section owners,
   and kernel owners reaches `ar t`; layout/proof owner lists are cross-bound in
   order.
6. Packaging now traverses pinned directory descriptors with
   `openat`/`O_NOFOLLOW`, retains them through archive creation, reopens each
   regular file relative to its pinned parent, compares full file identity, and
   hashes the exact descriptor bytes consumed by `tarfile`.
7. The mandatory checked fixture
   `tests/fixtures/x86_cache_gate_evidence/aarch64-attempt-5-records.tar.xz`
   contains unchanged reviewed capability/v2/v1 records plus all compact shape
   JSON/log records. Its archive SHA-256 is
   `088f5e3edfdc3d0d51ca2b7cb4f24bd2247f5b47c4794c726b9401f854144b69`;
   tests never skip or consult an external worktree.

No known Task 2 gaps remain. No Task 1 files were modified.

## Review-fix TDD and final verification

Focused verifier RED:

```text
uv run pytest -q tests/test_verify_x86_cache_gate_evidence.py \
  -k 'concrete_route_walk or unclassified_path_environment or real_capability_shape or shape_rejects or strict_manifest or exact_identity_contract or every_rlib_occurrence'
11 failed, 8 passed, 82 deselected in 0.83s
```

The two new descriptor-race package tests failed against the old pathname
implementation, then passed after the dirfd/same-FD implementation:

```text
uv run pytest -q tests/test_verify_x86_cache_gate_evidence.py -k 'package_'
5 passed, 85 deselected in 0.16s
```

Focused verifier GREEN:

```text
uv run pytest -q tests/test_verify_x86_cache_gate_evidence.py \
  -k 'concrete_route_walk or unclassified_path_environment or real_capability_shape or shape_rejects or strict_manifest or exact_identity_contract or every_rlib_occurrence'
19 passed, 82 deselected in 0.73s
```

Fresh final verification:

```text
uv run python -m py_compile \
  scripts/package-x86-cache-gate-evidence.py \
  scripts/verify-x86-cache-gate-evidence.py \
  tests/test_verify_x86_cache_gate_evidence.py
# exit 0

uv run pytest -q \
  tests/test_verify_x86_cache_gate_artifact.py \
  tests/test_verify_x86_cache_gate_evidence.py
116 passed in 1.66s

pre-commit run --files \
  scripts/package-x86-cache-gate-evidence.py \
  scripts/verify-x86-cache-gate-evidence.py \
  tests/test_verify_x86_cache_gate_evidence.py \
  tests/fixtures/x86_cache_gate_evidence/README.md
# all applicable hooks passed

git diff --check
# exit 0
```

## Final Re-review Round 4 remediation

Status: DONE

The final manifest-replay finding is closed:

1. Linker argv is decoded into one ordered semantic stream across direct
   driver arguments, `-Wl,...`, split/joined `-Xlinker`, and GCC's equivalent
   split/joined `--for-linker`. Forwarding origin is retained so an
   operand-taking forwarded option cannot consume a driver positional input.
2. Split/joined `-l` and `--library` forms normalize to one ordered `-l<name>`
   representation. Every remaining positional argument is an absolute direct
   input regardless of suffix; `-R`/`--just-symbols` inputs are also recorded.
   Output, map, script, search, rpath, and other proven non-input operands are
   consumed without being misclassified.
3. Empty/dangling forwarding, response files, mixed-origin operands, input
   remapping, unreviewed script mechanisms, and plugin pass-through are
   rejected. Undeclared forwarded objects, archives, or libraries therefore
   change the regenerated ordered/direct inputs and fingerprint or fail
   closed.
4. The authoritative fragment is exactly
   `capability["fragments"][target]`: both the executable fragment record and
   command fragment must equal that record, and the sole raw script control
   remains exact `-Wl,-T,<capability absolute path>`. A same-hash alternate
   path fails.
5. The reviewed AArch64 fixture's nine executable fragment records and
   corresponding command/trace `-T` tokens were normalized to that exact
   capability path. All dependent hashes were recomputed. The deterministic
   fixture SHA-256 is
   `100920ab673be133a57cd193c9d02118c2feb7bdc470e37c09e53124ee05d6ee`.

Regression-first evidence:

```text
# Required grammar, undeclared-input replay, and alternate fragment path
15 failed, 2 passed, 180 deselected

# Expanded option-operand, response-file, and fragment-record matrix
8 failed, 6 passed, 197 deselected

# Expanded alias, arbitrary positional, remap, and mixed-origin matrix
17 failed, 8 passed, 203 deselected
```

Fresh final verification on the formatted tree:

```text
uv run pytest -q tests/test_verify_x86_cache_gate_evidence.py \
  -k 'link_command_inputs or undeclared_forwarded or alternate_fragment or fragment_record_path or extra_aliased_linker_controls'
51 passed, 180 deselected

uv run pytest -q tests/test_verify_x86_cache_gate_evidence.py
231 passed

uv run pytest -q \
  tests/test_verify_x86_cache_gate_artifact.py \
  tests/test_verify_x86_cache_gate_evidence.py
246 passed

uv run python -m py_compile \
  scripts/package-x86-cache-gate-evidence.py \
  scripts/verify-x86-cache-gate-evidence.py \
  tests/test_verify_x86_cache_gate_evidence.py
# exit 0

cargo test
# exit 0

pre-commit run --all-files
# all applicable hooks passed

git diff --check
# exit 0
```

Fresh independent diff review: C0/I0/M0, PASS.

No known Task 2 gaps remain.
