#!/usr/bin/env bash
# Run the immutable native-x86 cache-gate proof and stage closed evidence.

set -Eeuo pipefail

SUBJECT_COMMIT=061d13da22b89208c801308efd578444c8e9caba
SUBJECT_TREE=24921a941f8c3c26467465b99d6b45ee5912b2da
V1_COMMIT=b0d53234dc051af91fe0321450b3e8312a84e635
V1_TREE=d77cc082fe48799f26ff4440bd1898a71d0dc8cc
TOOLCHAIN_NAME=1.95.0-x86_64-unknown-linux-gnu
PINNED_CARGO_VERSION='cargo 1.95.0 (f2d3ce0bd 2026-03-21)'
PINNED_RUSTC_VERSION=$'rustc 1.95.0 (59807616e 2026-04-14)\nbinary: rustc\ncommit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860\ncommit-date: 2026-04-14\nhost: x86_64-unknown-linux-gnu\nrelease: 1.95.0\nLLVM version: 22.1.2'
UNAME_TOOL=/usr/bin/uname
OSTYPE_FILE=/proc/sys/kernel/ostype
LLD_TOOL=/usr/bin/ld.lld

usage() {
	echo "usage: $0 --orchestrator ABS --subject ABS --v1 ABS --evidence ABS --run-id DECIMAL --run-attempt DECIMAL --status-file ABS" >&2
	exit 2
}

declare -A parsed=()
while (($#)); do
	case "$1" in
	--orchestrator | --subject | --v1 | --evidence | --run-id | --run-attempt | --status-file)
		(($# == 2 || $# > 2)) || usage
		[[ -z ${parsed[$1]+set} ]] || usage
		parsed[$1]=${2-}
		shift 2
		;;
	*)
		usage
		;;
	esac
done
for required in --orchestrator --subject --v1 --evidence --run-id --run-attempt --status-file; do
	[[ -n ${parsed[$required]+set} ]] || usage
done

orchestrator=${parsed[--orchestrator]}
subject=${parsed[--subject]}
v1=${parsed[--v1]}
evidence=${parsed[--evidence]}
run_id=${parsed[--run-id]}
run_attempt=${parsed[--run-attempt]}
status_file=${parsed[--status-file]}

# Validate raw spelling and all pre-existing ancestors before normalization can
# erase an alias. The evidence directory is created before, but the status trap
# is installed only after, the complete fixed-child check succeeds.
/usr/bin/python3 - "$orchestrator" "$subject" "$v1" "$evidence" "$status_file" <<'PY'
import os
import stat
import sys
from pathlib import Path

orchestrator, subject, v1, evidence, status_file = sys.argv[1:]


def canonical_absolute(raw: str, label: str) -> Path:
    if (
        not raw.startswith("/")
        or "\0" in raw
        or raw != os.path.normpath(raw)
        or any(part in {"", ".", ".."} for part in raw.split("/")[1:])
    ):
        raise SystemExit(f"error: {label} is not canonically spelled")
    return Path(raw)


def no_symlink_chain(path: Path, *, include_leaf: bool) -> None:
    current = Path("/")
    parts = path.parts[1:] if include_leaf else path.parent.parts[1:]
    for component in parts:
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            raise SystemExit(f"error: missing path component: {current}") from None
        if stat.S_ISLNK(metadata.st_mode):
            raise SystemExit(f"error: symlink path component is forbidden: {current}")


roots = [
    canonical_absolute(orchestrator, "orchestrator"),
    canonical_absolute(subject, "subject"),
    canonical_absolute(v1, "v1"),
]
if len(set(roots)) != len(roots):
    raise SystemExit("error: checkout roots must be distinct")
for root in roots:
    no_symlink_chain(root, include_leaf=True)
    metadata = os.lstat(root)
    if not stat.S_ISDIR(metadata.st_mode) or root.resolve(strict=True) != root:
        raise SystemExit(f"error: checkout root is not a canonical directory: {root}")

evidence_path = canonical_absolute(evidence, "evidence")
status_path = canonical_absolute(status_file, "status file")
if status_file != f"{evidence}/proof.status" or status_path.parent != evidence_path:
    raise SystemExit("error: status file must be fixed direct child proof.status")
if os.path.lexists(evidence_path):
    raise SystemExit("error: evidence root already exists")
no_symlink_chain(evidence_path, include_leaf=False)
parent = evidence_path.parent
parent_metadata = os.lstat(parent)
if not stat.S_ISDIR(parent_metadata.st_mode) or parent.resolve(strict=True) != parent:
    raise SystemExit("error: evidence parent is not a canonical directory")
os.mkdir(evidence_path, 0o700)
metadata = os.lstat(evidence_path)
if (
    not stat.S_ISDIR(metadata.st_mode)
    or stat.S_IMODE(metadata.st_mode) != 0o700
    or metadata.st_nlink < 2
):
    raise SystemExit("error: evidence root is not a private directory")
parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
PY

proof_status=125
write_status() {
	STATUS_VALUE="${1:?}" /usr/bin/python3 - "$evidence" proof.status <<'PY'
import os
import secrets
import stat
import sys
from pathlib import Path

root_raw, basename = sys.argv[1:]
value = os.environ.get("STATUS_VALUE", "")
if basename != "proof.status":
    raise SystemExit("fixed status basename mismatch")
if (
    not value.isascii()
    or not value.isdecimal()
    or str(int(value)) != value
    or not 0 <= int(value) <= 255
):
    raise SystemExit("invalid status value")
root = Path(root_raw)
if (
    not root.is_absolute()
    or str(root) != os.path.normpath(str(root))
    or root.resolve(strict=True) != root
):
    raise SystemExit("invalid status root")

directory_flags = (
    os.O_RDONLY
    | os.O_DIRECTORY
    | os.O_NOFOLLOW
    | getattr(os, "O_CLOEXEC", 0)
)
descriptor = os.open(root, directory_flags)
temporary = ""
renamed_identity = None
try:
    root_metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise RuntimeError("status root is not private")
    if os.environ.get("X86_CACHE_GATE_STATUS_FAULT") == "create":
        raise OSError("injected status temporary-file creation failure")
    for _ in range(128):
        temporary = f".proof.status.{secrets.token_hex(16)}"
        try:
            output = os.open(
                temporary,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=descriptor,
            )
            break
        except FileExistsError:
            continue
    else:
        raise RuntimeError("cannot allocate status temporary")
    try:
        payload = f"{value}\n".encode("ascii")
        view = memoryview(payload)
        while view:
            written = os.write(output, view)
            if written <= 0:
                raise OSError("short status write")
            view = view[written:]
        os.fsync(output)
        held = os.fstat(output)
        if (
            not stat.S_ISREG(held.st_mode)
            or stat.S_IMODE(held.st_mode) != 0o600
            or held.st_nlink != 1
        ):
            raise RuntimeError("unsafe status temporary")
        renamed_identity = (held.st_dev, held.st_ino)
    finally:
        os.close(output)
    if os.environ.get("X86_CACHE_GATE_STATUS_FAULT") == "rename":
        raise OSError("injected status rename failure")
    os.rename(
        temporary,
        basename,
        src_dir_fd=descriptor,
        dst_dir_fd=descriptor,
    )
    temporary = ""
    os.fsync(descriptor)
    final = os.stat(basename, dir_fd=descriptor, follow_symlinks=False)
    final_fd = os.open(
        basename,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        dir_fd=descriptor,
    )
    try:
        body = os.read(final_fd, 32)
        after = os.fstat(final_fd)
    finally:
        os.close(final_fd)
    if (
        not stat.S_ISREG(final.st_mode)
        or (final.st_dev, final.st_ino) != renamed_identity
        or (after.st_dev, after.st_ino) != renamed_identity
        or final.st_nlink != 1
        or stat.S_IMODE(final.st_mode) != 0o600
        or body != f"{value}\n".encode("ascii")
    ):
        raise RuntimeError("durable status validation failed")
except BaseException:
    if temporary:
        try:
            os.unlink(temporary, dir_fd=descriptor)
        except FileNotFoundError:
            pass
    if renamed_identity is not None:
        try:
            current = os.stat(basename, dir_fd=descriptor, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == renamed_identity:
                os.unlink(basename, dir_fd=descriptor)
                os.fsync(descriptor)
        except FileNotFoundError:
            pass
    raise
finally:
    os.close(descriptor)
PY
}
invalidate_staged_proof() {
	/usr/bin/python3 - "$evidence/staging/bundle" <<'PY'
import json
import os
import secrets
import stat
import sys
from pathlib import Path

bundle = Path(sys.argv[1])
if not bundle.exists():
    raise SystemExit(0)
descriptor = os.open(
    bundle,
    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
)
temporary = ""
try:
    source = os.open(
        "provenance.json",
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        dir_fd=descriptor,
    )
    try:
        metadata = os.fstat(source)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RuntimeError("unsafe provenance")
        chunks = []
        while chunk := os.read(source, 1024 * 1024):
            chunks.append(chunk)
    finally:
        os.close(source)
    document = json.loads(b"".join(chunks))
    document["proof"] = {"status": 125, "result": "FAIL"}
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    for _ in range(128):
        temporary = f".provenance.failed.{secrets.token_hex(16)}"
        try:
            output = os.open(
                temporary,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=descriptor,
            )
            break
        except FileExistsError:
            continue
    else:
        raise RuntimeError("cannot allocate failed provenance")
    try:
        view = memoryview(payload)
        while view:
            written = os.write(output, view)
            if written <= 0:
                raise OSError("short failed-provenance write")
            view = view[written:]
        os.fsync(output)
    finally:
        os.close(output)
    os.rename(
        temporary,
        "provenance.json",
        src_dir_fd=descriptor,
        dst_dir_fd=descriptor,
    )
    temporary = ""
    os.fsync(descriptor)
except FileNotFoundError:
    pass
except BaseException:
    if temporary:
        try:
            os.unlink(temporary, dir_fd=descriptor)
        except FileNotFoundError:
            pass
    try:
        os.unlink("provenance.json", dir_fd=descriptor)
        os.fsync(descriptor)
    except FileNotFoundError:
        pass
    raise
finally:
    os.close(descriptor)
PY
}
finish() {
	local code=$? final_status=125
	trap - EXIT
	if [[ "$code" =~ ^[0-9]+$ ]]; then
		if (( code <= 255 )); then
			final_status=$code
		fi
	fi
	if (( final_status != 0 )); then
		invalidate_staged_proof || true
	fi
	if ! write_status "$final_status"; then
		final_status=125
		invalidate_staged_proof || true
		write_status 125 || true
	fi
	exit "$final_status"
}
trap finish EXIT

fail() {
	echo "error: $*" >&2
	return 1
}

LC_ALL=C
export LC_ALL
[[ $run_id =~ ^[1-9][0-9]*$ ]] || fail "run ID must be a canonical positive decimal"
[[ $run_attempt =~ ^[1-9][0-9]*$ ]] || fail "run attempt must be a canonical positive decimal"
decimal_within_bound() {
	local value=$1 maximum=$2
	((${#value} < ${#maximum})) && return 0
	((${#value} == ${#maximum})) || return 1
	[[ $value == "$maximum" || $value < "$maximum" ]]
}
decimal_within_bound "$run_id" 9223372036854774 || fail "run ID is too large"
decimal_within_bound "$run_attempt" 999 || fail "run attempt is too large"
CACHE_GATE_ATTEMPT=$((run_id * 1000 + run_attempt))
export CACHE_GATE_ATTEMPT

[[ -r $OSTYPE_FILE ]] || fail "Linux kernel ostype is unavailable"
IFS= read -r kernel_ostype <"$OSTYPE_FILE"
[[ $kernel_ostype == Linux ]] || fail "native Linux is required"
[[ $("$UNAME_TOOL" -m) == x86_64 ]] || fail "native x86_64 is required"

[[ ${RUSTUP_HOME:-} == /* ]] || fail "absolute RUSTUP_HOME is required"
[[ ${CARGO_HOME:-} == /* ]] || fail "absolute CARGO_HOME is required"
toolchain_root="$RUSTUP_HOME/toolchains/$TOOLCHAIN_NAME"
[[ -d $toolchain_root/bin ]] || fail "pinned Rust toolchain is unavailable"
export PATH="$toolchain_root/bin:/usr/local/bin:/usr/bin:/bin"
unset LD_LIBRARY_PATH RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
[[ $(rustc --version --verbose) == "$PINNED_RUSTC_VERSION" ]] || fail "rustc 1.95.0 x86_64 identity mismatch"
[[ $(cargo --version) == "$PINNED_CARGO_VERSION" ]] || fail "cargo 1.95.0 identity mismatch"

checkout_identity() {
	local root=$1 expected_commit=$2 expected_tree=$3 label=$4 head tree dirty
	head=$(git -C "$root" rev-parse HEAD)
	tree=$(git -C "$root" rev-parse 'HEAD^{tree}')
	[[ $head == "$expected_commit" ]] || fail "$label commit mismatch"
	[[ $tree == "$expected_tree" ]] || fail "$label tree mismatch"
	dirty=$(git -C "$root" status --porcelain --untracked-files=normal)
	[[ -z $dirty ]] || fail "$label checkout must be clean"
}

orchestrator_head=$(git -C "$orchestrator" rev-parse HEAD)
orchestrator_tree=$(git -C "$orchestrator" rev-parse 'HEAD^{tree}')
[[ -n ${GITHUB_SHA:-} && $GITHUB_SHA == "$orchestrator_head" ]] || fail "GITHUB_SHA differs from orchestrator HEAD"
[[ -z $(git -C "$orchestrator" status --porcelain --untracked-files=normal) ]] || fail "orchestrator checkout must be clean"
checkout_identity "$subject" "$SUBJECT_COMMIT" "$SUBJECT_TREE" subject
checkout_identity "$v1" "$V1_COMMIT" "$V1_TREE" v1

[[ ${GITHUB_REPOSITORY:-} =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail "invalid GITHUB_REPOSITORY"
github_owner=${GITHUB_REPOSITORY%%/*}
github_name=${GITHUB_REPOSITORY#*/}
[[ $github_owner != . && $github_owner != .. && $github_name != . && $github_name != .. ]] || fail "invalid GITHUB_REPOSITORY"
[[ ${GITHUB_REF:-} == refs/heads/ci/x86-cache-gate-evidence ]] || fail "unexpected GITHUB_REF"

mkdir -m 0700 "$evidence/logs"
resolved_lld=$(command -v ld.lld || true)
[[ $resolved_lld == "$LLD_TOOL" && -e $LLD_TOOL ]] || fail "ld.lld must resolve to $LLD_TOOL"
lld_owner=$(dpkg-query -S "$LLD_TOOL") || fail "cannot identify ld.lld package"
[[ $lld_owner == "lld: $LLD_TOOL" || $lld_owner == "lld:amd64: $LLD_TOOL" ]] || fail "ld.lld is not owned by the Ubuntu lld package"
lld_package_record=$(dpkg-query -W '-f=${Status}\t${Architecture}\t${Version}\n' lld)
[[ $lld_package_record == $'install ok installed\t'* ]] || fail "invalid lld package record"
if ! dpkg -V lld >"$evidence/logs/lld.dpkg-verify.log" 2>&1; then
	fail "dpkg -V lld failed"
fi
[[ ! -s $evidence/logs/lld.dpkg-verify.log ]] || fail "dpkg -V lld reported modified files"

clean_variant="x86_64-061d13da22b8-attempt-${CACHE_GATE_ATTEMPT}-clean-a"
repeat_variant="x86_64-061d13da22b8-attempt-${CACHE_GATE_ATTEMPT}-clean-b"
adversary_variant="x86_64-061d13da22b8-attempt-${CACHE_GATE_ATTEMPT}-adversary"
v1_variant="x86_64-v1-replay-run-${run_id}-attempt-${run_attempt}"
output_roots=( \
	"$subject/target/cache-gate-linker/x86_64" \
	"$subject/target/cache-gate/x86_64/$clean_variant" \
	"$subject/target/cache-gate/x86_64/$repeat_variant" \
	"$subject/target/cache-gate/x86_64/$adversary_variant" \
	"$subject/target/cache-gate-build/$clean_variant" \
	"$subject/target/cache-gate-build/$repeat_variant" \
	"$subject/target/cache-gate-build/$adversary_variant" \
	"$subject/tools/cache-gate-control/target" \
	"$subject/target/cache-gate-control-bin.txt" \
	"$subject/target/cache-gate-control-build.json" \
	"$v1/target/cache-gate/x86_64/$v1_variant" \
	"$v1/target/cache-gate-build/x86_64/$v1_variant" \
	"$v1/tools/cache-gate-control/target" \
	"$v1/target/cache-gate-control-bin.txt" \
	"$v1/target/cache-gate-control-build.json" \
	"$evidence/staging"
)
/usr/bin/python3 - "${output_roots[@]}" <<'PY'
import os
import stat
import sys
from pathlib import Path

for raw in sys.argv[1:]:
    path = Path(raw)
    if os.path.lexists(path):
        raise SystemExit(f"error: immutable output root already exists: {path}")
    current = Path("/")
    for component in path.parent.parts[1:]:
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(metadata.st_mode):
            raise SystemExit(f"error: symlink output ancestor is forbidden: {current}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise SystemExit(f"error: non-directory output ancestor: {current}")
PY

mkdir -m 0700 "$evidence/work"
capability_stdout="$evidence/logs/capability.stdout"
"$subject/scripts/cache-gate-linker-capability.sh" >"$capability_stdout" 2>"$evidence/logs/capability.stderr"
mapfile -t capability_lines <"$capability_stdout"
[[ ${#capability_lines[@]} == 1 && ${capability_lines[0]} == /* ]] || fail "capability emitted malformed stdout path"
capability=${capability_lines[0]}
expected_capability="$subject/target/cache-gate-linker/x86_64/capability.json"
[[ $capability == "$expected_capability" && -f $capability && ! -L $capability ]] || fail "capability path is not canonical"

# Apply the complete reviewed schema/shape/identity contract before any control
# or manifest build. The later inventory adds live linker-chain/package proof.
/usr/bin/python3 - \
	"$orchestrator/scripts/verify-x86-cache-gate-evidence.py" \
	"$capability" "$subject" <<'PY'
import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

verifier_raw, capability_raw, subject_root = sys.argv[1:]
spec = importlib.util.spec_from_file_location(
    "cache_gate_capability_preflight",
    verifier_raw,
)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load reviewed capability verifier")
verifier = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verifier
spec.loader.exec_module(verifier)


def strict_object(data: bytes, label: str) -> dict:
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise RuntimeError(f"duplicate JSON key in {label}: {key}")
            result[key] = value
        return result

    document = json.loads(data, object_pairs_hook=pairs)
    if not isinstance(document, dict):
        raise RuntimeError(f"JSON document is not an object: {label}")
    return document


def read_regular(raw: str, label: str) -> bytes:
    if (
        not isinstance(raw, str)
        or not raw.startswith("/")
        or "\0" in raw
        or raw != os.path.normpath(raw)
        or any(part in {"", ".", ".."} for part in raw.split("/")[1:])
    ):
        raise RuntimeError(f"noncanonical capability path: {label}")
    descriptor = os.open(raw, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError(f"capability input is not regular: {label}")
        chunks = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if identity(before) != identity(after):
        raise RuntimeError(f"capability input changed while reading: {label}")
    return b"".join(chunks)


capability_data = read_regular(capability_raw, "capability")
capability = strict_object(capability_data, "capability")
verifier._validate_schema(capability, verifier.CAPABILITY_SCHEMA, "capability")
expected_shapes = {
    (flavor, target, count)
    for flavor in ("actual", "gnu", "lld")
    for target, count in (("elastic", 2), ("funnel", 2), ("profile", 4))
}
producer = capability["producer"]
if (
    capability["accepted"] is not True
    or capability["arch"] != "x86_64"
    or capability["target_triple"] != "x86_64-unknown-linux-gnu"
    or capability["cargo_version"] != verifier.PINNED_CARGO_VERSION
    or capability["rustc_version"] != verifier.PINNED_RUSTC_VERSION
    or producer["runner_root"] != subject_root
    or producer["commit"] != verifier.SUBJECT_COMMIT
    or producer["tree"] != verifier.SUBJECT_TREE
    or producer["empty_diff_assertion"] is not True
    or verifier.capability_shapes(capability) != expected_shapes
):
    raise RuntimeError("capability exact identity/shape contract mismatch")


def verify_hash_records(value: object) -> None:
    if isinstance(value, dict):
        if {"absolute_path", "sha256"}.issubset(value):
            raw = value["absolute_path"]
            expected = value["sha256"]
            data = read_regular(raw, raw)
            if hashlib.sha256(data).hexdigest() != expected:
                raise RuntimeError(f"capability file hash mismatch: {raw}")
        for child in value.values():
            verify_hash_records(child)
    elif isinstance(value, list):
        for child in value:
            verify_hash_records(child)


verify_hash_records(capability)


def read_shape_record(flavor: str, target: str, name: str) -> bytes:
    shape = capability["shapes"][flavor][target]
    direct = {
        "link-args.txt": shape["link_argv"]["absolute_path"],
        "linker-execution.json": shape["linker_execution"]["absolute_path"],
        "symbols.json": shape["symbols"]["absolute_path"],
        "layout.json": shape["layout"]["absolute_path"],
    }
    if name == "cargo-execution.json":
        raw = shape["cargo_execution"]["absolute_path"]
    elif name in {"linker-trace.jsonl", "cargo-trace.jsonl"}:
        key = "linker_execution" if name == "linker-trace.jsonl" else "cargo_execution"
        execution_data = read_regular(shape[key]["absolute_path"], name)
        execution = strict_object(execution_data, name)
        raw = execution["trace"]["absolute_path"]
    else:
        raw = direct[name]
    return read_regular(raw, f"{flavor}/{target}/{name}")


observed = verifier.verify_capability_shape_records(
    capability,
    read_shape_record,
)
if observed != expected_shapes:
    raise RuntimeError("capability exact 2/2/4 shape validation mismatch")
PY

# Validate all 2/2/4 execution records and every live linker chain before any
# control or manifest is built. Output is published only after every chain and
# package record succeeds.
/usr/bin/python3 - "$capability" "$subject" "$evidence/logs/linker-inventory.json" <<'PY'
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath

capability_path, subject_raw, output_raw = sys.argv[1:]


def strict_object(data: bytes, label: str) -> dict:
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise RuntimeError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    value = json.loads(data, object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise RuntimeError(f"invalid JSON object: {label}")
    return value


def strict_json(path: Path) -> dict:
    return strict_object(path.read_bytes(), str(path))


def canonical(raw: str) -> PurePosixPath:
    if (
        not isinstance(raw, str)
        or not raw.startswith("/")
        or "\0" in raw
        or any(part in {"", ".", ".."} for part in raw.split("/")[1:])
    ):
        raise RuntimeError(f"noncanonical absolute path: {raw!r}")
    return PurePosixPath(raw)


def resolve_target(source: PurePosixPath, raw: str) -> PurePosixPath:
    if not raw or "\0" in raw:
        raise RuntimeError("invalid linker symlink target")
    parts = [] if raw.startswith("/") else list(source.parent.parts[1:])
    for component in raw.split("/"):
        if component in {"", "."}:
            continue
        if component == "..":
            if not parts:
                raise RuntimeError("linker symlink escapes virtual root")
            parts.pop()
        else:
            parts.append(component)
    return canonical("/" + "/".join(parts))


def digest(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError(f"linker terminal is not regular: {path}")
        value = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            value.update(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise RuntimeError(f"linker terminal changed: {path}")
        return value.hexdigest()
    finally:
        os.close(descriptor)


def hashed_json(record: object, label: str) -> dict:
    if not isinstance(record, dict) or set(record) != {"absolute_path", "sha256"}:
        raise RuntimeError(f"invalid hashed JSON record: {label}")
    raw = record["absolute_path"]
    expected = record["sha256"]
    path = canonical(raw)
    if (
        not isinstance(expected, str)
        or len(expected) != 64
        or any(character not in "0123456789abcdef" for character in expected)
    ):
        raise RuntimeError(f"invalid hashed JSON digest: {label}")
    descriptor = os.open(path.as_posix(), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError(f"hashed JSON is not regular: {label}")
        chunks = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise RuntimeError(f"hashed JSON changed while reading: {label}")
    data = b"".join(chunks)
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError(f"hashed JSON digest mismatch: {label}")
    return strict_object(data, label)


def package(path: str) -> dict:
    owned = subprocess.run(
        ["dpkg-query", "-S", path], text=True, capture_output=True, check=False
    )
    if owned.returncode != 0:
        raise RuntimeError(f"linker chain member lacks package ownership: {path}")
    lines = [line for line in owned.stdout.splitlines() if line]
    if len(lines) != 1 or ": " not in lines[0]:
        raise RuntimeError(f"ambiguous linker package ownership: {path}")
    binary_package, owned_path = lines[0].split(": ", 1)
    if owned_path != path:
        raise RuntimeError(f"linker package ownership path mismatch: {path}")
    owner_parts = binary_package.split(":")
    if (
        len(owner_parts) not in {1, 2}
        or not owner_parts[0]
        or (len(owner_parts) == 2 and not owner_parts[1])
    ):
        raise RuntimeError(f"invalid linker package owner: {path}")
    package_name = owner_parts[0]
    owner_architecture = owner_parts[1] if len(owner_parts) == 2 else None
    queried = subprocess.run(
        [
            "dpkg-query",
            "-W",
            "-f=${Status}\\t${Architecture}\\t${Version}\\n",
            binary_package,
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    fields = queried.stdout.rstrip("\n").split("\t")
    if queried.returncode != 0 or len(fields) != 3 or fields[0] != "install ok installed":
        raise RuntimeError(f"invalid package record for {package_name}")
    if owner_architecture is not None and owner_architecture != fields[1]:
        raise RuntimeError(
            f"linker package ownership architecture mismatch: {path}"
        )
    verified = subprocess.run(
        ["dpkg", "-V", binary_package], text=True, capture_output=True, check=False
    )
    if verified.returncode != 0 or verified.stdout or verified.stderr:
        raise RuntimeError(f"dpkg -V failed for {package_name}")
    return {
        "name": package_name,
        "architecture": fields[1],
        "version": fields[2],
        "verification_status": 0,
    }


document = strict_json(Path(capability_path))
if (
    document.get("accepted") is not True
    or document.get("arch") != "x86_64"
    or document.get("target_triple") != "x86_64-unknown-linux-gnu"
    or document.get("producer", {}).get("runner_root") != subject_raw
):
    raise RuntimeError("capability identity is not accepted native x86_64")
shapes = document.get("shapes")
if not isinstance(shapes, dict) or set(shapes) != {"actual", "gnu", "lld"}:
    raise RuntimeError("capability lacks exact linker flavors")
top = document.get("linker")
required = document.get("required_linkers")
if (
    not isinstance(top, dict)
    or not isinstance(required, dict)
    or set(required) != {"gnu", "lld"}
):
    raise RuntimeError("invalid top-level linker records")
expected_linkers = {"actual": top, "gnu": required["gnu"], "lld": required["lld"]}
records = []
for flavor in ("actual", "gnu", "lld"):
    targets = shapes.get(flavor)
    if not isinstance(targets, dict) or set(targets) != {"elastic", "funnel", "profile"}:
        raise RuntimeError(f"capability lacks exact {flavor} shapes")
    for target, count in (("elastic", 2), ("funnel", 2), ("profile", 4)):
        shape = targets[target]
        record = shape.get("linker_execution")
        execution = hashed_json(record, f"{flavor}/{target} linker execution")
        linker = execution.get("linker")
        if linker != expected_linkers[flavor]:
            raise RuntimeError(f"wrong {flavor}/{target} linker record")
        records.append((f"{flavor}/{target}/{count}", linker))
        if flavor != "actual":
            cargo_record = shape.get("cargo_execution")
            cargo_execution = hashed_json(
                cargo_record,
                f"{flavor}/{target} Cargo-driver execution",
            )
            cargo_linker = cargo_execution.get("linker")
            if cargo_linker != top:
                raise RuntimeError(f"wrong {flavor}/{target} Cargo-driver linker record")
            records.append(
                (f"{flavor}/{target}/{count}/cargo-driver", cargo_linker)
            )
records.extend(
    [
        ("top/actual", top),
        ("top/gnu", required["gnu"]),
        ("top/lld", required["lld"]),
    ]
)

file_records = {}
associations = []
link_pairs = set()
package_records = {}
for association, record in records:
    invocation = canonical(record.get("invocation_path"))
    declared = record.get("invocation_chain")
    if not isinstance(declared, list) or not declared:
        raise RuntimeError(f"missing invocation chain: {association}")
    observed = []
    seen = set()
    current = invocation
    while True:
        raw_path = current.as_posix()
        if raw_path in seen:
            raise RuntimeError(f"linker chain cycle: {raw_path}")
        seen.add(raw_path)
        try:
            metadata = os.lstat(raw_path)
        except FileNotFoundError:
            raise RuntimeError(f"linker chain member is missing: {raw_path}") from None
        package_record = package(raw_path)
        previous_package = package_records.setdefault(
            package_record["name"], package_record
        )
        if previous_package != package_record:
            raise RuntimeError(
                f"inconsistent package record: {package_record['name']}"
            )
        if stat.S_ISLNK(metadata.st_mode):
            raw_target = os.readlink(raw_path)
            observed.append({"absolute_path": raw_path, "symlink_target": raw_target})
            link_pairs.add((raw_path, raw_target))
            file_records[raw_path] = {
                "absolute_path": raw_path,
                "type": "symlink",
                "mode": stat.S_IMODE(metadata.st_mode),
                "raw_target": raw_target,
                "package": package_record["name"],
            }
            current = resolve_target(current, raw_target)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"linker chain terminal is not regular: {raw_path}")
        sha256 = digest(Path(raw_path))
        observed.append({"absolute_path": raw_path, "symlink_target": None})
        file_records[raw_path] = {
            "absolute_path": raw_path,
            "type": "file",
            "mode": stat.S_IMODE(metadata.st_mode),
            "sha256": sha256,
            "package": package_record["name"],
        }
        if record.get("payload_path") != raw_path or record.get("payload_sha256") != sha256:
            raise RuntimeError(f"linker payload identity mismatch: {association}")
        break
    if declared != observed:
        raise RuntimeError(f"recorded linker chain differs from live chain: {association}")
    associations.append(
        {
            "record": association,
            "invocation_path": invocation.as_posix(),
            "members": [item["absolute_path"] for item in observed],
        }
    )

payload = {
    "version": 1,
    "associations": sorted(associations, key=lambda item: item["record"]),
    "files": [file_records[key] for key in sorted(file_records)],
    "packages": [package_records[key] for key in sorted(package_records)],
    "system_links": [
        {"source": source, "raw_target": target}
        for source, target in sorted(link_pairs)
    ],
}
output = Path(output_raw)
temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
temporary.replace(output)
PY

BUILD_CONTROL=1 "$subject/scripts/cache-gate.sh" --runner-root "$subject" >"$evidence/logs/v2-control.stdout" 2>"$evidence/logs/v2-control.stderr"
mapfile -t control <"$subject/target/cache-gate-control-bin.txt"
[[ ${#control[@]} == 2 && ${control[0]} == /* && ${control[1]} == /* ]] || fail "malformed v2 control record"

CACHE_GATE_CONTROL_BIN="${control[0]}" CACHE_GATE_CONTROL_PROVENANCE="${control[1]}" CACHE_GATE_LINKER_CAPABILITY="$capability" CACHE_GATE_VARIANT="$clean_variant" CACHE_GATE_MANIFEST_INSTANCE="$clean_variant" CACHE_GATE_LAYOUT_ADVERSARY=0 MANIFEST=1 \
	"$subject/scripts/cache-gate.sh" --runner-root "$subject" >"$evidence/logs/clean-a.stdout" 2>"$evidence/logs/clean-a.stderr"
CACHE_GATE_CONTROL_BIN="${control[0]}" CACHE_GATE_CONTROL_PROVENANCE="${control[1]}" CACHE_GATE_LINKER_CAPABILITY="$capability" CACHE_GATE_VARIANT="$repeat_variant" CACHE_GATE_MANIFEST_INSTANCE="$repeat_variant" CACHE_GATE_LAYOUT_ADVERSARY=0 MANIFEST=1 \
	"$subject/scripts/cache-gate.sh" --runner-root "$subject" >"$evidence/logs/clean-b.stdout" 2>"$evidence/logs/clean-b.stderr"
CACHE_GATE_CONTROL_BIN="${control[0]}" CACHE_GATE_CONTROL_PROVENANCE="${control[1]}" CACHE_GATE_LINKER_CAPABILITY="$capability" CACHE_GATE_VARIANT="$adversary_variant" CACHE_GATE_MANIFEST_INSTANCE="$adversary_variant" CACHE_GATE_LAYOUT_ADVERSARY=1 MANIFEST=1 \
	"$subject/scripts/cache-gate.sh" --runner-root "$subject" >"$evidence/logs/adversary.stdout" 2>"$evidence/logs/adversary.stderr"

clean_manifest="$subject/target/cache-gate/x86_64/$clean_variant/manifest.json"
repeat_manifest="$subject/target/cache-gate/x86_64/$repeat_variant/manifest.json"
adversary_manifest="$subject/target/cache-gate/x86_64/$adversary_variant/manifest.json"
for manifest in "$clean_manifest" "$repeat_manifest" "$adversary_manifest"; do
	[[ -f $manifest && ! -L $manifest ]] || fail "manifest was not published: $manifest"
done

"$subject/scripts/cache-gate-elf-layout.py" validate-manifest --manifest "$clean_manifest" >"$evidence/logs/clean-a.validate-manifest.stdout" 2>"$evidence/logs/clean-a.validate-manifest.stderr"
"$subject/scripts/cache-gate-elf-layout.py" validate-manifest --manifest "$repeat_manifest" >"$evidence/logs/clean-b.validate-manifest.stdout" 2>"$evidence/logs/clean-b.validate-manifest.stderr"
"$subject/scripts/cache-gate-elf-layout.py" validate-manifest --manifest "$adversary_manifest" >"$evidence/logs/adversary.validate-manifest.stdout" 2>"$evidence/logs/adversary.validate-manifest.stderr"
"$subject/scripts/cache-gate-elf-layout.py" compare --anchor "$clean_manifest" --candidate "$repeat_manifest" >"$evidence/logs/clean-repeat.compare.stdout" 2>"$evidence/logs/clean-repeat.compare.stderr"
"$subject/scripts/cache-gate-elf-layout.py" compare --anchor "$clean_manifest" --candidate "$adversary_manifest" >"$evidence/logs/adversary.compare.stdout" 2>"$evidence/logs/adversary.compare.stderr"

BUILD_CONTROL=1 "$v1/scripts/cache-gate.sh" --runner-root "$v1" >"$evidence/logs/v1-control.stdout" 2>"$evidence/logs/v1-control.stderr"
mapfile -t v1_control <"$v1/target/cache-gate-control-bin.txt"
[[ ${#v1_control[@]} == 2 && ${v1_control[0]} == /* && ${v1_control[1]} == /* ]] || fail "malformed v1 control record"
CACHE_GATE_CONTROL_BIN="${v1_control[0]}" CACHE_GATE_CONTROL_PROVENANCE="${v1_control[1]}" CACHE_GATE_VARIANT="$v1_variant" MANIFEST=1 \
	"$v1/scripts/cache-gate.sh" --runner-root "$v1" >"$evidence/logs/v1-manifest.stdout" 2>"$evidence/logs/v1-manifest.stderr"
v1_manifest="$v1/target/cache-gate/x86_64/$v1_variant/manifest.json"
[[ -f $v1_manifest && ! -L $v1_manifest ]] || fail "v1 manifest was not published"

# Fully authenticate the v1 manifest, both controls, current reviewed tools, and
# all hash-bearing inputs before the current extractor may observe a v1 binary.
/usr/bin/python3 - \
	"$orchestrator/scripts/verify-x86-cache-gate-evidence.py" \
	"$capability" "$clean_manifest" "$repeat_manifest" "$adversary_manifest" \
	"$v1_manifest" "$v1" <<'PY'
import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

(
    verifier_raw,
    capability_raw,
    clean_raw,
    repeat_raw,
    adversary_raw,
    v1_raw,
    v1_root,
) = sys.argv[1:]
spec = importlib.util.spec_from_file_location(
    "cache_gate_v1_preflight",
    verifier_raw,
)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load reviewed v1 verifier")
verifier = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verifier
spec.loader.exec_module(verifier)


def strict_object(data: bytes, label: str) -> dict:
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise RuntimeError(f"duplicate JSON key in {label}: {key}")
            result[key] = value
        return result

    document = json.loads(data, object_pairs_hook=pairs)
    if not isinstance(document, dict):
        raise RuntimeError(f"JSON document is not an object: {label}")
    return document


def read_regular(raw: str, label: str) -> bytes:
    if (
        not isinstance(raw, str)
        or not raw.startswith("/")
        or "\0" in raw
        or raw != os.path.normpath(raw)
        or any(part in {"", ".", ".."} for part in raw.split("/")[1:])
    ):
        raise RuntimeError(f"noncanonical hosted path: {label}")
    descriptor = os.open(raw, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError(f"hosted input is not regular: {label}")
        chunks = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if identity(before) != identity(after):
        raise RuntimeError(f"hosted input changed while reading: {label}")
    return b"".join(chunks)


def load(raw: str, label: str) -> tuple[dict, bytes]:
    data = read_regular(raw, label)
    return strict_object(data, label), data


capability, capability_data = load(capability_raw, "capability")
manifests = [
    load(raw, label)[0]
    for raw, label in (
        (clean_raw, "clean-a"),
        (repeat_raw, "clean-b"),
        (adversary_raw, "adversary"),
    )
]
v1, _v1_data = load(v1_raw, "manifest_v1")
verifier._validate_schema(capability, verifier.CAPABILITY_SCHEMA, "capability")
for index, manifest in enumerate(manifests):
    verifier._validate_schema(
        manifest,
        verifier.MANIFEST_V2_SCHEMA,
        f"manifest_v2[{index}]",
    )
verifier._validate_schema(v1, verifier.MANIFEST_V1_SCHEMA, "manifest_v1")
verifier.verify_x86_contracts(capability, manifests, v1)
verifier.verify_identity_contract(
    {
        "subject": {
            "commit": verifier.SUBJECT_COMMIT,
            "tree": verifier.SUBJECT_TREE,
        }
    },
    capability,
    manifests,
    v1,
    capability_data,
    v1_root,
)
verifier.verify_manifest_relationships(*manifests)


def verify_hash_records(value: object) -> None:
    if isinstance(value, dict):
        if {"absolute_path", "sha256"}.issubset(value):
            raw = value["absolute_path"]
            data = read_regular(raw, raw)
            if hashlib.sha256(data).hexdigest() != value["sha256"]:
                raise RuntimeError(f"hosted file hash mismatch: {raw}")
        for child in value.values():
            verify_hash_records(child)
    elif isinstance(value, list):
        for child in value:
            verify_hash_records(child)


for document in (capability, *manifests, v1):
    verify_hash_records(document)

for label, control in (
    *((f"v2 manifest {manifest['variant']}", manifest["control"]) for manifest in manifests),
    ("v1 manifest", v1["control"]),
):
    provenance_data = read_regular(
        control["provenance_path"],
        f"{label} control provenance",
    )
    if hashlib.sha256(provenance_data).hexdigest() != control["provenance_sha256"]:
        raise RuntimeError(f"{label} control provenance hash mismatch")

all_symbol_names: set[str] = set()
all_kernel_names: set[str] = set()
for executable, (_target, expected_kernels) in verifier.EXECUTABLE_TARGETS.items():
    symbols = v1["symbols"][executable]["symbols"]
    expected_selection = [
        (f"{executable}::{kernel}", f"::{kernel}$")
        for kernel in expected_kernels
    ]
    observed_selection = [
        (symbol["name"], symbol["pattern"])
        for symbol in symbols
    ]
    full_names = [symbol["name"] for symbol in symbols]
    observed_kernels = [
        name.rsplit("::", 1)[-1] for name, _pattern in observed_selection
    ]
    if (
        len(symbols) != len(expected_kernels)
        or observed_selection != expected_selection
        or len(full_names) != len(set(full_names))
        or any(name in all_symbol_names for name in full_names)
        or any(kernel in all_kernel_names for kernel in observed_kernels)
    ):
        raise RuntimeError(
            f"v1 exact symbol selection mismatch: {executable}"
        )
    all_symbol_names.update(full_names)
    all_kernel_names.update(observed_kernels)
if len(all_symbol_names) != 8 or len(all_kernel_names) != 8:
    raise RuntimeError("v1 exact symbol selection must contain eight unique names")

fragment_identities: set[tuple[int, int]] = set()
for target, fragment in capability["fragments"].items():
    metadata = os.lstat(fragment["absolute_path"])
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError(f"capability fragment is not regular: {target}")
    identity = (metadata.st_dev, metadata.st_ino)
    if identity in fragment_identities:
        raise RuntimeError("capability fragments lack distinct hosted identity")
    fragment_identities.add(identity)
private_fragment_count = 0
for manifest in manifests:
    for target in capability["fragments"]:
        raw = verifier._manifest_fragment_path(manifest, target)
        metadata = os.lstat(raw)
        identity = (metadata.st_dev, metadata.st_ino)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or identity in fragment_identities
        ):
            raise RuntimeError(
                "private fragment lacks distinct hosted identity: "
                f"{manifest['variant']}/{target}"
            )
        fragment_identities.add(identity)
        private_fragment_count += 1
if private_fragment_count != 9 or len(fragment_identities) != 12:
    raise RuntimeError("hosted fragment identity set is not exact")

for manifest in manifests:
    for executable, (target, _kernels) in verifier.EXECUTABLE_TARGETS.items():
        command = manifest["build_proof"]["executables"][executable][
            "link_command"
        ]
        trace_data = read_regular(
            command["trace"]["absolute_path"],
            f"{manifest['variant']}/{executable} trace",
        )
        verifier.verify_manifest_link_command(
            command,
            trace_data,
            capability,
            target,
            manifest["executables"][executable],
            expected_fragment=verifier._manifest_fragment_path(
                manifest,
                target,
            ),
        )

if (
    v1["commit"] != verifier.V1_REPLAY_COMMIT
    or v1["tree"] != verifier.V1_REPLAY_TREE
    or v1["empty_diff_assertion"] is not True
    or v1["architecture"] != "x86_64"
):
    raise RuntimeError("v1 exact identity mismatch before extraction")
PY

mapfile -t v1_binaries < <(/usr/bin/python3 - "$v1_manifest" "$V1_COMMIT" "$V1_TREE" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

manifest_path, commit, tree = sys.argv[1:]
manifest = json.loads(Path(manifest_path).read_bytes())
if (
    manifest.get("commit") != commit
    or manifest.get("tree") != tree
    or manifest.get("empty_diff_assertion") is not True
    or manifest.get("architecture") != "x86_64"
):
    raise SystemExit("error: v1 manifest identity mismatch")
expected = {
    "elastic_cache_gate": (
        "::elastic_cache_gate_insert_kernel$",
        "::elastic_cache_gate_get_kernel$",
    ),
    "funnel_cache_gate": (
        "::funnel_cache_gate_insert_kernel$",
        "::funnel_cache_gate_get_kernel$",
    ),
    "cache_gate_profile": (
        "::elastic_profile_insert_kernel$",
        "::elastic_profile_get_kernel$",
        "::funnel_profile_insert_kernel$",
        "::funnel_profile_get_kernel$",
    ),
}
for name in ("elastic_cache_gate", "funnel_cache_gate", "cache_gate_profile"):
    record = manifest["executables"][name]
    binary = Path(record["absolute_path"])
    if (
        not binary.is_absolute()
        or binary.is_symlink()
        or not binary.is_file()
        or hashlib.sha256(binary.read_bytes()).hexdigest() != record["sha256"]
    ):
        raise SystemExit(f"error: unauthenticated v1 binary: {name}")
    symbols = manifest["symbols"][name]
    if (
        symbols["binary"] != str(binary)
        or symbols["binary_sha256"] != record["sha256"]
        or tuple(item["pattern"] for item in symbols["symbols"]) != expected[name]
    ):
        raise SystemExit(f"error: v1 symbol selection mismatch: {name}")
    print(binary)
PY
)
[[ ${#v1_binaries[@]} == 3 ]] || fail "v1 manifest did not authenticate three binaries"
mkdir -m 0700 "$evidence/work/v1-reextractions"
"$subject/scripts/extract-hot-symbols.py" --binary "${v1_binaries[0]}" --arch x86_64 \
	--symbol '::elastic_cache_gate_insert_kernel$' --symbol '::elastic_cache_gate_get_kernel$' \
	--output "$evidence/work/v1-reextractions/elastic_cache_gate.json"
"$subject/scripts/extract-hot-symbols.py" --binary "${v1_binaries[1]}" --arch x86_64 \
	--symbol '::funnel_cache_gate_insert_kernel$' --symbol '::funnel_cache_gate_get_kernel$' \
	--output "$evidence/work/v1-reextractions/funnel_cache_gate.json"
"$subject/scripts/extract-hot-symbols.py" --binary "${v1_binaries[2]}" --arch x86_64 \
	--symbol '::elastic_profile_insert_kernel$' --symbol '::elastic_profile_get_kernel$' \
	--symbol '::funnel_profile_insert_kernel$' --symbol '::funnel_profile_get_kernel$' \
	--output "$evidence/work/v1-reextractions/cache_gate_profile.json"

cargo_registry="$CARGO_HOME/registry"
mkdir -p "$cargo_registry"
/usr/bin/python3 - \
	"$orchestrator" "$subject" "$v1" "$evidence" "$capability" \
	"$clean_manifest" "$repeat_manifest" "$adversary_manifest" "$v1_manifest" \
	"$evidence/logs/linker-inventory.json" "$run_id" "$run_attempt" \
	"$CACHE_GATE_ATTEMPT" "$orchestrator_head" "$orchestrator_tree" \
	"$toolchain_root" "$cargo_registry" "$PINNED_RUSTC_VERSION" \
	"$PINNED_CARGO_VERSION" <<'PY'
import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any

(
    orchestrator_raw,
    subject_raw,
    v1_raw,
    evidence_raw,
    capability_raw,
    clean_raw,
    repeat_raw,
    adversary_raw,
    v1_manifest_raw,
    linker_inventory_raw,
    run_id_raw,
    run_attempt_raw,
    derived_raw,
    orchestrator_commit,
    orchestrator_tree,
    toolchain_raw,
    cargo_registry_raw,
    rustc_version,
    cargo_version,
) = sys.argv[1:]

orchestrator = Path(orchestrator_raw)
subject = Path(subject_raw)
v1_root = Path(v1_raw)
evidence = Path(evidence_raw)
toolchain = Path(toolchain_raw)
cargo_registry = Path(cargo_registry_raw)
staging = evidence / "staging"
bundle = staging / "bundle"

BODY_FIELDS = (
    "size",
    "normalized_instructions_sha256",
    "direct_calls",
    "indirect_calls",
    "frame_adjustment",
    "spills",
)
EXECUTABLES = (
    "elastic_cache_gate",
    "funnel_cache_gate",
    "cache_gate_profile",
)
TARGETS = {
    "elastic_cache_gate": "elastic",
    "funnel_cache_gate": "funnel",
    "cache_gate_profile": "profile",
}
ARCHIVE_ROOTS = {
    "orchestrator": PurePosixPath("bundle/orchestrator"),
    "subject": PurePosixPath("bundle/subject"),
    "v1": PurePosixPath("bundle/v1"),
    "evidence": PurePosixPath("bundle/evidence"),
    "toolchain": PurePosixPath("bundle/toolchain/rust"),
    "cargo-registry": PurePosixPath("bundle/toolchain/cargo-registry"),
    "system-root": PurePosixPath("bundle/system-root"),
}
HOSTED_ROOTS = {
    "orchestrator": PurePosixPath(orchestrator_raw),
    "subject": PurePosixPath(subject_raw),
    "v1": PurePosixPath(v1_raw),
    "evidence": PurePosixPath(evidence_raw),
    "toolchain": PurePosixPath(toolchain_raw),
    "cargo-registry": PurePosixPath(cargo_registry_raw),
    "system-root": PurePosixPath("/"),
}


def strict_json(path: Path) -> tuple[dict[str, Any], bytes]:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise RuntimeError(f"duplicate JSON key in {path}: {key}")
            result[key] = value
        return result

    data = path.read_bytes()
    value = json.loads(data, object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON document is not an object: {path}")
    return value, data


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hosted(raw: str) -> PurePosixPath:
    if (
        not raw.startswith("/")
        or "\0" in raw
        or any(part in {"", ".", ".."} for part in raw.split("/")[1:])
    ):
        raise RuntimeError(f"invalid hosted path: {raw!r}")
    return PurePosixPath(raw)


def archive_for(raw: str) -> PurePosixPath:
    path = canonical_hosted(raw)
    matches = []
    for name, hosted in HOSTED_ROOTS.items():
        if path == hosted or path.is_relative_to(hosted):
            matches.append((len(hosted.parts), name, hosted))
    if not matches:
        raise RuntimeError(f"path is outside evidence roots: {raw}")
    _, name, hosted = max(matches)
    return ARCHIVE_ROOTS[name] / path.relative_to(hosted)


if staging.exists() or staging.is_symlink():
    raise RuntimeError("staging root already exists")
staging.mkdir(mode=0o700)
bundle.mkdir(mode=0o755)
for archive in ARCHIVE_ROOTS.values():
    (staging / archive).mkdir(parents=True, exist_ok=True)


def copy_regular(source: Path, archive: PurePosixPath) -> str:
    if not archive.is_relative_to(PurePosixPath("bundle")):
        raise RuntimeError(f"archive destination escapes bundle: {archive}")
    source_metadata = os.lstat(source)
    if not stat.S_ISREG(source_metadata.st_mode):
        raise RuntimeError(f"evidence source is not regular: {source}")
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        chunks = []
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if identity(source_metadata) != identity(before) or identity(before) != identity(after):
        raise RuntimeError(f"evidence source changed while reading: {source}")
    data = b"".join(chunks)
    destination = staging / archive
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        if (
            destination.is_symlink()
            or not destination.is_file()
            or destination.read_bytes() != data
        ):
            raise RuntimeError(f"archive path collision: {archive}")
        return digest.hexdigest()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    output = os.open(destination, flags, stat.S_IMODE(before.st_mode))
    try:
        view = memoryview(data)
        while view:
            written = os.write(output, view)
            if written <= 0:
                raise OSError("short staged-file write")
            view = view[written:]
        os.fchmod(output, stat.S_IMODE(before.st_mode))
        os.fsync(output)
    finally:
        os.close(output)
    return digest.hexdigest()


def write_document(archive: PurePosixPath, data: bytes, mode: int = 0o600) -> str:
    destination = staging / archive
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise RuntimeError(f"document destination already exists: {archive}")
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode,
    )
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short document write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return sha256(data)


verifier_path = orchestrator / "scripts/verify-x86-cache-gate-evidence.py"
spec = importlib.util.spec_from_file_location("cache_gate_evidence_verifier", verifier_path)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load reviewed portable verifier")
verifier = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verifier
spec.loader.exec_module(verifier)

capability, capability_data = strict_json(Path(capability_raw))
manifest_documents = [
    strict_json(Path(path))
    for path in (clean_raw, repeat_raw, adversary_raw)
]
manifests = [item[0] for item in manifest_documents]
v1_manifest, v1_manifest_data = strict_json(Path(v1_manifest_raw))
reextraction_documents = {
    executable: strict_json(
        evidence / f"work/v1-reextractions/{executable}.json"
    )
    for executable in EXECUTABLES
}

# Re-run all schema and semantic checks before any generated contract is trusted.
verifier._validate_schema(capability, verifier.CAPABILITY_SCHEMA, "capability")
for index, manifest in enumerate(manifests):
    verifier._validate_schema(
        manifest, verifier.MANIFEST_V2_SCHEMA, f"manifest_v2[{index}]"
    )
verifier._validate_schema(v1_manifest, verifier.MANIFEST_V1_SCHEMA, "manifest_v1")
verifier.verify_x86_contracts(capability, manifests, v1_manifest)
verifier.verify_identity_contract(
    {
        "subject": {
            "commit": verifier.SUBJECT_COMMIT,
            "tree": verifier.SUBJECT_TREE,
        }
    },
    capability,
    manifests,
    v1_manifest,
    capability_data,
    v1_raw,
)
verifier.verify_manifest_relationships(*manifests)


def read_shape_record(flavor: str, target: str, name: str) -> bytes:
    shape = capability["shapes"][flavor][target]
    direct = {
        "link-args.txt": shape["link_argv"]["absolute_path"],
        "linker-execution.json": shape["linker_execution"]["absolute_path"],
        "symbols.json": shape["symbols"]["absolute_path"],
        "layout.json": shape["layout"]["absolute_path"],
    }
    if name == "cargo-execution.json":
        raw = shape["cargo_execution"]["absolute_path"]
    elif name in {"linker-trace.jsonl", "cargo-trace.jsonl"}:
        key = "linker_execution" if name == "linker-trace.jsonl" else "cargo_execution"
        execution, _ = strict_json(Path(shape[key]["absolute_path"]))
        raw = execution["trace"]["absolute_path"]
    else:
        raw = direct[name]
    return Path(raw).read_bytes()


observed_shapes = verifier.verify_capability_shape_records(
    capability, read_shape_record
)
if observed_shapes != verifier.capability_shapes(capability):
    raise RuntimeError("capability shape proof is incomplete")

# Bind current-normalizer outputs to v1 binary identities and exact old symbol
# selections, while deriving cross-version body tuples only from fresh outputs.
current_by_kernel: dict[str, dict[str, Any]] = {}
v1_selection_by_kernel: dict[str, tuple[str, str]] = {}
for executable in EXECUTABLES:
    current, current_data = reextraction_documents[executable]
    verifier._validate_schema(
        current,
        verifier._symbol_document_schema(
            verifier.SYMBOL_V2_SCHEMA, veneers=True
        ),
        f"v1 re-extraction {executable}",
    )
    executable_record = v1_manifest["executables"][executable]
    if (
        current["binary"] != executable_record["absolute_path"]
        or current["binary_sha256"] != executable_record["sha256"]
        or current["architecture"] != "x86_64"
    ):
        raise RuntimeError(f"v1 re-extraction binary mismatch: {executable}")
    old_symbols = v1_manifest["symbols"][executable]["symbols"]
    current_symbols = current["symbols"]
    old_pairs = [(item["name"], item["pattern"]) for item in old_symbols]
    current_pairs = [(item["name"], item["pattern"]) for item in current_symbols]
    if old_pairs != current_pairs or len(current_symbols) != len(old_symbols):
        raise RuntimeError(f"v1 re-extraction selection mismatch: {executable}")
    for symbol in current_symbols:
        kernel = symbol["name"].rsplit("::", 1)[-1]
        if kernel in current_by_kernel:
            raise RuntimeError(f"duplicate v1 re-extracted kernel: {kernel}")
        current_by_kernel[kernel] = symbol
        v1_selection_by_kernel[kernel] = (symbol["name"], symbol["pattern"])
if len(current_by_kernel) != 8:
    raise RuntimeError("v1 re-extractions do not contain eight kernels")

clean_by_kernel = {}
for executable in EXECUTABLES:
    for symbol in manifests[0]["symbols"][executable]["symbols"]:
        kernel = symbol["name"].rsplit("::", 1)[-1]
        if kernel in clean_by_kernel:
            raise RuntimeError(f"duplicate clean kernel: {kernel}")
        clean_by_kernel[kernel] = symbol
if set(clean_by_kernel) != set(current_by_kernel):
    raise RuntimeError("v1/v2 kernel sets differ")


def body(symbol: dict[str, Any]) -> dict[str, Any]:
    return {field: symbol[field] for field in BODY_FIELDS}


rows = []
for kernel in sorted(current_by_kernel, key=lambda value: value.encode()):
    v1_body = body(current_by_kernel[kernel])
    v2_body = body(clean_by_kernel[kernel])
    if tuple(v1_body[field] for field in BODY_FIELDS) != tuple(
        v2_body[field] for field in BODY_FIELDS
    ):
        raise RuntimeError(f"current-normalizer body mismatch: {kernel}")
    rows.append({"kernel": kernel, "v1": v1_body, "v2": v2_body})
body_comparison = {
    "version": 1,
    "fields": list(BODY_FIELDS),
    "rows": rows,
}
body_comparison_sha = verifier.verify_body_rows(rows)

# Preserve immutable documents at evidence-document paths.
capability_archive = PurePosixPath("bundle/evidence/capability.json")
manifest_archives = {
    "clean_a": PurePosixPath("bundle/evidence/manifests/clean-a.json"),
    "clean_b": PurePosixPath("bundle/evidence/manifests/clean-b.json"),
    "adversary": PurePosixPath("bundle/evidence/manifests/adversary.json"),
}
v1_manifest_archive = PurePosixPath("bundle/evidence/v1-manifest.json")
reextraction_archives = {
    executable: PurePosixPath(
        f"bundle/evidence/v1-reextractions/{executable}.json"
    )
    for executable in EXECUTABLES
}
capability_document_sha = write_document(capability_archive, capability_data)
manifest_document_shas = {
    key: write_document(archive, data)
    for (key, archive), (_document, data) in zip(
        manifest_archives.items(), manifest_documents, strict=True
    )
}
v1_manifest_sha = write_document(v1_manifest_archive, v1_manifest_data)
reextraction_shas = {
    executable: write_document(
        reextraction_archives[executable],
        reextraction_documents[executable][1],
    )
    for executable in EXECUTABLES
}

# Copy every hash-bearing source record without changing its hosted route.
def iter_file_records(value: object) -> list[dict[str, Any]]:
    records = []
    if isinstance(value, dict):
        if set(("absolute_path", "sha256")).issubset(value):
            records.append(value)
        for child in value.values():
            records.extend(iter_file_records(child))
    elif isinstance(value, list):
        for child in value:
            records.extend(iter_file_records(child))
    return records


for label, document in (
    ("capability", capability),
    *(("manifest", manifest) for manifest in manifests),
    ("v1 manifest", v1_manifest),
):
    for record in iter_file_records(document):
        raw = record["absolute_path"]
        source = Path(raw)
        observed = copy_regular(source, archive_for(raw))
        if observed != record["sha256"]:
            raise RuntimeError(f"{label} hash-bearing file mismatch: {raw}")

for control in [
    *(manifest["control"] for manifest in manifests),
    v1_manifest["control"],
]:
    raw = control["provenance_path"]
    observed = copy_regular(Path(raw), archive_for(raw))
    if observed != control["provenance_sha256"]:
        raise RuntimeError(f"control provenance mismatch: {raw}")

# Link commands bind rlib(member) owners to actual archive indices. Preserve all
# absolute rlibs used by those commands, plus other extant referenced toolchain
# and registry files found in authenticated command transcripts.
referenced_paths: set[str] = set()
absolute_token = re.compile(r"/[^\s'\"`]+")
for manifest in manifests:
    for executable in EXECUTABLES:
        proof = manifest["build_proof"]["executables"][executable]
        for token in proof["link_command"]["argv"]:
            candidate = token[1:] if token.startswith("@/") else token
            if candidate.startswith("/") and candidate.endswith(".rlib"):
                referenced_paths.add(candidate)
        for line in proof["rustc_argv"]:
            try:
                tokens = shlex.split(line[len("Running `") : -1])
            except (ValueError, IndexError):
                tokens = absolute_token.findall(line)
            for token in tokens:
                for match in absolute_token.findall(token):
                    referenced_paths.add(match.rstrip(",);"))
        layout = manifest["elf_layout"][executable]
        for owner in [
            *layout["archive_member_owners"],
            *(item["owner"] for item in layout["cache_gate_input_sections"]),
            *(item["input_owner"] for item in layout["kernels"].values()),
        ]:
            if ".rlib(" in owner:
                referenced_paths.add(owner.rsplit("(", 1)[0])
for raw in sorted(referenced_paths):
    source = Path(raw)
    try:
        metadata = os.lstat(source)
    except FileNotFoundError:
        continue
    if not stat.S_ISREG(metadata.st_mode):
        continue
    path = canonical_hosted(raw)
    if any(
        path == HOSTED_ROOTS[name] or path.is_relative_to(HOSTED_ROOTS[name])
        for name in ("subject", "v1", "toolchain", "cargo-registry")
    ):
        copy_regular(source, archive_for(raw))

# Mirror exact no-follow system linker chains and raw symlink targets.
linker_inventory, linker_inventory_data = strict_json(Path(linker_inventory_raw))
system_links = linker_inventory["system_links"]
packages = linker_inventory["packages"]
if packages != sorted(packages, key=lambda item: (item["name"], item["architecture"], item["version"])):
    packages = sorted(
        packages, key=lambda item: (item["name"], item["architecture"], item["version"])
    )
if len({(item["name"], item["architecture"], item["version"]) for item in packages}) != len(packages):
    raise RuntimeError("duplicate package provenance record")
if not any(item["name"] == "lld" for item in packages):
    raise RuntimeError("package provenance lacks Ubuntu lld")
for record in linker_inventory["files"]:
    raw = record["absolute_path"]
    archive = ARCHIVE_ROOTS["system-root"] / canonical_hosted(raw).relative_to("/")
    destination = staging / archive
    destination.parent.mkdir(parents=True, exist_ok=True)
    if record["type"] == "symlink":
        if destination.exists() or destination.is_symlink():
            raise RuntimeError(f"duplicate system symlink: {raw}")
        os.symlink(record["raw_target"], destination)
        if os.readlink(destination) != record["raw_target"]:
            raise RuntimeError(f"system symlink target changed: {raw}")
    elif record["type"] == "file":
        observed = copy_regular(Path(raw), archive)
        if observed != record["sha256"]:
            raise RuntimeError(f"system linker payload hash mismatch: {raw}")
    else:
        raise RuntimeError(f"unsupported linker inventory type: {record['type']}")
write_document(
    PurePosixPath("bundle/evidence/logs/linker-inventory.json"),
    linker_inventory_data,
)

# Generate nine hash-bound hosted link-validation transcripts directly from the
# immutable commands and their authenticated final trace records.
transcript_records = []
for manifest in manifests:
    for executable in EXECUTABLES:
        command = manifest["build_proof"]["executables"][executable]["link_command"]
        trace_path = Path(command["trace"]["absolute_path"])
        trace_data = trace_path.read_bytes()
        if sha256(trace_data) != command["trace"]["sha256"]:
            raise RuntimeError(f"manifest trace changed: {manifest['variant']}/{executable}")
        verifier.verify_manifest_link_command(
            command,
            trace_data,
            capability,
            TARGETS[executable],
            manifest["executables"][executable],
            expected_fragment=verifier._manifest_fragment_path(
                manifest,
                TARGETS[executable],
            ),
        )
        trace_rows = [
            json.loads(line) for line in trace_data.splitlines() if line.strip()
        ]
        matches = [
            item
            for item in trace_rows
            if item.get("argv") == command["argv"]
            and item.get("payload_path") == command["driver"]["payload_path"]
            and item.get("payload_sha256") == command["driver"]["payload_sha256"]
        ]
        if len(matches) != 1:
            raise RuntimeError(
                f"manifest trace lacks exact final record: {manifest['variant']}/{executable}"
            )
        selected = matches[0]
        transcript = {
            "version": 1,
            "kind": "link-validation",
            "manifest_variant": manifest["variant"],
            "executable": executable,
            "trace": command["trace"],
            "argv": command["argv"],
            "argv0": command["driver"]["argv0"],
            "cwd": selected["cwd"],
            "path": selected["path"],
            "payload_path": command["driver"]["payload_path"],
            "payload_sha256": command["driver"]["payload_sha256"],
            "status": 0,
            "ordered_inputs": command["ordered_linker_inputs"],
        }
        data = json_bytes(transcript)
        archive = PurePosixPath(
            "bundle/evidence/transcripts/"
            f"{manifest['variant']}-{executable}.json"
        )
        transcript_records.append(
            {"archive_path": archive.as_posix(), "sha256": write_document(archive, data)}
        )
if len(transcript_records) != 9:
    raise RuntimeError("hosted transcript set is not exact")

# Stage reviewed orchestration sources at fixed archive identities.
source_relatives = {
    "workflow": ".github/workflows/x86-cache-gate-evidence.yml",
    "runner": "scripts/run-x86-cache-gate-evidence.sh",
    "packager": "scripts/package-x86-cache-gate-evidence.py",
    "verifier": "scripts/verify-x86-cache-gate-evidence.py",
}
source_records = {}
for name, relative in source_relatives.items():
    archive = ARCHIVE_ROOTS["orchestrator"] / PurePosixPath(relative)
    source_records[name] = {
        "archive_path": archive.as_posix(),
        "sha256": copy_regular(orchestrator / relative, archive),
    }

# Logs are diagnostic evidence, not semantic substitutes for provenance.
for path in sorted((evidence / "logs").rglob("*")):
    if path.is_symlink() or not path.is_file():
        continue
    relative = path.relative_to(evidence)
    archive = ARCHIVE_ROOTS["evidence"] / PurePosixPath(relative.as_posix())
    if not (staging / archive).exists():
        copy_regular(path, archive)

portable_roots = [
    {
        "name": name,
        "hosted": hosted.as_posix(),
        "archive": ARCHIVE_ROOTS[name].as_posix(),
    }
    for name, hosted in HOSTED_ROOTS.items()
]
portable_paths = {
    "version": 1,
    "roots": portable_roots,
    "system_links": system_links,
    "routing_records": [
        {
            "document": route[0],
            "key_path": list(route[1:]),
            "field_kind": kind,
        }
        for route, kind in sorted(verifier.PATH_ROUTES.items())
        if route not in verifier.ROUTE_COMPATIBILITY_ALIASES
    ],
}
portable_data = json_bytes(portable_paths)
body_data = json_bytes(body_comparison)
portable_sha = write_document(
    PurePosixPath("bundle/portable-paths.json"), portable_data
)
body_sha = write_document(PurePosixPath("bundle/body-comparison.json"), body_data)
if body_sha != sha256(body_data) or body_comparison_sha != verifier.verify_body_rows(rows):
    raise RuntimeError("body-comparison digest changed")

provenance = {
    "version": 2,
    "subject": {"commit": verifier.SUBJECT_COMMIT, "tree": verifier.SUBJECT_TREE},
    "v1": {"commit": verifier.V1_REPLAY_COMMIT, "tree": verifier.V1_REPLAY_TREE},
    "orchestration": {
        "commit": orchestrator_commit,
        "tree": orchestrator_tree,
        "sources": source_records,
    },
    "run": {
        "id": int(run_id_raw),
        "attempt": int(run_attempt_raw),
        "derived_attempt": int(derived_raw),
    },
    "github": {
        "repository": os.environ["GITHUB_REPOSITORY"],
        "ref": os.environ["GITHUB_REF"],
        "sha": os.environ["GITHUB_SHA"],
        "run_id": int(run_id_raw),
        "run_attempt": int(run_attempt_raw),
    },
    "rust": {
        "toolchain": "1.95.0-x86_64-unknown-linux-gnu",
        "rustc_version": rustc_version,
        "cargo_version": cargo_version,
    },
    "packages": packages,
    "roots": portable_roots,
    "system_links": system_links,
    "proof": {"status": 0, "result": "PASS"},
    "documents": {
        "capability": {
            "archive_path": capability_archive.as_posix(),
            "sha256": capability_document_sha,
        },
        "manifests": {
            key: {
                "archive_path": archive.as_posix(),
                "sha256": manifest_document_shas[key],
            }
            for key, archive in manifest_archives.items()
        },
        "v1_manifest": {
            "archive_path": v1_manifest_archive.as_posix(),
            "sha256": v1_manifest_sha,
        },
        "v1_reextractions": {
            executable: {
                "archive_path": reextraction_archives[executable].as_posix(),
                "sha256": reextraction_shas[executable],
            }
            for executable in EXECUTABLES
        },
        "transcripts": transcript_records,
        "body_comparison": {
            "archive_path": "bundle/body-comparison.json",
            "sha256": body_sha,
        },
        "portable_paths": {
            "archive_path": "bundle/portable-paths.json",
            "sha256": portable_sha,
        },
    },
    "hardlinks": [],
}
verifier._validate_schema(provenance, verifier.PROVENANCE_SCHEMA, "provenance")
write_document(PurePosixPath("bundle/provenance.json"), json_bytes(provenance))

summary = {
    "version": 1,
    "body_comparison_sha256": body_comparison_sha,
    "capability_shapes": sorted(
        [list(item) for item in observed_shapes],
        key=lambda item: tuple(str(value) for value in item),
    ),
    "manifest_variants": [manifest["variant"] for manifest in manifests],
    "v1_variant": v1_manifest["variant"],
}
write_document(
    PurePosixPath("bundle/evidence/logs/proof-summary.json"),
    json_bytes(summary),
)

# Close the staging tree before the workflow's separate always-run packager.
for directory in sorted(
    (path for path in staging.rglob("*") if path.is_dir()),
    key=lambda path: len(path.parts),
    reverse=True,
):
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
root_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    os.fsync(root_fd)
finally:
    os.close(root_fd)
PY

proof_status=0
exit "$proof_status"
