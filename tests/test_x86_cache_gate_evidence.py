from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import textwrap
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run-x86-cache-gate-evidence.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "x86-cache-gate-evidence.yml"
SUBJECT_COMMIT = "061d13da22b89208c801308efd578444c8e9caba"
SUBJECT_TREE = "24921a941f8c3c26467465b99d6b45ee5912b2da"
V1_COMMIT = "b0d53234dc051af91fe0321450b3e8312a84e635"
V1_TREE = "d77cc082fe48799f26ff4440bd1898a71d0dc8cc"
ORCHESTRATOR_COMMIT = "a" * 40
ORCHESTRATOR_TREE = "b" * 40
PINNED_RUSTC = """rustc 1.95.0 (59807616e 2026-04-14)
binary: rustc
commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860
commit-date: 2026-04-14
host: x86_64-unknown-linux-gnu
release: 1.95.0
LLVM version: 22.1.2
"""


def write_executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def materialize_runner(tmp_path: Path, tools: Path) -> Path:
    runner = tmp_path / "run-x86-cache-gate-evidence.sh"
    source = RUNNER.read_text()
    source = source.replace(
        "UNAME_TOOL=/usr/bin/uname", f"UNAME_TOOL={tools / 'uname'}"
    )
    source = source.replace(
        "OSTYPE_FILE=/proc/sys/kernel/ostype", f"OSTYPE_FILE={tmp_path / 'ostype'}"
    )
    source = source.replace("LLD_TOOL=/usr/bin/ld.lld", f"LLD_TOOL={tools / 'ld.lld'}")
    runner.write_text(source)
    runner.chmod(0o755)
    (tmp_path / "ostype").write_text("Linux\n")
    return runner


def capability_document(
    subject: Path,
    chain_root: Path,
    *,
    remove_flavor: str | None = None,
) -> dict[str, Any]:
    chain_root.mkdir(parents=True, exist_ok=True)
    records: dict[str, dict[str, Any]] = {}
    for flavor in ("actual", "gnu", "lld"):
        invocation = chain_root / flavor
        terminal = chain_root / f"{flavor}.real"
        invocation.symlink_to(terminal.name)
        terminal.write_bytes(flavor.encode())
        if remove_flavor == flavor:
            terminal.unlink()
        records[flavor] = {
            "invocation_path": str(invocation),
            "invocation_chain": [
                {"absolute_path": str(invocation), "symlink_target": terminal.name},
                {"absolute_path": str(terminal), "symlink_target": None},
            ],
            "payload_path": str(terminal),
            "payload_sha256": hashlib.sha256(flavor.encode()).hexdigest(),
            "argv0": str(terminal),
            "extraction_root": None,
            "flavor": {"actual": "GNU ld", "gnu": "GNU ld", "lld": "LLD"}[flavor],
            "version_argument": "--version",
            "version": f"{flavor} version",
        }
    shapes: dict[str, dict[str, Any]] = {}
    for flavor in ("actual", "gnu", "lld"):
        shapes[flavor] = {}
        for target in ("elastic", "funnel", "profile"):
            execution = chain_root / f"{flavor}-{target}.json"
            execution.write_text(json.dumps({"linker": records[flavor]}) + "\n")
            shapes[flavor][target] = {
                "linker_execution": {
                    "absolute_path": str(execution),
                    "sha256": hashlib.sha256(execution.read_bytes()).hexdigest(),
                }
            }
            if flavor != "actual":
                cargo_execution = chain_root / f"{flavor}-{target}-cargo.json"
                cargo_execution.write_text(
                    json.dumps({"linker": records["actual"]}) + "\n"
                )
                shapes[flavor][target]["cargo_execution"] = {
                    "absolute_path": str(cargo_execution),
                    "sha256": hashlib.sha256(cargo_execution.read_bytes()).hexdigest(),
                }
    fragments = {}
    for target in ("elastic", "funnel", "profile"):
        fragment = chain_root / f"{target}.ld"
        fragment.write_text(f"fragment {target}\n")
        fragments[target] = {
            "absolute_path": str(fragment),
            "sha256": hashlib.sha256(fragment.read_bytes()).hexdigest(),
        }
    return {
        "version": 1,
        "accepted": True,
        "arch": "x86_64",
        "target_triple": "x86_64-unknown-linux-gnu",
        "cargo_version": "cargo 1.95.0 (f2d3ce0bd 2026-03-21)",
        "rustc_version": PINNED_RUSTC.rstrip("\n"),
        "producer": {
            "runner_root": str(subject),
            "artifact_root": str(
                subject / "target/cache-gate-linker/x86_64/.probe.fake"
            ),
            "commit": SUBJECT_COMMIT,
            "tree": SUBJECT_TREE,
            "empty_diff_assertion": True,
        },
        "linker": records["actual"],
        "required_linkers": {"gnu": records["gnu"], "lld": records["lld"]},
        "fragments": fragments,
        "shapes": shapes,
    }


@pytest.fixture
def hosted(tmp_path: Path) -> dict[str, Any]:
    orchestrator = tmp_path / "orchestrator"
    subject = tmp_path / "subject"
    v1 = tmp_path / "v1"
    for root in (orchestrator, subject, v1):
        root.mkdir()
    (orchestrator / "scripts").mkdir()
    (orchestrator / "scripts/verify-x86-cache-gate-evidence.py").write_text(
        f"""\
import hashlib
import json
import os

SUBJECT_COMMIT = {SUBJECT_COMMIT!r}
SUBJECT_TREE = {SUBJECT_TREE!r}
V1_REPLAY_COMMIT = {V1_COMMIT!r}
V1_REPLAY_TREE = {V1_TREE!r}
PINNED_CARGO_VERSION = "cargo 1.95.0 (f2d3ce0bd 2026-03-21)"
PINNED_RUSTC_VERSION = {PINNED_RUSTC.rstrip(chr(10))!r}
CAPABILITY_SCHEMA = object()
MANIFEST_V2_SCHEMA = object()
MANIFEST_V1_SCHEMA = object()
SYMBOL_V2_SCHEMA = object()
PROVENANCE_SCHEMA = object()
PATH_ROUTES = {{}}
ROUTE_COMPATIBILITY_ALIASES = set()
BODY_FIELDS = (
    "size",
    "normalized_instructions_sha256",
    "direct_calls",
    "indirect_calls",
    "frame_adjustment",
    "spills",
)
EXECUTABLE_TARGETS = {{
    "elastic_cache_gate": ("elastic", ("elastic_cache_gate_insert_kernel", "elastic_cache_gate_get_kernel")),
    "funnel_cache_gate": ("funnel", ("funnel_cache_gate_insert_kernel", "funnel_cache_gate_get_kernel")),
    "cache_gate_profile": ("profile", ("elastic_profile_insert_kernel", "elastic_profile_get_kernel", "funnel_profile_insert_kernel", "funnel_profile_get_kernel")),
}}

def _validate_schema(document, schema, label):
    if label == "capability" and os.environ.get("FAKE_CAPABILITY_SCHEMA_FAIL"):
        raise RuntimeError("injected capability schema failure")
    if label == "manifest_v1" and os.environ.get("FAKE_V1_SCHEMA_FAIL"):
        raise RuntimeError("injected v1 schema failure")

def capability_shapes(capability):
    counts = {{"elastic": 2, "funnel": 2, "profile": 4}}
    return {{
        (flavor, target, counts[target])
        for flavor, targets in capability["shapes"].items()
        for target in targets
    }}

def verify_capability_shape_records(capability, read_record, roots=None):
    if os.environ.get("FAKE_CAPABILITY_SHAPE_FAIL"):
        raise RuntimeError("injected capability shape failure")
    return capability_shapes(capability)

def verify_x86_contracts(capability, manifests, v1):
    return None

def verify_identity_contract(provenance, capability, manifests, v1, capability_bytes, v1_root):
    return None

def verify_manifest_relationships(*manifests):
    return None

def verify_manifest_link_command(command, trace_bytes, capability, target, executable_record, **kwargs):
    return command

def _manifest_fragment_path(manifest, target):
    return (
        f"{{manifest['runner_root']}}/target/cache-gate/"
        f"{{manifest['architecture']}}/{{manifest['variant']}}/"
        f"linker-fragments/{{target}}.ld"
    )

def _symbol_document_schema(schema, veneers=False):
    return object()

def verify_body_rows(rows):
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()
"""
    )
    evidence = tmp_path / "evidence"
    tools = tmp_path / "rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin"
    tools.mkdir(parents=True)
    fake_log = tmp_path / "calls.log"

    write_executable(
        tools / "git",
        """#!/usr/bin/env bash
set -eu
root=
if [[ ${1:-} == -C ]]; then root=$2; shift 2; fi
printf 'git %s %s\n' "$root" "$*" >>"$FAKE_LOG"
case "$*" in
  "rev-parse HEAD")
    case "$root" in
      "$ORCHESTRATOR") printf '%s\n' "$ORCHESTRATOR_COMMIT" ;;
      "$SUBJECT") printf '%s\n' "${FAKE_SUBJECT_COMMIT:-$SUBJECT_COMMIT}" ;;
      "$V1") printf '%s\n' "${FAKE_V1_COMMIT:-$V1_COMMIT}" ;;
      *) exit 91 ;;
    esac ;;
  "rev-parse HEAD^{tree}")
    case "$root" in
      "$ORCHESTRATOR") printf '%s\n' "$ORCHESTRATOR_TREE" ;;
      "$SUBJECT") printf '%s\n' "${FAKE_SUBJECT_TREE:-$SUBJECT_TREE}" ;;
      "$V1") printf '%s\n' "${FAKE_V1_TREE:-$V1_TREE}" ;;
      *) exit 92 ;;
    esac ;;
  "status --porcelain --untracked-files=normal")
    [[ ${FAKE_DIRTY_ROOT:-} != "$root" ]] || printf ' M dirty\n' ;;
  *) exit 93 ;;
esac
""",
    )
    write_executable(
        tools / "rustc",
        """#!/usr/bin/env bash
[[ $* == "--version --verbose" || $* == "-vV" ]] || exit 94
printf '%s' "$PINNED_RUSTC"
""",
    )
    write_executable(
        tools / "cargo",
        """#!/usr/bin/env bash
[[ $* == "--version" || $* == "-V" ]] || exit 95
printf '%s\n' 'cargo 1.95.0 (f2d3ce0bd 2026-03-21)'
""",
    )
    write_executable(
        tools / "uname",
        """#!/usr/bin/env bash
[[ $* == "-m" ]] || exit 96
printf '%s\n' "${FAKE_ARCH:-x86_64}"
""",
    )
    write_executable(tools / "ld.lld", "#!/usr/bin/env bash\nexit 0\n")
    write_executable(
        tools / "dpkg-query",
        """#!/usr/bin/env bash
printf 'dpkg-query %s\n' "$*" >>"$FAKE_LOG"
if [[ $1 == -S ]]; then
  if [[ $2 == "$FAKE_LLD_TOOL" ]]; then
    owner=${FAKE_DPKG_OWNER:-lld}
    owner_path=${FAKE_DPKG_OWNER_PATH:-$2}
  else
    owner=${FAKE_DPKG_CHAIN_OWNER:-lld}
    owner_path=$2
  fi
  printf '%s: %s\n' "$owner" "$owner_path"
  if [[ -n ${FAKE_DPKG_SECOND_OWNER:-} ]]; then
    printf '%s: %s\n' "$FAKE_DPKG_SECOND_OWNER" "$2"
  fi
  exit 0
fi
if [[ $1 == -W ]]; then
  printf 'install ok installed\t%s\t18.1.3-1ubuntu1\n' \
    "${FAKE_DPKG_PACKAGE_ARCH:-amd64}"
  exit 0
fi
exit 97
""",
    )
    write_executable(
        tools / "dpkg",
        """#!/usr/bin/env bash
printf 'dpkg %s\n' "$*" >>"$FAKE_LOG"
[[ $1 == -V && ($2 == lld || $2 == lld:amd64) ]] || exit 98
exit "${FAKE_DPKG_VERIFY_STATUS:-0}"
""",
    )

    for checkout in (subject, v1):
        (checkout / "scripts").mkdir()
    chain_root = tmp_path / "system-chain"
    chain_root.mkdir()
    capability = capability_document(subject, chain_root)
    capability_path = tmp_path / "capability-template.json"
    capability_path.write_text(json.dumps(capability, sort_keys=True) + "\n")

    fake_assets = tmp_path / "fake-assets"
    fake_assets.mkdir()
    control_binary = b"fixed-control\n"
    control_provenance = b"{}\n"
    control_binary_sha = hashlib.sha256(control_binary).hexdigest()
    control_provenance_sha = hashlib.sha256(control_provenance).hexdigest()
    subject_control_bin = (
        subject / "tools/cache-gate-control/target/release/opthash-cache-gate-control"
    )
    subject_control_provenance = subject_control_bin.with_name(
        "opthash-cache-gate-control.provenance.json"
    )
    v1_control_bin = (
        v1 / "tools/cache-gate-control/target/release/opthash-cache-gate-control"
    )
    v1_control_provenance = v1_control_bin.with_name(
        "opthash-cache-gate-control.provenance.json"
    )
    kernels = {
        "elastic_cache_gate": (
            "elastic_cache_gate_insert_kernel",
            "elastic_cache_gate_get_kernel",
        ),
        "funnel_cache_gate": (
            "funnel_cache_gate_insert_kernel",
            "funnel_cache_gate_get_kernel",
        ),
        "cache_gate_profile": (
            "elastic_profile_insert_kernel",
            "elastic_profile_get_kernel",
            "funnel_profile_insert_kernel",
            "funnel_profile_get_kernel",
        ),
    }

    def symbol_record(namespace: str, kernel: str, index: int) -> dict[str, Any]:
        return {
            "name": f"{namespace}::{kernel}",
            "pattern": f"::{kernel}$",
            "start": 4096 * (index + 1),
            "end": 4096 * (index + 1) + 7,
            "size": 7,
            "section": ".text.fixture",
            "raw_sha256": "2" * 64,
            "normalized_instructions_sha256": "1" * 64,
            "direct_calls": ["callee"],
            "indirect_calls": [],
            "frame_adjustment": 16,
            "spills": ["x19"],
        }

    def symbols_document(
        binary: Path,
        binary_data: bytes,
        names: tuple[str, ...],
        namespace: str,
    ):
        return {
            "binary": str(binary),
            "binary_sha256": hashlib.sha256(binary_data).hexdigest(),
            "architecture": "x86_64",
            "symbols": [
                symbol_record(namespace, kernel, index)
                for index, kernel in enumerate(names)
            ],
        }

    def control_record(binary: Path, provenance: Path) -> dict[str, Any]:
        return {
            "binary": {
                "absolute_path": str(binary),
                "sha256": control_binary_sha,
            },
            "provenance_path": str(provenance),
            "provenance_sha256": control_provenance_sha,
        }

    clean_variant = "x86_64-061d13da22b8-attempt-7002-clean-a"
    repeat_variant = "x86_64-061d13da22b8-attempt-7002-clean-b"
    adversary_variant = "x86_64-061d13da22b8-attempt-7002-adversary"
    for variant in (clean_variant, repeat_variant, adversary_variant):
        asset = fake_assets / variant
        destination = subject / f"target/cache-gate/x86_64/{variant}"
        (asset / "bin").mkdir(parents=True)
        (asset / "traces").mkdir()
        (asset / "linker-fragments").mkdir()
        manifest: dict[str, Any] = {
            "architecture": "x86_64",
            "variant": variant,
            "manifest_instance": variant,
            "runner_root": str(subject),
            "control": control_record(
                subject_control_bin,
                subject_control_provenance,
            ),
            "symbols": {},
            "executables": {},
            "build_proof": {"executables": {}},
            "elf_layout": {},
        }
        for executable, executable_kernels in kernels.items():
            target = {
                "elastic_cache_gate": "elastic",
                "funnel_cache_gate": "funnel",
                "cache_gate_profile": "profile",
            }[executable]
            binary_data = f"binary {executable}\n".encode()
            (asset / "bin" / executable).write_bytes(binary_data)
            binary = destination / "bin" / executable
            binary_sha = hashlib.sha256(binary_data).hexdigest()
            fragment_data = (chain_root / f"{target}.ld").read_bytes()
            (asset / "linker-fragments" / f"{target}.ld").write_bytes(fragment_data)
            fragment = destination / "linker-fragments" / f"{target}.ld"
            argv = [
                str(binary),
                f"-Wl,-T,{fragment}",
                f"-Wl,-Map,{binary}",
                "-o",
                str(binary),
            ]
            trace = {
                "argv": argv,
                "argv0": capability["linker"]["argv0"],
                "cwd": str(subject),
                "path": str(tools),
                "payload_path": capability["linker"]["payload_path"],
                "payload_sha256": capability["linker"]["payload_sha256"],
            }
            trace_data = (json.dumps(trace, sort_keys=True) + "\n").encode()
            (asset / "traces" / f"{executable}.jsonl").write_bytes(trace_data)
            trace_path = destination / "traces" / f"{executable}.jsonl"
            trace_record = {
                "absolute_path": str(trace_path),
                "sha256": hashlib.sha256(trace_data).hexdigest(),
                "record_count": 1,
                "final_link_record_count": 1,
            }
            manifest["symbols"][executable] = symbols_document(
                binary,
                binary_data,
                executable_kernels,
                executable,
            )
            manifest["executables"][executable] = {
                "absolute_path": str(binary),
                "sha256": binary_sha,
                "link_map": {"absolute_path": str(binary), "sha256": binary_sha},
                "link_trace": {
                    "absolute_path": str(trace_path),
                    "sha256": trace_record["sha256"],
                },
                "linker_fragment": {
                    "absolute_path": str(fragment),
                    "sha256": hashlib.sha256(fragment_data).hexdigest(),
                },
            }
            manifest["build_proof"]["executables"][executable] = {
                "rustc_argv": ["Running `rustc -Ccodegen-units=16`"],
                "link_command": {
                    "driver": capability["linker"],
                    "argv": argv,
                    "ordered_linker_inputs": [str(binary)],
                    "trace": trace_record,
                    "executable": str(binary),
                    "fragment": str(fragment),
                    "link_map": str(binary),
                },
            }
            manifest["elf_layout"][executable] = {
                "archive_member_owners": [],
                "cache_gate_input_sections": [],
                "kernels": {},
            }
        (asset / "manifest.json").write_text(
            json.dumps(manifest, sort_keys=True) + "\n"
        )

    v1_variant = "x86_64-v1-replay-run-7-attempt-2"
    v1_asset = fake_assets / v1_variant
    v1_destination = v1 / f"target/cache-gate/x86_64/{v1_variant}"
    (v1_asset / "bin").mkdir(parents=True)
    v1_manifest: dict[str, Any] = {
        "commit": V1_COMMIT,
        "tree": V1_TREE,
        "empty_diff_assertion": True,
        "architecture": "x86_64",
        "variant": v1_variant,
        "control": control_record(v1_control_bin, v1_control_provenance),
        "executables": {},
        "symbols": {},
    }
    reextraction_assets = fake_assets / "v1-reextractions"
    reextraction_assets.mkdir()
    for executable, executable_kernels in kernels.items():
        binary_data = f"v1 binary {executable}\n".encode()
        (v1_asset / "bin" / executable).write_bytes(binary_data)
        binary = v1_destination / "bin" / executable
        binary_sha = hashlib.sha256(binary_data).hexdigest()
        v1_manifest["executables"][executable] = {
            "absolute_path": str(binary),
            "sha256": binary_sha,
        }
        symbol_document = symbols_document(
            binary,
            binary_data,
            executable_kernels,
            executable,
        )
        v1_manifest["symbols"][executable] = symbol_document
        (reextraction_assets / f"{executable}.json").write_text(
            json.dumps(symbol_document, sort_keys=True) + "\n"
        )
    (v1_asset / "manifest.json").write_text(
        json.dumps(v1_manifest, sort_keys=True) + "\n"
    )
    write_executable(
        subject / "scripts/cache-gate-linker-capability.sh",
        """#!/usr/bin/env bash
printf 'capability\n' >>"$FAKE_LOG"
if [[ -n ${FAKE_CAPABILITY_STDERR_FILE:-} ]]; then
  /bin/cat -- "$FAKE_CAPABILITY_STDERR_FILE" >&2
fi
if [[ ${FAKE_CAPABILITY_STDERR_UNSAFE:-} == hardlink ]]; then
  diagnostic=$(readlink -- "/proc/$$/fd/2")
  ln -- "$diagnostic" "$diagnostic.peer"
fi
if [[ ${FAKE_CAPABILITY_LOGS_SWAP:-} == symlink ]]; then
  diagnostic=$(readlink -- "/proc/$$/fd/2")
  logs=${diagnostic%/*}
  mv -- "$logs" "$logs.anchored"
  mkdir -- "$logs.replacement"
  printf '::error::attacker replacement\n' >"$logs.replacement/capability.stderr"
  ln -s -- "$logs.replacement" "$logs"
fi
if [[ -n ${FAKE_CAPABILITY_STATUS:-} ]]; then
  exit "$FAKE_CAPABILITY_STATUS"
fi
output="$SUBJECT/target/cache-gate-linker/x86_64/capability.json"
mkdir -p -- "$(dirname "$output")"
cp -- "$FAKE_CAPABILITY_TEMPLATE" "$output"
printf '%s\n' "$output"
""",
    )
    write_executable(
        subject / "scripts/cache-gate.sh",
        """#!/usr/bin/env bash
set -eu
printf 'subject-cache-gate %s\n' "$*" >>"$FAKE_LOG"
if [[ ${FAKE_SUCCESS:-0} != 1 ]]; then
  exit "${FAKE_CACHE_GATE_STATUS:-71}"
fi
if [[ ${BUILD_CONTROL:-0} == 1 ]]; then
  binary="$SUBJECT/tools/cache-gate-control/target/release/opthash-cache-gate-control"
  provenance="$binary.provenance.json"
  mkdir -p -- "$(dirname "$binary")" "$SUBJECT/target"
  printf 'fixed-control\n' >"$binary"
  printf '{}\n' >"$provenance"
  printf '%s\n%s\n' "$binary" "$provenance" >"$SUBJECT/target/cache-gate-control-bin.txt"
  cp -- "$provenance" "$SUBJECT/target/cache-gate-control-build.json"
  exit 0
fi
if [[ ${MANIFEST:-0} == 1 ]]; then
  destination="$SUBJECT/target/cache-gate/x86_64/$CACHE_GATE_VARIANT"
  mkdir -p -- "$destination"
  cp -R -- "$FAKE_ASSETS/$CACHE_GATE_VARIANT/." "$destination/"
  if [[ ${FAKE_HARDLINK_PRIVATE:-0} == 1 && $CACHE_GATE_VARIANT == *-clean-a ]]; then
    rm -- "$destination/linker-fragments/elastic.ld"
    ln -- "$FAKE_ELASTIC_FRAGMENT" "$destination/linker-fragments/elastic.ld"
  fi
  exit 0
fi
exit 99
""",
    )
    write_executable(
        v1 / "scripts/cache-gate.sh",
        """#!/usr/bin/env bash
set -eu
printf 'v1-cache-gate %s\n' "$*" >>"$FAKE_LOG"
if [[ ${FAKE_SUCCESS:-0} != 1 ]]; then
  exit "${FAKE_CACHE_GATE_STATUS:-71}"
fi
if [[ ${BUILD_CONTROL:-0} == 1 ]]; then
  binary="$V1/tools/cache-gate-control/target/release/opthash-cache-gate-control"
  provenance="$binary.provenance.json"
  mkdir -p -- "$(dirname "$binary")" "$V1/target"
  printf 'fixed-control\n' >"$binary"
  printf '{}\n' >"$provenance"
  printf '%s\n%s\n' "$binary" "$provenance" >"$V1/target/cache-gate-control-bin.txt"
  cp -- "$provenance" "$V1/target/cache-gate-control-build.json"
  exit 0
fi
if [[ ${MANIFEST:-0} == 1 ]]; then
  destination="$V1/target/cache-gate/x86_64/$CACHE_GATE_VARIANT"
  mkdir -p -- "$destination"
  cp -R -- "$FAKE_ASSETS/$CACHE_GATE_VARIANT/." "$destination/"
  if [[ ${FAKE_TAMPER_V1_CONTROL_PROVENANCE:-0} == 1 ]]; then
    printf 'tampered\n' >>"$V1/tools/cache-gate-control/target/release/opthash-cache-gate-control.provenance.json"
  fi
  exit 0
fi
exit 99
""",
    )
    write_executable(
        subject / "scripts/cache-gate-elf-layout.py",
        """#!/usr/bin/env bash
set -eu
printf 'layout %s\n' "$*" >>"$FAKE_LOG"
exit 0
""",
    )
    write_executable(
        subject / "scripts/extract-hot-symbols.py",
        """#!/usr/bin/env bash
set -eu
binary=
output=
while (($#)); do
  case "$1" in
    --binary) binary=$2; shift 2 ;;
    --output) output=$2; shift 2 ;;
    --arch|--symbol) shift 2 ;;
    *) exit 96 ;;
  esac
done
printf 'extractor %s\n' "$binary" >>"$FAKE_LOG"
mkdir -p -- "$(dirname "$output")"
cp -- "$FAKE_ASSETS/v1-reextractions/$(basename "$binary").json" "$output"
""",
    )

    runner = materialize_runner(tmp_path, tools)
    (orchestrator / ".github/workflows").mkdir(parents=True)
    (orchestrator / ".github/workflows/x86-cache-gate-evidence.yml").write_text(
        "name: fake\n"
    )
    (orchestrator / "scripts/package-x86-cache-gate-evidence.py").write_text(
        "# fake packager source\n"
    )
    shutil.copy2(
        runner,
        orchestrator / "scripts/run-x86-cache-gate-evidence.sh",
    )
    env = {
        **os.environ,
        "RUSTUP_HOME": str(tmp_path / "rustup"),
        "CARGO_HOME": str(tmp_path / "cargo-home"),
        "GITHUB_SHA": ORCHESTRATOR_COMMIT,
        "GITHUB_REPOSITORY": "owner/opthash",
        "GITHUB_REF": "refs/heads/ci/x86-cache-gate-evidence",
        "FAKE_LOG": str(fake_log),
        "ORCHESTRATOR": str(orchestrator),
        "SUBJECT": str(subject),
        "V1": str(v1),
        "ORCHESTRATOR_COMMIT": ORCHESTRATOR_COMMIT,
        "ORCHESTRATOR_TREE": ORCHESTRATOR_TREE,
        "SUBJECT_COMMIT": SUBJECT_COMMIT,
        "SUBJECT_TREE": SUBJECT_TREE,
        "V1_COMMIT": V1_COMMIT,
        "V1_TREE": V1_TREE,
        "PINNED_RUSTC": PINNED_RUSTC,
        "FAKE_CAPABILITY_TEMPLATE": str(capability_path),
        "FAKE_ASSETS": str(fake_assets),
        "FAKE_ELASTIC_FRAGMENT": str(chain_root / "elastic.ld"),
        "FAKE_LLD_TOOL": str(tools / "ld.lld"),
    }
    return {
        "orchestrator": orchestrator,
        "subject": subject,
        "v1": v1,
        "evidence": evidence,
        "status": evidence / "proof.status",
        "tools": tools,
        "runner": runner,
        "env": env,
        "log": fake_log,
        "capability": capability_path,
        "chain_root": chain_root,
        "assets": fake_assets,
    }


def runner_arguments(
    hosted: dict[str, Any],
    *,
    evidence: Path | None = None,
    status: Path | None = None,
    run_id: str = "7",
    run_attempt: str = "2",
) -> list[str]:
    evidence = evidence or hosted["evidence"]
    status = status or evidence / "proof.status"
    return [
        str(hosted["runner"]),
        "--orchestrator",
        str(hosted["orchestrator"]),
        "--subject",
        str(hosted["subject"]),
        "--v1",
        str(hosted["v1"]),
        "--evidence",
        str(evidence),
        "--run-id",
        run_id,
        "--run-attempt",
        run_attempt,
        "--status-file",
        str(status),
    ]


def invoke(
    hosted: dict[str, Any],
    *,
    evidence: Path | None = None,
    status: Path | None = None,
    run_id: str = "7",
    run_attempt: str = "2",
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    merged = dict(hosted["env"])
    if env:
        merged.update(env)
    return subprocess.run(
        runner_arguments(
            hosted,
            evidence=evidence,
            status=status,
            run_id=run_id,
            run_attempt=run_attempt,
        ),
        text=True,
        capture_output=True,
        check=False,
        env=merged,
    )


def test_workflow_is_valid_and_branch_scoped() -> None:
    assert WORKFLOW.is_file(), "native x86 evidence workflow is missing"
    source = WORKFLOW.read_text()
    ruby = shutil.which("ruby")
    if ruby is not None:
        completed = subprocess.run(
            [
                ruby,
                "-e",
                'require "yaml"; YAML.load_file(ARGV[0], aliases: true)',
                str(WORKFLOW),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
    assert re.search(
        r"(?m)^on:\n  push:\n    branches: \[ci/x86-cache-gate-evidence\]\n",
        source,
    )
    assert re.search(r"(?m)^permissions:\n  contents: read\n", source)
    assert re.search(
        r"(?m)^jobs:\n  x86-cache-gate-evidence:\n    runs-on: ubuntu-24\.04\n",
        source,
    )
    assert re.search(
        r"(?m)^    env:\n"
        r"      ARTIFACT_BASE: cache-gate-\$\{\{ github\.run_id \}\}-"
        r"\$\{\{ github\.run_attempt \}\}\n",
        source,
    )
    assert (
        source.count("cache-gate-${{ github.run_id }}-${{ github.run_attempt }}") == 1
    )


def test_workflow_uses_immutable_sibling_checkouts_and_native_tools() -> None:
    source = WORKFLOW.read_text()
    tool_homes = (
        r"        env:\n"
        r"          RUSTUP_HOME: \$\{\{ runner\.temp \}\}/rustup\n"
        r"          CARGO_HOME: \$\{\{ runner\.temp \}\}/cargo\n"
    )
    assert source.count("RUSTUP_HOME: ${{ runner.temp }}/rustup") == 2
    assert source.count("CARGO_HOME: ${{ runner.temp }}/cargo") == 2
    assert re.search(rf"(?m)^      - name: Install Rust 1\.95\.0\n{tool_homes}", source)
    assert not re.search(r"(?m)^    env:\n      RUSTUP_HOME:", source)
    checkout = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
    assert source.count(f"uses: {checkout}") == 3
    assert source.count("persist-credentials: false") == 3
    for path, ref in (
        ("orchestrator", "${{ github.sha }}"),
        ("subject", SUBJECT_COMMIT),
        ("v1", V1_COMMIT),
    ):
        assert re.search(
            rf"(?ms)^      - name: Checkout [^\n]+\n"
            rf"        uses: {re.escape(checkout)}\n"
            rf"        with:\n"
            rf"(?:          [^\n]+\n)*?"
            rf"          ref: {re.escape(ref)}\n"
            rf"(?:          [^\n]+\n)*?"
            rf"          path: {path}\n"
            rf"(?:          [^\n]+\n)*?"
            rf"          persist-credentials: false\n",
            source,
        )
    uses = re.findall(r"(?m)^\s*uses:\s*([^ \n]+)", source)
    assert uses
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", value) for value in uses)
    assert re.search(
        r"(?m)^      - name: Install Rust 1\.95\.0\n"
        + tool_homes
        + (
            r"        uses: dtolnay/rust-toolchain@"
            r"2c7215f132e9ebf062739d9130488b56d53c060c\n"
            r"        with:\n"
            r"          toolchain: 1\.95\.0\n"
        ),
        source,
    )
    assert re.search(
        r"(?m)^      - name: Install native LLD\n"
        r"        run: \|\n"
        r"          sudo apt-get update\n"
        r"          sudo apt-get install --yes --no-install-recommends lld\n",
        source,
    )
    assert all(
        token not in source
        for token in ("container:", "matrix:", "actions/cache@", "docker ")
    )
    sudo_lines = [
        line.strip() for line in source.splitlines() if re.search(r"\bsudo\b", line)
    ]
    assert sudo_lines == [
        "sudo apt-get update",
        "sudo apt-get install --yes --no-install-recommends lld",
    ]


def test_workflow_runs_proof_directly_with_durable_status() -> None:
    source = WORKFLOW.read_text()
    proof = re.search(
        r"(?ms)^      - name: Run native x86 proof\n"
        r"        id: proof\n"
        r"        continue-on-error: true\n"
        r"        shell: bash\n"
        r"        env:\n"
        r"          RUSTUP_HOME: \$\{\{ runner\.temp \}\}/rustup\n"
        r"          CARGO_HOME: \$\{\{ runner\.temp \}\}/cargo\n"
        r"        run: \|\n"
        r"(?P<body>(?:          [^\n]*\n)+)",
        source,
    )
    assert proof
    body = proof.group("body")
    for literal in (
        '"$GITHUB_WORKSPACE/orchestrator/scripts/run-x86-cache-gate-evidence.sh"',
        '--orchestrator "$GITHUB_WORKSPACE/orchestrator"',
        '--subject "$GITHUB_WORKSPACE/subject"',
        '--v1 "$GITHUB_WORKSPACE/v1"',
        '--evidence "$RUNNER_TEMP/$ARTIFACT_BASE"',
        '--run-id "${{ github.run_id }}"',
        '--run-attempt "${{ github.run_attempt }}"',
        '--status-file "$RUNNER_TEMP/$ARTIFACT_BASE/proof.status"',
    ):
        assert literal in body
    assert all(token not in body for token in ("set +e", "|| true", "exit 0"))


def workflow_run_script(step_name: str) -> str:
    source = WORKFLOW.read_text()
    match = re.search(
        rf"(?ms)^      - name: {re.escape(step_name)}\n"
        rf"(?:(?!^      - name:).)*?"
        rf"^        run: \|\n"
        rf"(?P<body>(?:^(?:          [^\n]*)?\n)+)",
        source,
    )
    assert match, f"workflow step has no executable body: {step_name}"
    return textwrap.dedent(match.group("body"))


def test_workflow_always_packages_and_uploads_only_archive_pair(
    tmp_path: Path,
) -> None:
    source = WORKFLOW.read_text()
    for step_name in (
        "Package evidence",
        "Upload evidence",
        "Exit with durable proof status",
    ):
        step = re.search(
            rf"(?ms)^      - name: {re.escape(step_name)}\n"
            rf"(?P<body>(?:(?!^      - name:).)*)",
            source,
        )
        assert step
        assert "if: ${{ always() }}" in step.group("body")

    upload = re.search(
        r"(?ms)^      - name: Upload evidence\n"
        r"        if: \$\{\{ always\(\) \}\}\n"
        r"        uses: actions/upload-artifact@"
        r"ea165f8d65b6e75b540449e92b4886f43607fa02\n"
        r"        with:\n"
        r"          name: x86-cache-gate-evidence-\$\{\{ github\.run_id \}\}-"
        r"\$\{\{ github\.run_attempt \}\}\n"
        r"          path: \|\n"
        r"            \$\{\{ runner\.temp \}\}/\$\{\{ env\.ARTIFACT_BASE \}\}\.tar\n"
        r"            \$\{\{ runner\.temp \}\}/\$\{\{ env\.ARTIFACT_BASE \}\}"
        r"\.tar\.sha256\n"
        r"          if-no-files-found: error\n"
        r"          overwrite: false\n",
        source,
    )
    assert upload
    assert "x86-cache-gate-evidence.tar" not in source

    runner_temp = tmp_path / "runner-temp"
    workspace = tmp_path / "workspace"
    runner_temp.mkdir()
    workspace.mkdir()
    completed = subprocess.run(
        ["bash", "-c", workflow_run_script("Package evidence")],
        text=True,
        capture_output=True,
        check=False,
        env={
            **os.environ,
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_WORKSPACE": str(workspace),
            "GITHUB_SHA": ORCHESTRATOR_COMMIT,
            "GITHUB_RUN_ID": "7",
            "GITHUB_RUN_ATTEMPT": "2",
            "ARTIFACT_BASE": "cache-gate-7-2",
            "PROOF_OUTCOME": "skipped",
        },
    )
    assert completed.returncode == 0, completed.stderr
    status = runner_temp / "cache-gate-7-2/proof.status"
    archive = runner_temp / "cache-gate-7-2.tar"
    checksum = runner_temp / "cache-gate-7-2.tar.sha256"
    assert status.read_bytes() == b"125\n"
    assert (runner_temp / "cache-gate-7-2-fallback/staging/bundle").is_dir()
    assert not (runner_temp / "x86-cache-gate-fallback").exists()
    assert archive.is_file()
    assert checksum.read_text() == (
        f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n"
    )
    with tarfile.open(archive, mode="r:") as evidence:
        names = evidence.getnames()
        assert "bundle/provenance.json" in names
        assert "bundle/proof.status" in names
        assert not any(
            name == "bundle/logs" or name.startswith("bundle/logs/") for name in names
        )


@pytest.mark.parametrize(
    ("raw_status", "proof_outcome", "expected_returncode", "effective_status"),
    [
        ("73\n", "failure", 0, 73),
        ("0\n", "success", 125, 125),
    ],
)
def test_workflow_packages_fallback_when_staging_is_partial(
    tmp_path: Path,
    raw_status: str,
    proof_outcome: str,
    expected_returncode: int,
    effective_status: int,
) -> None:
    runner_temp = tmp_path / "runner-temp"
    workspace = tmp_path / "workspace"
    evidence = runner_temp / "cache-gate-7-2"
    (evidence / "staging/bundle").mkdir(parents=True)
    (evidence / "proof.status").write_text(raw_status)
    scripts = workspace / "orchestrator/scripts"
    scripts.mkdir(parents=True)
    (scripts / "package-x86-cache-gate-evidence.py").symlink_to(
        ROOT / "scripts/package-x86-cache-gate-evidence.py"
    )
    completed = subprocess.run(
        ["bash", "-c", workflow_run_script("Package evidence")],
        text=True,
        capture_output=True,
        check=False,
        env={
            **os.environ,
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_WORKSPACE": str(workspace),
            "GITHUB_SHA": ORCHESTRATOR_COMMIT,
            "GITHUB_RUN_ID": "7",
            "GITHUB_RUN_ATTEMPT": "2",
            "ARTIFACT_BASE": "cache-gate-7-2",
            "PROOF_OUTCOME": proof_outcome,
        },
    )
    assert completed.returncode == expected_returncode, completed.stderr
    archive = runner_temp / "cache-gate-7-2.tar"
    checksum = runner_temp / "cache-gate-7-2.tar.sha256"
    assert checksum.read_text() == (
        f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n"
    )
    with tarfile.open(archive, mode="r:") as packaged:
        names = packaged.getnames()
        provenance = json.load(packaged.extractfile("bundle/provenance.json"))
        packaged_status = packaged.extractfile("bundle/proof.status").read()
        assert provenance["proof"] == {"status": effective_status, "result": "FAIL"}
        assert packaged_status == f"{effective_status}\n".encode()
        assert provenance["diagnostic"]["reason"] == (
            "canonical staging bundle unavailable"
        )
        assert not any(
            name == "bundle/logs" or name.startswith("bundle/logs/") for name in names
        )


@pytest.mark.parametrize(
    ("payload", "proof_outcome", "expected"),
    [
        (None, "skipped", 125),
        (b"0\n", "success", 0),
        (b"73\n", "failure", 73),
        (b"00\n", "success", 125),
        (b"256\n", "success", 125),
        (b"0\n", "failure", 125),
    ],
)
def test_workflow_final_status_is_authoritative(
    tmp_path: Path,
    payload: bytes | None,
    proof_outcome: str,
    expected: int,
) -> None:
    evidence = tmp_path / "cache-gate-7-2"
    if payload is not None:
        evidence.mkdir()
        (evidence / "proof.status").write_bytes(payload)
    completed = subprocess.run(
        ["bash", "-c", workflow_run_script("Exit with durable proof status")],
        text=True,
        capture_output=True,
        check=False,
        env={
            **os.environ,
            "RUNNER_TEMP": str(tmp_path),
            "ARTIFACT_BASE": "cache-gate-7-2",
            "PROOF_OUTCOME": proof_outcome,
        },
    )
    assert completed.returncode == expected, completed.stderr


def test_runner_source_contract_is_exact_and_never_times() -> None:
    source = RUNNER.read_text()
    assert RUNNER.stat().st_mode & stat.S_IXUSR
    for literal in (
        "set -Eeuo pipefail",
        SUBJECT_COMMIT,
        SUBJECT_TREE,
        V1_COMMIT,
        V1_TREE,
        "CACHE_GATE_ATTEMPT=$((run_id * 1000 + run_attempt))",
        "BUILD_CONTROL=1",
        "CACHE_GATE_LAYOUT_ADVERSARY=1",
        "O_EXCL",
        "O_NOFOLLOW",
        "src_dir_fd=",
        "dst_dir_fd=",
        "trap - EXIT",
        "proof.status",
        "if (( code <= 255 ))",
        "UNAME_TOOL=/usr/bin/uname",
        "OSTYPE_FILE=/proc/sys/kernel/ostype",
        "LLD_TOOL=/usr/bin/ld.lld",
        '"$subject/scripts/extract-hot-symbols.py"',
        "verifier.verify_identity_contract(",
        "verifier.verify_manifest_link_command(",
    ):
        assert literal in source
    assert source.count("/usr/bin/python3") == 10
    assert source.count("MANIFEST=1") >= 4
    assert source.count(" compare ") >= 2
    assert source.count(" validate-manifest ") >= 3
    for forbidden in (
        "cargo bench",
        "criterion",
        "perf stat",
        "ELASTIC=1",
        "FUNNEL=1",
        '"raw_sha256": symbol["raw_sha256"]',
        '"section": symbol["section"]',
        '"address": symbol["start"]',
    ):
        assert forbidden not in source


@pytest.mark.parametrize(
    "status_factory",
    [
        lambda evidence: evidence.parent / "outside.status",
        lambda evidence: str(evidence) + "/../evidence/proof.status",
        lambda evidence: str(evidence) + "/./proof.status",
        lambda evidence: evidence / "other.status",
    ],
)
def test_status_path_aliases_fail_before_finalizer(
    hosted: dict[str, Any], status_factory: Any
) -> None:
    status = status_factory(hosted["evidence"])
    completed = invoke(hosted, status=status)
    assert completed.returncode != 0
    assert not hosted["evidence"].exists()
    status_path = Path(status)
    assert not status_path.exists()
    assert not list(status_path.parent.glob(".proof.status.*"))


def test_status_path_through_symlink_fails_before_finalizer(
    hosted: dict[str, Any],
) -> None:
    real_parent = hosted["evidence"].parent / "real-parent"
    real_parent.mkdir()
    alias = hosted["evidence"].parent / "alias-parent"
    alias.symlink_to(real_parent, target_is_directory=True)
    evidence = alias / "evidence"
    completed = invoke(hosted, evidence=evidence)
    assert completed.returncode != 0
    assert not evidence.exists()
    assert not (real_parent / "evidence/proof.status").exists()


@pytest.mark.parametrize(
    ("run_id", "run_attempt"),
    [
        ("0", "1"),
        ("01", "1"),
        ("9223372036854775", "1"),
        ("1", "0"),
        ("1", "001"),
        ("1", "1000"),
    ],
)
def test_invalid_ids_write_bounded_failure_status(
    hosted: dict[str, Any], run_id: str, run_attempt: str
) -> None:
    completed = invoke(hosted, run_id=run_id, run_attempt=run_attempt)
    assert completed.returncode != 0
    value = hosted["status"].read_text().strip()
    assert value.isdecimal()
    assert 0 <= int(value) <= 255
    assert not list(hosted["evidence"].glob(".proof.status.*"))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_id", "18446744073709551617"),
        ("run_attempt", "18446744073709551617"),
        ("run_id", "9" * 10_000),
        ("run_attempt", "9" * 10_000),
    ],
)
def test_arbitrarily_large_ids_fail_before_shell_integer_conversion(
    hosted: dict[str, Any], field: str, value: str
) -> None:
    arguments = {field: value}
    completed = invoke(hosted, **arguments)
    assert completed.returncode != 0
    assert "too large" in completed.stderr
    assert "capability" not in (
        hosted["log"].read_text() if hosted["log"].exists() else ""
    )
    assert hosted["status"].read_text() == "1\n"


@pytest.mark.parametrize("field", ["run_id", "run_attempt"])
def test_non_ascii_digits_fail_under_utf8_locale_before_shell_arithmetic(
    hosted: dict[str, Any], field: str
) -> None:
    completed = invoke(
        hosted,
        env={"LC_ALL": "en_US.utf8"},
        **{field: "١"},
    )
    assert completed.returncode != 0
    assert "must be a canonical positive decimal" in completed.stderr
    assert "capability" not in (
        hosted["log"].read_text() if hosted["log"].exists() else ""
    )
    assert hosted["status"].read_text() == "1\n"


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({"FAKE_ARCH": "aarch64"}, "x86_64"),
        ({"GITHUB_SHA": "c" * 40}, "GITHUB_SHA"),
        ({"FAKE_SUBJECT_COMMIT": "c" * 40}, "subject commit"),
        ({"FAKE_SUBJECT_TREE": "c" * 40}, "subject tree"),
        ({"FAKE_V1_COMMIT": "c" * 40}, "v1 commit"),
        ({"FAKE_V1_TREE": "c" * 40}, "v1 tree"),
        ({"FAKE_DIRTY_ROOT": "{subject}"}, "clean"),
        ({"FAKE_DIRTY_ROOT": "{v1}"}, "clean"),
        ({"GITHUB_REPOSITORY": "./opthash"}, "GITHUB_REPOSITORY"),
        ({"FAKE_DPKG_VERIFY_STATUS": "1"}, "dpkg"),
    ],
)
def test_host_and_checkout_gates_precede_capability(
    hosted: dict[str, Any], env: dict[str, str], expected: str
) -> None:
    expanded = {
        key: (
            str(hosted["subject"])
            if value == "{subject}"
            else str(hosted["v1"])
            if value == "{v1}"
            else value
        )
        for key, value in env.items()
    }
    completed = invoke(hosted, env=expanded)
    assert completed.returncode != 0
    assert expected in completed.stderr
    assert "capability" not in (
        hosted["log"].read_text() if hosted["log"].exists() else ""
    )
    assert hosted["status"].exists()


@pytest.mark.parametrize("owner", ["lld", "lld:amd64"])
def test_lld_owner_accepts_unqualified_or_exact_native_multiarch(
    hosted: dict[str, Any], owner: str
) -> None:
    completed = invoke(
        hosted,
        env={
            "FAKE_DPKG_OWNER": owner,
            "FAKE_CAPABILITY_STATUS": "73",
        },
    )
    assert completed.returncode == 73
    assert "ld.lld is not owned" not in completed.stderr
    assert "capability" in hosted["log"].read_text()
    assert hosted["status"].read_text() == "73\n"


@pytest.mark.parametrize(
    "env",
    [
        {"FAKE_DPKG_OWNER": "lld:arm64"},
        {"FAKE_DPKG_OWNER": "lld-18:amd64"},
        {"FAKE_DPKG_OWNER": "lld:amd64:extra"},
        {"FAKE_DPKG_OWNER_PATH": "/usr/bin/not-ld.lld"},
        {"FAKE_DPKG_SECOND_OWNER": "lld:amd64"},
    ],
)
def test_lld_owner_rejects_foreign_malformed_or_ambiguous_ownership(
    hosted: dict[str, Any], env: dict[str, str]
) -> None:
    completed = invoke(hosted, env=env)
    assert completed.returncode != 0
    assert "ld.lld is not owned by the Ubuntu lld package" in completed.stderr
    assert "capability" not in hosted["log"].read_text()
    assert hosted["status"].read_text() == "1\n"


def test_native_multiarch_lld_owner_stages_base_package_provenance(
    hosted: dict[str, Any],
) -> None:
    completed = invoke(
        hosted,
        env={
            "FAKE_DPKG_OWNER": "lld:amd64",
            "FAKE_DPKG_CHAIN_OWNER": "lld:amd64",
            "FAKE_SUCCESS": "1",
        },
    )
    assert completed.returncode == 0, completed.stderr
    provenance = json.loads(
        (hosted["evidence"] / "staging/bundle/provenance.json").read_text()
    )
    assert provenance["packages"] == [
        {
            "architecture": "amd64",
            "name": "lld",
            "verification_status": 0,
            "version": "18.1.3-1ubuntu1",
        }
    ]
    calls = hosted["log"].read_text()
    assert re.search(r"(?m)^dpkg-query -W .* lld:amd64$", calls)
    assert "dpkg -V lld:amd64\n" in calls


def test_linker_chain_owner_qualifier_must_match_package_architecture(
    hosted: dict[str, Any],
) -> None:
    completed = invoke(
        hosted,
        env={
            "FAKE_DPKG_OWNER": "lld:amd64",
            "FAKE_DPKG_CHAIN_OWNER": "lld:arm64",
            "FAKE_SUCCESS": "1",
        },
    )
    assert completed.returncode != 0
    assert "linker package ownership architecture mismatch" in completed.stderr
    calls = hosted["log"].read_text()
    assert "capability" in calls
    assert "subject-cache-gate" not in calls
    assert not (hosted["evidence"] / "staging").exists()


def test_existing_evidence_root_fails_before_finalizer(
    hosted: dict[str, Any],
) -> None:
    hosted["evidence"].mkdir()
    completed = invoke(hosted)
    assert completed.returncode != 0
    assert "already exists" in completed.stderr
    assert not hosted["status"].exists()
    assert not list(hosted["evidence"].glob(".proof.status.*"))


def test_noncanonical_lld_resolution_fails_before_capability(
    hosted: dict[str, Any],
) -> None:
    expected = hosted["tools"] / "expected-ld.lld"
    source = (
        hosted["runner"]
        .read_text()
        .replace(
            f"LLD_TOOL={hosted['tools'] / 'ld.lld'}",
            f"LLD_TOOL={expected}",
        )
    )
    hosted["runner"].write_text(source)
    completed = invoke(hosted)
    assert completed.returncode != 0
    assert "ld.lld must resolve" in completed.stderr
    assert "capability" not in (
        hosted["log"].read_text() if hosted["log"].exists() else ""
    )


def test_existing_manifest_root_fails_before_capability(hosted: dict[str, Any]) -> None:
    (hosted["subject"] / "target/cache-gate-linker/x86_64").mkdir(parents=True)
    completed = invoke(hosted)
    assert completed.returncode != 0
    assert "already exists" in completed.stderr
    assert "capability" not in (
        hosted["log"].read_text() if hosted["log"].exists() else ""
    )


def test_symlinked_output_ancestor_fails_before_capability(
    hosted: dict[str, Any],
) -> None:
    redirected = hosted["evidence"].parent / "redirected-target"
    redirected.mkdir()
    (hosted["subject"] / "target").symlink_to(
        redirected,
        target_is_directory=True,
    )
    completed = invoke(hosted)
    assert completed.returncode != 0
    assert "symlink output ancestor" in completed.stderr
    assert "capability" not in (
        hosted["log"].read_text() if hosted["log"].exists() else ""
    )
    assert not list(redirected.iterdir())


@pytest.mark.parametrize("checkout", ["subject", "v1"])
def test_existing_control_record_fails_before_capability(
    hosted: dict[str, Any], checkout: str
) -> None:
    output = hosted[checkout] / "target/cache-gate-control-bin.txt"
    output.parent.mkdir(parents=True)
    output.write_text("stale\n")
    completed = invoke(hosted)
    assert completed.returncode != 0
    assert "already exists" in completed.stderr
    assert "capability" not in (
        hosted["log"].read_text() if hosted["log"].exists() else ""
    )


def test_accepted_multishape_inventory_reaches_manifest_build(
    hosted: dict[str, Any],
) -> None:
    completed = invoke(hosted)
    assert completed.returncode == 71
    assert hosted["status"].read_text() == "71\n"
    calls = hosted["log"].read_text()
    assert "capability" in calls
    assert "subject-cache-gate" in calls
    assert not (hosted["evidence"] / "staging").exists()


def test_success_path_stages_closed_provenance_and_zero_status(
    hosted: dict[str, Any],
) -> None:
    completed = invoke(hosted, env={"FAKE_SUCCESS": "1"})
    assert completed.returncode == 0, completed.stderr
    assert hosted["status"].read_text() == "0\n"
    bundle = hosted["evidence"] / "staging/bundle"
    provenance = json.loads((bundle / "provenance.json").read_text())
    assert provenance["version"] == 2
    assert provenance["proof"] == {"status": 0, "result": "PASS"}
    assert set(provenance["documents"]["v1_reextractions"]) == {
        "elastic_cache_gate",
        "funnel_cache_gate",
        "cache_gate_profile",
    }
    assert len(provenance["documents"]["transcripts"]) == 9
    assert (bundle / "body-comparison.json").is_file()
    assert (bundle / "portable-paths.json").is_file()
    body_comparison = json.loads((bundle / "body-comparison.json").read_text())
    expected_body_fields = {
        "size",
        "normalized_instructions_sha256",
        "direct_calls",
        "indirect_calls",
        "frame_adjustment",
        "spills",
    }
    assert len(body_comparison["rows"]) == 8
    for row in body_comparison["rows"]:
        assert set(row) == {"kernel", "v1", "v2"}
        assert set(row["v1"]) == expected_body_fields
        assert set(row["v2"]) == expected_body_fields
    private_fragments = []
    for suffix in ("clean-a", "clean-b", "adversary"):
        variant = f"x86_64-061d13da22b8-attempt-7002-{suffix}"
        for target in ("elastic", "funnel", "profile"):
            fragment = (
                bundle
                / "subject/target/cache-gate/x86_64"
                / variant
                / "linker-fragments"
                / f"{target}.ld"
            )
            assert (
                hashlib.sha256(fragment.read_bytes()).hexdigest()
                == (
                    json.loads(hosted["capability"].read_text())["fragments"][target][
                        "sha256"
                    ]
                )
            )
            private_fragments.append(fragment.stat().st_ino)
    assert len(set(private_fragments)) == 9
    calls = hosted["log"].read_text()
    assert calls.count("subject-cache-gate") == 4
    assert calls.count("v1-cache-gate") == 2
    assert calls.count("extractor") == 3


def test_v1_exact_preflight_fails_before_current_extractor(
    hosted: dict[str, Any],
) -> None:
    completed = invoke(
        hosted,
        env={"FAKE_SUCCESS": "1", "FAKE_V1_SCHEMA_FAIL": "1"},
    )
    assert completed.returncode != 0
    calls = hosted["log"].read_text()
    assert calls.count("v1-cache-gate") == 2
    assert "extractor" not in calls
    assert not (hosted["evidence"] / "staging").exists()


def test_v1_control_provenance_hash_fails_before_current_extractor(
    hosted: dict[str, Any],
) -> None:
    completed = invoke(
        hosted,
        env={
            "FAKE_SUCCESS": "1",
            "FAKE_TAMPER_V1_CONTROL_PROVENANCE": "1",
        },
    )
    assert completed.returncode != 0
    assert "control provenance hash mismatch" in completed.stderr
    calls = hosted["log"].read_text()
    assert calls.count("v1-cache-gate") == 2
    assert "extractor" not in calls
    assert not (hosted["evidence"] / "staging").exists()


@pytest.mark.parametrize("fault", ["wrong-name", "duplicate-name"])
def test_v1_exact_symbol_names_fail_before_current_extractor(
    hosted: dict[str, Any], fault: str
) -> None:
    manifest_path = (
        hosted["assets"] / "x86_64-v1-replay-run-7-attempt-2" / "manifest.json"
    )
    document = json.loads(manifest_path.read_text())
    symbols = document["symbols"]["elastic_cache_gate"]["symbols"]
    if fault == "wrong-name":
        symbols[0]["name"] = "fixture::wrong_kernel"
    else:
        symbols[1]["name"] = symbols[0]["name"]
    manifest_path.write_text(json.dumps(document, sort_keys=True) + "\n")

    completed = invoke(hosted, env={"FAKE_SUCCESS": "1"})
    assert completed.returncode != 0
    assert "v1 exact symbol selection mismatch" in completed.stderr
    calls = hosted["log"].read_text()
    assert calls.count("v1-cache-gate") == 2
    assert "extractor" not in calls
    assert not (hosted["evidence"] / "staging").exists()


def test_hosted_private_fragment_hardlink_fails_before_extractor_or_staging(
    hosted: dict[str, Any],
) -> None:
    completed = invoke(
        hosted,
        env={"FAKE_SUCCESS": "1", "FAKE_HARDLINK_PRIVATE": "1"},
    )
    assert completed.returncode != 0
    assert "private fragment lacks distinct hosted identity" in completed.stderr
    calls = hosted["log"].read_text()
    assert calls.count("v1-cache-gate") == 2
    assert "extractor" not in calls
    assert not (hosted["evidence"] / "staging").exists()


@pytest.mark.parametrize("fault", ["create", "rename"])
def test_success_status_fault_invalidates_staged_pass(
    hosted: dict[str, Any], fault: str
) -> None:
    completed = invoke(
        hosted,
        env={
            "FAKE_SUCCESS": "1",
            "X86_CACHE_GATE_STATUS_FAULT": fault,
        },
    )
    assert completed.returncode == 125
    if hosted["status"].exists():
        assert hosted["status"].read_text() == "125\n"
    provenance_path = hosted["evidence"] / "staging/bundle/provenance.json"
    if provenance_path.exists():
        provenance = json.loads(provenance_path.read_text())
        assert provenance["proof"] == {"status": 125, "result": "FAIL"}
    assert not list(hosted["evidence"].glob(".proof.status.*"))


@pytest.mark.parametrize("flavor", ["actual", "gnu", "lld"])
def test_missing_linker_chain_member_fails_before_manifests_or_bundle(
    hosted: dict[str, Any], flavor: str
) -> None:
    document = capability_document(
        hosted["subject"], hosted["chain_root"] / f"case-{flavor}", remove_flavor=flavor
    )
    hosted["capability"].write_text(json.dumps(document, sort_keys=True) + "\n")
    completed = invoke(hosted)
    assert completed.returncode != 0
    calls = hosted["log"].read_text()
    assert "capability" in calls
    assert "cache-gate" not in calls
    assert not (hosted["evidence"] / "staging").exists()
    assert not (hosted["evidence"] / "bundle").exists()


def test_missing_explicit_cargo_driver_record_fails_before_manifests(
    hosted: dict[str, Any],
) -> None:
    document = json.loads(hosted["capability"].read_text())
    document["shapes"]["gnu"]["elastic"].pop("cargo_execution")
    hosted["capability"].write_text(json.dumps(document, sort_keys=True) + "\n")
    completed = invoke(hosted)
    assert completed.returncode != 0
    calls = hosted["log"].read_text()
    assert "capability" in calls
    assert "cache-gate" not in calls


@pytest.mark.parametrize(
    "failure",
    ["FAKE_CAPABILITY_SCHEMA_FAIL", "FAKE_CAPABILITY_SHAPE_FAIL"],
)
def test_exact_capability_preflight_fails_before_manifests(
    hosted: dict[str, Any], failure: str
) -> None:
    completed = invoke(hosted, env={failure: "1"})
    assert completed.returncode != 0
    calls = hosted["log"].read_text()
    assert "capability" in calls
    assert "cache-gate" not in calls
    assert not (hosted["evidence"] / "staging").exists()


def test_changed_shape_execution_fails_before_manifests(
    hosted: dict[str, Any],
) -> None:
    document = json.loads(hosted["capability"].read_text())
    execution = Path(
        document["shapes"]["actual"]["elastic"]["linker_execution"]["absolute_path"]
    )
    execution.write_text(json.dumps({"linker": document["required_linkers"]["gnu"]}))
    completed = invoke(hosted)
    assert completed.returncode != 0
    calls = hosted["log"].read_text()
    assert "capability" in calls
    assert "cache-gate" not in calls


def test_explicit_cargo_driver_must_record_actual_linker(
    hosted: dict[str, Any],
) -> None:
    document = json.loads(hosted["capability"].read_text())
    record = document["shapes"]["gnu"]["elastic"]["cargo_execution"]
    execution = Path(record["absolute_path"])
    execution.write_text(
        json.dumps({"linker": document["required_linkers"]["gnu"]}) + "\n"
    )
    record["sha256"] = hashlib.sha256(execution.read_bytes()).hexdigest()
    hosted["capability"].write_text(json.dumps(document, sort_keys=True) + "\n")
    completed = invoke(hosted)
    assert completed.returncode != 0
    calls = hosted["log"].read_text()
    assert "capability" in calls
    assert "cache-gate" not in calls


def test_later_failure_writes_atomic_status_and_never_times(
    hosted: dict[str, Any],
) -> None:
    completed = invoke(hosted, env={"FAKE_CAPABILITY_STATUS": "73"})
    assert completed.returncode == 73
    assert hosted["status"].read_text() == "73\n"
    assert not list(hosted["evidence"].glob(".proof.status.*"))
    calls = hosted["log"].read_text()
    assert "capability" in calls
    assert all(word not in calls for word in ("bench", "criterion", "perf"))


def test_capability_failure_replays_bounded_sanitized_stderr(
    hosted: dict[str, Any],
) -> None:
    prefix = b"::error::forged\r\x1b[31m\t\xc3\xa9\x00\n"
    suffix = b"\n::warning::tail\r\x1b[0m\t\x7f"
    first = prefix + (b"H" * (4096 - len(prefix)))
    last = (b"T" * (4096 - len(suffix))) + suffix
    payload = first + b"DO_NOT_REPLAY" + (b"M" * 2048) + b"\xff" + last
    stderr_source = hosted["evidence"].parent / "capability-stderr.bin"
    stderr_source.write_bytes(payload)

    completed = invoke(
        hosted,
        env={
            "FAKE_CAPABILITY_STATUS": "73",
            "FAKE_CAPABILITY_STDERR_FILE": str(stderr_source),
        },
    )

    inert_prefix = "cache-gate capability diagnostic | "
    assert completed.returncode == 73
    assert hosted["status"].read_bytes() == b"73\n"
    assert (hosted["evidence"] / "logs/capability.stderr").read_bytes() == payload
    assert completed.stderr.endswith(
        f"{inert_prefix}HOLD: native linker capability probe failed\n"
    )
    assert completed.stderr.splitlines()
    assert all(line.startswith(inert_prefix) for line in completed.stderr.splitlines())
    assert f"{inert_prefix}::error::forged" in completed.stderr
    assert f"{inert_prefix}::warning::tail" in completed.stderr
    assert f"{inert_prefix}[... omitted ...]" in completed.stderr
    assert "DO_NOT_REPLAY" not in completed.stderr
    assert "\\xff" not in completed.stderr
    assert "\\x0d\\x1b[31m\\x09\\xc3\\xa9\\x00" in completed.stderr
    assert "\\x0d\\x1b[0m\\x09\\x7f" in completed.stderr
    assert all(character not in completed.stderr for character in "\r\x1b\té\x00")
    assert not any(line.startswith("::") for line in completed.stderr.splitlines())


def test_unsafe_capability_diagnostic_read_preserves_original_status(
    hosted: dict[str, Any],
) -> None:
    payload = b"unsafe diagnostic payload\n"
    stderr_source = hosted["evidence"].parent / "capability-stderr.bin"
    stderr_source.write_bytes(payload)

    completed = invoke(
        hosted,
        env={
            "FAKE_CAPABILITY_STATUS": "73",
            "FAKE_CAPABILITY_STDERR_FILE": str(stderr_source),
            "FAKE_CAPABILITY_STDERR_UNSAFE": "hardlink",
        },
    )

    assert completed.returncode == 73
    assert hosted["status"].read_bytes() == b"73\n"
    assert (hosted["evidence"] / "logs/capability.stderr").read_bytes() == payload
    assert completed.stderr == (
        "cache-gate capability diagnostic | diagnostic unavailable\n"
        "cache-gate capability diagnostic | "
        "HOLD: native linker capability probe failed\n"
    )


@pytest.mark.parametrize("sink", ["closed-stderr", "closed-pipe"])
def test_broken_diagnostic_sink_preserves_original_status(
    hosted: dict[str, Any],
    sink: str,
) -> None:
    environment = {
        **hosted["env"],
        "FAKE_CAPABILITY_STATUS": "73",
    }
    if sink == "closed-stderr":

        def close_stderr() -> None:
            os.close(2)

        completed = subprocess.run(
            runner_arguments(hosted),
            text=True,
            stdout=subprocess.PIPE,
            check=False,
            env=environment,
            preexec_fn=close_stderr,
        )
    else:
        reader, writer = os.pipe()
        os.close(reader)
        try:
            completed = subprocess.run(
                runner_arguments(hosted),
                text=True,
                stdout=subprocess.PIPE,
                stderr=writer,
                check=False,
                env=environment,
            )
        finally:
            os.close(writer)

    assert completed.returncode == 73
    assert hosted["status"].read_bytes() == b"73\n"


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"\x00" * 20_000, id="nul-heavy"),
        pytest.param(b"\n" * 20_000, id="newline-heavy"),
    ],
)
def test_serialized_capability_diagnostic_is_bounded(
    hosted: dict[str, Any],
    payload: bytes,
) -> None:
    stderr_source = hosted["evidence"].parent / "capability-stderr.bin"
    stderr_source.write_bytes(payload)

    completed = invoke(
        hosted,
        env={
            "FAKE_CAPABILITY_STATUS": "73",
            "FAKE_CAPABILITY_STDERR_FILE": str(stderr_source),
        },
    )

    inert_prefix = "cache-gate capability diagnostic | "
    serialized = completed.stderr.encode("ascii")
    assert completed.returncode == 73
    assert hosted["status"].read_bytes() == b"73\n"
    assert (hosted["evidence"] / "logs/capability.stderr").read_bytes() == payload
    assert 0 < len(serialized) <= 8192
    assert serialized.endswith(
        f"{inert_prefix}HOLD: native linker capability probe failed\n".encode()
    )
    assert all(line.startswith(inert_prefix) for line in completed.stderr.splitlines())


def test_logs_symlink_swap_makes_diagnostic_unavailable(
    hosted: dict[str, Any],
) -> None:
    payload = b"trusted captured diagnostic\n"
    stderr_source = hosted["evidence"].parent / "capability-stderr.bin"
    stderr_source.write_bytes(payload)

    completed = invoke(
        hosted,
        env={
            "FAKE_CAPABILITY_STATUS": "73",
            "FAKE_CAPABILITY_STDERR_FILE": str(stderr_source),
            "FAKE_CAPABILITY_LOGS_SWAP": "symlink",
        },
    )

    anchored_logs = Path(f"{hosted['evidence']}/logs.anchored")
    assert completed.returncode == 73
    assert hosted["status"].read_bytes() == b"73\n"
    assert (anchored_logs / "capability.stderr").read_bytes() == payload
    assert (hosted["evidence"] / "logs").is_symlink()
    assert "attacker replacement" not in completed.stderr
    assert completed.stderr == (
        "cache-gate capability diagnostic | diagnostic unavailable\n"
        "cache-gate capability diagnostic | "
        "HOLD: native linker capability probe failed\n"
    )


@pytest.mark.parametrize("fault", ["create", "rename"])
def test_status_write_fault_forces_125_without_recursion_or_success(
    hosted: dict[str, Any], fault: str
) -> None:
    completed = invoke(
        hosted,
        env={"FAKE_CAPABILITY_STATUS": "73", "X86_CACHE_GATE_STATUS_FAULT": fault},
    )
    assert completed.returncode == 125
    if hosted["status"].exists():
        raw = hosted["status"].read_text()
        assert raw == "125\n"
    assert not list(hosted["evidence"].glob(".proof.status.*"))


def test_unexpected_argument_is_rejected_without_creating_evidence(
    hosted: dict[str, Any],
) -> None:
    completed = subprocess.run(
        [str(hosted["runner"]), "--unknown", "value"],
        text=True,
        capture_output=True,
        check=False,
        env=hosted["env"],
    )
    assert completed.returncode != 0
    assert not hosted["evidence"].exists()


def test_fixture_helper_does_not_leak_files(hosted: dict[str, Any]) -> None:
    # Keep test cleanup honest: every executable fake is beneath the pytest root.
    assert shutil.which("git", path=str(hosted["tools"])) == str(
        hosted["tools"] / "git"
    )
