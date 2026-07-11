"""Transactional provenance for named Criterion baselines."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 4
TRANSACTION_CONTEXT = ".opthash-context.json"
ARTIFACT_NAMES = (
    "benchmark.json",
    "estimates.json",
    "sample.json",
    "tukey.json",
)
TARGETS = frozenset({"speedup", "mean_latency"})
IMPLEMENTATIONS = ("std", "hashbrown", "elastic", "funnel")
SPEEDUP_GROUPS = (
    "insert",
    "get_hit",
    "get_hit_sequential",
    "get_miss",
    "tiny_lookup",
    "mixed",
    "delete_heavy",
    "resize_heavy",
)
LATENCY_SIZE_LABELS = ("1K", "10K", "100K", "1M", "10M")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RESERVED_BASELINES = frozenset({"new", "base", "change", "report"})
_TRANSACTION_NAME = re.compile(
    r"(?:(?:speedup|mean_latency)-.+-[0-9a-f]{32}|hydrate-[0-9a-f]{32})\Z"
)
_COMMON_METHODOLOGY_FILES = (
    "benches/support/common.rs",
    "benches/support/fixtures.rs",
    "scripts/bench.sh",
    "scripts/criterion_manifest.py",
)
_TARGET_METHODOLOGY_FILES = {
    "speedup": (
        "benches/speedup.rs",
        "benches/support/throughput.rs",
    ),
    "mean_latency": ("benches/mean_latency.rs",),
}
_OPTIONAL_METHODOLOGY_FILES = (
    ".cargo/config",
    ".cargo/config.toml",
)
_BUILD_ENVIRONMENT_NAMES = frozenset(
    {
        "CARGO_BUILD_TARGET",
        "CARGO_ENCODED_RUSTDOCFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CC",
        "CFLAGS",
        "CPPFLAGS",
        "CXX",
        "CXXFLAGS",
        "GLIBC_TUNABLES",
        "HOME",
        "LDFLAGS",
        "LD_PRELOAD",
        "MALLOC_CONF",
        "RUSTC",
        "RUSTC_BOOTSTRAP",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTC_WRAPPER",
        "RUSTDOCFLAGS",
        "RUSTFLAGS",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
    }
)
_CPU_IDENTITY_FIELDS = frozenset(
    {
        "Architecture",
        "Byte Order",
        "Vendor ID",
        "Model name",
        "CPU family",
        "Model",
        "Stepping",
        "Socket(s)",
        "Core(s) per socket",
        "Thread(s) per core",
        "NUMA node(s)",
    }
)


class ManifestError(RuntimeError):
    """A named Criterion baseline failed a provenance invariant."""


def _validate_target_and_baseline(target: str, baseline: str) -> None:
    if target not in TARGETS:
        raise ManifestError(f"unsupported Criterion target: {target!r}")
    if _SAFE_NAME.fullmatch(baseline) is None:
        raise ManifestError(f"unsafe Criterion baseline name: {baseline!r}")
    if baseline.lower() in _RESERVED_BASELINES:
        raise ManifestError(f"reserved Criterion baseline name: {baseline!r}")


def _opthash_root(root: Path) -> Path:
    return root.resolve() / ".opthash"


def _manifest_dir(root: Path, target: str) -> Path:
    return _opthash_root(root) / "manifests" / target


def _assert_managed_path(root: Path, path: Path) -> None:
    """Reject lexical escapes and symlinks in every existing path component."""
    root = root.resolve()
    lexical = Path(os.path.abspath(path))
    try:
        relative = lexical.relative_to(root)
    except ValueError as error:
        raise ManifestError(
            f"managed path is outside Criterion root: {path}"
        ) from error
    current = root
    for part in relative.parts:
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise ManifestError(f"managed path contains a symlink: {current}")
    resolved_parent = lexical.parent.resolve(strict=False)
    try:
        resolved_parent.relative_to(root)
    except ValueError as error:
        raise ManifestError(
            f"managed path resolves outside Criterion root: {path}"
        ) from error


def _regular_file(path: Path, description: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as error:
        raise ManifestError(f"missing {description}: {path}") from error
    if not stat.S_ISREG(mode):
        raise ManifestError(f"{description} is not a regular file: {path}")


def _manifest_path(root: Path, target: str, baseline: str) -> Path:
    return _manifest_dir(root, target) / f"{baseline}.json"


def _pending_path(root: Path, target: str, baseline: str) -> Path:
    return _manifest_dir(root, target) / f"{baseline}.pending"


def _transactions_root(root: Path) -> Path:
    return _opthash_root(root) / "transactions"


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hash_file(path: Path) -> tuple[int, str]:
    _regular_file(path, "artifact")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _source_files(source_root: Path) -> list[Path]:
    source_root = source_root.resolve()
    paths = [source_root / name for name in ("Cargo.toml", "Cargo.lock", "build.rs")]
    paths.extend((source_root / "src").rglob("*.rs"))
    benches = source_root / "benches"
    paths.extend(path for path in benches.rglob("*") if path.suffix in {".rs", ".py"})
    unique = sorted(
        set(paths), key=lambda path: path.relative_to(source_root).as_posix()
    )
    for path in unique:
        _regular_file(path, "source fingerprint input")
    return unique


def source_fingerprint(source_root: Path) -> str:
    """Hash benchmark-relevant source paths and bytes deterministically."""
    source_root = source_root.resolve()
    digest = hashlib.sha256()
    for path in _source_files(source_root):
        relative = path.relative_to(source_root).as_posix().encode()
        digest.update(relative)
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _command_output(argv: list[str], cwd: Path | None = None) -> str | None:
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip()


def _source_metadata(source_root: Path) -> dict[str, Any]:
    source_root = source_root.resolve()
    head = _command_output(["git", "rev-parse", "HEAD"], source_root)
    status = _command_output(["git", "status", "--porcelain"], source_root)
    return {
        "algorithm": "sha256_path_nul_bytes_v1",
        "sha256": source_fingerprint(source_root),
        "git_head": head,
        "git_dirty": None if status is None else bool(status),
    }


def _host_identity() -> dict[str, str]:
    name = platform.node().strip()
    if not name:
        name = platform.uname().node.strip()
    if not name:
        raise ManifestError("cannot determine benchmark host identity")
    return {
        "algorithm": "sha256_hostname_v1",
        "name": name,
        "sha256": _sha256_bytes(name.encode()),
    }


def _cpu_identity() -> dict[str, Any]:
    fields: dict[str, str] = {}
    raw = _command_output(["lscpu", "--json"])
    if raw is not None:
        try:
            parsed = json.loads(raw)
            rows = parsed.get("lscpu") if isinstance(parsed, dict) else None
            if isinstance(rows, list):
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    field = row.get("field")
                    data = row.get("data")
                    if not isinstance(field, str) or not isinstance(data, str):
                        continue
                    field = field.rstrip(":")
                    if field in _CPU_IDENTITY_FIELDS:
                        fields[field] = data.strip()
        except json.JSONDecodeError:
            fields = {}
    if not fields:
        fields = {
            "Architecture": platform.machine().lower(),
            "Processor": platform.processor(),
        }
    return {
        "algorithm": "sha256_canonical_cpu_fields_v1",
        "fields": fields,
        "sha256": _sha256_bytes(_canonical_json(fields)),
    }


def _is_dynamic_build_environment_name(name: str) -> bool:
    if name.startswith(("CARGO_BUILD_", "CARGO_PROFILE_", "MALLOC_")):
        return True
    if name.startswith("CARGO_TARGET_") and name.endswith(
        ("_LINKER", "_RUNNER", "_RUSTDOCFLAGS", "_RUSTFLAGS")
    ):
        return True
    return name.startswith(("AR_", "CC_", "CFLAGS_", "CXX_", "CXXFLAGS_"))


def _build_environment() -> dict[str, str | None]:
    names = set(_BUILD_ENVIRONMENT_NAMES)
    names.update(
        name for name in os.environ if _is_dynamic_build_environment_name(name)
    )
    return {name: os.environ.get(name) for name in sorted(names)}


def _cargo_configuration(source_root: Path) -> dict[str, Any]:
    source_root = source_root.resolve()
    records: list[dict[str, Any]] = []
    seen: set[Path] = set()

    def record(scope: str, directory: Path) -> None:
        for name in ("config", "config.toml"):
            path = directory / name
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            size, digest = _hash_file(path)
            seen.add(resolved)
            records.append(
                {
                    "scope": scope,
                    "name": name,
                    "size_bytes": size,
                    "sha256": digest,
                }
            )

    for distance, parent in enumerate(source_root.parents, start=1):
        record(f"ancestor:{distance}", parent / ".cargo")
    cargo_home_raw = os.environ.get("CARGO_HOME")
    cargo_home = (
        Path(cargo_home_raw).expanduser() if cargo_home_raw else Path.home() / ".cargo"
    )
    record("cargo_home", cargo_home)
    return {
        "schema_version": 1,
        "algorithm": "sha256_canonical_cargo_config_records_v1",
        "sha256": _sha256_bytes(_canonical_json(records)),
        "files": records,
    }


def _execution_metadata(
    caller_context: dict[str, Any], source_root: Path
) -> dict[str, Any]:
    execution = dict(caller_context)
    execution.setdefault("core", None)
    execution.setdefault("criterion_args", [])
    execution.setdefault("forwarded_args", [])
    execution.setdefault("criterion_tuning", list(execution["forwarded_args"]))
    execution.update(
        {
            "architecture": platform.machine().lower(),
            "operating_system": platform.platform(aliased=True),
            "host_identity": _host_identity(),
            "cpu_identity": _cpu_identity(),
            "rustc_vv": _command_output(["rustc", "-Vv"]),
            "build_environment": _build_environment(),
            "cargo_configuration": _cargo_configuration(source_root),
        }
    )
    return execution


def fixture_for(target: str) -> dict[str, Any]:
    if target == "mean_latency":
        value: dict[str, Any] = {
            "schema_version": 1,
            "hit_traces": [
                {
                    "name": "randomized",
                    "algorithm": "splitmix64_fisher_yates_rejection_v1",
                    "seed": "0xd1b54a32d192ed03",
                },
                {
                    "name": "sequential",
                    "algorithm": "input_order_cycle_v1",
                    "seed": None,
                },
            ],
            "parameters": {
                "latency_sizes": [1_000, 10_000, 100_000, 1_000_000, 10_000_000]
            },
        }
    elif target == "speedup":
        value = {
            "schema_version": 1,
            "parameters": {
                "map_size": 20_000,
                "op_count": 100_000,
                "tiny_map_size": 32,
                "tiny_op_count": 500_000,
                "resize_insert_count": 8_000,
            },
        }
    else:
        raise ManifestError(f"unsupported Criterion target: {target!r}")
    value["fingerprint_sha256"] = _sha256_bytes(_canonical_json(value))
    return value


def methodology_for(source_root: Path, target: str) -> dict[str, Any]:
    """Hash the benchmark and wrapper files whose semantics must stay fixed."""
    if target not in TARGETS:
        raise ManifestError(f"unsupported Criterion target: {target!r}")
    source_root = source_root.resolve()
    required_paths = _COMMON_METHODOLOGY_FILES + _TARGET_METHODOLOGY_FILES[target]
    relative_paths = tuple(sorted(required_paths + _OPTIONAL_METHODOLOGY_FILES))
    digest = hashlib.sha256()
    for relative in relative_paths:
        path = source_root / relative
        digest.update(relative.encode())
        digest.update(b"\0")
        try:
            path.lstat()
        except FileNotFoundError:
            if relative not in _OPTIONAL_METHODOLOGY_FILES:
                raise ManifestError(f"missing benchmark methodology input: {path}")
            digest.update(b"missing\0")
            continue
        _regular_file(path, "benchmark methodology input")
        digest.update(b"present\0")
        digest.update(path.read_bytes())
    return {
        "schema_version": 1,
        "algorithm": "sha256_path_nul_presence_bytes_v1",
        "sha256": digest.hexdigest(),
        "files": list(relative_paths),
        "fixture_fingerprint_sha256": fixture_for(target)["fingerprint_sha256"],
    }


def expected_registration_ids(target: str) -> tuple[str, ...]:
    """Return the complete unfiltered registration set for a product target."""
    if target == "speedup":
        groups = SPEEDUP_GROUPS
    elif target == "mean_latency":
        groups = tuple(
            f"{prefix}_{size}"
            for prefix in ("get_hit_latency", "get_hit_sequential_latency")
            for size in LATENCY_SIZE_LABELS
        )
    else:
        raise ManifestError(f"unsupported Criterion target: {target!r}")
    return tuple(
        sorted(
            f"{group}/{group}_{implementation}"
            for group in groups
            for implementation in IMPLEMENTATIONS
        )
    )


def _write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def _read_json(path: Path) -> dict[str, Any]:
    _regular_file(path, "JSON file")
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ManifestError(f"invalid JSON file {path}: {error}") from error
    if not isinstance(value, dict):
        raise ManifestError(f"expected JSON object in {path}")
    return value


def prepare_save(
    root: Path,
    source_root: Path,
    target: str,
    baseline: str,
    caller_context: dict[str, Any],
) -> Path:
    """Start a fail-closed SAVE transaction and return its CRITERION_HOME."""
    _validate_target_and_baseline(target, baseline)
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    source_root = source_root.resolve()
    manifest_dir = _manifest_dir(root, target)
    _assert_managed_path(root, manifest_dir)
    manifest_dir.mkdir(parents=True, exist_ok=True)
    pending = _pending_path(root, target, baseline)
    transaction_id = f"{target}-{baseline}-{uuid.uuid4().hex}"
    try:
        descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError as error:
        raise ManifestError(
            f"baseline has a pending SAVE: {target}/{baseline}"
        ) from error
    try:
        os.write(descriptor, (transaction_id + "\n").encode())
    finally:
        os.close(descriptor)

    transaction = _transactions_root(root) / transaction_id
    _assert_managed_path(root, transaction)
    transaction.mkdir(parents=True, exist_ok=False)
    execution = _execution_metadata(caller_context, source_root)
    context = {
        "schema_version": SCHEMA_VERSION,
        "target": target,
        "baseline": baseline,
        "transaction_id": transaction_id,
        "source_root": str(source_root),
        "source": _source_metadata(source_root),
        "fixture": fixture_for(target),
        "methodology": methodology_for(source_root, target),
        "execution": execution,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    _write_json_atomic(transaction / TRANSACTION_CONTEXT, context)
    return transaction.resolve()


def _registration_from_directory(
    discovery_root: Path, baseline_dir: Path, baseline: str
) -> dict[str, Any]:
    _assert_managed_path(discovery_root, baseline_dir)
    try:
        baseline_mode = baseline_dir.lstat().st_mode
    except FileNotFoundError as error:
        raise ManifestError(f"missing baseline directory: {baseline_dir}") from error
    if not stat.S_ISDIR(baseline_mode):
        raise ManifestError(f"baseline path is not a regular directory: {baseline_dir}")
    entries = sorted(baseline_dir.iterdir(), key=lambda path: path.name)
    for path in entries:
        _regular_file(path, "baseline artifact")
    names = tuple(path.name for path in entries)
    if names != tuple(sorted(ARTIFACT_NAMES)):
        raise ManifestError(
            f"baseline must contain exactly {ARTIFACT_NAMES}, found {names}: {baseline_dir}"
        )
    try:
        function = baseline_dir.parent.name
        group = baseline_dir.parent.parent.name
        relative_dir = baseline_dir.relative_to(discovery_root)
    except ValueError as error:
        raise ManifestError(
            f"baseline escapes discovery root: {baseline_dir}"
        ) from error
    if len(relative_dir.parts) != 3 or relative_dir.parts == (".opthash",):
        raise ManifestError(f"unexpected Criterion baseline path: {relative_dir}")
    benchmark = _read_json(baseline_dir / "benchmark.json")
    expected_id = f"{group}/{function}"
    if (
        benchmark.get("group_id") != group
        or benchmark.get("function_id") != function
        or benchmark.get("full_id") != expected_id
        or benchmark.get("directory_name") != expected_id
    ):
        raise ManifestError(f"benchmark identity does not match path: {baseline_dir}")
    artifacts = []
    for name in ARTIFACT_NAMES:
        path = baseline_dir / name
        size, digest = _hash_file(path)
        artifacts.append(
            {
                "relative_path": f"{group}/{function}/{baseline}/{name}",
                "size_bytes": size,
                "sha256": digest,
            }
        )
    return {
        "group_id": group,
        "function_id": function,
        "full_id": expected_id,
        "artifacts": artifacts,
    }


def _discover_registrations(
    root: Path,
    baseline: str,
    *,
    allowed_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    root = root.resolve()
    directories = []
    for path in root.rglob(baseline):
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if relative.parts and relative.parts[0] == ".opthash":
            continue
        full_id = f"{path.parent.parent.name}/{path.parent.name}"
        if (
            path.name == baseline
            and path.is_dir()
            and (allowed_ids is None or full_id in allowed_ids)
        ):
            directories.append(path)
    registrations = [
        _registration_from_directory(root, directory, baseline)
        for directory in sorted(directories)
    ]
    if not registrations:
        raise ManifestError(
            f"no Criterion registrations found for baseline {baseline!r}"
        )
    ids = [registration["full_id"] for registration in registrations]
    if len(ids) != len(set(ids)):
        raise ManifestError(
            f"duplicate Criterion registration ID for baseline {baseline!r}"
        )
    paths = [
        artifact["relative_path"]
        for registration in registrations
        for artifact in registration["artifacts"]
    ]
    if len(paths) != len(set(paths)):
        raise ManifestError(
            f"duplicate Criterion artifact path for baseline {baseline!r}"
        )
    return registrations


def _require_complete_target(target: str, registrations: list[dict[str, Any]]) -> None:
    expected = set(expected_registration_ids(target))
    actual = {registration["full_id"] for registration in registrations}
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ManifestError(
            f"incomplete {target} registration set: missing={missing}, extra={extra}"
        )


def require_complete_target(manifest: dict[str, Any], target: str) -> None:
    """Require every unfiltered registration for a chart/report consumer."""
    criterion = manifest.get("criterion")
    registrations = (
        criterion.get("registrations") if isinstance(criterion, dict) else None
    )
    if not isinstance(registrations, list) or any(
        not isinstance(registration, dict) for registration in registrations
    ):
        raise ManifestError("manifest registration set is invalid")
    _require_complete_target(target, registrations)


def _publish_baseline_directories(
    root: Path,
    transaction: Path,
    baseline: str,
    registrations: list[dict[str, Any]],
) -> None:
    for registration in registrations:
        group = registration["group_id"]
        function = registration["function_id"]
        if (
            _SAFE_NAME.fullmatch(group) is None
            or _SAFE_NAME.fullmatch(function) is None
        ):
            raise ManifestError(
                f"unsafe Criterion registration path: {group}/{function}"
            )
        source = transaction / group / function / baseline
        destination = root / group / function / baseline
        _assert_managed_path(transaction, source)
        _assert_managed_path(root, destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{baseline}.{uuid.uuid4().hex}.tmp")
        shutil.copytree(source, temporary)
        if destination.exists():
            shutil.rmtree(destination)
        os.replace(temporary, destination)


def publish_save(root: Path, transaction: Path) -> dict[str, Any]:
    """Validate and atomically publish one completed SAVE transaction."""
    root = root.resolve()
    transaction = Path(os.path.abspath(transaction))
    expected_root = _transactions_root(root).resolve()
    if transaction.parent.resolve(strict=False) != expected_root:
        raise ManifestError(
            f"transaction is not a direct child of {expected_root}: {transaction}"
        )
    _assert_managed_path(root, transaction)
    try:
        transaction_mode = transaction.lstat().st_mode
    except FileNotFoundError as error:
        raise ManifestError(f"missing transaction: {transaction}") from error
    if not stat.S_ISDIR(transaction_mode):
        raise ManifestError(f"transaction is not a regular directory: {transaction}")
    context = _read_json(transaction / TRANSACTION_CONTEXT)
    target = str(context.get("target"))
    baseline = str(context.get("baseline"))
    _validate_target_and_baseline(target, baseline)
    pending = _pending_path(root, target, baseline)
    _assert_managed_path(root, pending)
    if not pending.exists():
        raise ManifestError(
            f"SAVE transaction has no pending marker: {target}/{baseline}"
        )
    _regular_file(pending, "pending marker")
    transaction_id = context.get("transaction_id")
    if (
        not isinstance(transaction_id, str)
        or transaction.name != transaction_id
        or pending.read_text().strip() != transaction_id
    ):
        raise ManifestError(
            "transaction, context, and pending marker identity mismatch"
        )
    if context.get("schema_version") != SCHEMA_VERSION:
        raise ManifestError("SAVE transaction context schema mismatch")
    source_root_value = context.get("source_root")
    source = context.get("source")
    if not isinstance(source_root_value, str) or not isinstance(source, dict):
        raise ManifestError("SAVE transaction source context is invalid")
    source_root = Path(source_root_value)
    if source_fingerprint(source_root) != source.get("sha256"):
        raise ManifestError("source changed during Criterion SAVE transaction")
    if context.get("fixture") != fixture_for(target):
        raise ManifestError("fixture changed during Criterion SAVE transaction")
    if context.get("methodology") != methodology_for(source_root, target):
        raise ManifestError("methodology changed during Criterion SAVE transaction")
    execution = context.get("execution")
    if not isinstance(execution, dict):
        raise ManifestError("SAVE transaction execution context is invalid")
    if execution.get("build_environment") != _build_environment():
        raise ManifestError(
            "build environment changed during Criterion SAVE transaction"
        )
    if execution.get("cargo_configuration") != _cargo_configuration(source_root):
        raise ManifestError(
            "Cargo configuration changed during Criterion SAVE transaction"
        )
    registrations = _discover_registrations(transaction, baseline)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "target": target,
        "baseline": baseline,
        "provenance": {
            "kind": "measured",
            "created_utc": context["created_utc"],
            "transaction_id": context["transaction_id"],
        },
        "source": source,
        "fixture": context["fixture"],
        "methodology": context["methodology"],
        "execution": execution,
        "criterion": {"registrations": registrations},
    }
    _validate_manifest_schema(manifest)
    _publish_baseline_directories(root, transaction, baseline, registrations)
    manifest_path = _manifest_path(root, target, baseline)
    _assert_managed_path(root, manifest_path)
    _write_json_atomic(manifest_path, manifest)
    shutil.rmtree(transaction)
    pending.unlink()
    return manifest


def _validate_manifest_schema(manifest: dict[str, Any]) -> None:
    provenance = manifest.get("provenance")
    source = manifest.get("source")
    fixture = manifest.get("fixture")
    methodology = manifest.get("methodology")
    execution = manifest.get("execution")
    if not isinstance(provenance, dict) or not isinstance(source, dict):
        raise ManifestError("manifest source/provenance schema is invalid")
    if not isinstance(fixture, dict) or not isinstance(methodology, dict):
        raise ManifestError("manifest fixture/methodology schema is invalid")
    if not isinstance(execution, dict):
        raise ManifestError("manifest execution schema is invalid")
    if not isinstance(provenance.get("created_utc"), str):
        raise ManifestError("manifest provenance has no creation timestamp")
    digest = source.get("sha256")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise ManifestError("manifest source digest is not lowercase SHA-256")
    if source.get("algorithm") != "sha256_path_nul_bytes_v1":
        raise ManifestError("manifest source algorithm is invalid")
    fixture_digest = fixture.get("fingerprint_sha256")
    if not isinstance(fixture_digest, str) or _SHA256.fullmatch(fixture_digest) is None:
        raise ManifestError("manifest fixture fingerprint is invalid")
    for field in (
        "architecture",
        "operating_system",
        "rustc_vv",
        "host_identity",
        "cpu_identity",
        "build_environment",
        "cargo_configuration",
        "core",
        "criterion_args",
        "forwarded_args",
        "criterion_tuning",
    ):
        if field not in execution:
            raise ManifestError(f"manifest execution is missing {field}")
    if provenance.get("kind") != "measured":
        raise ManifestError("manifest provenance is not measured")
    transaction_id = provenance.get("transaction_id")
    if not isinstance(transaction_id, str) or not transaction_id:
        raise ManifestError("measured provenance has no transaction identity")
    if "recovery" in manifest:
        raise ManifestError("measured provenance contains a recovery field")
    for field in ("architecture", "operating_system", "rustc_vv"):
        if not isinstance(execution.get(field), str) or not execution[field]:
            raise ManifestError("measured execution identity is incomplete")
    core = execution.get("core")
    if core is not None and (
        isinstance(core, bool) or not isinstance(core, int) or core < 0
    ):
        raise ManifestError("measured execution core is invalid")
    for field in ("criterion_args", "forwarded_args", "criterion_tuning"):
        values = execution.get(field)
        if not isinstance(values, list) or any(
            not isinstance(value, str) for value in values
        ):
            raise ManifestError(f"measured {field} is invalid")
    host = execution.get("host_identity")
    if (
        not isinstance(host, dict)
        or host.get("algorithm") != "sha256_hostname_v1"
        or not isinstance(host.get("name"), str)
        or not host["name"]
        or not isinstance(host.get("sha256"), str)
        or _SHA256.fullmatch(host["sha256"]) is None
    ):
        raise ManifestError("measured host identity is invalid")
    cpu = execution.get("cpu_identity")
    if (
        not isinstance(cpu, dict)
        or cpu.get("algorithm") != "sha256_canonical_cpu_fields_v1"
        or not isinstance(cpu.get("fields"), dict)
        or not cpu["fields"]
        or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in cpu["fields"].items()
        )
        or not isinstance(cpu.get("sha256"), str)
        or _SHA256.fullmatch(cpu["sha256"]) is None
    ):
        raise ManifestError("measured CPU identity is invalid")
    if host["sha256"] != _sha256_bytes(host["name"].encode()):
        raise ManifestError("measured host identity digest is invalid")
    if cpu["sha256"] != _sha256_bytes(_canonical_json(cpu["fields"])):
        raise ManifestError("measured CPU identity digest is invalid")
    build_environment = execution.get("build_environment")
    if (
        not isinstance(build_environment, dict)
        or not _BUILD_ENVIRONMENT_NAMES.issubset(build_environment)
        or any(
            not isinstance(name, str)
            or (
                name not in _BUILD_ENVIRONMENT_NAMES
                and not _is_dynamic_build_environment_name(name)
            )
            or (value is not None and not isinstance(value, str))
            for name, value in build_environment.items()
        )
    ):
        raise ManifestError("measured build environment is invalid")
    cargo_configuration = execution.get("cargo_configuration")
    cargo_files = (
        cargo_configuration.get("files")
        if isinstance(cargo_configuration, dict)
        else None
    )
    if (
        not isinstance(cargo_configuration, dict)
        or cargo_configuration.get("schema_version") != 1
        or cargo_configuration.get("algorithm")
        != "sha256_canonical_cargo_config_records_v1"
        or not isinstance(cargo_configuration.get("sha256"), str)
        or _SHA256.fullmatch(cargo_configuration["sha256"]) is None
        or not isinstance(cargo_files, list)
        or any(
            not isinstance(record, dict)
            or not isinstance(record.get("scope"), str)
            or record.get("name") not in {"config", "config.toml"}
            or isinstance(record.get("size_bytes"), bool)
            or not isinstance(record.get("size_bytes"), int)
            or record["size_bytes"] < 0
            or not isinstance(record.get("sha256"), str)
            or _SHA256.fullmatch(record["sha256"]) is None
            for record in cargo_files
        )
        or cargo_configuration["sha256"] != _sha256_bytes(_canonical_json(cargo_files))
    ):
        raise ManifestError("measured Cargo configuration is invalid")
    cargo_ids = [
        (record["scope"], record["name"])
        for record in cargo_files
        if isinstance(record, dict)
    ]
    if len(cargo_ids) != len(set(cargo_ids)):
        raise ManifestError("measured Cargo configuration has duplicates")
    if (
        methodology.get("schema_version") != 1
        or methodology.get("algorithm") != "sha256_path_nul_presence_bytes_v1"
        or not isinstance(methodology.get("sha256"), str)
        or _SHA256.fullmatch(methodology["sha256"]) is None
        or not isinstance(methodology.get("files"), list)
        or not methodology["files"]
        or any(not isinstance(path, str) or not path for path in methodology["files"])
        or methodology.get("fixture_fingerprint_sha256") != fixture_digest
    ):
        raise ManifestError("measured methodology identity is invalid")
    if methodology["files"] != sorted(set(methodology["files"])):
        raise ManifestError("measured methodology file set is invalid")


def _verify_registration(
    root: Path, baseline: str, registration: dict[str, Any]
) -> None:
    group = registration.get("group_id")
    function = registration.get("function_id")
    full_id = registration.get("full_id")
    if not isinstance(group, str) or not isinstance(function, str):
        raise ManifestError("manifest registration has invalid IDs")
    if full_id != f"{group}/{function}":
        raise ManifestError(f"manifest full ID mismatch: {full_id!r}")
    baseline_dir = root / group / function / baseline
    actual = _registration_from_directory(root, baseline_dir, baseline)
    if actual != registration:
        raise ManifestError(f"artifact hash or size mismatch for {full_id}")


def verify_manifest(
    root: Path,
    target: str,
    baseline: str,
    *,
    strict_measured: bool = False,
) -> dict[str, Any]:
    """Verify one canonical baseline and return its manifest."""
    _validate_target_and_baseline(target, baseline)
    root = root.resolve()
    pending = _pending_path(root, target, baseline)
    manifest_path = _manifest_path(root, target, baseline)
    _assert_managed_path(root, pending)
    _assert_managed_path(root, manifest_path)
    if pending.exists():
        raise ManifestError(f"baseline has a pending SAVE: {target}/{baseline}")
    manifest = _read_json(manifest_path)
    if (
        manifest.get("schema_version") != SCHEMA_VERSION
        or manifest.get("target") != target
        or manifest.get("baseline") != baseline
    ):
        raise ManifestError(f"manifest identity mismatch: {target}/{baseline}")
    provenance = manifest.get("provenance")
    kind = provenance.get("kind") if isinstance(provenance, dict) else None
    if kind != "measured":
        raise ManifestError(f"unsupported manifest provenance: {kind!r}")
    _validate_manifest_schema(manifest)
    if manifest.get("fixture") != fixture_for(target):
        raise ManifestError(
            f"fixture fingerprint or metadata mismatch: {target}/{baseline}"
        )
    criterion = manifest.get("criterion")
    registrations = (
        criterion.get("registrations") if isinstance(criterion, dict) else None
    )
    if not isinstance(registrations, list) or not registrations:
        raise ManifestError("manifest has no Criterion registrations")
    if any(not isinstance(registration, dict) for registration in registrations):
        raise ManifestError("manifest registration is not an object")
    ids = [registration.get("full_id") for registration in registrations]
    if len(ids) != len(set(ids)):
        raise ManifestError("manifest has duplicate Criterion registration IDs")
    for registration in registrations:
        _verify_registration(root, baseline, registration)
    return manifest


def _compatibility_value(manifest: dict[str, Any], field: str) -> Any:
    if field == "fixture":
        return manifest["fixture"]["fingerprint_sha256"]
    if field == "methodology":
        return manifest["methodology"]["sha256"]
    if field == "registrations":
        return sorted(
            registration["full_id"]
            for registration in manifest["criterion"]["registrations"]
        )
    if field in {"host_identity", "cpu_identity"}:
        identity = manifest["execution"].get(field)
        return identity.get("sha256") if isinstance(identity, dict) else None
    return manifest["execution"].get(field)


_COMPARISON_FIELDS = (
    "fixture",
    "methodology",
    "registrations",
    "architecture",
    "operating_system",
    "host_identity",
    "cpu_identity",
    "build_environment",
    "cargo_configuration",
    "core",
    "rustc_vv",
    "criterion_tuning",
)
_CURRENT_COMPARISON_FIELDS = tuple(
    field for field in _COMPARISON_FIELDS if field != "registrations"
)


def hydrate(
    root: Path,
    target: str,
    baseline: str,
    *,
    compare: str | None = None,
    strict_measured: bool = False,
    source_root: Path | None = None,
    caller_context: dict[str, Any] | None = None,
) -> Path:
    """Hydrate verified named baselines into a clean CRITERION_HOME."""
    root = root.resolve()
    if compare == baseline:
        raise ManifestError("baseline and comparison names must not be identical")
    first = verify_manifest(root, target, baseline, strict_measured=strict_measured)
    if strict_measured:
        require_complete_target(first, target)
    manifests = [(baseline, first)]
    if compare is not None:
        second = verify_manifest(root, target, compare, strict_measured=strict_measured)
        if strict_measured:
            require_complete_target(second, target)
        for field in _COMPARISON_FIELDS:
            if _compatibility_value(first, field) != _compatibility_value(
                second, field
            ):
                raise ManifestError(f"baseline comparison {field} mismatch")
        manifests.append((compare, second))
    if strict_measured:
        if source_root is None or caller_context is None:
            raise ManifestError(
                "strict regression hydration requires current source and execution context"
            )
        current = {
            "fixture": fixture_for(target),
            "methodology": methodology_for(source_root, target),
            "execution": _execution_metadata(caller_context, source_root),
        }
        for name, manifest in manifests:
            for field in _CURRENT_COMPARISON_FIELDS:
                if _compatibility_value(manifest, field) != _compatibility_value(
                    current, field
                ):
                    raise ManifestError(
                        f"current execution {field} mismatch for {target}/{name}"
                    )
    transaction = _transactions_root(root) / f"hydrate-{uuid.uuid4().hex}"
    _assert_managed_path(root, transaction)
    transaction.mkdir(parents=True, exist_ok=False)
    for name, manifest in manifests:
        for registration in manifest["criterion"]["registrations"]:
            group = registration["group_id"]
            function = registration["function_id"]
            source = root / group / function / name
            destination = transaction / group / function / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source, destination)
            if compare is not None and name == baseline:
                # Criterion's load-only report path reads the loaded samples
                # through its reserved `new` view while building group summary
                # plots. A clean transaction must provide that view explicitly;
                # relying on stale canonical `new/` data made offline reports
                # both crash-prone and provenance-ambiguous.
                shutil.copytree(source, destination.parent / "new")
    return transaction.resolve()


def discard_transaction(root: Path, transaction: Path) -> None:
    root = root.resolve()
    transaction = Path(os.path.abspath(transaction))
    transactions = _transactions_root(root).resolve()
    if transaction.parent.resolve(strict=False) != transactions:
        raise ManifestError("refusing to discard a non-root transaction path")
    if _TRANSACTION_NAME.fullmatch(transaction.name) is None:
        raise ManifestError("refusing to discard an invalid transaction name")
    _assert_managed_path(root, transaction)
    if transaction.exists():
        if not stat.S_ISDIR(transaction.lstat().st_mode):
            raise ManifestError("refusing to discard a non-directory transaction")
        shutil.rmtree(transaction)


def _parse_context(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ManifestError(f"invalid context JSON: {error}") from error
    if not isinstance(value, dict):
        raise ManifestError("context JSON must be an object")
    return value


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare-save")
    prepare.add_argument("--root", type=Path, required=True)
    prepare.add_argument("--source-root", type=Path, required=True)
    prepare.add_argument("--target", required=True)
    prepare.add_argument("--baseline", required=True)
    prepare.add_argument("--context-json", default="{}")
    prepare.add_argument("--core", type=int)
    prepare.add_argument("--requested-bench")
    prepare.add_argument("--criterion-arg", action="append")
    prepare.add_argument("--forwarded-arg", action="append")

    publish = subparsers.add_parser("publish-save")
    publish.add_argument("--root", type=Path, required=True)
    publish.add_argument("--transaction", type=Path, required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--root", type=Path, required=True)
    verify.add_argument("--target", required=True)
    verify.add_argument("--baseline", required=True)
    verify.add_argument("--strict-measured", action="store_true")

    hydrate_parser = subparsers.add_parser("hydrate")
    hydrate_parser.add_argument("--root", type=Path, required=True)
    hydrate_parser.add_argument("--target", required=True)
    hydrate_parser.add_argument("--baseline", required=True)
    hydrate_parser.add_argument("--compare")
    hydrate_parser.add_argument("--strict-measured", action="store_true")
    hydrate_parser.add_argument("--source-root", type=Path)
    hydrate_parser.add_argument("--core", type=int)
    hydrate_parser.add_argument("--criterion-arg", action="append")
    hydrate_parser.add_argument("--forwarded-arg", action="append")

    discard_parser = subparsers.add_parser("discard")
    discard_parser.add_argument("--root", type=Path, required=True)
    discard_parser.add_argument("--transaction", type=Path, required=True)

    return parser


def _merge_cli_context(context: dict[str, Any], args: argparse.Namespace) -> None:
    if getattr(args, "core", None) is not None:
        context["core"] = args.core
    if getattr(args, "requested_bench", None) is not None:
        context["requested_bench"] = args.requested_bench
    if getattr(args, "criterion_arg", None) is not None:
        context["criterion_args"] = args.criterion_arg
    if getattr(args, "forwarded_arg", None) is not None:
        context["forwarded_args"] = args.forwarded_arg
        context["criterion_tuning"] = args.forwarded_arg


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "prepare-save":
            context = _parse_context(args.context_json)
            _merge_cli_context(context, args)
            result: Any = prepare_save(
                args.root,
                args.source_root,
                args.target,
                args.baseline,
                context,
            )
        elif args.command == "publish-save":
            result = publish_save(args.root, args.transaction)
        elif args.command == "verify":
            result = verify_manifest(
                args.root,
                args.target,
                args.baseline,
                strict_measured=args.strict_measured,
            )
        elif args.command == "hydrate":
            context = {}
            _merge_cli_context(context, args)
            result = hydrate(
                args.root,
                args.target,
                args.baseline,
                compare=args.compare,
                strict_measured=args.strict_measured,
                source_root=args.source_root,
                caller_context=context,
            )
        else:
            discard_transaction(args.root, args.transaction)
            result = None
    except ManifestError as error:
        print(f"criterion manifest error: {error}", file=sys.stderr)
        return 2
    if isinstance(result, Path):
        print(result)
    elif result is not None and args.command == "verify":
        print(_canonical_json(result).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
