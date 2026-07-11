import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


SCHEMA_VERSION = 1
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
RESERVED_NAMES = {"new", "base", "change", "report"}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GIT_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
UTC_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?\+00:00\Z")
CPU_IDENTITY_FIELDS = {
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
TARGET_FILES = {
    "speedup": ("benches/speedup.rs",),
    "mean_latency": ("benches/mean_latency.rs",),
    "set_ops": ("benches/set_ops.rs",),
    "map_api": ("benches/map_api.rs",),
    "load_factor": ("benches/load_factor.rs",),
    "payload_size": ("benches/payload_size.rs",),
    "scaled_insert": ("benches/scaled_insert.rs",),
}
COMMON_METHODOLOGY_FILES = (
    "Cargo.toml",
    "Cargo.lock",
    "build.rs",
    "scripts/bench.sh",
    "scripts/benchmark_metadata.py",
)
COMPATIBILITY_FIELDS = (
    "methodology",
    "core",
    "cpu_identity",
    "os",
    "rustc_vv",
    "forwarded_args",
    "registrations",
)
METADATA_FIELDS = {
    "schema",
    "source",
    "methodology",
    "target",
    "requested_bench",
    "forwarded_args",
    "registrations",
    "cpu_identity",
    "core",
    "os",
    "rustc_vv",
    "measured_at_utc",
}
SOURCE_FIELDS = {"before", "after", "commit", "dirty"}
CPU_IDENTITY_METADATA_FIELDS = {"algorithm", "fields", "sha256"}


class MetadataError(Exception):
    pass


def validate_name(value: str) -> None:
    if SAFE_NAME.fullmatch(value) is None or value.lower() in RESERVED_NAMES:
        raise MetadataError(f"unsafe or reserved name: {value!r}")


def hash_paths(root: Path, paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        relative = path.relative_to(root).as_posix().encode()
        contents = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    return digest.hexdigest()


def metadata_path(root: Path, target: str, baseline: str) -> Path:
    validate_name(target)
    validate_name(baseline)
    return root.resolve() / ".opthash" / "metadata" / target / f"{baseline}.json"


def source_fingerprint(source_root: Path) -> str:
    paths = [
        source_root / "Cargo.toml",
        source_root / "Cargo.lock",
        source_root / "build.rs",
    ]
    paths += sorted((source_root / "src").rglob("*.rs"))
    paths += sorted((source_root / "benches").rglob("*.rs"))
    paths += [
        source_root / "scripts" / "bench.sh",
        source_root / "scripts" / "benchmark_metadata.py",
    ]
    return hash_paths(source_root, paths)


def methodology_fingerprint(source_root: Path, target: str) -> str:
    if target not in TARGET_FILES:
        raise MetadataError(f"unsupported benchmark target: {target!r}")
    relative = COMMON_METHODOLOGY_FILES + TARGET_FILES[target]
    paths = [source_root / path for path in relative]
    paths += sorted((source_root / "benches" / "support").rglob("*.rs"))
    return hash_paths(source_root, paths)


def _registration_name(value: object, sidecar: Path) -> str:
    if not isinstance(value, str):
        raise MetadataError(f"invalid ownership metadata in {sidecar}")
    parts = value.split("/")
    if len(parts) != 2 or any(part in {"", ".", ".."} for part in parts):
        raise MetadataError(f"invalid ownership metadata in {sidecar}")
    return value


def other_target_registrations(root: Path, target: str, baseline: str) -> set[str]:
    current_sidecar = metadata_path(root, target, baseline)
    metadata_root = current_sidecar.parent.parent
    registrations: set[str] = set()
    for sidecar in sorted(metadata_root.glob(f"*/{baseline}.json")):
        if sidecar == current_sidecar:
            continue
        try:
            value = json.loads(sidecar.read_text())
        except (OSError, json.JSONDecodeError) as error:
            raise MetadataError(
                f"cannot read ownership metadata from {sidecar}"
            ) from error
        sidecar_target = sidecar.parent.name
        if (
            not isinstance(value, dict)
            or value.get("schema") != SCHEMA_VERSION
            or value.get("target") != sidecar_target
            or not isinstance(value.get("registrations"), list)
            or not value["registrations"]
        ):
            raise MetadataError(f"invalid ownership metadata in {sidecar}")
        registrations.update(
            _registration_name(registration, sidecar)
            for registration in value["registrations"]
        )
    return registrations


def begin(root: Path, source_root: Path, target: str, baseline: str) -> str:
    root = root.resolve()
    sidecar = metadata_path(root, target, baseline)
    protected = other_target_registrations(root, target, baseline)
    sidecar.unlink(missing_ok=True)
    for directory in root.glob(f"*/*/{baseline}"):
        registration = "/".join(directory.relative_to(root).parts[:2])
        if directory.is_dir() and registration not in protected:
            shutil.rmtree(directory)
    return source_fingerprint(source_root)


def measured_registrations(
    root: Path, baseline: str, *, exclude: set[str] | None = None
) -> list[str]:
    excluded = set() if exclude is None else exclude
    registrations = []
    for estimates in root.glob(f"*/*/{baseline}/estimates.json"):
        registration = "/".join(estimates.relative_to(root).parts[:2])
        if registration not in excluded:
            registrations.append(registration)
    if not registrations:
        raise MetadataError(f"no Criterion registrations for baseline {baseline!r}")
    return sorted(registrations)


def target_registrations(root: Path, target: str, baseline: str) -> list[str]:
    root = root.resolve()
    return measured_registrations(
        root,
        baseline,
        exclude=other_target_registrations(root, target, baseline),
    )


def write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp-{os.getpid()}")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def read_metadata(root: Path, target: str, baseline: str) -> dict[str, object]:
    path = metadata_path(root, target, baseline)
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise MetadataError(f"cannot read benchmark metadata from {path}") from error
    if not isinstance(value, dict):
        raise MetadataError(f"invalid benchmark metadata in {path}")
    return value


def _invalid_metadata(name: str, field: str) -> None:
    raise MetadataError(f"invalid benchmark metadata for {name!r}: {field}")


def _validate_metadata(value: dict[str, object], name: str) -> None:
    if set(value) != METADATA_FIELDS:
        _invalid_metadata(name, "fields")
    schema = value["schema"]
    if type(schema) is not int or schema != SCHEMA_VERSION:
        _invalid_metadata(name, "schema")

    source = value["source"]
    if not isinstance(source, dict):
        _invalid_metadata(name, "source")
    if set(source) != SOURCE_FIELDS:
        _invalid_metadata(name, "source fields")
    for field in ("before", "after"):
        fingerprint = source[field]
        if not isinstance(fingerprint, str) or SHA256.fullmatch(fingerprint) is None:
            _invalid_metadata(name, f"source.{field}")
    commit = source["commit"]
    if not isinstance(commit, str) or GIT_COMMIT.fullmatch(commit) is None:
        _invalid_metadata(name, "source.commit")
    if type(source["dirty"]) is not bool:
        _invalid_metadata(name, "source.dirty")

    methodology = value["methodology"]
    if not isinstance(methodology, str) or SHA256.fullmatch(methodology) is None:
        _invalid_metadata(name, "methodology")
    for field in ("target", "requested_bench"):
        field_value = value[field]
        if not isinstance(field_value, str) or not field_value:
            _invalid_metadata(name, field)

    forwarded_args = value["forwarded_args"]
    if not isinstance(forwarded_args, list) or any(
        not isinstance(argument, str) for argument in forwarded_args
    ):
        _invalid_metadata(name, "forwarded_args")

    registrations = value["registrations"]
    if (
        not isinstance(registrations, list)
        or not registrations
        or any(not isinstance(registration, str) for registration in registrations)
        or registrations != sorted(set(registrations))
        or any(
            len(registration.split("/")) != 2
            or any(part in {"", ".", ".."} for part in registration.split("/"))
            for registration in registrations
        )
    ):
        _invalid_metadata(name, "registrations")

    cpu = value["cpu_identity"]
    if not isinstance(cpu, dict) or set(cpu) != CPU_IDENTITY_METADATA_FIELDS:
        _invalid_metadata(name, "cpu_identity")
    fields = cpu["fields"]
    if (
        cpu["algorithm"] != "sha256_canonical_cpu_fields_v1"
        or not isinstance(fields, dict)
        or not fields
        or any(
            not isinstance(field, str)
            or not field
            or field not in CPU_IDENTITY_FIELDS | {"Processor"}
            or not isinstance(field_value, str)
            for field, field_value in fields.items()
        )
        or not isinstance(cpu["sha256"], str)
        or SHA256.fullmatch(cpu["sha256"]) is None
    ):
        _invalid_metadata(name, "cpu_identity")
    canonical_cpu = json.dumps(fields, separators=(",", ":"), sort_keys=True).encode()
    if cpu["sha256"] != hashlib.sha256(canonical_cpu).hexdigest():
        _invalid_metadata(name, "cpu_identity")

    core = value["core"]
    if type(core) is not int or core < 0:
        _invalid_metadata(name, "core")
    for field in ("os", "rustc_vv"):
        field_value = value[field]
        if not isinstance(field_value, str) or not field_value:
            _invalid_metadata(name, field)

    measured_at = value["measured_at_utc"]
    if not isinstance(measured_at, str) or UTC_TIMESTAMP.fullmatch(measured_at) is None:
        _invalid_metadata(name, "measured_at_utc")
    try:
        measured_datetime = datetime.fromisoformat(measured_at)
    except ValueError:
        _invalid_metadata(name, "measured_at_utc")
    if measured_datetime.utcoffset() != timezone.utc.utcoffset(measured_datetime):
        _invalid_metadata(name, "measured_at_utc")


def verify(
    root: Path,
    target: str,
    baseline: str,
    compare: str | None = None,
    *,
    require_clean: bool = False,
) -> list[dict[str, object]]:
    names = [baseline] if compare is None else [baseline, compare]
    values = [read_metadata(root, target, name) for name in names]
    for name, value in zip(names, values, strict=True):
        _validate_metadata(value, name)
    for name, value in zip(names, values, strict=True):
        if value["target"] != target:
            raise MetadataError(f"invalid metadata target for {name!r}")
        source = value["source"]
        if source["before"] != source["after"]:
            raise MetadataError(f"source changed during baseline {name!r}")
        try:
            registrations = target_registrations(root, target, name)
        except MetadataError as error:
            raise MetadataError(
                f"Criterion registrations differ for {name!r}: {error}"
            ) from error
        if registrations != value["registrations"]:
            raise MetadataError(f"Criterion registrations differ for {name!r}")
        if require_clean and source["dirty"]:
            raise MetadataError("final evidence requires clean source metadata")
    for field in COMPATIBILITY_FIELDS:
        reference = values[0][field]
        incompatible = any(value[field] != reference for value in values[1:])
        if incompatible:
            raise MetadataError(f"incompatible benchmark metadata field: {field}")
    return values


def command_output(argv: list[str], cwd: Path | None = None) -> str | None:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return completed.stdout.strip()


def cpu_identity() -> dict[str, object]:
    fields: dict[str, str] = {}
    raw = command_output(["lscpu", "--json"])
    if raw is not None:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
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
                if field in CPU_IDENTITY_FIELDS:
                    fields[field] = data.strip()
    if not fields:
        fields = {
            "Architecture": platform.machine().lower(),
            "Processor": platform.processor(),
        }
    canonical = json.dumps(fields, separators=(",", ":"), sort_keys=True).encode()
    return {
        "algorithm": "sha256_canonical_cpu_fields_v1",
        "fields": fields,
        "sha256": hashlib.sha256(canonical).hexdigest(),
    }


def publish(
    *,
    root: Path,
    source_root: Path,
    target: str,
    baseline: str,
    source_before: str,
    core: int,
    requested_bench: str,
    forwarded_args: list[str],
) -> dict[str, object]:
    sidecar = metadata_path(root, target, baseline)
    source_after = source_fingerprint(source_root)
    if source_before != source_after:
        raise MetadataError("source changed during benchmark run")

    git_commit = command_output(["git", "rev-parse", "HEAD"], source_root)
    git_status = command_output(["git", "status", "--porcelain"], source_root)
    value: dict[str, object] = {
        "schema": SCHEMA_VERSION,
        "source": {
            "before": source_before,
            "after": source_after,
            "commit": git_commit,
            "dirty": None if git_status is None else bool(git_status),
        },
        "methodology": methodology_fingerprint(source_root, target),
        "target": target,
        "requested_bench": requested_bench,
        "forwarded_args": list(forwarded_args),
        "registrations": target_registrations(root, target, baseline),
        "cpu_identity": cpu_identity(),
        "core": core,
        "os": platform.platform(),
        "rustc_vv": command_output(["rustc", "-Vv"]),
        "measured_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    write_json_atomic(sidecar, value)
    return value


def _add_baseline_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--baseline", required=True)


def _normalize_forwarded_arg_options(argv: list[str]) -> list[str]:
    normalized: list[str] = []
    index = 0
    while index < len(argv):
        if argv[index] == "--forwarded-arg" and index + 1 < len(argv):
            normalized.append(f"--forwarded-arg={argv[index + 1]}")
            index += 2
        else:
            normalized.append(argv[index])
            index += 1
    return normalized


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    fingerprint = subparsers.add_parser("fingerprint")
    fingerprint.add_argument("--source-root", type=Path, required=True)
    begin_parser = subparsers.add_parser("begin")
    _add_baseline_arguments(begin_parser)
    publish_parser = subparsers.add_parser("publish")
    _add_baseline_arguments(publish_parser)
    publish_parser.add_argument("--source-before", required=True)
    publish_parser.add_argument("--core", type=int, required=True)
    publish_parser.add_argument("--requested-bench", required=True)
    publish_parser.add_argument("--forwarded-arg", action="append", default=[])
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--root", type=Path, required=True)
    verify_parser.add_argument("--target", required=True)
    verify_parser.add_argument("--baseline", required=True)
    verify_parser.add_argument("--compare")
    verify_parser.add_argument("--require-clean", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    raw_argv = sys.argv[1:] if argv is None else argv
    args = _build_parser().parse_args(_normalize_forwarded_arg_options(raw_argv))
    if args.command == "fingerprint":
        print(source_fingerprint(args.source_root))
    elif args.command == "begin":
        print(begin(args.root, args.source_root, args.target, args.baseline))
    elif args.command == "publish":
        value = publish(
            root=args.root,
            source_root=args.source_root,
            target=args.target,
            baseline=args.baseline,
            source_before=args.source_before,
            core=args.core,
            requested_bench=args.requested_bench,
            forwarded_args=args.forwarded_arg,
        )
        print(json.dumps(value, sort_keys=True))
    elif args.command == "verify":
        values = verify(
            args.root,
            args.target,
            args.baseline,
            args.compare,
            require_clean=args.require_clean,
        )
        print(json.dumps(values, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
