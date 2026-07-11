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


def begin(root: Path, source_root: Path, target: str, baseline: str) -> str:
    metadata_path(root, target, baseline).unlink(missing_ok=True)
    for directory in root.glob(f"*/*/{baseline}"):
        if directory.is_dir():
            shutil.rmtree(directory)
    return source_fingerprint(source_root)


def measured_registrations(root: Path, baseline: str) -> list[str]:
    registrations = []
    for estimates in root.glob(f"*/*/{baseline}/estimates.json"):
        registrations.append("/".join(estimates.relative_to(root).parts[:2]))
    if not registrations:
        raise MetadataError(f"no Criterion registrations for baseline {baseline!r}")
    return sorted(registrations)


def write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp-{os.getpid()}")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


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
        "registrations": measured_registrations(root, baseline),
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
