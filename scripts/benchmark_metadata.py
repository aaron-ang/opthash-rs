import argparse
import hashlib
import re
from pathlib import Path


SCHEMA_VERSION = 1
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
RESERVED_NAMES = {"new", "base", "change", "report"}
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    fingerprint = subparsers.add_parser("fingerprint")
    fingerprint.add_argument("--source-root", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    print(source_fingerprint(args.source_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
