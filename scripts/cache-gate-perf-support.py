#!/usr/bin/env python3
"""Checked shared-state helpers for cache-gate perf collection."""

from __future__ import annotations

import argparse
import csv
import fcntl
import json
import os
import re
from io import StringIO
from pathlib import Path
from typing import Mapping


SAFE_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _parse_cpu_list(value: str) -> set[int]:
    selected: set[int] = set()
    for part in value.strip().split(","):
        if not part:
            continue
        if "-" in part:
            left, right = map(int, part.split("-", 1))
            selected.update(range(left, right + 1))
        else:
            selected.add(int(part))
    return selected


def select_core_pmu(
    architecture: str, core: int, devices: Mapping[str, str | None]
) -> str:
    if architecture == "x86_64":
        if "cpu" not in devices:
            raise ValueError("x86 core PMU 'cpu' is unavailable")
        return "cpu"
    if architecture != "aarch64":
        raise ValueError(f"unsupported architecture: {architecture}")
    arm_devices = {
        name: cpus for name, cpus in devices.items() if name.startswith("armv8_pmuv3")
    }
    matching = sorted(
        name
        for name, cpus in arm_devices.items()
        if cpus is not None and core in _parse_cpu_list(cpus)
    )
    if len(matching) == 1:
        return matching[0]
    homogeneous = sorted(name for name, cpus in arm_devices.items() if cpus is None)
    if not matching and len(homogeneous) == 1:
        return homogeneous[0]
    raise ValueError(
        f"expected one ARM PMU for core {core}, found {matching or homogeneous}"
    )


def validate_perf_csv(text: str, expected_pmu: str) -> str:
    observed: set[str] = set()
    counted = 0
    for row in csv.reader(StringIO(text)):
        if (
            len(row) < 3
            or not row[0]
            or row[0].startswith("#")
            or row[0].startswith("<")
        ):
            continue
        event = row[2].strip()
        counted += 1
        observed.add(event.split("/", 1)[0] if "/" in event else expected_pmu)
    if counted != 4 or observed != {expected_pmu}:
        raise ValueError(
            f"PMU mismatch: expected {expected_pmu}, "
            f"observed {sorted(observed)}, counted rows {counted}"
        )
    return expected_pmu


def verify_process_executable(pid: int, expected: Path) -> bool:
    actual = Path(f"/proc/{pid}/exe").resolve(strict=True)
    expected = expected.resolve(strict=True)
    if actual != expected:
        raise ValueError(
            f"profile executable mismatch for PID {pid}: {actual} != {expected}"
        )
    return True


def _change_owner(path: Path, uid: int, gid: int) -> None:
    os.chown(path, uid, gid)


def _path_owner(path: Path) -> tuple[int, int]:
    metadata = path.stat()
    return metadata.st_uid, metadata.st_gid


def prepare_manifest_staging(
    manifest_root: Path, build_root: Path, owner_uid: int, owner_gid: int
) -> None:
    paths = (
        manifest_root,
        manifest_root / "link-maps",
        manifest_root / "symbols",
        build_root,
    )
    for path in paths:
        path.mkdir(mode=0o755, parents=True, exist_ok=True)
        if os.geteuid() == 0:
            _change_owner(path, owner_uid, owner_gid)
        if _path_owner(path) != (owner_uid, owner_gid):
            raise ValueError(f"staging owner mismatch: {path}")


def bind_contract(root: Path, record: dict[str, object]) -> Path:
    key = str(record["campaign_key"])
    if not root.is_absolute():
        raise ValueError("campaign contract root must be absolute")
    if not SAFE_KEY.fullmatch(key) or key in {".", ".."}:
        raise ValueError(f"unsafe campaign key: {key}")
    campaign = root / key
    campaign.mkdir(mode=0o755, parents=True, exist_ok=True)
    lock_path = campaign / ".contract.lock"
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        contract = (
            campaign
            / str(record["operation"])
            / f"repetition-{record['repetition']}.json"
        )
        contract.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if contract.exists():
            existing = json.loads(contract.read_text(encoding="utf-8"))
            if existing != record:
                raise ValueError(
                    f"campaign contract mismatch: existing {existing!r}, requested {record!r}"
                )
            return contract
        temporary = contract.with_name(f".{contract.name}.{os.getpid()}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(record, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, contract)
            directory = os.open(contract.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)
        return contract


def _devices(root: Path) -> dict[str, str | None]:
    devices: dict[str, str | None] = {}
    for device in root.glob("*"):
        cpus = device / "cpus"
        value = cpus.read_text(encoding="utf-8").strip() if cpus.exists() else ""
        devices[device.name] = value or None
    return devices


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    contract = subparsers.add_parser("bind-contract")
    for name in ("root", "key", "operation", "repetition", "iterations", "core", "pmu"):
        contract.add_argument(f"--{name}", required=True)
    pmu = subparsers.add_parser("select-pmu")
    pmu.add_argument("--architecture", required=True)
    pmu.add_argument("--core", required=True, type=int)
    pmu.add_argument("--devices-root", default="/sys/bus/event_source/devices")
    verify = subparsers.add_parser("verify-executable")
    verify.add_argument("--pid", required=True, type=int)
    verify.add_argument("--expected", required=True)
    csv_parser = subparsers.add_parser("validate-csv")
    csv_parser.add_argument("--path", required=True)
    csv_parser.add_argument("--expected-pmu", required=True)
    staging = subparsers.add_parser("prepare-staging")
    staging.add_argument("--manifest-root", required=True)
    staging.add_argument("--build-root", required=True)
    staging.add_argument("--uid", required=True, type=int)
    staging.add_argument("--gid", required=True, type=int)
    arguments = parser.parse_args()
    try:
        if arguments.command == "bind-contract":
            record = {
                "campaign_key": arguments.key,
                "operation": arguments.operation,
                "repetition": int(arguments.repetition),
                "iterations": int(arguments.iterations),
                "core": int(arguments.core),
                "pmu": arguments.pmu,
            }
            print(bind_contract(Path(arguments.root), record))
        elif arguments.command == "select-pmu":
            print(
                select_core_pmu(
                    arguments.architecture,
                    arguments.core,
                    _devices(Path(arguments.devices_root)),
                )
            )
        elif arguments.command == "verify-executable":
            verify_process_executable(arguments.pid, Path(arguments.expected))
        elif arguments.command == "validate-csv":
            print(
                validate_perf_csv(
                    Path(arguments.path).read_text(encoding="utf-8"),
                    arguments.expected_pmu,
                )
            )
        else:
            prepare_manifest_staging(
                Path(arguments.manifest_root),
                Path(arguments.build_root),
                arguments.uid,
                arguments.gid,
            )
    except (OSError, ValueError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
