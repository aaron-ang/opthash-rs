#!/usr/bin/env python3
"""Create deterministic, no-follow native cache-gate evidence archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import NamedTuple


class EvidenceError(RuntimeError):
    """Staging tree cannot safely serve as cache-gate evidence."""


class StagedEntry(NamedTuple):
    path: Path
    archive_path: str
    kind: str
    mode: int
    size: int = 0
    sha256: str = ""
    target: str = ""
    device: int = 0
    inode: int = 0
    links: int = 1


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _digest_file(path: Path, expected: os.stat_result) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvidenceError(
            f"cannot open staged regular file without following: {path}"
        ) from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceError(f"staged file changed type: {path}")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    def identity(item: os.stat_result) -> tuple[int, int, int, int, int, int]:
        return (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )

    if identity(before) != identity(after) or identity(before) != identity(expected):
        raise EvidenceError(f"staged regular file changed while packaging: {path}")
    return digest.hexdigest(), size


def _load_hardlinks(provenance_path: Path) -> dict[str, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(provenance_path, flags)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size > 16 * 1024 * 1024
            ):
                raise EvidenceError("invalid bundle/provenance.json")
            chunks: list[bytes] = []
            remaining = metadata.st_size
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            if remaining:
                raise EvidenceError("invalid bundle/provenance.json")
        finally:
            os.close(descriptor)

        def reject_duplicates(values: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in values:
                if key in result:
                    raise EvidenceError(f"duplicate provenance key: {key}")
                result[key] = value
            return result

        document = json.loads(b"".join(chunks), object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError("invalid bundle/provenance.json") from error
    if not isinstance(document, dict):
        raise EvidenceError("invalid bundle/provenance.json")
    raw_records = document.get("hardlinks", [])
    if not isinstance(raw_records, list):
        raise EvidenceError("invalid provenance hardlinks")
    result: dict[str, str] = {}
    for index, record in enumerate(raw_records):
        if not isinstance(record, dict) or set(record) != {"path", "target"}:
            raise EvidenceError(f"invalid provenance hardlink record {index}")
        path = record["path"]
        target = record["target"]
        if not isinstance(path, str) or not isinstance(target, str):
            raise EvidenceError(f"invalid provenance hardlink record {index}")
        _validate_archive_path(path)
        _validate_archive_path(target)
        if path in result:
            raise EvidenceError("duplicate provenance hardlink path")
        result[path] = target
    return result


def _validate_archive_path(raw: str) -> PurePosixPath:
    if (
        not raw
        or raw.startswith("/")
        or any(part in {"", ".", ".."} for part in raw.split("/"))
    ):
        raise EvidenceError(f"unsafe staged path: {raw!r}")
    path = PurePosixPath(raw)
    if not path.is_relative_to(PurePosixPath("bundle")):
        raise EvidenceError(f"staged path is outside bundle: {raw!r}")
    return path


def _walk(
    root: Path, hardlinks: dict[str, str], *, include_inventory: bool
) -> list[StagedEntry]:
    root_metadata = root.stat(follow_symlinks=False)
    if not stat.S_ISDIR(root_metadata.st_mode) or root.is_symlink():
        raise EvidenceError("bundle is not a real directory")
    entries: list[StagedEntry] = [
        StagedEntry(
            root,
            "bundle",
            "dir",
            stat.S_IMODE(root_metadata.st_mode),
            device=root_metadata.st_dev,
            inode=root_metadata.st_ino,
        )
    ]
    allowed_link_paths = set(hardlinks) | set(hardlinks.values())

    def visit(directory: Path, relative: PurePosixPath) -> None:
        try:
            children = list(os.scandir(directory))
        except OSError as error:
            raise EvidenceError(
                f"cannot scan staging directory: {directory}"
            ) from error
        children.sort(key=lambda child: os.fsencode((relative / child.name).as_posix()))
        for child in children:
            child_relative = relative / child.name
            archive_path = child_relative.as_posix()
            _validate_archive_path(archive_path)
            if archive_path == "bundle/inventory.json" and not include_inventory:
                continue
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as error:
                raise EvidenceError(
                    f"cannot stat staged entry: {child.path}"
                ) from error
            mode = stat.S_IMODE(metadata.st_mode)
            path = Path(child.path)
            if stat.S_ISDIR(metadata.st_mode):
                entries.append(
                    StagedEntry(
                        path,
                        archive_path,
                        "dir",
                        mode,
                        device=metadata.st_dev,
                        inode=metadata.st_ino,
                    )
                )
                visit(path, child_relative)
            elif stat.S_ISLNK(metadata.st_mode):
                try:
                    target = os.readlink(path)
                except OSError as error:
                    raise EvidenceError(
                        f"cannot read staged symlink: {path}"
                    ) from error
                if not target or "\x00" in target:
                    raise EvidenceError(
                        f"invalid staged symlink target: {archive_path}"
                    )
                entries.append(
                    StagedEntry(
                        path,
                        archive_path,
                        "symlink",
                        mode,
                        target=target,
                        device=metadata.st_dev,
                        inode=metadata.st_ino,
                    )
                )
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink > 1 and archive_path not in allowed_link_paths:
                    raise EvidenceError(f"unlisted hardlink: {archive_path}")
                digest, size = _digest_file(path, metadata)
                kind = "hardlink" if archive_path in hardlinks else "file"
                entries.append(
                    StagedEntry(
                        path,
                        archive_path,
                        kind,
                        mode,
                        size,
                        digest,
                        hardlinks.get(archive_path, ""),
                        metadata.st_dev,
                        metadata.st_ino,
                        metadata.st_nlink,
                    )
                )
            else:
                raise EvidenceError(f"unsupported staged entry type: {archive_path}")

    visit(root, PurePosixPath("bundle"))
    entries.sort(key=lambda entry: entry.archive_path.encode())
    return entries


def _inventory(entries: list[StagedEntry]) -> dict[str, object]:
    records: list[dict[str, object]] = []
    for entry in entries:
        record: dict[str, object] = {
            "path": entry.archive_path,
            "type": entry.kind,
            "mode": entry.mode,
        }
        if entry.kind == "file":
            record.update(size=entry.size, sha256=entry.sha256)
        elif entry.kind in {"symlink", "hardlink"}:
            record["target"] = entry.target
        records.append(record)
    return {"version": 1, "entries": records}


def _atomic_write(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def _same_entry(left: StagedEntry, right: StagedEntry) -> bool:
    return left[1:] == right[1:]


def _add_regular(
    archive: tarfile.TarFile, info: tarfile.TarInfo, entry: StagedEntry
) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(entry.path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError(f"staged file changed type: {entry.archive_path}")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            archive.addfile(info, source)
    finally:
        os.close(descriptor)


def _write_archive(path: Path, entries: list[StagedEntry]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with tarfile.open(temporary, mode="w:", format=tarfile.PAX_FORMAT) as archive:
            for entry in entries:
                info = tarfile.TarInfo(entry.archive_path)
                info.mode = entry.mode
                info.mtime = info.uid = info.gid = 0
                info.uname = info.gname = ""
                if entry.kind == "dir":
                    info.type = tarfile.DIRTYPE
                    archive.addfile(info)
                elif entry.kind == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = entry.target
                    archive.addfile(info)
                elif entry.kind == "hardlink":
                    info.type = tarfile.LNKTYPE
                    info.linkname = entry.target
                    archive.addfile(info)
                else:
                    info.type = tarfile.REGTYPE
                    info.size = entry.size
                    _add_regular(archive, info, entry)
        archive_fd = os.open(temporary, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        digest = hashlib.sha256()
        try:
            while True:
                chunk = os.read(archive_fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            os.fsync(archive_fd)
        finally:
            os.close(archive_fd)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return digest.hexdigest()
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def package_evidence(staging_root: Path, archive: Path, checksum: Path) -> str:
    staging_root = Path(staging_root)
    archive = Path(archive)
    checksum = Path(checksum)
    try:
        root_stat = staging_root.stat(follow_symlinks=False)
    except OSError as error:
        raise EvidenceError("staging root is not a real directory") from error
    if not stat.S_ISDIR(root_stat.st_mode) or staging_root.is_symlink():
        raise EvidenceError("staging root is not a real directory")
    top = list(os.scandir(staging_root))
    if (
        len(top) != 1
        or top[0].name != "bundle"
        or not top[0].is_dir(follow_symlinks=False)
    ):
        raise EvidenceError(
            "staging root must contain exactly one top-level bundle directory"
        )
    bundle = staging_root / "bundle"
    provenance = bundle / "provenance.json"
    hardlinks = _load_hardlinks(provenance)
    before = _walk(bundle, hardlinks, include_inventory=False)
    by_path = {entry.archive_path: entry for entry in before}
    for path, target in hardlinks.items():
        source_entry = by_path.get(path)
        target_entry = by_path.get(target)
        if source_entry is None or target_entry is None:
            raise EvidenceError("provenance hardlink member is missing")
        if target_entry.kind not in {"file", "hardlink"}:
            raise EvidenceError("provenance hardlink target is not regular")
        if (source_entry.device, source_entry.inode) != (
            target_entry.device,
            target_entry.inode,
        ):
            raise EvidenceError("provenance hardlink inode mismatch")
    _atomic_write(bundle / "inventory.json", _json_bytes(_inventory(before)))
    after = _walk(bundle, hardlinks, include_inventory=True)
    after_without_inventory = [
        entry for entry in after if entry.archive_path != "bundle/inventory.json"
    ]
    if len(before) != len(after_without_inventory) or any(
        not _same_entry(left, right)
        for left, right in zip(before, after_without_inventory, strict=True)
    ):
        raise EvidenceError("staging tree changed while packaging")
    digest = _write_archive(archive, after)
    _atomic_write(checksum, f"{digest}  {archive.name}\n".encode())
    return digest


def _absolute(value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise EvidenceError(f"{label} must be absolute")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staging-root", required=True)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--checksum", required=True)
    arguments = parser.parse_args(argv)
    try:
        package_evidence(
            _absolute(arguments.staging_root, "staging root"),
            _absolute(arguments.archive, "archive"),
            _absolute(arguments.checksum, "checksum"),
        )
    except EvidenceError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
