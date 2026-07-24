#!/usr/bin/env python3
"""Create deterministic, no-follow native cache-gate evidence archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
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
    parent_fd: int
    name: str
    directory_fd: int
    archive_path: str
    kind: str
    mode: int
    size: int = 0
    sha256: str = ""
    target: str = ""
    device: int = 0
    inode: int = 0
    links: int = 1
    raw_mode: int = 0
    metadata_size: int = 0
    modified_ns: int = 0
    changed_ns: int = 0
    children: tuple[str, ...] = ()


class ProvenanceAuthority(NamedTuple):
    hardlinks: dict[str, str]
    descriptor: int
    identity: tuple[int, int, int, int, int, int, int]
    data: bytes
    sha256: str


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _identity(item: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
        item.st_nlink,
    )


def _open_regular(
    parent_fd: int,
    name: str,
    expected: os.stat_result | tuple[int, int, int, int, int, int, int],
    display_path: Path,
) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as error:
        raise EvidenceError(
            f"cannot open staged regular file without following: {display_path}"
        ) from error
    expected_identity = (
        _identity(expected) if isinstance(expected, os.stat_result) else expected
    )
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or _identity(metadata) != expected_identity:
        os.close(descriptor)
        raise EvidenceError(
            f"staged regular file changed while packaging: {display_path}"
        )
    return descriptor


def _digest_file_at(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
    display_path: Path,
) -> tuple[str, int]:
    descriptor = _open_regular(parent_fd, name, expected, display_path)
    try:
        before = os.fstat(descriptor)
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
    if _identity(before) != _identity(after) or _identity(before) != _identity(
        expected
    ):
        raise EvidenceError(
            f"staged regular file changed while packaging: {display_path}"
        )
    return digest.hexdigest(), size


def _load_hardlinks(bundle_fd: int, bundle_path: Path) -> ProvenanceAuthority:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open("provenance.json", flags, dir_fd=bundle_fd)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 16 * 1024 * 1024:
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
        if _identity(os.fstat(descriptor)) != _identity(metadata):
            raise EvidenceError("bundle/provenance.json changed while packaging")
        data = b"".join(chunks)

        def reject_duplicates(values: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in values:
                if key in result:
                    raise EvidenceError(f"duplicate provenance key: {key}")
                result[key] = value
            return result

        document = json.loads(data, object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise EvidenceError(
            f"invalid bundle/provenance.json beneath {bundle_path}"
        ) from error
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    try:
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
        return ProvenanceAuthority(
            result,
            descriptor,
            _identity(metadata),
            data,
            hashlib.sha256(data).hexdigest(),
        )
    except BaseException:
        os.close(descriptor)
        raise


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
    root_fd: int,
    root: Path,
    hardlinks: dict[str, str],
    *,
    include_inventory: bool,
) -> tuple[list[StagedEntry], list[int]]:
    root_metadata = os.fstat(root_fd)
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise EvidenceError("bundle is not a real directory")
    entries: list[StagedEntry] = []
    opened_directories: list[int] = []
    allowed_link_paths = set(hardlinks) | set(hardlinks.values())

    def visit(
        directory_fd: int,
        directory: Path,
        relative: PurePosixPath,
        metadata: os.stat_result,
        parent_fd: int,
        name: str,
    ) -> None:
        try:
            child_names = os.listdir(directory_fd)
        except OSError as error:
            raise EvidenceError(
                f"cannot scan staging directory: {directory}"
            ) from error
        child_names = [
            child_name
            for child_name in child_names
            if include_inventory
            or (relative / child_name).as_posix() != "bundle/inventory.json"
        ]
        child_names.sort(
            key=lambda child_name: os.fsencode((relative / child_name).as_posix())
        )
        after_list = os.fstat(directory_fd)
        if _identity(metadata) != _identity(after_list):
            raise EvidenceError(f"staging tree changed while packaging: {directory}")
        entries.append(
            StagedEntry(
                directory,
                parent_fd,
                name,
                directory_fd,
                relative.as_posix(),
                "dir",
                stat.S_IMODE(after_list.st_mode),
                device=after_list.st_dev,
                inode=after_list.st_ino,
                links=after_list.st_nlink,
                raw_mode=after_list.st_mode,
                metadata_size=after_list.st_size,
                modified_ns=after_list.st_mtime_ns,
                changed_ns=after_list.st_ctime_ns,
                children=tuple(child_names),
            )
        )
        for child_name in child_names:
            child_relative = relative / child_name
            archive_path = child_relative.as_posix()
            _validate_archive_path(archive_path)
            path = directory / child_name
            try:
                child_metadata = os.stat(
                    child_name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise EvidenceError(f"cannot stat staged entry: {path}") from error
            mode = stat.S_IMODE(child_metadata.st_mode)
            common = {
                "device": child_metadata.st_dev,
                "inode": child_metadata.st_ino,
                "links": child_metadata.st_nlink,
                "raw_mode": child_metadata.st_mode,
                "metadata_size": child_metadata.st_size,
                "modified_ns": child_metadata.st_mtime_ns,
                "changed_ns": child_metadata.st_ctime_ns,
            }
            if stat.S_ISDIR(child_metadata.st_mode):
                flags = (
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                try:
                    child_fd = os.open(child_name, flags, dir_fd=directory_fd)
                except OSError as error:
                    raise EvidenceError(
                        f"cannot open staged directory without following: {path}"
                    ) from error
                opened_directories.append(child_fd)
                opened_metadata = os.fstat(child_fd)
                if _identity(opened_metadata) != _identity(child_metadata):
                    raise EvidenceError(f"staging tree changed while packaging: {path}")
                visit(
                    child_fd,
                    path,
                    child_relative,
                    opened_metadata,
                    directory_fd,
                    child_name,
                )
            elif stat.S_ISLNK(child_metadata.st_mode):
                try:
                    target = os.readlink(child_name, dir_fd=directory_fd)
                except OSError as error:
                    raise EvidenceError(
                        f"cannot read staged symlink: {path}"
                    ) from error
                after_readlink = os.stat(
                    child_name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                if _identity(after_readlink) != _identity(child_metadata):
                    raise EvidenceError(f"staging tree changed while packaging: {path}")
                if not target or "\x00" in target:
                    raise EvidenceError(
                        f"invalid staged symlink target: {archive_path}"
                    )
                entries.append(
                    StagedEntry(
                        path,
                        directory_fd,
                        child_name,
                        -1,
                        archive_path,
                        "symlink",
                        mode,
                        target=target,
                        **common,
                    )
                )
            elif stat.S_ISREG(child_metadata.st_mode):
                if (
                    child_metadata.st_nlink > 1
                    and archive_path not in allowed_link_paths
                ):
                    raise EvidenceError(f"unlisted hardlink: {archive_path}")
                digest, size = _digest_file_at(
                    directory_fd,
                    child_name,
                    child_metadata,
                    path,
                )
                kind = "hardlink" if archive_path in hardlinks else "file"
                entries.append(
                    StagedEntry(
                        path,
                        directory_fd,
                        child_name,
                        -1,
                        archive_path,
                        kind,
                        mode,
                        size,
                        digest,
                        hardlinks.get(archive_path, ""),
                        **common,
                    )
                )
            else:
                raise EvidenceError(f"unsupported staged entry type: {archive_path}")

    try:
        visit(
            root_fd,
            root,
            PurePosixPath("bundle"),
            root_metadata,
            -1,
            "",
        )
        entries.sort(key=lambda entry: entry.archive_path.encode())
        return entries, opened_directories
    except BaseException:
        for descriptor in reversed(opened_directories):
            os.close(descriptor)
        raise


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


def _atomic_write_at(
    directory_fd: int,
    name: str,
    data: bytes,
    mode: int = 0o644,
) -> None:
    temporary = ""
    descriptor = -1
    try:
        for _attempt in range(128):
            temporary = f".{name}.{secrets.token_hex(16)}"
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    mode,
                    dir_fd=directory_fd,
                )
                break
            except FileExistsError:
                continue
        if descriptor < 0:
            raise EvidenceError("cannot allocate private inventory temporary")
        os.fchmod(descriptor, mode)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise EvidenceError("cannot write inventory")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary = ""
        os.fsync(directory_fd)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        raise


def _same_entry(left: StagedEntry, right: StagedEntry) -> bool:
    return (
        left.archive_path,
        left.kind,
        left.mode,
        left.size,
        left.sha256,
        left.target,
        left.device,
        left.inode,
        left.links,
    ) == (
        right.archive_path,
        right.kind,
        right.mode,
        right.size,
        right.sha256,
        right.target,
        right.device,
        right.inode,
        right.links,
    )


def _entry_identity(entry: StagedEntry) -> tuple[int, int, int, int, int, int, int]:
    return (
        entry.device,
        entry.inode,
        entry.raw_mode,
        entry.metadata_size,
        entry.modified_ns,
        entry.changed_ns,
        entry.links,
    )


def _verify_provenance_authority(
    authority: ProvenanceAuthority,
    entries: list[StagedEntry],
) -> None:
    try:
        before = os.fstat(authority.descriptor)
        os.lseek(authority.descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = len(authority.data)
        while remaining:
            chunk = os.read(authority.descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        extra = os.read(authority.descriptor, 1)
        after = os.fstat(authority.descriptor)
    except OSError as error:
        raise EvidenceError("bundle/provenance.json changed while packaging") from error
    if (
        remaining
        or extra
        or b"".join(chunks) != authority.data
        or _identity(before) != authority.identity
        or _identity(after) != authority.identity
    ):
        raise EvidenceError("bundle/provenance.json changed while packaging")

    matches = [
        entry for entry in entries if entry.archive_path == "bundle/provenance.json"
    ]
    if len(matches) != 1:
        raise EvidenceError("bundle/provenance.json changed while packaging")
    entry = matches[0]
    if (
        entry.kind != "file"
        or _entry_identity(entry) != authority.identity
        or entry.size != len(authority.data)
        or entry.sha256 != authority.sha256
    ):
        raise EvidenceError("bundle/provenance.json changed while packaging")


class _HashingReader:
    def __init__(self, descriptor: int):
        self.descriptor = descriptor
        self.digest = hashlib.sha256()
        self.size = 0

    def read(self, size: int = -1) -> bytes:
        amount = 1024 * 1024 if size is None or size < 0 else size
        chunk = os.read(self.descriptor, amount)
        self.digest.update(chunk)
        self.size += len(chunk)
        return chunk


def _add_regular(
    archive: tarfile.TarFile, info: tarfile.TarInfo, entry: StagedEntry
) -> None:
    descriptor = _open_regular(
        entry.parent_fd,
        entry.name,
        _entry_identity(entry),
        entry.path,
    )
    try:
        before = os.fstat(descriptor)
        reader = _HashingReader(descriptor)
        archive.addfile(info, reader)
        after = os.fstat(descriptor)
        if (
            _identity(before) != _entry_identity(entry)
            or _identity(after) != _entry_identity(entry)
            or reader.size != entry.size
            or reader.digest.hexdigest() != entry.sha256
        ):
            raise EvidenceError(
                f"archive bytes differ from inventoried file: {entry.archive_path}"
            )
    finally:
        os.close(descriptor)


def _verify_snapshot(entries: list[StagedEntry]) -> None:
    for entry in entries:
        if entry.kind == "dir":
            metadata = os.fstat(entry.directory_fd)
            try:
                names = os.listdir(entry.directory_fd)
            except OSError as error:
                raise EvidenceError(
                    f"cannot rescan staged directory: {entry.path}"
                ) from error
            names.sort(
                key=lambda name: os.fsencode(
                    (PurePosixPath(entry.archive_path) / name).as_posix()
                )
            )
            if (
                _identity(metadata) != _entry_identity(entry)
                or tuple(names) != entry.children
            ):
                raise EvidenceError("staging tree changed while packaging")
            continue
        try:
            metadata = os.stat(
                entry.name,
                dir_fd=entry.parent_fd,
                follow_symlinks=False,
            )
        except OSError as error:
            raise EvidenceError("staging tree changed while packaging") from error
        if _identity(metadata) != _entry_identity(entry):
            raise EvidenceError("staging tree changed while packaging")
        if entry.kind == "symlink":
            try:
                target = os.readlink(entry.name, dir_fd=entry.parent_fd)
            except OSError as error:
                raise EvidenceError("staging tree changed while packaging") from error
            if target != entry.target:
                raise EvidenceError("staging tree changed while packaging")


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
        _verify_snapshot(entries)
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
    directory_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    staging_fd = -1
    bundle_fd = -1
    provenance_authority: ProvenanceAuthority | None = None
    before_directories: list[int] = []
    after_directories: list[int] = []
    try:
        staging_fd = os.open(staging_root, directory_flags)
    except OSError as error:
        raise EvidenceError("staging root is not a real directory") from error
    try:
        root_stat = os.fstat(staging_fd)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise EvidenceError("staging root is not a real directory")
        try:
            top_names = os.listdir(staging_fd)
        except OSError as error:
            raise EvidenceError("cannot scan staging root") from error
        if top_names != ["bundle"]:
            raise EvidenceError(
                "staging root must contain exactly one top-level bundle directory"
            )
        try:
            bundle_stat = os.stat(
                "bundle",
                dir_fd=staging_fd,
                follow_symlinks=False,
            )
            bundle_fd = os.open("bundle", directory_flags, dir_fd=staging_fd)
        except OSError as error:
            raise EvidenceError("bundle is not a real directory") from error
        if not stat.S_ISDIR(bundle_stat.st_mode) or _identity(
            os.fstat(bundle_fd)
        ) != _identity(bundle_stat):
            raise EvidenceError("bundle is not a real directory")

        bundle = staging_root / "bundle"
        provenance_authority = _load_hardlinks(bundle_fd, bundle)
        hardlinks = provenance_authority.hardlinks
        before, before_directories = _walk(
            bundle_fd,
            bundle,
            hardlinks,
            include_inventory=False,
        )
        _verify_provenance_authority(provenance_authority, before)
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
        for descriptor in reversed(before_directories):
            os.close(descriptor)
        before_directories = []

        _atomic_write_at(
            bundle_fd,
            "inventory.json",
            _json_bytes(_inventory(before)),
        )
        after, after_directories = _walk(
            bundle_fd,
            bundle,
            hardlinks,
            include_inventory=True,
        )
        _verify_provenance_authority(provenance_authority, after)
        after_without_inventory = [
            entry for entry in after if entry.archive_path != "bundle/inventory.json"
        ]
        if len(before) != len(after_without_inventory) or any(
            not _same_entry(left, right)
            for left, right in zip(
                before,
                after_without_inventory,
                strict=True,
            )
        ):
            raise EvidenceError("staging tree changed while packaging")
        digest = _write_archive(archive, after)
        _verify_provenance_authority(provenance_authority, after)
        _atomic_write(checksum, f"{digest}  {archive.name}\n".encode())
        return digest
    finally:
        for descriptor in reversed(after_directories):
            os.close(descriptor)
        for descriptor in reversed(before_directories):
            os.close(descriptor)
        if provenance_authority is not None:
            os.close(provenance_authority.descriptor)
        if bundle_fd >= 0:
            os.close(bundle_fd)
        os.close(staging_fd)


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
