#!/usr/bin/env python3
"""Bind a downloaded cache-gate Actions artifact to its exact ZIP members."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import zipfile


DIGEST_RE = re.compile(r"sha256:([0-9a-f]{64})\Z")


class EvidenceError(ValueError):
    """Artifact cannot serve as cache-gate evidence."""


def canonical_member(name: str) -> PurePosixPath:
    if not name or name.startswith("/"):
        raise EvidenceError("unsafe ZIP member name")
    raw_parts = name.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise EvidenceError("unsafe ZIP member name")
    path = PurePosixPath(*raw_parts)
    if path.is_absolute():
        raise EvidenceError("unsafe ZIP member name")
    return path


def is_regular(info: zipfile.ZipInfo) -> bool:
    unix_mode = info.external_attr >> 16
    file_type = stat.S_IFMT(unix_mode)
    return not info.is_dir() and file_type in {0, stat.S_IFREG}


def _expected_basename(name: str) -> PurePosixPath:
    path = canonical_member(name)
    if len(path.parts) != 1 or str(path) != name:
        raise EvidenceError("expected ZIP member name must be a basename")
    return path


def _hash_zip(path: Path, expected_digest: str) -> None:
    match = DIGEST_RE.fullmatch(expected_digest)
    if match is None:
        raise EvidenceError("invalid API digest")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != match.group(1):
        raise EvidenceError("API digest mismatch")


def _validated_members(
    archive: zipfile.ZipFile, expected: set[PurePosixPath]
) -> dict[PurePosixPath, zipfile.ZipInfo]:
    members: dict[PurePosixPath, zipfile.ZipInfo] = {}
    for info in archive.infolist():
        path = canonical_member(info.filename)
        if path in members:
            raise EvidenceError("duplicate ZIP member")
        if info.flag_bits & 0x1:
            raise EvidenceError("encrypted ZIP member")
        if not is_regular(info):
            raise EvidenceError("non-regular ZIP member")
        members[path] = info
    if set(members) != expected:
        raise EvidenceError("ZIP members do not match expected names")
    return members


def _write_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(descriptor, "wb") as destination, archive.open(info) as source:
        shutil.copyfileobj(source, destination)


def verify_artifact(
    zip_path: Path,
    expected_digest: str,
    tar_name: str,
    checksum_name: str,
    output: Path,
) -> tuple[Path, Path]:
    """Verify and safely materialize exact evidence members from an Actions ZIP."""
    tar_path = _expected_basename(tar_name)
    checksum_path = _expected_basename(checksum_name)
    if tar_path == checksum_path:
        raise EvidenceError("expected ZIP member names must differ")
    _hash_zip(zip_path, expected_digest)
    with zipfile.ZipFile(zip_path) as archive:
        members = _validated_members(archive, {tar_path, checksum_path})
        try:
            os.mkdir(output, mode=0o700)
        except FileExistsError as error:
            raise EvidenceError("output directory already exists") from error
        os.chmod(output, 0o700)
        tar_output = output / tar_path.name
        checksum_output = output / checksum_path.name
        _write_member(archive, members[tar_path], tar_output)
        _write_member(archive, members[checksum_path], checksum_output)
    return tar_output, checksum_output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", required=True, type=Path)
    parser.add_argument("--api-digest", required=True)
    parser.add_argument("--tar-name", required=True)
    parser.add_argument("--checksum-name", required=True)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        tar_path, checksum_path = verify_artifact(
            arguments.zip,
            arguments.api_digest,
            arguments.tar_name,
            arguments.checksum_name,
            arguments.output,
        )
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        parser.exit(1, f"error: {error}\n")
    print(tar_path)
    print(checksum_path)


if __name__ == "__main__":
    main()
