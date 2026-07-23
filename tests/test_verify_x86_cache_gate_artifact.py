import hashlib
import importlib.util
import os
import stat
import struct
import zipfile
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "verify-x86-cache-gate-artifact.py"
SPEC = importlib.util.spec_from_file_location("verify_x86_cache_gate_artifact", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
artifact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact)


TAR_NAME = "cache-gate-7-2.tar"
CHECKSUM_NAME = "cache-gate-7-2.tar.sha256"


def make_zip(path: Path, entries: list[tuple[str | zipfile.ZipInfo, bytes]]) -> str:
    with zipfile.ZipFile(path, "w") as archive:
        for name, body in entries:
            archive.writestr(name, body)
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def bind(path: Path, digest: str, output: Path) -> tuple[Path, Path]:
    return artifact.verify_artifact(
        path,
        digest,
        TAR_NAME,
        CHECKSUM_NAME,
        output,
    )


def test_binds_exact_regular_members_with_permission_only_unix_modes(tmp_path):
    archive = tmp_path / "artifact.zip"
    digest = make_zip(
        archive, [(TAR_NAME, b"tar body"), (CHECKSUM_NAME, b"checksum body")]
    )

    extracted_tar, extracted_checksum = bind(archive, digest, tmp_path / "output")

    assert extracted_tar == tmp_path / "output" / TAR_NAME
    assert extracted_checksum == tmp_path / "output" / CHECKSUM_NAME
    assert extracted_tar.read_bytes() == b"tar body"
    assert extracted_checksum.read_bytes() == b"checksum body"
    assert stat.S_IMODE((tmp_path / "output").stat().st_mode) == 0o700
    assert stat.S_IMODE(extracted_tar.stat().st_mode) == 0o600
    assert stat.S_IMODE(extracted_checksum.stat().st_mode) == 0o600


def test_rejects_wrong_api_digest(tmp_path):
    archive = tmp_path / "artifact.zip"
    make_zip(archive, [(TAR_NAME, b"tar"), (CHECKSUM_NAME, b"checksum")])

    with pytest.raises(artifact.EvidenceError, match="API digest"):
        bind(archive, "sha256:" + "0" * 64, tmp_path / "output")


@pytest.mark.parametrize(
    "entries",
    [
        [(TAR_NAME, b"tar"), (CHECKSUM_NAME, b"checksum"), ("extra", b"extra")],
        [(TAR_NAME, b"tar")],
    ],
    ids=["extra-member", "missing-member"],
)
def test_rejects_member_set_other_than_exact_expected_names(tmp_path, entries):
    archive = tmp_path / "artifact.zip"
    digest = make_zip(archive, entries)

    with pytest.raises(artifact.EvidenceError, match="ZIP members"):
        bind(archive, digest, tmp_path / "output")


@pytest.mark.parametrize(
    "unsafe_name",
    [
        "/cache-gate-7-2.tar",
        "../cache-gate-7-2.tar",
        "a/../cache-gate-7-2.tar",
        "a/./cache-gate-7-2.tar",
        "a//cache-gate-7-2.tar",
    ],
    ids=["absolute", "parent", "embedded-parent", "dot", "empty-component"],
)
def test_rejects_unsafe_raw_member_paths(tmp_path, unsafe_name):
    archive = tmp_path / "artifact.zip"
    digest = make_zip(archive, [(unsafe_name, b"tar"), (CHECKSUM_NAME, b"checksum")])

    with pytest.raises(artifact.EvidenceError, match="unsafe ZIP member name"):
        bind(archive, digest, tmp_path / "output")


def test_rejects_duplicate_canonical_member_name(tmp_path):
    archive = tmp_path / "artifact.zip"
    with pytest.warns(UserWarning, match="Duplicate name"):
        digest = make_zip(
            archive,
            [
                (TAR_NAME, b"first"),
                (TAR_NAME, b"second"),
                (CHECKSUM_NAME, b"checksum"),
            ],
        )

    with pytest.raises(artifact.EvidenceError, match="duplicate ZIP member"):
        bind(archive, digest, tmp_path / "output")


def test_rejects_directory_member(tmp_path):
    archive = tmp_path / "artifact.zip"
    directory = zipfile.ZipInfo(TAR_NAME)
    directory.external_attr = (stat.S_IFDIR | 0o755) << 16
    digest = make_zip(archive, [(directory, b""), (CHECKSUM_NAME, b"checksum")])

    with pytest.raises(artifact.EvidenceError, match="non-regular ZIP member"):
        bind(archive, digest, tmp_path / "output")


def test_rejects_unix_symlink_member(tmp_path):
    archive = tmp_path / "artifact.zip"
    link = zipfile.ZipInfo(TAR_NAME)
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    digest = make_zip(archive, [(link, b"target"), (CHECKSUM_NAME, b"checksum")])

    with pytest.raises(artifact.EvidenceError, match="non-regular ZIP member"):
        bind(archive, digest, tmp_path / "output")


def test_rejects_encrypted_member(tmp_path):
    archive = tmp_path / "artifact.zip"
    make_zip(archive, [(TAR_NAME, b"tar"), (CHECKSUM_NAME, b"checksum")])
    data = bytearray(archive.read_bytes())
    local_header = data.index(b"PK\x03\x04")
    central_header = data.index(b"PK\x01\x02")
    for offset in (local_header + 6, central_header + 8):
        flags = struct.unpack_from("<H", data, offset)[0]
        struct.pack_into("<H", data, offset, flags | 0x1)
    archive.write_bytes(data)
    digest = "sha256:" + hashlib.sha256(data).hexdigest()

    with pytest.raises(artifact.EvidenceError, match="encrypted ZIP member"):
        bind(archive, digest, tmp_path / "output")


def test_opens_zip_once_with_no_follow_and_checks_regular_file(tmp_path, monkeypatch):
    archive = tmp_path / "artifact.zip"
    digest = make_zip(archive, [(TAR_NAME, b"tar"), (CHECKSUM_NAME, b"checksum")])
    opened_archive_fds: list[int] = []
    real_open = artifact.os.open
    real_fstat = artifact.os.fstat

    def track_open(path, flags, mode=0o777):
        descriptor = real_open(path, flags, mode)
        if Path(path) == archive:
            opened_archive_fds.append(descriptor)
            assert flags & os.O_NOFOLLOW
        return descriptor

    def non_regular_archive(descriptor):
        if descriptor in opened_archive_fds:
            return os.stat_result((stat.S_IFIFO,) + (0,) * 9)
        return real_fstat(descriptor)

    monkeypatch.setattr(artifact.os, "open", track_open)
    monkeypatch.setattr(artifact.os, "fstat", non_regular_archive)

    with pytest.raises(artifact.EvidenceError, match="regular file"):
        bind(archive, digest, tmp_path / "output")

    assert len(opened_archive_fds) == 1


def test_preserves_zip_read_error_when_member_body_is_corrupt(tmp_path):
    archive = tmp_path / "artifact.zip"
    make_zip(archive, [(TAR_NAME, b"tar"), (CHECKSUM_NAME, b"checksum")])
    with zipfile.ZipFile(archive) as source:
        info = source.getinfo(TAR_NAME)
        body_offset = info.header_offset + 30 + len(info.filename) + len(info.extra)
    data = bytearray(archive.read_bytes())
    data[body_offset] ^= 0xFF
    archive.write_bytes(data)
    digest = "sha256:" + hashlib.sha256(data).hexdigest()

    with pytest.raises(zipfile.BadZipFile, match="Bad CRC-32"):
        bind(archive, digest, tmp_path / "output")
