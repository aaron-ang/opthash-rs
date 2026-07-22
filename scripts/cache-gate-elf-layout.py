#!/usr/bin/env python3
"""Validate and compare cache-gate ELF reservations without mutating binaries."""

from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
import hashlib
import json
import os
import re
import select
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable


KERNELS = {
    "elastic_cache_gate_insert_kernel": {
        "target": "elastic",
        "input": ".text.opthash.cache_gate.elastic.insert",
        "output": ".opthash.cache_gate.elastic.insert",
        "reservation_start": "__opthash_cache_gate_elastic_insert_reservation_start",
        "body_end": "__opthash_cache_gate_elastic_insert_body_end",
        "reservation_end": "__opthash_cache_gate_elastic_insert_reservation_end",
    },
    "elastic_cache_gate_get_kernel": {
        "target": "elastic",
        "input": ".text.opthash.cache_gate.elastic.get",
        "output": ".opthash.cache_gate.elastic.get",
        "reservation_start": "__opthash_cache_gate_elastic_get_reservation_start",
        "body_end": "__opthash_cache_gate_elastic_get_body_end",
        "reservation_end": "__opthash_cache_gate_elastic_get_reservation_end",
    },
    "funnel_cache_gate_insert_kernel": {
        "target": "funnel",
        "input": ".text.opthash.cache_gate.funnel.insert",
        "output": ".opthash.cache_gate.funnel.insert",
        "reservation_start": "__opthash_cache_gate_funnel_insert_reservation_start",
        "body_end": "__opthash_cache_gate_funnel_insert_body_end",
        "reservation_end": "__opthash_cache_gate_funnel_insert_reservation_end",
    },
    "funnel_cache_gate_get_kernel": {
        "target": "funnel",
        "input": ".text.opthash.cache_gate.funnel.get",
        "output": ".opthash.cache_gate.funnel.get",
        "reservation_start": "__opthash_cache_gate_funnel_get_reservation_start",
        "body_end": "__opthash_cache_gate_funnel_get_body_end",
        "reservation_end": "__opthash_cache_gate_funnel_get_reservation_end",
    },
    "elastic_profile_insert_kernel": {
        "target": "profile",
        "input": ".text.opthash.cache_gate.profile.elastic.insert",
        "output": ".opthash.cache_gate.profile.elastic.insert",
        "reservation_start": "__opthash_cache_gate_profile_elastic_insert_reservation_start",
        "body_end": "__opthash_cache_gate_profile_elastic_insert_body_end",
        "reservation_end": "__opthash_cache_gate_profile_elastic_insert_reservation_end",
    },
    "elastic_profile_get_kernel": {
        "target": "profile",
        "input": ".text.opthash.cache_gate.profile.elastic.get",
        "output": ".opthash.cache_gate.profile.elastic.get",
        "reservation_start": "__opthash_cache_gate_profile_elastic_get_reservation_start",
        "body_end": "__opthash_cache_gate_profile_elastic_get_body_end",
        "reservation_end": "__opthash_cache_gate_profile_elastic_get_reservation_end",
    },
    "funnel_profile_insert_kernel": {
        "target": "profile",
        "input": ".text.opthash.cache_gate.profile.funnel.insert",
        "output": ".opthash.cache_gate.profile.funnel.insert",
        "reservation_start": "__opthash_cache_gate_profile_funnel_insert_reservation_start",
        "body_end": "__opthash_cache_gate_profile_funnel_insert_body_end",
        "reservation_end": "__opthash_cache_gate_profile_funnel_insert_reservation_end",
    },
    "funnel_profile_get_kernel": {
        "target": "profile",
        "input": ".text.opthash.cache_gate.profile.funnel.get",
        "output": ".opthash.cache_gate.profile.funnel.get",
        "reservation_start": "__opthash_cache_gate_profile_funnel_get_reservation_start",
        "body_end": "__opthash_cache_gate_profile_funnel_get_body_end",
        "reservation_end": "__opthash_cache_gate_profile_funnel_get_reservation_end",
    },
}
TARGET_KERNELS = {
    target: tuple(name for name, spec in KERNELS.items() if spec["target"] == target)
    for target in ("elastic", "funnel", "profile")
}
EXECUTABLE_TARGETS = {
    "elastic_cache_gate": "elastic",
    "funnel_cache_gate": "funnel",
    "cache_gate_profile": "profile",
}
SUPPLIED_MANIFEST_KEYS = {
    "architecture",
    "build",
    "build_proof",
    "commit",
    "control",
    "elf_layout",
    "empty_diff_assertion",
    "executables",
    "layout_adversary",
    "linker_capability",
    "manifest_instance",
    "mode",
    "runner_root",
    "symbols",
    "tools",
    "tree",
    "variant",
}
AUTHENTICATED_TOOL_NAMES = {
    "elf_layout",
    "extractor",
    "launcher",
    "link_wrapper",
    "perf_launcher",
    "perf_support",
    "snapshot",
}
BODY_FIELDS = (
    "body_end",
    "body_size",
    "raw_sha256",
    "normalized_sha256",
    "direct_calls",
    "indirect_calls",
    "frame_bytes",
    "spills",
)
PLACEMENT_FIELDS = (
    "input_section",
    "output_section",
    "reservation_start",
    "reservation_end",
    "reservation_size",
    "page_offset",
    "max_page_remainder",
    "sh_addralign",
)
STRUCTURAL_FIELDS = (
    "input_start",
    "input_end",
    "input_size",
    "function_start",
    "function_end",
    "function_size",
    "function_section_index",
    "function_section_name",
)


class LayoutError(ValueError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*args: str) -> str:
    completed = subprocess.run(args, text=True, capture_output=True, check=False)
    if completed.returncode:
        raise LayoutError(
            f"command failed ({completed.returncode}): {' '.join(args)}\n"
            f"{completed.stderr.strip()}"
        )
    return completed.stdout


def checked_absolute_file(record: dict[str, Any], label: str) -> Path:
    path = Path(record.get("absolute_path", ""))
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise LayoutError(f"invalid {label} path: {path}")
    resolved = path.resolve(strict=True)
    if path != resolved or record.get("absolute_path") != str(resolved):
        raise LayoutError(f"{label} path is not canonical: {path}")
    if digest(path) != record.get("sha256"):
        raise LayoutError(f"{label} hash mismatch: {path}")
    return path


def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_directory_with_identity_chain(
    directory: Path,
) -> tuple[int, tuple[tuple[int, int], ...]]:
    _require(directory.is_absolute(), f"directory path must be absolute: {directory}")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    identities = [(os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)]
    try:
        for component in directory.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            metadata = os.fstat(descriptor)
            identities.append((metadata.st_dev, metadata.st_ino))
        return descriptor, tuple(identities)
    except Exception:
        os.close(descriptor)
        raise


def _open_directory_without_symlinks(directory: Path) -> int:
    descriptor, _ = _open_directory_with_identity_chain(directory)
    return descriptor


def _verify_directory_identity_chain(
    directory: Path,
    expected: tuple[tuple[int, int], ...],
    label: str,
) -> None:
    descriptor, observed = _open_directory_with_identity_chain(directory)
    try:
        _require(observed == expected, f"{label} directory ancestry changed")
    finally:
        os.close(descriptor)


def _directory_identity_fingerprint(
    identities: tuple[tuple[int, int], ...],
) -> str:
    return hashlib.sha256(
        "".join(f"{device}:{inode}\n" for device, inode in identities).encode()
    ).hexdigest()


def _file_identity_token(
    ancestry: tuple[tuple[int, int], ...], metadata: os.stat_result, content: bytes
) -> str:
    return ":".join(
        (
            _directory_identity_fingerprint(ancestry),
            str(metadata.st_dev),
            str(metadata.st_ino),
            str(metadata.st_mode),
            str(metadata.st_size),
            str(metadata.st_mtime_ns),
            str(metadata.st_ctime_ns),
            hashlib.sha256(content).hexdigest(),
        )
    )


def _read_descriptor(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _open_directory_chain_held(
    directory: Path,
) -> tuple[list[int], tuple[tuple[int, int], ...]]:
    _require(directory.is_absolute(), f"directory path must be absolute: {directory}")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptors = [os.open("/", flags)]
    try:
        for component in directory.parts[1:]:
            descriptors.append(os.open(component, flags, dir_fd=descriptors[-1]))
        identities = tuple(
            (metadata.st_dev, metadata.st_ino)
            for metadata in (os.fstat(descriptor) for descriptor in descriptors)
        )
        return descriptors, identities
    except Exception:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


class _CapabilityGuard:
    _IN_MODIFY = 0x00000002
    _IN_ATTRIB = 0x00000004
    _IN_CLOSE_WRITE = 0x00000008
    _IN_Q_OVERFLOW = 0x00004000
    _IN_UNMOUNT = 0x00002000
    _IN_MOVE_SELF = 0x00000800
    _IN_DELETE_SELF = 0x00000400
    _IN_IGNORED = 0x00008000

    def __init__(self, source: Path, destination: Path) -> None:
        self.source = source
        self.destination = destination
        self.source_directories: list[int] = []
        self.destination_directories: list[int] = []
        self.source_ancestry: tuple[tuple[int, int], ...] = ()
        self.destination_ancestry: tuple[tuple[int, int], ...] = ()
        self.source_descriptor: int | None = None
        self.staged_descriptor: int | None = None
        self.manifest_descriptor: int | None = None
        self.inotify_descriptor: int | None = None
        self.source_identity: tuple[int, int, int, int, int, int] | None = None
        self.staged_identity: tuple[int, int, int, int, int, int] | None = None
        self.staged_inode: tuple[int, int] | None = None
        self.manifest_identity: tuple[int, int, int, int, int, int] | None = None
        self.manifest_path: Path | None = None
        self.manifest_bytes = b""
        self.manifest_publish_identity = ""
        self.source_bytes = b""
        self.payload: dict[str, Any] = {}
        self.result = ""
        self.identity = ""
        self.poisoned = False
        self.committed = False

    @property
    def source_parent(self) -> int:
        return self.source_directories[-1]

    @property
    def destination_parent(self) -> int:
        return self.destination_directories[-1]

    @classmethod
    def stage(
        cls,
        source: Path,
        destination: Path,
        validator: Callable[[Path, dict[str, Any]], str],
    ) -> _CapabilityGuard:
        guard = cls(source, destination)
        try:
            guard._stage(validator)
            return guard
        except Exception:
            guard.close(remove_stage=True)
            raise

    def _stage(self, validator: Callable[[Path, dict[str, Any]], str]) -> None:
        _require(self.source.is_absolute(), "capability input must be absolute")
        _require(
            self.destination.is_absolute(), "staged capability path must be absolute"
        )
        _require(
            self.source == self.source.resolve(strict=True),
            "capability input path is not canonical",
        )
        _require(
            self.destination.parent == self.destination.parent.resolve(strict=True),
            "staged capability parent is not canonical",
        )
        self.source_directories, self.source_ancestry = _open_directory_chain_held(
            self.source.parent
        )
        (
            self.destination_directories,
            self.destination_ancestry,
        ) = _open_directory_chain_held(self.destination.parent)
        self.source_descriptor = os.open(
            self.source.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=self.source_parent,
        )
        source_stat = os.fstat(self.source_descriptor)
        _require(
            stat.S_ISREG(source_stat.st_mode) and source_stat.st_nlink == 1,
            "capability input is not a private regular file",
        )
        self.source_identity = _stat_identity(source_stat)
        _require(
            _stat_identity(
                os.stat(
                    self.source.name, dir_fd=self.source_parent, follow_symlinks=False
                )
            )
            == self.source_identity,
            "capability input path changed before staging",
        )
        self.source_bytes = _read_descriptor(self.source_descriptor)
        self.payload = json.loads(self.source_bytes)
        self.staged_descriptor = os.open(
            self.destination.name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=self.destination_parent,
        )
        view = memoryview(self.source_bytes)
        while view:
            written = os.write(self.staged_descriptor, view)
            _require(written > 0, "short staged capability write")
            view = view[written:]
        os.fsync(self.staged_descriptor)
        os.lseek(self.staged_descriptor, 0, os.SEEK_SET)
        _require(
            _read_descriptor(self.staged_descriptor) == self.source_bytes,
            "staged capability bytes differ from input",
        )
        staged_stat = os.fstat(self.staged_descriptor)
        _require(
            stat.S_ISREG(staged_stat.st_mode) and staged_stat.st_nlink == 1,
            "staged capability is not a private regular file",
        )
        self.staged_inode = (staged_stat.st_dev, staged_stat.st_ino)
        os.fchmod(self.staged_descriptor, 0o444)
        os.fsync(self.staged_descriptor)
        os.fsync(self.destination_parent)
        self.staged_identity = _stat_identity(os.fstat(self.staged_descriptor))
        self._install_watches()
        self.checkpoint()
        self.result = validator(self.destination, self.payload)
        self.checkpoint()
        self.identity = ":".join(
            (
                _directory_identity_fingerprint(self.destination_ancestry),
                str(self.staged_identity[0]),
                str(self.staged_identity[1]),
                str(self.staged_identity[3]),
                hashlib.sha256(self.source_bytes).hexdigest(),
            )
        )

    def _install_watches(self) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        init = libc.inotify_init1
        init.argtypes = (ctypes.c_int,)
        init.restype = ctypes.c_int
        add = libc.inotify_add_watch
        add.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32)
        add.restype = ctypes.c_int
        descriptor = init(os.O_CLOEXEC | os.O_NONBLOCK)
        if descriptor < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        self.inotify_descriptor = descriptor
        directory_mask = (
            self._IN_MOVE_SELF
            | self._IN_DELETE_SELF
            | self._IN_UNMOUNT
            | self._IN_IGNORED
        )
        file_mask = (
            directory_mask | self._IN_MODIFY | self._IN_ATTRIB | self._IN_CLOSE_WRITE
        )
        watched = [
            *(descriptor for descriptor in self.source_directories),
            *(descriptor for descriptor in self.destination_directories),
        ]
        watched.extend((self.source_descriptor, self.staged_descriptor))
        for held in watched:
            assert held is not None
            mask = (
                file_mask
                if held in (self.source_descriptor, self.staged_descriptor)
                else directory_mask
            )
            if add(descriptor, f"/proc/self/fd/{held}".encode(), mask) < 0:
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error))

    def _watch_manifest(self) -> None:
        assert self.inotify_descriptor is not None
        assert self.manifest_descriptor is not None
        libc = ctypes.CDLL(None, use_errno=True)
        add = libc.inotify_add_watch
        add.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32)
        add.restype = ctypes.c_int
        mask = (
            self._IN_MOVE_SELF
            | self._IN_DELETE_SELF
            | self._IN_UNMOUNT
            | self._IN_IGNORED
            | self._IN_MODIFY
            | self._IN_ATTRIB
            | self._IN_CLOSE_WRITE
        )
        if (
            add(
                self.inotify_descriptor,
                f"/proc/self/fd/{self.manifest_descriptor}".encode(),
                mask,
            )
            < 0
        ):
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))

    def _drain_events(self) -> None:
        if self.inotify_descriptor is None:
            return
        while True:
            try:
                events = os.read(self.inotify_descriptor, 1024 * 1024)
            except BlockingIOError:
                return
            if not events:
                return
            self.poisoned = True

    def checkpoint(self) -> None:
        self._drain_events()
        _require(
            not self.poisoned,
            (
                "guarded manifest lifecycle event"
                if self.manifest_descriptor is not None
                else "capability guardian observed an inode lifecycle event"
            ),
        )
        assert self.source_descriptor is not None
        assert self.staged_descriptor is not None
        assert self.source_identity is not None
        assert self.staged_identity is not None
        _require(
            _stat_identity(os.fstat(self.source_descriptor)) == self.source_identity
            and _stat_identity(
                os.stat(
                    self.source.name, dir_fd=self.source_parent, follow_symlinks=False
                )
            )
            == self.source_identity,
            "capability input changed while guarded",
        )
        os.lseek(self.source_descriptor, 0, os.SEEK_SET)
        _require(
            _read_descriptor(self.source_descriptor) == self.source_bytes,
            "capability input bytes changed while guarded",
        )
        _require(
            _stat_identity(os.fstat(self.staged_descriptor)) == self.staged_identity
            and _stat_identity(
                os.stat(
                    self.destination.name,
                    dir_fd=self.destination_parent,
                    follow_symlinks=False,
                )
            )
            == self.staged_identity,
            "staged capability changed while guarded",
        )
        os.lseek(self.staged_descriptor, 0, os.SEEK_SET)
        _require(
            _read_descriptor(self.staged_descriptor) == self.source_bytes,
            "staged capability bytes changed while guarded",
        )
        if self.manifest_descriptor is not None:
            assert self.manifest_identity is not None
            assert self.manifest_path is not None
            _require(
                _stat_identity(os.fstat(self.manifest_descriptor))
                == self.manifest_identity
                == _stat_identity(
                    os.stat(
                        self.manifest_path.name,
                        dir_fd=self.destination_parent,
                        follow_symlinks=False,
                    )
                ),
                "guarded manifest changed while guarded",
            )
            os.lseek(self.manifest_descriptor, 0, os.SEEK_SET)
            _require(
                _read_descriptor(self.manifest_descriptor) == self.manifest_bytes,
                "guarded manifest bytes changed while guarded",
            )
        _verify_directory_identity_chain(
            self.source.parent, self.source_ancestry, "capability input"
        )
        _verify_directory_identity_chain(
            self.destination.parent,
            self.destination_ancestry,
            "staged capability",
        )
        self._drain_events()
        _require(
            not self.poisoned,
            (
                "guarded manifest lifecycle event"
                if self.manifest_descriptor is not None
                else "capability guardian observed an inode lifecycle event"
            ),
        )

    def finalize(
        self,
        manifest_path: Path,
        manifest_validator: Callable[[dict[str, Any], Path, bytes], None] | None = None,
    ) -> None:
        self.checkpoint()
        _require(
            manifest_path.is_absolute()
            and manifest_path.parent == self.destination.parent
            and manifest_path.name.startswith(".manifest.")
            and manifest_path.name.endswith(".pending.json"),
            "guarded manifest pending path is invalid",
        )
        _require(
            not (self.destination.parent / "manifest.json").exists(),
            "final manifest path exists before guardian commit",
        )
        self.manifest_path = manifest_path
        self.manifest_descriptor = os.open(
            manifest_path.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=self.destination_parent,
        )
        before = os.fstat(self.manifest_descriptor)
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and before.st_mode & 0o777 == 0o444,
            "guarded manifest is not a private read-only regular file",
        )
        self.manifest_identity = _stat_identity(before)
        self.manifest_bytes = _read_descriptor(self.manifest_descriptor)
        self._watch_manifest()
        self.checkpoint()
        manifest = json.loads(self.manifest_bytes)
        if manifest_validator is not None:
            manifest_validator(manifest, manifest_path, self.source_bytes)
        self.checkpoint()
        embedded = manifest.get("linker_capability", {})
        _require(
            isinstance(embedded, dict)
            and embedded.get("copy")
            == {
                "absolute_path": str(self.destination),
                "sha256": hashlib.sha256(self.source_bytes).hexdigest(),
            }
            and {key: value for key, value in embedded.items() if key != "copy"}
            == self.payload,
            "guarded manifest capability differs from held bytes",
        )
        _require(
            not (self.destination.parent / "manifest.json").exists(),
            "final manifest path appeared during guardian validation",
        )
        self.checkpoint()
        assert self.manifest_identity is not None
        self.manifest_publish_identity = _file_identity_token(
            self.destination_ancestry,
            os.fstat(self.manifest_descriptor),
            self.manifest_bytes,
        )
        self.committed = True

    def close(self, *, remove_stage: bool) -> None:
        checkpoint_error: Exception | None = None
        if self.committed:
            try:
                self.checkpoint()
            except Exception as error:  # preserve cleanup before surfacing final race
                checkpoint_error = error
        if remove_stage and not self.committed and self.destination_directories:
            try:
                current = os.stat(
                    self.destination.name,
                    dir_fd=self.destination_parent,
                    follow_symlinks=False,
                )
                if (
                    self.staged_inode is not None
                    and (
                        current.st_dev,
                        current.st_ino,
                    )
                    == self.staged_inode
                ):
                    os.unlink(self.destination.name, dir_fd=self.destination_parent)
                    os.fsync(self.destination_parent)
            except OSError:
                pass
        if self.inotify_descriptor is not None:
            os.close(self.inotify_descriptor)
            self.inotify_descriptor = None
        for descriptor_name in (
            "manifest_descriptor",
            "staged_descriptor",
            "source_descriptor",
        ):
            descriptor = getattr(self, descriptor_name)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, descriptor_name, None)
        for descriptors in (
            self.destination_directories,
            self.source_directories,
        ):
            for descriptor in reversed(descriptors):
                os.close(descriptor)
            descriptors.clear()
        if checkpoint_error is not None:
            raise checkpoint_error


def _guarded_file_identity(path: Path) -> str:
    _require(path.is_absolute(), "guarded file path must be absolute")
    parent, ancestry = _open_directory_with_identity_chain(path.parent)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        metadata = os.fstat(descriptor)
        content = _read_descriptor(descriptor)
        _require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_nlink == 1
            and metadata.st_mode & 0o777 == 0o444
            and _stat_identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
            == _stat_identity(metadata),
            "guarded file is not one exact private read-only inode",
        )
        return _file_identity_token(ancestry, metadata, content)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _link_descriptor_noreplace(
    source_descriptor: int, destination_parent: int, destination_name: str
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    linkat = libc.linkat
    linkat.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
    )
    linkat.restype = ctypes.c_int
    if (
        linkat(
            -100,
            f"/proc/self/fd/{source_descriptor}".encode(),
            destination_parent,
            destination_name.encode(),
            0x400,
        )
        != 0
    ):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _write_private_pending(output: Path, content: bytes) -> None:
    _require(
        output.is_absolute()
        and output.name.startswith(".manifest.")
        and output.name.endswith(".pending.json"),
        "private pending manifest path is invalid",
    )
    parent, ancestry = _open_directory_with_identity_chain(output.parent)
    descriptor: int | None = None
    temporary_name: str | None = None
    metadata: os.stat_result | None = None
    linked = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        for _ in range(128):
            candidate = f".manifest.{os.urandom(16).hex()}.tmp"
            try:
                descriptor = os.open(candidate, flags, 0o600, dir_fd=parent)
            except FileExistsError:
                continue
            temporary_name = candidate
            metadata = os.fstat(descriptor)
            break
        _require(descriptor is not None, "cannot allocate private manifest temporary")
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            _require(written > 0, "cannot write private pending manifest")
            remaining = remaining[written:]
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        assert temporary_name is not None
        temporary_stat = os.stat(temporary_name, dir_fd=parent, follow_symlinks=False)
        _require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_nlink == 1
            and metadata.st_mode & 0o777 == 0o444
            and _stat_identity(temporary_stat) == _stat_identity(metadata),
            "private manifest temporary differs from held inode",
        )
        _verify_directory_identity_chain(
            output.parent, ancestry, "private pending manifest"
        )
        _link_descriptor_noreplace(descriptor, parent, output.name)
        linked = True
        linked_metadata = os.fstat(descriptor)
        published = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        _require(
            _stat_identity(published) == _stat_identity(linked_metadata)
            and published.st_nlink == 2,
            "private pending manifest differs from held inode",
        )
        _verify_directory_identity_chain(
            output.parent, ancestry, "private pending manifest"
        )
        current_temporary = os.stat(
            temporary_name, dir_fd=parent, follow_symlinks=False
        )
        _require(
            _stat_identity(current_temporary) == _stat_identity(linked_metadata),
            "private manifest temporary name changed during publication",
        )
        os.unlink(temporary_name, dir_fd=parent)
        temporary_name = None
        os.fsync(parent)
        final_metadata = os.fstat(descriptor)
        final = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        _require(
            _stat_identity(final) == _stat_identity(final_metadata)
            and final.st_nlink == 1
            and final.st_mode & 0o777 == 0o444,
            "private pending manifest final inode is invalid",
        )
        _verify_directory_identity_chain(
            output.parent, ancestry, "private pending manifest"
        )
        linked = False
    except Exception:
        if linked and metadata is not None:
            try:
                current = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == (
                    metadata.st_dev,
                    metadata.st_ino,
                ):
                    os.unlink(output.name, dir_fd=parent)
                    os.fsync(parent)
            except OSError:
                pass
        raise
    finally:
        if temporary_name is not None and metadata is not None:
            try:
                current = os.stat(temporary_name, dir_fd=parent, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == (
                    metadata.st_dev,
                    metadata.st_ino,
                ):
                    os.unlink(temporary_name, dir_fd=parent)
                    os.fsync(parent)
            except OSError:
                pass
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _publish_guarded_manifest(
    pending: Path,
    output: Path,
    expected_identity: str,
    held_fd_path: Path | None = None,
) -> None:
    _require(
        pending.is_absolute()
        and output.is_absolute()
        and pending.parent == output.parent
        and pending.name.startswith(".manifest.")
        and pending.name.endswith(".pending.json")
        and output.name == "manifest.json",
        "guarded manifest publication paths are invalid",
    )
    parent, ancestry = _open_directory_with_identity_chain(pending.parent)
    held: int | None = None
    linked = False
    try:
        source = held_fd_path if held_fd_path is not None else pending
        held = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
        metadata = os.fstat(held)
        content = _read_descriptor(held)
        pending_stat = os.stat(pending.name, dir_fd=parent, follow_symlinks=False)
        _require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_nlink == 1
            and metadata.st_mode & 0o777 == 0o444
            and _stat_identity(pending_stat) == _stat_identity(metadata)
            and _file_identity_token(ancestry, metadata, content) == expected_identity,
            "pending manifest differs from guardian publish identity",
        )
        _verify_directory_identity_chain(
            pending.parent, ancestry, "guarded manifest publication"
        )
        _link_descriptor_noreplace(held, parent, output.name)
        linked = True
        published = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        _require(
            (published.st_dev, published.st_ino) == (metadata.st_dev, metadata.st_ino),
            "published manifest differs from held guardian inode",
        )
        current_pending = os.stat(pending.name, dir_fd=parent, follow_symlinks=False)
        _require(
            (current_pending.st_dev, current_pending.st_ino)
            == (metadata.st_dev, metadata.st_ino),
            "pending manifest name changed during publication",
        )
        os.unlink(pending.name, dir_fd=parent)
        os.fsync(parent)
        final = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        _require(
            (final.st_dev, final.st_ino) == (metadata.st_dev, metadata.st_ino)
            and final.st_nlink == 1
            and final.st_mode & 0o777 == 0o444,
            "published manifest final inode is invalid",
        )
        _verify_directory_identity_chain(
            pending.parent, ancestry, "guarded manifest publication"
        )
        linked = False
    except Exception:
        if linked:
            try:
                current = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
                if held is not None:
                    held_stat = os.fstat(held)
                    if (current.st_dev, current.st_ino) == (
                        held_stat.st_dev,
                        held_stat.st_ino,
                    ):
                        os.unlink(output.name, dir_fd=parent)
                        os.fsync(parent)
            except OSError:
                pass
        raise
    finally:
        if held is not None:
            os.close(held)
        os.close(parent)


def _stage_capability_once(
    source: Path,
    destination: Path,
    validator: Callable[[Path, dict[str, Any]], str],
) -> tuple[str, str, str]:
    guard = _CapabilityGuard.stage(source, destination, validator)
    try:
        return (
            guard.result,
            guard.identity,
            base64.b64encode(guard.source_bytes).decode("ascii"),
        )
    finally:
        guard.close(remove_stage=False)


def _read_verified_staged_capability(path: Path, expected_identity: str) -> bytes:
    _require(path.is_absolute(), "staged capability path must be absolute")
    _require(
        path == path.resolve(strict=True), "staged capability path is not canonical"
    )
    parent, parent_ancestry = _open_directory_with_identity_chain(path.parent)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        before = os.fstat(descriptor)
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and before.st_mode & 0o777 == 0o444,
            "staged capability is not a read-only regular file",
        )
        content = _read_descriptor(descriptor)
        after = os.fstat(descriptor)
        path_stat = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        actual_identity = ":".join(
            (
                _directory_identity_fingerprint(parent_ancestry),
                str(after.st_dev),
                str(after.st_ino),
                str(after.st_size),
                hashlib.sha256(content).hexdigest(),
            )
        )
        _require(
            _stat_identity(before) == _stat_identity(after) == _stat_identity(path_stat)
            and actual_identity == expected_identity,
            "staged capability inode or hash changed",
        )
        _verify_directory_identity_chain(
            path.parent, parent_ancestry, "staged capability"
        )
        return content
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def verify_staged_capability(path: Path, expected_identity: str) -> None:
    _read_verified_staged_capability(path, expected_identity)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise LayoutError(message)


def validate_layout_record(layout: dict[str, Any], target: str) -> None:
    expected = set(TARGET_KERNELS[target])
    kernels = layout.get("kernels", {})
    _require(
        set(kernels) == expected,
        f"{target}: exact kernel set must be {sorted(expected)}, got {sorted(kernels)}",
    )
    _require(layout.get("target") == target, f"{target}: target mismatch")
    _require(
        layout.get("link_map_flavor") in {"gnu", "lld"},
        f"{target}: unsupported link-map flavor",
    )
    _require(layout.get("elf_type") == "ET_DYN", f"{target}: ELF must be PIE ET_DYN")
    _require(
        layout.get("program_headers_have_rwx") is False,
        f"{target}: program header is RWX",
    )
    max_page = layout.get("max_page_size")
    _require(
        isinstance(max_page, int) and max_page > 0, f"{target}: invalid MAXPAGESIZE"
    )
    veneer_names = {
        item.get("name")
        for item in layout.get("veneer_thunk_inventory", [])
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    veneer_marker = re.compile(r"(?:veneer|thunk)", re.IGNORECASE)

    ranges: list[tuple[int, int, str]] = []
    for name in TARGET_KERNELS[target]:
        kernel = kernels[name]
        start = kernel.get("reservation_start")
        body_end = kernel.get("body_end")
        end = kernel.get("reservation_end")
        if all(isinstance(value, int) for value in (start, end)):
            ranges.append((start, end, name))
    for left, right in zip(sorted(ranges), sorted(ranges)[1:], strict=False):
        _require(right[0] >= left[1], f"reservation overlap: {left[2]} and {right[2]}")

    for name in TARGET_KERNELS[target]:
        spec = KERNELS[name]
        kernel = kernels[name]
        prefix = f"{target}/{name}"
        _require(
            kernel.get("function_symbol_count") == 1,
            f"{prefix}: function_symbol_count must be 1",
        )
        _require(
            kernel.get("input_section_count") == 1,
            f"{prefix}: input_section_count must be 1",
        )
        _require(
            kernel.get("output_section_count") == 1,
            f"{prefix}: output_section_count must be 1",
        )
        _require(
            kernel.get("input_section") == spec["input"],
            f"{prefix}: input_section mismatch",
        )
        _require(
            kernel.get("output_section") == spec["output"],
            f"{prefix}: output_section mismatch",
        )
        _require(
            isinstance(kernel.get("input_owner"), str)
            and bool(kernel["input_owner"].strip()),
            f"{prefix}: input owner is missing",
        )
        start = kernel.get("reservation_start")
        body_end = kernel.get("body_end")
        end = kernel.get("reservation_end")
        _require(
            all(isinstance(value, int) for value in (start, body_end, end)),
            f"{prefix}: missing reservation bounds",
        )
        _require(start <= body_end <= end, f"{prefix}: reservation overflow")
        _require(end - start == max_page, f"{prefix}: reservation size != MAXPAGESIZE")
        _require(
            kernel.get("output_start") == start and kernel.get("output_end") == end,
            f"{prefix}: output section extent differs from reservation",
        )
        _require(
            kernel.get("reservation_size") == max_page,
            f"{prefix}: reservation_size mismatch",
        )
        _require(start % max_page == 0, f"{prefix}: start not aligned to MAXPAGESIZE")
        _require(
            kernel.get("max_page_remainder") == 0,
            f"{prefix}: MAXPAGESIZE remainder is nonzero",
        )
        _require(
            kernel.get("page_offset") == start % 4096, f"{prefix}: page_offset mismatch"
        )
        section_alignment = kernel.get("sh_addralign")
        _require(
            isinstance(section_alignment, int)
            and section_alignment > 0
            and section_alignment & (section_alignment - 1) == 0
            and section_alignment <= max_page,
            f"{prefix}: actual sh_addralign mismatch",
        )
        _require(
            set(kernel.get("section_flags", [])) == {"ALLOC", "EXECINSTR"},
            f"{prefix}: section flags must be ALLOC|EXECINSTR",
        )
        _require(
            kernel.get("pt_load_count") == 1, f"{prefix}: split across PT_LOAD segments"
        )
        _require(
            kernel.get("pt_load_flags") == "R E",
            f"{prefix}: containing PT_LOAD is not RX",
        )
        _require(
            kernel.get("writable_segment_overlap") is False,
            f"{prefix}: reservation overlaps writable segment",
        )
        for sentinel_key in ("reservation_start", "body_end", "reservation_end"):
            sentinel = kernel.get("sentinels", {}).get(sentinel_key, {})
            _require(
                sentinel.get("name") == spec[sentinel_key],
                f"{prefix}: {sentinel_key} sentinel name mismatch",
            )
            _require(
                sentinel.get("count") == 1,
                f"{prefix}: {sentinel_key} sentinel count must be 1",
            )
            _require(
                sentinel.get("binding") == "GLOBAL",
                f"{prefix}: {sentinel_key} sentinel is non-global",
            )
            _require(
                sentinel.get("visibility") == "DEFAULT"
                and sentinel.get("defined") is True,
                f"{prefix}: {sentinel_key} sentinel must be defined DEFAULT",
            )
            expected_address = {
                "reservation_start": start,
                "body_end": body_end,
                "reservation_end": end,
            }[sentinel_key]
            _require(
                sentinel.get("address") == expected_address,
                f"{prefix}: {sentinel_key} sentinel address mismatch",
            )
            _require(
                kernel.get("link_map_sentinels", {}).get(sentinel_key)
                == expected_address,
                f"{prefix}: link-map {sentinel_key} sentinel mismatch",
            )
        _require(
            kernel.get("body_size") == body_end - start,
            f"{prefix}: body_size mismatch",
        )
        _require(
            kernel.get("input_start") == start,
            f"{prefix}: input start does not equal reservation start",
        )
        _require(
            kernel.get("input_end") == body_end,
            f"{prefix}: input end does not equal body_end",
        )
        _require(
            kernel.get("input_size") == body_end - start,
            f"{prefix}: input size mismatch",
        )
        _require(
            kernel.get("function_section_name") == spec["output"],
            f"{prefix}: selected function section mismatch",
        )
        _require(
            kernel.get("function_section_index") == kernel.get("output_section_index"),
            f"{prefix}: selected function section index mismatch",
        )
        _require(
            kernel.get("function_start") == start
            and kernel.get("function_end") == body_end
            and kernel.get("function_size") == body_end - start,
            f"{prefix}: selected function range does not equal kept input body",
        )
        _require(
            kernel.get("overlapping_elf_sections") == [],
            f"{prefix}: reservation overlaps another ELF section",
        )
        for field in BODY_FIELDS:
            _require(field in kernel, f"{prefix}: missing body field {field}")
        for field in STRUCTURAL_FIELDS:
            _require(field in kernel, f"{prefix}: missing structural field {field}")
        _require(
            not kernel.get("veneer_thunks"), f"{prefix}: veneer|thunk in reservation"
        )
        direct_calls = kernel.get("direct_calls", [])
        _require(
            isinstance(direct_calls, list)
            and not any(
                not isinstance(call, str)
                or veneer_marker.search(call)
                or any(name in call for name in veneer_names)
                for call in direct_calls
            ),
            f"{prefix}: veneer|thunk in kernel call graph",
        )
        _require(not kernel.get("plt_calls"), f"{prefix}: kernel call targets PLT")


def validate_manifest(manifest: dict[str, Any]) -> None:
    capability = manifest.get("linker_capability", {})
    _require(capability.get("accepted") is True, "linker capability is not accepted")
    _require(
        set(manifest.get("elf_layout", {})) == set(EXECUTABLE_TARGETS),
        "ELF layout executable set mismatch",
    )
    _require(
        set(manifest.get("executables", {})) == set(EXECUTABLE_TARGETS),
        "executable set mismatch",
    )
    for executable, target in EXECUTABLE_TARGETS.items():
        binary = checked_absolute_file(
            manifest["executables"][executable], f"{executable} binary"
        )
        checked_absolute_file(
            manifest["executables"][executable]["link_map"], f"{executable} link map"
        )
        layout = manifest["elf_layout"][executable]
        _require(
            Path(layout.get("binary", "")) == binary,
            f"{executable}: layout binary mismatch",
        )
        _require(
            layout.get("binary_sha256") == digest(binary),
            f"{executable}: binary hash mismatch",
        )
        fragment_record = capability.get("fragments", {}).get(target)
        fragment_hash = (
            fragment_record.get("sha256")
            if isinstance(fragment_record, dict)
            else fragment_record
        )
        _require(
            layout.get("fragment_sha256") == fragment_hash,
            f"{executable}: fragment_sha256 mismatch",
        )
        _require(
            layout.get("fragment_set_sha256") == capability.get("fragment_set_sha256"),
            f"{executable}: fragment_set_sha256 mismatch",
        )
        _require(
            layout.get("max_page_size") == capability.get("max_page_size"),
            f"{executable}: capability MAXPAGESIZE mismatch",
        )
        expected_map_flavor = (
            "lld"
            if "lld" in capability.get("linker", {}).get("flavor", "").lower()
            else "gnu"
        )
        _require(
            layout.get("link_map_flavor") == expected_map_flavor,
            f"{executable}: link-map flavor differs from capability linker",
        )
        validate_layout_record(layout, target)


def _exact_keys(record: Any, expected: set[str], label: str) -> None:
    _require(isinstance(record, dict), f"{label} must be an object")
    _require(
        set(record) == expected,
        f"exact {label} schema mismatch: expected {sorted(expected)}, "
        f"got {sorted(record)}",
    )


def _is_contained(root: Path, path: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _json_file(path: Path, label: str) -> Any:
    _require(
        path.is_absolute() and path.is_file() and not path.is_symlink(),
        f"invalid {label}: {path}",
    )
    return json.loads(path.read_text())


def _file_record(record: Any, label: str) -> Path:
    _exact_keys(record, {"absolute_path", "sha256"}, label)
    return checked_absolute_file(record, label)


def _trace_record(record: Any, label: str) -> Path:
    _exact_keys(
        record,
        {"absolute_path", "sha256", "record_count", "final_link_record_count"},
        label,
    )
    _require(
        isinstance(record["record_count"], int)
        and record["record_count"] >= 1
        and record["final_link_record_count"] == 1,
        f"{label} counts are invalid",
    )
    return checked_absolute_file(record, label)


def _exact_capability_file_record(
    record: Any,
    expected: Path,
    label: str,
    *,
    trace: bool = False,
    required_links: int = 1,
) -> Path:
    _require(
        isinstance(record, dict) and record.get("absolute_path") == str(expected),
        f"{label} path differs from exact producer path",
    )
    path = _trace_record(record, label) if trace else _file_record(record, label)
    _require(
        path == expected
        and expected == expected.resolve(strict=True)
        and expected.stat(follow_symlinks=False).st_nlink == required_links,
        f"{label} path differs from exact producer path",
    )
    return path


def _fingerprint(values: list[str]) -> str:
    return hashlib.sha256(("\n".join(values) + "\n").encode()).hexdigest()


def _validate_manifest_component(kind: str, value: Any) -> None:
    patterns = {
        "variant": r"^[A-Za-z0-9._-]+$",
        "manifest_instance": r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    }
    _require(
        kind in patterns
        and isinstance(value, str)
        and value not in {".", ".."}
        and re.fullmatch(patterns[kind], value) is not None,
        f"unsafe manifest {kind}: {value!r}",
    )


def _validate_runner(manifest: dict[str, Any], manifest_path: Path) -> Path:
    runner = Path(manifest.get("runner_root", ""))
    _require(runner.is_absolute() and runner.is_dir(), "invalid manifest runner root")
    runner = runner.resolve()
    git_root = Path(
        run("git", "-C", str(runner), "rev-parse", "--show-toplevel").strip()
    ).resolve()
    _require(git_root == runner, "manifest runner root is not exact Git worktree root")
    target = (runner / "target").resolve()
    _require(
        _is_contained(target, manifest_path),
        "supplied manifest is outside recorded runner target",
    )
    head = run("git", "-C", str(runner), "rev-parse", "HEAD").strip()
    tree = run("git", "-C", str(runner), "rev-parse", "HEAD^{tree}").strip()
    _require(manifest.get("commit") == head, "manifest runner HEAD changed")
    _require(manifest.get("tree") == tree, "manifest runner tree changed")
    _require(
        manifest.get("empty_diff_assertion") is True,
        "manifest clean assertion is false",
    )
    status = run(
        "git", "-C", str(runner), "status", "--porcelain", "--untracked-files=no"
    )
    _require(not status.strip(), "manifest runner tracked worktree is dirty")
    return runner


def _validate_tools(tools: Any) -> dict[str, Path]:
    _exact_keys(tools, AUTHENTICATED_TOOL_NAMES, "authenticated tool set")
    resolved: dict[str, Path] = {}
    roots: set[Path] = set()
    revisions: set[tuple[str, str]] = set()
    tool_fields = {
        "absolute_path",
        "sha256",
        "git_blob",
        "git_blob_sha256",
        "reviewed_root",
        "reviewed_commit",
        "reviewed_tree",
    }
    for name, record in tools.items():
        _exact_keys(record, tool_fields, f"tool {name}")
        path = checked_absolute_file(record, f"tool {name}")
        root = Path(record["reviewed_root"])
        _require(
            root.is_absolute() and root.is_dir(),
            f"tool {name} reviewed root is invalid",
        )
        root = root.resolve()
        actual_root = Path(
            run("git", "-C", str(path.parent), "rev-parse", "--show-toplevel").strip()
        ).resolve()
        _require(
            actual_root == root and _is_contained(root, path),
            f"tool {name} reviewed root mismatch",
        )
        commit = run("git", "-C", str(root), "rev-parse", "HEAD").strip()
        tree = run("git", "-C", str(root), "rev-parse", "HEAD^{tree}").strip()
        _require(
            (record["reviewed_commit"], record["reviewed_tree"]) == (commit, tree),
            f"tool {name} reviewed revision changed",
        )
        relative = path.relative_to(root)
        blob = run("git", "-C", str(root), "rev-parse", f"HEAD:{relative}").strip()
        _require(blob == record["git_blob"], f"tool {name} Git blob changed")
        blob_bytes = subprocess.run(
            ["git", "-C", str(root), "cat-file", "blob", blob],
            capture_output=True,
            check=False,
        )
        _require(blob_bytes.returncode == 0, f"cannot read tool {name} Git blob")
        blob_sha = hashlib.sha256(blob_bytes.stdout).hexdigest()
        _require(
            blob_sha == record["git_blob_sha256"] == record["sha256"],
            f"tool {name} reviewed bytes mismatch",
        )
        roots.add(root)
        revisions.add((commit, tree))
        resolved[name] = path
    _require(
        len(roots) == 1 and len(revisions) == 1,
        "authenticated tools do not share one reviewed root/revision",
    )
    _require(
        resolved["elf_layout"] == Path(__file__).resolve(),
        "manifest ELF validator differs from the executing authenticated tool",
    )
    return resolved


LINKER_RECORD_KEYS = {
    "invocation_path",
    "invocation_chain",
    "payload_path",
    "payload_sha256",
    "argv0",
    "extraction_root",
    "flavor",
    "version_argument",
    "version",
}


def _linker_invocation_chain(invocation: Path) -> tuple[list[dict[str, Any]], Path]:
    _require(invocation.is_absolute(), "linker invocation path must be absolute")
    normalized = Path(os.path.normpath(str(invocation)))
    _require(
        str(invocation) == str(normalized), "linker invocation path is not normalized"
    )
    pending = list(normalized.parts[1:])
    current = Path("/")
    chain: list[dict[str, Any]] = []
    visited: set[tuple[str, str, tuple[str, ...]]] = set()
    while pending:
        component = pending.pop(0)
        candidate = current / component
        try:
            metadata = candidate.lstat()
        except OSError as error:
            raise LayoutError(
                f"linker invocation chain is missing: {candidate}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(candidate)
            state = (str(candidate), target, tuple(pending))
            _require(
                state not in visited and len(chain) < 40,
                "linker invocation chain contains a symlink loop",
            )
            visited.add(state)
            chain.append({"absolute_path": str(candidate), "symlink_target": target})
            destination = Path(target)
            if not destination.is_absolute():
                destination = candidate.parent / destination
            destination = Path(os.path.normpath(str(destination)))
            _require(
                destination.is_absolute(),
                "linker symlink target is not absolute after join",
            )
            pending = [*destination.parts[1:], *pending]
            current = Path("/")
            continue
        if pending:
            _require(
                stat.S_ISDIR(metadata.st_mode),
                f"linker invocation ancestry is not a directory: {candidate}",
            )
        else:
            _require(
                stat.S_ISREG(metadata.st_mode) and os.access(candidate, os.X_OK),
                f"linker payload is not an executable regular file: {candidate}",
            )
        current = candidate
    payload = current
    _require(
        payload == payload.resolve(strict=True) and not payload.is_symlink(),
        "linker payload path is not canonical",
    )
    chain.append({"absolute_path": str(payload), "symlink_target": None})
    return chain, payload


def _probe_linker_version(
    payload: Path, argv0: str, version_argument: str, flavor: str, label: str
) -> tuple[str, str]:
    _require(
        isinstance(argv0, str) and bool(argv0) and "\x00" not in argv0,
        f"{label} argv0 is invalid",
    )
    completed = subprocess.run(
        [argv0, version_argument],
        executable=str(payload),
        env={"LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
        text=True,
        capture_output=True,
        check=False,
    )
    combined = "\n".join((completed.stdout, completed.stderr)).strip()
    _require(
        completed.returncode == 0,
        f"{label} version probe exited {completed.returncode}: {combined}",
    )
    lines = [line.strip() for line in combined.splitlines() if line.strip()]
    if flavor == "gnu":
        matches = [line for line in lines if "GNU ld" in line]
        stored_flavor = "GNU ld"
    elif flavor == "lld":
        matches = [line for line in lines if "lld" in line.lower()]
        stored_flavor = "LLD"
    else:
        matches = [line for line in lines if "GNU ld" in line or "lld" in line.lower()]
        stored_flavor = "GNU ld" if matches and "GNU ld" in matches[0] else "LLD"
    _require(bool(matches), f"{label} emitted no recognized linker version")
    return stored_flavor, matches[0]


def _inspect_linker_record(
    invocation: Path,
    argv0: str,
    flavor: str,
    extraction_root: Path | None = None,
) -> dict[str, Any]:
    _require(flavor in {"actual", "gnu", "lld"}, "invalid linker probe flavor")
    chain, payload = _linker_invocation_chain(invocation)
    root_text: str | None = None
    if extraction_root is not None:
        _require(
            extraction_root.is_absolute()
            and extraction_root.is_dir()
            and not extraction_root.is_symlink()
            and extraction_root == extraction_root.resolve(strict=True),
            "linker extraction root is invalid",
        )
        for entry in chain:
            path = Path(entry["absolute_path"])
            _require(
                path == extraction_root or extraction_root in path.parents,
                "linker invocation chain escapes authenticated extraction root",
            )
        root_text = str(extraction_root)
    version_argument = "-Wl,--version" if flavor == "actual" else "--version"
    stored_flavor, version = _probe_linker_version(
        payload, argv0, version_argument, flavor, "linker"
    )
    record = {
        "invocation_path": str(invocation),
        "invocation_chain": chain,
        "payload_path": str(payload),
        "payload_sha256": digest(payload),
        "argv0": argv0,
        "extraction_root": root_text,
        "flavor": stored_flavor,
        "version_argument": version_argument,
        "version": version,
    }
    _validate_linker_record(record, "inspected linker")
    return record


def _validate_linker_record(record: Any, label: str) -> Path:
    _exact_keys(record, LINKER_RECORD_KEYS, label)
    invocation_text = record["invocation_path"]
    _require(isinstance(invocation_text, str), f"{label} invocation path is invalid")
    invocation = Path(invocation_text)
    chain, payload = _linker_invocation_chain(invocation)
    _require(chain == record["invocation_chain"], f"{label} invocation chain changed")
    _require(record["payload_path"] == str(payload), f"{label} payload path changed")
    _require(
        digest(payload) == record["payload_sha256"], f"{label} payload hash mismatch"
    )
    extraction_root = record["extraction_root"]
    if extraction_root is not None:
        _require(
            isinstance(extraction_root, str), f"{label} extraction root is invalid"
        )
        root = Path(extraction_root)
        _require(
            root.is_absolute()
            and root.is_dir()
            and not root.is_symlink()
            and root == root.resolve(strict=True),
            f"{label} extraction root is invalid",
        )
        for entry in chain:
            path = Path(entry["absolute_path"])
            _require(
                path == root or root in path.parents,
                f"{label} invocation chain escapes extraction root",
            )
    flavor = record["flavor"]
    version_argument = record["version_argument"]
    _require(
        flavor in {"GNU ld", "LLD"}
        and version_argument in {"--version", "-Wl,--version"}
        and isinstance(record["version"], str)
        and bool(record["version"])
        and isinstance(record["argv0"], str)
        and bool(record["argv0"])
        and "\x00" not in record["argv0"],
        f"{label} recorded identity is invalid",
    )
    _require(
        not (flavor == "LLD" and version_argument == "--version")
        or record["argv0"] == "ld.lld",
        f"{label} explicit LLD argv0 must be ld.lld",
    )
    return payload


def _verify_linker_record(record: Any, label: str) -> Path:
    payload = _validate_linker_record(record, label)
    flavor = record["flavor"]
    version_argument = record["version_argument"]
    expected_probe_flavor = (
        "gnu"
        if flavor == "GNU ld" and version_argument == "--version"
        else "lld"
        if flavor == "LLD" and version_argument == "--version"
        else "actual"
    )
    observed_flavor, version = _probe_linker_version(
        payload,
        record["argv0"],
        version_argument,
        expected_probe_flavor,
        label,
    )
    _require(
        observed_flavor == flavor and version == record["version"],
        f"{label} version changed",
    )
    _require(
        _validate_linker_record(record, label) == payload,
        f"{label} payload changed during version probe",
    )
    return payload


LINK_TRACE_BASE_KEYS = {
    "payload_path",
    "payload_sha256",
    "argv0",
    "argv",
    "cwd",
    "path",
}


def _validate_link_trace_record(record: Any, label: str) -> None:
    _require(isinstance(record, dict), f"{label} is not an object")
    has_correlation = "role" in record or "session" in record
    expected = LINK_TRACE_BASE_KEYS | (
        {"role", "session"} if has_correlation else set()
    )
    _exact_keys(record, expected, label)
    _require(
        isinstance(record["payload_path"], str)
        and isinstance(record["payload_sha256"], str)
        and isinstance(record["argv0"], str)
        and bool(record["argv0"])
        and isinstance(record["argv"], list)
        and all(isinstance(token, str) for token in record["argv"])
        and isinstance(record["cwd"], str)
        and Path(record["cwd"]).is_absolute()
        and isinstance(record["path"], str),
        f"{label} fields are invalid",
    )
    if has_correlation:
        _require(
            isinstance(record["role"], str)
            and bool(record["role"])
            and isinstance(record["session"], str)
            and bool(record["session"]),
            f"{label} role/session is incomplete",
        )


def replay_linker_execution(
    trace: Path,
    linker_record: dict[str, Any],
    executable: Path,
    flavor: str,
) -> dict[str, Any]:
    linker = _validate_linker_record(linker_record, f"recorded {flavor} linker")
    _require(
        (flavor == "gnu" and "GNU ld" in linker_record["version"])
        or (flavor == "lld" and "lld" in linker_record["version"].lower())
        or (
            flavor == "actual"
            and linker_record["flavor"] in {"GNU ld", "LLD"}
            and (
                "GNU ld" in linker_record["version"]
                or "lld" in linker_record["version"].lower()
            )
        ),
        f"recorded {flavor} linker flavor mismatch",
    )
    records = [
        json.loads(line) for line in trace.read_text().splitlines() if line.strip()
    ]
    for index, record in enumerate(records):
        _validate_link_trace_record(record, f"{flavor} linker trace record {index}")
    matches: list[tuple[dict[str, Any], Path]] = []
    for record in records:
        if not isinstance(record.get("argv"), list):
            continue
        try:
            raw_output = _cargo_output_alias(record["argv"], executable)
        except LayoutError:
            continue
        matches.append((record, raw_output))
    _require(
        len(matches) == 1,
        f"expected one observed {flavor} linker execution, got {len(matches)}",
    )
    observed, raw_output = matches[0]
    driver_text = observed.get("payload_path", "")
    _require(
        isinstance(driver_text, str) and driver_text == str(linker),
        f"observed {flavor} linker differs from recorded linker",
    )
    _require(
        observed.get("payload_sha256") == linker_record["payload_sha256"]
        and observed.get("argv0") == linker_record["argv0"],
        f"observed {flavor} linker hash differs from recorded linker",
    )
    role = observed.get("role")
    session = observed.get("session")
    result = {
        "linker": linker_record,
        "argv": observed["argv"],
        "executable": str(executable),
        "raw_output": str(raw_output),
        "trace": {
            "absolute_path": str(trace),
            "sha256": digest(trace),
            "record_count": len(records),
            "final_link_record_count": len(matches),
        },
    }
    if role is not None:
        cwd = observed.get("cwd")
        embedded_path = observed.get("path")
        _require(
            isinstance(cwd, str)
            and Path(cwd).is_absolute()
            and Path(cwd).is_dir()
            and isinstance(embedded_path, str)
            and bool(embedded_path),
            f"observed {flavor} linker environment is incomplete",
        )
        result["role"] = role
        result["session"] = session
        result["cwd"] = cwd
        result["path"] = embedded_path
    return result


def _validate_actual_link_argv_trace(
    link_argv: Path,
    observed: dict[str, Any],
    expected_wrapper: Path,
    fragment: Path,
    link_map: Path,
    label: str,
) -> None:
    _, printed_driver, printed_argv = _parse_cargo_link_argv(link_argv)
    expected_wrapper = expected_wrapper.resolve()
    _require(
        isinstance(printed_driver, str) and printed_driver == str(expected_wrapper),
        f"{label} link argv did not execute reviewed wrapper",
    )
    _require(
        printed_argv == observed.get("argv"),
        f"{label} link argv differs from execution trace",
    )
    _require(
        not _linker_response_files(printed_argv),
        f"{label} linker response files are forbidden",
    )
    selection, scripts, maps = _printed_linker_controls(printed_argv)
    _require(
        selection == []
        and scripts == [f"-Wl,-T,{fragment}"]
        and maps == [f"-Wl,-Map,{link_map}"],
        f"{label} linker controls are not exact",
    )


def _resolve_printed_cargo_driver(
    environment: dict[str, str], printed_driver: str, label: str
) -> Path:
    command = Path(printed_driver)
    if command.is_absolute():
        _require(
            printed_driver == str(command.resolve(strict=True)),
            f"{label} Cargo driver path is not canonical",
        )
        return command
    _require("/" not in printed_driver, f"{label} Cargo driver is unsafe")
    embedded_path = environment.get("PATH", "")
    search = embedded_path.split(os.pathsep)
    _require(
        bool(search)
        and all(component and Path(component).is_absolute() for component in search),
        f"{label} Cargo PATH is invalid",
    )
    resolved = next(
        (
            candidate.resolve()
            for directory in search
            for candidate in (Path(directory) / printed_driver,)
            if candidate.is_file() and os.access(candidate, os.X_OK)
        ),
        None,
    )
    _require(resolved is not None, f"{label} Cargo driver cannot be resolved")
    return resolved


def _is_script_control(argument: str) -> bool:
    return (
        argument in {"-T", "--script"}
        or (argument.startswith("-T") and len(argument) > 2)
        or argument.startswith("--script=")
    )


def _is_map_control(argument: str) -> bool:
    return (
        argument in {"-Map", "--Map"}
        or argument.startswith("-Map=")
        or argument.startswith("--Map=")
    )


def _printed_linker_controls(
    argv: list[str],
) -> tuple[list[str], list[str], list[str]]:
    selection: list[str] = []
    scripts: list[str] = []
    maps: list[str] = []
    for index, argument in enumerate(argv):
        if index > 0 and argv[index - 1] == "-Xlinker":
            continue
        forwarded = (
            argument.startswith("-Wl,")
            or argument == "-Xlinker"
            or argument.startswith("-Xlinker=")
        )
        candidates = [argument]
        if argument.startswith("-Wl,"):
            candidates = argument[4:].split(",")
        elif argument == "-Xlinker" and index + 1 < len(argv):
            candidates = [argv[index + 1]]
        elif argument.startswith("-Xlinker="):
            candidates = [argument.split("=", 1)[1]]
        if any(
            candidate == "--ld-path"
            or candidate.startswith("--ld-path=")
            or (
                not forwarded
                and (
                    candidate == "-B"
                    or (candidate.startswith("-B") and len(candidate) > 2)
                    or candidate == "-fuse-ld"
                    or candidate.startswith("-fuse-ld=")
                )
            )
            for candidate in candidates
        ):
            selection.append(argument)
        if any(_is_script_control(candidate) for candidate in candidates):
            scripts.append(argument)
        if any(_is_map_control(candidate) for candidate in candidates):
            maps.append(argument)
    return selection, scripts, maps


def _linker_response_files(argv: list[str]) -> bool:
    for index, argument in enumerate(argv):
        if index > 0 and argv[index - 1] == "-Xlinker":
            continue
        candidates = [argument]
        if argument.startswith("-Wl,"):
            candidates = argument[4:].split(",")
        elif argument == "-Xlinker" and index + 1 < len(argv):
            candidates = [argv[index + 1]]
        elif argument.startswith("-Xlinker="):
            candidates = [argument.split("=", 1)[1]]
        if any(candidate.startswith("@") for candidate in candidates):
            return True
    return False


def _raw_linker_controls(
    argv: list[str],
) -> tuple[list[tuple[str, str | None]], list[tuple[str, str | None]]]:
    scripts: list[tuple[str, str | None]] = []
    maps: list[tuple[str, str | None]] = []
    for index, argument in enumerate(argv):
        following = argv[index + 1] if index + 1 < len(argv) else None
        if argument in {"-T", "--script"}:
            scripts.append((argument, following))
        elif argument.startswith("--script="):
            scripts.append(("--script=", argument.split("=", 1)[1]))
        elif argument.startswith("-T") and len(argument) > 2:
            scripts.append(("-T", argument[2:]))
        if argument in {"-Map", "--Map"}:
            maps.append((argument, following))
        elif argument.startswith("-Map="):
            maps.append(("-Map=", argument.split("=", 1)[1]))
        elif argument.startswith("--Map="):
            maps.append(("--Map=", argument.split("=", 1)[1]))
    return scripts, maps


def _normalize_driver_flag(argument: str) -> str:
    if argument.startswith("-plugin-opt=-fresolution="):
        return "-plugin-opt=-fresolution=<driver-temporary>"
    return argument


def _linker_semantic_categories(argv: list[str]) -> dict[str, list[str]]:
    output: list[str] = []
    library_paths: list[str] = []
    ordered_semantics: list[str] = []
    paired_flags = {
        "-plugin",
        "-dynamic-linker",
        "-m",
        "-z",
        "-e",
        "-T",
        "--script",
        "-Map",
        "--Map",
        "-rpath",
        "-rpath-link",
        "-soname",
        "--version-script",
        "-u",
        "--undefined",
        "-Y",
        "-a",
        "-b",
        "--format",
    }
    file_suffix = re.compile(r"(?:\.o|\.rlib|\.a|\.so(?:\.[^/]+)*)$")
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument in {"-o", "--output"} and index + 1 < len(argv):
            output.append(argv[index + 1])
            index += 2
            continue
        if argument.startswith("--output="):
            output.append(argument.split("=", 1)[1])
        elif argument.startswith("-o") and len(argument) > 2:
            output.append(argument[2:])
        elif argument == "-L" and index + 1 < len(argv):
            library_paths.append(os.path.normpath(argv[index + 1]))
            index += 2
            continue
        elif argument.startswith("-L") and len(argument) > 2:
            library_paths.append(os.path.normpath(argument[2:]))
        elif argument in {"-l", "--library"} and index + 1 < len(argv):
            ordered_semantics.append(f"library:-l{argv[index + 1]}")
            index += 2
            continue
        elif argument.startswith("--library="):
            ordered_semantics.append(f"library:-l{argument.split('=', 1)[1]}")
        elif argument.startswith("-l") and len(argument) > 2:
            ordered_semantics.append(f"library:{argument}")
        elif argument in paired_flags and index + 1 < len(argv):
            ordered_semantics.append(
                f"flag:{argument}={_normalize_driver_flag(argv[index + 1])}"
            )
            index += 2
            continue
        elif not argument.startswith("-") and file_suffix.search(argument):
            ordered_semantics.append(f"input:{os.path.normpath(argument)}")
        else:
            ordered_semantics.append(f"argument:{_normalize_driver_flag(argument)}")
        index += 1
    return {
        "output": output,
        "library_paths": library_paths,
        "ordered_semantics": ordered_semantics,
    }


def _validate_driver_semantic_closure(
    projected: list[str], observed: list[str], label: str
) -> None:
    projected_categories = _linker_semantic_categories(projected)
    observed_categories = _linker_semantic_categories(observed)
    _require(
        projected_categories == observed_categories,
        f"{label} driver/linker semantic categories differ",
    )


def _project_driver_linker_argv(
    driver: Path,
    printed_argv: list[str],
    raw_output: str,
    cwd: Path,
    embedded_path: str,
    label: str,
) -> list[str]:
    _require(cwd.is_absolute() and cwd.is_dir(), f"{label} trace cwd is invalid")
    path_parts = embedded_path.split(os.pathsep)
    _require(
        bool(path_parts)
        and all(
            component and Path(component).is_absolute() for component in path_parts
        ),
        f"{label} trace PATH is invalid",
    )
    environment = {"LC_ALL": "C", "PATH": embedded_path}
    completed = subprocess.run(
        [str(driver), "-###", *printed_argv],
        cwd=cwd,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    _require(completed.returncode == 0, f"{label} compiler projection failed")
    candidates: list[list[str]] = []
    for line in (*completed.stdout.splitlines(), *completed.stderr.splitlines()):
        try:
            command = shlex.split(line)
        except ValueError:
            continue
        if len(command) < 2:
            continue
        executable = Path(command[0])
        if not executable.is_absolute() or not executable.is_file():
            continue
        candidate = [
            argument for argument in command[1:] if not argument.startswith("-fuse-ld=")
        ]
        if _raw_output_values(candidate) == [raw_output]:
            candidates.append(candidate)
    _require(
        len(candidates) == 1,
        f"{label} compiler projection did not identify one exact linker command",
    )
    return candidates[0]


def _validate_explicit_link_argv_trace(
    link_argv: Path,
    cargo_observed: dict[str, Any],
    observed: dict[str, Any],
    configured_driver: Path,
    reviewed_wrapper: Path,
    artifact_root: Path,
    flavor: str,
    fragment: Path,
    link_map: Path,
    label: str,
) -> None:
    _, printed_driver, printed_argv = _parse_cargo_link_argv(link_argv)
    _require(
        printed_driver == str(reviewed_wrapper.resolve()),
        f"{label} link argv did not execute reviewed wrapper",
    )
    _require(
        printed_argv == cargo_observed.get("argv")
        and cargo_observed.get("linker", {}).get("payload_path")
        == str(configured_driver),
        f"{label} Cargo link argv differs from execution trace",
    )
    fuse = "bfd" if flavor == "gnu" else "lld"
    wrapper_dir = artifact_root / flavor / "linker-wrapper"
    explicit_wrapper = wrapper_dir / f"ld.{fuse}"
    _require(
        explicit_wrapper.is_file()
        and not explicit_wrapper.is_symlink()
        and explicit_wrapper == explicit_wrapper.resolve(strict=True)
        and explicit_wrapper.stat(follow_symlinks=False).st_nlink == 1
        and digest(explicit_wrapper) == digest(reviewed_wrapper),
        f"{label} explicit linker wrapper differs from reviewed wrapper",
    )
    selection, scripts, maps = _printed_linker_controls(printed_argv)
    _require(
        not _linker_response_files(printed_argv)
        and not _linker_response_files(cargo_observed.get("argv", []))
        and not _linker_response_files(observed.get("argv", [])),
        f"{label} linker response files are forbidden",
    )
    _require(
        selection == [f"-B{wrapper_dir}", f"-fuse-ld={fuse}"]
        and scripts == [f"-Wl,-T,{fragment}"]
        and maps == [f"-Wl,-Map,{link_map}"]
        and _raw_output_values(printed_argv) == [cargo_observed.get("raw_output")]
        and cargo_observed.get("raw_output") == observed.get("raw_output"),
        f"{label} linker controls are not exact",
    )
    observed_argv = observed.get("argv", [])
    observed_scripts, observed_maps = (
        _raw_linker_controls(observed_argv)
        if isinstance(observed_argv, list)
        else ([], [])
    )
    _require(
        isinstance(observed_argv, list)
        and observed_scripts == [("-T", str(fragment))]
        and observed_maps == [("-Map", str(link_map))],
        f"{label} observed linker controls are not exact",
    )
    _require(
        cargo_observed.get("role") == "cargo-driver"
        and observed.get("role") == "explicit-linker"
        and cargo_observed.get("session") == observed.get("session")
        and isinstance(observed.get("session"), str)
        and bool(observed["session"]),
        f"{label} Cargo/linker trace correlation differs",
    )
    projected = _project_driver_linker_argv(
        configured_driver,
        printed_argv,
        cargo_observed["raw_output"],
        Path(cargo_observed.get("cwd", "")),
        cargo_observed.get("path", ""),
        label,
    )
    _validate_driver_semantic_closure(projected, observed_argv, label)


def replay_link_command(
    trace: Path,
    executable: Path,
    linker_record: dict[str, Any],
    fragment: Path,
    link_map: Path,
) -> dict[str, Any]:
    driver = _validate_linker_record(linker_record, "recorded capability linker")
    records = [
        json.loads(line) for line in trace.read_text().splitlines() if line.strip()
    ]
    for index, record in enumerate(records):
        _validate_link_trace_record(record, f"link trace record {index}")
    matches = [
        record
        for record in records
        if isinstance(record.get("argv"), list)
        and _output_matches(record["argv"], executable)
    ]
    _require(
        len(matches) == 1,
        f"expected one captured final link command, got {len(matches)}",
    )
    record = matches[0]
    observed_driver = record.get("payload_path", "")
    _require(
        isinstance(observed_driver, str) and observed_driver == str(driver),
        "captured link driver differs from recorded capability",
    )
    _require(
        record.get("payload_sha256") == linker_record["payload_sha256"]
        and record.get("argv0") == linker_record["argv0"],
        "captured link driver hash differs from recorded capability",
    )
    argv = record.get("argv", [])
    _require(
        isinstance(argv, list) and all(isinstance(token, str) for token in argv),
        "captured final link argv is invalid",
    )
    _require(
        not _linker_response_files(argv),
        "captured link command contains linker response files",
    )
    selection, scripts, maps = _printed_linker_controls(argv)
    _require(
        selection == []
        and scripts == [f"-Wl,-T,{fragment}"]
        and maps == [f"-Wl,-Map,{link_map}"],
        "captured link command linker controls are not exact",
    )
    ordered_inputs, direct_files = _link_command_inputs(argv)
    return {
        "driver": linker_record,
        "argv": argv,
        "ordered_linker_inputs": ordered_inputs,
        "ordered_linker_input_fingerprint": _fingerprint(ordered_inputs),
        "direct_input_files": direct_files,
        "direct_cgu_members": sorted(
            value for value in direct_files if ".rcgu.o" in value
        ),
        "trace": {
            "absolute_path": str(trace),
            "sha256": digest(trace),
            "record_count": len(records),
            "final_link_record_count": len(matches),
        },
        "executable": str(executable),
        "fragment": str(fragment),
        "link_map": str(link_map),
    }


def _validate_capability_producer(
    producer: Any, tool_records: dict[str, Any]
) -> tuple[Path, Path]:
    _exact_keys(
        producer,
        {"runner_root", "commit", "tree", "empty_diff_assertion", "artifact_root"},
        "capability producer",
    )
    root = Path(producer["runner_root"])
    _require(
        root.is_absolute() and root.is_dir() and not root.is_symlink(),
        "capability producer root is invalid",
    )
    root = root.resolve()
    _require(
        producer["runner_root"] == str(root),
        "capability producer root is not canonical",
    )
    _require(
        Path(
            run("git", "-C", str(root), "rev-parse", "--show-toplevel").strip()
        ).resolve()
        == root,
        "capability producer root is not an exact Git worktree",
    )
    head = run("git", "-C", str(root), "rev-parse", "HEAD").strip()
    tree = run("git", "-C", str(root), "rev-parse", "HEAD^{tree}").strip()
    status = run(
        "git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"
    )
    reviewed = tool_records["elf_layout"]
    _require(
        producer["commit"] == head == reviewed["reviewed_commit"]
        and producer["tree"] == tree == reviewed["reviewed_tree"]
        and producer["empty_diff_assertion"] is True
        and Path(reviewed["reviewed_root"]).resolve() == root
        and not status.strip(),
        "capability producer revision differs from reviewed harness",
    )
    artifact_root = Path(producer["artifact_root"])
    producer_target = root / "target"
    linker_root = producer_target / "cache-gate-linker"
    for component in (producer_target, linker_root):
        _require(
            component.is_dir() and not component.is_symlink(),
            f"capability producer ancestry contains symlink or non-directory: {component}",
        )
    _require(
        artifact_root.is_absolute()
        and artifact_root.is_dir()
        and not artifact_root.is_symlink(),
        "capability artifact root is invalid",
    )
    try:
        artifact_relative = artifact_root.relative_to(linker_root)
    except ValueError as error:
        raise LayoutError(
            "capability artifact root is outside producer target"
        ) from error
    _require(
        len(artifact_relative.parts) >= 2,
        "capability artifact root lacks architecture/probe ancestry",
    )
    cursor = linker_root
    for part in artifact_relative.parts:
        cursor /= part
        _require(
            cursor.is_dir() and not cursor.is_symlink(),
            f"capability producer ancestry contains symlink or non-directory: {cursor}",
        )
    resolved_artifact_root = artifact_root.resolve()
    _require(
        producer["artifact_root"] == str(resolved_artifact_root)
        and resolved_artifact_root == artifact_root
        and _is_contained(producer_target, resolved_artifact_root),
        "capability artifact root is outside producer target",
    )
    return root, resolved_artifact_root


def _expected_capability_shape_paths(
    artifact_root: Path, flavor: str, target: str
) -> dict[str, Path]:
    flavor_root = artifact_root / flavor
    return {
        "binary": flavor_root / target / "release" / target,
        "link_argv": flavor_root / f"{target}.link-args.txt",
        "link_map": flavor_root / f"{target}.map",
        "symbols": flavor_root / f"{target}.symbols.json",
        "layout": flavor_root / f"{target}.layout.json",
        "linker_execution": flavor_root / f"{target}.linker-execution.json",
        "linker_trace": flavor_root / f"{target}.linker-trace.jsonl",
        "cargo_execution": flavor_root / f"{target}.cargo-driver-execution.json",
        "cargo_trace": flavor_root / f"{target}.cargo-driver-trace.jsonl",
    }


def _validate_capability(
    manifest: dict[str, Any],
    manifest_path: Path,
    runner: Path,
    tools: dict[str, Path],
    capability_document: bytes | None = None,
) -> tuple[dict[str, Any], Path, dict[str, Path]]:
    embedded = manifest["linker_capability"]
    _exact_keys(
        embedded,
        {
            "accepted",
            "arch",
            "target_triple",
            "max_page_size",
            "rustc_version",
            "cargo_version",
            "linker",
            "required_linkers",
            "fragments",
            "fragment_set_sha256",
            "shapes",
            "producer",
            "copy",
        },
        "linker capability",
    )
    _require(embedded["accepted"] is True, "linker capability is not accepted")
    expected_copy = manifest_path.parent / "linker-capability.json"
    if capability_document is None:
        copy_path = _exact_capability_file_record(
            embedded["copy"],
            expected_copy,
            "linker capability copy",
        )
        capability = _json_file(copy_path, "linker capability copy")
    else:
        copy_path = expected_copy
        _require(
            embedded.get("copy")
            == {
                "absolute_path": str(expected_copy),
                "sha256": hashlib.sha256(capability_document).hexdigest(),
            },
            "linker capability copy record differs from held bytes",
        )
        capability = json.loads(capability_document)
    _require(
        capability == {key: value for key, value in embedded.items() if key != "copy"},
        "embedded linker capability differs from authenticated copy",
    )
    _require(
        capability.get("arch") == manifest["architecture"],
        "capability architecture mismatch",
    )
    _require(
        isinstance(capability.get("target_triple"), str)
        and capability["target_triple"].startswith(f"{manifest['architecture']}-")
        and capability["target_triple"].endswith("-linux-gnu")
        and isinstance(capability.get("rustc_version"), str)
        and "host: " + capability["target_triple"]
        in capability["rustc_version"].splitlines()
        and isinstance(capability.get("cargo_version"), str)
        and bool(capability["cargo_version"].strip()),
        "capability recorded Rust toolchain identity is invalid",
    )
    _require(
        isinstance(capability.get("max_page_size"), int)
        and capability["max_page_size"] > 0,
        "invalid capability MAXPAGESIZE",
    )
    producer_root, artifact_root = _validate_capability_producer(
        capability["producer"], manifest["tools"]
    )
    _require(
        artifact_root.parent
        == producer_root / "target/cache-gate-linker" / capability["arch"]
        and artifact_root.name.startswith(".probe."),
        "capability artifact root architecture/probe mismatch",
    )
    _validate_linker_record(capability["linker"], "capability linker")
    _exact_keys(capability["required_linkers"], {"gnu", "lld"}, "required linker set")
    for flavor, record in capability["required_linkers"].items():
        _validate_linker_record(record, f"required linker {flavor}")
    _require(
        "GNU ld" in capability["required_linkers"]["gnu"]["version"],
        "required GNU linker identity mismatch",
    )
    _require(
        "lld" in capability["required_linkers"]["lld"]["version"].lower(),
        "required LLD identity mismatch",
    )
    _exact_keys(capability["fragments"], set(TARGET_KERNELS), "capability fragment set")
    fragments: dict[str, Path] = {}
    fragment_lines: list[str] = []
    for target, record in sorted(capability["fragments"].items()):
        expected = (producer_root / f"benches/cache-gate-{target}-layout.ld").resolve()
        path = _exact_capability_file_record(
            record,
            expected,
            f"capability fragment {target}",
        )
        relative = path.relative_to(producer_root)
        blob = subprocess.run(
            [
                "git",
                "-C",
                str(producer_root),
                "show",
                f"{capability['producer']['commit']}:{relative}",
            ],
            capture_output=True,
            check=False,
        )
        _require(
            blob.returncode == 0
            and hashlib.sha256(blob.stdout).hexdigest() == record["sha256"],
            f"capability fragment {target} differs from producer Git blob",
        )
        fragments[target] = path
        fragment_lines.append(f"{target}:{record['sha256']}")
    _require(
        _fingerprint(fragment_lines) == capability["fragment_set_sha256"],
        "capability fragment-set hash mismatch",
    )
    _exact_keys(capability["shapes"], {"actual", "gnu", "lld"}, "capability shape set")
    readelf_text = shutil.which("readelf")
    _require(bool(readelf_text), "readelf is required to rederive capability shapes")
    readelf = Path(readelf_text).resolve()
    _require(
        readelf.is_file() and not readelf.is_symlink(), "invalid readelf executable"
    )
    with tempfile.TemporaryDirectory(
        prefix="cache-gate-capability-validate-"
    ) as temporary:
        temporary_root = Path(temporary)
        for flavor, shapes in capability["shapes"].items():
            _exact_keys(shapes, set(TARGET_KERNELS), f"{flavor} capability targets")
            for target, shape in shapes.items():
                expected_paths = _expected_capability_shape_paths(
                    artifact_root, flavor, target
                )
                expected_shape_keys = {
                    "binary",
                    "link_argv",
                    "link_map",
                    "symbols",
                    "layout",
                    "linker_execution",
                }
                if flavor != "actual":
                    expected_shape_keys.add("cargo_execution")
                _exact_keys(
                    shape, expected_shape_keys, f"{flavor}/{target} capability shape"
                )
                paths = {
                    key: _exact_capability_file_record(
                        shape[key],
                        expected_paths[key],
                        f"{flavor}/{target} {key}",
                        required_links=2 if key == "binary" else 1,
                    )
                    for key in (
                        "binary",
                        "link_argv",
                        "link_map",
                        "symbols",
                        "layout",
                    )
                }
                _require(
                    all(paths[key] == expected_paths[key] for key in paths),
                    f"{flavor}/{target} capability artifact path mismatch",
                )
                layout = _json_file(paths["layout"], f"{flavor}/{target} layout")
                link_argv_text = paths["link_argv"].read_text(errors="replace")
                _require(
                    str(fragments[target]) in link_argv_text
                    and str(paths["link_map"]) in link_argv_text
                    and "-T" in link_argv_text
                    and "-Map" in link_argv_text,
                    f"{flavor}/{target} link argv lacks exact fragment/map",
                )
                _require(
                    layout.get("binary") == str(paths["binary"]),
                    f"{flavor}/{target} shape binary mismatch",
                )
                _require(
                    layout.get("link_map") == str(paths["link_map"]),
                    f"{flavor}/{target} shape map mismatch",
                )
                _require(
                    layout.get("fragment_sha256")
                    == capability["fragments"][target]["sha256"],
                    f"{flavor}/{target} shape fragment mismatch",
                )
                _require(
                    layout.get("fragment_set_sha256")
                    == capability["fragment_set_sha256"],
                    f"{flavor}/{target} shape fragment set mismatch",
                )
                validate_layout_record(layout, target)
                regenerated_symbols = temporary_root / f"{flavor}-{target}.symbols.json"
                _run_extractor(
                    tools["extractor"],
                    paths["binary"],
                    manifest["architecture"],
                    target,
                    regenerated_symbols,
                    f"{flavor}/{target}",
                )
                _require(
                    _json_file(paths["symbols"], f"{flavor}/{target} recorded symbols")
                    == _json_file(
                        regenerated_symbols,
                        f"{flavor}/{target} regenerated symbols",
                    ),
                    f"{flavor}/{target} capability symbols differ from artifact bytes",
                )
                regenerated_layout = validate_elf(
                    argparse.Namespace(
                        binary=paths["binary"],
                        link_map=paths["link_map"],
                        script=fragments[target],
                        symbols=regenerated_symbols,
                        arch=manifest["architecture"],
                        readelf=readelf,
                    ),
                    capability,
                )
                _require(
                    regenerated_layout == layout,
                    f"{flavor}/{target} capability layout differs from artifact bytes",
                )
                execution_path = _exact_capability_file_record(
                    shape["linker_execution"],
                    expected_paths["linker_execution"],
                    f"{flavor}/{target} linker execution",
                )
                _require(
                    execution_path == expected_paths["linker_execution"],
                    f"{flavor}/{target} execution proof path mismatch",
                )
                observed = _json_file(
                    execution_path, f"{flavor}/{target} linker execution"
                )
                _require_output_contained(
                    observed.get("argv", []),
                    artifact_root,
                    f"{flavor}/{target} linker output is outside producer artifact root",
                )
                linker_record = (
                    capability["linker"]
                    if flavor == "actual"
                    else capability["required_linkers"][flavor]
                )
                trace = observed.get("trace", {})
                trace_path = _exact_capability_file_record(
                    trace,
                    expected_paths["linker_trace"],
                    f"{flavor}/{target} linker trace",
                    trace=True,
                )
                _require(
                    trace_path == expected_paths["linker_trace"],
                    f"{flavor}/{target} linker trace path mismatch",
                )
                regenerated = replay_linker_execution(
                    trace_path,
                    linker_record,
                    paths["binary"],
                    flavor,
                )
                _require(
                    regenerated == observed,
                    f"{flavor}/{target} linker execution proof differs from trace",
                )
                _require(
                    observed.get("linker") == linker_record,
                    f"{flavor}/{target} linker execution identity mismatch",
                )
                if flavor == "actual":
                    _validate_actual_link_argv_trace(
                        paths["link_argv"],
                        observed,
                        tools["link_wrapper"],
                        fragments[target],
                        paths["link_map"],
                        f"{flavor}/{target}",
                    )
                else:
                    cargo_execution_path = _exact_capability_file_record(
                        shape["cargo_execution"],
                        expected_paths["cargo_execution"],
                        f"{flavor}/{target} Cargo driver execution",
                    )
                    cargo_observed = _json_file(
                        cargo_execution_path,
                        f"{flavor}/{target} Cargo driver execution",
                    )
                    cargo_trace_path = _exact_capability_file_record(
                        cargo_observed.get("trace", {}),
                        expected_paths["cargo_trace"],
                        f"{flavor}/{target} Cargo driver trace",
                        trace=True,
                    )
                    regenerated_cargo = replay_linker_execution(
                        cargo_trace_path,
                        capability["linker"],
                        paths["binary"],
                        "actual",
                    )
                    _require(
                        regenerated_cargo == cargo_observed,
                        f"{flavor}/{target} Cargo driver execution proof differs from trace",
                    )
                    _validate_explicit_link_argv_trace(
                        paths["link_argv"],
                        cargo_observed,
                        observed,
                        Path(capability["linker"]["payload_path"]),
                        tools["link_wrapper"],
                        artifact_root,
                        flavor,
                        fragments[target],
                        paths["link_map"],
                        f"{flavor}/{target}",
                    )
    copied_fragments: dict[str, Path] = {}
    for target, record in capability["fragments"].items():
        copied = manifest_path.parent / "linker-fragments" / f"{target}.ld"
        _require(
            copied.is_file()
            and not copied.is_symlink()
            and copied == copied.resolve(strict=True)
            and copied.stat(follow_symlinks=False).st_nlink == 1,
            f"copied fragment {target} is not exact private file",
        )
        _require(
            digest(copied) == record["sha256"],
            f"copied fragment {target} hash mismatch",
        )
        copied_fragments[target] = copied
    return capability, copy_path, copied_fragments


def _validate_control(control: Any) -> None:
    required = {
        "builder_commit",
        "builder_tree",
        "runner_root",
        "runner_commit",
        "runner_tree",
        "mode",
        "binary",
        "inputs",
        "cargo_version",
        "rustc_version",
        "locked",
        "provenance_path",
        "provenance_sha256",
    }
    _exact_keys(control, required, "control provenance")
    control_root = Path(control["runner_root"])
    _require(
        control_root.is_absolute() and control_root.is_dir(),
        "control runner root is invalid",
    )
    control_root = control_root.resolve()
    _require(
        control["runner_root"] == str(control_root),
        "control runner root is not canonical",
    )
    _require(
        Path(
            run("git", "-C", str(control_root), "rev-parse", "--show-toplevel").strip()
        ).resolve()
        == control_root,
        "control runner root is not exact Git worktree root",
    )
    head = run("git", "-C", str(control_root), "rev-parse", "HEAD").strip()
    tree = run("git", "-C", str(control_root), "rev-parse", "HEAD^{tree}").strip()
    status = run(
        "git",
        "-C",
        str(control_root),
        "status",
        "--porcelain",
        "--untracked-files=no",
    )
    _require(
        control["runner_commit"] == control["builder_commit"] == head
        and control["runner_tree"] == control["builder_tree"] == tree
        and control["mode"] == "BUILD_CONTROL"
        and control["locked"] is True,
        "control runner/build identity mismatch",
    )
    _require(not status.strip(), "control runner tracked worktree is dirty")
    control_target = (control_root / "tools/cache-gate-control/target").resolve()
    binary = _file_record(control["binary"], "control binary")
    _require(
        _is_contained(control_target, binary),
        "control binary is outside control target",
    )
    provenance_path = Path(control["provenance_path"])
    _require(
        provenance_path.is_absolute()
        and provenance_path.is_file()
        and not provenance_path.is_symlink(),
        "invalid control provenance path",
    )
    provenance_path = provenance_path.resolve()
    _require(
        _is_contained(control_target, provenance_path),
        "control provenance is outside control target",
    )
    _require(
        digest(provenance_path) == control["provenance_sha256"],
        "control provenance hash mismatch",
    )
    expected_inputs = {
        "cargo_manifest": control_root / "tools/cache-gate-control/Cargo.toml",
        "cargo_lock": control_root / "tools/cache-gate-control/Cargo.lock",
        "source": control_root / "tools/cache-gate-control/src/main.rs",
    }
    _exact_keys(control["inputs"], set(expected_inputs), "control input set")
    for name, expected in expected_inputs.items():
        path = _file_record(control["inputs"][name], f"control input {name}")
        _require(path == expected.resolve(), f"control input {name} path mismatch")
    provenance = _json_file(provenance_path, "control provenance")
    _require(
        provenance
        == {
            key: value
            for key, value in control.items()
            if key not in {"provenance_path", "provenance_sha256"}
        },
        "control provenance content mismatch",
    )


def _validate_main_link_records(
    manifest: dict[str, Any],
    capability: dict[str, Any],
    fragments: dict[str, Path],
    root: Path,
    runner_target: Path,
) -> None:
    build = manifest["build"]
    _exact_keys(
        build,
        {
            "cargo_incremental",
            "profile",
            "locked",
            "rustc_flags",
            "linker_flags",
            "codegen_units",
        },
        "build",
    )
    _require(
        build["cargo_incremental"] == "0"
        and build["profile"] == "release"
        and build["locked"] is True
        and build["codegen_units"] == 16,
        "build configuration mismatch",
    )
    expected_rustc_flags = [
        "-C",
        "codegen-units=16",
        "-C",
        "link-arg=-Wl,-T,<target-fragment>",
        "-C",
        "link-arg=-Wl,-Map,<per-target-map>",
        "-C",
        f"linker={manifest['tools']['link_wrapper']['absolute_path']}",
    ]
    if manifest.get("layout_adversary", {}).get("enabled") is True:
        expected_rustc_flags.extend(
            [
                "--cfg",
                "cache_gate_layout_adversary",
                "--check-cfg=cfg(cache_gate_layout_adversary)",
            ]
        )
    _require(
        build["rustc_flags"] == expected_rustc_flags
        and build["linker_flags"]
        == [
            "-Wl,-T,<target-fragment>",
            "-Wl,-Map,<per-target-map>",
        ],
        "build flag manifest is not the exact authenticated vector",
    )
    proof = manifest["build_proof"]
    aggregate_fields = {
        "codegen_units",
        "executables",
        "cgu_partition_fingerprint",
        "object_member_fingerprint",
        "link_order_fingerprint",
        "reserved_input_owner_fingerprint",
    }
    _exact_keys(proof, aggregate_fields, "build proof")
    _require(proof["codegen_units"] == 16, "build proof must use codegen-units=16")
    _exact_keys(
        proof["executables"], set(EXECUTABLE_TARGETS), "build proof executable set"
    )
    all_cgus: list[str] = []
    all_objects: list[str] = []
    all_link_order: list[str] = []
    all_reserved: list[str] = []
    proof_fields = {
        "rustc_argv",
        "emitted_object_members",
        "ordered_linker_inputs",
        "direct_linker_input_files",
        "archive_member_owners",
        "cgu_members",
        "object_member_fingerprint",
        "link_order_fingerprint",
        "cgu_partition_fingerprint",
        "reserved_input_owners",
        "reserved_input_owner_fingerprint",
        "link_command",
        "adversary",
    }
    link_fields = {
        "driver",
        "argv",
        "ordered_linker_inputs",
        "ordered_linker_input_fingerprint",
        "direct_input_files",
        "direct_cgu_members",
        "trace",
        "executable",
        "fragment",
        "link_map",
    }
    for executable, target in EXECUTABLE_TARGETS.items():
        item = proof["executables"][executable]
        _exact_keys(item, proof_fields, f"{executable} build proof")
        _require(
            bool(item["rustc_argv"])
            and all(
                re.search(r"codegen-units(?:=|\s+)16", line)
                for line in item["rustc_argv"]
            ),
            f"{executable}: rustc argv lacks codegen-units=16",
        )
        command = item["link_command"]
        _exact_keys(command, link_fields, f"{executable} link command")
        executable_record = manifest["executables"][executable]
        command_path = _file_record(
            executable_record["link_command"], f"{executable} link command artifact"
        )
        _require(
            _is_contained(root, command_path),
            f"{executable}: link command escapes manifest root",
        )
        _require(
            _json_file(command_path, f"{executable} link command artifact") == command,
            f"{executable}: embedded link command differs from artifact",
        )
        trace = _trace_record(command["trace"], f"{executable} link trace")
        _require(
            _is_contained(root, trace),
            f"{executable}: link trace escapes manifest root",
        )
        trace_record = executable_record["link_trace"]
        _require(
            trace == Path(trace_record["absolute_path"]).resolve()
            and command["trace"]["sha256"] == trace_record["sha256"],
            f"{executable}: link trace record mismatch",
        )
        binary = checked_absolute_file(
            manifest["executables"][executable], f"{executable} binary"
        )
        link_map = checked_absolute_file(
            manifest["executables"][executable]["link_map"], f"{executable} link map"
        )
        regenerated = replay_link_command(
            trace,
            binary,
            capability["linker"],
            fragments[target],
            link_map,
        )
        _require_output_contained(
            regenerated["argv"],
            runner_target,
            f"{executable}: main link output is outside runner target",
        )
        _require(
            regenerated == command,
            f"{executable}: link command differs from authenticated trace",
        )
        _require(
            item["ordered_linker_inputs"] == command["ordered_linker_inputs"],
            f"{executable}: ordered linker inputs mismatch",
        )
        _require(
            item["link_order_fingerprint"]
            == _fingerprint(item["ordered_linker_inputs"]),
            f"{executable}: link-order fingerprint mismatch",
        )
        _require(
            item["object_member_fingerprint"]
            == _fingerprint(item["emitted_object_members"]),
            f"{executable}: object-member fingerprint mismatch",
        )
        _require(
            item["cgu_partition_fingerprint"] == _fingerprint(item["cgu_members"]),
            f"{executable}: CGU fingerprint mismatch",
        )
        _require(
            item["reserved_input_owner_fingerprint"]
            == _fingerprint(item["reserved_input_owners"]),
            f"{executable}: reserved-owner fingerprint mismatch",
        )
        expected_reserved = [
            Path(kernel["input_owner"]).name
            for kernel in manifest["elf_layout"][executable]["kernels"].values()
        ]
        _require(
            item["reserved_input_owners"] == expected_reserved,
            f"{executable}: reserved input owners mismatch",
        )
        all_cgus.extend(f"{executable}:{value}" for value in item["cgu_members"])
        all_objects.extend(
            f"{executable}:{value}" for value in item["emitted_object_members"]
        )
        all_link_order.extend(
            f"{executable}:{value}" for value in item["ordered_linker_inputs"]
        )
        all_reserved.extend(
            f"{executable}:{value}" for value in item["reserved_input_owners"]
        )
    for field, values in (
        ("cgu_partition_fingerprint", all_cgus),
        ("object_member_fingerprint", all_objects),
        ("link_order_fingerprint", all_link_order),
        ("reserved_input_owner_fingerprint", all_reserved),
    ):
        _require(proof[field] == _fingerprint(values), f"aggregate {field} mismatch")


def _run_extractor(
    extractor: Path,
    binary: Path,
    architecture: str,
    target: str,
    output: Path,
    label: str,
) -> None:
    command = [
        str(extractor),
        "--binary",
        str(binary),
        "--arch",
        architecture,
    ]
    for name in TARGET_KERNELS[target]:
        command.extend(("--symbol", f"::{name}$"))
    command.extend(("--output", str(output)))
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    _require(
        completed.returncode == 0,
        f"{label}: authenticated extractor failed: {completed.stderr.strip()}",
    )


def rederive_manifest_layouts(
    manifest: dict[str, Any],
    capability: dict[str, Any],
    capability_path: Path,
    fragments: dict[str, Path],
    tools: dict[str, Path],
    manifest_path: Path,
) -> None:
    root = manifest_path.parent
    readelf_text = shutil.which("readelf")
    _require(bool(readelf_text), "readelf is required to rederive supplied manifest")
    readelf = Path(readelf_text).resolve()
    _require(
        readelf.is_file() and not readelf.is_symlink(), "invalid readelf executable"
    )
    with tempfile.TemporaryDirectory(
        prefix="cache-gate-manifest-validate-"
    ) as temporary:
        temporary_root = Path(temporary)
        for executable, target in EXECUTABLE_TARGETS.items():
            item = manifest["executables"][executable]
            binary = checked_absolute_file(item, f"{executable} binary")
            link_map = checked_absolute_file(item["link_map"], f"{executable} link map")
            symbols_path = _file_record(item["symbols"], f"{executable} symbols")
            layout_path = _file_record(item["layout"], f"{executable} layout")
            _require(
                _is_contained(root, symbols_path) and _is_contained(root, layout_path),
                f"{executable}: artifact path escapes manifest root",
            )
            recorded_symbols = _json_file(symbols_path, f"{executable} symbols")
            recorded_layout = _json_file(layout_path, f"{executable} layout")
            _require(
                recorded_symbols == manifest["symbols"][executable],
                f"{executable}: embedded symbols differ from artifact",
            )
            _require(
                recorded_layout == manifest["elf_layout"][executable],
                f"{executable}: embedded layout differs from artifact",
            )
            regenerated_symbols_path = temporary_root / f"{executable}.symbols.json"
            _run_extractor(
                tools["extractor"],
                binary,
                manifest["architecture"],
                target,
                regenerated_symbols_path,
                executable,
            )
            regenerated_symbols = _json_file(
                regenerated_symbols_path, f"{executable} regenerated symbols"
            )
            _require(
                regenerated_symbols == recorded_symbols,
                f"{executable}: regenerated symbols differ from artifact bytes",
            )
            regenerated_layout = validate_elf(
                argparse.Namespace(
                    binary=binary,
                    link_map=link_map,
                    script=fragments[target],
                    symbols=regenerated_symbols_path,
                    arch=manifest["architecture"],
                    readelf=readelf,
                ),
                capability,
            )
            _require(
                regenerated_layout == recorded_layout,
                f"{executable}: regenerated layout differs from artifact bytes",
            )


def validate_supplied_manifest(
    manifest: dict[str, Any],
    manifest_path: Path,
    capability_document: bytes | None = None,
) -> None:
    _require(
        manifest_path.is_absolute()
        and manifest_path.is_file()
        and not manifest_path.is_symlink(),
        "invalid supplied manifest path",
    )
    # Reject an invalid structural record before reporting ancillary schema gaps.
    # The byte-derived replay below remains authoritative for a valid-looking record.
    validate_manifest(manifest)
    _exact_keys(manifest, SUPPLIED_MANIFEST_KEYS, "manifest")
    _require(
        manifest.get("mode") == "MANIFEST", "supplied manifest mode is not MANIFEST"
    )
    _require(
        manifest.get("architecture") in {"aarch64", "x86_64"},
        "unsupported manifest architecture",
    )
    _validate_manifest_component("variant", manifest.get("variant"))
    _validate_manifest_component("manifest_instance", manifest.get("manifest_instance"))
    runner = _validate_runner(manifest, manifest_path.resolve())
    runner_target = (runner / "target").resolve()
    tools = _validate_tools(manifest["tools"])
    capability, capability_path, fragments = _validate_capability(
        manifest,
        manifest_path.resolve(),
        runner,
        tools,
        capability_document,
    )
    _validate_control(manifest["control"])
    _exact_keys(manifest["symbols"], set(EXECUTABLE_TARGETS), "symbol executable set")
    for executable, target in EXECUTABLE_TARGETS.items():
        _exact_keys(
            manifest["executables"][executable],
            {
                "absolute_path",
                "sha256",
                "link_map",
                "symbols",
                "layout",
                "link_command",
                "link_trace",
                "linker_fragment",
            },
            f"executable {executable}",
        )
        executable_record = manifest["executables"][executable]
        binary = checked_absolute_file(executable_record, f"{executable} binary")
        _require(
            _is_contained(runner_target, binary),
            f"{executable}: binary is outside runner target",
        )
        for field in (
            "link_map",
            "symbols",
            "layout",
            "link_command",
            "link_trace",
            "linker_fragment",
        ):
            artifact = _file_record(executable_record[field], f"{executable} {field}")
            _require(
                _is_contained(manifest_path.resolve().parent, artifact),
                f"{executable}: {field} is outside manifest root",
            )
        _require(
            Path(executable_record["linker_fragment"]["absolute_path"]).resolve()
            == fragments[target]
            and executable_record["linker_fragment"]["sha256"]
            == capability["fragments"][target]["sha256"],
            f"{executable}: linker fragment record mismatch",
        )
        expected_suffixes = {f"::{name}" for name in TARGET_KERNELS[target]}
        symbols = manifest["symbols"][executable]
        _require(
            symbols.get("binary_sha256")
            == manifest["executables"][executable]["sha256"],
            f"{executable}: symbol binary hash mismatch",
        )
        names = [item.get("name", "") for item in symbols.get("symbols", [])]
        _require(
            len(names) == len(expected_suffixes)
            and all(
                sum(name.endswith(suffix) for name in names) == 1
                for suffix in expected_suffixes
            ),
            f"{executable}: exact required symbol set mismatch",
        )
    rederive_manifest_layouts(
        manifest, capability, capability_path, fragments, tools, manifest_path.resolve()
    )
    _validate_main_link_records(
        manifest,
        capability,
        fragments,
        manifest_path.resolve().parent,
        runner_target,
    )


def compare_manifests(
    anchor: dict[str, Any], candidate: dict[str, Any], allowed: set[str]
) -> None:
    unknown = allowed - set(KERNELS)
    _require(not unknown, f"unknown kernel in --allow-body-change: {sorted(unknown)}")
    validate_manifest(anchor)
    validate_manifest(candidate)
    for field in ("arch", "max_page_size", "fragment_set_sha256"):
        _require(
            anchor["linker_capability"].get(field)
            == candidate["linker_capability"].get(field),
            f"linker capability {field} mismatch",
        )
    for field in ("flavor", "version"):
        _require(
            anchor["linker_capability"]["linker"].get(field)
            == candidate["linker_capability"]["linker"].get(field),
            f"linker {field} mismatch",
        )
    for executable, target in EXECUTABLE_TARGETS.items():
        left_layout = anchor["elf_layout"][executable]
        right_layout = candidate["elf_layout"][executable]
        for field in ("fragment_sha256", "fragment_set_sha256", "max_page_size"):
            _require(
                left_layout.get(field) == right_layout.get(field),
                f"{executable}: {field} mismatch",
            )
        for name in TARGET_KERNELS[target]:
            left = left_layout["kernels"][name]
            right = right_layout["kernels"][name]
            for field in PLACEMENT_FIELDS:
                _require(
                    left.get(field) == right.get(field),
                    f"{name}: placement {field} mismatch",
                )
            for sentinel_key in ("reservation_start", "reservation_end"):
                _require(
                    left["sentinels"][sentinel_key] == right["sentinels"][sentinel_key],
                    f"{name}: {sentinel_key} sentinel mismatch",
                )
            if name not in allowed:
                for field in BODY_FIELDS:
                    _require(
                        left.get(field) == right.get(field),
                        f"{name}: body {field} mismatch",
                    )
    if "build_proof" in anchor or "build_proof" in candidate:
        _require(
            "build_proof" in anchor and "build_proof" in candidate,
            "build proof is missing from one manifest",
        )
        left_proof = anchor["build_proof"]
        right_proof = candidate["build_proof"]
        _require(
            left_proof.get("codegen_units") == right_proof.get("codegen_units") == 16,
            "build proof must use -C codegen-units=16",
        )
        for label, proof in (("anchor", left_proof), ("candidate", right_proof)):
            for executable in EXECUTABLE_TARGETS:
                argvs = (
                    proof.get("executables", {})
                    .get(executable, {})
                    .get("rustc_argv", [])
                )
                _require(
                    bool(argvs)
                    and all(
                        re.search(r"codegen-units(?:=|\s+)16", argv) for argv in argvs
                    ),
                    f"{label} {executable}: rustc argv lacks -C codegen-units=16",
                )
        is_adversary = candidate.get("layout_adversary", {}).get("enabled") is True
        proof_fields = (
            "cgu_partition_fingerprint",
            "object_member_fingerprint",
            "link_order_fingerprint",
        )
        if is_adversary:
            for field in proof_fields:
                _require(
                    left_proof.get(field) != right_proof.get(field),
                    f"adversary proof is vacuous: {field} did not differ",
                )
            for executable in EXECUTABLE_TARGETS:
                adversary = right_proof["executables"][executable]["adversary"]
                _require(
                    len(adversary.get("symbol_occurrences", [])) == 1
                    and adversary.get("input_section_occurrences") == 1
                    and adversary.get("outside_reservations") is True,
                    f"adversary symbol/section proof is not exact: {executable}",
                )
        else:
            for field in (*proof_fields, "reserved_input_owner_fingerprint"):
                _require(
                    left_proof.get(field) == right_proof.get(field),
                    f"clean build proof differs: {field}",
                )


def parse_sections(text: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    pattern = re.compile(
        r"^\s*\[\s*(?P<index>\d+)\]\s+(?P<name>\S+)\s+\S+\s+"
        r"(?P<address>[0-9A-Fa-f]+)\s+(?P<offset>[0-9A-Fa-f]+)\s+"
        r"(?P<size>[0-9A-Fa-f]+)\s+\S+\s+(?P<flags>\S+)\s+\S+\s+\S+\s+"
        r"(?P<align>\d+)\s*$"
    )
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            result.append(
                {
                    "name": match.group("name"),
                    "index": int(match.group("index")),
                    "address": int(match.group("address"), 16),
                    "offset": int(match.group("offset"), 16),
                    "size": int(match.group("size"), 16),
                    "flags": match.group("flags"),
                    "alignment": int(match.group("align")),
                }
            )
    return result


def parse_segments(text: str) -> list[dict[str, Any]]:
    segments = []
    pattern = re.compile(
        r"^\s*LOAD\s+(?P<offset>0x[0-9A-Fa-f]+)\s+"
        r"(?P<vaddr>0x[0-9A-Fa-f]+)\s+0x[0-9A-Fa-f]+\s+"
        r"(?P<filesz>0x[0-9A-Fa-f]+)\s+(?P<memsz>0x[0-9A-Fa-f]+)\s+"
        r"(?P<flags>[RWE ]+)\s+(?P<align>0x[0-9A-Fa-f]+)\s*$"
    )
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            flags = "".join(match.group("flags").split())
            segments.append(
                {
                    "offset": int(match.group("offset"), 16),
                    "vaddr": int(match.group("vaddr"), 16),
                    "filesz": int(match.group("filesz"), 16),
                    "memsz": int(match.group("memsz"), 16),
                    "flags": " ".join(flags),
                    "alignment": int(match.group("align"), 16),
                }
            )
    return segments


def parse_symbols(text: str) -> list[dict[str, Any]]:
    symbols = []
    pattern = re.compile(
        r"^\s*\d+:\s+(?P<address>[0-9A-Fa-f]+)\s+(?P<size>\d+)\s+"
        r"(?P<type>\S+)\s+(?P<binding>\S+)\s+(?P<visibility>\S+)\s+"
        r"(?P<section>\S+)\s+(?P<name>\S+)\s*$"
    )
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            symbols.append(
                {
                    "name": match.group("name"),
                    "address": int(match.group("address"), 16),
                    "size": int(match.group("size")),
                    "type": match.group("type"),
                    "binding": match.group("binding"),
                    "visibility": match.group("visibility"),
                    "section": match.group("section"),
                }
            )
    return symbols


def parse_link_map(text: str) -> dict[str, Any]:
    """Parse the structural subset emitted by GNU ld and LLD map files."""

    outputs: list[dict[str, Any]] = []
    inputs: list[dict[str, Any]] = []
    sentinels: dict[str, list[int]] = {}
    sentinel_names = {
        spec[key]
        for spec in KERNELS.values()
        for key in ("reservation_start", "body_end", "reservation_end")
    }

    def add_sentinel(address: int, payload: str) -> bool:
        found = False
        for name in sentinel_names:
            if re.match(rf"^\s*{re.escape(name)}\s*=", payload):
                sentinels.setdefault(name, []).append(address)
                found = True
        return found

    lines = text.splitlines()
    flavor = (
        "lld"
        if lines
        and re.search(r"\bVMA\b.*\bLMA\b.*\bOut\b.*\bIn\b.*\bSymbol\b", lines[0])
        else "gnu"
    )
    current_output: dict[str, Any] | None = None
    if flavor == "lld":
        row = re.compile(
            r"^\s*(?P<vma>[0-9A-Fa-f]+)\s+(?P<lma>[0-9A-Fa-f]+)\s+"
            r"(?P<size>[0-9A-Fa-f]+)\s+(?P<align>\d+)\s+(?P<payload>.*)$"
        )
        input_pattern = re.compile(r"^(?P<owner>.+):\((?P<section>\.[^)]+)\)$")
        for line in lines[1:]:
            match = row.match(line)
            if not match:
                continue
            address = int(match.group("vma"), 16)
            size = int(match.group("size"), 16)
            payload = match.group("payload").strip()
            if add_sentinel(address, payload):
                continue
            input_match = input_pattern.match(payload)
            if input_match:
                record = {
                    "section": input_match.group("section"),
                    "owner": input_match.group("owner"),
                    "start": address,
                    "size": size,
                    "end": address + size,
                    "output": current_output["name"] if current_output else None,
                }
                inputs.append(record)
                if current_output is not None:
                    current_output["inputs"].append(record)
                continue
            if payload.startswith(".") and "=" not in payload:
                name = payload.split()[0]
                current_output = {
                    "name": name,
                    "start": address,
                    "size": size,
                    "end": address + size,
                    "inputs": [],
                }
                outputs.append(current_output)
    else:
        output_header = re.compile(
            r"^(?P<name>\.\S+)(?:\s+(?P<address>0x[0-9A-Fa-f]+)\s+"
            r"(?P<size>0x[0-9A-Fa-f]+))?\s*$"
        )
        input_header = re.compile(
            r"^\s+(?P<name>\.\S+)(?:\s+(?P<address>0x[0-9A-Fa-f]+)\s+"
            r"(?P<size>0x[0-9A-Fa-f]+)\s+(?P<owner>\S+))?\s*$"
        )
        address_row = re.compile(
            r"^\s*(?P<address>0x[0-9A-Fa-f]+)\s+"
            r"(?P<size>0x[0-9A-Fa-f]+)(?:\s+(?P<owner>\S+))?\s*$"
        )
        symbol_row = re.compile(r"^\s*(?P<address>0x[0-9A-Fa-f]+)\s+(?P<payload>.*)$")
        pending_output: dict[str, Any] | None = None
        pending_input: dict[str, Any] | None = None
        for line in lines:
            symbol_match = symbol_row.match(line)
            if symbol_match and add_sentinel(
                int(symbol_match.group("address"), 16), symbol_match.group("payload")
            ):
                continue
            output_match = output_header.match(line)
            if output_match:
                current_output = {
                    "name": output_match.group("name"),
                    "start": (
                        int(output_match.group("address"), 16)
                        if output_match.group("address")
                        else None
                    ),
                    "size": (
                        int(output_match.group("size"), 16)
                        if output_match.group("size")
                        else None
                    ),
                    "end": None,
                    "inputs": [],
                }
                if current_output["start"] is not None:
                    current_output["end"] = (
                        current_output["start"] + current_output["size"]
                    )
                outputs.append(current_output)
                pending_output = (
                    current_output if current_output["start"] is None else None
                )
                pending_input = None
                continue
            input_match = input_header.match(line)
            if input_match and not line.lstrip().startswith(("*(", "*fill*")):
                record = {
                    "section": input_match.group("name"),
                    "owner": input_match.group("owner") or "",
                    "start": (
                        int(input_match.group("address"), 16)
                        if input_match.group("address")
                        else None
                    ),
                    "size": (
                        int(input_match.group("size"), 16)
                        if input_match.group("size")
                        else None
                    ),
                    "end": None,
                    "output": current_output["name"] if current_output else None,
                }
                if record["start"] is not None:
                    record["end"] = record["start"] + record["size"]
                inputs.append(record)
                if current_output is not None:
                    current_output["inputs"].append(record)
                pending_input = record if record["start"] is None else None
                continue
            address_match = address_row.match(line)
            if address_match and pending_output is not None:
                pending_output["start"] = int(address_match.group("address"), 16)
                pending_output["size"] = int(address_match.group("size"), 16)
                pending_output["end"] = pending_output["start"] + pending_output["size"]
                pending_output = None
                continue
            if address_match and pending_input is not None:
                pending_input["start"] = int(address_match.group("address"), 16)
                pending_input["size"] = int(address_match.group("size"), 16)
                pending_input["end"] = pending_input["start"] + pending_input["size"]
                pending_input["owner"] = address_match.group("owner") or ""
                pending_input = None

    return {
        "flavor": flavor,
        "outputs": outputs,
        "inputs": inputs,
        "sentinels": sentinels,
    }


def _decode_capability_document(encoded: str, label: str) -> bytes:
    try:
        return base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise LayoutError(f"invalid {label}") from error


def _load_capability() -> dict[str, Any]:
    encoded = os.environ.get("CACHE_GATE_LINKER_CAPABILITY_DOCUMENT_B64")
    if encoded:
        return json.loads(_decode_capability_document(encoded, "capability document"))
    path = os.environ.get("CACHE_GATE_LINKER_CAPABILITY")
    if not path:
        raise LayoutError("CACHE_GATE_LINKER_CAPABILITY is required for validate")
    capability_path = Path(path)
    if not capability_path.is_absolute() or not capability_path.is_file():
        raise LayoutError("CACHE_GATE_LINKER_CAPABILITY must be an absolute file")
    identity = os.environ.get("CACHE_GATE_LINKER_CAPABILITY_IDENTITY")
    if identity:
        return json.loads(_read_verified_staged_capability(capability_path, identity))
    return json.loads(capability_path.read_text())


def validate_elf(
    args: argparse.Namespace, capability: dict[str, Any] | None = None
) -> dict[str, Any]:
    binary = args.binary.resolve()
    link_map = args.link_map.resolve()
    script = args.script.resolve()
    symbols_path = args.symbols.resolve()
    for path, label in (
        (binary, "binary"),
        (link_map, "link map"),
        (script, "script"),
        (symbols_path, "symbols"),
    ):
        if not path.is_file() or path.is_symlink():
            raise LayoutError(f"invalid {label}: {path}")
    capability = capability if capability is not None else _load_capability()
    target = next(
        (
            name
            for name, record in capability["fragments"].items()
            if record.get("absolute_path") == str(script)
        ),
        None,
    )
    if target is None:
        target = next((name for name in TARGET_KERNELS if name in script.name), None)
    if target not in TARGET_KERNELS:
        raise LayoutError(f"cannot identify target fragment: {script}")
    expected_script_hash = capability["fragments"][target]
    if isinstance(expected_script_hash, dict):
        expected_script_hash = expected_script_hash["sha256"]
    _require(digest(script) == expected_script_hash, "target fragment hash mismatch")
    readelf = str(getattr(args, "readelf", "readelf"))
    header = run(readelf, "-hW", str(binary))
    section_text = run(readelf, "-SW", str(binary))
    segment_text = run(readelf, "-lW", str(binary))
    symbol_text = run(readelf, "-sW", str(binary))
    section_records = parse_sections(section_text)
    sections_by_name: dict[str, list[dict[str, Any]]] = {}
    for section in section_records:
        sections_by_name.setdefault(section["name"], []).append(section)
    segments = parse_segments(segment_text)
    elf_type_match = re.search(r"^\s*Type:\s+(\S+)", header, re.MULTILINE)
    elf_type = f"ET_{elf_type_match.group(1)}" if elf_type_match else "UNKNOWN"
    symbol_table = parse_symbols(symbol_text)
    extracted = json.loads(symbols_path.read_text())
    selected_symbols = extracted.get("symbols", [])
    map_text = link_map.read_text(errors="replace")
    parsed_map = parse_link_map(map_text)
    max_page = int(capability["max_page_size"])
    expected_outputs = {KERNELS[name]["output"] for name in TARGET_KERNELS[target]}
    elf_cache_gate_outputs = {
        section["name"]
        for section in section_records
        if section["name"].startswith(".opthash.cache_gate.")
    }
    map_cache_gate_outputs = {
        output["name"]
        for output in parsed_map["outputs"]
        if output["name"].startswith(".opthash.cache_gate.")
    }
    _require(
        elf_cache_gate_outputs == expected_outputs,
        "ELF cache-gate output section set does not match exact target shape",
    )
    _require(
        map_cache_gate_outputs == expected_outputs,
        "link-map cache-gate output section set does not match exact target shape",
    )
    kernel_records: dict[str, Any] = {}
    for name in TARGET_KERNELS[target]:
        spec = KERNELS[name]
        output_matches = sections_by_name.get(spec["output"], [])
        _require(
            len(output_matches) == 1,
            f"{name}: output_section_count must be 1 for {spec['output']}",
        )
        output = output_matches[0]
        map_outputs = [
            record
            for record in parsed_map["outputs"]
            if record["name"] == spec["output"]
        ]
        _require(
            len(map_outputs) == 1,
            f"{name}: link-map output_section_count must be 1",
        )
        map_output = map_outputs[0]
        _require(
            map_output["start"] == output["address"]
            and map_output["size"] == output["size"]
            and map_output["end"] == output["address"] + output["size"],
            f"{name}: link-map output extent differs from ELF section",
        )
        matching_inputs = [
            record
            for record in parsed_map["inputs"]
            if record["section"] == spec["input"]
        ]
        nested_inputs = [
            record for record in matching_inputs if record["output"] == spec["output"]
        ]
        _require(
            len(matching_inputs) == 1 and len(nested_inputs) == 1,
            f"{name}: input section must occur once in exact output section",
        )
        input_record = nested_inputs[0]
        _require(bool(input_record["owner"]), f"{name}: input owner is missing")
        matching_selected = [
            item for item in selected_symbols if item["name"].endswith(f"::{name}")
        ]
        _require(
            len(matching_selected) == 1, f"{name}: function_symbol_count must be 1"
        )
        selected = matching_selected[0]
        sentinel_records: dict[str, Any] = {}
        link_map_sentinels: dict[str, int] = {}
        for key in ("reservation_start", "body_end", "reservation_end"):
            matches = [item for item in symbol_table if item["name"] == spec[key]]
            sentinel = matches[0] if matches else {}
            sentinel_records[key] = {
                "name": spec[key],
                "address": sentinel.get("address"),
                "binding": sentinel.get("binding"),
                "visibility": sentinel.get("visibility"),
                "defined": sentinel.get("section") not in {None, "UND"},
                "count": len(matches),
            }
            map_matches = parsed_map["sentinels"].get(spec[key], [])
            link_map_sentinels[key] = map_matches[0] if len(map_matches) == 1 else -1
        start = sentinel_records["reservation_start"]["address"]
        body_end = sentinel_records["body_end"]["address"]
        end = sentinel_records["reservation_end"]["address"]
        containing = [
            segment
            for segment in segments
            if start is not None
            and end is not None
            and segment["vaddr"] <= start
            and end <= segment["vaddr"] + segment["memsz"]
        ]
        writable = [
            segment
            for segment in segments
            if "W" in segment["flags"]
            and start is not None
            and end is not None
            and start < segment["vaddr"] + segment["memsz"]
            and segment["vaddr"] < end
        ]
        overlapping_sections = [
            section["name"]
            for section in section_records
            if section["name"] != spec["output"]
            and section["size"] > 0
            and start is not None
            and end is not None
            and start < section["address"] + section["size"]
            and section["address"] < end
        ]
        veneer_inventory = extracted.get("linker_generated_veneer_thunks", [])
        veneers = [
            item["name"]
            for item in veneer_inventory
            if start is not None and end is not None and start <= item["start"] < end
        ]
        direct_calls = selected.get("direct_calls", [])
        kernel_records[name] = {
            "name": name,
            "function_symbol_count": len(matching_selected),
            "input_section": spec["input"],
            "input_section_count": len(matching_inputs),
            "input_owner": input_record["owner"],
            "input_start": input_record["start"],
            "input_end": input_record["end"],
            "input_size": input_record["size"],
            "output_section": spec["output"],
            "output_section_count": len(output_matches),
            "output_section_index": output["index"],
            "output_start": output["address"],
            "output_end": output["address"] + output["size"],
            "reservation_start": start,
            "body_end": body_end,
            "reservation_end": end,
            "body_size": body_end - start
            if start is not None and body_end is not None
            else None,
            "reservation_size": end - start
            if start is not None and end is not None
            else None,
            "page_offset": start % 4096 if start is not None else None,
            "max_page_remainder": start % max_page if start is not None else None,
            "sh_addralign": output["alignment"],
            "section_flags": [
                name
                for name, flag in (("ALLOC", "A"), ("EXECINSTR", "X"))
                if flag in output["flags"]
            ],
            "pt_load_count": len(containing),
            "pt_load_flags": containing[0]["flags"] if len(containing) == 1 else "",
            "writable_segment_overlap": bool(writable),
            "overlapping_elf_sections": overlapping_sections,
            "sentinels": sentinel_records,
            "link_map_sentinels": link_map_sentinels,
            "function_start": selected.get("start"),
            "function_end": selected.get("end"),
            "function_size": selected.get("size"),
            "function_section_index": selected.get("section_index"),
            "function_section_name": selected.get(
                "section_name", selected.get("section")
            ),
            "raw_sha256": selected.get("raw_sha256"),
            "normalized_sha256": selected.get("normalized_instructions_sha256"),
            "direct_calls": direct_calls,
            "indirect_calls": selected.get("indirect_calls"),
            "frame_bytes": selected.get("frame_adjustment"),
            "spills": selected.get("spills"),
            "veneer_thunks": veneers,
            "plt_calls": [call for call in direct_calls if "@plt" in call.lower()],
        }
    fragment_set = capability["fragment_set_sha256"]
    record = {
        "target": target,
        "arch": args.arch,
        "link_map_flavor": parsed_map["flavor"],
        "elf_type": elf_type,
        "binary": str(binary),
        "binary_sha256": digest(binary),
        "link_map": str(link_map),
        "link_map_sha256": digest(link_map),
        "fragment_sha256": digest(script),
        "fragment_set_sha256": fragment_set,
        "max_page_size": max_page,
        "program_headers_have_rwx": any(
            set(segment["flags"].split()) == {"R", "W", "E"} for segment in segments
        ),
        "program_headers": segments,
        "archive_member_owners": sorted(
            {
                record["owner"]
                for record in parsed_map["inputs"]
                if re.search(r"\.(?:a|rlib)\([^)]+\)$", record["owner"])
            }
        ),
        "cache_gate_input_sections": [
            record
            for record in parsed_map["inputs"]
            if record["section"].startswith(".text.opthash.cache_gate.")
        ],
        "kernels": kernel_records,
        "veneer_thunk_inventory": extracted.get("linker_generated_veneer_thunks", []),
        "plt_inventory": [
            item["name"] for item in symbol_table if "@plt" in item["name"].lower()
        ],
    }
    validate_layout_record(record, target)
    return record


def _write_json_atomic(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def authenticate_tools(args: argparse.Namespace) -> dict[str, Any]:
    parsed: list[tuple[str, Path, Path, str, str]] = []
    names: set[str] = set()
    for item in args.tool:
        name, separator, path_text = item.partition("=")
        _require(separator == "=" and bool(name), f"invalid --tool record: {item}")
        _require(name not in names, f"duplicate --tool name: {name}")
        names.add(name)
        original = Path(path_text)
        _require(original.is_absolute(), f"tool path must be absolute: {name}")
        _require(
            original.is_file() and not original.is_symlink(),
            f"invalid tool path: {name}",
        )
        path = original.resolve()
        root = Path(
            run("git", "-C", str(path.parent), "rev-parse", "--show-toplevel").strip()
        ).resolve()
        try:
            relative = path.relative_to(root)
        except ValueError as error:
            raise LayoutError(f"tool is outside reviewed root: {name}") from error
        commit = run("git", "-C", str(root), "rev-parse", "HEAD").strip()
        tree = run("git", "-C", str(root), "rev-parse", "HEAD^{tree}").strip()
        parsed.append((name, path, root, str(relative), f"{commit}:{tree}"))
    roots = {record[2] for record in parsed}
    revisions = {record[4] for record in parsed}
    _require(
        len(roots) == 1 and len(revisions) == 1,
        "authenticated tools must come from one reviewed root and revision",
    )
    records: dict[str, Any] = {}
    for name, path, root, relative, revision in parsed:
        commit, tree = revision.split(":", 1)
        blob = run("git", "-C", str(root), "rev-parse", f"HEAD:{relative}").strip()
        completed = subprocess.run(
            ["git", "-C", str(root), "cat-file", "blob", blob],
            capture_output=True,
            check=False,
        )
        _require(
            completed.returncode == 0,
            f"cannot read reviewed Git blob for tool: {name}",
        )
        blob_sha256 = hashlib.sha256(completed.stdout).hexdigest()
        working_sha256 = digest(path)
        _require(
            working_sha256 == blob_sha256,
            f"tool working bytes differ from reviewed Git blob: {name}",
        )
        records[name] = {
            "absolute_path": str(path),
            "sha256": working_sha256,
            "git_blob": blob,
            "git_blob_sha256": blob_sha256,
            "reviewed_root": str(root),
            "reviewed_commit": commit,
            "reviewed_tree": tree,
        }
    return records


def _link_command_inputs(argv: list[str]) -> tuple[list[str], list[str]]:
    """Return stable names for actual object/archive/library linker inputs."""

    file_suffix = re.compile(r"(?:\.o|\.rlib|\.a|\.so(?:\.[^/]+)*)$")
    ordered: list[str] = []
    direct_files: list[str] = []
    for token in argv:
        if token.startswith("-l") and len(token) > 2:
            ordered.append(token)
            continue
        if token.startswith("-") or not file_suffix.search(token):
            continue
        path = Path(token)
        _require(path.is_absolute(), f"captured linker input is not absolute: {token}")
        name = path.name
        ordered.append(name)
        direct_files.append(name)
    _require(
        bool(ordered), "captured link command has no object/archive/library inputs"
    )
    return ordered, sorted(set(direct_files))


def validate_link_command(args: argparse.Namespace) -> dict[str, Any]:
    for path, label in (
        (args.trace, "trace"),
        (args.executable, "executable"),
        (args.fragment, "fragment"),
        (args.link_map, "link map"),
    ):
        _require(path.is_absolute(), f"--{label.replace(' ', '-')} must be absolute")
        _require(path.is_file() and not path.is_symlink(), f"invalid {label}: {path}")
    _require(
        bool(args.capability) != bool(args.capability_document_b64),
        "provide exactly one capability path or held capability document",
    )
    if args.capability_document_b64:
        capability_bytes = _decode_capability_document(
            args.capability_document_b64, "held capability document"
        )
    else:
        _require(args.capability.is_absolute(), "--capability must be absolute")
        _require(
            args.capability.is_file() and not args.capability.is_symlink(),
            f"invalid capability: {args.capability}",
        )
        capability_bytes = (
            _read_verified_staged_capability(args.capability, args.capability_identity)
            if args.capability_identity
            else args.capability.read_bytes()
        )
    capability = json.loads(capability_bytes)
    linker = capability.get("linker", {})
    return replay_link_command(
        args.trace.resolve(),
        args.executable.resolve(),
        linker,
        args.fragment.resolve(),
        args.link_map.resolve(),
    )


def _raw_output_values(argv: list[str]) -> list[str]:
    def collect(tokens: list[str]) -> list[str]:
        outputs: list[str] = []
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token in ("-o", "--output"):
                if index + 1 < len(tokens):
                    outputs.append(tokens[index + 1])
                    index += 2
                    continue
            elif token.startswith("--output="):
                outputs.append(token.removeprefix("--output="))
            elif token.startswith("-o") and len(token) > 2:
                outputs.append(token[2:])
            index += 1
        return outputs

    direct: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "-Xlinker" and index + 1 < len(argv):
            index += 2
            continue
        if token.startswith(("-Xlinker=", "-Wl,")):
            index += 1
            continue
        direct.append(token)
        index += 1
    outputs = collect(direct)
    forwarded: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token.startswith("-Wl,"):
            forwarded.extend(token.removeprefix("-Wl,").split(","))
        elif token == "-Xlinker" and index + 1 < len(argv):
            forwarded.append(argv[index + 1])
            index += 1
        elif token.startswith("-Xlinker="):
            forwarded.append(token.removeprefix("-Xlinker="))
        index += 1
    outputs.extend(collect(forwarded))
    return outputs


def _output_path(argv: list[str]) -> Path | None:
    outputs = _raw_output_values(argv)
    return Path(outputs[0]).resolve() if len(outputs) == 1 else None


def _raw_output_matches(argv: list[str], executable: Path) -> bool:
    return _raw_output_values(argv) == [str(executable)]


def _cargo_output_alias(argv: list[str], executable: Path) -> Path:
    outputs = _raw_output_values(argv)
    _require(len(outputs) == 1, "capability trace lacks one exact Cargo output")
    raw_text = outputs[0]
    raw_output = Path(raw_text)
    _require(
        raw_output.is_absolute()
        and raw_text == str(raw_output.resolve(strict=True))
        and executable.is_absolute()
        and str(executable) == str(executable.resolve(strict=True)),
        "capability Cargo output alias is not canonical",
    )
    _require(
        raw_output.parent == executable.parent / "deps"
        and re.fullmatch(
            rf"{re.escape(executable.name)}-[0-9a-f]{{16}}", raw_output.name
        )
        is not None,
        "capability Cargo output alias has unexpected path",
    )
    raw_stat = raw_output.stat(follow_symlinks=False)
    executable_stat = executable.stat(follow_symlinks=False)
    _require(
        stat.S_ISREG(raw_stat.st_mode)
        and stat.S_ISREG(executable_stat.st_mode)
        and raw_stat.st_nlink == executable_stat.st_nlink == 2
        and (raw_stat.st_dev, raw_stat.st_ino)
        == (executable_stat.st_dev, executable_stat.st_ino),
        "capability Cargo output alias is not exact hardlink pair",
    )
    return raw_output


def _output_matches(argv: list[str], executable: Path) -> bool:
    return _raw_output_matches(argv, executable)


def _require_output_contained(argv: list[str], root: Path, message: str) -> None:
    output = _output_path(argv)
    _require(output is not None and _is_contained(root, output), message)


def validate_linker_execution(args: argparse.Namespace) -> dict[str, Any]:
    for path, label in (
        (args.trace, "trace"),
        (args.linker_record, "linker record"),
        (args.executable, "executable"),
    ):
        _require(path.is_absolute(), f"--{label} must be absolute")
        _require(path.is_file() and not path.is_symlink(), f"invalid {label}: {path}")
    linker_record = _json_file(args.linker_record, "linker record")
    linker = _verify_linker_record(linker_record, "linker record")
    executable = args.executable.resolve()
    if args.flavor == "gnu":
        _require(
            linker_record["flavor"] == "GNU ld"
            and linker_record["version_argument"] == "--version",
            "explicit linker is not GNU ld",
        )
    elif args.flavor == "lld":
        _require(
            linker_record["flavor"] == "LLD"
            and linker_record["version_argument"] == "--version",
            "explicit linker is not LLD",
        )
    else:
        _require(
            linker_record["flavor"] in {"GNU ld", "LLD"}
            and linker_record["version_argument"] == "-Wl,--version",
            "actual linker is not a compiler driver for GNU ld/LLD",
        )
    records = [
        json.loads(line) for line in args.trace.read_text().splitlines() if line.strip()
    ]
    for index, candidate in enumerate(records):
        _validate_link_trace_record(candidate, f"explicit linker trace record {index}")
    matches: list[tuple[dict[str, Any], Path]] = []
    for candidate in records:
        if not isinstance(candidate.get("argv"), list):
            continue
        try:
            raw_output = _cargo_output_alias(candidate["argv"], executable)
        except LayoutError:
            continue
        matches.append((candidate, raw_output))
    _require(
        len(matches) == 1,
        f"expected one observed explicit linker execution, got {len(matches)}",
    )
    record, raw_output = matches[0]
    observed = record.get("payload_path", "")
    _require(
        isinstance(observed, str) and observed == str(linker),
        "observed linker differs from required explicit linker",
    )
    _require(
        record.get("payload_sha256") == linker_record["payload_sha256"]
        and record.get("argv0") == linker_record["argv0"],
        "observed linker hash differs from required explicit linker",
    )
    role = record.get("role")
    session = record.get("session")
    _require(
        (role is None and session is None)
        or (
            isinstance(role, str)
            and bool(role)
            and isinstance(session, str)
            and bool(session)
        ),
        "observed linker role/session is incomplete",
    )
    result = {
        "linker": linker_record,
        "argv": record["argv"],
        "executable": str(executable),
        "raw_output": str(raw_output),
        "trace": {
            "absolute_path": str(args.trace.resolve()),
            "sha256": digest(args.trace),
            "record_count": len(records),
            "final_link_record_count": len(matches),
        },
    }
    if role is not None:
        cwd = record.get("cwd")
        embedded_path = record.get("path")
        _require(
            isinstance(cwd, str)
            and Path(cwd).is_absolute()
            and Path(cwd).is_dir()
            and isinstance(embedded_path, str)
            and bool(embedded_path),
            "observed linker environment is incomplete",
        )
        result["role"] = role
        result["session"] = session
        result["cwd"] = cwd
        result["path"] = embedded_path
    return result


def select_cargo_executable(args: argparse.Namespace) -> Path:
    _require(
        args.cargo_output.is_absolute()
        and args.cargo_output.is_file()
        and not args.cargo_output.is_symlink(),
        "--cargo-output must be an absolute regular file",
    )
    paths: set[Path] = set()
    success = False
    for line in args.cargo_output.read_text().splitlines():
        if not line.startswith("{"):
            continue
        event = json.loads(line)
        if (
            event.get("reason") == "compiler-artifact"
            and event.get("target", {}).get("name") == args.bench
            and event.get("executable")
        ):
            paths.add(Path(event["executable"]).resolve())
        if event.get("reason") == "build-finished":
            success = event.get("success") is True
    _require(
        success and len(paths) == 1,
        f"expected one successful Cargo executable, got {sorted(map(str, paths))}",
    )
    executable = next(iter(paths))
    _require(executable.is_file(), f"Cargo executable does not exist: {executable}")
    return executable


def _parse_cargo_link_argv(link_args: Path) -> tuple[dict[str, str], str, list[str]]:
    lines = [
        line.strip() for line in link_args.read_text().splitlines() if line.strip()
    ]
    _require(bool(lines), "Cargo link arguments are empty")
    tokens = shlex.split(lines[-1])
    environment: dict[str, str] = {}
    command_index = 0
    for command_index, token in enumerate(tokens):
        name, separator, value = token.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            break
        environment[name] = value
    else:
        command_index = len(tokens)
    _require(command_index < len(tokens), "Cargo link arguments contain no command")
    return environment, tokens[command_index], tokens[command_index + 1 :]


def resolve_cargo_linker(args: argparse.Namespace) -> Path:
    _require(
        args.link_args.is_absolute()
        and args.link_args.is_file()
        and not args.link_args.is_symlink(),
        "--link-args must be an absolute regular file",
    )
    environment, command, _ = _parse_cargo_link_argv(args.link_args)
    command_path = Path(command)
    if command_path.is_absolute():
        resolved = command_path
    else:
        _require("/" not in command, "relative Cargo linker command is unsupported")
        embedded_path = environment.get("PATH")
        _require(embedded_path is not None, "Cargo link arguments lack embedded PATH")
        search = embedded_path.split(os.pathsep)
        _require(
            bool(search)
            and all(value and Path(value).is_absolute() for value in search),
            "Cargo embedded PATH must contain only absolute directories",
        )
        resolved = next(
            (
                Path(directory) / command
                for directory in search
                if (Path(directory) / command).is_file()
                and os.access(Path(directory) / command, os.X_OK)
            ),
            None,
        )
        _require(resolved is not None, "cannot resolve linker from Cargo embedded PATH")
    driver = resolved.resolve(strict=True)
    _require(
        driver.is_file() and not driver.is_symlink() and os.access(driver, os.X_OK),
        "resolved Cargo linker is not a canonical executable",
    )
    return driver


def _capability_stage_validator(
    args: argparse.Namespace,
) -> Callable[[Path, dict[str, Any]], str]:
    _require(args.tools.is_absolute(), "--tools must be absolute")
    _require(
        args.tools.is_file()
        and not args.tools.is_symlink()
        and args.tools == args.tools.resolve(strict=True),
        "invalid authenticated tools path",
    )
    tool_records = _json_file(args.tools, "authenticated tools")
    tools = _validate_tools(tool_records)

    def validate_staged(staged: Path, capability: dict[str, Any]) -> str:
        embedded = {
            **capability,
            "copy": {"absolute_path": str(staged), "sha256": digest(staged)},
        }
        manifest = {
            "architecture": args.arch,
            "linker_capability": embedded,
            "tools": tool_records,
        }
        producer_root = Path(capability["producer"]["runner_root"])
        validated, _, _ = _validate_capability(
            manifest,
            staged.parent / "manifest.json",
            producer_root,
            tools,
        )
        driver = _verify_linker_record(validated["linker"], "capability linker")
        return str(driver)

    return validate_staged


def stage_validate_capability(args: argparse.Namespace) -> tuple[str, str, str]:
    return _stage_capability_once(
        args.input, args.output, _capability_stage_validator(args)
    )


def _serve_capability_guard(
    guard: _CapabilityGuard,
    command_stream: Any,
    response_stream: Any,
    manifest_validator: Callable[[dict[str, Any], Path, bytes], None] | None = None,
    manifest_path: Path | None = None,
) -> int:
    print(guard.result, file=response_stream, flush=True)
    print(guard.identity, file=response_stream, flush=True)
    print(
        base64.b64encode(guard.source_bytes).decode("ascii"),
        file=response_stream,
        flush=True,
    )
    print("READY", file=response_stream, flush=True)
    poller = select.poll()
    poller.register(
        command_stream.fileno(), select.POLLIN | select.POLLHUP | select.POLLERR
    )
    assert guard.inotify_descriptor is not None
    poller.register(
        guard.inotify_descriptor,
        select.POLLIN | select.POLLHUP | select.POLLERR,
    )
    while True:
        for descriptor, event in poller.poll():
            if descriptor == guard.inotify_descriptor:
                guard._drain_events()
                continue
            if event & (select.POLLHUP | select.POLLERR):
                raise LayoutError("capability guardian command channel closed")
            command = command_stream.readline()
            if not command:
                raise LayoutError("capability guardian command channel reached EOF")
            command = command.rstrip("\n")
            if command == "CHECK":
                guard.checkpoint()
                print("OK", file=response_stream, flush=True)
            elif command == "FINALIZE":
                _require(
                    manifest_path is not None, "guardian lacks pending manifest path"
                )
                guard.finalize(manifest_path, manifest_validator)
                print("COMMITTED", file=response_stream, flush=True)
                print(
                    guard.manifest_publish_identity,
                    file=response_stream,
                    flush=True,
                )
                return 0
            elif command == "ABORT":
                print("ABORTED", file=response_stream, flush=True)
                return 0
            else:
                raise LayoutError("invalid capability guardian command")


def guard_capability(args: argparse.Namespace) -> int:
    guard = _CapabilityGuard.stage(
        args.input, args.output, _capability_stage_validator(args)
    )
    remove_stage = True
    try:
        result = _serve_capability_guard(
            guard,
            sys.stdin,
            sys.stdout,
            validate_supplied_manifest,
            args.manifest_pending,
        )
        remove_stage = not guard.committed
        return result
    finally:
        guard.close(remove_stage=remove_stage)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--binary", type=Path, required=True)
    validate_parser.add_argument("--link-map", type=Path, required=True)
    validate_parser.add_argument("--script", type=Path, required=True)
    validate_parser.add_argument("--symbols", type=Path, required=True)
    validate_parser.add_argument("--arch", choices=("aarch64", "x86_64"), required=True)
    validate_parser.add_argument("--output", type=Path, required=True)
    compare_parser = subparsers.add_parser("compare")
    compare_parser.add_argument("--anchor", type=Path, required=True)
    compare_parser.add_argument("--candidate", type=Path, required=True)
    compare_parser.add_argument("--allow-body-change", action="append", default=[])
    manifest_parser = subparsers.add_parser("validate-manifest")
    manifest_parser.add_argument("--manifest", type=Path, required=True)
    manifest_parser.add_argument("--capability-document-b64")
    tools_parser = subparsers.add_parser("authenticate-tools")
    tools_parser.add_argument("--output", type=Path, required=True)
    tools_parser.add_argument("--tool", action="append", required=True)
    link_parser = subparsers.add_parser("validate-link-command")
    link_parser.add_argument("--trace", type=Path, required=True)
    link_parser.add_argument("--executable", type=Path, required=True)
    link_parser.add_argument("--capability", type=Path)
    link_parser.add_argument("--capability-document-b64")
    link_parser.add_argument("--capability-identity")
    link_parser.add_argument("--fragment", type=Path, required=True)
    link_parser.add_argument("--link-map", type=Path, required=True)
    link_parser.add_argument("--output", type=Path, required=True)
    linker_execution_parser = subparsers.add_parser("validate-linker-execution")
    linker_execution_parser.add_argument("--trace", type=Path, required=True)
    linker_execution_parser.add_argument("--linker-record", type=Path, required=True)
    linker_execution_parser.add_argument("--executable", type=Path, required=True)
    linker_execution_parser.add_argument(
        "--flavor", choices=("actual", "gnu", "lld"), required=True
    )
    linker_execution_parser.add_argument("--output", type=Path, required=True)
    inspect_linker_parser = subparsers.add_parser("inspect-linker-record")
    inspect_linker_parser.add_argument("--invocation-path", type=Path, required=True)
    inspect_linker_parser.add_argument("--argv0", required=True)
    inspect_linker_parser.add_argument(
        "--flavor", choices=("actual", "gnu", "lld"), required=True
    )
    inspect_linker_parser.add_argument("--extraction-root", type=Path)
    inspect_linker_parser.add_argument("--output", type=Path, required=True)
    verify_linker_parser = subparsers.add_parser("verify-linker-record")
    verify_linker_parser.add_argument("--record", type=Path, required=True)
    cargo_parser = subparsers.add_parser("select-cargo-executable")
    cargo_parser.add_argument("--cargo-output", type=Path, required=True)
    cargo_parser.add_argument("--bench", required=True)
    cargo_linker_parser = subparsers.add_parser("resolve-cargo-linker")
    cargo_linker_parser.add_argument("--link-args", type=Path, required=True)
    stage_capability_parser = subparsers.add_parser("stage-validate-capability")
    stage_capability_parser.add_argument("--input", type=Path, required=True)
    stage_capability_parser.add_argument("--output", type=Path, required=True)
    stage_capability_parser.add_argument(
        "--arch", choices=("aarch64", "x86_64"), required=True
    )
    stage_capability_parser.add_argument("--tools", type=Path, required=True)
    guard_capability_parser = subparsers.add_parser("guard-capability")
    guard_capability_parser.add_argument("--input", type=Path, required=True)
    guard_capability_parser.add_argument("--output", type=Path, required=True)
    guard_capability_parser.add_argument(
        "--arch", choices=("aarch64", "x86_64"), required=True
    )
    guard_capability_parser.add_argument("--tools", type=Path, required=True)
    guard_capability_parser.add_argument("--manifest-pending", type=Path, required=True)
    publish_manifest_parser = subparsers.add_parser("publish-guarded-manifest")
    publish_manifest_parser.add_argument("--input", type=Path, required=True)
    publish_manifest_parser.add_argument("--output", type=Path, required=True)
    publish_manifest_parser.add_argument("--identity", required=True)
    publish_manifest_parser.add_argument("--held-fd-path", type=Path)
    private_pending_parser = subparsers.add_parser("write-private-pending")
    private_pending_parser.add_argument("--output", type=Path, required=True)
    verify_capability_parser = subparsers.add_parser("verify-staged-capability")
    verify_capability_parser.add_argument("--path", type=Path, required=True)
    verify_capability_parser.add_argument("--identity", required=True)
    args = parser.parse_args()
    try:
        if args.command == "validate":
            for field in ("binary", "link_map", "script", "symbols", "output"):
                if not getattr(args, field).is_absolute():
                    raise LayoutError(f"--{field.replace('_', '-')} must be absolute")
            record = validate_elf(args)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            temporary = args.output.with_suffix(args.output.suffix + ".tmp")
            temporary.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
            temporary.replace(args.output)
        elif args.command == "compare":
            if not args.anchor.is_absolute() or not args.candidate.is_absolute():
                raise LayoutError("--anchor and --candidate must be absolute")
            anchor = json.loads(args.anchor.read_text())
            candidate = json.loads(args.candidate.read_text())
            compare_manifests(anchor, candidate, set(args.allow_body_change))
        elif args.command == "validate-manifest":
            if not args.manifest.is_absolute():
                raise LayoutError("--manifest must be absolute")
            validate_supplied_manifest(
                json.loads(args.manifest.read_text()),
                args.manifest,
                (
                    _decode_capability_document(
                        args.capability_document_b64,
                        "held capability document",
                    )
                    if args.capability_document_b64
                    else None
                ),
            )
        elif args.command == "authenticate-tools":
            if not args.output.is_absolute():
                raise LayoutError("--output must be absolute")
            _write_json_atomic(args.output, authenticate_tools(args))
        elif args.command == "validate-link-command":
            if not args.output.is_absolute():
                raise LayoutError("--output must be absolute")
            _write_json_atomic(args.output, validate_link_command(args))
        elif args.command == "validate-linker-execution":
            if not args.output.is_absolute():
                raise LayoutError("--output must be absolute")
            _write_json_atomic(args.output, validate_linker_execution(args))
        elif args.command == "inspect-linker-record":
            if not args.output.is_absolute():
                raise LayoutError("--output must be absolute")
            _write_json_atomic(
                args.output,
                _inspect_linker_record(
                    args.invocation_path,
                    args.argv0,
                    args.flavor,
                    args.extraction_root,
                ),
            )
        elif args.command == "verify-linker-record":
            if not args.record.is_absolute():
                raise LayoutError("--record must be absolute")
            _verify_linker_record(
                _json_file(args.record, "linker record"), "linker record"
            )
        elif args.command == "select-cargo-executable":
            print(select_cargo_executable(args))
        elif args.command == "stage-validate-capability":
            driver, identity, document = stage_validate_capability(args)
            print(driver)
            print(identity)
            print(document)
        elif args.command == "guard-capability":
            return guard_capability(args)
        elif args.command == "publish-guarded-manifest":
            _publish_guarded_manifest(
                args.input,
                args.output,
                args.identity,
                args.held_fd_path,
            )
        elif args.command == "write-private-pending":
            _write_private_pending(args.output, sys.stdin.buffer.read())
        elif args.command == "verify-staged-capability":
            verify_staged_capability(args.path, args.identity)
        else:
            print(resolve_cargo_linker(args))
    except (KeyError, OSError, json.JSONDecodeError, LayoutError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
