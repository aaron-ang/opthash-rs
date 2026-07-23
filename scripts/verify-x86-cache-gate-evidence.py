#!/usr/bin/env python3
"""Safely verify a portable native x86-64 cache-gate evidence archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, NamedTuple


HEX_DIGITS = frozenset("0123456789abcdef")
SYSTEM_PREFIX = PurePosixPath("bundle/system-root")
REQUIRED_ROOTS = (
    "orchestrator",
    "subject",
    "v1",
    "evidence",
    "toolchain",
    "system-root",
)
REQUIRED_DOCUMENTS = (
    "bundle/provenance.json",
    "bundle/inventory.json",
    "bundle/portable-paths.json",
    "bundle/body-comparison.json",
)
BODY_FIELDS = (
    "size",
    "normalized_instructions_sha256",
    "direct_calls",
    "indirect_calls",
    "frame_adjustment",
    "spills",
)


class ListSchema(NamedTuple):
    item: object
    nonempty: bool = False


class LiteralSchema(NamedTuple):
    value: object


STRING = str
INTEGER = int
BOOLEAN = bool
STRING_LIST = ListSchema(STRING)
FILE_RECORD_SCHEMA = {"absolute_path": STRING, "sha256": STRING}
BODY_SCHEMA = {
    "size": INTEGER,
    "normalized_instructions_sha256": STRING,
    "direct_calls": STRING_LIST,
    "indirect_calls": INTEGER,
    "frame_adjustment": INTEGER,
    "spills": STRING_LIST,
    "raw_sha256": STRING,
    "placement": {"section": STRING, "address": INTEGER},
}
CAPABILITY_SCHEMA = {
    "version": INTEGER,
    "accepted": BOOLEAN,
    "arch": STRING,
    "records": ListSchema(
        {
            "flavor": STRING,
            "target": STRING,
            "kernel_count": INTEGER,
            "invocation_path": STRING,
            "invocation_chain": ListSchema(STRING, nonempty=True),
            "artifacts": ListSchema(FILE_RECORD_SCHEMA, nonempty=True),
        },
        nonempty=True,
    ),
}
MANIFEST_V2_SCHEMA = {
    "version": INTEGER,
    "kind": STRING,
    "runner_root": STRING,
    "environment": {"PATH": STRING},
    "executables": ListSchema(
        {
            "name": STRING,
            "absolute_path": STRING,
            "sha256": STRING,
            "rustc_argv": ListSchema(STRING, nonempty=True),
        },
        nonempty=True,
    ),
    "aggregate": {
        "cgu": STRING,
        "objects": STRING,
        "link_order": STRING_LIST,
        "semantic": STRING,
    },
    "bodies": ListSchema({"kernel": STRING, **BODY_SCHEMA}, nonempty=True),
}
MANIFEST_V1_SCHEMA = {
    "version": INTEGER,
    "runner_root": STRING,
    "executables": ListSchema(
        {"name": STRING, "absolute_path": STRING, "sha256": STRING},
        nonempty=True,
    ),
    "bodies": ListSchema({"kernel": STRING, **BODY_SCHEMA}, nonempty=True),
}
PROVENANCE_SCHEMA = {
    "version": INTEGER,
    "subject": {"commit": STRING, "tree": STRING},
    "run": {"id": INTEGER, "attempt": INTEGER, "derived_attempt": INTEGER},
    "documents": {
        "capability": STRING,
        "manifests": ListSchema(STRING, nonempty=True),
        "v1_manifest": STRING,
        "transcripts": ListSchema(STRING, nonempty=True),
    },
    "hardlinks": ListSchema({"path": STRING, "target": STRING}),
}
INVENTORY_ENTRY_SCHEMAS = {
    "dir": {"path": STRING, "type": STRING, "mode": INTEGER},
    "file": {
        "path": STRING,
        "type": STRING,
        "mode": INTEGER,
        "size": INTEGER,
        "sha256": STRING,
    },
    "symlink": {"path": STRING, "type": STRING, "mode": INTEGER, "target": STRING},
    "hardlink": {"path": STRING, "type": STRING, "mode": INTEGER, "target": STRING},
}
TRANSCRIPT_SCHEMA = {
    "version": INTEGER,
    "kind": STRING,
    "argv": ListSchema(STRING, nonempty=True),
    "status": INTEGER,
    "ordered_inputs": STRING_LIST,
}
BODY_COMPARISON_SCHEMA = {
    "version": INTEGER,
    "fields": ListSchema(STRING, nonempty=True),
    "rows": ListSchema(
        {"kernel": STRING, "v1": BODY_SCHEMA, "v2": BODY_SCHEMA}, nonempty=True
    ),
}
PORTABLE_PATHS_SCHEMA = {
    "version": INTEGER,
    "roots": ListSchema(
        {"name": STRING, "hosted": STRING, "archive": STRING}, nonempty=True
    ),
    "system_links": ListSchema({"source": STRING, "raw_target": STRING}),
    "routing_records": ListSchema(
        {
            "document": STRING,
            "key_path": ListSchema(STRING, nonempty=True),
            "field_kind": STRING,
        },
        nonempty=True,
    ),
}
DOCUMENT_SCHEMAS: dict[str, object] = {
    "capability": CAPABILITY_SCHEMA,
    "manifest_v2": MANIFEST_V2_SCHEMA,
    "manifest_v1": MANIFEST_V1_SCHEMA,
    "provenance": PROVENANCE_SCHEMA,
    "transcript": TRANSCRIPT_SCHEMA,
    "body_comparison": BODY_COMPARISON_SCHEMA,
    "portable_paths": PORTABLE_PATHS_SCHEMA,
}

# Closed routing table. Patterns contain literal ``*`` for array elements.
PATH_ROUTES: dict[tuple[str, ...], str] = {
    ("manifest", "runner_root"): "root",
    ("manifest", "environment", "PATH"): "path-list",
    ("manifest", "executables", "*", "absolute_path"): "hashed-file",
    ("manifest", "executables", "*", "rustc_argv"): "rustc-command",
    ("v1-manifest", "runner_root"): "root",
    ("v1-manifest", "executables", "*", "absolute_path"): "hashed-file",
    ("capability", "records", "*", "invocation_path"): "system-file",
    ("capability", "records", "*", "invocation_chain", "*"): "system-file",
    ("capability", "records", "*", "artifacts", "*", "absolute_path"): "hashed-file",
    ("provenance", "documents", "capability"): "archive-file",
    ("provenance", "documents", "manifests", "*"): "archive-file",
    ("provenance", "documents", "v1_manifest"): "archive-file",
    ("provenance", "documents", "transcripts", "*"): "archive-file",
    ("provenance", "hardlinks", "*", "path"): "archive-member",
    ("provenance", "hardlinks", "*", "target"): "archive-member",
    ("inventory", "entries", "*", "path"): "archive-member",
    ("transcript", "argv"): "linker-command",
    ("transcript", "ordered_inputs", "*"): "transient-file",
}


class EvidenceError(RuntimeError):
    """Archive cannot serve as cache-gate evidence."""


class MemberRecord(NamedTuple):
    path: str
    kind: str
    mode: int
    size: int
    raw_target: str
    resolved_target: str
    info: tarfile.TarInfo


class ArchiveStructure(NamedTuple):
    archive_sha256: str
    members: dict[str, MemberRecord]


class VerificationReport(NamedTuple):
    archive_sha256: str
    subject_commit: str
    subject_tree: str
    run_id: int
    run_attempt: int
    manifest_sha256s: tuple[str, str, str]
    capability_sha256: str
    body_comparison_sha256: str
    status: str = "READY"

    def as_dict(self) -> dict[str, object]:
        return {
            "archive_sha256": self.archive_sha256,
            "subject_commit": self.subject_commit,
            "subject_tree": self.subject_tree,
            "run_id": self.run_id,
            "run_attempt": self.run_attempt,
            "manifest_sha256s": list(self.manifest_sha256s),
            "capability_sha256": self.capability_sha256,
            "body_comparison_sha256": self.body_comparison_sha256,
            "status": self.status,
        }


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def classify(path: tuple[str, ...]) -> str:
    normalized = tuple("*" if isinstance(part, int) else part for part in path)
    result = PATH_ROUTES.get(normalized)
    _require(result is not None, f"unclassified path field: {'.'.join(normalized)}")
    return result


def _validate_schema(value: object, schema: object, label: str) -> None:
    if isinstance(schema, ListSchema):
        _require(isinstance(value, list), f"{label} type mismatch")
        _require(not schema.nonempty or bool(value), f"{label} schema mismatch")
        for index, item in enumerate(value):
            _validate_schema(item, schema.item, f"{label}[{index}]")
        return
    if isinstance(schema, LiteralSchema):
        _require(
            value == schema.value and type(value) is type(schema.value),
            f"{label} schema mismatch",
        )
        return
    if isinstance(schema, dict):
        _require(isinstance(value, dict), f"{label} type mismatch")
        _require(set(value) == set(schema), f"{label} schema mismatch")
        for key, child_schema in schema.items():
            _validate_schema(value[key], child_schema, f"{label}.{key}")
        return
    if schema is int:
        _require(type(value) is int, f"{label} type mismatch")
        return
    if schema is bool:
        _require(type(value) is bool, f"{label} type mismatch")
        return
    if schema is str:
        _require(isinstance(value, str), f"{label} type mismatch")
        return
    raise AssertionError(f"unsupported schema at {label}: {schema!r}")


def _validate_inventory_schema(document: object) -> None:
    _require(isinstance(document, dict), "inventory type mismatch")
    _require(set(document) == {"version", "entries"}, "inventory schema mismatch")
    _validate_schema(document["version"], INTEGER, "inventory.version")
    _require(isinstance(document["entries"], list), "inventory.entries type mismatch")
    for index, entry in enumerate(document["entries"]):
        _require(isinstance(entry, dict), f"inventory.entries[{index}] type mismatch")
        kind = entry.get("type")
        _require(
            kind in INVENTORY_ENTRY_SCHEMAS,
            f"inventory.entries[{index}] schema mismatch",
        )
        _validate_schema(
            entry, INVENTORY_ENTRY_SCHEMAS[kind], f"inventory.entries[{index}]"
        )


def _validate_versions_and_values(documents: dict[str, dict[str, Any]]) -> None:
    _require(documents["capability"]["version"] == 1, "capability version mismatch")
    _require(documents["manifest_v2"]["version"] == 2, "v2 manifest version mismatch")
    _require(documents["manifest_v1"]["version"] == 1, "v1 manifest version mismatch")
    _require(documents["provenance"]["version"] == 1, "provenance version mismatch")
    _require(documents["inventory"]["version"] == 1, "inventory version mismatch")
    _require(documents["transcript"]["version"] == 1, "transcript version mismatch")
    _require(
        documents["body_comparison"]["version"] == 1, "body-comparison version mismatch"
    )
    _require(
        documents["portable_paths"]["version"] == 1, "portable-paths version mismatch"
    )
    _require(
        documents["body_comparison"]["fields"] == list(BODY_FIELDS),
        "body-comparison field set mismatch",
    )


def _declared_routes(document: dict[str, Any]) -> dict[tuple[str, ...], str]:
    routes: dict[tuple[str, ...], str] = {}
    for record in document["routing_records"]:
        key = (record["document"], *record["key_path"])
        _require(key not in routes, "duplicate routing record")
        routes[key] = record["field_kind"]
    return routes


def _required_fixture_routes(
    documents: dict[str, dict[str, Any]],
) -> set[tuple[str, ...]]:
    required = {
        ("manifest", "runner_root"),
        ("manifest", "environment", "PATH"),
        ("manifest", "executables", "*", "absolute_path"),
        ("manifest", "executables", "*", "rustc_argv"),
        ("v1-manifest", "runner_root"),
        ("v1-manifest", "executables", "*", "absolute_path"),
        ("capability", "records", "*", "invocation_path"),
        ("capability", "records", "*", "invocation_chain", "*"),
        ("capability", "records", "*", "artifacts", "*", "absolute_path"),
        ("provenance", "documents", "capability"),
        ("provenance", "documents", "manifests", "*"),
        ("provenance", "documents", "v1_manifest"),
        ("provenance", "documents", "transcripts", "*"),
        ("inventory", "entries", "*", "path"),
        ("transcript", "argv"),
        ("transcript", "ordered_inputs", "*"),
    }
    if documents["provenance"]["hardlinks"]:
        required.update(
            {
                ("provenance", "hardlinks", "*", "path"),
                ("provenance", "hardlinks", "*", "target"),
            }
        )
    return required


def validate_document_set(documents: dict[str, dict[str, Any]]) -> None:
    expected = {
        "capability",
        "manifest_v2",
        "manifest_v1",
        "provenance",
        "inventory",
        "transcript",
        "body_comparison",
        "portable_paths",
    }
    _require(set(documents) == expected, "document set schema mismatch")
    # Complete structural gate. No classifier or root construction occurs above this line.
    for kind, schema in DOCUMENT_SCHEMAS.items():
        _validate_schema(documents[kind], schema, kind)
    _validate_inventory_schema(documents["inventory"])
    _validate_versions_and_values(documents)
    _validate_portable_paths(documents["portable_paths"])

    routes = _declared_routes(documents["portable_paths"])
    required = _required_fixture_routes(documents)
    _require(set(routes) == required, "routing record set mismatch")
    for route, field_kind in routes.items():
        _require(classify(route) == field_kind, "routing record field kind mismatch")


class PortableRoots(NamedTuple):
    by_name: dict[str, tuple[PurePosixPath, PurePosixPath]]

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> "PortableRoots":
        _validate_schema(document, PORTABLE_PATHS_SCHEMA, "portable_paths")
        _validate_portable_paths(document)
        result: dict[str, tuple[PurePosixPath, PurePosixPath]] = {}
        hosted_seen: set[str] = set()
        archive_seen: set[str] = set()
        for item in document["roots"]:
            hosted = _canonical_absolute(item["hosted"], "hosted root")
            archive = _canonical_member(item["archive"])
            _require(item["hosted"] not in hosted_seen, "root alias mismatch")
            _require(item["archive"] not in archive_seen, "root alias mismatch")
            hosted_seen.add(item["hosted"])
            archive_seen.add(item["archive"])
            result[item["name"]] = (hosted, archive)
        return cls(result)

    def map_path(self, raw: str, *, expected_root: str | None = None) -> PurePosixPath:
        path = _canonical_absolute(raw, "hosted path")
        matches: list[tuple[int, str, PurePosixPath, PurePosixPath]] = []
        for name, (hosted, archive) in self.by_name.items():
            if path == hosted or path.is_relative_to(hosted):
                matches.append((len(hosted.parts), name, hosted, archive))
        _require(bool(matches), "path is outside declared roots")
        matches.sort(reverse=True)
        _, name, hosted, archive = matches[0]
        _require(
            expected_root is None or name == expected_root, "root namespace mismatch"
        )
        if name == "system-root" and hosted == PurePosixPath("/"):
            allowed = tuple(
                PurePosixPath(value)
                for value in (
                    "/bin",
                    "/etc/alternatives",
                    "/lib",
                    "/lib64",
                    "/usr/bin",
                    "/usr/lib",
                )
            )
            _require(
                any(
                    path == prefix or path.is_relative_to(prefix) for prefix in allowed
                ),
                "path is outside declared roots",
            )
        relative = path.relative_to(hosted)
        return archive / relative


def _canonical_absolute(raw: str, label: str) -> PurePosixPath:
    _require(
        isinstance(raw, str) and raw.startswith("/") and "\x00" not in raw,
        f"invalid {label}",
    )
    if raw == "/":
        return PurePosixPath("/")
    parts = raw.split("/")
    _require(
        parts[0] == "" and all(part not in {"", ".", ".."} for part in parts[1:]),
        f"invalid {label}",
    )
    return PurePosixPath(raw)


def validate_path_list(value: str, roots: PortableRoots) -> list[PurePosixPath]:
    _require(isinstance(value, str), "PATH type mismatch")
    parts = value.split(":")
    _require(all(parts), "empty PATH element")
    return [roots.map_path(item) for item in parts]


def _looks_path_valued(value: str) -> bool:
    return (
        "/" in value
        or value.startswith("@")
        or value.endswith((".o", ".a", ".so", ".rlib", ".rs", ".rsp", ".ld"))
    )


def _map_search_path(value: str, roots: PortableRoots) -> None:
    path = (
        value.split("=", 1)[1] if "=" in value and not value.startswith("/") else value
    )
    roots.map_path(path)


def _validate_link_arg(value: str, roots: PortableRoots) -> None:
    if value.startswith("@"):
        roots.map_path(value[1:])
        return
    for prefix in ("-T", "-B", "-L"):
        if value.startswith(prefix) and len(value) > len(prefix):
            roots.map_path(value[len(prefix) :])
            return
    for prefix in ("--script=", "--version-script=", "-Map=", "-Map,"):
        if value.startswith(prefix):
            roots.map_path(value[len(prefix) :])
            return
    if value.startswith("/"):
        roots.map_path(value)
        return
    _require(not _looks_path_valued(value), "unclassified path-valued link argument")


def validate_command(command: list[str], roots: PortableRoots, *, rustc: bool) -> None:
    _require(
        isinstance(command, list)
        and bool(command)
        and all(
            isinstance(token, str) and token and "\x00" not in token
            for token in command
        ),
        "command schema mismatch",
    )
    index = 0
    while index < len(command):
        token = command[index]
        if index == 0:
            if "/" in token:
                roots.map_path(token)
            index += 1
            continue
        if token in {"-o", "-L", "--extern"}:
            _require(index + 1 < len(command), "path-valued flag lacks value")
            value = command[index + 1]
            if token == "--extern":
                _require(
                    "=" in value and bool(value.split("=", 1)[0]), "malformed --extern"
                )
                roots.map_path(value.split("=", 1)[1])
            elif token == "-L":
                _map_search_path(value, roots)
            else:
                roots.map_path(value)
            index += 2
            continue
        if token.startswith("-o") and token != "-o":
            roots.map_path(token[2:])
        elif token.startswith("-L") and token != "-L":
            _map_search_path(token[2:], roots)
        elif token.startswith("--extern="):
            value = token.removeprefix("--extern=")
            _require(
                "=" in value and bool(value.split("=", 1)[0]), "malformed --extern"
            )
            roots.map_path(value.split("=", 1)[1])
        elif token == "-C":
            _require(index + 1 < len(command), "-C lacks value")
            option = command[index + 1]
            if option.startswith("linker="):
                roots.map_path(option.removeprefix("linker="))
            elif option.startswith("link-arg="):
                _validate_link_arg(option.removeprefix("link-arg="), roots)
            else:
                _require(
                    not _looks_path_valued(option),
                    "unclassified path-valued rustc flag",
                )
            index += 2
            continue
        elif token.startswith("-Clinker="):
            roots.map_path(token.removeprefix("-Clinker="))
        elif token.startswith("-Clink-arg="):
            _validate_link_arg(token.removeprefix("-Clink-arg="), roots)
        elif token.startswith("@"):
            _require(token[1:].startswith("/"), "unclassified response file path")
            roots.map_path(token[1:])
        elif token.startswith("-"):
            _require(not _looks_path_valued(token), "unclassified path-valued flag")
        elif _looks_path_valued(token):
            roots.map_path(token)
        index += 1


def parse_rlib_owner(value: str) -> tuple[str, str]:
    _require(isinstance(value, str), "malformed rlib(member) owner")
    opening = value.rfind("(")
    _require(
        opening > 0
        and value.endswith(")")
        and value[:opening].endswith(".rlib")
        and bool(value[opening + 1 : -1])
        and "/" not in value[opening + 1 : -1]
        and "(" not in value[opening + 1 : -1]
        and ")" not in value[opening + 1 : -1],
        "malformed rlib(member) owner",
    )
    return value[:opening], value[opening + 1 : -1]


def validate_rlib_member(archive: Path, member: str) -> None:
    completed = subprocess.run(
        ["ar", "t", archive], text=True, capture_output=True, check=False
    )
    _require(completed.returncode == 0, "cannot read rlib index")
    members = completed.stdout.splitlines()
    _require(member in members, "rlib index member is missing")


def verify_body_rows(rows: list[dict[str, Any]]) -> str:
    _require(
        isinstance(rows, list) and len(rows) == 8,
        "body comparison must contain eight rows",
    )
    canonical: list[dict[str, object]] = []
    kernels: set[str] = set()
    for row in rows:
        _validate_schema(
            row, {"kernel": STRING, "v1": BODY_SCHEMA, "v2": BODY_SCHEMA}, "body row"
        )
        kernel = row["kernel"]
        _require(kernel not in kernels, "duplicate body kernel")
        kernels.add(kernel)
        left = tuple(row["v1"][field] for field in BODY_FIELDS)
        right = tuple(row["v2"][field] for field in BODY_FIELDS)
        _require(left == right, f"body mismatch for {kernel}")
        canonical.append(
            {
                "kernel": kernel,
                "fields": {field: row["v2"][field] for field in BODY_FIELDS},
            }
        )
    canonical.sort(key=lambda item: str(item["kernel"]).encode())
    data = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def verify_manifest_relationships(
    clean_a: dict[str, Any], clean_b: dict[str, Any], adversary: dict[str, Any]
) -> None:
    _require(
        clean_a["kind"] == "clean-a"
        and clean_b["kind"] == "clean-b"
        and adversary["kind"] == "adversary",
        "manifest kind mismatch",
    )
    _require(clean_a["aggregate"] == clean_b["aggregate"], "clean aggregate mismatch")
    _require(
        adversary["aggregate"]["cgu"] != clean_a["aggregate"]["cgu"]
        and adversary["aggregate"]["objects"] != clean_a["aggregate"]["objects"],
        "adversary difference is vacuous",
    )
    _require(
        adversary["aggregate"]["semantic"] == clean_a["aggregate"]["semantic"]
        and adversary["aggregate"]["link_order"] == clean_a["aggregate"]["link_order"],
        "adversary semantic mismatch",
    )


def _canonical_member(raw: str) -> PurePosixPath:
    _require(isinstance(raw, str) and "\x00" not in raw, "unsafe archive member name")
    components = raw.split("/")
    _require(
        bool(raw)
        and not raw.startswith("/")
        and all(component not in {"", ".", ".."} for component in components),
        "unsafe archive member name",
    )
    path = PurePosixPath(*components)
    _require(
        path.is_relative_to(PurePosixPath("bundle")), "archive member outside bundle"
    )
    return path


def _resolve_target(base: PurePosixPath, raw: str) -> PurePosixPath:
    _require(
        isinstance(raw, str) and bool(raw) and "\x00" not in raw, "empty link target"
    )
    parts = list(base.parts)
    useful = False
    for component in raw.split("/"):
        if component in {"", "."}:
            continue
        useful = True
        if component == "..":
            _require(bool(parts), "link target escapes archive root")
            parts.pop()
        else:
            parts.append(component)
    _require(useful and bool(parts), "empty link target")
    path = PurePosixPath(*parts)
    _require(
        path.is_relative_to(PurePosixPath("bundle")), "link target escapes archive root"
    )
    return path


def _symlink_target(
    member: PurePosixPath, raw: str, system_pairs: set[tuple[str, str]]
) -> PurePosixPath:
    if member.is_relative_to(SYSTEM_PREFIX):
        source = "/" + member.relative_to(SYSTEM_PREFIX).as_posix()
        _require((source, raw) in system_pairs, "unallowlisted system link")
    if raw.startswith("/"):
        _require(
            member.is_relative_to(SYSTEM_PREFIX),
            "unallowlisted absolute system link",
        )
        return _resolve_target(SYSTEM_PREFIX, raw.removeprefix("/"))
    return _resolve_target(member.parent, raw)


def _hardlink_target(raw: str) -> PurePosixPath:
    _require(not raw.startswith("/"), "absolute hardlink target")
    return _resolve_target(PurePosixPath(), raw)


def _snapshot_archive(archive: Path) -> tuple[BinaryIO, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(archive, flags)
    except OSError as error:
        raise EvidenceError("cannot open archive without following links") from error
    snapshot = tempfile.TemporaryFile(mode="w+b")
    try:
        before = os.fstat(source_fd)
        _require(stat.S_ISREG(before.st_mode), "archive is not a regular file")
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            snapshot.write(chunk)
            copied += len(chunk)
        after = os.fstat(source_fd)

        def identity(item: os.stat_result) -> tuple[int, int, int, int, int, int]:
            return (
                item.st_dev,
                item.st_ino,
                item.st_mode,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )

        _require(
            identity(before) == identity(after) and copied == before.st_size,
            "archive changed while reading",
        )
        snapshot.flush()
        snapshot.seek(0)
        return snapshot, digest.hexdigest()
    except BaseException:
        snapshot.close()
        raise
    finally:
        os.close(source_fd)


def _expected_digest(value: str) -> str:
    _require(
        isinstance(value, str)
        and len(value) == 64
        and all(character in HEX_DIGITS for character in value),
        "expected SHA-256 is not 64 lowercase hex",
    )
    return value


def _read_member(archive: tarfile.TarFile, info: tarfile.TarInfo, label: str) -> bytes:
    _require(info.isreg(), f"{label} is not a regular file")
    _require(info.size <= 128 * 1024 * 1024, f"{label} is too large")
    extracted = archive.extractfile(info)
    _require(extracted is not None, f"cannot read {label}")
    data = extracted.read(info.size + 1)
    _require(len(data) == info.size, f"truncated {label}")
    return data


def _json_member(
    archive: tarfile.TarFile, info: tarfile.TarInfo, label: str
) -> tuple[object, bytes]:
    data = _read_member(archive, info, label)
    try:
        value = _strict_json(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"invalid JSON in {label}") from error
    return value, data


def _strict_json(data: bytes) -> object:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise EvidenceError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def constant(value: str) -> object:
        raise EvidenceError(f"non-finite JSON number: {value}")

    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def _validate_portable_paths(document: object) -> set[tuple[str, str]]:
    _require(isinstance(document, dict), "portable-paths schema mismatch")
    _require(
        set(document) == {"version", "roots", "system_links", "routing_records"},
        "portable-paths schema mismatch",
    )
    _require(
        type(document["version"]) is int and document["version"] == 1,
        "portable-paths version mismatch",
    )
    roots = document["roots"]
    links = document["system_links"]
    routes = document["routing_records"]
    _require(
        isinstance(roots, list)
        and isinstance(links, list)
        and isinstance(routes, list),
        "portable-paths schema mismatch",
    )
    root_names: set[str] = set()
    for item in roots:
        _require(
            isinstance(item, dict) and set(item) == {"name", "hosted", "archive"},
            "portable-paths root schema mismatch",
        )
        _require(
            all(isinstance(item[key], str) and item[key] for key in item),
            "portable-paths root type mismatch",
        )
        _require(item["name"] not in root_names, "duplicate portable root")
        root_names.add(item["name"])
    _require(root_names == set(REQUIRED_ROOTS), "portable root set mismatch")
    pairs: set[tuple[str, str]] = set()
    for item in links:
        _require(
            isinstance(item, dict) and set(item) == {"source", "raw_target"},
            "portable-paths system-link schema mismatch",
        )
        _require(
            isinstance(item["source"], str)
            and item["source"].startswith("/")
            and isinstance(item["raw_target"], str)
            and bool(item["raw_target"]),
            "portable-paths system-link type mismatch",
        )
        pair = (item["source"], item["raw_target"])
        _require(pair not in pairs, "duplicate system-link allowlist pair")
        pairs.add(pair)
    for item in routes:
        _require(
            isinstance(item, dict)
            and set(item) == {"document", "key_path", "field_kind"},
            "portable-paths routing-record schema mismatch",
        )
        _require(
            isinstance(item["document"], str)
            and bool(item["document"])
            and isinstance(item["field_kind"], str)
            and bool(item["field_kind"])
            and isinstance(item["key_path"], list)
            and bool(item["key_path"])
            and all(isinstance(part, str) and part for part in item["key_path"]),
            "portable-paths routing-record type mismatch",
        )
    return pairs


def _member_kind(info: tarfile.TarInfo) -> str:
    if info.isdir():
        return "dir"
    if info.isreg():
        return "file"
    if info.issym():
        return "symlink"
    if info.islnk():
        return "hardlink"
    raise EvidenceError("unsupported archive member type")


def _inspect(archive: tarfile.TarFile, digest: str) -> ArchiveStructure:
    raw_members = archive.getmembers()
    records: dict[str, MemberRecord] = {}
    paths: dict[str, PurePosixPath] = {}
    for info in raw_members:
        path = _canonical_member(info.name)
        canonical = path.as_posix()
        _require(canonical not in records, "duplicate archive member")
        kind = _member_kind(info)
        _require(
            info.uid == 0 and info.gid == 0 and info.uname == "" and info.gname == "",
            "noncanonical archive ownership",
        )
        _require(info.mtime == 0, "noncanonical archive timestamp")
        mode = info.mode & 0o7777
        records[canonical] = MemberRecord(
            canonical, kind, mode, info.size, info.linkname, "", info
        )
        paths[canonical] = path
    _require(
        "bundle" in records and records["bundle"].kind == "dir",
        "archive lacks bundle directory",
    )
    for root in REQUIRED_ROOTS:
        name = f"bundle/{root}"
        _require(
            name in records and records[name].kind == "dir",
            f"archive lacks {name} directory",
        )
    for document in REQUIRED_DOCUMENTS:
        _require(
            document in records and records[document].kind == "file",
            f"archive lacks {document}",
        )

    portable, _ = _json_member(
        archive, records["bundle/portable-paths.json"].info, "portable-paths.json"
    )
    system_pairs = _validate_portable_paths(portable)

    for name, path in paths.items():
        parent = path.parent
        while parent != PurePosixPath("."):
            parent_name = parent.as_posix()
            ancestor = records.get(parent_name)
            _require(
                ancestor is not None, "archive member has missing directory ancestor"
            )
            _require(
                ancestor.kind not in {"symlink", "hardlink"},
                "archive member has link-valued ancestor",
            )
            _require(
                ancestor.kind == "dir", "archive member has non-directory ancestor"
            )
            parent = parent.parent

    targets: dict[str, str] = {}
    for name, record in records.items():
        path = paths[name]
        if record.kind == "symlink":
            targets[name] = _symlink_target(
                path, record.raw_target, system_pairs
            ).as_posix()
        elif record.kind == "hardlink":
            targets[name] = _hardlink_target(record.raw_target).as_posix()

    colors: dict[str, int] = {}

    def resolve(name: str, *, hard_only: bool = False) -> str:
        color = colors.get(name, 0)
        _require(color != 1, "link cycle")
        if color == 2 and not hard_only:
            return records[name].resolved_target or name
        record = records.get(name)
        _require(record is not None, "link target is missing")
        if record.kind not in {"symlink", "hardlink"}:
            return name
        if hard_only:
            _require(
                record.kind == "hardlink", "hardlink must terminate at a regular file"
            )
        colors[name] = 1
        target_name = targets[name]
        target = records.get(target_name)
        _require(target is not None, "link target is missing")
        if record.kind == "hardlink":
            _require(
                target.kind in {"file", "hardlink"},
                "hardlink must terminate at a regular file",
            )
            terminal = (
                resolve(target_name, hard_only=True)
                if target.kind == "hardlink"
                else target_name
            )
            _require(
                records[terminal].kind == "file",
                "hardlink must terminate at a regular file",
            )
        else:
            terminal = resolve(target_name)
        colors[name] = 2
        records[name] = record._replace(resolved_target=terminal)
        return terminal

    for name, record in tuple(records.items()):
        if record.kind in {"symlink", "hardlink"}:
            terminal = resolve(name, hard_only=record.kind == "hardlink")
            if paths[name].is_relative_to(SYSTEM_PREFIX):
                _require(
                    records[terminal].kind == "file",
                    "system link chain must terminate at regular file",
                )
    for source, raw_target in system_pairs:
        name = (SYSTEM_PREFIX / source.removeprefix("/")).as_posix()
        record = records.get(name)
        _require(
            record is not None and record.kind == "symlink",
            "allowlisted system link is missing",
        )
        _require(
            record.raw_target == raw_target, "allowlisted system link target mismatch"
        )

    inventory, _ = _json_member(
        archive, records["bundle/inventory.json"].info, "inventory.json"
    )
    _validate_inventory(archive, records, inventory)
    return ArchiveStructure(digest, records)


def _validate_inventory(
    archive: tarfile.TarFile, records: dict[str, MemberRecord], document: object
) -> None:
    _require(
        isinstance(document, dict) and set(document) == {"version", "entries"},
        "inventory schema mismatch",
    )
    _require(
        type(document["version"]) is int and document["version"] == 1,
        "inventory version mismatch",
    )
    entries = document["entries"]
    _require(isinstance(entries, list), "inventory schema mismatch")
    expected: dict[str, dict[str, object]] = {}
    for index, item in enumerate(entries):
        _require(isinstance(item, dict), f"inventory entry {index} schema mismatch")
        kind = item.get("type")
        keys = {
            "dir": {"path", "type", "mode"},
            "file": {"path", "type", "mode", "size", "sha256"},
            "symlink": {"path", "type", "mode", "target"},
            "hardlink": {"path", "type", "mode", "target"},
        }.get(kind)
        _require(
            keys is not None and set(item) == keys,
            f"inventory entry {index} schema mismatch",
        )
        path = item["path"]
        _require(
            isinstance(path, str) and path not in expected,
            "duplicate or invalid inventory path",
        )
        _canonical_member(path)
        _require(
            type(item["mode"]) is int and 0 <= item["mode"] <= 0o7777,
            "invalid inventory mode",
        )
        if kind == "file":
            _require(
                type(item["size"]) is int and item["size"] >= 0,
                "invalid inventory size",
            )
            _require(
                isinstance(item["sha256"], str)
                and len(item["sha256"]) == 64
                and all(c in HEX_DIGITS for c in item["sha256"]),
                "invalid inventory SHA-256",
            )
        elif kind in {"symlink", "hardlink"}:
            _require(
                isinstance(item["target"], str) and bool(item["target"]),
                "invalid inventory target",
            )
        expected[path] = item
    observed_names = set(records) - {"bundle/inventory.json"}
    _require(set(expected) == observed_names, "inventory mismatch")
    for name in sorted(observed_names, key=str.encode):
        record = records[name]
        item = expected[name]
        _require(
            item["type"] == record.kind and item["mode"] == record.mode,
            "inventory mismatch",
        )
        if record.kind == "file":
            data = _read_member(archive, record.info, f"inventory file {name}")
            _require(
                item["size"] == len(data)
                and item["sha256"] == hashlib.sha256(data).hexdigest(),
                "inventory mismatch",
            )
        elif record.kind in {"symlink", "hardlink"}:
            _require(item["target"] == record.raw_target, "inventory mismatch")


def _open_parent(root_fd: int, path: PurePosixPath) -> tuple[int, str]:
    parts = path.parts
    _require(bool(parts), "invalid extraction path")
    descriptor = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_fd
        return descriptor, parts[-1]
    except BaseException:
        os.close(descriptor)
        raise


def _extract(
    archive: tarfile.TarFile, members: dict[str, MemberRecord], destination: Path
) -> None:
    if destination.exists() or destination.is_symlink():
        raise EvidenceError("extraction root already exists")
    try:
        os.mkdir(destination, 0o700)
    except FileExistsError as error:
        raise EvidenceError("extraction root already exists") from error
    root_fd = os.open(
        destination, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directories = sorted(
            (record for record in members.values() if record.kind == "dir"),
            key=lambda record: (
                len(PurePosixPath(record.path).parts),
                record.path.encode(),
            ),
        )
        for record in directories:
            parent_fd, basename = _open_parent(root_fd, PurePosixPath(record.path))
            try:
                os.mkdir(basename, 0o700, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
        for record in sorted(members.values(), key=lambda item: item.path.encode()):
            if record.kind != "file":
                continue
            parent_fd, basename = _open_parent(root_fd, PurePosixPath(record.path))
            try:
                flags = (
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(basename, flags, 0o600, dir_fd=parent_fd)
                try:
                    source = archive.extractfile(record.info)
                    _require(source is not None, f"cannot extract {record.path}")
                    remaining = record.size
                    while remaining:
                        chunk = source.read(min(1024 * 1024, remaining))
                        _require(bool(chunk), f"truncated archive member {record.path}")
                        view = memoryview(chunk)
                        while view:
                            written = os.write(descriptor, view)
                            view = view[written:]
                        remaining -= len(chunk)
                    os.fchmod(descriptor, record.mode)
                finally:
                    os.close(descriptor)
            finally:
                os.close(parent_fd)
        for record in sorted(members.values(), key=lambda item: item.path.encode()):
            if record.kind != "symlink":
                continue
            parent_fd, basename = _open_parent(root_fd, PurePosixPath(record.path))
            try:
                os.symlink(record.raw_target, basename, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
        for record in sorted(members.values(), key=lambda item: item.path.encode()):
            if record.kind != "hardlink":
                continue
            source_fd, source_name = _open_parent(
                root_fd, PurePosixPath(record.resolved_target)
            )
            destination_fd, destination_name = _open_parent(
                root_fd, PurePosixPath(record.path)
            )
            try:
                os.link(
                    source_name,
                    destination_name,
                    src_dir_fd=source_fd,
                    dst_dir_fd=destination_fd,
                    follow_symlinks=False,
                )
            finally:
                os.close(source_fd)
                os.close(destination_fd)
        for record in reversed(directories):
            directory_fd, basename = _open_parent(root_fd, PurePosixPath(record.path))
            try:
                target_fd = os.open(
                    basename,
                    os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
                try:
                    os.fchmod(target_fd, record.mode)
                finally:
                    os.close(target_fd)
            finally:
                os.close(directory_fd)
    except OSError as error:
        raise EvidenceError(f"safe extraction failed: {error}") from error
    finally:
        os.close(root_fd)


def extract_validated_archive(
    members: dict[str, MemberRecord],
    destination: Path,
    archive: tarfile.TarFile | None = None,
) -> None:
    if destination.exists() or destination.is_symlink():
        raise EvidenceError("extraction root already exists")
    _require(archive is not None, "validated archive handle is required")
    _extract(archive, members, destination)


def _with_verified_archive(
    archive_path: Path, expected_sha256: str, *, extract_to: Path | None = None
) -> ArchiveStructure:
    expected = _expected_digest(expected_sha256)
    snapshot, digest = _snapshot_archive(Path(archive_path))
    try:
        _require(digest == expected, "archive SHA-256 mismatch")
        try:
            with tarfile.open(fileobj=snapshot, mode="r:") as archive:
                structure = _inspect(archive, digest)
                if extract_to is not None:
                    _extract(archive, structure.members, extract_to)
                return structure
        except tarfile.TarError as error:
            raise EvidenceError("invalid uncompressed POSIX tar archive") from error
    finally:
        snapshot.close()


def verify_archive_structure(archive: Path, expected_sha256: str) -> ArchiveStructure:
    return _with_verified_archive(Path(archive), expected_sha256)


def verify_archive(archive: Path, expected_sha256: str) -> VerificationReport:
    with tempfile.TemporaryDirectory(prefix="cache-gate-verifier-") as parent_text:
        root = Path(parent_text) / "root"
        structure = _with_verified_archive(
            Path(archive), expected_sha256, extract_to=root
        )
        return _verify_extracted_documents(root, structure.archive_sha256)


def _extracted_path(root: Path, raw: str) -> Path:
    member = _canonical_member(raw)
    return root.joinpath(*member.parts)


def _read_extracted(root: Path, raw: str) -> bytes:
    path = _extracted_path(root, raw)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise EvidenceError(f"referenced archive file is missing: {raw}") from error
    _require(
        stat.S_ISREG(metadata.st_mode), f"referenced archive path is not regular: {raw}"
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvidenceError(f"cannot open referenced archive file: {raw}") from error
    try:
        before = os.fstat(descriptor)
        _require(
            stat.S_ISREG(before.st_mode),
            f"referenced archive path is not regular: {raw}",
        )
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            _require(size <= 128 * 1024 * 1024, f"referenced JSON is too large: {raw}")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        _require(
            (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ),
            f"referenced archive file changed: {raw}",
        )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_extracted_json(
    root: Path, raw: str, label: str
) -> tuple[dict[str, Any], bytes]:
    data = _read_extracted(root, raw)
    try:
        document = _strict_json(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"invalid JSON in {label}") from error
    _require(isinstance(document, dict), f"{label} schema mismatch")
    return document, data


def _validate_all_structures(
    capability: dict[str, Any],
    manifests: list[dict[str, Any]],
    v1: dict[str, Any],
    provenance: dict[str, Any],
    inventory: dict[str, Any],
    transcripts: list[dict[str, Any]],
    body: dict[str, Any],
    portable: dict[str, Any],
) -> None:
    # This is deliberately one uninterrupted structural phase. Typed routing starts
    # only after every recursive object and array element has passed.
    _validate_schema(capability, CAPABILITY_SCHEMA, "capability")
    for index, manifest in enumerate(manifests):
        _validate_schema(manifest, MANIFEST_V2_SCHEMA, f"manifest_v2[{index}]")
    _validate_schema(v1, MANIFEST_V1_SCHEMA, "manifest_v1")
    _validate_schema(provenance, PROVENANCE_SCHEMA, "provenance")
    _validate_inventory_schema(inventory)
    for index, transcript in enumerate(transcripts):
        _validate_schema(transcript, TRANSCRIPT_SCHEMA, f"transcript[{index}]")
    _validate_schema(body, BODY_COMPARISON_SCHEMA, "body_comparison")
    _validate_schema(portable, PORTABLE_PATHS_SCHEMA, "portable_paths")
    _require(capability["version"] == 1, "capability version mismatch")
    _require(
        all(manifest["version"] == 2 for manifest in manifests),
        "v2 manifest version mismatch",
    )
    _require(v1["version"] == 1, "v1 manifest version mismatch")
    _require(provenance["version"] == 1, "provenance version mismatch")
    _require(inventory["version"] == 1, "inventory version mismatch")
    _require(
        all(item["version"] == 1 for item in transcripts), "transcript version mismatch"
    )
    _require(
        body["version"] == 1 and body["fields"] == list(BODY_FIELDS),
        "body-comparison version or fields mismatch",
    )
    _validate_portable_paths(portable)

    representative = {
        "capability": capability,
        "manifest_v2": manifests[0],
        "manifest_v1": v1,
        "provenance": provenance,
        "inventory": inventory,
        "transcript": transcripts[0],
        "body_comparison": body,
        "portable_paths": portable,
    }
    routes = _declared_routes(portable)
    required = _required_fixture_routes(representative)
    _require(set(routes) == required, "routing record set mismatch")
    for route, field_kind in routes.items():
        _require(classify(route) == field_kind, "routing record field kind mismatch")


def _hex_sha(value: object, label: str, *, length: int = 64) -> str:
    _require(
        isinstance(value, str)
        and len(value) == length
        and all(character in HEX_DIGITS for character in value),
        f"invalid {label}",
    )
    return value


def _verify_mapped_file(
    root: Path, roots: PortableRoots, record: dict[str, Any], label: str
) -> PurePosixPath:
    expected = _hex_sha(record["sha256"], f"{label} SHA-256")
    mapped = roots.map_path(record["absolute_path"])
    data = _read_extracted(root, mapped.as_posix())
    _require(hashlib.sha256(data).hexdigest() == expected, f"{label} hash mismatch")
    return mapped


def _require_archived_path(
    root: Path, mapped: PurePosixPath, label: str
) -> os.stat_result:
    path = _extracted_path(root, mapped.as_posix())
    try:
        return path.lstat()
    except OSError as error:
        raise EvidenceError(f"{label} is missing from archive") from error


def _verify_capability(
    root: Path, roots: PortableRoots, capability: dict[str, Any]
) -> None:
    _require(
        capability["accepted"] is True and capability["arch"] == "x86_64",
        "capability is not accepted native x86_64",
    )
    expected = {
        (flavor, target, count)
        for flavor in ("actual", "gnu", "lld")
        for target, count in (("elastic", 2), ("funnel", 2), ("profile", 4))
    }
    observed: set[tuple[str, str, int]] = set()
    for index, record in enumerate(capability["records"]):
        shape = (record["flavor"], record["target"], record["kernel_count"])
        _require(shape not in observed, "duplicate capability shape")
        observed.add(shape)
        chain = record["invocation_chain"]
        _require(
            chain[0] == record["invocation_path"] and len(chain) == len(set(chain)),
            "invalid capability invocation chain",
        )
        for chain_index, raw in enumerate(chain):
            mapped = roots.map_path(raw, expected_root="system-root")
            metadata = _require_archived_path(
                root, mapped, f"capability chain member {index}/{chain_index}"
            )
            _require(
                stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode),
                "capability chain member has invalid type",
            )
        terminal = roots.map_path(chain[-1], expected_root="system-root")
        _require(
            stat.S_ISREG(
                _require_archived_path(
                    root, terminal, "capability chain terminal"
                ).st_mode
            ),
            "capability chain terminal is not regular",
        )
        for artifact_index, artifact in enumerate(record["artifacts"]):
            _verify_mapped_file(
                root, roots, artifact, f"capability artifact {index}/{artifact_index}"
            )
    _require(
        observed == expected,
        "capability does not have exact actual/GNU/LLD 2/2/4 shapes",
    )


def _verify_manifests(
    root: Path,
    roots: PortableRoots,
    manifests: list[dict[str, Any]],
    v1: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    by_kind = {manifest["kind"]: manifest for manifest in manifests}
    _require(
        set(by_kind) == {"clean-a", "clean-b", "adversary"},
        "manifest kind set mismatch",
    )
    _require(len(by_kind) == len(manifests), "duplicate manifest kind")
    subject_root = roots.by_name["subject"][0].as_posix()
    v1_root = roots.by_name["v1"][0].as_posix()
    for manifest in manifests:
        _require(
            manifest["runner_root"] == subject_root, "manifest root alias mismatch"
        )
        validate_path_list(manifest["environment"]["PATH"], roots)
        for executable in manifest["executables"]:
            _verify_mapped_file(
                root,
                roots,
                executable,
                f"{manifest['kind']} executable {executable['name']}",
            )
            validate_command(executable["rustc_argv"], roots, rustc=True)
    _require(v1["runner_root"] == v1_root, "v1 manifest root alias mismatch")
    for executable in v1["executables"]:
        _verify_mapped_file(
            root, roots, executable, f"v1 executable {executable['name']}"
        )
    clean_a, clean_b, adversary = (
        by_kind["clean-a"],
        by_kind["clean-b"],
        by_kind["adversary"],
    )
    verify_manifest_relationships(clean_a, clean_b, adversary)
    return clean_a, clean_b, adversary


def _verify_transcripts(
    roots: PortableRoots, transcripts: list[dict[str, Any]]
) -> None:
    for transcript in transcripts:
        _require(transcript["status"] == 0, "hosted transcript failed")
        validate_command(transcript["argv"], roots, rustc=False)
        for raw in transcript["ordered_inputs"]:
            roots.map_path(raw)


def _verify_body_contract(
    body: dict[str, Any], clean: dict[str, Any], v1: dict[str, Any]
) -> str:
    digest = verify_body_rows(body["rows"])
    clean_bodies = {record["kernel"]: record for record in clean["bodies"]}
    v1_bodies = {record["kernel"]: record for record in v1["bodies"]}
    _require(
        len(clean_bodies) == len(clean["bodies"]) == 8,
        "clean manifest body set mismatch",
    )
    _require(len(v1_bodies) == len(v1["bodies"]) == 8, "v1 manifest body set mismatch")
    _require(set(clean_bodies) == set(v1_bodies), "v1/v2 manifest body kernel mismatch")
    rows = {record["kernel"]: record for record in body["rows"]}
    _require(set(rows) == set(clean_bodies), "body-comparison kernel set mismatch")
    for kernel, row in rows.items():
        for field in BODY_FIELDS:
            _require(
                row["v1"][field] == v1_bodies[kernel][field],
                f"v1 body contract mismatch for {kernel}",
            )
            _require(
                row["v2"][field] == clean_bodies[kernel][field],
                f"v2 body contract mismatch for {kernel}",
            )
    return digest


def _verify_extracted_documents(root: Path, archive_sha256: str) -> VerificationReport:
    provenance, _provenance_bytes = _load_extracted_json(
        root, "bundle/provenance.json", "provenance"
    )
    _validate_schema(provenance, PROVENANCE_SCHEMA, "provenance")
    # Provenance paths become usable only after its exact recursive schema passes.
    paths = provenance["documents"]
    _require(len(paths["manifests"]) == 3, "provenance must name three manifests")
    all_paths = [
        paths["capability"],
        *paths["manifests"],
        paths["v1_manifest"],
        *paths["transcripts"],
    ]
    _require(
        len(all_paths) == len(set(all_paths)), "duplicate provenance document path"
    )
    for raw in all_paths:
        _canonical_member(raw)

    capability, capability_bytes = _load_extracted_json(
        root, paths["capability"], "capability"
    )
    manifests_and_bytes = [
        _load_extracted_json(root, raw, f"manifest {index}")
        for index, raw in enumerate(paths["manifests"])
    ]
    manifests = [item[0] for item in manifests_and_bytes]
    v1, _v1_bytes = _load_extracted_json(root, paths["v1_manifest"], "v1 manifest")
    transcripts = [
        _load_extracted_json(root, raw, f"transcript {index}")[0]
        for index, raw in enumerate(paths["transcripts"])
    ]
    inventory, _inventory_bytes = _load_extracted_json(
        root, "bundle/inventory.json", "inventory"
    )
    body, _body_bytes = _load_extracted_json(
        root, "bundle/body-comparison.json", "body comparison"
    )
    portable, _portable_bytes = _load_extracted_json(
        root, "bundle/portable-paths.json", "portable paths"
    )

    _validate_all_structures(
        capability,
        manifests,
        v1,
        provenance,
        inventory,
        transcripts,
        body,
        portable,
    )
    roots = PortableRoots.from_document(portable)
    for name, (_hosted, archive) in roots.by_name.items():
        _require(
            archive == PurePosixPath(f"bundle/{name}"),
            "portable archive root alias mismatch",
        )

    _verify_capability(root, roots, capability)
    clean_a, _clean_b, _adversary = _verify_manifests(root, roots, manifests, v1)
    _verify_transcripts(roots, transcripts)
    body_sha = _verify_body_contract(body, clean_a, v1)

    subject = provenance["subject"]
    _hex_sha(subject["commit"], "subject commit", length=40)
    _hex_sha(subject["tree"], "subject tree", length=40)
    run = provenance["run"]
    _require(
        1 <= run["id"] <= 9223372036854774
        and 1 <= run["attempt"] <= 999
        and run["derived_attempt"] == run["id"] * 1000 + run["attempt"],
        "invalid run identity",
    )
    manifest_hashes_by_kind = {
        manifest["kind"]: hashlib.sha256(data).hexdigest()
        for manifest, data in manifests_and_bytes
    }
    return VerificationReport(
        archive_sha256=archive_sha256,
        subject_commit=subject["commit"],
        subject_tree=subject["tree"],
        run_id=run["id"],
        run_attempt=run["attempt"],
        manifest_sha256s=(
            manifest_hashes_by_kind["clean-a"],
            manifest_hashes_by_kind["clean-b"],
            manifest_hashes_by_kind["adversary"],
        ),
        capability_sha256=hashlib.sha256(capability_bytes).hexdigest(),
        body_comparison_sha256=body_sha,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--expected-sha256", required=True)
    arguments = parser.parse_args(argv)
    try:
        report = verify_archive(arguments.archive, arguments.expected_sha256)
    except EvidenceError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report.as_dict(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
