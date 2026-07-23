from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import copy
import tarfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


ROOT = Path(__file__).parents[1]
PACKAGE_SCRIPT = ROOT / "scripts/package-x86-cache-gate-evidence.py"
VERIFY_SCRIPT = ROOT / "scripts/verify-x86-cache-gate-evidence.py"
HEX = "0" * 64


def load_script(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def package_module() -> ModuleType:
    return load_script(PACKAGE_SCRIPT, "package_x86_cache_gate_evidence")


@pytest.fixture
def verify_module() -> ModuleType:
    return load_script(VERIFY_SCRIPT, "verify_x86_cache_gate_evidence")


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def portable_paths(system_links: list[dict[str, str]] | None = None) -> dict[str, Any]:
    route_values = {
        ("manifest", "runner_root"): "root",
        ("manifest", "environment", "PATH"): "path-list",
        ("manifest", "executables", "*", "absolute_path"): "hashed-file",
        ("manifest", "executables", "*", "rustc_argv"): "rustc-command",
        ("v1-manifest", "runner_root"): "root",
        ("v1-manifest", "executables", "*", "absolute_path"): "hashed-file",
        ("capability", "records", "*", "invocation_path"): "system-file",
        ("capability", "records", "*", "invocation_chain", "*"): "system-file",
        (
            "capability",
            "records",
            "*",
            "artifacts",
            "*",
            "absolute_path",
        ): "hashed-file",
        ("provenance", "documents", "capability"): "archive-file",
        ("provenance", "documents", "manifests", "*"): "archive-file",
        ("provenance", "documents", "v1_manifest"): "archive-file",
        ("provenance", "documents", "transcripts", "*"): "archive-file",
        ("inventory", "entries", "*", "path"): "archive-member",
        ("transcript", "argv"): "linker-command",
        ("transcript", "ordered_inputs", "*"): "transient-file",
    }
    return {
        "version": 1,
        "roots": [
            {
                "name": name,
                "hosted": "/" if name == "system-root" else f"/host/{name}",
                "archive": f"bundle/{name}",
            }
            for name in (
                "orchestrator",
                "subject",
                "v1",
                "evidence",
                "toolchain",
                "system-root",
            )
        ],
        "system_links": system_links or [],
        "routing_records": [
            {"document": route[0], "key_path": list(route[1:]), "field_kind": kind}
            for route, kind in sorted(route_values.items())
        ],
    }


def tar_entry(
    name: str,
    *,
    data: bytes = b"",
    kind: bytes = tarfile.REGTYPE,
    mode: int = 0o644,
    linkname: str = "",
) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.mode = mode
    info.uid = info.gid = info.mtime = 0
    info.uname = info.gname = ""
    info.linkname = linkname
    info.size = len(data) if kind in (tarfile.REGTYPE, tarfile.AREGTYPE) else 0
    return info, data


def write_tar(path: Path, entries: list[tuple[tarfile.TarInfo, bytes]]) -> str:
    with tarfile.open(path, mode="w:", format=tarfile.PAX_FORMAT) as archive:
        for info, data in entries:
            archive.addfile(info, io.BytesIO(data) if info.isreg() else None)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def structural_entries(
    *,
    system_links: list[dict[str, str]] | None = None,
) -> list[tuple[tarfile.TarInfo, bytes]]:
    entries = [tar_entry("bundle", kind=tarfile.DIRTYPE, mode=0o755)]
    for root in (
        "orchestrator",
        "subject",
        "v1",
        "evidence",
        "toolchain",
        "system-root",
    ):
        entries.append(tar_entry(f"bundle/{root}", kind=tarfile.DIRTYPE, mode=0o755))
    entries.extend(
        [
            tar_entry(
                "bundle/portable-paths.json",
                data=json_bytes(portable_paths(system_links)),
            ),
            tar_entry("bundle/provenance.json", data=b"{}\n"),
            tar_entry("bundle/body-comparison.json", data=b"{}\n"),
        ]
    )
    return entries


def inventory_for(entries: list[tuple[tarfile.TarInfo, bytes]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for info, data in entries:
        if info.name == "bundle/inventory.json":
            continue
        if info.isdir():
            records.append({"path": info.name, "type": "dir", "mode": info.mode})
        elif info.isreg():
            records.append(
                {
                    "path": info.name,
                    "type": "file",
                    "mode": info.mode,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        elif info.issym():
            records.append(
                {
                    "path": info.name,
                    "type": "symlink",
                    "mode": info.mode,
                    "target": info.linkname,
                }
            )
        elif info.islnk():
            records.append(
                {
                    "path": info.name,
                    "type": "hardlink",
                    "mode": info.mode,
                    "target": info.linkname,
                }
            )
    return sorted(records, key=lambda item: item["path"].encode())


def complete_inventory(entries: list[tuple[tarfile.TarInfo, bytes]]) -> None:
    inventory = {"version": 1, "entries": inventory_for(entries)}
    entries.append(tar_entry("bundle/inventory.json", data=json_bytes(inventory)))


def test_archive_checksum_fails_before_tar_parser(
    tmp_path: Path, verify_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "evidence.tar"
    archive.write_bytes(b"not a tar")

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("tar parser called before checksum verification")

    monkeypatch.setattr(verify_module.tarfile, "open", forbidden)
    with pytest.raises(verify_module.EvidenceError, match="archive SHA-256 mismatch"):
        verify_module.verify_archive_structure(archive, HEX)


@pytest.mark.parametrize(
    "raw_name",
    ["/bundle/evil", "bundle/a/./b", "bundle/a//b", "bundle/a/../b"],
)
def test_archive_rejects_unsafe_raw_member_names(
    tmp_path: Path, verify_module: ModuleType, raw_name: str
) -> None:
    archive = tmp_path / "unsafe.tar"
    entries = structural_entries()
    entries.append(tar_entry(raw_name, data=b"evil"))
    complete_inventory(entries)
    digest = write_tar(archive, entries)
    with pytest.raises(verify_module.EvidenceError, match="unsafe archive member name"):
        verify_module.verify_archive_structure(archive, digest)


def test_archive_rejects_duplicate_member_name(
    tmp_path: Path, verify_module: ModuleType
) -> None:
    archive = tmp_path / "duplicate.tar"
    entries = structural_entries()
    entries.extend(
        [tar_entry("bundle/dup", data=b"one"), tar_entry("bundle/dup", data=b"two")]
    )
    complete_inventory(entries)
    digest = write_tar(archive, entries)
    with pytest.raises(verify_module.EvidenceError, match="duplicate archive member"):
        verify_module.verify_archive_structure(archive, digest)


@pytest.mark.parametrize("kind", [tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE])
def test_archive_rejects_special_members(
    tmp_path: Path, verify_module: ModuleType, kind: bytes
) -> None:
    archive = tmp_path / "special.tar"
    entries = structural_entries()
    entries.append(tar_entry("bundle/special", kind=kind))
    complete_inventory(entries)
    digest = write_tar(archive, entries)
    with pytest.raises(
        verify_module.EvidenceError, match="unsupported archive member type"
    ):
        verify_module.verify_archive_structure(archive, digest)


@pytest.mark.parametrize(
    ("name", "kind", "target", "message"),
    [
        ("bundle/bad", tarfile.SYMTYPE, "missing", "link target is missing"),
        ("bundle/a", tarfile.SYMTYPE, "b", "link cycle"),
        ("bundle/hard", tarfile.LNKTYPE, "bundle/link", "hardlink must terminate"),
        ("bundle/hard", tarfile.LNKTYPE, "bundle/sub", "hardlink must terminate"),
    ],
)
def test_archive_rejects_invalid_link_graph(
    tmp_path: Path,
    verify_module: ModuleType,
    name: str,
    kind: bytes,
    target: str,
    message: str,
) -> None:
    archive = tmp_path / "bad-link.tar"
    entries = structural_entries()
    entries.append(tar_entry("bundle/sub", kind=tarfile.DIRTYPE, mode=0o755))
    entries.append(tar_entry("bundle/original", data=b"original"))
    entries.append(tar_entry("bundle/link", kind=tarfile.SYMTYPE, linkname="original"))
    entries.append(tar_entry(name, kind=kind, linkname=target))
    if name == "bundle/a":
        entries.append(tar_entry("bundle/b", kind=tarfile.SYMTYPE, linkname="a"))
    complete_inventory(entries)
    digest = write_tar(archive, entries)
    with pytest.raises(verify_module.EvidenceError, match=message):
        verify_module.verify_archive_structure(archive, digest)


@pytest.mark.parametrize("ancestor_kind", [tarfile.SYMTYPE, tarfile.LNKTYPE])
def test_archive_rejects_member_below_link_ancestor(
    tmp_path: Path, verify_module: ModuleType, ancestor_kind: bytes
) -> None:
    archive = tmp_path / "link-ancestor.tar"
    entries = structural_entries()
    entries.extend(
        [
            tar_entry("bundle/target", kind=tarfile.DIRTYPE, mode=0o755),
            tar_entry(
                "bundle/alias",
                kind=ancestor_kind,
                linkname="target"
                if ancestor_kind == tarfile.SYMTYPE
                else "bundle/file",
            ),
            tar_entry("bundle/file", data=b"file"),
            tar_entry("bundle/alias/child", data=b"child"),
        ]
    )
    complete_inventory(entries)
    digest = write_tar(archive, entries)
    with pytest.raises(verify_module.EvidenceError, match="link-valued ancestor"):
        verify_module.verify_archive_structure(archive, digest)


def test_archive_accepts_links_and_root_relative_hardlink(
    tmp_path: Path, verify_module: ModuleType
) -> None:
    pairs = [
        {"source": "/usr/bin/cc", "raw_target": "/etc/alternatives/cc"},
        {"source": "/usr/bin/ld", "raw_target": "../lib/ld.real"},
    ]
    archive = tmp_path / "links.tar"
    entries = structural_entries(system_links=pairs)
    entries.extend(
        [
            tar_entry("bundle/sub", kind=tarfile.DIRTYPE, mode=0o755),
            tar_entry("bundle/original", data=b"original", mode=0o755),
            tar_entry(
                "bundle/sub/copy",
                kind=tarfile.LNKTYPE,
                mode=0o755,
                linkname="bundle/original",
            ),
            tar_entry("bundle/ordinary", kind=tarfile.SYMTYPE, linkname="original"),
            tar_entry("bundle/system-root/usr", kind=tarfile.DIRTYPE, mode=0o755),
            tar_entry("bundle/system-root/usr/bin", kind=tarfile.DIRTYPE, mode=0o755),
            tar_entry("bundle/system-root/usr/lib", kind=tarfile.DIRTYPE, mode=0o755),
            tar_entry("bundle/system-root/etc", kind=tarfile.DIRTYPE, mode=0o755),
            tar_entry(
                "bundle/system-root/etc/alternatives",
                kind=tarfile.DIRTYPE,
                mode=0o755,
            ),
            tar_entry(
                "bundle/system-root/usr/bin/cc",
                kind=tarfile.SYMTYPE,
                mode=0o777,
                linkname="/etc/alternatives/cc",
            ),
            tar_entry("bundle/system-root/etc/alternatives/cc", data=b"cc", mode=0o755),
            tar_entry(
                "bundle/system-root/usr/bin/ld",
                kind=tarfile.SYMTYPE,
                mode=0o777,
                linkname="../lib/ld.real",
            ),
            tar_entry("bundle/system-root/usr/lib/ld.real", data=b"ld", mode=0o755),
        ]
    )
    complete_inventory(entries)
    digest = write_tar(archive, entries)
    result = verify_module.verify_archive_structure(archive, digest)
    assert result.archive_sha256 == digest
    assert (
        result.members[Path("bundle/sub/copy").as_posix()].resolved_target
        == Path("bundle/original").as_posix()
    )


@pytest.mark.parametrize(
    ("member", "target"),
    [
        ("bundle/outside", "/etc/passwd"),
        ("bundle/system-root/usr/bin/cc", "/etc/alternatives/cc"),
        ("bundle/system-root/usr/bin/ld", "../lib/ld.real"),
    ],
)
def test_archive_rejects_unallowlisted_system_link(
    tmp_path: Path, verify_module: ModuleType, member: str, target: str
) -> None:
    archive = tmp_path / "unallowlisted.tar"
    entries = structural_entries()
    for directory in (
        "bundle/system-root/usr",
        "bundle/system-root/usr/bin",
        "bundle/system-root/usr/lib",
        "bundle/system-root/etc",
        "bundle/system-root/etc/alternatives",
    ):
        entries.append(tar_entry(directory, kind=tarfile.DIRTYPE, mode=0o755))
    entries.extend(
        [
            tar_entry(member, kind=tarfile.SYMTYPE, linkname=target),
            tar_entry("bundle/system-root/etc/alternatives/cc", data=b"cc"),
            tar_entry("bundle/system-root/usr/lib/ld.real", data=b"ld"),
        ]
    )
    complete_inventory(entries)
    digest = write_tar(archive, entries)
    expected = (
        "unallowlisted absolute system link"
        if member == "bundle/outside"
        else "unallowlisted system link"
    )
    with pytest.raises(verify_module.EvidenceError, match=expected):
        verify_module.verify_archive_structure(archive, digest)


def test_archive_rejects_missing_allowlisted_chain_member(
    tmp_path: Path, verify_module: ModuleType
) -> None:
    pairs = [{"source": "/usr/bin/ld", "raw_target": "../lib/ld.real"}]
    archive = tmp_path / "missing-chain.tar"
    entries = structural_entries(system_links=pairs)
    for directory in (
        "bundle/system-root/usr",
        "bundle/system-root/usr/bin",
        "bundle/system-root/usr/lib",
    ):
        entries.append(tar_entry(directory, kind=tarfile.DIRTYPE, mode=0o755))
    entries.append(
        tar_entry(
            "bundle/system-root/usr/bin/ld",
            kind=tarfile.SYMTYPE,
            linkname="../lib/ld.real",
        )
    )
    complete_inventory(entries)
    digest = write_tar(archive, entries)
    with pytest.raises(verify_module.EvidenceError, match="link target is missing"):
        verify_module.verify_archive_structure(archive, digest)


def test_archive_rejects_inventory_mismatch(
    tmp_path: Path, verify_module: ModuleType
) -> None:
    archive = tmp_path / "inventory.tar"
    entries = structural_entries()
    entries.append(tar_entry("bundle/proof", data=b"proof"))
    complete_inventory(entries)
    inventory_info, inventory_data = entries[-1]
    inventory = json.loads(inventory_data)
    next(item for item in inventory["entries"] if item["path"] == "bundle/proof")[
        "sha256"
    ] = HEX
    entries[-1] = (inventory_info, json_bytes(inventory))
    digest = write_tar(archive, entries)
    with pytest.raises(verify_module.EvidenceError, match="inventory mismatch"):
        verify_module.verify_archive_structure(archive, digest)


def test_extraction_rejects_preexisting_root(
    tmp_path: Path, verify_module: ModuleType
) -> None:
    destination = tmp_path / "existing"
    destination.mkdir()
    with pytest.raises(
        verify_module.EvidenceError, match="extraction root already exists"
    ):
        verify_module.extract_validated_archive({}, destination)


def test_package_round_trip_is_deterministic_and_preserves_metadata(
    tmp_path: Path, package_module: ModuleType, verify_module: ModuleType
) -> None:
    staging = tmp_path / "staging"
    bundle = staging / "bundle"
    for root in (
        "orchestrator",
        "subject",
        "v1",
        "evidence/logs",
        "toolchain/bin",
        "system-root",
    ):
        (bundle / root).mkdir(parents=True, exist_ok=True)
    (bundle / "evidence/logs/.hidden").write_bytes(b"hidden\n")
    executable = bundle / "toolchain/bin/tool"
    executable.write_bytes(b"#!/bin/sh\n")
    executable.chmod(0o755)
    (bundle / "ordinary").symlink_to("evidence/logs/.hidden")
    (bundle / "provenance.json").write_bytes(b"{}\n")
    (bundle / "portable-paths.json").write_bytes(json_bytes(portable_paths()))
    (bundle / "body-comparison.json").write_bytes(b"{}\n")

    first = tmp_path / "first.tar"
    second = tmp_path / "second.tar"
    package_module.package_evidence(staging, first, tmp_path / "first.tar.sha256")
    package_module.package_evidence(staging, second, tmp_path / "second.tar.sha256")
    assert first.read_bytes() == second.read_bytes()
    digest = hashlib.sha256(first.read_bytes()).hexdigest()
    structure = verify_module.verify_archive_structure(first, digest)
    assert structure.members["bundle/evidence/logs/.hidden"].mode == 0o644
    assert structure.members["bundle/toolchain/bin/tool"].mode == 0o755
    assert structure.members["bundle/ordinary"].raw_target == "evidence/logs/.hidden"
    assert (tmp_path / "first.tar.sha256").read_text() == f"{digest}  first.tar\n"


def test_package_rejects_non_bundle_top_level(
    tmp_path: Path, package_module: ModuleType
) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "bundle").mkdir()
    (staging / "extra").write_text("extra")
    with pytest.raises(
        package_module.EvidenceError, match="exactly one top-level bundle"
    ):
        package_module.package_evidence(
            staging, tmp_path / "out.tar", tmp_path / "out.tar.sha256"
        )


def test_package_rejects_unlisted_hardlink(
    tmp_path: Path, package_module: ModuleType
) -> None:
    staging = tmp_path / "staging"
    bundle = staging / "bundle"
    bundle.mkdir(parents=True)
    original = bundle / "original"
    original.write_bytes(b"same inode")
    os.link(original, bundle / "copy")
    (bundle / "provenance.json").write_bytes(b"{}\n")
    with pytest.raises(package_module.EvidenceError, match="unlisted hardlink"):
        package_module.package_evidence(
            staging, tmp_path / "out.tar", tmp_path / "out.tar.sha256"
        )


def semantic_documents() -> dict[str, dict[str, Any]]:
    file_sha = hashlib.sha256(b"payload").hexdigest()
    body = {
        "size": 7,
        "normalized_instructions_sha256": "1" * 64,
        "direct_calls": ["callee"],
        "indirect_calls": 0,
        "frame_adjustment": 16,
        "spills": ["x19"],
        "raw_sha256": "2" * 64,
        "placement": {"section": ".text.one", "address": 4096},
    }
    body_rows = [
        {
            "kernel": f"kernel-{index}",
            "v1": copy.deepcopy(body),
            "v2": copy.deepcopy(body),
        }
        for index in range(8)
    ]
    return {
        "capability": {
            "version": 1,
            "accepted": True,
            "arch": "x86_64",
            "records": [
                {
                    "flavor": flavor,
                    "target": target,
                    "kernel_count": count,
                    "invocation_path": f"/usr/bin/{flavor}",
                    "invocation_chain": [f"/usr/bin/{flavor}"],
                    "artifacts": [
                        {
                            "absolute_path": f"/host/subject/{flavor}-{target}",
                            "sha256": file_sha,
                        }
                    ],
                }
                for flavor in ("actual", "gnu", "lld")
                for target, count in (("elastic", 2), ("funnel", 2), ("profile", 4))
            ],
        },
        "manifest_v2": {
            "version": 2,
            "kind": "clean-a",
            "runner_root": "/host/subject",
            "environment": {"PATH": "/host/toolchain/bin:/usr/bin:/bin"},
            "executables": [
                {
                    "name": "elastic",
                    "absolute_path": "/host/subject/payload",
                    "sha256": file_sha,
                    "rustc_argv": [
                        "rustc",
                        "/host/subject/input.rs",
                        "-o",
                        "/host/subject/out",
                        "-L",
                        "/host/subject/lib",
                        "--extern",
                        "dep=/host/subject/libdep.rlib",
                        "-C",
                        "linker=/usr/bin/actual",
                        "-C",
                        "link-arg=@/host/subject/link.rsp",
                    ],
                }
            ],
            "aggregate": {
                "cgu": "a",
                "objects": "b",
                "link_order": ["one", "one", "two"],
                "semantic": "same",
            },
            "bodies": [
                {"kernel": f"kernel-{index}", **copy.deepcopy(body)}
                for index in range(8)
            ],
        },
        "manifest_v1": {
            "version": 1,
            "runner_root": "/host/v1",
            "executables": [
                {
                    "name": "elastic",
                    "absolute_path": "/host/v1/payload",
                    "sha256": file_sha,
                }
            ],
            "bodies": [
                {"kernel": f"kernel-{index}", **copy.deepcopy(body)}
                for index in range(8)
            ],
        },
        "provenance": {
            "version": 1,
            "subject": {"commit": "a" * 40, "tree": "b" * 40},
            "run": {"id": 7, "attempt": 2, "derived_attempt": 7002},
            "documents": {
                "capability": "bundle/evidence/capability.json",
                "manifests": [
                    "bundle/evidence/clean-a.json",
                    "bundle/evidence/clean-b.json",
                    "bundle/evidence/adversary.json",
                ],
                "v1_manifest": "bundle/evidence/v1.json",
                "transcripts": ["bundle/evidence/transcript.json"],
            },
            "hardlinks": [],
        },
        "inventory": {
            "version": 1,
            "entries": [
                {
                    "path": "bundle/subject/payload",
                    "type": "file",
                    "mode": 420,
                    "size": 7,
                    "sha256": file_sha,
                }
            ],
        },
        "transcript": {
            "version": 1,
            "kind": "link",
            "argv": [
                "/usr/bin/actual",
                "/host/subject/input.o",
                "-o",
                "/host/subject/out",
            ],
            "status": 0,
            "ordered_inputs": ["/host/subject/input.o", "/host/subject/input.o"],
        },
        "body_comparison": {
            "version": 1,
            "fields": list(
                (
                    "size",
                    "normalized_instructions_sha256",
                    "direct_calls",
                    "indirect_calls",
                    "frame_adjustment",
                    "spills",
                )
            ),
            "rows": body_rows,
        },
        "portable_paths": portable_paths(),
    }


def nested_objects(
    value: Any, path: tuple[str, ...] = ()
) -> list[tuple[tuple[str, ...], dict[str, Any]]]:
    found: list[tuple[tuple[str, ...], dict[str, Any]]] = []
    if isinstance(value, dict):
        found.append((path, value))
        for key, child in value.items():
            found.extend(nested_objects(child, path + (key,)))
    elif isinstance(value, list):
        for child in value:
            found.extend(nested_objects(child, path + ("*",)))
    return found


def at_path(value: Any, path: tuple[str, ...]) -> Any:
    current = value
    for component in path:
        current = current[0] if component == "*" else current[component]
    return current


def test_classifier_is_closed_and_covers_required_routes(
    verify_module: ModuleType,
) -> None:
    assert verify_module.classify(("manifest", "runner_root")) == "root"
    assert (
        verify_module.classify(("manifest", "executables", "*", "absolute_path"))
        == "hashed-file"
    )
    assert (
        verify_module.classify(("manifest", "executables", "*", "rustc_argv"))
        == "rustc-command"
    )
    assert verify_module.classify(("manifest", "environment", "PATH")) == "path-list"
    with pytest.raises(verify_module.EvidenceError, match="unclassified path field"):
        verify_module.classify(("manifest", "binary"))


@pytest.mark.parametrize("kind", list(semantic_documents()))
def test_recursive_schema_rejects_unknown_key_before_routing(
    verify_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    documents = semantic_documents()
    target_kind = kind
    path, _ = nested_objects(documents[target_kind])[-1]
    mutated = copy.deepcopy(documents)
    at_path(mutated[target_kind], path)["binary"] = "unknown"
    called = False

    def classifier_spy(_path: tuple[str, ...]) -> str:
        nonlocal called
        called = True
        raise AssertionError("routing called before structural gate")

    monkeypatch.setattr(verify_module, "classify", classifier_spy)
    with pytest.raises(verify_module.EvidenceError, match="schema mismatch"):
        verify_module.validate_document_set(mutated)
    assert not called


@pytest.mark.parametrize("kind", list(semantic_documents()))
def test_recursive_schema_rejects_missing_key_before_routing(
    verify_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    documents = semantic_documents()
    path, target = nested_objects(documents[kind])[-1]
    key = next(iter(target))
    mutated = copy.deepcopy(documents)
    del at_path(mutated[kind], path)[key]
    called = False

    def classifier_spy(_path: tuple[str, ...]) -> str:
        nonlocal called
        called = True
        raise AssertionError("routing called before structural gate")

    monkeypatch.setattr(verify_module, "classify", classifier_spy)
    with pytest.raises(verify_module.EvidenceError, match="schema mismatch"):
        verify_module.validate_document_set(mutated)
    assert not called


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("portable_paths", "version"), "1"),
        (("portable_paths", "roots"), {}),
        (("portable_paths", "roots", "*", "hosted"), []),
        (("portable_paths", "system_links"), {}),
        (("portable_paths", "routing_records", "*", "key_path"), []),
        (("inventory", "entries", "*", "mode"), True),
        (("transcript", "argv"), "not-a-list"),
    ],
)
def test_schema_rejects_wrong_types(
    verify_module: ModuleType, path: tuple[str, ...], value: Any
) -> None:
    documents = semantic_documents()
    parent = at_path(documents, path[:-1])
    key = path[-1]
    if key == "*":
        raise AssertionError("test path must end in field")
    parent[key] = value
    with pytest.raises(
        verify_module.EvidenceError, match="schema mismatch|type mismatch"
    ):
        verify_module.validate_document_set(documents)


def test_body_comparison_ignores_raw_hash_and_placement(
    verify_module: ModuleType,
) -> None:
    rows = semantic_documents()["body_comparison"]["rows"]
    rows[0]["v2"]["raw_sha256"] = "f" * 64
    rows[0]["v2"]["placement"] = {"section": ".other", "address": 9999}
    digest = verify_module.verify_body_rows(rows)
    assert len(digest) == 64


@pytest.mark.parametrize(
    "field",
    [
        "size",
        "normalized_instructions_sha256",
        "direct_calls",
        "indirect_calls",
        "frame_adjustment",
        "spills",
    ],
)
def test_body_comparison_rejects_semantic_change(
    verify_module: ModuleType, field: str
) -> None:
    rows = semantic_documents()["body_comparison"]["rows"]
    current = rows[0]["v2"][field]
    rows[0]["v2"][field] = (
        current + 1
        if isinstance(current, int)
        else ["changed"]
        if isinstance(current, list)
        else "f" * 64
    )
    with pytest.raises(verify_module.EvidenceError, match="body mismatch"):
        verify_module.verify_body_rows(rows)


@pytest.mark.parametrize(
    "command",
    [
        ["rustc", "--out-dir=/host/subject/out"],
        ["rustc", "@relative.rsp"],
        ["rustc", "-C", "link-arg=-T/unknown/layout.ld"],
        ["rustc", "/outside/input.rs"],
    ],
)
def test_rustc_command_rejects_unclassified_path_positions(
    verify_module: ModuleType, command: list[str]
) -> None:
    roots = verify_module.PortableRoots.from_document(portable_paths())
    with pytest.raises(
        verify_module.EvidenceError, match="unclassified|outside declared roots"
    ):
        verify_module.validate_command(command, roots, rustc=True)


def test_path_list_rejects_empty_and_cross_namespace_entries(
    verify_module: ModuleType,
) -> None:
    roots = verify_module.PortableRoots.from_document(portable_paths())
    with pytest.raises(verify_module.EvidenceError, match="empty PATH element"):
        verify_module.validate_path_list("/host/toolchain/bin::/usr/bin", roots)
    with pytest.raises(verify_module.EvidenceError, match="root namespace mismatch"):
        roots.map_path("/host/toolchain/bin/rustc", expected_root="subject")


@pytest.mark.parametrize("owner", ["bad", "foo.rlib(", "foo.rlib()", "(member.o)"])
def test_rlib_owner_rejects_malformed_value(
    verify_module: ModuleType, owner: str
) -> None:
    with pytest.raises(verify_module.EvidenceError, match="malformed rlib"):
        verify_module.parse_rlib_owner(owner)


def test_semantic_aggregate_comparison_preserves_order_and_duplicates(
    verify_module: ModuleType,
) -> None:
    documents = semantic_documents()
    clean = documents["manifest_v2"]
    clean_b = copy.deepcopy(clean)
    clean_b["kind"] = "clean-b"
    adversary = copy.deepcopy(clean)
    adversary["kind"] = "adversary"
    adversary["aggregate"]["cgu"] = "different"
    adversary["aggregate"]["objects"] = "different"
    adversary["aggregate"]["semantic"] = clean["aggregate"]["semantic"]
    verify_module.verify_manifest_relationships(clean, clean_b, adversary)
    clean_b["aggregate"]["link_order"] = ["one", "two", "one"]
    with pytest.raises(verify_module.EvidenceError, match="clean aggregate mismatch"):
        verify_module.verify_manifest_relationships(clean, clean_b, adversary)


def write_semantic_staging(staging: Path) -> dict[str, dict[str, Any]]:
    documents = semantic_documents()
    bundle = staging / "bundle"
    for root in (
        "orchestrator",
        "subject",
        "v1",
        "evidence",
        "toolchain/bin",
        "system-root/usr/bin",
        "system-root/bin",
    ):
        (bundle / root).mkdir(parents=True, exist_ok=True)
    for name in ("actual", "gnu", "lld"):
        (bundle / f"system-root/usr/bin/{name}").write_bytes(b"linker")
    for flavor in ("actual", "gnu", "lld"):
        for target in ("elastic", "funnel", "profile"):
            (bundle / f"subject/{flavor}-{target}").write_bytes(b"payload")
    (bundle / "subject/payload").write_bytes(b"payload")
    (bundle / "v1/payload").write_bytes(b"payload")

    clean_a = documents["manifest_v2"]
    clean_b = copy.deepcopy(clean_a)
    clean_b["kind"] = "clean-b"
    adversary = copy.deepcopy(clean_a)
    adversary["kind"] = "adversary"
    adversary["aggregate"]["cgu"] = "different-cgu"
    adversary["aggregate"]["objects"] = "different-objects"
    named_documents = {
        "capability.json": documents["capability"],
        "clean-a.json": clean_a,
        "clean-b.json": clean_b,
        "adversary.json": adversary,
        "v1.json": documents["manifest_v1"],
        "transcript.json": documents["transcript"],
    }
    for name, document in named_documents.items():
        (bundle / f"evidence/{name}").write_bytes(json_bytes(document))
    (bundle / "provenance.json").write_bytes(json_bytes(documents["provenance"]))
    (bundle / "portable-paths.json").write_bytes(
        json_bytes(documents["portable_paths"])
    )
    (bundle / "body-comparison.json").write_bytes(
        json_bytes(documents["body_comparison"])
    )
    return documents


def test_verify_archive_returns_stable_ready_report(
    tmp_path: Path, package_module: ModuleType, verify_module: ModuleType
) -> None:
    staging = tmp_path / "staging"
    documents = write_semantic_staging(staging)
    archive = tmp_path / "evidence.tar"
    digest = package_module.package_evidence(
        staging, archive, tmp_path / "evidence.tar.sha256"
    )
    report = verify_module.verify_archive(archive, digest)
    assert report.status == "READY"
    assert report.archive_sha256 == digest
    assert report.subject_commit == "a" * 40
    assert report.subject_tree == "b" * 40
    assert (report.run_id, report.run_attempt) == (7, 2)
    assert report.body_comparison_sha256 == verify_module.verify_body_rows(
        documents["body_comparison"]["rows"]
    )
    assert len(report.manifest_sha256s) == 3
