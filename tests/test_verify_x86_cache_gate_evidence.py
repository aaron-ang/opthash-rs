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
REVIEWED_RECORDS = (
    ROOT / "tests/fixtures/x86_cache_gate_evidence" / "aarch64-attempt-5-records.tar.xz"
)
REVIEWED_RECORDS_SHA256 = (
    "100920ab673be133a57cd193c9d02118c2feb7bdc470e37c09e53124ee05d6ee"
)
HEX = "0" * 64
SUBJECT_COMMIT = "061d13da22b89208c801308efd578444c8e9caba"
SUBJECT_TREE = "24921a941f8c3c26467465b99d6b45ee5912b2da"
V1_REPLAY_COMMIT = "b0d53234dc051af91fe0321450b3e8312a84e635"
V1_REPLAY_TREE = "d77cc082fe48799f26ff4440bd1898a71d0dc8cc"
ORCHESTRATION_COMMIT = "a" * 40
ORCHESTRATION_TREE = "b" * 40
ORCHESTRATION_SOURCE_BYTES = {
    "workflow": b"workflow\n",
    "runner": b"runner\n",
    "packager": b"packager\n",
    "verifier": b"verifier\n",
}
ORCHESTRATION_SOURCE_PATHS = {
    "workflow": "bundle/orchestrator/.github/workflows/x86-cache-gate-evidence.yml",
    "runner": "bundle/orchestrator/scripts/run-x86-cache-gate-evidence.sh",
    "packager": "bundle/orchestrator/scripts/package-x86-cache-gate-evidence.py",
    "verifier": "bundle/orchestrator/scripts/verify-x86-cache-gate-evidence.py",
}
PINNED_CARGO_VERSION = "cargo 1.95.0 (f2d3ce0bd 2026-03-21)"
PINNED_RUSTC_VERSION = (
    "rustc 1.95.0 (59807616e 2026-04-14)\n"
    "binary: rustc\n"
    "commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860\n"
    "commit-date: 2026-04-14\n"
    "host: x86_64-unknown-linux-gnu\n"
    "release: 1.95.0\n"
    "LLVM version: 22.1.2"
)
EXPECTED_BODY_FIELDS = (
    "size",
    "normalized_instructions_sha256",
    "direct_calls",
    "indirect_calls",
    "frame_adjustment",
    "spills",
)
FORBIDDEN_BODY_FIELD_VALUES = (
    ("raw_sha256", "2" * 64),
    ("placement", {"section": ".text.one", "address": 4096}),
    ("section", ".text.one"),
    ("address", 4096),
)
KERNEL_SENTINEL_STEMS = {
    "elastic_cache_gate_insert_kernel": "elastic_insert",
    "elastic_cache_gate_get_kernel": "elastic_get",
    "funnel_cache_gate_insert_kernel": "funnel_insert",
    "funnel_cache_gate_get_kernel": "funnel_get",
    "elastic_profile_insert_kernel": "profile_elastic_insert",
    "elastic_profile_get_kernel": "profile_elastic_get",
    "funnel_profile_insert_kernel": "profile_funnel_insert",
    "funnel_profile_get_kernel": "profile_funnel_get",
}
SUBJECT_TOOL_IDENTITIES = {
    "elf_layout": (
        "scripts/cache-gate-elf-layout.py",
        "38d77e3253673342ac8150836dae2f790386c152",
        "b6cb974d815b1bfb3132632fade62bf894bd431f8f0836e5a7ddd026be69e088",
    ),
    "extractor": (
        "scripts/extract-hot-symbols.py",
        "c6f856f32f7207a5a7975a9332039e4141f11403",
        "8553fed90042dbde1414f8d6c17e123d5c1d3dc0101c66fa336ef098e84293f7",
    ),
    "launcher": (
        "scripts/cache-gate.sh",
        "ef778aa3c7bbe8795af9d6d878a4e830a26cea79",
        "9d549d7a19e31a6d8cba13339955aff2e5f8b26539429a67aedfaf7de393dddc",
    ),
    "link_wrapper": (
        "scripts/cache-gate-link-wrapper.py",
        "34b6761cb5f27d61553bb69105ad16b6b5bbe10a",
        "afdb7442212dc346db0104b95d218e96b85e628e1f1ed7b6ad59203ab1e3a08c",
    ),
    "perf_launcher": (
        "scripts/cache-gate-perf.sh",
        "ce8d418fd6c7d1b798affdc4e9cf5fba69db2cc2",
        "02d96dd5347ef52d96f5a1418ce15905087105d6ee80b9523af6353059f7fbd8",
    ),
    "perf_support": (
        "scripts/cache-gate-perf-support.py",
        "7f5434d586a1466e171f4e343adc79b3d5e224e3",
        "8bc1de76aa791b7b10d9934db32d12f7da4d774537a00ce7d8bd99549bed4531",
    ),
    "snapshot": (
        "scripts/snapshot-criterion-pair.sh",
        "ce25155fcca66c2e1a2129c51562dad912335a42",
        "5a050eb68b3abf8d398e7849abb2cb08fddaac8e88e1fef24314dbfbaba77607",
    ),
}
CONTROL_INPUT_IDENTITIES = {
    "cargo_manifest": (
        "tools/cache-gate-control/Cargo.toml",
        "086cbc963cf2b336da7f4f0ee8d06cd17c475ed1c31956058e410d05e09634dd",
    ),
    "cargo_lock": (
        "tools/cache-gate-control/Cargo.lock",
        "c8e86f671e65831bcd69ca653ae6c5761bc32ff671c24b9cac19ab17879e8666",
    ),
    "source": (
        "tools/cache-gate-control/src/main.rs",
        "2efeafb631c3bc1b04bb35729f83f221168bf0d55e02e383912c78b18d722e8c",
    ),
}
REVIEWED_RECORD_SHA256S = {
    "capability.json": "29a43afea6137683f8b8df0bcc6864c753697b1cc4de51276dd9ab7770558d6f",
    "clean-a.json": "0f2af3d5f2aad807c00abf243f3a821da6bd2917a3174e69e679f1b438b0bfc9",
    "clean-b.json": "d416c6e698e491a294807591c534e271b7a4ef42f6074dbd15675ef22f62a20d",
    "adversary.json": "86fed381cc8a17b9b7fad3e4d90cb2cbbf845e01c8b265de90396e3fbca5567d",
    "v1.json": "b48df7e6221402b4e3d099262a1b3f1e8f3a13568c160f390b2ca735ee0fafd9",
}


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


def reviewed_records() -> dict[str, Any]:
    assert REVIEWED_RECORDS.is_file(), (
        "checked-in reviewed cache-gate records are required"
    )
    assert hashlib.sha256(REVIEWED_RECORDS.read_bytes()).hexdigest() == (
        REVIEWED_RECORDS_SHA256
    )
    with tarfile.open(REVIEWED_RECORDS, mode="r:xz") as archive:
        members = {item.name: item for item in archive.getmembers() if item.isfile()}
        for name, expected in REVIEWED_RECORD_SHA256S.items():
            assert name in members
            extracted = archive.extractfile(members[name])
            assert extracted is not None
            data = extracted.read()
            assert hashlib.sha256(data).hexdigest() == expected
            members[name] = data
        shape_records: dict[str, bytes] = {}
        manifest_link_records: dict[str, bytes] = {}
        for name, item in list(members.items()):
            if not isinstance(item, tarfile.TarInfo):
                continue
            if not name.startswith(
                (
                    "capability-shapes/",
                    "manifest-link-commands/",
                    "manifest-link-traces/",
                )
            ):
                continue
            extracted = archive.extractfile(item)
            assert extracted is not None
            data = extracted.read()
            if name.startswith("capability-shapes/"):
                shape_records[name] = data
            else:
                manifest_link_records[name] = data
    return {
        "capability": json.loads(members["capability.json"]),
        "clean_a": json.loads(members["clean-a.json"]),
        "clean_b": json.loads(members["clean-b.json"]),
        "adversary": json.loads(members["adversary.json"]),
        "v1": json.loads(members["v1.json"]),
        "shape_records": shape_records,
        "manifest_link_records": manifest_link_records,
    }


def reviewed_record_roots(verify_module: ModuleType, records: dict[str, Any]) -> Any:
    capability = records["capability"]
    subject = capability["producer"]["runner_root"]
    v1 = str(
        Path(
            records["v1"]["executables"]["elastic_cache_gate"]["absolute_path"]
        ).parents[3]
    )
    document = full_portable_paths(verify_module)
    hosted = {
        "orchestrator": "/home/aang",
        "subject": subject,
        "v1": v1,
        "evidence": f"{subject}/target/cache-gate-evidence",
        "toolchain": "/home/aang/.rustup",
        "cargo-registry": "/home/aang/.cargo/registry",
        "system-root": "/",
    }
    for root in document["roots"]:
        root["hosted"] = hosted[root["name"]]
    return verify_module.PortableRoots.from_document(document)


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


def test_package_pins_scanned_directory_descriptors(
    tmp_path: Path,
    package_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "staging"
    bundle = staging / "bundle"
    subdirectory = bundle / "sub"
    subdirectory.mkdir(parents=True)
    (bundle / "provenance.json").write_bytes(b"{}\n")
    (subdirectory / "proof.bin").write_bytes(b"trusted")
    original_write_archive = package_module._write_archive

    def swap_then_write(path: Path, entries: list[Any]) -> str:
        retired = bundle / "retired"
        subdirectory.rename(retired)
        subdirectory.mkdir()
        (subdirectory / "proof.bin").write_bytes(b"forged!")
        return original_write_archive(path, entries)

    monkeypatch.setattr(package_module, "_write_archive", swap_then_write)
    archive = tmp_path / "out.tar"
    with pytest.raises(
        package_module.EvidenceError,
        match="staging tree changed while packaging",
    ):
        package_module.package_evidence(staging, archive, tmp_path / "out.tar.sha256")


def test_package_hashes_bytes_read_from_archive_file_descriptor(
    tmp_path: Path,
    package_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "staging"
    bundle = staging / "bundle"
    bundle.mkdir(parents=True)
    proof = bundle / "proof.bin"
    proof.write_bytes(b"trusted")
    (bundle / "provenance.json").write_bytes(b"{}\n")
    original_addfile = package_module.tarfile.TarFile.addfile

    def mutate_before_read(
        archive: tarfile.TarFile,
        info: tarfile.TarInfo,
        fileobj: Any = None,
    ) -> None:
        if info.name == "bundle/proof.bin" and fileobj is not None:
            proof.write_bytes(b"forged!")
        original_addfile(archive, info, fileobj)

    monkeypatch.setattr(
        package_module.tarfile.TarFile,
        "addfile",
        mutate_before_read,
    )
    with pytest.raises(
        package_module.EvidenceError,
        match="changed while packaging|archive bytes differ",
    ):
        package_module.package_evidence(
            staging, tmp_path / "out.tar", tmp_path / "out.tar.sha256"
        )


def test_package_keeps_provenance_authority_pinned_through_archive(
    tmp_path: Path,
    package_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "staging"
    bundle = staging / "bundle"
    bundle.mkdir(parents=True)
    original = bundle / "original"
    original.write_bytes(b"same inode")
    os.link(original, bundle / "copy")
    provenance = bundle / "provenance.json"
    provenance.write_bytes(
        json_bytes(
            {
                "hardlinks": [
                    {"path": "bundle/copy", "target": "bundle/original"},
                ]
            }
        )
    )
    original_walk = package_module._walk
    swapped = False

    def swap_provenance_then_walk(*args: Any, **kwargs: Any) -> Any:
        nonlocal swapped
        if not swapped:
            replacement = bundle / "replacement.json"
            replacement.write_bytes(json_bytes({"hardlinks": []}))
            replacement.replace(provenance)
            swapped = True
        return original_walk(*args, **kwargs)

    monkeypatch.setattr(package_module, "_walk", swap_provenance_then_walk)
    with pytest.raises(
        package_module.EvidenceError,
        match="provenance.*changed|staging tree changed",
    ):
        package_module.package_evidence(
            staging, tmp_path / "out.tar", tmp_path / "out.tar.sha256"
        )


def test_extracted_reads_require_exact_member_and_no_follow_ancestors(
    tmp_path: Path,
    verify_module: ModuleType,
) -> None:
    root = tmp_path / "root"
    (root / "bundle/subject").mkdir(parents=True)
    (root / "bundle/evidence").mkdir(parents=True)
    (root / "bundle/evidence/proof").write_bytes(b"forged")
    (root / "bundle/subject/alias").symlink_to("../evidence", target_is_directory=True)
    members = {
        path: verify_module.MemberRecord(
            path,
            kind,
            0o755 if kind == "dir" else 0o644,
            0,
            "../evidence" if kind == "symlink" else "",
            "",
            tarfile.TarInfo(path),
        )
        for path, kind in (
            ("bundle", "dir"),
            ("bundle/subject", "dir"),
            ("bundle/evidence", "dir"),
            ("bundle/evidence/proof", "file"),
            ("bundle/subject/alias", "symlink"),
        )
    }
    with pytest.raises(
        verify_module.EvidenceError,
        match="exact archive member|missing from archive",
    ):
        verify_module._read_extracted(
            root,
            members,
            "bundle/subject/alias/proof",
        )

    real_directory = root / "bundle/subject/real"
    real_directory.mkdir()
    (real_directory / "proof").write_bytes(b"trusted")
    members["bundle/subject/real"] = verify_module.MemberRecord(
        "bundle/subject/real",
        "dir",
        0o755,
        0,
        "",
        "",
        tarfile.TarInfo("bundle/subject/real"),
    )
    members["bundle/subject/real/proof"] = verify_module.MemberRecord(
        "bundle/subject/real/proof",
        "file",
        0o644,
        7,
        "",
        "",
        tarfile.TarInfo("bundle/subject/real/proof"),
    )
    real_directory.rename(root / "bundle/subject/retired")
    real_directory.symlink_to("../../evidence", target_is_directory=True)
    with pytest.raises(
        verify_module.EvidenceError, match="no-follow|ancestor|directory"
    ):
        verify_module._read_extracted(
            root,
            members,
            "bundle/subject/real/proof",
        )


def test_provenance_hardlinks_must_equal_tar_and_inventory(
    verify_module: ModuleType,
) -> None:
    hardlink = verify_module.MemberRecord(
        "bundle/copy",
        "hardlink",
        0o644,
        0,
        "bundle/original",
        "bundle/original",
        tarfile.TarInfo("bundle/copy"),
    )
    inventory = {
        "version": 1,
        "entries": [
            {
                "path": "bundle/copy",
                "type": "hardlink",
                "mode": 0o644,
                "target": "bundle/original",
            }
        ],
    }
    with pytest.raises(verify_module.EvidenceError, match="hardlink.*provenance"):
        verify_module._verify_provenance_hardlinks(
            {"hardlinks": []},
            {"bundle/copy": hardlink},
            inventory,
        )


def semantic_documents() -> dict[str, dict[str, Any]]:
    file_sha = hashlib.sha256(b"payload").hexdigest()
    body = {
        "size": 7,
        "normalized_instructions_sha256": "1" * 64,
        "direct_calls": ["callee"],
        "indirect_calls": [],
        "frame_adjustment": 16,
        "spills": ["x19"],
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
            "fields": list(EXPECTED_BODY_FIELDS),
            "rows": body_rows,
        },
        "portable_paths": portable_paths(),
    }


def schema_sample(schema: Any, verify_module: ModuleType) -> Any:
    if isinstance(schema, verify_module.ListSchema):
        return [schema_sample(schema.item, verify_module)]
    if isinstance(schema, verify_module.NullableSchema):
        return None
    if isinstance(schema, verify_module.LiteralSchema):
        return copy.deepcopy(schema.value)
    if isinstance(schema, dict):
        return {
            key: schema_sample(child, verify_module) for key, child in schema.items()
        }
    if schema is str:
        return "value"
    if schema is int:
        return 1
    if schema is bool:
        return False
    raise AssertionError(f"unsupported test schema: {schema!r}")


def rewrite_file_records(value: Any, absolute_path: str, sha256: str) -> None:
    if isinstance(value, dict):
        if {"absolute_path", "sha256"}.issubset(value):
            value["absolute_path"] = absolute_path
            value["sha256"] = sha256
        for child in value.values():
            rewrite_file_records(child, absolute_path, sha256)
    elif isinstance(value, list):
        for child in value:
            rewrite_file_records(child, absolute_path, sha256)


def full_portable_paths(verify_module: ModuleType) -> dict[str, Any]:
    archives = {
        "orchestrator": "bundle/orchestrator",
        "subject": "bundle/subject",
        "v1": "bundle/v1",
        "evidence": "bundle/evidence",
        "toolchain": "bundle/toolchain/rust",
        "cargo-registry": "bundle/toolchain/cargo-registry",
        "system-root": "bundle/system-root",
    }
    return {
        "version": 1,
        "roots": [
            {
                "name": name,
                "hosted": "/" if name == "system-root" else f"/host/{name}",
                "archive": archive,
            }
            for name, archive in archives.items()
        ],
        "system_links": [],
        "routing_records": [
            {"document": path[0], "key_path": list(path[1:]), "field_kind": kind}
            for path, kind in sorted(verify_module.PATH_ROUTES.items())
            if path not in verify_module.ROUTE_COMPATIBILITY_ALIASES
        ],
    }


def full_symbol(
    verify_module: ModuleType, kernel: str, *, v1: bool = False
) -> dict[str, Any]:
    schema = verify_module.SYMBOL_V1_SCHEMA if v1 else verify_module.SYMBOL_V2_SCHEMA
    symbol = schema_sample(schema, verify_module)
    symbol.update(
        {
            "name": f"crate::{kernel}",
            "start": 4096,
            "end": 4103,
            "size": 7,
            "kind": "T",
            "pattern": f"::{kernel}$",
            "section": ".text.proof",
            "file_offset": 64,
            "page_offset": 0,
            "raw_sha256": "2" * 64,
            "normalized_instructions_sha256": "1" * 64,
            "normalized_instructions": ["ret"],
            "direct_calls": ["callee"],
            "indirect_calls": [],
            "frame_adjustment": 16,
            "spills": ["x19"],
        }
    )
    if not v1:
        symbol.update(
            {
                "section_index": 1,
                "section_name": ".text.proof",
                "section_alignment": 16,
            }
        )
    else:
        symbol["declared_alignment"] = 16
    return symbol


def fixture_body_records(
    verify_module: ModuleType, manifest: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for executable in verify_module.EXECUTABLE_TARGETS:
        for symbol in manifest["symbols"][executable]["symbols"]:
            kernel = symbol["name"].rsplit("::", 1)[-1]
            records[kernel] = {
                "size": symbol["size"],
                "normalized_instructions_sha256": symbol[
                    "normalized_instructions_sha256"
                ],
                "direct_calls": copy.deepcopy(symbol["direct_calls"]),
                "indirect_calls": copy.deepcopy(symbol["indirect_calls"]),
                "frame_adjustment": symbol["frame_adjustment"],
                "spills": copy.deepcopy(symbol["spills"]),
            }
    return records


def bind_fixture_symbol_layout(
    symbols: dict[str, Any],
    layout: dict[str, Any],
    target: str,
    link_map_flavor: str,
) -> None:
    layout.update(
        {
            "target": target,
            "arch": symbols["architecture"],
            "link_map_flavor": link_map_flavor,
            "elf_type": "ET_DYN",
            "max_page_size": 4096,
            "program_headers_have_rwx": False,
            "program_headers": [
                {
                    "offset": 0,
                    "vaddr": 4096,
                    "filesz": 4096,
                    "memsz": 4096,
                    "flags": "R E",
                    "alignment": 4096,
                }
            ],
            "cache_gate_input_sections": [],
            "veneer_thunk_inventory": [],
            "plt_inventory": [],
        }
    )
    by_kernel = {
        symbol["name"].rsplit("::", 1)[-1]: symbol for symbol in symbols["symbols"]
    }
    for index, (kernel_name, kernel) in enumerate(layout["kernels"].items(), start=1):
        symbol = by_kernel[kernel_name]
        start = index * 4096
        body_end = start + symbol["size"]
        reservation_end = start + 4096
        symbol["start"] = start
        symbol["end"] = body_end
        symbol["page_offset"] = start % 4096
        section_stem = KERNEL_SENTINEL_STEMS[kernel_name].replace("_", ".")
        input_section = f".text.opthash.cache_gate.{section_stem}"
        output_section = f".opthash.cache_gate.{section_stem}"
        input_owner = f"/host/subject/{kernel_name}.o"
        kernel.update(
            {
                "name": kernel_name,
                "function_symbol_count": 1,
                "input_section": input_section,
                "input_section_count": 1,
                "input_owner": input_owner,
                "input_start": start,
                "input_end": body_end,
                "input_size": symbol["size"],
                "output_section": output_section,
                "output_section_count": 1,
                "output_section_index": symbol["section_index"],
                "output_start": start,
                "output_end": reservation_end,
                "reservation_start": start,
                "body_end": body_end,
                "reservation_end": reservation_end,
                "body_size": symbol["size"],
                "reservation_size": 4096,
                "page_offset": symbol["page_offset"],
                "max_page_remainder": 0,
                "sh_addralign": symbol["section_alignment"],
                "section_flags": ["ALLOC", "EXECINSTR"],
                "pt_load_count": 1,
                "pt_load_flags": "R E",
                "writable_segment_overlap": False,
                "overlapping_elf_sections": [],
                "function_start": start,
                "function_end": body_end,
                "function_size": symbol["size"],
                "function_section_index": symbol["section_index"],
                "function_section_name": output_section,
                "raw_sha256": symbol["raw_sha256"],
                "normalized_sha256": symbol["normalized_instructions_sha256"],
                "direct_calls": copy.deepcopy(symbol["direct_calls"]),
                "indirect_calls": copy.deepcopy(symbol["indirect_calls"]),
                "frame_bytes": symbol["frame_adjustment"],
                "spills": copy.deepcopy(symbol["spills"]),
                "veneer_thunks": [],
                "plt_calls": [],
                "sentinels": {
                    name: {
                        "name": (
                            "__opthash_cache_gate_"
                            f"{KERNEL_SENTINEL_STEMS[kernel_name]}_{name}"
                        ),
                        "address": address,
                        "binding": "GLOBAL",
                        "visibility": "DEFAULT",
                        "defined": True,
                        "count": 1,
                    }
                    for name, address in (
                        ("reservation_start", start),
                        ("body_end", body_end),
                        ("reservation_end", reservation_end),
                    )
                },
                "link_map_sentinels": {
                    "reservation_start": start,
                    "body_end": body_end,
                    "reservation_end": reservation_end,
                },
            }
        )
        symbol["section"] = output_section
        symbol["section_name"] = output_section
        layout["cache_gate_input_sections"].append(
            {
                "owner": input_owner,
                "section": input_section,
                "output": output_section,
                "start": start,
                "end": body_end,
                "size": symbol["size"],
            }
        )


def set_linker_record(record: dict[str, Any], flavor: str, linker_sha: str) -> None:
    path = f"/usr/bin/{flavor}"
    record.update(
        {
            "invocation_path": path,
            "invocation_chain": [{"absolute_path": path, "symlink_target": None}],
            "payload_path": path,
            "payload_sha256": linker_sha,
            "argv0": path,
            "extraction_root": None,
            "flavor": flavor,
            "version_argument": "--version",
            "version": f"{flavor} version",
        }
    )


def private_fragment_path(manifest: dict[str, Any], target: str) -> str:
    return (
        f"{manifest['runner_root']}/target/cache-gate/"
        f"{manifest['architecture']}/{manifest['variant']}/"
        f"linker-fragments/{target}.ld"
    )


def full_semantic_documents(verify_module: ModuleType) -> dict[str, Any]:
    payload_sha = hashlib.sha256(b"payload").hexdigest()
    linker_sha = hashlib.sha256(b"linker").hexdigest()
    capability = schema_sample(verify_module.CAPABILITY_SCHEMA, verify_module)
    rewrite_file_records(capability, "/host/subject/payload", payload_sha)
    capability.update(
        {
            "accepted": True,
            "arch": "x86_64",
            "target_triple": "x86_64-unknown-linux-gnu",
            "cargo_version": PINNED_CARGO_VERSION,
            "rustc_version": PINNED_RUSTC_VERSION,
            "max_page_size": 4096,
            "fragment_set_sha256": verify_module._fingerprint(
                [
                    f"{target}:{payload_sha}"
                    for target in sorted(("elastic", "funnel", "profile"))
                ]
            ),
        }
    )
    capability["producer"].update(
        {
            "runner_root": "/host/subject",
            "artifact_root": (
                "/host/subject/target/cache-gate-linker/x86_64/.probe.fixture"
            ),
            "commit": SUBJECT_COMMIT,
            "tree": SUBJECT_TREE,
            "empty_diff_assertion": True,
        }
    )
    set_linker_record(capability["linker"], "actual", linker_sha)
    set_linker_record(capability["required_linkers"]["gnu"], "gnu", linker_sha)
    set_linker_record(capability["required_linkers"]["lld"], "lld", linker_sha)
    capability["linker"]["flavor"] = "GNU ld"
    capability["required_linkers"]["gnu"]["flavor"] = "GNU ld"
    capability["required_linkers"]["lld"]["flavor"] = "LLD"
    shape_files: dict[str, bytes] = {}
    hosted_files: dict[str, bytes] = {}
    for flavor in ("actual", "gnu", "lld"):
        for target in ("elastic", "funnel", "profile"):
            kernel_names = next(
                kernels
                for shape_target, kernels in verify_module.EXECUTABLE_TARGETS.values()
                if shape_target == target
            )
            shape = capability["shapes"][flavor][target]
            prefix = f"{capability['producer']['artifact_root']}/{flavor}/{target}"
            symbols = schema_sample(
                verify_module._symbol_document_schema(
                    verify_module.SYMBOL_V2_SCHEMA, veneers=True
                ),
                verify_module,
            )
            symbols.update(
                {
                    "binary": "/host/subject/payload",
                    "binary_sha256": payload_sha,
                    "architecture": "x86_64",
                    "symbols": [
                        full_symbol(verify_module, kernel) for kernel in kernel_names
                    ],
                    "linker_generated_veneer_thunks": [],
                }
            )
            layout = schema_sample(
                verify_module._layout_schema(kernel_names), verify_module
            )
            layout.update(
                {
                    "binary": "/host/subject/payload",
                    "binary_sha256": payload_sha,
                    "link_map": "/host/subject/payload",
                    "link_map_sha256": payload_sha,
                    "fragment_sha256": payload_sha,
                    "fragment_set_sha256": capability["fragment_set_sha256"],
                    "archive_member_owners": [],
                    "veneer_thunk_inventory": [],
                    "plt_inventory": [],
                }
            )
            bind_fixture_symbol_layout(
                symbols,
                layout,
                target,
                ("gnu" if flavor in {"actual", "gnu"} else "lld"),
            )
            for item in layout["cache_gate_input_sections"]:
                item["owner"] = "/host/subject/input.o"
            for kernel, record in layout["kernels"].items():
                record["name"] = kernel
                record["input_owner"] = "/host/subject/input.o"
            symbols_bytes = json_bytes(symbols)
            layout_bytes = json_bytes(layout)
            symbols_path = f"{prefix}/symbols.json"
            layout_path = f"{prefix}/layout.json"
            shape_files[symbols_path] = symbols_bytes
            shape_files[layout_path] = layout_bytes
            shape["symbols"] = {
                "absolute_path": symbols_path,
                "sha256": hashlib.sha256(symbols_bytes).hexdigest(),
            }
            shape["layout"] = {
                "absolute_path": layout_path,
                "sha256": hashlib.sha256(layout_bytes).hexdigest(),
            }
            raw_output = f"{prefix}/raw-output"
            common = [
                "/host/subject/input.o",
                "-Wl,-T,/host/subject/payload",
                "-Wl,-Map,/host/subject/payload",
                "-o",
                raw_output,
            ]
            if flavor == "actual":
                cargo_argv = common
                linker_argv = common
                linker_role = "actual-driver"
            else:
                fuse = "bfd" if flavor == "gnu" else "lld"
                cargo_argv = [
                    f"-B{capability['producer']['artifact_root']}/{flavor}/linker-wrapper",
                    f"-fuse-ld={fuse}",
                    *common,
                ]
                linker_argv = [
                    "/host/subject/input.o",
                    "-T",
                    "/host/subject/payload",
                    "-Map",
                    "/host/subject/payload",
                    "-o",
                    raw_output,
                ]
                linker_role = "explicit-linker"
            session = f"{flavor}-{target}-session"
            path_value = "/host/toolchain/bin:/usr/bin"

            def execution_record(
                *,
                argv: list[str],
                linker: dict[str, Any],
                role: str,
                trace_name: str,
            ) -> tuple[dict[str, Any], bytes]:
                trace_path = f"{prefix}/{trace_name}"
                trace_record = {
                    "argv": argv,
                    "argv0": linker["argv0"],
                    "cwd": "/host/subject",
                    "path": path_value,
                    "payload_path": linker["payload_path"],
                    "payload_sha256": linker["payload_sha256"],
                    "role": role,
                    "session": session,
                }
                trace_bytes = json_bytes(trace_record)
                shape_files[trace_path] = trace_bytes
                return (
                    {
                        "linker": copy.deepcopy(linker),
                        "argv": argv,
                        "executable": "/host/subject/payload",
                        "raw_output": raw_output,
                        "trace": {
                            "absolute_path": trace_path,
                            "sha256": hashlib.sha256(trace_bytes).hexdigest(),
                            "record_count": 1,
                            "final_link_record_count": 1,
                        },
                        "role": role,
                        "session": session,
                        "cwd": "/host/subject",
                        "path": path_value,
                    },
                    trace_bytes,
                )

            linker = (
                capability["linker"]
                if flavor == "actual"
                else capability["required_linkers"][flavor]
            )
            linker_execution, _ = execution_record(
                argv=linker_argv,
                linker=linker,
                role=linker_role,
                trace_name="linker-trace.jsonl",
            )
            linker_execution_bytes = json_bytes(linker_execution)
            linker_execution_path = f"{prefix}/linker-execution.json"
            shape_files[linker_execution_path] = linker_execution_bytes
            shape["linker_execution"] = {
                "absolute_path": linker_execution_path,
                "sha256": hashlib.sha256(linker_execution_bytes).hexdigest(),
            }
            if flavor != "actual":
                cargo_execution, _ = execution_record(
                    argv=cargo_argv,
                    linker=capability["linker"],
                    role="cargo-driver",
                    trace_name="cargo-trace.jsonl",
                )
                cargo_execution_bytes = json_bytes(cargo_execution)
                cargo_execution_path = f"{prefix}/cargo-execution.json"
                shape_files[cargo_execution_path] = cargo_execution_bytes
                shape["cargo_execution"] = {
                    "absolute_path": cargo_execution_path,
                    "sha256": hashlib.sha256(cargo_execution_bytes).hexdigest(),
                }
            link_argv = " ".join(
                [
                    "LC_ALL=C",
                    f"PATH={path_value}",
                    "VSLANG=1033",
                    "/host/subject/scripts/cache-gate-link-wrapper.py",
                    *cargo_argv,
                ]
            ).encode()
            link_argv_path = f"{prefix}/link-args.txt"
            shape_files[link_argv_path] = link_argv
            shape["link_argv"] = {
                "absolute_path": link_argv_path,
                "sha256": hashlib.sha256(link_argv).hexdigest(),
            }

    manifest = schema_sample(verify_module.MANIFEST_V2_SCHEMA, verify_module)
    rewrite_file_records(manifest, "/host/subject/payload", payload_sha)
    manifest.update(
        {
            "commit": SUBJECT_COMMIT,
            "tree": SUBJECT_TREE,
            "empty_diff_assertion": True,
            "mode": "MANIFEST",
            "architecture": "x86_64",
            "variant": "proof-clean-a",
            "manifest_instance": "proof-clean-a",
            "runner_root": "/host/subject",
        }
    )
    manifest["layout_adversary"].update(
        {
            "enabled": False,
            "symbol": "cache_gate_layout_adversary_private",
            "input_section": ".text.opthash.cache_gate.layout_adversary",
        }
    )
    manifest["build"].update(
        {
            "cargo_incremental": "0",
            "profile": "release",
            "locked": True,
            "codegen_units": 16,
            "rustc_flags": [
                "-C",
                "codegen-units=16",
                "-C",
                "linker=/host/subject/scripts/cache-gate-link-wrapper.py",
            ],
            "linker_flags": [
                "-Wl,-T,<target-fragment>",
                "-Wl,-Map,<per-target-map>",
            ],
        }
    )
    manifest["build_proof"]["codegen_units"] = 16
    manifest["control"]["runner_root"] = "/host/subject"
    manifest["control"]["mode"] = "BUILD_CONTROL"
    manifest["control"]["locked"] = True
    manifest["control"]["cargo_version"] = PINNED_CARGO_VERSION
    manifest["control"]["rustc_version"] = PINNED_RUSTC_VERSION
    for field in ("runner_commit", "builder_commit"):
        manifest["control"][field] = SUBJECT_COMMIT
    for field in ("runner_tree", "builder_tree"):
        manifest["control"][field] = SUBJECT_TREE
    control_binary_path = (
        "/host/subject/tools/cache-gate-control/target/release/"
        "opthash-cache-gate-control"
    )
    manifest["control"]["binary"] = {
        "absolute_path": control_binary_path,
        "sha256": payload_sha,
    }
    hosted_files[control_binary_path] = b"payload"
    for name, (relative, sha256) in CONTROL_INPUT_IDENTITIES.items():
        data = (ROOT / relative).read_bytes()
        assert hashlib.sha256(data).hexdigest() == sha256
        hosted = f"/host/subject/{relative}"
        manifest["control"]["inputs"][name] = {
            "absolute_path": hosted,
            "sha256": sha256,
        }
        hosted_files[hosted] = data
    for name, (relative, git_blob, sha256) in SUBJECT_TOOL_IDENTITIES.items():
        data = (ROOT / relative).read_bytes()
        assert hashlib.sha256(data).hexdigest() == sha256
        hosted = f"/host/subject/{relative}"
        manifest["tools"][name] = {
            "absolute_path": hosted,
            "sha256": sha256,
            "git_blob": git_blob,
            "git_blob_sha256": sha256,
            "reviewed_root": "/host/subject",
            "reviewed_commit": SUBJECT_COMMIT,
            "reviewed_tree": SUBJECT_TREE,
        }
        hosted_files[hosted] = data
    manifest["linker_capability"] = {
        **copy.deepcopy(capability),
        "copy": {
            "absolute_path": "/host/evidence/capability.json",
            "sha256": "",
        },
    }
    for executable, (_target, kernels) in verify_module.EXECUTABLE_TARGETS.items():
        manifest["symbols"][executable].update(
            {
                "binary": "/host/subject/payload",
                "binary_sha256": payload_sha,
                "architecture": "x86_64",
                "linker_generated_veneer_thunks": [],
                "symbols": [full_symbol(verify_module, kernel) for kernel in kernels],
            }
        )
        layout = manifest["elf_layout"][executable]
        layout["binary"] = "/host/subject/payload"
        layout["binary_sha256"] = payload_sha
        layout["link_map"] = "/host/subject/payload"
        layout["link_map_sha256"] = payload_sha
        layout["fragment_sha256"] = capability["fragments"][_target]["sha256"]
        layout["fragment_set_sha256"] = capability["fragment_set_sha256"]
        layout["archive_member_owners"] = []
        layout["veneer_thunk_inventory"] = []
        layout["plt_inventory"] = []
        bind_fixture_symbol_layout(
            manifest["symbols"][executable],
            layout,
            _target,
            "gnu",
        )
        for item in layout["cache_gate_input_sections"]:
            item["owner"] = "/host/subject/input.o"
        for kernel_name, kernel in layout["kernels"].items():
            kernel["name"] = kernel_name
            kernel["input_owner"] = "/host/subject/input.o"
        proof = manifest["build_proof"]["executables"][executable]
        proof["rustc_argv"] = [
            "Running `/host/toolchain/bin/rustc /host/subject/input.rs "
            "-Ccodegen-units=16 -o /host/subject/out`"
        ]
        proof["archive_member_owners"] = []
        proof["emitted_object_members"] = ["input.o"]
        proof["cgu_members"] = ["input.o"]
        proof["ordered_linker_inputs"] = ["input.o"]
        proof["link_command"]["argv"] = [
            "/host/subject/input.o",
            "-Wl,-T,/host/subject/payload",
            "-Wl,-Map,/host/subject/payload",
            "-o",
            "/host/subject/payload",
        ]
        proof["link_command"]["ordered_linker_inputs"] = ["input.o"]
        proof["link_command"]["direct_input_files"] = ["input.o"]
        proof["link_command"]["direct_cgu_members"] = []
        proof["link_command"]["executable"] = "/host/subject/payload"
        proof["link_command"]["fragment"] = "/host/subject/payload"
        proof["link_command"]["link_map"] = "/host/subject/payload"
        proof["link_command"]["driver"] = copy.deepcopy(capability["linker"])
        proof["adversary"] = {
            "symbol_occurrences": [],
            "input_section_occurrences": 0,
            "outside_reservations": True,
        }

    capability_bytes = json_bytes(capability)
    manifest["linker_capability"]["copy"]["sha256"] = hashlib.sha256(
        capability_bytes
    ).hexdigest()
    clean_a = manifest
    clean_b = copy.deepcopy(manifest)
    clean_b["variant"] = clean_b["manifest_instance"] = "proof-clean-b"
    adversary = copy.deepcopy(manifest)
    adversary["variant"] = adversary["manifest_instance"] = "proof-adversary"
    adversary["layout_adversary"]["enabled"] = True
    adversary["build"]["rustc_flags"].extend(
        [
            "--cfg",
            "cache_gate_layout_adversary",
            "--check-cfg=cfg(cache_gate_layout_adversary)",
        ]
    )
    for executable, proof in adversary["build_proof"]["executables"].items():
        proof["emitted_object_members"].append("adversary-object.o")
        proof["ordered_linker_inputs"].append("adversary.o")
        proof["link_command"]["ordered_linker_inputs"].append("adversary.o")
        proof["link_command"]["argv"].insert(1, "/host/subject/adversary.o")
        proof["link_command"]["direct_input_files"] = ["adversary.o", "input.o"]
        proof["link_command"]["direct_cgu_members"] = []
        proof["cgu_members"].append("adversary-cgu.o")
        layout = adversary["elf_layout"][executable]
        occurrence_start = (len(layout["kernels"]) + 2) * 4096
        occurrence_size = 32
        layout["cache_gate_input_sections"].append(
            {
                "owner": "/host/subject/adversary.o",
                "section": ".text.opthash.cache_gate.layout_adversary",
                "output": ".text",
                "start": occurrence_start,
                "end": occurrence_start + occurrence_size,
                "size": occurrence_size,
            }
        )
        proof["adversary"] = {
            "symbol_occurrences": [
                {
                    "name": f"{executable}::cache_gate_layout_adversary_private",
                    "start": occurrence_start,
                    "size": occurrence_size,
                }
            ],
            "input_section_occurrences": 1,
            "outside_reservations": True,
        }

    def finalize_build_proof(document: dict[str, Any]) -> None:
        artifact_root = f"/host/subject/manifest-artifacts/{document['variant']}"
        control = document["control"]
        control_bytes = json_bytes(
            {
                key: value
                for key, value in control.items()
                if key not in {"provenance_path", "provenance_sha256"}
            }
        )
        control_path = (
            "/host/subject/tools/cache-gate-control/target/release/"
            "opthash-cache-gate-control.provenance.json"
        )
        hosted_files[control_path] = control_bytes
        control["provenance_path"] = control_path
        control["provenance_sha256"] = hashlib.sha256(control_bytes).hexdigest()
        aggregate = {
            "cgu_partition_fingerprint": [],
            "object_member_fingerprint": [],
            "link_order_fingerprint": [],
            "reserved_input_owner_fingerprint": [],
        }
        for executable, proof in document["build_proof"]["executables"].items():
            command = proof["link_command"]
            target = verify_module.EXECUTABLE_TARGETS[executable][0]
            source_fragment = capability["fragments"][target]
            fragment_path = private_fragment_path(document, target)
            hosted_files[fragment_path] = b"payload"
            document["executables"][executable]["linker_fragment"] = {
                "absolute_path": fragment_path,
                "sha256": source_fragment["sha256"],
            }
            command["argv"] = [
                token.replace(
                    f"-Wl,-T,{command['fragment']}",
                    f"-Wl,-T,{fragment_path}",
                )
                for token in command["argv"]
            ]
            command["fragment"] = fragment_path
            driver = command["driver"]
            trace_record = {
                "argv": command["argv"],
                "argv0": driver["argv0"],
                "cwd": "/host/subject",
                "path": "/host/toolchain/bin:/usr/bin",
                "payload_path": driver["payload_path"],
                "payload_sha256": driver["payload_sha256"],
            }
            trace_bytes = json_bytes(trace_record)
            trace_path = f"{artifact_root}/{executable}.trace.jsonl"
            hosted_files[trace_path] = trace_bytes
            command["trace"] = {
                "absolute_path": trace_path,
                "sha256": hashlib.sha256(trace_bytes).hexdigest(),
                "record_count": 1,
                "final_link_record_count": 1,
            }
            document["executables"][executable]["link_trace"] = {
                "absolute_path": trace_path,
                "sha256": hashlib.sha256(trace_bytes).hexdigest(),
            }
            command["ordered_linker_input_fingerprint"] = verify_module._fingerprint(
                command["ordered_linker_inputs"]
            )
            proof["direct_linker_input_files"] = copy.deepcopy(
                command["direct_input_files"]
            )
            proof["reserved_input_owners"] = [
                Path(kernel["input_owner"]).name
                for kernel in document["elf_layout"][executable]["kernels"].values()
            ]
            values_by_field = {
                "cgu_partition_fingerprint": proof["cgu_members"],
                "object_member_fingerprint": proof["emitted_object_members"],
                "link_order_fingerprint": proof["ordered_linker_inputs"],
                "reserved_input_owner_fingerprint": proof["reserved_input_owners"],
            }
            for field, values in values_by_field.items():
                proof[field] = verify_module._fingerprint(values)
                aggregate[field].extend(f"{executable}:{value}" for value in values)
            artifacts = (
                ("symbols", document["symbols"][executable]),
                ("layout", document["elf_layout"][executable]),
                ("link_command", command),
            )
            for name, embedded in artifacts:
                data = json_bytes(embedded)
                path = f"{artifact_root}/{executable}.{name}.json"
                hosted_files[path] = data
                document["executables"][executable][name] = {
                    "absolute_path": path,
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
        for field, values in aggregate.items():
            document["build_proof"][field] = verify_module._fingerprint(values)

    for document in (clean_a, clean_b, adversary):
        finalize_build_proof(document)

    v1 = schema_sample(verify_module.MANIFEST_V1_SCHEMA, verify_module)
    rewrite_file_records(v1, "/host/v1/payload", payload_sha)
    v1.update(
        {
            "commit": V1_REPLAY_COMMIT,
            "tree": V1_REPLAY_TREE,
            "empty_diff_assertion": True,
            "architecture": "x86_64",
            "variant": "proof-v1",
        }
    )
    v1["build"] = {
        "cargo_incremental": "0",
        "profile": "release",
        "locked": True,
        "rustc_flags": ["-C", "link-arg=-Wl,-Map,<per-target-map>"],
        "linker_flags": ["-Wl,-Map,<per-target-map>"],
    }
    v1["control"]["builder_commit"] = V1_REPLAY_COMMIT
    v1["control"]["builder_tree"] = V1_REPLAY_TREE
    v1["control"]["locked"] = True
    v1["control"]["cargo_version"] = PINNED_CARGO_VERSION
    v1["control"]["rustc_version"] = PINNED_RUSTC_VERSION
    v1_binary_path = (
        "/host/v1/tools/cache-gate-control/target/release/opthash-cache-gate-control"
    )
    v1["control"]["binary"] = {
        "absolute_path": v1_binary_path,
        "sha256": payload_sha,
    }
    hosted_files[v1_binary_path] = b"payload"
    for name, (relative, sha256) in CONTROL_INPUT_IDENTITIES.items():
        data = (ROOT / relative).read_bytes()
        assert hashlib.sha256(data).hexdigest() == sha256
        hosted = f"/host/v1/{relative}"
        v1["control"]["inputs"][name] = {
            "absolute_path": hosted,
            "sha256": sha256,
        }
        hosted_files[hosted] = data
    v1_control_bytes = json_bytes(
        {
            key: value
            for key, value in v1["control"].items()
            if key not in {"provenance_path", "provenance_sha256"}
        }
    )
    v1["control"]["provenance_path"] = (
        "/host/v1/tools/cache-gate-control/target/release/"
        "opthash-cache-gate-control.provenance.json"
    )
    v1["control"]["provenance_sha256"] = hashlib.sha256(v1_control_bytes).hexdigest()
    hosted_files[v1["control"]["provenance_path"]] = v1_control_bytes
    for executable, (_target, kernels) in verify_module.EXECUTABLE_TARGETS.items():
        v1["symbols"][executable].update(
            {
                "binary": "/host/v1/payload",
                "binary_sha256": payload_sha,
                "architecture": "x86_64",
                "symbols": [
                    full_symbol(verify_module, kernel, v1=True) for kernel in kernels
                ],
            }
        )

    v1_reextractions: dict[str, dict[str, Any]] = {}
    for executable, (_target, kernels) in verify_module.EXECUTABLE_TARGETS.items():
        document = schema_sample(
            verify_module._symbol_document_schema(
                verify_module.SYMBOL_V2_SCHEMA, veneers=True
            ),
            verify_module,
        )
        document.update(
            {
                "binary": v1["executables"][executable]["absolute_path"],
                "binary_sha256": v1["executables"][executable]["sha256"],
                "architecture": "x86_64",
                "linker_generated_veneer_thunks": [],
                "symbols": [full_symbol(verify_module, kernel) for kernel in kernels],
            }
        )
        for current, original in zip(
            document["symbols"],
            v1["symbols"][executable]["symbols"],
            strict=True,
        ):
            current["name"] = original["name"]
            current["pattern"] = original["pattern"]
        v1_reextractions[executable] = document

    v1_body_records = fixture_body_records(verify_module, {"symbols": v1_reextractions})
    v2_body_records = fixture_body_records(verify_module, clean_a)
    body_rows = [
        {
            "kernel": kernel,
            "v1": copy.deepcopy(v1_body),
            "v2": copy.deepcopy(v2_body_records[kernel]),
        }
        for kernel, v1_body in sorted(v1_body_records.items())
    ]
    transcript_documents = []
    for hosted_manifest in (clean_a, clean_b, adversary):
        for executable in verify_module.EXECUTABLE_TARGETS:
            proof = hosted_manifest["build_proof"]["executables"][executable]
            command = proof["link_command"]
            driver = command["driver"]
            transcript_documents.append(
                {
                    "version": 1,
                    "kind": "link-validation",
                    "manifest_variant": hosted_manifest["variant"],
                    "executable": executable,
                    "trace": copy.deepcopy(command["trace"]),
                    "argv": copy.deepcopy(command["argv"]),
                    "argv0": driver["argv0"],
                    "cwd": "/host/subject",
                    "path": "/host/toolchain/bin:/usr/bin",
                    "payload_path": driver["payload_path"],
                    "payload_sha256": driver["payload_sha256"],
                    "status": 0,
                    "ordered_inputs": copy.deepcopy(command["ordered_linker_inputs"]),
                }
            )
    manifest_names = ("clean-a", "clean-b", "adversary")
    manifest_records = {
        name.replace("-", "_"): {
            "archive_path": f"bundle/evidence/{name}.json",
            "sha256": hashlib.sha256(json_bytes(document)).hexdigest(),
        }
        for name, document in zip(
            manifest_names, (clean_a, clean_b, adversary), strict=True
        )
    }
    transcript_records = [
        {
            "archive_path": f"bundle/evidence/transcript-{index}.json",
            "sha256": hashlib.sha256(json_bytes(document)).hexdigest(),
        }
        for index, document in enumerate(transcript_documents)
    ]
    v1_reextraction_records = {
        executable: {
            "archive_path": (f"bundle/evidence/v1-reextractions/{executable}.json"),
            "sha256": hashlib.sha256(json_bytes(document)).hexdigest(),
        }
        for executable, document in v1_reextractions.items()
    }
    body_comparison = {
        "version": 1,
        "fields": list(EXPECTED_BODY_FIELDS),
        "rows": body_rows,
    }
    portable_paths_document = full_portable_paths(verify_module)
    return {
        "capability": capability,
        "capability_bytes": capability_bytes,
        "manifests": [clean_a, clean_b, adversary],
        "manifest_v1": v1,
        "v1_reextractions": v1_reextractions,
        "provenance": {
            "version": 2,
            "subject": {"commit": SUBJECT_COMMIT, "tree": SUBJECT_TREE},
            "v1": {"commit": V1_REPLAY_COMMIT, "tree": V1_REPLAY_TREE},
            "orchestration": {
                "commit": ORCHESTRATION_COMMIT,
                "tree": ORCHESTRATION_TREE,
                "sources": {
                    name: {
                        "archive_path": ORCHESTRATION_SOURCE_PATHS[name],
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                    for name, data in ORCHESTRATION_SOURCE_BYTES.items()
                },
            },
            "run": {"id": 7, "attempt": 2, "derived_attempt": 7002},
            "github": {
                "repository": "owner/opthash",
                "ref": "refs/heads/ci/x86-cache-gate-evidence",
                "sha": ORCHESTRATION_COMMIT,
                "run_id": 7,
                "run_attempt": 2,
            },
            "rust": {
                "toolchain": "1.95.0-x86_64-unknown-linux-gnu",
                "rustc_version": PINNED_RUSTC_VERSION,
                "cargo_version": PINNED_CARGO_VERSION,
            },
            "packages": [
                {
                    "name": "lld",
                    "architecture": "amd64",
                    "version": "1:18.1.3-1ubuntu1",
                    "verification_status": 0,
                }
            ],
            "roots": copy.deepcopy(portable_paths_document["roots"]),
            "system_links": copy.deepcopy(portable_paths_document["system_links"]),
            "proof": {"status": 0, "result": "PASS"},
            "documents": {
                "capability": {
                    "archive_path": "bundle/evidence/capability.json",
                    "sha256": hashlib.sha256(capability_bytes).hexdigest(),
                },
                "manifests": manifest_records,
                "v1_manifest": {
                    "archive_path": "bundle/evidence/v1.json",
                    "sha256": hashlib.sha256(json_bytes(v1)).hexdigest(),
                },
                "v1_reextractions": v1_reextraction_records,
                "transcripts": transcript_records,
                "body_comparison": {
                    "archive_path": "bundle/body-comparison.json",
                    "sha256": hashlib.sha256(json_bytes(body_comparison)).hexdigest(),
                },
                "portable_paths": {
                    "archive_path": "bundle/portable-paths.json",
                    "sha256": hashlib.sha256(
                        json_bytes(portable_paths_document)
                    ).hexdigest(),
                },
            },
            "hardlinks": [],
        },
        "transcripts": transcript_documents,
        "body_comparison": body_comparison,
        "portable_paths": portable_paths_document,
        "shape_files": shape_files,
        "hosted_files": hosted_files,
    }


def full_document_set(verify_module: ModuleType) -> dict[str, dict[str, Any]]:
    documents = full_semantic_documents(verify_module)
    return {
        "capability": documents["capability"],
        "manifest_v2": documents["manifests"][0],
        "manifest_v1": documents["manifest_v1"],
        "v1_reextraction": documents["v1_reextractions"]["elastic_cache_gate"],
        "provenance": documents["provenance"],
        "inventory": {
            "version": 1,
            "entries": [
                {
                    "path": "bundle/subject/payload",
                    "type": "file",
                    "mode": 420,
                    "size": 7,
                    "sha256": hashlib.sha256(b"payload").hexdigest(),
                }
            ],
        },
        "transcript": documents["transcripts"][0],
        "body_comparison": documents["body_comparison"],
        "portable_paths": documents["portable_paths"],
    }


def test_ready_schema_requires_exact_provenance_v2_and_current_reextraction(
    verify_module: ModuleType,
) -> None:
    documents = full_document_set(verify_module)
    verify_module.validate_document_set(documents)

    legacy = copy.deepcopy(documents)
    legacy["provenance"]["version"] = 1
    with pytest.raises(verify_module.EvidenceError, match="provenance version"):
        verify_module.validate_document_set(legacy)


def test_body_contract_uses_only_current_normalizer_v1_reextractions(
    verify_module: ModuleType,
) -> None:
    documents = full_semantic_documents(verify_module)
    v1 = documents["manifest_v1"]
    reextractions = documents["v1_reextractions"]
    body = documents["body_comparison"]
    clean = documents["manifests"][0]

    v1["symbols"]["elastic_cache_gate"]["symbols"][0][
        "normalized_instructions_sha256"
    ] = "f" * 64
    reextractions["elastic_cache_gate"]["symbols"][0]["raw_sha256"] = "d" * 64
    reextractions["elastic_cache_gate"]["symbols"][0]["start"] = 9999
    reextractions["elastic_cache_gate"]["symbols"][0]["section"] = ".other"
    clean["symbols"]["elastic_cache_gate"]["symbols"][0]["raw_sha256"] = "c" * 64
    clean["symbols"]["elastic_cache_gate"]["symbols"][0]["start"] = 8888
    clean["symbols"]["elastic_cache_gate"]["symbols"][0]["section"] = ".different"
    verify_module._verify_body_contract(body, clean, v1, reextractions)

    reextractions["elastic_cache_gate"]["symbols"][0][
        "normalized_instructions_sha256"
    ] = "e" * 64
    with pytest.raises(verify_module.EvidenceError, match="v1 body contract"):
        verify_module._verify_body_contract(body, clean, v1, reextractions)


def test_body_records_contain_exact_body_fields(
    verify_module: ModuleType,
) -> None:
    clean = full_semantic_documents(verify_module)["manifests"][0]

    assert verify_module.BODY_FIELDS == EXPECTED_BODY_FIELDS
    for record in verify_module._body_records(clean).values():
        assert tuple(record) == EXPECTED_BODY_FIELDS


@pytest.mark.parametrize("side", ["v1", "v2"])
@pytest.mark.parametrize(("field", "value"), FORBIDDEN_BODY_FIELD_VALUES)
def test_body_contract_rejects_extra_body_fields(
    verify_module: ModuleType,
    side: str,
    field: str,
    value: Any,
) -> None:
    documents = full_semantic_documents(verify_module)
    documents["body_comparison"]["rows"][0][side][field] = copy.deepcopy(value)

    with pytest.raises(verify_module.EvidenceError, match="schema mismatch"):
        verify_module._verify_body_contract(
            documents["body_comparison"],
            documents["manifests"][0],
            documents["manifest_v1"],
            documents["v1_reextractions"],
        )


@pytest.mark.parametrize(
    "mutation",
    ["binary", "binary-hash", "architecture", "selection", "count", "extractor"],
)
def test_current_v1_reextractions_bind_binary_architecture_and_exact_selection(
    verify_module: ModuleType,
    mutation: str,
) -> None:
    documents = full_semantic_documents(verify_module)
    reextractions = documents["v1_reextractions"]
    current = reextractions["elastic_cache_gate"]
    if mutation == "binary":
        current["binary"] = "/host/v1/alternate"
    elif mutation == "binary-hash":
        current["binary_sha256"] = "f" * 64
    elif mutation == "architecture":
        current["architecture"] = "aarch64"
    elif mutation == "selection":
        current["symbols"][0]["pattern"] = "::attacker$"
    elif mutation == "count":
        current["symbols"].pop()
    else:
        documents["manifests"][0]["tools"]["extractor"]["sha256"] = "f" * 64

    with pytest.raises(
        verify_module.EvidenceError,
        match="binary|architecture|selection|count|extractor",
    ):
        verify_module._verify_body_contract(
            documents["body_comparison"],
            documents["manifests"][0],
            documents["manifest_v1"],
            reextractions,
        )


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


@pytest.mark.parametrize(
    "kind",
    [
        "capability",
        "manifest_v2",
        "manifest_v1",
        "v1_reextraction",
        "provenance",
        "inventory",
        "transcript",
        "body_comparison",
        "portable_paths",
    ],
)
def test_recursive_schema_rejects_unknown_key_before_routing(
    verify_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    documents = full_document_set(verify_module)
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


@pytest.mark.parametrize(
    "kind",
    [
        "capability",
        "manifest_v2",
        "manifest_v1",
        "v1_reextraction",
        "provenance",
        "inventory",
        "transcript",
        "body_comparison",
        "portable_paths",
    ],
)
def test_recursive_schema_rejects_missing_key_before_routing(
    verify_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    documents = full_document_set(verify_module)
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
    documents = full_document_set(verify_module)
    parent = at_path(documents, path[:-1])
    key = path[-1]
    if key == "*":
        raise AssertionError("test path must end in field")
    parent[key] = value
    with pytest.raises(
        verify_module.EvidenceError, match="schema mismatch|type mismatch"
    ):
        verify_module.validate_document_set(documents)


def test_full_document_set_passes_recursive_schema_and_routes(
    verify_module: ModuleType,
) -> None:
    verify_module.validate_document_set(full_document_set(verify_module))


@pytest.mark.parametrize("side", ["v1", "v2"])
@pytest.mark.parametrize(("field", "value"), FORBIDDEN_BODY_FIELD_VALUES)
def test_body_schema_rejects_extra_body_fields(
    verify_module: ModuleType,
    side: str,
    field: str,
    value: Any,
) -> None:
    documents = full_document_set(verify_module)
    documents["body_comparison"]["rows"][0][side][field] = copy.deepcopy(value)

    with pytest.raises(verify_module.EvidenceError, match="schema mismatch"):
        verify_module.validate_document_set(documents)


@pytest.mark.parametrize(
    "kind",
    [
        "capability",
        "manifest_v2",
        "manifest_v1",
        "v1_reextraction",
        "provenance",
        "inventory",
        "transcript",
        "body_comparison",
        "portable_paths",
    ],
)
def test_every_recursive_object_shape_rejects_unknown_and_missing_keys_before_routing(
    verify_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    base = full_document_set(verify_module)
    paths = sorted({path for path, _value in nested_objects(base[kind])})
    called = False

    def classifier_spy(_path: tuple[str, ...]) -> str:
        nonlocal called
        called = True
        raise AssertionError("routing called before structural gate")

    monkeypatch.setattr(verify_module, "classify", classifier_spy)
    for path in paths:
        unknown = copy.deepcopy(base)
        at_path(unknown[kind], path)["ordinary_unknown"] = "rejected"
        with pytest.raises(verify_module.EvidenceError, match="schema mismatch"):
            verify_module.validate_document_set(unknown)
        assert not called

        missing = copy.deepcopy(base)
        target = at_path(missing[kind], path)
        del target[next(iter(target))]
        with pytest.raises(verify_module.EvidenceError, match="schema mismatch"):
            verify_module.validate_document_set(missing)
        assert not called


@pytest.mark.parametrize("side", ["v1", "v2"])
@pytest.mark.parametrize(("field", "value"), FORBIDDEN_BODY_FIELD_VALUES)
def test_body_comparison_rejects_extra_body_fields(
    verify_module: ModuleType,
    side: str,
    field: str,
    value: Any,
) -> None:
    rows = semantic_documents()["body_comparison"]["rows"]
    rows[0][side][field] = copy.deepcopy(value)

    with pytest.raises(verify_module.EvidenceError, match="schema mismatch"):
        verify_module.verify_body_rows(rows)


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


def test_rustc_command_classifies_output_directory(
    verify_module: ModuleType,
) -> None:
    roots = verify_module.PortableRoots.from_document(portable_paths())
    verify_module.validate_command(
        ["rustc", "--out-dir=/host/subject/out"], roots, rustc=True
    )


def test_command_resolves_every_relative_positional_against_authenticated_cwd(
    verify_module: ModuleType,
) -> None:
    roots = verify_module.PortableRoots.from_document(
        full_portable_paths(verify_module)
    )
    verify_module.validate_command(
        ["rustc", "--crate-name", "proof", "src/lib.rs", "bare-input"],
        roots,
        rustc=True,
        cwd="/host/subject",
    )
    with pytest.raises(verify_module.EvidenceError, match="authenticated cwd"):
        verify_module.validate_command(
            ["rustc", "src/lib.rs"],
            roots,
            rustc=True,
        )


def test_command_accepts_only_exact_gcc_resolution_transient_grammar(
    verify_module: ModuleType,
) -> None:
    roots = verify_module.PortableRoots.from_document(
        full_portable_paths(verify_module)
    )
    verify_module.validate_command(
        ["ld", "-plugin-opt=-fresolution=/tmp/ccA09zQ2.res"],
        roots,
        rustc=False,
        cwd="/host/subject",
    )
    for value in (
        "/tmp/ccA09z.res",
        "/tmp/ccA09zQ2x.res",
        "/outside/ccA09z.res",
        "/tmp/not-gcc.res",
        "/tmp/ccA09z.o",
        "ccA09z.res",
    ):
        with pytest.raises(verify_module.EvidenceError, match="resolution"):
            verify_module.validate_command(
                ["ld", f"-plugin-opt=-fresolution={value}"],
                roots,
                rustc=False,
                cwd="/host/subject",
            )
    with pytest.raises(verify_module.EvidenceError, match="outside declared roots"):
        verify_module.validate_command(
            ["ld", "/tmp/evil.o"],
            roots,
            rustc=False,
            cwd="/host/subject",
        )


LINKER_PATH_OPERAND_GRAMMAR_CASES = (
    pytest.param(
        ["--dynamic-linker", "relative-loader"],
        id="split",
    ),
    pytest.param(
        ["--dynamic-linker=relative-loader"],
        id="joined-long-dynamic-linker",
    ),
    pytest.param(
        ["--rpath=relative-lib"],
        id="joined-long-rpath",
    ),
    pytest.param(
        ["-rpath=relative-lib"],
        id="joined-short",
    ),
    pytest.param(
        ["-Wl,--rpath,relative-lib"],
        id="wl-split",
    ),
    pytest.param(
        ["-Wl,--rpath=relative-lib"],
        id="wl-joined",
    ),
    pytest.param(
        ["-Xlinker", "--rpath", "-Xlinker", "relative-lib"],
        id="xlinker-split",
    ),
    pytest.param(
        ["-Xlinker=--rpath", "-Xlinker=relative-lib"],
        id="xlinker-joined",
    ),
    pytest.param(
        ["--for-linker", "--rpath", "--for-linker", "relative-lib"],
        id="for-linker-split",
    ),
    pytest.param(
        ["--for-linker=--rpath", "--for-linker=relative-lib"],
        id="for-linker-joined",
    ),
)


@pytest.mark.parametrize("tokens", LINKER_PATH_OPERAND_GRAMMAR_CASES)
def test_linker_path_operands_require_authenticated_cwd_across_every_grammar(
    verify_module: ModuleType,
    tokens: list[str],
) -> None:
    roots = verify_module.PortableRoots.from_document(
        full_portable_paths(verify_module)
    )
    with pytest.raises(verify_module.EvidenceError, match="authenticated cwd"):
        verify_module.validate_command(["ld", *tokens], roots, rustc=False)
    verify_module.validate_command(
        ["ld", *tokens],
        roots,
        rustc=False,
        cwd="/host/subject",
    )


UNSUPPORTED_LINKER_OPERAND_GRAMMAR_CASES = (
    pytest.param(
        ["--remap-inputs", "source=relative"],
        id="split",
    ),
    pytest.param(
        ["--remap-inputs=source=relative"],
        id="joined",
    ),
    pytest.param(
        ["-Wl,--remap-inputs,source=relative"],
        id="wl",
    ),
    pytest.param(
        ["-Xlinker", "--remap-inputs", "-Xlinker", "source=relative"],
        id="xlinker",
    ),
    pytest.param(
        ["--for-linker", "--remap-inputs", "--for-linker", "source=relative"],
        id="for-linker",
    ),
)


@pytest.mark.parametrize("tokens", UNSUPPORTED_LINKER_OPERAND_GRAMMAR_CASES)
def test_linker_rejects_unsupported_operand_bearing_options_across_every_grammar(
    verify_module: ModuleType,
    tokens: list[str],
) -> None:
    roots = verify_module.PortableRoots.from_document(
        full_portable_paths(verify_module)
    )
    with pytest.raises(
        verify_module.EvidenceError,
        match="unsupported operand-bearing linker option",
    ):
        verify_module.validate_command(
            ["ld", *tokens],
            roots,
            rustc=False,
            cwd="/host/subject",
        )


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


def test_rlib_member_rejects_missing_index_member(
    tmp_path: Path,
    verify_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = tmp_path / "libproof.rlib"
    archive.write_bytes(b"archive")
    monkeypatch.setattr(
        verify_module.subprocess,
        "run",
        lambda *_args, **_kwargs: verify_module.subprocess.CompletedProcess(
            [], 0, stdout="present.o\n"
        ),
    )
    with pytest.raises(verify_module.EvidenceError, match="index member is missing"):
        verify_module.validate_rlib_member(archive, "missing.o")


def test_semantic_aggregate_comparison_preserves_order_and_duplicates(
    verify_module: ModuleType,
) -> None:
    verify_module.require_ordered_equal(
        ["one", "one", "two"], ["one", "one", "two"], "ordered inputs"
    )
    with pytest.raises(verify_module.EvidenceError, match="ordered inputs"):
        verify_module.require_ordered_equal(
            ["one", "one", "two"], ["one", "two", "one"], "ordered inputs"
        )


def write_semantic_staging(staging: Path, verify_module: ModuleType) -> dict[str, Any]:
    documents = full_semantic_documents(verify_module)
    bundle = staging / "bundle"
    for root in (
        "orchestrator",
        "subject",
        "v1",
        "evidence",
        "toolchain/rust/bin",
        "toolchain/cargo-registry",
        "system-root/usr/bin",
    ):
        (bundle / root).mkdir(parents=True, exist_ok=True)
    for name, data in ORCHESTRATION_SOURCE_BYTES.items():
        destination = staging / ORCHESTRATION_SOURCE_PATHS[name]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    for name in ("actual", "gnu", "lld"):
        (bundle / f"system-root/usr/bin/{name}").write_bytes(b"linker")
    (bundle / "subject/payload").write_bytes(b"payload")
    (bundle / "subject/input.o").write_bytes(b"object")
    (bundle / "subject/scripts").mkdir()
    (bundle / "subject/scripts/cache-gate-link-wrapper.py").write_bytes(b"wrapper")
    (bundle / "v1/payload").write_bytes(b"payload")
    (bundle / "toolchain/rust/bin/rustc").write_bytes(b"rustc")
    for hosted, data in documents["shape_files"].items():
        relative = Path(hosted).relative_to("/host/subject")
        destination = bundle / "subject" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    for hosted, data in documents["hosted_files"].items():
        if hosted.startswith("/host/subject/"):
            root_name = "subject"
            relative = Path(hosted).relative_to("/host/subject")
        else:
            root_name = "v1"
            relative = Path(hosted).relative_to("/host/v1")
        destination = bundle / root_name / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)

    named_documents = {
        "capability.json": documents["capability"],
        "clean-a.json": documents["manifests"][0],
        "clean-b.json": documents["manifests"][1],
        "adversary.json": documents["manifests"][2],
        "v1.json": documents["manifest_v1"],
    }
    for name, document in named_documents.items():
        (bundle / f"evidence/{name}").write_bytes(json_bytes(document))
    for executable, document in documents["v1_reextractions"].items():
        destination = bundle / f"evidence/v1-reextractions/{executable}.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(json_bytes(document))
    for index, transcript in enumerate(documents["transcripts"]):
        (bundle / f"evidence/transcript-{index}.json").write_bytes(
            json_bytes(transcript)
        )
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
    documents = write_semantic_staging(staging, verify_module)
    archive = tmp_path / "evidence.tar"
    digest = package_module.package_evidence(
        staging, archive, tmp_path / "evidence.tar.sha256"
    )
    report = verify_module.verify_archive(archive, digest)
    assert report.status == "READY"
    assert report.archive_sha256 == digest
    assert report.subject_commit == SUBJECT_COMMIT
    assert report.subject_tree == SUBJECT_TREE
    assert (report.run_id, report.run_attempt) == (7, 2)
    assert report.body_comparison_sha256 == verify_module.verify_body_rows(
        documents["body_comparison"]["rows"]
    )
    assert len(report.manifest_sha256s) == 3


@pytest.mark.parametrize(
    "alias_kind",
    ["source-private", "source-private-reverse", "private-private"],
)
def test_ready_rejects_hardlink_aliased_private_fragments(
    tmp_path: Path,
    package_module: ModuleType,
    verify_module: ModuleType,
    alias_kind: str,
) -> None:
    staging = tmp_path / "staging"
    documents = write_semantic_staging(staging, verify_module)
    clean_a, clean_b, _adversary = documents["manifests"]
    private_a = private_fragment_path(clean_a, "elastic")
    source = documents["capability"]["fragments"]["elastic"]["absolute_path"]
    if alias_kind == "source-private":
        alias, target = private_a, source
    elif alias_kind == "source-private-reverse":
        alias, target = source, private_a
    else:
        alias = private_fragment_path(clean_b, "elastic")
        target = private_a

    def staged_path(absolute_path: str) -> Path:
        return (
            staging
            / "bundle/subject"
            / Path(absolute_path).relative_to("/host/subject")
        )

    alias_path = staged_path(alias)
    alias_path.unlink()
    os.link(staged_path(target), alias_path)
    documents["provenance"]["hardlinks"] = [
        {
            "path": f"bundle/subject/{Path(alias).relative_to('/host/subject')}",
            "target": f"bundle/subject/{Path(target).relative_to('/host/subject')}",
        }
    ]
    (staging / "bundle/provenance.json").write_bytes(
        json_bytes(documents["provenance"])
    )
    archive = tmp_path / "evidence.tar"
    digest = package_module.package_evidence(
        staging, archive, tmp_path / "evidence.tar.sha256"
    )
    with pytest.raises(
        verify_module.EvidenceError,
        match="manifest private fragment.*regular file identity",
    ):
        verify_module.verify_archive(archive, digest)


@pytest.mark.parametrize(
    "mutation",
    [
        "v1",
        "source-path",
        "source-bytes",
        "github-repository",
        "github-ref",
        "github-sha",
        "github-run",
        "rust",
        "package-empty",
        "package-status",
        "package-order",
        "package-duplicate",
        "package-lld",
        "roots",
        "system-links",
        "proof",
    ],
)
def test_ready_provenance_v2_semantics_are_cross_bound(
    tmp_path: Path,
    package_module: ModuleType,
    verify_module: ModuleType,
    mutation: str,
) -> None:
    staging = tmp_path / "staging"
    write_semantic_staging(staging, verify_module)
    provenance_path = staging / "bundle/provenance.json"
    provenance = json.loads(provenance_path.read_bytes())
    if mutation == "v1":
        provenance["v1"]["tree"] = "f" * 40
    elif mutation == "source-path":
        provenance["orchestration"]["sources"]["runner"]["archive_path"] = (
            "bundle/orchestrator/scripts/alternate.sh"
        )
    elif mutation == "source-bytes":
        (staging / ORCHESTRATION_SOURCE_PATHS["runner"]).write_bytes(b"changed\n")
    elif mutation == "github-repository":
        provenance["github"]["repository"] = "not-a-repository"
    elif mutation == "github-ref":
        provenance["github"]["ref"] = "refs/heads/other"
    elif mutation == "github-sha":
        provenance["github"]["sha"] = "f" * 40
    elif mutation == "github-run":
        provenance["github"]["run_id"] += 1
    elif mutation == "rust":
        provenance["rust"]["toolchain"] = "nightly"
    elif mutation == "package-empty":
        provenance["packages"][0]["version"] = ""
    elif mutation == "package-status":
        provenance["packages"][0]["verification_status"] = 1
    elif mutation == "package-order":
        provenance["packages"].append(
            {
                "name": "aaa",
                "architecture": "amd64",
                "version": "1",
                "verification_status": 0,
            }
        )
    elif mutation == "package-duplicate":
        provenance["packages"].append(copy.deepcopy(provenance["packages"][0]))
    elif mutation == "package-lld":
        provenance["packages"][0]["name"] = "clang"
    elif mutation == "roots":
        provenance["roots"][0]["hosted"] = "/host/alternate"
    elif mutation == "system-links":
        provenance["system_links"].append(
            {"source": "/usr/bin/ld", "raw_target": "x86_64-linux-gnu-ld"}
        )
    else:
        provenance["proof"] = {"status": 1, "result": "FAIL"}
    provenance_path.write_bytes(json_bytes(provenance))

    archive = tmp_path / "evidence.tar"
    digest = package_module.package_evidence(
        staging, archive, tmp_path / "evidence.tar.sha256"
    )
    with pytest.raises(
        verify_module.EvidenceError,
        match=(
            "v1|orchestration|document hash|GitHub|Rust|package|roots|"
            "system links|proof"
        ),
    ):
        verify_module.verify_archive(archive, digest)


def test_provenance_hash_binds_current_v1_reextraction_bytes(
    tmp_path: Path,
    package_module: ModuleType,
    verify_module: ModuleType,
) -> None:
    staging = tmp_path / "staging"
    write_semantic_staging(staging, verify_module)
    path = staging / "bundle/evidence/v1-reextractions/elastic_cache_gate.json"
    path.write_bytes(path.read_bytes() + b" ")
    archive = tmp_path / "evidence.tar"
    digest = package_module.package_evidence(
        staging, archive, tmp_path / "evidence.tar.sha256"
    )
    with pytest.raises(verify_module.EvidenceError, match="document hash mismatch"):
        verify_module.verify_archive(archive, digest)


def test_provenance_binds_original_document_bytes(
    tmp_path: Path, package_module: ModuleType, verify_module: ModuleType
) -> None:
    staging = tmp_path / "staging"
    write_semantic_staging(staging, verify_module)
    manifest_path = staging / "bundle/evidence/clean-a.json"
    manifest_path.write_bytes(manifest_path.read_bytes() + b" ")
    archive = tmp_path / "evidence.tar"
    digest = package_module.package_evidence(
        staging, archive, tmp_path / "evidence.tar.sha256"
    )
    with pytest.raises(verify_module.EvidenceError, match="document hash mismatch"):
        verify_module.verify_archive(archive, digest)


def test_hosted_transcript_must_match_manifest_link_proof(
    tmp_path: Path, package_module: ModuleType, verify_module: ModuleType
) -> None:
    staging = tmp_path / "staging"
    write_semantic_staging(staging, verify_module)
    transcript_path = staging / "bundle/evidence/transcript-0.json"
    transcript = json.loads(transcript_path.read_bytes())
    transcript["argv"].insert(0, "--gc-sections")
    transcript_bytes = json_bytes(transcript)
    transcript_path.write_bytes(transcript_bytes)
    provenance_path = staging / "bundle/provenance.json"
    provenance = json.loads(provenance_path.read_bytes())
    provenance["documents"]["transcripts"][0]["sha256"] = hashlib.sha256(
        transcript_bytes
    ).hexdigest()
    provenance_path.write_bytes(json_bytes(provenance))
    archive = tmp_path / "evidence.tar"
    digest = package_module.package_evidence(
        staging, archive, tmp_path / "evidence.tar.sha256"
    )
    with pytest.raises(verify_module.EvidenceError, match="hosted transcript argv"):
        verify_module.verify_archive(archive, digest)


UNSAFE_LINK_COMMAND_SUFFIXES = (
    pytest.param(
        ["--outp=redirected-output"],
        id="direct-abbreviated-output",
    ),
    pytest.param(
        ["-Wl,--outp=redirected-output"],
        id="wl-abbreviated-output",
    ),
    pytest.param(
        ["-Xlinker=--outp=redirected-output"],
        id="xlinker-abbreviated-output",
    ),
    pytest.param(
        ["--for-linker=--outp=redirected-output"],
        id="for-linker-abbreviated-output",
    ),
    pytest.param(
        ["--", "--outp=redirected-output"],
        id="option-terminator",
    ),
)


@pytest.mark.parametrize("suffix", UNSAFE_LINK_COMMAND_SUFFIXES)
def test_hosted_transcript_rejects_unsafe_output_interpretation(
    tmp_path: Path,
    package_module: ModuleType,
    verify_module: ModuleType,
    suffix: list[str],
) -> None:
    staging = tmp_path / "staging"
    documents = write_semantic_staging(staging, verify_module)
    transcript = documents["transcripts"][0]
    transcript["argv"].extend(suffix)
    command = documents["manifests"][0]["build_proof"]["executables"][
        transcript["executable"]
    ]["link_command"]
    command["argv"].extend(suffix)
    trace_hosted = command["trace"]["absolute_path"]
    trace_path = (
        staging / "bundle/subject" / Path(trace_hosted).relative_to("/host/subject")
    )
    trace_record = json.loads(trace_path.read_bytes())
    trace_record["argv"].extend(suffix)
    trace_bytes = json_bytes(trace_record)
    trace_path.write_bytes(trace_bytes)
    command["trace"]["sha256"] = hashlib.sha256(trace_bytes).hexdigest()
    transcript["trace"] = copy.deepcopy(command["trace"])
    expected = {
        (manifest["variant"], executable): proof["link_command"]
        for manifest in documents["manifests"]
        for executable, proof in manifest["build_proof"]["executables"].items()
    }
    archive = tmp_path / "evidence.tar"
    digest = package_module.package_evidence(
        staging, archive, tmp_path / "evidence.tar.sha256"
    )
    extracted = tmp_path / "extracted"
    with tarfile.open(archive, mode="r:") as handle:
        structure = verify_module._inspect(handle, digest)
        verify_module.extract_validated_archive(
            structure.members,
            extracted,
            handle,
        )
    roots = verify_module.PortableRoots.from_document(documents["portable_paths"])
    with pytest.raises(
        verify_module.EvidenceError,
        match="abbreviated|terminator|unsafe|output",
    ):
        verify_module._verify_transcripts(
            extracted,
            structure.members,
            roots,
            documents["transcripts"],
            expected,
        )


def test_full_immutable_capability_and_v2_schemas_accept_attempt_5(
    verify_module: ModuleType,
) -> None:
    records = reviewed_records()
    capability = records["capability"]
    manifest = records["clean_a"]
    verify_module._validate_schema(
        capability, verify_module.CAPABILITY_SCHEMA, "capability"
    )
    verify_module._validate_schema(
        manifest, verify_module.MANIFEST_V2_SCHEMA, "manifest_v2"
    )
    assert capability["producer"]["commit"] == SUBJECT_COMMIT
    assert capability["producer"]["tree"] == SUBJECT_TREE
    assert manifest["commit"] == SUBJECT_COMMIT
    assert manifest["tree"] == SUBJECT_TREE
    assert any(
        item["symlink_target"] is not None
        for linker in (
            capability["linker"],
            *capability["required_linkers"].values(),
        )
        for item in linker["invocation_chain"]
    )
    assert any(
        layout["archive_member_owners"] for layout in manifest["elf_layout"].values()
    )


def test_full_immutable_v1_schema_accepts_replayed_shape(
    verify_module: ModuleType,
) -> None:
    manifest = reviewed_records()["v1"]
    verify_module._validate_schema(
        manifest, verify_module.MANIFEST_V1_SCHEMA, "manifest_v1"
    )
    assert manifest["tree"] == V1_REPLAY_TREE


@pytest.mark.parametrize(
    ("path", "field_kind"),
    [
        (
            (
                "capability",
                "shapes",
                "*",
                "*",
                "binary",
                "absolute_path",
            ),
            "hashed-file",
        ),
        (
            (
                "manifest",
                "build_proof",
                "executables",
                "*",
                "rustc_argv",
                "*",
            ),
            "rustc-command",
        ),
        (
            (
                "manifest",
                "elf_layout",
                "*",
                "archive_member_owners",
                "*",
            ),
            "rlib-member",
        ),
        (
            (
                "manifest",
                "build_proof",
                "executables",
                "*",
                "link_command",
                "argv",
            ),
            "linker-command",
        ),
    ],
)
def test_full_typed_route_table_is_closed(
    verify_module: ModuleType, path: tuple[str, ...], field_kind: str
) -> None:
    assert verify_module.classify(path) == field_kind


def test_concrete_route_walk_reaches_real_nested_path_fields(
    verify_module: ModuleType,
) -> None:
    manifest = reviewed_records()["clean_a"]
    routed = {
        path: field_kind
        for path, field_kind, _value in verify_module.collect_concrete_routes(
            "manifest", manifest
        )
    }
    assert (
        routed[
            (
                "manifest",
                "control",
                "runner_root",
            )
        ]
        == "root"
    )
    assert (
        routed[
            (
                "manifest",
                "linker_capability",
                "required_linkers",
                "lld",
                "invocation_chain",
                0,
                "absolute_path",
            )
        ]
        == "system-file"
    )
    assert (
        routed[
            (
                "manifest",
                "build_proof",
                "executables",
                "elastic_cache_gate",
                "rustc_argv",
                0,
            )
        ]
        == "rustc-command"
    )
    assert (
        routed[
            (
                "manifest",
                "elf_layout",
                "elastic_cache_gate",
                "kernels",
                "elastic_cache_gate_insert_kernel",
                "input_owner",
            )
        ]
        == "transient-file"
    )


@pytest.mark.parametrize(
    "environment",
    [
        "MYSTERY_PATH=/outside",
        "CARGO_ENCODED_RUSTFLAGS='-Ccodegen-units=16-Clinker=/outside/wrapper'",
    ],
)
def test_rustc_transcript_rejects_unclassified_path_environment(
    verify_module: ModuleType,
    environment: str,
) -> None:
    roots = verify_module.PortableRoots.from_document(
        full_portable_paths(verify_module)
    )
    line = (
        f"Running `{environment} /host/toolchain/bin/rustc "
        "/host/subject/input.rs -o /host/subject/out`"
    )
    with pytest.raises(
        verify_module.EvidenceError,
        match="environment|outside declared roots",
    ):
        verify_module.validate_rustc_transcript(line, roots)


def test_rustc_transcript_rejects_empty_ld_library_path_element(
    verify_module: ModuleType,
) -> None:
    roots = verify_module.PortableRoots.from_document(
        full_portable_paths(verify_module)
    )
    line = (
        "Running `LD_LIBRARY_PATH=/host/toolchain/lib::/usr/lib "
        "/host/toolchain/bin/rustc /host/subject/input.rs "
        "-o /host/subject/out`"
    )
    with pytest.raises(verify_module.EvidenceError, match="empty LD_LIBRARY_PATH"):
        verify_module.validate_rustc_transcript(line, roots)


def test_full_capability_has_exact_nine_linker_shapes(
    verify_module: ModuleType,
) -> None:
    capability = reviewed_records()["capability"]
    assert verify_module.capability_shapes(capability) == {
        ("actual", "elastic", 2),
        ("actual", "funnel", 2),
        ("actual", "profile", 4),
        ("gnu", "elastic", 2),
        ("gnu", "funnel", 2),
        ("gnu", "profile", 4),
        ("lld", "elastic", 2),
        ("lld", "funnel", 2),
        ("lld", "profile", 4),
    }


def test_real_capability_shape_records_bind_nine_executions(
    verify_module: ModuleType,
) -> None:
    records = reviewed_records()

    def read_record(flavor: str, target: str, name: str) -> bytes:
        return records["shape_records"][f"capability-shapes/{flavor}/{target}/{name}"]

    assert verify_module.verify_capability_shape_records(
        records["capability"],
        read_record,
    ) == {
        (flavor, target, count)
        for flavor in ("actual", "gnu", "lld")
        for target, count in (("elastic", 2), ("funnel", 2), ("profile", 4))
    }


def test_real_fixture_routes_every_authentic_command_with_authenticated_roots(
    verify_module: ModuleType,
) -> None:
    records = reviewed_records()
    roots = reviewed_record_roots(verify_module, records)

    rustc_commands = [
        line
        for proof in records["clean_a"]["build_proof"]["executables"].values()
        for line in proof["rustc_argv"]
    ]
    assert len(rustc_commands) == 92
    for line in rustc_commands:
        verify_module.validate_rustc_transcript(line, roots)

    def read_record(flavor: str, target: str, name: str) -> bytes:
        return records["shape_records"][f"capability-shapes/{flavor}/{target}/{name}"]

    assert (
        len(
            verify_module.verify_capability_shape_records(
                records["capability"], read_record, roots
            )
        )
        == 9
    )
    verify_module.validate_concrete_route_values(
        "capability",
        records["capability"],
        roots,
    )
    replayed = 0
    for kind, manifest in (
        ("clean-a", records["clean_a"]),
        ("clean-b", records["clean_b"]),
        ("adversary", records["adversary"]),
    ):
        verify_module.validate_concrete_route_values("manifest", manifest, roots)
        for executable, (target, _kernels) in verify_module.EXECUTABLE_TARGETS.items():
            command = manifest["build_proof"]["executables"][executable]["link_command"]
            command_bytes = records["manifest_link_records"][
                f"manifest-link-commands/{kind}/{executable}.json"
            ]
            trace_bytes = records["manifest_link_records"][
                f"manifest-link-traces/{kind}/{executable}.jsonl"
            ]
            assert json.loads(command_bytes) == command
            assert (
                verify_module.verify_manifest_link_command(
                    command,
                    trace_bytes,
                    records["capability"],
                    target,
                    manifest["executables"][executable],
                    roots=roots,
                    subject_root=manifest["runner_root"],
                )
                == command
            )
            replayed += 1
    assert replayed == 9


def test_capability_shape_rejects_linker_identity_substitution(
    verify_module: ModuleType,
) -> None:
    records = reviewed_records()
    substituted = copy.deepcopy(records["shape_records"])
    key = "capability-shapes/lld/elastic/linker-execution.json"
    execution = json.loads(substituted[key])
    execution["linker"] = copy.deepcopy(
        records["capability"]["required_linkers"]["gnu"]
    )
    substituted[key] = json_bytes(execution)

    def read_record(flavor: str, target: str, name: str) -> bytes:
        return substituted[f"capability-shapes/{flavor}/{target}/{name}"]

    with pytest.raises(
        verify_module.EvidenceError,
        match="shape linker identity mismatch",
    ):
        verify_module.verify_capability_shape_records(
            records["capability"],
            read_record,
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("elf_type", "ET_EXEC"),
        ("program_headers_have_rwx", True),
        ("function_symbol_count", 2),
        ("input_section", ".text.attacker"),
        ("output_section_count", 2),
        ("section_flags", ["ALLOC", "WRITE", "EXECINSTR"]),
        ("pt_load_count", 2),
        ("pt_load_flags", "RWE"),
        ("writable_segment_overlap", True),
        ("overlapping_elf_sections", [".data"]),
        ("sh_addralign", 3),
        ("veneer_thunks", ["attacker_thunk"]),
        ("plt_calls", ["puts@plt"]),
    ],
)
def test_manifest_layout_ports_every_hosted_safety_invariant(
    verify_module: ModuleType,
    field: str,
    replacement: Any,
) -> None:
    records = reviewed_records()
    layout = records["clean_a"]["elf_layout"]["elastic_cache_gate"]
    if field in {"elf_type", "program_headers_have_rwx"}:
        layout[field] = replacement
    else:
        layout["kernels"]["elastic_cache_gate_insert_kernel"][field] = replacement
    with pytest.raises(
        verify_module.EvidenceError,
        match="ELF|RWX|count|section|segment|overlap|align|veneer|thunk|PLT",
    ):
        verify_module.verify_manifest_relationships(
            records["clean_a"],
            records["clean_b"],
            records["adversary"],
        )


def test_capability_layout_binds_max_page_size(
    verify_module: ModuleType,
) -> None:
    records = reviewed_records()
    capability = records["capability"]
    capability["max_page_size"] *= 2

    def read_record(flavor: str, target: str, name: str) -> bytes:
        return records["shape_records"][f"capability-shapes/{flavor}/{target}/{name}"]

    with pytest.raises(verify_module.EvidenceError, match="MAXPAGESIZE|max.page"):
        verify_module.verify_capability_shape_records(capability, read_record)


def test_manifest_layout_binds_keyed_capability_fragment(
    verify_module: ModuleType,
) -> None:
    records = reviewed_records()
    for manifest in (
        records["clean_a"],
        records["clean_b"],
        records["adversary"],
    ):
        manifest["elf_layout"]["elastic_cache_gate"]["fragment_sha256"] = "f" * 64
    with pytest.raises(verify_module.EvidenceError, match="fragment"):
        verify_module.verify_manifest_relationships(
            records["clean_a"],
            records["clean_b"],
            records["adversary"],
        )


def test_manifest_layout_binds_executable_link_map_hash(
    verify_module: ModuleType,
) -> None:
    records = reviewed_records()
    records["clean_a"]["elf_layout"]["elastic_cache_gate"]["link_map_sha256"] = "f" * 64
    with pytest.raises(verify_module.EvidenceError, match="link-map.*association"):
        verify_module.verify_manifest_relationships(
            records["clean_a"],
            records["clean_b"],
            records["adversary"],
        )


LINKER_INPUT_GRAMMAR_CASES = (
    pytest.param(
        ["-Wl,/host/subject/wl-hidden.o"],
        "wl-hidden.o",
        True,
        id="wl-comma-object",
    ),
    pytest.param(
        ["-Wl,-l,wl_hidden"],
        "-lwl_hidden",
        False,
        id="wl-comma-library",
    ),
    pytest.param(
        ["-Xlinker", "-l", "-Xlinker", "xsplit"],
        "-lxsplit",
        False,
        id="xlinker-split-library",
    ),
    pytest.param(
        ["-Xlinker=/host/subject/xjoined.a"],
        "xjoined.a",
        True,
        id="xlinker-joined-archive",
    ),
    pytest.param(
        ["-l", "split"],
        "-lsplit",
        False,
        id="library-short-split",
    ),
    pytest.param(
        ["-ljoined"],
        "-ljoined",
        False,
        id="library-short-joined",
    ),
    pytest.param(
        ["--library", "longsplit"],
        "-llongsplit",
        False,
        id="library-long-split",
    ),
    pytest.param(
        ["--library=longjoined"],
        "-llongjoined",
        False,
        id="library-long-joined",
    ),
)


@pytest.mark.parametrize(
    ("tokens", "expected_input", "is_direct"),
    LINKER_INPUT_GRAMMAR_CASES,
)
def test_link_command_inputs_classify_every_forwarding_grammar(
    verify_module: ModuleType,
    tokens: list[str],
    expected_input: str,
    is_direct: bool,
) -> None:
    ordered, direct = verify_module._link_command_inputs(
        ["/host/subject/input.o", *tokens]
    )
    assert ordered == ["input.o", expected_input]
    assert direct == (sorted(["input.o", expected_input]) if is_direct else ["input.o"])


@pytest.mark.parametrize(
    "tokens",
    [
        pytest.param(
            ["-Wl,-Map,/host/subject/not-an-input.o"],
            id="wl-map-operand",
        ),
        pytest.param(
            ["-Wl,-T,/host/subject/not-an-input.a"],
            id="wl-script-operand",
        ),
        pytest.param(
            ["-Xlinker", "-o", "-Xlinker", "/host/subject/not-an-input.so"],
            id="xlinker-output-operand",
        ),
        pytest.param(["-o", "/host/subject/not-an-input.o"], id="driver-output"),
        pytest.param(
            ["-L", "/host/subject/not-an-input.a"],
            id="driver-library-search-path",
        ),
    ],
)
def test_link_command_inputs_exclude_non_input_option_operands(
    verify_module: ModuleType,
    tokens: list[str],
) -> None:
    assert verify_module._link_command_inputs(["/host/subject/input.o", *tokens]) == (
        ["input.o"],
        ["input.o"],
    )


@pytest.mark.parametrize(
    "loader_control",
    [
        pytest.param(
            ["-dynamic-linker", "/lib64/ld-linux-x86-64.so.2"],
            id="direct",
        ),
        pytest.param(
            ["-Wl,-dynamic-linker,/lib64/ld-linux-x86-64.so.2"],
            id="wl-forwarded",
        ),
    ],
)
def test_effective_link_command_excludes_dynamic_loader_operand_from_inputs(
    verify_module: ModuleType,
    loader_control: list[str],
) -> None:
    parsed = verify_module._parse_effective_link_command(
        [
            "/host/subject/input.o",
            *loader_control,
            "-o",
            "/host/subject/output",
        ]
    )
    assert parsed.outputs == ("/host/subject/output",)
    assert parsed.inputs.ordered == ("input.o",)
    assert parsed.inputs.direct_files == ("input.o",)


def test_effective_link_command_preserves_known_lto_plugin_controls(
    verify_module: ModuleType,
) -> None:
    argv = [
        "-plugin",
        "/usr/libexec/gcc/x86_64-linux-gnu/14/liblto_plugin.so",
        "-plugin-opt=/usr/libexec/gcc/x86_64-linux-gnu/14/lto-wrapper",
        "-plugin-opt=-fresolution=/tmp/ccAb12Cd.res",
        "/host/subject/input.o",
        "-o",
        "/host/subject/output",
    ]
    parsed = verify_module._parse_effective_link_command(argv)
    assert parsed.inputs.ordered == ("input.o",)
    assert [
        (control.option, control.operand) for control in parsed.controls.mechanisms
    ] == [
        ("-plugin", "/usr/libexec/gcc/x86_64-linux-gnu/14/liblto_plugin.so"),
        ("-plugin-opt", "/usr/libexec/gcc/x86_64-linux-gnu/14/lto-wrapper"),
        ("-plugin-opt", "-fresolution=/tmp/ccAb12Cd.res"),
    ]
    with pytest.raises(verify_module.EvidenceError, match="plugin"):
        verify_module._link_command_inputs(argv)


@pytest.mark.parametrize(
    ("tokens", "expected_input"),
    [
        pytest.param(
            ["--for-linker=-lfor_joined"],
            "-lfor_joined",
            id="for-linker-joined-library",
        ),
        pytest.param(
            ["--for-linker", "-l", "--for-linker", "for_split"],
            "-lfor_split",
            id="for-linker-split-library",
        ),
        pytest.param(
            ["--for-linker=/host/subject/for-linker-input"],
            "for-linker-input",
            id="for-linker-direct-input",
        ),
        pytest.param(
            ["/host/subject/extensionless"],
            "extensionless",
            id="extensionless-positional",
        ),
        pytest.param(
            ["/host/subject/alternate.obj"],
            "alternate.obj",
            id="obj-positional",
        ),
        pytest.param(
            ["/host/subject/alternate.lo"],
            "alternate.lo",
            id="lo-positional",
        ),
        pytest.param(
            ["/host/subject/positional-script.ld"],
            "positional-script.ld",
            id="script-positional",
        ),
        pytest.param(
            ["-R", "/host/subject/symbol-source"],
            "symbol-source",
            id="just-symbols-short-split",
        ),
        pytest.param(
            ["--just-symbols=/host/subject/symbol-source"],
            "symbol-source",
            id="just-symbols-long-joined",
        ),
    ],
)
def test_link_command_inputs_classify_all_positional_and_alias_inputs(
    verify_module: ModuleType,
    tokens: list[str],
    expected_input: str,
) -> None:
    ordered, direct = verify_module._link_command_inputs(
        ["/host/subject/input.o", *tokens]
    )
    assert ordered == ["input.o", expected_input]
    assert direct == (
        ["input.o"]
        if expected_input.startswith("-l")
        else sorted(["input.o", expected_input])
    )


@pytest.mark.parametrize(
    "tokens",
    [
        pytest.param(["-l"], id="dangling-short-library"),
        pytest.param(["--library"], id="dangling-long-library"),
        pytest.param(["-Wl,-l"], id="dangling-wl-library"),
        pytest.param(["-Xlinker"], id="dangling-xlinker"),
        pytest.param(["-Xlinker="], id="empty-joined-xlinker"),
        pytest.param(["-Wl,"], id="empty-wl"),
        pytest.param(["-Wl,@hidden.rsp"], id="wl-response-file"),
        pytest.param(["-Xlinker", "@hidden.rsp"], id="xlinker-response-file"),
        pytest.param(
            ["-Xlinker", "-o", "/host/subject/driver-input.o"],
            id="mixed-origin-xlinker-operand",
        ),
        pytest.param(["--for-linker"], id="dangling-for-linker"),
        pytest.param(["--for-linker="], id="empty-for-linker"),
        pytest.param(["--output="], id="empty-long-option"),
        pytest.param(["-Map="], id="empty-short-option"),
        pytest.param(["-rpath="], id="empty-short-equals-option"),
        pytest.param(
            ["--remap-inputs=input.o=/host/subject/hidden.o"],
            id="input-remap",
        ),
        pytest.param(
            ["--remap-inputs-file=/host/subject/remaps.txt"],
            id="input-remap-file",
        ),
        pytest.param(
            ["--version-script=/host/subject/version.ld"],
            id="version-script",
        ),
    ],
)
def test_link_command_inputs_reject_malformed_or_opaque_forwarding(
    verify_module: ModuleType,
    tokens: list[str],
) -> None:
    with pytest.raises(verify_module.EvidenceError):
        verify_module._link_command_inputs(["/host/subject/input.o", *tokens])


@pytest.mark.parametrize(
    ("tokens", "_expected_input", "_is_direct"),
    LINKER_INPUT_GRAMMAR_CASES,
)
def test_manifest_replay_rejects_undeclared_forwarded_linker_input(
    verify_module: ModuleType,
    tokens: list[str],
    _expected_input: str,
    _is_direct: bool,
) -> None:
    documents = full_semantic_documents(verify_module)
    capability = documents["capability"]
    manifest = documents["manifests"][0]
    executable = "elastic_cache_gate"
    command = manifest["build_proof"]["executables"][executable]["link_command"]
    trace_path = command["trace"]["absolute_path"]
    trace_record = json.loads(documents["hosted_files"][trace_path])
    command["argv"][1:1] = tokens
    trace_record["argv"] = copy.deepcopy(command["argv"])
    trace_bytes = json_bytes(trace_record)
    command["trace"]["sha256"] = hashlib.sha256(trace_bytes).hexdigest()
    with pytest.raises(
        verify_module.EvidenceError,
        match="input|link command",
    ):
        verify_module.verify_manifest_link_command(
            command,
            trace_bytes,
            capability,
            "elastic",
            manifest["executables"][executable],
            expected_fragment=private_fragment_path(manifest, "elastic"),
        )


def test_manifest_replay_rejects_same_hash_alternate_fragment_path(
    verify_module: ModuleType,
) -> None:
    documents = full_semantic_documents(verify_module)
    capability = documents["capability"]
    manifest = documents["manifests"][0]
    executable = "elastic_cache_gate"
    command = manifest["build_proof"]["executables"][executable]["link_command"]
    executable_record = manifest["executables"][executable]
    authority = private_fragment_path(manifest, "elastic")
    assert executable_record["linker_fragment"]["absolute_path"] == authority
    assert command["fragment"] == authority
    alternate = "/host/subject/alternate-same-hash.ld"
    executable_record["linker_fragment"]["absolute_path"] = alternate
    command["fragment"] = alternate
    command["argv"] = [
        token.replace(
            f"-Wl,-T,{authority}",
            f"-Wl,-T,{alternate}",
        )
        for token in command["argv"]
    ]
    trace_path = command["trace"]["absolute_path"]
    trace_record = json.loads(documents["hosted_files"][trace_path])
    trace_record["argv"] = copy.deepcopy(command["argv"])
    trace_bytes = json_bytes(trace_record)
    command["trace"]["sha256"] = hashlib.sha256(trace_bytes).hexdigest()
    with pytest.raises(verify_module.EvidenceError, match="fragment"):
        verify_module.verify_manifest_link_command(
            command,
            trace_bytes,
            capability,
            "elastic",
            executable_record,
            expected_fragment=authority,
        )


def test_manifest_replay_rejects_private_fragment_aliasing_source_fragment(
    verify_module: ModuleType,
) -> None:
    documents = full_semantic_documents(verify_module)
    capability = documents["capability"]
    manifest = documents["manifests"][0]
    executable = "elastic_cache_gate"
    authority = private_fragment_path(manifest, "elastic")
    capability["fragments"]["elastic"]["absolute_path"] = authority
    command = manifest["build_proof"]["executables"][executable]["link_command"]
    trace_path = command["trace"]["absolute_path"]
    with pytest.raises(
        verify_module.EvidenceError,
        match="private fragment aliases capability source fragment",
    ):
        verify_module.verify_manifest_link_command(
            command,
            documents["hosted_files"][trace_path],
            capability,
            "elastic",
            manifest["executables"][executable],
            expected_fragment=authority,
        )


def test_manifest_replay_rejects_alternate_executable_fragment_record_path(
    verify_module: ModuleType,
) -> None:
    documents = full_semantic_documents(verify_module)
    capability = documents["capability"]
    manifest = documents["manifests"][0]
    executable = "elastic_cache_gate"
    command = manifest["build_proof"]["executables"][executable]["link_command"]
    executable_record = manifest["executables"][executable]
    executable_record["linker_fragment"]["absolute_path"] = (
        "/host/subject/alternate-same-hash.ld"
    )
    trace_path = command["trace"]["absolute_path"]
    trace_bytes = documents["hosted_files"][trace_path]
    with pytest.raises(verify_module.EvidenceError, match="fragment"):
        verify_module.verify_manifest_link_command(
            command,
            trace_bytes,
            capability,
            "elastic",
            executable_record,
            expected_fragment=private_fragment_path(manifest, "elastic"),
        )


@pytest.mark.parametrize(
    "tokens",
    [
        pytest.param(
            ["--for-linker=-T", "--for-linker=/host/subject/extra.ld"],
            id="for-linker-script",
        ),
        pytest.param(
            ["-Xlinker=-Map", "-Xlinker=/host/subject/extra.map"],
            id="xlinker-map",
        ),
    ],
)
def test_manifest_replay_rejects_extra_aliased_linker_controls(
    verify_module: ModuleType,
    tokens: list[str],
) -> None:
    documents = full_semantic_documents(verify_module)
    capability = documents["capability"]
    manifest = documents["manifests"][0]
    executable = "elastic_cache_gate"
    command = manifest["build_proof"]["executables"][executable]["link_command"]
    command["argv"][1:1] = tokens
    trace_path = command["trace"]["absolute_path"]
    trace_record = json.loads(documents["hosted_files"][trace_path])
    trace_record["argv"] = copy.deepcopy(command["argv"])
    trace_bytes = json_bytes(trace_record)
    command["trace"]["sha256"] = hashlib.sha256(trace_bytes).hexdigest()
    with pytest.raises(verify_module.EvidenceError, match="controls"):
        verify_module.verify_manifest_link_command(
            command,
            trace_bytes,
            capability,
            "elastic",
            manifest["executables"][executable],
            expected_fragment=private_fragment_path(manifest, "elastic"),
        )


FORWARDED_OUTPUT_REDIRECT_CASES = (
    pytest.param(
        ["-Wl,-o,/host/subject/redirected-output"],
        id="wl-comma",
    ),
    pytest.param(
        ["-Xlinker", "-o", "-Xlinker", "/host/subject/redirected-output"],
        id="xlinker-split",
    ),
    pytest.param(
        ["-Xlinker=-o", "-Xlinker=/host/subject/redirected-output"],
        id="xlinker-joined",
    ),
    pytest.param(
        ["--for-linker", "-o", "--for-linker", "/host/subject/redirected-output"],
        id="for-linker-split",
    ),
    pytest.param(
        ["--for-linker=-o", "--for-linker=/host/subject/redirected-output"],
        id="for-linker-joined",
    ),
)


@pytest.mark.parametrize("suffix", UNSAFE_LINK_COMMAND_SUFFIXES)
def test_raw_output_values_rejects_unsafe_output_interpretation(
    verify_module: ModuleType,
    suffix: list[str],
) -> None:
    expected = "/host/subject/expected-output"
    with pytest.raises(
        verify_module.EvidenceError,
        match="abbreviated|terminator|unsafe|output",
    ):
        verify_module._raw_output_values(["-o", expected, *suffix])


@pytest.mark.parametrize("redirect", FORWARDED_OUTPUT_REDIRECT_CASES)
def test_raw_output_values_uses_fully_flattened_linker_stream(
    verify_module: ModuleType,
    redirect: list[str],
) -> None:
    expected = "/host/subject/expected-output"
    assert verify_module._raw_output_values(["-o", expected, *redirect]) == [
        expected,
        "/host/subject/redirected-output",
    ]


@pytest.mark.parametrize(
    "argv",
    [
        pytest.param(["-o"], id="direct-short-dangling"),
        pytest.param(["--output"], id="direct-long-dangling"),
        pytest.param(["--output="], id="direct-long-empty"),
        pytest.param(["-Wl,-o"], id="wl-dangling"),
        pytest.param(["-Wl,--output="], id="wl-empty"),
        pytest.param(["-Xlinker=-o"], id="xlinker-dangling"),
        pytest.param(["--for-linker=-o"], id="for-linker-dangling"),
        pytest.param(
            ["-Xlinker", "-o", "/host/subject/mixed-output"],
            id="xlinker-mixed-origin",
        ),
        pytest.param(
            ["--for-linker", "-o", "/host/subject/mixed-output"],
            id="for-linker-mixed-origin",
        ),
        pytest.param(["-Wl,@hidden.rsp"], id="response-file"),
    ],
)
def test_raw_output_values_rejects_malformed_or_opaque_controls(
    verify_module: ModuleType,
    argv: list[str],
) -> None:
    with pytest.raises(verify_module.EvidenceError):
        verify_module._raw_output_values(argv)


@pytest.mark.parametrize("suffix", UNSAFE_LINK_COMMAND_SUFFIXES)
def test_manifest_trace_rejects_unsafe_output_interpretation(
    verify_module: ModuleType,
    suffix: list[str],
) -> None:
    documents = full_semantic_documents(verify_module)
    capability = documents["capability"]
    manifest = documents["manifests"][0]
    executable = "elastic_cache_gate"
    command = manifest["build_proof"]["executables"][executable]["link_command"]
    command["argv"].extend(suffix)
    trace_path = command["trace"]["absolute_path"]
    trace_record = json.loads(documents["hosted_files"][trace_path])
    trace_record["argv"] = copy.deepcopy(command["argv"])
    trace_bytes = json_bytes(trace_record)
    command["trace"]["sha256"] = hashlib.sha256(trace_bytes).hexdigest()
    with pytest.raises(
        verify_module.EvidenceError,
        match="abbreviated|terminator|unsafe|output",
    ):
        verify_module.verify_manifest_link_command(
            command,
            trace_bytes,
            capability,
            "elastic",
            manifest["executables"][executable],
            expected_fragment=private_fragment_path(manifest, "elastic"),
        )


@pytest.mark.parametrize("redirect", FORWARDED_OUTPUT_REDIRECT_CASES)
def test_manifest_trace_rejects_forwarded_output_redirect(
    verify_module: ModuleType,
    redirect: list[str],
) -> None:
    documents = full_semantic_documents(verify_module)
    capability = documents["capability"]
    manifest = documents["manifests"][0]
    executable = "elastic_cache_gate"
    command = manifest["build_proof"]["executables"][executable]["link_command"]
    command["argv"].extend(redirect)
    trace_path = command["trace"]["absolute_path"]
    trace_record = json.loads(documents["hosted_files"][trace_path])
    trace_record["argv"] = copy.deepcopy(command["argv"])
    trace_bytes = json_bytes(trace_record)
    command["trace"]["sha256"] = hashlib.sha256(trace_bytes).hexdigest()
    with pytest.raises(
        verify_module.EvidenceError,
        match="producer|count|output",
    ):
        verify_module.verify_manifest_link_command(
            command,
            trace_bytes,
            capability,
            "elastic",
            manifest["executables"][executable],
            expected_fragment=private_fragment_path(manifest, "elastic"),
        )


@pytest.mark.parametrize("suffix", UNSAFE_LINK_COMMAND_SUFFIXES)
def test_shape_trace_rejects_unsafe_output_interpretation(
    verify_module: ModuleType,
    suffix: list[str],
) -> None:
    documents = full_semantic_documents(verify_module)
    capability = documents["capability"]
    shape = capability["shapes"]["actual"]["elastic"]
    execution_path = shape["linker_execution"]["absolute_path"]
    execution = json.loads(documents["shape_files"][execution_path])
    execution["argv"].extend(suffix)
    trace_path = execution["trace"]["absolute_path"]
    trace_record = json.loads(documents["shape_files"][trace_path])
    trace_record["argv"] = copy.deepcopy(execution["argv"])
    trace_bytes = json_bytes(trace_record)
    execution["trace"]["sha256"] = hashlib.sha256(trace_bytes).hexdigest()
    with pytest.raises(
        verify_module.EvidenceError,
        match="abbreviated|terminator|unsafe|output",
    ):
        verify_module._verify_shape_trace(
            execution,
            trace_bytes,
            capability["linker"],
        )


@pytest.mark.parametrize("redirect", FORWARDED_OUTPUT_REDIRECT_CASES)
def test_shape_trace_rejects_forwarded_output_redirect(
    verify_module: ModuleType,
    redirect: list[str],
) -> None:
    documents = full_semantic_documents(verify_module)
    capability = documents["capability"]
    shape = capability["shapes"]["actual"]["elastic"]
    execution_path = shape["linker_execution"]["absolute_path"]
    execution = json.loads(documents["shape_files"][execution_path])
    execution["argv"].extend(redirect)
    trace_path = execution["trace"]["absolute_path"]
    trace_record = json.loads(documents["shape_files"][trace_path])
    trace_record["argv"] = copy.deepcopy(execution["argv"])
    trace_bytes = json_bytes(trace_record)
    execution["trace"]["sha256"] = hashlib.sha256(trace_bytes).hexdigest()
    with pytest.raises(
        verify_module.EvidenceError,
        match="producer|count|output",
    ):
        verify_module._verify_shape_trace(
            execution,
            trace_bytes,
            capability["linker"],
        )


@pytest.mark.parametrize("mutation", ["driver", "fragment", "map", "inputs"])
def test_manifest_link_command_is_independently_replayed(
    verify_module: ModuleType,
    mutation: str,
) -> None:
    documents = full_semantic_documents(verify_module)
    capability = documents["capability"]
    manifest = documents["manifests"][0]
    executable = "elastic_cache_gate"
    target = "elastic"
    command = manifest["build_proof"]["executables"][executable]["link_command"]
    executable_record = manifest["executables"][executable]
    trace_path = command["trace"]["absolute_path"]
    trace_record = json.loads(documents["hosted_files"][trace_path])
    if mutation == "driver":
        command["driver"] = copy.deepcopy(capability["required_linkers"]["lld"])
        trace_record["argv0"] = command["driver"]["argv0"]
        trace_record["payload_path"] = command["driver"]["payload_path"]
        trace_record["payload_sha256"] = command["driver"]["payload_sha256"]
    elif mutation == "fragment":
        command["fragment"] = "/host/subject/attacker.ld"
        command["argv"] = [
            token.replace(
                "-Wl,-T,/host/subject/payload",
                "-Wl,-T,/host/subject/attacker.ld",
            )
            for token in command["argv"]
        ]
        trace_record["argv"] = copy.deepcopy(command["argv"])
    elif mutation == "map":
        command["link_map"] = "/host/subject/attacker.map"
        command["argv"] = [
            token.replace(
                "-Wl,-Map,/host/subject/payload",
                "-Wl,-Map,/host/subject/attacker.map",
            )
            for token in command["argv"]
        ]
        trace_record["argv"] = copy.deepcopy(command["argv"])
    else:
        command["ordered_linker_inputs"].append("forged.o")
        command["direct_input_files"].append("forged.o")
        command["direct_cgu_members"].append("forged.rcgu.o")
        command["ordered_linker_input_fingerprint"] = verify_module._fingerprint(
            command["ordered_linker_inputs"]
        )
    trace_bytes = json_bytes(trace_record)
    command["trace"]["sha256"] = hashlib.sha256(trace_bytes).hexdigest()
    with pytest.raises(
        verify_module.EvidenceError,
        match="driver|fragment|map|input|trace|link command",
    ):
        verify_module.verify_manifest_link_command(
            command,
            trace_bytes,
            capability,
            target,
            executable_record,
            expected_fragment=private_fragment_path(manifest, target),
        )


@pytest.mark.parametrize("extra_kind", ["malformed", "second-producer"])
def test_manifest_link_trace_validates_every_record_and_unique_producer(
    verify_module: ModuleType,
    extra_kind: str,
) -> None:
    documents = full_semantic_documents(verify_module)
    capability = documents["capability"]
    manifest = documents["manifests"][0]
    executable = "elastic_cache_gate"
    command = manifest["build_proof"]["executables"][executable]["link_command"]
    trace_path = command["trace"]["absolute_path"]
    original = json.loads(documents["hosted_files"][trace_path])
    if extra_kind == "malformed":
        extra = {"argv": []}
    else:
        extra = copy.deepcopy(original)
        extra["argv"].insert(0, "--build-id")
    trace_bytes = json_bytes(original) + json_bytes(extra)
    command["trace"]["sha256"] = hashlib.sha256(trace_bytes).hexdigest()
    command["trace"]["record_count"] = 2
    command["trace"]["final_link_record_count"] = 1
    with pytest.raises(
        verify_module.EvidenceError,
        match="trace record|one captured final|producer|count",
    ):
        verify_module.verify_manifest_link_command(
            command,
            trace_bytes,
            capability,
            "elastic",
            manifest["executables"][executable],
            expected_fragment=private_fragment_path(manifest, "elastic"),
        )


def test_shape_trace_recomputes_unique_final_output_producer(
    verify_module: ModuleType,
) -> None:
    documents = full_semantic_documents(verify_module)
    capability = documents["capability"]
    shape = capability["shapes"]["actual"]["elastic"]
    execution_path = shape["linker_execution"]["absolute_path"]
    execution = json.loads(documents["shape_files"][execution_path])
    trace_path = execution["trace"]["absolute_path"]
    first = json.loads(documents["shape_files"][trace_path])
    second = copy.deepcopy(first)
    second["argv"].insert(0, "--build-id")
    trace_bytes = json_bytes(first) + json_bytes(second)
    execution["trace"]["sha256"] = hashlib.sha256(trace_bytes).hexdigest()
    execution["trace"]["record_count"] = 2
    execution["trace"]["final_link_record_count"] = 1
    with pytest.raises(
        verify_module.EvidenceError,
        match="one.*execution|producer|count",
    ):
        verify_module._verify_shape_trace(
            execution,
            trace_bytes,
            capability["linker"],
        )


@pytest.mark.parametrize("mutation", ["cwd", "raw-output"])
def test_shape_execution_is_confined_to_subject_and_artifact_roots(
    verify_module: ModuleType,
    mutation: str,
) -> None:
    documents = full_semantic_documents(verify_module)
    capability = documents["capability"]
    shape = capability["shapes"]["actual"]["elastic"]
    execution_path = shape["linker_execution"]["absolute_path"]
    execution = json.loads(documents["shape_files"][execution_path])
    trace_path = execution["trace"]["absolute_path"]
    trace = json.loads(documents["shape_files"][trace_path])
    if mutation == "cwd":
        execution["cwd"] = trace["cwd"] = "/host/v1"
    else:
        old_output = execution["raw_output"]
        new_output = "/host/evidence/forged-output"
        execution["raw_output"] = new_output
        execution["argv"] = [
            new_output if token == old_output else token for token in execution["argv"]
        ]
        trace["argv"] = copy.deepcopy(execution["argv"])
        link_argv_path = shape["link_argv"]["absolute_path"]
        link_argv = documents["shape_files"][link_argv_path].replace(
            old_output.encode(),
            new_output.encode(),
        )
        documents["shape_files"][link_argv_path] = link_argv
        shape["link_argv"]["sha256"] = hashlib.sha256(link_argv).hexdigest()
    trace_bytes = json_bytes(trace)
    documents["shape_files"][trace_path] = trace_bytes
    execution["trace"]["sha256"] = hashlib.sha256(trace_bytes).hexdigest()
    execution_bytes = json_bytes(execution)
    documents["shape_files"][execution_path] = execution_bytes
    shape["linker_execution"]["sha256"] = hashlib.sha256(execution_bytes).hexdigest()
    roots = verify_module.PortableRoots.from_document(documents["portable_paths"])

    def read_record(flavor: str, target: str, name: str) -> bytes:
        prefix = f"{capability['producer']['artifact_root']}/{flavor}/{target}"
        return documents["shape_files"][f"{prefix}/{name}"]

    with pytest.raises(
        verify_module.EvidenceError,
        match="subject root|artifact root|outside producer",
    ):
        verify_module.verify_capability_shape_records(
            capability,
            read_record,
            roots,
        )


def test_bare_linker_argv0_uses_explicit_safe_grammar(
    verify_module: ModuleType,
) -> None:
    records = reviewed_records()
    roots = reviewed_record_roots(verify_module, records)
    linker = records["capability"]["required_linkers"]["lld"]
    verify_module.validate_linker_record_routes(linker, roots)
    forged = copy.deepcopy(linker)
    forged["argv0"] = "../ld.lld"
    with pytest.raises(verify_module.EvidenceError, match="argv0"):
        verify_module.validate_linker_record_routes(forged, roots)


def test_full_clean_and_adversary_relationships_use_immutable_fields(
    verify_module: ModuleType,
) -> None:
    records = reviewed_records()
    clean_a = records["clean_a"]
    clean_b = records["clean_b"]
    adversary = records["adversary"]
    verify_module.verify_manifest_relationships(clean_a, clean_b, adversary)
    clean_b["build_proof"]["link_order_fingerprint"] = "f" * 64
    with pytest.raises(verify_module.EvidenceError, match="clean build proof"):
        verify_module.verify_manifest_relationships(clean_a, clean_b, adversary)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("raw_sha256", "f" * 64),
        ("body_end", 999_999),
        ("sentinels", {"reservation_start": {"address": 999_999}}),
        ("link_map_sentinels", {"body_end": 999_999}),
    ],
)
def test_clean_layout_comparison_rejects_raw_body_end_and_sentinel_drift(
    verify_module: ModuleType,
    field: str,
    replacement: Any,
) -> None:
    records = reviewed_records()
    clean_a = records["clean_a"]
    clean_b = records["clean_b"]
    adversary = records["adversary"]
    kernel = clean_b["elf_layout"]["elastic_cache_gate"]["kernels"][
        "elastic_cache_gate_insert_kernel"
    ]
    if field in {"sentinels", "link_map_sentinels"}:
        for key, value in replacement.items():
            if isinstance(value, dict):
                kernel[field][key].update(value)
            else:
                kernel[field][key] = value
    else:
        kernel[field] = replacement
    with pytest.raises(
        verify_module.EvidenceError,
        match="body|sentinel|symbol/layout",
    ):
        verify_module.verify_manifest_relationships(clean_a, clean_b, adversary)


def test_layout_body_is_cross_bound_to_symbol_record(
    verify_module: ModuleType,
) -> None:
    records = reviewed_records()
    for manifest in (
        records["clean_a"],
        records["clean_b"],
        records["adversary"],
    ):
        manifest["elf_layout"]["elastic_cache_gate"]["kernels"][
            "elastic_cache_gate_insert_kernel"
        ]["raw_sha256"] = "f" * 64
    with pytest.raises(verify_module.EvidenceError, match="symbol/layout"):
        verify_module.verify_manifest_relationships(
            records["clean_a"], records["clean_b"], records["adversary"]
        )


def test_manifest_layout_rejects_coherent_non_arithmetic_body_size(
    verify_module: ModuleType,
) -> None:
    records = reviewed_records()
    kernel_name = "elastic_cache_gate_insert_kernel"
    for manifest in (
        records["clean_a"],
        records["clean_b"],
        records["adversary"],
    ):
        layout = manifest["elf_layout"]["elastic_cache_gate"]["kernels"][kernel_name]
        for field in ("body_size", "input_size", "function_size"):
            layout[field] += 1
        symbol = next(
            item
            for item in manifest["symbols"]["elastic_cache_gate"]["symbols"]
            if item["name"].endswith(f"::{kernel_name}")
        )
        symbol["size"] += 1
    with pytest.raises(verify_module.EvidenceError, match="size|range|arithmetic"):
        verify_module.verify_manifest_relationships(
            records["clean_a"], records["clean_b"], records["adversary"]
        )


def test_manifest_layout_rejects_coherent_attacker_sentinel_names(
    verify_module: ModuleType,
) -> None:
    records = reviewed_records()
    for manifest in (
        records["clean_a"],
        records["clean_b"],
        records["adversary"],
    ):
        manifest["elf_layout"]["elastic_cache_gate"]["kernels"][
            "elastic_cache_gate_insert_kernel"
        ]["sentinels"]["body_end"]["name"] = "__attacker_body_end"
    with pytest.raises(verify_module.EvidenceError, match="sentinel.*name|sentinel"):
        verify_module.verify_manifest_relationships(
            records["clean_a"], records["clean_b"], records["adversary"]
        )


def test_capability_shape_rejects_attacker_sentinel_name(
    verify_module: ModuleType,
) -> None:
    records = reviewed_records()
    capability = copy.deepcopy(records["capability"])
    shape_records = copy.deepcopy(records["shape_records"])
    key = "capability-shapes/actual/elastic/layout.json"
    layout = json.loads(shape_records[key])
    layout["kernels"]["elastic_cache_gate_insert_kernel"]["sentinels"]["body_end"][
        "name"
    ] = "__attacker_body_end"
    shape_records[key] = json_bytes(layout)
    capability["shapes"]["actual"]["elastic"]["layout"]["sha256"] = hashlib.sha256(
        shape_records[key]
    ).hexdigest()

    def read_record(flavor: str, target: str, name: str) -> bytes:
        return shape_records[f"capability-shapes/{flavor}/{target}/{name}"]

    with pytest.raises(verify_module.EvidenceError, match="sentinel.*name|sentinel"):
        verify_module.verify_capability_shape_records(capability, read_record)


def test_adversary_raw_relocation_is_accepted_only_when_symbol_and_layout_agree(
    verify_module: ModuleType,
) -> None:
    records = reviewed_records()
    adversary = records["adversary"]
    kernel_name = "elastic_cache_gate_insert_kernel"
    raw_sha256 = "f" * 64
    adversary["elf_layout"]["elastic_cache_gate"]["kernels"][kernel_name][
        "raw_sha256"
    ] = raw_sha256
    symbol = next(
        item
        for item in adversary["symbols"]["elastic_cache_gate"]["symbols"]
        if item["name"].endswith(f"::{kernel_name}")
    )
    symbol["raw_sha256"] = raw_sha256
    verify_module.verify_manifest_relationships(
        records["clean_a"], records["clean_b"], adversary
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "constants",
        "clean-occurrence",
        "occurrence-name",
        "occurrence-start",
        "occurrence-size",
        "occurrence-count",
        "outside",
    ],
)
def test_layout_adversary_occurrences_are_recomputed_from_layout(
    verify_module: ModuleType,
    mutation: str,
) -> None:
    records = reviewed_records()
    clean_a = records["clean_a"]
    clean_b = records["clean_b"]
    adversary = records["adversary"]
    executable = "elastic_cache_gate"
    if mutation == "constants":
        for manifest in (clean_a, clean_b, adversary):
            manifest["layout_adversary"]["symbol"] = "attacker_symbol"
            manifest["layout_adversary"]["input_section"] = ".text.attacker"
    elif mutation == "clean-occurrence":
        clean_a["build_proof"]["executables"][executable]["adversary"] = {
            "symbol_occurrences": [
                {"name": "attacker", "start": 1, "size": 999},
            ],
            "input_section_occurrences": 999,
            "outside_reservations": False,
        }
    else:
        occurrence = adversary["build_proof"]["executables"][executable]["adversary"]
        if mutation == "occurrence-name":
            occurrence["symbol_occurrences"][0]["name"] = "attacker"
        elif mutation == "occurrence-start":
            occurrence["symbol_occurrences"][0]["start"] = 1
        elif mutation == "occurrence-size":
            occurrence["symbol_occurrences"][0]["size"] = 999
        elif mutation == "occurrence-count":
            occurrence["input_section_occurrences"] = 999
        else:
            occurrence["outside_reservations"] = False
    with pytest.raises(
        verify_module.EvidenceError,
        match="adversary.*(constant|symbol|section|occurrence|reservation|outside)",
    ):
        verify_module.verify_manifest_relationships(clean_a, clean_b, adversary)


@pytest.mark.parametrize(
    "mutation",
    [
        "target-triple",
        "manifest-architecture",
        "v1-architecture",
        "v1-symbol-architecture",
        "symbol-architecture",
        "layout-target",
        "layout-architecture",
        "actual-record-flavor",
        "gnu-record-flavor",
        "lld-record-flavor",
        "lld-link-map-flavor",
    ],
)
def test_exact_x86_target_architecture_and_linker_flavor_contract(
    verify_module: ModuleType,
    mutation: str,
) -> None:
    documents = full_semantic_documents(verify_module)
    capability = documents["capability"]
    manifests = documents["manifests"]
    v1 = documents["manifest_v1"]
    if mutation == "target-triple":
        capability["target_triple"] = "aarch64-unknown-linux-gnu"
    elif mutation == "manifest-architecture":
        manifests[0]["architecture"] = "aarch64"
    elif mutation == "v1-architecture":
        v1["architecture"] = "aarch64"
    elif mutation == "v1-symbol-architecture":
        v1["symbols"]["elastic_cache_gate"]["architecture"] = "aarch64"
    elif mutation == "symbol-architecture":
        manifests[0]["symbols"]["elastic_cache_gate"]["architecture"] = "aarch64"
    elif mutation == "layout-target":
        manifests[0]["elf_layout"]["elastic_cache_gate"]["target"] = "funnel"
    elif mutation == "layout-architecture":
        manifests[0]["elf_layout"]["elastic_cache_gate"]["arch"] = "aarch64"
    elif mutation == "actual-record-flavor":
        capability["linker"]["flavor"] = "mold"
    elif mutation == "gnu-record-flavor":
        capability["required_linkers"]["gnu"]["flavor"] = "LLD"
    elif mutation == "lld-record-flavor":
        capability["required_linkers"]["lld"]["flavor"] = "GNU ld"
    else:
        manifests[0]["elf_layout"]["elastic_cache_gate"]["link_map_flavor"] = "lld"
    with pytest.raises(
        verify_module.EvidenceError,
        match="x86|architecture|target|flavor",
    ):
        verify_module.verify_x86_contracts(capability, manifests, v1)


@pytest.mark.parametrize(
    ("flavor", "record_name", "field", "replacement"),
    [
        ("actual", "symbols.json", "architecture", "x86_64"),
        ("actual", "layout.json", "target", "funnel"),
        ("actual", "layout.json", "arch", "x86_64"),
        ("actual", "layout.json", "link_map_flavor", "lld"),
        ("gnu", "layout.json", "link_map_flavor", "lld"),
        ("lld", "layout.json", "link_map_flavor", "gnu"),
    ],
)
def test_capability_shape_records_bind_arch_target_and_keyed_flavor(
    verify_module: ModuleType,
    flavor: str,
    record_name: str,
    field: str,
    replacement: str,
) -> None:
    records = reviewed_records()
    capability = copy.deepcopy(records["capability"])
    shape_records = copy.deepcopy(records["shape_records"])
    key = f"capability-shapes/{flavor}/elastic/{record_name}"
    document = json.loads(shape_records[key])
    document[field] = replacement
    shape_records[key] = json_bytes(document)
    artifact = "symbols" if record_name == "symbols.json" else "layout"
    capability["shapes"][flavor]["elastic"][artifact]["sha256"] = hashlib.sha256(
        shape_records[key]
    ).hexdigest()

    def read_record(shape_flavor: str, target: str, name: str) -> bytes:
        return shape_records[f"capability-shapes/{shape_flavor}/{target}/{name}"]

    with pytest.raises(
        verify_module.EvidenceError,
        match="architecture|target|flavor",
    ):
        verify_module.verify_capability_shape_records(capability, read_record)


@pytest.mark.parametrize(
    "mutation",
    [
        "per-executable-fingerprint",
        "ordered-inputs",
        "adversary-reserved",
        "kernel-name",
    ],
)
def test_strict_manifest_relationships_recompute_every_semantic(
    verify_module: ModuleType,
    mutation: str,
) -> None:
    records = reviewed_records()
    clean_a = records["clean_a"]
    clean_b = records["clean_b"]
    adversary = records["adversary"]
    executable = "elastic_cache_gate"
    if mutation == "per-executable-fingerprint":
        for manifest in (clean_a, clean_b):
            manifest["build_proof"]["executables"][executable][
                "object_member_fingerprint"
            ] = "f" * 64
    elif mutation == "ordered-inputs":
        for manifest in (clean_a, clean_b):
            manifest["build_proof"]["executables"][executable][
                "ordered_linker_inputs"
            ].reverse()
    elif mutation == "adversary-reserved":
        adversary["build_proof"]["reserved_input_owner_fingerprint"] = "f" * 64
    else:
        for manifest in (clean_a, clean_b, adversary):
            manifest["symbols"][executable]["symbols"][0]["name"] = (
                "crate::substituted_kernel"
            )
            layout = manifest["elf_layout"][executable]
            kernel = layout["kernels"].pop("elastic_cache_gate_insert_kernel")
            kernel["name"] = "substituted_kernel"
            layout["kernels"]["elastic_cache_gate_insert_kernel"] = kernel
    with pytest.raises(
        verify_module.EvidenceError,
        match="fingerprint|ordered linker inputs|adversary|kernel",
    ):
        verify_module.verify_manifest_relationships(clean_a, clean_b, adversary)


def test_exact_identity_contract_binds_subject_v1_controls_and_capability_bytes(
    verify_module: ModuleType,
) -> None:
    documents = full_semantic_documents(verify_module)
    capability = documents["capability"]
    manifests = documents["manifests"]
    v1 = documents["manifest_v1"]
    provenance = documents["provenance"]
    capability["producer"]["commit"] = SUBJECT_COMMIT
    capability["producer"]["tree"] = SUBJECT_TREE
    provenance["subject"] = {"commit": SUBJECT_COMMIT, "tree": SUBJECT_TREE}
    for manifest in manifests:
        manifest["commit"] = SUBJECT_COMMIT
        manifest["tree"] = SUBJECT_TREE
        for field in ("runner_commit", "builder_commit"):
            manifest["control"][field] = SUBJECT_COMMIT
        for field in ("runner_tree", "builder_tree"):
            manifest["control"][field] = SUBJECT_TREE
        manifest["linker_capability"] = {
            **copy.deepcopy(capability),
            "copy": {
                "absolute_path": "/host/evidence/capability.json",
                "sha256": hashlib.sha256(json_bytes(capability)).hexdigest(),
            },
        }
    v1["commit"] = V1_REPLAY_COMMIT
    v1["tree"] = V1_REPLAY_TREE
    v1["control"]["builder_commit"] = V1_REPLAY_COMMIT
    v1["control"]["builder_tree"] = V1_REPLAY_TREE
    verify_module.verify_identity_contract(
        provenance,
        capability,
        manifests,
        v1,
        json_bytes(capability),
        "/host/v1",
    )
    manifests[0]["control"]["builder_commit"] = "f" * 40
    with pytest.raises(
        verify_module.EvidenceError,
        match="exact subject identity",
    ):
        verify_module.verify_identity_contract(
            provenance,
            capability,
            manifests,
            v1,
            json_bytes(capability),
            "/host/v1",
        )


def test_identity_rejects_equal_but_unpinned_rust_toolchain(
    verify_module: ModuleType,
) -> None:
    documents = full_semantic_documents(verify_module)
    capability = documents["capability"]
    manifests = documents["manifests"]
    v1 = documents["manifest_v1"]
    capability["cargo_version"] = "cargo 9.9.9"
    capability["rustc_version"] = (
        "rustc 9.9.9\nhost: x86_64-unknown-linux-gnu\nrelease: 9.9.9"
    )
    for manifest in manifests:
        manifest["control"]["cargo_version"] = capability["cargo_version"]
        manifest["control"]["rustc_version"] = capability["rustc_version"]
        manifest["linker_capability"]["cargo_version"] = capability["cargo_version"]
        manifest["linker_capability"]["rustc_version"] = capability["rustc_version"]
        manifest["linker_capability"]["copy"]["sha256"] = hashlib.sha256(
            json_bytes(capability)
        ).hexdigest()
    v1["control"]["cargo_version"] = capability["cargo_version"]
    v1["control"]["rustc_version"] = capability["rustc_version"]

    with pytest.raises(verify_module.EvidenceError, match="Rust|toolchain|version"):
        verify_module.verify_identity_contract(
            documents["provenance"],
            capability,
            manifests,
            v1,
            json_bytes(capability),
            "/host/v1",
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "tool-revision",
        "tool-tree",
        "tool-blob",
        "tool-blob-sha",
        "tool-path",
        "tool-bytes",
        "v2-unlocked",
        "v1-unlocked",
        "v2-control-root",
        "control-version",
        "v1-declared-root",
        "v1-control-input-path",
    ],
)
def test_exact_identity_contract_binds_tools_and_locked_controls(
    verify_module: ModuleType,
    mutation: str,
) -> None:
    documents = full_semantic_documents(verify_module)
    capability = documents["capability"]
    manifests = documents["manifests"]
    v1 = documents["manifest_v1"]
    provenance = documents["provenance"]
    declared_v1_root = "/host/v1"
    if mutation == "tool-revision":
        manifests[0]["tools"]["launcher"]["reviewed_commit"] = "f" * 40
    elif mutation == "tool-tree":
        manifests[0]["tools"]["launcher"]["reviewed_tree"] = "f" * 40
    elif mutation == "tool-blob":
        manifests[0]["tools"]["launcher"]["git_blob"] = "f" * 40
    elif mutation == "tool-blob-sha":
        manifests[0]["tools"]["launcher"]["git_blob_sha256"] = "f" * 64
    elif mutation == "tool-path":
        manifests[0]["tools"]["launcher"]["absolute_path"] = (
            "/host/subject/scripts/cache-gate-perf.sh"
        )
    elif mutation == "tool-bytes":
        manifests[0]["tools"]["launcher"]["sha256"] = "f" * 64
    elif mutation == "v2-unlocked":
        manifests[0]["control"]["locked"] = False
    elif mutation == "v1-unlocked":
        v1["control"]["locked"] = False
    elif mutation == "v2-control-root":
        manifests[0]["control"]["runner_root"] = "/host/v1"
    elif mutation == "control-version":
        for manifest in manifests:
            manifest["control"]["cargo_version"] = "cargo 9.9.9"
        v1["control"]["cargo_version"] = "cargo 9.9.9"
    elif mutation == "v1-declared-root":
        declared_v1_root = "/host/not-v1"
    else:
        v1["control"]["inputs"]["source"]["absolute_path"] = (
            "/host/v1/tools/cache-gate-control/Cargo.toml"
        )
    with pytest.raises(
        verify_module.EvidenceError,
        match="tool|locked|identity|control",
    ):
        verify_module.verify_identity_contract(
            provenance,
            capability,
            manifests,
            v1,
            documents["capability_bytes"],
            declared_v1_root,
        )


def test_rlib_member_validation_is_reached_from_manifest_owner(
    tmp_path: Path,
    verify_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = tmp_path / "libproof.rlib"
    archive.write_bytes(b"archive")
    called: list[tuple[Path, str]] = []

    monkeypatch.setattr(
        verify_module,
        "validate_rlib_member",
        lambda path, member: called.append((path, member)),
    )
    verify_module.validate_manifest_rlib_owners(
        ["/host/toolchain/lib/libproof.rlib(member.o)"],
        lambda raw: archive if raw == "/host/toolchain/lib/libproof.rlib" else None,
    )
    assert called == [(archive, "member.o")]


def test_every_rlib_occurrence_is_index_checked_and_owner_lists_cross_bound(
    tmp_path: Path,
    verify_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = tmp_path / "libproof.rlib"
    archive.write_bytes(b"archive")
    absolute = "/host/toolchain/lib/libproof.rlib(member.o)"
    relative = "libproof.rlib(member.o)"
    layout = {
        "archive_member_owners": [absolute],
        "cache_gate_input_sections": [{"owner": absolute}],
        "kernels": {"kernel": {"input_owner": absolute}},
    }
    proof = {"archive_member_owners": [relative]}
    called: list[tuple[Path, str]] = []
    monkeypatch.setattr(
        verify_module,
        "validate_rlib_member",
        lambda path, member: called.append((path, member)),
    )
    verify_module.validate_manifest_rlib_occurrences(
        layout,
        proof,
        lambda raw: (
            archive
            if raw
            in {
                "/host/toolchain/lib/libproof.rlib",
                "libproof.rlib",
            }
            else None
        ),
    )
    assert called == [(archive, "member.o")] * 4
