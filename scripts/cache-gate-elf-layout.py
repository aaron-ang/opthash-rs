#!/usr/bin/env python3
"""Validate and compare cache-gate ELF reservations without mutating binaries."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


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
    if digest(path) != record.get("sha256"):
        raise LayoutError(f"{label} hash mismatch: {path}")
    return path.resolve()


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
            segments.append(
                {
                    "offset": int(match.group("offset"), 16),
                    "vaddr": int(match.group("vaddr"), 16),
                    "filesz": int(match.group("filesz"), 16),
                    "memsz": int(match.group("memsz"), 16),
                    "flags": " ".join(match.group("flags").split()),
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


def _load_capability() -> dict[str, Any]:
    path = os.environ.get("CACHE_GATE_LINKER_CAPABILITY")
    if not path:
        raise LayoutError("CACHE_GATE_LINKER_CAPABILITY is required for validate")
    capability_path = Path(path)
    if not capability_path.is_absolute() or not capability_path.is_file():
        raise LayoutError("CACHE_GATE_LINKER_CAPABILITY must be an absolute file")
    return json.loads(capability_path.read_text())


def validate_elf(args: argparse.Namespace) -> dict[str, Any]:
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
    capability = _load_capability()
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
    header = run("readelf", "-hW", str(binary))
    section_text = run("readelf", "-SW", str(binary))
    segment_text = run("readelf", "-lW", str(binary))
    symbol_text = run("readelf", "-sW", str(binary))
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


def _linker_version(driver: Path) -> str:
    output = run(str(driver), "-Wl,--version")
    return next(
        (
            line.strip()
            for line in output.splitlines()
            if "GNU ld" in line or "LLD" in line or "lld" in line
        ),
        "",
    )


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
        (args.capability, "capability"),
        (args.fragment, "fragment"),
        (args.link_map, "link map"),
    ):
        _require(path.is_absolute(), f"--{label.replace(' ', '-')} must be absolute")
        _require(path.is_file() and not path.is_symlink(), f"invalid {label}: {path}")
    capability = json.loads(args.capability.read_text())
    linker = capability.get("linker", {})
    configured_driver = Path(linker.get("absolute_path", ""))
    _require(
        configured_driver.is_absolute() and configured_driver.is_file(),
        "capability linker driver is invalid",
    )
    configured_driver = configured_driver.resolve()
    _require(
        _linker_version(configured_driver) == linker.get("version"),
        "capability linker version no longer matches actual driver",
    )
    records = [
        json.loads(line) for line in args.trace.read_text().splitlines() if line.strip()
    ]

    def output_path(argv: list[str]) -> Path | None:
        for index, token in enumerate(argv[:-1]):
            if token == "-o":
                return Path(argv[index + 1]).resolve()
        return None

    executable = args.executable.resolve()
    matches = [
        record
        for record in records
        if output_path(record.get("argv", [])) == executable
    ]
    _require(
        len(matches) == 1,
        f"expected one captured final link command, got {len(matches)}",
    )
    record = matches[0]
    driver = Path(record.get("driver", ""))
    _require(
        driver.is_absolute() and driver.resolve() == configured_driver,
        "captured link driver differs from capability",
    )
    _require(
        record.get("driver_sha256") == digest(configured_driver),
        "captured link driver hash differs from capability driver bytes",
    )
    argv = record.get("argv", [])
    _require(
        isinstance(argv, list) and all(isinstance(token, str) for token in argv),
        "captured final link argv is invalid",
    )
    selectors = (
        "-fuse-ld",
        "-B",
        "--ld-path",
        "-Wl,--ld-path",
    )
    _require(
        not any(token.startswith(selectors) for token in argv),
        "captured link command contains unprobed linker-selection arguments",
    )
    fragment_flag = f"-Wl,-T,{args.fragment.resolve()}"
    map_flag = f"-Wl,-Map,{args.link_map.resolve()}"
    _require(fragment_flag in argv, "captured link command lacks exact fragment")
    _require(map_flag in argv, "captured link command lacks exact map path")
    ordered_inputs, direct_files = _link_command_inputs(argv)
    return {
        "driver": {
            "absolute_path": str(configured_driver),
            "sha256": digest(configured_driver),
            "flavor": linker.get("flavor"),
            "version": linker.get("version"),
        },
        "argv": argv,
        "ordered_linker_inputs": ordered_inputs,
        "ordered_linker_input_fingerprint": hashlib.sha256(
            ("\n".join(ordered_inputs) + "\n").encode()
        ).hexdigest(),
        "direct_input_files": direct_files,
        "direct_cgu_members": sorted(
            value for value in direct_files if ".rcgu.o" in value
        ),
        "trace": {
            "absolute_path": str(args.trace.resolve()),
            "sha256": digest(args.trace),
            "record_count": len(records),
            "final_link_record_count": len(matches),
        },
        "executable": str(executable),
        "fragment": str(args.fragment.resolve()),
        "link_map": str(args.link_map.resolve()),
    }


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
    tools_parser = subparsers.add_parser("authenticate-tools")
    tools_parser.add_argument("--output", type=Path, required=True)
    tools_parser.add_argument("--tool", action="append", required=True)
    link_parser = subparsers.add_parser("validate-link-command")
    link_parser.add_argument("--trace", type=Path, required=True)
    link_parser.add_argument("--executable", type=Path, required=True)
    link_parser.add_argument("--capability", type=Path, required=True)
    link_parser.add_argument("--fragment", type=Path, required=True)
    link_parser.add_argument("--link-map", type=Path, required=True)
    link_parser.add_argument("--output", type=Path, required=True)
    cargo_parser = subparsers.add_parser("select-cargo-executable")
    cargo_parser.add_argument("--cargo-output", type=Path, required=True)
    cargo_parser.add_argument("--bench", required=True)
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
        elif args.command == "authenticate-tools":
            if not args.output.is_absolute():
                raise LayoutError("--output must be absolute")
            _write_json_atomic(args.output, authenticate_tools(args))
        elif args.command == "validate-link-command":
            if not args.output.is_absolute():
                raise LayoutError("--output must be absolute")
            _write_json_atomic(args.output, validate_link_command(args))
        else:
            print(select_cargo_executable(args))
    except (KeyError, OSError, json.JSONDecodeError, LayoutError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
