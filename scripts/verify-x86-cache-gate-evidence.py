#!/usr/bin/env python3
"""Safely verify a portable native x86-64 cache-gate evidence archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
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
SEMANTIC_ROOTS = (*REQUIRED_ROOTS, "cargo-registry")
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
SUBJECT_COMMIT = "061d13da22b89208c801308efd578444c8e9caba"
SUBJECT_TREE = "24921a941f8c3c26467465b99d6b45ee5912b2da"
V1_REPLAY_COMMIT = "b0d53234dc051af91fe0321450b3e8312a84e635"
V1_REPLAY_TREE = "d77cc082fe48799f26ff4440bd1898a71d0dc8cc"
X86_TARGET_TRIPLE = "x86_64-unknown-linux-gnu"
PINNED_CARGO_VERSION = "cargo 1.95.0 (f2d3ce0bd 2026-03-21)"
PINNED_RUST_TOOLCHAIN = "1.95.0-x86_64-unknown-linux-gnu"
PINNED_RUSTC_VERSION = (
    "rustc 1.95.0 (59807616e 2026-04-14)\n"
    "binary: rustc\n"
    "commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860\n"
    "commit-date: 2026-04-14\n"
    f"host: {X86_TARGET_TRIPLE}\n"
    "release: 1.95.0\n"
    "LLVM version: 22.1.2"
)
EXPECTED_GITHUB_REF = "refs/heads/ci/x86-cache-gate-evidence"
ORCHESTRATION_SOURCE_PATHS = {
    "workflow": "bundle/orchestrator/.github/workflows/x86-cache-gate-evidence.yml",
    "runner": "bundle/orchestrator/scripts/run-x86-cache-gate-evidence.sh",
    "packager": "bundle/orchestrator/scripts/package-x86-cache-gate-evidence.py",
    "verifier": "bundle/orchestrator/scripts/verify-x86-cache-gate-evidence.py",
}
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
KERNEL_LAYOUT_SPECS = {
    "elastic_cache_gate_insert_kernel": {
        "input": ".text.opthash.cache_gate.elastic.insert",
        "output": ".opthash.cache_gate.elastic.insert",
    },
    "elastic_cache_gate_get_kernel": {
        "input": ".text.opthash.cache_gate.elastic.get",
        "output": ".opthash.cache_gate.elastic.get",
    },
    "funnel_cache_gate_insert_kernel": {
        "input": ".text.opthash.cache_gate.funnel.insert",
        "output": ".opthash.cache_gate.funnel.insert",
    },
    "funnel_cache_gate_get_kernel": {
        "input": ".text.opthash.cache_gate.funnel.get",
        "output": ".opthash.cache_gate.funnel.get",
    },
    "elastic_profile_insert_kernel": {
        "input": ".text.opthash.cache_gate.profile.elastic.insert",
        "output": ".opthash.cache_gate.profile.elastic.insert",
    },
    "elastic_profile_get_kernel": {
        "input": ".text.opthash.cache_gate.profile.elastic.get",
        "output": ".opthash.cache_gate.profile.elastic.get",
    },
    "funnel_profile_insert_kernel": {
        "input": ".text.opthash.cache_gate.profile.funnel.insert",
        "output": ".opthash.cache_gate.profile.funnel.insert",
    },
    "funnel_profile_get_kernel": {
        "input": ".text.opthash.cache_gate.profile.funnel.get",
        "output": ".opthash.cache_gate.profile.funnel.get",
    },
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
LAYOUT_BODY_FIELDS = (
    "body_end",
    "body_size",
    "raw_sha256",
    "normalized_sha256",
    "direct_calls",
    "indirect_calls",
    "frame_bytes",
    "spills",
)
SENTINEL_FIELDS = ("reservation_start", "body_end", "reservation_end")


class ListSchema(NamedTuple):
    item: object
    nonempty: bool = False


class LiteralSchema(NamedTuple):
    value: object


class NullableSchema(NamedTuple):
    item: object


STRING = str
INTEGER = int
BOOLEAN = bool
STRING_LIST = ListSchema(STRING)
FILE_RECORD_SCHEMA = {"absolute_path": STRING, "sha256": STRING}
TRACE_RECORD_SCHEMA = {
    "absolute_path": STRING,
    "sha256": STRING,
    "record_count": INTEGER,
    "final_link_record_count": INTEGER,
}
BODY_SCHEMA = {
    "size": INTEGER,
    "normalized_instructions_sha256": STRING,
    "direct_calls": STRING_LIST,
    "indirect_calls": STRING_LIST,
    "frame_adjustment": INTEGER,
    "spills": STRING_LIST,
}

EXECUTABLE_TARGETS = {
    "elastic_cache_gate": (
        "elastic",
        ("elastic_cache_gate_insert_kernel", "elastic_cache_gate_get_kernel"),
    ),
    "funnel_cache_gate": (
        "funnel",
        ("funnel_cache_gate_insert_kernel", "funnel_cache_gate_get_kernel"),
    ),
    "cache_gate_profile": (
        "profile",
        (
            "elastic_profile_insert_kernel",
            "elastic_profile_get_kernel",
            "funnel_profile_insert_kernel",
            "funnel_profile_get_kernel",
        ),
    ),
}

LINKER_CHAIN_ITEM_SCHEMA = {
    "absolute_path": STRING,
    "symlink_target": NullableSchema(STRING),
}
LINKER_RECORD_SCHEMA = {
    "invocation_path": STRING,
    "invocation_chain": ListSchema(LINKER_CHAIN_ITEM_SCHEMA, nonempty=True),
    "payload_path": STRING,
    "payload_sha256": STRING,
    "argv0": STRING,
    "extraction_root": NullableSchema(STRING),
    "flavor": STRING,
    "version_argument": STRING,
    "version": STRING,
}
CAPABILITY_PRODUCER_SCHEMA = {
    "runner_root": STRING,
    "commit": STRING,
    "tree": STRING,
    "empty_diff_assertion": BOOLEAN,
    "artifact_root": STRING,
}
ACTUAL_SHAPE_SCHEMA = {
    "binary": FILE_RECORD_SCHEMA,
    "symbols": FILE_RECORD_SCHEMA,
    "layout": FILE_RECORD_SCHEMA,
    "link_map": FILE_RECORD_SCHEMA,
    "link_argv": FILE_RECORD_SCHEMA,
    "linker_execution": FILE_RECORD_SCHEMA,
}
EXPLICIT_SHAPE_SCHEMA = {
    **ACTUAL_SHAPE_SCHEMA,
    "cargo_execution": FILE_RECORD_SCHEMA,
}
CAPABILITY_BASE_SCHEMA = {
    "accepted": BOOLEAN,
    "arch": STRING,
    "target_triple": STRING,
    "rustc_version": STRING,
    "cargo_version": STRING,
    "producer": CAPABILITY_PRODUCER_SCHEMA,
    "linker": LINKER_RECORD_SCHEMA,
    "required_linkers": {
        "gnu": LINKER_RECORD_SCHEMA,
        "lld": LINKER_RECORD_SCHEMA,
    },
    "max_page_size": INTEGER,
    "fragments": {
        "elastic": FILE_RECORD_SCHEMA,
        "funnel": FILE_RECORD_SCHEMA,
        "profile": FILE_RECORD_SCHEMA,
    },
    "fragment_set_sha256": STRING,
    "shapes": {
        "actual": {
            "elastic": ACTUAL_SHAPE_SCHEMA,
            "funnel": ACTUAL_SHAPE_SCHEMA,
            "profile": ACTUAL_SHAPE_SCHEMA,
        },
        "gnu": {
            "elastic": EXPLICIT_SHAPE_SCHEMA,
            "funnel": EXPLICIT_SHAPE_SCHEMA,
            "profile": EXPLICIT_SHAPE_SCHEMA,
        },
        "lld": {
            "elastic": EXPLICIT_SHAPE_SCHEMA,
            "funnel": EXPLICIT_SHAPE_SCHEMA,
            "profile": EXPLICIT_SHAPE_SCHEMA,
        },
    },
}
CAPABILITY_SCHEMA = {
    **CAPABILITY_BASE_SCHEMA,
}

CONTROL_INPUTS_SCHEMA = {
    "cargo_manifest": FILE_RECORD_SCHEMA,
    "cargo_lock": FILE_RECORD_SCHEMA,
    "source": FILE_RECORD_SCHEMA,
}
CONTROL_V2_SCHEMA = {
    "mode": STRING,
    "runner_root": STRING,
    "runner_commit": STRING,
    "runner_tree": STRING,
    "builder_commit": STRING,
    "builder_tree": STRING,
    "locked": BOOLEAN,
    "cargo_version": STRING,
    "rustc_version": STRING,
    "binary": FILE_RECORD_SCHEMA,
    "inputs": CONTROL_INPUTS_SCHEMA,
    "provenance_path": STRING,
    "provenance_sha256": STRING,
}
CONTROL_V1_SCHEMA = {
    "builder_commit": STRING,
    "builder_tree": STRING,
    "locked": BOOLEAN,
    "cargo_version": STRING,
    "rustc_version": STRING,
    "binary": FILE_RECORD_SCHEMA,
    "inputs": CONTROL_INPUTS_SCHEMA,
    "provenance_path": STRING,
    "provenance_sha256": STRING,
}
TOOL_RECORD_SCHEMA = {
    "absolute_path": STRING,
    "sha256": STRING,
    "git_blob": STRING,
    "git_blob_sha256": STRING,
    "reviewed_root": STRING,
    "reviewed_commit": STRING,
    "reviewed_tree": STRING,
}
TOOLS_SCHEMA = {
    "elf_layout": TOOL_RECORD_SCHEMA,
    "extractor": TOOL_RECORD_SCHEMA,
    "launcher": TOOL_RECORD_SCHEMA,
    "link_wrapper": TOOL_RECORD_SCHEMA,
    "perf_launcher": TOOL_RECORD_SCHEMA,
    "perf_support": TOOL_RECORD_SCHEMA,
    "snapshot": TOOL_RECORD_SCHEMA,
}
SYMBOL_BASE_SCHEMA = {
    "name": STRING,
    "start": INTEGER,
    "end": INTEGER,
    "size": INTEGER,
    "kind": STRING,
    "pattern": STRING,
    "section": STRING,
    "file_offset": INTEGER,
    "page_offset": INTEGER,
    "raw_sha256": STRING,
    "normalized_instructions_sha256": STRING,
    "normalized_instructions": STRING_LIST,
    "direct_calls": STRING_LIST,
    "indirect_calls": STRING_LIST,
    "frame_adjustment": INTEGER,
    "spills": STRING_LIST,
}
SYMBOL_V2_SCHEMA = {
    **SYMBOL_BASE_SCHEMA,
    "section_index": INTEGER,
    "section_name": STRING,
    "section_alignment": INTEGER,
}
SYMBOL_V1_SCHEMA = {
    **SYMBOL_BASE_SCHEMA,
    "declared_alignment": INTEGER,
}
LINKER_GENERATED_SYMBOL_SCHEMA = {
    "start": INTEGER,
    "end": INTEGER,
    "size": INTEGER,
    "kind": STRING,
    "name": STRING,
}


def _symbol_document_schema(
    symbol_schema: object, *, veneers: bool
) -> dict[str, object]:
    result: dict[str, object] = {
        "binary": STRING,
        "binary_sha256": STRING,
        "architecture": STRING,
        "symbols": ListSchema(symbol_schema, nonempty=True),
    }
    if veneers:
        result["linker_generated_veneer_thunks"] = ListSchema(
            LINKER_GENERATED_SYMBOL_SCHEMA
        )
    return result


SENTINEL_SCHEMA = {
    "name": STRING,
    "address": INTEGER,
    "binding": STRING,
    "visibility": STRING,
    "defined": BOOLEAN,
    "count": INTEGER,
}
KERNEL_LAYOUT_SCHEMA = {
    "name": STRING,
    "function_symbol_count": INTEGER,
    "input_section": STRING,
    "input_section_count": INTEGER,
    "input_owner": STRING,
    "input_start": INTEGER,
    "input_end": INTEGER,
    "input_size": INTEGER,
    "output_section": STRING,
    "output_section_count": INTEGER,
    "output_section_index": INTEGER,
    "output_start": INTEGER,
    "output_end": INTEGER,
    "reservation_start": INTEGER,
    "body_end": INTEGER,
    "reservation_end": INTEGER,
    "body_size": INTEGER,
    "reservation_size": INTEGER,
    "page_offset": INTEGER,
    "max_page_remainder": INTEGER,
    "sh_addralign": INTEGER,
    "section_flags": STRING_LIST,
    "pt_load_count": INTEGER,
    "pt_load_flags": STRING,
    "writable_segment_overlap": BOOLEAN,
    "overlapping_elf_sections": STRING_LIST,
    "sentinels": {
        "reservation_start": SENTINEL_SCHEMA,
        "body_end": SENTINEL_SCHEMA,
        "reservation_end": SENTINEL_SCHEMA,
    },
    "link_map_sentinels": {
        "reservation_start": INTEGER,
        "body_end": INTEGER,
        "reservation_end": INTEGER,
    },
    "function_start": INTEGER,
    "function_end": INTEGER,
    "function_size": INTEGER,
    "function_section_index": INTEGER,
    "function_section_name": STRING,
    "raw_sha256": STRING,
    "normalized_sha256": STRING,
    "direct_calls": STRING_LIST,
    "indirect_calls": STRING_LIST,
    "frame_bytes": INTEGER,
    "spills": STRING_LIST,
    "veneer_thunks": STRING_LIST,
    "plt_calls": STRING_LIST,
}
PROGRAM_HEADER_SCHEMA = {
    "offset": INTEGER,
    "vaddr": INTEGER,
    "filesz": INTEGER,
    "memsz": INTEGER,
    "flags": STRING,
    "alignment": INTEGER,
}
INPUT_SECTION_SCHEMA = {
    "owner": STRING,
    "section": STRING,
    "output": STRING,
    "start": INTEGER,
    "end": INTEGER,
    "size": INTEGER,
}


def _layout_schema(kernel_names: tuple[str, ...]) -> dict[str, object]:
    return {
        "target": STRING,
        "arch": STRING,
        "link_map_flavor": STRING,
        "elf_type": STRING,
        "binary": STRING,
        "binary_sha256": STRING,
        "link_map": STRING,
        "link_map_sha256": STRING,
        "fragment_sha256": STRING,
        "fragment_set_sha256": STRING,
        "max_page_size": INTEGER,
        "program_headers_have_rwx": BOOLEAN,
        "program_headers": ListSchema(PROGRAM_HEADER_SCHEMA, nonempty=True),
        "archive_member_owners": STRING_LIST,
        "cache_gate_input_sections": ListSchema(INPUT_SECTION_SCHEMA, nonempty=True),
        "kernels": {name: KERNEL_LAYOUT_SCHEMA for name in kernel_names},
        "veneer_thunk_inventory": ListSchema(LINKER_GENERATED_SYMBOL_SCHEMA),
        "plt_inventory": STRING_LIST,
    }


EXECUTABLE_RECORD_SCHEMA = {
    "absolute_path": STRING,
    "sha256": STRING,
    "link_map": FILE_RECORD_SCHEMA,
    "symbols": FILE_RECORD_SCHEMA,
    "layout": FILE_RECORD_SCHEMA,
    "link_command": FILE_RECORD_SCHEMA,
    "link_trace": FILE_RECORD_SCHEMA,
    "linker_fragment": FILE_RECORD_SCHEMA,
}
ADVERSARY_SYMBOL_SCHEMA = {"name": STRING, "start": INTEGER, "size": INTEGER}
ADVERSARY_RECORD_SCHEMA = {
    "symbol_occurrences": ListSchema(ADVERSARY_SYMBOL_SCHEMA),
    "input_section_occurrences": INTEGER,
    "outside_reservations": BOOLEAN,
}
LINK_COMMAND_SCHEMA = {
    "driver": LINKER_RECORD_SCHEMA,
    "argv": ListSchema(STRING, nonempty=True),
    "ordered_linker_inputs": STRING_LIST,
    "ordered_linker_input_fingerprint": STRING,
    "direct_input_files": STRING_LIST,
    "direct_cgu_members": STRING_LIST,
    "trace": TRACE_RECORD_SCHEMA,
    "executable": STRING,
    "fragment": STRING,
    "link_map": STRING,
}
BUILD_PROOF_EXECUTABLE_SCHEMA = {
    "rustc_argv": ListSchema(STRING, nonempty=True),
    "emitted_object_members": STRING_LIST,
    "ordered_linker_inputs": STRING_LIST,
    "direct_linker_input_files": STRING_LIST,
    "archive_member_owners": STRING_LIST,
    "cgu_members": STRING_LIST,
    "object_member_fingerprint": STRING,
    "link_order_fingerprint": STRING,
    "cgu_partition_fingerprint": STRING,
    "reserved_input_owners": STRING_LIST,
    "reserved_input_owner_fingerprint": STRING,
    "link_command": LINK_COMMAND_SCHEMA,
    "adversary": ADVERSARY_RECORD_SCHEMA,
}
BUILD_PROOF_SCHEMA = {
    "codegen_units": INTEGER,
    "executables": {name: BUILD_PROOF_EXECUTABLE_SCHEMA for name in EXECUTABLE_TARGETS},
    "object_member_fingerprint": STRING,
    "link_order_fingerprint": STRING,
    "cgu_partition_fingerprint": STRING,
    "reserved_input_owner_fingerprint": STRING,
}
MANIFEST_V2_SCHEMA = {
    "commit": STRING,
    "tree": STRING,
    "empty_diff_assertion": BOOLEAN,
    "mode": STRING,
    "architecture": STRING,
    "variant": STRING,
    "manifest_instance": STRING,
    "runner_root": STRING,
    "build": {
        "cargo_incremental": STRING,
        "profile": STRING,
        "locked": BOOLEAN,
        "codegen_units": INTEGER,
        "rustc_flags": STRING_LIST,
        "linker_flags": STRING_LIST,
    },
    "control": CONTROL_V2_SCHEMA,
    "tools": TOOLS_SCHEMA,
    "linker_capability": {**CAPABILITY_BASE_SCHEMA, "copy": FILE_RECORD_SCHEMA},
    "executables": {name: EXECUTABLE_RECORD_SCHEMA for name in EXECUTABLE_TARGETS},
    "symbols": {
        name: _symbol_document_schema(SYMBOL_V2_SCHEMA, veneers=True)
        for name in EXECUTABLE_TARGETS
    },
    "elf_layout": {
        name: _layout_schema(kernel_names)
        for name, (_target, kernel_names) in EXECUTABLE_TARGETS.items()
    },
    "build_proof": BUILD_PROOF_SCHEMA,
    "layout_adversary": {
        "enabled": BOOLEAN,
        "symbol": STRING,
        "input_section": STRING,
    },
}
MANIFEST_V1_SCHEMA = {
    "commit": STRING,
    "tree": STRING,
    "empty_diff_assertion": BOOLEAN,
    "architecture": STRING,
    "variant": STRING,
    "build": {
        "cargo_incremental": STRING,
        "profile": STRING,
        "locked": BOOLEAN,
        "rustc_flags": STRING_LIST,
        "linker_flags": STRING_LIST,
    },
    "control": CONTROL_V1_SCHEMA,
    "executables": {
        name: {
            "absolute_path": STRING,
            "sha256": STRING,
            "link_map": FILE_RECORD_SCHEMA,
        }
        for name in EXECUTABLE_TARGETS
    },
    "symbols": {
        name: _symbol_document_schema(SYMBOL_V1_SCHEMA, veneers=False)
        for name in EXECUTABLE_TARGETS
    },
}
DOCUMENT_RECORD_SCHEMA = {"archive_path": STRING, "sha256": STRING}
ROOT_RECORD_SCHEMA = {"name": STRING, "hosted": STRING, "archive": STRING}
SYSTEM_LINK_SCHEMA = {"source": STRING, "raw_target": STRING}
PROVENANCE_SCHEMA = {
    "version": INTEGER,
    "subject": {"commit": STRING, "tree": STRING},
    "v1": {"commit": STRING, "tree": STRING},
    "orchestration": {
        "commit": STRING,
        "tree": STRING,
        "sources": {
            name: DOCUMENT_RECORD_SCHEMA for name in ORCHESTRATION_SOURCE_PATHS
        },
    },
    "run": {"id": INTEGER, "attempt": INTEGER, "derived_attempt": INTEGER},
    "github": {
        "repository": STRING,
        "ref": STRING,
        "sha": STRING,
        "run_id": INTEGER,
        "run_attempt": INTEGER,
    },
    "rust": {
        "toolchain": STRING,
        "rustc_version": STRING,
        "cargo_version": STRING,
    },
    "packages": ListSchema(
        {
            "name": STRING,
            "architecture": STRING,
            "version": STRING,
            "verification_status": INTEGER,
        },
        nonempty=True,
    ),
    "roots": ListSchema(ROOT_RECORD_SCHEMA, nonempty=True),
    "system_links": ListSchema(SYSTEM_LINK_SCHEMA),
    "proof": {"status": INTEGER, "result": STRING},
    "documents": {
        "capability": DOCUMENT_RECORD_SCHEMA,
        "manifests": {
            "clean_a": DOCUMENT_RECORD_SCHEMA,
            "clean_b": DOCUMENT_RECORD_SCHEMA,
            "adversary": DOCUMENT_RECORD_SCHEMA,
        },
        "v1_manifest": DOCUMENT_RECORD_SCHEMA,
        "v1_reextractions": {
            name: DOCUMENT_RECORD_SCHEMA for name in EXECUTABLE_TARGETS
        },
        "transcripts": ListSchema(DOCUMENT_RECORD_SCHEMA, nonempty=True),
        "body_comparison": DOCUMENT_RECORD_SCHEMA,
        "portable_paths": DOCUMENT_RECORD_SCHEMA,
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
    "manifest_variant": STRING,
    "executable": STRING,
    "trace": TRACE_RECORD_SCHEMA,
    "argv": ListSchema(STRING, nonempty=True),
    "argv0": STRING,
    "cwd": STRING,
    "path": STRING,
    "payload_path": STRING,
    "payload_sha256": STRING,
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
    "roots": ListSchema(ROOT_RECORD_SCHEMA, nonempty=True),
    "system_links": ListSchema(SYSTEM_LINK_SCHEMA),
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
    "v1_reextraction": _symbol_document_schema(SYMBOL_V2_SCHEMA, veneers=True),
    "provenance": PROVENANCE_SCHEMA,
    "transcript": TRANSCRIPT_SCHEMA,
    "body_comparison": BODY_COMPARISON_SCHEMA,
    "portable_paths": PORTABLE_PATHS_SCHEMA,
}

# Closed routing table. Patterns contain literal ``*`` for array elements.
PATH_ROUTES: dict[tuple[str, ...], str] = {
    ("manifest", "runner_root"): "root",
    ("manifest", "build", "rustc_flags"): "rustc-options",
    ("manifest", "build", "linker_flags"): "linker-template",
    # Stable classifier examples retained by the versioned routing interface.
    ("manifest", "environment", "PATH"): "path-list",
    ("manifest", "executables", "*", "rustc_argv"): "rustc-command",
    ("manifest", "control", "runner_root"): "root",
    ("manifest", "control", "binary", "absolute_path"): "hashed-file",
    ("manifest", "control", "inputs", "*", "absolute_path"): "hashed-file",
    ("manifest", "control", "provenance_path"): "hashed-file-pair",
    ("manifest", "tools", "*", "absolute_path"): "hashed-file",
    ("manifest", "tools", "*", "reviewed_root"): "root",
    ("v1-manifest", "executables", "*", "absolute_path"): "hashed-file",
    ("v1-manifest", "build", "rustc_flags"): "rustc-options-template",
    ("v1-manifest", "build", "linker_flags"): "linker-template",
    ("v1-manifest", "executables", "*", "link_map", "absolute_path"): "hashed-file",
    ("v1-manifest", "control", "binary", "absolute_path"): "hashed-file",
    ("v1-manifest", "control", "inputs", "*", "absolute_path"): "hashed-file",
    ("v1-manifest", "control", "provenance_path"): "hashed-file-pair",
    ("v1-manifest", "symbols", "*", "binary"): "duplicate-file",
    ("v1-reextraction", "binary"): "duplicate-file",
    ("capability", "producer", "runner_root"): "root",
    ("capability", "producer", "artifact_root"): "root",
    ("capability", "fragments", "*", "absolute_path"): "hashed-file",
    ("capability", "shapes", "*", "*", "*", "absolute_path"): "hashed-file",
    ("capability", "linker", "invocation_path"): "system-file",
    ("capability", "linker", "invocation_chain", "*", "absolute_path"): "system-file",
    ("capability", "linker", "payload_path"): "system-hashed-file",
    ("capability", "linker", "argv0"): "system-file",
    ("capability", "linker", "extraction_root"): "nullable-root",
    ("capability", "required_linkers", "*", "invocation_path"): "system-file",
    (
        "capability",
        "required_linkers",
        "*",
        "invocation_chain",
        "*",
        "absolute_path",
    ): "system-file",
    ("capability", "required_linkers", "*", "payload_path"): "system-hashed-file",
    ("capability", "required_linkers", "*", "argv0"): "system-file",
    ("capability", "required_linkers", "*", "extraction_root"): "nullable-root",
    ("manifest", "executables", "*", "absolute_path"): "hashed-file",
    ("manifest", "executables", "*", "*", "absolute_path"): "hashed-file",
    ("manifest", "symbols", "*", "binary"): "duplicate-file",
    ("manifest", "elf_layout", "*", "binary"): "duplicate-file",
    ("manifest", "elf_layout", "*", "link_map"): "duplicate-file",
    (
        "manifest",
        "elf_layout",
        "*",
        "archive_member_owners",
        "*",
    ): "rlib-member",
    (
        "manifest",
        "elf_layout",
        "*",
        "cache_gate_input_sections",
        "*",
        "owner",
    ): "transient-file",
    (
        "manifest",
        "elf_layout",
        "*",
        "kernels",
        "*",
        "input_owner",
    ): "transient-file",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "rustc_argv",
        "*",
    ): "rustc-command",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "emitted_object_members",
        "*",
    ): "semantic-file",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "ordered_linker_inputs",
        "*",
    ): "semantic-file",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "direct_linker_input_files",
        "*",
    ): "semantic-file",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "archive_member_owners",
        "*",
    ): "semantic-rlib-member",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "cgu_members",
        "*",
    ): "semantic-file",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "reserved_input_owners",
        "*",
    ): "semantic-file",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "link_command",
        "argv",
    ): "linker-command",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "link_command",
        "ordered_linker_inputs",
        "*",
    ): "semantic-file",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "link_command",
        "direct_input_files",
        "*",
    ): "semantic-file",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "link_command",
        "direct_cgu_members",
        "*",
    ): "semantic-file",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "link_command",
        "driver",
        "invocation_path",
    ): "system-file",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "link_command",
        "driver",
        "invocation_chain",
        "*",
        "absolute_path",
    ): "system-file",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "link_command",
        "driver",
        "payload_path",
    ): "system-hashed-file",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "link_command",
        "driver",
        "argv0",
    ): "system-file",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "link_command",
        "driver",
        "extraction_root",
    ): "nullable-root",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "link_command",
        "trace",
        "absolute_path",
    ): "hashed-file",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "link_command",
        "executable",
    ): "duplicate-file",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "link_command",
        "fragment",
    ): "duplicate-file",
    (
        "manifest",
        "build_proof",
        "executables",
        "*",
        "link_command",
        "link_map",
    ): "duplicate-file",
    ("manifest", "linker_capability", "copy", "absolute_path"): "hashed-file",
    ("manifest", "linker_capability", "producer", "runner_root"): "root",
    ("manifest", "linker_capability", "producer", "artifact_root"): "root",
    ("manifest", "linker_capability", "linker", "invocation_path"): "system-file",
    (
        "manifest",
        "linker_capability",
        "linker",
        "invocation_chain",
        "*",
        "absolute_path",
    ): "system-file",
    ("manifest", "linker_capability", "linker", "payload_path"): "system-hashed-file",
    ("manifest", "linker_capability", "linker", "argv0"): "system-file",
    ("manifest", "linker_capability", "linker", "extraction_root"): "nullable-root",
    (
        "manifest",
        "linker_capability",
        "required_linkers",
        "*",
        "invocation_path",
    ): "system-file",
    (
        "manifest",
        "linker_capability",
        "required_linkers",
        "*",
        "invocation_chain",
        "*",
        "absolute_path",
    ): "system-file",
    (
        "manifest",
        "linker_capability",
        "required_linkers",
        "*",
        "payload_path",
    ): "system-hashed-file",
    (
        "manifest",
        "linker_capability",
        "required_linkers",
        "*",
        "argv0",
    ): "system-file",
    (
        "manifest",
        "linker_capability",
        "required_linkers",
        "*",
        "extraction_root",
    ): "nullable-root",
    ("manifest", "linker_capability", "fragments", "*", "absolute_path"): "hashed-file",
    (
        "manifest",
        "linker_capability",
        "shapes",
        "*",
        "*",
        "*",
        "absolute_path",
    ): "hashed-file",
    ("provenance", "documents", "capability", "archive_path"): "archive-file",
    (
        "provenance",
        "documents",
        "manifests",
        "*",
        "archive_path",
    ): "archive-file",
    ("provenance", "documents", "v1_manifest", "archive_path"): "archive-file",
    (
        "provenance",
        "documents",
        "v1_reextractions",
        "*",
        "archive_path",
    ): "archive-file",
    (
        "provenance",
        "documents",
        "transcripts",
        "*",
        "archive_path",
    ): "archive-file",
    (
        "provenance",
        "documents",
        "body_comparison",
        "archive_path",
    ): "archive-file",
    (
        "provenance",
        "documents",
        "portable_paths",
        "archive_path",
    ): "archive-file",
    (
        "provenance",
        "orchestration",
        "sources",
        "*",
        "archive_path",
    ): "archive-file",
    ("provenance", "roots", "*", "hosted"): "root-definition",
    ("provenance", "roots", "*", "archive"): "archive-root",
    ("provenance", "system_links", "*", "source"): "system-link-source",
    ("provenance", "system_links", "*", "raw_target"): "system-link-target",
    ("provenance", "hardlinks", "*", "path"): "archive-member",
    ("provenance", "hardlinks", "*", "target"): "archive-member",
    ("inventory", "entries", "*", "path"): "archive-member",
    ("transcript", "argv"): "linker-command",
    ("transcript", "argv0"): "system-file",
    ("transcript", "cwd"): "transient-directory",
    ("transcript", "path"): "path-list",
    ("transcript", "payload_path"): "system-hashed-file",
    ("transcript", "trace", "absolute_path"): "hashed-file",
    ("transcript", "ordered_inputs", "*"): "semantic-file",
    ("portable-paths", "roots", "*", "hosted"): "root-definition",
    ("portable-paths", "roots", "*", "archive"): "archive-root",
    ("portable-paths", "system_links", "*", "source"): "system-link-source",
    ("portable-paths", "system_links", "*", "raw_target"): "system-link-target",
}
ROUTE_COMPATIBILITY_ALIASES = {
    ("manifest", "environment", "PATH"),
    ("manifest", "executables", "*", "rustc_argv"),
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


class RlibArchive(NamedTuple):
    path: PurePosixPath
    data: bytes


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
    if result is None:
        matches = {
            field_kind
            for pattern, field_kind in PATH_ROUTES.items()
            if len(pattern) == len(normalized)
            and all(
                expected == "*" or expected == observed
                for expected, observed in zip(pattern, normalized, strict=True)
            )
        }
        _require(len(matches) <= 1, f"ambiguous path field: {'.'.join(normalized)}")
        result = next(iter(matches), None)
    _require(result is not None, f"unclassified path field: {'.'.join(normalized)}")
    return result


def collect_concrete_routes(
    document_kind: str, document: object
) -> list[tuple[tuple[str | int, ...], str, object]]:
    """Expand every declared route against a concrete, schema-checked document."""

    collected: list[tuple[tuple[str | int, ...], str, object]] = []

    def can_follow(value: object, pattern: tuple[str, ...]) -> bool:
        if not pattern:
            return True
        head, *tail = pattern
        if head == "*":
            children = value.values() if isinstance(value, dict) else value
            return isinstance(value, (dict, list)) and any(
                can_follow(child, tuple(tail)) for child in children
            )
        return (
            isinstance(value, dict)
            and head in value
            and can_follow(value[head], tuple(tail))
        )

    def expand(
        value: object,
        pattern: tuple[str, ...],
        concrete: tuple[str | int, ...],
    ) -> None:
        if not pattern:
            normalized = tuple(
                "*" if isinstance(part, int) else part for part in concrete
            )
            collected.append((concrete, classify(normalized), value))
            return
        head, *tail = pattern
        if head == "*":
            if isinstance(value, dict):
                for key, child in value.items():
                    if can_follow(child, tuple(tail)):
                        expand(child, tuple(tail), (*concrete, key))
                return
            _require(isinstance(value, list), "route wildcard reached non-container")
            for index, child in enumerate(value):
                if can_follow(child, tuple(tail)):
                    expand(child, tuple(tail), (*concrete, index))
            return
        _require(
            isinstance(value, dict) and head in value,
            "declared route is absent: "
            + ".".join(str(part) for part in (*concrete, head)),
        )
        expand(value[head], tuple(tail), (*concrete, head))

    patterns = [
        path
        for path in PATH_ROUTES
        if path[0] == document_kind and path not in ROUTE_COMPATIBILITY_ALIASES
    ]
    for pattern in patterns:
        expand(document, pattern[1:], (document_kind,))
    return collected


def _validate_schema(value: object, schema: object, label: str) -> None:
    if isinstance(schema, ListSchema):
        _require(isinstance(value, list), f"{label} type mismatch")
        _require(not schema.nonempty or bool(value), f"{label} schema mismatch")
        for index, item in enumerate(value):
            _validate_schema(item, schema.item, f"{label}[{index}]")
        return
    if isinstance(schema, NullableSchema):
        if value is not None:
            _validate_schema(value, schema.item, label)
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
    _require(
        documents["capability"]["accepted"] is True,
        "capability acceptance mismatch",
    )
    _require(
        documents["manifest_v2"]["mode"] == "MANIFEST",
        "v2 manifest mode mismatch",
    )
    _require(documents["provenance"]["version"] == 2, "provenance version mismatch")
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
    del documents
    return set(PATH_ROUTES) - ROUTE_COMPATIBILITY_ALIASES


def validate_document_set(documents: dict[str, dict[str, Any]]) -> None:
    expected = {
        "capability",
        "manifest_v2",
        "manifest_v1",
        "v1_reextraction",
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
                    "/opt/miniforge3/condabin",
                    "/sbin",
                    "/snap/bin",
                    "/usr/bin",
                    "/usr/games",
                    "/usr/lib",
                    "/usr/libexec",
                    "/usr/local/bin",
                    "/usr/local/cuda/bin",
                    "/usr/local/cuda/lib64",
                    "/usr/local/games",
                    "/usr/local/lib",
                    "/usr/local/sbin",
                    "/usr/sbin",
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


def _validate_linker_argv0(value: str, roots: PortableRoots) -> None:
    _require(isinstance(value, str) and bool(value), "linker argv0 mismatch")
    if value.startswith("/"):
        roots.map_path(value)
        return
    _require(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", value) is not None
        and "/" not in value
        and value not in {".", ".."},
        "unsafe linker argv0",
    )


def validate_linker_record_routes(record: dict[str, Any], roots: PortableRoots) -> None:
    invocation = _canonical_absolute(record["invocation_path"], "linker invocation")
    payload = _canonical_absolute(record["payload_path"], "linker payload")
    chain = record["invocation_chain"]
    _require(
        bool(chain)
        and chain[0]["absolute_path"] == record["invocation_path"]
        and len({item["absolute_path"] for item in chain}) == len(chain),
        "invalid linker invocation chain",
    )
    chain_paths = [
        _canonical_absolute(item["absolute_path"], "linker chain path")
        for item in chain
    ]
    _validate_linker_argv0(record["argv0"], roots)
    extraction_root = record["extraction_root"]
    if extraction_root is None:
        for path in (invocation, *chain_paths, payload):
            roots.map_path(path.as_posix(), expected_root="system-root")
        _require(
            record["argv0"] == record["payload_path"],
            "system linker argv0 mismatch",
        )
        return
    extracted = _canonical_absolute(extraction_root, "linker extraction root")
    roots.map_path(extracted.as_posix())
    _require(
        all(
            path == extracted or path.is_relative_to(extracted)
            for path in (invocation, *chain_paths, payload)
        ),
        "linker path is outside extraction root",
    )
    for path in (invocation, *chain_paths, payload):
        roots.map_path(path.as_posix())
    _require(
        record["argv0"] == invocation.name,
        "extracted linker argv0 mismatch",
    )


def validate_linker_trace_record_routes(
    record: dict[str, Any],
    expected_linker: dict[str, Any],
    roots: PortableRoots,
    subject_root: PurePosixPath | None,
) -> None:
    cwd = _canonical_absolute(record["cwd"], "link trace cwd")
    if subject_root is None:
        roots.map_path(cwd.as_posix())
    else:
        _require(
            cwd == subject_root or cwd.is_relative_to(subject_root),
            "link trace cwd is outside subject root",
        )
        roots.map_path(cwd.as_posix(), expected_root="subject")
    validate_path_list(record["path"], roots)
    _validate_linker_argv0(record["argv0"], roots)
    roots.map_path(record["payload_path"])
    _require(
        record["argv0"] == expected_linker["argv0"]
        and record["payload_path"] == expected_linker["payload_path"]
        and record["payload_sha256"] == expected_linker["payload_sha256"],
        "link trace linker identity mismatch",
    )


def validate_link_trace_routes(
    records: list[dict[str, Any]],
    selected: dict[str, Any],
    expected_linker: dict[str, Any],
    roots: PortableRoots,
    subject_root: PurePosixPath,
) -> None:
    for record in records:
        validate_command(
            record["argv"],
            roots,
            rustc=False,
            has_program=False,
            cwd=record["cwd"],
        )
        validate_linker_trace_record_routes(record, expected_linker, roots, None)
    validate_linker_trace_record_routes(
        selected,
        expected_linker,
        roots,
        subject_root,
    )


def validate_concrete_route_values(
    document_kind: str, document: object, roots: PortableRoots
) -> None:
    command_cwd = (
        document.get("cwd")
        if isinstance(document, dict) and document_kind == "transcript"
        else document.get("runner_root")
        if isinstance(document, dict) and document_kind == "manifest"
        else None
    )
    for concrete, field_kind, value in collect_concrete_routes(document_kind, document):
        label = ".".join(str(part) for part in concrete)
        if field_kind in {
            "root",
            "hashed-file",
            "hashed-file-pair",
            "duplicate-file",
            "transient-directory",
            "archive-file",
            "archive-member",
        }:
            _require(isinstance(value, str), f"{label} route type mismatch")
            if field_kind.startswith("archive-"):
                _canonical_member(value)
            else:
                roots.map_path(value)
        elif field_kind in {"system-file", "system-hashed-file"}:
            _require(isinstance(value, str), f"{label} route type mismatch")
            if concrete[-1] == "argv0":
                _validate_linker_argv0(value, roots)
            else:
                roots.map_path(value)
        elif field_kind == "nullable-root":
            _require(
                value is None or isinstance(value, str), f"{label} route type mismatch"
            )
            if value is not None:
                roots.map_path(value)
        elif field_kind == "path-list":
            validate_path_list(value, roots)
        elif field_kind == "rustc-command":
            _require(isinstance(value, str), f"{label} route type mismatch")
            validate_rustc_transcript(value, roots)
        elif field_kind == "linker-command":
            _require(isinstance(value, list), f"{label} route type mismatch")
            validate_command(
                value,
                roots,
                rustc=False,
                has_program=False,
                cwd=command_cwd,
            )
        elif field_kind in {"rustc-options", "rustc-options-template"}:
            _require(isinstance(value, list), f"{label} route type mismatch")
            validate_command(
                ["rustc", *value],
                roots,
                rustc=True,
                cwd=command_cwd,
                allow_linker_templates=field_kind == "rustc-options-template",
            )
        elif field_kind == "linker-template":
            _require(
                isinstance(value, list)
                and all(
                    isinstance(token, str) and token and "\x00" not in token
                    for token in value
                ),
                f"{label} route type mismatch",
            )
        elif field_kind == "semantic-file":
            _require(
                isinstance(value, str)
                and value not in {"", ".", ".."}
                and "/" not in value
                and "\x00" not in value,
                f"{label} semantic file mismatch",
            )
        elif field_kind == "semantic-rlib-member":
            _require(isinstance(value, str), f"{label} route type mismatch")
            archive, _member = parse_rlib_owner(value)
            _require(
                "/" not in archive and PurePosixPath(archive).name == archive,
                f"{label} semantic rlib mismatch",
            )
        elif field_kind in {"rlib-member", "transient-file"}:
            _require(isinstance(value, str), f"{label} route type mismatch")
            raw = parse_rlib_owner(value)[0] if ".rlib(" in value else value
            roots.map_path(raw)
        elif field_kind == "root-definition":
            _canonical_absolute(value, label)
        elif field_kind == "archive-root":
            _canonical_member(value)
        elif field_kind == "system-link-source":
            _canonical_absolute(value, label)
        elif field_kind == "system-link-target":
            _require(
                isinstance(value, str) and bool(value) and "\x00" not in value,
                f"{label} route type mismatch",
            )
        else:
            raise AssertionError(f"unsupported concrete route kind: {field_kind}")
    if isinstance(document, dict) and document_kind == "capability":
        validate_linker_record_routes(document["linker"], roots)
        for record in document["required_linkers"].values():
            validate_linker_record_routes(record, roots)
    elif isinstance(document, dict) and document_kind == "manifest":
        embedded = document["linker_capability"]
        validate_linker_record_routes(embedded["linker"], roots)
        for record in embedded["required_linkers"].values():
            validate_linker_record_routes(record, roots)
        for proof in document["build_proof"]["executables"].values():
            validate_linker_record_routes(proof["link_command"]["driver"], roots)


def _looks_path_valued(value: str) -> bool:
    return (
        "/" in value
        or value.startswith("@")
        or value.endswith((".o", ".a", ".so", ".rlib", ".rs", ".rsp", ".ld"))
    )


def _normalize_absolute_command_path(value: str, label: str) -> PurePosixPath:
    _require(
        isinstance(value, str) and value.startswith("/") and "\0" not in value,
        f"invalid {label}",
    )
    parts: list[str] = []
    for part in value.split("/")[1:]:
        if part in {"", "."}:
            continue
        if part == "..":
            _require(bool(parts), "command path escapes filesystem root")
            parts.pop()
        else:
            parts.append(part)
    return PurePosixPath("/", *parts)


def _map_command_path(
    value: str,
    roots: PortableRoots,
    *,
    cwd: str | None,
    expected_root: str | None = None,
) -> PurePosixPath:
    if value.startswith("/"):
        normalized = _normalize_absolute_command_path(value, "command path")
        return roots.map_path(normalized.as_posix(), expected_root=expected_root)
    _require(
        cwd is not None,
        "unclassified relative command input lacks authenticated cwd",
    )
    base = _canonical_absolute(cwd, "authenticated cwd")
    roots.map_path(base.as_posix())
    parts = value.split("/")
    _require(
        bool(value) and all(part not in {"", ".", ".."} for part in parts),
        "invalid relative command input",
    )
    return roots.map_path(
        (base / PurePosixPath(*parts)).as_posix(), expected_root=expected_root
    )


def _map_search_path(value: str, roots: PortableRoots, *, cwd: str | None) -> None:
    path = (
        value.split("=", 1)[1] if "=" in value and not value.startswith("/") else value
    )
    _map_command_path(path, roots, cwd=cwd)


def _validate_gcc_resolution_file(value: str) -> None:
    path = _canonical_absolute(value, "GCC resolution file")
    stem = path.name.removeprefix("cc").removesuffix(".res")
    _require(
        path.parent == PurePosixPath("/tmp")
        and path.name.startswith("cc")
        and path.name.endswith(".res")
        and bool(stem)
        and stem.isascii()
        and stem.isalnum()
        and len(stem) == 6,
        "invalid GCC resolution file",
    )


def _validate_link_arg(
    value: str,
    roots: PortableRoots,
    *,
    cwd: str | None,
    allow_template: bool = False,
) -> None:
    if allow_template and value in {
        "-Wl,-Map,<per-target-map>",
        "-Wl,-T,<target-fragment>",
    }:
        return
    if value.startswith("-fresolution="):
        _validate_gcc_resolution_file(value.removeprefix("-fresolution="))
        return
    parsed = _parse_effective_link_command([value])
    _route_effective_link_operands(parsed, roots, cwd=cwd)


def validate_command(
    command: list[str],
    roots: PortableRoots,
    *,
    rustc: bool,
    has_program: bool = True,
    cwd: str | None = None,
    allow_linker_templates: bool = False,
) -> None:
    _require(
        isinstance(command, list)
        and bool(command)
        and all(
            isinstance(token, str) and token and "\x00" not in token
            for token in command
        ),
        "command schema mismatch",
    )
    if not rustc:
        linker_arguments = command
        if has_program:
            _validate_linker_argv0(command[0], roots)
            linker_arguments = command[1:]
        parsed = _parse_effective_link_command(linker_arguments)
        _route_effective_link_operands(parsed, roots, cwd=cwd)
        return

    index = 0
    while index < len(command):
        token = command[index]
        if index == 0 and has_program:
            if "/" in token:
                _map_command_path(token, roots, cwd=cwd)
            index += 1
            continue
        if token in {"-o", "-L", "--extern", "--out-dir", "--sysroot"}:
            _require(index + 1 < len(command), "path-valued flag lacks value")
            value = command[index + 1]
            if token == "--extern":
                if "=" in value:
                    _require(bool(value.split("=", 1)[0]), "malformed --extern")
                    _map_command_path(value.split("=", 1)[1], roots, cwd=cwd)
                else:
                    _require(not _looks_path_valued(value), "malformed --extern")
            elif token == "-L":
                _map_search_path(value, roots, cwd=cwd)
            else:
                _map_command_path(value, roots, cwd=cwd)
            index += 2
            continue
        if token in {
            "-Map",
            "-T",
            "--dynamic-linker",
            "--script",
            "--version-script",
            "-dynamic-linker",
            "-plugin",
            "-rpath",
        }:
            _require(index + 1 < len(command), "path-valued flag lacks value")
            _map_command_path(command[index + 1], roots, cwd=cwd)
            index += 2
            continue
        if token.startswith("-o") and token != "-o":
            _map_command_path(token[2:], roots, cwd=cwd)
        elif token.startswith("-L") and token != "-L":
            _map_search_path(token[2:], roots, cwd=cwd)
        elif token.startswith("--out-dir="):
            _map_command_path(token.removeprefix("--out-dir="), roots, cwd=cwd)
        elif token.startswith("--sysroot="):
            _map_command_path(token.removeprefix("--sysroot="), roots, cwd=cwd)
        elif token.startswith("--extern="):
            value = token.removeprefix("--extern=")
            if "=" in value:
                _require(bool(value.split("=", 1)[0]), "malformed --extern")
                _map_command_path(value.split("=", 1)[1], roots, cwd=cwd)
            else:
                _require(not _looks_path_valued(value), "malformed --extern")
        elif token == "-C":
            _require(index + 1 < len(command), "-C lacks value")
            option = command[index + 1]
            if option.startswith("linker="):
                _map_command_path(option.removeprefix("linker="), roots, cwd=cwd)
            elif option.startswith("link-arg="):
                _validate_link_arg(
                    option.removeprefix("link-arg="),
                    roots,
                    cwd=cwd,
                    allow_template=allow_linker_templates,
                )
            else:
                _require(
                    not _looks_path_valued(option),
                    "unclassified path-valued rustc flag",
                )
            index += 2
            continue
        elif token.startswith("-Clinker="):
            _map_command_path(token.removeprefix("-Clinker="), roots, cwd=cwd)
        elif token.startswith("-Clink-arg="):
            _validate_link_arg(
                token.removeprefix("-Clink-arg="),
                roots,
                cwd=cwd,
                allow_template=allow_linker_templates,
            )
        elif token.startswith("-Wl,"):
            _validate_link_arg(
                token,
                roots,
                cwd=cwd,
                allow_template=allow_linker_templates,
            )
        elif token.startswith("-plugin-opt="):
            _validate_link_arg(
                token.removeprefix("-plugin-opt="),
                roots,
                cwd=cwd,
                allow_template=allow_linker_templates,
            )
        elif token.startswith("-B") and token != "-B":
            _map_command_path(token[2:], roots, cwd=cwd)
        elif token == "-B":
            _require(index + 1 < len(command), "-B lacks value")
            _map_command_path(command[index + 1], roots, cwd=cwd)
            index += 2
            continue
        elif token == "-Xlinker":
            _require(index + 1 < len(command), "-Xlinker lacks value")
            _validate_link_arg(
                command[index + 1],
                roots,
                cwd=cwd,
                allow_template=allow_linker_templates,
            )
            index += 2
            continue
        elif token.startswith("@"):
            _map_command_path(token[1:], roots, cwd=cwd)
        elif rustc and token in {
            "--allow",
            "--cap-lints",
            "--cfg",
            "--check-cfg",
            "--crate-name",
            "--crate-type",
            "--deny",
            "--edition",
            "--emit",
            "--error-format",
            "--forbid",
            "--json",
            "--target",
            "--warn",
            "-A",
            "-D",
            "-F",
            "-W",
            "-l",
        }:
            _require(index + 1 < len(command), f"{token} lacks value")
            value = command[index + 1]
            _require(
                not _looks_path_valued(value),
                f"unclassified path-valued {token} value",
            )
            index += 2
            continue
        elif token.startswith("-"):
            _require(not _looks_path_valued(token), "unclassified path-valued flag")
        else:
            _map_command_path(token, roots, cwd=cwd)
        index += 1


def validate_rustc_transcript(line: str, roots: PortableRoots) -> None:
    _require(
        isinstance(line, str)
        and line.startswith("Running `")
        and line.endswith("`")
        and "\x00" not in line,
        "rustc transcript grammar mismatch",
    )
    try:
        tokens = shlex.split(line[len("Running `") : -1], posix=True)
    except ValueError as error:
        raise EvidenceError("rustc transcript grammar mismatch") from error
    _require(bool(tokens), "rustc transcript grammar mismatch")
    index = 0
    manifest_dir: str | None = None
    manifest_path: str | None = None
    encoded_rustflags: list[str] = []

    def map_manifest_value(value: str) -> None:
        accepted = False
        for root_name in ("subject", "cargo-registry"):
            try:
                roots.map_path(value, expected_root=root_name)
            except EvidenceError:
                continue
            accepted = True
            break
        _require(accepted, "manifest path is outside subject/registry roots")

    while index < len(tokens):
        name, separator, value = tokens[index].partition("=")
        if (
            separator != "="
            or not name
            or any(
                character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
                for character in name
            )
        ):
            break
        if name == "CARGO":
            roots.map_path(value, expected_root="toolchain")
        elif name == "CARGO_MANIFEST_DIR":
            map_manifest_value(value)
            manifest_dir = value
        elif name == "CARGO_MANIFEST_PATH":
            map_manifest_value(value)
            manifest_path = value
        elif name == "LD_LIBRARY_PATH":
            elements = value.split(":")
            _require(all(elements), "empty LD_LIBRARY_PATH element")
            for element in elements:
                roots.map_path(element)
        elif name in {"CARGO_TARGET_TMPDIR", "OUT_DIR", "RUSTC", "RUSTDOC"}:
            roots.map_path(value)
        elif name == "CARGO_ENCODED_RUSTFLAGS":
            encoded_rustflags.extend(value.split("\x1f") if value else [])
        elif name.startswith(
            ("CARGO_CFG_", "CARGO_FEATURE_", "CARGO_PKG_", "CODSPEED_")
        ) or name in {
            "CARGO_CRATE_NAME",
            "CARGO_MANIFEST_LINKS",
            "CARGO_PRIMARY_PACKAGE",
            "DEBUG",
            "HOST",
            "NUM_JOBS",
            "OPT_LEVEL",
            "PROFILE",
            "TARGET",
        }:
            pass
        elif _looks_path_valued(value):
            raise EvidenceError(f"unclassified path-valued environment: {name}")
        index += 1
    _require(index < len(tokens), "rustc transcript lacks command")
    if manifest_path is not None:
        _require(
            manifest_dir is not None
            and PurePosixPath(manifest_path).parent
            == _canonical_absolute(manifest_dir, "Cargo manifest directory"),
            "Cargo manifest path/directory mismatch",
        )
    if encoded_rustflags:
        try:
            for encoded in encoded_rustflags:
                residual = encoded
                for marker in ("-Clinker=", "-Clink-arg="):
                    if marker not in residual:
                        continue
                    start = residual.index(marker)
                    option = residual[start + len(marker) :]
                    _require(bool(option), "empty encoded rustflag path")
                    if marker == "-Clinker=":
                        _map_command_path(option, roots, cwd=manifest_dir)
                    else:
                        _validate_link_arg(
                            option,
                            roots,
                            cwd=manifest_dir,
                            allow_template=False,
                        )
                    residual = residual[:start]
                _require(
                    not _looks_path_valued(residual),
                    "unclassified encoded rustflag path",
                )
        except EvidenceError as error:
            raise EvidenceError("unclassified path-valued environment") from error
    validate_command(tokens[index:], roots, rustc=True, cwd=manifest_dir)


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


def validate_rlib_member(archive: Path | RlibArchive, member: str) -> None:
    if isinstance(archive, RlibArchive):
        with tempfile.NamedTemporaryFile(
            prefix="cache-gate-rlib-", suffix=".rlib"
        ) as held:
            held.write(archive.data)
            held.flush()
            completed = subprocess.run(
                ["ar", "t", held.name],
                text=True,
                capture_output=True,
                check=False,
            )
    else:
        completed = subprocess.run(
            ["ar", "t", archive], text=True, capture_output=True, check=False
        )
    _require(completed.returncode == 0, "cannot read rlib index")
    members = completed.stdout.splitlines()
    _require(member in members, "rlib index member is missing")


def validate_manifest_rlib_owners(owners: list[str], resolve_archive: Any) -> None:
    _require(
        isinstance(owners, list) and all(isinstance(item, str) for item in owners),
        "rlib owner list schema mismatch",
    )
    for owner in owners:
        archive_raw, member = parse_rlib_owner(owner)
        archive = resolve_archive(archive_raw)
        _require(
            isinstance(archive, (Path, RlibArchive)),
            f"rlib archive is not mapped: {archive_raw}",
        )
        validate_rlib_member(archive, member)


def validate_manifest_rlib_occurrences(
    layout: dict[str, Any], proof: dict[str, Any], resolve_archive: Any
) -> None:
    layout_owners = layout["archive_member_owners"]
    proof_owners = proof["archive_member_owners"]
    _require(
        [
            f"{PurePosixPath(parse_rlib_owner(owner)[0]).name}"
            f"({parse_rlib_owner(owner)[1]})"
            for owner in layout_owners
        ]
        == proof_owners,
        "layout/proof rlib owner lists differ",
    )
    occurrences = [
        *layout_owners,
        *proof_owners,
        *(item["owner"] for item in layout["cache_gate_input_sections"]),
        *(item["input_owner"] for item in layout["kernels"].values()),
    ]
    for owner in occurrences:
        if not isinstance(owner, str) or ".rlib(" not in owner:
            continue
        archive_raw, member = parse_rlib_owner(owner)
        archive = resolve_archive(archive_raw)
        _require(
            isinstance(archive, (Path, RlibArchive)),
            f"rlib archive is not mapped: {archive_raw}",
        )
        validate_rlib_member(archive, member)


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


def _shape_json(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = _strict_json(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"invalid JSON in {label}") from error
    _require(isinstance(value, dict), f"{label} schema mismatch")
    return value


class EffectiveLinkToken(NamedTuple):
    value: str
    forwarded: bool
    source_argument: str
    source_index: int


class EffectiveLinkOperand(NamedTuple):
    option: str | None
    value: str
    forwarded: bool
    source_argument: str


class EffectiveLinkOutput(NamedTuple):
    option: str
    value: str
    forwarded: bool
    source_argument: str


class EffectiveLinkInputs(NamedTuple):
    ordered: tuple[str, ...]
    direct_files: tuple[str, ...]


class EffectiveLinkControl(NamedTuple):
    option: str
    operand: str
    forwarded: bool
    source_argument: str


class EffectiveLinkControls(NamedTuple):
    selection: tuple[EffectiveLinkControl, ...]
    scripts: tuple[EffectiveLinkControl, ...]
    maps: tuple[EffectiveLinkControl, ...]
    mechanisms: tuple[EffectiveLinkControl, ...]


class EffectiveLinkCommand(NamedTuple):
    tokens: tuple[EffectiveLinkToken, ...]
    operands: tuple[EffectiveLinkOperand, ...]
    output_controls: tuple[EffectiveLinkOutput, ...]
    inputs: EffectiveLinkInputs
    controls: EffectiveLinkControls

    @property
    def outputs(self) -> tuple[str, ...]:
        return tuple(control.value for control in self.output_controls)


class _LinkOperandSpec(NamedTuple):
    route: str
    role: str
    joined: str | None
    split: bool


_LINK_OPTION_OPERANDS: dict[str, _LinkOperandSpec] = {
    "-A": _LinkOperandSpec("scalar", "ordinary", "attached", True),
    "-B": _LinkOperandSpec("b-mode-or-path", "ordinary", "attached", True),
    "-F": _LinkOperandSpec("search-path", "ordinary", "attached", True),
    "-G": _LinkOperandSpec("scalar", "ordinary", "attached", True),
    "-I": _LinkOperandSpec("path", "ordinary", "attached", True),
    "-L": _LinkOperandSpec("search-path", "ordinary", "attached", True),
    "-Map": _LinkOperandSpec("path", "ordinary", "attached", True),
    "-R": _LinkOperandSpec("path", "direct-input", "attached", True),
    "-T": _LinkOperandSpec("path", "ordinary", "attached", True),
    "-Tbss": _LinkOperandSpec("scalar", "ordinary", "attached", True),
    "-Tdata": _LinkOperandSpec("scalar", "ordinary", "attached", True),
    "-Ttext": _LinkOperandSpec("scalar", "ordinary", "attached", True),
    "-Y": _LinkOperandSpec("y-path-list", "ordinary", "attached", True),
    "-b": _LinkOperandSpec("scalar", "ordinary", "attached", True),
    "-c": _LinkOperandSpec("path", "mechanism", "attached", True),
    "-dT": _LinkOperandSpec("path", "mechanism", "attached", True),
    "-dynamic-linker": _LinkOperandSpec("path", "ordinary", "equals", True),
    "-e": _LinkOperandSpec("scalar", "ordinary", "attached", True),
    "-f": _LinkOperandSpec("scalar", "ordinary", "attached", True),
    "-fuse-ld": _LinkOperandSpec("linker-selection", "ordinary", "equals", True),
    "-h": _LinkOperandSpec("scalar", "ordinary", "attached", True),
    "-l": _LinkOperandSpec("library", "library", "attached", True),
    "-m": _LinkOperandSpec("scalar", "ordinary", "attached", True),
    "-o": _LinkOperandSpec("path", "ordinary", "attached", True),
    "-plugin": _LinkOperandSpec("path", "mechanism", "attached", True),
    "-plugin-opt": _LinkOperandSpec("plugin-option", "mechanism", "attached", True),
    "-rpath": _LinkOperandSpec("path-list", "ordinary", "equals", True),
    "-rpath-link": _LinkOperandSpec("path-list", "ordinary", "equals", True),
    "-soname": _LinkOperandSpec("scalar", "ordinary", "equals", True),
    "-u": _LinkOperandSpec("scalar", "ordinary", "attached", True),
    "-y": _LinkOperandSpec("scalar", "ordinary", "attached", True),
    "-z": _LinkOperandSpec("scalar", "ordinary", "attached", True),
    "--Map": _LinkOperandSpec("path", "ordinary", None, True),
    "--build-id": _LinkOperandSpec("scalar", "ordinary", "equals", False),
    "--default-script": _LinkOperandSpec("path", "mechanism", None, True),
    "--defsym": _LinkOperandSpec("scalar", "ordinary", None, True),
    "--dependency-file": _LinkOperandSpec("path", "ordinary", None, True),
    "--dynamic-linker": _LinkOperandSpec("path", "ordinary", None, True),
    "--dynamic-list": _LinkOperandSpec("path", "mechanism", None, True),
    "--entry": _LinkOperandSpec("scalar", "ordinary", None, True),
    "--export-dynamic-symbol-list": _LinkOperandSpec("path", "mechanism", None, True),
    "--format": _LinkOperandSpec("scalar", "ordinary", None, True),
    "--hash-style": _LinkOperandSpec("scalar", "ordinary", None, True),
    "--just-symbols": _LinkOperandSpec("path", "direct-input", None, True),
    "--ld-path": _LinkOperandSpec("path", "ordinary", None, True),
    "--library": _LinkOperandSpec("library", "library", None, True),
    "--library-path": _LinkOperandSpec("search-path", "ordinary", None, True),
    "--mri-script": _LinkOperandSpec("path", "mechanism", None, True),
    "--oformat": _LinkOperandSpec("scalar", "ordinary", None, True),
    "--output": _LinkOperandSpec("path", "ordinary", None, True),
    "--out-implib": _LinkOperandSpec("path", "ordinary", None, True),
    "--plugin": _LinkOperandSpec("path", "mechanism", None, True),
    "--plugin-opt": _LinkOperandSpec("plugin-option", "mechanism", None, True),
    "--remap-inputs": _LinkOperandSpec("unsupported", "mechanism", None, True),
    "--remap-inputs-file": _LinkOperandSpec("path", "mechanism", None, True),
    "--retain-symbols-file": _LinkOperandSpec("path", "mechanism", None, True),
    "--rpath": _LinkOperandSpec("path-list", "ordinary", None, True),
    "--rpath-link": _LinkOperandSpec("path-list", "ordinary", None, True),
    "--script": _LinkOperandSpec("path", "ordinary", None, True),
    "--section-start": _LinkOperandSpec("scalar", "ordinary", None, True),
    "--soname": _LinkOperandSpec("scalar", "ordinary", None, True),
    "--sysroot": _LinkOperandSpec("path", "ordinary", None, True),
    "--undefined": _LinkOperandSpec("scalar", "ordinary", None, True),
    "--version-script": _LinkOperandSpec("path", "mechanism", None, True),
    "--wrap": _LinkOperandSpec("scalar", "ordinary", None, True),
}
_LINK_JOINED_SHORT_OPTIONS = tuple(
    sorted(
        (
            option
            for option, spec in _LINK_OPTION_OPERANDS.items()
            if not option.startswith("--") and spec.joined is not None
        ),
        key=len,
        reverse=True,
    )
)
_KNOWN_LINK_LONG_OPTIONS = frozenset(
    {
        *(option for option in _LINK_OPTION_OPERANDS if option.startswith("--")),
    }
)


def _flatten_effective_linker_tokens(argv: list[str]) -> tuple[EffectiveLinkToken, ...]:
    tokens: list[EffectiveLinkToken] = []
    index = 0
    while index < len(argv):
        argument = argv[index]
        _require(
            isinstance(argument, str) and bool(argument) and "\0" not in argument,
            "malformed linker argument",
        )
        if argument.startswith("-Wl,"):
            forwarded = argument[4:].split(",")
            _require(
                all(token and "\0" not in token for token in forwarded),
                "malformed -Wl linker argument",
            )
            tokens.extend(
                EffectiveLinkToken(token, True, argument, index) for token in forwarded
            )
        elif argument in {"-Xlinker", "--for-linker"}:
            _require(index + 1 < len(argv), f"dangling {argument} argument")
            forwarded_argument = argv[index + 1]
            _require(
                isinstance(forwarded_argument, str)
                and bool(forwarded_argument)
                and "\0" not in forwarded_argument,
                f"malformed {argument} argument",
            )
            tokens.append(EffectiveLinkToken(forwarded_argument, True, argument, index))
            index += 1
        elif argument.startswith(("-Xlinker=", "--for-linker=")):
            wrapper, forwarded_argument = argument.split("=", 1)
            _require(
                bool(forwarded_argument) and "\0" not in forwarded_argument,
                f"malformed {wrapper} argument",
            )
            tokens.append(EffectiveLinkToken(forwarded_argument, True, argument, index))
        elif argument == "-Wl":
            raise EvidenceError("malformed -Wl linker argument")
        else:
            tokens.append(EffectiveLinkToken(argument, False, argument, index))
        index += 1
    return tuple(tokens)


def _parse_effective_link_command(argv: list[str]) -> EffectiveLinkCommand:
    tokens = _flatten_effective_linker_tokens(argv)
    _require(
        not any(token.value == "--" for token in tokens),
        "linker option terminator is unsafe",
    )
    _require(
        not any(token.value.startswith("@") for token in tokens),
        "captured link command contains linker response files",
    )
    operands: list[EffectiveLinkOperand] = []
    outputs: list[EffectiveLinkOutput] = []
    ordered_inputs: list[str] = []
    direct_files: list[str] = []
    selection: list[EffectiveLinkControl] = []
    scripts: list[EffectiveLinkControl] = []
    maps: list[EffectiveLinkControl] = []
    mechanisms: list[EffectiveLinkControl] = []

    def operand_after(option_index: int, option_token: EffectiveLinkToken) -> str:
        _require(
            option_index + 1 < len(tokens),
            f"dangling linker option: {option_token.value}",
        )
        operand_token = tokens[option_index + 1]
        _require(
            operand_token.forwarded == option_token.forwarded,
            f"mixed forwarding for linker option: {option_token.value}",
        )
        return operand_token.value

    def record_direct_input(value: str) -> None:
        path = _normalize_absolute_command_path(
            value,
            f"captured linker input {value!r}",
        )
        ordered_inputs.append(path.name)
        direct_files.append(path.name)

    def record_control(
        option_token: EffectiveLinkToken,
        option: str,
        operand: str,
    ) -> None:
        control = EffectiveLinkControl(
            option,
            operand,
            option_token.forwarded,
            option_token.source_argument,
        )
        if option in {"-T", "--script"}:
            scripts.append(control)
        elif option in {"-Map", "--Map"}:
            maps.append(control)
        elif option == "-B":
            if operand in {"static", "dynamic"}:
                return
            _require(
                not option_token.forwarded and operand.startswith("/"),
                "ambiguous linker -B control is unsafe",
            )
            selection.append(control)
        elif option == "--ld-path" or (
            not option_token.forwarded and option == "-fuse-ld"
        ):
            selection.append(control)

    def reject_abbreviated_long_option(value: str) -> None:
        if not value.startswith("--") or value == "--":
            return
        option = value.split("=", 1)[0]
        if option in _KNOWN_LINK_LONG_OPTIONS:
            return
        candidates = tuple(
            known for known in _KNOWN_LINK_LONG_OPTIONS if known.startswith(option)
        )
        if not candidates:
            return
        if "--output" in candidates:
            raise EvidenceError("abbreviated linker output control is unsafe")
        raise EvidenceError(f"abbreviated linker option is unsafe: {option}")

    def parse_operand_option(
        option_index: int, option_token: EffectiveLinkToken
    ) -> tuple[str, str, int] | None:
        value = option_token.value
        spec = _LINK_OPTION_OPERANDS.get(value)
        if spec is not None and spec.split:
            return value, operand_after(option_index, option_token), 2
        if value.startswith("--") and "=" in value:
            option, operand = value.split("=", 1)
            spec = _LINK_OPTION_OPERANDS.get(option)
            _require(
                spec is not None,
                f"unsupported operand-bearing linker option: {option}",
            )
            _require(bool(operand), f"empty linker option operand: {option}")
            return option, operand, 1
        for option in _LINK_JOINED_SHORT_OPTIONS:
            joined = _LINK_OPTION_OPERANDS[option].joined
            prefix = f"{option}=" if joined == "equals" else option
            if not value.startswith(prefix):
                continue
            _require(
                len(value) > len(prefix),
                f"empty linker option operand: {option}",
            )
            operand = value[len(prefix) :]
            if joined == "attached":
                operand = operand.removeprefix("=")
            _require(bool(operand), f"empty linker option operand: {option}")
            return option, operand, 1
        _require(
            not (value.startswith("-") and "=" in value),
            f"unsupported operand-bearing linker option: {value.split('=', 1)[0]}",
        )
        return None

    index = 0
    while index < len(tokens):
        token = tokens[index]
        value = token.value
        reject_abbreviated_long_option(value)

        parsed_operand = parse_operand_option(index, token)
        if parsed_operand is not None:
            option, operand, consumed = parsed_operand
            spec = _LINK_OPTION_OPERANDS[option]
            operands.append(
                EffectiveLinkOperand(
                    option,
                    operand,
                    token.forwarded,
                    token.source_argument,
                )
            )
            if spec.role == "mechanism":
                mechanisms.append(
                    EffectiveLinkControl(
                        option,
                        operand,
                        token.forwarded,
                        token.source_argument,
                    )
                )
            elif spec.role == "library":
                _require(
                    bool(operand)
                    and not operand.startswith("-")
                    and "/" not in operand
                    and "\0" not in operand,
                    "malformed linker library argument",
                )
                ordered_inputs.append(f"-l{operand}")
            elif spec.role == "direct-input":
                record_direct_input(operand)
            else:
                if option in {"-o", "--output"}:
                    outputs.append(
                        EffectiveLinkOutput(
                            option,
                            operand,
                            token.forwarded,
                            token.source_argument,
                        )
                    )
                record_control(token, option, operand)
            index += consumed
            continue

        if value.startswith("-"):
            _require(
                not _looks_path_valued(value),
                f"unsupported file-bearing linker option: {value}",
            )
            index += 1
            continue
        operands.append(
            EffectiveLinkOperand(
                None,
                value,
                token.forwarded,
                token.source_argument,
            )
        )
        record_direct_input(value)
        index += 1

    return EffectiveLinkCommand(
        tokens,
        tuple(operands),
        tuple(outputs),
        EffectiveLinkInputs(
            tuple(ordered_inputs),
            tuple(sorted(set(direct_files))),
        ),
        EffectiveLinkControls(
            tuple(selection),
            tuple(scripts),
            tuple(maps),
            tuple(mechanisms),
        ),
    )


def _map_link_path_list(
    value: str,
    roots: PortableRoots,
    *,
    cwd: str | None,
) -> None:
    paths = value.split(":")
    _require(all(paths), "empty linker path-list element")
    for path in paths:
        _map_command_path(path, roots, cwd=cwd)


def _route_effective_link_operands(
    command: EffectiveLinkCommand,
    roots: PortableRoots,
    *,
    cwd: str | None,
) -> None:
    for operand in command.operands:
        if operand.option is None:
            _map_command_path(operand.value, roots, cwd=cwd)
            continue
        spec = _LINK_OPTION_OPERANDS[operand.option]
        route = spec.route
        if route == "path":
            _map_command_path(operand.value, roots, cwd=cwd)
        elif route == "path-list":
            _map_link_path_list(operand.value, roots, cwd=cwd)
        elif route == "search-path":
            _map_search_path(operand.value, roots, cwd=cwd)
        elif route == "y-path-list":
            _require(
                operand.value.startswith("P,") and len(operand.value) > 2,
                "malformed linker -Y operand",
            )
            _map_link_path_list(operand.value[2:], roots, cwd=cwd)
        elif route == "b-mode-or-path":
            if operand.value not in {"static", "dynamic"}:
                _map_command_path(operand.value, roots, cwd=cwd)
        elif route == "linker-selection":
            if "/" in operand.value:
                _map_command_path(operand.value, roots, cwd=cwd)
            else:
                _validate_linker_argv0(operand.value, roots)
        elif route == "plugin-option":
            if operand.value.startswith("-fresolution="):
                _validate_gcc_resolution_file(
                    operand.value.removeprefix("-fresolution=")
                )
            else:
                _require(
                    not operand.value.startswith("-"),
                    "unsupported linker plugin option",
                )
                _map_command_path(operand.value, roots, cwd=cwd)
        elif route == "scalar":
            _require(
                not _looks_path_valued(operand.value),
                f"path-valued operand for scalar linker option: {operand.option}",
            )
        elif route == "library":
            pass
        elif route == "unsupported":
            raise EvidenceError(
                f"unsupported operand-bearing linker option: {operand.option}"
            )
        else:
            raise AssertionError(f"unsupported linker operand route: {route}")


def _raw_output_values(argv: list[str]) -> list[str]:
    return list(_parse_effective_link_command(argv).outputs)


def _verify_known_lto_plugin_controls(
    controls: tuple[EffectiveLinkControl, ...],
) -> None:
    if controls == ():
        return
    _require(
        len(controls) == 3,
        "explicit shape linker plugin controls are not exact",
    )
    plugin, wrapper, resolution = controls
    plugin_path = _canonical_absolute(plugin.operand, "LTO plugin path")
    wrapper_path = _canonical_absolute(wrapper.operand, "LTO wrapper path")
    _require(
        plugin
        == EffectiveLinkControl(
            "-plugin",
            plugin.operand,
            False,
            "-plugin",
        )
        and plugin_path.name == "liblto_plugin.so"
        and wrapper
        == EffectiveLinkControl(
            "-plugin-opt",
            wrapper.operand,
            False,
            f"-plugin-opt={wrapper.operand}",
        )
        and wrapper_path.name == "lto-wrapper"
        and resolution
        == EffectiveLinkControl(
            "-plugin-opt",
            resolution.operand,
            False,
            f"-plugin-opt={resolution.operand}",
        )
        and resolution.operand.startswith("-fresolution="),
        "explicit shape linker plugin controls are not exact",
    )
    _validate_gcc_resolution_file(resolution.operand.removeprefix("-fresolution="))


def _output_values(argv: list[str]) -> list[str]:
    """Compatibility alias for callers that need linker output extraction."""

    return _raw_output_values(argv)


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
    _require(set(record) == expected, f"{label} schema mismatch")
    _require(
        isinstance(record["payload_path"], str)
        and isinstance(record["payload_sha256"], str)
        and isinstance(record["argv0"], str)
        and bool(record["argv0"])
        and isinstance(record["argv"], list)
        and all(isinstance(token, str) for token in record["argv"])
        and isinstance(record["cwd"], str)
        and record["cwd"].startswith("/")
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


def _verify_shape_trace(
    execution: dict[str, Any],
    trace_bytes: bytes,
    expected_linker: dict[str, Any],
    *,
    roots: PortableRoots | None = None,
    subject_root: PurePosixPath | None = None,
) -> EffectiveLinkCommand:
    trace = execution["trace"]
    _validate_schema(trace, TRACE_RECORD_SCHEMA, "shape execution trace")
    _require(
        hashlib.sha256(trace_bytes).hexdigest() == trace["sha256"],
        "shape trace hash mismatch",
    )
    records: list[dict[str, Any]] = []
    for line in trace_bytes.splitlines():
        if not line.strip():
            continue
        records.append(_shape_json(line, "shape trace record"))
    parsed_records: list[tuple[dict[str, Any], EffectiveLinkCommand]] = []
    for index, record in enumerate(records):
        _validate_link_trace_record(record, f"shape trace record {index}")
        parsed_records.append((record, _parse_effective_link_command(record["argv"])))
        if roots is not None:
            _require(subject_root is not None, "shape subject root is missing")
            validate_command(
                record["argv"],
                roots,
                rustc=False,
                has_program=False,
                cwd=record["cwd"],
            )
            validate_linker_trace_record_routes(
                record, expected_linker, roots, subject_root
            )
    matches = [
        (record, parsed)
        for record, parsed in parsed_records
        if parsed.outputs == (execution["raw_output"],)
    ]
    _require(
        len(records) == trace["record_count"]
        and trace["final_link_record_count"] == len(matches),
        "shape trace counts mismatch",
    )
    _require(len(matches) == 1, "shape trace lacks one exact output producer execution")
    record, parsed = matches[0]
    _require(
        record
        == {
            "argv": execution["argv"],
            "argv0": expected_linker["argv0"],
            "cwd": execution["cwd"],
            "path": execution["path"],
            "payload_path": expected_linker["payload_path"],
            "payload_sha256": expected_linker["payload_sha256"],
            "role": execution["role"],
            "session": execution["session"],
        },
        "shape execution differs from trace",
    )
    _require(
        parsed.outputs == (execution["raw_output"],),
        "shape execution raw output mismatch",
    )
    return parsed


def _printed_linker_controls(
    argv: list[str],
) -> tuple[list[str], list[str], list[str]]:
    controls = _parse_effective_link_command(argv).controls
    return (
        [control.source_argument for control in controls.selection],
        [control.source_argument for control in controls.scripts],
        [control.source_argument for control in controls.maps],
    )


def _link_command_inputs(argv: list[str]) -> tuple[list[str], list[str]]:
    parsed = _parse_effective_link_command(argv)
    _require(
        parsed.controls.mechanisms == (),
        "unsupported linker plugin mechanism",
    )
    _require(
        bool(parsed.inputs.ordered),
        "captured link command has no linker inputs",
    )
    return list(parsed.inputs.ordered), list(parsed.inputs.direct_files)


def verify_manifest_link_command(
    command: dict[str, Any],
    trace_bytes: bytes,
    capability: dict[str, Any],
    target: str,
    executable_record: dict[str, Any],
    *,
    expected_fragment: str | None = None,
    roots: PortableRoots | None = None,
    subject_root: str | None = None,
) -> dict[str, Any]:
    _validate_schema(command, LINK_COMMAND_SCHEMA, "manifest link command")
    expected_driver = capability["linker"]
    expected_executable = executable_record["absolute_path"]
    capability_fragment = capability["fragments"][target]
    private_fragment_required = expected_fragment is not None
    if expected_fragment is None:
        expected_fragment = capability_fragment["absolute_path"]
    if private_fragment_required:
        _require(
            capability_fragment["absolute_path"] != expected_fragment,
            "manifest private fragment aliases capability source fragment",
        )
    expected_map = executable_record["link_map"]["absolute_path"]
    _require(
        command["driver"] == expected_driver, "manifest link command driver mismatch"
    )
    _require(
        executable_record["linker_fragment"]
        == {
            "absolute_path": expected_fragment,
            "sha256": capability_fragment["sha256"],
        }
        and command["fragment"] == expected_fragment,
        "manifest link command fragment mismatch",
    )
    _require(
        command["executable"] == expected_executable
        and command["link_map"] == expected_map,
        "manifest link command executable/map mismatch",
    )
    _require(
        hashlib.sha256(trace_bytes).hexdigest() == command["trace"]["sha256"],
        "manifest link command trace hash mismatch",
    )
    records = [
        _shape_json(line, "manifest link trace record")
        for line in trace_bytes.splitlines()
        if line.strip()
    ]
    parsed_records: list[tuple[dict[str, Any], EffectiveLinkCommand]] = []
    for index, record in enumerate(records):
        _validate_link_trace_record(record, f"manifest link trace record {index}")
        parsed_records.append((record, _parse_effective_link_command(record["argv"])))
    matches = [
        (record, parsed)
        for record, parsed in parsed_records
        if parsed.outputs == (expected_executable,)
    ]
    _require(
        len(records) == command["trace"]["record_count"]
        and len(matches) == command["trace"]["final_link_record_count"],
        "manifest link trace count mismatch",
    )
    _require(len(matches) == 1, "expected one captured final output producer")
    selected, parsed = matches[0]
    _require(
        selected["payload_path"] == expected_driver["payload_path"]
        and selected["payload_sha256"] == expected_driver["payload_sha256"]
        and selected["argv0"] == expected_driver["argv0"],
        "manifest link trace driver mismatch",
    )
    argv = selected["argv"]
    controls = parsed.controls
    _require(
        controls.selection == ()
        and controls.mechanisms == ()
        and controls.scripts
        == (
            EffectiveLinkControl(
                "-T",
                expected_fragment,
                True,
                f"-Wl,-T,{expected_fragment}",
            ),
        )
        and controls.maps
        == (
            EffectiveLinkControl(
                "-Map",
                expected_map,
                True,
                f"-Wl,-Map,{expected_map}",
            ),
        ),
        "manifest link command fragment/map controls mismatch",
    )
    _require(
        bool(parsed.inputs.ordered),
        "captured link command has no linker inputs",
    )
    ordered_inputs = list(parsed.inputs.ordered)
    direct_files = list(parsed.inputs.direct_files)
    regenerated = {
        "driver": expected_driver,
        "argv": argv,
        "ordered_linker_inputs": ordered_inputs,
        "ordered_linker_input_fingerprint": _fingerprint(ordered_inputs),
        "direct_input_files": direct_files,
        "direct_cgu_members": sorted(
            value for value in direct_files if ".rcgu.o" in value
        ),
        "trace": {
            "absolute_path": command["trace"]["absolute_path"],
            "sha256": hashlib.sha256(trace_bytes).hexdigest(),
            "record_count": len(records),
            "final_link_record_count": len(matches),
        },
        "executable": expected_executable,
        "fragment": expected_fragment,
        "link_map": expected_map,
    }
    _require(regenerated == command, "manifest link command differs from trace inputs")
    if roots is not None:
        validate_linker_record_routes(expected_driver, roots)
        expected_subject = subject_root or capability["producer"]["runner_root"]
        subject_path = _canonical_absolute(expected_subject, "subject root")
        validate_link_trace_routes(
            records,
            selected,
            expected_driver,
            roots,
            subject_path,
        )
    return regenerated


def _expected_link_map_flavor(linker: dict[str, Any], label: str) -> str:
    flavor = linker["flavor"]
    _require(flavor in {"GNU ld", "LLD"}, f"{label} linker flavor mismatch")
    return "gnu" if flavor == "GNU ld" else "lld"


def _verify_symbol_layout_contract(
    symbols: dict[str, Any],
    layout: dict[str, Any],
    target: str,
    kernel_names: tuple[str, ...],
    label: str,
) -> None:
    _require(
        symbols["architecture"] == layout["arch"],
        f"{label} symbol/layout architecture mismatch",
    )
    _require(layout["target"] == target, f"{label} layout target mismatch")
    _require(
        layout["link_map_flavor"] in {"gnu", "lld"},
        f"{label} unsupported link-map flavor",
    )
    _require(layout["elf_type"] == "ET_DYN", f"{label} ELF must be PIE ET_DYN")
    _require(
        layout["program_headers_have_rwx"] is False,
        f"{label} program header is RWX",
    )
    by_kernel: dict[str, dict[str, Any]] = {}
    for symbol in symbols["symbols"]:
        kernel = symbol["name"].rsplit("::", 1)[-1]
        _require(kernel not in by_kernel, f"{label} duplicate symbol kernel")
        by_kernel[kernel] = symbol
    _require(
        set(by_kernel) == set(kernel_names)
        and set(layout["kernels"]) == set(kernel_names),
        f"{label} exact symbol/layout kernel set mismatch",
    )
    max_page = layout["max_page_size"]
    _require(max_page > 0, f"{label} invalid MAXPAGESIZE")
    veneer_names = {
        item["name"]
        for item in layout["veneer_thunk_inventory"]
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    veneer_marker = re.compile(r"(?:veneer|thunk)", re.IGNORECASE)
    field_pairs = (
        ("function_start", "start"),
        ("function_end", "end"),
        ("function_size", "size"),
        ("body_end", "end"),
        ("body_size", "size"),
        ("function_section_index", "section_index"),
        ("output_section_index", "section_index"),
        ("function_section_name", "section_name"),
        ("output_section", "section"),
        ("sh_addralign", "section_alignment"),
        ("page_offset", "page_offset"),
        ("raw_sha256", "raw_sha256"),
        ("normalized_sha256", "normalized_instructions_sha256"),
        ("direct_calls", "direct_calls"),
        ("indirect_calls", "indirect_calls"),
        ("frame_bytes", "frame_adjustment"),
        ("spills", "spills"),
    )
    reservation_ranges: list[tuple[int, int, str]] = []
    for kernel_name in kernel_names:
        kernel = layout["kernels"][kernel_name]
        symbol = by_kernel[kernel_name]
        spec = KERNEL_LAYOUT_SPECS[kernel_name]
        reservation_start = kernel["reservation_start"]
        body_end = kernel["body_end"]
        reservation_end = kernel["reservation_end"]
        reservation_ranges.append((reservation_start, reservation_end, kernel_name))
        _require(
            kernel["function_symbol_count"] == 1
            and kernel["input_section_count"] == 1
            and kernel["output_section_count"] == 1,
            f"{label} section/symbol count mismatch: {kernel_name}",
        )
        _require(
            kernel["input_section"] == spec["input"]
            and kernel["output_section"] == spec["output"]
            and isinstance(kernel["input_owner"], str)
            and bool(kernel["input_owner"].strip()),
            f"{label} section/owner mismatch: {kernel_name}",
        )
        section_alignment = kernel["sh_addralign"]
        _require(
            section_alignment > 0
            and section_alignment & (section_alignment - 1) == 0
            and section_alignment <= max_page,
            f"{label} actual sh_addralign mismatch: {kernel_name}",
        )
        _require(
            kernel["name"] == kernel_name
            and all(kernel[left] == symbol[right] for left, right in field_pairs),
            f"{label} symbol/layout body mismatch: {kernel_name}",
        )
        _require(
            kernel["reservation_start"]
            == kernel["input_start"]
            == kernel["function_start"]
            and kernel["body_end"] == kernel["input_end"] == kernel["function_end"]
            and kernel["body_size"] == kernel["input_size"] == kernel["function_size"],
            f"{label} symbol/layout body range mismatch: {kernel_name}",
        )
        _require(
            reservation_start <= body_end <= reservation_end
            and reservation_end - reservation_start == max_page
            and kernel["output_start"] == reservation_start
            and kernel["output_end"] == reservation_end
            and kernel["reservation_size"] == max_page
            and reservation_start % max_page == 0
            and kernel["max_page_remainder"] == 0
            and kernel["page_offset"] == reservation_start % 4096
            and kernel["body_size"] == body_end - reservation_start,
            f"{label} layout reservation/body arithmetic mismatch: {kernel_name}",
        )
        _require(
            set(kernel["section_flags"]) == {"ALLOC", "EXECINSTR"}
            and kernel["pt_load_count"] == 1
            and kernel["pt_load_flags"] == "R E"
            and kernel["writable_segment_overlap"] is False,
            f"{label} unsafe section/PT_LOAD placement: {kernel_name}",
        )
        _require(
            kernel["function_symbol_count"] == 1
            and kernel["input_section_count"] == 1
            and kernel["output_section_count"] == 1
            and kernel["function_section_name"] == spec["output"]
            and kernel["function_section_index"] == kernel["output_section_index"]
            and kernel["overlapping_elf_sections"] == [],
            f"{label} section cardinality/overlap mismatch: {kernel_name}",
        )
        _require(
            not kernel["veneer_thunks"]
            and not kernel["plt_calls"]
            and isinstance(kernel["direct_calls"], list)
            and not any(
                not isinstance(call, str)
                or veneer_marker.search(call)
                or any(veneer in call for veneer in veneer_names)
                for call in kernel["direct_calls"]
            ),
            f"{label} veneer/thunk/PLT safety mismatch: {kernel_name}",
        )
        sentinel_stem = KERNEL_SENTINEL_STEMS[kernel_name]
        for sentinel_name in SENTINEL_FIELDS:
            sentinel = kernel["sentinels"][sentinel_name]
            _require(
                sentinel["name"]
                == f"__opthash_cache_gate_{sentinel_stem}_{sentinel_name}"
                and sentinel["address"] == kernel[sentinel_name]
                and kernel["link_map_sentinels"][sentinel_name] == kernel[sentinel_name]
                and sentinel["count"] == 1
                and sentinel["binding"] == "GLOBAL"
                and sentinel["visibility"] == "DEFAULT"
                and sentinel["defined"] is True,
                f"{label} sentinel mismatch: {kernel_name}/{sentinel_name}",
            )
    for left, right in zip(
        sorted(reservation_ranges), sorted(reservation_ranges)[1:], strict=False
    ):
        _require(
            right[0] >= left[1],
            f"{label} reservation overlap: {left[2]}/{right[2]}",
        )


def _verify_layout_capability_association(
    layout: dict[str, Any],
    capability: dict[str, Any],
    target: str,
    label: str,
    *,
    linker: dict[str, Any] | None = None,
    executable_record: dict[str, Any] | None = None,
) -> None:
    _require(
        capability["max_page_size"] > 0
        and layout["max_page_size"] == capability["max_page_size"],
        f"{label} capability MAXPAGESIZE mismatch",
    )
    _require(
        layout["fragment_sha256"] == capability["fragments"][target]["sha256"],
        f"{label} keyed capability fragment mismatch",
    )
    _require(
        layout["fragment_set_sha256"] == capability["fragment_set_sha256"],
        f"{label} capability fragment-set mismatch",
    )
    _require(
        layout["link_map_flavor"]
        == _expected_link_map_flavor(linker or capability["linker"], label),
        f"{label} capability linker flavor mismatch",
    )
    if executable_record is not None:
        _require(
            layout["binary"] == executable_record["absolute_path"]
            and layout["binary_sha256"] == executable_record["sha256"],
            f"{label} executable artifact association mismatch",
        )
        _require(
            layout["link_map"] == executable_record["link_map"]["absolute_path"]
            and layout["link_map_sha256"] == executable_record["link_map"]["sha256"],
            f"{label} link-map artifact association mismatch",
        )
        _require(
            executable_record["linker_fragment"]["sha256"]
            == capability["fragments"][target]["sha256"],
            f"{label} keyed capability fragment record mismatch",
        )


def verify_capability_shape_records(
    capability: dict[str, Any],
    read_record: Any,
    roots: PortableRoots | None = None,
) -> set[tuple[str, str, int]]:
    _validate_schema(capability, CAPABILITY_SCHEMA, "capability")
    subject_root = _canonical_absolute(
        capability["producer"]["runner_root"], "capability producer subject root"
    )
    artifact_root = _canonical_absolute(
        capability["producer"]["artifact_root"], "capability producer artifact root"
    )
    _require(
        artifact_root.is_relative_to(subject_root),
        "capability artifact root is outside producer subject root",
    )
    if roots is not None:
        roots.map_path(subject_root.as_posix(), expected_root="subject")
        roots.map_path(artifact_root.as_posix(), expected_root="subject")
    observed_shapes: set[tuple[str, str, int]] = set()
    execution_keys = {
        "argv",
        "cwd",
        "executable",
        "linker",
        "path",
        "raw_output",
        "role",
        "session",
        "trace",
    }
    for flavor, shapes in capability["shapes"].items():
        for target, shape in shapes.items():
            linker = (
                capability["linker"]
                if flavor == "actual"
                else capability["required_linkers"][flavor]
            )
            records = {
                "link-args.txt": shape["link_argv"],
                "linker-execution.json": shape["linker_execution"],
                "symbols.json": shape["symbols"],
                "layout.json": shape["layout"],
            }
            raw: dict[str, bytes] = {}
            for name, record in records.items():
                data = read_record(flavor, target, name)
                _require(isinstance(data, bytes), "shape reader did not return bytes")
                if name != "linker-execution.json":
                    _require(
                        hashlib.sha256(data).hexdigest() == record["sha256"],
                        f"{flavor}/{target} {name} hash mismatch",
                    )
                raw[name] = data
            symbols = _shape_json(raw["symbols.json"], "shape symbols")
            layout = _shape_json(raw["layout.json"], "shape layout")
            executable, kernel_names = next(
                (name, kernels)
                for name, (shape_target, kernels) in EXECUTABLE_TARGETS.items()
                if shape_target == target
            )
            del executable
            _validate_schema(
                symbols,
                _symbol_document_schema(SYMBOL_V2_SCHEMA, veneers=True),
                f"{flavor}/{target} symbols",
            )
            _validate_schema(
                layout,
                _layout_schema(kernel_names),
                f"{flavor}/{target} layout",
            )
            _verify_symbol_layout_contract(
                symbols,
                layout,
                target,
                kernel_names,
                f"{flavor}/{target}",
            )
            _verify_layout_capability_association(
                layout,
                capability,
                target,
                f"{flavor}/{target}",
                linker=linker,
            )
            _require(
                symbols["architecture"] == capability["arch"],
                f"{flavor}/{target} architecture mismatch",
            )
            expected_map_flavor = (
                _expected_link_map_flavor(capability["linker"], "actual")
                if flavor == "actual"
                else flavor
            )
            _require(
                layout["link_map_flavor"] == expected_map_flavor,
                f"{flavor}/{target} link-map flavor mismatch",
            )
            symbol_names = [
                symbol["name"].rsplit("::", 1)[-1] for symbol in symbols["symbols"]
            ]
            _require(
                len(symbol_names) == len(kernel_names)
                and set(symbol_names) == set(kernel_names)
                and set(layout["kernels"]) == set(kernel_names)
                and all(
                    layout["kernels"][kernel]["name"] == kernel
                    for kernel in kernel_names
                ),
                f"{flavor}/{target} exact kernel shape mismatch",
            )
            _require(
                symbols["binary"]
                == layout["binary"]
                == shape["binary"]["absolute_path"]
                and symbols["binary_sha256"]
                == layout["binary_sha256"]
                == shape["binary"]["sha256"]
                and layout["link_map"] == shape["link_map"]["absolute_path"]
                and layout["link_map_sha256"] == shape["link_map"]["sha256"]
                and layout["fragment_sha256"]
                == capability["fragments"][target]["sha256"]
                and layout["fragment_set_sha256"] == capability["fragment_set_sha256"],
                f"{flavor}/{target} shape artifact association mismatch",
            )
            execution = _shape_json(
                raw["linker-execution.json"], "shape linker execution"
            )
            _require(
                set(execution) == execution_keys, "shape execution schema mismatch"
            )
            _require(
                execution["linker"] == linker,
                "shape linker identity mismatch",
            )
            _require(
                hashlib.sha256(raw["linker-execution.json"]).hexdigest()
                == shape["linker_execution"]["sha256"],
                f"{flavor}/{target} linker-execution.json hash mismatch",
            )
            _require(
                execution["executable"] == shape["binary"]["absolute_path"],
                "shape executable identity mismatch",
            )
            expected_role = "actual-driver" if flavor == "actual" else "explicit-linker"
            _require(
                execution["role"] == expected_role
                and isinstance(execution["session"], str)
                and bool(execution["session"]),
                "shape execution correlation mismatch",
            )
            execution_cwd = _canonical_absolute(execution["cwd"], "shape cwd")
            execution_output = _canonical_absolute(
                execution["raw_output"], "shape raw output"
            )
            _require(
                (
                    execution_cwd == subject_root
                    or execution_cwd.is_relative_to(subject_root)
                ),
                "shape cwd is outside producer subject root",
            )
            _require(
                execution_output.is_relative_to(artifact_root),
                "shape raw output is outside producer artifact root",
            )
            trace_bytes = read_record(flavor, target, "linker-trace.jsonl")
            execution_command = _verify_shape_trace(
                execution,
                trace_bytes,
                linker,
                roots=roots,
                subject_root=subject_root,
            )
            if roots is not None:
                validate_linker_record_routes(linker, roots)
                roots.map_path(execution["cwd"], expected_root="subject")
                validate_path_list(execution["path"], roots)
                validate_command(
                    execution["argv"],
                    roots,
                    rustc=False,
                    has_program=False,
                    cwd=execution["cwd"],
                )
                roots.map_path(execution["raw_output"], expected_root="subject")

            try:
                printed = shlex.split(raw["link-args.txt"].decode(), posix=True)
            except (UnicodeDecodeError, ValueError) as error:
                raise EvidenceError("shape link argv grammar mismatch") from error
            _require(
                len(printed) >= 5
                and printed[0] == "LC_ALL=C"
                and printed[1] == f"PATH={execution['path']}"
                and printed[2] == "VSLANG=1033"
                and printed[3]
                == f"{capability['producer']['runner_root']}/scripts/"
                "cache-gate-link-wrapper.py",
                "shape link argv environment/wrapper mismatch",
            )
            driver_argv = execution["argv"]
            driver_command = execution_command
            if flavor != "actual":
                cargo_record = shape["cargo_execution"]
                cargo_bytes = read_record(flavor, target, "cargo-execution.json")
                _require(
                    hashlib.sha256(cargo_bytes).hexdigest() == cargo_record["sha256"],
                    f"{flavor}/{target} cargo execution hash mismatch",
                )
                cargo = _shape_json(cargo_bytes, "shape Cargo execution")
                _require(
                    set(cargo) == execution_keys
                    and cargo["linker"] == capability["linker"]
                    and cargo["role"] == "cargo-driver"
                    and cargo["session"] == execution["session"]
                    and cargo["executable"] == execution["executable"]
                    and cargo["raw_output"] == execution["raw_output"],
                    "shape Cargo/linker execution association mismatch",
                )
                cargo_command = _verify_shape_trace(
                    cargo,
                    read_record(flavor, target, "cargo-trace.jsonl"),
                    capability["linker"],
                    roots=roots,
                    subject_root=subject_root,
                )
                cargo_cwd = _canonical_absolute(cargo["cwd"], "shape Cargo cwd")
                cargo_output = _canonical_absolute(
                    cargo["raw_output"], "shape Cargo raw output"
                )
                _require(
                    (
                        cargo_cwd == subject_root
                        or cargo_cwd.is_relative_to(subject_root)
                    ),
                    "shape Cargo cwd is outside producer subject root",
                )
                _require(
                    cargo_output.is_relative_to(artifact_root),
                    "shape Cargo raw output is outside producer artifact root",
                )
                if roots is not None:
                    validate_linker_record_routes(capability["linker"], roots)
                    roots.map_path(cargo["cwd"], expected_root="subject")
                    validate_path_list(cargo["path"], roots)
                    validate_command(
                        cargo["argv"],
                        roots,
                        rustc=False,
                        has_program=False,
                        cwd=cargo["cwd"],
                    )
                    roots.map_path(cargo["raw_output"], expected_root="subject")
                driver_argv = cargo["argv"]
                driver_command = cargo_command
            _require(
                printed[4:] == driver_argv,
                "shape link argv differs from execution",
            )
            if roots is not None:
                roots.map_path(printed[3])
            fragment = capability["fragments"][target]["absolute_path"]
            link_map = shape["link_map"]["absolute_path"]
            driver_controls = driver_command.controls
            _require(
                driver_controls.scripts
                == (
                    EffectiveLinkControl(
                        "-T",
                        fragment,
                        True,
                        f"-Wl,-T,{fragment}",
                    ),
                )
                and driver_controls.maps
                == (
                    EffectiveLinkControl(
                        "-Map",
                        link_map,
                        True,
                        f"-Wl,-Map,{link_map}",
                    ),
                )
                and driver_controls.mechanisms == (),
                "shape linker controls are not exact",
            )
            if flavor == "actual":
                _require(
                    driver_controls.selection == (),
                    "actual shape linker selection is not exact",
                )
            else:
                fuse = "bfd" if flavor == "gnu" else "lld"
                wrapper_dir = (
                    f"{capability['producer']['artifact_root']}/{flavor}/linker-wrapper"
                )
                _require(
                    driver_controls.selection
                    == (
                        EffectiveLinkControl(
                            "-B",
                            wrapper_dir,
                            False,
                            f"-B{wrapper_dir}",
                        ),
                        EffectiveLinkControl(
                            "-fuse-ld",
                            fuse,
                            False,
                            f"-fuse-ld={fuse}",
                        ),
                    ),
                    "explicit shape linker selection is not exact",
                )
                _require(
                    execution_command.controls.selection == ()
                    and execution_command.controls.scripts
                    == (
                        EffectiveLinkControl(
                            "-T",
                            fragment,
                            False,
                            "-T",
                        ),
                    )
                    and execution_command.controls.maps
                    == (
                        EffectiveLinkControl(
                            "-Map",
                            link_map,
                            False,
                            "-Map",
                        ),
                    ),
                    "explicit shape raw linker controls are not exact",
                )
                _verify_known_lto_plugin_controls(execution_command.controls.mechanisms)
            observed_shapes.add((flavor, target, len(kernel_names)))
    return observed_shapes


def capability_shapes(capability: dict[str, Any]) -> set[tuple[str, str, int]]:
    _validate_schema(capability, CAPABILITY_SCHEMA, "capability")
    counts = {
        target: len(kernel_names)
        for target, kernel_names in (value for value in EXECUTABLE_TARGETS.values())
    }
    return {
        (flavor, target, counts[target])
        for flavor, targets in capability["shapes"].items()
        for target in targets
    }


def verify_x86_contracts(
    capability: dict[str, Any],
    manifests: list[dict[str, Any]],
    v1: dict[str, Any],
) -> None:
    _require(
        capability["arch"] == "x86_64"
        and capability["target_triple"] == X86_TARGET_TRIPLE,
        "exact native x86_64 target mismatch",
    )
    actual_map_flavor = _expected_link_map_flavor(capability["linker"], "actual")
    _require(
        capability["required_linkers"]["gnu"]["flavor"] == "GNU ld"
        and capability["required_linkers"]["lld"]["flavor"] == "LLD",
        "required GNU/LLD linker flavor mismatch",
    )
    for manifest in manifests:
        _require(
            manifest["architecture"] == "x86_64",
            "v2 manifest architecture mismatch",
        )
        for executable, (target, _kernel_names) in EXECUTABLE_TARGETS.items():
            _require(
                manifest["symbols"][executable]["architecture"] == "x86_64",
                f"{executable} symbol architecture mismatch",
            )
            layout = manifest["elf_layout"][executable]
            _require(
                layout["target"] == target
                and layout["arch"] == "x86_64"
                and layout["link_map_flavor"] == actual_map_flavor,
                f"{executable} x86 layout target/architecture/flavor mismatch",
            )
    _require(v1["architecture"] == "x86_64", "v1 manifest architecture mismatch")
    for executable in EXECUTABLE_TARGETS:
        _require(
            v1["symbols"][executable]["architecture"] == "x86_64",
            f"v1 {executable} symbol architecture mismatch",
        )


def _rooted_path(root: str, relative: str) -> str:
    base = _canonical_absolute(root, "identity root")
    return (base / PurePosixPath(relative)).as_posix()


def _control_root(control: dict[str, Any]) -> str:
    relative = PurePosixPath(CONTROL_INPUT_IDENTITIES["cargo_manifest"][0])
    manifest = _canonical_absolute(
        control["inputs"]["cargo_manifest"]["absolute_path"],
        "control Cargo manifest",
    )
    _require(
        len(manifest.parts) > len(relative.parts)
        and manifest.parts[-len(relative.parts) :] == relative.parts,
        "control input identity mismatch",
    )
    root_parts = manifest.parts[: -len(relative.parts)]
    return PurePosixPath(*root_parts).as_posix()


def _verify_control_identity(
    control: dict[str, Any],
    root: str,
    commit: str,
    tree: str,
    *,
    v2: bool,
) -> None:
    _require(control["locked"] is True, "control locked identity mismatch")
    if v2:
        _require(
            control["runner_root"] == root
            and control["runner_commit"] == commit
            and control["builder_commit"] == commit
            and control["runner_tree"] == tree
            and control["builder_tree"] == tree
            and control["mode"] == "BUILD_CONTROL",
            "v2 control identity mismatch",
        )
    else:
        _require(
            control["builder_commit"] == commit and control["builder_tree"] == tree,
            "v1 control identity mismatch",
        )
    for name, (relative, sha256) in CONTROL_INPUT_IDENTITIES.items():
        _require(
            control["inputs"][name]
            == {
                "absolute_path": _rooted_path(root, relative),
                "sha256": sha256,
            },
            f"control input identity mismatch: {name}",
        )
    release_root = _rooted_path(root, "tools/cache-gate-control/target/release")
    _require(
        control["binary"]["absolute_path"]
        == f"{release_root}/opthash-cache-gate-control"
        and control["provenance_path"]
        == f"{release_root}/opthash-cache-gate-control.provenance.json",
        "control output identity mismatch",
    )


def verify_identity_contract(
    provenance: dict[str, Any],
    capability: dict[str, Any],
    manifests: list[dict[str, Any]],
    v1: dict[str, Any],
    capability_bytes: bytes,
    v1_root: str,
) -> None:
    _require(
        provenance["subject"] == {"commit": SUBJECT_COMMIT, "tree": SUBJECT_TREE},
        "exact subject identity mismatch",
    )
    producer = capability["producer"]
    _require(
        producer["commit"] == SUBJECT_COMMIT
        and producer["tree"] == SUBJECT_TREE
        and producer["empty_diff_assertion"] is True,
        "exact subject identity mismatch in capability producer",
    )
    _require(
        capability["cargo_version"] == PINNED_CARGO_VERSION
        and capability["rustc_version"] == PINNED_RUSTC_VERSION,
        "exact pinned Rust toolchain version mismatch",
    )
    capability_sha = hashlib.sha256(capability_bytes).hexdigest()
    subject_root = producer["runner_root"]
    v2_controls: list[dict[str, Any]] = []
    for manifest in manifests:
        control = manifest["control"]
        v2_controls.append(control)
        _require(
            manifest["commit"] == SUBJECT_COMMIT
            and manifest["tree"] == SUBJECT_TREE
            and manifest["empty_diff_assertion"] is True
            and control["runner_commit"] == SUBJECT_COMMIT
            and control["builder_commit"] == SUBJECT_COMMIT
            and control["runner_tree"] == SUBJECT_TREE
            and control["builder_tree"] == SUBJECT_TREE
            and control["mode"] == "BUILD_CONTROL",
            "exact subject identity mismatch in v2 manifest/control",
        )
        _require(
            control["cargo_version"] == capability["cargo_version"]
            and control["rustc_version"] == capability["rustc_version"],
            "v2 control Rust toolchain identity mismatch",
        )
        _verify_control_identity(
            control,
            subject_root,
            SUBJECT_COMMIT,
            SUBJECT_TREE,
            v2=True,
        )
        for name, (relative, git_blob, sha256) in SUBJECT_TOOL_IDENTITIES.items():
            _require(
                manifest["tools"][name]
                == {
                    "absolute_path": _rooted_path(subject_root, relative),
                    "sha256": sha256,
                    "git_blob": git_blob,
                    "git_blob_sha256": sha256,
                    "reviewed_root": subject_root,
                    "reviewed_commit": SUBJECT_COMMIT,
                    "reviewed_tree": SUBJECT_TREE,
                },
                f"tool {name} exact identity mismatch",
            )
        embedded = {
            key: value
            for key, value in manifest["linker_capability"].items()
            if key != "copy"
        }
        _require(
            embedded == capability,
            "embedded capability differs from exact capability document",
        )
        _require(
            manifest["linker_capability"]["copy"]["sha256"] == capability_sha,
            "capability copy differs from held capability bytes",
        )
    _require(
        bool(v2_controls)
        and all(control == v2_controls[0] for control in v2_controls[1:]),
        "v2 control identities differ",
    )
    declared_v1_root = _canonical_absolute(str(v1_root), "declared v1 root").as_posix()
    _require(
        _control_root(v1["control"]) == declared_v1_root,
        "v1 control root differs from declared portable root",
    )
    _require(
        v1["commit"] == V1_REPLAY_COMMIT
        and v1["tree"] == V1_REPLAY_TREE
        and v1["empty_diff_assertion"] is True
        and v1["control"]["builder_commit"] == V1_REPLAY_COMMIT
        and v1["control"]["builder_tree"] == V1_REPLAY_TREE,
        "exact v1 replay identity mismatch",
    )
    _verify_control_identity(
        v1["control"],
        declared_v1_root,
        V1_REPLAY_COMMIT,
        V1_REPLAY_TREE,
        v2=False,
    )
    _require(
        v1["control"]["binary"]["sha256"] == v2_controls[0]["binary"]["sha256"]
        and v1["control"]["cargo_version"]
        == v2_controls[0]["cargo_version"]
        == capability["cargo_version"]
        and v1["control"]["rustc_version"]
        == v2_controls[0]["rustc_version"]
        == capability["rustc_version"]
        and {name: record["sha256"] for name, record in v1["control"]["inputs"].items()}
        == {
            name: record["sha256"] for name, record in v2_controls[0]["inputs"].items()
        },
        "v1/v2 control identity mismatch",
    )


def _symbol_bodies(manifest: dict[str, Any]) -> dict[str, tuple[object, ...]]:
    bodies: dict[str, tuple[object, ...]] = {}
    for executable in EXECUTABLE_TARGETS:
        for symbol in manifest["symbols"][executable]["symbols"]:
            name = symbol["name"].rsplit("::", 1)[-1]
            _require(name not in bodies, "duplicate manifest body symbol")
            bodies[name] = tuple(
                symbol[field]
                for field in (
                    "size",
                    "normalized_instructions_sha256",
                    "direct_calls",
                    "indirect_calls",
                    "frame_adjustment",
                    "spills",
                )
            )
    _require(len(bodies) == 8, "manifest must contain eight body symbols")
    return bodies


def require_ordered_equal(left: list[str], right: list[str], label: str) -> None:
    _require(
        isinstance(left, list)
        and isinstance(right, list)
        and all(isinstance(item, str) for item in (*left, *right)),
        f"{label} schema mismatch",
    )
    _require(left == right, f"{label} mismatch")


def _fingerprint(values: list[str]) -> str:
    _require(
        isinstance(values, list) and all(isinstance(value, str) for value in values),
        "fingerprint input schema mismatch",
    )
    return hashlib.sha256(("\n".join(values) + "\n").encode()).hexdigest()


def _validate_manifest_build_proof(manifest: dict[str, Any], label: str) -> None:
    proof = manifest["build_proof"]
    expected_rustc_flags = [
        "-C",
        "codegen-units=16",
        "-C",
        f"linker={manifest['tools']['link_wrapper']['absolute_path']}",
    ]
    if manifest["layout_adversary"]["enabled"]:
        expected_rustc_flags.extend(
            [
                "--cfg",
                "cache_gate_layout_adversary",
                "--check-cfg=cfg(cache_gate_layout_adversary)",
            ]
        )
    _require(
        manifest["build"]
        == {
            "cargo_incremental": "0",
            "profile": "release",
            "locked": True,
            "codegen_units": 16,
            "rustc_flags": expected_rustc_flags,
            "linker_flags": [
                "-Wl,-T,<target-fragment>",
                "-Wl,-Map,<per-target-map>",
            ],
        }
        and proof["codegen_units"] == 16,
        f"{label} build proof/configuration mismatch",
    )
    aggregate: dict[str, list[str]] = {
        "cgu_partition_fingerprint": [],
        "object_member_fingerprint": [],
        "link_order_fingerprint": [],
        "reserved_input_owner_fingerprint": [],
    }
    for executable, (_target, kernel_names) in EXECUTABLE_TARGETS.items():
        item = proof["executables"][executable]
        command = item["link_command"]
        _require(
            bool(item["rustc_argv"])
            and all(
                "codegen-units=16" in line or "codegen-units 16" in line
                for line in item["rustc_argv"]
            ),
            f"{label} {executable} rustc argv lacks codegen-units=16",
        )
        _require(
            item["ordered_linker_inputs"] == command["ordered_linker_inputs"],
            f"{label} {executable} ordered linker inputs mismatch",
        )
        _require(
            item["direct_linker_input_files"] == command["direct_input_files"],
            f"{label} {executable} direct linker inputs mismatch",
        )
        fingerprint_inputs = (
            ("object_member_fingerprint", item["emitted_object_members"]),
            ("link_order_fingerprint", item["ordered_linker_inputs"]),
            ("cgu_partition_fingerprint", item["cgu_members"]),
            ("reserved_input_owner_fingerprint", item["reserved_input_owners"]),
        )
        for field, values in fingerprint_inputs:
            _require(
                item[field] == _fingerprint(values),
                f"{label} {executable} {field} mismatch",
            )
            aggregate[field].extend(f"{executable}:{value}" for value in values)
        _require(
            command["ordered_linker_input_fingerprint"]
            == _fingerprint(command["ordered_linker_inputs"]),
            f"{label} {executable} command link-order fingerprint mismatch",
        )
        layout = manifest["elf_layout"][executable]
        expected_reserved = [
            PurePosixPath(kernel["input_owner"]).name
            for kernel in layout["kernels"].values()
        ]
        _require(
            item["reserved_input_owners"] == expected_reserved,
            f"{label} {executable} reserved input owners mismatch",
        )
        _require(
            set(layout["kernels"]) == set(kernel_names)
            and all(
                layout["kernels"][kernel]["name"] == kernel for kernel in kernel_names
            ),
            f"{label} {executable} exact kernel layout mismatch",
        )
        symbol_names = [
            symbol["name"].rsplit("::", 1)[-1]
            for symbol in manifest["symbols"][executable]["symbols"]
        ]
        _require(
            len(symbol_names) == len(kernel_names)
            and set(symbol_names) == set(kernel_names),
            f"{label} {executable} exact kernel symbol set mismatch",
        )
    for field, values in aggregate.items():
        _require(
            proof[field] == _fingerprint(values),
            f"clean build proof mismatch: {label} aggregate {field}",
        )


def _verify_layout_adversary_records(manifest: dict[str, Any], label: str) -> None:
    adversary = manifest["layout_adversary"]
    _require(
        adversary["symbol"] == "cache_gate_layout_adversary_private"
        and adversary["input_section"] == ".text.opthash.cache_gate.layout_adversary",
        f"{label} adversary constants mismatch",
    )
    enabled = adversary["enabled"]
    for executable in EXECUTABLE_TARGETS:
        layout = manifest["elf_layout"][executable]
        proof = manifest["build_proof"]["executables"][executable]["adversary"]
        sections = [
            section
            for section in layout["cache_gate_input_sections"]
            if section["section"] == adversary["input_section"]
        ]
        _require(
            all(
                section["size"] > 0
                and section["end"] - section["start"] == section["size"]
                for section in sections
            ),
            f"{label} adversary section range mismatch: {executable}",
        )
        reservations = [
            (kernel["reservation_start"], kernel["reservation_end"])
            for kernel in layout["kernels"].values()
        ]
        outside = all(
            all(
                section["end"] <= start or section["start"] >= end
                for start, end in reservations
            )
            for section in sections
        )
        occurrences = proof["symbol_occurrences"]
        _require(
            proof["input_section_occurrences"] == len(sections)
            and proof["outside_reservations"] is outside,
            f"{label} adversary section occurrence/outside mismatch: {executable}",
        )
        if enabled:
            _require(
                len(sections) == len(occurrences) == 1 and outside,
                f"{label} adversary section occurrence/reservation mismatch: {executable}",
            )
            occurrence = occurrences[0]
            section = sections[0]
            _require(
                occurrence["name"].rsplit("::", 1)[-1] == adversary["symbol"]
                and occurrence["start"] == section["start"]
                and occurrence["size"] == section["size"],
                f"{label} adversary symbol/section occurrence mismatch: {executable}",
            )
        else:
            _require(
                sections == []
                and occurrences == []
                and proof["input_section_occurrences"] == 0
                and proof["outside_reservations"] is True,
                f"{label} clean adversary occurrence mismatch: {executable}",
            )


def verify_manifest_relationships(
    clean_a: dict[str, Any], clean_b: dict[str, Any], adversary: dict[str, Any]
) -> None:
    for label, manifest in (
        ("clean-a", clean_a),
        ("clean-b", clean_b),
        ("adversary", adversary),
    ):
        _validate_schema(manifest, MANIFEST_V2_SCHEMA, label)
        _validate_manifest_build_proof(manifest, label)
        _verify_layout_adversary_records(manifest, label)
        for executable, (target, kernel_names) in EXECUTABLE_TARGETS.items():
            _verify_symbol_layout_contract(
                manifest["symbols"][executable],
                manifest["elf_layout"][executable],
                target,
                kernel_names,
                f"{label}/{executable}",
            )
            _verify_layout_capability_association(
                manifest["elf_layout"][executable],
                manifest["linker_capability"],
                target,
                f"{label}/{executable}",
                executable_record=manifest["executables"][executable],
            )
    _require(
        clean_a["variant"].endswith("-clean-a")
        and clean_b["variant"].endswith("-clean-b")
        and adversary["variant"].endswith("-adversary")
        and clean_a["manifest_instance"].endswith("-clean-a")
        and clean_b["manifest_instance"].endswith("-clean-b")
        and adversary["manifest_instance"].endswith("-adversary"),
        "manifest kind mismatch",
    )
    _require(
        clean_a["layout_adversary"]["enabled"] is False
        and clean_b["layout_adversary"]["enabled"] is False
        and adversary["layout_adversary"]["enabled"] is True,
        "manifest adversary mode mismatch",
    )
    for field in (
        "commit",
        "tree",
        "architecture",
        "empty_diff_assertion",
        "mode",
    ):
        _require(
            clean_a[field] == clean_b[field] == adversary[field],
            f"manifest {field} mismatch",
        )
    _require(clean_a["build"] == clean_b["build"], "clean build mismatch")
    for field in (
        "cargo_incremental",
        "profile",
        "locked",
        "codegen_units",
        "linker_flags",
    ):
        _require(
            adversary["build"][field] == clean_a["build"][field],
            f"adversary build {field} mismatch",
        )
    clean_flags = clean_a["build"]["rustc_flags"]
    adversary_flags = adversary["build"]["rustc_flags"]
    _require(
        adversary_flags[: len(clean_flags)] == clean_flags
        and adversary_flags[len(clean_flags) :]
        == [
            "--cfg",
            "cache_gate_layout_adversary",
            "--check-cfg=cfg(cache_gate_layout_adversary)",
        ],
        "adversary build rustc flags mismatch",
    )
    for field in (
        "cgu_partition_fingerprint",
        "object_member_fingerprint",
        "link_order_fingerprint",
        "reserved_input_owner_fingerprint",
    ):
        _require(
            clean_a["build_proof"][field] == clean_b["build_proof"][field],
            f"clean build proof differs: {field}",
        )
    _require(
        _symbol_bodies(clean_a) == _symbol_bodies(clean_b),
        "clean manifest bodies differ",
    )
    _require(
        all(
            adversary["build_proof"][field] != clean_a["build_proof"][field]
            for field in (
                "cgu_partition_fingerprint",
                "object_member_fingerprint",
                "link_order_fingerprint",
            )
        ),
        "adversary difference is vacuous",
    )
    _require(
        _symbol_bodies(adversary) == _symbol_bodies(clean_a),
        "adversary semantic mismatch",
    )
    placement_fields = (
        "input_section",
        "output_section",
        "reservation_start",
        "reservation_end",
        "reservation_size",
        "page_offset",
        "max_page_remainder",
        "sh_addralign",
    )
    for executable, (_target, kernels) in EXECUTABLE_TARGETS.items():
        for kernel in kernels:
            anchor = clean_a["elf_layout"][executable]["kernels"][kernel]
            for candidate, label in (
                (clean_b, "clean"),
                (adversary, "adversary"),
            ):
                observed = candidate["elf_layout"][executable]["kernels"][kernel]
                _require(
                    all(observed[field] == anchor[field] for field in placement_fields),
                    f"{label} kernel placement mismatch: {kernel}",
                )
                body_fields = (
                    LAYOUT_BODY_FIELDS
                    if label == "clean"
                    else tuple(
                        field for field in LAYOUT_BODY_FIELDS if field != "raw_sha256"
                    )
                )
                _require(
                    all(observed[field] == anchor[field] for field in body_fields),
                    f"{label} kernel body mismatch: {kernel}",
                )
                _require(
                    observed["sentinels"] == anchor["sentinels"]
                    and observed["link_map_sentinels"] == anchor["link_map_sentinels"],
                    f"{label} kernel sentinel mismatch: {kernel}",
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
    _require(
        root_names == set(REQUIRED_ROOTS) or root_names == set(SEMANTIC_ROOTS),
        "portable root set mismatch",
    )
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
        return _verify_extracted_documents(
            root, structure.members, structure.archive_sha256
        )


def _extracted_path(root: Path, raw: str) -> Path:
    member = _canonical_member(raw)
    return root.joinpath(*member.parts)


def _open_extracted_parent(
    root: Path,
    members: dict[str, MemberRecord],
    member: PurePosixPath,
) -> tuple[int, str]:
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(root, flags)
    except OSError as error:
        raise EvidenceError(
            "cannot open extraction root without following links"
        ) from error
    try:
        parts = member.parts
        for index, component in enumerate(parts[:-1], start=1):
            prefix = PurePosixPath(*parts[:index]).as_posix()
            record = members.get(prefix)
            _require(
                record is not None and record.kind == "dir",
                f"archive ancestor is not an exact directory member: {prefix}",
            )
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as error:
                raise EvidenceError(
                    f"no-follow archive ancestor directory open failed: {prefix}"
                ) from error
            os.close(descriptor)
            descriptor = child
        return descriptor, parts[-1]
    except BaseException:
        os.close(descriptor)
        raise


def _stat_extracted(
    root: Path,
    members: dict[str, MemberRecord],
    raw: str,
) -> tuple[MemberRecord, os.stat_result]:
    member = _canonical_member(raw)
    record = members.get(member.as_posix())
    _require(record is not None, f"exact archive member is missing: {raw}")
    parent_fd, basename = _open_extracted_parent(root, members, member)
    try:
        try:
            metadata = os.stat(basename, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as error:
            raise EvidenceError(
                f"referenced archive member is missing: {raw}"
            ) from error
    finally:
        os.close(parent_fd)
    return record, metadata


def _read_extracted_link(
    root: Path,
    members: dict[str, MemberRecord],
    raw: str,
) -> str:
    member = _canonical_member(raw)
    record = members.get(member.as_posix())
    _require(
        record is not None and record.kind == "symlink",
        f"exact archive symlink member is missing: {raw}",
    )
    parent_fd, basename = _open_extracted_parent(root, members, member)
    try:
        try:
            return os.readlink(basename, dir_fd=parent_fd)
        except OSError as error:
            raise EvidenceError(
                f"cannot read archive symlink without following ancestors: {raw}"
            ) from error
    finally:
        os.close(parent_fd)


def _read_extracted(root: Path, members: dict[str, MemberRecord], raw: str) -> bytes:
    member = _canonical_member(raw)
    record = members.get(member.as_posix())
    _require(record is not None, f"exact archive member is missing: {raw}")
    _require(
        record.kind in {"file", "hardlink"},
        f"referenced archive member is not a regular file: {raw}",
    )
    parent_fd, basename = _open_extracted_parent(root, members, member)
    try:
        try:
            metadata = os.stat(basename, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as error:
            raise EvidenceError(f"referenced archive file is missing: {raw}") from error
        _require(
            stat.S_ISREG(metadata.st_mode),
            f"referenced archive path is not regular: {raw}",
        )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(basename, flags, dir_fd=parent_fd)
        except OSError as error:
            raise EvidenceError(
                f"cannot open referenced archive file without following links: {raw}"
            ) from error
    finally:
        os.close(parent_fd)
    _require(
        stat.S_ISREG(metadata.st_mode), f"referenced archive path is not regular: {raw}"
    )
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
        _record, final = _stat_extracted(root, members, raw)
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
        _require(
            (after.st_dev, after.st_ino, after.st_size)
            == (final.st_dev, final.st_ino, final.st_size),
            f"referenced archive file identity changed: {raw}",
        )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_extracted_json(
    root: Path, members: dict[str, MemberRecord], raw: str, label: str
) -> tuple[dict[str, Any], bytes]:
    data = _read_extracted(root, members, raw)
    try:
        document = _strict_json(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"invalid JSON in {label}") from error
    _require(isinstance(document, dict), f"{label} schema mismatch")
    return document, data


def _load_provenance_document(
    root: Path,
    members: dict[str, MemberRecord],
    record: dict[str, Any],
    label: str,
) -> tuple[dict[str, Any], bytes]:
    data = _load_provenance_bytes(root, members, record, label)
    try:
        document = _strict_json(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"invalid JSON in {label}") from error
    _require(isinstance(document, dict), f"{label} schema mismatch")
    return document, data


def _load_provenance_bytes(
    root: Path,
    members: dict[str, MemberRecord],
    record: dict[str, Any],
    label: str,
) -> bytes:
    raw = record["archive_path"]
    expected = _hex_sha(record["sha256"], f"{label} provenance SHA-256")
    _canonical_member(raw)
    data = _read_extracted(root, members, raw)
    _require(
        hashlib.sha256(data).hexdigest() == expected,
        f"{label} document hash mismatch",
    )
    return data


def _validate_all_structures(
    capability: dict[str, Any],
    manifests: list[dict[str, Any]],
    v1: dict[str, Any],
    v1_reextractions: dict[str, dict[str, Any]],
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
    for executable, document in v1_reextractions.items():
        _validate_schema(
            document,
            _symbol_document_schema(SYMBOL_V2_SCHEMA, veneers=True),
            f"v1_reextraction[{executable}]",
        )
    _validate_schema(provenance, PROVENANCE_SCHEMA, "provenance")
    _validate_inventory_schema(inventory)
    for index, transcript in enumerate(transcripts):
        _validate_schema(transcript, TRANSCRIPT_SCHEMA, f"transcript[{index}]")
    _validate_schema(body, BODY_COMPARISON_SCHEMA, "body_comparison")
    _validate_schema(portable, PORTABLE_PATHS_SCHEMA, "portable_paths")
    _require(
        capability["accepted"] is True,
        "capability acceptance mismatch",
    )
    _require(
        all(manifest["mode"] == "MANIFEST" for manifest in manifests),
        "v2 manifest mode mismatch",
    )
    _require(provenance["version"] == 2, "provenance version mismatch")
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
        "v1_reextraction": next(iter(v1_reextractions.values())),
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


def _verify_provenance_hardlinks(
    provenance: dict[str, Any],
    members: dict[str, MemberRecord],
    inventory: dict[str, Any],
) -> None:
    declared = {
        (record["path"], record["target"]) for record in provenance["hardlinks"]
    }
    archived = {
        (record.path, record.raw_target)
        for record in members.values()
        if record.kind == "hardlink"
    }
    inventoried = {
        (record["path"], record["target"])
        for record in inventory["entries"]
        if record["type"] == "hardlink"
    }
    _require(
        len(declared) == len(provenance["hardlinks"])
        and declared == archived == inventoried,
        "hardlink provenance mismatch with archive/inventory",
    )


def _hex_sha(value: object, label: str, *, length: int = 64) -> str:
    _require(
        isinstance(value, str)
        and len(value) == length
        and all(character in HEX_DIGITS for character in value),
        f"invalid {label}",
    )
    return value


def _verify_provenance_contract(
    root: Path,
    members: dict[str, MemberRecord],
    provenance: dict[str, Any],
    portable: dict[str, Any],
    capability: dict[str, Any],
    manifests: list[dict[str, Any]],
    v1: dict[str, Any],
) -> None:
    _require(provenance["version"] == 2, "provenance version mismatch")
    _require(
        provenance["subject"] == {"commit": SUBJECT_COMMIT, "tree": SUBJECT_TREE},
        "exact subject identity mismatch",
    )
    _require(
        provenance["v1"] == {"commit": V1_REPLAY_COMMIT, "tree": V1_REPLAY_TREE},
        "exact v1 replay identity mismatch",
    )
    orchestration = provenance["orchestration"]
    orchestration_commit = _hex_sha(
        orchestration["commit"], "orchestration commit", length=40
    )
    _hex_sha(orchestration["tree"], "orchestration tree", length=40)
    for name, expected_path in ORCHESTRATION_SOURCE_PATHS.items():
        record = orchestration["sources"][name]
        _require(
            record["archive_path"] == expected_path,
            f"orchestration source path mismatch: {name}",
        )
        _load_provenance_bytes(
            root,
            members,
            record,
            f"orchestration source {name}",
        )

    run = provenance["run"]
    _require(
        1 <= run["id"] <= 9223372036854774
        and 1 <= run["attempt"] <= 999
        and run["derived_attempt"] == run["id"] * 1000 + run["attempt"],
        "invalid run identity",
    )
    github = provenance["github"]
    repository_parts = github["repository"].split("/")
    _require(
        len(repository_parts) == 2
        and all(
            re.fullmatch(r"[A-Za-z0-9_.-]+", part) is not None
            and part not in {".", ".."}
            for part in repository_parts
        ),
        "invalid GitHub repository identity",
    )
    _require(
        github["ref"] == EXPECTED_GITHUB_REF
        and github["sha"] == orchestration_commit
        and github["run_id"] == run["id"]
        and github["run_attempt"] == run["attempt"],
        "GitHub provenance identity mismatch",
    )

    rust = provenance["rust"]
    _require(
        rust
        == {
            "toolchain": PINNED_RUST_TOOLCHAIN,
            "rustc_version": PINNED_RUSTC_VERSION,
            "cargo_version": PINNED_CARGO_VERSION,
        }
        and capability["rustc_version"] == rust["rustc_version"]
        and capability["cargo_version"] == rust["cargo_version"]
        and all(
            manifest["control"]["rustc_version"] == rust["rustc_version"]
            and manifest["control"]["cargo_version"] == rust["cargo_version"]
            for manifest in manifests
        )
        and v1["control"]["rustc_version"] == rust["rustc_version"]
        and v1["control"]["cargo_version"] == rust["cargo_version"],
        "provenance Rust toolchain identity mismatch",
    )
    packages = provenance["packages"]
    package_keys = [
        (item["name"], item["architecture"], item["version"]) for item in packages
    ]
    _require(
        all(
            all(isinstance(item[field], str) and bool(item[field]) for field in key)
            and item["verification_status"] == 0
            for item in packages
            for key in (("name", "architecture", "version"),)
        )
        and package_keys == sorted(package_keys)
        and len(package_keys) == len(set(package_keys))
        and any(item["name"] == "lld" for item in packages),
        "package provenance must be sorted, unique, verified, and include lld",
    )
    _require(
        provenance["roots"] == portable["roots"],
        "provenance roots differ from portable paths",
    )
    _require(
        provenance["system_links"] == portable["system_links"],
        "provenance system links differ from portable paths",
    )
    _require(
        provenance["proof"] == {"status": 0, "result": "PASS"},
        "proof provenance is not PASS",
    )


def _verify_mapped_file(
    root: Path,
    members: dict[str, MemberRecord],
    roots: PortableRoots,
    record: dict[str, Any],
    label: str,
) -> PurePosixPath:
    expected = _hex_sha(record["sha256"], f"{label} SHA-256")
    mapped = roots.map_path(record["absolute_path"])
    data = _read_extracted(root, members, mapped.as_posix())
    _require(hashlib.sha256(data).hexdigest() == expected, f"{label} hash mismatch")
    return mapped


def _archive_regular_file_identity(
    root: Path,
    members: dict[str, MemberRecord],
    mapped: PurePosixPath,
    label: str,
    *,
    direct_file: bool = False,
) -> tuple[int, int]:
    record, metadata = _stat_extracted(root, members, mapped.as_posix())
    _require(
        stat.S_ISREG(metadata.st_mode) and (not direct_file or record.kind == "file"),
        f"{label} lacks independent regular file identity",
    )
    return metadata.st_dev, metadata.st_ino


def _require_archived_path(
    root: Path,
    members: dict[str, MemberRecord],
    mapped: PurePosixPath,
    label: str,
) -> os.stat_result:
    try:
        _record, metadata = _stat_extracted(root, members, mapped.as_posix())
    except EvidenceError as error:
        raise EvidenceError(f"{label} is missing from archive") from error
    return metadata


def _iter_hash_file_records(
    value: object, path: tuple[str, ...] = ()
) -> list[tuple[tuple[str, ...], dict[str, Any]]]:
    records: list[tuple[tuple[str, ...], dict[str, Any]]] = []
    if isinstance(value, dict):
        if {"absolute_path", "sha256"}.issubset(value):
            records.append((path, value))
        for key, child in value.items():
            records.extend(_iter_hash_file_records(child, (*path, key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            records.extend(_iter_hash_file_records(child, (*path, str(index))))
    return records


def _verify_hash_file_records(
    root: Path,
    members: dict[str, MemberRecord],
    roots: PortableRoots,
    document: dict[str, Any],
    label: str,
) -> None:
    seen: dict[str, str] = {}
    for path, record in _iter_hash_file_records(document):
        absolute_path = record["absolute_path"]
        expected_hash = record["sha256"]
        previous = seen.setdefault(absolute_path, expected_hash)
        _require(previous == expected_hash, f"{label} duplicate file hash mismatch")
        _verify_mapped_file(
            root,
            members,
            roots,
            record,
            f"{label} {'.'.join(path)}",
        )


def _verify_subject_tool_bytes(
    root: Path,
    members: dict[str, MemberRecord],
    roots: PortableRoots,
    tools: dict[str, Any],
) -> None:
    for name, record in tools.items():
        mapped = roots.map_path(record["absolute_path"], expected_root="subject")
        data = _read_extracted(root, members, mapped.as_posix())
        blob_payload = f"blob {len(data)}\0".encode() + data
        git_blob = hashlib.sha1(blob_payload, usedforsecurity=False).hexdigest()
        _require(
            git_blob == record["git_blob"]
            and hashlib.sha256(data).hexdigest()
            == record["git_blob_sha256"]
            == record["sha256"],
            f"tool {name} archived bytes differ from exact Git blob",
        )


def _verify_path_hash_pair(
    root: Path,
    members: dict[str, MemberRecord],
    roots: PortableRoots,
    raw: str,
    expected_hash: str,
    label: str,
) -> None:
    mapped = roots.map_path(raw)
    data = _read_extracted(root, members, mapped.as_posix())
    _require(
        hashlib.sha256(data).hexdigest() == _hex_sha(expected_hash, label),
        f"{label} hash mismatch",
    )


def _verify_control_provenance(
    root: Path,
    members: dict[str, MemberRecord],
    roots: PortableRoots,
    control: dict[str, Any],
    label: str,
) -> None:
    _verify_path_hash_pair(
        root,
        members,
        roots,
        control["provenance_path"],
        control["provenance_sha256"],
        label,
    )
    mapped = roots.map_path(control["provenance_path"])
    data = _read_extracted(root, members, mapped.as_posix())
    document = _shape_json(data, label)
    _require(
        document
        == {
            key: value
            for key, value in control.items()
            if key not in {"provenance_path", "provenance_sha256"}
        },
        f"{label} content mismatch",
    )


def _verify_control_namespace(
    control: dict[str, Any], roots: PortableRoots, expected_root: str
) -> None:
    for record in (control["binary"], *control["inputs"].values()):
        roots.map_path(record["absolute_path"], expected_root=expected_root)
    roots.map_path(control["provenance_path"], expected_root=expected_root)


def _mapped_extracted_file(
    root: Path,
    members: dict[str, MemberRecord],
    roots: PortableRoots,
    raw: str,
) -> RlibArchive:
    mapped = roots.map_path(raw)
    metadata = _require_archived_path(root, members, mapped, "mapped file")
    _require(stat.S_ISREG(metadata.st_mode), "mapped file is not regular")
    return RlibArchive(
        mapped,
        _read_extracted(root, members, mapped.as_posix()),
    )


def _manifest_rlib_paths(
    root: Path,
    members: dict[str, MemberRecord],
    roots: PortableRoots,
    manifest: dict[str, Any],
    executable: str,
) -> dict[str, RlibArchive]:
    argv = manifest["build_proof"]["executables"][executable]["link_command"]["argv"]
    candidates: dict[str, RlibArchive] = {}
    duplicates: set[str] = set()
    for token in argv:
        if token.startswith("/") and token.endswith(".rlib"):
            name = PurePosixPath(token).name
            mapped = _mapped_extracted_file(root, members, roots, token)
            if name in candidates and candidates[name].path != mapped.path:
                duplicates.add(name)
            candidates[name] = mapped
    for name in duplicates:
        candidates.pop(name, None)
    return candidates


def _resolve_hosted_symlink(source: str, raw_target: str) -> PurePosixPath:
    _require(
        isinstance(raw_target, str) and bool(raw_target) and "\x00" not in raw_target,
        "invalid capability symlink target",
    )
    parts = (
        [""]
        if raw_target.startswith("/")
        else ["", *PurePosixPath(source).parent.parts[1:]]
    )
    for component in raw_target.split("/"):
        if component in {"", "."}:
            continue
        if component == "..":
            _require(len(parts) > 1, "capability symlink escapes hosted root")
            parts.pop()
        else:
            parts.append(component)
    return _canonical_absolute("/".join(parts), "capability symlink target")


def _verify_capability(
    root: Path,
    members: dict[str, MemberRecord],
    roots: PortableRoots,
    capability: dict[str, Any],
) -> None:
    _require(
        capability["accepted"] is True and capability["arch"] == "x86_64",
        "capability is not accepted native x86_64",
    )
    _require(
        capability_shapes(capability)
        == {
            (flavor, target, count)
            for flavor in ("actual", "gnu", "lld")
            for target, count in (("elastic", 2), ("funnel", 2), ("profile", 4))
        },
        "capability does not have exact actual/GNU/LLD 2/2/4 shapes",
    )
    _require(
        roots.by_name["system-root"][0] == PurePosixPath("/"),
        "system-root hosted identity must be exact /",
    )
    subject_root = roots.by_name["subject"][0].as_posix()
    _require(
        capability["producer"]["runner_root"] == subject_root,
        "capability producer root alias mismatch",
    )
    artifact_root = _canonical_absolute(
        capability["producer"]["artifact_root"], "capability artifact root"
    )
    expected_artifact_parent = (
        _canonical_absolute(subject_root, "subject root")
        / "target"
        / "cache-gate-linker"
        / capability["arch"]
    )
    _require(
        artifact_root.parent == expected_artifact_parent
        and artifact_root.name.startswith(".probe."),
        "capability artifact root identity mismatch",
    )
    fragment_lines = [
        f"{target}:{capability['fragments'][target]['sha256']}"
        for target in sorted(capability["fragments"])
    ]
    _require(
        capability["fragment_set_sha256"] == _fingerprint(fragment_lines),
        "capability fragment-set hash mismatch",
    )
    for target, fragment in capability["fragments"].items():
        _verify_mapped_file(
            root, members, roots, fragment, f"capability fragment {target}"
        )
    for flavor, targets in capability["shapes"].items():
        for target, shape in targets.items():
            for artifact_name, artifact in shape.items():
                _verify_mapped_file(
                    root,
                    members,
                    roots,
                    artifact,
                    f"capability {flavor}/{target}/{artifact_name}",
                )
    linker_records = {
        "actual": capability["linker"],
        **capability["required_linkers"],
    }
    for flavor, record in linker_records.items():
        validate_linker_record_routes(record, roots)
        chain = record["invocation_chain"]
        _require(
            chain[0]["absolute_path"] == record["invocation_path"]
            and len({item["absolute_path"] for item in chain}) == len(chain),
            "invalid capability invocation chain",
        )
        for chain_index, item in enumerate(chain):
            raw = item["absolute_path"]
            mapped = roots.map_path(raw)
            metadata = _require_archived_path(
                root,
                members,
                mapped,
                f"capability {flavor} chain member {chain_index}",
            )
            if item["symlink_target"] is None:
                _require(
                    chain_index == len(chain) - 1
                    and raw == record["payload_path"]
                    and stat.S_ISREG(metadata.st_mode),
                    "capability chain terminal identity mismatch",
                )
            else:
                _require(
                    chain_index < len(chain) - 1 and stat.S_ISLNK(metadata.st_mode),
                    "capability chain symlink type mismatch",
                )
                _require(
                    _read_extracted_link(root, members, mapped.as_posix())
                    == item["symlink_target"],
                    "capability chain raw symlink target mismatch",
                )
                _require(
                    _resolve_hosted_symlink(raw, item["symlink_target"])
                    == PurePosixPath(chain[chain_index + 1]["absolute_path"]),
                    "capability chain adjacency mismatch",
                )
        extraction_root = record["extraction_root"]
        if extraction_root is None:
            _require(
                record["argv0"] == record["payload_path"],
                "capability linker argv0 mismatch",
            )
        else:
            extracted = _canonical_absolute(extraction_root, "linker extraction root")
            invocation = _canonical_absolute(
                record["invocation_path"], "linker invocation path"
            )
            payload_path = _canonical_absolute(
                record["payload_path"], "linker payload path"
            )
            _require(
                invocation.is_relative_to(extracted)
                and payload_path.is_relative_to(extracted)
                and record["argv0"] == invocation.name,
                "capability linker extraction-root/argv0 mismatch",
            )
        terminal = roots.map_path(record["payload_path"])
        payload_metadata = _require_archived_path(
            root, members, terminal, f"capability {flavor} payload"
        )
        _require(
            stat.S_ISREG(payload_metadata.st_mode),
            "capability chain terminal is not regular",
        )
        payload = _read_extracted(root, members, terminal.as_posix())
        _require(
            hashlib.sha256(payload).hexdigest()
            == _hex_sha(record["payload_sha256"], f"capability {flavor} payload"),
            f"capability {flavor} payload hash mismatch",
        )

    def read_shape_record(flavor: str, target: str, name: str) -> bytes:
        shape = capability["shapes"][flavor][target]
        direct = {
            "link-args.txt": shape["link_argv"]["absolute_path"],
            "linker-execution.json": shape["linker_execution"]["absolute_path"],
            "symbols.json": shape["symbols"]["absolute_path"],
            "layout.json": shape["layout"]["absolute_path"],
        }
        if name == "cargo-execution.json":
            raw_path = shape["cargo_execution"]["absolute_path"]
        elif name in {"linker-trace.jsonl", "cargo-trace.jsonl"}:
            execution_key = (
                "linker_execution"
                if name == "linker-trace.jsonl"
                else "cargo_execution"
            )
            execution_data = _read_extracted(
                root,
                members,
                roots.map_path(shape[execution_key]["absolute_path"]).as_posix(),
            )
            execution = _shape_json(execution_data, "shape execution")
            raw_path = execution["trace"]["absolute_path"]
        else:
            _require(name in direct, "unknown shape record")
            raw_path = direct[name]
        return _read_extracted(root, members, roots.map_path(raw_path).as_posix())

    _require(
        verify_capability_shape_records(capability, read_shape_record, roots)
        == capability_shapes(capability),
        "capability shape record set mismatch",
    )


def _manifest_fragment_path(manifest: dict[str, Any], target: str) -> str:
    architecture = manifest["architecture"]
    variant = manifest["variant"]
    _require(
        all(
            isinstance(value, str)
            and value not in {"", ".", ".."}
            and PurePosixPath(value).name == value
            for value in (architecture, variant, target)
        ),
        "manifest fragment namespace mismatch",
    )
    return (
        _canonical_absolute(manifest["runner_root"], "manifest runner root")
        / "target"
        / "cache-gate"
        / architecture
        / variant
        / "linker-fragments"
        / f"{target}.ld"
    ).as_posix()


def _verify_manifests(
    root: Path,
    members: dict[str, MemberRecord],
    roots: PortableRoots,
    capability: dict[str, Any],
    capability_bytes: bytes,
    manifests: list[dict[str, Any]],
    v1: dict[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[tuple[str, str], dict[str, Any]],
]:
    by_kind: dict[str, dict[str, Any]] = {}
    replayed_commands: dict[tuple[str, str], dict[str, Any]] = {}
    for manifest in manifests:
        kinds = [
            kind
            for kind in ("clean-a", "clean-b", "adversary")
            if manifest["variant"].endswith(f"-{kind}")
        ]
        _require(len(kinds) == 1, "manifest kind mismatch")
        _require(kinds[0] not in by_kind, "duplicate manifest kind")
        by_kind[kinds[0]] = manifest
    _require(
        set(by_kind) == {"clean-a", "clean-b", "adversary"},
        "manifest kind set mismatch",
    )
    source_fragment_identities = {
        _archive_regular_file_identity(
            root,
            members,
            roots.map_path(fragment["absolute_path"]),
            f"capability source fragment {target}",
        )
        for target, fragment in capability["fragments"].items()
    }
    private_fragment_identities: set[tuple[int, int]] = set()
    subject_root = roots.by_name["subject"][0].as_posix()
    for manifest in manifests:
        _require(
            manifest["runner_root"] == subject_root, "manifest root alias mismatch"
        )
        _require(
            {
                key: value
                for key, value in manifest["linker_capability"].items()
                if key != "copy"
            }
            == capability,
            "embedded capability differs from original document",
        )
        _verify_hash_file_records(
            root, members, roots, manifest, f"manifest {manifest['variant']}"
        )
        _verify_subject_tool_bytes(root, members, roots, manifest["tools"])
        _require(
            _read_extracted(
                root,
                members,
                roots.map_path(
                    manifest["linker_capability"]["copy"]["absolute_path"]
                ).as_posix(),
            )
            == capability_bytes,
            "capability copy bytes differ from original document",
        )
        _verify_control_namespace(manifest["control"], roots, "subject")
        _verify_control_provenance(
            root, members, roots, manifest["control"], "control provenance"
        )
        for name, tool in manifest["tools"].items():
            _require(
                tool["reviewed_root"] == subject_root,
                f"tool {name} reviewed-root alias mismatch",
            )
        for executable in EXECUTABLE_TARGETS:
            executable_record = manifest["executables"][executable]
            symbols = manifest["symbols"][executable]
            layout = manifest["elf_layout"][executable]
            proof = manifest["build_proof"]["executables"][executable]
            target = EXECUTABLE_TARGETS[executable][0]
            expected_fragment = _manifest_fragment_path(manifest, target)
            private_identity = _archive_regular_file_identity(
                root,
                members,
                roots.map_path(expected_fragment),
                "manifest private fragment",
                direct_file=True,
            )
            _require(
                private_identity not in source_fragment_identities
                and private_identity not in private_fragment_identities,
                "manifest private fragment lacks distinct regular file identity",
            )
            private_fragment_identities.add(private_identity)
            _require(
                symbols["binary"]
                == layout["binary"]
                == proof["link_command"]["executable"]
                == executable_record["absolute_path"],
                f"{executable} binary aliases differ",
            )
            _require(
                symbols["binary_sha256"]
                == layout["binary_sha256"]
                == executable_record["sha256"],
                f"{executable} binary hashes differ",
            )
            _require(
                layout["link_map"]
                == proof["link_command"]["link_map"]
                == executable_record["link_map"]["absolute_path"],
                f"{executable} link-map aliases differ",
            )
            _require(
                executable_record["link_trace"]
                == {
                    "absolute_path": proof["link_command"]["trace"]["absolute_path"],
                    "sha256": proof["link_command"]["trace"]["sha256"],
                },
                f"{executable} link-trace aliases differ",
            )
            for artifact_label, record, embedded in (
                ("symbols", executable_record["symbols"], symbols),
                ("layout", executable_record["layout"], layout),
                (
                    "link command",
                    executable_record["link_command"],
                    proof["link_command"],
                ),
            ):
                mapped = roots.map_path(record["absolute_path"])
                document = _shape_json(
                    _read_extracted(root, members, mapped.as_posix()),
                    f"{executable} {artifact_label} artifact",
                )
                _require(
                    document == embedded,
                    f"{executable} {artifact_label} artifact differs from manifest",
                )
            command = proof["link_command"]
            trace_bytes = _read_extracted(
                root,
                members,
                roots.map_path(command["trace"]["absolute_path"]).as_posix(),
            )
            replay_key = (manifest["variant"], executable)
            _require(
                replay_key not in replayed_commands,
                "duplicate replayed manifest link command",
            )
            replayed_commands[replay_key] = verify_manifest_link_command(
                command,
                trace_bytes,
                capability,
                target,
                executable_record,
                expected_fragment=expected_fragment,
                roots=roots,
                subject_root=manifest["runner_root"],
            )
            for line in proof["rustc_argv"]:
                validate_rustc_transcript(line, roots)
            validate_command(
                proof["link_command"]["argv"],
                roots,
                rustc=False,
                has_program=False,
                cwd=manifest["runner_root"],
            )
            rlib_paths = _manifest_rlib_paths(
                root, members, roots, manifest, executable
            )

            def resolve_archive(raw: str) -> RlibArchive | None:
                if raw.startswith("/"):
                    return _mapped_extracted_file(root, members, roots, raw)
                return rlib_paths.get(PurePosixPath(raw).name)

            validate_manifest_rlib_occurrences(layout, proof, resolve_archive)
            for item in layout["cache_gate_input_sections"]:
                archive_owner = (
                    parse_rlib_owner(item["owner"])[0]
                    if ".rlib(" in item["owner"]
                    else item["owner"]
                )
                roots.map_path(archive_owner)
            for kernel in layout["kernels"].values():
                archive_owner = (
                    parse_rlib_owner(kernel["input_owner"])[0]
                    if ".rlib(" in kernel["input_owner"]
                    else kernel["input_owner"]
                )
                roots.map_path(archive_owner)
    _verify_hash_file_records(root, members, roots, v1, "v1 manifest")
    _require(
        v1["build"]
        == {
            "cargo_incremental": "0",
            "profile": "release",
            "locked": True,
            "rustc_flags": ["-C", "link-arg=-Wl,-Map,<per-target-map>"],
            "linker_flags": ["-Wl,-Map,<per-target-map>"],
        },
        "v1 build configuration mismatch",
    )
    _verify_control_namespace(v1["control"], roots, "v1")
    _verify_control_provenance(
        root, members, roots, v1["control"], "v1 control provenance"
    )
    v1_hosted = roots.by_name["v1"][0]
    for executable in EXECUTABLE_TARGETS:
        executable_record = v1["executables"][executable]
        symbols = v1["symbols"][executable]
        _require(
            symbols["binary"] == executable_record["absolute_path"]
            and symbols["binary_sha256"] == executable_record["sha256"],
            f"v1 {executable} binary aliases differ",
        )
        _require(
            PurePosixPath(executable_record["absolute_path"]).is_relative_to(v1_hosted),
            f"v1 {executable} is outside v1 root",
        )
    clean_a, clean_b, adversary = (
        by_kind["clean-a"],
        by_kind["clean-b"],
        by_kind["adversary"],
    )
    verify_manifest_relationships(clean_a, clean_b, adversary)
    _require(len(replayed_commands) == 9, "manifest link replay set mismatch")
    return clean_a, clean_b, adversary, replayed_commands


def _verify_transcripts(
    root: Path,
    members: dict[str, MemberRecord],
    roots: PortableRoots,
    transcripts: list[dict[str, Any]],
    expected: dict[tuple[str, str], dict[str, Any]],
) -> None:
    _require(len(expected) == 9, "hosted transcript expectation mismatch")
    seen: set[tuple[str, str]] = set()
    for transcript in transcripts:
        _require(
            transcript["kind"] == "link-validation" and transcript["status"] == 0,
            "hosted transcript failed",
        )
        key = (transcript["manifest_variant"], transcript["executable"])
        _require(key in expected, "unexpected hosted transcript identity")
        _require(key not in seen, "duplicate hosted transcript identity")
        seen.add(key)
        command = expected[key]
        driver = command["driver"]
        parsed_transcript = _parse_effective_link_command(transcript["argv"])
        require_ordered_equal(
            transcript["argv"], command["argv"], "hosted transcript argv"
        )
        require_ordered_equal(
            transcript["ordered_inputs"],
            command["ordered_linker_inputs"],
            "hosted transcript ordered inputs",
        )
        require_ordered_equal(
            list(parsed_transcript.inputs.ordered),
            transcript["ordered_inputs"],
            "hosted transcript parsed inputs",
        )
        _require(
            transcript["trace"] == command["trace"],
            "hosted transcript trace mismatch",
        )
        _require(
            transcript["argv0"] == driver["argv0"]
            and transcript["payload_path"] == driver["payload_path"]
            and transcript["payload_sha256"] == driver["payload_sha256"],
            "hosted transcript linker identity mismatch",
        )
        validate_command(
            transcript["argv"],
            roots,
            rustc=False,
            has_program=False,
            cwd=transcript["cwd"],
        )
        validate_linker_record_routes(driver, roots)
        _validate_linker_argv0(transcript["argv0"], roots)
        roots.map_path(transcript["cwd"], expected_root="subject")
        validate_path_list(transcript["path"], roots)
        _verify_mapped_file(
            root,
            members,
            roots,
            transcript["trace"],
            "hosted transcript trace",
        )
        trace_bytes = _read_extracted(
            root,
            members,
            roots.map_path(transcript["trace"]["absolute_path"]).as_posix(),
        )
        trace_records = [
            _shape_json(line, "hosted transcript trace record")
            for line in trace_bytes.splitlines()
            if line.strip()
        ]
        parsed_trace_records: list[tuple[dict[str, Any], EffectiveLinkCommand]] = []
        for index, record in enumerate(trace_records):
            _validate_link_trace_record(
                record, f"hosted transcript trace record {index}"
            )
            parsed_trace_records.append(
                (record, _parse_effective_link_command(record["argv"]))
            )
        trace_matches = [
            (record, parsed)
            for record, parsed in parsed_trace_records
            if parsed.outputs == (command["executable"],)
        ]
        _require(
            len(trace_records) == transcript["trace"]["record_count"]
            and transcript["trace"]["final_link_record_count"] == len(trace_matches),
            "hosted transcript trace schema/count mismatch",
        )
        _require(
            len(trace_matches) == 1,
            "hosted transcript trace lacks one final output producer",
        )
        selected_record, selected_command = trace_matches[0]
        validate_link_trace_routes(
            trace_records,
            selected_record,
            driver,
            roots,
            roots.by_name["subject"][0],
        )
        _require(
            selected_record
            == {
                "argv": transcript["argv"],
                "argv0": transcript["argv0"],
                "cwd": transcript["cwd"],
                "path": transcript["path"],
                "payload_path": transcript["payload_path"],
                "payload_sha256": transcript["payload_sha256"],
            }
            and selected_command == parsed_transcript
            and parsed_transcript.outputs == (command["executable"],),
            "hosted transcript differs from trace contents",
        )
        _verify_path_hash_pair(
            root,
            members,
            roots,
            transcript["payload_path"],
            transcript["payload_sha256"],
            "hosted transcript payload",
        )
    _require(seen == set(expected), "hosted transcript set mismatch")


def _body_records(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for executable in EXECUTABLE_TARGETS:
        for symbol in manifest["symbols"][executable]["symbols"]:
            kernel = symbol["name"].rsplit("::", 1)[-1]
            _require(kernel not in records, "duplicate body kernel")
            records[kernel] = {field: symbol[field] for field in BODY_FIELDS}
    return records


def _verify_v1_reextractions(
    clean: dict[str, Any],
    v1: dict[str, Any],
    reextractions: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    _require(
        set(reextractions) == set(EXECUTABLE_TARGETS),
        "v1 re-extraction executable set mismatch",
    )
    relative, git_blob, sha256 = SUBJECT_TOOL_IDENTITIES["extractor"]
    subject_root = clean["runner_root"]
    _require(
        clean["tools"]["extractor"]
        == {
            "absolute_path": _rooted_path(subject_root, relative),
            "sha256": sha256,
            "git_blob": git_blob,
            "git_blob_sha256": sha256,
            "reviewed_root": subject_root,
            "reviewed_commit": SUBJECT_COMMIT,
            "reviewed_tree": SUBJECT_TREE,
        },
        "v1 re-extraction current extractor identity mismatch",
    )
    all_kernels: list[str] = []
    for executable, (_target, expected_kernels) in EXECUTABLE_TARGETS.items():
        current = reextractions[executable]
        _validate_schema(
            current,
            _symbol_document_schema(SYMBOL_V2_SCHEMA, veneers=True),
            f"v1 re-extraction {executable}",
        )
        executable_record = v1["executables"][executable]
        original = v1["symbols"][executable]
        _require(
            current["binary"]
            == original["binary"]
            == executable_record["absolute_path"]
            and current["binary_sha256"]
            == original["binary_sha256"]
            == executable_record["sha256"],
            f"v1 re-extraction binary identity mismatch: {executable}",
        )
        _require(
            current["architecture"] == original["architecture"] == "x86_64",
            f"v1 re-extraction architecture mismatch: {executable}",
        )
        original_selection = [
            (symbol["name"], symbol["pattern"]) for symbol in original["symbols"]
        ]
        current_selection = [
            (symbol["name"], symbol["pattern"]) for symbol in current["symbols"]
        ]
        _require(
            len(current_selection) == len(expected_kernels)
            and current_selection == original_selection,
            f"v1 re-extraction selection/count mismatch: {executable}",
        )
        kernels = [name.rsplit("::", 1)[-1] for name, _pattern in current_selection]
        _require(
            len(kernels) == len(set(kernels)) and set(kernels) == set(expected_kernels),
            f"v1 re-extraction exact kernel selection mismatch: {executable}",
        )
        all_kernels.extend(kernels)
    _require(
        len(all_kernels) == len(set(all_kernels)) == 8,
        "v1 re-extraction must contain eight unique kernels",
    )
    return _body_records({"symbols": reextractions})


def _verify_body_contract(
    body: dict[str, Any],
    clean: dict[str, Any],
    v1: dict[str, Any],
    v1_reextractions: dict[str, dict[str, Any]],
) -> str:
    _validate_schema(body, BODY_COMPARISON_SCHEMA, "body comparison")
    _require(
        body["version"] == 1 and body["fields"] == list(BODY_FIELDS),
        "body-comparison version or fields mismatch",
    )
    digest = verify_body_rows(body["rows"])
    clean_bodies = _body_records(clean)
    v1_bodies = _verify_v1_reextractions(clean, v1, v1_reextractions)
    _require(len(clean_bodies) == 8, "clean manifest body set mismatch")
    _require(len(v1_bodies) == 8, "v1 re-extraction body set mismatch")
    _require(
        set(clean_bodies) == set(v1_bodies),
        "v1 re-extraction/v2 manifest body kernel mismatch",
    )
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


def _verify_extracted_documents(
    root: Path,
    members: dict[str, MemberRecord],
    archive_sha256: str,
) -> VerificationReport:
    provenance, _provenance_bytes = _load_extracted_json(
        root, members, "bundle/provenance.json", "provenance"
    )
    _validate_schema(provenance, PROVENANCE_SCHEMA, "provenance")
    # Provenance paths become usable only after its exact recursive schema passes.
    paths = provenance["documents"]
    manifest_records = [
        paths["manifests"]["clean_a"],
        paths["manifests"]["clean_b"],
        paths["manifests"]["adversary"],
    ]
    v1_reextraction_records = paths["v1_reextractions"]
    _require(len(paths["transcripts"]) == 9, "provenance must name nine transcripts")
    all_records = [
        *provenance["orchestration"]["sources"].values(),
        paths["capability"],
        *manifest_records,
        paths["v1_manifest"],
        *v1_reextraction_records.values(),
        *paths["transcripts"],
        paths["body_comparison"],
        paths["portable_paths"],
    ]
    _require(
        len(all_records) == len({record["archive_path"] for record in all_records}),
        "duplicate provenance document path",
    )

    capability, capability_bytes = _load_provenance_document(
        root, members, paths["capability"], "capability"
    )
    manifests_and_bytes = [
        _load_provenance_document(root, members, record, f"manifest {index}")
        for index, record in enumerate(manifest_records)
    ]
    manifests = [item[0] for item in manifests_and_bytes]
    v1, _v1_bytes = _load_provenance_document(
        root, members, paths["v1_manifest"], "v1 manifest"
    )
    v1_reextractions = {
        executable: _load_provenance_document(
            root,
            members,
            v1_reextraction_records[executable],
            f"v1 re-extraction {executable}",
        )[0]
        for executable in EXECUTABLE_TARGETS
    }
    transcripts = [
        _load_provenance_document(root, members, record, f"transcript {index}")[0]
        for index, record in enumerate(paths["transcripts"])
    ]
    inventory, _inventory_bytes = _load_extracted_json(
        root, members, "bundle/inventory.json", "inventory"
    )
    _require(
        paths["body_comparison"]["archive_path"] == "bundle/body-comparison.json"
        and paths["portable_paths"]["archive_path"] == "bundle/portable-paths.json",
        "provenance fixed document path mismatch",
    )
    _require(
        all(
            v1_reextraction_records[executable]["archive_path"]
            == f"bundle/evidence/v1-reextractions/{executable}.json"
            for executable in EXECUTABLE_TARGETS
        ),
        "provenance v1 re-extraction path mismatch",
    )
    body, _body_bytes = _load_provenance_document(
        root, members, paths["body_comparison"], "body comparison"
    )
    portable, _portable_bytes = _load_provenance_document(
        root, members, paths["portable_paths"], "portable paths"
    )

    _validate_all_structures(
        capability,
        manifests,
        v1,
        v1_reextractions,
        provenance,
        inventory,
        transcripts,
        body,
        portable,
    )
    _verify_provenance_hardlinks(provenance, members, inventory)
    roots = PortableRoots.from_document(portable)
    _require(set(roots.by_name) == set(SEMANTIC_ROOTS), "portable root set mismatch")
    expected_archives = {
        "orchestrator": PurePosixPath("bundle/orchestrator"),
        "subject": PurePosixPath("bundle/subject"),
        "v1": PurePosixPath("bundle/v1"),
        "evidence": PurePosixPath("bundle/evidence"),
        "toolchain": PurePosixPath("bundle/toolchain/rust"),
        "cargo-registry": PurePosixPath("bundle/toolchain/cargo-registry"),
        "system-root": PurePosixPath("bundle/system-root"),
    }
    for name, (_hosted, archive) in roots.by_name.items():
        _require(
            archive == expected_archives[name],
            "portable archive root alias mismatch",
        )
    for kind, document in (
        ("capability", capability),
        *(("manifest", manifest) for manifest in manifests),
        ("v1-manifest", v1),
        *(("v1-reextraction", document) for document in v1_reextractions.values()),
        ("provenance", provenance),
        ("inventory", inventory),
        *(("transcript", transcript) for transcript in transcripts),
        ("portable-paths", portable),
    ):
        validate_concrete_route_values(kind, document, roots)

    _verify_provenance_contract(
        root,
        members,
        provenance,
        portable,
        capability,
        manifests,
        v1,
    )
    verify_identity_contract(
        provenance,
        capability,
        manifests,
        v1,
        capability_bytes,
        roots.by_name["v1"][0],
    )
    verify_x86_contracts(capability, manifests, v1)
    _verify_capability(root, members, roots, capability)
    clean_a, clean_b, adversary, replayed_commands = _verify_manifests(
        root, members, roots, capability, capability_bytes, manifests, v1
    )
    _verify_transcripts(
        root,
        members,
        roots,
        transcripts,
        replayed_commands,
    )
    body_sha = _verify_body_contract(body, clean_a, v1, v1_reextractions)

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
    manifest_hashes_by_kind: dict[str, str] = {}
    for manifest, data in manifests_and_bytes:
        kinds = [
            kind
            for kind in ("clean-a", "clean-b", "adversary")
            if manifest["variant"].endswith(f"-{kind}")
        ]
        _require(len(kinds) == 1, "manifest kind mismatch")
        manifest_hashes_by_kind[kinds[0]] = hashlib.sha256(data).hexdigest()
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
