#!/usr/bin/env python3
"""Safely verify a portable native x86-64 cache-gate evidence archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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
    "raw_sha256": STRING,
    "placement": {"section": STRING, "address": INTEGER},
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
PROVENANCE_SCHEMA = {
    "version": INTEGER,
    "subject": {"commit": STRING, "tree": STRING},
    "run": {"id": INTEGER, "attempt": INTEGER, "derived_attempt": INTEGER},
    "documents": {
        "capability": DOCUMENT_RECORD_SCHEMA,
        "manifests": {
            "clean_a": DOCUMENT_RECORD_SCHEMA,
            "clean_b": DOCUMENT_RECORD_SCHEMA,
            "adversary": DOCUMENT_RECORD_SCHEMA,
        },
        "v1_manifest": DOCUMENT_RECORD_SCHEMA,
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
    del documents
    return set(PATH_ROUTES) - ROUTE_COMPATIBILITY_ALIASES


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
                    "/sbin",
                    "/usr/bin",
                    "/usr/lib",
                    "/usr/local/bin",
                    "/usr/local/lib",
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


def validate_concrete_route_values(
    document_kind: str, document: object, roots: PortableRoots
) -> None:
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
            roots.map_path(value, expected_root="system-root")
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
            validate_command(value, roots, rustc=False, has_program=False)
        elif field_kind in {"rustc-options", "rustc-options-template"}:
            _require(isinstance(value, list), f"{label} route type mismatch")
            validate_command(["rustc", *value], roots, rustc=True)
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
    for prefix in (
        "--script=",
        "--version-script=",
        "--dynamic-linker=",
        "-Map=",
        "-Map,",
        "-rpath=",
        "-rpath,",
    ):
        if value.startswith(prefix):
            roots.map_path(value[len(prefix) :])
            return
    if value.startswith("/"):
        roots.map_path(value)
        return
    _require(not _looks_path_valued(value), "unclassified path-valued link argument")


def _validate_wl_token(token: str, roots: PortableRoots) -> None:
    values = token.removeprefix("-Wl,").split(",")
    _require(all(values), "malformed -Wl argument")
    index = 0
    while index < len(values):
        value = values[index]
        if value in {"-T", "--script", "--version-script", "-Map", "-rpath"}:
            _require(index + 1 < len(values), "path-valued linker flag lacks value")
            roots.map_path(values[index + 1])
            index += 2
            continue
        _validate_link_arg(value, roots)
        index += 1


def validate_command(
    command: list[str],
    roots: PortableRoots,
    *,
    rustc: bool,
    has_program: bool = True,
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
    index = 0
    while index < len(command):
        token = command[index]
        if index == 0 and has_program:
            if "/" in token:
                roots.map_path(token)
            index += 1
            continue
        if token in {"-o", "-L", "--extern", "--out-dir", "--sysroot"}:
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
        elif token.startswith("--out-dir="):
            roots.map_path(token.removeprefix("--out-dir="))
        elif token.startswith("--sysroot="):
            roots.map_path(token.removeprefix("--sysroot="))
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
        elif token.startswith("-Wl,"):
            _validate_wl_token(token, roots)
        elif token.startswith("-B") and token != "-B":
            roots.map_path(token[2:])
        elif token == "-B":
            _require(index + 1 < len(command), "-B lacks value")
            roots.map_path(command[index + 1])
            index += 2
            continue
        elif token == "-Xlinker":
            _require(index + 1 < len(command), "-Xlinker lacks value")
            _validate_link_arg(command[index + 1], roots)
            index += 2
            continue
        elif token.startswith("@"):
            _require(token[1:].startswith("/"), "unclassified response file path")
            roots.map_path(token[1:])
        elif token.startswith("-"):
            _require(not _looks_path_valued(token), "unclassified path-valued flag")
        elif _looks_path_valued(token):
            roots.map_path(token)
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
        elif name in {"CARGO_MANIFEST_DIR", "CARGO_MANIFEST_PATH"}:
            roots.map_path(value, expected_root="cargo-registry")
        elif name == "LD_LIBRARY_PATH":
            for element in value.split(":"):
                if element:
                    roots.map_path(element)
        elif name in {"CARGO_TARGET_TMPDIR", "OUT_DIR", "RUSTC", "RUSTDOC"}:
            roots.map_path(value)
        elif name == "CARGO_ENCODED_RUSTFLAGS":
            encoded = value.replace("\x1f", " ")
            residual = encoded
            for marker in ("-Clinker=", "-Clink-arg="):
                search_from = 0
                while marker in encoded[search_from:]:
                    start = encoded.index(marker, search_from) + len(marker)
                    end = encoded.find(" ", start)
                    option = encoded[start:] if end == -1 else encoded[start:end]
                    if marker == "-Clinker=":
                        roots.map_path(option)
                    else:
                        _validate_link_arg(option, roots)
                    residual = residual.replace(f"{marker}{option}", "")
                    search_from = len(encoded) if end == -1 else end + 1
            _require(
                not _looks_path_valued(residual),
                "unclassified path-valued environment",
            )
        elif _looks_path_valued(value):
            raise EvidenceError(f"unclassified path-valued environment: {name}")
        index += 1
    _require(index < len(tokens), "rustc transcript lacks command")
    validate_command(tokens[index:], roots, rustc=True)


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


def validate_manifest_rlib_owners(owners: list[str], resolve_archive: Any) -> None:
    _require(
        isinstance(owners, list) and all(isinstance(item, str) for item in owners),
        "rlib owner list schema mismatch",
    )
    for owner in owners:
        archive_raw, member = parse_rlib_owner(owner)
        archive = resolve_archive(archive_raw)
        _require(
            isinstance(archive, Path),
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
            isinstance(archive, Path),
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


def _output_values(argv: list[str]) -> list[str]:
    outputs: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "-o":
            _require(index + 1 < len(argv), "shape output flag lacks value")
            outputs.append(argv[index + 1])
            index += 2
            continue
        if token.startswith("-o") and token != "-o":
            outputs.append(token[2:])
        index += 1
    return outputs


def _verify_shape_trace(
    execution: dict[str, Any], trace_bytes: bytes, expected_linker: dict[str, Any]
) -> None:
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
    expected_trace_keys = {
        "argv",
        "argv0",
        "cwd",
        "path",
        "payload_path",
        "payload_sha256",
        "role",
        "session",
    }
    _require(
        len(records) == trace["record_count"] and trace["final_link_record_count"] == 1,
        "shape trace counts mismatch",
    )
    matches = [record for record in records if record.get("argv") == execution["argv"]]
    _require(len(matches) == 1, "shape trace lacks exact final execution")
    record = matches[0]
    _require(set(record) == expected_trace_keys, "shape trace record schema mismatch")
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
        _output_values(execution["argv"]) == [execution["raw_output"]],
        "shape execution raw output mismatch",
    )


def verify_capability_shape_records(
    capability: dict[str, Any],
    read_record: Any,
    roots: PortableRoots | None = None,
) -> set[tuple[str, str, int]]:
    _validate_schema(capability, CAPABILITY_SCHEMA, "capability")
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
            trace_bytes = read_record(flavor, target, "linker-trace.jsonl")
            _verify_shape_trace(execution, trace_bytes, linker)
            if roots is not None:
                roots.map_path(execution["cwd"])
                validate_path_list(execution["path"], roots)
                validate_command(
                    execution["argv"], roots, rustc=False, has_program=False
                )
                roots.map_path(execution["raw_output"])

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
                _verify_shape_trace(
                    cargo,
                    read_record(flavor, target, "cargo-trace.jsonl"),
                    capability["linker"],
                )
                if roots is not None:
                    roots.map_path(cargo["cwd"])
                    validate_path_list(cargo["path"], roots)
                    validate_command(
                        cargo["argv"], roots, rustc=False, has_program=False
                    )
                    roots.map_path(cargo["raw_output"])
                driver_argv = cargo["argv"]
            _require(
                printed[4:] == driver_argv,
                "shape link argv differs from execution",
            )
            if roots is not None:
                roots.map_path(printed[3])
            fragment = capability["fragments"][target]["absolute_path"]
            link_map = shape["link_map"]["absolute_path"]
            printed_scripts = [
                token for token in driver_argv if token.startswith("-Wl,-T,")
            ]
            printed_maps = [
                token for token in driver_argv if token.startswith("-Wl,-Map,")
            ]
            _require(
                printed_scripts == [f"-Wl,-T,{fragment}"]
                and printed_maps == [f"-Wl,-Map,{link_map}"]
                and not any(token.startswith("@") for token in driver_argv),
                "shape linker controls are not exact",
            )
            selection = [
                token
                for token in driver_argv
                if token.startswith("-B/") or token.startswith("-fuse-ld=")
            ]
            if flavor == "actual":
                _require(selection == [], "actual shape linker selection is not exact")
            else:
                fuse = "bfd" if flavor == "gnu" else "lld"
                wrapper_dir = (
                    f"{capability['producer']['artifact_root']}/{flavor}/linker-wrapper"
                )
                _require(
                    selection == [f"-B{wrapper_dir}", f"-fuse-ld={fuse}"],
                    "explicit shape linker selection is not exact",
                )
                raw_scripts = [
                    (
                        token,
                        execution["argv"][index + 1]
                        if token == "-T" and index + 1 < len(execution["argv"])
                        else token[2:],
                    )
                    for index, token in enumerate(execution["argv"])
                    if token == "-T" or token.startswith("-T")
                ]
                raw_maps = [
                    (
                        token,
                        execution["argv"][index + 1]
                        if token == "-Map" and index + 1 < len(execution["argv"])
                        else token[4:],
                    )
                    for index, token in enumerate(execution["argv"])
                    if token == "-Map" or token.startswith("-Map")
                ]
                _require(
                    raw_scripts == [("-T", fragment)]
                    and raw_maps == [("-Map", link_map)]
                    and not any(token.startswith("@") for token in execution["argv"]),
                    "explicit shape raw linker controls are not exact",
                )
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


def verify_identity_contract(
    provenance: dict[str, Any],
    capability: dict[str, Any],
    manifests: list[dict[str, Any]],
    v1: dict[str, Any],
    capability_bytes: bytes,
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
    capability_sha = hashlib.sha256(capability_bytes).hexdigest()
    for manifest in manifests:
        control = manifest["control"]
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
        v1["commit"] == V1_REPLAY_COMMIT
        and v1["tree"] == V1_REPLAY_TREE
        and v1["empty_diff_assertion"] is True
        and v1["control"]["builder_commit"] == V1_REPLAY_COMMIT
        and v1["control"]["builder_tree"] == V1_REPLAY_TREE,
        "exact v1 replay identity mismatch",
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
    for executable in EXECUTABLE_TARGETS:
        record = adversary["build_proof"]["executables"][executable]["adversary"]
        _require(
            len(record["symbol_occurrences"]) == 1
            and record["input_section_occurrences"] == 1
            and record["outside_reservations"] is True,
            f"adversary symbol/section proof is not exact: {executable}",
        )
        _require(
            record["symbol_occurrences"][0]["name"].endswith(
                adversary["layout_adversary"]["symbol"]
            ),
            f"adversary symbol identity mismatch: {executable}",
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


def _load_provenance_document(
    root: Path, record: dict[str, Any], label: str
) -> tuple[dict[str, Any], bytes]:
    raw = record["archive_path"]
    expected = _hex_sha(record["sha256"], f"{label} provenance SHA-256")
    _canonical_member(raw)
    data = _read_extracted(root, raw)
    _require(
        hashlib.sha256(data).hexdigest() == expected,
        f"{label} document hash mismatch",
    )
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
    _require(
        capability["accepted"] is True,
        "capability acceptance mismatch",
    )
    _require(
        all(manifest["mode"] == "MANIFEST" for manifest in manifests),
        "v2 manifest mode mismatch",
    )
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
    root: Path, roots: PortableRoots, document: dict[str, Any], label: str
) -> None:
    seen: dict[str, str] = {}
    for path, record in _iter_hash_file_records(document):
        absolute_path = record["absolute_path"]
        expected_hash = record["sha256"]
        previous = seen.setdefault(absolute_path, expected_hash)
        _require(previous == expected_hash, f"{label} duplicate file hash mismatch")
        _verify_mapped_file(
            root,
            roots,
            record,
            f"{label} {'.'.join(path)}",
        )


def _verify_path_hash_pair(
    root: Path,
    roots: PortableRoots,
    raw: str,
    expected_hash: str,
    label: str,
) -> None:
    mapped = roots.map_path(raw)
    data = _read_extracted(root, mapped.as_posix())
    _require(
        hashlib.sha256(data).hexdigest() == _hex_sha(expected_hash, label),
        f"{label} hash mismatch",
    )


def _verify_control_provenance(
    root: Path, roots: PortableRoots, control: dict[str, Any], label: str
) -> None:
    _verify_path_hash_pair(
        root,
        roots,
        control["provenance_path"],
        control["provenance_sha256"],
        label,
    )
    mapped = roots.map_path(control["provenance_path"])
    data = _read_extracted(root, mapped.as_posix())
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


def _mapped_extracted_file(root: Path, roots: PortableRoots, raw: str) -> Path:
    mapped = roots.map_path(raw)
    metadata = _require_archived_path(root, mapped, "mapped file")
    _require(stat.S_ISREG(metadata.st_mode), "mapped file is not regular")
    return _extracted_path(root, mapped.as_posix())


def _manifest_rlib_paths(
    root: Path, roots: PortableRoots, manifest: dict[str, Any], executable: str
) -> dict[str, Path]:
    argv = manifest["build_proof"]["executables"][executable]["link_command"]["argv"]
    candidates: dict[str, Path] = {}
    duplicates: set[str] = set()
    for token in argv:
        if token.startswith("/") and token.endswith(".rlib"):
            name = PurePosixPath(token).name
            mapped = _mapped_extracted_file(root, roots, token)
            if name in candidates and candidates[name] != mapped:
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
    root: Path, roots: PortableRoots, capability: dict[str, Any]
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
        _verify_mapped_file(root, roots, fragment, f"capability fragment {target}")
    for flavor, targets in capability["shapes"].items():
        for target, shape in targets.items():
            for artifact_name, artifact in shape.items():
                _verify_mapped_file(
                    root,
                    roots,
                    artifact,
                    f"capability {flavor}/{target}/{artifact_name}",
                )
    linker_records = {
        "actual": capability["linker"],
        **capability["required_linkers"],
    }
    for flavor, record in linker_records.items():
        chain = record["invocation_chain"]
        _require(
            chain[0]["absolute_path"] == record["invocation_path"]
            and len({item["absolute_path"] for item in chain}) == len(chain),
            "invalid capability invocation chain",
        )
        for chain_index, item in enumerate(chain):
            raw = item["absolute_path"]
            mapped = roots.map_path(raw, expected_root="system-root")
            metadata = _require_archived_path(
                root, mapped, f"capability {flavor} chain member {chain_index}"
            )
            hosted_path = _extracted_path(root, mapped.as_posix())
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
                    os.readlink(hosted_path) == item["symlink_target"],
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
        terminal = roots.map_path(record["payload_path"], expected_root="system-root")
        payload_metadata = _require_archived_path(
            root, terminal, f"capability {flavor} payload"
        )
        _require(
            stat.S_ISREG(payload_metadata.st_mode),
            "capability chain terminal is not regular",
        )
        payload = _read_extracted(root, terminal.as_posix())
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
                roots.map_path(shape[execution_key]["absolute_path"]).as_posix(),
            )
            execution = _shape_json(execution_data, "shape execution")
            raw_path = execution["trace"]["absolute_path"]
        else:
            _require(name in direct, "unknown shape record")
            raw_path = direct[name]
        return _read_extracted(root, roots.map_path(raw_path).as_posix())

    _require(
        verify_capability_shape_records(capability, read_shape_record, roots)
        == capability_shapes(capability),
        "capability shape record set mismatch",
    )


def _verify_manifests(
    root: Path,
    roots: PortableRoots,
    capability: dict[str, Any],
    capability_bytes: bytes,
    manifests: list[dict[str, Any]],
    v1: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    by_kind: dict[str, dict[str, Any]] = {}
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
            root, roots, manifest, f"manifest {manifest['variant']}"
        )
        _require(
            _read_extracted(
                root,
                roots.map_path(
                    manifest["linker_capability"]["copy"]["absolute_path"]
                ).as_posix(),
            )
            == capability_bytes,
            "capability copy bytes differ from original document",
        )
        _verify_control_provenance(
            root, roots, manifest["control"], "control provenance"
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
                    _read_extracted(root, mapped.as_posix()),
                    f"{executable} {artifact_label} artifact",
                )
                _require(
                    document == embedded,
                    f"{executable} {artifact_label} artifact differs from manifest",
                )
            for line in proof["rustc_argv"]:
                validate_rustc_transcript(line, roots)
            validate_command(
                proof["link_command"]["argv"],
                roots,
                rustc=False,
                has_program=False,
            )
            rlib_paths = _manifest_rlib_paths(root, roots, manifest, executable)

            def resolve_archive(raw: str) -> Path | None:
                if raw.startswith("/"):
                    return _mapped_extracted_file(root, roots, raw)
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
    _verify_hash_file_records(root, roots, v1, "v1 manifest")
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
    _verify_control_provenance(root, roots, v1["control"], "v1 control provenance")
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
    return clean_a, clean_b, adversary


def _verify_transcripts(
    root: Path,
    roots: PortableRoots,
    transcripts: list[dict[str, Any]],
    manifests: tuple[dict[str, Any], dict[str, Any], dict[str, Any]],
) -> None:
    expected: dict[tuple[str, str], dict[str, Any]] = {}
    for manifest in manifests:
        for executable in EXECUTABLE_TARGETS:
            key = (manifest["variant"], executable)
            _require(key not in expected, "duplicate hosted transcript identity")
            expected[key] = manifest["build_proof"]["executables"][executable][
                "link_command"
            ]
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
        require_ordered_equal(
            transcript["argv"], command["argv"], "hosted transcript argv"
        )
        require_ordered_equal(
            transcript["ordered_inputs"],
            command["ordered_linker_inputs"],
            "hosted transcript ordered inputs",
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
        validate_command(transcript["argv"], roots, rustc=False, has_program=False)
        roots.map_path(transcript["argv0"], expected_root="system-root")
        roots.map_path(transcript["cwd"], expected_root="subject")
        validate_path_list(transcript["path"], roots)
        _verify_mapped_file(root, roots, transcript["trace"], "hosted transcript trace")
        trace_bytes = _read_extracted(
            root, roots.map_path(transcript["trace"]["absolute_path"]).as_posix()
        )
        trace_records = [
            _shape_json(line, "hosted transcript trace record")
            for line in trace_bytes.splitlines()
            if line.strip()
        ]
        trace_keys = {
            "argv",
            "argv0",
            "cwd",
            "path",
            "payload_path",
            "payload_sha256",
        }
        _require(
            len(trace_records) == transcript["trace"]["record_count"]
            and transcript["trace"]["final_link_record_count"] == 1
            and all(set(record) == trace_keys for record in trace_records),
            "hosted transcript trace schema/count mismatch",
        )
        for record in trace_records:
            validate_command(record["argv"], roots, rustc=False, has_program=False)
            roots.map_path(record["argv0"], expected_root="system-root")
            roots.map_path(record["cwd"])
            validate_path_list(record["path"], roots)
            roots.map_path(record["payload_path"], expected_root="system-root")
        trace_matches = [
            record
            for record in trace_records
            if record
            == {
                "argv": transcript["argv"],
                "argv0": transcript["argv0"],
                "cwd": transcript["cwd"],
                "path": transcript["path"],
                "payload_path": transcript["payload_path"],
                "payload_sha256": transcript["payload_sha256"],
            }
        ]
        _require(
            len(trace_matches) == 1
            and _output_values(transcript["argv"]) == [command["executable"]],
            "hosted transcript differs from trace contents",
        )
        _verify_path_hash_pair(
            root,
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
            records[kernel] = {
                "size": symbol["size"],
                "normalized_instructions_sha256": symbol[
                    "normalized_instructions_sha256"
                ],
                "direct_calls": symbol["direct_calls"],
                "indirect_calls": symbol["indirect_calls"],
                "frame_adjustment": symbol["frame_adjustment"],
                "spills": symbol["spills"],
                "raw_sha256": symbol["raw_sha256"],
                "placement": {
                    "section": symbol["section"],
                    "address": symbol["start"],
                },
            }
    return records


def _verify_body_contract(
    body: dict[str, Any], clean: dict[str, Any], v1: dict[str, Any]
) -> str:
    digest = verify_body_rows(body["rows"])
    clean_bodies = _body_records(clean)
    v1_bodies = _body_records(v1)
    _require(len(clean_bodies) == 8, "clean manifest body set mismatch")
    _require(len(v1_bodies) == 8, "v1 manifest body set mismatch")
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
    manifest_records = [
        paths["manifests"]["clean_a"],
        paths["manifests"]["clean_b"],
        paths["manifests"]["adversary"],
    ]
    _require(len(paths["transcripts"]) == 9, "provenance must name nine transcripts")
    all_records = [
        paths["capability"],
        *manifest_records,
        paths["v1_manifest"],
        *paths["transcripts"],
        paths["body_comparison"],
        paths["portable_paths"],
    ]
    _require(
        len(all_records) == len({record["archive_path"] for record in all_records}),
        "duplicate provenance document path",
    )

    capability, capability_bytes = _load_provenance_document(
        root, paths["capability"], "capability"
    )
    manifests_and_bytes = [
        _load_provenance_document(root, record, f"manifest {index}")
        for index, record in enumerate(manifest_records)
    ]
    manifests = [item[0] for item in manifests_and_bytes]
    v1, _v1_bytes = _load_provenance_document(root, paths["v1_manifest"], "v1 manifest")
    transcripts = [
        _load_provenance_document(root, record, f"transcript {index}")[0]
        for index, record in enumerate(paths["transcripts"])
    ]
    inventory, _inventory_bytes = _load_extracted_json(
        root, "bundle/inventory.json", "inventory"
    )
    _require(
        paths["body_comparison"]["archive_path"] == "bundle/body-comparison.json"
        and paths["portable_paths"]["archive_path"] == "bundle/portable-paths.json",
        "provenance fixed document path mismatch",
    )
    body, _body_bytes = _load_provenance_document(
        root, paths["body_comparison"], "body comparison"
    )
    portable, _portable_bytes = _load_provenance_document(
        root, paths["portable_paths"], "portable paths"
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
        ("provenance", provenance),
        ("inventory", inventory),
        *(("transcript", transcript) for transcript in transcripts),
        ("portable-paths", portable),
    ):
        validate_concrete_route_values(kind, document, roots)

    verify_identity_contract(provenance, capability, manifests, v1, capability_bytes)
    _verify_capability(root, roots, capability)
    clean_a, clean_b, adversary = _verify_manifests(
        root, roots, capability, capability_bytes, manifests, v1
    )
    _verify_transcripts(root, roots, transcripts, (clean_a, clean_b, adversary))
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
