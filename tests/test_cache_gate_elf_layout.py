import base64
import copy
import ctypes
import errno
import hashlib
import json
import os
import runpy
import shlex
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "cache-gate-elf-layout.py"
LAUNCHER = ROOT / "scripts" / "cache-gate.sh"
LINK_WRAPPER = ROOT / "scripts" / "cache-gate-link-wrapper.py"
LINK_CAPABILITY = ROOT / "scripts" / "cache-gate-linker-capability.sh"
MAP_FIXTURES = ROOT / "tests" / "fixtures" / "cache_gate_link_maps"

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
    "elastic": tuple(
        name for name, spec in KERNELS.items() if spec["target"] == "elastic"
    ),
    "funnel": tuple(
        name for name, spec in KERNELS.items() if spec["target"] == "funnel"
    ),
    "profile": tuple(
        name for name, spec in KERNELS.items() if spec["target"] == "profile"
    ),
}
assert tuple(map(len, TARGET_KERNELS.values())) == (2, 2, 4)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_cargo_output_pair(tmp_path: Path, target: str = "probe") -> tuple[Path, Path]:
    release = tmp_path / target / "release"
    deps = release / "deps"
    deps.mkdir(parents=True)
    raw_output = deps / f"{target}-0123456789abcdef"
    raw_output.write_bytes(b"ELF fixture\n")
    binary = release / target
    os.link(raw_output, binary)
    return binary, raw_output


def make_manifest(tmp_path: Path) -> dict:
    max_page = 65536
    fragments = {
        target: hashlib.sha256(target.encode()).hexdigest() for target in TARGET_KERNELS
    }
    fragment_set = hashlib.sha256(
        "\n".join(
            f"{name}:{value}" for name, value in sorted(fragments.items())
        ).encode()
    ).hexdigest()
    executables = {}
    layouts = {}
    for target_index, (target, kernel_names) in enumerate(TARGET_KERNELS.items()):
        binary = tmp_path / f"{target}.bin"
        binary.write_bytes(f"ELF fixture {target}\n".encode())
        link_map = tmp_path / f"{target}.map"
        link_map.write_text("fixture map\n")
        executable_name = {
            "elastic": "elastic_cache_gate",
            "funnel": "funnel_cache_gate",
            "profile": "cache_gate_profile",
        }[target]
        executables[executable_name] = {
            "absolute_path": str(binary.resolve()),
            "sha256": digest(binary),
            "link_map": {
                "absolute_path": str(link_map.resolve()),
                "sha256": digest(link_map),
            },
        }
        kernels = {}
        for kernel_index, name in enumerate(kernel_names):
            spec = KERNELS[name]
            start = (target_index * 8 + kernel_index + 1) * max_page
            body_end = start + 128 + kernel_index * 4
            end = start + max_page
            sentinels = {
                key: {
                    "name": spec[key],
                    "address": {
                        "reservation_start": start,
                        "body_end": body_end,
                        "reservation_end": end,
                    }[key],
                    "binding": "GLOBAL",
                    "visibility": "DEFAULT",
                    "defined": True,
                    "count": 1,
                }
                for key in ("reservation_start", "body_end", "reservation_end")
            }
            kernels[name] = {
                "name": name,
                "function_symbol_count": 1,
                "input_section": spec["input"],
                "input_section_count": 1,
                "input_owner": f"fixture.{target}.{kernel_index}.o",
                "input_start": start,
                "input_end": body_end,
                "input_size": body_end - start,
                "output_section": spec["output"],
                "output_section_count": 1,
                "output_section_index": kernel_index + 1,
                "output_start": start,
                "output_end": end,
                "reservation_start": start,
                "body_end": body_end,
                "reservation_end": end,
                "body_size": body_end - start,
                "reservation_size": max_page,
                "page_offset": 0,
                "max_page_remainder": 0,
                "sh_addralign": max_page,
                "section_flags": ["ALLOC", "EXECINSTR"],
                "pt_load_count": 1,
                "pt_load_flags": "R E",
                "writable_segment_overlap": False,
                "overlapping_elf_sections": [],
                "sentinels": sentinels,
                "link_map_sentinels": {
                    key: value["address"] for key, value in sentinels.items()
                },
                "raw_sha256": hashlib.sha256(f"raw:{name}".encode()).hexdigest(),
                "function_start": start,
                "function_end": body_end,
                "function_size": body_end - start,
                "function_section_index": kernel_index + 1,
                "function_section_name": spec["output"],
                "normalized_sha256": hashlib.sha256(
                    f"normalized:{name}".encode()
                ).hexdigest(),
                "direct_calls": [],
                "indirect_calls": [],
                "frame_bytes": 0,
                "spills": [],
                "veneer_thunks": [],
                "plt_calls": [],
            }
        layouts[executable_name] = {
            "target": target,
            "arch": "aarch64",
            "link_map_flavor": "gnu",
            "elf_type": "ET_DYN",
            "binary": str(binary.resolve()),
            "binary_sha256": digest(binary),
            "link_map": str(link_map.resolve()),
            "link_map_sha256": digest(link_map),
            "fragment_sha256": fragments[target],
            "fragment_set_sha256": fragment_set,
            "max_page_size": max_page,
            "program_headers_have_rwx": False,
            "kernels": kernels,
            "veneer_thunk_inventory": [],
            "plt_inventory": [],
        }
    return {
        "commit": "a" * 40,
        "tree": "b" * 40,
        "architecture": "aarch64",
        "runner_root": str(ROOT.resolve()),
        "executables": executables,
        "linker_capability": {
            "accepted": True,
            "arch": "aarch64",
            "linker": {
                "absolute_path": "/usr/bin/ld",
                "flavor": "GNU ld",
                "version": "GNU ld 2.42",
            },
            "max_page_size": max_page,
            "fragments": fragments,
            "fragment_set_sha256": fragment_set,
        },
        "elf_layout": layouts,
    }


def run_compare(
    tmp_path: Path,
    anchor: dict,
    candidate: dict | None = None,
    *extra: str,
) -> subprocess.CompletedProcess[str]:
    anchor_path = tmp_path / "anchor.json"
    candidate_path = tmp_path / "candidate.json"
    anchor_path.write_text(json.dumps(anchor))
    candidate_path.write_text(
        json.dumps(candidate if candidate is not None else anchor)
    )
    return subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "compare",
            "--anchor",
            str(anchor_path.resolve()),
            "--candidate",
            str(candidate_path.resolve()),
            *extra,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


def run_validate_manifest(
    tmp_path: Path, manifest: dict, *extra: str
) -> subprocess.CompletedProcess[str]:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    return subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "validate-manifest",
            "--manifest",
            str(manifest_path.resolve()),
            *extra,
        ],
        text=True,
        capture_output=True,
    )


def one_kernel(manifest: dict, name: str) -> dict:
    executable = {
        "elastic": "elastic_cache_gate",
        "funnel": "funnel_cache_gate",
        "profile": "cache_gate_profile",
    }[KERNELS[name]["target"]]
    return manifest["elf_layout"][executable]["kernels"][name]


def write_validate_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flavor: str
) -> tuple[list[str], Path]:
    start = 0x10000 if flavor == "gnu" else 0x20000
    binary = tmp_path / "elastic"
    binary.write_bytes(b"captured ELF fixture\n")
    fragment = ROOT / "benches" / "cache-gate-elastic-layout.ld"
    link_map = tmp_path / "elastic.map"
    link_map.write_bytes((MAP_FIXTURES / f"{flavor}-elastic.map").read_bytes())
    selected = []
    for index, name in enumerate(TARGET_KERNELS["elastic"]):
        spec = KERNELS[name]
        kernel_start = start + index * 0x10000
        selected.append(
            {
                "name": f"fixture::{name}",
                "start": kernel_start,
                "end": kernel_start + 0x20,
                "size": 0x20,
                "section": spec["output"],
                "section_name": spec["output"],
                "section_index": index + 1,
                "raw_sha256": hashlib.sha256(f"raw:{name}".encode()).hexdigest(),
                "normalized_instructions_sha256": hashlib.sha256(
                    f"normalized:{name}".encode()
                ).hexdigest(),
                "direct_calls": [],
                "indirect_calls": [],
                "frame_adjustment": 0,
                "spills": [],
            }
        )
    symbols = tmp_path / "symbols.json"
    symbols.write_text(
        json.dumps({"symbols": selected, "linker_generated_veneer_thunks": []})
    )
    capability = tmp_path / "capability.json"
    capability.write_text(
        json.dumps(
            {
                "accepted": True,
                "arch": "aarch64",
                "max_page_size": 0x10000,
                "fragment_set_sha256": "f" * 64,
                "fragments": {
                    "elastic": {
                        "absolute_path": str(fragment.resolve()),
                        "sha256": digest(fragment),
                    }
                },
            }
        )
    )
    readelf_root = tmp_path / "readelf"
    readelf_root.mkdir()
    (readelf_root / "header.txt").write_text(
        "  Type:                              DYN (Position-Independent Executable file)\n"
    )
    section_lines = []
    symbol_lines = []
    for index, name in enumerate(TARGET_KERNELS["elastic"]):
        spec = KERNELS[name]
        kernel_start = start + index * 0x10000
        section_lines.append(
            f"  [ {index + 1}] {spec['output']} PROGBITS {kernel_start:016x} {kernel_start:06x} 010000 00 AX 0 0 4"
        )
        for symbol_index, key in enumerate(
            ("reservation_start", "body_end", "reservation_end"), start=1
        ):
            address = {
                "reservation_start": kernel_start,
                "body_end": kernel_start + 0x20,
                "reservation_end": kernel_start + 0x10000,
            }[key]
            symbol_lines.append(
                f" {index * 3 + symbol_index}: {address:016x} 0 NOTYPE GLOBAL DEFAULT {index + 1} {spec[key]}"
            )
    (readelf_root / "sections.txt").write_text("\n".join(section_lines) + "\n")
    (readelf_root / "segments.txt").write_text(
        f"  LOAD 0x000000 {start:#018x} {start:#018x} 0x020000 0x020000 R E 0x10000\n"
    )
    (readelf_root / "symbols.txt").write_text("\n".join(symbol_lines) + "\n")
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    fake_readelf = fake_bin / "readelf"
    fake_readelf.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        f"  -hW) exec /bin/cat {readelf_root / 'header.txt'} ;;\n"
        f"  -SW) exec /bin/cat {readelf_root / 'sections.txt'} ;;\n"
        f"  -lW) exec /bin/cat {readelf_root / 'segments.txt'} ;;\n"
        f"  -sW) exec /bin/cat {readelf_root / 'symbols.txt'} ;;\n"
        "esac\n"
        "exit 2\n"
    )
    fake_readelf.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}:{os.environ['PATH']}")
    monkeypatch.setenv("CACHE_GATE_LINKER_CAPABILITY", str(capability.resolve()))
    output = tmp_path / "layout.json"
    argv = [
        "python3",
        str(SCRIPT),
        "validate",
        "--binary",
        str(binary.resolve()),
        "--link-map",
        str(link_map.resolve()),
        "--script",
        str(fragment.resolve()),
        "--symbols",
        str(symbols.resolve()),
        "--arch",
        "aarch64",
        "--output",
        str(output.resolve()),
    ]
    return argv, output


@pytest.mark.parametrize("flavor", ["gnu", "lld"])
def test_validate_accepts_captured_gnu_and_lld_maps(tmp_path, monkeypatch, flavor):
    argv, output = write_validate_fixture(tmp_path, monkeypatch, flavor)
    completed = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True)
    assert completed.returncode == 0, completed.stderr
    layout = json.loads(output.read_text())
    assert layout["link_map_flavor"] == flavor
    assert len(layout["cache_gate_input_sections"]) == 2
    assert layout["archive_member_owners"] == []
    for kernel in layout["kernels"].values():
        assert kernel["input_start"] == kernel["reservation_start"]
        assert kernel["input_end"] == kernel["body_end"]
        assert kernel["function_start"] == kernel["input_start"]
        assert kernel["function_end"] == kernel["input_end"]


def test_validate_rejects_compact_rwe_program_header_outside_reservations(
    tmp_path, monkeypatch
):
    argv, _ = write_validate_fixture(tmp_path, monkeypatch, "gnu")
    segments = tmp_path / "readelf" / "segments.txt"
    with segments.open("a", encoding="utf-8") as stream:
        stream.write(
            "  LOAD 0x030000 0x0000000000040000 0x0000000000040000 "
            "0x001000 0x001000 RWE 0x1000\n"
        )
    completed = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True)
    assert completed.returncode != 0
    assert "program header is RWX" in completed.stderr


@pytest.mark.parametrize("flavor", ["gnu", "lld"])
def test_validate_records_map_owners_only_for_archive_members(
    tmp_path, monkeypatch, flavor
):
    argv, output = write_validate_fixture(tmp_path, monkeypatch, flavor)
    link_map = tmp_path / "elastic.map"
    direct_owner = f"/captured/{flavor}/elastic.fixture.rcgu.o"
    archive_owner = f"/captured/{flavor}/libelastic.rlib(elastic.fixture.rcgu.o)"
    link_map.write_text(link_map.read_text().replace(direct_owner, archive_owner))
    completed = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True)
    assert completed.returncode == 0, completed.stderr
    layout = json.loads(output.read_text())
    assert layout["archive_member_owners"] == [archive_owner]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("wrong_parent", "exact output section"),
        ("missing_owner", "input owner"),
        ("wrong_extent", "input end"),
        ("wrong_function_section", "selected function section"),
        ("wrong_function_range", "selected function range"),
    ],
)
def test_validate_rejects_structural_map_or_function_mismatch(
    tmp_path, monkeypatch, mutation, message
):
    argv, _ = write_validate_fixture(tmp_path, monkeypatch, "gnu")
    link_map = Path(argv[argv.index("--link-map") + 1])
    symbols = Path(argv[argv.index("--symbols") + 1])
    if mutation == "wrong_parent":
        text = link_map.read_text()
        input_block = (
            " .text.opthash.cache_gate.elastic.insert\n"
            "                0x0000000000010000       0x20 /captured/gnu/elastic.fixture.rcgu.o\n"
        )
        link_map.write_text(
            text.replace(input_block, "").replace(
                ".text           ", input_block + ".text           "
            )
        )
    elif mutation == "missing_owner":
        link_map.write_text(
            link_map.read_text().replace(" /captured/gnu/elastic.fixture.rcgu.o", "", 1)
        )
    elif mutation == "wrong_extent":
        link_map.write_text(
            link_map.read_text().replace(
                "0x0000000000010000       0x20", "0x0000000000010000       0x10", 1
            )
        )
    else:
        payload = json.loads(symbols.read_text())
        if mutation == "wrong_function_section":
            payload["symbols"][0]["section_name"] = ".text"
        else:
            payload["symbols"][0]["end"] -= 4
            payload["symbols"][0]["size"] -= 4
        symbols.write_text(json.dumps(payload))
    completed = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True)
    assert completed.returncode != 0
    assert message in completed.stderr


def test_authenticate_tools_rejects_dirty_blob_and_mixed_roots(tmp_path):
    roots = [tmp_path / "one", tmp_path / "two"]
    tools = []
    for index, root in enumerate(roots):
        root.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        tool = root / f"tool-{index}.sh"
        tool.write_text("#!/bin/sh\nexit 0\n")
        tool.chmod(0o755)
        subprocess.run(["git", "add", tool.name], cwd=root, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "-qm",
                "fixture",
            ],
            cwd=root,
            check=True,
        )
        tools.append(tool.resolve())
    output = tmp_path / "tools.json"
    base = [
        "python3",
        str(SCRIPT),
        "authenticate-tools",
        "--output",
        str(output.resolve()),
    ]
    accepted = subprocess.run(
        [*base, "--tool", f"first={tools[0]}"], text=True, capture_output=True
    )
    assert accepted.returncode == 0, accepted.stderr
    tools[0].write_text("#!/bin/sh\nexit 1\n")
    dirty = subprocess.run(
        [*base, "--tool", f"first={tools[0]}"], text=True, capture_output=True
    )
    assert dirty.returncode != 0
    assert "reviewed Git blob" in dirty.stderr
    mixed = subprocess.run(
        [
            *base,
            "--tool",
            f"first={roots[0] / 'tool-0.sh'}",
            "--tool",
            f"second={tools[1]}",
        ],
        text=True,
        capture_output=True,
    )
    assert mixed.returncode != 0
    assert "one reviewed root" in mixed.stderr


def test_validate_link_command_binds_real_driver_and_final_output(tmp_path):
    driver = tmp_path / "cc-fixture"
    driver.write_text("#!/bin/sh\necho 'GNU ld fixture 1.0'\n")
    driver.chmod(0o755)
    executable = tmp_path / "bench"
    executable.write_bytes(b"ELF\n")
    fragment = tmp_path / "layout.ld"
    fragment.write_text("SECTIONS {}\n")
    link_map = tmp_path / "bench.map"
    link_map.write_text("map\n")
    first_object = tmp_path / "first.rcgu.o"
    first_object.write_bytes(b"object one\n")
    second_object = tmp_path / "second.rcgu.o"
    second_object.write_bytes(b"object two\n")
    archive = tmp_path / "libfixture.rlib"
    archive.write_bytes(b"archive\n")
    capability = tmp_path / "capability.json"
    capability.write_text(
        json.dumps(
            {
                "linker": {
                    "absolute_path": str(driver.resolve()),
                    "sha256": digest(driver),
                    "flavor": "GNU ld",
                    "version": "GNU ld fixture 1.0",
                }
            }
        )
    )
    trace = tmp_path / "trace.jsonl"
    trace.write_text(
        json.dumps(
            {
                "driver": str(driver.resolve()),
                "driver_sha256": digest(driver),
                "argv": [
                    str(first_object.resolve()),
                    str(second_object.resolve()),
                    str(archive.resolve()),
                    "-lgcc_s",
                    "-o",
                    str(executable.resolve()),
                    f"-Wl,-T,{fragment.resolve()}",
                    f"-Wl,-Map,{link_map.resolve()}",
                ],
            }
        )
        + "\n"
    )
    output = tmp_path / "link-command.json"
    command = [
        "python3",
        str(SCRIPT),
        "validate-link-command",
        "--trace",
        str(trace.resolve()),
        "--executable",
        str(executable.resolve()),
        "--capability",
        str(capability.resolve()),
        "--fragment",
        str(fragment.resolve()),
        "--link-map",
        str(link_map.resolve()),
        "--output",
        str(output.resolve()),
    ]
    accepted = subprocess.run(command, text=True, capture_output=True)
    assert accepted.returncode == 0, accepted.stderr
    record = json.loads(output.read_text())
    assert record["driver"]["absolute_path"] == str(driver.resolve())
    assert record["ordered_linker_inputs"] == [
        first_object.name,
        second_object.name,
        archive.name,
        "-lgcc_s",
    ]
    assert record["direct_input_files"] == sorted(
        [first_object.name, second_object.name, archive.name]
    )
    original_fingerprint = record["ordered_linker_input_fingerprint"]
    payload = json.loads(trace.read_text())
    payload["argv"][:2] = reversed(payload["argv"][:2])
    trace.write_text(json.dumps(payload) + "\n")
    reordered = subprocess.run(command, text=True, capture_output=True)
    assert reordered.returncode == 0, reordered.stderr
    reordered_record = json.loads(output.read_text())
    assert reordered_record["direct_input_files"] == record["direct_input_files"]
    assert reordered_record["ordered_linker_input_fingerprint"] != original_fingerprint
    trace.write_text(trace.read_text().replace("-Wl,-T,", "-fuse-ld=lld -Wl,-T,"))
    rejected = subprocess.run(command, text=True, capture_output=True)
    assert rejected.returncode != 0
    assert "linker controls are not exact" in rejected.stderr


@pytest.mark.parametrize("attack", ["conflicting-controls", "response", "xresponse"])
def test_main_link_replay_rejects_hidden_or_conflicting_controls(tmp_path, attack):
    namespace = runpy.run_path(str(SCRIPT))
    driver = tmp_path / "cc"
    driver.write_text("#!/bin/sh\nexit 0\n")
    driver.chmod(0o755)
    executable = tmp_path / "bench"
    executable.write_bytes(b"ELF\n")
    fragment = tmp_path / "layout.ld"
    fragment.write_text("SECTIONS {}\n")
    link_map = tmp_path / "bench.map"
    link_map.write_text("map\n")
    obj = tmp_path / "input.o"
    obj.write_bytes(b"object\n")
    response = tmp_path / "hidden.rsp"
    response.write_text("--script=/evil.ld\n")
    argv = [
        str(obj),
        "-o",
        str(executable),
        f"-Wl,-T,{fragment}",
        f"-Wl,-Map,{link_map}",
    ]
    if attack == "conflicting-controls":
        argv.extend(("-Wl,--script,/evil.ld", "-Wl,-Map,/evil.map"))
    elif attack == "response":
        argv.append(f"-Wl,@{response}")
    else:
        argv.extend(("-Xlinker", f"@{response}"))
    trace = tmp_path / "trace.jsonl"
    trace.write_text(
        json.dumps(
            {
                "driver": str(driver.resolve()),
                "driver_sha256": digest(driver),
                "argv": argv,
            }
        )
        + "\n"
    )
    linker = {
        "absolute_path": str(driver.resolve()),
        "sha256": digest(driver),
        "flavor": "GNU ld",
        "version": "GNU ld fixture",
    }

    with pytest.raises(ValueError, match="linker (controls|response files)"):
        namespace["replay_link_command"](trace, executable, linker, fragment, link_map)


def test_link_wrapper_records_driver_bytes_and_exact_argv(tmp_path):
    driver = tmp_path / "driver"
    driver.write_text("#!/bin/sh\nexit 0\n")
    driver.chmod(0o755)
    trace = tmp_path / "trace.jsonl"
    env = {
        **os.environ,
        "CACHE_GATE_LINK_DRIVER": str(driver.resolve()),
        "CACHE_GATE_LINK_TRACE": str(trace.resolve()),
    }
    completed = subprocess.run(
        [str(LINK_WRAPPER), "-o", str((tmp_path / "output").resolve())],
        env=env,
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stderr
    records = [json.loads(line) for line in trace.read_text().splitlines()]
    assert records == [
        {
            "argv": ["-o", str((tmp_path / "output").resolve())],
            "cwd": str(Path.cwd().resolve()),
            "driver": str(driver.resolve()),
            "driver_sha256": digest(driver),
            "path": os.environ["PATH"],
        }
    ]


def test_explicit_linker_execution_record_binds_observed_path_hash_and_version(
    tmp_path,
):
    linker = tmp_path / "ld.bfd"
    linker.write_text(
        "#!/bin/sh\n"
        "if test \"${1:-}\" = --version; then echo 'GNU ld fixture 2.42'; fi\n"
        "exit 0\n"
    )
    linker.chmod(0o755)
    binary, raw_output = make_cargo_output_pair(tmp_path)
    trace = tmp_path / "linker-trace.jsonl"
    trace.write_text(
        json.dumps(
            {
                "driver": str(linker.resolve()),
                "driver_sha256": digest(linker),
                "argv": ["-o", str(raw_output.resolve())],
                "cwd": str(tmp_path.resolve()),
                "path": os.environ["PATH"],
            }
        )
        + "\n"
    )
    output = tmp_path / "execution.json"
    command = [
        "python3",
        str(SCRIPT),
        "validate-linker-execution",
        "--trace",
        str(trace.resolve()),
        "--linker",
        str(linker.resolve()),
        "--executable",
        str(binary.resolve()),
        "--flavor",
        "gnu",
        "--output",
        str(output.resolve()),
    ]
    completed = subprocess.run(command, text=True, capture_output=True)
    assert completed.returncode == 0, completed.stderr
    record = json.loads(output.read_text())
    assert record["linker"] == {
        "absolute_path": str(linker.resolve()),
        "flavor": "GNU ld",
        "sha256": digest(linker),
        "version": "GNU ld fixture 2.42",
    }
    assert record["trace"]["final_link_record_count"] == 1

    wrong_linker = tmp_path / "other-ld"
    wrong_linker.write_text(linker.read_text())
    wrong_linker.chmod(0o755)
    command[command.index("--linker") + 1] = str(wrong_linker.resolve())
    rejected = subprocess.run(command, text=True, capture_output=True)
    assert rejected.returncode != 0
    assert "observed linker differs" in rejected.stderr


def test_actual_driver_execution_record_uses_forwarded_linker_version(tmp_path):
    driver = tmp_path / "cc"
    driver.write_text(
        "#!/bin/sh\n"
        "if test \"${1:-}\" = -Wl,--version; then echo 'GNU ld fixture 2.42'; fi\n"
        "exit 0\n"
    )
    driver.chmod(0o755)
    binary, raw_output = make_cargo_output_pair(tmp_path)
    trace = tmp_path / "actual-trace.jsonl"
    trace.write_text(
        json.dumps(
            {
                "driver": str(driver.resolve()),
                "driver_sha256": digest(driver),
                "argv": ["-o", str(raw_output.resolve())],
                "cwd": str(tmp_path.resolve()),
                "path": os.environ["PATH"],
            }
        )
        + "\n"
    )
    output = tmp_path / "execution.json"

    completed = subprocess.run(
        [
            str(SCRIPT),
            "validate-linker-execution",
            "--trace",
            str(trace.resolve()),
            "--linker",
            str(driver.resolve()),
            "--executable",
            str(binary.resolve()),
            "--flavor",
            "actual",
            "--output",
            str(output.resolve()),
        ],
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(output.read_text())["linker"] == {
        "absolute_path": str(driver.resolve()),
        "flavor": "GNU ld",
        "sha256": digest(driver),
        "version": "GNU ld fixture 2.42",
    }


def test_capability_probe_traces_explicit_linker_executables():
    source = (ROOT / "scripts/cache-gate-linker-capability.sh").read_text()
    assert "validate-linker-execution" in source
    assert "CACHE_GATE_LINK_TRACE" in source
    assert "CACHE_GATE_LINK_DRIVER" in source
    assert "-B" in source
    assert (
        'for target in elastic funnel profile; do run_shape actual "$target" '
        '"$actual_driver" actual; done'
    ) in source


def test_cargo_linker_resolver_canonicalizes_path_symlink(tmp_path):
    real_driver = tmp_path / "real-cc"
    real_driver.write_text("#!/bin/sh\nexit 0\n")
    real_driver.chmod(0o755)
    path_dir = tmp_path / "path"
    path_dir.mkdir()
    (path_dir / "cc").symlink_to(real_driver)
    ambient_dir = tmp_path / "ambient-path"
    ambient_dir.mkdir()
    ambient_driver = ambient_dir / "cc"
    ambient_driver.write_text("#!/bin/sh\nexit 0\n")
    ambient_driver.chmod(0o755)
    link_args = tmp_path / "link-args.txt"
    link_args.write_text(
        f'LC_ALL="C" PATH="{path_dir}" VSLANG="1033" '
        '"cc" -Wl,--gc-sections -o /tmp/probe\n'
    )
    env = os.environ.copy()
    env["PATH"] = f"{ambient_dir}:{env['PATH']}"

    completed = subprocess.run(
        [
            str(SCRIPT),
            "resolve-cargo-linker",
            "--link-args",
            str(link_args.resolve()),
        ],
        env=env,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == str(real_driver.resolve())
    assert not Path(completed.stdout.strip()).is_symlink()


def test_cargo_linker_resolver_rejects_bare_driver_without_embedded_path(tmp_path):
    ambient_driver = tmp_path / "cc"
    ambient_driver.write_text("#!/bin/sh\nexit 0\n")
    ambient_driver.chmod(0o755)
    link_args = tmp_path / "link-args.txt"
    link_args.write_text("cc -Wl,--gc-sections -o /tmp/probe\n")
    env = os.environ.copy()
    env["PATH"] = f"{tmp_path}:{env['PATH']}"

    completed = subprocess.run(
        [
            str(SCRIPT),
            "resolve-cargo-linker",
            "--link-args",
            str(link_args.resolve()),
        ],
        env=env,
        text=True,
        capture_output=True,
    )

    assert completed.returncode != 0
    assert "embedded PATH" in completed.stderr


def test_capability_producer_may_differ_from_subject_but_authenticates_root(tmp_path):
    namespace = runpy.run_path(str(SCRIPT))
    producer = tmp_path / "producer"
    producer.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=producer, check=True)
    write = producer / "reviewed.txt"
    write.write_text("reviewed\n")
    subprocess.run(["git", "add", "reviewed.txt"], cwd=producer, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "producer fixture",
        ],
        cwd=producer,
        check=True,
    )
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=producer, text=True
    ).strip()
    tree = subprocess.check_output(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=producer, text=True
    ).strip()
    artifact_root = producer / "target/cache-gate-linker/aarch64/.probe.fixture"
    artifact_root.mkdir(parents=True)
    record = {
        "runner_root": str(producer.resolve()),
        "commit": commit,
        "tree": tree,
        "empty_diff_assertion": True,
        "artifact_root": str(artifact_root.resolve()),
    }
    tools = {
        "elf_layout": {
            "reviewed_root": str(producer.resolve()),
            "reviewed_commit": commit,
            "reviewed_tree": tree,
        }
    }
    subject = tmp_path / "different-subject"
    subject.mkdir()

    root, artifacts = namespace["_validate_capability_producer"](record, tools)

    assert root == producer.resolve()
    assert artifacts == artifact_root.resolve()
    assert root != subject.resolve()
    escaped = tmp_path / "escaped-artifacts"
    escaped.mkdir()
    record["artifact_root"] = str(escaped.resolve())
    with pytest.raises(ValueError, match="artifact root is outside producer target"):
        namespace["_validate_capability_producer"](record, tools)

    external_target = tmp_path / "external-producer-target"
    (producer / "target").rename(external_target)
    (producer / "target").symlink_to(external_target, target_is_directory=True)
    record["artifact_root"] = str(
        (external_target / "cache-gate-linker/aarch64/.probe.fixture").resolve()
    )
    with pytest.raises(ValueError, match="symlink"):
        namespace["_validate_capability_producer"](record, tools)


def make_capability_output_fixture(tmp_path: Path) -> tuple[Path, str, Path]:
    repo = tmp_path / "capability-producer"
    scripts = repo / "scripts"
    benches = repo / "benches"
    scripts.mkdir(parents=True)
    benches.mkdir()
    script = scripts / LINK_CAPABILITY.name
    script.write_text(LINK_CAPABILITY.read_text())
    script.chmod(0o755)
    for target in ("elastic", "funnel", "profile"):
        (benches / f"cache-gate-{target}-layout.ld").write_text(
            f"/* {target} fixture */\n"
        )
    (repo / ".gitignore").write_text("target\n")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "capability fixture",
        ],
        cwd=repo,
        check=True,
    )
    machine = subprocess.check_output(["uname", "-m"], text=True).strip()
    arch = "aarch64" if machine in {"aarch64", "arm64"} else "x86_64"
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    fake_cargo = fake_bin / "cargo"
    fake_cargo.write_text("#!/bin/sh\nexit 97\n")
    fake_cargo.chmod(0o755)
    for name in ("realpath", "sha256sum"):
        forged_bootstrap = fake_bin / name
        forged_bootstrap.write_text("#!/bin/sh\nexit 98\n")
        forged_bootstrap.chmod(0o755)
    return repo, arch, fake_bin


@pytest.mark.parametrize("symlink_level", ["target", "cache-gate-linker", "arch"])
def test_capability_producer_rejects_output_ancestor_symlink_before_probe(
    tmp_path, symlink_level
):
    repo, arch, fake_bin = make_capability_output_fixture(tmp_path)
    outside = tmp_path / f"outside-{symlink_level}"
    outside.mkdir()
    target = repo / "target"
    if symlink_level == "target":
        target.symlink_to(outside, target_is_directory=True)
    else:
        target.mkdir()
        linker_root = target / "cache-gate-linker"
        if symlink_level == "cache-gate-linker":
            linker_root.symlink_to(outside, target_is_directory=True)
        else:
            linker_root.mkdir()
            (linker_root / arch).symlink_to(outside, target_is_directory=True)
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"

    completed = subprocess.run(
        [str(repo / "scripts/cache-gate-linker-capability.sh")],
        cwd=repo,
        env=environment,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 3
    assert "symlink" in completed.stderr
    assert not list(outside.glob(".probe.*"))


def test_capability_producer_rejects_dangling_record_before_probe(tmp_path):
    repo, arch, fake_bin = make_capability_output_fixture(tmp_path)
    output = repo / f"target/cache-gate-linker/{arch}"
    output.mkdir(parents=True)
    (output / "capability.json").symlink_to(output / "missing-capability.json")
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"

    completed = subprocess.run(
        [str(repo / "scripts/cache-gate-linker-capability.sh")],
        cwd=repo,
        env=environment,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 3
    assert "capability record already exists" in completed.stderr
    assert not list(output.glob(".probe.*"))


def test_capability_publication_rejects_source_and_destination_symlinks(tmp_path):
    source = LINK_CAPABILITY.read_text()
    for required in (
        "os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC",
        "os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC",
        "RENAME_NOREPLACE=1",
        "follow_symlinks=False",
        "source_stat.st_nlink!=1",
        "published=False",
        'os.unlink("capability.json",dir_fd=arch_fd)',
    ):
        assert required in source
    assert source.rindex("validate_probe_root") < source.index("if ! python3 -")

    probe = tmp_path / "probe"
    outside = tmp_path / "outside"
    output = tmp_path / "output"
    probe.mkdir()
    outside.mkdir()
    output.mkdir()
    source_path = probe / "capability.json"
    source_path.write_text("authenticated\n")
    destination = output / "capability.json"
    destination.symlink_to(outside, target_is_directory=True)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    probe_fd = os.open(probe, directory_flags)
    output_fd = os.open(output, directory_flags)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
        renameat2.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameat2.restype = ctypes.c_int
        assert (
            renameat2(probe_fd, b"capability.json", output_fd, b"capability.json", 1)
            == -1
        )
        assert ctypes.get_errno() == errno.EEXIST
    finally:
        os.close(output_fd)
        os.close(probe_fd)
    assert destination.is_symlink() and not (outside / "capability.json").exists()

    source_path.unlink()
    source_path.symlink_to(outside / "forged-capability.json")
    with pytest.raises(FileExistsError):
        os.open(
            source_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )


def test_checked_absolute_file_rejects_existing_child_parent_alias(tmp_path):
    namespace = runpy.run_path(str(SCRIPT))
    subject = tmp_path / "subject.json"
    subject.write_text("authenticated\n")
    (tmp_path / "existing-child").mkdir()
    aliased = tmp_path / "existing-child" / ".." / subject.name
    record = {"absolute_path": str(aliased), "sha256": digest(subject)}

    with pytest.raises(ValueError, match="canonical"):
        namespace["checked_absolute_file"](record, "aliased capability artifact")


@pytest.mark.parametrize(
    "alias_kind", ["hardlink", "existing-child-parent", "exact-extra-hardlink"]
)
def test_capability_record_requires_exact_expected_path(tmp_path, alias_kind):
    namespace = runpy.run_path(str(SCRIPT))
    expected = tmp_path / "actual/elastic.map"
    expected.parent.mkdir(parents=True)
    expected.write_text("authenticated map\n")
    if alias_kind == "hardlink":
        alias = tmp_path / "actual/elastic-alias.map"
        os.link(expected, alias)
    elif alias_kind == "exact-extra-hardlink":
        os.link(expected, tmp_path / "actual/extra-hardlink.map")
        alias = expected
    else:
        (expected.parent / "existing-child").mkdir()
        alias = expected.parent / "existing-child" / ".." / expected.name
    record = {"absolute_path": str(alias), "sha256": digest(expected)}

    with pytest.raises(ValueError, match="exact producer path"):
        namespace["_exact_capability_file_record"](
            record, expected.resolve(), "actual/elastic link map"
        )


def test_stage_capability_rejects_input_inode_swap_during_validation(tmp_path):
    namespace = runpy.run_path(str(SCRIPT))
    source = tmp_path / "capability.json"
    source.write_text('{"accepted":true}\n')
    replacement = tmp_path / "replacement.json"
    replacement.write_text('{"accepted":false}\n')
    destination_dir = tmp_path / "staged"
    destination_dir.mkdir()
    destination = destination_dir / "linker-capability.json"

    def swap_input(_staged, _payload):
        source.rename(tmp_path / "original-capability.json")
        replacement.rename(source)
        return "validated"

    with pytest.raises(ValueError, match="input.*changed"):
        namespace["_stage_capability_once"](source, destination, swap_input)
    assert not destination.exists()
    assert source.read_text() == '{"accepted":false}\n'


def test_stage_capability_rejects_staged_inode_swap_without_deleting_replacement(
    tmp_path,
):
    namespace = runpy.run_path(str(SCRIPT))
    source = tmp_path / "capability.json"
    source.write_text('{"accepted":true}\n')
    destination_dir = tmp_path / "staged"
    destination_dir.mkdir()
    destination = destination_dir / "linker-capability.json"

    def swap_stage(staged, payload):
        assert payload == {"accepted": True}
        staged.rename(destination_dir / "validated-original.json")
        staged.write_text('{"accepted":"forged"}\n')
        return "validated"

    with pytest.raises(ValueError, match="staged capability changed"):
        namespace["_stage_capability_once"](source, destination, swap_stage)
    assert json.loads(destination.read_text()) == {"accepted": "forged"}


@pytest.mark.parametrize("swapped_parent", ["source", "destination"])
def test_stage_capability_rejects_parent_directory_replacement(
    tmp_path, swapped_parent
):
    namespace = runpy.run_path(str(SCRIPT))
    source_parent = tmp_path / "source"
    destination_parent = tmp_path / "staged"
    source_parent.mkdir()
    destination_parent.mkdir()
    source = source_parent / "capability.json"
    source.write_text('{"accepted":true}\n')
    destination = destination_parent / "linker-capability.json"

    def replace_parent(_staged, _payload):
        parent = source_parent if swapped_parent == "source" else destination_parent
        moved = tmp_path / f"detached-{swapped_parent}"
        parent.rename(moved)
        parent.mkdir()
        replacement = source if swapped_parent == "source" else destination
        replacement.write_text('{"accepted":true}\n')
        return "validated"

    with pytest.raises(ValueError, match="directory ancestry changed"):
        namespace["_stage_capability_once"](source, destination, replace_parent)
    if swapped_parent == "destination":
        assert destination.read_text() == '{"accepted":true}\n'


def test_stage_capability_preserves_exact_input_bytes(tmp_path):
    namespace = runpy.run_path(str(SCRIPT))
    source = tmp_path / "capability.json"
    source_bytes = b'{"accepted": true, "padding": "exact bytes"}\n'
    source.write_bytes(source_bytes)
    destination_dir = tmp_path / "staged"
    destination_dir.mkdir()
    destination = destination_dir / "linker-capability.json"

    result, identity, document = namespace["_stage_capability_once"](
        source,
        destination,
        lambda staged, payload: f"{staged.name}:{payload['accepted']}",
    )

    assert result == "linker-capability.json:True"
    assert base64.b64decode(document) == source_bytes
    assert identity.rsplit(":", 1)[1] == hashlib.sha256(source_bytes).hexdigest()
    assert destination.read_bytes() == source_bytes
    assert destination.stat().st_mode & 0o777 == 0o444
    namespace["verify_staged_capability"](destination, identity)
    destination.chmod(0o644)
    destination.write_bytes(b'{"accepted": false}\n')
    with pytest.raises(ValueError, match="staged capability"):
        namespace["verify_staged_capability"](destination, identity)


def test_staged_identity_holds_original_parent_ancestry_across_verifications(tmp_path):
    namespace = runpy.run_path(str(SCRIPT))
    source = tmp_path / "capability.json"
    source.write_text('{"accepted":true}\n')
    destination_parent = tmp_path / "staged"
    destination_parent.mkdir()
    destination = destination_parent / "linker-capability.json"
    _, identity, _ = namespace["_stage_capability_once"](
        source, destination, lambda *_: "validated"
    )
    original_stat = destination.stat(follow_symlinks=False)

    detached = tmp_path / "detached-staged"
    destination_parent.rename(detached)
    destination_parent.mkdir()
    (detached / destination.name).rename(destination)
    moved_stat = destination.stat(follow_symlinks=False)
    assert (moved_stat.st_dev, moved_stat.st_ino) == (
        original_stat.st_dev,
        original_stat.st_ino,
    )

    with pytest.raises(ValueError, match="staged capability"):
        namespace["verify_staged_capability"](destination, identity)


def make_semantic_capability_fixture(tmp_path, namespace):
    module_globals = namespace["_validate_capability"].__globals__
    producer = tmp_path / "producer"
    artifact_root = producer / "target/cache-gate-linker/aarch64/.probe.fixture"
    manifest_root = tmp_path / "manifest"
    copied_fragments = manifest_root / "linker-fragments"
    wrapper = producer / "scripts/cache-gate-link-wrapper.py"
    extractor = producer / "scripts/extract-hot-symbols.py"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text("#!/usr/bin/env python3\n")
    extractor.write_text("#!/usr/bin/env python3\n")
    wrapper.chmod(0o755)
    extractor.chmod(0o755)
    copied_fragments.mkdir(parents=True)
    (producer / "benches").mkdir()
    fragments = {}
    for target in ("elastic", "funnel", "profile"):
        fragment = producer / f"benches/cache-gate-{target}-layout.ld"
        fragment.write_text(f"/* {target} */\n")
        fragments[target] = {
            "absolute_path": str(fragment.resolve()),
            "sha256": digest(fragment),
        }
        (copied_fragments / f"{target}.ld").write_bytes(fragment.read_bytes())
    fragment_set = namespace["_fingerprint"](
        [f"{target}:{fragments[target]['sha256']}" for target in sorted(fragments)]
    )
    drivers = {}
    for flavor, identity, version in (
        ("actual", "GNU ld", "GNU ld actual fixture"),
        ("gnu", "GNU ld", "GNU ld explicit fixture"),
        ("lld", "LLD", "LLD explicit fixture"),
    ):
        driver = producer / f"tools/{flavor}-driver"
        driver.parent.mkdir(exist_ok=True)
        driver.write_text("#!/bin/sh\nexit 0\n")
        driver.chmod(0o755)
        drivers[flavor] = {
            "absolute_path": str(driver.resolve()),
            "sha256": digest(driver),
            "flavor": identity,
            "version": version,
        }
    shapes = {}
    for flavor in ("actual", "gnu", "lld"):
        shapes[flavor] = {}
        linker = drivers[flavor]
        for target in ("elastic", "funnel", "profile"):
            expected = namespace["_expected_capability_shape_paths"](
                artifact_root, flavor, target
            )
            deps = expected["binary"].parent / "deps"
            deps.mkdir(parents=True)
            raw_output = deps / f"{target}-0123456789abcdef"
            raw_output.write_bytes(f"ELF {flavor}/{target}\n".encode())
            os.link(raw_output, expected["binary"])
            expected["link_map"].write_text(f"map {flavor}/{target}\n")
            expected["symbols"].write_text(json.dumps({"target": target}) + "\n")
            expected["layout"].write_text(
                json.dumps(
                    {
                        "binary": str(expected["binary"]),
                        "link_map": str(expected["link_map"]),
                        "fragment_sha256": fragments[target]["sha256"],
                        "fragment_set_sha256": fragment_set,
                    }
                )
                + "\n"
            )
            printed_argv = [
                "-o",
                str(raw_output),
                "-Wl,-Bstatic",
                "-Wl,-Bdynamic",
            ]
            if flavor == "actual":
                printed_driver = wrapper
                printed_argv.extend(
                    (
                        f"-Wl,-T,{fragments[target]['absolute_path']}",
                        f"-Wl,-Map,{expected['link_map']}",
                    )
                )
                observed_argv = printed_argv
            else:
                fuse = "bfd" if flavor == "gnu" else "lld"
                wrapper_dir = artifact_root / flavor / "linker-wrapper"
                wrapper_dir.mkdir(exist_ok=True)
                explicit_wrapper = wrapper_dir / f"ld.{fuse}"
                if not explicit_wrapper.exists():
                    explicit_wrapper.write_bytes(wrapper.read_bytes())
                    explicit_wrapper.chmod(0o755)
                printed_driver = Path(drivers["actual"]["absolute_path"])
                printed_argv.extend(
                    (
                        f"-B{wrapper_dir}",
                        f"-fuse-ld={fuse}",
                        f"-Wl,-T,{fragments[target]['absolute_path']}",
                        f"-Wl,-Map,{expected['link_map']}",
                    )
                )
                observed_argv = [
                    "-o",
                    str(raw_output),
                    "-T",
                    fragments[target]["absolute_path"],
                    "-Map",
                    str(expected["link_map"]),
                ]
            expected["link_argv"].write_text(
                f'PATH="/usr/bin" "{printed_driver}" '
                + " ".join(shlex.quote(value) for value in printed_argv)
                + "\n"
            )
            expected["linker_trace"].write_text(
                json.dumps(
                    {
                        "driver": linker["absolute_path"],
                        "driver_sha256": linker["sha256"],
                        "argv": observed_argv,
                    }
                )
                + "\n"
            )
            execution = namespace["replay_linker_execution"](
                expected["linker_trace"], linker, expected["binary"], flavor
            )
            expected["linker_execution"].write_text(json.dumps(execution) + "\n")
            shapes[flavor][target] = {
                key: {
                    "absolute_path": str(expected[key]),
                    "sha256": digest(expected[key]),
                }
                for key in (
                    "binary",
                    "link_argv",
                    "link_map",
                    "symbols",
                    "layout",
                    "linker_execution",
                )
            }
    payload = {
        "accepted": True,
        "arch": "aarch64",
        "target_triple": "aarch64-unknown-linux-gnu",
        "max_page_size": 65536,
        "rustc_version": "rustc fixture\nhost: aarch64-unknown-linux-gnu",
        "cargo_version": "cargo fixture",
        "linker": drivers["actual"],
        "required_linkers": {"gnu": drivers["gnu"], "lld": drivers["lld"]},
        "fragments": fragments,
        "fragment_set_sha256": fragment_set,
        "shapes": shapes,
        "producer": {
            "runner_root": str(producer.resolve()),
            "commit": "a" * 40,
            "tree": "b" * 40,
            "empty_diff_assertion": True,
            "artifact_root": str(artifact_root.resolve()),
        },
    }
    capability_copy = manifest_root / "linker-capability.json"

    def refresh():
        capability_copy.write_text(json.dumps(payload) + "\n")
        return {
            "architecture": "aarch64",
            "tools": {"elf_layout": {}},
            "linker_capability": {
                **copy.deepcopy(payload),
                "copy": {
                    "absolute_path": str(capability_copy.resolve()),
                    "sha256": digest(capability_copy),
                },
            },
        }

    class SubprocessProxy:
        def run(self, arguments, *args, **kwargs):
            if arguments[:4] == ["git", "-C", str(producer), "show"]:
                relative = arguments[4].split(":", 1)[1]
                return subprocess.CompletedProcess(
                    arguments, 0, stdout=(producer / relative).read_bytes(), stderr=b""
                )
            return subprocess.run(arguments, *args, **kwargs)

        def __getattr__(self, name):
            return getattr(subprocess, name)

    module_globals["subprocess"] = SubprocessProxy()
    module_globals["_validate_capability_producer"] = lambda *_: (
        producer.resolve(),
        artifact_root.resolve(),
    )
    module_globals["validate_layout_record"] = lambda *_: None

    def copy_symbols(_extractor, binary, _arch, _target, output, _label):
        flavor = binary.parents[2].name
        recorded = artifact_root / flavor / f"{binary.name}.symbols.json"
        output.write_bytes(recorded.read_bytes())

    module_globals["_run_extractor"] = copy_symbols
    module_globals["validate_elf"] = lambda arguments, _capability=None: json.loads(
        (
            artifact_root
            / arguments.binary.parents[2].name
            / f"{arguments.binary.name}.layout.json"
        ).read_text()
    )
    tools = {"extractor": extractor.resolve(), "link_wrapper": wrapper.resolve()}
    return payload, refresh, capability_copy, manifest_root, tools, module_globals


def test_shared_capability_validator_replays_all_nine_shapes(tmp_path):
    namespace = runpy.run_path(str(SCRIPT))
    payload, refresh, capability_copy, manifest_root, tools, module_globals = (
        make_semantic_capability_fixture(tmp_path, namespace)
    )
    observed = []
    replay = namespace["replay_linker_execution"]

    def record_replay(trace, linker, executable, flavor):
        observed.append((flavor, executable.name))
        return replay(trace, linker, executable, flavor)

    module_globals["replay_linker_execution"] = record_replay
    manifest = refresh()
    namespace["_validate_capability"](
        manifest, manifest_root / "manifest.json", ROOT, tools
    )

    assert set(observed) == {
        (flavor, target)
        for flavor in ("actual", "gnu", "lld")
        for target in ("elastic", "funnel", "profile")
    }
    assert payload["accepted"] is True and capability_copy.is_file()


@pytest.mark.parametrize("flavor", ["gnu", "lld"])
def test_shared_capability_validator_rejects_forged_explicit_driver(tmp_path, flavor):
    namespace = runpy.run_path(str(SCRIPT))
    payload, refresh, _, manifest_root, tools, _ = make_semantic_capability_fixture(
        tmp_path, namespace
    )
    target = "elastic"
    execution_path = Path(
        payload["shapes"][flavor][target]["linker_execution"]["absolute_path"]
    )
    execution = json.loads(execution_path.read_text())
    trace_path = Path(execution["trace"]["absolute_path"])
    forged_driver = trace_path.parent / "forged-driver"
    forged_driver.write_text("#!/bin/sh\nexit 0\n")
    forged_driver.chmod(0o755)
    trace = json.loads(trace_path.read_text())
    trace["driver"] = str(forged_driver.resolve())
    trace["driver_sha256"] = digest(forged_driver)
    trace_path.write_text(json.dumps(trace) + "\n")
    execution["trace"]["sha256"] = digest(trace_path)
    execution_path.write_text(json.dumps(execution) + "\n")
    payload["shapes"][flavor][target]["linker_execution"]["sha256"] = digest(
        execution_path
    )
    manifest = refresh()

    with pytest.raises(ValueError, match=f"observed {flavor} linker differs"):
        namespace["_validate_capability"](
            manifest, manifest_root / "manifest.json", ROOT, tools
        )


@pytest.mark.parametrize("flavor", ["gnu", "lld"])
def test_shared_capability_validator_binds_explicit_trace_fragment_and_map(
    tmp_path, flavor
):
    namespace = runpy.run_path(str(SCRIPT))
    payload, refresh, _, manifest_root, tools, _ = make_semantic_capability_fixture(
        tmp_path, namespace
    )
    target = "elastic"
    execution_path = Path(
        payload["shapes"][flavor][target]["linker_execution"]["absolute_path"]
    )
    execution = json.loads(execution_path.read_text())
    trace_path = Path(execution["trace"]["absolute_path"])
    trace = json.loads(trace_path.read_text())
    trace["argv"] = trace["argv"][:2]
    trace_path.write_text(json.dumps(trace) + "\n")
    execution["argv"] = trace["argv"]
    execution["trace"]["sha256"] = digest(trace_path)
    execution_path.write_text(json.dumps(execution) + "\n")
    payload["shapes"][flavor][target]["linker_execution"]["sha256"] = digest(
        execution_path
    )
    manifest = refresh()

    with pytest.raises(ValueError, match="observed linker controls are not exact"):
        namespace["_validate_capability"](
            manifest, manifest_root / "manifest.json", ROOT, tools
        )


@pytest.mark.parametrize("flavor", ["actual", "gnu", "lld"])
def test_shared_capability_validator_rejects_conflicting_linker_controls(
    tmp_path, flavor
):
    namespace = runpy.run_path(str(SCRIPT))
    payload, refresh, _, manifest_root, tools, _ = make_semantic_capability_fixture(
        tmp_path, namespace
    )
    target = "elastic"
    shape = payload["shapes"][flavor][target]
    link_argv_path = Path(shape["link_argv"]["absolute_path"])
    conflicting_printed = [
        "-Wl,--script,/evil.ld",
        "-Wl,-Map,/evil.map",
        "-B/evil",
        "-fuse-ld=gold",
    ]
    link_argv_path.write_text(
        link_argv_path.read_text().rstrip()
        + " "
        + " ".join(shlex.quote(value) for value in conflicting_printed)
        + "\n"
    )
    shape["link_argv"]["sha256"] = digest(link_argv_path)

    execution_path = Path(shape["linker_execution"]["absolute_path"])
    execution = json.loads(execution_path.read_text())
    trace_path = Path(execution["trace"]["absolute_path"])
    trace = json.loads(trace_path.read_text())
    conflicting_observed = (
        conflicting_printed
        if flavor == "actual"
        else ["--script=/evil.ld", "-Map=/evil.map"]
    )
    trace["argv"].extend(conflicting_observed)
    trace_path.write_text(json.dumps(trace) + "\n")
    execution["argv"] = trace["argv"]
    execution["trace"]["sha256"] = digest(trace_path)
    execution_path.write_text(json.dumps(execution) + "\n")
    shape["linker_execution"]["sha256"] = digest(execution_path)
    manifest = refresh()

    with pytest.raises(ValueError, match="linker controls are not exact"):
        namespace["_validate_capability"](
            manifest, manifest_root / "manifest.json", ROOT, tools
        )


@pytest.mark.parametrize("flavor", ["actual", "gnu", "lld"])
def test_shared_capability_validator_rejects_linker_response_files(tmp_path, flavor):
    namespace = runpy.run_path(str(SCRIPT))
    payload, refresh, _, manifest_root, tools, _ = make_semantic_capability_fixture(
        tmp_path, namespace
    )
    target = "elastic"
    shape = payload["shapes"][flavor][target]
    response = tmp_path / f"{flavor}.rsp"
    response.write_text("--script=/evil.ld\n")
    link_argv_path = Path(shape["link_argv"]["absolute_path"])
    printed_response = f"-Wl,@{response}"
    link_argv_path.write_text(
        link_argv_path.read_text().rstrip() + " " + shlex.quote(printed_response) + "\n"
    )
    shape["link_argv"]["sha256"] = digest(link_argv_path)

    execution_path = Path(shape["linker_execution"]["absolute_path"])
    execution = json.loads(execution_path.read_text())
    trace_path = Path(execution["trace"]["absolute_path"])
    trace = json.loads(trace_path.read_text())
    trace["argv"].append(printed_response if flavor == "actual" else f"@{response}")
    trace_path.write_text(json.dumps(trace) + "\n")
    execution["argv"] = trace["argv"]
    execution["trace"]["sha256"] = digest(trace_path)
    execution_path.write_text(json.dumps(execution) + "\n")
    shape["linker_execution"]["sha256"] = digest(execution_path)
    manifest = refresh()

    with pytest.raises(ValueError, match="linker response files are forbidden"):
        namespace["_validate_capability"](
            manifest, manifest_root / "manifest.json", ROOT, tools
        )


@pytest.mark.parametrize(
    "argv",
    [
        ["@/evil.rsp"],
        ["-Wl,@/evil.rsp"],
        ["-Xlinker", "@/evil.rsp"],
    ],
)
def test_linker_response_file_detection_covers_forwarding_forms(argv):
    namespace = runpy.run_path(str(SCRIPT))
    assert namespace["_linker_response_files"](argv)


@pytest.mark.parametrize(
    "argv", [["-Wl,--ld-path=/evil"], ["-Xlinker", "--ld-path=/evil"]]
)
def test_linker_selection_detection_covers_forwarding_forms(argv):
    namespace = runpy.run_path(str(SCRIPT))
    selection, _, _ = namespace["_printed_linker_controls"](argv)
    assert selection == [argv[0]]


def test_linker_selection_ignores_forwarded_static_dynamic_modes():
    namespace = runpy.run_path(str(SCRIPT))
    selection, _, _ = namespace["_printed_linker_controls"](
        [
            "-Wl,-Bstatic",
            "-Wl,-Bdynamic",
            "-B/exact-wrapper",
            "-fuse-ld=bfd",
        ]
    )
    assert selection == ["-B/exact-wrapper", "-fuse-ld=bfd"]


@pytest.mark.parametrize("alias_kind", ["symlink", "hardlink"])
def test_shared_capability_validator_rejects_copied_fragment_alias(
    tmp_path, alias_kind
):
    namespace = runpy.run_path(str(SCRIPT))
    payload, refresh, _, manifest_root, tools, _ = make_semantic_capability_fixture(
        tmp_path, namespace
    )
    copied = manifest_root / "linker-fragments/elastic.ld"
    producer_fragment = Path(payload["fragments"]["elastic"]["absolute_path"])
    copied.unlink()
    if alias_kind == "symlink":
        copied.symlink_to(producer_fragment)
    else:
        outside = tmp_path / "copied-fragment-alias.ld"
        outside.write_bytes(producer_fragment.read_bytes())
        os.link(outside, copied)
    manifest = refresh()

    with pytest.raises(ValueError, match="copied fragment elastic is not exact"):
        namespace["_validate_capability"](
            manifest, manifest_root / "manifest.json", ROOT, tools
        )


def test_launcher_stages_then_fully_validates_capability_before_build():
    source = LAUNCHER.read_text()
    stage = 'stage-validate-capability --input "$capability_input"'
    assert stage in source
    assert source.index(stage) < source.index("cargo build -vv")
    assert 'cp -- "$CACHE_GATE_LINKER_CAPABILITY"' not in source
    assert "capability=json.load(open(capability_path" not in source
    assert (
        'CACHE_GATE_LINKER_CAPABILITY="$manifest_dir/linker-capability.json"' in source
    )
    assert source.count("verify_staged_capability") >= 10
    assert "error: staged capability identity changed" in source
    assert "staged capability changed during manifest construction" in source
    assert "elastic_bin=$(build_bench" not in source
    assert "build_bench elastic_bin elastic_cache_gate elastic" in source
    manifest_builder = source[source.index('python3 - "$manifest_dir/manifest.json"') :]
    assert (
        "base64.b64decode(capability_document_b64, validate=True)" in manifest_builder
    )
    assert "capability_path.read_bytes()" not in manifest_builder
    assert "capability_path.resolve()" not in manifest_builder
    assert "digest(capability_path)" not in manifest_builder
    build_bench = source[
        source.index("build_bench() {") : source.index("build_bench elastic_bin")
    ]
    assert '"$manifest_dir/link-maps/$bench.map"' in build_bench
    assert '"$manifest_dir/$bench.cargo.json"' in build_bench
    assert '"$manifest_dir/link-traces/$bench.jsonl"' in build_bench
    assert '"$manifest_dir/link-commands/$bench.json"' in build_bench
    assert "$manifest_dir/link-maps/$1.map" not in build_bench


def test_manifest_build_captures_and_authenticates_each_real_link_command():
    source = LAUNCHER.read_text()
    assert "cache-gate-link-wrapper.py" in source
    assert source.count("validate-link-command") >= 1
    assert "authenticate-tools" in source


def test_cargo_executable_selector_ignores_verbose_build_script_lines(tmp_path):
    executable = tmp_path / "bench"
    executable.write_bytes(b"ELF\n")
    cargo_output = tmp_path / "cargo.json"
    cargo_output.write_text(
        "[dependency 1.0.0] cargo:rerun-if-changed=build.rs\n"
        + json.dumps(
            {
                "reason": "compiler-artifact",
                "target": {"name": "elastic_cache_gate"},
                "executable": str(executable.resolve()),
            }
        )
        + "\n"
        + json.dumps({"reason": "build-finished", "success": True})
        + "\n"
    )
    completed = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "select-cargo-executable",
            "--cargo-output",
            str(cargo_output.resolve()),
            "--bench",
            "elastic_cache_gate",
        ],
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == str(executable.resolve())


@pytest.mark.parametrize("field", ["input_section_count", "output_section_count"])
@pytest.mark.parametrize("count", [0, 2])
def test_missing_or_duplicate_input_or_output_section_is_fatal(tmp_path, field, count):
    manifest = make_manifest(tmp_path)
    one_kernel(manifest, "elastic_cache_gate_insert_kernel")[field] = count
    completed = run_compare(tmp_path, manifest)
    assert completed.returncode != 0
    assert field in completed.stderr


def test_wrong_output_section_is_fatal(tmp_path):
    manifest = make_manifest(tmp_path)
    one_kernel(manifest, "elastic_cache_gate_get_kernel")["output_section"] = ".text"
    completed = run_compare(tmp_path, manifest)
    assert completed.returncode != 0
    assert "output_section" in completed.stderr


@pytest.mark.parametrize(
    "sentinel", ["reservation_start", "body_end", "reservation_end"]
)
@pytest.mark.parametrize(
    ("field", "value"),
    [("count", 0), ("count", 2), ("binding", "LOCAL"), ("defined", False)],
)
def test_missing_duplicate_or_non_global_sentinel_is_fatal(
    tmp_path, sentinel, field, value
):
    manifest = make_manifest(tmp_path)
    one_kernel(manifest, "funnel_cache_gate_insert_kernel")["sentinels"][sentinel][
        field
    ] = value
    completed = run_compare(tmp_path, manifest)
    assert completed.returncode != 0
    assert sentinel in completed.stderr


def test_reservation_overflow_is_fatal(tmp_path):
    manifest = make_manifest(tmp_path)
    kernel = one_kernel(manifest, "funnel_cache_gate_get_kernel")
    kernel["body_end"] = kernel["reservation_end"] + 1
    completed = run_compare(tmp_path, manifest)
    assert completed.returncode != 0
    assert "overflow" in completed.stderr


def test_wrong_alloc_execinstr_flags_are_fatal(tmp_path):
    manifest = make_manifest(tmp_path)
    one_kernel(manifest, "elastic_profile_insert_kernel")["section_flags"] = ["ALLOC"]
    completed = run_compare(tmp_path, manifest)
    assert completed.returncode != 0
    assert "ALLOC|EXECINSTR" in completed.stderr


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("pt_load_count", 2, "PT_LOAD"),
        ("pt_load_flags", "R W E", "RX"),
        ("writable_segment_overlap", True, "writable"),
    ],
)
def test_kernel_split_or_non_rx_or_rwx_segment_is_fatal(
    tmp_path, field, value, message
):
    manifest = make_manifest(tmp_path)
    one_kernel(manifest, "elastic_profile_get_kernel")[field] = value
    completed = run_compare(tmp_path, manifest)
    assert completed.returncode != 0
    assert message in completed.stderr


def test_program_header_rwx_is_fatal(tmp_path):
    manifest = make_manifest(tmp_path)
    manifest["elf_layout"]["cache_gate_profile"]["program_headers_have_rwx"] = True
    completed = run_compare(tmp_path, manifest)
    assert completed.returncode != 0
    assert "RWX" in completed.stderr


def test_supplied_manifest_validation_rejects_corrupt_structural_field(tmp_path):
    manifest = make_manifest(tmp_path)
    manifest["elf_layout"]["cache_gate_profile"]["program_headers_have_rwx"] = True
    completed = run_validate_manifest(tmp_path, manifest)
    assert completed.returncode != 0
    assert "program header is RWX" in completed.stderr


def test_supplied_manifest_requires_the_exact_authenticated_schema(tmp_path):
    manifest = make_manifest(tmp_path)
    completed = run_validate_manifest(tmp_path, manifest)
    assert completed.returncode != 0
    assert "exact manifest schema" in completed.stderr


def test_supplied_manifest_validation_rederives_all_three_layouts_from_bytes():
    source = SCRIPT.read_text()
    assert "rederive_manifest_layouts" in source
    assert "AUTHENTICATED_TOOL_NAMES" in source
    assert 'resolved["elf_layout"] == Path(__file__).resolve()' in source
    assert "validate_link_command" in source
    assert "regenerated layout differs" in source


def test_supplied_manifest_validation_never_executes_build_toolchain():
    source = SCRIPT.read_text()
    capability = source[
        source.index("def _validate_capability(") : source.index(
            "def _validate_control("
        )
    ]
    link_records = source[
        source.index("def _validate_main_link_records(") : source.index(
            "def _run_extractor("
        )
    ]
    assert 'run("rustc"' not in capability
    assert 'run("cargo"' not in capability
    assert "validate_linker_execution(" not in capability
    assert "validate_link_command(" not in link_records
    assert "replay_linker_execution" in capability
    assert "replay_link_command" in link_records


def test_explicit_linker_trace_uses_exact_producer_path():
    source = SCRIPT.read_text()
    capability = source[
        source.index("def _validate_capability(") : source.index(
            "def _validate_control("
        )
    ]
    assert "linker trace path mismatch" in capability
    assert "_exact_capability_file_record" in capability


def test_main_link_trace_output_hardlink_cannot_escape_runner_target(tmp_path):
    namespace = runpy.run_path(str(SCRIPT))
    runner_target = tmp_path / "runner/target"
    runner_target.mkdir(parents=True)
    binary = runner_target / "bench"
    binary.write_bytes(b"ELF fixture\n")
    outside = tmp_path / "outside-bench"
    os.link(binary, outside)

    assert not namespace["_output_matches"](["ld", "-o", str(outside)], binary)
    with pytest.raises(ValueError, match="main link output is outside runner target"):
        namespace["_require_output_contained"](
            ["ld", "-o", str(outside)],
            runner_target,
            "main link output is outside runner target",
        )


@pytest.mark.parametrize(
    ("kind", "value", "accepted"),
    [
        ("variant", "cache-off-v2", True),
        ("variant", "-candidate.2", True),
        ("variant", "candidate/path", False),
        ("variant", ".", False),
        ("variant", "..", False),
        ("variant", "", False),
        ("manifest_instance", "build-2", True),
        ("manifest_instance", "-build", False),
        ("manifest_instance", ".build", False),
        ("manifest_instance", "build/path", False),
    ],
)
def test_supplied_manifest_component_validation_matches_builder(kind, value, accepted):
    namespace = runpy.run_path(str(SCRIPT))
    if accepted:
        namespace["_validate_manifest_component"](kind, value)
    else:
        with pytest.raises(ValueError, match="unsafe"):
            namespace["_validate_manifest_component"](kind, value)


def test_control_validation_requires_current_clean_root_and_target_containment():
    source = SCRIPT.read_text()
    control = source[
        source.index("def _validate_control(") : source.index(
            "def _validate_main_link_records("
        )
    ]
    assert 'rev-parse", "HEAD"' in control
    assert 'rev-parse", "HEAD^{tree}"' in control
    assert '"--untracked-files=no"' in control
    assert '(control_root / "tools/cache-gate-control/target").resolve()' in control
    assert '"tools/cache-gate-control/Cargo.toml"' in control
    assert '"tools/cache-gate-control/Cargo.lock"' in control
    assert '"tools/cache-gate-control/src/main.rs"' in control


def test_control_validation_rejects_binary_outside_recorded_control_target(tmp_path):
    namespace = runpy.run_path(str(SCRIPT))
    control_root = tmp_path / "control-root"
    crate = control_root / "tools/cache-gate-control"
    cargo_manifest = crate / "Cargo.toml"
    cargo_lock = crate / "Cargo.lock"
    source = crate / "src/main.rs"
    source.parent.mkdir(parents=True)
    cargo_manifest.write_text("[package]\nname='control'\nversion='0.0.0'\n")
    cargo_lock.write_text("version = 4\n")
    source.write_text("fn main() {}\n")
    subprocess.run(["git", "init", "-q"], cwd=control_root, check=True)
    subprocess.run(["git", "add", "."], cwd=control_root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "control fixture",
        ],
        cwd=control_root,
        check=True,
    )
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=control_root, text=True
    ).strip()
    tree = subprocess.check_output(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=control_root, text=True
    ).strip()
    binary = crate / "target/release/control"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"control binary\n")

    def record(path):
        return {"absolute_path": str(path.resolve()), "sha256": digest(path)}

    provenance = {
        "builder_commit": commit,
        "builder_tree": tree,
        "runner_root": str(control_root.resolve()),
        "runner_commit": commit,
        "runner_tree": tree,
        "mode": "BUILD_CONTROL",
        "binary": record(binary),
        "inputs": {
            "cargo_manifest": record(cargo_manifest),
            "cargo_lock": record(cargo_lock),
            "source": record(source),
        },
        "cargo_version": "cargo fixture",
        "rustc_version": "rustc fixture",
        "locked": True,
    }
    provenance_path = binary.with_suffix(".provenance.json")
    provenance_path.write_text(json.dumps(provenance) + "\n")
    control = {
        **provenance,
        "provenance_path": str(provenance_path.resolve()),
        "provenance_sha256": digest(provenance_path),
    }
    namespace["_validate_control"](control)
    outside = tmp_path / "outside-control"
    outside.write_bytes(b"outside\n")
    control["binary"] = record(outside)
    with pytest.raises(ValueError, match="outside control target"):
        namespace["_validate_control"](control)


def test_link_trace_replay_never_executes_recorded_linkers(tmp_path):
    namespace = runpy.run_path(str(SCRIPT))
    marker = tmp_path / "executed"
    driver = tmp_path / "recorded-linker"
    driver.write_text(f"#!/bin/sh\ntouch {marker}\n")
    driver.chmod(0o755)
    binary, raw_output = make_cargo_output_pair(tmp_path, "bench")
    fragment = tmp_path / "layout.ld"
    fragment.write_text("SECTIONS {}\n")
    link_map = tmp_path / "bench.map"
    link_map.write_text("map\n")
    obj = tmp_path / "input.o"
    obj.write_bytes(b"object\n")
    argv = [
        str(driver),
        "-o",
        str(raw_output),
        f"-Wl,-T,{fragment}",
        f"-Wl,-Map,{link_map}",
        str(obj),
    ]
    trace = tmp_path / "trace.jsonl"
    trace.write_text(
        json.dumps(
            {
                "driver": str(driver),
                "driver_sha256": digest(driver),
                "argv": argv,
            }
        )
        + "\n"
    )
    linker = {
        "absolute_path": str(driver),
        "sha256": digest(driver),
        "flavor": "GNU ld",
        "version": "GNU ld fixture",
    }
    namespace["replay_linker_execution"](trace, linker, binary, "gnu")
    main_argv = [*argv]
    main_argv[main_argv.index(str(raw_output))] = str(binary)
    trace.write_text(
        json.dumps(
            {
                "driver": str(driver),
                "driver_sha256": digest(driver),
                "argv": main_argv,
            }
        )
        + "\n"
    )
    namespace["replay_link_command"](trace, binary, linker, fragment, link_map)
    assert not marker.exists()

    forged = json.loads(trace.read_text())
    forged["driver"] = str(tmp_path / "missing" / ".." / driver.name)
    trace.write_text(json.dumps(forged) + "\n")
    with pytest.raises(ValueError, match="captured link driver differs"):
        namespace["replay_link_command"](trace, binary, linker, fragment, link_map)


@pytest.mark.parametrize(
    ("flavor", "identity", "version"),
    [("gnu", "GNU ld", "GNU ld fixture"), ("lld", "LLD", "LLD fixture")],
)
def test_capability_replay_rejects_lexical_output_alias(
    tmp_path, flavor, identity, version
):
    namespace = runpy.run_path(str(SCRIPT))
    driver = tmp_path / f"{flavor}-linker"
    driver.write_text("#!/bin/sh\nexit 0\n")
    driver.chmod(0o755)
    binary, raw_output = make_cargo_output_pair(tmp_path)
    (raw_output.parent / "existing-child").mkdir()
    aliased_output = raw_output.parent / "existing-child" / ".." / raw_output.name
    trace = tmp_path / f"{flavor}.trace.jsonl"
    trace.write_text(
        json.dumps(
            {
                "driver": str(driver.resolve()),
                "driver_sha256": digest(driver),
                "argv": ["-o", str(aliased_output)],
            }
        )
        + "\n"
    )
    linker = {
        "absolute_path": str(driver.resolve()),
        "sha256": digest(driver),
        "flavor": identity,
        "version": version,
    }

    with pytest.raises(ValueError, match=f"observed {flavor} linker"):
        namespace["replay_linker_execution"](trace, linker, binary, flavor)


@pytest.mark.parametrize("flavor", ["gnu", "lld"])
def test_capability_replay_rejects_duplicate_output_selectors(tmp_path, flavor):
    namespace = runpy.run_path(str(SCRIPT))
    driver = tmp_path / f"{flavor}-linker"
    driver.write_text("#!/bin/sh\nexit 0\n")
    driver.chmod(0o755)
    binary, raw_output = make_cargo_output_pair(tmp_path)
    outside = tmp_path / "outside"
    outside.write_bytes(b"ELF outside\n")
    trace = tmp_path / f"{flavor}.trace.jsonl"
    trace.write_text(
        json.dumps(
            {
                "driver": str(driver.resolve()),
                "driver_sha256": digest(driver),
                "argv": [
                    "-o",
                    str(raw_output.resolve()),
                    "-o",
                    str(outside.resolve()),
                ],
            }
        )
        + "\n"
    )
    linker = {
        "absolute_path": str(driver.resolve()),
        "sha256": digest(driver),
        "flavor": "GNU ld" if flavor == "gnu" else "LLD",
        "version": "GNU ld fixture" if flavor == "gnu" else "LLD fixture",
    }

    with pytest.raises(ValueError, match=f"observed {flavor} linker"):
        namespace["replay_linker_execution"](trace, linker, binary, flavor)


@pytest.mark.parametrize("flavor", ["actual", "gnu", "lld"])
def test_capability_replay_binds_exact_cargo_deps_output_alias(tmp_path, flavor):
    namespace = runpy.run_path(str(SCRIPT))
    driver = tmp_path / f"{flavor}-linker"
    driver.write_text("#!/bin/sh\nexit 0\n")
    driver.chmod(0o755)
    release = tmp_path / flavor / "elastic/release"
    deps = release / "deps"
    deps.mkdir(parents=True)
    raw_output = deps / "elastic-0123456789abcdef"
    raw_output.write_bytes(b"ELF fixture\n")
    binary = release / "elastic"
    os.link(raw_output, binary)
    trace = tmp_path / f"{flavor}.trace.jsonl"
    trace.write_text(
        json.dumps(
            {
                "driver": str(driver.resolve()),
                "driver_sha256": digest(driver),
                "argv": ["-o", str(raw_output.resolve())],
            }
        )
        + "\n"
    )
    linker = {
        "absolute_path": str(driver.resolve()),
        "sha256": digest(driver),
        "flavor": "GNU ld" if flavor != "lld" else "LLD",
        "version": "GNU ld fixture" if flavor != "lld" else "LLD fixture",
    }

    observed = namespace["replay_linker_execution"](
        trace, linker, binary.resolve(), flavor
    )

    assert observed["executable"] == str(binary.resolve())
    assert observed["raw_output"] == str(raw_output.resolve())

    extra_alias = tmp_path / "forged-extra-alias"
    os.link(raw_output, extra_alias)
    with pytest.raises(ValueError, match=f"observed {flavor} linker"):
        namespace["replay_linker_execution"](trace, linker, binary.resolve(), flavor)


@pytest.mark.parametrize("flavor", ["gnu", "lld"])
def test_capability_replay_rejects_noncanonical_raw_driver(tmp_path, flavor):
    namespace = runpy.run_path(str(SCRIPT))
    driver = tmp_path / f"{flavor}-linker"
    driver.write_text("#!/bin/sh\nexit 0\n")
    driver.chmod(0o755)
    binary, raw_output = make_cargo_output_pair(tmp_path)
    trace = tmp_path / f"{flavor}.trace.jsonl"
    raw_driver = f"{tmp_path}//{driver.name}"
    trace.write_text(
        json.dumps(
            {
                "driver": raw_driver,
                "driver_sha256": digest(driver),
                "argv": ["-o", str(raw_output.resolve())],
            }
        )
        + "\n"
    )
    linker = {
        "absolute_path": str(driver.resolve()),
        "sha256": digest(driver),
        "flavor": "GNU ld" if flavor == "gnu" else "LLD",
        "version": "GNU ld fixture" if flavor == "gnu" else "LLD fixture",
    }

    with pytest.raises(ValueError, match=f"observed {flavor} linker differs"):
        namespace["replay_linker_execution"](trace, linker, binary, flavor)


def test_actual_link_trace_replay_binds_capability_driver_path_and_hash(tmp_path):
    namespace = runpy.run_path(str(SCRIPT))
    driver = tmp_path / "cc"
    driver.write_text("#!/bin/sh\nexit 0\n")
    driver.chmod(0o755)
    binary, raw_output = make_cargo_output_pair(tmp_path)
    trace = tmp_path / "actual-trace.jsonl"
    trace.write_text(
        json.dumps(
            {
                "driver": str(driver.resolve()),
                "driver_sha256": digest(driver),
                "argv": ["-o", str(raw_output.resolve())],
                "cwd": str(tmp_path.resolve()),
                "path": os.environ["PATH"],
            }
        )
        + "\n"
    )
    linker = {
        "absolute_path": str(driver.resolve()),
        "sha256": digest(driver),
        "flavor": "GNU ld",
        "version": "GNU ld fixture",
    }

    observed = namespace["replay_linker_execution"](trace, linker, binary, "actual")
    assert observed["linker"] == linker

    wrong_driver = tmp_path / "wrong-cc"
    wrong_driver.write_text(driver.read_text())
    wrong_driver.chmod(0o755)
    forged = json.loads(trace.read_text())
    forged["driver"] = str(wrong_driver.resolve())
    forged["driver_sha256"] = digest(wrong_driver)
    trace.write_text(json.dumps(forged) + "\n")
    with pytest.raises(ValueError, match="observed actual linker differs"):
        namespace["replay_linker_execution"](trace, linker, binary, "actual")

    forged["driver"] = str(tmp_path / "missing" / ".." / driver.name)
    forged["driver_sha256"] = digest(driver)
    trace.write_text(json.dumps(forged) + "\n")
    with pytest.raises(ValueError, match="observed actual linker differs"):
        namespace["replay_linker_execution"](trace, linker, binary, "actual")


@pytest.mark.parametrize("target", ["elastic", "funnel", "profile"])
def test_every_actual_shape_binds_printed_argv_to_observed_trace(tmp_path, target):
    namespace = runpy.run_path(str(SCRIPT))
    producer = tmp_path / "producer"
    wrapper = producer / "scripts/cache-gate-link-wrapper.py"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text("#!/usr/bin/env python3\n")
    wrapper.chmod(0o755)
    output = tmp_path / target
    fragment = tmp_path / "layout.ld"
    link_map = tmp_path / "map"
    argv = [
        "-Wl,--gc-sections",
        "-o",
        str(output.resolve()),
        f"-Wl,-T,{fragment}",
        f"-Wl,-Map,{link_map}",
    ]
    link_argv = tmp_path / f"{target}.link-args.txt"
    link_argv.write_text(
        f'LC_ALL="C" PATH="/usr/bin" "{wrapper.resolve()}" '
        + " ".join(shlex.quote(value) for value in argv)
        + "\n"
    )
    observed = {"argv": argv}

    namespace["_validate_actual_link_argv_trace"](
        link_argv,
        observed,
        wrapper.resolve(),
        fragment,
        link_map,
        f"actual/{target}",
    )

    observed["argv"] = [*argv, "--forged"]
    with pytest.raises(ValueError, match="link argv differs from execution trace"):
        namespace["_validate_actual_link_argv_trace"](
            link_argv,
            observed,
            wrapper.resolve(),
            fragment,
            link_map,
            f"actual/{target}",
        )

    observed["argv"] = argv
    forged_wrapper = producer / "missing" / ".." / "scripts/cache-gate-link-wrapper.py"
    link_argv.write_text(
        f'LC_ALL="C" PATH="/usr/bin" "{forged_wrapper}" '
        + " ".join(shlex.quote(value) for value in argv)
        + "\n"
    )
    with pytest.raises(ValueError, match="did not execute reviewed wrapper"):
        namespace["_validate_actual_link_argv_trace"](
            link_argv,
            observed,
            wrapper.resolve(),
            fragment,
            link_map,
            f"actual/{target}",
        )

    for raw_wrapper in (
        f"{wrapper.parent}//{wrapper.name}",
        f"{wrapper.parent}/./{wrapper.name}",
    ):
        link_argv.write_text(
            f'LC_ALL="C" PATH="/usr/bin" "{raw_wrapper}" '
            + " ".join(shlex.quote(value) for value in argv)
            + "\n"
        )
        with pytest.raises(ValueError, match="did not execute reviewed wrapper"):
            namespace["_validate_actual_link_argv_trace"](
                link_argv,
                observed,
                wrapper.resolve(),
                fragment,
                link_map,
                f"actual/{target}",
            )


def test_inline_capability_consumer_requires_exact_actual_wrapper_path():
    source = SCRIPT.read_text()
    assert "printed_driver == str(expected_wrapper)" in source


def test_launcher_rejects_capability_input_symlink_ancestry_before_read():
    source = SCRIPT.read_text()
    start = source.index("def _stage_capability_once(")
    validator = source[start : source.index("def _require(", start)]
    opened = validator.index("os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC")
    read = validator.index("source_bytes = _read_descriptor(source_descriptor)")
    parsed = validator.index("payload = json.loads(source_bytes)")
    assert opened < read < parsed
    assert "_open_directory_with_identity_chain(source.parent)" in validator
    assert "_verify_directory_identity_chain(\n            source.parent" in validator


def test_stable_launcher_rejects_corrupt_manifest_before_execution(tmp_path):
    fixture_root = (
        ROOT
        / "target"
        / "cache-gate-test-fixtures"
        / f"{tmp_path.parent.name}-{tmp_path.name}-stable-corrupt"
    )
    fixture_root.mkdir(parents=True, exist_ok=False)
    harness_root = fixture_root / "reviewed-harness"
    harness_scripts = harness_root / "scripts"
    harness_scripts.mkdir(parents=True)
    for filename in (
        "cache-gate.sh",
        "cache-gate-elf-layout.py",
        "snapshot-criterion-pair.sh",
        "cache-gate-perf.sh",
        "cache-gate-perf-support.py",
        "extract-hot-symbols.py",
        "cache-gate-link-wrapper.py",
    ):
        source = ROOT / "scripts" / filename
        copied = harness_scripts / filename
        copied.write_bytes(source.read_bytes())
        copied.chmod(source.stat().st_mode)
    subprocess.run(["git", "init", "-q"], cwd=harness_root, check=True)
    subprocess.run(["git", "add", "scripts"], cwd=harness_root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Cache Gate Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "fixture harness",
        ],
        cwd=harness_root,
        check=True,
    )
    harness_launcher = harness_scripts / "cache-gate.sh"
    authenticated_tools_path = fixture_root / "authenticated-tools.json"
    tool_files = {
        "launcher": "cache-gate.sh",
        "elf_layout": "cache-gate-elf-layout.py",
        "snapshot": "snapshot-criterion-pair.sh",
        "perf_launcher": "cache-gate-perf.sh",
        "perf_support": "cache-gate-perf-support.py",
        "extractor": "extract-hot-symbols.py",
        "link_wrapper": "cache-gate-link-wrapper.py",
    }
    subprocess.run(
        [
            str(harness_scripts / "cache-gate-elf-layout.py"),
            "authenticate-tools",
            "--output",
            str(authenticated_tools_path),
            *[
                argument
                for name, filename in tool_files.items()
                for argument in ("--tool", f"{name}={harness_scripts / filename}")
            ],
        ],
        check=True,
    )
    authenticated_tools = json.loads(authenticated_tools_path.read_text())
    manifest = make_manifest(fixture_root)
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    tree = subprocess.check_output(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True
    ).strip()
    manifest.update(
        {
            "commit": commit,
            "tree": tree,
            "runner_root": str(ROOT.resolve()),
            "empty_diff_assertion": True,
            "variant": "fixture-corrupt",
            "tools": authenticated_tools,
        }
    )
    manifest["elf_layout"]["cache_gate_profile"]["program_headers_have_rwx"] = True
    manifest_path = fixture_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest) + "\n")
    completed = subprocess.run(
        [str(harness_launcher), "--runner-root", str(ROOT)],
        cwd=ROOT,
        env={
            **os.environ,
            "ELASTIC": "1",
            "SAVE": "fixture",
            "CACHE_GATE_MANIFEST": str(manifest_path),
        },
        text=True,
        capture_output=True,
    )
    assert completed.returncode != 0
    assert "program header is RWX" in completed.stderr


def test_overlap_is_fatal(tmp_path):
    manifest = make_manifest(tmp_path)
    left = one_kernel(manifest, "elastic_profile_insert_kernel")
    right = one_kernel(manifest, "elastic_profile_get_kernel")
    right["reservation_start"] = left["reservation_start"] + 1
    right["reservation_end"] = right["reservation_start"] + 65536
    completed = run_compare(tmp_path, manifest)
    assert completed.returncode != 0
    assert "overlap" in completed.stderr


def test_non_pie_et_exec_is_fatal(tmp_path):
    manifest = make_manifest(tmp_path)
    manifest["elf_layout"]["elastic_cache_gate"]["elf_type"] = "ET_EXEC"
    completed = run_compare(tmp_path, manifest)
    assert completed.returncode != 0
    assert "ET_DYN" in completed.stderr


def test_reservation_start_not_aligned_to_capability_maxpagesize_is_fatal(tmp_path):
    manifest = make_manifest(tmp_path)
    kernel = one_kernel(manifest, "elastic_cache_gate_get_kernel")
    for field in ("reservation_start", "body_end", "reservation_end"):
        kernel[field] += 4096
        kernel["sentinels"][field]["address"] += 4096
        kernel["link_map_sentinels"][field] += 4096
    for field in (
        "output_start",
        "output_end",
        "input_start",
        "input_end",
        "function_start",
        "function_end",
    ):
        kernel[field] += 4096
    kernel["max_page_remainder"] = 4096
    completed = run_compare(tmp_path, manifest)
    assert completed.returncode != 0
    assert "MAXPAGESIZE" in completed.stderr


def test_actual_sh_addralign_mismatch_is_fatal_even_when_trailing_zeros_match(tmp_path):
    anchor = make_manifest(tmp_path)
    candidate = copy.deepcopy(anchor)
    one_kernel(candidate, "elastic_cache_gate_insert_kernel")["sh_addralign"] = 4096
    completed = run_compare(tmp_path, anchor, candidate)
    assert completed.returncode != 0
    assert "sh_addralign" in completed.stderr


@pytest.mark.parametrize("field", ["fragment_sha256", "fragment_set_sha256"])
def test_target_fragment_or_set_hash_mismatch_is_fatal(tmp_path, field):
    anchor = make_manifest(tmp_path)
    candidate = copy.deepcopy(anchor)
    candidate["elf_layout"]["elastic_cache_gate"][field] = "f" * 64
    completed = run_compare(tmp_path, anchor, candidate)
    assert completed.returncode != 0
    assert field in completed.stderr


def test_binary_hash_mismatch_is_fatal(tmp_path):
    manifest = make_manifest(tmp_path)
    path = Path(manifest["executables"]["elastic_cache_gate"]["absolute_path"])
    path.write_bytes(b"tampered")
    completed = run_compare(tmp_path, manifest)
    assert completed.returncode != 0
    assert "binary hash mismatch" in completed.stderr


def test_link_map_sentinel_mismatch_is_fatal(tmp_path):
    manifest = make_manifest(tmp_path)
    one_kernel(manifest, "funnel_profile_insert_kernel")["link_map_sentinels"][
        "body_end"
    ] += 4
    completed = run_compare(tmp_path, manifest)
    assert completed.returncode != 0
    assert "link-map" in completed.stderr


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("veneer_thunks", ["fixture::__AArch64AbsLongThunk_target"], "veneer|thunk"),
        ("plt_calls", ["fixture@plt"], "PLT"),
    ],
)
def test_veneer_thunk_or_kernel_plt_call_is_fatal(tmp_path, field, value, message):
    manifest = make_manifest(tmp_path)
    one_kernel(manifest, "funnel_profile_get_kernel")[field] = value
    completed = run_compare(tmp_path, manifest)
    assert completed.returncode != 0
    assert message in completed.stderr


def test_out_of_reservation_thunk_in_kernel_direct_call_graph_is_fatal(tmp_path):
    manifest = make_manifest(tmp_path)
    layout = manifest["elf_layout"]["cache_gate_profile"]
    thunk = {
        "name": "fixture::__AArch64AbsLongThunk_target",
        "start": 0xF00000,
        "end": 0xF00010,
        "size": 0x10,
    }
    layout["veneer_thunk_inventory"] = [thunk]
    kernel = one_kernel(manifest, "funnel_profile_get_kernel")
    assert not kernel["reservation_start"] <= thunk["start"] < kernel["reservation_end"]
    kernel["direct_calls"] = [f"0xf00000 <{thunk['name']}>"]
    completed = run_compare(tmp_path, manifest)
    assert completed.returncode != 0
    assert "veneer|thunk in kernel call graph" in completed.stderr


def test_exact_shape_rejects_absent_expected_reservation(tmp_path):
    manifest = make_manifest(tmp_path)
    del manifest["elf_layout"]["elastic_cache_gate"]["kernels"][
        "elastic_cache_gate_get_kernel"
    ]
    completed = run_compare(tmp_path, manifest)
    assert completed.returncode != 0
    assert "exact kernel set" in completed.stderr


def test_exact_shape_rejects_cross_target_reservation(tmp_path):
    manifest = make_manifest(tmp_path)
    cross = copy.deepcopy(one_kernel(manifest, "funnel_cache_gate_get_kernel"))
    manifest["elf_layout"]["elastic_cache_gate"]["kernels"][
        "funnel_cache_gate_get_kernel"
    ] = cross
    completed = run_compare(tmp_path, manifest)
    assert completed.returncode != 0
    assert "exact kernel set" in completed.stderr


def test_compare_rejects_body_change_by_default_and_allows_only_declared_kernel(
    tmp_path,
):
    anchor = make_manifest(tmp_path)
    candidate = copy.deepcopy(anchor)
    kernel = one_kernel(candidate, "elastic_cache_gate_insert_kernel")
    kernel["body_end"] += 4
    kernel["body_size"] += 4
    kernel["input_end"] += 4
    kernel["input_size"] += 4
    kernel["function_end"] += 4
    kernel["function_size"] += 4
    kernel["raw_sha256"] = "c" * 64
    kernel["normalized_sha256"] = "d" * 64
    kernel["sentinels"]["body_end"]["address"] += 4
    kernel["link_map_sentinels"]["body_end"] += 4
    rejected = run_compare(tmp_path, anchor, candidate)
    assert rejected.returncode != 0
    accepted = run_compare(
        tmp_path,
        anchor,
        candidate,
        "--allow-body-change",
        "elastic_cache_gate_insert_kernel",
    )
    assert accepted.returncode == 0, accepted.stderr


def test_compare_rejects_unknown_body_change_declaration(tmp_path):
    manifest = make_manifest(tmp_path)
    completed = run_compare(
        tmp_path, manifest, manifest, "--allow-body-change", "unknown_kernel"
    )
    assert completed.returncode != 0
    assert "unknown kernel" in completed.stderr


def attach_build_proof(manifest: dict, token: str, *, adversary: bool = False):
    executable_proofs = {}
    for executable in ("elastic_cache_gate", "funnel_cache_gate", "cache_gate_profile"):
        executable_proofs[executable] = {
            "rustc_argv": [f"rustc --crate-name {executable} -C codegen-units=16"],
            "adversary": {
                "symbol_occurrences": (
                    [{"name": "cache_gate_layout_adversary_private"}]
                    if adversary
                    else []
                ),
                "input_section_occurrences": 1 if adversary else 0,
                "outside_reservations": True,
            },
        }
    manifest["build_proof"] = {
        "codegen_units": 16,
        "executables": executable_proofs,
        "cgu_partition_fingerprint": f"cgu-{token}",
        "object_member_fingerprint": f"objects-{token}",
        "link_order_fingerprint": f"link-{token}",
        "reserved_input_owner_fingerprint": "reserved-exact",
    }
    manifest["layout_adversary"] = {"enabled": adversary}


def test_compare_authenticates_codegen_units_in_every_rustc_argv(tmp_path):
    anchor = make_manifest(tmp_path)
    candidate = copy.deepcopy(anchor)
    attach_build_proof(anchor, "clean")
    attach_build_proof(candidate, "clean")
    candidate["build_proof"]["executables"]["elastic_cache_gate"]["rustc_argv"] = [
        "rustc --crate-name elastic_cache_gate"
    ]
    completed = run_compare(tmp_path, anchor, candidate)
    assert completed.returncode != 0
    assert "rustc argv" in completed.stderr


def test_compare_rejects_vacuous_adversary_fingerprints(tmp_path):
    anchor = make_manifest(tmp_path)
    candidate = copy.deepcopy(anchor)
    attach_build_proof(anchor, "same")
    attach_build_proof(candidate, "same", adversary=True)
    completed = run_compare(tmp_path, anchor, candidate)
    assert completed.returncode != 0
    assert "vacuous" in completed.stderr


def test_compare_accepts_linked_exact_nonvacuous_adversary_proof(tmp_path):
    anchor = make_manifest(tmp_path)
    candidate = copy.deepcopy(anchor)
    attach_build_proof(anchor, "clean")
    attach_build_proof(candidate, "adversary", adversary=True)
    completed = run_compare(tmp_path, anchor, candidate)
    assert completed.returncode == 0, completed.stderr
