import copy
import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "cache-gate-elf-layout.py"
LAUNCHER = ROOT / "scripts" / "cache-gate.sh"
LINK_WRAPPER = ROOT / "scripts" / "cache-gate-link-wrapper.py"
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
    assert "linker-selection" in rejected.stderr


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
