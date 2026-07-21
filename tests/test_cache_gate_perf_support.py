import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "cache-gate-perf-support.py"
SPEC = importlib.util.spec_from_file_location("cache_gate_perf_support", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
support = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(support)


@pytest.mark.parametrize(
    ("flag", "mismatched_value"),
    [("--iterations", "1001"), ("--core", "6"), ("--pmu", "armv8_pmuv3_0")],
)
def test_shared_contract_rejects_mismatch_from_distinct_roots(
    tmp_path, flag, mismatched_value
):
    campaign_root = tmp_path / "shared-campaign"
    first_root = tmp_path / "anchor-worktree"
    second_root = tmp_path / "candidate-worktree"
    first_root.mkdir()
    second_root.mkdir()
    arguments = [
        str(SCRIPT),
        "bind-contract",
        "--root",
        str(campaign_root),
        "--key",
        "campaign-1",
        "--operation",
        "elastic-get",
        "--repetition",
        "1",
        "--iterations",
        "1000",
        "--core",
        "5",
        "--pmu",
        "armv8_pmuv3_1",
    ]
    first = subprocess.run(arguments, cwd=first_root, text=True, capture_output=True)
    assert first.returncode == 0, first.stderr
    mismatched_arguments = list(arguments)
    mismatched_arguments[mismatched_arguments.index(flag) + 1] = mismatched_value
    mismatch = subprocess.run(
        mismatched_arguments, cwd=second_root, text=True, capture_output=True
    )
    assert mismatch.returncode != 0
    assert "campaign contract mismatch" in mismatch.stderr
    contract = json.loads(Path(first.stdout.strip()).read_text())
    assert contract == {
        "campaign_key": "campaign-1",
        "core": 5,
        "iterations": 1000,
        "operation": "elastic-get",
        "pmu": "armv8_pmuv3_1",
        "repetition": 1,
    }


def test_manifest_staging_has_requested_owner(tmp_path):
    manifest = tmp_path / "manifest"
    build = tmp_path / "build"
    support.prepare_manifest_staging(manifest, build, os.getuid(), os.getgid())
    for path in (manifest, manifest / "link-maps", manifest / "symbols", build):
        metadata = path.stat()
        assert metadata.st_uid == os.getuid()
        assert metadata.st_gid == os.getgid()


def test_manifest_staging_root_path_chowns_every_path_to_distinct_invoker(
    tmp_path, monkeypatch
):
    manifest = tmp_path / "root-manifest"
    build = tmp_path / "root-build"
    requested_uid = 12345
    requested_gid = 23456
    calls = []
    simulated_owners = {}

    def observe_chown(path, uid, gid):
        calls.append((Path(path), uid, gid))
        simulated_owners[Path(path)] = (uid, gid)

    monkeypatch.setattr(support.os, "geteuid", lambda: 0)
    monkeypatch.setattr(support, "_change_owner", observe_chown)
    monkeypatch.setattr(
        support, "_path_owner", lambda path: simulated_owners[Path(path)]
    )
    support.prepare_manifest_staging(manifest, build, requested_uid, requested_gid)
    expected_paths = [manifest, manifest / "link-maps", manifest / "symbols", build]
    assert calls == [(path, requested_uid, requested_gid) for path in expected_paths]
    assert [support._path_owner(path) for path in expected_paths] == [
        (requested_uid, requested_gid)
    ] * 4


@pytest.mark.parametrize(
    ("architecture", "devices", "core", "expected"),
    [
        (
            "aarch64",
            {"armv8_pmuv3_0": "0-3", "armv8_pmuv3_1": "4-7"},
            5,
            "armv8_pmuv3_1",
        ),
        ("aarch64", {"armv8_pmuv3": None}, 2, "armv8_pmuv3"),
        ("x86_64", {"cpu": None}, 2, "cpu"),
    ],
)
def test_select_core_pmu_handles_hybrid_homogeneous_and_x86(
    architecture, devices, core, expected
):
    assert support.select_core_pmu(architecture, core, devices) == expected


@pytest.mark.parametrize(
    ("expected", "event_names"),
    [
        ("armv8_pmuv3_1", ["armv8_pmuv3_1/cycles/", "instructions"]),
        ("armv8_pmuv3", ["cycles", "instructions"]),
        ("cpu", ["cycles", "instructions"]),
    ],
)
def test_perf_rows_attribute_bare_events_to_selected_pmu(expected, event_names):
    rows = "".join(f"1,,{event},1,100.0,,\n" for event in event_names)
    rows += "1,,cache-misses,1,100.0,,\n1,,branch-misses,1,100.0,,\n"
    assert support.validate_perf_csv(rows, expected) == expected


def test_reported_exec_pid_is_verified_in_sudo_like_monitor_topology(tmp_path):
    child_pid = tmp_path / "child.pid"
    monitor = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import pathlib,subprocess,sys; "
                "child=subprocess.Popen(['/bin/sleep','30']); "
                "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); "
                "child.wait()"
            ),
            str(child_pid),
        ]
    )
    try:
        deadline = time.monotonic() + 5
        while not child_pid.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        reported_pid = int(child_pid.read_text())
        assert reported_pid != monitor.pid
        assert support.verify_process_executable(reported_pid, Path("/bin/sleep"))
        with pytest.raises(ValueError, match="profile executable mismatch"):
            support.verify_process_executable(reported_pid, Path(sys.executable))
    finally:
        if child_pid.exists():
            os.kill(int(child_pid.read_text()), 15)
        monitor.wait(timeout=5)
