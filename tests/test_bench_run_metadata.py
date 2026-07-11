import os
import json
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_bench_script_runs_cargo_from_the_repository_root(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    captured_cwd = tmp_path / "cargo-cwd"
    _write_executable(bin_dir / "uname", "#!/bin/sh\necho Darwin\n")
    _write_executable(bin_dir / "cargo", '#!/bin/sh\npwd > "$CAPTURE_CWD"\n')
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{bin_dir}{os.pathsep}{environment['PATH']}",
            "BENCH": "scaled_insert",
            "CAPTURE_CWD": str(captured_cwd),
        }
    )

    result = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts/bench.sh")],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert Path(captured_cwd.read_text().strip()) == REPO_ROOT


def test_bench_script_passes_named_metadata_to_unmanifested_targets(
    tmp_path: Path,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    capture_env = tmp_path / "environment"
    capture_args = tmp_path / "arguments"
    _write_executable(bin_dir / "uname", "#!/bin/sh\necho Darwin\n")
    _write_executable(
        bin_dir / "cargo",
        '#!/bin/sh\nenv > "$CAPTURE_ENV"\nprintf \'%s\\n\' "$@" > "$CAPTURE_ARGS"\n',
    )

    cases = [
        ({}, ("ref", "", ""), ["--save-baseline", "ref"]),
        ({"SAVE": "opt1"}, ("opt1", "", ""), ["--save-baseline", "opt1"]),
        ({"BASELINE": "anchor"}, ("", "", "anchor"), ["--baseline", "anchor"]),
        (
            {"LOAD": "opt1", "BASELINE": "anchor"},
            ("", "opt1", "anchor"),
            ["--load-baseline", "opt1", "--baseline", "anchor"],
        ),
    ]
    for overrides, expected_metadata, expected_criterion_args in cases:
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{bin_dir}{os.pathsep}{environment['PATH']}",
                "BENCH": "scaled_insert",
                "CAPTURE_ENV": str(capture_env),
                "CAPTURE_ARGS": str(capture_args),
                "OPTHASH_BENCH_SAVE_BASELINE": "stale-save",
                "OPTHASH_BENCH_LOAD_BASELINE": "stale-load",
                "OPTHASH_BENCH_COMPARE_BASELINE": "stale-compare",
            }
        )
        for name in ("SAVE", "LOAD", "BASELINE"):
            environment.pop(name, None)
        environment.update(overrides)

        subprocess.run(
            ["bash", "scripts/bench.sh"],
            cwd=REPO_ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )

        captured = dict(
            line.split("=", 1)
            for line in capture_env.read_text(encoding="utf-8").splitlines()
            if "=" in line
        )
        assert (
            captured["OPTHASH_BENCH_SAVE_BASELINE"],
            captured["OPTHASH_BENCH_LOAD_BASELINE"],
            captured["OPTHASH_BENCH_COMPARE_BASELINE"],
        ) == expected_metadata
        arguments = capture_args.read_text(encoding="utf-8").splitlines()
        assert arguments[:4] == [
            "bench",
            "--bench",
            "scaled_insert",
            "--",
        ]
        assert arguments[4:] == expected_criterion_args


def test_bench_script_can_lock_a_read_only_shared_core_directory(
    tmp_path: Path,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "cargo-ran"
    lock_root = tmp_path / "locks"
    lock_root.mkdir()
    core_lock = lock_root / "opthash-bench-core-5.lock"
    core_lock.mkdir()
    core_lock.chmod(0o555)

    _write_executable(bin_dir / "uname", "#!/bin/sh\necho Linux\n")
    _write_executable(
        bin_dir / "taskset",
        '#!/bin/sh\nshift 2\nexec "$@"\n',
    )
    _write_executable(
        bin_dir / "setarch",
        '#!/bin/sh\nshift\nexec "$@"\n',
    )
    _write_executable(
        bin_dir / "chrt",
        '#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$LAUNCH_LOG"\nshift 2\nexec "$@"\n',
    )
    _write_executable(
        bin_dir / "numactl",
        '#!/bin/sh\nshift\nexec "$@"\n',
    )
    _write_executable(
        bin_dir / "cargo",
        '#!/bin/sh\nenv > "$CAPTURE_ENV"\n: > "$CARGO_MARKER"\n',
    )
    manifest_log = tmp_path / "manifest-log"
    transaction = tmp_path / "transaction"
    _write_fake_manifest_helper(tmp_path / "manifest-helper", transaction)

    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{bin_dir}{os.pathsep}{environment['PATH']}",
            "CORE": "5",
            "LOCK_DIR": str(lock_root),
            "BENCH": "speedup",
            "SAVE": "lock-smoke",
            "CARGO_MARKER": str(marker),
            "CAPTURE_ENV": str(tmp_path / "cargo-environment"),
            "MANIFEST_LOG": str(manifest_log),
            "LAUNCH_LOG": str(tmp_path / "launcher-log"),
            "OPTHASH_CRITERION_MANIFEST_HELPER": str(tmp_path / "manifest-helper"),
        }
    )

    result = subprocess.run(
        ["bash", "scripts/bench.sh"],
        cwd=REPO_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "acquired perf core 5" in result.stderr
    assert marker.exists()
    captured = dict(
        line.split("=", 1)
        for line in (tmp_path / "cargo-environment").read_text().splitlines()
        if "=" in line
    )
    assert captured["CRITERION_HOME"] == str(transaction)
    commands = [json.loads(line) for line in manifest_log.read_text().splitlines()]
    assert [command[0] for command in commands] == ["prepare-save", "publish-save"]
    launches = (tmp_path / "launcher-log").read_text().splitlines()
    assert len(launches) == 3
    assert "manifest-helper prepare-save" in launches[0]
    assert "taskset -c 5" in launches[1]
    assert "manifest-helper publish-save" in launches[2]


def test_bench_script_routes_named_speedup_modes_through_manifest_transactions(
    tmp_path: Path,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_executable(bin_dir / "uname", "#!/bin/sh\necho Linux\n")
    for name, shift in (("taskset", 2), ("setarch", 1), ("chrt", 2), ("numactl", 1)):
        _write_executable(
            bin_dir / name,
            f'#!/bin/sh\nshift {shift}\nexec "$@"\n',
        )
    _write_executable(
        bin_dir / "cargo",
        '#!/bin/sh\nenv > "$CAPTURE_ENV"\nprintf \'%s\\n\' "$@" > "$CAPTURE_ARGS"\n',
    )
    transaction = tmp_path / "transaction"
    helper = tmp_path / "manifest-helper"
    _write_fake_manifest_helper(helper, transaction)

    cases = [
        ({"SAVE": "candidate"}, ["prepare-save", "publish-save"]),
        ({"BASELINE": "anchor"}, ["hydrate", "discard"]),
        (
            {"LOAD": "candidate", "BASELINE": "anchor"},
            ["hydrate", "discard"],
        ),
    ]
    for index, (overrides, expected_commands) in enumerate(cases):
        capture_env = tmp_path / f"environment-{index}"
        capture_args = tmp_path / f"arguments-{index}"
        manifest_log = tmp_path / f"manifest-{index}"
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{bin_dir}{os.pathsep}{environment['PATH']}",
                "CORE": "5",
                "LOCK_DIR": str(tmp_path / "locks"),
                "BENCH": "speedup",
                "CAPTURE_ENV": str(capture_env),
                "CAPTURE_ARGS": str(capture_args),
                "MANIFEST_LOG": str(manifest_log),
                "OPTHASH_CRITERION_MANIFEST_HELPER": str(helper),
            }
        )
        for name in ("SAVE", "LOAD", "BASELINE"):
            environment.pop(name, None)
        environment.update(overrides)

        result = subprocess.run(
            ["bash", "scripts/bench.sh", "--", "--measurement-time", "10"],
            cwd=REPO_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, result.stderr
        captured = dict(
            line.split("=", 1)
            for line in capture_env.read_text().splitlines()
            if "=" in line
        )
        assert captured["CRITERION_HOME"] == str(transaction)
        commands = [json.loads(line) for line in manifest_log.read_text().splitlines()]
        assert [command[0] for command in commands] == expected_commands
        first = commands[0]
        assert "--target" in first and first[first.index("--target") + 1] == "speedup"
        if first[0] == "prepare-save":
            assert first[first.index("--baseline") + 1] == "candidate"
            assert first[first.index("--core") + 1] == "5"
            assert "--forwarded-arg=--measurement-time" in first
            assert "--forwarded-arg=10" in first
        elif "LOAD" in overrides:
            assert first[first.index("--baseline") + 1] == "candidate"
            assert first[first.index("--compare") + 1] == "anchor"
        else:
            assert first[first.index("--baseline") + 1] == "anchor"
        if first[0] == "hydrate":
            assert "--strict-measured" in first
            assert first[first.index("--source-root") + 1] == str(REPO_ROOT)
            assert first[first.index("--core") + 1] == "5"
            assert "--forwarded-arg=--measurement-time" in first
            assert "--forwarded-arg=10" in first


def _write_fake_manifest_helper(path: Path, transaction: Path) -> None:
    _write_executable(
        path,
        """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
with Path(os.environ["MANIFEST_LOG"]).open("a") as stream:
    stream.write(json.dumps(args) + "\\n")
if args[0] in {"prepare-save", "hydrate"}:
    transaction = Path(%r)
    transaction.mkdir(parents=True, exist_ok=True)
    print(transaction)
"""
        % str(transaction),
    )


def _write_executable(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o755)
