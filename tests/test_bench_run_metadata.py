import json
import os
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
        """#!/bin/sh
env > "$CAPTURE_ENV"
: > "$CARGO_MARKER"
printf 'cargo\n' >> "$EVENT_LOG"
""",
    )
    metadata_log = tmp_path / "metadata-log"
    event_log = tmp_path / "event-log"
    helper = tmp_path / "metadata-helper"
    _write_fake_metadata_helper(helper)

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
            "METADATA_LOG": str(metadata_log),
            "EVENT_LOG": str(event_log),
            "LAUNCH_LOG": str(tmp_path / "launcher-log"),
            "OPTHASH_BENCHMARK_METADATA_HELPER": str(helper),
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
    assert "CRITERION_HOME" not in captured
    assert captured["OPTHASH_BENCH_SAVE_BASELINE"] == "lock-smoke"
    commands = [json.loads(line) for line in metadata_log.read_text().splitlines()]
    assert [command[0] for command in commands] == ["begin", "publish"]
    assert event_log.read_text().splitlines() == ["begin", "cargo", "publish"]
    begin, publish = commands
    assert begin[begin.index("--target") + 1] == "speedup"
    assert begin[begin.index("--baseline") + 1] == "lock-smoke"
    assert publish[publish.index("--source-before") + 1] == "source-before"
    assert publish[publish.index("--requested-bench") + 1] == "speedup"
    assert publish[publish.index("--core") + 1] == "5"
    launches = (tmp_path / "launcher-log").read_text().splitlines()
    assert len(launches) == 3
    assert "metadata-helper begin" in launches[0]
    assert "taskset -c 5" in launches[1]
    assert "metadata-helper publish" in launches[2]


def test_bench_script_scrubs_stale_criterion_home_only_from_cargo(
    tmp_path: Path,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_executable(bin_dir / "uname", "#!/bin/sh\necho Linux\n")
    _write_executable(bin_dir / "taskset", '#!/bin/sh\nshift 2\nexec "$@"\n')
    _write_executable(bin_dir / "setarch", '#!/bin/sh\nshift\nexec "$@"\n')
    _write_executable(
        bin_dir / "chrt",
        '#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$LAUNCH_LOG"\nshift 2\nexec "$@"\n',
    )
    _write_executable(bin_dir / "numactl", '#!/bin/sh\nshift\nexec "$@"\n')
    _write_executable(bin_dir / "cargo", '#!/bin/sh\nenv > "$CAPTURE_ENV"\n')
    helper = tmp_path / "metadata-helper"
    _write_fake_metadata_helper(helper)
    stale_home = tmp_path / "stale-criterion-home"
    metadata_environment_log = tmp_path / "metadata-environment-log"
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{bin_dir}{os.pathsep}{environment['PATH']}",
            "CORE": "5",
            "LOCK_DIR": str(tmp_path / "locks"),
            "BENCH": "speedup",
            "SAVE": "candidate",
            "CAPTURE_ENV": str(tmp_path / "cargo-environment"),
            "CRITERION_HOME": str(stale_home),
            "METADATA_LOG": str(tmp_path / "metadata-log"),
            "METADATA_ENVIRONMENT_LOG": str(metadata_environment_log),
            "EVENT_LOG": str(tmp_path / "event-log"),
            "LAUNCH_LOG": str(tmp_path / "launcher-log"),
            "OPTHASH_BENCHMARK_METADATA_HELPER": str(helper),
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
    cargo_environment = dict(
        line.split("=", 1)
        for line in (tmp_path / "cargo-environment").read_text().splitlines()
        if "=" in line
    )
    assert "CRITERION_HOME" not in cargo_environment
    assert metadata_environment_log.read_text().splitlines() == [
        str(stale_home),
        str(stale_home),
    ]
    launches = (tmp_path / "launcher-log").read_text().splitlines()
    assert len(launches) == 3
    assert "env -u CRITERION_HOME" not in launches[0]
    assert "taskset -c 5" in launches[1]
    assert "env -u CRITERION_HOME" in launches[1]
    assert "env -u CRITERION_HOME" not in launches[2]


def test_bench_script_routes_named_speedup_modes_through_metadata_sidecars(
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
        """#!/bin/sh
env > "$CAPTURE_ENV"
printf '%s\n' "$@" > "$CAPTURE_ARGS"
printf 'cargo\n' >> "$EVENT_LOG"
""",
    )
    helper = tmp_path / "metadata-helper"
    _write_fake_metadata_helper(helper)

    cases = [
        ({"SAVE": "candidate"}, ["begin", "publish"]),
        ({"BASELINE": "anchor"}, ["verify"]),
        (
            {"LOAD": "candidate", "BASELINE": "anchor"},
            ["verify"],
        ),
    ]
    for index, (overrides, expected_commands) in enumerate(cases):
        capture_env = tmp_path / f"environment-{index}"
        capture_args = tmp_path / f"arguments-{index}"
        metadata_log = tmp_path / f"metadata-{index}"
        event_log = tmp_path / f"events-{index}"
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{bin_dir}{os.pathsep}{environment['PATH']}",
                "CORE": "5",
                "LOCK_DIR": str(tmp_path / "locks"),
                "BENCH": "speedup",
                "CAPTURE_ENV": str(capture_env),
                "CAPTURE_ARGS": str(capture_args),
                "METADATA_LOG": str(metadata_log),
                "EVENT_LOG": str(event_log),
                "OPTHASH_BENCHMARK_METADATA_HELPER": str(helper),
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
        assert "CRITERION_HOME" not in captured
        commands = [json.loads(line) for line in metadata_log.read_text().splitlines()]
        assert [command[0] for command in commands] == expected_commands
        assert event_log.read_text().splitlines() == [
            *expected_commands[:1],
            "cargo",
            *expected_commands[1:],
        ]
        first = commands[0]
        assert "--target" in first and first[first.index("--target") + 1] == "speedup"
        if first[0] == "begin":
            assert first[first.index("--baseline") + 1] == "candidate"
            publish = commands[1]
            assert publish[publish.index("--source-before") + 1] == "source-before"
            assert publish[publish.index("--core") + 1] == "5"
            assert publish[publish.index("--requested-bench") + 1] == "speedup"
            assert publish[publish.index("--forwarded-arg") + 1] == "--measurement-time"
            assert (
                publish[
                    publish.index(
                        "--forwarded-arg", publish.index("--forwarded-arg") + 1
                    )
                    + 1
                ]
                == "10"
            )
        elif "LOAD" in overrides:
            assert first[first.index("--baseline") + 1] == "candidate"
            assert first[first.index("--compare") + 1] == "anchor"
        else:
            assert first[first.index("--baseline") + 1] == "anchor"
            assert "--compare" not in first
        assert capture_args.read_text().splitlines()[-2:] == [
            "--measurement-time",
            "10",
        ]


def test_bench_script_does_not_publish_metadata_when_cargo_fails(
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
        "#!/bin/sh\nprintf 'cargo\n' >> \"$EVENT_LOG\"\nexit 23\n",
    )
    helper = tmp_path / "metadata-helper"
    _write_fake_metadata_helper(helper)
    metadata_log = tmp_path / "metadata-log"
    event_log = tmp_path / "event-log"
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{bin_dir}{os.pathsep}{environment['PATH']}",
            "CORE": "5",
            "LOCK_DIR": str(tmp_path / "locks"),
            "BENCH": "speedup",
            "SAVE": "candidate",
            "METADATA_LOG": str(metadata_log),
            "EVENT_LOG": str(event_log),
            "OPTHASH_BENCHMARK_METADATA_HELPER": str(helper),
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

    assert result.returncode == 23
    commands = [json.loads(line) for line in metadata_log.read_text().splitlines()]
    assert [command[0] for command in commands] == ["begin"]
    assert event_log.read_text().splitlines() == ["begin", "cargo"]


def test_bench_script_saves_all_sidecars_without_linux_pinning(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_executable(bin_dir / "uname", "#!/bin/sh\necho Darwin\n")
    _write_executable(
        bin_dir / "cargo",
        "#!/bin/sh\nprintf 'cargo\\n' >> \"$EVENT_LOG\"\n",
    )
    helper = tmp_path / "metadata-helper"
    _write_fake_metadata_helper(helper)
    metadata_log = tmp_path / "metadata-log"
    event_log = tmp_path / "event-log"
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{bin_dir}{os.pathsep}{environment['PATH']}",
            "BENCH": "all",
            "SAVE": "candidate",
            "METADATA_LOG": str(metadata_log),
            "EVENT_LOG": str(event_log),
            "OPTHASH_BENCHMARK_METADATA_HELPER": str(helper),
        }
    )
    environment.pop("CORE", None)

    result = subprocess.run(
        ["bash", "scripts/bench.sh"],
        cwd=REPO_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    commands = [json.loads(line) for line in metadata_log.read_text().splitlines()]
    assert [command[0] for command in commands] == [
        "begin",
        "publish",
        "begin",
        "publish",
    ]
    assert event_log.read_text().splitlines() == [
        "begin",
        "cargo",
        "publish",
        "begin",
        "cargo",
        "publish",
    ]
    assert [command[command.index("--target") + 1] for command in commands] == [
        "speedup",
        "speedup",
        "mean_latency",
        "mean_latency",
    ]
    assert [
        command[command.index("--core") + 1]
        for command in commands
        if command[0] == "publish"
    ] == ["0", "0"]


def _write_fake_metadata_helper(path: Path) -> None:
    _write_executable(
        path,
        """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
with Path(os.environ["METADATA_LOG"]).open("a") as stream:
    stream.write(json.dumps(args) + "\\n")
with Path(os.environ["EVENT_LOG"]).open("a") as stream:
    stream.write(args[0] + "\\n")
if environment_log := os.environ.get("METADATA_ENVIRONMENT_LOG"):
    with Path(environment_log).open("a") as stream:
        stream.write(os.environ.get("CRITERION_HOME", "<unset>") + "\\n")
if args[0] == "begin":
    print("source-before")
""",
    )


def _write_executable(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o755)
