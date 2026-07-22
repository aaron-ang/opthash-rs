import copy
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "snapshot-criterion-pair.sh"
LAUNCHER = ROOT / "scripts" / "cache-gate.sh"
PERF_LAUNCHER = ROOT / "scripts" / "cache-gate-perf.sh"
PERF_SUPPORT = ROOT / "scripts" / "cache-gate-perf-support.py"
CONTROL_IDS = (
    "cache_gate_insert/cache_gate_insert_std",
    "cache_gate_insert/cache_gate_insert_hashbrown",
)
ELASTIC_IDS = (
    "cache_gate_insert/cache_gate_insert_elastic",
    "cache_gate_get_hit_elastic",
)
FUNNEL_IDS = (
    "cache_gate_insert/cache_gate_insert_funnel",
    "cache_gate_get_hit_funnel",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def make_fixture(
    tmp_path: Path, *, omit_change: bool = False, preexisting_changes: bool = False
):
    tmp_path = (
        ROOT
        / "target"
        / "cache-gate-test-fixtures"
        / f"{tmp_path.parent.name}-{tmp_path.name}"
    )
    tmp_path.mkdir(parents=True, exist_ok=False)
    harness = tmp_path / "reviewed-harness"
    scripts = harness / "scripts"
    scripts.mkdir(parents=True)
    snapshot_tool = write(scripts / "snapshot-criterion-pair.sh", SCRIPT.read_text())
    snapshot_tool.chmod(0o755)
    elf_layout_tool = write(
        scripts / "cache-gate-elf-layout.py",
        """#!/usr/bin/env python3
import json
import sys
from pathlib import Path

if len(sys.argv) != 4 or sys.argv[1:3] != ["validate-manifest", "--manifest"]:
    raise SystemExit("error: unsupported fixture validator invocation")
manifest = json.loads(Path(sys.argv[3]).read_text())
if "elf_layout" in manifest and set(manifest["elf_layout"]) != {
    "elastic_cache_gate", "funnel_cache_gate", "cache_gate_profile"
}:
    raise SystemExit("error: ELF layout executable set mismatch")
""",
    )
    elf_layout_tool.chmod(0o755)
    tool_paths = {
        "snapshot": snapshot_tool,
        "elf_layout": elf_layout_tool,
    }
    for name, filename in {
        "launcher": "cache-gate.sh",
        "perf_launcher": "cache-gate-perf.sh",
        "perf_support": "cache-gate-perf-support.py",
        "extractor": "extract-hot-symbols.py",
        "link_wrapper": "cache-gate-link-wrapper.py",
    }.items():
        contents = (
            LAUNCHER.read_text() if name == "launcher" else "#!/bin/sh\nexit 97\n"
        )
        path = write(scripts / filename, contents)
        path.chmod(0o755)
        tool_paths[name] = path
    subprocess.run(["git", "init", "-q"], cwd=harness, check=True)
    subprocess.run(["git", "add", "scripts"], cwd=harness, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Cache Gate Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "fixture tools",
        ],
        cwd=harness,
        check=True,
    )
    harness_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=harness, text=True
    ).strip()
    harness_tree = subprocess.check_output(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=harness, text=True
    ).strip()

    def tool_record(path: Path) -> dict:
        relative = path.relative_to(harness)
        blob = subprocess.check_output(
            ["git", "rev-parse", f"HEAD:{relative}"], cwd=harness, text=True
        ).strip()
        return {
            "absolute_path": str(path.resolve()),
            "sha256": digest(path),
            "git_blob": blob,
            "git_blob_sha256": digest(path),
            "reviewed_root": str(harness.resolve()),
            "reviewed_commit": harness_commit,
            "reviewed_tree": harness_tree,
        }

    authenticated_tools = {name: tool_record(path) for name, path in tool_paths.items()}
    criterion = tmp_path / "criterion"
    snapshot = tmp_path / "snapshots"
    run_key = hashlib.sha256(str(tmp_path).encode()).hexdigest()[:12]
    anchor_run = f"anchor-{run_key}"
    candidate_run = f"candidate-{run_key}"
    for benchmark in (*CONTROL_IDS, *ELASTIC_IDS, *FUNNEL_IDS):
        write(
            criterion / benchmark / anchor_run / "estimates.json", '{"run":"anchor"}\n'
        )
        write(
            criterion / benchmark / anchor_run / "sample.json",
            '{"samples":[1]}\n',
        )
        write(
            criterion / benchmark / candidate_run / "estimates.json",
            '{"run":"candidate"}\n',
        )
        write(
            criterion / benchmark / candidate_run / "sample.json",
            '{"samples":[2]}\n',
        )
        if preexisting_changes:
            write(
                criterion / benchmark / "change" / "estimates.json",
                '{"stale":true}\n',
            )

    invocation = tmp_path / "control-invocation.txt"
    generated = CONTROL_IDS[:1] if omit_change else CONTROL_IDS
    commands = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "save_baseline=",
        "previous=",
        'for argument in "$@"; do',
        "  if [[ $previous == --save-baseline ]]; then save_baseline=$argument; previous=; continue; fi",
        "  previous=$argument",
        "done",
        "if [[ -n $save_baseline ]]; then",
    ]
    for benchmark in CONTROL_IDS:
        commands += [
            f'  mkdir -p "$CRITERION_HOME/{benchmark}/$save_baseline"',
            f'  printf \'{{"saved":true}}\\n\' > "$CRITERION_HOME/{benchmark}/$save_baseline/estimates.json"',
            f'  printf \'{{"samples":[3]}}\\n\' > "$CRITERION_HOME/{benchmark}/$save_baseline/sample.json"',
        ]
    commands += [
        "  exit 0",
        "fi",
        f"printf '%s\\n' \"$*\" > {invocation}",
    ]
    for benchmark in generated:
        output = criterion / benchmark / "change" / "estimates.json"
        commands += [
            f"mkdir -p {output.parent}",
            f"printf '{{\"fresh\":true}}\\n' > {output}",
        ]
    control = write(tmp_path / "control", "\n".join(commands) + "\n")
    control.chmod(0o755)
    cargo_manifest = write(
        tmp_path / "control-Cargo.toml", "[package]\nname='control'\n"
    )
    cargo_lock = write(tmp_path / "control-Cargo.lock", "version = 4\n")
    source = write(tmp_path / "control-main.rs", "fn main() {}\n")
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    tree = subprocess.check_output(
        ["git", "rev-parse", f"{commit}^{{tree}}"], cwd=ROOT, text=True
    ).strip()
    provenance = {
        "builder_commit": commit,
        "builder_tree": tree,
        "binary": {"absolute_path": str(control), "sha256": digest(control)},
        "inputs": {
            "cargo_manifest": {
                "absolute_path": str(cargo_manifest),
                "sha256": digest(cargo_manifest),
            },
            "cargo_lock": {
                "absolute_path": str(cargo_lock),
                "sha256": digest(cargo_lock),
            },
            "source": {"absolute_path": str(source), "sha256": digest(source)},
        },
    }
    provenance_path = write(
        tmp_path / "control.provenance.json", json.dumps(provenance) + "\n"
    )

    executable_ids = {
        "elastic_cache_gate": (
            "cache_gate_insert/cache_gate_insert_elastic",
            "cache_gate_get_hit_elastic",
        ),
        "funnel_cache_gate": (
            "cache_gate_insert/cache_gate_insert_funnel",
            "cache_gate_get_hit_funnel",
        ),
        "cache_gate_profile": (),
    }
    executables = {}
    symbols = {}
    for name in ("elastic_cache_gate", "funnel_cache_gate", "cache_gate_profile"):
        invocation_path = tmp_path / f"{name}.invocation"
        executable_lines = [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            f"printf '%s\\n' \"$*\" > {invocation_path}",
        ]
        for benchmark in executable_ids[name]:
            output = criterion / benchmark / "change" / "estimates.json"
            executable_lines += [
                f"mkdir -p {output.parent}",
                f"printf '{{\"fresh\":true}}\\n' > {output}",
            ]
        executable = write(tmp_path / name, "\n".join(executable_lines) + "\n")
        executable.chmod(0o755)
        link_map = write(tmp_path / f"{name}.map", f"map {name}\n")
        executables[name] = {
            "absolute_path": str(executable),
            "sha256": digest(executable),
            "link_map": {"absolute_path": str(link_map), "sha256": digest(link_map)},
        }
        symbol_names = {
            "elastic_cache_gate": [
                "fixture::elastic_cache_gate_insert_kernel",
                "fixture::elastic_cache_gate_get_kernel",
            ],
            "funnel_cache_gate": [
                "fixture::funnel_cache_gate_insert_kernel",
                "fixture::funnel_cache_gate_get_kernel",
            ],
            "cache_gate_profile": [
                "fixture::elastic_profile_insert_kernel",
                "fixture::elastic_profile_get_kernel",
                "fixture::funnel_profile_insert_kernel",
                "fixture::funnel_profile_get_kernel",
            ],
        }[name]
        symbols[name] = {
            "binary": str(executable),
            "binary_sha256": digest(executable),
            "architecture": "aarch64",
            "symbols": [
                {
                    "name": symbol,
                    "start": index * 2 + 1,
                    "end": index * 2 + 2,
                    "size": 1,
                }
                for index, symbol in enumerate(symbol_names)
            ],
        }
    control_record = {
        **provenance,
        "provenance_path": str(provenance_path),
        "provenance_sha256": digest(provenance_path),
    }
    manifest = {
        "commit": commit,
        "tree": tree,
        "architecture": "aarch64",
        "runner_root": str(ROOT.resolve()),
        "empty_diff_assertion": True,
        "variant": f"fixture-anchor-{run_key}",
        "control": control_record,
        "executables": executables,
        "symbols": symbols,
        "tools": authenticated_tools,
    }
    anchor_manifest = write(
        tmp_path / "anchor-manifest.json", json.dumps(manifest) + "\n"
    )
    candidate = copy.deepcopy(manifest)
    candidate["variant"] = f"fixture-candidate-{run_key}"
    for name in executable_ids:
        original = Path(candidate["executables"][name]["absolute_path"])
        candidate_binary = write(tmp_path / f"candidate-{name}", original.read_text())
        candidate_binary.chmod(0o755)
        candidate["executables"][name]["absolute_path"] = str(candidate_binary)
        candidate["executables"][name]["sha256"] = digest(candidate_binary)
        candidate["symbols"][name]["binary"] = str(candidate_binary)
        candidate["symbols"][name]["binary_sha256"] = digest(candidate_binary)
    candidate_manifest = write(
        tmp_path / "candidate-manifest.json", json.dumps(candidate) + "\n"
    )

    def result_records(ids, run):
        records = []
        for benchmark in ids:
            baseline = criterion / benchmark / run
            for path in sorted(baseline.rglob("*")):
                if path.is_file():
                    records.append(
                        {
                            "absolute_path": str(path.resolve()),
                            "relative_path": path.relative_to(criterion).as_posix(),
                            "sha256": digest(path),
                            "size": path.stat().st_size,
                        }
                    )
        return records

    env_tool = Path(shutil.which("env")).resolve()
    flock_tool = Path(shutil.which("flock")).resolve()
    taskset_tool = Path(shutil.which("taskset")).resolve()
    setarch_tool = Path(shutil.which("setarch")).resolve()
    fixture_core = str(min(os.sched_getaffinity(0)))
    fixture_system_tools = [
        {"absolute_path": str(path), "sha256": digest(path)}
        for path in (env_tool, flock_tool, taskset_tool, setarch_tool)
    ]

    def run_evidence(manifest_path, data, target, run, ids, executable):
        mode = "CONTROL" if target == "control" else target
        executable_argv = [
            executable["absolute_path"],
            "--bench",
            "--save-baseline",
            run,
        ]
        criterion_environment = [
            str(env_tool),
            f"CRITERION_HOME={criterion.resolve()}",
        ]
        pin_wrapper = [
            str(taskset_tool),
            "-c",
            fixture_core,
            str(setarch_tool),
            "-R",
        ]
        record = {
            "schema": "opthash-criterion-run-v2",
            "runner_root": str(ROOT.resolve()),
            "commit": commit,
            "tree": tree,
            "empty_diff_assertion": True,
            "mode": mode,
            "run": run,
            "criterion_evidence_root": str(criterion.resolve()),
            "build_manifest": None
            if target == "control"
            else {
                "absolute_path": str(manifest_path.resolve()),
                "sha256": digest(manifest_path),
            },
            "control_provenance": {
                "absolute_path": control_record["provenance_path"],
                "sha256": control_record["provenance_sha256"],
            }
            if target == "control"
            else None,
            "producer_launcher": authenticated_tools["launcher"],
            "measurement": {
                "core": fixture_core,
                "launcher_prefix": [],
                "numa_wrapper": [],
                "pin_wrapper": pin_wrapper,
                "criterion_environment": criterion_environment,
                "system_tools": fixture_system_tools,
                "executable_argv": executable_argv,
                "executed_argv": pin_wrapper + criterion_environment + executable_argv,
            },
            "executable": executable,
            "expected_benchmark_ids": list(ids),
            "results": result_records(ids, run),
        }
        if target == "control":
            output = ROOT / "target/cache-gate-runs/control" / f"{run}.json"
        else:
            output = (
                ROOT
                / "target/cache-gate-runs"
                / data["variant"]
                / f"{target}-{run}.json"
            )
        write(output, json.dumps(record, indent=2, sort_keys=True) + "\n")
        return output

    run_evidence_paths = {"anchor": {}, "candidate": {}}
    for label, manifest_path, data, run in (
        ("anchor", anchor_manifest, manifest, anchor_run),
        ("candidate", candidate_manifest, candidate, candidate_run),
    ):
        run_evidence_paths[label]["control"] = run_evidence(
            manifest_path, data, "control", run, CONTROL_IDS, control_record["binary"]
        )
        for target, ids in (
            ("elastic_cache_gate", ELASTIC_IDS),
            ("funnel_cache_gate", FUNNEL_IDS),
        ):
            run_evidence_paths[label][target] = run_evidence(
                manifest_path,
                data,
                target,
                run,
                ids,
                {
                    "absolute_path": data["executables"][target]["absolute_path"],
                    "sha256": data["executables"][target]["sha256"],
                },
            )
    return {
        "criterion": criterion,
        "snapshot": snapshot,
        "anchor_run": anchor_run,
        "candidate_run": candidate_run,
        "commit": commit,
        "anchor_manifest": anchor_manifest,
        "candidate_manifest": candidate_manifest,
        "invocation": invocation,
        "candidate_elastic": Path(
            candidate["executables"]["elastic_cache_gate"]["absolute_path"]
        ),
        "elastic_invocation": tmp_path / "elastic_cache_gate.invocation",
        "snapshot_tool": snapshot_tool,
        "launcher": tool_paths["launcher"],
        "run_evidence": run_evidence_paths,
        "control": control,
        "control_provenance": provenance_path,
    }


def command(fixture, **overrides):
    values = {
        "runner-root": ROOT,
        "criterion-root": fixture["criterion"],
        "snapshot-root": fixture["snapshot"].relative_to(ROOT),
        "arch": "aarch64",
        "comparison": "fixture-comparison",
        "pair": "1",
        "target": "control",
        "anchor-run": fixture["anchor_run"],
        "candidate-run": fixture["candidate_run"],
        "anchor-commit": fixture["commit"],
        "candidate-commit": fixture["commit"],
        "anchor-manifest": fixture["anchor_manifest"],
        "candidate-manifest": fixture["candidate_manifest"],
    }
    values.update(overrides)
    result = [str(fixture["snapshot_tool"])]
    for name, value in values.items():
        result += [f"--{name}", str(value)]
    return result


def test_snapshot_executes_exact_comparison_and_copies_complete_pair(tmp_path):
    fixture = make_fixture(tmp_path)
    completed = subprocess.run(
        command(fixture), cwd=ROOT, text=True, capture_output=True
    )
    assert completed.returncode == 0, completed.stderr
    invocation = fixture["invocation"].read_text()
    assert invocation == (
        f"--bench --load-baseline {fixture['candidate_run']} "
        f"--baseline {fixture['anchor_run']}\n"
    )
    destination = fixture["snapshot"] / "aarch64/fixture-comparison/pair-1"
    assert len(list((destination / "change").rglob("estimates.json"))) == 2
    assert len(list((destination / "absolute/anchor").rglob("estimates.json"))) == 2
    assert len(list((destination / "absolute/anchor").rglob("sample.json"))) == 2
    pair_manifest = json.loads((destination / "pair-manifest.json").read_text())
    assert pair_manifest["comparison_command"][1:] == [
        "--bench",
        "--load-baseline",
        fixture["candidate_run"],
        "--baseline",
        fixture["anchor_run"],
    ]
    assert (
        pair_manifest["control"]
        == json.loads(fixture["anchor_manifest"].read_text())["control"]
    )


def test_real_launcher_save_evidence_is_consumed_end_to_end(tmp_path):
    fixture = make_fixture(tmp_path)
    harness = fixture["launcher"].parents[1]
    harness_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=harness, text=True
    ).strip()
    harness_tree = subprocess.check_output(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=harness, text=True
    ).strip()

    provenance = json.loads(fixture["control_provenance"].read_text())
    provenance["builder_commit"] = harness_commit
    provenance["builder_tree"] = harness_tree
    fixture["control_provenance"].write_text(json.dumps(provenance) + "\n")
    control_record = {
        **provenance,
        "provenance_path": str(fixture["control_provenance"].resolve()),
        "provenance_sha256": digest(fixture["control_provenance"]),
    }
    for manifest_path in (
        fixture["anchor_manifest"],
        fixture["candidate_manifest"],
    ):
        manifest = json.loads(manifest_path.read_text())
        manifest["runner_root"] = str(harness.resolve())
        manifest["commit"] = harness_commit
        manifest["tree"] = harness_tree
        manifest["control"] = control_record
        manifest_path.write_text(json.dumps(manifest) + "\n")

    run_key = hashlib.sha256(str(tmp_path).encode()).hexdigest()[:12]
    anchor_run = f"produced-anchor-{run_key}"
    candidate_run = f"produced-candidate-{run_key}"
    environment = launcher_env(
        CONTROL=1,
        CORE=min(os.sched_getaffinity(0)),
        OPTHASH_CRITERION_ROOT=fixture["criterion"],
        CACHE_GATE_CONTROL_BIN=fixture["control"],
        CACHE_GATE_CONTROL_PROVENANCE=fixture["control_provenance"],
    )
    evidence_paths = []
    for run in (anchor_run, candidate_run):
        completed = subprocess.run(
            [str(fixture["launcher"]), "--runner-root", str(harness)],
            env={**environment, "SAVE": run},
            text=True,
            capture_output=True,
        )
        assert completed.returncode == 0, completed.stderr
        evidence_paths.append(
            harness / "target/cache-gate-runs/control" / f"{run}.json"
        )

    evidence = json.loads(evidence_paths[0].read_text())
    assert evidence["schema"] == "opthash-criterion-run-v2"
    assert (
        evidence["producer_launcher"]
        == json.loads(fixture["anchor_manifest"].read_text())["tools"]["launcher"]
    )
    assert evidence["measurement"]["executable_argv"][:4] == [
        str(fixture["control"].resolve()),
        "--bench",
        "--save-baseline",
        anchor_run,
    ]
    assert len(evidence["results"]) == 4

    snapshot_root = harness / "target/snapshots"
    completed = subprocess.run(
        command(
            fixture,
            **{
                "runner-root": harness,
                "snapshot-root": "target/snapshots",
                "anchor-run": anchor_run,
                "candidate-run": candidate_run,
                "anchor-commit": harness_commit,
                "candidate-commit": harness_commit,
            },
        ),
        cwd=harness,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 0, completed.stderr
    destination = snapshot_root / "aarch64/fixture-comparison/pair-1"
    assert (destination / "run-evidence/anchor.json").read_bytes() == evidence_paths[
        0
    ].read_bytes()
    assert len(list((destination / "absolute/anchor").rglob("*.json"))) == 4


def test_snapshot_rejects_missing_fresh_change_output(tmp_path):
    fixture = make_fixture(tmp_path, omit_change=True)
    completed = subprocess.run(
        command(fixture), cwd=ROOT, text=True, capture_output=True
    )
    assert completed.returncode != 0
    assert "missing fresh change" in completed.stderr
    assert not (fixture["snapshot"] / "aarch64/fixture-comparison/pair-1").exists()


def test_snapshot_rejects_control_binary_mutated_during_offline_execution(tmp_path):
    fixture = make_fixture(tmp_path)
    control = fixture["control"]
    control.write_text(
        control.read_text() + "\nprintf '# mutated during comparison\\n' >> \"$0\"\n"
    )
    control.chmod(0o755)
    provenance_path = fixture["control_provenance"]
    provenance = json.loads(provenance_path.read_text())
    provenance["binary"]["sha256"] = digest(control)
    provenance_path.write_text(json.dumps(provenance) + "\n")
    for manifest_name in ("anchor_manifest", "candidate_manifest"):
        manifest = json.loads(fixture[manifest_name].read_text())
        manifest["control"]["binary"]["sha256"] = digest(control)
        manifest["control"]["provenance_sha256"] = digest(provenance_path)
        fixture[manifest_name].write_text(json.dumps(manifest) + "\n")
    for label in ("anchor", "candidate"):
        evidence_path = fixture["run_evidence"][label]["control"]
        evidence = json.loads(evidence_path.read_text())
        evidence["executable"]["sha256"] = digest(control)
        evidence["control_provenance"]["sha256"] = digest(provenance_path)
        evidence_path.write_text(json.dumps(evidence) + "\n")

    completed = subprocess.run(
        command(fixture), cwd=ROOT, text=True, capture_output=True
    )

    assert completed.returncode != 0
    assert "control binary changed during offline execution" in completed.stderr
    assert not (fixture["snapshot"] / "aarch64/fixture-comparison/pair-1").exists()


def test_snapshot_does_not_accept_preexisting_change_as_fresh(tmp_path):
    fixture = make_fixture(tmp_path, omit_change=True, preexisting_changes=True)
    completed = subprocess.run(
        command(fixture), cwd=ROOT, text=True, capture_output=True
    )
    assert completed.returncode != 0
    assert "missing fresh change" in completed.stderr
    assert not (fixture["snapshot"] / "aarch64/fixture-comparison/pair-1").exists()


def test_snapshot_rejects_unexpected_relevant_change_output(tmp_path):
    fixture = make_fixture(tmp_path)
    control = fixture["criterion"].parents[0] / "control"
    extra = (
        fixture["criterion"]
        / "cache_gate_insert/cache_gate_insert_elastic/change/estimates.json"
    )
    with control.open("a") as stream:
        stream.write(f"mkdir -p {extra.parent}\n")
        stream.write(f"printf '{{\"fresh\":true}}\\n' > {extra}\n")
    manifest = json.loads(fixture["anchor_manifest"].read_text())
    manifest["control"]["binary"]["sha256"] = digest(control)
    provenance_path = Path(manifest["control"]["provenance_path"])
    provenance = json.loads(provenance_path.read_text())
    provenance["binary"]["sha256"] = digest(control)
    provenance_path.write_text(json.dumps(provenance) + "\n")
    manifest["control"]["provenance_sha256"] = digest(provenance_path)
    fixture["anchor_manifest"].write_text(json.dumps(manifest) + "\n")
    fixture["candidate_manifest"].write_text(json.dumps(manifest) + "\n")
    for label in ("anchor", "candidate"):
        evidence_path = fixture["run_evidence"][label]["control"]
        evidence = json.loads(evidence_path.read_text())
        evidence["executable"]["sha256"] = digest(control)
        evidence["control_provenance"]["sha256"] = digest(provenance_path)
        evidence_path.write_text(json.dumps(evidence, sort_keys=True) + "\n")

    completed = subprocess.run(
        command(fixture), cwd=ROOT, text=True, capture_output=True
    )
    assert completed.returncode != 0
    assert "unexpected target change result" in completed.stderr


@pytest.mark.parametrize("name", ["../escape", ".", "..", "a/b"])
def test_snapshot_rejects_unsafe_components(tmp_path, name):
    fixture = make_fixture(tmp_path)
    completed = subprocess.run(
        command(fixture, comparison=name), cwd=ROOT, text=True, capture_output=True
    )
    assert completed.returncode != 0
    assert "unsafe component" in completed.stderr


def test_snapshot_rejects_relative_criterion_root(tmp_path):
    fixture = make_fixture(tmp_path)
    completed = subprocess.run(
        command(fixture, **{"criterion-root": "../../criterion-escape"}),
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    assert completed.returncode != 0
    assert "--criterion-root must be absolute" in completed.stderr


def test_snapshot_rejects_path_spoofed_writable_flock(tmp_path):
    fixture = make_fixture(tmp_path)
    fake_bin = fixture["criterion"].parent / "fake-flock-bin"
    fake_flock = write(fake_bin / "flock", "#!/bin/sh\nexit 0\n")
    fake_flock.chmod(0o775)
    fake_realpath = write(fake_bin / "realpath", "#!/bin/sh\nexit 97\n")
    fake_realpath.chmod(0o755)
    fake_stat = write(
        fake_bin / "stat",
        "#!/bin/sh\ncase \"$*\" in *%u*) printf '0\\n' ;; *) printf '755\\n' ;; esac\n",
    )
    fake_stat.chmod(0o755)
    fake_sha = write(fake_bin / "sha256sum", f"#!/bin/sh\nprintf '{'0' * 64}  -\\n'\n")
    fake_sha.chmod(0o755)

    completed = subprocess.run(
        command(fixture),
        cwd=ROOT,
        env=launcher_env(PATH=f"{fake_bin}:{os.environ['PATH']}"),
        text=True,
        capture_output=True,
    )

    assert completed.returncode != 0
    assert "system tool" in completed.stderr
    assert not fixture["invocation"].exists()


def test_cache_gate_rejects_combined_measurement_tool_bootstrap_spoof(tmp_path):
    fixture = make_fixture(tmp_path)
    fake_bin = fixture["criterion"].parent / "fake-measurement-bin"
    for name, contents, mode in (
        ("taskset", "#!/bin/sh\nexit 0\n", 0o775),
        ("realpath", "#!/bin/sh\nexit 97\n", 0o755),
        (
            "stat",
            "#!/bin/sh\ncase \"$*\" in *%u*) printf '0\\n' ;; *) printf '755\\n' ;; esac\n",
            0o755,
        ),
        ("sha256sum", f"#!/bin/sh\nprintf '{'0' * 64}  -\\n'\n", 0o755),
    ):
        tool = write(fake_bin / name, contents)
        tool.chmod(mode)
    save = f"spoof-{hashlib.sha256(str(tmp_path).encode()).hexdigest()[:12]}"

    completed = subprocess.run(
        [str(fixture["launcher"]), "--runner-root", str(ROOT)],
        env=launcher_env(
            CONTROL=1,
            SAVE=save,
            CORE=min(os.sched_getaffinity(0)),
            OPTHASH_CRITERION_ROOT=fixture["criterion"],
            CACHE_GATE_CONTROL_BIN=fixture["control"],
            CACHE_GATE_CONTROL_PROVENANCE=fixture["control_provenance"],
            PATH=f"{fake_bin}:{os.environ['PATH']}",
        ),
        text=True,
        capture_output=True,
    )

    assert completed.returncode != 0
    assert "system tool" in completed.stderr
    assert not any(
        (fixture["criterion"] / benchmark / save).exists() for benchmark in CONTROL_IDS
    )


def test_snapshot_rejects_different_control_provenance(tmp_path):
    fixture = make_fixture(tmp_path)
    candidate = json.loads(fixture["candidate_manifest"].read_text())
    candidate["control"]["binary"]["sha256"] = "0" * 64
    fixture["candidate_manifest"].write_text(json.dumps(candidate) + "\n")
    completed = subprocess.run(
        command(fixture), cwd=ROOT, text=True, capture_output=True
    )
    assert completed.returncode != 0
    assert "control provenance differs" in completed.stderr


def test_stable_snapshot_executes_exact_candidate_binary_without_cargo(tmp_path):
    fixture = make_fixture(tmp_path)
    for benchmark in (
        "cache_gate_insert/cache_gate_insert_elastic",
        "cache_gate_get_hit_elastic",
    ):
        write(
            fixture["criterion"] / benchmark / fixture["anchor_run"] / "estimates.json",
            '{"run":"anchor"}\n',
        )
        write(
            fixture["criterion"]
            / benchmark
            / fixture["candidate_run"]
            / "estimates.json",
            '{"run":"candidate"}\n',
        )
    completed = subprocess.run(
        command(fixture, target="elastic_cache_gate"),
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stderr
    destination = fixture["snapshot"] / "aarch64/fixture-comparison/pair-1"
    pair = json.loads((destination / "pair-manifest.json").read_text())
    assert Path(pair["comparison_command"][0]) == fixture["candidate_elastic"]
    assert "cargo" not in " ".join(pair["comparison_command"])
    assert pair["offline_execution_count"] == 1
    assert pair["runner_root"] == str(ROOT.resolve())


def test_stable_snapshot_refuses_candidate_binary_hash_mismatch(tmp_path):
    fixture = make_fixture(tmp_path)
    fixture["candidate_elastic"].write_text("tampered\n")
    completed = subprocess.run(
        command(fixture, target="elastic_cache_gate"),
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    assert completed.returncode != 0
    assert "hash mismatch" in completed.stderr


def test_snapshot_rejects_stable_binary_mutated_during_offline_execution(tmp_path):
    fixture = make_fixture(tmp_path)
    binary = fixture["candidate_elastic"]
    binary.write_text(
        binary.read_text() + "\nprintf '# mutated during comparison\\n' >> \"$0\"\n"
    )
    binary.chmod(0o755)
    manifest_path = fixture["candidate_manifest"]
    manifest = json.loads(manifest_path.read_text())
    manifest["executables"]["elastic_cache_gate"]["sha256"] = digest(binary)
    manifest["symbols"]["elastic_cache_gate"]["binary_sha256"] = digest(binary)
    manifest_path.write_text(json.dumps(manifest) + "\n")
    evidence_path = fixture["run_evidence"]["candidate"]["elastic_cache_gate"]
    evidence = json.loads(evidence_path.read_text())
    evidence["executable"]["sha256"] = digest(binary)
    evidence["build_manifest"]["sha256"] = digest(manifest_path)
    evidence_path.write_text(json.dumps(evidence) + "\n")

    completed = subprocess.run(
        command(fixture, target="elastic_cache_gate"),
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    assert completed.returncode != 0
    assert "stable binary changed during offline execution" in completed.stderr
    assert not (fixture["snapshot"] / "aarch64/fixture-comparison/pair-1").exists()


def test_offline_binary_rehash_is_immediate_and_branch_local():
    source = SCRIPT.read_text()
    execution = (
        '\tCRITERION_HOME="$criterion_root" "${comparison_command[@]}" '
        '>"$comparison_stdout" 2>"$comparison_stderr"'
    )
    control_rehash = (
        '\tpost_execution_control_hash=$("$CACHE_GATE_SHA256_TOOL" -- '
        '"$control_binary"); '
    )
    stable_rehash = (
        '\tpost_execution_stable_hash=$("$CACHE_GATE_SHA256_TOOL" -- '
        '"$stable_binary"); '
    )
    control_branch = source.index("control)\n")
    stable_branch = source.index("elastic_cache_gate | funnel_cache_gate)\n")
    scaled_branch = source.index("scaled_insert)\n", stable_branch)

    assert execution + "\n" + control_rehash in source[control_branch:stable_branch]
    assert execution + "\n" + stable_rehash in source[stable_branch:scaled_branch]
    assert "$offline_binary" not in source


def test_stable_snapshot_rejects_run_evidence_manifest_mismatch(tmp_path):
    fixture = make_fixture(tmp_path)
    evidence_path = fixture["run_evidence"]["candidate"]["elastic_cache_gate"]
    evidence = json.loads(evidence_path.read_text())
    evidence["build_manifest"]["sha256"] = "0" * 64
    evidence_path.write_text(json.dumps(evidence) + "\n")

    completed = subprocess.run(
        command(fixture, target="elastic_cache_gate"),
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    assert completed.returncode != 0
    assert "saved run build manifest mismatch" in completed.stderr


def test_snapshot_rejects_run_evidence_producer_launcher_mismatch(tmp_path):
    fixture = make_fixture(tmp_path)
    evidence_path = fixture["run_evidence"]["candidate"]["control"]
    evidence = json.loads(evidence_path.read_text())
    evidence["producer_launcher"]["reviewed_commit"] = "0" * 40
    evidence_path.write_text(json.dumps(evidence) + "\n")

    completed = subprocess.run(
        command(fixture), cwd=ROOT, text=True, capture_output=True
    )

    assert completed.returncode != 0
    assert "saved run producer launcher mismatch" in completed.stderr


def test_snapshot_rejects_different_saved_measurement_argv(tmp_path):
    fixture = make_fixture(tmp_path)
    evidence_path = fixture["run_evidence"]["candidate"]["control"]
    evidence = json.loads(evidence_path.read_text())
    evidence["measurement"]["executable_argv"] += ["--measurement-time", "17"]
    evidence["measurement"]["executed_argv"] += ["--measurement-time", "17"]
    evidence_path.write_text(json.dumps(evidence) + "\n")

    completed = subprocess.run(
        command(fixture), cwd=ROOT, text=True, capture_output=True
    )

    assert completed.returncode != 0
    assert "saved run measurement settings differ" in completed.stderr


def test_snapshot_rejects_internally_inconsistent_saved_measurement(tmp_path):
    fixture = make_fixture(tmp_path)
    evidence_path = fixture["run_evidence"]["candidate"]["control"]
    evidence = json.loads(evidence_path.read_text())
    evidence["measurement"]["core"] = "7"
    evidence_path.write_text(json.dumps(evidence) + "\n")

    completed = subprocess.run(
        command(fixture), cwd=ROOT, text=True, capture_output=True
    )

    assert completed.returncode != 0
    assert "saved run pin/core mismatch" in completed.stderr


def test_snapshot_rejects_unpinned_saved_measurement(tmp_path):
    fixture = make_fixture(tmp_path)
    evidence_path = fixture["run_evidence"]["candidate"]["control"]
    evidence = json.loads(evidence_path.read_text())
    measurement = evidence["measurement"]
    measurement["core"] = None
    measurement["pin_wrapper"] = []
    measurement["system_tools"] = [
        item
        for item in measurement["system_tools"]
        if Path(item["absolute_path"]).name == "env"
    ]
    measurement["executed_argv"] = (
        measurement["criterion_environment"] + measurement["executable_argv"]
    )
    evidence_path.write_text(json.dumps(evidence) + "\n")

    completed = subprocess.run(
        command(fixture), cwd=ROOT, text=True, capture_output=True
    )

    assert completed.returncode != 0
    assert "saved run pin/core mismatch" in completed.stderr


def test_snapshot_rejects_saved_system_tool_hash_mismatch(tmp_path):
    fixture = make_fixture(tmp_path)
    evidence_path = fixture["run_evidence"]["candidate"]["control"]
    evidence = json.loads(evidence_path.read_text())
    evidence["measurement"]["system_tools"][0]["sha256"] = "0" * 64
    evidence_path.write_text(json.dumps(evidence) + "\n")

    completed = subprocess.run(
        command(fixture), cwd=ROOT, text=True, capture_output=True
    )

    assert completed.returncode != 0
    assert "saved run system tool mismatch" in completed.stderr


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("commit", "0" * 40, "saved run identity mismatch"),
        ("tree", "0" * 40, "saved run identity mismatch"),
        ("run", "wrong-run", "saved run identity mismatch"),
        (
            "criterion_evidence_root",
            "/tmp/wrong-criterion-root",
            "saved run identity mismatch",
        ),
        ("executable.sha256", "0" * 64, "saved run executable mismatch"),
    ],
)
def test_stable_snapshot_rejects_run_evidence_identity_mismatch(
    tmp_path, field, value, message
):
    fixture = make_fixture(tmp_path)
    evidence_path = fixture["run_evidence"]["candidate"]["elastic_cache_gate"]
    evidence = json.loads(evidence_path.read_text())
    if field == "executable.sha256":
        evidence["executable"]["sha256"] = value
    else:
        evidence[field] = value
    evidence_path.write_text(json.dumps(evidence) + "\n")

    completed = subprocess.run(
        command(fixture, target="elastic_cache_gate"),
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    assert completed.returncode != 0
    assert message in completed.stderr


def test_snapshot_rejects_saved_sample_changed_after_run(tmp_path):
    fixture = make_fixture(tmp_path)
    result = (
        fixture["criterion"] / CONTROL_IDS[0] / fixture["candidate_run"] / "sample.json"
    )
    result.write_text('{"samples":[999]}\n')

    completed = subprocess.run(
        command(fixture), cwd=ROOT, text=True, capture_output=True
    )

    assert completed.returncode != 0
    assert "saved run result inventory mismatch" in completed.stderr


def test_snapshot_rejects_symlinked_saved_baseline_directory(tmp_path):
    fixture = make_fixture(tmp_path)
    baseline = fixture["criterion"] / CONTROL_IDS[0] / fixture["candidate_run"]
    moved = baseline.with_name(f"{baseline.name}-moved")
    baseline.rename(moved)
    baseline.symlink_to(moved, target_is_directory=True)

    completed = subprocess.run(
        command(fixture), cwd=ROOT, text=True, capture_output=True
    )

    assert completed.returncode != 0
    assert "baseline path contains symlink" in completed.stderr


@pytest.mark.parametrize("target", ["all", "scaled_insert"])
def test_snapshot_fails_closed_for_targets_without_save_provenance(tmp_path, target):
    fixture = make_fixture(tmp_path)
    completed = subprocess.run(
        command(fixture, target=target), cwd=ROOT, text=True, capture_output=True
    )
    assert completed.returncode != 0
    assert "authenticated SAVE provenance is unavailable" in completed.stderr


def test_snapshot_rejects_corrupt_structural_manifest_before_execution(tmp_path):
    fixture = make_fixture(tmp_path)
    for name in ("anchor_manifest", "candidate_manifest"):
        manifest = json.loads(fixture[name].read_text())
        manifest["linker_capability"] = {"accepted": True}
        manifest["elf_layout"] = {"corrupt": {"program_headers_have_rwx": True}}
        fixture[name].write_text(json.dumps(manifest) + "\n")
    completed = subprocess.run(
        command(fixture), cwd=ROOT, text=True, capture_output=True
    )
    assert completed.returncode != 0
    assert "ELF layout executable set mismatch" in completed.stderr
    assert not fixture["invocation"].exists()


def test_manifest_builder_uses_approved_perf_tool_schema_and_authenticates_helper():
    source = LAUNCHER.read_text()
    assert '--tool "perf_launcher=$CACHE_GATE_PERF_TOOL"' in source
    assert '--tool "perf_support=$CACHE_GATE_PERF_SUPPORT_TOOL"' in source
    assert '--tool "perf=' not in source


def test_launchers_bootstrap_tools_only_from_their_own_reviewed_root():
    launcher_source = LAUNCHER.read_text()
    perf_source = PERF_LAUNCHER.read_text()
    for variable in (
        "CACHE_GATE_LAUNCHER",
        "CACHE_GATE_ELF_LAYOUT_TOOL",
        "CACHE_GATE_SNAPSHOT_TOOL",
        "CACHE_GATE_PERF_TOOL",
        "CACHE_GATE_PERF_SUPPORT_TOOL",
        "CACHE_GATE_EXTRACTOR_TOOL",
        "CACHE_GATE_LINK_WRAPPER",
    ):
        assert f"${{{variable}:-" not in launcher_source
    for variable in ("CACHE_GATE_ELF_LAYOUT_TOOL", "CACHE_GATE_PERF_SUPPORT_TOOL"):
        assert f"${{{variable}:-" not in perf_source
    for source in (launcher_source, perf_source, SCRIPT.read_text()):
        assert "verify_reviewed_tool_blob" in source
        assert "verify_manifest_tool_binding" in source
        assert 'git hash-object "$tool"' in source
        assert 'record.get("reviewed_commit")!=head' in source


def test_perf_launcher_executes_only_manifested_reviewed_helpers():
    source = PERF_LAUNCHER.read_text()
    assert '"$CACHE_GATE_ELF_LAYOUT_TOOL" validate-manifest' in source
    assert '"$CACHE_GATE_PERF_SUPPORT_TOOL" select-pmu' in source
    assert '"$CACHE_GATE_PERF_SUPPORT_TOOL" bind-contract' in source
    assert '"$CACHE_GATE_PERF_SUPPORT_TOOL" verify-executable' in source
    assert '"$CACHE_GATE_PERF_SUPPORT_TOOL" validate-csv' in source
    assert "$REPO_ROOT/scripts/cache-gate-perf-support.py" not in source
    assert source.count('require_tool_hash "$CACHE_GATE_PERF_SUPPORT_TOOL"') == 4
    assert "perf destination escapes runner target" in source


def test_perf_run_manifest_records_reviewed_launcher_and_helper_provenance():
    source = PERF_LAUNCHER.read_text()
    for field in (
        '"build_manifest_sha256": manifest_hash',
        '"tools": {"perf_launcher": perf_launcher, "perf_support": perf_support}',
        '"root": perf_launcher["reviewed_root"]',
        '"commit": perf_launcher["reviewed_commit"]',
        '"tree": perf_launcher["reviewed_tree"]',
    ):
        assert field in source


def test_manifest_metadata_hashes_the_exact_bytes_it_parses():
    stable = LAUNCHER.read_text()
    perf = PERF_LAUNCHER.read_text()
    snapshot = SCRIPT.read_text()
    assert "manifest_bytes=Path(manifest_path).read_bytes()" in stable
    assert "manifest=json.loads(manifest_bytes)" in stable
    assert "hashlib.sha256(manifest_bytes).hexdigest()" in stable
    assert "manifest_bytes = Path(sys.argv[1]).read_bytes()" in perf
    assert "data = json.loads(manifest_bytes)" in perf
    assert "return json.loads(raw), hashlib.sha256(raw).hexdigest()" in snapshot


def test_stable_and_perf_destination_roots_remain_under_runner_target():
    stable = LAUNCHER.read_text()
    perf = PERF_LAUNCHER.read_text()
    assert "stable run root escapes runner target" in stable
    assert "stable run destination escapes runner target" in stable
    assert "perf destination root escapes runner target" in perf
    assert "perf destination escapes runner target" in perf


def test_snapshot_rechecks_executed_control_and_copies_authenticated_bytes():
    source = SCRIPT.read_text()
    assert "control binary hash mismatch immediately before execution" in source
    assert "authenticated source hash mismatch" in source
    assert 'python3 - "$copied_manifest"' in source
    assert 'item["link_map"]["sha256"]' in source


def perf_command(fixture, manifest, binary):
    return [
        str(PERF_LAUNCHER),
        "--runner-root",
        str(ROOT),
        "--manifest",
        str(manifest),
        "--operation",
        "elastic-get",
        "--iterations",
        "1",
        "--repetition",
        "1",
    ], launcher_env(
        CACHE_GATE_CAMPAIGN_ROOT=ROOT / "target/cache-gate-perf-test-campaign",
        CACHE_GATE_CAMPAIGN_KEY="fixture-campaign",
        CACHE_GATE_PERF_BIN=binary,
    )


def test_perf_launcher_rejects_manifest_outside_runner_target(tmp_path):
    manifest = write(tmp_path / "manifest.json", "{}\n")
    binary = write(ROOT / "target/cache-gate-test-fixtures/perf-outside-bin", "bin\n")
    binary.chmod(0o755)
    arguments, env = perf_command({}, manifest, binary)
    completed = subprocess.run(arguments, env=env, text=True, capture_output=True)
    assert completed.returncode != 0
    assert "manifest must stay below runner root target" in completed.stderr


def test_perf_launcher_rejects_binary_outside_runner_target(tmp_path):
    manifest = write(
        ROOT / "target/cache-gate-test-fixtures/perf-binary-outside-manifest.json",
        "{}\n",
    )
    binary = write(tmp_path / "outside-bin", "bin\n")
    binary.chmod(0o755)
    arguments, env = perf_command({}, manifest, binary)
    completed = subprocess.run(arguments, env=env, text=True, capture_output=True)
    assert completed.returncode != 0
    assert "profile binary must stay below runner root target" in completed.stderr


def launcher_env(**values):
    env = os.environ.copy()
    env.update({name: str(value) for name, value in values.items()})
    return env


@pytest.mark.parametrize("script", [LAUNCHER, PERF_LAUNCHER])
def test_launchers_reject_omitted_runner_root(tmp_path, script):
    completed = subprocess.run(
        [str(script)],
        cwd=tmp_path,
        env=launcher_env(ELASTIC=1),
        text=True,
        capture_output=True,
    )
    assert completed.returncode != 0
    assert "--runner-root" in completed.stderr


@pytest.mark.parametrize("runner_root", ["relative", "/tmp"])
def test_cache_gate_rejects_nonabsolute_or_nonworktree_runner_root(
    tmp_path, runner_root
):
    completed = subprocess.run(
        [str(LAUNCHER), "--runner-root", runner_root],
        cwd=tmp_path,
        env=launcher_env(ELASTIC=1),
        text=True,
        capture_output=True,
    )
    assert completed.returncode != 0
    assert "runner root" in completed.stderr.lower()


def test_cache_gate_resolves_runner_root_symlink_before_manifest_check(tmp_path):
    link = tmp_path / "runner"
    link.symlink_to(ROOT, target_is_directory=True)
    completed = subprocess.run(
        [str(LAUNCHER), "--runner-root", str(link)],
        env=launcher_env(ELASTIC=1),
        text=True,
        capture_output=True,
    )
    assert completed.returncode != 0
    assert "CACHE_GATE_MANIFEST" in completed.stderr
    assert "runner root" not in completed.stderr.lower()


def test_cache_gate_rejects_relative_shared_criterion_root():
    completed = subprocess.run(
        [str(LAUNCHER), "--runner-root", str(ROOT)],
        env=launcher_env(ELASTIC=1, OPTHASH_CRITERION_ROOT="../../escape"),
        text=True,
        capture_output=True,
    )
    assert completed.returncode != 0
    assert "OPTHASH_CRITERION_ROOT must be absolute" in completed.stderr


def test_cache_gate_rejects_symlinked_save_benchmark_parent_before_execution(
    tmp_path,
):
    fixture = make_fixture(tmp_path)
    outside = fixture["criterion"].parent / "outside-criterion"
    outside.mkdir()
    group = fixture["criterion"] / "cache_gate_insert"
    benchmark = group / "cache_gate_insert_std"
    moved = outside / "cache_gate_insert_std"
    benchmark.rename(moved)
    benchmark.symlink_to(moved, target_is_directory=True)
    save = f"save-{hashlib.sha256(str(tmp_path).encode()).hexdigest()[:12]}"
    fake_bin = fixture["criterion"].parent / "fake-bin"
    fake_uname = write(fake_bin / "uname", "#!/bin/sh\nprintf 'Darwin\\n'\n")
    fake_uname.chmod(0o755)

    completed = subprocess.run(
        [str(fixture["launcher"]), "--runner-root", str(ROOT)],
        env=launcher_env(
            CONTROL=1,
            SAVE=save,
            OPTHASH_CRITERION_ROOT=fixture["criterion"],
            CACHE_GATE_CONTROL_BIN=fixture["control"],
            CACHE_GATE_CONTROL_PROVENANCE=fixture["control_provenance"],
            PATH=f"{fake_bin}:{os.environ['PATH']}",
            CORE=min(os.sched_getaffinity(0)),
        ),
        text=True,
        capture_output=True,
    )

    assert completed.returncode != 0
    assert "symlink in SAVE benchmark path" in completed.stderr
    assert not (moved / save).exists()


@pytest.mark.parametrize("mode", ["ELASTIC", "FUNNEL"])
def test_stable_launcher_requires_cache_gate_manifest(mode):
    completed = subprocess.run(
        [str(LAUNCHER), "--runner-root", str(ROOT)],
        env=launcher_env(**{mode: 1}),
        text=True,
        capture_output=True,
    )
    assert completed.returncode != 0
    assert "CACHE_GATE_MANIFEST" in completed.stderr
