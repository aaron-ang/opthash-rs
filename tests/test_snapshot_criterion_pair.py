import hashlib
import json
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "snapshot-criterion-pair.sh"
CONTROL_IDS = (
    "cache_gate_insert/cache_gate_insert_std",
    "cache_gate_insert/cache_gate_insert_hashbrown",
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
    criterion = tmp_path / "criterion"
    snapshot = tmp_path / "snapshots"
    anchor_run = "anchor-run"
    candidate_run = "candidate-run"
    for benchmark in CONTROL_IDS:
        write(
            criterion / benchmark / anchor_run / "estimates.json", '{"run":"anchor"}\n'
        )
        write(
            criterion / benchmark / candidate_run / "estimates.json",
            '{"run":"candidate"}\n',
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

    executables = {}
    symbols = {}
    for name in ("elastic_cache_gate", "funnel_cache_gate", "cache_gate_profile"):
        executable = write(tmp_path / name, f"binary {name}\n")
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
        "empty_diff_assertion": True,
        "control": control_record,
        "executables": executables,
        "symbols": symbols,
    }
    anchor_manifest = write(
        tmp_path / "anchor-manifest.json", json.dumps(manifest) + "\n"
    )
    candidate_manifest = write(
        tmp_path / "candidate-manifest.json", json.dumps(manifest) + "\n"
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
    }


def command(fixture, **overrides):
    values = {
        "criterion-root": fixture["criterion"],
        "snapshot-root": fixture["snapshot"],
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
    result = [str(SCRIPT)]
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
    assert invocation == "--bench --load-baseline candidate-run --baseline anchor-run\n"
    destination = fixture["snapshot"] / "aarch64/fixture-comparison/pair-1"
    assert len(list((destination / "change").rglob("estimates.json"))) == 2
    assert len(list((destination / "absolute/anchor").rglob("estimates.json"))) == 2
    pair_manifest = json.loads((destination / "pair-manifest.json").read_text())
    assert pair_manifest["comparison_command"][1:] == [
        "--bench",
        "--load-baseline",
        "candidate-run",
        "--baseline",
        "anchor-run",
    ]
    assert (
        pair_manifest["control"]
        == json.loads(fixture["anchor_manifest"].read_text())["control"]
    )


def test_snapshot_rejects_missing_fresh_change_output(tmp_path):
    fixture = make_fixture(tmp_path, omit_change=True)
    completed = subprocess.run(
        command(fixture), cwd=ROOT, text=True, capture_output=True
    )
    assert completed.returncode != 0
    assert "missing fresh change" in completed.stderr
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
