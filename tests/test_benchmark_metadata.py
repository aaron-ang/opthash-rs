import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import benchmark_metadata


def make_source_tree(root: Path) -> Path:
    for directory in ("src", "benches/support", "scripts"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    files = {
        "Cargo.toml": "[package]\nname='fixture'\n",
        "Cargo.lock": "# lock\n",
        "build.rs": "fn main() {}\n",
        "src/lib.rs": "// library\n",
        "benches/speedup.rs": "fn main() {}\n",
        "benches/mean_latency.rs": "fn main() {}\n",
        "benches/scaled_insert.rs": "fn main() {}\n",
        "benches/support/common.rs": "// constants\n",
        "benches/support/fixtures.rs": "// fixtures\n",
        "benches/support/throughput.rs": "// harness\n",
        "scripts/bench.sh": "#!/bin/sh\n",
        "scripts/benchmark_metadata.py": "# helper\n",
    }
    for relative, contents in files.items():
        (root / relative).write_text(contents)
    return root


def make_criterion_baseline(root: Path, baseline: str) -> Path:
    estimates = root / "get_hit" / "get_hit_elastic" / baseline / "estimates.json"
    estimates.parent.mkdir(parents=True)
    estimates.write_text(json.dumps({"mean": {"point_estimate": 1.0}}))
    return root


def test_metadata_path_is_target_and_baseline_scoped(tmp_path: Path) -> None:
    assert benchmark_metadata.metadata_path(tmp_path, "speedup", "anchor") == (
        tmp_path / ".opthash" / "metadata" / "speedup" / "anchor.json"
    )


def test_source_and_methodology_fingerprints_are_separate(tmp_path: Path) -> None:
    repo = make_source_tree(tmp_path)
    source_before = benchmark_metadata.source_fingerprint(repo)
    method_before = benchmark_metadata.methodology_fingerprint(repo, "speedup")
    (repo / "src/lib.rs").write_text("// changed library\n")
    assert benchmark_metadata.source_fingerprint(repo) != source_before
    assert benchmark_metadata.methodology_fingerprint(repo, "speedup") == method_before
    source_after_library_change = benchmark_metadata.source_fingerprint(repo)
    (repo / "benches/speedup.rs").write_text("// changed fixture\n")
    assert benchmark_metadata.source_fingerprint(repo) != source_after_library_change
    assert benchmark_metadata.methodology_fingerprint(repo, "speedup") != method_before


@pytest.mark.parametrize("unsafe", ["../anchor", "/anchor", "new", "REPORT"])
@pytest.mark.parametrize("position", ["target", "baseline"])
def test_metadata_path_rejects_unsafe_or_reserved_names(
    tmp_path: Path, unsafe: str, position: str
) -> None:
    target = unsafe if position == "target" else "speedup"
    baseline = unsafe if position == "baseline" else "anchor"

    with pytest.raises(benchmark_metadata.MetadataError, match="unsafe or reserved"):
        benchmark_metadata.metadata_path(tmp_path, target, baseline)


def test_methodology_fingerprint_rejects_unsupported_target(tmp_path: Path) -> None:
    repo = make_source_tree(tmp_path)

    with pytest.raises(benchmark_metadata.MetadataError, match="unsupported benchmark"):
        benchmark_metadata.methodology_fingerprint(repo, "unknown")


def test_fingerprint_cli_prints_source_fingerprint(tmp_path: Path) -> None:
    repo = make_source_tree(tmp_path)

    completed = subprocess.run(
        [
            sys.executable,
            str(Path(benchmark_metadata.__file__)),
            "fingerprint",
            "--source-root",
            str(repo),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == benchmark_metadata.source_fingerprint(repo)
    assert completed.stderr == ""


def test_begin_invalidates_only_the_named_baseline(tmp_path: Path) -> None:
    repo = make_source_tree(tmp_path / "repo")
    criterion = make_criterion_baseline(tmp_path / "criterion", "candidate")
    make_criterion_baseline(criterion, "anchor")
    write_json = benchmark_metadata.metadata_path(criterion, "speedup", "candidate")
    write_json.parent.mkdir(parents=True)
    write_json.write_text("{}")

    before = benchmark_metadata.begin(criterion, repo, "speedup", "candidate")

    assert before == benchmark_metadata.source_fingerprint(repo)
    assert not write_json.exists()
    assert not (criterion / "get_hit/get_hit_elastic/candidate").exists()
    assert (criterion / "get_hit/get_hit_elastic/anchor").exists()


def test_publish_records_measured_registrations_atomically(tmp_path: Path) -> None:
    repo = make_source_tree(tmp_path / "repo")
    criterion = make_criterion_baseline(tmp_path / "criterion", "anchor")
    before = benchmark_metadata.source_fingerprint(repo)
    result = benchmark_metadata.publish(
        root=criterion,
        source_root=repo,
        target="speedup",
        baseline="anchor",
        source_before=before,
        core=5,
        requested_bench="speedup",
        forwarded_args=["--measurement-time", "10", "get_hit"],
    )
    assert result["registrations"] == ["get_hit/get_hit_elastic"]
    assert result["source"]["before"] == result["source"]["after"]
    assert benchmark_metadata.metadata_path(criterion, "speedup", "anchor").exists()


def test_publish_rejects_source_change_without_sidecar(tmp_path: Path) -> None:
    repo = make_source_tree(tmp_path / "repo")
    criterion = make_criterion_baseline(tmp_path / "criterion", "anchor")
    before = benchmark_metadata.source_fingerprint(repo)
    (repo / "src/lib.rs").write_text("// changed during run\n")
    with pytest.raises(benchmark_metadata.MetadataError, match="source changed"):
        benchmark_metadata.publish(
            root=criterion,
            source_root=repo,
            target="speedup",
            baseline="anchor",
            source_before=before,
            core=5,
            requested_bench="speedup",
            forwarded_args=[],
        )
    assert not benchmark_metadata.metadata_path(criterion, "speedup", "anchor").exists()


def test_begin_cli_prints_source_fingerprint(tmp_path: Path) -> None:
    repo = make_source_tree(tmp_path / "repo")
    criterion = make_criterion_baseline(tmp_path / "criterion", "anchor")

    completed = subprocess.run(
        [
            sys.executable,
            str(Path(benchmark_metadata.__file__)),
            "begin",
            "--root",
            str(criterion),
            "--source-root",
            str(repo),
            "--target",
            "speedup",
            "--baseline",
            "anchor",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == benchmark_metadata.source_fingerprint(repo)
    assert not (criterion / "get_hit/get_hit_elastic/anchor").exists()


def test_publish_cli_accepts_exact_forwarded_arguments(tmp_path: Path) -> None:
    repo = make_source_tree(tmp_path / "repo")
    criterion = make_criterion_baseline(tmp_path / "criterion", "anchor")
    before = benchmark_metadata.source_fingerprint(repo)

    completed = subprocess.run(
        [
            sys.executable,
            str(Path(benchmark_metadata.__file__)),
            "publish",
            "--root",
            str(criterion),
            "--source-root",
            str(repo),
            "--target",
            "speedup",
            "--baseline",
            "anchor",
            "--source-before",
            before,
            "--core",
            "5",
            "--requested-bench",
            "speedup",
            "--forwarded-arg",
            "--measurement-time",
            "--forwarded-arg",
            "10",
            "--forwarded-arg",
            "get_hit",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["forwarded_args"] == [
        "--measurement-time",
        "10",
        "get_hit",
    ]
