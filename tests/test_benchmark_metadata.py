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
