from pathlib import Path

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
