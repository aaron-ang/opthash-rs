import hashlib
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
    subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ],
        cwd=root,
        check=True,
    )
    return root


def make_criterion_baseline(root: Path, baseline: str) -> Path:
    return make_criterion_registration(root, "get_hit/get_hit_elastic", baseline)


def make_criterion_registration(root: Path, registration: str, baseline: str) -> Path:
    group, function = registration.split("/")
    estimates = root / group / function / baseline / "estimates.json"
    estimates.parent.mkdir(parents=True)
    estimates.write_text(json.dumps({"mean": {"point_estimate": 1.0}}))
    return root


def write_target_metadata(
    root: Path, target: str, name: str, value: dict[str, object]
) -> None:
    path = benchmark_metadata.metadata_path(root, target, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def write_metadata(root: Path, name: str, value: dict[str, object]) -> None:
    write_target_metadata(root, "speedup", name, value)


def fixture_cpu_identity(model: str) -> dict[str, object]:
    fields = {"Architecture": "fixture-arch", "Model name": model}
    canonical = json.dumps(fields, separators=(",", ":"), sort_keys=True).encode()
    return {
        "algorithm": "sha256_canonical_cpu_fields_v1",
        "fields": fields,
        "sha256": hashlib.sha256(canonical).hexdigest(),
    }


def compatible_metadata_pair(
    root: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    common = {
        "schema": 1,
        "methodology": "a" * 64,
        "target": "speedup",
        "requested_bench": "speedup",
        "forwarded_args": ["--measurement-time", "10", "get_hit"],
        "registrations": ["get_hit/get_hit_elastic"],
        "cpu_identity": fixture_cpu_identity("fixture-cpu"),
        "core": 5,
        "os": "fixture-os",
        "rustc_vv": "rustc fixture",
        "measured_at_utc": "2026-07-11T00:00:00+00:00",
    }
    anchor = common | {
        "source": {
            "before": "a" * 64,
            "after": "a" * 64,
            "commit": "1" * 40,
            "dirty": False,
        }
    }
    candidate = common | {
        "source": {
            "before": "b" * 64,
            "after": "b" * 64,
            "commit": "2" * 40,
            "dirty": False,
        }
    }
    write_metadata(root, "anchor", anchor)
    write_metadata(root, "candidate", candidate)
    make_criterion_baseline(root, "anchor")
    make_criterion_baseline(root, "candidate")
    return anchor, candidate


def incompatible_value(field: str) -> object:
    return {
        "methodology": "c" * 64,
        "core": 6,
        "cpu_identity": fixture_cpu_identity("other-cpu"),
        "os": "other-os",
        "rustc_vv": "other-rustc",
        "forwarded_args": ["get_miss"],
        "registrations": ["get_miss/get_miss_elastic"],
    }[field]


def copy_metadata(value: dict[str, object]) -> dict[str, object]:
    return json.loads(json.dumps(value))


def other_target_metadata(value: dict[str, object]) -> dict[str, object]:
    other = copy_metadata(value)
    other["target"] = "mean_latency"
    other["registrations"] = ["get_hit/get_hit_elastic"]
    return other


def malformed_other_target_metadata(
    value: dict[str, object], malformed: str
) -> dict[str, object]:
    other = other_target_metadata(value)
    if malformed == "boolean-schema":
        other["schema"] = True
    elif malformed == "partial":
        other = {
            "schema": 1,
            "target": "mean_latency",
            "registrations": ["get_hit/get_hit_elastic"],
        }
    else:
        other["forwarded_args"] = {"filter": "get_hit"}
    return other


def metadata_pair_with_hidden_registration(
    root: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    anchor, candidate = compatible_metadata_pair(root)
    for name, value in (("anchor", anchor), ("candidate", candidate)):
        make_criterion_registration(root, "insert/insert_elastic", name)
        value["registrations"] = ["insert/insert_elastic"]
        write_metadata(root, name, value)
    return anchor, candidate


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
    assert benchmark_metadata.verify(criterion, "speedup", "anchor") == [result]


@pytest.mark.parametrize(
    ("failure", "field"),
    [
        ("git-commit", "source.commit"),
        ("git-dirty", "source.dirty"),
        ("rustc", "rustc_vv"),
        ("cpu", "cpu_identity"),
        ("timestamp", "measured_at_utc"),
        ("os", "os"),
    ],
)
def test_publish_rejects_invalid_identity_without_sidecar(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    field: str,
) -> None:
    repo = make_source_tree(tmp_path / "repo")
    criterion = make_criterion_baseline(tmp_path / "criterion", "anchor")
    before = benchmark_metadata.source_fingerprint(repo)
    original_command_output = benchmark_metadata.command_output

    def command_output(argv: list[str], cwd: Path | None = None) -> str | None:
        if failure == "git-commit" and argv == ["git", "rev-parse", "HEAD"]:
            return None
        if failure == "git-dirty" and argv == ["git", "status", "--porcelain"]:
            return None
        if failure == "rustc" and argv == ["rustc", "-Vv"]:
            return None
        return original_command_output(argv, cwd)

    monkeypatch.setattr(benchmark_metadata, "command_output", command_output)
    if failure == "cpu":
        monkeypatch.setattr(benchmark_metadata, "cpu_identity", lambda: None)
    elif failure == "timestamp":

        class InvalidDateTime:
            @classmethod
            def now(cls, tz: object) -> object:
                class InvalidTimestamp:
                    @staticmethod
                    def isoformat() -> str:
                        return "not-a-timestamp"

                return InvalidTimestamp()

        monkeypatch.setattr(benchmark_metadata, "datetime", InvalidDateTime)
    elif failure == "os":
        monkeypatch.setattr(benchmark_metadata.platform, "platform", lambda: "")

    with pytest.raises(benchmark_metadata.MetadataError, match=field):
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


def test_failed_publish_keeps_invalidated_baseline_without_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_source_tree(tmp_path / "repo")
    criterion = make_criterion_baseline(tmp_path / "criterion", "anchor")
    sidecar = benchmark_metadata.metadata_path(criterion, "speedup", "anchor")
    sidecar.parent.mkdir(parents=True)
    sidecar.write_text("stale")
    before = benchmark_metadata.begin(criterion, repo, "speedup", "anchor")
    make_criterion_baseline(criterion, "anchor")
    original_command_output = benchmark_metadata.command_output

    def command_output(argv: list[str], cwd: Path | None = None) -> str | None:
        if argv == ["git", "status", "--porcelain"]:
            return None
        return original_command_output(argv, cwd)

    monkeypatch.setattr(benchmark_metadata, "command_output", command_output)

    with pytest.raises(benchmark_metadata.MetadataError, match="source.dirty"):
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

    assert not sidecar.exists()


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


def test_sequential_targets_preserve_distinct_baseline_ownership(
    tmp_path: Path,
) -> None:
    repo = make_source_tree(tmp_path / "repo")
    criterion = tmp_path / "criterion"

    speed_before = benchmark_metadata.begin(criterion, repo, "speedup", "anchor")
    make_criterion_registration(criterion, "get_hit/get_hit_elastic", "anchor")
    speed = benchmark_metadata.publish(
        root=criterion,
        source_root=repo,
        target="speedup",
        baseline="anchor",
        source_before=speed_before,
        core=5,
        requested_bench="all",
        forwarded_args=[],
    )
    speed_sidecar = benchmark_metadata.metadata_path(criterion, "speedup", "anchor")
    speed_sidecar_before = speed_sidecar.read_text()

    latency_before = benchmark_metadata.begin(criterion, repo, "mean_latency", "anchor")

    assert speed_sidecar.read_text() == speed_sidecar_before
    assert (criterion / "get_hit/get_hit_elastic/anchor").exists()

    make_criterion_registration(
        criterion,
        "get_hit_latency_1K/get_hit_latency_1K_elastic",
        "anchor",
    )
    latency = benchmark_metadata.publish(
        root=criterion,
        source_root=repo,
        target="mean_latency",
        baseline="anchor",
        source_before=latency_before,
        core=5,
        requested_bench="all",
        forwarded_args=[],
    )

    assert speed["registrations"] == ["get_hit/get_hit_elastic"]
    assert latency["registrations"] == ["get_hit_latency_1K/get_hit_latency_1K_elastic"]
    assert json.loads(speed_sidecar.read_text())["registrations"] == [
        "get_hit/get_hit_elastic"
    ]


def test_begin_removes_stale_registrations_unclaimed_by_other_targets(
    tmp_path: Path,
) -> None:
    repo = make_source_tree(tmp_path / "repo")
    criterion = tmp_path / "criterion"
    speed_before = benchmark_metadata.begin(criterion, repo, "speedup", "anchor")
    make_criterion_registration(criterion, "get_hit/get_hit_elastic", "anchor")
    benchmark_metadata.publish(
        root=criterion,
        source_root=repo,
        target="speedup",
        baseline="anchor",
        source_before=speed_before,
        core=5,
        requested_bench="all",
        forwarded_args=[],
    )
    make_criterion_registration(criterion, "interrupted/interrupted_elastic", "anchor")

    benchmark_metadata.begin(criterion, repo, "mean_latency", "anchor")

    assert (criterion / "get_hit/get_hit_elastic/anchor").exists()
    assert not (criterion / "interrupted/interrupted_elastic/anchor").exists()


def test_begin_fails_closed_for_malformed_other_target_ownership(
    tmp_path: Path,
) -> None:
    repo = make_source_tree(tmp_path / "repo")
    criterion = make_criterion_baseline(tmp_path / "criterion", "anchor")
    other_sidecar = benchmark_metadata.metadata_path(criterion, "speedup", "anchor")
    other_sidecar.parent.mkdir(parents=True)
    other_sidecar.write_text("{")
    current_sidecar = benchmark_metadata.metadata_path(
        criterion, "mean_latency", "anchor"
    )
    current_sidecar.parent.mkdir(parents=True)
    current_sidecar.write_text("{}")

    with pytest.raises(benchmark_metadata.MetadataError, match="ownership metadata"):
        benchmark_metadata.begin(criterion, repo, "mean_latency", "anchor")

    assert other_sidecar.exists()
    assert current_sidecar.exists()
    assert (criterion / "get_hit/get_hit_elastic/anchor").exists()


def test_begin_fails_closed_when_other_target_sidecar_disappears(
    tmp_path: Path,
) -> None:
    repo = make_source_tree(tmp_path / "repo")
    criterion = make_criterion_baseline(tmp_path / "criterion", "anchor")
    missing_sidecar = benchmark_metadata.metadata_path(criterion, "speedup", "anchor")
    missing_sidecar.parent.mkdir(parents=True)
    missing_sidecar.symlink_to(tmp_path / "missing.json")

    with pytest.raises(benchmark_metadata.MetadataError, match="ownership metadata"):
        benchmark_metadata.begin(criterion, repo, "mean_latency", "anchor")

    assert missing_sidecar.is_symlink()
    assert (criterion / "get_hit/get_hit_elastic/anchor").exists()


@pytest.mark.parametrize("malformed", ["boolean-schema", "partial", "bad-field-type"])
def test_verify_rejects_malformed_other_target_before_it_hides_registration(
    tmp_path: Path, malformed: str
) -> None:
    anchor, _ = metadata_pair_with_hidden_registration(tmp_path)
    write_target_metadata(
        tmp_path,
        "mean_latency",
        "anchor",
        malformed_other_target_metadata(anchor, malformed),
    )

    with pytest.raises(benchmark_metadata.MetadataError, match="ownership metadata"):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor")


@pytest.mark.parametrize("malformed", ["boolean-schema", "partial", "bad-field-type"])
def test_paired_verify_rejects_malformed_other_target_before_comparison(
    tmp_path: Path, malformed: str
) -> None:
    anchor, candidate = metadata_pair_with_hidden_registration(tmp_path)
    write_target_metadata(
        tmp_path,
        "mean_latency",
        "anchor",
        other_target_metadata(anchor),
    )
    write_target_metadata(
        tmp_path,
        "mean_latency",
        "candidate",
        malformed_other_target_metadata(candidate, malformed),
    )

    with pytest.raises(benchmark_metadata.MetadataError, match="ownership metadata"):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor", "candidate")


def test_verify_rejects_duplicate_registration_claims_by_other_targets(
    tmp_path: Path,
) -> None:
    anchor, _ = compatible_metadata_pair(tmp_path)
    anchor["registrations"] = ["insert/insert_elastic"]
    make_criterion_registration(tmp_path, "insert/insert_elastic", "anchor")
    write_metadata(tmp_path, "anchor", anchor)
    for target in ("mean_latency", "map_api"):
        other = other_target_metadata(anchor)
        other["target"] = target
        other["registrations"] = ["get_hit/get_hit_elastic"]
        write_target_metadata(tmp_path, target, "anchor", other)

    with pytest.raises(benchmark_metadata.MetadataError, match="duplicate.*ownership"):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor")


@pytest.mark.parametrize(
    "field",
    [
        "methodology",
        "core",
        "cpu_identity",
        "os",
        "rustc_vv",
        "forwarded_args",
        "registrations",
    ],
)
def test_verify_rejects_incompatible_metadata(tmp_path: Path, field: str) -> None:
    _, candidate = compatible_metadata_pair(tmp_path)
    candidate[field] = incompatible_value(field)
    if field == "registrations":
        (tmp_path / "get_hit/get_hit_elastic/candidate/estimates.json").unlink()
        make_criterion_registration(tmp_path, "get_miss/get_miss_elastic", "candidate")
    write_metadata(tmp_path, "candidate", candidate)

    with pytest.raises(benchmark_metadata.MetadataError, match=field):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor", "candidate")


def test_verify_allows_different_source_fingerprints(tmp_path: Path) -> None:
    _, candidate = compatible_metadata_pair(tmp_path)
    candidate["source"]["before"] = "f" * 64
    candidate["source"]["after"] = "f" * 64
    write_metadata(tmp_path, "candidate", candidate)

    values = benchmark_metadata.verify(tmp_path, "speedup", "anchor", "candidate")

    assert [value["source"]["after"] for value in values] == ["a" * 64, "f" * 64]


def test_verify_current_allows_different_source_with_matching_live_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_source_tree(tmp_path / "repo")
    criterion = tmp_path / "criterion"
    anchor, _ = compatible_metadata_pair(criterion)
    anchor["methodology"] = benchmark_metadata.methodology_fingerprint(repo, "speedup")
    write_metadata(criterion, "anchor", anchor)
    live_cpu = copy_metadata(anchor["cpu_identity"])
    live_os = str(anchor["os"])
    live_rustc = str(anchor["rustc_vv"])
    monkeypatch.setattr(benchmark_metadata, "cpu_identity", lambda: live_cpu)
    monkeypatch.setattr(benchmark_metadata.platform, "platform", lambda: live_os)
    original_command_output = benchmark_metadata.command_output

    def live_command_output(argv: list[str], cwd: Path | None = None) -> str | None:
        if argv[:2] == ["git", "status"]:
            return ""
        if argv[:2] == ["rustc", "-Vv"]:
            return live_rustc
        return original_command_output(argv, cwd)

    monkeypatch.setattr(benchmark_metadata, "command_output", live_command_output)

    fingerprint = benchmark_metadata.verify_current(
        root=criterion,
        source_root=repo,
        target="speedup",
        baseline="anchor",
        core=5,
        forwarded_args=["--measurement-time", "10", "get_hit"],
    )

    assert fingerprint == benchmark_metadata.source_fingerprint(repo)
    assert fingerprint != anchor["source"]["after"]


@pytest.mark.parametrize(
    "field",
    ["methodology", "core", "cpu_identity", "os", "rustc_vv", "forwarded_args"],
)
def test_verify_current_rejects_incompatible_live_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    repo = make_source_tree(tmp_path / "repo")
    criterion = tmp_path / "criterion"
    anchor, _ = compatible_metadata_pair(criterion)
    anchor["methodology"] = benchmark_metadata.methodology_fingerprint(repo, "speedup")
    write_metadata(criterion, "anchor", anchor)
    live_cpu = copy_metadata(anchor["cpu_identity"])
    live_os = str(anchor["os"])
    live_rustc = str(anchor["rustc_vv"])
    monkeypatch.setattr(benchmark_metadata, "cpu_identity", lambda: live_cpu)
    monkeypatch.setattr(benchmark_metadata.platform, "platform", lambda: live_os)

    def live_command_output(argv: list[str], cwd: Path | None = None) -> str | None:
        if argv[:2] == ["git", "status"]:
            return ""
        if argv[:2] == ["rustc", "-Vv"]:
            return live_rustc
        return None

    monkeypatch.setattr(benchmark_metadata, "command_output", live_command_output)
    if field == "methodology":
        anchor["methodology"] = "f" * 64
    elif field == "core":
        anchor["core"] = 7
    elif field == "cpu_identity":
        anchor["cpu_identity"] = fixture_cpu_identity("other-cpu")
    elif field == "os":
        anchor["os"] = "other-os"
    elif field == "rustc_vv":
        anchor["rustc_vv"] = "other-rustc"
    else:
        anchor["forwarded_args"] = ["get_miss"]
    write_metadata(criterion, "anchor", anchor)

    with pytest.raises(benchmark_metadata.MetadataError, match=field):
        benchmark_metadata.verify_current(
            root=criterion,
            source_root=repo,
            target="speedup",
            baseline="anchor",
            core=5,
            forwarded_args=["--measurement-time", "10", "get_hit"],
        )


def test_verify_current_rejects_dirty_live_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_source_tree(tmp_path / "repo")
    criterion = tmp_path / "criterion"
    anchor, _ = compatible_metadata_pair(criterion)
    anchor["methodology"] = benchmark_metadata.methodology_fingerprint(repo, "speedup")
    write_metadata(criterion, "anchor", anchor)
    monkeypatch.setattr(
        benchmark_metadata, "cpu_identity", lambda: anchor["cpu_identity"]
    )
    monkeypatch.setattr(benchmark_metadata.platform, "platform", lambda: anchor["os"])

    def live_command_output(argv: list[str], cwd: Path | None = None) -> str | None:
        if argv[:2] == ["git", "status"]:
            return " M src/lib.rs"
        if argv[:2] == ["rustc", "-Vv"]:
            return str(anchor["rustc_vv"])
        return None

    monkeypatch.setattr(benchmark_metadata, "command_output", live_command_output)

    with pytest.raises(
        benchmark_metadata.MetadataError, match="live comparison requires clean"
    ):
        benchmark_metadata.verify_current(
            root=criterion,
            source_root=repo,
            target="speedup",
            baseline="anchor",
            core=5,
            forwarded_args=list(anchor["forwarded_args"]),
        )


def test_verify_source_rejects_change_after_live_comparison(tmp_path: Path) -> None:
    repo = make_source_tree(tmp_path / "repo")
    before = benchmark_metadata.source_fingerprint(repo)
    (repo / "src/lib.rs").write_text("// changed during run\n")

    with pytest.raises(benchmark_metadata.MetadataError, match="source changed"):
        benchmark_metadata.verify_source(repo, before)


def test_verify_rejects_source_change_during_baseline(tmp_path: Path) -> None:
    _, candidate = compatible_metadata_pair(tmp_path)
    candidate["source"]["after"] = "f" * 64
    write_metadata(tmp_path, "candidate", candidate)

    with pytest.raises(benchmark_metadata.MetadataError, match="source changed"):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor", "candidate")


def test_verify_rejects_missing_criterion_baseline(tmp_path: Path) -> None:
    compatible_metadata_pair(tmp_path)
    (tmp_path / "get_hit/get_hit_elastic/anchor/estimates.json").unlink()

    with pytest.raises(benchmark_metadata.MetadataError, match="registrations"):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor")


def test_verify_requires_clean_source_only_for_final_evidence(tmp_path: Path) -> None:
    anchor, _ = compatible_metadata_pair(tmp_path)
    anchor["source"]["dirty"] = True
    write_metadata(tmp_path, "anchor", anchor)

    benchmark_metadata.verify(tmp_path, "speedup", "anchor")
    with pytest.raises(benchmark_metadata.MetadataError, match="requires clean"):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor", require_clean=True)


def test_verify_rejects_unknown_cleanliness_for_final_evidence(tmp_path: Path) -> None:
    anchor, _ = compatible_metadata_pair(tmp_path)
    anchor["source"]["dirty"] = None
    write_metadata(tmp_path, "anchor", anchor)

    with pytest.raises(benchmark_metadata.MetadataError, match="invalid benchmark"):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor", require_clean=True)


def test_verify_rejects_boolean_schema_before_artifact_checks(tmp_path: Path) -> None:
    anchor, _ = compatible_metadata_pair(tmp_path)
    anchor["schema"] = True
    write_metadata(tmp_path, "anchor", anchor)
    (tmp_path / "get_hit/get_hit_elastic/anchor/estimates.json").unlink()

    with pytest.raises(benchmark_metadata.MetadataError, match="anchor.*schema"):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source", None),
        ("forwarded_args", {"argument": "get_hit"}),
        ("cpu_identity", ["fixture-cpu"]),
        ("measured_at_utc", None),
    ],
)
def test_verify_rejects_json_type_substitutions(
    tmp_path: Path, field: str, value: object
) -> None:
    anchor, _ = compatible_metadata_pair(tmp_path)
    anchor[field] = value
    write_metadata(tmp_path, "anchor", anchor)

    with pytest.raises(benchmark_metadata.MetadataError, match=f"anchor.*{field}"):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("before", "a" * 63),
        ("after", "A" * 64),
        ("commit", "1" * 39),
        ("dirty", 0),
    ],
)
def test_verify_rejects_malformed_source_metadata(
    tmp_path: Path, field: str, value: object
) -> None:
    anchor, _ = compatible_metadata_pair(tmp_path)
    anchor["source"][field] = value
    write_metadata(tmp_path, "anchor", anchor)

    with pytest.raises(
        benchmark_metadata.MetadataError, match=f"anchor.*source.{field}"
    ):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor")


@pytest.mark.parametrize("change", ["missing", "extra"])
def test_verify_rejects_incomplete_or_extended_source_shape(
    tmp_path: Path, change: str
) -> None:
    anchor, _ = compatible_metadata_pair(tmp_path)
    if change == "missing":
        del anchor["source"]["commit"]
    else:
        anchor["source"]["unexpected"] = "value"
    write_metadata(tmp_path, "anchor", anchor)

    with pytest.raises(benchmark_metadata.MetadataError, match="anchor.*source fields"):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor")


def test_verify_rejects_malformed_methodology_fingerprint(tmp_path: Path) -> None:
    anchor, _ = compatible_metadata_pair(tmp_path)
    anchor["methodology"] = "A" * 64
    write_metadata(tmp_path, "anchor", anchor)

    with pytest.raises(benchmark_metadata.MetadataError, match="anchor.*methodology"):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor")


@pytest.mark.parametrize(
    "registrations",
    [
        ["z/z", "a/a"],
        ["get_hit/get_hit_elastic", "get_hit/get_hit_elastic"],
        [""],
        ["get_hit"],
    ],
)
def test_verify_rejects_invalid_registration_metadata(
    tmp_path: Path, registrations: list[str]
) -> None:
    anchor, _ = compatible_metadata_pair(tmp_path)
    anchor["registrations"] = registrations
    write_metadata(tmp_path, "anchor", anchor)

    with pytest.raises(benchmark_metadata.MetadataError, match="anchor.*registrations"):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor")


@pytest.mark.parametrize("change", ["missing", "extra"])
def test_verify_rejects_incomplete_or_extended_sidecar_shape(
    tmp_path: Path, change: str
) -> None:
    anchor, _ = compatible_metadata_pair(tmp_path)
    if change == "missing":
        del anchor["requested_bench"]
    else:
        anchor["unexpected"] = "value"
    write_metadata(tmp_path, "anchor", anchor)

    with pytest.raises(benchmark_metadata.MetadataError, match="anchor.*fields"):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor")


def test_verify_rejects_malformed_cpu_identity(tmp_path: Path) -> None:
    anchor, _ = compatible_metadata_pair(tmp_path)
    anchor["cpu_identity"]["sha256"] = "0" * 64
    write_metadata(tmp_path, "anchor", anchor)

    with pytest.raises(benchmark_metadata.MetadataError, match="anchor.*cpu_identity"):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor")


@pytest.mark.parametrize(
    "fields",
    [
        {"Architecture": "x86_64"},
        {"Model name": "fixture-cpu"},
        {"Architecture": "", "Model name": "fixture-cpu"},
        {"Architecture": "x86_64", "Model name": "   "},
        {"Architecture": "aarch64", "Processor": ""},
    ],
)
def test_verify_rejects_partial_or_empty_cpu_identity_fields(
    tmp_path: Path, fields: dict[str, str]
) -> None:
    anchor, _ = compatible_metadata_pair(tmp_path)
    canonical = json.dumps(fields, separators=(",", ":"), sort_keys=True).encode()
    anchor["cpu_identity"] = {
        "algorithm": "sha256_canonical_cpu_fields_v1",
        "fields": fields,
        "sha256": hashlib.sha256(canonical).hexdigest(),
    }
    write_metadata(tmp_path, "anchor", anchor)

    with pytest.raises(benchmark_metadata.MetadataError, match="anchor.*cpu_identity"):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor")


def test_verify_rejects_nonpublisher_timestamp_format(tmp_path: Path) -> None:
    anchor, _ = compatible_metadata_pair(tmp_path)
    anchor["measured_at_utc"] = "2026-07-11T00:00:00Z"
    write_metadata(tmp_path, "anchor", anchor)

    with pytest.raises(
        benchmark_metadata.MetadataError, match="anchor.*measured_at_utc"
    ):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor")


@pytest.mark.parametrize("core", [None, True])
def test_verify_rejects_malformed_candidate_before_comparison(
    tmp_path: Path, core: object
) -> None:
    _, candidate = compatible_metadata_pair(tmp_path)
    candidate["core"] = core
    write_metadata(tmp_path, "candidate", candidate)

    with pytest.raises(benchmark_metadata.MetadataError, match="candidate.*core"):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor", "candidate")


def test_verify_cli_prints_compatible_metadata(tmp_path: Path) -> None:
    compatible_metadata_pair(tmp_path)

    completed = subprocess.run(
        [
            sys.executable,
            str(Path(benchmark_metadata.__file__)),
            "verify",
            "--root",
            str(tmp_path),
            "--target",
            "speedup",
            "--baseline",
            "anchor",
            "--compare",
            "candidate",
            "--require-clean",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert [value["source"]["after"] for value in json.loads(completed.stdout)] == [
        "a" * 64,
        "b" * 64,
    ]
    assert completed.stderr == ""
