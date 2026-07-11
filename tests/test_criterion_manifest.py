from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from scripts import criterion_manifest


ARTIFACTS = ("benchmark.json", "estimates.json", "sample.json", "tukey.json")


def _source_tree(root: Path, marker: str = "v1") -> Path:
    root.mkdir()
    (root / "src").mkdir()
    (root / "benches").mkdir()
    (root / "benches" / "support").mkdir()
    (root / "scripts").mkdir()
    (root / "Cargo.toml").write_text("[package]\nname='fixture'\n")
    (root / "Cargo.lock").write_text("# lock\n")
    (root / "build.rs").write_text("fn main() {}\n")
    (root / "src" / "lib.rs").write_text(f"// {marker}\n")
    (root / "benches" / "speedup.rs").write_text("fn bench() {}\n")
    (root / "benches" / "support" / "common.rs").write_text("// common\n")
    (root / "benches" / "support" / "fixtures.rs").write_text("// fixtures\n")
    (root / "benches" / "support" / "throughput.rs").write_text(
        "pub const MAP_SIZE: usize = 20_000;\n"
    )
    (root / "scripts" / "bench.sh").write_text("#!/bin/sh\n")
    (root / "scripts" / "criterion_manifest.py").write_text("# helper\n")
    return root


def _registration(
    root: Path,
    baseline: str,
    *,
    group: str = "get_hit",
    function: str = "get_hit_elastic",
) -> Path:
    directory = root / group / function / baseline
    directory.mkdir(parents=True)
    benchmark = {
        "group_id": group,
        "function_id": function,
        "full_id": f"{group}/{function}",
        "directory_name": f"{group}/{function}",
    }
    (directory / "benchmark.json").write_text(json.dumps(benchmark))
    for name in ARTIFACTS[1:]:
        (directory / name).write_text(json.dumps({"artifact": name}))
    return directory


def _target_registrations(root: Path, baseline: str, target: str = "speedup") -> None:
    for full_id in criterion_manifest.expected_registration_ids(target):
        group, function = full_id.split("/", 1)
        _registration(root, baseline, group=group, function=function)


def _prepare(
    tmp_path: Path,
    *,
    target: str = "speedup",
    baseline: str = "candidate",
    source_marker: str = "v1",
) -> tuple[Path, Path, Path]:
    criterion = tmp_path / "criterion"
    source = _source_tree(tmp_path / "repo", source_marker)
    transaction = criterion_manifest.prepare_save(
        criterion,
        source,
        target,
        baseline,
        {
            "core": 5,
            "criterion_tuning": ["--measurement-time", "10"],
            "requested_bench": target,
        },
    )
    return criterion, source, transaction


@pytest.mark.parametrize(
    ("target", "baseline"),
    [
        ("unknown", "ref"),
        ("speedup", ""),
        ("speedup", "../ref"),
        ("speedup", "ref name"),
        ("mean_latency", "nested/ref"),
        ("speedup", "new"),
        ("speedup", "BASE"),
        ("speedup", "change"),
        ("speedup", "report"),
    ],
)
def test_prepare_rejects_unsafe_target_or_baseline(
    tmp_path: Path, target: str, baseline: str
) -> None:
    source = _source_tree(tmp_path / "repo")

    with pytest.raises(criterion_manifest.ManifestError):
        criterion_manifest.prepare_save(
            tmp_path / "criterion", source, target, baseline, {}
        )


def test_prepare_publishes_pending_before_a_clean_transaction(tmp_path: Path) -> None:
    criterion, _source, transaction = _prepare(tmp_path)
    pending = criterion / ".opthash" / "manifests" / "speedup" / "candidate.pending"

    assert pending.is_file()
    assert transaction.is_dir()
    assert not any(path.name == "candidate" for path in transaction.rglob("*"))
    context = json.loads(
        (transaction / criterion_manifest.TRANSACTION_CONTEXT).read_text()
    )
    assert context["source"]["sha256"] == criterion_manifest.source_fingerprint(
        tmp_path / "repo"
    )
    assert context["fixture"]["fingerprint_sha256"]
    assert context["methodology"]["sha256"]
    assert context["execution"]["criterion_tuning"] == [
        "--measurement-time",
        "10",
    ]
    assert context["execution"]["host_identity"]["sha256"]
    assert context["execution"]["cpu_identity"]["sha256"]
    assert "RUSTFLAGS" in context["execution"]["build_environment"]
    assert context["execution"]["cargo_configuration"]["sha256"]

    with pytest.raises(criterion_manifest.ManifestError, match="pending"):
        criterion_manifest.prepare_save(
            criterion, tmp_path / "repo", "speedup", "candidate", {}
        )


def test_publish_verify_and_hydrate_bind_exact_artifacts(tmp_path: Path) -> None:
    criterion, _source, transaction = _prepare(tmp_path)
    _target_registrations(transaction, "candidate")

    manifest = criterion_manifest.publish_save(criterion, transaction)

    assert manifest["provenance"]["kind"] == "measured"
    assert len(manifest["criterion"]["registrations"]) == 32
    pending = criterion / ".opthash" / "manifests" / "speedup" / "candidate.pending"
    assert not pending.exists()
    verified = criterion_manifest.verify_manifest(
        criterion, "speedup", "candidate", strict_measured=True
    )
    assert verified == manifest

    hydrated = criterion_manifest.hydrate(criterion, "speedup", "candidate")
    for artifact in ARTIFACTS:
        assert (
            hydrated / "get_hit" / "get_hit_elastic" / "candidate" / artifact
        ).is_file()

    canonical = criterion / "get_hit" / "get_hit_elastic" / "candidate"
    (canonical / "sample.json").write_text("tampered")
    with pytest.raises(criterion_manifest.ManifestError, match="hash|size"):
        criterion_manifest.verify_manifest(criterion, "speedup", "candidate")


def test_publish_rejects_source_change_and_leaves_pending(tmp_path: Path) -> None:
    criterion, source, transaction = _prepare(tmp_path)
    _registration(transaction, "candidate")
    (source / "src" / "lib.rs").write_text("// changed during benchmark\n")

    with pytest.raises(criterion_manifest.ManifestError, match="source"):
        criterion_manifest.publish_save(criterion, transaction)

    assert (criterion / ".opthash/manifests/speedup/candidate.pending").exists()
    assert not (criterion / ".opthash/manifests/speedup/candidate.json").exists()


def test_default_save_has_a_verifiable_execution_schema(tmp_path: Path) -> None:
    criterion = tmp_path / "criterion"
    source = _source_tree(tmp_path / "repo")
    transaction = criterion_manifest.prepare_save(
        criterion, source, "speedup", "candidate", {}
    )
    _registration(transaction, "candidate")

    manifest = criterion_manifest.publish_save(criterion, transaction)

    assert manifest["execution"]["core"] is None
    assert manifest["execution"]["criterion_tuning"] == []
    assert manifest["execution"]["forwarded_args"] == []
    assert (
        criterion_manifest.verify_manifest(
            criterion, "speedup", "candidate", strict_measured=True
        )
        == manifest
    )


def test_publish_schema_validates_before_canonical_artifacts_are_replaced(
    tmp_path: Path,
) -> None:
    criterion, _source, transaction = _prepare(tmp_path)
    _registration(transaction, "candidate")
    context_path = transaction / criterion_manifest.TRANSACTION_CONTEXT
    context = json.loads(context_path.read_text())
    del context["execution"]["criterion_tuning"]
    context_path.write_text(json.dumps(context))

    with pytest.raises(criterion_manifest.ManifestError, match="tuning|execution"):
        criterion_manifest.publish_save(criterion, transaction)

    assert not (criterion / "get_hit/get_hit_elastic/candidate").exists()
    assert (criterion / ".opthash/manifests/speedup/candidate.pending").exists()


def test_publish_rejects_methodology_change_during_measurement(
    tmp_path: Path,
) -> None:
    criterion, source, transaction = _prepare(tmp_path)
    _registration(transaction, "candidate")
    (source / "scripts" / "bench.sh").write_text("#!/bin/sh\n# changed\n")

    with pytest.raises(criterion_manifest.ManifestError, match="methodology"):
        criterion_manifest.publish_save(criterion, transaction)

    assert (criterion / ".opthash/manifests/speedup/candidate.pending").exists()


def test_publish_rejects_build_environment_change_during_measurement(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("RUSTFLAGS", raising=False)
    criterion, _source, transaction = _prepare(tmp_path)
    _registration(transaction, "candidate")
    monkeypatch.setenv("RUSTFLAGS", "-C target-cpu=native")

    with pytest.raises(criterion_manifest.ManifestError, match="build environment"):
        criterion_manifest.publish_save(criterion, transaction)

    assert (criterion / ".opthash/manifests/speedup/candidate.pending").exists()


@pytest.mark.parametrize("fault", ["missing", "extra", "symlink", "identity"])
def test_publish_rejects_invalid_registration_artifacts(
    tmp_path: Path, fault: str
) -> None:
    criterion, _source, transaction = _prepare(tmp_path)
    _target_registrations(transaction, "candidate")
    directory = transaction / "get_hit" / "get_hit_elastic" / "candidate"
    if fault == "missing":
        (directory / "sample.json").unlink()
    elif fault == "extra":
        (directory / "unbound.json").write_text("{}")
    elif fault == "symlink":
        (directory / "sample.json").unlink()
        (directory / "sample.json").symlink_to("estimates.json")
    else:
        benchmark = json.loads((directory / "benchmark.json").read_text())
        benchmark["function_id"] = "different"
        (directory / "benchmark.json").write_text(json.dumps(benchmark))

    with pytest.raises(criterion_manifest.ManifestError):
        criterion_manifest.publish_save(criterion, transaction)


def test_hydrate_comparison_allows_source_change_but_rejects_fixture_or_core(
    tmp_path: Path,
) -> None:
    criterion, _source, transaction = _prepare(
        tmp_path, baseline="anchor", source_marker="base"
    )
    _target_registrations(transaction, "anchor")
    criterion_manifest.publish_save(criterion, transaction)

    source = tmp_path / "repo"
    (source / "src" / "lib.rs").write_text("// candidate source\n")
    candidate = criterion_manifest.prepare_save(
        criterion,
        source,
        "speedup",
        "candidate",
        {
            "core": 5,
            "criterion_tuning": ["--measurement-time", "10"],
            "requested_bench": "speedup",
        },
    )
    _target_registrations(candidate, "candidate")
    criterion_manifest.publish_save(criterion, candidate)

    hydrated = criterion_manifest.hydrate(
        criterion, "speedup", "candidate", compare="anchor"
    )
    assert (hydrated / "get_hit/get_hit_elastic/anchor/sample.json").is_file()
    assert (hydrated / "get_hit/get_hit_elastic/candidate/sample.json").is_file()
    for artifact in ARTIFACTS:
        assert (hydrated / "get_hit/get_hit_elastic/new" / artifact).read_bytes() == (
            hydrated / "get_hit/get_hit_elastic/candidate" / artifact
        ).read_bytes()

    manifest_path = criterion / ".opthash/manifests/speedup/candidate.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["execution"]["core"] = 7
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(criterion_manifest.ManifestError, match="core"):
        criterion_manifest.hydrate(criterion, "speedup", "candidate", compare="anchor")


def test_hydrate_comparison_binds_os_host_and_cpu_identity(tmp_path: Path) -> None:
    criterion, source, anchor = _prepare(tmp_path, baseline="anchor")
    _registration(anchor, "anchor")
    criterion_manifest.publish_save(criterion, anchor)
    candidate = criterion_manifest.prepare_save(
        criterion,
        source,
        "speedup",
        "candidate",
        {
            "core": 5,
            "criterion_tuning": ["--measurement-time", "10"],
            "requested_bench": "speedup",
        },
    )
    _registration(candidate, "candidate")
    criterion_manifest.publish_save(criterion, candidate)
    manifest_path = criterion / ".opthash/manifests/speedup/candidate.json"
    original = json.loads(manifest_path.read_text())

    changed_os = json.loads(json.dumps(original))
    changed_os["execution"]["operating_system"] = "different-os"

    changed_host = json.loads(json.dumps(original))
    host_name = "different-host"
    changed_host["execution"]["host_identity"] = {
        "algorithm": "sha256_hostname_v1",
        "name": host_name,
        "sha256": hashlib.sha256(host_name.encode()).hexdigest(),
    }

    changed_cpu = json.loads(json.dumps(original))
    cpu_fields = {"Architecture": "different-cpu"}
    cpu_bytes = json.dumps(cpu_fields, sort_keys=True, separators=(",", ":")).encode()
    changed_cpu["execution"]["cpu_identity"] = {
        "algorithm": "sha256_canonical_cpu_fields_v1",
        "fields": cpu_fields,
        "sha256": hashlib.sha256(cpu_bytes).hexdigest(),
    }

    for manifest, field in (
        (changed_os, "operating_system"),
        (changed_host, "host_identity"),
        (changed_cpu, "cpu_identity"),
    ):
        manifest_path.write_text(json.dumps(manifest))
        with pytest.raises(criterion_manifest.ManifestError, match=field):
            criterion_manifest.hydrate(
                criterion, "speedup", "candidate", compare="anchor"
            )


def test_cli_has_no_historical_recovery_command() -> None:
    with pytest.raises(SystemExit):
        criterion_manifest._build_parser().parse_args(
            [
                "recover-audit",
                "--root",
                "criterion",
                "--target",
                "speedup",
                "--baseline",
                "ref",
                "--source-sha256",
                "1" * 64,
            ]
        )


def test_strict_hydrate_rejects_current_methodology_and_execution_mismatches(
    tmp_path: Path,
) -> None:
    criterion, source, transaction = _prepare(tmp_path, baseline="anchor")
    _target_registrations(transaction, "anchor")
    criterion_manifest.publish_save(criterion, transaction)
    caller = {
        "core": 5,
        "criterion_tuning": ["--measurement-time", "10"],
    }

    hydrated = criterion_manifest.hydrate(
        criterion,
        "speedup",
        "anchor",
        strict_measured=True,
        source_root=source,
        caller_context=caller,
    )
    criterion_manifest.discard_transaction(criterion, hydrated)

    (source / "benches" / "support" / "throughput.rs").write_text(
        "pub const MAP_SIZE: usize = 123;\n"
    )
    with pytest.raises(criterion_manifest.ManifestError, match="methodology"):
        criterion_manifest.hydrate(
            criterion,
            "speedup",
            "anchor",
            strict_measured=True,
            source_root=source,
            caller_context=caller,
        )

    (source / "benches" / "support" / "throughput.rs").write_text(
        "pub const MAP_SIZE: usize = 20_000;\n"
    )
    (source / ".cargo").mkdir()
    config = source / ".cargo/config.toml"
    config.write_text('[build]\nrustflags = ["-C", "target-cpu=native"]\n')
    with pytest.raises(criterion_manifest.ManifestError, match="methodology"):
        criterion_manifest.hydrate(
            criterion,
            "speedup",
            "anchor",
            strict_measured=True,
            source_root=source,
            caller_context=caller,
        )
    config.unlink()
    with pytest.raises(criterion_manifest.ManifestError, match="core"):
        criterion_manifest.hydrate(
            criterion,
            "speedup",
            "anchor",
            strict_measured=True,
            source_root=source,
            caller_context={**caller, "core": 7},
        )


def test_strict_hydrate_rejects_a_partial_measured_manifest(tmp_path: Path) -> None:
    criterion, source, transaction = _prepare(tmp_path, baseline="anchor")
    _registration(transaction, "anchor")
    criterion_manifest.publish_save(criterion, transaction)

    with pytest.raises(criterion_manifest.ManifestError, match="incomplete"):
        criterion_manifest.hydrate(
            criterion,
            "speedup",
            "anchor",
            strict_measured=True,
            source_root=source,
            caller_context={
                "core": 5,
                "criterion_tuning": ["--measurement-time", "10"],
            },
        )


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("RUSTFLAGS", "-C target-cpu=native"),
        ("CARGO_BUILD_RUSTFLAGS", "--cfg probe"),
        ("CARGO_PROFILE_RELEASE_LTO", "true"),
    ],
)
def test_strict_hydrate_binds_the_current_build_environment(
    tmp_path: Path, monkeypatch, variable: str, value: str
) -> None:
    monkeypatch.delenv(variable, raising=False)
    criterion, source, transaction = _prepare(tmp_path, baseline="anchor")
    _target_registrations(transaction, "anchor")
    criterion_manifest.publish_save(criterion, transaction)
    monkeypatch.setenv(variable, value)

    with pytest.raises(criterion_manifest.ManifestError, match="build_environment"):
        criterion_manifest.hydrate(
            criterion,
            "speedup",
            "anchor",
            strict_measured=True,
            source_root=source,
            caller_context={
                "core": 5,
                "criterion_tuning": ["--measurement-time", "10"],
            },
        )


def test_strict_hydrate_binds_ancestor_cargo_configuration(tmp_path: Path) -> None:
    criterion, source, transaction = _prepare(tmp_path, baseline="anchor")
    _target_registrations(transaction, "anchor")
    criterion_manifest.publish_save(criterion, transaction)
    cargo_dir = tmp_path / ".cargo"
    cargo_dir.mkdir()
    (cargo_dir / "config.toml").write_text('[profile.release]\nlto = "thin"\n')

    with pytest.raises(criterion_manifest.ManifestError, match="cargo_configuration"):
        criterion_manifest.hydrate(
            criterion,
            "speedup",
            "anchor",
            strict_measured=True,
            source_root=source,
            caller_context={
                "core": 5,
                "criterion_tuning": ["--measurement-time", "10"],
            },
        )


def test_discard_is_confined_to_transaction_root(tmp_path: Path) -> None:
    criterion, _source, transaction = _prepare(tmp_path)
    criterion_manifest.discard_transaction(criterion, transaction)
    assert not transaction.exists()

    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(criterion_manifest.ManifestError):
        criterion_manifest.discard_transaction(criterion, outside)
    assert outside.exists()


def test_publish_accepts_a_nonempty_filtered_registration_set(tmp_path: Path) -> None:
    criterion, _source, transaction = _prepare(tmp_path)
    _registration(transaction, "candidate")

    manifest = criterion_manifest.publish_save(criterion, transaction)

    assert [
        registration["full_id"]
        for registration in manifest["criterion"]["registrations"]
    ] == ["get_hit/get_hit_elastic"]
    with pytest.raises(criterion_manifest.ManifestError, match="incomplete"):
        criterion_manifest.require_complete_target(manifest, "speedup")


def test_publish_rejects_symlinked_managed_ancestors(tmp_path: Path) -> None:
    criterion, _source, transaction = _prepare(tmp_path)
    _target_registrations(transaction, "candidate")
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "keep"
    marker.write_text("outside")
    criterion.mkdir(exist_ok=True)
    (criterion / "delete_heavy").symlink_to(outside, target_is_directory=True)

    with pytest.raises(criterion_manifest.ManifestError, match="symlink|outside"):
        criterion_manifest.publish_save(criterion, transaction)

    assert marker.read_text() == "outside"
    assert (criterion / ".opthash/manifests/speedup/candidate.pending").exists()


def test_publish_binds_transaction_context_and_pending_identity(tmp_path: Path) -> None:
    criterion, _source, transaction = _prepare(tmp_path)
    forged = transaction.with_name("speedup-candidate-forged")
    forged.mkdir()
    (forged / criterion_manifest.TRANSACTION_CONTEXT).write_bytes(
        (transaction / criterion_manifest.TRANSACTION_CONTEXT).read_bytes()
    )
    _target_registrations(forged, "candidate")

    with pytest.raises(criterion_manifest.ManifestError, match="transaction|pending"):
        criterion_manifest.publish_save(criterion, forged)

    assert (criterion / ".opthash/manifests/speedup/candidate.pending").exists()


def test_publish_removes_pending_only_after_transaction_cleanup(
    tmp_path: Path, monkeypatch
) -> None:
    criterion, _source, transaction = _prepare(tmp_path)
    _target_registrations(transaction, "candidate")
    real_rmtree = criterion_manifest.shutil.rmtree

    def fail_transaction_cleanup(path: Path, *args, **kwargs):
        if Path(path).resolve() == transaction.resolve():
            raise OSError("scripted cleanup failure")
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(criterion_manifest.shutil, "rmtree", fail_transaction_cleanup)

    with pytest.raises(OSError, match="cleanup"):
        criterion_manifest.publish_save(criterion, transaction)

    assert (criterion / ".opthash/manifests/speedup/candidate.pending").exists()


def test_discard_rejects_nested_transaction_descendants(tmp_path: Path) -> None:
    criterion, _source, transaction = _prepare(tmp_path)
    nested = transaction / "group"
    nested.mkdir()

    with pytest.raises(criterion_manifest.ManifestError):
        criterion_manifest.discard_transaction(criterion, nested)

    assert transaction.exists()


def test_hydrate_rejects_identical_baseline_names(tmp_path: Path) -> None:
    criterion, _source, transaction = _prepare(tmp_path, baseline="anchor")
    _target_registrations(transaction, "anchor")
    criterion_manifest.publish_save(criterion, transaction)

    with pytest.raises(criterion_manifest.ManifestError, match="same|identical"):
        criterion_manifest.hydrate(criterion, "speedup", "anchor", compare="anchor")


def test_cli_preserves_context_fields_when_optional_flags_are_absent(
    tmp_path: Path, capsys
) -> None:
    criterion = tmp_path / "criterion"
    source = _source_tree(tmp_path / "repo")
    context = {
        "criterion_args": ["custom"],
        "forwarded_args": ["filter"],
        "criterion_tuning": ["tuning"],
    }

    status = criterion_manifest.main(
        [
            "prepare-save",
            "--root",
            str(criterion),
            "--source-root",
            str(source),
            "--target",
            "speedup",
            "--baseline",
            "candidate",
            "--context-json",
            json.dumps(context),
        ]
    )

    assert status == 0
    transaction = Path(capsys.readouterr().out.strip())
    stored = json.loads(
        (transaction / criterion_manifest.TRANSACTION_CONTEXT).read_text()
    )
    for field, expected in context.items():
        assert stored["execution"][field] == expected


def test_fixture_metadata_matches_rust_benchmark_constants() -> None:
    repository = Path(__file__).resolve().parents[1]
    throughput = (repository / "benches/support/throughput.rs").read_text()
    common = (repository / "benches/support/common.rs").read_text()
    fixtures = (repository / "benches/support/fixtures.rs").read_text()

    def integer_constant(source: str, name: str) -> int:
        match = re.search(
            rf"pub const {name}: usize = ([0-9_]+);",
            source,
        )
        assert match is not None, name
        return int(match.group(1).replace("_", ""))

    speedup = criterion_manifest.fixture_for("speedup")["parameters"]
    assert speedup == {
        "map_size": integer_constant(throughput, "MAP_SIZE"),
        "op_count": integer_constant(throughput, "OP_COUNT"),
        "tiny_map_size": integer_constant(throughput, "TINY_MAP_SIZE"),
        "tiny_op_count": integer_constant(throughput, "TINY_OP_COUNT"),
        "resize_insert_count": integer_constant(throughput, "RESIZE_INSERT_COUNT"),
    }
    size_match = re.search(
        r"pub const LATENCY_SIZES: &\[usize\] = &\[([^]]+)\];",
        common,
    )
    assert size_match is not None
    latency_sizes = [
        int(value.strip().replace("_", ""))
        for value in size_match.group(1).split(",")
        if value.strip()
    ]
    mean_latency = criterion_manifest.fixture_for("mean_latency")
    assert mean_latency["parameters"]["latency_sizes"] == latency_sizes
    seed_match = re.search(
        r"DEFAULT_HIT_QUERY_SEED: u64 = (0x[0-9A-Fa-f_]+);",
        fixtures,
    )
    assert seed_match is not None
    randomized = mean_latency["hit_traces"][0]
    assert randomized["seed"] == hex(int(seed_match.group(1).replace("_", ""), 16))
