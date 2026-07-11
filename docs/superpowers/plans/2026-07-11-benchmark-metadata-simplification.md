# Benchmark Metadata Simplification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace transactional Criterion manifests with small atomic metadata sidecars while retaining reliable compatibility checks for named A/B runs and charts.

**Architecture:** Criterion owns its baseline directories. A focused Python helper records source and methodology fingerprints plus execution identity after successful measurements, and verifies compatibility before stored comparisons. `scripts/bench.sh` remains the sole orchestration entry point.

**Tech Stack:** Bash, Python 3.10+, Criterion JSON, pytest, Git, Linux CPU affinity tools.

## Global Constraints

- Preserve `SAVE`, `LOAD`, `BASELINE`, `BENCH`, `CORE`, filters, pinning, core locking, and NUMA behavior.
- Candidate and baseline source fingerprints may differ; methodology, fixtures, target, filter, hardware/core, rustc, and registration sets may not.
- Publish no metadata when Cargo fails, the run is interrupted, or source changes during measurement.
- Final chart evidence requires a clean measured source.
- Do not duplicate fixture values or expected Criterion IDs in Python.

---

### Task 1: Define the compact sidecar schema and fingerprints

**Files:**
- Create: `scripts/benchmark_metadata.py`
- Test: `tests/test_benchmark_metadata.py`

**Interfaces:**
- Produces: `source_fingerprint(source_root: Path) -> str`
- Produces: `methodology_fingerprint(source_root: Path, target: str) -> str`
- Produces: `metadata_path(criterion_root: Path, target: str, baseline: str) -> Path`
- Produces: CLI commands `fingerprint`, `begin`, `publish`, and `verify`.

- [ ] **Step 1: Write failing path and fingerprint tests**

```python
import json
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
```

- [ ] **Step 2: Run the tests and verify the missing-module failure**

Run: `uv run pytest tests/test_benchmark_metadata.py -q`

Expected: collection fails because `scripts.benchmark_metadata` does not exist.

- [ ] **Step 3: Implement canonical hashing and safe paths**

```python
import hashlib
import re

SCHEMA_VERSION = 1
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
RESERVED_NAMES = {"new", "base", "change", "report"}
TARGET_FILES = {
    "speedup": ("benches/speedup.rs",),
    "mean_latency": ("benches/mean_latency.rs",),
    "set_ops": ("benches/set_ops.rs",),
    "map_api": ("benches/map_api.rs",),
    "load_factor": ("benches/load_factor.rs",),
    "payload_size": ("benches/payload_size.rs",),
    "scaled_insert": ("benches/scaled_insert.rs",),
}
COMMON_METHODOLOGY_FILES = (
    "Cargo.toml",
    "Cargo.lock",
    "build.rs",
    "scripts/bench.sh",
    "scripts/benchmark_metadata.py",
)


def validate_name(value: str) -> None:
    if SAFE_NAME.fullmatch(value) is None or value.lower() in RESERVED_NAMES:
        raise MetadataError(f"unsafe or reserved name: {value!r}")


def hash_paths(root: Path, paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        relative = path.relative_to(root).as_posix().encode()
        contents = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    return digest.hexdigest()


def metadata_path(root: Path, target: str, baseline: str) -> Path:
    validate_name(target)
    validate_name(baseline)
    return root.resolve() / ".opthash" / "metadata" / target / f"{baseline}.json"


def source_fingerprint(source_root: Path) -> str:
    paths = [source_root / "Cargo.toml", source_root / "Cargo.lock", source_root / "build.rs"]
    paths += sorted((source_root / "src").rglob("*.rs"))
    paths += sorted((source_root / "benches").rglob("*.rs"))
    paths += [source_root / "scripts" / "bench.sh",
              source_root / "scripts" / "benchmark_metadata.py"]
    return hash_paths(source_root, paths)


def methodology_fingerprint(source_root: Path, target: str) -> str:
    if target not in TARGET_FILES:
        raise MetadataError(f"unsupported benchmark target: {target!r}")
    relative = COMMON_METHODOLOGY_FILES + TARGET_FILES[target]
    paths = [source_root / path for path in relative]
    paths += sorted((source_root / "benches" / "support").rglob("*.rs"))
    return hash_paths(source_root, paths)
```

- [ ] **Step 4: Run focused tests**

Run: `uv run pytest tests/test_benchmark_metadata.py -q`

Expected: path and fingerprint tests pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/benchmark_metadata.py tests/test_benchmark_metadata.py
git commit -m "bench: define compact baseline metadata"
```

### Task 2: Publish metadata atomically after successful runs

**Files:**
- Modify: `scripts/benchmark_metadata.py`
- Modify: `tests/test_benchmark_metadata.py`

**Interfaces:**
- Produces: `begin(root, source_root, target, baseline) -> str`, which removes
  only that named baseline's old Criterion directories and sidecar, then
  returns the pre-run source fingerprint.
- Produces: `publish(*, root, source_root, target, baseline, source_before, core, requested_bench, forwarded_args) -> dict[str, object]`
- Consumes: Criterion directories at `<root>/<group>/<function>/<baseline>/`.

- [ ] **Step 1: Write failing publication tests**

```python
def make_criterion_baseline(root: Path, baseline: str) -> Path:
    estimates = root / "get_hit" / "get_hit_elastic" / baseline / "estimates.json"
    estimates.parent.mkdir(parents=True)
    estimates.write_text(json.dumps({"mean": {"point_estimate": 1.0}}))
    return root


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
```

- [ ] **Step 2: Run the tests and verify failure**

Run: `uv run pytest tests/test_benchmark_metadata.py -q`

Expected: failures because `publish` is undefined.

- [ ] **Step 3: Implement measured registration discovery and atomic JSON**

```python
def begin(root: Path, source_root: Path, target: str, baseline: str) -> str:
    metadata_path(root, target, baseline).unlink(missing_ok=True)
    for directory in root.glob(f"*/*/{baseline}"):
        if directory.is_dir():
            shutil.rmtree(directory)
    return source_fingerprint(source_root)


def measured_registrations(root: Path, baseline: str) -> list[str]:
    registrations = []
    for estimates in root.glob(f"*/*/{baseline}/estimates.json"):
        registrations.append("/".join(estimates.relative_to(root).parts[:2]))
    if not registrations:
        raise MetadataError(f"no Criterion registrations for baseline {baseline!r}")
    return sorted(registrations)


def write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp-{os.getpid()}")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)
```

The published object must have this stable shape (values shown are examples):

```python
{
    "schema": 1,
    "source": {
        "before": source_before,
        "after": source_after,
        "commit": git_commit,
        "dirty": git_dirty,
    },
    "methodology": methodology_fingerprint(source_root, target),
    "target": target,
    "requested_bench": requested_bench,
    "forwarded_args": forwarded_args,
    "registrations": measured_registrations(root, baseline),
    "cpu_identity": cpu_identity(),
    "core": core,
    "os": platform.platform(),
    "rustc_vv": command_output(["rustc", "-Vv"]),
    "measured_at_utc": datetime.now(timezone.utc).isoformat(),
}
```

`forwarded_args` contains the exact baseline-neutral arguments passed after
Criterion's baseline flags, including filters and tuning such as
`--measurement-time`. Do not record `--save-baseline`, `--load-baseline`,
`--baseline`, or their names in that field. The source dirty flag is captured
after confirming `before == after`.

- [ ] **Step 4: Run publication tests**

Run: `uv run pytest tests/test_benchmark_metadata.py -q`

Expected: publication and source-change tests pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/benchmark_metadata.py tests/test_benchmark_metadata.py
git commit -m "bench: publish atomic baseline metadata"
```

### Task 3: Verify compatibility without hydration

**Files:**
- Modify: `scripts/benchmark_metadata.py`
- Modify: `tests/test_benchmark_metadata.py`

**Interfaces:**
- Produces: `verify(root, target, baseline, compare=None, require_clean=False) -> list[dict]`.

- [ ] **Step 1: Write compatibility tests**

```python
def write_metadata(root: Path, name: str, value: dict[str, object]) -> None:
    path = benchmark_metadata.metadata_path(root, "speedup", name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def compatible_metadata_pair(root: Path) -> tuple[dict[str, object], dict[str, object]]:
    common = {
        "schema": 1,
        "methodology": "a" * 64,
        "target": "speedup",
        "requested_bench": "speedup",
        "forwarded_args": ["--measurement-time", "10", "get_hit"],
        "registrations": ["get_hit/get_hit_elastic"],
        "cpu_identity": "fixture-cpu",
        "core": 5,
        "os": "fixture-os",
        "rustc_vv": "rustc fixture",
        "measured_at_utc": "2026-07-11T00:00:00+00:00",
    }
    anchor = common | {
        "source": {"before": "a" * 64, "after": "a" * 64,
                   "commit": "1" * 40, "dirty": False}
    }
    candidate = common | {
        "source": {"before": "b" * 64, "after": "b" * 64,
                   "commit": "2" * 40, "dirty": False}
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
        "cpu_identity": "other-cpu",
        "os": "other-os",
        "rustc_vv": "other-rustc",
        "forwarded_args": ["get_miss"],
        "registrations": ["get_miss/get_miss_elastic"],
    }[field]


@pytest.mark.parametrize(
    "field",
    ["methodology", "core", "cpu_identity", "os", "rustc_vv",
     "forwarded_args", "registrations"],
)
def test_verify_rejects_incompatible_metadata(tmp_path: Path, field: str) -> None:
    anchor, candidate = compatible_metadata_pair(tmp_path)
    candidate[field] = incompatible_value(field)
    write_metadata(tmp_path, "candidate", candidate)
    with pytest.raises(benchmark_metadata.MetadataError, match=field):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor", "candidate")


def test_verify_allows_different_source_fingerprints(tmp_path: Path) -> None:
    anchor, candidate = compatible_metadata_pair(tmp_path)
    candidate["source"]["after"] = "f" * 64
    write_metadata(tmp_path, "candidate", candidate)
    benchmark_metadata.verify(tmp_path, "speedup", "anchor", "candidate")


def test_verify_rejects_missing_criterion_baseline(tmp_path: Path) -> None:
    metadata, _ = compatible_metadata_pair(tmp_path)
    (tmp_path / "get_hit" / "get_hit_elastic" / "anchor" / "estimates.json").unlink()
    write_metadata(tmp_path, "anchor", metadata)
    with pytest.raises(benchmark_metadata.MetadataError, match="registrations"):
        benchmark_metadata.verify(tmp_path, "speedup", "anchor")
```

- [ ] **Step 2: Run and verify failures**

Run: `uv run pytest tests/test_benchmark_metadata.py -q`

Expected: compatibility tests fail because `verify` is undefined.

- [ ] **Step 3: Implement compatibility checks**

```python
COMPATIBILITY_FIELDS = (
    "methodology",
    "core",
    "cpu_identity",
    "os",
    "rustc_vv",
    "forwarded_args",
    "registrations",
)


def verify(root: Path, target: str, baseline: str, compare: str | None = None, *, require_clean: bool = False):
    names = [baseline] if compare is None else [baseline, compare]
    values = [read_metadata(root, target, name) for name in names]
    for name, value in zip(names, values, strict=True):
        if value.get("schema") != SCHEMA_VERSION or value.get("target") != target:
            raise MetadataError(f"invalid metadata schema or target for {name!r}")
        if value["source"]["before"] != value["source"]["after"]:
            raise MetadataError(f"source changed during baseline {name!r}")
        registrations = measured_registrations(root, name)
        if registrations != value["registrations"]:
            raise MetadataError(f"Criterion registrations differ for {name!r}")
    if require_clean and any(value["source"]["dirty"] for value in values):
        raise MetadataError("final evidence requires clean source metadata")
    for field in COMPATIBILITY_FIELDS:
        if any(value[field] != values[0][field] for value in values[1:]):
            raise MetadataError(f"incompatible benchmark metadata field: {field}")
    return values
```

- [ ] **Step 4: Run metadata tests**

Run: `uv run pytest tests/test_benchmark_metadata.py -q`

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/benchmark_metadata.py tests/test_benchmark_metadata.py
git commit -m "bench: reject incompatible named baselines"
```

### Task 4: Simplify `bench.sh`

**Files:**
- Modify: `scripts/bench.sh:45-55,238-end`
- Modify: `tests/test_bench_run_metadata.py`

**Interfaces:**
- Consumes: `benchmark_metadata.py fingerprint|publish|verify`.
- Preserves: existing Criterion and `OPTHASH_BENCH_*` environment arguments.

- [ ] **Step 1: Replace transaction expectations with sidecar expectations in tests**

The fake helper must log `fingerprint`, `verify`, and `publish`. Assert that
Cargo never receives `CRITERION_HOME`, that `publish` follows a successful
Cargo invocation, and that failed Cargo has no `publish` call.

```python
assert [command[0] for command in commands] == ["fingerprint", "publish"]
assert "CRITERION_HOME" not in captured
assert captured["OPTHASH_BENCH_SAVE_BASELINE"] == "candidate"
```

- [ ] **Step 2: Run runner tests and verify failure**

Run: `uv run pytest tests/test_bench_run_metadata.py -q`

Expected: transaction-oriented assertions fail.

- [ ] **Step 3: Replace transaction orchestration**

Before Cargo on a save:

```bash
source_before=$("${metadata_helper[@]}" begin --root "$CRITERION_ROOT"
  --source-root "$REPO_ROOT" --target "$target" --baseline "$metadata_save")
```

Before Cargo on a comparison:

```bash
verify_args=(verify --root "$CRITERION_ROOT" --target "$target"
  --baseline "${metadata_load:-$metadata_compare}")
if [[ -n "$metadata_load" ]]; then
  verify_args+=(--compare "$metadata_compare")
fi
"${metadata_helper[@]}" "${verify_args[@]}"
```

After successful Cargo on a save:

```bash
publish_args=(publish --root "$CRITERION_ROOT" --source-root "$REPO_ROOT"
  --target "$target" --baseline "$metadata_save" --source-before "$source_before"
  --requested-bench "$BENCH" --core "$core")
for arg in "${forward_args[@]}"; do
  publish_args+=(--forwarded-arg "$arg")
done
"${metadata_helper[@]}" "${publish_args[@]}"
```

This `begin` call makes a failed or interrupted overwrite unusable and prevents
a filtered rerun from inheriting stale registration directories. Remove
`transaction`, `manifest_mode`, `CRITERION_HOME`, hydration, and discard
branches. Rename the test override to `OPTHASH_BENCHMARK_METADATA_HELPER` and
remove `OPTHASH_CRITERION_MANIFEST_HELPER`. Keep the launcher around metadata
commands so user/core identity is consistent under sudo.

- [ ] **Step 4: Run shell runner tests**

Run: `uv run pytest tests/test_bench_run_metadata.py -q`

Expected: all runner tests pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/bench.sh tests/test_bench_run_metadata.py
git commit -m "bench: use metadata sidecars directly"
```

### Task 5: Switch charts and remove the old manifest subsystem

**Files:**
- Modify: `scripts/_plot_common.py`
- Modify: `scripts/generate_speedup_chart.py`
- Modify: `scripts/generate_latency_chart.py`
- Modify: `tests/test_plot_common.py`
- Delete: `scripts/criterion_manifest.py`
- Delete: `tests/test_criterion_manifest.py`

**Interfaces:**
- `verify_criterion_baseline(target, baseline)` delegates to `benchmark_metadata.verify(..., require_clean=True)`.
- `require_registrations(metadata, required)` rejects every missing chart cell.
- Each chart constructs required registration IDs from its existing workload,
  size, and implementation constants; the metadata schema does not duplicate
  benchmark registrations.

- [ ] **Step 1: Update plot tests to expect compact metadata**

```python
def test_chart_verification_requires_clean_complete_metadata(monkeypatch) -> None:
    monkeypatch.setattr(
        benchmark_metadata,
        "verify",
        lambda *args, **kwargs: [{"source": {"dirty": False}, "registrations": EXPECTED}],
    )
    metadata = verify_criterion_baseline("speedup", "anchor")
    require_registrations(metadata, EXPECTED)


def test_chart_verification_rejects_one_missing_registration() -> None:
    with pytest.raises(RuntimeError, match="missing Criterion registrations"):
        require_registrations({"registrations": EXPECTED[:-1]}, EXPECTED)
```

- [ ] **Step 2: Run plot tests and verify failure**

Run: `uv run pytest tests/test_plot_common.py -q`

Expected: imports still depend on `criterion_manifest`.

- [ ] **Step 3: Move compact provenance formatting into `_plot_common.py`**

```python
from scripts import benchmark_metadata


def verify_criterion_baseline(target: str, baseline: str) -> dict:
    return benchmark_metadata.verify(
        CRITERION_DIR, target, baseline, require_clean=True
    )[0]


def require_registrations(metadata: dict, required: Iterable[str]) -> None:
    missing = sorted(set(required) - set(metadata["registrations"]))
    if missing:
        raise RuntimeError(f"missing Criterion registrations: {missing}")


def provenance_text(metadata: dict) -> str:
    return f"Source: {metadata['source']['after'][:12]} · measured"
```

Immediately after verification, `generate_speedup_chart.py` constructs
`f"{workload}/{workload}_{implementation}"` for every existing
`THROUGHPUT_WORKLOADS`/`IMPLEMENTATIONS` pair. `generate_latency_chart.py`
constructs both trace prefixes over every existing
`LATENCY_SIZES`/`IMPLEMENTATIONS` pair. Both call `require_registrations`
before loading estimates or replacing an asset.

Delete the old helper and its test file only after all imports are gone.

- [ ] **Step 4: Run the focused and full Python suites**

Run: `uv run pytest tests/test_benchmark_metadata.py tests/test_bench_run_metadata.py tests/test_plot_common.py -q`

Expected: focused tests pass.

Run: `uv run pytest -q`

Expected: full Python suite passes with fewer manifest-specific tests.

- [ ] **Step 5: Smoke named workflows**

Run: `SCALED_INSERT_SIZES=1000 SAVE=metadata-smoke BENCH=scaled_insert scripts/bench.sh -- insert_scale_1K`

Expected: Criterion baseline and one atomic sidecar exist; no transaction directory exists.

Run: `LOAD=metadata-smoke BASELINE=metadata-smoke BENCH=scaled_insert scripts/bench.sh -- insert_scale_1K`

Expected: metadata compatibility succeeds and Criterion loads stored results.

- [ ] **Step 6: Commit**

```bash
git add scripts tests
git commit -m "bench: remove transactional manifest machinery"
```

### Task 6: Final verification

**Files:** None.

- [ ] **Step 1: Run required repository gates**

Run: `cargo test`

Expected: all Rust tests pass.

Run: `pre-commit run --all-files`

Expected: all hooks pass.

- [ ] **Step 2: Verify no obsolete terminology or files remain**

Run: `rg -n "criterion_manifest|prepare-save|publish-save|hydrate|manifest_mode" scripts tests benches AGENTS.md`

Expected: no matches.

- [ ] **Step 3: Verify package contents**

Run: `cargo package --allow-dirty --list`

Expected: benchmark scripts, metadata, tests, and plan files are absent from the package.

- [ ] **Step 4: Commit any test-only corrections, otherwise leave the task without a commit**

```bash
git status --short
```

Expected: only pre-existing user changes outside this plan remain.
