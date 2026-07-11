from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import _plot_common  # noqa: E402
import criterion_manifest  # noqa: E402
import generate_latency_chart  # noqa: E402
import generate_speedup_chart  # noqa: E402


def _verified_manifest() -> dict[str, object]:
    return {
        "provenance": {"kind": "measured"},
        "source": {"sha256": "1" * 64},
        "criterion": {
            "registrations": [
                {"full_id": full_id}
                for full_id in criterion_manifest.expected_registration_ids(
                    "mean_latency"
                )
            ]
        },
    }


def _write_estimate(
    root: Path,
    group: str,
    variant: str,
    baseline: str,
    value: float,
    *,
    lower: float | None = None,
    upper: float | None = None,
) -> None:
    path = root / group / variant / baseline / "estimates.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "mean": {
                    "point_estimate": value,
                    "confidence_interval": {
                        "confidence_level": 0.95,
                        "lower_bound": value - 1.0 if lower is None else lower,
                        "upper_bound": value + 1.0 if upper is None else upper,
                    },
                }
            }
        )
    )


def test_criterion_loader_reads_the_requested_named_baseline(
    tmp_path: Path, monkeypatch
) -> None:
    _write_estimate(tmp_path, "lookup", "lookup_elastic", "new", 99.0)
    _write_estimate(tmp_path, "lookup", "lookup_elastic", "ref", 42.0)
    monkeypatch.setattr(_plot_common, "CRITERION_DIR", tmp_path)

    with pytest.raises(TypeError):
        _plot_common.load_criterion_mean_ns("lookup", "lookup_elastic")

    estimate = _plot_common.load_criterion_mean_ns(
        "lookup", "lookup_elastic", baseline="ref"
    )
    assert estimate.point_estimate == 42.0
    assert estimate.lower_bound == 41.0
    assert estimate.upper_bound == 43.0


@pytest.mark.parametrize(
    "mean",
    [
        {"point_estimate": 42.0},
        {
            "point_estimate": 42.0,
            "confidence_interval": {
                "confidence_level": 0.90,
                "lower_bound": 41.0,
                "upper_bound": 43.0,
            },
        },
        {
            "point_estimate": 42.0,
            "confidence_interval": {
                "confidence_level": 0.95,
                "lower_bound": 43.0,
                "upper_bound": 41.0,
            },
        },
    ],
)
def test_criterion_loader_rejects_missing_or_malformed_95_percent_intervals(
    tmp_path: Path, monkeypatch, mean: dict[str, object]
) -> None:
    path = tmp_path / "lookup" / "lookup_elastic" / "ref" / "estimates.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"mean": mean}))
    monkeypatch.setattr(_plot_common, "CRITERION_DIR", tmp_path)

    with pytest.raises(RuntimeError, match="95% confidence interval"):
        _plot_common.load_criterion_mean_ns("lookup", "lookup_elastic", baseline="ref")


def test_criterion_loader_rejects_unsafe_baseline_names(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(_plot_common, "CRITERION_DIR", tmp_path)

    for baseline in ("", ".", "..", "../ref", "nested/ref", "ref\\nested", "ref name"):
        try:
            _plot_common.load_criterion_mean_ns(
                "lookup", "lookup_elastic", baseline=baseline
            )
        except ValueError as error:
            assert "baseline" in str(error)
        else:
            raise AssertionError(f"accepted unsafe baseline {baseline!r}")


@pytest.mark.parametrize(
    ("function", "args"),
    [
        (generate_speedup_chart.plot_throughput_speedup, (Path("assets"),)),
        (generate_latency_chart.plot_mean_latency_by_size, (Path("assets"),)),
    ],
)
def test_rust_chart_apis_require_an_explicit_baseline(function, args) -> None:
    with pytest.raises(TypeError):
        function(*args)


@pytest.mark.parametrize(
    "module",
    [generate_speedup_chart, generate_latency_chart],
)
def test_rust_chart_clis_require_an_explicit_baseline(monkeypatch, module) -> None:
    monkeypatch.setattr(sys, "argv", [str(module.__file__)])

    with pytest.raises(SystemExit) as error:
        module.main()

    assert error.value.code == 2


def test_save_svg_emits_diff_clean_lines(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(_plot_common, "ROOT", tmp_path)
    figure, axis = _plot_common.plt.subplots()
    axis.plot([0, 1], [0, 1])
    path = tmp_path / "assets" / "chart.svg"

    _plot_common.save_svg(figure, path)

    assert all(line == line.rstrip() for line in path.read_text().splitlines())


def test_ratio_estimate_uses_conservative_propagated_interval() -> None:
    randomized = SimpleNamespace(
        point_estimate=12.0, lower_bound=10.0, upper_bound=14.0
    )
    sequential = SimpleNamespace(point_estimate=6.0, lower_bound=5.0, upper_bound=8.0)

    ratio = generate_latency_chart._ratio_estimate(randomized, sequential)

    assert ratio.point_estimate == 2.0
    assert ratio.lower_bound == 1.25
    assert ratio.upper_bound == 2.8


@pytest.mark.parametrize(
    "module,function_name,output_name",
    [
        (
            generate_speedup_chart,
            "plot_throughput_speedup",
            "benchmark-speedup.svg",
        ),
        (
            generate_latency_chart,
            "plot_mean_latency_by_size",
            "benchmark-latency.svg",
        ),
    ],
)
def test_named_baseline_chart_generation_fails_closed_when_an_artifact_is_missing(
    tmp_path: Path, monkeypatch, module, function_name: str, output_name: str
) -> None:
    output = tmp_path / output_name
    output.write_text("previous chart")

    def missing(*_args, **_kwargs):
        raise FileNotFoundError("missing named-baseline estimate")

    monkeypatch.setattr(module, "load_criterion_mean_ns", missing)
    monkeypatch.setattr(
        module,
        "verify_criterion_baseline",
        lambda *_args, **_kwargs: _verified_manifest(),
    )

    with pytest.raises(FileNotFoundError, match="named-baseline"):
        getattr(module, function_name)(tmp_path, baseline="ref")

    assert output.read_text() == "previous chart"


def test_latency_chart_loads_all_40_cells_before_writing_output(
    tmp_path: Path, monkeypatch
) -> None:
    output = tmp_path / "benchmark-latency.svg"
    output.write_text("previous chart")
    calls: list[tuple[str, str, str]] = []

    def load(group: str, variant: str, *, baseline: str):
        calls.append((group, variant, baseline))
        if len(calls) == 40:
            raise FileNotFoundError("missing final named-baseline estimate")
        return SimpleNamespace(point_estimate=10.0, lower_bound=9.0, upper_bound=11.0)

    monkeypatch.setattr(generate_latency_chart, "load_criterion_mean_ns", load)
    monkeypatch.setattr(
        generate_latency_chart,
        "verify_criterion_baseline",
        lambda *_args, **_kwargs: _verified_manifest(),
    )

    with pytest.raises(FileNotFoundError, match="final named-baseline"):
        generate_latency_chart.plot_mean_latency_by_size(tmp_path, baseline="ref")

    expected = []
    for prefix in ("get_hit_latency", "get_hit_sequential_latency"):
        for size in _plot_common.LATENCY_SIZES:
            group = f"{prefix}_{size}"
            expected.extend(
                (group, f"{group}_{implementation}", "ref")
                for implementation in _plot_common.IMPLEMENTATIONS
            )
    assert calls == expected
    assert output.read_text() == "previous chart"


def test_latency_chart_is_two_panel_labeled_and_byte_deterministic(
    tmp_path: Path, monkeypatch
) -> None:
    criterion = tmp_path / "criterion"
    for trace_index, prefix in enumerate(
        ("get_hit_latency", "get_hit_sequential_latency"), start=1
    ):
        for size_index, size in enumerate(_plot_common.LATENCY_SIZES, start=1):
            group = f"{prefix}_{size}"
            for implementation_index, implementation in enumerate(
                _plot_common.IMPLEMENTATIONS, start=1
            ):
                value = float(10 * trace_index + size_index + implementation_index)
                _write_estimate(
                    criterion,
                    group,
                    f"{group}_{implementation}",
                    "ref",
                    value,
                    lower=value - 0.5,
                    upper=value + 0.75,
                )

    monkeypatch.setattr(_plot_common, "CRITERION_DIR", criterion)
    monkeypatch.setattr(_plot_common, "ROOT", tmp_path)
    monkeypatch.setattr(
        generate_latency_chart,
        "verify_criterion_baseline",
        lambda *_args, **_kwargs: _verified_manifest(),
    )
    output = tmp_path / "benchmark-latency.svg"

    generate_latency_chart.plot_mean_latency_by_size(tmp_path, baseline="ref")
    first = output.read_bytes()
    generate_latency_chart.plot_mean_latency_by_size(tmp_path, baseline="ref")
    second = output.read_bytes()

    svg = second.decode()
    assert first == second
    assert svg.count('<g id="axes_') == 2
    assert "<dc:date>" not in svg
    for label in (
        "Randomized fixed-seed Fisher-Yates trace",
        "0xD1B54A32D192ED03",
        "Selected baseline: ref",
        "Sequential locality control",
        "lower is better for absolute latency",
        "95% CI",
        "Provenance: measured",
        "Source: 111111111111",
    ):
        assert label in svg


def test_chart_verifier_rejects_an_unbound_named_baseline(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(_plot_common, "CRITERION_DIR", tmp_path)

    with pytest.raises(Exception, match="manifest|JSON"):
        _plot_common.verify_criterion_baseline("mean_latency", "ref")
