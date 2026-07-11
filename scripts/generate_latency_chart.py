import argparse
from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt

from _plot_common import (
    ASSETS_DIR,
    CriterionEstimate,
    IMPL_COLORS,
    IMPLEMENTATIONS,
    IMPL_LABELS,
    LATENCY_SIZES,
    apply_axis_style,
    load_criterion_mean_ns,
    provenance_text,
    save_svg,
    verify_criterion_baseline,
)


def _ratio_estimate(
    randomized: CriterionEstimate, sequential: CriterionEstimate
) -> CriterionEstimate:
    return CriterionEstimate(
        randomized.point_estimate / sequential.point_estimate,
        randomized.lower_bound / sequential.upper_bound,
        randomized.upper_bound / sequential.lower_bound,
    )


def _errorbar(ax, x, estimates: list[CriterionEstimate], implementation: str):
    points = np.array([estimate.point_estimate for estimate in estimates])
    lower = np.array([estimate.lower_bound for estimate in estimates])
    upper = np.array([estimate.upper_bound for estimate in estimates])
    ax.errorbar(
        x,
        points,
        yerr=np.vstack((points - lower, upper - points)),
        color=IMPL_COLORS[implementation],
        linewidth=2,
        marker="o",
        markersize=4,
        capsize=3,
        label=IMPL_LABELS[implementation],
    )


def plot_mean_latency_by_size(assets_dir: Path, *, baseline: str):
    """Plot randomized absolute latency and its ratio to sequential control."""
    manifest = verify_criterion_baseline("mean_latency", baseline)
    traces: dict[str, dict[str, list[CriterionEstimate]]] = {
        trace: {implementation: [] for implementation in IMPLEMENTATIONS}
        for trace in ("randomized", "sequential")
    }
    for trace, prefix in (
        ("randomized", "get_hit_latency"),
        ("sequential", "get_hit_sequential_latency"),
    ):
        for size_label in LATENCY_SIZES:
            group = f"{prefix}_{size_label}"
            for implementation in IMPLEMENTATIONS:
                traces[trace][implementation].append(
                    load_criterion_mean_ns(
                        group, f"{group}_{implementation}", baseline=baseline
                    )
                )

    ratios = {
        implementation: [
            _ratio_estimate(randomized, sequential)
            for randomized, sequential in zip(
                traces["randomized"][implementation],
                traces["sequential"][implementation],
                strict=True,
            )
        ]
        for implementation in IMPLEMENTATIONS
    }
    x = np.arange(len(LATENCY_SIZES))
    fig, (absolute_ax, ratio_ax) = plt.subplots(
        2,
        1,
        figsize=(13, 9.5),
        sharex=True,
        constrained_layout=True,
        gridspec_kw={"height_ratios": (3, 2)},
    )
    for implementation in IMPLEMENTATIONS:
        _errorbar(absolute_ax, x, traces["randomized"][implementation], implementation)
        _errorbar(ratio_ax, x, ratios[implementation], implementation)

    apply_axis_style(
        absolute_ax,
        title="Randomized fixed-seed Fisher-Yates trace",
        subtitle=(
            "Seed 0xD1B54A32D192ED03 · "
            f"Selected baseline: {baseline} · 95% CI · "
            "lower is better for absolute latency\n"
            f"{provenance_text(manifest)}"
        ),
        xlabel="",
        ylabel="Mean latency (ns/lookup)",
        y_formatter=lambda v, _: f"{v:.0f}",
    )
    absolute_ax.legend(fontsize=11, ncol=2)

    ratio_ax.axhline(1.0, linestyle="--", color="0.4", linewidth=1.0)
    ratio_ax.set_xticks(x)
    ratio_ax.set_xticklabels(LATENCY_SIZES, fontsize=12)
    apply_axis_style(
        ratio_ax,
        title="Randomized / Sequential Latency Ratio",
        subtitle="Sequential locality control · conservative propagated 95% CI",
        xlabel="Map size (entries)",
        ylabel="Randomized / sequential",
        y_formatter=lambda v, _: f"{v:.2f}",
    )
    save_svg(fig, assets_dir / "benchmark-latency.svg")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--baseline",
        required=True,
        help="safe named Criterion baseline to chart",
    )
    args = parser.parse_args()
    plot_mean_latency_by_size(ASSETS_DIR, baseline=args.baseline)


if __name__ == "__main__":
    main()
