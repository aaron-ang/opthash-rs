import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

from _plot_common import (
    ASSETS_DIR,
    IMPL_COLORS,
    IMPLEMENTATIONS,
    apply_axis_style,
    load_criterion_mean_ns,
    provenance_text,
    save_svg,
    verify_criterion_baseline,
)


THROUGHPUT_WORKLOADS = (
    ("insert", "Insert"),
    ("get_hit", "Get Hit"),
    ("get_miss", "Get Miss"),
    ("tiny_lookup", "Tiny"),
    ("mixed", "Mixed"),
    ("delete_heavy", "Delete"),
    ("resize_heavy", "Resize"),
)


def plot_throughput_speedup(assets_dir: Path, *, baseline: str):
    """Single bar chart: all throughput workloads, speedup vs std."""
    manifest = verify_criterion_baseline("speedup", baseline)
    labels = []
    elastic_speedups = []
    funnel_speedups = []

    # Group name is the workload; bench id is `<workload>_<impl>`.
    for workload, label in THROUGHPUT_WORKLOADS:
        times = {
            impl: load_criterion_mean_ns(
                workload, f"{workload}_{impl}", baseline=baseline
            )
            for impl in IMPLEMENTATIONS
        }
        labels.append(label)
        elastic_speedups.append(
            times["std"].point_estimate / times["elastic"].point_estimate
        )
        funnel_speedups.append(
            times["std"].point_estimate / times["funnel"].point_estimate
        )

    if not labels:
        print("no throughput data found, skipping")
        return

    fig, ax = plt.subplots(figsize=(13, 6.5), constrained_layout=True)

    x = np.arange(len(labels))
    w = 0.34

    elastic_bars = ax.bar(
        x - w / 2,
        elastic_speedups,
        width=w,
        label="ElasticHashMap",
        color=IMPL_COLORS["elastic"],
    )
    funnel_bars = ax.bar(
        x + w / 2,
        funnel_speedups,
        width=w,
        label="FunnelHashMap",
        color=IMPL_COLORS["funnel"],
    )

    max_val = max(1.0, *(elastic_speedups + funnel_speedups))
    ax.set_ylim(0.0, max_val * 1.30)
    ax.axhline(1.0, linestyle="--", color="0.4", linewidth=0.8)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=12)
    apply_axis_style(
        ax,
        title="Throughput Speedup over std::HashMap",
        subtitle=(
            "Criterion throughput — std::HashMap is 1.0× · "
            f"Selected baseline: {baseline}\n{provenance_text(manifest)}"
        ),
        xlabel="Workload",
        ylabel="Speedup (higher is better)",
        y_formatter=lambda v, _: f"{v:.1f}",
    )

    ax.legend(loc="upper left", bbox_to_anchor=(0.0, 1.0), ncol=2, fontsize=12)

    for bars in (elastic_bars, funnel_bars):
        for bar in bars:
            v = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                v + max_val * 0.03,
                f"{v:.2f}",
                ha="center",
                va="bottom",
                fontsize=10,
                color="black",
            )

    save_svg(fig, assets_dir / "benchmark-speedup.svg")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--baseline",
        required=True,
        help="safe named Criterion baseline to chart",
    )
    args = parser.parse_args()
    plot_throughput_speedup(ASSETS_DIR, baseline=args.baseline)


if __name__ == "__main__":
    main()
