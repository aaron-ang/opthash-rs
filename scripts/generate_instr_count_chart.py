"""Chart instructions-per-op + branch-mispredicts-per-op from iai-callgrind.

Deterministic counts (no CPU noise) per bench → structural overhead chart that
the wall-clock throughput chart can't show.

Reads: target/iai/opthash/instr_count/<group>/<bench>/callgrind.<bench>.out
Run:   uv run --group charts python scripts/generate_instr_count_chart.py
"""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

from _plot_common import (
    ASSETS_DIR,
    IMPL_COLORS,
    IMPL_LABELS,
    apply_axis_style,
    save_svg,
)


ROOT = Path(__file__).resolve().parents[1]
IAI_DIR = ROOT / "target" / "iai" / "opthash" / "instr_count"

# Bench groups in `benches/instr_count.rs`. Order = display order.
OP_GROUPS = (
    ("get_hit", "Get Hit"),
    ("insert", "Insert"),
    ("remove", "Remove"),
    ("iter", "Iter"),
    ("drain", "Drain"),
    ("extract_if", "Extract-If"),
)

# Same order as `plot_common.IMPLEMENTATIONS`. `std` may be absent for some
# ops (e.g. `extract_if` — nightly only on `std::HashMap`); missing benches
# are skipped per-op.
IMPLS = ("std", "hashbrown", "elastic", "funnel")
N_OPS = 1024  # must match `N` in `benches/instr_count.rs`

# `events:` line in callgrind.out — field index of metrics we care about.
EVENT_FIELDS = {
    "Ir": 0,  # instructions retired
}


def parse_callgrind_summary(path: Path) -> dict[str, int] | None:
    """Extract the `summary:` line counters as {event: value}."""
    if not path.exists():
        return None
    summary: list[int] | None = None
    for line in path.read_text().splitlines():
        if line.startswith("summary:"):
            summary = [int(x) for x in line.split()[1:]]
            break
    if summary is None:
        return None
    return {name: summary[idx] for name, idx in EVENT_FIELDS.items()}


def load_op_metrics() -> dict[str, dict[str, dict[str, float]]]:
    """{op: {impl: {metric: value_per_op}}}. Missing entries skipped."""
    out: dict[str, dict[str, dict[str, float]]] = {}
    for group, _ in OP_GROUPS:
        per_impl: dict[str, dict[str, float]] = {}
        for impl in IMPLS:
            bench = f"{group}_{impl}"
            path = IAI_DIR / group / bench / f"callgrind.{bench}.out"
            summary = parse_callgrind_summary(path)
            if summary is None:
                continue
            per_impl[impl] = {k: v / N_OPS for k, v in summary.items()}
        if per_impl:
            out[group] = per_impl
    return out


def plot_grouped_bars(
    metrics: dict[str, dict[str, dict[str, float]]],
    metric: str,
    title: str,
    subtitle: str,
    ylabel: str,
    out_path: Path,
) -> None:
    """Grouped bars: x = op, group of 3 bars per op (one per impl)."""
    op_labels = [label for group, label in OP_GROUPS if group in metrics]
    op_keys = [group for group, _ in OP_GROUPS if group in metrics]
    if not op_keys:
        print(f"no iai-callgrind data for {metric}, skipping")
        return

    values = {impl: [] for impl in IMPLS}
    for op in op_keys:
        for impl in IMPLS:
            values[impl].append(metrics[op].get(impl, {}).get(metric, 0.0))

    fig, ax = plt.subplots(figsize=(13, 6.5), constrained_layout=True)
    x = np.arange(len(op_labels))
    n = len(IMPLS)
    w = 0.8 / n
    offsets = [(i - (n - 1) / 2) * w for i in range(n)]

    bars_per_impl = []
    for impl, dx in zip(IMPLS, offsets):
        bars = ax.bar(
            x + dx,
            values[impl],
            width=w,
            label=IMPL_LABELS[impl],
            color=IMPL_COLORS[impl],
        )
        bars_per_impl.append(bars)

    max_val = max((max(v) for v in values.values()), default=1.0) or 1.0
    ax.set_ylim(0.0, max_val * 1.18)

    ax.set_xticks(x)
    ax.set_xticklabels(op_labels, fontsize=12)
    apply_axis_style(
        ax,
        title=title,
        subtitle=subtitle,
        xlabel="Operation",
        ylabel=ylabel,
        y_formatter=lambda v, _: f"{v:.0f}",
    )
    ax.legend(loc="upper left", fontsize=12)

    for bars in bars_per_impl:
        for bar in bars:
            v = bar.get_height()
            if v == 0:
                continue
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                v + max_val * 0.02,
                f"{v:.0f}",
                ha="center",
                va="bottom",
                fontsize=9,
                color="black",
            )

    save_svg(fig, out_path)


def main() -> None:
    metrics = load_op_metrics()
    if not metrics:
        print(
            f"no iai-callgrind output found under {IAI_DIR.relative_to(ROOT)}\n"
            "  run: cargo bench --bench instr_count"
        )
        return

    plot_grouped_bars(
        metrics,
        metric="Ir",
        title="Instructions per Op (iai-callgrind)",
        subtitle="Deterministic counts — lower is better; structural workload comparison",
        ylabel="Instructions / op",
        out_path=ASSETS_DIR / "benchmark-instr-count.svg",
    )


if __name__ == "__main__":
    main()
