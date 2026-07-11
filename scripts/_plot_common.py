from __future__ import annotations

import io
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path

import matplotlib.colors as mcolors
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

try:
    from criterion_manifest import require_complete_target, verify_manifest
except ModuleNotFoundError:  # Imported as `scripts._plot_common`.
    from scripts.criterion_manifest import require_complete_target, verify_manifest


ROOT = Path(__file__).resolve().parents[1]
CRITERION_DIR = ROOT / "target" / "criterion"
ASSETS_DIR = ROOT / "assets"

IMPLEMENTATIONS = ("std", "hashbrown", "elastic", "funnel")
IMPL_LABELS = {
    "std": "std::HashMap",
    "hashbrown": "hashbrown::HashMap",
    "elastic": "ElasticHashMap",
    "funnel": "FunnelHashMap",
}
_PAIRED = plt.get_cmap("Paired").colors
IMPL_COLORS = {
    "std": mcolors.to_hex(_PAIRED[0]),  # light blue   (baseline)
    "hashbrown": mcolors.to_hex(_PAIRED[1]),  # dark  blue   (baseline)
    "elastic": mcolors.to_hex(_PAIRED[6]),  # light orange (opthash)
    "funnel": mcolors.to_hex(_PAIRED[7]),  # dark  orange (opthash)
}

LATENCY_SIZES = ("1K", "10K", "100K", "1M", "10M")

TITLE_COLOR = "darkslategray"
SUBTITLE_COLOR = "dimgray"
SVG_HASHSALT = "opthash-benchmark-charts-v1"
_SAFE_BASELINE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


@dataclass(frozen=True)
class CriterionEstimate:
    point_estimate: float
    lower_bound: float
    upper_bound: float


def verify_criterion_baseline(target: str, baseline: str) -> dict:
    """Verify and return the content-bound manifest for a chart baseline."""
    manifest = verify_manifest(CRITERION_DIR, target, baseline)
    require_complete_target(manifest, target)
    return manifest


def provenance_text(manifest: dict) -> str:
    """Compact provenance label embedded in generated assets."""
    kind = manifest["provenance"]["kind"]
    source = manifest["source"]["sha256"][:12]
    return f"Provenance: {kind} · Source: {source}"


def load_criterion_mean_ns(
    group: str, variant: str, *, baseline: str
) -> CriterionEstimate:
    if _SAFE_BASELINE.fullmatch(baseline) is None:
        raise ValueError(f"unsafe Criterion baseline name: {baseline!r}")
    path = CRITERION_DIR / group / variant / baseline / "estimates.json"
    if not path.exists():
        raise FileNotFoundError(f"missing Criterion estimates: {path}")
    data = json.loads(path.read_text())
    try:
        mean = data["mean"]
        interval = mean["confidence_interval"]
        point_estimate = float(mean["point_estimate"])
        confidence_level = float(interval["confidence_level"])
        lower_bound = float(interval["lower_bound"])
        upper_bound = float(interval["upper_bound"])
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError(
            f"no usable mean 95% confidence interval in {path}"
        ) from error
    if (
        confidence_level != 0.95
        or not all(
            math.isfinite(value) for value in (point_estimate, lower_bound, upper_bound)
        )
        or lower_bound <= 0.0
        or not lower_bound <= point_estimate <= upper_bound
    ):
        raise RuntimeError(f"no usable mean 95% confidence interval in {path}")
    return CriterionEstimate(point_estimate, lower_bound, upper_bound)


def apply_axis_style(
    ax,
    *,
    title: str,
    subtitle: str | None = None,
    xlabel: str,
    ylabel: str,
    y_formatter=None,
):
    ax.tick_params(axis="y", labelsize=11, length=0)
    ax.tick_params(axis="x", length=0)
    if y_formatter is not None:
        ax.yaxis.set_major_formatter(FuncFormatter(y_formatter))
    ax.set_ylabel(ylabel, fontsize=14)
    ax.set_xlabel(xlabel, fontsize=14, labelpad=14)
    ax.set_title(title, fontsize=22, pad=28, color=TITLE_COLOR)
    if subtitle is not None:
        ax.text(
            0.5,
            1.02,
            subtitle,
            transform=ax.transAxes,
            ha="center",
            va="bottom",
            fontsize=13,
            color=SUBTITLE_COLOR,
        )


def save_svg(fig, path: Path):
    buffer = io.StringIO()
    try:
        with plt.rc_context({"svg.hashsalt": SVG_HASHSALT}):
            fig.savefig(
                buffer,
                format="svg",
                bbox_inches="tight",
                metadata={"Date": None},
            )
    finally:
        plt.close(fig)
    raw = buffer.getvalue()
    clean = "\n".join(line.rstrip() for line in raw.splitlines())
    if raw.endswith("\n"):
        clean += "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(clean)
    print(f"wrote {path.relative_to(ROOT)}")
