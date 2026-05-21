from generate_instr_count_chart import main as plot_instr_count
from generate_latency_chart import plot_mean_latency_by_size, plot_tail_cdf
from generate_speedup_chart import plot_throughput_speedup
from _plot_common import ASSETS_DIR


def main() -> None:
    plot_throughput_speedup(ASSETS_DIR)
    plot_mean_latency_by_size(ASSETS_DIR)
    plot_tail_cdf(ASSETS_DIR)
    plot_instr_count()


if __name__ == "__main__":
    main()
