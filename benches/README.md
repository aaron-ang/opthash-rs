# Benchmarking

Rust bench targets compare `std::collections::HashMap`, `hashbrown::HashMap`, `opthash::ElasticHashMap`, `opthash::FunnelHashMap`. Shared fixtures live in `benches/common.rs`. Python-side benches under `benches/python/` compare the opthash bindings against builtin `dict`.

## Results

### Throughput (Rust, vs `std::HashMap`)

![Throughput speedup chart](../assets/benchmark-speedup.svg)

### Mean latency by map size (Rust)

![Latency chart](../assets/benchmark-latency.svg)

### Tail latency distribution (Rust)

![Tail latency — get-hit @ 10M](../assets/latency-tail-10M-get-hit.svg)

### Instructions per op (iai-callgrind, deterministic)

Structural workload comparison — no CPU noise.

![Instructions per op](../assets/benchmark-instr-count.svg)

### Python: opthash bindings vs builtin `dict`

![Python speedup chart](../assets/benchmark-python-speedup.svg)

## `benches/speedup.rs` — throughput + mean latency (Criterion)

Throughput workloads:

1. `insert_throughput`
2. `get_hit_throughput`
3. `get_miss_throughput`
4. `tiny_lookup_throughput`
5. `delete_heavy_throughput`
6. `resize_heavy_throughput`

Run:

```bash
cargo bench --bench speedup
cargo bench --bench speedup -- "get_hit"          # Criterion name filter
```

## `benches/latency.rs` — tail-latency histograms (hdrhistogram)

Captures per-operation latency distributions (p50/p90/p99/p999/p9999/max) and dumps them to JSON for plotting. Output: `target/latency/<map>/<size>/<op>.json`.

```bash
cargo bench --bench latency
```

## `benches/instr_count.rs` — deterministic instruction counts (iai-callgrind)

```bash
cargo install iai-callgrind-runner   # one-time
cargo bench --bench instr_count
```

Output: `target/iai/opthash/instr_count/<group>/<bench>/callgrind.<bench>.out` — parsed by `scripts/generate_instr_count_chart.py` into `assets/benchmark-instr-count.svg`.

## `benches/python/throughput.py` — Python bindings vs builtin `dict` (pytest-benchmark)

End-to-end workloads. Each opthash op crosses the GIL → `HashedAny::hash()` → Python bytecode, so this measures binding overhead as well as the map.

```bash
pytest benches/python/throughput.py --benchmark-json=.benchmarks/python.json
uv run --group charts python scripts/generate_python_chart.py
```

## `benches/python/binding_overhead.py` — per-op binding overhead

Decomposes one `m[k]` call: `loop -> hash(k) -> dict[k] -> __contains__ -> __getitem__ -> .get()`. Δ between rows attributes each primitive's ns cost. Run with `python benches/python/binding_overhead.py`.

For symbol-level attribution, drive a hot loop under `py-spy --native` and aggregate the folded-stack output:

```bash
py-spy record --native --rate 1000 --duration 8 \
  --format raw --output /tmp/perf_raw.txt -- \
  python benches/python/binding_overhead.py
```

## Reports

- Criterion HTML: `target/criterion/report/index.html`, per-workload pages below (e.g. `target/criterion/insert_throughput/report/index.html`)
- Charts: `uv run scripts/generate_all_charts.py` writes every SVG to `assets/` (speedup bars, mean-latency line, tail CDF, instructions-per-op bars, Python speedup bars)

## Profiling / flamegraphs

`benches/speedup.rs` integrates a `pprof` profiler. Pass `--profile-time N` and Criterion captures CPU samples instead of timing, writing `target/criterion/<workload>/<impl>/profile/flamegraph.svg`.

```bash
cargo bench --bench speedup -- --profile-time 5
cargo bench --bench speedup -- --profile-time 5 "get_hit"
```
