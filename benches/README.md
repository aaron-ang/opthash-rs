# Benchmarks

Methodology + commands in [AGENTS.md](../AGENTS.md), and at the top of each benchmark file.

## Throughput (Rust, vs `std::HashMap`)

![Throughput speedup chart](../assets/benchmark-speedup.svg)

## Mean latency by map size (Rust)

![Latency chart](../assets/benchmark-latency.svg)

## Tail latency distribution (Rust)

![Tail latency — get-hit @ 10M](../assets/latency-tail-10M-get-hit.svg)

## Python bindings vs builtin `dict`

![Python speedup chart](../assets/benchmark-python-speedup.svg)
