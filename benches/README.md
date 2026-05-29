# Benchmarks

Methodology + commands in [AGENTS.md](../AGENTS.md), and at the top of each benchmark file.

## Naming convention

CodSpeed identifies each benchmark by its full Criterion URI

```
benches/<file>.rs::<group-const>::<bench-fn>::<benchmark_group>::<bench-id>
```

and surfaces the **bench id** (last segment) as the benchmark's name. Renaming
or moving *any* segment makes CodSpeed treat it as a new benchmark: the old one
orphans (it stops being tracked and loses history, but can't fail CI — CodSpeed
only diffs benchmarks present in both the base and the PR). So additions must be
purely additive; reworks reset history.

Rules for the CodSpeed-tracked suite (`speedup.rs`):

- **One file, one group const.** All tracked benches live in `speedup.rs` under
  `criterion_group!(name = benches; …)`. Don't move tracked benches to another
  file or rename the const — both orphan every bench in them.
- **Bench id = `<workload>_<impl>`** — globally unique and self-describing, since
  it is the surfaced name. `impl ∈ {std, hashbrown, elastic, funnel}`, e.g.
  `get_hit_elastic`, `delete_heavy_funnel`, `set_union_std`. Never impl-only here
  (bare `elastic`/`funnel` would collide across workloads), and **variant configs
  are distinct workloads** — fold the variant into the token so ids stay unique:
  `get_hit_load_50_elastic`, `get_hit_big_elastic`, not a bare `get_hit_elastic`
  reused across groups.
- **`benchmark_group` = `<workload>`**, **bench fn = `bench_<workload>`** — both
  the bare workload (`get_hit`, `delete_heavy`, `set_union`, `get_hit_load_50`, …);
  no `_throughput` suffix (the whole suite is throughput).
- **Add benches additively**: a new `bench_<workload>` fn registered in the
  `benches` targets, emitting the four `<workload>_<impl>` ids via the
  `bench_all_impls!` family. Never rename or relocate an existing one.
- **Charts** ([generate_speedup_chart.py](../scripts/generate_speedup_chart.py))
  read `target/criterion/<benchmark_group>/<bench-id>/` and rebuild ids as
  `<workload>_<impl>`; add new workloads to its `WORKLOADS` list and keep
  `IMPLEMENTATIONS` in [_plot_common.py](../scripts/_plot_common.py) in sync.

Local-only suites (`mean_latency.rs`, `tail_latency.rs`) are never uploaded to
CodSpeed, so they use impl-only ids (`std`/`elastic`/…) scoped by their group or
output directory.

## Throughput (Rust, vs `std::HashMap`)

![Throughput speedup chart](../assets/benchmark-speedup.svg)

## Mean latency by map size (Rust)

![Latency chart](../assets/benchmark-latency.svg)

## Tail latency distribution (Rust)

![Tail latency — get-hit @ 10M](../assets/latency-tail-10M-get-hit.svg)

## Python bindings vs builtin `dict`

![Python speedup chart](../assets/benchmark-python-speedup.svg)
