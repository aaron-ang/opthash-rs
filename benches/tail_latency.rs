//! HDR tail-latency histograms for get-hit at SIZE=10M. Writes
//! percentiles + bucket counts to `target/latency/<map>/<size>/<op>.json`,
//! consumed by `scripts/generate_latency_chart.py` for the tail CDF.
//!
//! ```sh
//! cargo bench --bench tail_latency
//! uv run scripts/generate_latency_chart.py
//! ```

mod common;

use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;

use hdrhistogram::Histogram;
use serde::Serialize;

/// Map implementations measured side-by-side.
const MAPS: &[&str] = &["std", "hashbrown", "elastic", "funnel"];
/// Items inserted into the map before sampling.
const SIZE: usize = 10_000_000;
/// Operation label written into the output JSON.
const OP: &str = "get-hit";
/// Latency samples recorded per (map, op).
const SAMPLES: usize = 1_000_000;
/// Pre-sample warmup iterations to stabilize caches + branch predictor.
const WARMUP: usize = 10_000;

#[derive(Serialize)]
struct Percentiles {
    p50: u64,
    p90: u64,
    p99: u64,
    p999: u64,
    p9999: u64,
    p99999: u64,
    max: u64,
    mean: f64,
}

#[derive(Serialize)]
struct Bucket {
    ns_low: u64,
    ns_high: u64,
    count: u64,
}

#[derive(Serialize)]
struct LatencyReport<'a> {
    map: &'a str,
    size: usize,
    op: &'a str,
    samples: usize,
    clock_overhead_ns: u64,
    percentiles: Percentiles,
    histogram: Vec<Bucket>,
}

fn elapsed_ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).expect("elapsed fits in u64")
}

fn measure_clock_overhead_ns() -> u64 {
    let n = 10_000u64;
    let t0 = Instant::now();
    for _ in 0..n {
        black_box(Instant::now());
    }
    elapsed_ns(t0) / n
}

fn new_hist() -> Histogram<u64> {
    Histogram::new_with_bounds(1, 1_000_000_000, 3).expect("valid hdr bounds")
}

fn scatter(i: usize, n: usize) -> usize {
    #[allow(clippy::cast_possible_truncation)]
    let mixed = (i as u64).wrapping_mul(common::GOLDEN_RATIO_U64) as usize;
    mixed % n
}

fn measure<F, R>(samples: usize, warmup: usize, mut op: F) -> Histogram<u64>
where
    F: FnMut(usize) -> R,
{
    for i in 0..warmup {
        black_box(op(i));
    }
    let mut h = new_hist();
    for i in 0..samples {
        let t0 = Instant::now();
        let r = op(i);
        let dt = elapsed_ns(t0);
        black_box(r);
        h.record(dt.max(1)).unwrap();
    }
    h
}

fn run_get_hit(map: &str, size: usize, samples: usize, warmup: usize) -> Histogram<u64> {
    let pairs = common::make_pairs(size);
    let keys: Vec<u64> = pairs.iter().map(|&(k, _)| k).collect();
    let n = keys.len();

    macro_rules! run {
        ($build:expr) => {{
            let m = $build(&pairs);
            measure(samples, warmup, |i| {
                m.get(black_box(&keys[scatter(i, n)])).copied()
            })
        }};
    }

    match map {
        "std" => run!(common::build_std_map),
        "hashbrown" => run!(common::build_hashbrown_map),
        "elastic" => run!(common::build_elastic_map),
        "funnel" => run!(common::build_funnel_map),
        _ => unreachable!(),
    }
}

fn build_report<'a>(
    map: &'a str,
    h: &Histogram<u64>,
    overhead: u64,
    samples: usize,
) -> LatencyReport<'a> {
    let percentiles = Percentiles {
        p50: h.value_at_quantile(0.50),
        p90: h.value_at_quantile(0.90),
        p99: h.value_at_quantile(0.99),
        p999: h.value_at_quantile(0.999),
        p9999: h.value_at_quantile(0.9999),
        p99999: h.value_at_quantile(0.99999),
        max: h.max(),
        mean: h.mean(),
    };
    let cap = percentiles
        .p99999
        .saturating_mul(2)
        .max(percentiles.p9999.saturating_mul(4));
    let histogram = h
        .iter_recorded()
        .take_while(|v| v.value_iterated_to() <= cap)
        .filter(|v| v.count_since_last_iteration() > 0)
        .map(|v| {
            let hi = v.value_iterated_to();
            Bucket {
                ns_low: h.lowest_equivalent(hi),
                ns_high: hi,
                count: v.count_since_last_iteration(),
            }
        })
        .collect();
    LatencyReport {
        map,
        size: SIZE,
        op: OP,
        samples,
        clock_overhead_ns: overhead,
        percentiles,
        histogram,
    }
}

fn write_json(
    map: &str,
    h: &Histogram<u64>,
    overhead: u64,
    samples: usize,
) -> std::io::Result<PathBuf> {
    let dir = PathBuf::from(format!("target/latency/{map}/{SIZE}"));
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{OP}.json"));
    let report = build_report(map, h, overhead, samples);
    let file = fs::File::create(&path)?;
    serde_json::to_writer_pretty(file, &report)?;
    Ok(path)
}

fn main() {
    let overhead = measure_clock_overhead_ns();
    eprintln!("clock_overhead_ns ≈ {overhead}");

    for &m in MAPS {
        eprint!("running map={m} size={SIZE} op={OP} samples={SAMPLES} ... ");
        let t0 = Instant::now();
        let h = run_get_hit(m, SIZE, SAMPLES, WARMUP);
        let dur = t0.elapsed();
        let path = write_json(m, &h, overhead, SAMPLES).expect("write latency json");
        eprintln!(
            "done in {:.1}s | p50={}ns p99={}ns p999={}ns max={}ns → {}",
            dur.as_secs_f64(),
            h.value_at_quantile(0.50),
            h.value_at_quantile(0.99),
            h.value_at_quantile(0.999),
            h.max(),
            path.display()
        );
    }
}
