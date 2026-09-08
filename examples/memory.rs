//! Heap footprint of the four maps: live bytes, the peak while building, and
//! allocation traffic, for a preallocated fill and a grow-from-empty fill.
//! Prints TSV. Counts are deterministic, so this runs under the release profile
//! instead of the fat-LTO bench profile:
//!
//! ```bash
//! cargo run --release --example memory
//! MEMORY_SIZES=1000,10000 cargo run --release --example memory
//! ```

#[path = "../benches/harness/fixtures.rs"]
mod fixtures;
#[path = "../benches/harness/memory.rs"]
mod memory;
#[path = "../benches/harness/queries.rs"]
mod queries;

use std::env;
use std::hash::Hash;
use std::hint::black_box;

use fixtures::{ElasticHashMap, FunnelHashMap, HashbrownMap, StdHashMap};
use memory::{AllocationCounters, AllocationMeasurement, CountingAllocator};

/// Straddles hashbrown's 7/8 · 2^20 = 917,504 capacity step so the
/// power-of-two sawtooth shows: 900K sits just under it, 1M just over, and
/// 1.8M refills the doubled table.
const DEFAULT_SIZES: &[usize] = &[100_000, 900_000, 1_000_000, 1_800_000];

static COUNTERS: AllocationCounters = AllocationCounters::new();

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator::new(&COUNTERS);

#[derive(Clone, Copy)]
enum Mode {
    /// `with_capacity(n)` then `n` inserts: the harness constructors' path.
    Prealloc,
    /// Empty map then `n` inserts: exercises each map's growth policy.
    Grow,
}

impl Mode {
    const ALL: [Self; 2] = [Self::Prealloc, Self::Grow];

    fn label(self) -> &'static str {
        match self {
            Self::Prealloc => "prealloc",
            Self::Grow => "grow",
        }
    }
}

/// Construction and sizing surface the harness needs from each map.
trait MapUnderTest<K, V> {
    const NAME: &'static str;
    fn empty() -> Self;
    fn with_capacity(capacity: usize) -> Self;
    fn insert(&mut self, key: K, value: V);
    fn len(&self) -> usize;
    fn capacity(&self) -> usize;
}

macro_rules! maps_under_test {
    ($($name:literal => $Map:ident),+ $(,)?) => {$(
        impl<K: Eq + Hash, V> MapUnderTest<K, V> for $Map<K, V> {
            const NAME: &'static str = $name;
            fn empty() -> Self {
                Self::with_hasher(Default::default())
            }
            fn with_capacity(capacity: usize) -> Self {
                Self::with_capacity_and_hasher(capacity, Default::default())
            }
            fn insert(&mut self, key: K, value: V) {
                <$Map<K, V>>::insert(self, key, value);
            }
            fn len(&self) -> usize {
                <$Map<K, V>>::len(self)
            }
            fn capacity(&self) -> usize {
                <$Map<K, V>>::capacity(self)
            }
        }
    )+};
}

maps_under_test!(
    "std" => StdHashMap,
    "hashbrown" => HashbrownMap,
    "elastic" => ElasticHashMap,
    "funnel" => FunnelHashMap,
);

struct Report {
    payload: &'static str,
    mode: Mode,
    implementation: &'static str,
    capacity: usize,
    measurement: AllocationMeasurement,
}

fn configured_sizes() -> Vec<usize> {
    match env::var("MEMORY_SIZES") {
        Ok(raw) => queries::parse_positive_sizes("MEMORY_SIZES", &raw)
            .unwrap_or_else(|error| panic!("{error}")),
        Err(env::VarError::NotPresent) => DEFAULT_SIZES.to_vec(),
        Err(env::VarError::NotUnicode(_)) => panic!("MEMORY_SIZES must contain valid Unicode"),
    }
}

fn measure<M, V>(payload: &'static str, mode: Mode, pairs: &[(u64, V)]) -> Report
where
    M: MapUnderTest<u64, V>,
    V: Copy,
{
    ALLOCATOR.reset_peak();
    let before = ALLOCATOR.snapshot();
    let mut map = match mode {
        Mode::Prealloc => M::with_capacity(pairs.len()),
        Mode::Grow => M::empty(),
    };
    for &(key, value) in pairs {
        map.insert(key, value);
    }
    black_box(&map);
    let after = ALLOCATOR.snapshot();

    assert_eq!(map.len(), pairs.len(), "measured map length");
    let capacity = map.capacity();
    let measurement = AllocationMeasurement::between(before, after, pairs.len());
    drop(map);
    let after_drop = ALLOCATOR.snapshot();
    assert_eq!(after_drop.live_bytes, before.live_bytes, "map leaked bytes");
    assert_eq!(
        after_drop.live_allocations, before.live_allocations,
        "map leaked allocations"
    );
    Report {
        payload,
        mode,
        implementation: M::NAME,
        capacity,
        measurement,
    }
}

fn family<V: Copy>(payload: &'static str, pairs: &[(u64, V)]) {
    for mode in Mode::ALL {
        print_report(&measure::<StdHashMap<u64, V>, V>(payload, mode, pairs));
        print_report(&measure::<HashbrownMap<u64, V>, V>(payload, mode, pairs));
        print_report(&measure::<ElasticHashMap<u64, V>, V>(payload, mode, pairs));
        print_report(&measure::<FunnelHashMap<u64, V>, V>(payload, mode, pairs));
    }
}

#[allow(clippy::cast_precision_loss)]
fn print_report(report: &Report) {
    let m = report.measurement;
    println!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{:.3}\t{:.3}\t{}\t{:.3}\t{}\t{}\t{}\t{:.3}",
        report.payload,
        m.live_entries,
        report.mode.label(),
        report.implementation,
        report.capacity,
        m.live_bytes,
        m.per_entry(m.live_bytes),
        m.live_bytes as f64 / report.capacity as f64,
        m.peak_live_bytes,
        m.per_entry(m.peak_live_bytes),
        m.live_allocations,
        m.allocation_calls,
        m.allocated_bytes,
        m.per_entry(m.allocated_bytes),
    );
}

fn main() {
    println!(
        "payload\tentries\tmode\timplementation\tcapacity\tlive_bytes\tbytes_per_entry\t\
         bytes_per_capacity\tpeak_bytes\tpeak_bytes_per_entry\tlive_allocations\t\
         allocation_calls\tallocated_bytes\tallocated_bytes_per_entry"
    );
    for size in configured_sizes() {
        family("u64", &fixtures::make_pairs(size));
        family("big32", &fixtures::make_big_pairs(size));
    }
}
