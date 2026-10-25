//! Workload constants, deterministic fixtures, map constructors, and
//! Criterion comparison helpers shared by every bench target and by
//! `tests/benchmark_fixtures.rs`.

// Unpublished dev crate: API-documentation lints have no reader here.
#![allow(
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

mod fixtures;
mod group_probe;
mod map_matrix;
pub mod memory;
mod queries;

pub use fixtures::*;
pub use group_probe::GroupProbeMap;
pub use map_matrix::bench_one_lookup_group;
pub use queries::*;

#[doc(hidden)]
pub use criterion as __criterion;

use opthash::ReserveFraction;

/// Slot count of the throughput maps. A power of two, so Elastic and hashbrown
/// allocate exactly this many slots for `MAP_SIZE` entries.
pub const MAP_SLOTS: usize = 1 << 15;
/// Pre-populated map size for the throughput benchmarks: the full insert
/// budget of a `MAP_SLOTS` table at the default reserve fraction, and Funnel's
/// exact size, so every map is measured at its full insert budget.
pub const MAP_SIZE: usize = MAP_SLOTS - ReserveFraction::DEFAULT.floor_reserved(MAP_SLOTS);
/// Small delete burst for entry reinsertion, below either maintenance threshold.
pub const ENTRY_REINSERT_COUNT: usize = MAP_SIZE / 32;
/// Leave insertion slack so `SwissTable` controls do not grow after deletion.
pub const ENTRY_REINSERT_FILL: usize = MAP_SIZE * 3 / 4;
/// Operations per iteration for throughput benchmarks.
pub const OP_COUNT: usize = 100_000;
/// `key_at` index offset for miss queries: past every populated index in any
/// fixture, so a miss key never collides with a stored key.
pub const MISS_KEY_OFFSET: usize = 10_000_000;
/// Tiny map size; fits comfortably in L1.
pub const TINY_MAP_SIZE: usize = 32;
/// Tiny-map lookups per iteration.
pub const TINY_OP_COUNT: usize = 500_000;
/// Inserts per `resize_heavy` iteration.
pub const RESIZE_INSERT_COUNT: usize = 8_000;
