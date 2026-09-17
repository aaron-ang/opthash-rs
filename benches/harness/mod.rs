#![allow(dead_code, unused_imports)]

mod fixtures;
#[macro_use]
mod map_matrix;
mod queries;

pub use fixtures::*;
pub use map_matrix::bench_one_lookup_group;
pub use queries::*;

use opthash::ReserveFraction;

/// Slot count of the throughput maps. A power of two, so Elastic and hashbrown
/// allocate exactly this many slots for `MAP_SIZE` entries.
pub const MAP_SLOTS: usize = 1 << 15;
/// Pre-populated map size for the throughput benchmarks: the full insert
/// budget of a `MAP_SLOTS` table at the default reserve fraction, and Funnel's
/// exact size, so every map is measured at its full insert budget.
pub const MAP_SIZE: usize = MAP_SLOTS - ReserveFraction::DEFAULT.floor_reserved(MAP_SLOTS);
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
