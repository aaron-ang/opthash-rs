#![allow(dead_code, unused_imports)]

mod fixtures;
#[macro_use]
mod map_matrix;
mod queries;

pub use fixtures::*;
pub use map_matrix::bench_one_lookup_group;
pub use queries::*;

/// Pre-populated map size for the throughput benchmarks.
pub const MAP_SIZE: usize = 20_000;
/// Operations per iteration for throughput benchmarks.
pub const OP_COUNT: usize = 100_000;
/// Tiny map size; fits comfortably in L1.
pub const TINY_MAP_SIZE: usize = 32;
/// Tiny-map lookups per iteration.
pub const TINY_OP_COUNT: usize = 500_000;
/// Inserts per `resize_heavy` iteration.
pub const RESIZE_INSERT_COUNT: usize = 8_000;
