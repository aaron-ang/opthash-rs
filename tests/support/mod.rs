//! Shared fixtures for the integration suites.
#![allow(dead_code)]

/// Seeded foldhash state: every integration test hashes the same key stream
/// on every run, so nothing depends on the process's random seed.
pub type FixedHashBuilder = foldhash::fast::FixedState;
pub const FIXED_HASH_SEED: u64 = 0xD1B5_4A32_D192_ED03;

pub fn fixed_hasher() -> FixedHashBuilder {
    FixedHashBuilder::with_seed(FIXED_HASH_SEED)
}
