//! Shared fixtures for the integration suites.
#![allow(dead_code)]

use std::hash::Hash;

/// Seeded foldhash state: every integration test hashes the same key stream
/// on every run, so nothing depends on the process's random seed.
pub type FixedHashBuilder = foldhash::fast::FixedState;
pub const FIXED_HASH_SEED: u64 = 0xD1B5_4A32_D192_ED03;

pub fn fixed_hasher() -> FixedHashBuilder {
    FixedHashBuilder::with_seed(FIXED_HASH_SEED)
}

pub type ElasticHashMap<K, V> = opthash::ElasticHashMap<K, V, FixedHashBuilder>;
pub type FunnelHashMap<K, V> = opthash::FunnelHashMap<K, V, FixedHashBuilder>;
pub type ElasticHashSet<T> = opthash::ElasticHashSet<T, FixedHashBuilder>;
pub type FunnelHashSet<T> = opthash::FunnelHashSet<T, FixedHashBuilder>;

/// `new` / `with_capacity` for the fixed-hasher aliases above. The library
/// offers those constructors only for the random-seeded default hasher; when
/// that inherent bound fails, resolution falls through to this trait, so a
/// suite that imports it reads exactly like the std/hashbrown tests it ports.
pub trait Deterministic: Sized {
    fn new() -> Self;
    fn with_capacity(capacity: usize) -> Self;
}

macro_rules! impl_deterministic {
    (maps: $($Map:ident),*; sets: $($Set:ident),*) => {
        $(impl<K: Eq + Hash, V> Deterministic for $Map<K, V> {
            fn new() -> Self {
                Self::with_hasher(fixed_hasher())
            }

            fn with_capacity(capacity: usize) -> Self {
                Self::with_capacity_and_hasher(capacity, fixed_hasher())
            }
        })*
        $(impl<T: Eq + Hash> Deterministic for $Set<T> {
            fn new() -> Self {
                Self::with_hasher(fixed_hasher())
            }

            fn with_capacity(capacity: usize) -> Self {
                Self::with_capacity_and_hasher(capacity, fixed_hasher())
            }
        })*
    };
}

impl_deterministic!(maps: ElasticHashMap, FunnelHashMap; sets: ElasticHashSet, FunnelHashSet);
