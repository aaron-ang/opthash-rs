// `mod common;` is included by each bench binary; items unused in one binary
// may be used in another, so `dead_code` has to be suppressed module-wide.
#![allow(dead_code)]

use std::collections::HashMap as StdHashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use hashbrown::HashMap as HashbrownMap;
use opthash::{ElasticHashMap, FunnelHashMap};

/// Map sizes the Criterion latency suite sweeps over.
pub const LATENCY_SIZES: &[usize] = &[1_000, 10_000, 100_000, 1_000_000, 10_000_000];

/// Knuth multiplicative-hash constant (golden ratio * 2^64, odd).
pub const GOLDEN_RATIO_U64: u64 = 0x9E37_79B9_7F4A_7C15;
/// Alternating 1010... bit pattern; cheap key→value mix that flips every bit.
pub const VALUE_XOR_MIX: u64 = 0xA5A5_A5A5_A5A5_A5A5;
/// Bit-inverse of [`VALUE_XOR_MIX`]; used in delete-heavy bench to mark
/// replacement values as distinct from the initial value mix.
pub const VALUE_XOR_MIX_ALT: u64 = 0x5A5A_5A5A_5A5A_5A5A;

#[must_use]
pub fn key_at(index: usize) -> u64 {
    (index as u64).wrapping_mul(GOLDEN_RATIO_U64)
}

#[must_use]
pub fn make_pairs(count: usize) -> Vec<(u64, u64)> {
    (0..count)
        .map(|idx| {
            let key = key_at(idx);
            (key, key ^ VALUE_XOR_MIX)
        })
        .collect()
}

#[must_use]
pub fn build_std_map(pairs: &[(u64, u64)]) -> StdHashMap<u64, u64> {
    let mut map = StdHashMap::with_capacity(pairs.len());
    for &(key, value) in pairs {
        map.insert(key, value);
    }
    map
}

#[must_use]
pub fn build_elastic_map(pairs: &[(u64, u64)]) -> ElasticHashMap<u64, u64> {
    let mut map = ElasticHashMap::with_capacity(pairs.len());
    for &(key, value) in pairs {
        map.insert(key, value);
    }
    map
}

#[must_use]
pub fn build_funnel_map(pairs: &[(u64, u64)]) -> FunnelHashMap<u64, u64> {
    let mut map = FunnelHashMap::with_capacity(pairs.len());
    for &(key, value) in pairs {
        map.insert(key, value);
    }
    map
}

#[must_use]
pub fn build_hashbrown_map(pairs: &[(u64, u64)]) -> HashbrownMap<u64, u64> {
    let mut map = HashbrownMap::with_capacity(pairs.len());
    for &(key, value) in pairs {
        map.insert(key, value);
    }
    map
}

// ---------------------------------------------------------------------------
// `DropU64` payload — Drop-bearing variant of `u64`.
//
// Several bench groups (clear, drain, extract_if) measure code paths whose
// dominant cost is per-entry `Drop`. With `(u64, u64)` payload — `Copy`,
// no-op `Drop` — LLVM can prove the walk is side-effect-free and elide
// the entire loop, hiding regressions. `DropU64`'s `Drop` impl issues an
// atomic xor against a global sink: observable to the optimizer, so the
// drop loop has to actually execute, and trivially cheap at runtime (~1
// ns per drop on modern x86).
// ---------------------------------------------------------------------------

/// Sink for [`DropU64::drop`] side-effects. Read in [`drop_sink_value`]
/// after each bench to keep the writes observable.
pub static DROP_SINK: AtomicU64 = AtomicU64::new(0);

/// Wrapper around `u64` whose `Drop` impl is observable. Keeps LLVM from
/// eliding the drop loop in clear / drain / extract_if benches.
#[derive(PartialEq, Eq, Hash)]
pub struct DropU64(pub u64);

impl Drop for DropU64 {
    #[inline]
    fn drop(&mut self) {
        DROP_SINK.fetch_xor(self.0, Ordering::Relaxed);
    }
}

#[must_use]
pub fn drop_sink_value() -> u64 {
    DROP_SINK.load(Ordering::Relaxed)
}

#[must_use]
pub fn build_std_drop_map(n: usize) -> StdHashMap<DropU64, DropU64> {
    let mut map = StdHashMap::with_capacity(n);
    for idx in 0..n {
        let key = key_at(idx);
        map.insert(DropU64(key), DropU64(key ^ VALUE_XOR_MIX));
    }
    map
}

#[must_use]
pub fn build_hashbrown_drop_map(n: usize) -> HashbrownMap<DropU64, DropU64> {
    let mut map = HashbrownMap::with_capacity(n);
    for idx in 0..n {
        let key = key_at(idx);
        map.insert(DropU64(key), DropU64(key ^ VALUE_XOR_MIX));
    }
    map
}

#[must_use]
pub fn build_elastic_drop_map(n: usize) -> ElasticHashMap<DropU64, DropU64> {
    let mut map = ElasticHashMap::with_capacity(n);
    for idx in 0..n {
        let key = key_at(idx);
        map.insert(DropU64(key), DropU64(key ^ VALUE_XOR_MIX));
    }
    map
}

#[must_use]
pub fn build_funnel_drop_map(n: usize) -> FunnelHashMap<DropU64, DropU64> {
    let mut map = FunnelHashMap::with_capacity(n);
    for idx in 0..n {
        let key = key_at(idx);
        map.insert(DropU64(key), DropU64(key ^ VALUE_XOR_MIX));
    }
    map
}

#[must_use]
pub fn size_label(size: usize) -> String {
    if size >= 1_000_000 {
        format!("{}M", size / 1_000_000)
    } else if size >= 1_000 {
        format!("{}K", size / 1_000)
    } else {
        format!("{size}")
    }
}
