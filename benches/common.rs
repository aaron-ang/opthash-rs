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

/// Emits `pub fn $fn(pairs: &[(u64, $val)]) -> $Map<u64, $val>` for each
/// `$fn => $Map`, each a `with_capacity` + insert loop. Covers the map and
/// big-value builder families.
macro_rules! pairs_builders {
    ($val:ty; $($fn:ident => $Map:ident),+ $(,)?) => {
        $(
            #[must_use]
            pub fn $fn(pairs: &[(u64, $val)]) -> $Map<u64, $val> {
                let mut map = $Map::with_capacity(pairs.len());
                for &(key, value) in pairs {
                    map.insert(key, value);
                }
                map
            }
        )+
    };
}

/// Emits `pub fn $fn(n: usize) -> $Map<DropU64, DropU64>` for each
/// `$fn => $Map`, inserting `n` observable-drop entries.
macro_rules! drop_builders {
    ($($fn:ident => $Map:ident),+ $(,)?) => {
        $(
            #[must_use]
            pub fn $fn(n: usize) -> $Map<DropU64, DropU64> {
                let mut map = $Map::with_capacity(n);
                for idx in 0..n {
                    let key = key_at(idx);
                    map.insert(DropU64(key), DropU64(key ^ VALUE_XOR_MIX));
                }
                map
            }
        )+
    };
}

pairs_builders!(u64;
    build_std_map => StdHashMap,
    build_hashbrown_map => HashbrownMap,
    build_elastic_map => ElasticHashMap,
    build_funnel_map => FunnelHashMap,
);

/// Side-effect sink for [`DropU64::drop`]; defeats LLVM elision of drop loops.
pub static DROP_SINK: AtomicU64 = AtomicU64::new(0);

/// `u64` with an observable `Drop`. Use for `clear`/`drain`/`extract_if`
/// benches where `(u64, u64)` payload would let the optimizer skip the walk.
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

drop_builders!(
    build_std_drop_map => StdHashMap,
    build_hashbrown_drop_map => HashbrownMap,
    build_elastic_drop_map => ElasticHashMap,
    build_funnel_drop_map => FunnelHashMap,
);

/// 32-byte Copy value for memcpy-cost benches
/// (insert rehash, drain move-out, get cache footprint).
/// Pair with `u64` keys.
pub type BigVal = [u64; 4];

#[inline]
#[must_use]
pub fn big_val(key: u64) -> BigVal {
    [key, key ^ VALUE_XOR_MIX, key.wrapping_add(1), !key]
}

#[must_use]
pub fn make_big_pairs(count: usize) -> Vec<(u64, BigVal)> {
    (0..count)
        .map(|idx| {
            let key = key_at(idx);
            (key, big_val(key))
        })
        .collect()
}

pairs_builders!(BigVal;
    build_std_big_map => StdHashMap,
    build_hashbrown_big_map => HashbrownMap,
    build_elastic_big_map => ElasticHashMap,
    build_funnel_big_map => FunnelHashMap,
);

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
