#![allow(dead_code)]

/// Fixed seed for reproducible randomized hit traces.
pub const DEFAULT_HIT_QUERY_SEED: u64 = 0xD1B5_4A32_D192_ED03;

const SPLITMIX_INCREMENT: u64 = 0x9E37_79B9_7F4A_7C15;

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(SPLITMIX_INCREMENT);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    fn index_below(&mut self, upper: usize) -> usize {
        debug_assert!(upper > 0);
        let upper = u64::try_from(upper).expect("shuffle length must fit in u64");
        let rejection_floor = upper.wrapping_neg() % upper;
        loop {
            let value = self.next_u64();
            if value >= rejection_floor {
                return usize::try_from(value % upper).expect("sampled index must fit in usize");
            }
        }
    }
}

/// Creates `count` hit keys by cycling one deterministic Fisher-Yates
/// permutation of the supplied pair keys. Empty inputs yield an empty list.
#[must_use]
pub fn shuffled_hit_keys(pairs: &[(u64, u64)], count: usize) -> Vec<u64> {
    shuffled_hit_keys_with_seed(pairs, count, DEFAULT_HIT_QUERY_SEED)
}

/// Seed-selectable form of [`shuffled_hit_keys`] for reproducibility tests.
#[must_use]
pub fn shuffled_hit_keys_with_seed(pairs: &[(u64, u64)], count: usize, seed: u64) -> Vec<u64> {
    let mut keys = pairs.iter().map(|&(key, _)| key).collect::<Vec<_>>();
    let mut random = SplitMix64::new(seed);
    for upper in (2..=keys.len()).rev() {
        keys.swap(upper - 1, random.index_below(upper));
    }
    cycle_keys(&keys, count)
}

/// Creates `count` hit keys by cycling pair keys in their original order.
/// Empty inputs yield an empty list.
#[must_use]
pub fn sequential_hit_keys(pairs: &[(u64, u64)], count: usize) -> Vec<u64> {
    let keys = pairs.iter().map(|&(key, _)| key).collect::<Vec<_>>();
    cycle_keys(&keys, count)
}

fn cycle_keys(keys: &[u64], count: usize) -> Vec<u64> {
    keys.iter().copied().cycle().take(count).collect()
}

/// Compact labels for round K/M sizes without truncating arbitrary overrides.
#[must_use]
pub fn exact_size_label(size: usize) -> String {
    if size >= 1_000_000 && size.is_multiple_of(1_000_000) {
        format!("{}M", size / 1_000_000)
    } else if size >= 1_000 && size.is_multiple_of(1_000) {
        format!("{}K", size / 1_000)
    } else {
        size.to_string()
    }
}

/// Criterion samples for the scaled preallocated-insert sweep.
#[must_use]
pub const fn scaled_insert_sample_size(size: usize) -> usize {
    if size >= 10_000_000 { 10 } else { 100 }
}

pub fn parse_positive_sizes(name: &str, raw: &str) -> Result<Vec<usize>, String> {
    if raw.trim().is_empty() {
        return Err(format!(
            "{name} must be a non-empty comma-separated list of positive integers"
        ));
    }

    let mut sizes = Vec::new();
    for (index, raw_value) in raw.split(',').enumerate() {
        let value = raw_value.trim();
        if value.is_empty() {
            return Err(format!(
                "{name} contains an empty value at position {}",
                index + 1
            ));
        }

        let parsed = value
            .parse::<usize>()
            .map_err(|_| format!("{name} value `{value}` is not a positive integer"))?;
        if parsed == 0 {
            return Err(format!("{name} values must be greater than zero"));
        }
        if sizes.contains(&parsed) {
            return Err(format!("{name} contains duplicate value `{parsed}`"));
        }
        sizes.push(parsed);
    }
    Ok(sizes)
}
