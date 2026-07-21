use std::hash::BuildHasher;

use super::{BenchHasher, ElasticHashMap, FunnelHashMap, OP_COUNT, make_pairs};

pub const CACHE_GATE_OP_COUNT: usize = OP_COUNT;
/// Caps preallocated insert-profile maps at roughly 0.6 GiB on reviewed hosts.
pub const CACHE_GATE_MAX_INSERT_PROFILE_ITERATIONS: usize = 100;

pub fn cache_gate_profile_ready_message(pid: u32) -> String {
    format!("PID {pid}\nREADY\n")
}

pub fn validate_cache_gate_profile_fds(ready_fd: i32, go_fd: i32) -> Result<(), &'static str> {
    if ready_fd == go_fd {
        Err("--ready-fd and --go-fd must be distinct")
    } else {
        Ok(())
    }
}

pub fn validate_cache_gate_profile_iterations(
    is_insert: bool,
    iterations: usize,
) -> Result<(), String> {
    if is_insert && iterations > CACHE_GATE_MAX_INSERT_PROFILE_ITERATIONS {
        Err(format!(
            "insert profiling supports at most {CACHE_GATE_MAX_INSERT_PROFILE_ITERATIONS} iterations"
        ))
    } else {
        Ok(())
    }
}

pub fn cache_gate_pairs() -> Vec<(u64, u64)> {
    make_pairs(CACHE_GATE_OP_COUNT)
}

pub fn elastic_cache_gate_map() -> ElasticHashMap<u64, u64> {
    ElasticHashMap::with_capacity_and_hasher(CACHE_GATE_OP_COUNT * 2, BenchHasher::default())
}

pub fn funnel_cache_gate_map() -> FunnelHashMap<u64, u64> {
    FunnelHashMap::with_capacity_and_hasher(CACHE_GATE_OP_COUNT * 2, BenchHasher::default())
}

pub fn validate_cache_gate_fill<S>(
    map: &mut opthash::ElasticHashMap<u64, u64, S>,
    pairs: &[(u64, u64)],
) where
    S: BuildHasher,
{
    let capacity = map.capacity();
    for &(key, value) in pairs {
        assert_eq!(map.insert(key, value), None);
    }
    assert_eq!(map.len(), pairs.len());
    assert_eq!(map.capacity(), capacity);
    for &(key, value) in pairs {
        assert_eq!(map.get(&key), Some(&value));
    }
}

pub fn validate_funnel_cache_gate_fill<S>(
    map: &mut opthash::FunnelHashMap<u64, u64, S>,
    pairs: &[(u64, u64)],
) where
    S: BuildHasher,
{
    let capacity = map.capacity();
    for &(key, value) in pairs {
        assert_eq!(map.insert(key, value), None);
    }
    assert_eq!(map.len(), pairs.len());
    assert_eq!(map.capacity(), capacity);
    for &(key, value) in pairs {
        assert_eq!(map.get(&key), Some(&value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_gate_fixture_is_fixed_and_distinct() {
        let pairs = cache_gate_pairs();
        assert_eq!(pairs.len(), CACHE_GATE_OP_COUNT);
        assert_eq!(pairs[0], (0, 0xA5A5_A5A5_A5A5_A5A5));
        assert_eq!(pairs[1].0, 0x9E37_79B9_7F4A_7C15);
        let mut keys = pairs.iter().map(|pair| pair.0).collect::<Vec<_>>();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), pairs.len());
    }

    #[test]
    fn cache_gate_preflight_requires_exact_fill_without_growth() {
        let pairs = cache_gate_pairs();
        let mut map = elastic_cache_gate_map();
        let capacity = map.capacity();
        validate_cache_gate_fill(&mut map, &pairs);
        assert_eq!(map.len(), CACHE_GATE_OP_COUNT);
        assert_eq!(map.capacity(), capacity);
    }

    #[test]
    fn funnel_cache_gate_preflight_requires_exact_fill_without_growth() {
        let pairs = cache_gate_pairs();
        let mut map = funnel_cache_gate_map();
        let capacity = map.capacity();
        validate_funnel_cache_gate_fill(&mut map, &pairs);
        assert_eq!(map.len(), CACHE_GATE_OP_COUNT);
        assert_eq!(map.capacity(), capacity);
    }

    #[test]
    fn cache_gate_profile_rejects_duplicate_descriptors() {
        assert!(validate_cache_gate_profile_fds(7, 7).is_err());
        assert!(validate_cache_gate_profile_fds(7, 8).is_ok());
    }

    #[test]
    fn cache_gate_profile_caps_preallocated_insert_maps() {
        assert!(validate_cache_gate_profile_iterations(true, 100).is_ok());
        assert!(validate_cache_gate_profile_iterations(true, 101).is_err());
        assert!(validate_cache_gate_profile_iterations(false, usize::MAX).is_ok());
    }

    #[test]
    fn cache_gate_profile_authenticates_exec_pid_before_ready() {
        assert_eq!(cache_gate_profile_ready_message(42), "PID 42\nREADY\n");
    }
}
