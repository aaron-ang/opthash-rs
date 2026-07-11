use std::hash::{BuildHasher, Hasher};

use opthash::{ElasticHashMap, ElasticHashSet, EpochTransition, FunnelHashMap, ReserveFraction};

#[derive(Clone, Copy, Default)]
struct ConstantBuildHasher;

struct ConstantHasher;

impl Hasher for ConstantHasher {
    fn finish(&self) -> u64 {
        0
    }

    fn write(&mut self, _bytes: &[u8]) {}
}

impl BuildHasher for ConstantBuildHasher {
    type Hasher = ConstantHasher;

    fn build_hasher(&self) -> Self::Hasher {
        ConstantHasher
    }
}

#[test]
fn compact_observability_exposes_epoch_and_reserve() {
    let elastic = ElasticHashMap::<usize, usize>::new();
    let funnel = FunnelHashMap::<usize, usize>::new();
    let set = ElasticHashSet::<usize>::new();

    assert_eq!(elastic.reserve_fraction(), ReserveFraction::DEFAULT);
    assert_eq!(funnel.reserve_fraction(), ReserveFraction::DEFAULT);
    assert_eq!(set.reserve_fraction(), ReserveFraction::DEFAULT);
    assert_eq!(elastic.epoch().generation, 0);
    assert_eq!(funnel.epoch().generation, 0);
    assert_eq!(set.epoch().generation, 0);
}

#[test]
fn duplicate_at_capacity_does_not_start_a_new_epoch() {
    macro_rules! check {
        ($map:expr) => {{
            let mut map = $map;
            let capacity = map.capacity();
            for key in 0..capacity {
                assert_eq!(map.insert(key, key), None);
            }
            let before = map.epoch();

            let duplicate = capacity / 2;
            assert_eq!(map.insert(duplicate, usize::MAX), Some(duplicate));
            assert_eq!(map.len(), capacity);
            assert_eq!(map.capacity(), capacity);
            assert_eq!(map.epoch(), before);
        }};
    }

    check!(ElasticHashMap::<usize, usize>::with_capacity(64));
    check!(FunnelHashMap::<usize, usize>::with_capacity(64));
}

#[test]
fn duplicate_set_insert_at_capacity_does_not_grow() {
    let mut set = ElasticHashSet::<usize>::with_capacity(64);
    let capacity = set.capacity();
    for key in 0..capacity {
        assert!(set.insert(key));
    }
    let before = set.epoch();

    assert!(!set.insert(0));
    assert_eq!(set.capacity(), capacity);
    assert_eq!(set.epoch(), before);
}

#[test]
fn first_absent_insert_beyond_capacity_grows_once() {
    let mut map = FunnelHashMap::<usize, usize>::with_capacity(64);
    let capacity = map.capacity();
    for key in 0..capacity {
        map.insert(key, key);
    }
    let before = map.epoch();

    map.insert(capacity, capacity);
    let after = map.epoch();
    assert!(map.capacity() > capacity);
    assert_eq!(after.generation, before.generation + 1);
    assert_eq!(after.transition, EpochTransition::Growth);
    for key in 0..=capacity {
        assert_eq!(map.get(&key), Some(&key));
    }
}

#[test]
fn ordinary_delete_marks_the_epoch_without_moving_to_a_new_one() {
    let mut map = ElasticHashMap::<usize, usize>::with_capacity(512);
    for key in 0..100 {
        map.insert(key, key);
    }
    let before = map.epoch();

    assert_eq!(map.remove(&0), Some(0));
    let after = map.epoch();
    assert_eq!(after.generation, before.generation);
    assert!(after.had_delete);
    assert_eq!(after.distinct_insertions, before.distinct_insertions);
    for key in 1..100 {
        assert_eq!(map.get(&key), Some(&key));
    }
}

#[test]
fn insert_after_a_full_epoch_reuses_space_without_an_eager_rebuild() {
    macro_rules! check {
        ($map:expr) => {{
            let mut map = $map;
            let capacity = map.capacity();
            for key in 0..capacity {
                map.insert(key, key);
            }
            assert_eq!(map.remove(&0), Some(0));
            let before = map.epoch();

            map.insert(capacity, capacity);
            let after = map.epoch();
            assert_eq!(map.capacity(), capacity);
            assert_eq!(after.generation, before.generation);
            assert!(after.had_delete);
            assert_eq!(after.distinct_insertions, before.distinct_insertions + 1);
            assert!(after.distinct_insertions > capacity);
            for key in 1..=capacity {
                assert_eq!(map.get(&key), Some(&key));
            }
        }};
    }

    check!(ElasticHashMap::<usize, usize>::with_capacity(64));
    check!(FunnelHashMap::<usize, usize>::with_capacity(64));
}

#[test]
fn tombstone_cleanup_is_an_observable_same_size_epoch_boundary() {
    let mut map = ElasticHashMap::<usize, usize>::with_capacity(512);
    let capacity = map.capacity();
    for key in 0..capacity {
        map.insert(key, key);
    }
    let before = map.epoch();

    let mut removed = 0;
    while map.epoch().generation == before.generation {
        assert_eq!(map.remove(&removed), Some(removed));
        removed += 1;
        assert!(
            removed < capacity,
            "cleanup must occur before the map empties"
        );
    }

    let after = map.epoch();
    assert_eq!(map.capacity(), capacity);
    assert_eq!(after.generation, before.generation + 1);
    assert_eq!(after.transition, EpochTransition::TombstoneCleanup);
    assert!(!after.had_delete);
    assert_eq!(after.distinct_insertions, map.len());
}

#[test]
fn bulk_removal_cleans_tombstones_after_iteration_finishes() {
    macro_rules! check {
        ($map:expr) => {{
            let mut map = $map;
            let capacity = map.capacity();
            for key in 0..capacity {
                map.insert(key, key);
            }
            let before = map.epoch();

            map.retain(|key, _| *key == capacity - 1);

            let after = map.epoch();
            assert_eq!(map.len(), 1);
            assert_eq!(map.get(&(capacity - 1)), Some(&(capacity - 1)));
            assert_eq!(map.capacity(), capacity);
            assert_eq!(after.generation, before.generation + 1);
            assert_eq!(after.transition, EpochTransition::TombstoneCleanup);
        }};
    }

    check!(ElasticHashMap::<usize, usize>::with_capacity(512));
    check!(FunnelHashMap::<usize, usize>::with_capacity(512));
}

#[test]
fn clear_starts_a_fresh_epoch_in_the_same_allocation() {
    let mut map = FunnelHashMap::<usize, usize>::with_capacity(64);
    map.insert(1, 1);
    let capacity = map.capacity();
    let before = map.epoch();

    map.clear();
    let after = map.epoch();
    assert_eq!(map.capacity(), capacity);
    assert_eq!(after.generation, before.generation + 1);
    assert_eq!(after.transition, EpochTransition::Clear);
    assert_eq!(after.distinct_insertions, 0);
    assert!(!after.had_delete);
}

#[test]
fn below_capacity_funnel_placement_recovery_is_observable() {
    const FOLLOW_UP_INSERTS: usize = 32;

    let mut map = FunnelHashMap::<usize, usize, ConstantBuildHasher>::with_capacity_and_hasher(
        1_024,
        ConstantBuildHasher,
    );
    let mut next_key = 0;
    let first_recovery = loop {
        assert!(next_key < map.capacity());
        let before = map.epoch();
        assert_eq!(map.insert(next_key, next_key), None);
        next_key += 1;
        let after = map.epoch();
        if after.placement_recoveries > before.placement_recoveries {
            assert_eq!(after.transition, EpochTransition::PlacementRecovery);
            assert_eq!(after.generation, before.generation + 1);
            break after;
        }
    };

    assert!(map.len() + FOLLOW_UP_INSERTS < map.capacity());
    for _ in 0..FOLLOW_UP_INSERTS {
        assert_eq!(map.insert(next_key, next_key), None);
        next_key += 1;
    }
    let after_follow_up = map.epoch();
    assert_eq!(
        after_follow_up.placement_recoveries,
        first_recovery.placement_recoveries + FOLLOW_UP_INSERTS as u64
    );
    assert_eq!(
        after_follow_up.generation,
        first_recovery.generation + FOLLOW_UP_INSERTS as u64
    );
    assert_eq!(
        after_follow_up.transition,
        EpochTransition::PlacementRecovery
    );

    for key in 0..next_key {
        assert_eq!(map.get(&key), Some(&key));
    }

    let recovered_key = next_key - 1;
    let before_replacement = map.epoch();
    assert_eq!(map.insert(recovered_key, usize::MAX), Some(recovered_key));
    assert_eq!(map.epoch(), before_replacement);

    assert_eq!(map.remove(&recovered_key), Some(usize::MAX));
    assert!(map.epoch().had_delete);

    let mut rebuilt = map.clone();
    assert_eq!(rebuilt.epoch(), map.epoch());
    for key in 0..recovered_key {
        assert_eq!(rebuilt.get(&key), Some(&key));
    }

    let before_reserve = rebuilt.epoch();
    let old_capacity = rebuilt.capacity();
    let additional = old_capacity - rebuilt.len() + 1;
    rebuilt.reserve(additional);
    let after_reserve = rebuilt.epoch();
    assert!(rebuilt.capacity() > old_capacity);
    assert_eq!(after_reserve.generation, before_reserve.generation + 1);
    assert_eq!(after_reserve.transition, EpochTransition::ExplicitResize);
    assert!(after_reserve.placement_recoveries > before_reserve.placement_recoveries);
    assert!(!after_reserve.had_delete);

    let before_shrink = rebuilt.epoch();
    let old_capacity = rebuilt.capacity();
    rebuilt.shrink_to_fit();
    let after_shrink = rebuilt.epoch();
    assert!(rebuilt.capacity() < old_capacity);
    assert_eq!(after_shrink.generation, before_shrink.generation + 1);
    assert_eq!(after_shrink.transition, EpochTransition::ExplicitResize);
    assert!(after_shrink.placement_recoveries > before_shrink.placement_recoveries);

    for key in 0..recovered_key {
        assert_eq!(rebuilt.get(&key), Some(&key));
    }
}
