//! Untimed churn attribution. The ignored diagnostic uses the throughput key
//! trace, size and seed; counters never enter the Criterion binaries. Values
//! identify their keys so every observed result can be checked directly.

#[path = "../benches/harness/mod.rs"]
mod harness;

use std::cell::Cell;
use std::hash::{BuildHasher, Hash, Hasher};

use opthash::{EpochSnapshot, EpochTransition};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Counts {
    hashes: usize,
    comparisons: usize,
}

thread_local! {
    static COUNTS: Cell<Counts> = Cell::new(Counts::default());
}

#[derive(Clone, Copy, Debug, Eq)]
#[repr(transparent)]
struct Key(u64);

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        COUNTS.with(|cell| {
            let mut counts = cell.get();
            counts.comparisons += 1;
            cell.set(counts);
        });
        self.0 == other.0
    }
}

impl Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        COUNTS.with(|cell| {
            let mut counts = cell.get();
            counts.hashes += 1;
            cell.set(counts);
        });
        self.0.hash(state);
    }
}

fn counted<T>(operation: impl FnOnce() -> T) -> (T, Counts) {
    COUNTS.with(|cell| cell.set(Counts::default()));
    let result = operation();
    (result, COUNTS.with(Cell::get))
}

trait ChurnMap: Sized {
    fn with_capacity(capacity: usize) -> Self;
    fn insert(&mut self, key: Key, value: u64) -> Option<u64>;
    fn remove(&mut self, key: Key) -> Option<u64>;
    fn get(&self, key: Key) -> Option<&u64>;
    fn len(&self) -> usize;
    fn capacity(&self) -> usize;
    fn epoch(&self) -> EpochSnapshot;
}

macro_rules! churn_map {
    ($map:ident) => {
        impl ChurnMap for harness::$map<Key, u64> {
            fn with_capacity(capacity: usize) -> Self {
                Self::with_capacity_and_hasher(capacity, harness::BenchHasher::default())
            }
            fn insert(&mut self, key: Key, value: u64) -> Option<u64> {
                self.insert(key, value)
            }
            fn remove(&mut self, key: Key) -> Option<u64> {
                self.remove(&key)
            }
            fn get(&self, key: Key) -> Option<&u64> {
                self.get(&key)
            }
            fn len(&self) -> usize {
                self.len()
            }
            fn capacity(&self) -> usize {
                self.capacity()
            }
            fn epoch(&self) -> EpochSnapshot {
                self.epoch()
            }
        }
    };
}

churn_map!(ElasticHashMap);
churn_map!(FunnelHashMap);

#[derive(Debug, Default)]
struct Phase {
    operations: usize,
    comparisons: usize,
    cleanup: usize,
    growth: usize,
    recovery: usize,
    moved: usize,
    refreshes: usize,
    refresh_hashes: usize,
    max_maintenance_hashes: usize,
}

impl Phase {
    /// Each measured operation hashes its query once. A single epoch boundary
    /// reinserts every survivor; extra hashes without a boundary are a filter
    /// refresh. Assert that model instead of silently misattributing work if a
    /// future backend adds another source of hashing or multiple boundaries.
    fn record(
        &mut self,
        before: EpochSnapshot,
        after: EpochSnapshot,
        counts: Counts,
        survivors: usize,
    ) {
        self.operations += 1;
        self.comparisons += counts.comparisons;
        let maintenance_hashes = counts.hashes.checked_sub(1).expect("query hash");
        self.max_maintenance_hashes = self.max_maintenance_hashes.max(maintenance_hashes);
        if after.generation != before.generation {
            assert_eq!(after.generation, before.generation + 1);
            match after.transition {
                EpochTransition::TombstoneCleanup => self.cleanup += 1,
                EpochTransition::Growth => self.growth += 1,
                EpochTransition::PlacementRecovery => self.recovery += 1,
                reason => panic!("unexpected transition: {reason:?}"),
            }
            assert_eq!(maintenance_hashes, survivors);
            self.moved += maintenance_hashes;
        } else if maintenance_hashes != 0 {
            assert_eq!(maintenance_hashes, survivors);
            self.refreshes += 1;
            self.refresh_hashes += maintenance_hashes;
        }
    }
}

fn populate<M: ChurnMap>(capacity: usize, range: std::ops::Range<usize>) -> M {
    let mut map = M::with_capacity(capacity);
    for index in range {
        let key = harness::key_at(index);
        assert_eq!(map.insert(Key(key), key), None);
    }
    map
}

fn remove<M: ChurnMap>(map: &mut M, index: usize, phase: &mut Phase) {
    let before = map.epoch();
    let key = harness::key_at(index);
    let (removed, counts) = counted(|| map.remove(Key(key)));
    assert_eq!(removed, Some(key));
    phase.record(before, map.epoch(), counts, map.len());
}

fn insert<M: ChurnMap>(map: &mut M, index: usize, phase: &mut Phase) {
    let before = map.epoch();
    let survivors = map.len();
    let key = harness::key_at(index);
    let (replaced, counts) = counted(|| map.insert(Key(key), key));
    assert_eq!(replaced, None);
    phase.record(before, map.epoch(), counts, survivors);
}

fn queries<M: ChurnMap>(map: &M, range: std::ops::Range<usize>, hits: bool) -> Counts {
    let ((), counts) = counted(|| {
        for index in range {
            let key = harness::key_at(index);
            assert_eq!(map.get(Key(key)).copied(), hits.then_some(key));
        }
    });
    counts
}

fn diagnose<M: ChurnMap>(name: &str, size: usize, operations: usize) {
    let mut map = populate::<M>(size, 0..size);
    let capacity = map.capacity();
    let mut removes = Phase::default();
    let mut inserts = Phase::default();
    for index in 0..operations {
        remove(&mut map, index, &mut removes);
        insert(&mut map, index + size, &mut inserts);
    }
    assert_eq!(map.len(), size);
    assert_eq!(map.capacity(), capacity);
    println!("{name} delete_heavy remove {removes:?}");
    println!("{name} delete_heavy insert {inserts:?}");
    let clean = populate::<M>(size, operations..operations + size);
    assert_eq!(clean.capacity(), map.capacity());
    for (state, map) in [("steady", &map), ("clean_full", &clean)] {
        println!(
            "{name} {state} hit {:?}",
            queries(map, operations..operations + size, true)
        );
        println!(
            "{name} {state} departed {:?}",
            queries(map, 0..size.min(operations), false)
        );
        println!(
            "{name} {state} never_inserted {:?}",
            queries(
                map,
                harness::MISS_KEY_OFFSET..harness::MISS_KEY_OFFSET + size,
                false
            )
        );
    }

    let mut map = populate::<M>(size, 0..size);
    let keep = size * 2 / 5;
    let mut removes = Phase::default();
    for index in keep..size {
        remove(&mut map, index, &mut removes);
    }
    assert_eq!(map.len(), keep);
    assert_eq!(map.capacity(), capacity);
    println!("{name} remove_burst {removes:?}");
    let clean = populate::<M>(size, 0..keep);
    assert_eq!(clean.capacity(), map.capacity());
    for (state, map) in [("post_burst", &map), ("clean_sparse", &clean)] {
        println!("{name} {state} hit {:?}", queries(map, 0..keep, true));
        println!(
            "{name} {state} departed {:?}",
            queries(map, keep..size, false)
        );
        println!(
            "{name} {state} never_inserted {:?}",
            queries(
                map,
                harness::MISS_KEY_OFFSET..harness::MISS_KEY_OFFSET + size,
                false
            )
        );
    }
    let mut inserts = Phase::default();
    for index in keep..size {
        insert(&mut map, index, &mut inserts);
    }
    assert_eq!(map.len(), size);
    assert_eq!(map.capacity(), capacity);
    assert_eq!(queries(&map, 0..size, true).hashes, size);
    println!("{name} post_delete_insert {inserts:?}");
}

#[test]
fn counters_preserve_benchmark_hashes_and_count_actual_calls() {
    let hasher = harness::BenchHasher::default();
    let (hash, counts) = counted(|| hasher.hash_one(Key(17)));
    assert_eq!(hash, hasher.hash_one(17_u64));
    assert_eq!(
        counts,
        Counts {
            hashes: 1,
            comparisons: 0
        }
    );
    let (equal, counts) = counted(|| Key(17) == Key(19));
    assert!(!equal);
    assert_eq!(
        counts,
        Counts {
            hashes: 0,
            comparisons: 1
        }
    );
}

#[test]
fn churn_diagnostics_preserve_contents_and_capacity() {
    diagnose::<harness::ElasticHashMap<Key, u64>>("elastic", 896, 3_000);
    diagnose::<harness::FunnelHashMap<Key, u64>>("funnel", 896, 3_000);
}

#[test]
#[ignore = "full-size untimed diagnostic; run with --ignored --nocapture"]
fn deletion_churn_attribution() {
    diagnose::<harness::ElasticHashMap<Key, u64>>("elastic", harness::MAP_SIZE, harness::OP_COUNT);
    diagnose::<harness::FunnelHashMap<Key, u64>>("funnel", harness::MAP_SIZE, harness::OP_COUNT);
}
