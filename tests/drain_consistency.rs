//! A removing iterator that is leaked, or unwound by a panicking `Drop`,
//! `Hash`, or predicate, must leave its map or set consistent: `len` matches
//! the entries iteration yields, every one of them is found, later operations
//! behave, and each value is dropped at most once.
//!
//! `drain` follows `std`: the map is empty from the moment it is called, the
//! iterator owns the entries, and dropping it hands the allocation back. A
//! leaked drain leaks what it had not yielded.

mod support;

use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use allocator_api2::alloc::{AllocError, Allocator, Global, Layout};
use opthash::ReserveFraction;

/// Shared record of every [`Tracked`] made and dropped, plus the switches
/// that make the next drop or hash panic.
#[derive(Default)]
struct Ledger {
    made: AtomicUsize,
    dropped: AtomicUsize,
    drop_bomb: AtomicBool,
    hash_bomb: AtomicBool,
}

impl Ledger {
    fn live(&self) -> usize {
        self.made.load(Ordering::SeqCst) - self.dropped.load(Ordering::SeqCst)
    }

    /// Stops counting `leaked` values that will never be dropped.
    fn write_off(&self, leaked: usize) {
        self.dropped.fetch_add(leaked, Ordering::SeqCst);
    }
}

/// Map value and set element. Counts its construction and drop; panics in
/// the first drop after `drop_bomb` is set, and in every hash while
/// `hash_bomb` is set.
struct Tracked {
    id: u64,
    ledger: Arc<Ledger>,
}

impl Tracked {
    fn new(id: u64, ledger: &Arc<Ledger>) -> Self {
        ledger.made.fetch_add(1, Ordering::SeqCst);
        Self {
            id,
            ledger: Arc::clone(ledger),
        }
    }
}

impl Drop for Tracked {
    fn drop(&mut self) {
        self.ledger.dropped.fetch_add(1, Ordering::SeqCst);
        assert!(
            !self.ledger.drop_bomb.swap(false, Ordering::SeqCst),
            "armed drop"
        );
    }
}

impl PartialEq for Tracked {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Tracked {}

impl Hash for Tracked {
    fn hash<H: Hasher>(&self, state: &mut H) {
        assert!(!self.ledger.hash_bomb.load(Ordering::SeqCst), "armed hash");
        state.write_u64(self.id);
    }
}

/// Counts the blocks it hands out and takes back; storage comes from
/// [`Global`].
#[derive(Clone, Default)]
struct CountingAlloc {
    allocated: Arc<AtomicUsize>,
    freed: Arc<AtomicUsize>,
}

impl CountingAlloc {
    fn allocated(&self) -> usize {
        self.allocated.load(Ordering::SeqCst)
    }

    fn freed(&self) -> usize {
        self.freed.load(Ordering::SeqCst)
    }
}

// SAFETY: forwards to `Global`, so blocks stay valid across clones and moves;
// the counters only observe.
unsafe impl Allocator for CountingAlloc {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let block = Global.allocate(layout)?;
        self.allocated.fetch_add(1, Ordering::SeqCst);
        Ok(block)
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        self.freed.fetch_add(1, Ordering::SeqCst);
        // SAFETY: `ptr` came from `allocate`, i.e. `Global`, with `layout`.
        unsafe { Global.deallocate(ptr, layout) };
    }
}

/// Initial entries, keyed by `INITIAL`.
const ENTRIES: usize = 200;
const INITIAL: std::ops::Range<u64> = 0..200;
/// Keys the model workload adds; disjoint from `INITIAL`.
const FRESH: std::ops::Range<u64> = 1_000..1_400;

macro_rules! drain_consistency_suite {
    ($mod_name:ident, $TestMap:ident, $TestSet:ident) => {
        mod $mod_name {
            use std::collections::BTreeSet;
            use std::mem;
            use std::panic::{AssertUnwindSafe, catch_unwind};

            use super::*;
            use crate::support::{
                Deterministic, FixedHashBuilder, fixed_hasher, $TestMap as HashMap,
                $TestSet as HashSet,
            };

            type AllocMap = opthash::$TestMap<u64, u64, FixedHashBuilder, CountingAlloc>;

            fn full_alloc_map(alloc: &CountingAlloc) -> AllocMap {
                let mut map = AllocMap::with_capacity_and_reserve_and_hasher_in(
                    ENTRIES,
                    ReserveFraction::DEFAULT,
                    fixed_hasher(),
                    alloc.clone(),
                );
                for id in INITIAL {
                    assert!(map.insert(id, id).is_none());
                }
                map
            }

            /// Checks `map` holds nothing: no key of `INITIAL` is found and
            /// iteration yields no entry.
            fn assert_empty(map: &HashMap<u64, Tracked>) {
                assert_eq!(map.len(), 0);
                assert!(map.is_empty());
                assert_eq!(map.iter().len(), 0);
                assert!(map.iter().next().is_none());
                for key in INITIAL {
                    assert!(!map.contains_key(&key));
                    assert!(map.get(&key).is_none());
                }
            }

            fn full_map(ledger: &Arc<Ledger>) -> HashMap<u64, Tracked> {
                let mut map = HashMap::with_capacity(ENTRIES);
                for id in INITIAL {
                    assert!(map.insert(id, Tracked::new(id, ledger)).is_none());
                }
                map
            }

            fn full_set(ledger: &Arc<Ledger>) -> HashSet<Tracked> {
                let mut set = HashSet::with_capacity(ENTRIES);
                for id in INITIAL {
                    assert!(set.insert(Tracked::new(id, ledger)));
                }
                set
            }

            /// Checks `map` holds exactly `survivors` entries, all counted,
            /// iterable, and found; then runs inserts, removes, and lookups
            /// against a `BTreeMap` model and checks every value drops once.
            fn assert_consistent_and_usable(
                mut map: HashMap<u64, Tracked>,
                survivors: usize,
                ledger: &Arc<Ledger>,
            ) {
                assert_eq!(map.len(), survivors);
                assert_eq!(map.iter().count(), survivors);
                assert_eq!(map.iter().len(), survivors);
                assert_eq!(map.is_empty(), survivors == 0);
                assert_eq!(ledger.live(), survivors);

                let mut model: BTreeMap<u64, u64> =
                    map.iter().map(|(&key, value)| (key, value.id)).collect();
                assert_eq!(model.len(), survivors);
                for (key, id) in &model {
                    assert_eq!(key, id);
                    assert_eq!(map.get(key).map(|value| value.id), Some(*id));
                }
                for key in INITIAL {
                    assert_eq!(map.contains_key(&key), model.contains_key(&key));
                }

                for key in FRESH {
                    let old = map.insert(key, Tracked::new(key, ledger));
                    assert_eq!(old.map(|value| value.id), model.insert(key, key));
                    if key % 3 == 0 {
                        let victim = key / 3 % INITIAL.end;
                        assert_eq!(
                            map.remove(&victim).map(|value| value.id),
                            model.remove(&victim)
                        );
                    }
                    if key % 5 == 0 {
                        let victim = key - 4;
                        assert_eq!(
                            map.remove(&victim).map(|value| value.id),
                            model.remove(&victim)
                        );
                    }
                    assert_eq!(map.len(), model.len());
                }

                assert_eq!(map.iter().count(), model.len());
                let seen: BTreeMap<u64, u64> =
                    map.iter().map(|(&key, value)| (key, value.id)).collect();
                assert_eq!(seen, model);
                for key in INITIAL.chain(FRESH) {
                    assert_eq!(
                        map.get(&key).map(|value| value.id),
                        model.get(&key).copied()
                    );
                }
                assert_eq!(ledger.live(), model.len());

                drop(map);
                assert_eq!(ledger.live(), 0);
            }

            /// Set counterpart of [`assert_consistent_and_usable`].
            fn assert_set_consistent_and_usable(
                mut set: HashSet<Tracked>,
                survivors: usize,
                ledger: &Arc<Ledger>,
            ) {
                let probe = |id| Tracked::new(id, ledger);
                assert_eq!(set.len(), survivors);
                assert_eq!(set.iter().count(), survivors);
                assert_eq!(set.is_empty(), survivors == 0);
                assert_eq!(ledger.live(), survivors);

                let mut model: BTreeSet<u64> = set.iter().map(|value| value.id).collect();
                assert_eq!(model.len(), survivors);
                for id in INITIAL {
                    assert_eq!(set.contains(&probe(id)), model.contains(&id));
                }

                for id in FRESH {
                    assert_eq!(set.insert(probe(id)), model.insert(id));
                    if id % 3 == 0 {
                        let victim = id / 3 % INITIAL.end;
                        assert_eq!(set.remove(&probe(victim)), model.remove(&victim));
                    }
                    assert_eq!(set.len(), model.len());
                }

                let seen: BTreeSet<u64> = set.iter().map(|value| value.id).collect();
                assert_eq!(seen, model);
                for id in INITIAL.chain(FRESH) {
                    assert_eq!(set.contains(&probe(id)), model.contains(&id));
                }
                assert_eq!(ledger.live(), model.len());

                drop(set);
                assert_eq!(ledger.live(), 0);
            }

            #[test]
            #[cfg_attr(miri, ignore = "leaks the drained entries by design")]
            fn forgotten_drain_leaves_the_map_empty_and_usable() {
                for taken in [0, 5, ENTRIES] {
                    let ledger = Arc::new(Ledger::default());
                    let mut map = full_map(&ledger);
                    let mut drain = map.drain();
                    for _ in 0..taken {
                        assert!(drain.next().is_some());
                    }
                    assert_eq!(drain.len(), ENTRIES - taken);
                    mem::forget(drain);

                    assert_empty(&map);
                    assert_eq!(map.capacity(), 0);
                    assert_eq!(ledger.live(), ENTRIES - taken);
                    ledger.write_off(ENTRIES - taken);
                    assert_consistent_and_usable(map, 0, &ledger);
                }
            }

            #[test]
            fn dropped_drain_keeps_the_capacity() {
                for taken in [0, 5, ENTRIES] {
                    let ledger = Arc::new(Ledger::default());
                    let mut map = full_map(&ledger);
                    let capacity = map.capacity();
                    let mut drain = map.drain();
                    for _ in 0..taken {
                        assert!(drain.next().is_some());
                    }
                    drop(drain);

                    assert_empty(&map);
                    assert_eq!(map.capacity(), capacity);
                    assert_consistent_and_usable(map, 0, &ledger);
                }
            }

            #[test]
            fn consumed_drain_keeps_the_capacity_and_drops_each_value_once() {
                let ledger = Arc::new(Ledger::default());
                let mut map = full_map(&ledger);
                let capacity = map.capacity();
                let mut drain = map.drain();
                let taken = drain.by_ref().collect::<Vec<_>>();
                assert_eq!(taken.len(), ENTRIES);
                drop(drain);

                assert_eq!(ledger.live(), ENTRIES);
                assert_empty(&map);
                assert_eq!(map.capacity(), capacity);
                drop(taken);
                assert_eq!(ledger.live(), 0);
                assert_consistent_and_usable(map, 0, &ledger);
            }

            #[test]
            fn refilled_map_drains_again_in_the_same_allocation() {
                let ledger = Arc::new(Ledger::default());
                let mut map = full_map(&ledger);
                let capacity = map.capacity();
                for _ in 0..3 {
                    let drained: BTreeSet<u64> = map.drain().map(|(key, _)| key).collect();
                    assert!(drained.into_iter().eq(INITIAL));
                    assert_empty(&map);
                    assert_eq!(ledger.live(), 0);
                    for id in INITIAL {
                        assert!(map.insert(id, Tracked::new(id, &ledger)).is_none());
                    }
                    assert_eq!(map.capacity(), capacity);
                }
                assert_consistent_and_usable(map, ENTRIES, &ledger);
            }

            #[test]
            fn value_drop_panic_while_dropping_a_drain_empties_the_map() {
                for taken in [0, 5] {
                    let ledger = Arc::new(Ledger::default());
                    let mut map = full_map(&ledger);
                    let capacity = map.capacity();
                    let mut drain = map.drain();
                    for _ in 0..taken {
                        assert!(drain.next().is_some());
                    }
                    ledger.drop_bomb.store(true, Ordering::SeqCst);
                    assert!(catch_unwind(AssertUnwindSafe(|| drop(drain))).is_err());

                    assert_empty(&map);
                    assert_eq!(map.capacity(), capacity);
                    assert_consistent_and_usable(map, 0, &ledger);
                }
            }

            #[test]
            fn panic_in_a_drain_loop_body_empties_the_map() {
                let ledger = Arc::new(Ledger::default());
                let mut map = full_map(&ledger);
                let capacity = map.capacity();
                let result = catch_unwind(AssertUnwindSafe(|| {
                    for (taken, _entry) in map.drain().enumerate() {
                        assert!(taken < 5, "loop body");
                    }
                }));
                assert!(result.is_err());
                assert_empty(&map);
                assert_eq!(map.capacity(), capacity);
                assert_consistent_and_usable(map, 0, &ledger);
            }

            /// Leaves `full_map` with `ENTRIES - removed` entries. Both ends
            /// of the range matter: Funnel scans a full table and a mostly
            /// empty one differently.
            fn map_without_the_first(removed: u64, ledger: &Arc<Ledger>) -> HashMap<u64, Tracked> {
                let mut map = full_map(ledger);
                for id in 0..removed {
                    assert!(map.remove(&id).is_some());
                }
                map
            }

            #[test]
            fn folded_drain_yields_every_remaining_entry_once() {
                for removed in [0, 180] {
                    for taken in [0, 5] {
                        let ledger = Arc::new(Ledger::default());
                        let mut map = map_without_the_first(removed, &ledger);
                        let capacity = map.capacity();
                        let mut drain = map.drain();
                        let first = drain
                            .by_ref()
                            .take(taken)
                            .map(|(key, _)| key)
                            .collect::<Vec<_>>();
                        let mut seen = drain.fold(first, |mut seen, (key, value)| {
                            assert_eq!(key, value.id);
                            seen.push(key);
                            seen
                        });

                        seen.sort_unstable();
                        assert_eq!(seen, (removed..INITIAL.end).collect::<Vec<_>>());
                        assert_empty(&map);
                        assert_eq!(map.capacity(), capacity);
                        assert_consistent_and_usable(map, 0, &ledger);
                    }
                }
            }

            #[test]
            fn panic_in_a_drain_fold_empties_the_map() {
                for removed in [0, 180] {
                    let ledger = Arc::new(Ledger::default());
                    let mut map = map_without_the_first(removed, &ledger);
                    let capacity = map.capacity();
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        map.drain().fold(0, |taken, _entry| {
                            assert!(taken < 5, "fold body");
                            taken + 1
                        })
                    }));
                    assert!(result.is_err());
                    assert_empty(&map);
                    assert_eq!(map.capacity(), capacity);
                    assert_consistent_and_usable(map, 0, &ledger);
                }
            }

            #[test]
            fn drain_allocates_nothing_and_returns_the_allocation() {
                let alloc = CountingAlloc::default();
                let mut map = full_alloc_map(&alloc);
                let capacity = map.capacity();
                let (allocated, freed) = (alloc.allocated(), alloc.freed());

                for taken in [0, 5, ENTRIES] {
                    let mut drain = map.drain();
                    assert_eq!(drain.by_ref().take(taken).count(), taken);
                    drop(drain);
                    assert!(map.is_empty());
                    assert_eq!(map.capacity(), capacity);
                    assert_eq!((alloc.allocated(), alloc.freed()), (allocated, freed));
                    for id in INITIAL {
                        assert!(map.insert(id, id).is_none());
                    }
                    assert_eq!((alloc.allocated(), alloc.freed()), (allocated, freed));
                }

                drop(map);
                assert_eq!(alloc.allocated(), alloc.freed());
            }

            #[test]
            #[cfg_attr(miri, ignore = "leaks the drained allocation by design")]
            fn forgotten_drain_leaks_the_allocation_and_the_map_allocates_anew() {
                let alloc = CountingAlloc::default();
                let mut map = full_alloc_map(&alloc);
                let (allocated, freed) = (alloc.allocated(), alloc.freed());

                mem::forget(map.drain());
                assert!(map.is_empty());
                assert_eq!(map.capacity(), 0);
                assert_eq!((alloc.allocated(), alloc.freed()), (allocated, freed));

                let mut model = BTreeMap::new();
                for id in FRESH {
                    assert_eq!(map.insert(id, id), model.insert(id, id));
                }
                assert!(alloc.allocated() > allocated);
                assert_eq!(map.len(), model.len());
                for (key, value) in &model {
                    assert_eq!(map.get(key), Some(value));
                }

                drop(map);
                assert_eq!(alloc.allocated(), alloc.freed() + 1);
            }

            #[test]
            #[cfg_attr(miri, ignore = "leaks the drained values by design")]
            fn forgotten_set_drain_leaves_the_set_empty_and_usable() {
                for taken in [0, 5, ENTRIES] {
                    let ledger = Arc::new(Ledger::default());
                    let mut set = full_set(&ledger);
                    let mut drain = set.drain();
                    for _ in 0..taken {
                        assert!(drain.next().is_some());
                    }
                    mem::forget(drain);

                    assert!(set.is_empty());
                    assert_eq!(set.capacity(), 0);
                    assert_eq!(ledger.live(), ENTRIES - taken);
                    ledger.write_off(ENTRIES - taken);
                    assert_set_consistent_and_usable(set, 0, &ledger);
                }
            }

            #[test]
            fn dropped_set_drain_keeps_the_capacity() {
                for taken in [0, 5, ENTRIES] {
                    let ledger = Arc::new(Ledger::default());
                    let mut set = full_set(&ledger);
                    let capacity = set.capacity();
                    let mut drain = set.drain();
                    for _ in 0..taken {
                        assert!(drain.next().is_some());
                    }
                    drop(drain);

                    assert_eq!(set.capacity(), capacity);
                    assert_set_consistent_and_usable(set, 0, &ledger);
                }
            }

            /// Set counterpart of [`map_without_the_first`].
            fn set_without_the_first(removed: u64, ledger: &Arc<Ledger>) -> HashSet<Tracked> {
                let mut set = full_set(ledger);
                for id in 0..removed {
                    assert!(set.remove(&Tracked::new(id, ledger)));
                }
                set
            }

            #[test]
            fn folded_set_drain_yields_every_remaining_value_once() {
                for removed in [0, 180] {
                    for taken in [0, 5] {
                        let ledger = Arc::new(Ledger::default());
                        let mut set = set_without_the_first(removed, &ledger);
                        let capacity = set.capacity();
                        let mut drain = set.drain();
                        let first = drain
                            .by_ref()
                            .take(taken)
                            .map(|value| value.id)
                            .collect::<Vec<_>>();
                        let mut seen = drain.fold(first, |mut seen, value| {
                            seen.push(value.id);
                            seen
                        });

                        seen.sort_unstable();
                        assert_eq!(seen, (removed..INITIAL.end).collect::<Vec<_>>());
                        assert_eq!(set.capacity(), capacity);
                        assert_set_consistent_and_usable(set, 0, &ledger);
                    }
                }
            }

            #[test]
            fn panic_in_a_set_drain_fold_empties_the_set() {
                for removed in [0, 180] {
                    let ledger = Arc::new(Ledger::default());
                    let mut set = set_without_the_first(removed, &ledger);
                    let capacity = set.capacity();
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        set.drain().fold(0, |taken, _value| {
                            assert!(taken < 5, "fold body");
                            taken + 1
                        })
                    }));
                    assert!(result.is_err());
                    assert_eq!(set.capacity(), capacity);
                    assert_set_consistent_and_usable(set, 0, &ledger);
                }
            }

            #[test]
            fn value_drop_panic_while_dropping_a_set_drain_empties_the_set() {
                let ledger = Arc::new(Ledger::default());
                let mut set = full_set(&ledger);
                let capacity = set.capacity();
                let mut drain = set.drain();
                for _ in 0..5 {
                    assert!(drain.next().is_some());
                }
                ledger.drop_bomb.store(true, Ordering::SeqCst);
                assert!(catch_unwind(AssertUnwindSafe(|| drop(drain))).is_err());

                assert_eq!(set.capacity(), capacity);
                assert_set_consistent_and_usable(set, 0, &ledger);
            }

            #[test]
            fn forgotten_extract_if_keeps_the_entries_it_did_not_yield() {
                for taken in [0, 5, ENTRIES] {
                    let ledger = Arc::new(Ledger::default());
                    let mut map = full_map(&ledger);
                    let mut extract = map.extract_if(|_, _| true);
                    for _ in 0..taken {
                        assert!(extract.next().is_some());
                    }
                    mem::forget(extract);
                    assert_consistent_and_usable(map, ENTRIES - taken, &ledger);
                }
            }

            #[test]
            fn predicate_panic_in_retain_keeps_the_entries_not_yet_removed() {
                let ledger = Arc::new(Ledger::default());
                let mut map = full_map(&ledger);
                let mut visited = 0;
                let result = catch_unwind(AssertUnwindSafe(|| {
                    map.retain(|_, _| {
                        visited += 1;
                        assert!(visited <= 150, "predicate");
                        false
                    });
                }));
                assert!(result.is_err());
                assert_consistent_and_usable(map, ENTRIES - 150, &ledger);
            }

            #[test]
            fn value_drop_panic_in_retain_keeps_the_entries_not_yet_removed() {
                let ledger = Arc::new(Ledger::default());
                let mut map = full_map(&ledger);
                let mut visited = 0;
                let result = catch_unwind(AssertUnwindSafe(|| {
                    map.retain(|_, _| {
                        visited += 1;
                        if visited == 150 {
                            ledger.drop_bomb.store(true, Ordering::SeqCst);
                        }
                        false
                    });
                }));
                assert!(result.is_err());
                assert_consistent_and_usable(map, ENTRIES - 150, &ledger);
            }

            #[test]
            fn extract_if_resumes_after_a_caught_predicate_panic() {
                let ledger = Arc::new(Ledger::default());
                let mut map = full_map(&ledger);
                let mut visited = 0;
                let mut extract = map.extract_if(|_, _| {
                    visited += 1;
                    assert!(visited != 6, "predicate");
                    true
                });
                for _ in 0..5 {
                    assert!(extract.next().is_some());
                }
                assert!(catch_unwind(AssertUnwindSafe(|| extract.next())).is_err());
                assert_eq!(extract.by_ref().count(), ENTRIES - 6);
                assert!(extract.next().is_none());
                drop(extract);
                assert_consistent_and_usable(map, 1, &ledger);
            }

            /// Removing most of a set and then unwinding out of the predicate
            /// must not hash the survivors: their `Hash` panics here, and a
            /// second panic during the unwind would abort the process.
            #[test]
            fn predicate_panic_in_set_extract_if_does_not_hash_during_unwind() {
                let ledger = Arc::new(Ledger::default());
                let mut set = full_set(&ledger);
                let mut visited = 0;
                let result = catch_unwind(AssertUnwindSafe(|| {
                    set.extract_if(|_| {
                        visited += 1;
                        if visited > 190 {
                            ledger.hash_bomb.store(true, Ordering::SeqCst);
                            panic!("predicate");
                        }
                        true
                    })
                    .for_each(drop);
                }));
                assert!(result.is_err());
                ledger.hash_bomb.store(false, Ordering::SeqCst);
                assert_set_consistent_and_usable(set, ENTRIES - 190, &ledger);
            }

            #[test]
            fn value_drop_panic_in_clear_keeps_the_rest() {
                let ledger = Arc::new(Ledger::default());
                let mut map = full_map(&ledger);
                ledger.drop_bomb.store(true, Ordering::SeqCst);
                assert!(catch_unwind(AssertUnwindSafe(|| map.clear())).is_err());
                assert_consistent_and_usable(map, ENTRIES - 1, &ledger);
            }

            #[test]
            fn value_drop_panic_while_dropping_into_iter_drops_the_rest() {
                let ledger = Arc::new(Ledger::default());
                let mut iter = full_map(&ledger).into_iter();
                for _ in 0..5 {
                    assert!(iter.next().is_some());
                }
                ledger.drop_bomb.store(true, Ordering::SeqCst);
                assert!(catch_unwind(AssertUnwindSafe(|| drop(iter))).is_err());
                assert_eq!(ledger.live(), 0);
            }

            #[test]
            fn value_drop_panic_in_into_keys_drops_the_rest() {
                let ledger = Arc::new(Ledger::default());
                let mut keys = full_map(&ledger).into_keys();
                assert!(keys.next().is_some());
                ledger.drop_bomb.store(true, Ordering::SeqCst);
                assert!(catch_unwind(AssertUnwindSafe(|| keys.next())).is_err());
                assert_eq!(keys.len(), ENTRIES - 2);
                assert_eq!(keys.by_ref().count(), ENTRIES - 2);
                drop(keys);
                assert_eq!(ledger.live(), 0);
            }
        }
    };
}

drain_consistency_suite!(elastic, ElasticHashMap, ElasticHashSet);
drain_consistency_suite!(funnel, FunnelHashMap, FunnelHashSet);
