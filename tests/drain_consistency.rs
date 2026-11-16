//! A removing iterator that is leaked, or unwound by a panicking `Drop`,
//! `Hash`, or predicate, must leave its map or set consistent: `len` matches
//! the entries iteration yields, every one of them is found, later operations
//! behave, and each value is dropped exactly once.

mod support;

use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
            use crate::support::{Deterministic, $TestMap as HashMap, $TestSet as HashSet};

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
