macro_rules! common_suite {
    ($mod_name:ident, $TestMap:ident, $Entry:ident) => {
        mod $mod_name {
            use std::collections::HashSet;
            use std::sync::Arc;
            use std::sync::atomic::{AtomicUsize, Ordering};

            use opthash::$Entry as Entry;
            use opthash::$TestMap as HashMap;

            #[test]
            fn entry_and_modify_runs_on_occupied() {
                let mut map: HashMap<i32, i32> = HashMap::new();
                map.insert(1, 10);
                let value = map.entry(1).and_modify(|v| *v += 5).or_insert(0);
                assert_eq!(*value, 15);
                assert_eq!(map.get(&1), Some(&15));
            }

            #[test]
            fn entry_and_modify_skips_on_vacant() {
                let mut map: HashMap<i32, i32> = HashMap::new();
                let mut touched = false;
                let value = map.entry(1).and_modify(|_| touched = true).or_insert(42);
                assert_eq!(*value, 42);
                assert!(!touched);
                assert_eq!(map.get(&1), Some(&42));
            }

            #[test]
            fn entry_occupied_get_mut_mutates() {
                let mut map: HashMap<i32, i32> = HashMap::new();
                map.insert(1, 10);
                if let Entry::Occupied(mut occ) = map.entry(1) {
                    *occ.get_mut() = 99;
                    assert_eq!(*occ.get(), 99);
                } else {
                    panic!("expected occupied");
                }
                assert_eq!(map.get(&1), Some(&99));
            }

            #[test]
            fn entry_occupied_insert_returns_old_and_replaces() {
                let mut map: HashMap<i32, i32> = HashMap::new();
                map.insert(1, 10);
                if let Entry::Occupied(mut occ) = map.entry(1) {
                    let old = occ.insert(99);
                    assert_eq!(old, 10);
                } else {
                    panic!("expected occupied");
                }
                assert_eq!(map.get(&1), Some(&99));
            }

            #[test]
            fn entry_occupied_into_mut_outlives_entry_borrow() {
                let mut map: HashMap<i32, i32> = HashMap::new();
                map.insert(1, 10);
                let value: &mut i32 = match map.entry(1) {
                    Entry::Occupied(occ) => occ.into_mut(),
                    Entry::Vacant(_) => panic!("expected occupied"),
                };
                *value = 123;
                assert_eq!(map.get(&1), Some(&123));
            }

            #[test]
            fn entry_occupied_remove_returns_value() {
                let mut map: HashMap<i32, i32> = HashMap::new();
                map.insert(1, 10);
                map.insert(2, 20);
                if let Entry::Occupied(occ) = map.entry(1) {
                    assert_eq!(occ.remove(), 10);
                } else {
                    panic!("expected occupied");
                }
                assert!(map.get(&1).is_none());
                assert_eq!(map.get(&2), Some(&20));
                assert_eq!(map.len(), 1);
            }

            #[test]
            fn entry_or_insert_creates_when_missing() {
                let mut map: HashMap<i32, i32> = HashMap::new();
                let value = map.entry(1).or_insert(10);
                assert_eq!(*value, 10);
                assert_eq!(map.get(&1), Some(&10));
                assert_eq!(map.len(), 1);
            }

            #[test]
            fn entry_or_insert_returns_existing() {
                let mut map: HashMap<i32, i32> = HashMap::new();
                map.insert(1, 10);
                let value = map.entry(1).or_insert(99);
                assert_eq!(*value, 10);
                assert_eq!(map.get(&1), Some(&10));
                assert_eq!(map.len(), 1);
            }

            #[test]
            fn entry_or_insert_with_key_uses_key_in_default() {
                let mut map: HashMap<i32, i32> = HashMap::new();
                let value = map.entry(7).or_insert_with_key(|k| k * 100);
                assert_eq!(*value, 700);
                assert_eq!(map.get(&7), Some(&700));
            }

            #[test]
            fn entry_or_insert_with_lazy_default_not_called_on_hit() {
                let mut map: HashMap<i32, i32> = HashMap::new();
                map.insert(1, 10);
                let mut called = false;
                let value = map.entry(1).or_insert_with(|| {
                    called = true;
                    42
                });
                assert_eq!(*value, 10);
                assert!(!called, "default closure must not run on occupied entry");
            }

            #[test]
            fn entry_vacant_insert_returns_mut_ref() {
                let mut map: HashMap<i32, i32> = HashMap::new();
                let value: &mut i32 = match map.entry(5) {
                    Entry::Vacant(vac) => vac.insert(50),
                    Entry::Occupied(_) => panic!("expected vacant"),
                };
                *value += 1;
                assert_eq!(map.get(&5), Some(&51));
            }

            #[test]
            fn get_disjoint_mut_mutation_propagates() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(32);
                for i in 0..8 {
                    map.insert(i, i);
                }
                {
                    let [a, b] = map.get_disjoint_mut([&2, &5]);
                    *a.unwrap() = 222;
                    *b.unwrap() = 555;
                }
                assert_eq!(map.get(&2), Some(&222));
                assert_eq!(map.get(&5), Some(&555));
            }

            #[test]
            fn get_disjoint_mut_zero_keys_returns_empty_array() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(16);
                map.insert(1, 1);
                let got = map.get_disjoint_mut::<i32, 0>([]);
                assert_eq!(got.len(), 0);
            }

            #[test]
            fn get_disjoint_unchecked_mut_returns_all_refs_on_hits() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(64);
                for i in 0..16 {
                    map.insert(i, i * 10);
                }
                // SAFETY: keys are distinct.
                let got = unsafe { map.get_disjoint_unchecked_mut([&1, &3, &7, &15]) };
                assert_eq!(
                    got,
                    [Some(&mut 10), Some(&mut 30), Some(&mut 70), Some(&mut 150)]
                );
            }

            #[test]
            fn get_disjoint_unchecked_mut_yields_none_per_missing_key() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(32);
                for i in 0..8 {
                    map.insert(i, i);
                }
                // SAFETY: keys are distinct (one misses → None at that slot).
                let got = unsafe { map.get_disjoint_unchecked_mut([&0, &1, &99]) };
                assert_eq!(got, [Some(&mut 0), Some(&mut 1), None]);
            }

            #[test]
            fn get_key_value_returns_both_on_hit_none_on_miss() {
                let mut map: HashMap<String, i32> = HashMap::with_capacity(16);
                map.insert("alpha".to_string(), 1);
                map.insert("beta".to_string(), 2);

                let (k, v) = map.get_key_value("alpha").expect("hit");
                assert_eq!(k, "alpha");
                assert_eq!(*v, 1);

                assert!(map.get_key_value("missing").is_none());
            }

            #[test]
            fn hasher_returns_consistent_handle() {
                let map: HashMap<i32, i32> = HashMap::new();
                let a: *const _ = map.hasher();
                let b: *const _ = map.hasher();
                assert!(std::ptr::eq(a, b));
            }

            #[test]
            fn insert_resizes_from_zero_capacity() {
                let mut map: HashMap<i32, i32> = HashMap::new();
                map.insert(1, 10);
                assert_eq!(map.get(&1), Some(&10));
                assert!(map.capacity() > 0);
            }

            #[test]
            #[cfg_attr(miri, ignore = "large-map stress test is too slow")]
            fn large_map_correctness() {
                let n = 10_000;
                let mut map = HashMap::with_capacity(n * 2);
                for i in 0..n {
                    assert_eq!(map.insert(i, i), None);
                }
                for i in 0..n {
                    assert_eq!(map.get(&i), Some(&i), "key {i} missing");
                }
                assert_eq!(map.len(), n);
            }

            #[test]
            fn retain_with_empty_map_is_noop() {
                let mut map: HashMap<i32, i32> = HashMap::new();
                let mut called = false;
                map.retain(|_, _| {
                    called = true;
                    true
                });
                assert!(!called);
                assert!(map.is_empty());
            }

            #[test]
            fn try_insert_fails_with_occupied_error_when_present() {
                let mut map: HashMap<i32, i32> = HashMap::new();
                map.insert(1, 10);
                let err = map.try_insert(1, 99).expect_err("occupied must error");
                assert_eq!(err.entry.key(), &1);
                assert_eq!(err.entry.get(), &10);
                assert_eq!(map.get(&1), Some(&10));
            }

            #[test]
            fn try_insert_occupied_error_carries_rejected_value() {
                let mut map: HashMap<i32, i32> = HashMap::new();
                map.insert(1, 10);
                let err = map.try_insert(1, 99).expect_err("occupied must error");
                assert_eq!(err.value, 99);
            }

            #[test]
            fn try_insert_succeeds_when_missing() {
                let mut map: HashMap<i32, i32> = HashMap::new();
                let value = map.try_insert(1, 10).expect("vacant should succeed");
                assert_eq!(*value, 10);
                assert_eq!(map.get(&1), Some(&10));
            }

            #[test]
            fn try_reserve_grows_when_needed() {
                let mut map: HashMap<i32, i32> = HashMap::new();
                assert_eq!(map.capacity(), 0);
                map.try_reserve(1024).expect("alloc should succeed");
                let cap = map.capacity();
                assert!(cap >= 1024, "reserve under-allocated: cap={cap}");
                for i in 0..1024 {
                    map.insert(i, i * 2);
                }
                for i in 0..1024 {
                    assert_eq!(map.get(&i), Some(&(i * 2)));
                }
                assert_eq!(map.len(), 1024);
            }

            #[test]
            fn drain_partial_consume_then_drop_still_empties_map() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(256);
                for i in 0..60 {
                    map.insert(i, i);
                }
                {
                    let mut drain = map.drain();
                    let _first = drain.next();
                    let _second = drain.next();
                    // Drop without exhausting; remainder must still be freed.
                }
                assert!(map.is_empty());
                assert_eq!(map.iter().count(), 0);
            }

            #[test]
            fn drain_yields_all_entries_then_empties_map() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(256);
                for i in 0..60 {
                    map.insert(i, i * 7);
                }
                let mut collected: Vec<(i32, i32)> = map.drain().collect();
                collected.sort_unstable();
                let expected: Vec<(i32, i32)> = (0..60).map(|i| (i, i * 7)).collect();
                assert_eq!(collected, expected);
                assert!(map.is_empty());
                assert_eq!(map.iter().count(), 0);
                map.insert(999, 999);
                assert_eq!(map.get(&999), Some(&999));
            }

            #[test]
            fn extract_if_partial_consume_then_drop_keeps_remaining_in_map() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(256);
                for i in 0..60 {
                    map.insert(i, i);
                }
                let original_len = map.len();
                let extracted_count;
                {
                    let mut it = map.extract_if(|_, _| true);
                    assert!(it.next().is_some());
                    assert!(it.next().is_some());
                    extracted_count = 2;
                }
                assert_eq!(map.len(), original_len - extracted_count);
                let remaining: Vec<i32> = map.iter().map(|(&k, _)| k).collect();
                assert_eq!(remaining.len(), original_len - extracted_count);
            }

            #[test]
            fn into_iter_partial_drop_drops_remaining() {
                struct DropCounter {
                    counter: Arc<AtomicUsize>,
                }
                impl Drop for DropCounter {
                    fn drop(&mut self) {
                        self.counter.fetch_add(1, Ordering::SeqCst);
                    }
                }

                let counter = Arc::new(AtomicUsize::new(0));
                let n: usize = 50;
                let mut map: HashMap<usize, DropCounter> = HashMap::with_capacity(128);
                for i in 0..n {
                    map.insert(
                        i,
                        DropCounter {
                            counter: Arc::clone(&counter),
                        },
                    );
                }
                let take = 12;
                let mut it = map.into_iter();
                let mut taken: Vec<(usize, DropCounter)> = Vec::with_capacity(take);
                for _ in 0..take {
                    taken.push(it.next().expect("element"));
                }
                drop(it);
                assert_eq!(counter.load(Ordering::SeqCst), n - take);
                drop(taken);
                assert_eq!(counter.load(Ordering::SeqCst), n);
            }

            #[test]
            fn into_iter_skips_tombstones() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(128);
                for i in 0..60 {
                    map.insert(i, i);
                }
                for i in (0..60).step_by(3) {
                    map.remove(&i);
                }
                let expected_len = map.len();
                let collected: Vec<(i32, i32)> = map.into_iter().collect();
                assert_eq!(collected.len(), expected_len);
            }

            #[test]
            fn into_iter_yields_all_entries() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(128);
                for i in 0..60 {
                    map.insert(i, i * 11);
                }
                let mut collected: Vec<(i32, i32)> = map.into_iter().collect();
                collected.sort_unstable();
                let expected: Vec<(i32, i32)> = (0..60).map(|i| (i, i * 11)).collect();
                assert_eq!(collected, expected);
            }

            #[test]
            fn into_keys_drops_values() {
                struct DropCounter {
                    counter: Arc<AtomicUsize>,
                }
                impl Drop for DropCounter {
                    fn drop(&mut self) {
                        self.counter.fetch_add(1, Ordering::SeqCst);
                    }
                }

                let counter = Arc::new(AtomicUsize::new(0));
                let n: usize = 32;
                let mut map: HashMap<usize, DropCounter> = HashMap::with_capacity(64);
                for i in 0..n {
                    map.insert(
                        i,
                        DropCounter {
                            counter: Arc::clone(&counter),
                        },
                    );
                }
                let keys: Vec<usize> = map.into_keys().collect();
                assert_eq!(keys.len(), n);
                assert_eq!(counter.load(Ordering::SeqCst), n);
            }

            #[test]
            fn into_values_drops_keys() {
                struct DropKey {
                    id: usize,
                    counter: Arc<AtomicUsize>,
                }
                impl std::hash::Hash for DropKey {
                    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                        self.id.hash(state);
                    }
                }
                impl PartialEq for DropKey {
                    fn eq(&self, other: &Self) -> bool {
                        self.id == other.id
                    }
                }
                impl Eq for DropKey {}
                impl Drop for DropKey {
                    fn drop(&mut self) {
                        self.counter.fetch_add(1, Ordering::SeqCst);
                    }
                }

                let counter = Arc::new(AtomicUsize::new(0));
                let n: usize = 32;
                let mut map: HashMap<DropKey, usize> = HashMap::with_capacity(64);
                for i in 0..n {
                    map.insert(
                        DropKey {
                            id: i,
                            counter: Arc::clone(&counter),
                        },
                        i,
                    );
                }
                let vals: Vec<usize> = map.into_values().collect();
                assert_eq!(vals.len(), n);
                assert_eq!(counter.load(Ordering::SeqCst), n);
            }

            #[test]
            fn iter_mut_partial_consume_then_drop() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(128);
                for i in 0..40 {
                    map.insert(i, i);
                }
                {
                    let mut it = map.iter_mut();
                    for _ in 0..7 {
                        if let Some((_, v)) = it.next() {
                            *v += 1000;
                        }
                    }
                }
                assert_eq!(map.len(), 40);
                for i in 0..40 {
                    assert!(map.get(&i).is_some(), "key {i} disappeared");
                }
            }

            #[test]
            fn iter_mut_skips_tombstones() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(64);
                for i in 0..40 {
                    map.insert(i, i);
                }
                for i in (0..40).step_by(2) {
                    map.remove(&i);
                }
                let count = map.iter_mut().count();
                assert_eq!(count, map.len());
            }

            #[test]
            fn iter_mut_yields_each_entry_exactly_once() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(128);
                for i in 0..80 {
                    map.insert(i, i * 3);
                }
                let mut collected: Vec<(i32, i32)> =
                    map.iter_mut().map(|(&k, v)| (k, *v)).collect();
                collected.sort_unstable();
                let expected: Vec<(i32, i32)> = (0..80).map(|i| (i, i * 3)).collect();
                assert_eq!(collected, expected);
            }

            #[test]
            fn iter_skips_tombstones_after_remove() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(64);
                for i in 0..40 {
                    map.insert(i, i);
                }
                for i in (0..40).step_by(3) {
                    map.remove(&i);
                }
                let keys: Vec<i32> = map.iter().map(|(&k, _)| k).collect();
                assert_eq!(keys.len(), map.len());
            }

            #[test]
            fn iter_yields_every_inserted_pair_once() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(128);
                for i in 0..80 {
                    map.insert(i, i * 7);
                }
                let mut collected: Vec<(i32, i32)> = map.iter().map(|(&k, &v)| (k, v)).collect();
                collected.sort_unstable();
                let expected: Vec<(i32, i32)> = (0..80).map(|i| (i, i * 7)).collect();
                assert_eq!(collected, expected);
            }

            #[test]
            fn keys_yields_inserted_keys_only() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(128);
                for i in 0..50 {
                    map.insert(i, i * 7);
                }
                let got: HashSet<i32> = map.keys().copied().collect();
                let expected: HashSet<i32> = (0..50).collect();
                assert_eq!(got, expected);
            }

            #[test]
            fn retain_can_mutate_values_in_place() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(256);
                for i in 0..40 {
                    map.insert(i, i);
                }
                map.retain(|k, v| {
                    *v += 100;
                    k % 2 == 0
                });
                assert_eq!(map.len(), 20);
                for i in (0..40).step_by(2) {
                    assert_eq!(map.get(&i), Some(&(i + 100)));
                }
            }

            #[test]
            fn shrink_then_insert_works() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(2048);
                for i in 0..400 {
                    map.insert(i, i * 3);
                }
                for i in 0..300 {
                    map.remove(&i);
                }
                map.shrink_to_fit();
                for i in 0..100 {
                    assert_eq!(map.insert(i, i * 5), None);
                }
                for i in 0..100 {
                    assert_eq!(map.get(&i), Some(&(i * 5)));
                }
                for i in 300..400 {
                    assert_eq!(map.get(&i), Some(&(i * 3)));
                }
            }

            #[test]
            fn shrink_to_above_capacity_is_noop() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(256);
                for i in 0..20 {
                    map.insert(i, i);
                }
                let cap = map.capacity();
                map.shrink_to(cap * 4);
                assert_eq!(map.capacity(), cap);
            }

            #[test]
            fn shrink_to_below_len_clamps_to_len() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(4096);
                for i in 0..200 {
                    map.insert(i, i);
                }
                let cap_before = map.capacity();
                map.shrink_to(0);
                let cap_after = map.capacity();
                assert!(cap_after < cap_before);
                assert!(cap_after >= map.len());
                for i in 0..200 {
                    assert_eq!(map.get(&i), Some(&i));
                }
            }

            #[test]
            #[cfg_attr(miri, ignore = "broad resize and drop workload is too slow")]
            fn shrink_to_fit_reduces_capacity_when_sparse() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(4096);
                for i in 0..2000 {
                    map.insert(i, i);
                }
                for i in 0..1800 {
                    map.remove(&i);
                }
                let cap_before = map.capacity();
                map.shrink_to_fit();
                assert!(map.capacity() < cap_before);
                for i in 1800..2000 {
                    assert_eq!(map.get(&i), Some(&i));
                }
            }

            #[test]
            fn try_reserve_zero_additional_is_noop() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(128);
                let cap_before = map.capacity();
                map.try_reserve(0).expect("noop");
                assert_eq!(map.capacity(), cap_before);
            }

            #[test]
            fn values_yields_inserted_values_only() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(128);
                for i in 0..50 {
                    map.insert(i, i * 7);
                }
                let got: HashSet<i32> = map.values().copied().collect();
                let expected: HashSet<i32> = (0..50).map(|i| i * 7).collect();
                assert_eq!(got, expected);
            }

            #[test]
            fn options_constructor_fits_requested_capacity() {
                // `capacity` arg is the insertion budget; the map allocates
                // at least enough slots so `capacity() >= requested`.
                let map: HashMap<i32, i32> = HashMap::with_capacity(320);
                assert!(map.capacity() >= 320);
            }

            #[test]
            fn insert_resizes_when_threshold_is_reached() {
                let mut map: HashMap<usize, usize> = HashMap::with_capacity(64);
                // `capacity()` returns max_insertions for the current allocation.
                let max_insertions = map.capacity();
                for key in 0..max_insertions + 10 {
                    assert_eq!(map.insert(key, key), None);
                }
                for key in 0..max_insertions + 10 {
                    assert_eq!(map.get(&key), Some(&key));
                }
                assert!(map.capacity() > max_insertions);
            }

            #[test]
            #[cfg_attr(miri, ignore = "broad delete and reinsert workload is too slow")]
            fn delete_heavy_preserves_correctness() {
                let n = if cfg!(miri) { 200 } else { 5_000 };
                let trials = if cfg!(miri) { 5 } else { 10 };
                let cutoff = (n * 4) / 5;
                for trial in 0..trials {
                    let mut map = HashMap::new();
                    for i in 0..n {
                        map.insert(i, i * 10);
                    }
                    for i in 0..cutoff {
                        assert_eq!(
                            map.remove(&i),
                            Some(i * 10),
                            "trial {trial}: missing key {i} during delete"
                        );
                    }
                    for i in cutoff..n {
                        assert_eq!(
                            map.get(&i),
                            Some(&(i * 10)),
                            "trial {trial}: key {i} missing after deletes"
                        );
                    }
                    assert_eq!(map.len(), usize::try_from(n - cutoff).unwrap());
                    for i in n..(n + n / 5) {
                        assert_eq!(map.insert(i, i), None);
                    }
                    for i in n..(n + n / 5) {
                        assert_eq!(
                            map.get(&i),
                            Some(&i),
                            "trial {trial}: key {i} missing after re-insert"
                        );
                    }
                }
            }

            #[test]
            fn clear_removes_all_entries_and_resets_map() {
                let mut map = HashMap::with_capacity(64);
                for key in 0..10 {
                    assert_eq!(map.insert(key, key * 10), None);
                }

                map.clear();
                assert!(map.is_empty());
                for key in 0..10 {
                    assert_eq!(map.get(&key), None);
                }

                assert_eq!(map.insert(99, 990), None);
                assert_eq!(map.get(&99), Some(&990));
            }

            #[test]
            fn interleaved_insert_delete_correctness() {
                let mut map = HashMap::with_capacity(256);
                // Insert 100, delete odd keys, verify even keys survive.
                for i in 0..100 {
                    map.insert(i, i);
                }
                for i in (1..100).step_by(2) {
                    assert!(map.remove(&i).is_some());
                }
                for i in (0..100).step_by(2) {
                    assert_eq!(map.get(&i), Some(&i), "even key {i} missing");
                }
                for i in (1..100).step_by(2) {
                    assert_eq!(map.get(&i), None, "odd key {i} should be gone");
                }
            }

            #[test]
            fn iter_mut_yields_mutable_values_in_some_order() {
                let mut map: HashMap<i32, i32> = HashMap::with_capacity(128);
                for i in 0..50 {
                    map.insert(i, i);
                }
                for (_, v) in &mut map {
                    *v *= 2;
                }
                for i in 0..50 {
                    assert_eq!(map.get(&i), Some(&(i * 2)), "key {i} not doubled");
                }
            }
        }
    };
}

common_suite!(elastic_common, ElasticHashMap, ElasticEntry);
common_suite!(funnel_common, FunnelHashMap, FunnelEntry);
