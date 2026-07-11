#![cfg_attr(feature = "nightly", feature(allocator_api))]

//! Parity tests against `hashbrown::HashMap`, ported from
//! `hashbrown-0.17/src/map.rs::test_map` and run via macro against both maps.
//!
//! Tests requiring APIs opthash lacks (`EntryRef`, `raw_entry`,
//! `raw_capacity`, `insert_unique_unchecked`, `replace_entry_with`) are omitted.

macro_rules! parity_suite {
    ($mod_name:ident, $TestMap:ident, $Entry:ident) => {
        mod $mod_name {
            #![allow(
                clippy::cognitive_complexity,
                clippy::needless_range_loop,
                clippy::should_panic_without_expect,
                clippy::items_after_statements
            )]

            use core::cell::RefCell;
            use opthash::$Entry as Entry;
            use opthash::{DefaultHashBuilder, $TestMap as HashMap};

            thread_local! {
                static DROP_VECTOR: RefCell<Vec<i32>> = const { RefCell::new(Vec::new()) };
            }

            #[derive(Hash, PartialEq, Eq)]
            struct Droppable {
                k: usize,
            }

            impl Droppable {
                fn new(k: usize) -> Droppable {
                    DROP_VECTOR.with(|slot| {
                        slot.borrow_mut()[k] += 1;
                    });
                    Droppable { k }
                }
            }

            impl Drop for Droppable {
                fn drop(&mut self) {
                    DROP_VECTOR.with(|slot| {
                        slot.borrow_mut()[self.k] -= 1;
                    });
                }
            }

            impl Clone for Droppable {
                fn clone(&self) -> Self {
                    Droppable::new(self.k)
                }
            }

            #[test]
            fn test_zero_capacities() {
                type HM = HashMap<i32, i32>;

                let m = HM::new();
                assert_eq!(m.capacity(), 0);

                let m = HM::default();
                assert_eq!(m.capacity(), 0);

                let m = HM::with_hasher(DefaultHashBuilder::default());
                assert_eq!(m.capacity(), 0);

                let m = HM::with_capacity(0);
                assert_eq!(m.capacity(), 0);

                let m = HM::with_capacity_and_hasher(0, DefaultHashBuilder::default());
                assert_eq!(m.capacity(), 0);

                let mut m = HM::new();
                m.insert(1, 1);
                m.insert(2, 2);
                m.remove(&1);
                m.remove(&2);
                m.shrink_to_fit();
                assert_eq!(m.capacity(), 0);

                let mut m = HM::new();
                m.reserve(0);
                assert_eq!(m.capacity(), 0);
            }

            #[test]
            fn test_create_capacity_zero() {
                let mut m = HashMap::with_capacity(0);

                assert!(m.insert(1, 1).is_none());

                assert!(m.contains_key(&1));
                assert!(!m.contains_key(&0));
            }

            #[test]
            fn test_insert() {
                let mut m = HashMap::new();
                assert_eq!(m.len(), 0);
                assert!(m.insert(1, 2).is_none());
                assert_eq!(m.len(), 1);
                assert!(m.insert(2, 4).is_none());
                assert_eq!(m.len(), 2);
                assert_eq!(*m.get(&1).unwrap(), 2);
                assert_eq!(*m.get(&2).unwrap(), 4);
            }

            #[test]
            fn test_drops() {
                DROP_VECTOR.with(|slot| {
                    *slot.borrow_mut() = vec![0; 200];
                });

                {
                    let mut m = HashMap::new();

                    DROP_VECTOR.with(|v| {
                        for i in 0..200 {
                            assert_eq!(v.borrow()[i], 0);
                        }
                    });

                    for i in 0..100 {
                        let d1 = Droppable::new(i);
                        let d2 = Droppable::new(i + 100);
                        m.insert(d1, d2);
                    }

                    DROP_VECTOR.with(|v| {
                        for i in 0..200 {
                            assert_eq!(v.borrow()[i], 1);
                        }
                    });

                    for i in 0..50 {
                        let k = Droppable::new(i);
                        let v = m.remove(&k);

                        assert!(v.is_some());

                        DROP_VECTOR.with(|v| {
                            assert_eq!(v.borrow()[i], 1);
                            assert_eq!(v.borrow()[i + 100], 1);
                        });
                    }

                    DROP_VECTOR.with(|v| {
                        for i in 0..50 {
                            assert_eq!(v.borrow()[i], 0);
                            assert_eq!(v.borrow()[i + 100], 0);
                        }

                        for i in 50..100 {
                            assert_eq!(v.borrow()[i], 1);
                            assert_eq!(v.borrow()[i + 100], 1);
                        }
                    });
                }

                DROP_VECTOR.with(|v| {
                    for i in 0..200 {
                        assert_eq!(v.borrow()[i], 0);
                    }
                });
            }

            #[test]
            fn test_into_iter_drops() {
                DROP_VECTOR.with(|v| {
                    *v.borrow_mut() = vec![0; 200];
                });

                let hm = {
                    let mut hm = HashMap::new();

                    DROP_VECTOR.with(|v| {
                        for i in 0..200 {
                            assert_eq!(v.borrow()[i], 0);
                        }
                    });

                    for i in 0..100 {
                        let d1 = Droppable::new(i);
                        let d2 = Droppable::new(i + 100);
                        hm.insert(d1, d2);
                    }

                    DROP_VECTOR.with(|v| {
                        for i in 0..200 {
                            assert_eq!(v.borrow()[i], 1);
                        }
                    });

                    hm
                };

                // By the way, ensure that cloning doesn't screw up the dropping.
                drop(hm.clone());

                {
                    let mut half = hm.into_iter().take(50);

                    DROP_VECTOR.with(|v| {
                        for i in 0..200 {
                            assert_eq!(v.borrow()[i], 1);
                        }
                    });

                    for _ in half.by_ref() {}

                    DROP_VECTOR.with(|v| {
                        let nk = (0..100).filter(|&i| v.borrow()[i] == 1).count();
                        let nv = (0..100).filter(|&i| v.borrow()[i + 100] == 1).count();
                        assert_eq!(nk, 50);
                        assert_eq!(nv, 50);
                    });
                }

                DROP_VECTOR.with(|v| {
                    for i in 0..200 {
                        assert_eq!(v.borrow()[i], 0);
                    }
                });
            }

            #[test]
            fn test_empty_remove() {
                let mut m: HashMap<i32, bool> = HashMap::new();
                assert_eq!(m.remove(&0), None);
            }

            #[test]
            fn test_empty_entry() {
                let mut m: HashMap<i32, bool> = HashMap::new();
                match m.entry(0) {
                    Entry::Occupied(_) => panic!(),
                    Entry::Vacant(_) => {}
                }
                assert!(*m.entry(0).or_insert(true));
                assert_eq!(m.len(), 1);
            }

            #[test]
            fn test_empty_iter() {
                let mut m: HashMap<i32, bool> = HashMap::new();
                assert_eq!(m.drain().next(), None);
                assert_eq!(m.keys().next(), None);
                assert_eq!(m.values().next(), None);
                assert_eq!(m.values_mut().next(), None);
                assert_eq!(m.iter().next(), None);
                assert_eq!(m.iter_mut().next(), None);
                assert_eq!(m.len(), 0);
                assert!(m.is_empty());
                assert_eq!(m.into_iter().next(), None);
            }

            #[test]
            #[cfg_attr(miri, ignore)] // FIXME: takes too long
            fn test_lots_of_insertions() {
                let mut m = HashMap::new();

                for _ in 0..10 {
                    assert!(m.is_empty());

                    for i in 1..1001 {
                        assert!(m.insert(i, i).is_none());

                        for j in 1..=i {
                            let r = m.get(&j);
                            assert_eq!(r, Some(&j));
                        }

                        for j in i + 1..1001 {
                            let r = m.get(&j);
                            assert_eq!(r, None);
                        }
                    }

                    for i in 1001..2001 {
                        assert!(!m.contains_key(&i));
                    }

                    for i in 1..1001 {
                        assert!(m.remove(&i).is_some());

                        for j in 1..=i {
                            assert!(!m.contains_key(&j));
                        }

                        for j in i + 1..1001 {
                            assert!(m.contains_key(&j));
                        }
                    }

                    for i in 1..1001 {
                        assert!(!m.contains_key(&i));
                    }

                    for i in 1..1001 {
                        assert!(m.insert(i, i).is_none());
                    }

                    for i in (1..1001).rev() {
                        assert!(m.remove(&i).is_some());

                        for j in i..1001 {
                            assert!(!m.contains_key(&j));
                        }

                        for j in 1..i {
                            assert!(m.contains_key(&j));
                        }
                    }
                }
            }

            #[test]
            fn test_find_mut() {
                let mut m = HashMap::new();
                assert!(m.insert(1, 12).is_none());
                assert!(m.insert(2, 8).is_none());
                assert!(m.insert(5, 14).is_none());
                let new = 100;
                match m.get_mut(&5) {
                    None => panic!(),
                    Some(x) => *x = new,
                }
                assert_eq!(m.get(&5), Some(&new));
                let mut hashmap: HashMap<i32, String> = HashMap::default();
                let key = &1;
                let result = hashmap.get_mut(key);
                assert!(result.is_none());
            }

            #[test]
            fn test_insert_overwrite() {
                let mut m = HashMap::new();
                assert!(m.insert(1, 2).is_none());
                assert_eq!(*m.get(&1).unwrap(), 2);
                assert!(m.insert(1, 3).is_some());
                assert_eq!(*m.get(&1).unwrap(), 3);
            }

            #[test]
            fn test_insert_conflicts() {
                let mut m = HashMap::with_capacity(4);
                assert!(m.insert(1, 2).is_none());
                assert!(m.insert(5, 3).is_none());
                assert!(m.insert(9, 4).is_none());
                assert_eq!(*m.get(&9).unwrap(), 4);
                assert_eq!(*m.get(&5).unwrap(), 3);
                assert_eq!(*m.get(&1).unwrap(), 2);
            }

            #[test]
            fn test_conflict_remove() {
                let mut m = HashMap::with_capacity(4);
                assert!(m.insert(1, 2).is_none());
                assert_eq!(*m.get(&1).unwrap(), 2);
                assert!(m.insert(5, 3).is_none());
                assert_eq!(*m.get(&1).unwrap(), 2);
                assert_eq!(*m.get(&5).unwrap(), 3);
                assert!(m.insert(9, 4).is_none());
                assert_eq!(*m.get(&1).unwrap(), 2);
                assert_eq!(*m.get(&5).unwrap(), 3);
                assert_eq!(*m.get(&9).unwrap(), 4);
                assert!(m.remove(&1).is_some());
                assert_eq!(*m.get(&9).unwrap(), 4);
                assert_eq!(*m.get(&5).unwrap(), 3);
            }

            #[test]
            fn test_is_empty() {
                let mut m = HashMap::with_capacity(4);
                assert!(m.insert(1, 2).is_none());
                assert!(!m.is_empty());
                assert!(m.remove(&1).is_some());
                assert!(m.is_empty());
            }

            #[test]
            fn test_remove() {
                let mut m = HashMap::new();
                m.insert(1, 2);
                assert_eq!(m.remove(&1), Some(2));
                assert_eq!(m.remove(&1), None);
            }

            #[test]
            fn test_remove_entry() {
                let mut m = HashMap::new();
                m.insert(1, 2);
                assert_eq!(m.remove_entry(&1), Some((1, 2)));
                assert_eq!(m.remove(&1), None);
            }

            #[test]
            fn test_iterate() {
                let mut m = HashMap::with_capacity(4);
                for i in 0..32 {
                    assert!(m.insert(i, i * 2).is_none());
                }
                assert_eq!(m.len(), 32);

                let mut observed: u32 = 0;

                for (k, v) in &m {
                    assert_eq!(*v, *k * 2);
                    observed |= 1 << *k;
                }
                assert_eq!(observed, 0xFFFF_FFFF);
            }

            #[test]
            fn test_find() {
                let mut m = HashMap::new();
                assert!(m.get(&1).is_none());
                m.insert(1, 2);
                match m.get(&1) {
                    None => panic!(),
                    Some(v) => assert_eq!(*v, 2),
                }
            }

            #[test]
            fn test_keys() {
                let vec = vec![(1, 'a'), (2, 'b'), (3, 'c')];
                let map: HashMap<_, _> = vec.into_iter().collect();
                let keys: Vec<_> = map.keys().copied().collect();
                assert_eq!(keys.len(), 3);
                assert!(keys.contains(&1));
                assert!(keys.contains(&2));
                assert!(keys.contains(&3));
            }

            #[test]
            fn test_values() {
                let vec = vec![(1, 'a'), (2, 'b'), (3, 'c')];
                let map: HashMap<_, _> = vec.into_iter().collect();
                let values: Vec<_> = map.values().copied().collect();
                assert_eq!(values.len(), 3);
                assert!(values.contains(&'a'));
                assert!(values.contains(&'b'));
                assert!(values.contains(&'c'));
            }

            #[test]
            fn test_values_mut() {
                let vec = vec![(1, 1), (2, 2), (3, 3)];
                let mut map: HashMap<_, _> = vec.into_iter().collect();
                for value in map.values_mut() {
                    *value *= 2;
                }
                let values: Vec<_> = map.values().copied().collect();
                assert_eq!(values.len(), 3);
                assert!(values.contains(&2));
                assert!(values.contains(&4));
                assert!(values.contains(&6));
            }

            #[test]
            fn test_into_keys() {
                let vec = vec![(1, 'a'), (2, 'b'), (3, 'c')];
                let map: HashMap<_, _> = vec.into_iter().collect();
                let keys: Vec<_> = map.into_keys().collect();

                assert_eq!(keys.len(), 3);
                assert!(keys.contains(&1));
                assert!(keys.contains(&2));
                assert!(keys.contains(&3));
            }

            #[test]
            fn test_into_values() {
                let vec = vec![(1, 'a'), (2, 'b'), (3, 'c')];
                let map: HashMap<_, _> = vec.into_iter().collect();
                let values: Vec<_> = map.into_values().collect();

                assert_eq!(values.len(), 3);
                assert!(values.contains(&'a'));
                assert!(values.contains(&'b'));
                assert!(values.contains(&'c'));
            }

            #[test]
            fn test_eq() {
                let mut m1 = HashMap::new();
                m1.insert(1, 2);
                m1.insert(2, 3);
                m1.insert(3, 4);

                let mut m2 = HashMap::new();
                m2.insert(1, 2);
                m2.insert(2, 3);

                assert!(m1 != m2);

                m2.insert(3, 4);

                assert_eq!(m1, m2);
            }

            #[test]
            fn test_from_iter() {
                let xs = [(1, 1), (2, 2), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6)];

                let map: HashMap<_, _> = xs.iter().copied().collect();

                for &(k, v) in &xs {
                    assert_eq!(map.get(&k), Some(&v));
                }

                assert_eq!(map.iter().count(), xs.len() - 1);
            }

            #[test]
            fn test_index() {
                let mut map = HashMap::new();

                map.insert(1, 2);
                map.insert(2, 1);
                map.insert(3, 4);

                assert_eq!(map[&2], 1);
            }

            #[test]
            #[should_panic]
            fn test_index_nonexistent() {
                let mut map = HashMap::new();

                map.insert(1, 2);
                map.insert(2, 1);
                map.insert(3, 4);

                _ = map[&4];
            }

            #[test]
            fn test_entry() {
                let xs = [(1, 10), (2, 20), (3, 30), (4, 40), (5, 50), (6, 60)];

                let mut map: HashMap<_, _> = xs.iter().copied().collect();

                // Existing key (insert)
                match map.entry(1) {
                    Entry::Vacant(_) => unreachable!(),
                    Entry::Occupied(mut view) => {
                        assert_eq!(view.get(), &10);
                        assert_eq!(view.insert(100), 10);
                    }
                }
                assert_eq!(map.get(&1).unwrap(), &100);
                assert_eq!(map.len(), 6);

                // Existing key (update)
                match map.entry(2) {
                    Entry::Vacant(_) => unreachable!(),
                    Entry::Occupied(mut view) => {
                        let v = view.get_mut();
                        let new_v = (*v) * 10;
                        *v = new_v;
                    }
                }
                assert_eq!(map.get(&2).unwrap(), &200);
                assert_eq!(map.len(), 6);

                // Existing key (take)
                match map.entry(3) {
                    Entry::Vacant(_) => unreachable!(),
                    Entry::Occupied(view) => {
                        assert_eq!(view.remove(), 30);
                    }
                }
                assert_eq!(map.get(&3), None);
                assert_eq!(map.len(), 5);

                // Inexistent key (insert)
                match map.entry(10) {
                    Entry::Occupied(_) => unreachable!(),
                    Entry::Vacant(view) => {
                        assert_eq!(*view.insert(1000), 1000);
                    }
                }
                assert_eq!(map.get(&10).unwrap(), &1000);
                assert_eq!(map.len(), 6);
            }

            #[test]
            fn test_extend_ref_k_ref_v() {
                let mut a = HashMap::new();
                a.insert(1, "one");
                let mut b = HashMap::new();
                b.insert(2, "two");
                b.insert(3, "three");

                a.extend(&b);

                assert_eq!(a.len(), 3);
                assert_eq!(a[&1], "one");
                assert_eq!(a[&2], "two");
                assert_eq!(a[&3], "three");
            }

            #[test]
            fn test_extend_ref_kv_tuple() {
                use std::ops::AddAssign;
                let mut a = HashMap::new();
                a.insert(0, 0);

                fn create_arr<T: AddAssign<T> + Copy, const N: usize>(
                    start: T,
                    step: T,
                ) -> [(T, T); N] {
                    let mut outs = [(start, start); N];
                    let mut element = step;
                    outs.iter_mut().skip(1).for_each(|(k, v)| {
                        *k += element;
                        *v += element;
                        element += step;
                    });
                    outs
                }

                let for_iter: Vec<_> = (0..100).map(|i| (i, i)).collect();
                let iter = for_iter.iter();
                let vec: Vec<_> = (100..200).map(|i| (i, i)).collect();
                a.extend(iter);
                a.extend(&vec);
                a.extend(create_arr::<i32, 100>(200, 1));

                assert_eq!(a.len(), 300);

                for item in 0..300 {
                    assert_eq!(a[&item], item);
                }
            }

            #[test]
            fn test_capacity_not_less_than_len() {
                let mut a = HashMap::new();
                for i in 0..512 {
                    a.insert(i, 0);
                    assert!(a.capacity() >= a.len());
                }
                for i in 0..128 {
                    a.remove(&i);
                    assert!(a.capacity() >= a.len());
                }
                for i in 512..640 {
                    a.insert(i, 0);
                    assert!(a.capacity() >= a.len());
                }
            }

            #[test]
            fn test_occupied_entry_key() {
                let mut a = HashMap::new();
                let key = "hello there";
                let value = "value goes here";
                assert!(a.is_empty());
                a.insert(key, value);
                assert_eq!(a.len(), 1);
                assert_eq!(a[key], value);

                match a.entry(key) {
                    Entry::Vacant(_) => panic!(),
                    Entry::Occupied(e) => assert_eq!(key, *e.key()),
                }
                assert_eq!(a.len(), 1);
                assert_eq!(a[key], value);
            }

            #[test]
            fn test_vacant_entry_key() {
                let mut a = HashMap::new();
                let key = "hello there";
                let value = "value goes here";

                assert!(a.is_empty());
                match a.entry(key) {
                    Entry::Occupied(_) => panic!(),
                    Entry::Vacant(e) => {
                        assert_eq!(key, *e.key());
                        e.insert(value);
                    }
                }
                assert_eq!(a.len(), 1);
                assert_eq!(a[key], value);
            }

            #[test]
            fn test_retain() {
                let mut map: HashMap<i32, i32> = (0..100).map(|x| (x, x * 10)).collect();

                map.retain(|&k, _| k % 2 == 0);
                assert_eq!(map.len(), 50);
                assert_eq!(map[&2], 20);
                assert_eq!(map[&4], 40);
                assert_eq!(map[&6], 60);
            }

            #[test]
            fn test_extract_if() {
                {
                    let mut map: HashMap<i32, i32> = (0..8).map(|x| (x, x * 10)).collect();
                    let drained = map.extract_if(|&k, _| k % 2 == 0);
                    let mut out = drained.collect::<Vec<_>>();
                    out.sort_unstable();
                    assert_eq!(vec![(0, 0), (2, 20), (4, 40), (6, 60)], out);
                    assert_eq!(map.len(), 4);
                }
                {
                    let mut map: HashMap<i32, i32> = (0..8).map(|x| (x, x * 10)).collect();
                    map.extract_if(|&k, _| k % 2 == 0).for_each(drop);
                    assert_eq!(map.len(), 4);
                }
            }

            #[test]
            #[cfg_attr(miri, ignore)] // FIXME: no OOM signalling
            fn test_try_reserve() {
                use opthash::TryReserveError::{AllocError, CapacityOverflow};

                const MAX_ISIZE: usize = isize::MAX as usize;

                let mut empty_bytes: HashMap<u8, u8> = HashMap::new();

                if let Err(CapacityOverflow) = empty_bytes.try_reserve(usize::MAX) {
                } else {
                    panic!("usize::MAX should trigger an overflow!");
                }

                if let Err(CapacityOverflow) = empty_bytes.try_reserve(MAX_ISIZE) {
                } else {
                    panic!("isize::MAX should trigger an overflow!");
                }

                if matches!(
                    empty_bytes.try_reserve(MAX_ISIZE / 5),
                    Err(AllocError | CapacityOverflow)
                ) {
                } else {
                    let mut empty_bytes2: HashMap<u8, u8> = HashMap::new();
                    let _ = empty_bytes2.try_reserve(MAX_ISIZE / 5);
                    let mut empty_bytes3: HashMap<u8, u8> = HashMap::new();
                    let _ = empty_bytes3.try_reserve(MAX_ISIZE / 5);
                    let mut empty_bytes4: HashMap<u8, u8> = HashMap::new();
                    if matches!(
                        empty_bytes4.try_reserve(MAX_ISIZE / 5),
                        Err(AllocError | CapacityOverflow)
                    ) {
                    } else {
                        panic!("isize::MAX / 5 should trigger an OOM!");
                    }
                }
            }

            #[test]
            fn test_get_disjoint_mut() {
                let mut map = HashMap::new();
                map.insert("foo".to_owned(), 0);
                map.insert("bar".to_owned(), 10);
                map.insert("baz".to_owned(), 20);
                map.insert("qux".to_owned(), 30);

                let xs = map.get_disjoint_mut(["foo", "qux"]);
                assert_eq!(xs, [Some(&mut 0), Some(&mut 30)]);

                let xs = map.get_disjoint_mut(["foo", "dud"]);
                assert_eq!(xs, [Some(&mut 0), None]);

                let ys = map.get_disjoint_key_value_mut(["bar", "baz"]);
                assert_eq!(
                    ys,
                    [
                        Some((&"bar".to_owned(), &mut 10)),
                        Some((&"baz".to_owned(), &mut 20))
                    ],
                );

                let ys = map.get_disjoint_key_value_mut(["bar", "dip"]);
                assert_eq!(ys, [Some((&"bar".to_owned(), &mut 10)), None]);
            }

            #[test]
            fn test_reserve_shrink_to_fit() {
                // Std contract probes only: `reserve(n)` gives `capacity >= len + n`,
                // `shrink_to_fit` keeps `capacity >= len`. Hashbrown's stricter
                // "capacity unchanged across the next n inserts" is impl-specific
                // (funnel's bucket+special arch can hit probe-budget exhaustion
                // mid-fill), so omitted.
                let mut m = HashMap::new();
                m.insert(0, 0);
                m.remove(&0);
                assert!(m.capacity() >= m.len());

                for i in 0..128 {
                    m.insert(i, i);
                }
                let before = m.len();
                m.reserve(256);
                assert!(m.capacity() >= before + 256);

                for i in 128..(128 + 256) {
                    m.insert(i, i);
                }
                assert_eq!(m.len(), 384);

                for i in 100..(128 + 256) {
                    assert_eq!(m.remove(&i), Some(i));
                }
                m.shrink_to_fit();
                assert_eq!(m.len(), 100);
                assert!(m.capacity() >= m.len());

                for i in 0..100 {
                    assert_eq!(m.remove(&i), Some(i));
                }
                m.shrink_to_fit();
                m.insert(0, 0);
                assert_eq!(m.len(), 1);
                assert!(m.capacity() >= m.len());
                assert_eq!(m.remove(&0), Some(0));
            }

            #[test]
            #[should_panic(expected = "duplicate keys")]
            fn test_get_disjoint_mut_duplicate() {
                let mut map = HashMap::new();
                map.insert("foo".to_owned(), 0);

                let _xs = map.get_disjoint_mut(["foo", "foo"]);
            }

            #[test]
            fn test_size_hint() {
                let xs = [(1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6)];

                let map: HashMap<_, _> = xs.iter().copied().collect();

                let mut iter = map.iter();

                for _ in iter.by_ref().take(3) {}

                assert_eq!(iter.size_hint(), (3, Some(3)));
            }

            #[test]
            fn test_iter_len() {
                let xs = [(1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6)];

                let map: HashMap<_, _> = xs.iter().copied().collect();

                let mut iter = map.iter();

                for _ in iter.by_ref().take(3) {}

                assert_eq!(iter.len(), 3);
            }

            #[test]
            fn test_mut_size_hint() {
                let xs = [(1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6)];

                let mut map: HashMap<_, _> = xs.iter().copied().collect();

                let mut iter = map.iter_mut();

                for _ in iter.by_ref().take(3) {}

                assert_eq!(iter.size_hint(), (3, Some(3)));
            }

            #[test]
            fn test_iter_mut_len() {
                let xs = [(1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6)];

                let mut map: HashMap<_, _> = xs.iter().copied().collect();

                let mut iter = map.iter_mut();

                for _ in iter.by_ref().take(3) {}

                assert_eq!(iter.len(), 3);
            }

            #[test]
            fn test_clone() {
                let mut m = HashMap::new();
                assert_eq!(m.len(), 0);
                assert!(m.insert(1, 2).is_none());
                assert_eq!(m.len(), 1);
                assert!(m.insert(2, 4).is_none());
                assert_eq!(m.len(), 2);
                let m2 = m.clone();
                assert_eq!(*m2.get(&1).unwrap(), 2);
                assert_eq!(*m2.get(&2).unwrap(), 4);
                assert_eq!(m2.len(), 2);
            }

            #[test]
            fn test_clone_from() {
                let mut m = HashMap::new();
                let mut m2 = HashMap::new();
                assert_eq!(m.len(), 0);
                assert!(m.insert(1, 2).is_none());
                assert_eq!(m.len(), 1);
                assert!(m.insert(2, 4).is_none());
                assert_eq!(m.len(), 2);
                m2.clone_from(&m);
                assert_eq!(*m2.get(&1).unwrap(), 2);
                assert_eq!(*m2.get(&2).unwrap(), 4);
                assert_eq!(m2.len(), 2);
            }

            #[test]
            #[should_panic = "panic in drop"]
            fn test_clone_from_double_drop() {
                #[derive(Clone)]
                struct CheckedDrop {
                    panic_in_drop: bool,
                    dropped: bool,
                }
                impl Drop for CheckedDrop {
                    fn drop(&mut self) {
                        if self.panic_in_drop {
                            self.dropped = true;
                            panic!("panic in drop");
                        }
                        if self.dropped {
                            panic!("double drop");
                        }
                        self.dropped = true;
                    }
                }
                const DISARMED: CheckedDrop = CheckedDrop {
                    panic_in_drop: false,
                    dropped: false,
                };
                const ARMED: CheckedDrop = CheckedDrop {
                    panic_in_drop: true,
                    dropped: false,
                };

                let mut map1 = HashMap::new();
                map1.insert(1, DISARMED);
                map1.insert(2, DISARMED);
                map1.insert(3, DISARMED);
                map1.insert(4, DISARMED);

                let mut map2 = HashMap::new();
                map2.insert(1, DISARMED);
                map2.insert(2, ARMED);
                map2.insert(3, DISARMED);
                map2.insert(4, DISARMED);

                map2.clone_from(&map1);
            }

            #[test]
            #[should_panic = "panic in clone"]
            fn test_clone_from_memory_leaks() {
                struct CheckedClone {
                    panic_in_clone: bool,
                    need_drop: Vec<i32>,
                }
                impl Clone for CheckedClone {
                    fn clone(&self) -> Self {
                        if self.panic_in_clone {
                            panic!("panic in clone")
                        }
                        Self {
                            panic_in_clone: self.panic_in_clone,
                            need_drop: self.need_drop.clone(),
                        }
                    }
                }
                let mut map1 = HashMap::new();
                map1.insert(
                    1,
                    CheckedClone {
                        panic_in_clone: false,
                        need_drop: vec![0, 1, 2],
                    },
                );
                map1.insert(
                    2,
                    CheckedClone {
                        panic_in_clone: false,
                        need_drop: vec![3, 4, 5],
                    },
                );
                map1.insert(
                    3,
                    CheckedClone {
                        panic_in_clone: true,
                        need_drop: vec![6, 7, 8],
                    },
                );
                let _map2 = map1.clone();
            }

            #[test]
            fn test_clone_of_empty_map() {
                let map: HashMap<u32, u32> = HashMap::new();
                let cloned = map.clone();
                assert!(cloned.is_empty());
                assert_eq!(cloned.len(), 0);
            }

            #[test]
            fn test_clone_is_independent_of_source() {
                let mut map: HashMap<i32, i32> = HashMap::new();
                for i in 0..40 {
                    map.insert(i, i * 7);
                }
                for i in 0..20 {
                    map.remove(&i);
                }

                let mut cloned = map.clone();
                assert_eq!(cloned.len(), map.len());
                for i in 20..40 {
                    assert_eq!(cloned.get(&i), Some(&(i * 7)));
                }
                for i in 0..20 {
                    assert_eq!(cloned.get(&i), None);
                }

                // Mutating the clone must not bleed into the source.
                cloned.insert(999, 0);
                assert_eq!(map.get(&999), None);
                assert_eq!(cloned.get(&999), Some(&0));
            }

            #[test]
            fn test_clone_drops_each_value_exactly_once() {
                use std::sync::Arc;
                use std::sync::atomic::{AtomicUsize, Ordering};

                struct DropCounter(Arc<AtomicUsize>);
                impl Clone for DropCounter {
                    fn clone(&self) -> Self {
                        Self(Arc::clone(&self.0))
                    }
                }
                impl Drop for DropCounter {
                    fn drop(&mut self) {
                        self.0.fetch_add(1, Ordering::SeqCst);
                    }
                }

                let counter = Arc::new(AtomicUsize::new(0));
                let mut map: HashMap<i32, DropCounter> = HashMap::with_capacity(32);
                for i in 0..16 {
                    map.insert(i, DropCounter(Arc::clone(&counter)));
                }
                let cloned = map.clone();
                drop(map);
                drop(cloned);
                assert_eq!(counter.load(Ordering::SeqCst), 32);
            }
        }
    };
}

parity_suite!(elastic_parity, ElasticHashMap, ElasticEntry);
parity_suite!(funnel_parity, FunnelHashMap, FunnelEntry);

/// Clone tests with a custom allocator whose Drop count we observe, so
/// leaks of the allocator value itself show up as a non-zero counter.
macro_rules! clone_alloc_suite {
    ($mod_name:ident, $TestMap:ident) => {
        mod $mod_name {
            use std::ptr::NonNull;
            use std::sync::Arc;
            use std::sync::atomic::{AtomicI8, Ordering};

            use allocator_api2::alloc::{AllocError, Allocator, Global, Layout};
            use opthash::$TestMap as HashMap;

            struct MyAllocInner {
                drop_count: Arc<AtomicI8>,
            }

            #[derive(Clone)]
            struct MyAlloc {
                _inner: Arc<MyAllocInner>,
            }

            impl MyAlloc {
                fn new(drop_count: Arc<AtomicI8>) -> Self {
                    MyAlloc {
                        _inner: Arc::new(MyAllocInner { drop_count }),
                    }
                }
            }

            impl Drop for MyAllocInner {
                fn drop(&mut self) {
                    self.drop_count.fetch_sub(1, Ordering::SeqCst);
                }
            }

            unsafe impl Allocator for MyAlloc {
                fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
                    Global.allocate(layout)
                }
                unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
                    unsafe { Global.deallocate(ptr, layout) };
                }
            }

            #[test]
            fn test_hashmap_into_iter_bug() {
                let dropped: Arc<AtomicI8> = Arc::new(AtomicI8::new(1));
                {
                    let mut map = HashMap::with_capacity_in(10, MyAlloc::new(dropped.clone()));
                    for i in 0..10 {
                        map.entry(i).or_insert_with(|| "i".to_owned());
                    }
                    for (k, v) in map {
                        let _ = (k, v);
                    }
                }
                assert_eq!(dropped.load(Ordering::SeqCst), 0);
            }

            #[derive(Debug)]
            struct CheckedCloneDrop<T> {
                panic_in_clone: bool,
                panic_in_drop: bool,
                dropped: bool,
                data: T,
            }

            impl<T> CheckedCloneDrop<T> {
                fn new(panic_in_clone: bool, panic_in_drop: bool, data: T) -> Self {
                    Self {
                        panic_in_clone,
                        panic_in_drop,
                        dropped: false,
                        data,
                    }
                }
            }

            impl<T: Clone> Clone for CheckedCloneDrop<T> {
                fn clone(&self) -> Self {
                    if self.panic_in_clone {
                        panic!("panic in clone")
                    }
                    Self {
                        panic_in_clone: self.panic_in_clone,
                        panic_in_drop: self.panic_in_drop,
                        dropped: self.dropped,
                        data: self.data.clone(),
                    }
                }
            }

            impl<T> Drop for CheckedCloneDrop<T> {
                fn drop(&mut self) {
                    if self.panic_in_drop {
                        self.dropped = true;
                        panic!("panic in drop");
                    }
                    if self.dropped {
                        panic!("double drop");
                    }
                    self.dropped = true;
                }
            }

            const DISARMED: bool = false;
            const ARMED: bool = true;
            const ARMED_FLAGS: [bool; 8] = [
                DISARMED, DISARMED, DISARMED, ARMED, DISARMED, DISARMED, DISARMED, DISARMED,
            ];
            const DISARMED_FLAGS: [bool; 8] = [DISARMED; 8];

            fn build_test_map<T, F>(
                clone_flags: [bool; 8],
                drop_flags: [bool; 8],
                mut fun: F,
                alloc: MyAlloc,
            ) -> HashMap<u64, CheckedCloneDrop<T>, opthash::DefaultHashBuilder, MyAlloc>
            where
                F: FnMut(u64) -> T,
            {
                let mut map = HashMap::with_capacity_in(clone_flags.len(), alloc);
                for (i, (c, d)) in clone_flags.into_iter().zip(drop_flags).enumerate() {
                    let i = i as u64;
                    map.insert(i, CheckedCloneDrop::new(c, d, fun(i)));
                }
                map
            }

            #[test]
            #[should_panic = "panic in clone"]
            fn test_clone_memory_leaks_and_double_drop_one() {
                let dropped: Arc<AtomicI8> = Arc::new(AtomicI8::new(2));
                let map = build_test_map(
                    ARMED_FLAGS,
                    DISARMED_FLAGS,
                    |n| vec![n],
                    MyAlloc::new(dropped.clone()),
                );
                // Clone panics; partial allocations must unwind cleanly.
                let _map2 = map.clone();
            }

            #[test]
            #[should_panic = "panic in drop"]
            fn test_clone_memory_leaks_and_double_drop_two() {
                let dropped: Arc<AtomicI8> = Arc::new(AtomicI8::new(2));
                let map = build_test_map(
                    DISARMED_FLAGS,
                    DISARMED_FLAGS,
                    |n| n,
                    MyAlloc::new(dropped.clone()),
                );
                let mut map2 = build_test_map(
                    DISARMED_FLAGS,
                    ARMED_FLAGS,
                    |n| n,
                    MyAlloc::new(dropped.clone()),
                );
                // `clone_from` drops `map2`'s existing entries; one panics in
                // drop. Cleanup must not double-drop or abort.
                map2.clone_from(&map);
            }

            #[test]
            #[cfg(panic = "unwind")]
            fn test_catch_panic_clone_from_when_len_is_equal() {
                use std::thread;

                let dropped: Arc<AtomicI8> = Arc::new(AtomicI8::new(2));
                {
                    let mut map = build_test_map(
                        DISARMED_FLAGS,
                        DISARMED_FLAGS,
                        |n| vec![n],
                        MyAlloc::new(dropped.clone()),
                    );
                    thread::scope(|s| {
                        let handle = s.spawn(|| {
                            let scope_map = build_test_map(
                                ARMED_FLAGS,
                                DISARMED_FLAGS,
                                |n| vec![n * 2],
                                MyAlloc::new(dropped.clone()),
                            );
                            map.clone_from(&scope_map);
                            "clone_from should have panicked"
                        });
                        if let Ok(msg) = handle.join() {
                            panic!("{msg}");
                        }
                    });
                }
                assert_eq!(dropped.load(Ordering::SeqCst), 0);
            }

            #[test]
            #[cfg(panic = "unwind")]
            fn test_catch_panic_clone_from_when_len_is_not_equal() {
                use std::thread;

                let dropped: Arc<AtomicI8> = Arc::new(AtomicI8::new(2));
                {
                    // Source capacity differs from dest so clone_from falls
                    // through to the free + realloc path.
                    let mut map = HashMap::with_capacity_in(8, MyAlloc::new(dropped.clone()));
                    map.insert(0, CheckedCloneDrop::new(DISARMED, DISARMED, vec![0u64]));
                    thread::scope(|s| {
                        let handle = s.spawn(|| {
                            let scope_map = build_test_map(
                                ARMED_FLAGS,
                                DISARMED_FLAGS,
                                |n| vec![n * 2],
                                MyAlloc::new(dropped.clone()),
                            );
                            map.clone_from(&scope_map);
                            "clone_from should have panicked"
                        });
                        if let Ok(msg) = handle.join() {
                            panic!("{msg}");
                        }
                    });
                }
                assert_eq!(dropped.load(Ordering::SeqCst), 0);
            }
        }
    };
}

clone_alloc_suite!(elastic_clone_alloc, ElasticHashMap);
clone_alloc_suite!(funnel_clone_alloc, FunnelHashMap);
