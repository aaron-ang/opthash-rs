//! Parity tests against `hashbrown::HashMap`, ported from
//! `hashbrown-0.17/src/map.rs::test_map` and run via macro against both maps.
//!
//! Tests requiring APIs opthash lacks (`Clone`, `EntryRef`, `raw_entry`,
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
            use opthash::$Entry::{Occupied, Vacant};
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

                // Upstream's `drop(hm.clone())` check omitted: no Clone impl.

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
                    Occupied(_) => panic!(),
                    Vacant(_) => {}
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
                    Vacant(_) => unreachable!(),
                    Occupied(mut view) => {
                        assert_eq!(view.get(), &10);
                        assert_eq!(view.insert(100), 10);
                    }
                }
                assert_eq!(map.get(&1).unwrap(), &100);
                assert_eq!(map.len(), 6);

                // Existing key (update)
                match map.entry(2) {
                    Vacant(_) => unreachable!(),
                    Occupied(mut view) => {
                        let v = view.get_mut();
                        let new_v = (*v) * 10;
                        *v = new_v;
                    }
                }
                assert_eq!(map.get(&2).unwrap(), &200);
                assert_eq!(map.len(), 6);

                // Existing key (take)
                match map.entry(3) {
                    Vacant(_) => unreachable!(),
                    Occupied(view) => {
                        assert_eq!(view.remove(), 30);
                    }
                }
                assert_eq!(map.get(&3), None);
                assert_eq!(map.len(), 5);

                // Inexistent key (insert)
                match map.entry(10) {
                    Occupied(_) => unreachable!(),
                    Vacant(view) => {
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
                    let mut outs: [(T, T); N] = [(start, start); N];
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
                    Vacant(_) => panic!(),
                    Occupied(e) => assert_eq!(key, *e.key()),
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
                    Occupied(_) => panic!(),
                    Vacant(e) => {
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

                if let Err(AllocError) = empty_bytes.try_reserve(MAX_ISIZE / 5) {
                } else {
                    let mut empty_bytes2: HashMap<u8, u8> = HashMap::new();
                    let _ = empty_bytes2.try_reserve(MAX_ISIZE / 5);
                    let mut empty_bytes3: HashMap<u8, u8> = HashMap::new();
                    let _ = empty_bytes3.try_reserve(MAX_ISIZE / 5);
                    let mut empty_bytes4: HashMap<u8, u8> = HashMap::new();
                    if let Err(AllocError) = empty_bytes4.try_reserve(MAX_ISIZE / 5) {
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
        }
    };
}

parity_suite!(elastic_parity, ElasticHashMap, ElasticEntry);
parity_suite!(funnel_parity, FunnelHashMap, FunnelEntry);
