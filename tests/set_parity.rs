//! Parity tests ported from `hashbrown-0.17/src/set.rs::test_set`, run via
//! macro against both `ElasticHashSet` and `FunnelHashSet`.
//!
//! Tests for APIs opthash lacks (`From<HashMap>`, `allocation_size`, const
//! constructors, hashbrown-internal `Equivalent` debug asserts) and ones that
//! assert hashbrown-specific capacity growth (`rehash_in_place`) are omitted.

macro_rules! set_suite {
    ($mod_name:ident, $TestSet:ident, $Entry:ident) => {
        mod $mod_name {
            use opthash::$Entry as Entry;
            use opthash::{DefaultHashBuilder, $TestSet as HashSet};

            #[test]
            fn test_zero_capacities() {
                type HS = HashSet<i32>;

                let s = HS::new();
                assert_eq!(s.capacity(), 0);

                let s = HS::default();
                assert_eq!(s.capacity(), 0);

                let s = HS::with_hasher(DefaultHashBuilder::default());
                assert_eq!(s.capacity(), 0);

                let s = HS::with_capacity(0);
                assert_eq!(s.capacity(), 0);

                let s = HS::with_capacity_and_hasher(0, DefaultHashBuilder::default());
                assert_eq!(s.capacity(), 0);

                let mut s = HS::new();
                s.insert(1);
                s.insert(2);
                s.remove(&1);
                s.remove(&2);
                s.shrink_to_fit();
                assert_eq!(s.capacity(), 0);

                let mut s = HS::new();
                s.reserve(0);
                assert_eq!(s.capacity(), 0);
            }

            #[test]
            fn test_disjoint() {
                let mut xs = HashSet::new();
                let mut ys = HashSet::new();
                assert!(xs.is_disjoint(&ys));
                assert!(ys.is_disjoint(&xs));
                assert!(xs.insert(5));
                assert!(ys.insert(11));
                assert!(xs.is_disjoint(&ys));
                assert!(ys.is_disjoint(&xs));
                assert!(xs.insert(7));
                assert!(xs.insert(19));
                assert!(xs.insert(4));
                assert!(ys.insert(2));
                assert!(ys.insert(-11));
                assert!(xs.is_disjoint(&ys));
                assert!(ys.is_disjoint(&xs));
                assert!(ys.insert(7));
                assert!(!xs.is_disjoint(&ys));
                assert!(!ys.is_disjoint(&xs));
            }

            #[test]
            fn test_subset_and_superset() {
                let mut a = HashSet::new();
                assert!(a.insert(0));
                assert!(a.insert(5));
                assert!(a.insert(11));
                assert!(a.insert(7));

                let mut b = HashSet::new();
                assert!(b.insert(0));
                assert!(b.insert(7));
                assert!(b.insert(19));
                assert!(b.insert(250));
                assert!(b.insert(11));
                assert!(b.insert(200));

                assert!(!a.is_subset(&b));
                assert!(!a.is_superset(&b));
                assert!(!b.is_subset(&a));
                assert!(!b.is_superset(&a));

                assert!(b.insert(5));

                assert!(a.is_subset(&b));
                assert!(!a.is_superset(&b));
                assert!(!b.is_subset(&a));
                assert!(b.is_superset(&a));
            }

            #[test]
            fn test_iterate() {
                let mut a = HashSet::new();
                for i in 0..32 {
                    assert!(a.insert(i));
                }
                let mut observed: u32 = 0;
                for k in &a {
                    observed |= 1 << *k;
                }
                assert_eq!(observed, 0xFFFF_FFFF);
            }

            #[test]
            fn test_intersection() {
                let mut a = HashSet::new();
                let mut b = HashSet::new();

                assert!(a.insert(11));
                assert!(a.insert(1));
                assert!(a.insert(3));
                assert!(a.insert(77));
                assert!(a.insert(103));
                assert!(a.insert(5));
                assert!(a.insert(-5));

                assert!(b.insert(2));
                assert!(b.insert(11));
                assert!(b.insert(77));
                assert!(b.insert(-9));
                assert!(b.insert(-42));
                assert!(b.insert(5));
                assert!(b.insert(3));

                let mut i = 0;
                let expected = [3, 5, 11, 77];
                for x in a.intersection(&b) {
                    assert!(expected.contains(x));
                    i += 1;
                }
                assert_eq!(i, expected.len());
            }

            #[test]
            fn test_difference() {
                let mut a = HashSet::new();
                let mut b = HashSet::new();

                assert!(a.insert(1));
                assert!(a.insert(3));
                assert!(a.insert(5));
                assert!(a.insert(9));
                assert!(a.insert(11));

                assert!(b.insert(3));
                assert!(b.insert(9));

                let mut i = 0;
                let expected = [1, 5, 11];
                for x in a.difference(&b) {
                    assert!(expected.contains(x));
                    i += 1;
                }
                assert_eq!(i, expected.len());
            }

            #[test]
            fn test_symmetric_difference() {
                let mut a = HashSet::new();
                let mut b = HashSet::new();

                assert!(a.insert(1));
                assert!(a.insert(3));
                assert!(a.insert(5));
                assert!(a.insert(9));
                assert!(a.insert(11));

                assert!(b.insert(-2));
                assert!(b.insert(3));
                assert!(b.insert(9));
                assert!(b.insert(14));
                assert!(b.insert(22));

                let mut i = 0;
                let expected = [-2, 1, 5, 11, 14, 22];
                for x in a.symmetric_difference(&b) {
                    assert!(expected.contains(x));
                    i += 1;
                }
                assert_eq!(i, expected.len());
            }

            #[test]
            fn test_sub_assign() {
                let mut a: HashSet<_> = vec![1, 2, 3, 4, 5].into_iter().collect();
                let b: HashSet<_> = vec![4, 5, 6].into_iter().collect();

                a -= &b;

                let mut i = 0;
                let expected = [1, 2, 3];
                for x in &a {
                    assert!(expected.contains(x));
                    i += 1;
                }
                assert_eq!(i, expected.len());
            }

            #[test]
            fn test_union() {
                let mut a = HashSet::new();
                let mut b = HashSet::new();

                assert!(a.insert(1));
                assert!(a.insert(3));
                assert!(a.insert(5));
                assert!(a.insert(9));
                assert!(a.insert(11));
                assert!(a.insert(16));
                assert!(a.insert(19));
                assert!(a.insert(24));

                assert!(b.insert(-2));
                assert!(b.insert(1));
                assert!(b.insert(5));
                assert!(b.insert(9));
                assert!(b.insert(13));
                assert!(b.insert(19));

                let mut i = 0;
                let expected = [-2, 1, 3, 5, 9, 11, 13, 16, 19, 24];
                for x in a.union(&b) {
                    assert!(expected.contains(x));
                    i += 1;
                }
                assert_eq!(i, expected.len());
            }

            #[test]
            fn test_from_iter() {
                let xs = [1, 2, 2, 3, 4, 5, 6, 7, 8, 9];

                let set: HashSet<_> = xs.iter().copied().collect();

                for x in &xs {
                    assert!(set.contains(x));
                }

                assert_eq!(set.iter().len(), xs.len() - 1);
            }

            #[test]
            fn test_move_iter() {
                let hs = {
                    let mut hs = HashSet::new();
                    hs.insert('a');
                    hs.insert('b');
                    hs
                };

                let v = hs.into_iter().collect::<Vec<char>>();
                assert!(v == ['a', 'b'] || v == ['b', 'a']);
            }

            #[test]
            fn test_eq() {
                let mut s1 = HashSet::new();
                s1.insert(1);
                s1.insert(2);
                s1.insert(3);

                let mut s2 = HashSet::new();
                s2.insert(1);
                s2.insert(2);

                assert!(s1 != s2);

                s2.insert(3);

                assert_eq!(s1, s2);
            }

            #[test]
            fn test_show() {
                let mut set = HashSet::new();
                let empty = HashSet::<i32>::new();

                set.insert(1);
                set.insert(2);

                let set_str = format!("{set:?}");

                assert!(set_str == "{1, 2}" || set_str == "{2, 1}");
                assert_eq!(format!("{empty:?}"), "{}");
            }

            #[test]
            fn test_trivial_drain() {
                let mut s = HashSet::<i32>::new();
                for _ in s.drain() {}
                assert!(s.is_empty());
                drop(s);

                let mut s = HashSet::<i32>::new();
                drop(s.drain());
                assert!(s.is_empty());
            }

            #[test]
            #[cfg_attr(miri, ignore)] // Repetitive drain parity loop is slow under Miri.
            fn test_drain() {
                let mut s: HashSet<_> = (1..100).collect();

                // try this a bunch of times to make sure we don't screw up internal state.
                for _ in 0..20 {
                    assert_eq!(s.len(), 99);

                    {
                        let mut last_i = 0;
                        let mut d = s.drain();
                        for (i, x) in d.by_ref().take(50).enumerate() {
                            last_i = i;
                            assert!(x != 0);
                        }
                        assert_eq!(last_i, 49);
                    }

                    if !s.is_empty() {
                        panic!("s should be empty!");
                    }

                    // reset to try again.
                    s.extend(1..100);
                }
            }

            #[test]
            fn test_replace() {
                use core::hash;

                #[derive(Debug)]
                #[expect(dead_code)]
                struct Foo(&'static str, i32);

                impl PartialEq for Foo {
                    fn eq(&self, other: &Self) -> bool {
                        self.0 == other.0
                    }
                }

                impl Eq for Foo {}

                impl hash::Hash for Foo {
                    fn hash<H: hash::Hasher>(&self, h: &mut H) {
                        self.0.hash(h);
                    }
                }

                let mut s = HashSet::new();
                assert_eq!(s.replace(Foo("a", 1)), None);
                assert_eq!(s.len(), 1);
                assert_eq!(s.replace(Foo("a", 2)), Some(Foo("a", 1)));
                assert_eq!(s.len(), 1);

                let mut it = s.iter();
                assert_eq!(it.next(), Some(&Foo("a", 2)));
                assert_eq!(it.next(), None);
            }

            #[test]
            fn test_extend_ref() {
                let mut a = HashSet::new();
                a.insert(1);

                a.extend([2, 3, 4]);

                assert_eq!(a.len(), 4);
                assert!(a.contains(&1));
                assert!(a.contains(&2));
                assert!(a.contains(&3));
                assert!(a.contains(&4));

                let mut b = HashSet::new();
                b.insert(5);
                b.insert(6);

                a.extend(&b);

                assert_eq!(a.len(), 6);
                assert!(a.contains(&1));
                assert!(a.contains(&2));
                assert!(a.contains(&3));
                assert!(a.contains(&4));
                assert!(a.contains(&5));
                assert!(a.contains(&6));
            }

            #[test]
            fn test_retain() {
                let xs = [1, 2, 3, 4, 5, 6];
                let mut set: HashSet<i32> = xs.iter().copied().collect();
                set.retain(|&k| k % 2 == 0);
                assert_eq!(set.len(), 3);
                assert!(set.contains(&2));
                assert!(set.contains(&4));
                assert!(set.contains(&6));
            }

            #[test]
            fn test_extract_if() {
                {
                    let mut set: HashSet<i32> = (0..8).collect();
                    let drained = set.extract_if(|&k| k % 2 == 0);
                    let mut out = drained.collect::<Vec<_>>();
                    out.sort_unstable();
                    assert_eq!(vec![0, 2, 4, 6], out);
                    assert_eq!(set.len(), 4);
                }
                {
                    let mut set: HashSet<i32> = (0..8).collect();
                    set.extract_if(|&k| k % 2 == 0).for_each(drop);
                    assert_eq!(set.len(), 4, "Retains non-matching items");
                }
            }

            #[test]
            fn test_with_custom_hasher() {
                // Adapted from hashbrown's `test_const_with_hasher`; opthash's
                // constructors are not `const fn`, so build at runtime.
                use core::hash::BuildHasher;
                use std::collections::hash_map::DefaultHasher;

                #[derive(Clone)]
                struct MyHasher;
                impl BuildHasher for MyHasher {
                    type Hasher = DefaultHasher;
                    fn build_hasher(&self) -> DefaultHasher {
                        DefaultHasher::new()
                    }
                }

                let mut set: HashSet<u32, MyHasher> = HashSet::with_hasher(MyHasher);
                set.insert(19);
                assert!(set.contains(&19));
            }

            #[test]
            fn collect() {
                // Exercises the ZST element case.
                let mut _set: HashSet<_> = (0..3).map(|_| ()).collect();
            }

            #[test]
            fn duplicate_insert() {
                let mut set = HashSet::new();
                set.insert(1);
                set.get_or_insert_with(&1, |_| 1);
                set.get_or_insert_with(&1, |_| 1);
                assert!([1].iter().eq(set.iter()));
            }

            #[test]
            fn entry_api() {
                // opthash-specific: hashbrown unit-tests the set `Entry` API only
                // via its map; cover the set wrapper directly here.
                let mut set: HashSet<&str> = HashSet::new();
                match set.entry("a") {
                    Entry::Occupied(_) => unreachable!(),
                    Entry::Vacant(v) => {
                        assert_eq!(v.get(), &"a");
                        v.insert();
                    }
                }
                assert!(set.contains("a"));

                match set.entry("a") {
                    Entry::Vacant(_) => unreachable!(),
                    Entry::Occupied(o) => {
                        assert_eq!(o.get(), &"a");
                        assert_eq!(o.remove(), "a");
                    }
                }
                assert!(!set.contains("a"));

                if let Entry::Vacant(v) = set.entry("b") {
                    assert_eq!(v.into_value(), "b");
                }
                assert!(set.is_empty());

                set.entry("c").or_insert();
                assert_eq!(set.entry("c").insert().get(), &"c");
                assert_eq!(set.len(), 1);
            }
        }
    };
}

set_suite!(elastic_set, ElasticHashSet, ElasticSetEntry);
set_suite!(funnel_set, FunnelHashSet, FunnelSetEntry);
