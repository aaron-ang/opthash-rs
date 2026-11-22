//! Parity tests ported from `hashbrown-0.17/src/set.rs::test_set`, run via
//! macro against both `ElasticHashSet` and `FunnelHashSet`.
//!
//! Tests for APIs opthash lacks (`From<HashMap>`, `allocation_size`, const
//! constructors, hashbrown-internal `Equivalent` debug asserts) and ones that
//! assert hashbrown-specific capacity growth (`rehash_in_place`) are omitted.

mod support;

macro_rules! set_suite {
    ($mod_name:ident, $TestSet:ident, $Entry:ident) => {
        mod $mod_name {
            use crate::support::{Deterministic, $TestSet as HashSet};
            use core::cell::Cell;
            use core::hash::{Hash, Hasher};
            use opthash::DefaultHashBuilder;
            use opthash::$Entry as Entry;
            use std::collections::BTreeSet;

            #[test]
            fn test_zero_capacities() {
                // Default-hasher constructor surface; no key is hashed here.
                type HS = opthash::$TestSet<i32>;

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

                let mut s = HashSet::new();
                s.insert(1);
                s.insert(2);
                s.remove(&1);
                s.remove(&2);
                s.shrink_to_fit();
                assert_eq!(s.capacity(), 0);

                let mut s: HashSet<i32> = HashSet::new();
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

                let mut single = HashSet::new();
                single.insert(1);
                assert_eq!(format!("{:?}", single.clone().drain()), "[1]");
                let mut into_iter = single.into_iter();
                assert_eq!(format!("{into_iter:?}"), "[1]");
                into_iter.next();
                assert_eq!(format!("{into_iter:?}"), "[]");
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
            #[cfg_attr(miri, ignore = "repetitive drain parity loop is too slow")]
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
            fn test_replace_among_removals() {
                use core::hash;

                #[derive(Debug)]
                struct Tagged(u32, u32);

                impl PartialEq for Tagged {
                    fn eq(&self, other: &Self) -> bool {
                        self.0 == other.0
                    }
                }

                impl Eq for Tagged {}

                impl hash::Hash for Tagged {
                    fn hash<H: hash::Hasher>(&self, h: &mut H) {
                        self.0.hash(h);
                    }
                }

                const KEYS: u32 = 2_000;
                let mut s = HashSet::new();
                for id in 0..KEYS {
                    assert!(s.insert(Tagged(id, 0)));
                }
                for id in (0..KEYS).step_by(3) {
                    assert!(s.remove(&Tagged(id, 0)));
                }
                for id in 0..KEYS {
                    let displaced = s.replace(Tagged(id, 1));
                    if id % 3 == 0 {
                        assert!(displaced.is_none(), "id {id}");
                    } else {
                        assert_eq!(displaced.map(|old| old.1), Some(0), "id {id}");
                    }
                }
                assert_eq!(s.len(), KEYS as usize);
                for id in 0..KEYS {
                    assert_eq!(s.get(&Tagged(id, 0)).map(|kept| kept.1), Some(1));
                }
                assert!(s.iter().all(|kept| kept.1 == 1));
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

                let mut set: opthash::$TestSet<u32, MyHasher> =
                    opthash::$TestSet::with_hasher(MyHasher);
                set.insert(19);
                assert!(set.contains(&19));
            }

            /// A value that counts how often the calling thread hashes one.
            #[derive(Clone, Copy, PartialEq, Eq)]
            struct Counted(u32);

            thread_local! {
                static HASHES: Cell<usize> = const { Cell::new(0) };
            }

            impl Hash for Counted {
                fn hash<H: Hasher>(&self, state: &mut H) {
                    HASHES.set(HASHES.get() + 1);
                    self.0.hash(state);
                }
            }

            fn hashes_during(run: impl FnOnce()) -> usize {
                let before = HASHES.get();
                run();
                HASHES.get() - before
            }

            /// Pairs of operands: disjoint, overlapping, nested, equal and
            /// empty, the longer one on either side.
            fn operand_pairs() -> Vec<(Vec<u32>, Vec<u32>)> {
                let ranges = [
                    (0..0, 0..0),
                    (0..5, 0..0),
                    (0..5, 5..9),
                    (0..5, 3..12),
                    (0..40, 10..13),
                    (0..7, 0..7),
                    (0..7, 3..10),
                ];
                ranges
                    .into_iter()
                    .flat_map(|(left, right)| {
                        let (left, right): (Vec<u32>, Vec<u32>) = (left.collect(), right.collect());
                        [(left.clone(), right.clone()), (right, left)]
                    })
                    .collect()
            }

            fn sorted<T: Ord>(values: impl IntoIterator<Item = T>) -> Vec<T> {
                let mut values: Vec<T> = values.into_iter().collect();
                values.sort_unstable();
                values
            }

            #[test]
            fn operators_match_the_ordered_set_operators() {
                type Assign = (fn(&mut HashSet<u32>, &HashSet<u32>), BTreeSet<u32>);
                for (left, right) in operand_pairs() {
                    let (a, b): (HashSet<u32>, HashSet<u32>) = (
                        left.iter().copied().collect(),
                        right.iter().copied().collect(),
                    );
                    let (x, y): (BTreeSet<u32>, BTreeSet<u32>) = (
                        left.iter().copied().collect(),
                        right.iter().copied().collect(),
                    );

                    assert_eq!(sorted(&a | &b), sorted(&x | &y), "{left:?} | {right:?}");
                    assert_eq!(sorted(&a & &b), sorted(&x & &y), "{left:?} & {right:?}");
                    assert_eq!(sorted(&a ^ &b), sorted(&x ^ &y), "{left:?} ^ {right:?}");
                    assert_eq!(sorted(&a - &b), sorted(&x - &y), "{left:?} - {right:?}");

                    let assigns: [Assign; 4] = [
                        (|a, b| *a |= b, &x | &y),
                        (|a, b| *a &= b, &x & &y),
                        (|a, b| *a ^= b, &x ^ &y),
                        (|a, b| *a -= b, &x - &y),
                    ];
                    for (index, (assign, expected)) in assigns.into_iter().enumerate() {
                        let mut assigned = a.clone();
                        assign(&mut assigned, &b);
                        assert_eq!(
                            sorted(assigned),
                            sorted(expected),
                            "operator {index} of {left:?} and {right:?}"
                        );
                    }
                    // The compound assignments worked on clones; the operands are unchanged.
                    assert_eq!(sorted(a), left);
                    assert_eq!(sorted(b), right);
                }
            }

            #[test]
            fn set_operations_look_up_only_the_shorter_operand() {
                let long: HashSet<Counted> = (0..64).map(Counted).collect();
                let short: HashSet<Counted> = (60..63).map(Counted).collect();
                for (a, b) in [(&long, &short), (&short, &long)] {
                    let hashes = hashes_during(|| assert_eq!(a.intersection(b).count(), 3));
                    assert_eq!(hashes, short.len(), "intersection");
                    let hashes = hashes_during(|| assert_eq!(a.union(b).count(), 64));
                    assert_eq!(hashes, short.len(), "union");
                }

                let mut left = long.clone();
                let hashes = hashes_during(|| left -= &short);
                assert_eq!(hashes, short.len());
                assert_eq!(left.len(), 61);
                let mut left = short.clone();
                let hashes = hashes_during(|| left -= &long);
                assert_eq!(hashes, short.len());
                assert!(left.is_empty());
            }

            #[test]
            fn capacity_calls_reach_the_table() {
                let mut set: HashSet<u32> = HashSet::new();
                let mut model = BTreeSet::new();
                assert!(set.is_empty());
                set.reserve(100);
                assert!(set.capacity() >= 100);
                for value in 0..10 {
                    assert_eq!(set.insert(value), model.insert(value));
                    assert_eq!(set.is_empty(), model.is_empty());
                }

                let reserved = set.capacity();
                assert_eq!(set.try_reserve(4 * reserved), Ok(()));
                let grown = set.capacity();
                assert!(grown >= set.len() + 4 * reserved);
                assert!(set.try_reserve(usize::MAX).is_err());
                assert_eq!(set.capacity(), grown);

                set.shrink_to(reserved);
                assert!((reserved..grown).contains(&set.capacity()));
                assert_eq!(sorted(set.iter().copied()), sorted(model.iter().copied()));

                set.clear();
                model.clear();
                assert_eq!(set.len(), model.len());
                assert!(set.is_empty());
                assert!(!set.contains(&3));
                assert!(set.insert(3));
            }

            #[test]
            fn default_hasher_constructors_keep_their_reserve() {
                // Default-hasher constructor surface; no value is hashed here.
                type HS = opthash::$TestSet<i32>;
                let reserve = opthash::ReserveFraction::from_exponent(4).unwrap();
                assert_ne!(reserve, opthash::ReserveFraction::default());
                assert_eq!(HS::with_reserve(reserve).reserve_fraction(), reserve);
                assert_eq!(
                    HS::with_capacity_and_reserve(100, reserve).reserve_fraction(),
                    reserve
                );
                assert!(HS::with_capacity_and_reserve(100, reserve).capacity() >= 100);
            }

            #[test]
            fn from_array_holds_each_distinct_value() {
                let values = [4, 1, 4, 9, 1, 7];
                let set = <HashSet<i32>>::from(values);
                assert_eq!(sorted(set), sorted(BTreeSet::from(values)));
            }

            #[test]
            fn extract_if_size_hint_is_unbounded_and_the_filter_decides_the_count() {
                type Keep = fn(u32) -> bool;
                let keeps: [(Keep, usize); 3] =
                    [(|_| false, 0), (|value| value % 2 == 0, 20), (|_| true, 40)];
                for (extract, expected) in keeps {
                    let mut set: HashSet<u32> = (0..40).collect();
                    let mut extracted = set.extract_if(|value| extract(*value));
                    let mut yielded = 0;
                    loop {
                        assert_eq!(extracted.size_hint(), (0, None));
                        if extracted.next().is_none() {
                            break;
                        }
                        yielded += 1;
                    }
                    assert_eq!(yielded, expected);
                    drop(extracted);
                    assert_eq!(set.len(), 40 - expected);
                }
            }

            #[test]
            fn entry_or_insert_adds_only_an_absent_value() {
                let mut set: HashSet<&str> = HashSet::new();
                let mut model = BTreeSet::new();
                for value in ["a", "b", "a", "c", "b"] {
                    set.entry(value).or_insert();
                    model.insert(value);
                    assert!(set.contains(value));
                    assert_eq!(set.len(), model.len());
                }
            }

            #[test]
            fn set_equality_follows_the_values() {
                let model = BTreeSet::from([1, 2, 3]);
                let base: HashSet<i32> = model.iter().copied().collect();
                for other in [vec![1, 2, 4], vec![1, 2], vec![1, 2, 3, 4], vec![3, 1, 2]] {
                    let theirs: BTreeSet<i32> = other.iter().copied().collect();
                    let ours: HashSet<i32> = other.into_iter().collect();
                    assert_eq!(base == ours, model == theirs);
                    assert_eq!(ours == base, model == theirs);
                }
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
