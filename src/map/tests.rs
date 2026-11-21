use alloc::collections::BTreeMap;

use super::{HashMap, TableBackend};
use crate::FunnelHashMap;
use crate::test_support::{Deterministic, FixedElasticHashMap, FixedHashBuilder};

/// Keys inserted. Fewer under Miri, where each lookup is slow; still enough
/// for the maps to grow and to hold tombstones.
const KEYS: u64 = if cfg!(miri) { 96 } else { 600 };

/// Every keyed lookup and removal answers alike through the public function,
/// which takes the form the backend selects, and through the by-call form:
/// on an empty map, over hits, misses and removed keys, and after the
/// removed keys are inserted again. `in_caller` is the form the backend is
/// expected to select.
fn assert_forms_agree<P>(
    mut public: HashMap<u64, u64, P>,
    mut by_call: HashMap<u64, u64, P>,
    in_caller: bool,
) where
    P: TableBackend<u64, u64>,
{
    assert_eq!(P::LOOKUP_IN_CALLER, in_caller);
    let mut model = BTreeMap::new();
    assert_lookups_agree(&mut public, &mut by_call, &model);
    for key in 0..KEYS {
        public.insert(key, key * 3);
        by_call.insert(key, key * 3);
        model.insert(key, key * 3);
    }
    for key in (0..KEYS * 2).step_by(3) {
        let expected = model.remove(&key);
        if key % 2 == 0 {
            assert_eq!(public.remove(&key), expected);
            assert_eq!(by_call.remove_by_call(&key), expected);
        } else {
            let expected = expected.map(|value| (key, value));
            assert_eq!(public.remove_entry(&key), expected);
            assert_eq!(by_call.remove_entry_by_call(&key), expected);
        }
    }
    assert_lookups_agree(&mut public, &mut by_call, &model);
    // The removed keys come back into a table that holds their tombstones.
    for key in (0..KEYS).step_by(3) {
        public.insert(key, key + 1);
        by_call.insert(key, key + 1);
        model.insert(key, key + 1);
    }
    assert_lookups_agree(&mut public, &mut by_call, &model);
}

/// Looks every key of the universe up in every form, and writes through
/// each mutable reference: `public` through the public form and `by_call`
/// through the other, so each map's later answers show its own writes.
fn assert_lookups_agree<P>(
    public: &mut HashMap<u64, u64, P>,
    by_call: &mut HashMap<u64, u64, P>,
    model: &BTreeMap<u64, u64>,
) where
    P: TableBackend<u64, u64>,
{
    assert_eq!(public.len(), model.len());
    assert_eq!(by_call.len(), model.len());
    for key in 0..KEYS * 2 {
        let expected = model.get(&key);
        assert_eq!(public.get(&key), expected);
        assert_eq!(public.get_by_call(&key), expected);
        assert_eq!(public.get_in_place(&key), expected);
        let pair = model.get_key_value(&key);
        assert_eq!(public.get_key_value(&key), pair);
        assert_eq!(public.get_key_value_by_call(&key), pair);
        assert_eq!(public.get_key_value_in_place(&key), pair);
        assert_eq!(public.contains_key(&key), expected.is_some());
        assert_eq!(public.contains_key_by_call(&key), expected.is_some());
        assert_eq!(public.contains_key_in_place(&key), expected.is_some());
        if let Some(value) = public.get_mut(&key) {
            *value += 1;
        }
        if let Some(value) = by_call.get_mut_by_call(&key) {
            *value += 1;
        }
        let written = expected.map(|value| value + 1);
        assert_eq!(public.get(&key).copied(), written);
        assert_eq!(by_call.get_by_call(&key).copied(), written);
        if let Some(value) = public.get_mut_by_call(&key) {
            *value -= 1;
        }
        if let Some(value) = by_call.get_mut(&key) {
            *value -= 1;
        }
        assert_eq!(public.get(&key), expected);
        assert_eq!(by_call.get(&key), expected);
    }
}

#[test]
fn keyed_forms_agree_when_the_backend_looks_up_in_the_caller() {
    type Map = FunnelHashMap<u64, u64, FixedHashBuilder>;
    assert_forms_agree(Map::with_capacity(0), Map::with_capacity(0), true);
}

#[test]
fn keyed_forms_agree_when_the_backend_looks_up_by_call() {
    type Map = FixedElasticHashMap<u64, u64>;
    assert_forms_agree(Map::with_capacity(0), Map::with_capacity(0), false);
}
