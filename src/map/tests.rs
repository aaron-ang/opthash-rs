use alloc::collections::BTreeMap;

use super::{HashMap, TableBackend};
use crate::FunnelHashMap;
use crate::test_support::{Deterministic, FixedElasticHashMap, FixedHashBuilder};

const KEYS: u64 = 600;

/// Every keyed lookup and removal answers alike in both of its forms,
/// whichever one the backend selects, over hits, misses and removed keys.
fn assert_forms_agree<P>(mut public: HashMap<u64, u64, P>, mut by_call: HashMap<u64, u64, P>)
where
    P: TableBackend<u64, u64>,
{
    let mut model = BTreeMap::new();
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
    assert_eq!(public.len(), model.len());
    assert_eq!(by_call.len(), model.len());
    for key in 0..KEYS * 2 {
        let expected = model.get(&key);
        assert_eq!(public.get(&key), expected);
        assert_eq!(public.get_by_call(&key), expected);
        let pair = model.get_key_value(&key);
        assert_eq!(public.get_key_value(&key), pair);
        assert_eq!(public.get_key_value_by_call(&key), pair);
        assert_eq!(public.contains_key(&key), expected.is_some());
        assert_eq!(public.contains_key_by_call(&key), expected.is_some());
        let mut value = expected.copied();
        assert_eq!(public.get_mut(&key).copied(), value);
        assert_eq!(by_call.get_mut_by_call(&key), value.as_mut());
    }
}

#[test]
fn keyed_forms_agree_when_the_backend_looks_up_in_the_caller() {
    type Map = FunnelHashMap<u64, u64, FixedHashBuilder>;
    assert_forms_agree(Map::with_capacity(0), Map::with_capacity(0));
}

#[test]
fn keyed_forms_agree_when_the_backend_looks_up_by_call() {
    type Map = FixedElasticHashMap<u64, u64>;
    assert_forms_agree(Map::with_capacity(0), Map::with_capacity(0));
}
