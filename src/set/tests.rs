use alloc::collections::BTreeSet;

use super::HashSet;
use crate::map::TableBackend;
use crate::test_support::{FixedHashBuilder, fixed_hasher};
use crate::{ElasticHashSet, FunnelHashSet};

/// Values inserted. Fewer under Miri, where each lookup is slow; still
/// enough for the sets to grow and to hold tombstones.
const VALUES: u64 = if cfg!(miri) { 96 } else { 600 };

/// `contains`, `get`, `insert`, `remove` and `take` answer alike through the
/// public function, which takes the form the backend selects, and through
/// the by-call form: on an empty set, over present, absent and removed
/// values, and after the removed values are inserted again. `in_caller` is
/// the form the backend is expected to select.
fn assert_forms_agree<P>(mut public: HashSet<u64, P>, mut by_call: HashSet<u64, P>, in_caller: bool)
where
    P: TableBackend<u64, ()>,
{
    assert_eq!(P::LOOKUP_IN_CALLER, in_caller);
    let mut model = BTreeSet::new();
    assert_lookups_agree(&public, &by_call, &model);
    for value in 0..VALUES {
        let added = model.insert(value);
        assert_eq!(public.insert(value), added);
        assert_eq!(by_call.insert_by_call(value), added);
    }
    for value in (0..VALUES * 2).step_by(3) {
        if value % 2 == 0 {
            let removed = model.remove(&value);
            assert_eq!(public.remove(&value), removed);
            assert_eq!(by_call.remove_by_call(&value), removed);
        } else {
            let taken = model.take(&value);
            assert_eq!(public.take(&value), taken);
            assert_eq!(by_call.take_by_call(&value), taken);
        }
    }
    assert_lookups_agree(&public, &by_call, &model);
    // Half the universe comes back: values still present, and removed ones
    // into a table that holds their tombstones.
    for value in 0..VALUES {
        let added = model.insert(value);
        assert_eq!(public.insert(value), added);
        assert_eq!(by_call.insert_by_call(value), added);
    }
    assert_lookups_agree(&public, &by_call, &model);
}

/// Looks every value of the universe up in every form.
fn assert_lookups_agree<P>(
    public: &HashSet<u64, P>,
    by_call: &HashSet<u64, P>,
    model: &BTreeSet<u64>,
) where
    P: TableBackend<u64, ()>,
{
    assert_eq!(public.len(), model.len());
    assert_eq!(by_call.len(), model.len());
    for value in 0..VALUES * 2 {
        let expected = model.get(&value);
        assert_eq!(public.contains(&value), expected.is_some());
        assert_eq!(by_call.contains_by_call(&value), expected.is_some());
        assert_eq!(by_call.contains_in_place(&value), expected.is_some());
        assert_eq!(public.get(&value), expected);
        assert_eq!(by_call.get_by_call(&value), expected);
        assert_eq!(by_call.get_in_place(&value), expected);
    }
}

#[test]
fn set_forms_agree_when_the_backend_looks_up_in_the_caller() {
    type Set = FunnelHashSet<u64, FixedHashBuilder>;
    let set = || Set::with_capacity_and_hasher(0, fixed_hasher());
    assert_forms_agree(set(), set(), true);
}

#[test]
fn set_forms_agree_when_the_backend_looks_up_by_call() {
    type Set = ElasticHashSet<u64, FixedHashBuilder>;
    let set = || Set::with_capacity_and_hasher(0, fixed_hasher());
    assert_forms_agree(set(), set(), false);
}
