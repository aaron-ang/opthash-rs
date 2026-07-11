import collections.abc as abc

import pytest

import opthash

SET_CLASSES = [opthash.ElasticHashSet, opthash.FunnelHashSet]


@pytest.fixture(params=SET_CLASSES, ids=["elastic", "funnel"])
def set_cls(request):
    return request.param


def test_registered_as_mutable_set(set_cls):
    assert issubclass(set_cls, abc.MutableSet)
    assert isinstance(set_cls(), abc.MutableSet)


def test_construct_from_iterable_and_same_class(set_cls):
    s = set_cls([1, 2, 2, 3])
    assert len(s) == 3
    assert set(s) == {1, 2, 3}
    assert set(set_cls(s)) == {1, 2, 3}
    assert set(set_cls()) == set()


def test_unhashable_elements_raise_type_error(set_cls):
    s = set_cls()
    with pytest.raises(TypeError):
        s.add([1])
    with pytest.raises(TypeError):
        set_cls([[1]])
    with pytest.raises(TypeError):
        [1] in s


def test_options_validation(set_cls):
    assert len(set_cls.with_options(capacity=8)) == 0
    assert len(set_cls.with_options(delta_log2=4)) == 0
    with pytest.raises(ValueError):
        set_cls.with_options(reserve_fraction=0.0)
    with pytest.raises(ValueError):
        set_cls.with_options(reserve_fraction=1.5)
    with pytest.raises(ValueError):
        set_cls.with_options(reserve_fraction=0.125, delta_log2=3)


def test_add_discard_remove_membership(set_cls):
    s = set_cls()
    s.add(1)
    s.add(1)
    assert len(s) == 1 and 1 in s
    s.discard(2)  # absent: no error
    s.add(2)
    s.discard(2)
    assert 2 not in s
    s.remove(1)
    assert 1 not in s
    with pytest.raises(KeyError):
        s.remove(1)


def test_pop_and_clear(set_cls):
    s = set_cls([1, 2, 3])
    popped = {s.pop(), s.pop(), s.pop()}
    assert popped == {1, 2, 3}
    assert len(s) == 0
    with pytest.raises(KeyError):
        s.pop()
    s2 = set_cls([1, 2])
    s2.clear()
    assert len(s2) == 0


def test_copy_is_independent(set_cls):
    s = set_cls([1, 2, 3])
    c = s.copy()
    assert c is not s
    assert set(c) == set(s)
    c.add(4)
    assert 4 not in s


def test_equality(set_cls):
    assert set_cls([1, 2, 3]) == set_cls([3, 2, 1])
    assert set_cls([1, 2, 3]) == {1, 2, 3}
    assert set_cls([1, 2]) != set_cls([1, 3])
    assert set_cls([1, 2]) != [1, 2]  # never equal to a non-set
    assert set_cls([1, 2]) != {1, 2, 3}


def test_subset_superset_disjoint(set_cls):
    s = set_cls([1, 2, 3])
    assert s.issubset([1, 2, 3, 4])
    assert not s.issubset([1, 2])
    assert s.issuperset([1, 2])
    assert not s.issuperset([1, 2, 5])
    assert s.isdisjoint([7, 8])
    assert not s.isdisjoint([3, 9])


@pytest.mark.parametrize(
    "method, expected",
    [
        ("union", {1, 2, 3, 4, 5, 6}),
        ("intersection", {3, 4}),
        ("difference", {1, 2}),
        ("symmetric_difference", {1, 2, 5, 6}),
    ],
)
def test_algebra_methods(set_cls, method, expected):
    a = set_cls([1, 2, 3, 4])
    b = [3, 4, 5, 6]
    result = getattr(a, method)(b)
    assert isinstance(result, set_cls)  # left-backend result type
    assert set(result) == expected


def test_variadic_algebra(set_cls):
    a = set_cls([1, 2, 3, 4])
    assert set(a.union([5], [6])) == {1, 2, 3, 4, 5, 6}
    assert set(a.intersection([2, 3, 4], [3, 4, 9])) == {3, 4}
    assert set(a.difference([1], [2])) == {3, 4}


def test_operators_result_type_and_value(set_cls):
    a = set_cls([1, 2, 3, 4])
    b = set_cls([3, 4, 5, 6])
    for op, expected in [
        (lambda: a | b, {1, 2, 3, 4, 5, 6}),
        (lambda: a & b, {3, 4}),
        (lambda: a - b, {1, 2}),
        (lambda: a ^ b, {1, 2, 5, 6}),
    ]:
        result = op()
        assert isinstance(result, set_cls)
        assert set(result) == expected


def test_reflected_operators_with_builtin_set(set_cls):
    a = set_cls([1, 2, 3])
    assert set({4, 5} | a) == {1, 2, 3, 4, 5}
    assert set({2, 3, 4} & a) == {2, 3}
    assert set({2, 3, 9} - a) == {9}
    assert set({3, 4} ^ a) == {1, 2, 4}


def test_in_place_updates(set_cls):
    s = set_cls([1, 2, 3])
    s |= set_cls([3, 4])
    assert set(s) == {1, 2, 3, 4}
    s &= [2, 3, 4]
    assert set(s) == {2, 3, 4}
    s -= [2]
    assert set(s) == {3, 4}
    s ^= [4, 5]
    assert set(s) == {3, 5}


def test_named_in_place_updates(set_cls):
    s = set_cls([1, 2, 3])
    s.update([3, 4], [5])
    assert set(s) == {1, 2, 3, 4, 5}
    s.intersection_update([2, 3, 4, 5])
    assert set(s) == {2, 3, 4, 5}
    s.difference_update([2])
    assert set(s) == {3, 4, 5}
    s.symmetric_difference_update([5, 6])
    assert set(s) == {3, 4, 6}


def test_symmetric_difference_uniqueifies_iterable_input(set_cls):
    assert set(set_cls().symmetric_difference([1, 1])) == {1}

    s = set_cls()
    s.symmetric_difference_update([1, 1])
    assert set(s) == {1}


def test_iterator_mutation_detection(set_cls):
    s = set_cls([1, 2, 3, 4, 5])
    with pytest.raises(RuntimeError, match="changed size during iteration"):
        for _ in s:
            s.add(99)


def test_repr(set_cls):
    s = set_cls([1])
    assert repr(s).startswith(set_cls.__name__)
