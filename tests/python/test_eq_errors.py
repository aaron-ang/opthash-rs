import pytest


class Key:
    """Collides with every other `Key`; `__eq__` raises once armed."""

    armed = False

    def __hash__(self):
        return 1

    def __eq__(self, other):
        if Key.armed:
            raise ValueError("eq")
        return self is other


@pytest.fixture
def keys():
    Key.armed = False
    stored, probe = Key(), Key()
    yield stored, probe
    Key.armed = False


def arm():
    Key.armed = True


@pytest.mark.parametrize(
    "op",
    [
        lambda m, k: k in m,
        lambda m, k: m[k],
        lambda m, k: m.get(k),
        lambda m, k: m.pop(k),
        lambda m, k: m.__delitem__(k),
        lambda m, k: m.setdefault(k, 2),
        lambda m, k: m.__setitem__(k, 2),
        lambda m, k: m.update({k: 2}),
        lambda m, k: m.update([(k, 2)]),
        lambda m, k: k in m.keys(),
        lambda m, k: (k, 1) in m.items(),
    ],
)
def test_map_ops_raise_and_change_nothing(map_cls, keys, op):
    stored, probe = keys
    m = map_cls({stored: 1})
    arm()
    with pytest.raises(ValueError, match="eq"):
        op(m, probe)
    Key.armed = False
    assert list(m.items()) == [(stored, 1)]


def test_map_update_from_same_type_raises(map_cls, keys):
    stored, probe = keys
    m, other = map_cls({stored: 1}), map_cls({probe: 2})
    arm()
    with pytest.raises(ValueError, match="eq"):
        m.update(other)
    with pytest.raises(ValueError, match="eq"):
        m == map_cls({probe: 1})


def test_map_value_comparisons_raise(map_cls, keys):
    stored, probe = keys
    m = map_cls({"a": stored})
    arm()
    with pytest.raises(ValueError, match="eq"):
        m == map_cls({"a": probe})
    with pytest.raises(ValueError, match="eq"):
        m == {"a": probe}
    with pytest.raises(ValueError, match="eq"):
        probe in m.values()
    with pytest.raises(ValueError, match="eq"):
        ("a", probe) in m.items()


@pytest.mark.parametrize(
    "op",
    [
        lambda s, k, cls: k in s,
        lambda s, k, cls: s.add(k),
        lambda s, k, cls: s.discard(k),
        lambda s, k, cls: s.remove(k),
        lambda s, k, cls: s.update([k]),
        lambda s, k, cls: s.update(cls([k])),
        lambda s, k, cls: s.difference_update(cls([k])),
        lambda s, k, cls: s.symmetric_difference_update(cls([k])),
        lambda s, k, cls: s.intersection_update(cls([k])),
        lambda s, k, cls: s.__iand__(cls([k])),
        lambda s, k, cls: s.issubset(cls([k])),
        lambda s, k, cls: s.issuperset(cls([k])),
        lambda s, k, cls: s.isdisjoint(cls([k])),
        lambda s, k, cls: s == cls([k]),
        lambda s, k, cls: s.issuperset([k]),
    ],
)
def test_set_ops_raise_and_change_nothing(set_cls, keys, op):
    stored, probe = keys
    s = set_cls([stored])
    arm()
    with pytest.raises(ValueError, match="eq"):
        op(s, probe, set_cls)
    Key.armed = False
    assert list(s) == [stored]


def test_copies_of_distinct_keys_do_not_compare(map_cls, set_cls, keys):
    stored, probe = keys
    d = {stored: 1, probe: 2}
    m = map_cls(d)
    s, plain = set_cls([stored, probe]), {stored, probe}
    arm()
    assert len(m.copy()) == len(m | {}) == len(map_cls(m)) == len(map_cls(d)) == 2
    assert len(s.copy()) == len(set_cls(s)) == len(set_cls(plain)) == 2


@pytest.mark.parametrize(
    "op",
    [
        lambda m, k: m.__delitem__(k),
        lambda m, k: m.pop(k),
        lambda m, k: m.__setitem__(k, 3),
        lambda m, k: m.update({k: 3}),
    ],
)
def test_map_op_on_key_behind_raising_key_changes_nothing(map_cls, keys, op):
    first, second = keys
    m = map_cls({first: 1, second: 2})
    it = iter(m)
    arm()
    with pytest.raises(ValueError, match="eq"):
        op(m, second)
    Key.armed = False
    assert dict(m.items()) == {first: 1, second: 2}
    assert next(it) in (first, second)


@pytest.mark.parametrize(
    "op",
    [
        lambda s, k, cls: s.discard(k),
        lambda s, k, cls: s.remove(k),
        lambda s, k, cls: s.difference_update([k]),
        lambda s, k, cls: s.difference_update(cls([k])),
        lambda s, k, cls: s.symmetric_difference_update([k]),
    ],
)
def test_set_op_on_element_behind_raising_element_changes_nothing(set_cls, keys, op):
    first, second = keys
    s = set_cls([first, second])
    it = iter(s)
    arm()
    with pytest.raises(ValueError, match="eq"):
        op(s, second, set_cls)
    Key.armed = False
    assert set(s) == {first, second}
    assert next(it) in (first, second)
