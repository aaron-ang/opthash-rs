import pytest

import opthash


def test_elastic_with_options_defaults():
    m = opthash.ElasticHashMap.with_options()
    assert len(m) == 0
    m[1] = 2
    assert m[1] == 2


def test_elastic_with_options_custom_kwargs():
    m = opthash.ElasticHashMap.with_options(capacity=64, reserve_exponent=3)
    for i in range(50):
        m[i] = i * 2
    for i in range(50):
        assert m[i] == i * 2


def test_funnel_with_options_defaults():
    m = opthash.FunnelHashMap.with_options()
    assert len(m) == 0
    m["a"] = 1
    assert m["a"] == 1


def test_funnel_with_options_custom_kwargs():
    m = opthash.FunnelHashMap.with_options(capacity=128, reserve_exponent=4)
    for i in range(100):
        m[f"k{i}"] = i
    for i in range(100):
        assert m[f"k{i}"] == i


@pytest.mark.parametrize("map_cls", [opthash.ElasticHashMap, opthash.FunnelHashMap])
def test_with_options_accepts_exact_reserve_exponent(map_cls):
    m = map_cls.with_options(capacity=64, reserve_exponent=4)
    m["x"] = 1
    assert m["x"] == 1


@pytest.mark.parametrize("map_cls", [opthash.ElasticHashMap, opthash.FunnelHashMap])
def test_with_options_rejects_removed_reserve_fraction(map_cls):
    with pytest.raises(TypeError, match="reserve_fraction"):
        map_cls.with_options(reserve_fraction=0.125)
