import pytest

import opthash


def test_elastic_with_options_defaults():
    m = opthash.ElasticHashMap.with_options()
    assert len(m) == 0
    m[1] = 2
    assert m[1] == 2


def test_elastic_with_options_custom_kwargs():
    m = opthash.ElasticHashMap.with_options(capacity=64, reserve_fraction=0.125)
    for i in range(50):
        m[i] = i * 2
    for i in range(50):
        assert m[i] == i * 2


def test_elastic_with_options_reject_invalid_reserve_fraction():
    with pytest.raises(ValueError):
        opthash.ElasticHashMap.with_options(reserve_fraction=2.0)
    with pytest.raises(ValueError):
        opthash.ElasticHashMap.with_options(reserve_fraction=0.0)
    with pytest.raises(ValueError):
        opthash.ElasticHashMap.with_options(reserve_fraction=-0.1)
    with pytest.raises(ValueError):
        opthash.ElasticHashMap.with_options(reserve_fraction=0.1)


def test_funnel_with_options_defaults():
    m = opthash.FunnelHashMap.with_options()
    assert len(m) == 0
    m["a"] = 1
    assert m["a"] == 1


def test_funnel_with_options_custom_kwargs():
    m = opthash.FunnelHashMap.with_options(capacity=128, reserve_fraction=0.0625)
    for i in range(100):
        m[f"k{i}"] = i
    for i in range(100):
        assert m[f"k{i}"] == i


def test_funnel_with_options_reject_invalid_reserve_fraction():
    with pytest.raises(ValueError):
        opthash.FunnelHashMap.with_options(reserve_fraction=1.0)
    with pytest.raises(ValueError):
        opthash.FunnelHashMap.with_options(reserve_fraction=0.5)  # above 1/8 cap
    with pytest.raises(ValueError):
        opthash.FunnelHashMap.with_options(reserve_fraction=0.0)
    with pytest.raises(ValueError):
        opthash.FunnelHashMap.with_options(reserve_fraction=-0.1)


def test_funnel_with_options_accept_max_reserve_fraction():
    m = opthash.FunnelHashMap.with_options(reserve_fraction=0.125)
    m["x"] = 1
    assert m["x"] == 1


@pytest.mark.parametrize("map_cls", [opthash.ElasticHashMap, opthash.FunnelHashMap])
def test_with_options_accepts_exact_reserve_exponent(map_cls):
    m = map_cls.with_options(capacity=64, reserve_exponent=4)
    m["x"] = 1
    assert m["x"] == 1


@pytest.mark.parametrize("map_cls", [opthash.ElasticHashMap, opthash.FunnelHashMap])
def test_with_options_rejects_two_reserve_representations(map_cls):
    with pytest.raises(ValueError):
        map_cls.with_options(reserve_fraction=0.125, reserve_exponent=3)
