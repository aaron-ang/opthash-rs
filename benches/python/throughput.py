"""Python-side pytest-benchmark suite: opthash maps vs builtin dict.

Run:
    uv run pytest benches/python/throughput.py --benchmark-json=.benchmarks/python.json

The raw benchmark result is written to .benchmarks/python.json.
"""

import random

import pytest

import opthash


N = 20_000
TINY_N = 32
TINY_QUERIES = 20_000
RESIZE_N = 8_000
SEED = 42


def _factory_dict(_n: int):
    return dict()


def _factory_elastic(n: int):
    return opthash.ElasticHashMap(capacity=n)


def _factory_funnel(n: int):
    return opthash.FunnelHashMap(capacity=n)


IMPLS = [
    pytest.param(_factory_dict, id="dict"),
    pytest.param(_factory_elastic, id="elastic"),
    pytest.param(_factory_funnel, id="funnel"),
]


@pytest.fixture(scope="module")
def keys() -> list[str]:
    return [f"key_{i}" for i in range(N)]


@pytest.fixture(scope="module")
def miss_keys() -> list[str]:
    return [f"miss_{i}" for i in range(N)]


@pytest.fixture(scope="module")
def mixed_indices() -> list[int]:
    rng = random.Random(SEED)
    return [rng.randrange(N) for _ in range(N)]


@pytest.fixture(scope="module")
def tiny_keys() -> list[str]:
    return [f"tkey_{i}" for i in range(TINY_N)]


@pytest.fixture(scope="module")
def tiny_query_keys(tiny_keys) -> list[str]:
    out: list[str] = []
    for idx in range(TINY_QUERIES):
        if idx % 2 == 0:
            out.append(tiny_keys[idx % TINY_N])
        else:
            out.append(f"tmiss_{idx}")
    return out


@pytest.fixture(scope="module")
def resize_keys() -> list[str]:
    return [f"rkey_{i}" for i in range(RESIZE_N)]


@pytest.mark.benchmark(group="insert")
@pytest.mark.parametrize("factory", IMPLS)
def test_insert(benchmark, factory, keys):
    def run():
        m = factory(N)
        for k in keys:
            m[k] = 0

    benchmark(run)


@pytest.mark.benchmark(group="get_hit")
@pytest.mark.parametrize("factory", IMPLS)
def test_get_hit(benchmark, factory, keys):
    m = factory(N)
    for k in keys:
        m[k] = 0

    def run():
        for k in keys:
            _ = m[k]

    benchmark(run)


@pytest.mark.benchmark(group="get_miss")
@pytest.mark.parametrize("factory", IMPLS)
def test_get_miss(benchmark, factory, keys, miss_keys):
    m = factory(N)
    for k in keys:
        m[k] = 0

    def run():
        for k in miss_keys:
            _ = m.get(k)

    benchmark(run)


@pytest.mark.benchmark(group="mixed")
@pytest.mark.parametrize("factory", IMPLS)
def test_mixed(benchmark, factory, keys, mixed_indices):
    m = factory(N)
    for k in keys:
        m[k] = 0

    def run():
        for i in mixed_indices:
            k = keys[i]
            if i & 1:
                m[k] = i
            else:
                _ = m[k]

    benchmark(run)


@pytest.mark.benchmark(group="delete")
@pytest.mark.parametrize("factory", IMPLS)
def test_delete(benchmark, factory, keys):
    def run():
        m = factory(N)
        for k in keys:
            m[k] = 0
        for k in keys:
            del m[k]

    benchmark(run)


@pytest.mark.benchmark(group="tiny_lookup")
@pytest.mark.parametrize("factory", IMPLS)
def test_tiny_lookup(benchmark, factory, tiny_keys, tiny_query_keys):
    m = factory(TINY_N)
    for k in tiny_keys:
        m[k] = 0

    def run():
        for k in tiny_query_keys:
            _ = m.get(k)

    benchmark(run)


@pytest.mark.benchmark(group="resize")
@pytest.mark.parametrize("factory", IMPLS)
def test_resize(benchmark, factory, resize_keys):
    def run():
        m = factory(0)
        for k in resize_keys:
            m[k] = 0

    benchmark(run)


@pytest.mark.benchmark(group="setdefault_hit")
@pytest.mark.parametrize("factory", IMPLS)
def test_setdefault_hit(benchmark, factory, keys):
    m = factory(N)
    for k in keys:
        m[k] = 0

    def run():
        for k in keys:
            _ = m.setdefault(k, 1)

    benchmark(run)


@pytest.mark.benchmark(group="setdefault_miss")
@pytest.mark.parametrize("factory", IMPLS)
def test_setdefault_miss(benchmark, factory, keys, miss_keys):
    def run():
        m = factory(N)
        for k in keys:
            m[k] = 0
        for k in miss_keys:
            _ = m.setdefault(k, 1)

    benchmark(run)


@pytest.mark.benchmark(group="keys_contains_hit")
@pytest.mark.parametrize("factory", IMPLS)
def test_keys_contains_hit(benchmark, factory, keys):
    m = factory(N)
    for k in keys:
        m[k] = 0
    view = m.keys()

    def run():
        for k in keys:
            _ = k in view

    benchmark(run)


@pytest.mark.benchmark(group="keys_contains_miss")
@pytest.mark.parametrize("factory", IMPLS)
def test_keys_contains_miss(benchmark, factory, keys, miss_keys):
    m = factory(N)
    for k in keys:
        m[k] = 0
    view = m.keys()

    def run():
        for k in miss_keys:
            _ = k in view

    benchmark(run)


@pytest.mark.benchmark(group="items_contains_hit")
@pytest.mark.parametrize("factory", IMPLS)
def test_items_contains_hit(benchmark, factory, keys):
    m = factory(N)
    for k in keys:
        m[k] = 0
    view = m.items()
    pairs = [(k, 0) for k in keys]

    def run():
        for p in pairs:
            _ = p in view

    benchmark(run)


@pytest.mark.benchmark(group="union")
@pytest.mark.parametrize("factory", IMPLS)
def test_union(benchmark, factory, keys, miss_keys):
    m = factory(N)
    for k in keys:
        m[k] = 0
    other = {k: 1 for k in miss_keys}

    def run():
        _ = m | other

    benchmark(run)


@pytest.mark.benchmark(group="runion")
@pytest.mark.parametrize("factory", IMPLS)
def test_runion(benchmark, factory, keys, miss_keys):
    m = factory(N)
    for k in keys:
        m[k] = 0
    other = {k: 1 for k in miss_keys}

    def run():
        _ = other | m

    benchmark(run)


@pytest.mark.benchmark(group="eq_dict")
@pytest.mark.parametrize("factory", IMPLS)
def test_eq_dict(benchmark, factory, keys):
    m = factory(N)
    for k in keys:
        m[k] = 0
    other = {k: 0 for k in keys}

    def run():
        _ = m == other

    benchmark(run)


@pytest.mark.benchmark(group="fromkeys")
@pytest.mark.parametrize("factory", IMPLS)
def test_fromkeys(benchmark, factory, keys):
    cls = factory(0).__class__

    def run():
        _ = cls.fromkeys(keys, 0)

    benchmark(run)


@pytest.mark.benchmark(group="update_same")
@pytest.mark.parametrize("factory", IMPLS)
def test_update_same(benchmark, factory, keys, miss_keys):
    cls = factory(0).__class__
    a = factory(N)
    for k in keys:
        a[k] = 0
    b = cls()
    for k in miss_keys:
        b[k] = 1

    def run():
        m = cls(a)
        m.update(b)

    benchmark(run)


@pytest.mark.benchmark(group="eq_same")
@pytest.mark.parametrize("factory", IMPLS)
def test_eq_same(benchmark, factory, keys):
    cls = factory(0).__class__
    a = factory(N)
    for k in keys:
        a[k] = 0
    b = cls()
    for k in keys:
        b[k] = 0

    def run():
        _ = a == b

    benchmark(run)


@pytest.mark.benchmark(group="update_dict")
@pytest.mark.parametrize("factory", IMPLS)
def test_update_dict(benchmark, factory, keys, miss_keys):
    other = {k: 1 for k in miss_keys}

    def run():
        m = factory(N)
        for k in keys:
            m[k] = 0
        m.update(other)

    benchmark(run)


@pytest.mark.benchmark(group="values_contains_hit")
@pytest.mark.parametrize("factory", IMPLS)
def test_values_contains_hit(benchmark, factory, keys):
    m = factory(N)
    sentinel = object()
    for k in keys:
        m[k] = sentinel
    view = m.values()

    def run():
        _ = sentinel in view

    benchmark(run)


@pytest.mark.benchmark(group="values_contains_miss")
@pytest.mark.parametrize("factory", IMPLS)
def test_values_contains_miss(benchmark, factory, keys):
    m = factory(N)
    for k in keys:
        m[k] = 0
    view = m.values()
    target = object()

    def run():
        _ = target in view

    benchmark(run)


@pytest.mark.benchmark(group="copy")
@pytest.mark.parametrize("factory", IMPLS)
def test_copy(benchmark, factory, keys):
    m = factory(N)
    for k in keys:
        m[k] = 0

    def run():
        _ = m.copy()

    benchmark(run)
