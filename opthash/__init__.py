from collections.abc import (
    ItemsView,
    KeysView,
    MutableMapping,
    MutableSet,
    ValuesView,
)

from .opthash import (
    ElasticHashMap,
    ElasticHashSet,
    FunnelHashMap,
    FunnelHashSet,
    elastic_items,
    elastic_keys,
    elastic_values,
    funnel_items,
    funnel_keys,
    funnel_values,
)

MutableMapping.register(ElasticHashMap)
MutableMapping.register(FunnelHashMap)
MutableSet.register(ElasticHashSet)
MutableSet.register(FunnelHashSet)
KeysView.register(elastic_keys)
KeysView.register(funnel_keys)
ValuesView.register(elastic_values)
ValuesView.register(funnel_values)
ItemsView.register(elastic_items)
ItemsView.register(funnel_items)

__all__ = [
    "ElasticHashMap",
    "ElasticHashSet",
    "FunnelHashMap",
    "FunnelHashSet",
]
