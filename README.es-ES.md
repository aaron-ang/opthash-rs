# opthash

[![Crates.io](https://img.shields.io/crates/v/opthash?logo=rust&label=crates.io)](https://crates.io/crates/opthash)
[![PyPI](https://img.shields.io/pypi/v/opthash?logo=pypi&logoColor=white&label=pypi)](https://pypi.org/project/opthash/)
[![MSRV](https://img.shields.io/crates/msrv/opthash?logo=rust)](https://crates.io/crates/opthash)
[![Python](https://img.shields.io/pypi/pyversions/opthash?logo=python&logoColor=white)](https://pypi.org/project/opthash/)
[![CI](https://github.com/aaron-ang/opthash-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/aaron-ang/opthash-rs/actions/workflows/ci.yml)
[![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://codspeed.io/aaron-ang/opthash-rs?utm_source=badge)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

opthash proporciona mapas y conjuntos hash de Rust basados en **Elastic Hashing** y
**Funnel Hashing**, dos algoritmos de direccionamiento abierto introducidos en
[_Optimal Bounds for Open Addressing Without Reordering_](https://arxiv.org/abs/2501.02305).
Convierte las construcciones de tablas fijas del artículo en APIs de colecciones familiares
que se pueden utilizar en programas reales.

> [!IMPORTANT]
> opthash es experimental. Está diseñado para evaluar y mejorar estos
> algoritmos, no como un reemplazo directo de rendimiento para `std::HashMap` o
> `hashbrown`. Realiza pruebas comparativas y evalúalo contra tu propia carga de trabajo antes de adoptarlo
> en producción.

## Características

- `ElasticHashMap`, `ElasticHashSet`, `FunnelHashMap` y `FunnelHashSet`
- APIs familiares para mapas, conjuntos, entradas, iteradores y colecciones
- Colocación fiel al artículo durante la operación normal de tamaño fijo
- Capacidad de reserva, hashers y asignadores configurables
- Compatibilidad con `no_std` mediante `alloc`
- Bindings opcionales para Python con APIs tipadas para mapas y conjuntos

## Inicio rápido

Añade opthash a un proyecto Rust:

```bash
cargo add opthash
```

Ambos algoritmos exponen las mismas APIs centrales de colección:

```rust
use opthash::{ElasticHashMap, FunnelHashSet};

let mut scores = ElasticHashMap::new();
scores.insert("Ada", 42);
scores.entry("Linus").or_insert(37);

assert_eq!(scores.get("Ada"), Some(&42));

let mut visited = FunnelHashSet::new();
visited.insert("Paris");

assert!(visited.contains("Paris"));
```

La configuración predeterminada utiliza `foldhash` y mantiene una octava parte de la tabla
disponible como capacidad de reserva. La mayoría de los usuarios deberían comenzar con estos valores predeterminados.
Los usuarios avanzados pueden ajustar la reserva con `ReserveFraction`, proporcionar otro
`BuildHasher` o utilizar un asignador personalizado.

Para utilizar opthash sin `std`, deshabilita las características predeterminadas y proporciona un hasher:

```toml
[dependencies]
opthash = { version = "0.10", default-features = false }
```

## Elección del algoritmo

Elastic y Funnel utilizan estrategias de colocación diferentes pero comparten la misma API
central. Elige la construcción que desees explorar; cambiar entre ellos es
sencillo. Para ver los resultados de rendimiento actuales, consulta la
[guía de benchmarks](benches/README.md).

## Comparación con el artículo

opthash preserva la geometría finita, las reglas de colocación y el orden de sondas
del artículo durante la operación normal entre reconstrucciones de tabla. Una colección dinámica
utilizable también necesita un comportamiento fuera del modelo del artículo:

| Tema | Artículo | opthash |
| --- | --- | --- |
| Vida útil de la tabla | Tamaño fijo | Crece y se reconstruye según sea necesario |
| Actualizaciones | Solo inserciones | También reemplaza, elimina, vacía y limpia tumbstones |
| Colocación | Utiliza los candidatos prescritos | Los sigue normalmente; el agotamiento ocasional puede activar un mecanismo de respaldo más amplio para garantizar la corrección |
| Aleatoriedad | Analiza elecciones aleatorias ideales | Utiliza un mezclado determinista concreto |
| Límites | Analiza la complejidad de sondas en un modelo de tamaño fijo y solo inserciones | Los límites del artículo no cubren la eliminación, el crecimiento, los fallos de Elastic ni el rendimiento en tiempo real |

Estas diferencias preservan las trazas normales fieles al artículo mientras hacen que los mapas
sean utilizables como colecciones generales. También significan que los límites teóricos
del artículo no deben interpretarse como garantías para cada operación de la biblioteca. Consulta el
[código fuente del artículo utilizado por este proyecto](https://github.com/aaron-ang/opthash-rs/blob/main/paper/main.tex)
para conocer la construcción exacta.

## Python

Los bindings de Python exponen las mismas cuatro familias de mapas y conjuntos:

```bash
pip install opthash
```

```python
from opthash import FunnelHashMap

scores = FunnelHashMap({"Ada": 42})
scores["Linus"] = 37

assert scores["Ada"] == 42
```

Se admite Python 3.10 o versiones posteriores.

## Recursos del proyecto

- [Documentación de la API de Rust](https://docs.rs/opthash)
- [Artículo de investigación](https://arxiv.org/abs/2501.02305)
- [Metodología de benchmarks](benches/README.md)
- [Registro de cambios](CHANGELOG.md)
- [Seguimiento de incidencias](https://github.com/aaron-ang/opthash-rs/issues)

## Licencia

Licenciado bajo la [Licencia Apache 2.0](LICENSE).
