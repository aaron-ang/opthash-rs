# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.5](https://github.com/aaron-ang/opthash-rs/compare/v0.10.4...v0.10.5) - 2026-08-17

### Other

- add Spanish README ([#133](https://github.com/aaron-ang/opthash-rs/pull/133))

## [0.10.4](https://github.com/aaron-ang/opthash-rs/compare/v0.10.3...v0.10.4) - 2026-07-26

### Added

- make paper-exact hashing the default ([#115](https://github.com/aaron-ang/opthash-rs/pull/115))

### Fixed

- update exclude paths in Cargo.toml

### Other

- cut wasted probing on both maps ([#132](https://github.com/aaron-ang/opthash-rs/pull/132))
- pack Elastic probe counters ([#131](https://github.com/aaron-ang/opthash-rs/pull/131))
- reduce Funnel probe preparation cost
- accelerate elastic and funnel map operations ([#130](https://github.com/aaron-ang/opthash-rs/pull/130))
- update README to clarify opthash features and usage
- streamline exact probes and Elastic membership ([#129](https://github.com/aaron-ang/opthash-rs/pull/129))
- *(x86)* retain sixteen-lane control groups for AVX-512 ([#128](https://github.com/aaron-ang/opthash-rs/pull/128))
- explain hashing algorithms in more detail
- preserve paper fidelity in hot paths ([#127](https://github.com/aaron-ang/opthash-rs/pull/127))
- streamline paper-faithful hot paths ([#121](https://github.com/aaron-ang/opthash-rs/pull/121))
- qualify exact probe functions ([#120](https://github.com/aaron-ang/opthash-rs/pull/120))
- define exact-default benchmark methodology ([#116](https://github.com/aaron-ang/opthash-rs/pull/116))
- remove benchmark plotting machinery ([#114](https://github.com/aaron-ang/opthash-rs/pull/114))

## [0.10.3](https://github.com/aaron-ang/opthash-rs/compare/v0.10.2...v0.10.3) - 2026-07-05

### Added

- *(simd)* SWAR-8 generic control-scan fallback ([#112](https://github.com/aaron-ang/opthash-rs/pull/112))

### Fixed

- *(tests)* ignore slow tests under Miri ([#102](https://github.com/aaron-ang/opthash-rs/pull/102))
- make funnel fallback choose emptier bucket ([#98](https://github.com/aaron-ang/opthash-rs/pull/98))
- use paper-linear elastic probe budget ([#99](https://github.com/aaron-ang/opthash-rs/pull/99))

### Other

- no_std support, optional foldhash, Cargo/lint hygiene ([#111](https://github.com/aaron-ang/opthash-rs/pull/111))
- *(funnel)* assert clear/reinsert invariants, not special-array placement ([#109](https://github.com/aaron-ang/opthash-rs/pull/109))
- *(bench,docs)* drop redundant bench, relocate helpers, tidy README ([#107](https://github.com/aaron-ang/opthash-rs/pull/107))
- cut hot-path instructions in elastic insert and funnel remove ([#108](https://github.com/aaron-ang/opthash-rs/pull/108))
- deterministic hasher + drop redundant crate:: qualification ([#106](https://github.com/aaron-ang/opthash-rs/pull/106))
- deepen backend seams and shared internals ([#105](https://github.com/aaron-ang/opthash-rs/pull/105))
- consolidate backend code-gen mechanisms and contracts ([#104](https://github.com/aaron-ang/opthash-rs/pull/104))
- hash table backend architecture ([#103](https://github.com/aaron-ang/opthash-rs/pull/103))
- *(funnel)* exact paper bucket counts on cold levels ([#101](https://github.com/aaron-ang/opthash-rs/pull/101))
- fix flaky Miri (limited_group_budget) + steady-state delete_heavy bench ([#100](https://github.com/aaron-ang/opthash-rs/pull/100))
- *(deps)* bump pyo3 from 0.28.3 to 0.29.0 in the cargo group across 1 directory ([#95](https://github.com/aaron-ang/opthash-rs/pull/95))

## [0.10.2](https://github.com/aaron-ang/opthash-rs/compare/v0.10.1...v0.10.2) - 2026-06-09

### Added

- optimize funnel throughput paths ([#91](https://github.com/aaron-ang/opthash-rs/pull/91))
- add nightly AVX-512 SIMD groups ([#77](https://github.com/aaron-ang/opthash-rs/pull/77))

### Other

- *(elastic)* amortized defrag + raise default reserve to 0.45 ([#92](https://github.com/aaron-ang/opthash-rs/pull/92))
- *(map)* deepen RawTable lookup helpers ([#87](https://github.com/aaron-ang/opthash-rs/pull/87))
- *(funnel)* centralize region removal ([#89](https://github.com/aaron-ang/opthash-rs/pull/89))
- *(elastic)* package geometry setup ([#86](https://github.com/aaron-ang/opthash-rs/pull/86))
- *(arena)* unify arena lifecycle guards ([#88](https://github.com/aaron-ang/opthash-rs/pull/88))
- *(python)* centralize adapter policies ([#90](https://github.com/aaron-ang/opthash-rs/pull/90))
- *(arena)* extract LayoutCursor for region offset stamping ([#81](https://github.com/aaron-ang/opthash-rs/pull/81))
- name backend type aliases consistently at definition ([#83](https://github.com/aaron-ang/opthash-rs/pull/83))
- flatten EntryView into a concrete OccupiedError ([#82](https://github.com/aaron-ang/opthash-rs/pull/82))
- drive backend white-box tests through the public shell ([#80](https://github.com/aaron-ang/opthash-rs/pull/80))
- *(funnel)* fold arena builders into FunnelGeometry methods ([#79](https://github.com/aaron-ang/opthash-rs/pull/79))
- deepen RawTable resize + scan seams ([#78](https://github.com/aaron-ang/opthash-rs/pull/78))
- replace raw pointers with MaybeUninit in arena and funnel modules

## [0.10.1](https://github.com/aaron-ang/opthash-rs/compare/v0.10.0...v0.10.1) - 2026-05-31

### Added

- add max_probe_groups to elastic Level to restore query bound

### Fixed

- update default reserve fraction to improve allocation efficiency

### Other

- replot bench assets
- change salt type from u64 to u32 in Level structs
- update benchmark commands to use 'uv run' for consistency
- optimize funnel bucket level access with unsafe indexing to eliminate bounds checks
- split benches from speedup.rs
- inline funnel higher level probe
- set shell over map primitives ([#74](https://github.com/aaron-ang/opthash-rs/pull/74))
- remove tail latency benchmarking and associated plotting scripts
- Generic HashMap shell over a RawTable trait + Elastic/Funnel hash sets ([#72](https://github.com/aaron-ang/opthash-rs/pull/72))
- Refactor shared slot iterators ([#71](https://github.com/aaron-ang/opthash-rs/pull/71))
- update README to clarify probing methods for ElasticHashMap and FunnelHashMap
- hashbrown-style iter primitives (IterRange, SlotHandle, ScanCursor) ([#70](https://github.com/aaron-ang/opthash-rs/pull/70))
- drop &Arena arg from ArenaSlots + descriptor cleanup ([#69](https://github.com/aaron-ang/opthash-rs/pull/69))
- single-arena descriptors + ArenaSlots trait ([#68](https://github.com/aaron-ang/opthash-rs/pull/68))
- Equivalent trait, FreeSlot, IterPhase, common cleanup ([#67](https://github.com/aaron-ang/opthash-rs/pull/67))
- *(funnel)* skip special-array dedup on clean probe chain ([#66](https://github.com/aaron-ang/opthash-rs/pull/66))
- *(scripts)* swap to process-local noise mitigations ([#63](https://github.com/aaron-ang/opthash-rs/pull/63))

## [0.10.0](https://github.com/aaron-ang/opthash-rs/compare/v0.9.0...v0.10.0) - 2026-05-25

### Other

- [**breaking**] drop ElasticOptions / FunnelOptions in favor of ad-hoc ctors ([#61](https://github.com/aaron-ang/opthash-rs/pull/61))
- broaden clippy scope; switch release-plz to PAT ([#60](https://github.com/aaron-ang/opthash-rs/pull/60))

## [0.9.0](https://github.com/aaron-ang/opthash-rs/compare/v0.8.0...v0.9.0) - 2026-05-25

### Fixed

- *(funnel)* floor special_capacity to keep A_{α+1} non-empty ([#52](https://github.com/aaron-ang/opthash-rs/pull/52))

### Other

- [**breaking**] hide probe_scale + primary_probe_limit from public Options ([#59](https://github.com/aaron-ang/opthash-rs/pull/59))
- *(probe)* unify elastic on shared TriangularProbe helper ([#58](https://github.com/aaron-ang/opthash-rs/pull/58))
- remove unnecessary Clone and Copy derives from various structs ([#57](https://github.com/aaron-ang/opthash-rs/pull/57))
- *(funnel)* extract ProbeSeq + drop resize_if_needed on extract_if drop ([#56](https://github.com/aaron-ang/opthash-rs/pull/56))
- trim data layout; compute probe budget on demand ([#55](https://github.com/aaron-ang/opthash-rs/pull/55))
- drop unused metadata + ineffective prefetches; bench tooling ([#53](https://github.com/aaron-ang/opthash-rs/pull/53))

## [0.8.0](https://github.com/aaron-ang/opthash-rs/compare/v0.7.0...v0.8.0) - 2026-05-24

### Added

- *(api)* impl Clone + clone_from for ElasticHashMap and FunnelHashMap ([#46](https://github.com/aaron-ang/opthash-rs/pull/46))
- *(parity)* hashbrown parity tests + std-style API + Miri CI ([#37](https://github.com/aaron-ang/opthash-rs/pull/37))

### Fixed

- *(funnel)* route insert overflow through bucket levels per paper §5 ([#47](https://github.com/aaron-ang/opthash-rs/pull/47))

### Other

- add rust-cache to pre-commit, migrate codspeed off raw actions/cache ([#51](https://github.com/aaron-ang/opthash-rs/pull/51))
- add MSRV + rust-test matrix; slim bench docs ([#49](https://github.com/aaron-ang/opthash-rs/pull/49))
- add release-plz, decouple python release workflow ([#48](https://github.com/aaron-ang/opthash-rs/pull/48))
- *(simd)* fix import cfg gate
- *(funnel)* skip free-slot SIMD scan when insert candidate exists ([#45](https://github.com/aaron-ang/opthash-rs/pull/45))
- *(scan)* cursor API + bulk-walk helper ([#34](https://github.com/aaron-ang/opthash-rs/pull/34))
- split latency into mean_latency + tail_latency ([#43](https://github.com/aaron-ang/opthash-rs/pull/43))
- stage jobs + cap matrix parallelism ([#42](https://github.com/aaron-ang/opthash-rs/pull/42))
- *(bench)* drop iai-callgrind in favor of CodSpeed callgrind sim
- Add CodSpeed continuous performance benchmarking ([#36](https://github.com/aaron-ang/opthash-rs/pull/36))
- *(python)* iter lazy take + bulk-drop clear + int eq fast path ([#35](https://github.com/aaron-ang/opthash-rs/pull/35))
- *(funnel,elastic)* paper-audit pass + cold-path opts
- *(pyproject)* move test extras to dependency-groups
- *(resize)* drain via SIMD scan, skip intermediate Vec
