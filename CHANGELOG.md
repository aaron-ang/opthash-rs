# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
