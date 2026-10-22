#!/usr/bin/env bash
# Run tests under Miri with strict provenance.
#
# Slow tests are gated with `#[cfg_attr(miri, ignore)]` or shrink their inputs
# with `cfg!(miri)`.
#
# Extra args pass through to nextest.

set -ex

export MIRIFLAGS="${MIRIFLAGS:--Zmiri-strict-provenance}"

cargo +nightly miri nextest run --no-fail-fast "$@"
cargo +nightly miri test --doc
