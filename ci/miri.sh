#!/usr/bin/env bash
# Run tests under Miri with strict provenance.
#
# Slow tests are gated with `#[cfg_attr(miri, ignore)]`.
#
# Extra args pass through.

set -ex

export MIRIFLAGS="${MIRIFLAGS:--Zmiri-strict-provenance}"

cargo +nightly miri test "$@"
