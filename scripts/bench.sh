#!/usr/bin/env bash
# Run a Criterion bench with low-noise mitigations applied.
#
# No sudo: taskset (core pin), setarch -R (ASLR off), chrt -b 0 (SCHED_BATCH).
# With sudo: nice -n -20 (max CFS prio), prlimit memlock (no page-out);
# drops back to invoking user so cargo artifacts stay user-owned.
# All settings are process-local — die with the bench process.
#
# Hardware-aware:
# - CORE unset: pins to the lowest-numbered max-cpufreq core.
# - Explicit and detected cores are locked, so concurrent runs serialize.
# - Multi-node NUMA: binds memory to the pinned core's node via numactl
#   --membind so cache misses don't traverse the inter-socket interconnect.
#
# Env knobs:
#   CORE=5           pin to and lock one explicit CPU.
#   LOCK_DIR=/tmp     Linux-only external root/core lock namespace.
#   BENCH=all        cargo bench --bench target (default all = speedup + latency)
#   SAVE=            --save-baseline <name>; runs the bench and stores results
#                    under <name>. With no mode, a clean HEAD is saved under
#                    its 12-character commit hash.
#   BASELINE=        --baseline <name>; compares against an existing baseline
#                    without overwriting it.
#   LOAD=            --load-baseline <name>; loads stored samples instead of
#                    re-measuring. Use with BASELINE=other to compare two
#                    stored baselines without rerunning. Implies a comparison
#                    against BASELINE (defaults to ref).
#   OPTHASH_CRITERION_ROOT=
#                    override Criterion output; its canonical path is locked.
#
# Common workflows:
#   scripts/bench.sh                      # save clean HEAD under its commit stamp
#   SAVE=attempt-a scripts/bench.sh       # store this run as "attempt-a"
#   LOAD=attempt-a scripts/bench.sh       # compare attempt-a vs ref (no rerun)
#   LOAD=attempt-a BASELINE=attempt-b scripts/bench.sh  # a vs b (no rerun)
#
# Forwarded args are appended to the Criterion command line.
# The script strips the leading `--` before forwarding.

set -euo pipefail

BENCH=${BENCH:-all}
SAVE=${SAVE:-}
BASELINE=${BASELINE:-}
LOAD=${LOAD:-}
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$REPO_ROOT"
CRITERION_ROOT=${OPTHASH_CRITERION_ROOT:-$REPO_ROOT/target/criterion}
criterion_env_args=(-u CRITERION_HOME)
if [[ -n ${OPTHASH_CRITERION_ROOT:-} ]]; then
	criterion_env_args=("CRITERION_HOME=$CRITERION_ROOT")
fi
LOCK_DIR=${LOCK_DIR:-/tmp}

# Low-noise primitives below are Linux-only; elsewhere we fall through to
# plain `cargo bench`.
IS_LINUX=0
[[ $(uname) == Linux ]] && IS_LINUX=1

claim_criterion_root_lock() {
	local canonical_root root_key lock
	canonical_root=$(realpath -m -- "$CRITERION_ROOT")
	root_key=$(printf '%s' "$canonical_root" | sha256sum)
	root_key=${root_key%% *}
	mkdir -p "$LOCK_DIR" 2>/dev/null || true
	lock="$LOCK_DIR/opthash-bench-root-${root_key}.lock"
	if [[ -L "$lock" ]] || { [[ -e "$lock" ]] && [[ ! -d "$lock" && ! -f "$lock" ]]; }; then
		echo "error: unsafe Criterion root lock $lock" >&2
		exit 1
	fi
	if [[ ! -e "$lock" ]] && ! mkdir -m 0755 "$lock" 2>/dev/null && [[ ! -e "$lock" ]]; then
		echo "error: cannot create Criterion root lock $lock" >&2
		exit 1
	fi
	exec {CRITERION_LOCK_FD}<"$lock"
	echo "info: waiting for Criterion root lock..." >&2
	flock "$CRITERION_LOCK_FD"
	echo "info: acquired Criterion root lock" >&2
}

# Cores at the system's max cpufreq — perf cluster on hybrid SoCs, every
# core on homogeneous CPUs.
detect_perf_cores() {
	local max_freq=0
	local path f
	for path in /sys/devices/system/cpu/cpu*/cpufreq/cpuinfo_max_freq; do
		f=$(<"$path") 2>/dev/null || continue
		((f > max_freq)) && max_freq=$f
	done
	for path in /sys/devices/system/cpu/cpu*/cpufreq/cpuinfo_max_freq; do
		f=$(<"$path") 2>/dev/null || continue
		if ((f == max_freq)); then
			local c=${path#/sys/devices/system/cpu/cpu}
			c=${c%/cpufreq/cpuinfo_max_freq}
			echo "$c"
		fi
	done
}

# Lock fd is held for the script's lifetime; the kernel releases it on exit.
select_perf_core() {
	local perf_cores=()
	while IFS= read -r c; do perf_cores+=("$c"); done < <(detect_perf_cores)
	if ((${#perf_cores[@]} == 0)); then
		echo "warn: no cpufreq info; defaulting to CORE=0" >&2
		CORE=0
		return
	fi
	# Lowest-numbered perf core (glob order is lexical, not numeric).
	local c min=${perf_cores[0]}
	for c in "${perf_cores[@]}"; do
		((c < min)) && min=$c
	done
	CORE=$min
}

claim_core_lock() {
	if [[ ! $CORE =~ ^[0-9]+$ ]]; then
		echo "error: CORE must be one CPU number" >&2
		exit 1
	fi
	mkdir -p "$LOCK_DIR" 2>/dev/null || true
	local lock="$LOCK_DIR/opthash-bench-core-${CORE}.lock"
	if [[ -L "$lock" ]] || { [[ -e "$lock" ]] && [[ ! -d "$lock" && ! -f "$lock" ]]; }; then
		echo "error: unsafe benchmark lock $lock" >&2
		exit 1
	fi
	if [[ ! -e "$lock" ]] && ! mkdir -m 0755 "$lock" 2>/dev/null && [[ ! -e "$lock" ]]; then
		echo "error: cannot create benchmark lock $lock" >&2
		exit 1
	fi
	exec {LOCK_FD}<"$lock"
	echo "info: waiting for perf core $CORE lock..." >&2
	flock "$LOCK_FD"
	echo "info: acquired perf core $CORE" >&2
}

if ((IS_LINUX)); then
	if [[ -z ${CORE:-} ]]; then
		select_perf_core
	fi
	claim_criterion_root_lock
	claim_core_lock
fi

# sudo strips PATH/HOME; recover invoker's rustup so the shim resolves their
# default toolchain.
if [[ -n "${SUDO_USER:-}" ]]; then
	user_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
	if [[ -x "$user_home/.cargo/bin/cargo" ]]; then
		export PATH="$user_home/.cargo/bin:$PATH"
		export CARGO_HOME="${CARGO_HOME:-$user_home/.cargo}"
		export RUSTUP_HOME="${RUSTUP_HOME:-$user_home/.rustup}"
	fi
fi
command -v cargo >/dev/null 2>&1 || {
	echo "error: cargo not found in PATH" >&2
	exit 1
}

# NUMA: bind memory to the node that owns the pinned core
# so cache misses don't traverse the inter-socket interconnect.
numa_wrapper=()
if ((IS_LINUX)) && command -v numactl >/dev/null 2>&1 && [[ -n "${CORE:-}" ]]; then
	node_count=$(find /sys/devices/system/node -maxdepth 1 -name 'node[0-9]*' -type d 2>/dev/null | wc -l)
	if ((node_count > 1)); then
		first_core=${CORE%%,*}
		node_dir=$(find "/sys/devices/system/cpu/cpu${first_core}" -maxdepth 1 -name 'node[0-9]*' 2>/dev/null | head -1)
		if [[ -n "$node_dir" ]]; then
			numa_node=${node_dir##*/node}
			numa_wrapper=(numactl --membind="$numa_node")
			echo "info: NUMA pinning memory to node $numa_node" >&2
		fi
	fi
fi

# Linux: use `taskset` to pin core and `setarch` to disable ASLR.
pin_wrapper=()
if ((IS_LINUX)) && [[ -n "${CORE:-}" ]]; then
	pin_wrapper=(taskset -c "$CORE" setarch -R)
fi

# As root: nice -n -20 (max CFS prio) + prlimit memlock (no page-out).
# Both attributes survive the UID drop, so when SUDO_USER is set we
# unconditionally hand off to the invoking user — keeps cargo artifacts
# user-owned even if nice/prlimit are missing.
#
# Non-root: chrt -b 0 (SCHED_BATCH) — kernel skips interactive scheduling
# heuristics, smaller context-switch overhead.
launcher=()
if ((IS_LINUX)) && [[ $EUID -eq 0 ]]; then
	if command -v nice >/dev/null 2>&1; then
		launcher+=(nice -n -20)
	fi
	if command -v prlimit >/dev/null 2>&1; then
		launcher+=(prlimit --memlock=unlimited --)
	fi
	if [[ -n "${SUDO_USER:-}" ]]; then
		launcher+=(sudo -u "$SUDO_USER"
			--preserve-env=PATH,CARGO_HOME,RUSTUP_HOME --)
	fi
elif ((IS_LINUX)) && command -v chrt >/dev/null 2>&1; then
	launcher=(chrt -b 0)
fi

if [[ "$BENCH" == "all" ]]; then
	bench_targets=(speedup mean_latency)
else
	bench_targets=("$BENCH")
fi
echo "info: running benchmarks: ${bench_targets[*]}" >&2

if [[ -n "$LOAD" ]]; then
	criterion_args=(--load-baseline "$LOAD" --baseline "${BASELINE:-ref}")
elif [[ -n "$BASELINE" ]]; then
	criterion_args=(--baseline "$BASELINE")
elif [[ -n "$SAVE" ]]; then
	criterion_args=(--save-baseline "$SAVE")
else
	if [[ -n $(git status --porcelain --untracked-files=normal) ]]; then
		echo "error: commit changes before benchmarking without an explicit SAVE name" >&2
		exit 1
	fi
	commit_stamp=$(git rev-parse --short=12 HEAD)
	criterion_args=(--save-baseline "$commit_stamp")
fi
echo "info: Criterion args: ${criterion_args[*]}" >&2

# Strip a leading '--' from forwarded args since we include it ourselves.
forward_args=("$@")
if [[ "${#forward_args[@]}" -gt 0 && "${forward_args[0]}" == "--" ]]; then
	forward_args=("${forward_args[@]:1}")
fi
echo "info: forwarding args: ${forward_args[*]}" >&2

for target in "${bench_targets[@]}"; do
	cmd=("${numa_wrapper[@]}" "${pin_wrapper[@]}" env "${criterion_env_args[@]}"
		cargo bench --bench "$target" -- "${criterion_args[@]}" "${forward_args[@]}")
	"${launcher[@]}" "${cmd[@]}"
done
