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
# - CORE set or detected: blocks on that core's flock, so concurrent runs
#   serialize instead of contending.
# - Multi-node NUMA: binds memory to the pinned core's node via numactl
#   --membind so cache misses don't traverse the inter-socket interconnect.
#
# Env knobs:
#   CORE=5           pin to one explicit CPU; detected or explicit CPUs are
#                    always locked for the script's lifetime.
#   BENCH=all        cargo bench --bench target (default all = speedup + latency)
#   SAVE=            --save-baseline <name>; runs the bench and stores results
#                    under <name>. Default: ref (only when neither BASELINE nor
#                    LOAD is set).
#   BASELINE=        --baseline <name>; compares against an existing baseline
#                    without overwriting it.
#   LOAD=            --load-baseline <name>; loads stored samples instead of
#                    re-measuring. Use with BASELINE=other to compare two
#                    stored baselines without rerunning. Implies a comparison
#                    against BASELINE (defaults to ref).
#   OPTHASH_CRITERION_ROOT=
#                    overrides Criterion's output and metadata root together.
#
# Common workflows:
#   scripts/bench.sh                      # save baseline "ref"
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
if [[ -n ${OPTHASH_BENCHMARK_METADATA_HELPER:-} ]]; then
	metadata_helper=("$OPTHASH_BENCHMARK_METADATA_HELPER")
else
	metadata_helper=(python3 "$REPO_ROOT/scripts/benchmark_metadata.py")
fi
# Each per-core lock is a readable directory under this root. The default /tmp
# sticky directory lets sudo and non-sudo invocations open the same inode
# without requiring a shared writable file.
LOCK_DIR=${LOCK_DIR:-/tmp}

# Low-noise primitives below are Linux-only; elsewhere we fall through to
# plain `cargo bench`.
IS_LINUX=0
[[ $(uname) == Linux ]] && IS_LINUX=1

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

# Select the lowest-numbered performance core when the caller did not provide
# one explicitly.
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

# Lock fd is held for the script's lifetime; the kernel releases it on exit.
# Low-noise measurements are single-core by construction, so reject CPU-list
# syntax rather than allowing partially overlapping lists to evade the lock.
claim_core_lock() {
	if [[ ! $CORE =~ ^[0-9]+$ ]]; then
		echo "error: CORE must be one CPU number so benchmark locking is unambiguous" >&2
		exit 1
	fi
	mkdir -p "$LOCK_DIR" 2>/dev/null || true
	local lock="$LOCK_DIR/opthash-bench-core-${CORE}.lock"
	# A directory gives every user a read-only flockable inode and avoids
	# truncating or writing a predictable /tmp path under sudo. mkdir is atomic;
	# a concurrent creator is harmless.
	if [[ ! -e "$lock" ]] && ! mkdir -m 0755 "$lock" 2>/dev/null && [[ ! -e "$lock" ]]; then
		echo "error: cannot create benchmark lock $lock" >&2
		exit 1
	fi
	# Accept a regular file created by an older release, but never follow a
	# symbolic link. Read-only exclusive flock works for both files and
	# directories on Linux and is independent of the creator's uid.
	if [[ -L "$lock" || (! -d "$lock" && ! -f "$lock") ]]; then
		echo "error: unsafe benchmark lock $lock" >&2
		exit 1
	fi
	if ! (exec {fd}<"$lock") 2>/dev/null; then
		echo "error: cannot open benchmark lock $lock" >&2
		exit 1
	fi
	exec {LOCK_FD}<"$lock"
	echo "info: waiting for perf core $CORE lock..." >&2
	flock "$LOCK_FD" # blocks until free -> runs serialize on this core
	echo "info: acquired perf core $CORE" >&2
}

if ((IS_LINUX)); then
	if [[ -z ${CORE:-} ]]; then
		select_perf_core
	fi
	claim_core_lock
fi
core=${CORE:-0}

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
	metadata_save=
	metadata_load=$LOAD
	metadata_compare=${BASELINE:-ref}
elif [[ -n "$BASELINE" ]]; then
	criterion_args=(--baseline "$BASELINE")
	metadata_save=
	metadata_load=
	metadata_compare=$BASELINE
elif [[ -n "$SAVE" ]]; then
	criterion_args=(--save-baseline "$SAVE")
	metadata_save=$SAVE
	metadata_load=
	metadata_compare=
else
	criterion_args=(--save-baseline ref)
	metadata_save=ref
	metadata_load=
	metadata_compare=
fi
echo "info: Criterion args: ${criterion_args[*]}" >&2

# Strip a leading '--' from forwarded args since we include it ourselves.
forward_args=("$@")
if [[ "${#forward_args[@]}" -gt 0 && "${forward_args[0]}" == "--" ]]; then
	forward_args=("${forward_args[@]:1}")
fi
echo "info: forwarding args: ${forward_args[*]}" >&2

for target in "${bench_targets[@]}"; do
	cargo_feature_args=()
	source_before=
	if [[ -n "$metadata_save" ]]; then
		begin_args=(begin --root "$CRITERION_ROOT" --source-root "$REPO_ROOT"
			--target "$target" --baseline "$metadata_save")
		source_before=$("${launcher[@]}" "${metadata_helper[@]}" "${begin_args[@]}")
	elif [[ -n "$metadata_compare" ]]; then
		verify_args=(verify --root "$CRITERION_ROOT" --target "$target"
			--baseline "${metadata_load:-$metadata_compare}")
		if [[ -n "$metadata_load" ]]; then
			verify_args+=(--compare "$metadata_compare")
		fi
		"${launcher[@]}" "${metadata_helper[@]}" "${verify_args[@]}"
	fi

	env_args=(
		"OPTHASH_BENCH_SAVE_BASELINE=$metadata_save"
		"OPTHASH_BENCH_LOAD_BASELINE=$metadata_load"
		"OPTHASH_BENCH_COMPARE_BASELINE=$metadata_compare"
	)
	cmd=("${numa_wrapper[@]}" "${pin_wrapper[@]}" env "${criterion_env_args[@]}" "${env_args[@]}"
		cargo bench "${cargo_feature_args[@]}" --bench "$target" -- "${criterion_args[@]}" "${forward_args[@]}")
	if "${launcher[@]}" "${cmd[@]}"; then
		:
	else
		status=$?
		exit "$status"
	fi
	if [[ -n "$source_before" ]]; then
		publish_args=(publish --root "$CRITERION_ROOT" --source-root "$REPO_ROOT"
			--target "$target" --baseline "$metadata_save" --source-before "$source_before"
			--requested-bench "$BENCH" --core "$core")
		for arg in "${forward_args[@]}"; do
			publish_args+=(--forwarded-arg "$arg")
		done
		"${launcher[@]}" "${metadata_helper[@]}" "${publish_args[@]}"
	fi
done
