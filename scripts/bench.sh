#!/usr/bin/env bash
# Run a Criterion bench with low-noise mitigations applied.
#
# No sudo: taskset (core pin), setarch -R (ASLR off), chrt -b 0 (SCHED_BATCH).
# With sudo: nice -n -20 (max CFS prio), prlimit memlock (no page-out);
# drops back to invoking user so cargo artifacts stay user-owned.
# All settings are process-local — die with the bench process.
#
# Hardware-aware:
# - CORE unset: claims a free core in the perf cluster (max cpufreq) via
#   flock. Falls back to the full cluster list when every core is claimed.
# - Multi-node NUMA: binds memory to the pinned core's node via numactl
#   --membind so cache misses don't traverse the inter-socket interconnect.
#
# Env knobs:
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
#
# Common workflows:
#   scripts/bench.sh                      # save baseline "ref"
#   SAVE=attempt-a scripts/bench.sh       # store this run as "attempt-a"
#   LOAD=attempt-a scripts/bench.sh       # compare attempt-a vs ref (no rerun)
#   LOAD=attempt-a BASELINE=attempt-b scripts/bench.sh  # a vs b (no rerun)
#
# Forwarded args (after `--`) are appended to the Criterion command line

set -euo pipefail

BENCH=${BENCH:-all}
SAVE=${SAVE:-}
BASELINE=${BASELINE:-}
LOAD=${LOAD:-}
LOCK_DIR=${LOCK_DIR:-/tmp/opthash-bench-locks}

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

# Lock fd is held for the script's lifetime; the kernel releases it on exit.
claim_perf_core() {
	mkdir -p "$LOCK_DIR" 2>/dev/null || true
	local perf_cores=()
	while IFS= read -r c; do perf_cores+=("$c"); done < <(detect_perf_cores)
	if ((${#perf_cores[@]} == 0)); then
		echo "warn: no cpufreq info; defaulting to CORE=0" >&2
		CORE=0
		return
	fi
	local c lock
	for c in "${perf_cores[@]}"; do
		lock="$LOCK_DIR/core-${c}.lock"
		# Permission-denied (e.g. lock owned by another user) → try next core.
		if ! (exec {fd}>"$lock") 2>/dev/null; then
			continue
		fi
		exec {LOCK_FD}>"$lock"
		if flock -n "$LOCK_FD"; then
			CORE=$c
			echo "info: claimed perf core $c (lock: $lock)" >&2
			return
		fi
		exec {LOCK_FD}>&-
		unset LOCK_FD
	done
	# All perf cores busy or unlockable: restrict to the cluster, let OS schedule.
	CORE=$(
		IFS=,
		echo "${perf_cores[*]}"
	)
	echo "info: all perf cores busy; restricting to cluster CORE=$CORE" >&2
}

if ((IS_LINUX)) && [[ -z ${CORE:-} ]]; then
	claim_perf_core
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

if [[ -n "$LOAD" ]]; then
	criterion_args=(--load-baseline "$LOAD" --baseline "${BASELINE:-ref}")
elif [[ -n "$BASELINE" ]]; then
	criterion_args=(--baseline "$BASELINE")
elif [[ -n "$SAVE" ]]; then
	criterion_args=(--save-baseline "$SAVE")
else
	criterion_args=(--save-baseline ref)
fi

if [[ "$BENCH" == "all" ]]; then
	bench_targets=(speedup mean_latency tail_latency)
else
	bench_targets=("$BENCH")
fi

# Linux: use `taskset` to pin core and `setarch` to disable ASLR.
pin_wrapper=()
if ((IS_LINUX)) && [[ -n "${CORE:-}" ]]; then
	pin_wrapper=(taskset -c "$CORE" setarch -R)
fi

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

for target in "${bench_targets[@]}"; do
	cmd=("${numa_wrapper[@]}" "${pin_wrapper[@]}" cargo bench --bench "$target" -- "${criterion_args[@]}" "$@")
	"${launcher[@]}" "${cmd[@]}"
done
