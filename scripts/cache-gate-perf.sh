#!/usr/bin/env bash
# Collect one operation from an already-manifested profiling executable.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$REPO_ROOT"
manifest=
operation=
iterations=
repetition=
original_command=$(printf '%q ' "$0" "$@")
while (($#)); do
	case "$1" in
	--manifest | --operation | --iterations | --repetition)
		(($# >= 2)) || { echo "error: missing value for $1" >&2; exit 2; }
		name=${1#--}; printf -v "$name" '%s' "$2"; shift 2
		;;
	*) echo "error: unsupported argument: $1" >&2; exit 2 ;;
	esac
done
for name in manifest operation iterations repetition; do
	[[ -n ${!name} ]] || { echo "error: --$name is required" >&2; exit 2; }
done
case "$operation" in elastic-insert | elastic-get | funnel-insert | funnel-get) ;; *) echo "error: unsupported operation: $operation" >&2; exit 2 ;; esac
[[ $iterations =~ ^[1-9][0-9]*$ ]] || { echo "error: --iterations must be positive" >&2; exit 2; }
[[ $repetition =~ ^[123]$ ]] || { echo "error: --repetition must be 1, 2, or 3" >&2; exit 2; }
[[ -n ${CACHE_GATE_CAMPAIGN_ROOT:-} && $CACHE_GATE_CAMPAIGN_ROOT == /* ]] || { echo "error: absolute CACHE_GATE_CAMPAIGN_ROOT is required" >&2; exit 2; }
[[ -n ${CACHE_GATE_CAMPAIGN_KEY:-} ]] || { echo "error: CACHE_GATE_CAMPAIGN_KEY is required" >&2; exit 2; }
[[ -n ${CACHE_GATE_PERF_BIN:-} && $CACHE_GATE_PERF_BIN == /* ]] || { echo "error: absolute CACHE_GATE_PERF_BIN is required" >&2; exit 2; }
[[ $manifest == /* ]] || { echo "error: --manifest must be absolute" >&2; exit 2; }
manifest=$(realpath -- "$manifest")
CACHE_GATE_PERF_BIN=$(realpath -- "$CACHE_GATE_PERF_BIN")
[[ -x $CACHE_GATE_PERF_BIN ]] || { echo "error: profile binary is not executable" >&2; exit 2; }
command -v perf >/dev/null 2>&1 || { echo "error: perf is required" >&2; exit 1; }

LOCK_DIR=${LOCK_DIR:-/tmp}
IS_LINUX=0
[[ $(uname) == Linux ]] && IS_LINUX=1
((IS_LINUX)) || { echo "error: cache-gate perf requires Linux" >&2; exit 1; }
if [[ -n "${SUDO_USER:-}" ]]; then
	user_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
	if [[ -x "$user_home/.cargo/bin/cargo" ]]; then
		export PATH="$user_home/.cargo/bin:$PATH"
		export CARGO_HOME="${CARGO_HOME:-$user_home/.cargo}"
		export RUSTUP_HOME="${RUSTUP_HOME:-$user_home/.rustup}"
	fi
fi

detect_perf_core() {
	local maximum=0 path frequency candidates=()
	for path in /sys/devices/system/cpu/cpu*/cpufreq/cpuinfo_max_freq; do
		frequency=$(<"$path") 2>/dev/null || continue
		((frequency > maximum)) && maximum=$frequency
	done
	for path in /sys/devices/system/cpu/cpu*/cpufreq/cpuinfo_max_freq; do
		frequency=$(<"$path") 2>/dev/null || continue
		if ((frequency == maximum)); then cpu=${path#/sys/devices/system/cpu/cpu}; candidates+=("${cpu%/cpufreq/cpuinfo_max_freq}"); fi
	done
	if ((${#candidates[@]} == 0)); then CORE=0; return; fi
	CORE=${candidates[0]}
	for cpu in "${candidates[@]}"; do ((cpu < CORE)) && CORE=$cpu; done
	return 0
}
[[ -n ${CORE:-} ]] || detect_perf_core
[[ $CORE =~ ^[0-9]+$ ]] || { echo "error: CORE must be one CPU number" >&2; exit 2; }
mkdir -p "$LOCK_DIR" 2>/dev/null || true
core_lock="$LOCK_DIR/opthash-bench-core-$CORE.lock"
if [[ -L $core_lock ]] || { [[ -e $core_lock ]] && [[ ! -d $core_lock && ! -f $core_lock ]]; }; then echo "error: unsafe core lock" >&2; exit 1; fi
if [[ ! -e $core_lock ]] && ! mkdir -m 0755 "$core_lock" 2>/dev/null && [[ ! -e $core_lock ]]; then echo "error: cannot create core lock" >&2; exit 1; fi
exec {core_lock_fd}<"$core_lock"
flock "$core_lock_fd"

numa_node=
numa_wrapper=()
if command -v numactl >/dev/null 2>&1; then
	node_count=$(find /sys/devices/system/node -maxdepth 1 -name 'node[0-9]*' -type d 2>/dev/null | wc -l)
	if ((node_count > 1)); then
		node_dir=$(find "/sys/devices/system/cpu/cpu$CORE" -maxdepth 1 -name 'node[0-9]*' 2>/dev/null | head -1)
		if [[ -n $node_dir ]]; then numa_node=${node_dir##*/node}; numa_wrapper=(numactl --membind="$numa_node"); fi
	fi
fi
pin_wrapper=(taskset -c "$CORE" setarch -R)
launcher=()
if [[ $EUID -eq 0 ]]; then
	command -v nice >/dev/null 2>&1 && launcher+=(nice -n -20)
	command -v prlimit >/dev/null 2>&1 && launcher+=(prlimit --memlock=unlimited --)
	if [[ -n ${SUDO_USER:-} ]]; then launcher+=(sudo -u "$SUDO_USER" --preserve-env=PATH,CARGO_HOME,RUSTUP_HOME --); fi
elif command -v chrt >/dev/null 2>&1; then
	launcher=(chrt -b 0)
fi
readarray -t metadata < <(python3 - "$manifest" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    data = json.load(stream)
profile = data["executables"]["cache_gate_profile"]
print(profile["absolute_path"])
print(profile["sha256"])
print(data["architecture"])
print(data["variant"])
print(data["commit"])
PY
)
(( ${#metadata[@]} == 5 )) || { echo "error: malformed build manifest" >&2; exit 1; }
[[ $CACHE_GATE_PERF_BIN == "$(realpath -- "${metadata[0]}")" ]] || { echo "error: profile binary path is not manifested" >&2; exit 1; }
actual_hash=$(sha256sum -- "$CACHE_GATE_PERF_BIN"); actual_hash=${actual_hash%% *}
[[ $actual_hash == "${metadata[1]}" ]] || { echo "error: profile binary hash mismatch" >&2; exit 1; }

expected_pmu=$("$REPO_ROOT/scripts/cache-gate-perf-support.py" select-pmu \
	--architecture "${metadata[2]}" --core "$CORE")
contract=$("$REPO_ROOT/scripts/cache-gate-perf-support.py" bind-contract \
	--root "$CACHE_GATE_CAMPAIGN_ROOT" --key "$CACHE_GATE_CAMPAIGN_KEY" \
	--operation "$operation" --repetition "$repetition" --iterations "$iterations" \
	--core "$CORE" --pmu "$expected_pmu")

destination="$REPO_ROOT/target/cache-gate-perf/${metadata[2]}/${metadata[3]}/$operation/repetition-$repetition"
[[ ! -e $destination ]] || { echo "error: perf destination already exists: $destination" >&2; exit 1; }
mkdir -p "$(dirname "$destination")"
temporary=$(mktemp -d "$(dirname "$destination")/.repetition-$repetition.tmp.XXXXXX")
profile_monitor_pid=
profile_exec_pid=
perf_pid=
cleanup() {
	if [[ -n ${control_fd:-} && -n $perf_pid ]] && kill -0 "$perf_pid" 2>/dev/null; then printf 'disable\n' >&"$control_fd" 2>/dev/null || true; fi
	if [[ -n ${go_fd:-} && -n $profile_exec_pid ]] && kill -0 "$profile_exec_pid" 2>/dev/null; then printf 'STOP\n' >&"$go_fd" 2>/dev/null || true; fi
	[[ -z $profile_exec_pid ]] || kill "$profile_exec_pid" 2>/dev/null || true
	[[ -z $profile_monitor_pid ]] || { kill "$profile_monitor_pid" 2>/dev/null || true; wait "$profile_monitor_pid" 2>/dev/null || true; }
	[[ -z $perf_pid ]] || { kill "$perf_pid" 2>/dev/null || true; wait "$perf_pid" 2>/dev/null || true; }
	rm -rf -- "$temporary"
}
trap cleanup EXIT

ready_fifo="$temporary/ready.fifo"
go_fifo="$temporary/go.fifo"
control_fifo="$temporary/perf-control.fifo"
ack_fifo="$temporary/perf-ack.fifo"
mkfifo "$ready_fifo" "$go_fifo" "$control_fifo" "$ack_fifo"
exec {ready_fd}<>"$ready_fifo"
exec {go_fd}<>"$go_fifo"
exec {control_fd}<>"$control_fifo"
exec {ack_fd}<>"$ack_fifo"

read_bounded() {
	local fd=$1 variable=$2 label=$3 child=$4 value deadline=$((SECONDS + 30))
	while ! IFS= read -r -t 1 -u "$fd" value; do
		kill -0 "$child" 2>/dev/null || { wait "$child" 2>/dev/null || true; echo "error: $label child exited before response" >&2; return 1; }
		((SECONDS < deadline)) || { echo "error: timeout waiting for $label" >&2; return 1; }
	done
	printf -v "$variable" '%s' "$value"
}

"${launcher[@]}" "${numa_wrapper[@]}" "${pin_wrapper[@]}" "$CACHE_GATE_PERF_BIN" --operation "$operation" --iterations "$iterations" --ready-fd "$ready_fd" --go-fd "$go_fd" &
profile_monitor_pid=$!
recorded_profile_monitor_pid=$profile_monitor_pid
read_bounded "$ready_fd" pid_message profile-pid "$profile_monitor_pid"
[[ $pid_message =~ ^PID\ ([1-9][0-9]*)$ ]] || { echo "error: malformed profile PID handshake: $pid_message" >&2; exit 1; }
profile_exec_pid=${BASH_REMATCH[1]}
recorded_profile_pid=$profile_exec_pid
read_bounded "$ready_fd" ready READY "$profile_monitor_pid"
[[ $ready == READY ]] || { echo "error: profile process did not report READY" >&2; exit 1; }
"$REPO_ROOT/scripts/cache-gate-perf-support.py" verify-executable \
	--pid "$profile_exec_pid" --expected "$CACHE_GATE_PERF_BIN"

raw_csv="$temporary/perf-stat.csv"
perf stat -x, -D -1 --control="fifo:$control_fifo,$ack_fifo" \
	-e cycles,instructions,cache-misses,branch-misses -p "$profile_exec_pid" -o "$raw_csv" &
perf_pid=$!
printf 'enable\n' >&"$control_fd"
read_bounded "$ack_fd" enabled_ack enable-ack "$perf_pid"
[[ $enabled_ack == ack ]] || { echo "error: perf did not acknowledge enable" >&2; exit 1; }
printf 'GO\n' >&"$go_fd"
read_bounded "$ready_fd" done DONE "$profile_monitor_pid"
[[ $done == DONE ]] || { echo "error: profile process did not report DONE" >&2; exit 1; }
printf 'disable\n' >&"$control_fd"
read_bounded "$ack_fd" disabled_ack disable-ack "$perf_pid"
[[ $disabled_ack == ack ]] || { echo "error: perf did not acknowledge disable" >&2; exit 1; }
printf 'STOP\n' >&"$go_fd"

profile_status=0
wait "$profile_monitor_pid" || profile_status=$?
profile_monitor_pid=
profile_exec_pid=
perf_status=0
wait "$perf_pid" || perf_status=$?
perf_pid=
((profile_status == 0)) || { echo "error: profile binary exited $profile_status" >&2; exit 1; }
((perf_status == 0)) || { echo "error: perf exited $perf_status" >&2; exit 1; }
[[ -s $raw_csv ]] || { echo "error: perf produced no CSV" >&2; exit 1; }

observed_pmu=$("$REPO_ROOT/scripts/cache-gate-perf-support.py" validate-csv \
	--path "$raw_csv" --expected-pmu "$expected_pmu")

rm -f "$ready_fifo" "$go_fifo" "$control_fifo" "$ack_fifo"
python3 - "$temporary/run-manifest.json" "$manifest" "$operation" "$iterations" "$repetition" "$profile_status" "$perf_status" "$actual_hash" "$original_command" "${metadata[4]}" "$recorded_profile_pid" "$recorded_profile_monitor_pid" "$CORE" "$numa_node" "$observed_pmu" "$contract" "$CACHE_GATE_CAMPAIGN_ROOT" "$CACHE_GATE_CAMPAIGN_KEY" <<'PY'
import json
import platform
import sys

output, manifest, operation, iterations, repetition, profile_status, perf_status, binary_hash, command, commit, profile_pid, profile_monitor_pid, core, numa_node, pmu, contract, campaign_root, campaign_key = sys.argv[1:]
payload = {
    "build_manifest": manifest,
    "commit": commit,
    "operation": operation,
    "iterations": int(iterations),
    "exact_operations": int(iterations) * (100_000 if operation.endswith("-insert") else 1),
    "repetition": int(repetition),
    "profile_pid": int(profile_pid),
    "profile_monitor_pid": int(profile_monitor_pid),
    "core": int(core),
    "numa_node": int(numa_node) if numa_node else None,
    "pmu": pmu,
    "campaign_contract": contract,
    "campaign_contract_root": campaign_root,
    "campaign_key": campaign_key,
    "profile_exit_status": int(profile_status),
    "perf_exit_status": int(perf_status),
    "profile_binary_sha256": binary_hash,
    "host": platform.node(),
    "command": command.rstrip(),
    "counters_initially_disabled": True,
    "setup_and_insert_clears_outside_enabled_window": True,
    "done_disable_ack_stop_handshake": True,
}
with open(output, "w", encoding="utf-8") as stream:
    json.dump(payload, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
mv "$temporary" "$destination"
trap - EXIT
echo "$destination"
