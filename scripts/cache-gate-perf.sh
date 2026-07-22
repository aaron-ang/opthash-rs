#!/usr/bin/env bash
# Collect one operation from an already-manifested profiling executable.

set -euo pipefail

manifest=
operation=
iterations=
repetition=
runner_root=
original_command=$(printf '%q ' "$0" "$@")
while (($#)); do
	case "$1" in
	--runner-root | --manifest | --operation | --iterations | --repetition)
		(($# >= 2)) || { echo "error: missing value for $1" >&2; exit 2; }
		name=${1#--}; name=${name//-/_}; printf -v "$name" '%s' "$2"; shift 2
		;;
	*) echo "error: unsupported argument: $1" >&2; exit 2 ;;
	esac
done
for name in runner_root manifest operation iterations repetition; do
	[[ -n ${!name} ]] || { echo "error: --${name//_/-} is required" >&2; exit 2; }
done
[[ $runner_root == /* ]] || { echo "error: runner root must be absolute" >&2; exit 2; }
runner_root=$(realpath -e -- "$runner_root")
REPO_ROOT=$(git -C "$runner_root" rev-parse --show-toplevel 2>/dev/null) || { echo "error: runner root is not a Git worktree" >&2; exit 2; }
REPO_ROOT=$(realpath -e -- "$REPO_ROOT")
[[ $REPO_ROOT == "$runner_root" ]] || { echo "error: runner root must be exact Git worktree top level" >&2; exit 2; }
cd "$REPO_ROOT"
PERF_LAUNCHER_PATH=$(realpath -e -- "${BASH_SOURCE[0]}")
HARNESS_ROOT=$(git -C "$(dirname "$PERF_LAUNCHER_PATH")" rev-parse --show-toplevel 2>/dev/null) || { echo "error: perf launcher is not in a reviewed Git worktree" >&2; exit 2; }
HARNESS_ROOT=$(realpath -e -- "$HARNESS_ROOT")
[[ $PERF_LAUNCHER_PATH == "$HARNESS_ROOT/"* ]] || { echo "error: perf launcher is outside reviewed harness root" >&2; exit 2; }
CACHE_GATE_ELF_LAYOUT_TOOL=$(realpath -e -- "$HARNESS_ROOT/scripts/cache-gate-elf-layout.py")
CACHE_GATE_PERF_SUPPORT_TOOL=$(realpath -e -- "$HARNESS_ROOT/scripts/cache-gate-perf-support.py")
for tool in "$PERF_LAUNCHER_PATH" "$CACHE_GATE_ELF_LAYOUT_TOOL" "$CACHE_GATE_PERF_SUPPORT_TOOL"; do
	[[ -f $tool && ! -L $tool ]] || { echo "error: invalid reviewed perf tool: $tool" >&2; exit 2; }
done
verify_reviewed_tool_blob() {
	local tool=$1 relative expected actual
	relative=${tool#"$HARNESS_ROOT/"}
	[[ $relative != "$tool" ]] || { echo "error: perf tool is outside reviewed root: $tool" >&2; exit 2; }
	expected=$(git -C "$HARNESS_ROOT" rev-parse "HEAD:$relative")
	actual=$(git hash-object "$tool")
	[[ $actual == "$expected" ]] || { echo "error: perf tool differs from reviewed Git blob: $tool" >&2; exit 2; }
}
verify_manifest_tool_binding() {
	local manifest=$1 name=$2 tool=$3 relative head tree blob
	verify_reviewed_tool_blob "$tool"
	relative=${tool#"$HARNESS_ROOT/"}
	head=$(git -C "$HARNESS_ROOT" rev-parse HEAD)
	tree=$(git -C "$HARNESS_ROOT" rev-parse 'HEAD^{tree}')
	blob=$(git -C "$HARNESS_ROOT" rev-parse "HEAD:$relative")
	python3 - "$manifest" "$name" "$tool" "$HARNESS_ROOT" "$head" "$tree" "$blob" <<'PY'
import hashlib,json,sys
from pathlib import Path
manifest,name,tool,root,head,tree,blob=sys.argv[1:]
record=json.loads(Path(manifest).read_bytes())["tools"][name]
actual=hashlib.sha256(Path(tool).read_bytes()).hexdigest()
if (Path(record.get("absolute_path", "")).resolve()!=Path(tool) or record.get("sha256")!=actual or
    Path(record.get("reviewed_root", "")).resolve()!=Path(root) or record.get("reviewed_commit")!=head or
    record.get("reviewed_tree")!=tree or record.get("git_blob")!=blob or record.get("git_blob_sha256")!=actual):
    raise SystemExit(f"error: manifested {name} is not the executing reviewed tool")
PY
}
case "$operation" in elastic-insert | elastic-get | funnel-insert | funnel-get) ;; *) echo "error: unsupported operation: $operation" >&2; exit 2 ;; esac
[[ $iterations =~ ^[1-9][0-9]*$ ]] || { echo "error: --iterations must be positive" >&2; exit 2; }
[[ $repetition =~ ^[123]$ ]] || { echo "error: --repetition must be 1, 2, or 3" >&2; exit 2; }
[[ -n ${CACHE_GATE_CAMPAIGN_ROOT:-} && $CACHE_GATE_CAMPAIGN_ROOT == /* ]] || { echo "error: absolute CACHE_GATE_CAMPAIGN_ROOT is required" >&2; exit 2; }
CACHE_GATE_CAMPAIGN_ROOT=$(realpath -m -- "$CACHE_GATE_CAMPAIGN_ROOT")
[[ $CACHE_GATE_CAMPAIGN_ROOT == "$REPO_ROOT/target" || $CACHE_GATE_CAMPAIGN_ROOT == "$REPO_ROOT/target/"* ]] || { echo "error: CACHE_GATE_CAMPAIGN_ROOT must stay below runner root target" >&2; exit 2; }
[[ -n ${CACHE_GATE_CAMPAIGN_KEY:-} ]] || { echo "error: CACHE_GATE_CAMPAIGN_KEY is required" >&2; exit 2; }
[[ -n ${CACHE_GATE_PERF_BIN:-} && $CACHE_GATE_PERF_BIN == /* ]] || { echo "error: absolute CACHE_GATE_PERF_BIN is required" >&2; exit 2; }
[[ $manifest == /* ]] || { echo "error: --manifest must be absolute" >&2; exit 2; }
[[ -f $manifest && ! -L $manifest ]] || { echo "error: manifest must be a regular non-symlink file" >&2; exit 2; }
[[ -f $CACHE_GATE_PERF_BIN && ! -L $CACHE_GATE_PERF_BIN ]] || { echo "error: profile binary must be a regular non-symlink file" >&2; exit 2; }
manifest=$(realpath -e -- "$manifest")
CACHE_GATE_PERF_BIN=$(realpath -e -- "$CACHE_GATE_PERF_BIN")
target_root=$(realpath -m -- "$REPO_ROOT/target")
[[ $manifest == "$target_root/"* ]] || { echo "error: manifest must stay below runner root target" >&2; exit 2; }
[[ $CACHE_GATE_PERF_BIN == "$target_root/"* ]] || { echo "error: profile binary must stay below runner root target" >&2; exit 2; }
[[ -x $CACHE_GATE_PERF_BIN ]] || { echo "error: profile binary is not executable" >&2; exit 2; }
verify_manifest_tool_binding "$manifest" perf_launcher "$PERF_LAUNCHER_PATH"
verify_manifest_tool_binding "$manifest" elf_layout "$CACHE_GATE_ELF_LAYOUT_TOOL"
"$CACHE_GATE_ELF_LAYOUT_TOOL" validate-manifest --manifest "$manifest"
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
readarray -t metadata < <(python3 - "$manifest" "$REPO_ROOT" "$(git rev-parse HEAD)" "$(git rev-parse 'HEAD^{tree}')" "$PERF_LAUNCHER_PATH" "$CACHE_GATE_PERF_SUPPORT_TOOL" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

manifest_bytes = Path(sys.argv[1]).read_bytes()
data = json.loads(manifest_bytes)
if Path(data.get("runner_root", "")).resolve()!=Path(sys.argv[2]) or data.get("commit")!=sys.argv[3] or data.get("tree")!=sys.argv[4]:
    raise SystemExit("error: profile manifest runner root/HEAD/tree mismatch")
for name, actual in (("perf_launcher", sys.argv[5]), ("perf_support", sys.argv[6])):
    record=data["tools"][name]
    if Path(record["absolute_path"]).resolve()!=Path(actual):
        raise SystemExit(f"error: manifested {name} differs from executed tool")
profile = data["executables"]["cache_gate_profile"]
print(profile["absolute_path"])
print(profile["sha256"])
print(data["architecture"])
print(data["variant"])
print(data["commit"])
print(json.dumps(data["tools"]["perf_launcher"], sort_keys=True, separators=(",", ":")))
print(json.dumps(data["tools"]["perf_support"], sort_keys=True, separators=(",", ":")))
print(json.dumps(data["tools"]["elf_layout"], sort_keys=True, separators=(",", ":")))
print(hashlib.sha256(manifest_bytes).hexdigest())
PY
)
(( ${#metadata[@]} == 9 )) || { echo "error: malformed build manifest" >&2; exit 1; }
manifest_hash=${metadata[8]}
[[ $CACHE_GATE_PERF_BIN == "$(realpath -- "${metadata[0]}")" ]] || { echo "error: profile binary path is not manifested" >&2; exit 1; }
actual_hash=$(sha256sum -- "$CACHE_GATE_PERF_BIN"); actual_hash=${actual_hash%% *}
[[ $actual_hash == "${metadata[1]}" ]] || { echo "error: profile binary hash mismatch" >&2; exit 1; }

record_sha256() { python3 -c 'import json,sys; print(json.loads(sys.argv[1])["sha256"])' "$1"; }
perf_support_sha256=$(record_sha256 "${metadata[6]}")
elf_layout_sha256=$(record_sha256 "${metadata[7]}")
require_tool_hash() {
	local path=$1 expected=$2 label=$3 actual
	actual=$(sha256sum -- "$path"); actual=${actual%% *}
	[[ $actual == "$expected" ]] || { echo "error: authenticated $label changed before execution" >&2; exit 1; }
}
verify_manifest_tool_binding "$manifest" perf_launcher "$PERF_LAUNCHER_PATH"
verify_manifest_tool_binding "$manifest" elf_layout "$CACHE_GATE_ELF_LAYOUT_TOOL"
"$CACHE_GATE_ELF_LAYOUT_TOOL" validate-manifest --manifest "$manifest"
require_tool_hash "$CACHE_GATE_PERF_SUPPORT_TOOL" "$perf_support_sha256" perf-support
expected_pmu=$("$CACHE_GATE_PERF_SUPPORT_TOOL" select-pmu \
	--architecture "${metadata[2]}" --core "$CORE")
require_tool_hash "$CACHE_GATE_PERF_SUPPORT_TOOL" "$perf_support_sha256" perf-support
contract=$("$CACHE_GATE_PERF_SUPPORT_TOOL" bind-contract \
	--root "$CACHE_GATE_CAMPAIGN_ROOT" --key "$CACHE_GATE_CAMPAIGN_KEY" \
	--operation "$operation" --repetition "$repetition" --iterations "$iterations" \
	--core "$CORE" --pmu "$expected_pmu")

perf_destination_root=$(realpath -m -- "$REPO_ROOT/target/cache-gate-perf/${metadata[2]}")
[[ $perf_destination_root == "$target_root/"* ]] || { echo "error: perf destination root escapes runner target" >&2; exit 1; }
destination=$(realpath -m -- "$perf_destination_root/${metadata[3]}/$operation/repetition-$repetition")
[[ $destination == "$perf_destination_root/"* ]] || { echo "error: perf destination escapes runner target" >&2; exit 1; }
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

verify_manifest_tool_binding "$manifest" perf_launcher "$PERF_LAUNCHER_PATH"
verify_manifest_tool_binding "$manifest" elf_layout "$CACHE_GATE_ELF_LAYOUT_TOOL"
require_tool_hash "$CACHE_GATE_ELF_LAYOUT_TOOL" "$elf_layout_sha256" ELF-validator
"$CACHE_GATE_ELF_LAYOUT_TOOL" validate-manifest --manifest "$manifest"
pre_exec_manifest_hash=$(sha256sum -- "$manifest"); pre_exec_manifest_hash=${pre_exec_manifest_hash%% *}
[[ $pre_exec_manifest_hash == "$manifest_hash" ]] || { echo "error: build manifest changed before execution" >&2; exit 1; }
pre_exec_hash=$(sha256sum -- "$CACHE_GATE_PERF_BIN"); pre_exec_hash=${pre_exec_hash%% *}
[[ $pre_exec_hash == "$actual_hash" ]] || { echo "error: profile binary changed immediately before execution" >&2; exit 1; }
"${launcher[@]}" "${numa_wrapper[@]}" "${pin_wrapper[@]}" "$CACHE_GATE_PERF_BIN" --operation "$operation" --iterations "$iterations" --ready-fd "$ready_fd" --go-fd "$go_fd" &
profile_monitor_pid=$!
recorded_profile_monitor_pid=$profile_monitor_pid
read_bounded "$ready_fd" pid_message profile-pid "$profile_monitor_pid"
[[ $pid_message =~ ^PID\ ([1-9][0-9]*)$ ]] || { echo "error: malformed profile PID handshake: $pid_message" >&2; exit 1; }
profile_exec_pid=${BASH_REMATCH[1]}
recorded_profile_pid=$profile_exec_pid
read_bounded "$ready_fd" ready READY "$profile_monitor_pid"
[[ $ready == READY ]] || { echo "error: profile process did not report READY" >&2; exit 1; }
require_tool_hash "$CACHE_GATE_PERF_SUPPORT_TOOL" "$perf_support_sha256" perf-support
"$CACHE_GATE_PERF_SUPPORT_TOOL" verify-executable \
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

require_tool_hash "$CACHE_GATE_PERF_SUPPORT_TOOL" "$perf_support_sha256" perf-support
observed_pmu=$("$CACHE_GATE_PERF_SUPPORT_TOOL" validate-csv \
	--path "$raw_csv" --expected-pmu "$expected_pmu")
post_exec_manifest_hash=$(sha256sum -- "$manifest"); post_exec_manifest_hash=${post_exec_manifest_hash%% *}
[[ $post_exec_manifest_hash == "$manifest_hash" ]] || { echo "error: build manifest changed during execution" >&2; exit 1; }

rm -f "$ready_fifo" "$go_fifo" "$control_fifo" "$ack_fifo"
python3 - "$temporary/run-manifest.json" "$manifest" "$manifest_hash" "$operation" "$iterations" "$repetition" "$profile_status" "$perf_status" "$actual_hash" "$original_command" "${metadata[4]}" "$recorded_profile_pid" "$recorded_profile_monitor_pid" "$CORE" "$numa_node" "$observed_pmu" "$contract" "$CACHE_GATE_CAMPAIGN_ROOT" "$CACHE_GATE_CAMPAIGN_KEY" "$REPO_ROOT" "$(git rev-parse 'HEAD^{tree}')" "${metadata[5]}" "${metadata[6]}" <<'PY'
import json
import platform
import sys

output, manifest, manifest_hash, operation, iterations, repetition, profile_status, perf_status, binary_hash, command, commit, profile_pid, profile_monitor_pid, core, numa_node, pmu, contract, campaign_root, campaign_key, runner_root, runner_tree, perf_launcher_json, perf_support_json = sys.argv[1:]
perf_launcher = json.loads(perf_launcher_json)
perf_support = json.loads(perf_support_json)
payload = {
    "build_manifest": manifest,
    "build_manifest_sha256": manifest_hash,
    "commit": commit,
    "tree": runner_tree,
    "runner_root": runner_root,
    "tools": {"perf_launcher": perf_launcher, "perf_support": perf_support},
    "reviewed_harness": {
        "root": perf_launcher["reviewed_root"],
        "commit": perf_launcher["reviewed_commit"],
        "tree": perf_launcher["reviewed_tree"],
    },
    "mode": "PROFILE",
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
