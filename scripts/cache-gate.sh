#!/usr/bin/env bash
# Stable cache-gate timing launcher and clean-commit manifest builder.

set -euo pipefail

CACHE_GATE_REALPATH_TOOL=/usr/bin/realpath
CACHE_GATE_STAT_TOOL=/usr/bin/stat
CACHE_GATE_SHA256_TOOL=/usr/bin/sha256sum
for bootstrap_tool in "$CACHE_GATE_REALPATH_TOOL" "$CACHE_GATE_STAT_TOOL" "$CACHE_GATE_SHA256_TOOL"; do
	[[ -f $bootstrap_tool && -x $bootstrap_tool && ! -L $bootstrap_tool ]] || { echo "error: trusted bootstrap tool is unavailable: $bootstrap_tool" >&2; exit 1; }
done

[[ $# -ge 2 && $1 == --runner-root ]] || { echo "error: --runner-root ABS is required" >&2; exit 2; }
runner_root=$2
shift 2
[[ $runner_root == /* ]] || { echo "error: runner root must be absolute" >&2; exit 2; }
runner_root=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$runner_root")
REPO_ROOT=$(git -C "$runner_root" rev-parse --show-toplevel 2>/dev/null) || { echo "error: runner root is not a Git worktree" >&2; exit 2; }
REPO_ROOT=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$REPO_ROOT")
[[ $REPO_ROOT == "$runner_root" ]] || { echo "error: runner root must be exact Git worktree top level" >&2; exit 2; }
cd "$REPO_ROOT"
CACHE_GATE_LAUNCHER_PATH=$("$CACHE_GATE_REALPATH_TOOL" -e -- "${BASH_SOURCE[0]}")
HARNESS_ROOT=$(git -C "$(dirname "$CACHE_GATE_LAUNCHER_PATH")" rev-parse --show-toplevel 2>/dev/null) || { echo "error: cache-gate launcher is not in a reviewed Git worktree" >&2; exit 2; }
HARNESS_ROOT=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$HARNESS_ROOT")
[[ $CACHE_GATE_LAUNCHER_PATH == "$HARNESS_ROOT/"* ]] || { echo "error: cache-gate launcher is outside reviewed harness root" >&2; exit 2; }
CACHE_GATE_ELF_LAYOUT_TOOL=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$HARNESS_ROOT/scripts/cache-gate-elf-layout.py")
CACHE_GATE_SNAPSHOT_TOOL=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$HARNESS_ROOT/scripts/snapshot-criterion-pair.sh")
CACHE_GATE_PERF_TOOL=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$HARNESS_ROOT/scripts/cache-gate-perf.sh")
CACHE_GATE_PERF_SUPPORT_TOOL=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$HARNESS_ROOT/scripts/cache-gate-perf-support.py")
CACHE_GATE_EXTRACTOR_TOOL=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$HARNESS_ROOT/scripts/extract-hot-symbols.py")
CACHE_GATE_LINK_WRAPPER=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$HARNESS_ROOT/scripts/cache-gate-link-wrapper.py")
for tool in "$CACHE_GATE_LAUNCHER_PATH" "$CACHE_GATE_ELF_LAYOUT_TOOL" "$CACHE_GATE_SNAPSHOT_TOOL" "$CACHE_GATE_PERF_TOOL" "$CACHE_GATE_PERF_SUPPORT_TOOL" "$CACHE_GATE_EXTRACTOR_TOOL" "$CACHE_GATE_LINK_WRAPPER"; do
	[[ $tool == /* && -f $tool && ! -L $tool ]] || { echo "error: invalid authenticated harness tool: $tool" >&2; exit 2; }
done
verify_reviewed_tool_blob() {
	local tool=$1 relative expected actual
	relative=${tool#"$HARNESS_ROOT/"}
	[[ $relative != "$tool" ]] || { echo "error: harness tool is outside reviewed root: $tool" >&2; exit 2; }
	expected=$(git -C "$HARNESS_ROOT" rev-parse "HEAD:$relative")
	actual=$(git hash-object "$tool")
	[[ $actual == "$expected" ]] || { echo "error: harness tool differs from reviewed Git blob: $tool" >&2; exit 2; }
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
LOCK_DIR=${LOCK_DIR:-/tmp}
if [[ -n ${OPTHASH_CRITERION_ROOT:-} && $OPTHASH_CRITERION_ROOT != /* ]]; then
	echo "error: OPTHASH_CRITERION_ROOT must be absolute" >&2
	exit 2
fi
CRITERION_ROOT=${OPTHASH_CRITERION_ROOT:-$REPO_ROOT/target/criterion}
CRITERION_ROOT=$("$CACHE_GATE_REALPATH_TOOL" -m -- "$CRITERION_ROOT")
SAVE=${SAVE:-}
LOAD=${LOAD:-}
BASELINE=${BASELINE:-}
IS_LINUX=0
kernel_ostype=
[[ ! -r /proc/sys/kernel/ostype ]] || IFS= read -r kernel_ostype </proc/sys/kernel/ostype
[[ $kernel_ostype == Linux ]] && IS_LINUX=1

mode_count=0
for name in BUILD_CONTROL CONTROL ELASTIC FUNNEL MANIFEST; do
	value=${!name:-0}
	[[ $value == 0 || $value == 1 ]] || { echo "error: $name must be 0 or 1" >&2; exit 2; }
	mode_count=$((mode_count + value))
done
((mode_count == 1)) || { echo "error: select exactly one of BUILD_CONTROL=1, CONTROL=1, ELASTIC=1, FUNNEL=1, MANIFEST=1" >&2; exit 2; }

runner_head=$(git rev-parse HEAD)
runner_tree=$(git rev-parse 'HEAD^{tree}')

stable_manifest_binary=
stable_manifest_hash=
stable_manifest_variant=
stable_build_manifest_hash=
if [[ ${ELASTIC:-0} == 1 || ${FUNNEL:-0} == 1 ]]; then
	[[ -n ${CACHE_GATE_MANIFEST:-} ]] || { echo "error: CACHE_GATE_MANIFEST is required for stable timing" >&2; exit 2; }
	[[ $CACHE_GATE_MANIFEST == /* ]] || { echo "error: CACHE_GATE_MANIFEST must be absolute" >&2; exit 2; }
	[[ -f $CACHE_GATE_MANIFEST && ! -L $CACHE_GATE_MANIFEST ]] || { echo "error: CACHE_GATE_MANIFEST must be a regular non-symlink file" >&2; exit 2; }
	CACHE_GATE_MANIFEST=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$CACHE_GATE_MANIFEST")
	[[ $CACHE_GATE_MANIFEST == "$REPO_ROOT/target/"* ]] || { echo "error: manifest is outside runner root target" >&2; exit 2; }
	verify_manifest_tool_binding "$CACHE_GATE_MANIFEST" launcher "$CACHE_GATE_LAUNCHER_PATH"
	verify_manifest_tool_binding "$CACHE_GATE_MANIFEST" elf_layout "$CACHE_GATE_ELF_LAYOUT_TOOL"
	"$CACHE_GATE_ELF_LAYOUT_TOOL" validate-manifest --manifest "$CACHE_GATE_MANIFEST"
	stable_target=elastic_cache_gate
	[[ ${FUNNEL:-0} == 1 ]] && stable_target=funnel_cache_gate
	readarray -t stable_metadata < <(python3 - "$CACHE_GATE_MANIFEST" "$REPO_ROOT" "$runner_head" "$runner_tree" "$stable_target" "$CACHE_GATE_LAUNCHER_PATH" <<'PY'
import hashlib,json,os,sys
from pathlib import Path
manifest_path,repo,head,tree,target,launcher=sys.argv[1:]
manifest_bytes=Path(manifest_path).read_bytes()
manifest=json.loads(manifest_bytes)
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
if Path(manifest.get("runner_root", "")).resolve()!=Path(repo):
    raise SystemExit("error: manifest runner root mismatch")
if manifest.get("commit")!=head or manifest.get("tree")!=tree or manifest.get("empty_diff_assertion") is not True:
    raise SystemExit("error: immutable runner HEAD/tree mismatch")
capability=manifest.get("linker_capability",{})
if capability.get("accepted") is not True:
    raise SystemExit("error: manifest linker capability is not accepted")
for name,record in manifest.get("tools",{}).items():
    path=Path(record.get("absolute_path", ""))
    if not path.is_absolute() or not path.is_file() or digest(path)!=record.get("sha256"):
        raise SystemExit(f"error: authenticated tool mismatch: {name}")
if Path(manifest["tools"]["launcher"]["absolute_path"]).resolve()!=Path(launcher):
    raise SystemExit("error: stable launcher path differs from manifest")
item=manifest["executables"][target]
binary=Path(item["absolute_path"])
target_root=Path(repo)/"target"
if not binary.is_absolute() or os.path.commonpath([str(target_root),str(binary.resolve())])!=str(target_root):
    raise SystemExit("error: stable binary is outside runner root target")
if not binary.is_file() or digest(binary)!=item["sha256"]:
    raise SystemExit("error: stable binary hash mismatch")
layout=manifest["elf_layout"][target]
if Path(layout["binary"]).resolve()!=binary.resolve() or layout["binary_sha256"]!=item["sha256"]:
    raise SystemExit("error: stable ELF layout does not authenticate binary")
print(binary.resolve())
print(item["sha256"])
print(manifest["variant"])
print(hashlib.sha256(manifest_bytes).hexdigest())
PY
	)
	((${#stable_metadata[@]} == 4)) || { echo "error: malformed stable manifest" >&2; exit 1; }
	stable_manifest_binary=${stable_metadata[0]}
	stable_manifest_hash=${stable_metadata[1]}
	stable_manifest_variant=${stable_metadata[2]}
	stable_build_manifest_hash=${stable_metadata[3]}
fi

if [[ -n "${SUDO_USER:-}" ]]; then
	user_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
	if [[ -x "$user_home/.cargo/bin/cargo" ]]; then
		export PATH="$user_home/.cargo/bin:$PATH"
		export CARGO_HOME="${CARGO_HOME:-$user_home/.cargo}"
		export RUSTUP_HOME="${RUSTUP_HOME:-$user_home/.rustup}"
	fi
fi

require_control_binary() {
	[[ -n ${CACHE_GATE_CONTROL_BIN:-} ]] || { echo "error: CACHE_GATE_CONTROL_BIN is required" >&2; exit 2; }
	[[ $CACHE_GATE_CONTROL_BIN == /* ]] || { echo "error: CACHE_GATE_CONTROL_BIN must be absolute" >&2; exit 2; }
	[[ -x $CACHE_GATE_CONTROL_BIN && -f $CACHE_GATE_CONTROL_BIN ]] || { echo "error: control binary is not executable: $CACHE_GATE_CONTROL_BIN" >&2; exit 2; }
	CACHE_GATE_CONTROL_BIN=$("$CACHE_GATE_REALPATH_TOOL" -- "$CACHE_GATE_CONTROL_BIN")
	CACHE_GATE_CONTROL_PROVENANCE=${CACHE_GATE_CONTROL_PROVENANCE:-$CACHE_GATE_CONTROL_BIN.provenance.json}
	[[ -f $CACHE_GATE_CONTROL_PROVENANCE && ! -L $CACHE_GATE_CONTROL_PROVENANCE ]] || { echo "error: control provenance is missing" >&2; exit 2; }
	CACHE_GATE_CONTROL_PROVENANCE=$("$CACHE_GATE_REALPATH_TOOL" -- "$CACHE_GATE_CONTROL_PROVENANCE")
	python3 - "$CACHE_GATE_CONTROL_BIN" "$CACHE_GATE_CONTROL_PROVENANCE" "$REPO_ROOT" <<'PY'
import hashlib,json,subprocess,sys
from pathlib import Path
binary, provenance_path, repo = sys.argv[1:]
provenance=json.load(open(provenance_path, encoding="utf-8"))
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
record=provenance["binary"]
if Path(record["absolute_path"]).resolve() != Path(binary) or digest(binary) != record["sha256"]:
    raise SystemExit("error: control binary provenance mismatch")
for name,item in provenance["inputs"].items():
    if digest(item["absolute_path"]) != item["sha256"]:
        raise SystemExit(f"error: control input provenance mismatch: {name}")
tree=subprocess.check_output(["git","rev-parse",f'{provenance["builder_commit"]}^{{tree}}'],cwd=repo,text=True).strip()
if tree != provenance["builder_tree"]:
    raise SystemExit("error: control builder tree mismatch")
PY
}

if [[ ${BUILD_CONTROL:-0} == 1 ]]; then
	[[ -z $(git status --porcelain --untracked-files=normal) ]] || { echo "error: BUILD_CONTROL requires a clean immutable worktree" >&2; exit 1; }
	git diff --quiet 849b8b3 -- src || { echo "error: BUILD_CONTROL is allowed only on cache-off production source" >&2; exit 1; }
	git diff --quiet -- src || { echo "error: production source is dirty" >&2; exit 1; }
	if cargo metadata --locked --manifest-path tools/cache-gate-control/Cargo.toml --format-version 1 --no-deps | rg -q '"name":"opthash"'; then
		echo "error: fixed controls depend on opthash" >&2
		exit 1
	fi
	if [[ $EUID -eq 0 && -n ${SUDO_USER:-} ]]; then
		sudo -u "$SUDO_USER" --preserve-env=PATH,CARGO_HOME,RUSTUP_HOME -- cargo build --release --locked --manifest-path tools/cache-gate-control/Cargo.toml
	else
		cargo build --release --locked --manifest-path tools/cache-gate-control/Cargo.toml
	fi
	control_bin=$("$CACHE_GATE_REALPATH_TOOL" -- tools/cache-gate-control/target/release/opthash-cache-gate-control)
	[[ -x $control_bin ]] || { echo "error: control build produced no executable" >&2; exit 1; }
	control_provenance="$control_bin.provenance.json"
	python3 - "$control_provenance" "$control_bin" "$REPO_ROOT" "$(git rev-parse HEAD)" "$(git rev-parse 'HEAD^{tree}')" <<'PY'
import hashlib,json,subprocess,sys
from pathlib import Path
output,binary,repo,commit,tree=sys.argv[1:]
def record(path):
    path=Path(path).resolve()
    return {"absolute_path":str(path),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
payload={
 "builder_commit":commit,"builder_tree":tree,
 "runner_root":str(Path(repo).resolve()),"runner_commit":commit,"runner_tree":tree,"mode":"BUILD_CONTROL",
 "binary":record(binary),
 "inputs":{
  "cargo_manifest":record(Path(repo)/"tools/cache-gate-control/Cargo.toml"),
  "cargo_lock":record(Path(repo)/"tools/cache-gate-control/Cargo.lock"),
  "source":record(Path(repo)/"tools/cache-gate-control/src/main.rs"),
 },
 "cargo_version":subprocess.check_output(["cargo","--version"],text=True).strip(),
 "rustc_version":subprocess.check_output(["rustc","--version","--verbose"],text=True).strip(),
 "locked":True,
}
Path(output+".tmp").write_text(json.dumps(payload,indent=2,sort_keys=True)+"\n")
Path(output+".tmp").replace(output)
PY
	mkdir -p "$REPO_ROOT/target"
	{
		printf '%s\n' "$control_bin"
		printf '%s\n' "$control_provenance"
	} >target/cache-gate-control-bin.txt
	cp -- "$control_provenance" target/cache-gate-control-build.json
	exit 0
fi

criterion_args=()
if [[ ${CONTROL:-0} == 1 || ${ELASTIC:-0} == 1 || ${FUNNEL:-0} == 1 ]]; then
	[[ -z $SAVE || ( -z $LOAD && -z $BASELINE ) ]] || { echo "error: SAVE cannot be combined with LOAD or BASELINE" >&2; exit 2; }
	if [[ -n $LOAD ]]; then
		criterion_args=(--load-baseline "$LOAD" --baseline "${BASELINE:-ref}")
	elif [[ -n $BASELINE ]]; then
		criterion_args=(--baseline "$BASELINE")
	elif [[ -n $SAVE ]]; then
		criterion_args=(--save-baseline "$SAVE")
	else
		echo "error: timing modes require SAVE, LOAD, or BASELINE" >&2
		exit 2
	fi
fi
forward_args=("$@")
if ((${#forward_args[@]} > 0)) && [[ ${forward_args[0]} == -- ]]; then
	forward_args=("${forward_args[@]:1}")
fi

claim_directory_lock() {
	local name=$1 key_source=$2 lock key
	if [[ $name == bench-root ]]; then key=$(printf '%s' "$key_source" | "$CACHE_GATE_SHA256_TOOL"); key=${key%% *}; lock="$LOCK_DIR/opthash-bench-root-$key.lock"; else lock="$LOCK_DIR/opthash-bench-core-$key_source.lock"; fi
	mkdir -p "$LOCK_DIR" 2>/dev/null || true
	if [[ -L $lock ]] || { [[ -e $lock ]] && [[ ! -d $lock && ! -f $lock ]]; }; then
		echo "error: unsafe lock: $lock" >&2
		exit 1
	fi
	if [[ ! -e $lock ]] && ! mkdir -m 0755 "$lock" 2>/dev/null && [[ ! -e $lock ]]; then
		echo "error: cannot create lock: $lock" >&2
		exit 1
	fi
	exec {lock_fd}<"$lock"
	"${CACHE_GATE_FLOCK_TOOL:?}" "$lock_fd"
}

detect_perf_core() {
	local maximum=0 path frequency candidate=()
	for path in /sys/devices/system/cpu/cpu*/cpufreq/cpuinfo_max_freq; do
		frequency=$(<"$path") 2>/dev/null || continue
		((frequency > maximum)) && maximum=$frequency
	done
	for path in /sys/devices/system/cpu/cpu*/cpufreq/cpuinfo_max_freq; do
		frequency=$(<"$path") 2>/dev/null || continue
		if ((frequency == maximum)); then
			local cpu=${path#/sys/devices/system/cpu/cpu}
			candidate+=("${cpu%/cpufreq/cpuinfo_max_freq}")
		fi
	done
	if ((${#candidate[@]} == 0)); then CORE=0; return; fi
	CORE=${candidate[0]}
	for cpu in "${candidate[@]}"; do ((cpu < CORE)) && CORE=$cpu; done
	return 0
}

resolve_trusted_system_tool() {
	local name=$1 path owner mode
	path=$(type -P -- "$name") || { echo "error: required system tool is unavailable: $name" >&2; exit 1; }
	path=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$path")
	[[ $path == /* && -f $path && -x $path && ! -L $path ]] || { echo "error: invalid system tool: $name" >&2; exit 1; }
	owner=$("$CACHE_GATE_STAT_TOOL" -Lc '%u' -- "$path")
	mode=$("$CACHE_GATE_STAT_TOOL" -Lc '%a' -- "$path")
	[[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ ]] || { echo "error: untrusted system tool ownership/mode: $path" >&2; exit 1; }
	(( (8#$mode & 8#022) == 0 )) || { echo "error: writable system tool is not trusted: $path" >&2; exit 1; }
	printf '%s\n' "$path"
}

prepare_launcher() {
	local env_tool flock_tool taskset_tool setarch_tool numactl_tool nice_tool prlimit_tool sudo_tool chrt_tool node_dir candidate_node_dir
	launcher=()
	numa_wrapper=()
	pin_wrapper=()
	measurement_system_tools=()
	env_tool=$(resolve_trusted_system_tool env)
	measurement_system_tools+=("$env_tool")
	criterion_env=("$env_tool" -u CRITERION_HOME)
	if [[ -n ${OPTHASH_CRITERION_ROOT:-} ]]; then criterion_env=("$env_tool" "CRITERION_HOME=$CRITERION_ROOT"); fi
	if ((IS_LINUX)); then
		[[ -n ${CORE:-} ]] || detect_perf_core
		[[ $CORE =~ ^[0-9]+$ ]] || { echo "error: CORE must be one CPU number" >&2; exit 2; }
		flock_tool=$(resolve_trusted_system_tool flock)
		CACHE_GATE_FLOCK_TOOL=$flock_tool
		measurement_system_tools+=("$flock_tool")
		claim_directory_lock bench-root "$("$CACHE_GATE_REALPATH_TOOL" -m -- "$CRITERION_ROOT")"
		claim_directory_lock bench-core "$CORE"
		taskset_tool=$(resolve_trusted_system_tool taskset)
		setarch_tool=$(resolve_trusted_system_tool setarch)
		measurement_system_tools+=("$taskset_tool" "$setarch_tool")
		pin_wrapper=("$taskset_tool" -c "$CORE" "$setarch_tool" -R)
		if type -P numactl >/dev/null 2>&1; then
			numactl_tool=$(resolve_trusted_system_tool numactl)
			node_count=0
			for node_dir in /sys/devices/system/node/node[0-9]*; do
				[[ -d $node_dir ]] && node_count=$((node_count + 1))
			done
			if ((node_count > 1)); then
				node_dir=
				for candidate_node_dir in "/sys/devices/system/cpu/cpu$CORE"/node[0-9]*; do
					[[ -d $candidate_node_dir ]] || continue
					node_dir=$candidate_node_dir
					break
				done
				if [[ -n $node_dir ]]; then
					measurement_system_tools+=("$numactl_tool")
					numa_wrapper=("$numactl_tool" --membind="${node_dir##*/node}")
				fi
			fi
		fi
		if [[ $EUID -eq 0 ]]; then
			if type -P nice >/dev/null 2>&1; then
				nice_tool=$(resolve_trusted_system_tool nice)
				measurement_system_tools+=("$nice_tool")
				launcher+=("$nice_tool" -n -20)
			fi
			if type -P prlimit >/dev/null 2>&1; then
				prlimit_tool=$(resolve_trusted_system_tool prlimit)
				measurement_system_tools+=("$prlimit_tool")
				launcher+=("$prlimit_tool" --memlock=unlimited --)
			fi
			if [[ -n ${SUDO_USER:-} ]]; then
				sudo_tool=$(resolve_trusted_system_tool sudo)
				measurement_system_tools+=("$sudo_tool")
				launcher+=("$sudo_tool" -u "$SUDO_USER" --preserve-env=PATH,CARGO_HOME,RUSTUP_HOME --)
			fi
		elif type -P chrt >/dev/null 2>&1; then
			chrt_tool=$(resolve_trusted_system_tool chrt)
			measurement_system_tools+=("$chrt_tool")
			launcher=("$chrt_tool" -b 0)
		fi
	fi
	return 0
}

write_save_evidence() {
	local output=$1 mode=$2 manifest=$3 manifest_hash=$4 control_provenance=$5 control_provenance_hash=$6 binary=$7 binary_hash=$8
	shift 8
	python3 - "$output" "$REPO_ROOT" "$runner_head" "$runner_tree" "$mode" "$SAVE" \
		"$CRITERION_ROOT" "$manifest" "$manifest_hash" "$control_provenance" \
		"$control_provenance_hash" "$binary" "$binary_hash" "$@" <<'PY'
import hashlib,json,os,subprocess,sys
from pathlib import Path

(output,root,commit,tree,mode,run,criterion_root,manifest,manifest_hash,
 control_provenance,control_provenance_hash,binary,binary_hash,producer_launcher,
 harness_root,core,*arguments)=sys.argv[1:]
def take(values):
    if not values: raise SystemExit("error: truncated SAVE measurement metadata")
    try: count=int(values.pop(0))
    except ValueError: raise SystemExit("error: invalid SAVE measurement count")
    if count<0 or len(values)<count: raise SystemExit("error: truncated SAVE measurement argv")
    result=values[:count]; del values[:count]
    return result
launcher_prefix=take(arguments)
numa_wrapper=take(arguments)
pin_wrapper=take(arguments)
criterion_environment=take(arguments)
system_tool_paths=take(arguments)
executable_argv=take(arguments)
benchmark_ids=take(arguments)
if arguments: raise SystemExit("error: trailing SAVE measurement metadata")
root=Path(root).resolve()
actual_root=Path(subprocess.check_output(["git","-C",str(root),"rev-parse","--show-toplevel"],text=True).strip()).resolve()
actual_commit=subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD"],text=True).strip()
actual_tree=subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD^{tree}"],text=True).strip()
status=subprocess.check_output(["git","-C",str(root),"status","--porcelain","--untracked-files=no"],text=True)
if actual_root!=root or actual_commit!=commit or actual_tree!=tree or status.strip():
    raise SystemExit("error: SAVE runner revision changed before evidence capture")
producer_launcher_path=Path(producer_launcher)
harness=Path(harness_root)
if (not producer_launcher_path.is_absolute() or producer_launcher_path.is_symlink() or
    not producer_launcher_path.is_file() or not harness.is_absolute() or harness.is_symlink()):
    raise SystemExit("error: invalid SAVE producer launcher")
producer_launcher_path=producer_launcher_path.resolve(strict=True)
harness=harness.resolve(strict=True)
actual_harness=Path(subprocess.check_output(
    ["git","-C",str(harness),"rev-parse","--show-toplevel"],text=True).strip()).resolve()
harness_commit=subprocess.check_output(["git","-C",str(harness),"rev-parse","HEAD"],text=True).strip()
harness_tree=subprocess.check_output(["git","-C",str(harness),"rev-parse","HEAD^{tree}"],text=True).strip()
harness_status=subprocess.check_output(
    ["git","-C",str(harness),"status","--porcelain","--untracked-files=no"],text=True)
if actual_harness!=harness or harness_status.strip():
    raise SystemExit("error: SAVE producer harness is not an immutable reviewed worktree")
try: launcher_relative=producer_launcher_path.relative_to(harness).as_posix()
except ValueError: raise SystemExit("error: SAVE producer launcher is outside reviewed harness")
launcher_blob=subprocess.check_output(
    ["git","-C",str(harness),"rev-parse",f"HEAD:{launcher_relative}"],text=True).strip()
launcher_blob_bytes=subprocess.check_output(
    ["git","-C",str(harness),"show",f"HEAD:{launcher_relative}"])
launcher_bytes=producer_launcher_path.read_bytes()
launcher_hash=hashlib.sha256(launcher_bytes).hexdigest()
if launcher_blob_bytes!=launcher_bytes:
    raise SystemExit("error: SAVE producer launcher differs from reviewed Git blob")
producer_launcher_record={
    "absolute_path":str(producer_launcher_path),"sha256":launcher_hash,
    "git_blob":launcher_blob,"git_blob_sha256":hashlib.sha256(launcher_blob_bytes).hexdigest(),
    "reviewed_root":str(harness),"reviewed_commit":harness_commit,"reviewed_tree":harness_tree,
}
if len(system_tool_paths)!=len(set(system_tool_paths)):
    raise SystemExit("error: duplicate SAVE system tool record")
system_tools=[]
for value in system_tool_paths:
    path=Path(value)
    if (not path.is_absolute() or path.is_symlink() or not path.is_file() or
        not os.access(path,os.X_OK) or str(path.resolve(strict=True))!=value):
        raise SystemExit(f"error: invalid SAVE system tool: {value}")
    metadata=path.stat()
    if metadata.st_uid!=0 or metadata.st_mode & 0o022:
        raise SystemExit(f"error: mutable SAVE system tool: {value}")
    system_tools.append({"absolute_path":value,"sha256":hashlib.sha256(path.read_bytes()).hexdigest()})
criterion_root=Path(criterion_root).resolve(strict=True)
output=Path(output)
if output.exists() or output.is_symlink():
    raise SystemExit(f"error: SAVE run evidence already exists: {output}")
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
binary_path=Path(binary).resolve(strict=True)
if binary_path.is_symlink() or not binary_path.is_file() or digest(binary_path)!=binary_hash:
    raise SystemExit("error: SAVE executable changed before evidence capture")
if (len(executable_argv)<4 or executable_argv[:4]!=[
        str(binary_path),"--bench","--save-baseline",run]):
    raise SystemExit("error: SAVE executable argv does not match authenticated run")
manifest_record=None
control_record=None
if manifest:
    manifest_path=Path(manifest).resolve(strict=True)
    if manifest_path.is_symlink() or digest(manifest_path)!=manifest_hash:
        raise SystemExit("error: SAVE build manifest changed before evidence capture")
    manifest_record={"absolute_path":str(manifest_path),"sha256":manifest_hash}
if control_provenance:
    control_path=Path(control_provenance).resolve(strict=True)
    if control_path.is_symlink() or digest(control_path)!=control_provenance_hash:
        raise SystemExit("error: SAVE control provenance changed before evidence capture")
    control_record={"absolute_path":str(control_path),"sha256":control_provenance_hash}
results=[]
for benchmark in benchmark_ids:
    baseline_path=criterion_root/benchmark/run
    cursor=criterion_root
    for part in baseline_path.relative_to(criterion_root).parts:
        cursor=cursor/part
        if cursor.is_symlink():
            raise SystemExit(f"error: symlink in SAVE baseline path: {cursor}")
    baseline=baseline_path.resolve()
    try: baseline.relative_to(criterion_root)
    except ValueError: raise SystemExit(f"error: SAVE baseline escapes Criterion root: {baseline}")
    if not baseline.is_dir():
        raise SystemExit(f"error: missing SAVE baseline directory: {baseline}")
    baseline_files=[]
    for current, directories, files in os.walk(baseline, followlinks=False):
        current_path=Path(current)
        for name in directories:
            path=current_path/name
            if path.is_symlink(): raise SystemExit(f"error: symlink in SAVE baseline: {path}")
        for name in files:
            path=current_path/name
            if path.is_symlink() or not path.is_file():
                raise SystemExit(f"error: invalid SAVE result file: {path}")
            relative=path.relative_to(criterion_root).as_posix()
            baseline_files.append({"absolute_path":str(path.resolve()),"relative_path":relative,
                                   "sha256":digest(path),"size":path.stat().st_size})
    if not any(item["relative_path"]==f"{benchmark}/{run}/estimates.json" for item in baseline_files):
        raise SystemExit(f"error: SAVE baseline lacks estimates.json: {benchmark}")
    results.extend(sorted(baseline_files,key=lambda item:item["relative_path"]))
payload={
 "schema":"opthash-criterion-run-v2","runner_root":str(root),"commit":commit,
 "tree":tree,"empty_diff_assertion":True,"mode":mode,"run":run,
 "criterion_evidence_root":str(criterion_root),"build_manifest":manifest_record,
 "control_provenance":control_record,
 "producer_launcher":producer_launcher_record,
 "measurement":{
  "core":core or None,"launcher_prefix":launcher_prefix,"numa_wrapper":numa_wrapper,
  "pin_wrapper":pin_wrapper,"criterion_environment":criterion_environment,
  "system_tools":system_tools,
  "executable_argv":executable_argv,
  "executed_argv":launcher_prefix+numa_wrapper+pin_wrapper+criterion_environment+executable_argv,
 },
 "executable":{"absolute_path":str(binary_path),"sha256":binary_hash},
 "expected_benchmark_ids":benchmark_ids,"results":results,
}
output.parent.mkdir(parents=True,exist_ok=True)
temporary=output.with_name(output.name+f".tmp.{os.getpid()}")
with temporary.open("x",encoding="utf-8") as stream:
    json.dump(payload,stream,indent=2,sort_keys=True); stream.write("\n")
    stream.flush(); os.fsync(stream.fileno())
temporary.replace(output)
PY
}

prepare_save_evidence() {
	expected_save_ids=()
	if [[ ${CONTROL:-0} == 1 ]]; then
		expected_save_ids=(cache_gate_insert/cache_gate_insert_std cache_gate_insert/cache_gate_insert_hashbrown)
		save_mode=CONTROL
		save_binary=$CACHE_GATE_CONTROL_BIN
		save_binary_hash=$("$CACHE_GATE_SHA256_TOOL" -- "$save_binary"); save_binary_hash=${save_binary_hash%% *}
		save_manifest=
		save_manifest_hash=
		save_control_provenance=$CACHE_GATE_CONTROL_PROVENANCE
		save_control_provenance_hash=$("$CACHE_GATE_SHA256_TOOL" -- "$save_control_provenance"); save_control_provenance_hash=${save_control_provenance_hash%% *}
		save_evidence="$REPO_ROOT/target/cache-gate-runs/control/$SAVE.json"
	elif [[ ${ELASTIC:-0} == 1 ]]; then
		expected_save_ids=(cache_gate_insert/cache_gate_insert_elastic cache_gate_get_hit_elastic)
		save_mode=elastic_cache_gate
		save_binary=$stable_manifest_binary
		save_binary_hash=$stable_manifest_hash
		save_manifest=$CACHE_GATE_MANIFEST
		save_manifest_hash=$stable_build_manifest_hash
		save_control_provenance=
		save_control_provenance_hash=
		save_evidence="$REPO_ROOT/target/cache-gate-runs/$stable_manifest_variant/elastic_cache_gate-$SAVE.json"
	else
		expected_save_ids=(cache_gate_insert/cache_gate_insert_funnel cache_gate_get_hit_funnel)
		save_mode=funnel_cache_gate
		save_binary=$stable_manifest_binary
		save_binary_hash=$stable_manifest_hash
		save_manifest=$CACHE_GATE_MANIFEST
		save_manifest_hash=$stable_build_manifest_hash
		save_control_provenance=
		save_control_provenance_hash=
		save_evidence="$REPO_ROOT/target/cache-gate-runs/$stable_manifest_variant/funnel_cache_gate-$SAVE.json"
	fi
	runner_target_root=$("$CACHE_GATE_REALPATH_TOOL" -m -- "$REPO_ROOT/target")
	stable_runs_root=$("$CACHE_GATE_REALPATH_TOOL" -m -- "$REPO_ROOT/target/cache-gate-runs")
	[[ $stable_runs_root == "$runner_target_root/"* ]] || { echo "error: stable run root escapes runner target" >&2; exit 1; }
	save_evidence=$("$CACHE_GATE_REALPATH_TOOL" -m -- "$save_evidence")
	[[ $save_evidence == "$stable_runs_root/"* ]] || { echo "error: stable run destination escapes runner target" >&2; exit 1; }
	[[ -n $SAVE ]] || return 0
	((IS_LINUX)) || { echo "error: authenticated SAVE evidence requires Linux pinning" >&2; exit 1; }
	[[ $SAVE =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ && $SAVE != . && $SAVE != .. ]] || { echo "error: unsafe SAVE evidence name" >&2; exit 2; }
	[[ ! -e $save_evidence && ! -L $save_evidence ]] || { echo "error: SAVE run evidence already exists: $save_evidence" >&2; exit 1; }
	python3 - "$CRITERION_ROOT" "$SAVE" "${expected_save_ids[@]}" <<'PY'
import sys
from pathlib import Path

root=Path(sys.argv[1])
run=sys.argv[2]
root.mkdir(parents=True,exist_ok=True)
root=root.resolve(strict=True)
for benchmark in sys.argv[3:]:
    cursor=root
    for part in Path(benchmark).parts:
        if part in {"", ".", ".."}:
            raise SystemExit(f"error: unsafe SAVE benchmark component: {benchmark}")
        cursor=cursor/part
        if cursor.is_symlink():
            raise SystemExit(f"error: symlink in SAVE benchmark path: {cursor}")
        cursor.mkdir(exist_ok=True)
        if not cursor.is_dir():
            raise SystemExit(f"error: non-directory in SAVE benchmark path: {cursor}")
    baseline=cursor/run
    if baseline.exists() or baseline.is_symlink():
        raise SystemExit(f"error: SAVE baseline already exists: {baseline}")
PY
	for benchmark in "${expected_save_ids[@]}"; do
		baseline="$CRITERION_ROOT/$benchmark/$SAVE"
		[[ ! -e $baseline && ! -L $baseline ]] || { echo "error: SAVE baseline already exists: $baseline" >&2; exit 1; }
	done
}

if [[ ${CONTROL:-0} == 1 || ${ELASTIC:-0} == 1 || ${FUNNEL:-0} == 1 ]]; then
	verify_reviewed_tool_blob "$CACHE_GATE_LAUNCHER_PATH"
	prepare_launcher
	if [[ ${CONTROL:-0} == 1 ]]; then
		require_control_binary
		executable_argv=("$CACHE_GATE_CONTROL_BIN" --bench "${criterion_args[@]}" "${forward_args[@]}")
	else
		verify_manifest_tool_binding "$CACHE_GATE_MANIFEST" launcher "$CACHE_GATE_LAUNCHER_PATH"
		verify_manifest_tool_binding "$CACHE_GATE_MANIFEST" elf_layout "$CACHE_GATE_ELF_LAYOUT_TOOL"
		"$CACHE_GATE_ELF_LAYOUT_TOOL" validate-manifest --manifest "$CACHE_GATE_MANIFEST"
		pre_exec_manifest_hash=$("$CACHE_GATE_SHA256_TOOL" -- "$CACHE_GATE_MANIFEST"); pre_exec_manifest_hash=${pre_exec_manifest_hash%% *}
		[[ $pre_exec_manifest_hash == "$stable_build_manifest_hash" ]] || { echo "error: stable build manifest changed before execution" >&2; exit 1; }
		actual_hash=$("$CACHE_GATE_SHA256_TOOL" -- "$stable_manifest_binary"); actual_hash=${actual_hash%% *}
		[[ $actual_hash == "$stable_manifest_hash" ]] || { echo "error: stable binary hash mismatch immediately before execution" >&2; exit 1; }
		executable_argv=("$stable_manifest_binary" --bench "${criterion_args[@]}" "${forward_args[@]}")
	fi
	command=("${numa_wrapper[@]}" "${pin_wrapper[@]}" "${criterion_env[@]}" "${executable_argv[@]}")
	measurement_core=
	((${#pin_wrapper[@]} == 0)) || measurement_core=$CORE
	prepare_save_evidence
	"${launcher[@]}" "${command[@]}"
	if [[ -n $SAVE ]]; then
		if [[ ${ELASTIC:-0} == 1 || ${FUNNEL:-0} == 1 ]]; then
			post_exec_manifest_hash=$("$CACHE_GATE_SHA256_TOOL" -- "$CACHE_GATE_MANIFEST"); post_exec_manifest_hash=${post_exec_manifest_hash%% *}
		[[ $post_exec_manifest_hash == "$stable_build_manifest_hash" ]] || { echo "error: stable build manifest changed during execution" >&2; exit 1; }
		fi
		write_save_evidence "$save_evidence" "$save_mode" "$save_manifest" "$save_manifest_hash" \
			"$save_control_provenance" "$save_control_provenance_hash" \
			"$save_binary" "$save_binary_hash" "$CACHE_GATE_LAUNCHER_PATH" "$HARNESS_ROOT" "$measurement_core" \
			"${#launcher[@]}" "${launcher[@]}" \
			"${#numa_wrapper[@]}" "${numa_wrapper[@]}" \
			"${#pin_wrapper[@]}" "${pin_wrapper[@]}" \
			"${#criterion_env[@]}" "${criterion_env[@]}" \
			"${#measurement_system_tools[@]}" "${measurement_system_tools[@]}" \
			"${#executable_argv[@]}" "${executable_argv[@]}" \
			"${#expected_save_ids[@]}" "${expected_save_ids[@]}"
	fi
	exit 0
fi

require_control_binary
[[ -n ${CACHE_GATE_VARIANT:-} ]] || { echo "error: CACHE_GATE_VARIANT is required" >&2; exit 2; }
[[ $CACHE_GATE_VARIANT =~ ^[A-Za-z0-9._-]+$ ]] || { echo "error: unsafe CACHE_GATE_VARIANT" >&2; exit 2; }
[[ -n ${CACHE_GATE_MANIFEST_INSTANCE:-} ]] || { echo "error: CACHE_GATE_MANIFEST_INSTANCE is required" >&2; exit 2; }
[[ $CACHE_GATE_MANIFEST_INSTANCE =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || { echo "error: unsafe CACHE_GATE_MANIFEST_INSTANCE" >&2; exit 2; }
[[ -z $(git status --porcelain --untracked-files=normal) ]] || { echo "error: MANIFEST requires a clean worktree" >&2; exit 1; }
git diff --quiet HEAD -- || { echo "error: tracked diff is not empty" >&2; exit 1; }

case $(uname -m) in
aarch64 | arm64) arch=aarch64 ;;
x86_64 | amd64) arch=x86_64 ;;
*) echo "error: unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
esac
[[ -n ${CACHE_GATE_LINKER_CAPABILITY:-} && $CACHE_GATE_LINKER_CAPABILITY == /* ]] || { echo "error: absolute CACHE_GATE_LINKER_CAPABILITY is required" >&2; exit 2; }
capability_input=$CACHE_GATE_LINKER_CAPABILITY
[[ ${CARGO_PROFILE_RELEASE_CODEGEN_UNITS:-16} == 16 ]] || { echo "error: conflicting CARGO_PROFILE_RELEASE_CODEGEN_UNITS" >&2; exit 2; }
[[ ${RUSTFLAGS:-} != *codegen-units* && ${CARGO_ENCODED_RUSTFLAGS:-} != *codegen-units* ]] || { echo "error: conflicting rustc codegen-unit configuration" >&2; exit 2; }
[[ -z ${CARGO_ENCODED_RUSTFLAGS:-} ]] || { echo "error: CARGO_ENCODED_RUSTFLAGS is unsupported for authenticated manifest builds" >&2; exit 2; }
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
manifest_dir="$REPO_ROOT/target/cache-gate/$arch/$CACHE_GATE_VARIANT"
build_root="$REPO_ROOT/target/cache-gate-build/$CACHE_GATE_MANIFEST_INSTANCE"
[[ ! -e $manifest_dir && ! -e $build_root ]] || { echo "error: variant output already exists" >&2; exit 1; }
staging_uid=$(id -u)
staging_gid=$(id -g)
if [[ $EUID -eq 0 && -n ${SUDO_USER:-} ]]; then
	staging_uid=$(id -u "$SUDO_USER")
	staging_gid=$(id -g "$SUDO_USER")
fi
mkdir -p "$REPO_ROOT/target"
authenticated_tools_staging=$(mktemp "$REPO_ROOT/target/.cache-gate-authenticated-tools.XXXXXX")
cleanup_authenticated_tools() { rm -f -- "$authenticated_tools_staging"; }
trap cleanup_authenticated_tools EXIT
verify_reviewed_tool_blob "$CACHE_GATE_ELF_LAYOUT_TOOL"
"$CACHE_GATE_ELF_LAYOUT_TOOL" authenticate-tools --output "$authenticated_tools_staging" \
	--tool "elf_layout=$CACHE_GATE_ELF_LAYOUT_TOOL" \
	--tool "snapshot=$CACHE_GATE_SNAPSHOT_TOOL" \
	--tool "launcher=$CACHE_GATE_LAUNCHER_PATH" \
	--tool "perf_launcher=$CACHE_GATE_PERF_TOOL" \
	--tool "perf_support=$CACHE_GATE_PERF_SUPPORT_TOOL" \
	--tool "extractor=$CACHE_GATE_EXTRACTOR_TOOL" \
	--tool "link_wrapper=$CACHE_GATE_LINK_WRAPPER"
"$CACHE_GATE_PERF_SUPPORT_TOOL" prepare-staging \
	--manifest-root "$manifest_dir" --build-root "$build_root" \
	--uid "$staging_uid" --gid "$staging_gid"
authenticated_tools="$manifest_dir/authenticated-tools.json"
mv -- "$authenticated_tools_staging" "$authenticated_tools"
trap - EXIT
head_commit=$(git rev-parse HEAD)
head_tree=$(git rev-parse 'HEAD^{tree}')
head_epoch=$(git show -s --format=%ct HEAD)
mkdir -p "$manifest_dir/linker-fragments" "$manifest_dir/layout" "$manifest_dir/link-traces" "$manifest_dir/link-commands"
cp -- "$REPO_ROOT/benches/cache-gate-elastic-layout.ld" "$manifest_dir/linker-fragments/elastic.ld"
cp -- "$REPO_ROOT/benches/cache-gate-funnel-layout.ld" "$manifest_dir/linker-fragments/funnel.ld"
cp -- "$REPO_ROOT/benches/cache-gate-profile-layout.ld" "$manifest_dir/linker-fragments/profile.ld"
mapfile -t staged_capability < <("$CACHE_GATE_ELF_LAYOUT_TOOL" stage-validate-capability --input "$capability_input" \
	--output "$manifest_dir/linker-capability.json" --arch "$arch" --tools "$authenticated_tools")
((${#staged_capability[@]} == 3)) || { echo "error: invalid staged capability result" >&2; exit 1; }
CACHE_GATE_LINK_DRIVER=${staged_capability[0]}
capability_identity=${staged_capability[1]}
capability_document_b64=${staged_capability[2]}
CACHE_GATE_LINKER_CAPABILITY="$manifest_dir/linker-capability.json"
verify_staged_capability() {
	"$CACHE_GATE_ELF_LAYOUT_TOOL" verify-staged-capability \
		--path "$CACHE_GATE_LINKER_CAPABILITY" --identity "$capability_identity" || {
		echo "error: staged capability identity changed" >&2
		exit 1
	}
}
verify_staged_capability

build_bench() {
	local -n result=$1
	local bench=$2 target=$3 fragment="$manifest_dir/linker-fragments/$3.ld"
	local map_path="$manifest_dir/link-maps/$bench.map" json_path="$manifest_dir/$bench.cargo.json" verbose_path="$manifest_dir/$bench.rustc.txt" executable
	local trace_path="$manifest_dir/link-traces/$bench.jsonl" command_path="$manifest_dir/link-commands/$bench.json"
	local rustflags="${RUSTFLAGS:-} -C codegen-units=16 -C link-arg=-Wl,-T,$fragment -C link-arg=-Wl,-Map,$map_path -C linker=$CACHE_GATE_LINK_WRAPPER"
	verify_staged_capability
	[[ ! -e $trace_path && ! -e $command_path ]] || { echo "error: link proof output already exists for $bench" >&2; exit 1; }
	if [[ ${CACHE_GATE_LAYOUT_ADVERSARY:-0} == 1 ]]; then
		rustflags+=" --cfg cache_gate_layout_adversary --check-cfg=cfg(cache_gate_layout_adversary)"
	elif [[ ${CACHE_GATE_LAYOUT_ADVERSARY:-0} != 0 ]]; then
		echo "error: CACHE_GATE_LAYOUT_ADVERSARY must be 0 or 1" >&2; exit 2
	fi
	if [[ $EUID -eq 0 && -n ${SUDO_USER:-} ]]; then
		sudo -u "$SUDO_USER" --preserve-env=PATH,CARGO_HOME,RUSTUP_HOME -- env \
			CACHE_GATE_LINK_DRIVER="$CACHE_GATE_LINK_DRIVER" CACHE_GATE_LINK_TRACE="$trace_path" \
			CARGO_TARGET_DIR="$build_root" CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 RUSTFLAGS="$rustflags" \
			cargo build -vv --release --locked --bench "$bench" --message-format=json >"$json_path" 2>"$verbose_path" || return 1
	else
		CACHE_GATE_LINK_DRIVER="$CACHE_GATE_LINK_DRIVER" CACHE_GATE_LINK_TRACE="$trace_path" \
			CARGO_TARGET_DIR="$build_root" CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 RUSTFLAGS="$rustflags" \
			cargo build -vv --release --locked --bench "$bench" --message-format=json >"$json_path" 2>"$verbose_path" || return 1
	fi
	rg -q -- 'codegen-units(=|[[:space:]]+)16' "$verbose_path" || { echo "error: captured rustc argv lacks -C codegen-units=16 for $bench" >&2; exit 1; }
	verify_staged_capability
	executable=$("$CACHE_GATE_ELF_LAYOUT_TOOL" select-cargo-executable \
		--cargo-output "$json_path" --bench "$bench") || return 1
	executable=$("$CACHE_GATE_REALPATH_TOOL" -- "$executable") || return 1
	[[ -x $executable && -s $map_path ]] || { echo "error: missing executable or link map for $bench" >&2; exit 1; }
	(($("$CACHE_GATE_STAT_TOOL" -c %Y "$executable") >= head_epoch)) || { echo "error: stale artifact for $bench" >&2; exit 1; }
	"$CACHE_GATE_ELF_LAYOUT_TOOL" validate-link-command \
		--trace "$trace_path" --executable "$executable" \
		--capability "$CACHE_GATE_LINKER_CAPABILITY" --capability-identity "$capability_identity" --fragment "$fragment" \
		--link-map "$map_path" --output "$command_path" || return 1
	verify_staged_capability
	result=$executable
}

build_bench elastic_bin elastic_cache_gate elastic || exit 1
build_bench funnel_bin funnel_cache_gate funnel || exit 1
build_bench profile_bin cache_gate_profile profile || exit 1

"$CACHE_GATE_EXTRACTOR_TOOL" --binary "$elastic_bin" --arch "$arch" \
	--symbol '::elastic_cache_gate_insert_kernel$' --symbol '::elastic_cache_gate_get_kernel$' \
	--output "$manifest_dir/symbols/elastic_cache_gate.json"
"$CACHE_GATE_EXTRACTOR_TOOL" --binary "$funnel_bin" --arch "$arch" \
	--symbol '::funnel_cache_gate_insert_kernel$' --symbol '::funnel_cache_gate_get_kernel$' \
	--output "$manifest_dir/symbols/funnel_cache_gate.json"
"$CACHE_GATE_EXTRACTOR_TOOL" --binary "$profile_bin" --arch "$arch" \
	--symbol '::elastic_profile_insert_kernel$' --symbol '::elastic_profile_get_kernel$' \
	--symbol '::funnel_profile_insert_kernel$' --symbol '::funnel_profile_get_kernel$' \
	--output "$manifest_dir/symbols/cache_gate_profile.json"

for executable in elastic_cache_gate funnel_cache_gate cache_gate_profile; do
	case "$executable" in
	elastic_cache_gate) binary=$elastic_bin; target=elastic ;;
	funnel_cache_gate) binary=$funnel_bin; target=funnel ;;
	cache_gate_profile) binary=$profile_bin; target=profile ;;
	esac
	verify_staged_capability
	CACHE_GATE_LINKER_CAPABILITY="$manifest_dir/linker-capability.json" \
		CACHE_GATE_LINKER_CAPABILITY_IDENTITY="$capability_identity" \
		"$CACHE_GATE_ELF_LAYOUT_TOOL" validate --binary "$binary" \
		--link-map "$manifest_dir/link-maps/$executable.map" \
		--script "$manifest_dir/linker-fragments/$target.ld" \
		--symbols "$manifest_dir/symbols/$executable.json" --arch "$arch" \
		--output "$manifest_dir/layout/$executable.json"
	verify_staged_capability
done

verify_staged_capability
python3 - "$manifest_dir/manifest.json" "$head_commit" "$head_tree" "$arch" "$CACHE_GATE_VARIANT" "$CACHE_GATE_CONTROL_BIN" "$CACHE_GATE_CONTROL_PROVENANCE" "$elastic_bin" "$funnel_bin" "$profile_bin" "$REPO_ROOT" "${CACHE_GATE_LAYOUT_ADVERSARY:-0}" "$CACHE_GATE_MANIFEST_INSTANCE" "$authenticated_tools" "$capability_identity" "$capability_document_b64" <<'PY'
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

output, commit, tree, arch, variant, control, control_provenance_path, elastic, funnel, profile, repo, adversary, instance, authenticated_tools_path, capability_identity, capability_document_b64 = sys.argv[1:]
root = Path(output).parent
repository = Path(repo)

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

executables = {}
for name, path in {
    "elastic_cache_gate": elastic,
    "funnel_cache_gate": funnel,
    "cache_gate_profile": profile,
}.items():
    link_map = root / "link-maps" / f"{name}.map"
    executables[name] = {
        "absolute_path": str(Path(path).resolve()),
        "sha256": digest(path),
        "link_map": {
            "absolute_path": str(link_map.resolve()),
            "sha256": digest(link_map),
        },
    }
symbols = {}
elf_layout = {}
for name in executables:
    path = root / "symbols" / f"{name}.json"
    with path.open(encoding="utf-8") as stream:
        symbols[name] = json.load(stream)
    elf_layout[name] = json.load((root / "layout" / f"{name}.json").open(encoding="utf-8"))
    executables[name]["symbols"] = {
        "absolute_path": str(path.resolve()),
        "sha256": digest(path),
    }
    layout_path = root / "layout" / f"{name}.json"
    executables[name]["layout"] = {
        "absolute_path": str(layout_path.resolve()),
        "sha256": digest(layout_path),
    }
    link_command_path = root / "link-commands" / f"{name}.json"
    executables[name]["link_command"] = {
        "absolute_path": str(link_command_path.resolve()),
        "sha256": digest(link_command_path),
    }
    link_trace_path = root / "link-traces" / f"{name}.jsonl"
    executables[name]["link_trace"] = {
        "absolute_path": str(link_trace_path.resolve()),
        "sha256": digest(link_trace_path),
    }
    target = {"elastic_cache_gate":"elastic", "funnel_cache_gate":"funnel", "cache_gate_profile":"profile"}[name]
    fragment_path = root / "linker-fragments" / f"{target}.ld"
    executables[name]["linker_fragment"] = {
        "absolute_path": str(fragment_path.resolve()),
        "sha256": digest(fragment_path),
    }
control_provenance = json.load(open(control_provenance_path, encoding="utf-8"))
capability_path = root / "linker-capability.json"
capability_bytes = base64.b64decode(capability_document_b64, validate=True)
if hashlib.sha256(capability_bytes).hexdigest() != capability_identity.rsplit(":", 1)[1]:
    raise SystemExit("staged capability changed during manifest construction")
linker_capability = json.loads(capability_bytes)
linker_capability["copy"] = {
    "absolute_path": str(capability_path),
    "sha256": capability_identity.rsplit(":", 1)[1],
}

def fingerprint(values):
    return hashlib.sha256(("\n".join(values)+"\n").encode()).hexdigest()

proof_executables={}
all_cgus=[]
all_objects=[]
all_link_order=[]
all_reserved=[]
adversary_enabled=adversary=="1"
for name,item in executables.items():
    link_command=json.load((root/"link-commands"/f"{name}.json").open(encoding="utf-8"))
    inputs=link_command["ordered_linker_inputs"]
    archive_members=[Path(owner).name for owner in elf_layout[name]["archive_member_owners"]]
    objects=sorted(set(link_command["direct_input_files"]+archive_members))
    cgus=sorted(set(link_command["direct_cgu_members"]+[value for value in archive_members if ".rcgu.o" in value]))
    reserved=[Path(kernel["input_owner"]).name for kernel in elf_layout[name]["kernels"].values()]
    rustc_lines=[line.strip() for line in (root/f"{name}.rustc.txt").read_text(errors="replace").splitlines() if "rustc" in line and "Running" in line]
    if not rustc_lines or not any(re.search(r"codegen-units(?:=|\s+)16",line) for line in rustc_lines):
        raise SystemExit(f"error: incomplete captured rustc argv: {name}")
    nm=subprocess.check_output(["nm","-S","-n","-C",item["absolute_path"]],text=True)
    adversary_symbols=[]
    for line in nm.splitlines():
        match=re.match(r"^([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+[tT]\s+(.+cache_gate_layout_adversary_private.*)$",line)
        if match: adversary_symbols.append({"start":int(match.group(1),16),"size":int(match.group(2),16),"name":match.group(3)})
    input_count=sum(entry.get("section")==".text.opthash.cache_gate.layout_adversary" for entry in elf_layout[name]["cache_gate_input_sections"])
    reservations=[(kernel["reservation_start"],kernel["reservation_end"]) for kernel in elf_layout[name]["kernels"].values()]
    outside=all(not any(start <= symbol["start"] < end for start,end in reservations) for symbol in adversary_symbols)
    expected_count=1 if adversary_enabled else 0
    if len(adversary_symbols)!=expected_count or input_count!=expected_count or not outside:
        raise SystemExit(f"error: adversary symbol/section proof is not exact: {name}")
    proof_executables[name]={
        "rustc_argv":rustc_lines,
        "emitted_object_members":objects,
        "ordered_linker_inputs":inputs,
        "direct_linker_input_files":link_command["direct_input_files"],
        "archive_member_owners":archive_members,
        "cgu_members":cgus,
        "object_member_fingerprint":fingerprint(objects),
        "link_order_fingerprint":link_command["ordered_linker_input_fingerprint"],
        "cgu_partition_fingerprint":fingerprint(cgus),
        "reserved_input_owners":reserved,
        "reserved_input_owner_fingerprint":fingerprint(reserved),
        "link_command":link_command,
        "adversary":{"symbol_occurrences":adversary_symbols,"input_section_occurrences":input_count,"outside_reservations":outside},
    }
    all_cgus.extend(f"{name}:{value}" for value in cgus)
    all_objects.extend(f"{name}:{value}" for value in objects)
    all_link_order.extend(f"{name}:{value}" for value in inputs)
    all_reserved.extend(f"{name}:{value}" for value in reserved)

tools=json.load(open(authenticated_tools_path,encoding="utf-8"))
payload = {
    "commit": commit,
    "tree": tree,
    "empty_diff_assertion": True,
    "architecture": arch,
    "variant": variant,
    "manifest_instance": instance,
    "runner_root": str(repository.resolve()),
    "mode": "MANIFEST",
    "build": {
        "cargo_incremental": "0",
        "profile": "release",
        "locked": True,
        "rustc_flags": ["-C", "codegen-units=16", "-C", "link-arg=-Wl,-T,<target-fragment>", "-C", "link-arg=-Wl,-Map,<per-target-map>"],
        "linker_flags": ["-Wl,-T,<target-fragment>", "-Wl,-Map,<per-target-map>"],
        "codegen_units": 16,
    },
    "control": {
        **control_provenance,
        "provenance_path": str(Path(control_provenance_path).resolve()),
        "provenance_sha256": digest(control_provenance_path),
    },
    "executables": executables,
    "symbols": symbols,
    "elf_layout": elf_layout,
    "linker_capability": linker_capability,
    "tools": tools,
    "build_proof": {
        "codegen_units":16,
        "executables":proof_executables,
        "cgu_partition_fingerprint":fingerprint(all_cgus),
        "object_member_fingerprint":fingerprint(all_objects),
        "link_order_fingerprint":fingerprint(all_link_order),
        "reserved_input_owner_fingerprint":fingerprint(all_reserved),
    },
    "layout_adversary":{"enabled":adversary_enabled,"symbol":"cache_gate_layout_adversary_private","input_section":".text.opthash.cache_gate.layout_adversary"},
}
with open(output + ".tmp", "w", encoding="utf-8") as stream:
    json.dump(payload, stream, indent=2, sort_keys=True)
    stream.write("\n")
Path(output + ".tmp").replace(output)
PY

verify_staged_capability
symbol_count=$(jq '[.symbols[].symbols[]] | length' "$manifest_dir/manifest.json")
[[ $symbol_count == 8 ]] || { echo "error: manifest resolved $symbol_count symbols, expected 8" >&2; exit 1; }
verify_staged_capability
echo "$manifest_dir/manifest.json"
