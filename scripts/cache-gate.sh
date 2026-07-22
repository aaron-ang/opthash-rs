#!/usr/bin/env bash
# Stable cache-gate timing launcher and clean-commit manifest builder.

set -euo pipefail

[[ $# -ge 2 && $1 == --runner-root ]] || { echo "error: --runner-root ABS is required" >&2; exit 2; }
runner_root=$2
shift 2
[[ $runner_root == /* ]] || { echo "error: runner root must be absolute" >&2; exit 2; }
runner_root=$(realpath -e -- "$runner_root")
REPO_ROOT=$(git -C "$runner_root" rev-parse --show-toplevel 2>/dev/null) || { echo "error: runner root is not a Git worktree" >&2; exit 2; }
REPO_ROOT=$(realpath -e -- "$REPO_ROOT")
[[ $REPO_ROOT == "$runner_root" ]] || { echo "error: runner root must be exact Git worktree top level" >&2; exit 2; }
cd "$REPO_ROOT"
HARNESS_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
CACHE_GATE_LAUNCHER_PATH=$(realpath -e -- "${CACHE_GATE_LAUNCHER:-${BASH_SOURCE[0]}}")
CACHE_GATE_ELF_LAYOUT_TOOL=$(realpath -e -- "${CACHE_GATE_ELF_LAYOUT_TOOL:-$HARNESS_ROOT/scripts/cache-gate-elf-layout.py}")
CACHE_GATE_SNAPSHOT_TOOL=$(realpath -e -- "${CACHE_GATE_SNAPSHOT_TOOL:-$HARNESS_ROOT/scripts/snapshot-criterion-pair.sh}")
CACHE_GATE_PERF_TOOL=$(realpath -e -- "${CACHE_GATE_PERF_TOOL:-$HARNESS_ROOT/scripts/cache-gate-perf.sh}")
CACHE_GATE_LINK_WRAPPER=$(realpath -e -- "${CACHE_GATE_LINK_WRAPPER:-$HARNESS_ROOT/scripts/cache-gate-link-wrapper.py}")
for tool in "$CACHE_GATE_LAUNCHER_PATH" "$CACHE_GATE_ELF_LAYOUT_TOOL" "$CACHE_GATE_SNAPSHOT_TOOL" "$CACHE_GATE_PERF_TOOL" "$CACHE_GATE_LINK_WRAPPER"; do
	[[ $tool == /* && -f $tool && ! -L $tool ]] || { echo "error: invalid authenticated harness tool: $tool" >&2; exit 2; }
done
LOCK_DIR=${LOCK_DIR:-/tmp}
CRITERION_ROOT=${OPTHASH_CRITERION_ROOT:-$REPO_ROOT/target/criterion}
SAVE=${SAVE:-}
LOAD=${LOAD:-}
BASELINE=${BASELINE:-}
IS_LINUX=0
[[ $(uname) == Linux ]] && IS_LINUX=1

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
if [[ ${ELASTIC:-0} == 1 || ${FUNNEL:-0} == 1 ]]; then
	[[ -n ${CACHE_GATE_MANIFEST:-} ]] || { echo "error: CACHE_GATE_MANIFEST is required for stable timing" >&2; exit 2; }
	[[ $CACHE_GATE_MANIFEST == /* ]] || { echo "error: CACHE_GATE_MANIFEST must be absolute" >&2; exit 2; }
	CACHE_GATE_MANIFEST=$(realpath -e -- "$CACHE_GATE_MANIFEST")
	[[ $CACHE_GATE_MANIFEST == "$REPO_ROOT/target/"* ]] || { echo "error: manifest is outside runner root target" >&2; exit 2; }
	stable_target=elastic_cache_gate
	[[ ${FUNNEL:-0} == 1 ]] && stable_target=funnel_cache_gate
	readarray -t stable_metadata < <(python3 - "$CACHE_GATE_MANIFEST" "$REPO_ROOT" "$runner_head" "$runner_tree" "$stable_target" "$CACHE_GATE_LAUNCHER_PATH" <<'PY'
import hashlib,json,os,sys
from pathlib import Path
manifest_path,repo,head,tree,target,launcher=sys.argv[1:]
manifest=json.load(open(manifest_path,encoding="utf-8"))
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
PY
	)
	((${#stable_metadata[@]} == 3)) || { echo "error: malformed stable manifest" >&2; exit 1; }
	stable_manifest_binary=${stable_metadata[0]}
	stable_manifest_hash=${stable_metadata[1]}
	stable_manifest_variant=${stable_metadata[2]}
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
	CACHE_GATE_CONTROL_BIN=$(realpath -- "$CACHE_GATE_CONTROL_BIN")
	CACHE_GATE_CONTROL_PROVENANCE=${CACHE_GATE_CONTROL_PROVENANCE:-$CACHE_GATE_CONTROL_BIN.provenance.json}
	[[ -f $CACHE_GATE_CONTROL_PROVENANCE && ! -L $CACHE_GATE_CONTROL_PROVENANCE ]] || { echo "error: control provenance is missing" >&2; exit 2; }
	CACHE_GATE_CONTROL_PROVENANCE=$(realpath -- "$CACHE_GATE_CONTROL_PROVENANCE")
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
	control_bin=$(realpath -- tools/cache-gate-control/target/release/opthash-cache-gate-control)
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
	if [[ $name == bench-root ]]; then key=$(printf '%s' "$key_source" | sha256sum); key=${key%% *}; lock="$LOCK_DIR/opthash-bench-root-$key.lock"; else lock="$LOCK_DIR/opthash-bench-core-$key_source.lock"; fi
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
	flock "$lock_fd"
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

prepare_launcher() {
	launcher=()
	numa_wrapper=()
	pin_wrapper=()
	criterion_env=(env -u CRITERION_HOME)
	if [[ -n ${OPTHASH_CRITERION_ROOT:-} ]]; then criterion_env=(env "CRITERION_HOME=$CRITERION_ROOT"); fi
	if ((IS_LINUX)); then
		[[ -n ${CORE:-} ]] || detect_perf_core
		[[ $CORE =~ ^[0-9]+$ ]] || { echo "error: CORE must be one CPU number" >&2; exit 2; }
		claim_directory_lock bench-root "$(realpath -m -- "$CRITERION_ROOT")"
		claim_directory_lock bench-core "$CORE"
		pin_wrapper=(taskset -c "$CORE" setarch -R)
		if command -v numactl >/dev/null 2>&1; then
			node_count=$(find /sys/devices/system/node -maxdepth 1 -name 'node[0-9]*' -type d 2>/dev/null | wc -l)
			if ((node_count > 1)); then
				node_dir=$(find "/sys/devices/system/cpu/cpu$CORE" -maxdepth 1 -name 'node[0-9]*' 2>/dev/null | head -1)
				[[ -z $node_dir ]] || numa_wrapper=(numactl --membind="${node_dir##*/node}")
			fi
		fi
		if [[ $EUID -eq 0 ]]; then
			command -v nice >/dev/null 2>&1 && launcher+=(nice -n -20)
			command -v prlimit >/dev/null 2>&1 && launcher+=(prlimit --memlock=unlimited --)
			if [[ -n ${SUDO_USER:-} ]]; then
				launcher+=(sudo -u "$SUDO_USER" --preserve-env=PATH,CARGO_HOME,RUSTUP_HOME --)
			fi
		elif command -v chrt >/dev/null 2>&1; then
			launcher=(chrt -b 0)
		fi
	fi
	return 0
}

if [[ ${CONTROL:-0} == 1 || ${ELASTIC:-0} == 1 || ${FUNNEL:-0} == 1 ]]; then
	prepare_launcher
	if [[ ${CONTROL:-0} == 1 ]]; then
		require_control_binary
		command=("${numa_wrapper[@]}" "${pin_wrapper[@]}" "${criterion_env[@]}" "$CACHE_GATE_CONTROL_BIN" --bench "${criterion_args[@]}" "${forward_args[@]}")
	else
		actual_hash=$(sha256sum -- "$stable_manifest_binary"); actual_hash=${actual_hash%% *}
		[[ $actual_hash == "$stable_manifest_hash" ]] || { echo "error: stable binary hash mismatch immediately before execution" >&2; exit 1; }
		command=("${numa_wrapper[@]}" "${pin_wrapper[@]}" "${criterion_env[@]}" "$stable_manifest_binary" --bench "${criterion_args[@]}" "${forward_args[@]}")
	fi
	"${launcher[@]}" "${command[@]}"
	if [[ ${CONTROL:-0} == 1 ]]; then
		run_name=${SAVE:-${LOAD:-${BASELINE:-comparison}}}
		[[ $run_name =~ ^[A-Za-z0-9._-]+$ ]] || { echo "error: unsafe run metadata name" >&2; exit 2; }
		run_dir="$REPO_ROOT/target/cache-gate-runs/control"
		mkdir -p "$run_dir"
		control_hash=$(sha256sum -- "$CACHE_GATE_CONTROL_BIN"); control_hash=${control_hash%% *}
		python3 - "$run_dir/$run_name.json" "$REPO_ROOT" "$runner_head" "$runner_tree" "$CACHE_GATE_CONTROL_BIN" "$control_hash" "$run_name" "$CRITERION_ROOT" <<'PY'
import json,sys
output,root,commit,tree,binary,binary_hash,run,evidence_root=sys.argv[1:]
json.dump({"runner_root":root,"commit":commit,"tree":tree,"mode":"CONTROL","run":run,"executable":{"absolute_path":binary,"sha256":binary_hash},"criterion_evidence_root":evidence_root,"build_commands":[]},open(output,"w"),indent=2,sort_keys=True);open(output,"a").write("\n")
PY
	elif [[ ${ELASTIC:-0} == 1 || ${FUNNEL:-0} == 1 ]]; then
		run_name=${SAVE:-${LOAD:-${BASELINE:-comparison}}}
		[[ $run_name =~ ^[A-Za-z0-9._-]+$ ]] || { echo "error: unsafe run metadata name" >&2; exit 2; }
		run_dir="$REPO_ROOT/target/cache-gate-runs/$stable_manifest_variant"
		mkdir -p "$run_dir"
		python3 - "$run_dir/$stable_target-$run_name.json" "$REPO_ROOT" "$runner_head" "$runner_tree" "$CACHE_GATE_MANIFEST" "$stable_manifest_binary" "$stable_manifest_hash" "$stable_target" "$run_name" "$CRITERION_ROOT" <<'PY'
import json,sys
output,root,commit,tree,manifest,binary,binary_hash,mode,run,evidence_root=sys.argv[1:]
json.dump({"runner_root":root,"commit":commit,"tree":tree,"mode":mode,"run":run,"build_manifest":manifest,"executable":{"absolute_path":binary,"sha256":binary_hash},"criterion_evidence_root":evidence_root,"build_commands":[]},open(output,"w"),indent=2,sort_keys=True);open(output,"a").write("\n")
PY
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
CACHE_GATE_LINKER_CAPABILITY=$(realpath -e -- "$CACHE_GATE_LINKER_CAPABILITY")
CACHE_GATE_LINK_DRIVER=$(python3 - "$CACHE_GATE_LINKER_CAPABILITY" "$REPO_ROOT" "$arch" <<'PY'
import hashlib,json,subprocess,sys
from pathlib import Path
path,repo,arch=sys.argv[1:]
capability=json.load(open(path,encoding="utf-8"))
if capability.get("accepted") is not True or capability.get("arch")!=arch:
    raise SystemExit("error: linker capability is not accepted for this architecture")
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
if set(capability.get("fragments",{}))!={"elastic","funnel","profile"}:
    raise SystemExit("error: linker fragment capability set mismatch")
for target,record in capability["fragments"].items():
    expected=(Path(repo)/f"benches/cache-gate-{target}-layout.ld").resolve()
    source=Path(record["absolute_path"])
    if not source.is_absolute() or not source.is_file() or digest(source)!=record["sha256"] or digest(expected)!=record["sha256"]:
        raise SystemExit(f"error: linker fragment capability mismatch: {target}")
driver=Path(capability["linker"]["absolute_path"])
if not driver.is_absolute() or not driver.is_file():
    raise SystemExit("error: capability linker path is invalid")
version=next((line for line in subprocess.check_output([str(driver),"-Wl,--version"],stderr=subprocess.STDOUT,text=True).splitlines() if "GNU ld" in line or "LLD" in line or "lld" in line),"")
if version!=capability["linker"]["version"]:
    raise SystemExit("error: actual linker identity differs from capability")
print(driver.resolve())
PY
)
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
"$REPO_ROOT/scripts/cache-gate-perf-support.py" prepare-staging \
	--manifest-root "$manifest_dir" --build-root "$build_root" \
	--uid "$staging_uid" --gid "$staging_gid"
head_commit=$(git rev-parse HEAD)
head_tree=$(git rev-parse 'HEAD^{tree}')
head_epoch=$(git show -s --format=%ct HEAD)
cp -- "$CACHE_GATE_LINKER_CAPABILITY" "$manifest_dir/linker-capability.json"
mkdir -p "$manifest_dir/linker-fragments" "$manifest_dir/layout" "$manifest_dir/link-traces" "$manifest_dir/link-commands"
cp -- "$REPO_ROOT/benches/cache-gate-elastic-layout.ld" "$manifest_dir/linker-fragments/elastic.ld"
cp -- "$REPO_ROOT/benches/cache-gate-funnel-layout.ld" "$manifest_dir/linker-fragments/funnel.ld"
cp -- "$REPO_ROOT/benches/cache-gate-profile-layout.ld" "$manifest_dir/linker-fragments/profile.ld"

build_bench() {
	local bench=$1 target=$2 fragment="$manifest_dir/linker-fragments/$2.ld"
	local map_path="$manifest_dir/link-maps/$1.map" json_path="$manifest_dir/$1.cargo.json" verbose_path="$manifest_dir/$1.rustc.txt" executable
	local trace_path="$manifest_dir/link-traces/$1.jsonl" command_path="$manifest_dir/link-commands/$1.json"
	local rustflags="${RUSTFLAGS:-} -C codegen-units=16 -C link-arg=-Wl,-T,$fragment -C link-arg=-Wl,-Map,$map_path -C linker=$CACHE_GATE_LINK_WRAPPER"
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
			cargo build -vv --release --locked --bench "$bench" --message-format=json >"$json_path" 2>"$verbose_path"
	else
		CACHE_GATE_LINK_DRIVER="$CACHE_GATE_LINK_DRIVER" CACHE_GATE_LINK_TRACE="$trace_path" \
			CARGO_TARGET_DIR="$build_root" CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 RUSTFLAGS="$rustflags" \
			cargo build -vv --release --locked --bench "$bench" --message-format=json >"$json_path" 2>"$verbose_path"
	fi
	rg -q -- 'codegen-units(=|[[:space:]]+)16' "$verbose_path" || { echo "error: captured rustc argv lacks -C codegen-units=16 for $bench" >&2; exit 1; }
	executable=$("$CACHE_GATE_ELF_LAYOUT_TOOL" select-cargo-executable \
		--cargo-output "$json_path" --bench "$bench")
	executable=$(realpath -- "$executable")
	[[ -x $executable && -s $map_path ]] || { echo "error: missing executable or link map for $bench" >&2; exit 1; }
	(($(stat -c %Y "$executable") >= head_epoch)) || { echo "error: stale artifact for $bench" >&2; exit 1; }
	"$CACHE_GATE_ELF_LAYOUT_TOOL" validate-link-command \
		--trace "$trace_path" --executable "$executable" \
		--capability "$CACHE_GATE_LINKER_CAPABILITY" --fragment "$fragment" \
		--link-map "$map_path" --output "$command_path"
	printf '%s\n' "$executable"
}

elastic_bin=$(build_bench elastic_cache_gate elastic)
funnel_bin=$(build_bench funnel_cache_gate funnel)
profile_bin=$(build_bench cache_gate_profile profile)

"$REPO_ROOT/scripts/extract-hot-symbols.py" --binary "$elastic_bin" --arch "$arch" \
	--symbol '::elastic_cache_gate_insert_kernel$' --symbol '::elastic_cache_gate_get_kernel$' \
	--output "$manifest_dir/symbols/elastic_cache_gate.json"
"$REPO_ROOT/scripts/extract-hot-symbols.py" --binary "$funnel_bin" --arch "$arch" \
	--symbol '::funnel_cache_gate_insert_kernel$' --symbol '::funnel_cache_gate_get_kernel$' \
	--output "$manifest_dir/symbols/funnel_cache_gate.json"
"$REPO_ROOT/scripts/extract-hot-symbols.py" --binary "$profile_bin" --arch "$arch" \
	--symbol '::elastic_profile_insert_kernel$' --symbol '::elastic_profile_get_kernel$' \
	--symbol '::funnel_profile_insert_kernel$' --symbol '::funnel_profile_get_kernel$' \
	--output "$manifest_dir/symbols/cache_gate_profile.json"

for executable in elastic_cache_gate funnel_cache_gate cache_gate_profile; do
	case "$executable" in
	elastic_cache_gate) binary=$elastic_bin; target=elastic ;;
	funnel_cache_gate) binary=$funnel_bin; target=funnel ;;
	cache_gate_profile) binary=$profile_bin; target=profile ;;
	esac
	CACHE_GATE_LINKER_CAPABILITY="$manifest_dir/linker-capability.json" \
		"$CACHE_GATE_ELF_LAYOUT_TOOL" validate --binary "$binary" \
		--link-map "$manifest_dir/link-maps/$executable.map" \
		--script "$manifest_dir/linker-fragments/$target.ld" \
		--symbols "$manifest_dir/symbols/$executable.json" --arch "$arch" \
		--output "$manifest_dir/layout/$executable.json"
done

authenticated_tools="$manifest_dir/authenticated-tools.json"
"$CACHE_GATE_ELF_LAYOUT_TOOL" authenticate-tools --output "$authenticated_tools" \
	--tool "elf_layout=$CACHE_GATE_ELF_LAYOUT_TOOL" \
	--tool "snapshot=$CACHE_GATE_SNAPSHOT_TOOL" \
	--tool "launcher=$CACHE_GATE_LAUNCHER_PATH" \
	--tool "perf=$CACHE_GATE_PERF_TOOL" \
	--tool "link_wrapper=$CACHE_GATE_LINK_WRAPPER"

python3 - "$manifest_dir/manifest.json" "$head_commit" "$head_tree" "$arch" "$CACHE_GATE_VARIANT" "$CACHE_GATE_CONTROL_BIN" "$CACHE_GATE_CONTROL_PROVENANCE" "$elastic_bin" "$funnel_bin" "$profile_bin" "$REPO_ROOT" "${CACHE_GATE_LAYOUT_ADVERSARY:-0}" "$CACHE_GATE_MANIFEST_INSTANCE" "$authenticated_tools" <<'PY'
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

output, commit, tree, arch, variant, control, control_provenance_path, elastic, funnel, profile, repo, adversary, instance, authenticated_tools_path = sys.argv[1:]
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
control_provenance = json.load(open(control_provenance_path, encoding="utf-8"))
capability_path = root / "linker-capability.json"
linker_capability = json.load(capability_path.open(encoding="utf-8"))
linker_capability["copy"] = {
    "absolute_path": str(capability_path.resolve()),
    "sha256": digest(capability_path),
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

symbol_count=$(jq '[.symbols[].symbols[]] | length' "$manifest_dir/manifest.json")
[[ $symbol_count == 8 ]] || { echo "error: manifest resolved $symbol_count symbols, expected 8" >&2; exit 1; }
echo "$manifest_dir/manifest.json"
