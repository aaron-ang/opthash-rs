#!/usr/bin/env bash
# Stable cache-gate timing launcher and clean-commit manifest builder.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$REPO_ROOT"
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
		bench=elastic_cache_gate
		[[ ${FUNNEL:-0} == 1 ]] && bench=funnel_cache_gate
		command=("${numa_wrapper[@]}" "${pin_wrapper[@]}" "${criterion_env[@]}" cargo bench --locked --bench "$bench" -- "${criterion_args[@]}" "${forward_args[@]}")
	fi
	"${launcher[@]}" "${command[@]}"
	exit 0
fi

require_control_binary
[[ -n ${CACHE_GATE_VARIANT:-} ]] || { echo "error: CACHE_GATE_VARIANT is required" >&2; exit 2; }
[[ $CACHE_GATE_VARIANT =~ ^[A-Za-z0-9._-]+$ ]] || { echo "error: unsafe CACHE_GATE_VARIANT" >&2; exit 2; }
[[ -z $(git status --porcelain --untracked-files=normal) ]] || { echo "error: MANIFEST requires a clean worktree" >&2; exit 1; }
git diff --quiet HEAD -- || { echo "error: tracked diff is not empty" >&2; exit 1; }

case $(uname -m) in
aarch64 | arm64) arch=aarch64 ;;
x86_64 | amd64) arch=x86_64 ;;
*) echo "error: unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
esac
manifest_dir="$REPO_ROOT/target/cache-gate/$arch/$CACHE_GATE_VARIANT"
build_root="$REPO_ROOT/target/cache-gate-build/$arch/$CACHE_GATE_VARIANT"
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

build_bench() {
	local bench=$1 map_path="$manifest_dir/link-maps/$1.map" json_path="$manifest_dir/$1.cargo.json" executable
	if [[ $EUID -eq 0 && -n ${SUDO_USER:-} ]]; then
		sudo -u "$SUDO_USER" --preserve-env=PATH,CARGO_HOME,RUSTUP_HOME -- env \
			CARGO_TARGET_DIR="$build_root" CARGO_INCREMENTAL=0 RUSTFLAGS="-C link-arg=-Wl,-Map,$map_path" \
			cargo build --release --locked --bench "$bench" --message-format=json >"$json_path"
	else
		CARGO_TARGET_DIR="$build_root" CARGO_INCREMENTAL=0 RUSTFLAGS="-C link-arg=-Wl,-Map,$map_path" \
			cargo build --release --locked --bench "$bench" --message-format=json >"$json_path"
	fi
	executable=$(python3 - "$json_path" "$bench" <<'PY'
import json
import sys

paths = []
success = False
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        event = json.loads(line)
        if event.get("reason") == "compiler-artifact" and event.get("target", {}).get("name") == sys.argv[2] and event.get("executable"):
            paths.append(event["executable"])
        if event.get("reason") == "build-finished":
            success = event.get("success") is True
paths = sorted(set(paths))
if not success or len(paths) != 1:
    raise SystemExit(f"expected one successful Cargo executable, got {paths!r}")
print(paths[0])
PY
)
	executable=$(realpath -- "$executable")
	[[ -x $executable && -s $map_path ]] || { echo "error: missing executable or link map for $bench" >&2; exit 1; }
	(($(stat -c %Y "$executable") >= head_epoch)) || { echo "error: stale artifact for $bench" >&2; exit 1; }
	printf '%s\n' "$executable"
}

elastic_bin=$(build_bench elastic_cache_gate)
funnel_bin=$(build_bench funnel_cache_gate)
profile_bin=$(build_bench cache_gate_profile)

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

python3 - "$manifest_dir/manifest.json" "$head_commit" "$head_tree" "$arch" "$CACHE_GATE_VARIANT" "$CACHE_GATE_CONTROL_BIN" "$CACHE_GATE_CONTROL_PROVENANCE" "$elastic_bin" "$funnel_bin" "$profile_bin" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

output, commit, tree, arch, variant, control, control_provenance_path, elastic, funnel, profile = sys.argv[1:]
root = Path(output).parent
repository = root.parents[3]

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
for name in executables:
    path = root / "symbols" / f"{name}.json"
    with path.open(encoding="utf-8") as stream:
        symbols[name] = json.load(stream)
control_provenance = json.load(open(control_provenance_path, encoding="utf-8"))
payload = {
    "commit": commit,
    "tree": tree,
    "empty_diff_assertion": True,
    "architecture": arch,
    "variant": variant,
    "build": {
        "cargo_incremental": "0",
        "profile": "release",
        "locked": True,
        "rustc_flags": ["-C", "link-arg=-Wl,-Map,<per-target-map>"],
        "linker_flags": ["-Wl,-Map,<per-target-map>"],
    },
    "control": {
        **control_provenance,
        "provenance_path": str(Path(control_provenance_path).resolve()),
        "provenance_sha256": digest(control_provenance_path),
    },
    "executables": executables,
    "symbols": symbols,
}
with open(output + ".tmp", "w", encoding="utf-8") as stream:
    json.dump(payload, stream, indent=2, sort_keys=True)
    stream.write("\n")
Path(output + ".tmp").replace(output)
PY

symbol_count=$(jq '[.symbols[].symbols[]] | length' "$manifest_dir/manifest.json")
[[ $symbol_count == 8 ]] || { echo "error: manifest resolved $symbol_count symbols, expected 8" >&2; exit 1; }
echo "$manifest_dir/manifest.json"
