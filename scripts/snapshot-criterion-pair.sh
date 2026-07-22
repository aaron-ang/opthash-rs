#!/usr/bin/env bash
# Execute and atomically preserve one authenticated offline Criterion comparison.

set -euo pipefail

CACHE_GATE_REALPATH_TOOL=/usr/bin/realpath
CACHE_GATE_STAT_TOOL=/usr/bin/stat
CACHE_GATE_SHA256_TOOL=/usr/bin/sha256sum
for bootstrap_tool in "$CACHE_GATE_REALPATH_TOOL" "$CACHE_GATE_STAT_TOOL" "$CACHE_GATE_SHA256_TOOL"; do
	[[ -f $bootstrap_tool && -x $bootstrap_tool && ! -L $bootstrap_tool ]] || { echo "error: trusted bootstrap tool is unavailable: $bootstrap_tool" >&2; exit 1; }
done

LOCK_DIR=${LOCK_DIR:-/tmp}
original_command=$(printf '%q ' "$0" "$@")
criterion_root= snapshot_root= arch= comparison= pair= target=
anchor_run= candidate_run= anchor_commit= candidate_commit=
anchor_manifest= candidate_manifest= runner_root=

while (($#)); do
	case "$1" in
	--runner-root | --criterion-root | --snapshot-root | --arch | --comparison | --pair | --target | --anchor-run | --candidate-run | --anchor-commit | --candidate-commit | --anchor-manifest | --candidate-manifest)
		(($# >= 2)) || { echo "error: missing value for $1" >&2; exit 2; }
		name=${1#--}; name=${name//-/_}; printf -v "$name" '%s' "$2"; shift 2
		;;
	*) echo "error: unsupported argument: $1" >&2; exit 2 ;;
	esac
done
for name in runner_root criterion_root snapshot_root arch comparison pair target anchor_run candidate_run anchor_commit candidate_commit anchor_manifest candidate_manifest; do
	[[ -n ${!name} ]] || { echo "error: --${name//_/-} is required" >&2; exit 2; }
done
[[ $runner_root == /* ]] || { echo "error: --runner-root must be absolute" >&2; exit 2; }
runner_root=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$runner_root")
REPO_ROOT=$(git -C "$runner_root" rev-parse --show-toplevel 2>/dev/null) || { echo "error: runner root is not a Git worktree" >&2; exit 2; }
REPO_ROOT=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$REPO_ROOT")
[[ $REPO_ROOT == "$runner_root" ]] || { echo "error: runner root must be exact Git worktree top level" >&2; exit 2; }
snapshot_tool=$("$CACHE_GATE_REALPATH_TOOL" -e -- "${BASH_SOURCE[0]}")
HARNESS_ROOT=$(git -C "$(dirname "$snapshot_tool")" rev-parse --show-toplevel 2>/dev/null) || { echo "error: snapshot executor is not in a reviewed Git worktree" >&2; exit 2; }
HARNESS_ROOT=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$HARNESS_ROOT")
[[ $snapshot_tool == "$HARNESS_ROOT"/* ]] || { echo "error: snapshot executor is outside reviewed harness root" >&2; exit 2; }
elf_layout_tool=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$HARNESS_ROOT/scripts/cache-gate-elf-layout.py")
verify_reviewed_tool_blob() {
	local tool=$1 relative expected actual
	relative=${tool#"$HARNESS_ROOT/"}
	[[ $relative != "$tool" ]] || { echo "error: snapshot tool is outside reviewed root: $tool" >&2; exit 2; }
	expected=$(git -C "$HARNESS_ROOT" rev-parse "HEAD:$relative")
	actual=$(git hash-object "$tool")
	[[ $actual == "$expected" ]] || { echo "error: snapshot tool differs from reviewed Git blob: $tool" >&2; exit 2; }
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
safe_component() {
	[[ $2 =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ && $2 != . && $2 != .. ]] || {
		echo "error: unsafe component for $1: $2" >&2
		exit 2
	}
}
safe_component comparison "$comparison"
safe_component anchor-run "$anchor_run"
safe_component candidate-run "$candidate_run"
[[ $arch == aarch64 || $arch == x86_64 ]] || { echo "error: unsupported architecture: $arch" >&2; exit 2; }
[[ $pair =~ ^[1-9][0-9]*$ ]] || { echo "error: --pair must be positive" >&2; exit 2; }
case "$target" in
control | elastic_cache_gate | funnel_cache_gate) ;;
scaled_insert | all)
	echo "error: authenticated SAVE provenance is unavailable for target: $target" >&2
	exit 2
	;;
*) echo "error: unsupported target: $target" >&2; exit 2 ;;
esac

[[ $criterion_root == /* ]] || { echo "error: --criterion-root must be absolute" >&2; exit 2; }
criterion_root=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$criterion_root")
if [[ $snapshot_root == /* ]]; then
	snapshot_root=$("$CACHE_GATE_REALPATH_TOOL" -m -- "$snapshot_root")
else
	snapshot_root=$("$CACHE_GATE_REALPATH_TOOL" -m -- "$REPO_ROOT/$snapshot_root")
fi
target_root=$("$CACHE_GATE_REALPATH_TOOL" -m -- "$REPO_ROOT/target")
[[ $snapshot_root == "$target_root" || $snapshot_root == "$target_root"/* ]] || { echo "error: snapshot root must stay below runner root target" >&2; exit 2; }
[[ -f $anchor_manifest && ! -L $anchor_manifest ]] || { echo "error: anchor manifest must be a regular non-symlink file" >&2; exit 2; }
[[ -f $candidate_manifest && ! -L $candidate_manifest ]] || { echo "error: candidate manifest must be a regular non-symlink file" >&2; exit 2; }
anchor_manifest=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$anchor_manifest")
candidate_manifest=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$candidate_manifest")
destination="$snapshot_root/$arch/$comparison/pair-$pair"
[[ ! -e $destination ]] || { echo "error: destination already exists: $destination" >&2; exit 1; }
mkdir -p -- "$(dirname "$destination")" "$LOCK_DIR"

root_key=$(printf '%s' "$criterion_root" | "$CACHE_GATE_SHA256_TOOL"); root_key=${root_key%% *}
snapshot_flock_tool=$(resolve_trusted_system_tool flock)
snapshot_flock_tool_hash=$("$CACHE_GATE_SHA256_TOOL" -- "$snapshot_flock_tool"); snapshot_flock_tool_hash=${snapshot_flock_tool_hash%% *}
root_lock="$LOCK_DIR/opthash-bench-root-$root_key.lock"
if [[ -L $root_lock ]] || { [[ -e $root_lock ]] && [[ ! -d $root_lock && ! -f $root_lock ]]; }; then
	echo "error: unsafe Criterion root lock $root_lock" >&2; exit 1
fi
if [[ ! -e $root_lock ]] && ! mkdir -m 0755 "$root_lock" 2>/dev/null && [[ ! -e $root_lock ]]; then
	echo "error: cannot create Criterion root lock $root_lock" >&2; exit 1
fi
exec {criterion_lock_fd}<"$root_lock"
"$snapshot_flock_tool" "$criterion_lock_fd"

temporary=$(mktemp -d "$(dirname "$destination")/.pair-$pair.tmp.XXXXXX")
stale=$(mktemp -d "$(dirname "$destination")/.pair-$pair.stale.XXXXXX")
cleanup() { rm -rf -- "$temporary" "$stale"; }
trap cleanup EXIT

validation="$temporary/validated-manifests.json"
python3 - "$anchor_manifest" "$candidate_manifest" "$anchor_commit" "$candidate_commit" "$arch" "$validation" "$REPO_ROOT" "$HARNESS_ROOT" "$snapshot_tool" <<'PY'
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

anchor_path, candidate_path, anchor_commit, candidate_commit, arch, output, repo, harness_root, snapshot_tool = sys.argv[1:]
def load_manifest(path):
    raw = Path(path).read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()

anchor, anchor_hash = load_manifest(anchor_path)
candidate, candidate_hash = load_manifest(candidate_path)
if anchor.get("control") != candidate.get("control"):
    raise SystemExit("error: control provenance differs between manifests")

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def checked_file(record, label):
    path = Path(record["absolute_path"])
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise SystemExit(f"error: invalid {label} path: {path}")
    if digest(path) != record["sha256"]:
        raise SystemExit(f"error: {label} hash mismatch: {path}")
    return str(path.resolve())

def validate(manifest, path, supplied_commit, require_subject_root):
    if manifest.get("commit") != supplied_commit or manifest.get("architecture") != arch:
        raise SystemExit(f"error: manifest commit/architecture mismatch: {path}")
    subprocess.run(["git", "cat-file", "-e", f"{supplied_commit}^{{commit}}"], cwd=repo, check=True)
    tree = subprocess.check_output(
        ["git", "rev-parse", f"{supplied_commit}^{{tree}}"], cwd=repo, text=True
    ).strip()
    if manifest.get("tree") != tree or manifest.get("empty_diff_assertion") is not True:
        raise SystemExit(f"error: manifest tree/clean assertion mismatch: {path}")
    recorded_root = Path(manifest.get("runner_root", ""))
    if not recorded_root.is_absolute() or not recorded_root.is_dir():
        raise SystemExit(f"error: invalid recorded manifest runner root: {path}")
    actual_root = Path(subprocess.check_output(["git", "-C", str(recorded_root), "rev-parse", "--show-toplevel"], text=True).strip()).resolve()
    if actual_root != recorded_root.resolve():
        raise SystemExit(f"error: recorded manifest runner root is not exact worktree root: {path}")
    if subprocess.check_output(["git", "-C", str(actual_root), "rev-parse", "HEAD"], text=True).strip() != supplied_commit:
        raise SystemExit(f"error: recorded manifest runner HEAD changed: {path}")
    if require_subject_root and recorded_root.resolve() != Path(repo):
        raise SystemExit(f"error: manifest runner root differs from authenticated --runner-root: {path}")
    control = manifest["control"]
    checked_file(control["binary"], "control binary")
    for name, record in control["inputs"].items():
        checked_file(record, f"control input {name}")
    provenance_path = Path(control["provenance_path"])
    if digest(provenance_path) != control["provenance_sha256"]:
        raise SystemExit("error: control provenance file hash mismatch")
    provenance = json.load(provenance_path.open(encoding="utf-8"))
    for key in ("builder_commit", "builder_tree", "binary", "inputs"):
        if provenance.get(key) != control.get(key):
            raise SystemExit(f"error: control provenance content mismatch: {key}")
    builder_commit = control["builder_commit"]
    subprocess.run(
        ["git", "cat-file", "-e", f"{builder_commit}^{{commit}}"],
        cwd=repo,
        check=True,
    )
    builder_tree = subprocess.check_output(
        ["git", "rev-parse", f"{builder_commit}^{{tree}}"], cwd=repo, text=True
    ).strip()
    if builder_tree != control["builder_tree"]:
        raise SystemExit("error: control builder tree mismatch")
    for name, executable in manifest["executables"].items():
        binary = checked_file(executable, f"executable {name}")
        checked_file(executable["link_map"], f"link map {name}")
        symbol = manifest["symbols"][name]
        if Path(symbol["binary"]).resolve() != Path(binary) or symbol["binary_sha256"] != executable["sha256"] or symbol["architecture"] != arch:
            raise SystemExit(f"error: symbol/executable mismatch: {name}")
        ranges = sorted((item["start"], item["end"], item["size"]) for item in symbol["symbols"])
        if not ranges or any(size <= 0 or end <= start for start, end, size in ranges):
            raise SystemExit(f"error: invalid symbol ranges: {name}")
        if any(right[0] < left[1] for left, right in zip(ranges, ranges[1:])):
            raise SystemExit(f"error: overlapping symbol ranges: {name}")
    if set(manifest["executables"]) != set(manifest["symbols"]):
        raise SystemExit("error: executable/symbol target sets differ")
    tools = manifest.get("tools", {})
    if set(tools) != {"snapshot", "launcher", "perf_launcher", "perf_support", "elf_layout", "extractor", "link_wrapper"}:
        raise SystemExit("error: authenticated tool set mismatch")
    for name, record in tools.items():
        resolved = Path(checked_file(record, f"tool {name}"))
        if os.path.commonpath([str(Path(harness_root)), str(resolved)]) != str(Path(harness_root)):
            raise SystemExit(f"error: tool {name} is outside reviewed harness root")
    required={
      "elastic_cache_gate":{"::elastic_cache_gate_insert_kernel","::elastic_cache_gate_get_kernel"},
      "funnel_cache_gate":{"::funnel_cache_gate_insert_kernel","::funnel_cache_gate_get_kernel"},
      "cache_gate_profile":{"::elastic_profile_insert_kernel","::elastic_profile_get_kernel","::funnel_profile_insert_kernel","::funnel_profile_get_kernel"},
    }
    for name,suffixes in required.items():
        names=[item["name"] for item in manifest["symbols"][name]["symbols"]]
        if len(names)!=len(suffixes) or any(sum(value.endswith(suffix) for value in names)!=1 for suffix in suffixes):
            raise SystemExit(f"error: required symbols mismatch: {name}")

validate(anchor, anchor_path, anchor_commit, False)
validate(candidate, candidate_path, candidate_commit, True)
if Path(candidate["tools"]["snapshot"]["absolute_path"]).resolve() != Path(snapshot_tool):
    raise SystemExit("error: candidate snapshot executor path mismatch")
json.dump({"control": anchor["control"], "candidate_executables":candidate["executables"], "tools":candidate["tools"], "manifest_hashes":{"anchor":anchor_hash,"candidate":candidate_hash}}, open(output, "w", encoding="utf-8"), indent=2, sort_keys=True)
with open(output, "a", encoding="utf-8") as stream:
    stream.write("\n")
PY
control_binary=$(jq -er '.control.binary.absolute_path' "$validation")

expected_ids=()
implementations=(std hashbrown elastic funnel)
case "$target" in
control) expected_ids=(cache_gate_insert/cache_gate_insert_std cache_gate_insert/cache_gate_insert_hashbrown) ;;
elastic_cache_gate) expected_ids=(cache_gate_insert/cache_gate_insert_elastic cache_gate_get_hit_elastic) ;;
funnel_cache_gate) expected_ids=(cache_gate_insert/cache_gate_insert_funnel cache_gate_get_hit_funnel) ;;
scaled_insert)
	for size in 100K 1M 10M; do for implementation in "${implementations[@]}"; do expected_ids+=("insert_scale_$size/insert_scale_${size}_$implementation"); done; done
	;;
all)
	for group in insert get_hit get_hit_sequential get_miss tiny_lookup mixed delete_heavy resize_heavy; do
		for implementation in "${implementations[@]}"; do expected_ids+=("$group/${group}_$implementation"); done
	done
	for size in 1K 10K 100K 1M 10M; do
		for prefix in get_hit_latency get_hit_sequential_latency; do
			group="${prefix}_$size"
			for implementation in "${implementations[@]}"; do expected_ids+=("$group/${group}_$implementation"); done
		done
	done
	;;
esac
case "$target" in control | elastic_cache_gate | funnel_cache_gate) expected_count=2 ;; scaled_insert) expected_count=12 ;; all) expected_count=72 ;; esac
((${#expected_ids[@]} == expected_count)) || { echo "error: internal expected-ID count mismatch" >&2; exit 1; }

validate_saved_runs() {
	local output=$1
	python3 - "$output" "$anchor_manifest" "$candidate_manifest" "$anchor_run" \
		"$candidate_run" "$target" "$criterion_root" "${expected_ids[@]}" <<'PY'
import hashlib,json,os,subprocess,sys
from pathlib import Path

(output,anchor_manifest,candidate_manifest,anchor_run,candidate_run,target,
 criterion_root,*expected_ids)=sys.argv[1:]
criterion_root=Path(criterion_root).resolve(strict=True)
schema={"schema","runner_root","commit","tree","empty_diff_assertion","mode",
        "run","criterion_evidence_root","build_manifest","control_provenance","executable",
        "producer_launcher","measurement","expected_benchmark_ids","results"}
result_schema={"absolute_path","relative_path","sha256","size"}
tool_schema={"absolute_path","sha256","git_blob","git_blob_sha256","reviewed_root",
             "reviewed_commit","reviewed_tree"}
measurement_schema={"core","launcher_prefix","numa_wrapper","pin_wrapper",
                    "criterion_environment","system_tools","executable_argv","executed_argv"}
system_tool_schema={"absolute_path","sha256"}
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load_manifest(path):
    raw=Path(path).read_bytes()
    return json.loads(raw),hashlib.sha256(raw).hexdigest(),Path(path).resolve()
def inventory(run):
    records=[]
    for benchmark in expected_ids:
        benchmark_records=[]
        baseline_path=criterion_root/benchmark/run
        cursor=criterion_root
        for part in baseline_path.relative_to(criterion_root).parts:
            cursor=cursor/part
            if cursor.is_symlink():
                raise SystemExit(f"error: saved run baseline path contains symlink: {cursor}")
        baseline=baseline_path.resolve()
        try: baseline.relative_to(criterion_root)
        except ValueError: raise SystemExit(f"error: saved run baseline escapes Criterion root: {baseline}")
        if not baseline.is_dir():
            raise SystemExit(f"error: missing saved run baseline: {baseline}")
        for current,directories,files in os.walk(baseline,followlinks=False):
            current_path=Path(current)
            for name in directories:
                path=current_path/name
                if path.is_symlink(): raise SystemExit(f"error: saved run contains symlink: {path}")
            for name in files:
                path=current_path/name
                if path.is_symlink() or not path.is_file():
                    raise SystemExit(f"error: invalid saved run result: {path}")
                relative=path.relative_to(criterion_root).as_posix()
                benchmark_records.append({"absolute_path":str(path.resolve()),"relative_path":relative,
                                          "sha256":digest(path),"size":path.stat().st_size})
        if not any(item["relative_path"]==f"{benchmark}/{run}/estimates.json" for item in benchmark_records):
            raise SystemExit(f"error: saved run lacks estimates.json: {benchmark}")
        records.extend(sorted(benchmark_records,key=lambda item:item["relative_path"]))
    return records
def validate(label,manifest_path,run):
    manifest,manifest_hash,canonical_manifest=load_manifest(manifest_path)
    runner=Path(manifest["runner_root"]).resolve()
    if target=="control":
        evidence=runner/"target/cache-gate-runs/control"/f"{run}.json"
        expected_mode="CONTROL"
        expected_manifest=None
        expected_control={"absolute_path":manifest["control"]["provenance_path"],
                          "sha256":manifest["control"]["provenance_sha256"]}
        expected_executable=manifest["control"]["binary"]
    else:
        evidence=(runner/"target/cache-gate-runs"/manifest["variant"]/
                  f"{target}-{run}.json")
        expected_mode=target
        expected_manifest={"absolute_path":str(canonical_manifest),"sha256":manifest_hash}
        expected_control=None
        item=manifest["executables"][target]
        expected_executable={"absolute_path":item["absolute_path"],"sha256":item["sha256"]}
    runner_target=(runner/"target").resolve()
    evidence_path=evidence
    cursor=runner_target
    try: relative_evidence=evidence_path.relative_to(runner_target)
    except ValueError: raise SystemExit(f"error: {label} run evidence escapes runner target")
    for part in relative_evidence.parts:
        cursor=cursor/part
        if cursor.is_symlink():
            raise SystemExit(f"error: {label} run evidence path contains symlink")
    evidence=evidence_path.resolve()
    try: evidence.relative_to(runner_target)
    except ValueError: raise SystemExit(f"error: {label} run evidence escapes runner target")
    if not evidence.is_file():
        raise SystemExit(f"error: missing {label} saved run evidence: {evidence}")
    raw=evidence.read_bytes(); record=json.loads(raw)
    if set(record)!=schema:
        raise SystemExit(f"error: exact {label} saved run evidence schema mismatch")
    if (record["schema"]!="opthash-criterion-run-v2" or
        record["runner_root"]!=str(runner) or record["commit"]!=manifest["commit"] or
        record["tree"]!=manifest["tree"] or record["empty_diff_assertion"] is not True or
        record["mode"]!=expected_mode or record["run"]!=run or
        record["criterion_evidence_root"]!=str(criterion_root) or
        record["expected_benchmark_ids"]!=expected_ids):
        raise SystemExit(f"error: {label} saved run identity mismatch")
    if record["build_manifest"]!=expected_manifest:
        raise SystemExit(f"error: {label} saved run build manifest mismatch")
    if record["control_provenance"]!=expected_control:
        raise SystemExit(f"error: {label} saved run control provenance mismatch")
    if record["executable"]!=expected_executable:
        raise SystemExit(f"error: {label} saved run executable mismatch")
    if (set(record["producer_launcher"])!=tool_schema or
        record["producer_launcher"]!=manifest["tools"]["launcher"]):
        raise SystemExit(f"error: {label} saved run producer launcher mismatch")
    measurement=record["measurement"]
    if set(measurement)!=measurement_schema:
        raise SystemExit(f"error: exact {label} saved run measurement schema mismatch")
    array_names=("launcher_prefix","numa_wrapper","pin_wrapper",
                 "criterion_environment","executable_argv","executed_argv")
    if any(not isinstance(measurement[name],list) or
           any(not isinstance(value,str) for value in measurement[name])
           for name in array_names):
        raise SystemExit(f"error: invalid {label} saved run measurement argv")
    executable_argv=measurement["executable_argv"]
    if (len(executable_argv)<4 or executable_argv[:4]!=[
            expected_executable["absolute_path"],"--bench","--save-baseline",run]):
        raise SystemExit(f"error: {label} saved run measurement executable argv mismatch")
    criterion_environment=measurement["criterion_environment"]
    if (not criterion_environment or not Path(criterion_environment[0]).is_absolute() or
        Path(criterion_environment[0]).name!="env"):
        raise SystemExit(f"error: {label} saved run Criterion wrapper mismatch")
    valid_criterion_environments=(
        [criterion_environment[0],"-u","CRITERION_HOME"],
        [criterion_environment[0],f"CRITERION_HOME={criterion_root}"],
    )
    if criterion_environment not in valid_criterion_environments:
        raise SystemExit(f"error: {label} saved run Criterion environment mismatch")
    core=measurement["core"]
    pin=measurement["pin_wrapper"]
    if (not isinstance(core,str) or not core.isdigit() or len(pin)!=5 or
        not Path(pin[0]).is_absolute() or Path(pin[0]).name!="taskset" or
        pin[1:3]!=["-c",core] or not Path(pin[3]).is_absolute() or
        Path(pin[3]).name!="setarch" or pin[4]!="-R"):
        raise SystemExit(f"error: {label} saved run pin/core mismatch")
    numa=measurement["numa_wrapper"]
    if numa and (len(numa)!=2 or not Path(numa[0]).is_absolute() or
                 Path(numa[0]).name!="numactl" or not numa[1].startswith("--membind=")):
        raise SystemExit(f"error: {label} saved run NUMA wrapper mismatch")
    system_tools=measurement["system_tools"]
    if (not isinstance(system_tools,list) or
        any(set(item)!=system_tool_schema for item in system_tools)):
        raise SystemExit(f"error: exact {label} saved run system tool schema mismatch")
    used_system_tools={value for name in ("launcher_prefix","numa_wrapper","pin_wrapper",
                                           "criterion_environment")
                       for value in measurement[name] if value.startswith("/")}
    recorded_system_tools={item["absolute_path"] for item in system_tools}
    setup_system_tools={path for path in recorded_system_tools if Path(path).name=="flock"}
    if (len(recorded_system_tools)!=len(system_tools) or len(setup_system_tools)!=1 or
        recorded_system_tools!=used_system_tools|setup_system_tools):
        raise SystemExit(f"error: {label} saved run system tool set mismatch")
    for item in system_tools:
        path=Path(item["absolute_path"])
        if (not path.is_absolute() or path.is_symlink() or not path.is_file() or
            str(path.resolve())!=item["absolute_path"] or path.stat().st_uid!=0 or
            path.stat().st_mode & 0o022 or digest(path)!=item["sha256"]):
            raise SystemExit(f"error: {label} saved run system tool mismatch: {path}")
    executed=(measurement["launcher_prefix"]+numa+measurement["pin_wrapper"]+
              measurement["criterion_environment"]+executable_argv)
    if measurement["executed_argv"]!=executed:
        raise SystemExit(f"error: {label} saved run executed argv mismatch")
    if any(set(item)!=result_schema for item in record["results"]):
        raise SystemExit(f"error: exact {label} saved run result schema mismatch")
    if record["results"]!=inventory(run):
        raise SystemExit(f"error: {label} saved run result inventory mismatch")
    return {"absolute_path":str(evidence),"sha256":hashlib.sha256(raw).hexdigest(),
            "record":record}
payload={"anchor":validate("anchor",anchor_manifest,anchor_run),
         "candidate":validate("candidate",candidate_manifest,candidate_run)}
def measurement_invariant(record):
    measurement=record["measurement"]
    return {
        "core":measurement["core"],
        "launcher_prefix":measurement["launcher_prefix"],
        "numa_wrapper":measurement["numa_wrapper"],
        "pin_wrapper":measurement["pin_wrapper"],
        "criterion_environment":measurement["criterion_environment"],
        "system_tools":measurement["system_tools"],
        "forwarded_argv":measurement["executable_argv"][4:],
    }
if measurement_invariant(payload["anchor"]["record"])!=measurement_invariant(payload["candidate"]["record"]):
    raise SystemExit("error: saved run measurement settings differ")
Path(output).write_text(json.dumps(payload,indent=2,sort_keys=True)+"\n")
PY
}

run_validation="$temporary/validated-runs.json"
validate_saved_runs "$run_validation"

assert_contained() {
	python3 - "$1" "$2" <<'PY'
import os
import sys
root = os.path.realpath(sys.argv[1])
path = os.path.realpath(sys.argv[2])
if os.path.commonpath([root, path]) != root:
    raise SystemExit(f"error: path escapes root: {path}")
PY
}

for benchmark in "${expected_ids[@]}"; do
	for run in "$anchor_run" "$candidate_run"; do
		absolute="$criterion_root/$benchmark/$run/estimates.json"
		assert_contained "$criterion_root" "$absolute"
		[[ -f $absolute && ! -L $absolute ]] || { echo "error: missing absolute result: $absolute" >&2; exit 1; }
	done
	change="$criterion_root/$benchmark/change/estimates.json"
	assert_contained "$criterion_root" "$change"
	if [[ -e $change ]]; then
		mkdir -p "$stale/$benchmark/change"
		mv -- "$change" "$stale/$benchmark/change/estimates.json"
	fi
done

# The supplied manifests are mutable files. Re-derive and authenticate every
# structural claim while holding the comparison lock, immediately before use.
verify_manifest_tool_binding "$anchor_manifest" snapshot "$snapshot_tool"
verify_manifest_tool_binding "$anchor_manifest" elf_layout "$elf_layout_tool"
"$elf_layout_tool" validate-manifest --manifest "$anchor_manifest"
verify_manifest_tool_binding "$candidate_manifest" snapshot "$snapshot_tool"
verify_manifest_tool_binding "$candidate_manifest" elf_layout "$elf_layout_tool"
"$elf_layout_tool" validate-manifest --manifest "$candidate_manifest"
expected_anchor_manifest_hash=$(jq -er '.manifest_hashes.anchor' "$validation")
expected_candidate_manifest_hash=$(jq -er '.manifest_hashes.candidate' "$validation")
actual_anchor_manifest_hash=$("$CACHE_GATE_SHA256_TOOL" -- "$anchor_manifest"); actual_anchor_manifest_hash=${actual_anchor_manifest_hash%% *}
actual_candidate_manifest_hash=$("$CACHE_GATE_SHA256_TOOL" -- "$candidate_manifest"); actual_candidate_manifest_hash=${actual_candidate_manifest_hash%% *}
[[ $actual_anchor_manifest_hash == "$expected_anchor_manifest_hash" ]] || { echo "error: anchor manifest changed before execution" >&2; exit 1; }
[[ $actual_candidate_manifest_hash == "$expected_candidate_manifest_hash" ]] || { echo "error: candidate manifest changed before execution" >&2; exit 1; }
validate_saved_runs "$temporary/validated-runs.pre-exec.json"
cmp --silent "$run_validation" "$temporary/validated-runs.pre-exec.json" || { echo "error: saved run evidence changed before execution" >&2; exit 1; }
marker="$temporary/comparison-start.marker"
touch "$marker"
start_ns=$(python3 -c 'import time; print(time.time_ns())')
start_iso=$(date --iso-8601=ns)
comparison_stdout="$temporary/comparison.stdout"
comparison_stderr="$temporary/comparison.stderr"
criterion_args=(--load-baseline "$candidate_run" --baseline "$anchor_run")
comparison_commands="$temporary/comparison-commands.json"
case "$target" in
control)
	control_hash=$(jq -er '.control.binary.sha256' "$validation")
	actual_control_hash=$("$CACHE_GATE_SHA256_TOOL" -- "$control_binary"); actual_control_hash=${actual_control_hash%% *}
	[[ $actual_control_hash == "$control_hash" ]] || { echo "error: control binary hash mismatch immediately before execution" >&2; exit 1; }
	comparison_command=("$control_binary" --bench "${criterion_args[@]}")
	CRITERION_HOME="$criterion_root" "${comparison_command[@]}" >"$comparison_stdout" 2>"$comparison_stderr"
	post_execution_control_hash=$("$CACHE_GATE_SHA256_TOOL" -- "$control_binary"); post_execution_control_hash=${post_execution_control_hash%% *}
	[[ $post_execution_control_hash == "$control_hash" ]] || { echo "error: control binary changed during offline execution" >&2; exit 1; }
	python3 - "$comparison_commands" "${comparison_command[@]}" <<'PY'
import json,sys
json.dump([sys.argv[2:]], open(sys.argv[1], "w"), indent=2)
PY
	;;
elastic_cache_gate | funnel_cache_gate)
	stable_binary=$(jq -er --arg target "$target" '.candidate_executables[$target].absolute_path' "$validation")
	stable_hash=$(jq -er --arg target "$target" '.candidate_executables[$target].sha256' "$validation")
	actual_stable_hash=$("$CACHE_GATE_SHA256_TOOL" -- "$stable_binary"); actual_stable_hash=${actual_stable_hash%% *}
	[[ $actual_stable_hash == "$stable_hash" ]] || { echo "error: candidate stable binary hash mismatch" >&2; exit 1; }
	comparison_command=("$stable_binary" --bench "${criterion_args[@]}")
	CRITERION_HOME="$criterion_root" "${comparison_command[@]}" >"$comparison_stdout" 2>"$comparison_stderr"
	post_execution_stable_hash=$("$CACHE_GATE_SHA256_TOOL" -- "$stable_binary"); post_execution_stable_hash=${post_execution_stable_hash%% *}
	[[ $post_execution_stable_hash == "$stable_hash" ]] || { echo "error: stable binary changed during offline execution" >&2; exit 1; }
	python3 - "$comparison_commands" "${comparison_command[@]}" <<'PY'
import json,sys
json.dump([sys.argv[2:]], open(sys.argv[1], "w"), indent=2)
PY
	;;
scaled_insert)
	comparison_command=(env "LOAD=$candidate_run" "BASELINE=$anchor_run" "OPTHASH_CRITERION_ROOT=$criterion_root" BENCH=scaled_insert "$REPO_ROOT/scripts/bench.sh")
	"${comparison_command[@]}" >"$comparison_stdout" 2>"$comparison_stderr"
	python3 - "$comparison_commands" "${comparison_command[@]}" <<'PY'
import json,sys
json.dump([sys.argv[2:]], open(sys.argv[1], "w"), indent=2)
PY
	;;
all)
	comparison_command=(env "LOAD=$candidate_run" "BASELINE=$anchor_run" "OPTHASH_CRITERION_ROOT=$criterion_root" BENCH=all "$REPO_ROOT/scripts/bench.sh")
	"${comparison_command[@]}" >"$comparison_stdout" 2>"$comparison_stderr"
	python3 - "$comparison_commands" "${comparison_command[@]}" <<'PY'
import json,sys
json.dump([sys.argv[2:]], open(sys.argv[1], "w"), indent=2)
PY
	;;
esac
end_ns=$(python3 -c 'import time; print(time.time_ns())')
end_iso=$(date --iso-8601=ns)
validate_saved_runs "$temporary/validated-runs.post-exec.json"
cmp --silent "$run_validation" "$temporary/validated-runs.post-exec.json" || { echo "error: saved run evidence changed during execution" >&2; exit 1; }

for benchmark in "${expected_ids[@]}"; do
	change="$criterion_root/$benchmark/change/estimates.json"
	[[ -f $change && ! -L $change ]] || { echo "error: missing fresh change result: $change" >&2; exit 1; }
	python3 - "$marker" "$change" <<'PY'
import os,sys
if os.stat(sys.argv[2]).st_mtime_ns < os.stat(sys.argv[1]).st_mtime_ns:
    raise SystemExit(f"error: pre-command change result: {sys.argv[2]}")
PY
done

declare -A expected_set=()
for benchmark in "${expected_ids[@]}"; do expected_set["$benchmark"]=1; done
while IFS= read -r -d '' change; do
	relative=${change#"$criterion_root"/}; benchmark=${relative%/change/estimates.json}
	case "$target" in
	control) relevant=$([[ $benchmark == cache_gate_insert/cache_gate_insert_* ]] && echo 1 || echo 0) ;;
	elastic_cache_gate) relevant=$([[ $benchmark == *cache_gate*elastic* ]] && echo 1 || echo 0) ;;
	funnel_cache_gate) relevant=$([[ $benchmark == *cache_gate*funnel* ]] && echo 1 || echo 0) ;;
	scaled_insert) relevant=$([[ $benchmark == insert_scale_*/* ]] && echo 1 || echo 0) ;;
	all) relevant=$([[ $benchmark == insert/* || $benchmark == get_hit/* || $benchmark == get_hit_sequential/* || $benchmark == get_miss/* || $benchmark == tiny_lookup/* || $benchmark == mixed/* || $benchmark == delete_heavy/* || $benchmark == resize_heavy/* || $benchmark == get_hit_latency_*/* || $benchmark == get_hit_sequential_latency_*/* ]] && echo 1 || echo 0) ;;
	esac
	if [[ $relevant == 1 && -z ${expected_set[$benchmark]+x} ]]; then echo "error: unexpected target change result: $benchmark" >&2; exit 1; fi
done < <(find "$criterion_root" -type f -path '*/change/estimates.json' -print0)

copy_verified() {
	local source=$1 output=$2 source_root=${3:-} expected=${4:-} before after copied
	[[ -f $source && ! -L $source ]] || { echo "error: invalid copy source: $source" >&2; exit 1; }
	[[ -z $source_root ]] || assert_contained "$source_root" "$source"
	assert_contained "$temporary" "$output"
	before=$("$CACHE_GATE_SHA256_TOOL" -- "$source"); before=${before%% *}
	[[ -z $expected || $before == "$expected" ]] || { echo "error: authenticated source hash mismatch: $source" >&2; exit 1; }
	mkdir -p -- "$(dirname "$output")"; cp --preserve=mode,timestamps -- "$source" "$output"
	after=$("$CACHE_GATE_SHA256_TOOL" -- "$source"); after=${after%% *}; copied=$("$CACHE_GATE_SHA256_TOOL" -- "$output"); copied=${copied%% *}
	[[ $before == "$after" && $before == "$copied" ]] || { echo "error: hash changed while copying $source" >&2; exit 1; }
}
for benchmark in "${expected_ids[@]}"; do
	copy_verified "$criterion_root/$benchmark/change/estimates.json" "$temporary/change/$benchmark/change/estimates.json" "$criterion_root"
done
for label in anchor candidate; do
	while IFS=$'\t' read -r source relative expected; do
		case "$label" in
		anchor) run=$anchor_run ;;
		candidate) run=$candidate_run ;;
		esac
		copy_verified "$source" "$temporary/absolute/$label/${relative%/$run/*}/${relative#*/$run/}" "$criterion_root" "$expected"
	done < <(jq -r --arg label "$label" '.[$label].record.results[] | [.absolute_path,.relative_path,.sha256] | @tsv' "$run_validation")
	run_source=$(jq -er --arg label "$label" '.[$label].absolute_path' "$run_validation")
	run_hash=$(jq -er --arg label "$label" '.[$label].sha256' "$run_validation")
	copy_verified "$run_source" "$temporary/run-evidence/$label.json" "" "$run_hash"
done
validate_saved_runs "$temporary/validated-runs.post-copy.json"
cmp --silent "$run_validation" "$temporary/validated-runs.post-copy.json" || { echo "error: saved run evidence changed during copy" >&2; exit 1; }

copy_bundle() {
	local label=$1 manifest=$2 expected_manifest_hash=$3 copied_manifest="$temporary/build/$1-manifest.json"
	mkdir -p "$temporary/build"
	copy_verified "$manifest" "$copied_manifest" "" "$expected_manifest_hash"
	while IFS=$'\t' read -r name map map_hash; do
		copy_verified "$map" "$temporary/build/$label-link-maps/$name.map" "" "$map_hash"
	done < <(
		python3 - "$copied_manifest" <<'PY'
import json,sys
m=json.load(open(sys.argv[1]))
for name,item in sorted(m["executables"].items()): print(f'{name}\t{item["link_map"]["absolute_path"]}\t{item["link_map"]["sha256"]}')
PY
	)
}
post_anchor_manifest_hash=$("$CACHE_GATE_SHA256_TOOL" -- "$anchor_manifest"); post_anchor_manifest_hash=${post_anchor_manifest_hash%% *}
post_candidate_manifest_hash=$("$CACHE_GATE_SHA256_TOOL" -- "$candidate_manifest"); post_candidate_manifest_hash=${post_candidate_manifest_hash%% *}
[[ $post_anchor_manifest_hash == "$expected_anchor_manifest_hash" ]] || { echo "error: anchor manifest changed during execution" >&2; exit 1; }
[[ $post_candidate_manifest_hash == "$expected_candidate_manifest_hash" ]] || { echo "error: candidate manifest changed during execution" >&2; exit 1; }
copy_bundle anchor "$anchor_manifest" "$expected_anchor_manifest_hash"
copy_bundle candidate "$candidate_manifest" "$expected_candidate_manifest_hash"

python3 - "$temporary/pair-manifest.json" "$temporary/build/anchor-manifest.json" "$temporary/build/candidate-manifest.json" "$validation" "$run_validation" "$comparison_commands" "$original_command" "$start_ns" "$end_ns" "$start_iso" "$end_iso" "$target" "$anchor_run" "$candidate_run" "$REPO_ROOT" "$snapshot_tool" "$snapshot_flock_tool" "$snapshot_flock_tool_hash" <<'PY'
import json,platform,sys
output, anchor_path, candidate_path, validation_path, run_validation_path, commands_path, snapshot_command, start_ns, end_ns, start_iso, end_iso, target, anchor_run, candidate_run, runner_root, executor, flock_tool, flock_hash = sys.argv[1:]
anchor=json.load(open(anchor_path)); candidate=json.load(open(candidate_path)); validation=json.load(open(validation_path)); run_validation=json.load(open(run_validation_path)); commands=json.load(open(commands_path))
payload={
 "target":target, "host":platform.node(), "snapshot_command":snapshot_command.rstrip(),
 "comparison_command":commands[0], "comparison_commands":commands,
 "offline_execution_count":1,"runner_root":runner_root,
 "executor":{"absolute_path":executor,"sha256":validation["tools"]["snapshot"]["sha256"]},
 "system_tools":{"flock":{"absolute_path":flock_tool,"sha256":flock_hash}},
 "comparison_started_ns":int(start_ns), "comparison_finished_ns":int(end_ns),
 "comparison_started_at":start_iso, "comparison_finished_at":end_iso,
 "control":validation["control"],
 "anchor":{"run":anchor_run,"commit":anchor["commit"],"tree":anchor["tree"],"manifest_sha256":validation["manifest_hashes"]["anchor"],"executable_hashes":{k:v["sha256"] for k,v in anchor["executables"].items()},"run_evidence_sha256":run_validation["anchor"]["sha256"]},
 "candidate":{"run":candidate_run,"commit":candidate["commit"],"tree":candidate["tree"],"manifest_sha256":validation["manifest_hashes"]["candidate"],"executable_hashes":{k:v["sha256"] for k,v in candidate["executables"].items()},"run_evidence_sha256":run_validation["candidate"]["sha256"]},
}
json.dump(payload,open(output,"w"),indent=2,sort_keys=True); open(output,"a").write("\n")
PY
rm -f "$marker" "$validation" "$run_validation" "$temporary/validated-runs.pre-exec.json" "$temporary/validated-runs.post-exec.json" "$temporary/validated-runs.post-copy.json" "$comparison_commands"
(
	cd "$temporary"
	find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 "$CACHE_GATE_SHA256_TOOL" >SHA256SUMS
	"$CACHE_GATE_SHA256_TOOL" -c SHA256SUMS
)
python3 - "$temporary" <<'PY'
import os,sys
from pathlib import Path
root=Path(sys.argv[1])
for path in root.rglob("*"):
    if path.is_file():
        with path.open("rb") as stream: os.fsync(stream.fileno())
for path in sorted((p for p in root.rglob("*") if p.is_dir()),reverse=True):
    fd=os.open(path,os.O_RDONLY); os.fsync(fd); os.close(fd)
fd=os.open(root,os.O_RDONLY); os.fsync(fd); os.close(fd)
PY
mv -- "$temporary" "$destination"
rm -rf -- "$stale"
trap - EXIT
echo "$destination"
