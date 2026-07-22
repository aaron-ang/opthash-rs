#!/usr/bin/env bash
# Execute and atomically preserve one authenticated offline Criterion comparison.

set -euo pipefail

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
runner_root=$(realpath -e -- "$runner_root")
REPO_ROOT=$(git -C "$runner_root" rev-parse --show-toplevel 2>/dev/null) || { echo "error: runner root is not a Git worktree" >&2; exit 2; }
REPO_ROOT=$(realpath -e -- "$REPO_ROOT")
[[ $REPO_ROOT == "$runner_root" ]] || { echo "error: runner root must be exact Git worktree top level" >&2; exit 2; }
snapshot_tool=$(realpath -e -- "${BASH_SOURCE[0]}")
HARNESS_ROOT=$(git -C "$(dirname "$snapshot_tool")" rev-parse --show-toplevel 2>/dev/null) || { echo "error: snapshot executor is not in a reviewed Git worktree" >&2; exit 2; }
HARNESS_ROOT=$(realpath -e -- "$HARNESS_ROOT")
[[ $snapshot_tool == "$HARNESS_ROOT"/* ]] || { echo "error: snapshot executor is outside reviewed harness root" >&2; exit 2; }
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
case "$target" in control | elastic_cache_gate | funnel_cache_gate | scaled_insert | all) ;; *) echo "error: unsupported target: $target" >&2; exit 2 ;; esac

criterion_root=$(realpath -- "$criterion_root")
if [[ $snapshot_root == /* ]]; then
	snapshot_root=$(realpath -m -- "$snapshot_root")
else
	snapshot_root=$(realpath -m -- "$REPO_ROOT/$snapshot_root")
fi
target_root=$(realpath -m -- "$REPO_ROOT/target")
[[ $snapshot_root == "$target_root" || $snapshot_root == "$target_root"/* ]] || { echo "error: snapshot root must stay below runner root target" >&2; exit 2; }
anchor_manifest=$(realpath -- "$anchor_manifest")
candidate_manifest=$(realpath -- "$candidate_manifest")
destination="$snapshot_root/$arch/$comparison/pair-$pair"
[[ ! -e $destination ]] || { echo "error: destination already exists: $destination" >&2; exit 1; }
mkdir -p -- "$(dirname "$destination")" "$LOCK_DIR"

root_key=$(printf '%s' "$criterion_root" | sha256sum); root_key=${root_key%% *}
root_lock="$LOCK_DIR/opthash-bench-root-$root_key.lock"
if [[ -L $root_lock ]] || { [[ -e $root_lock ]] && [[ ! -d $root_lock && ! -f $root_lock ]]; }; then
	echo "error: unsafe Criterion root lock $root_lock" >&2; exit 1
fi
if [[ ! -e $root_lock ]] && ! mkdir -m 0755 "$root_lock" 2>/dev/null && [[ ! -e $root_lock ]]; then
	echo "error: cannot create Criterion root lock $root_lock" >&2; exit 1
fi
exec {criterion_lock_fd}<"$root_lock"
flock "$criterion_lock_fd"

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
anchor = json.load(open(anchor_path, encoding="utf-8"))
candidate = json.load(open(candidate_path, encoding="utf-8"))
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
    if set(tools) != {"snapshot", "launcher", "perf", "elf_layout", "link_wrapper"}:
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
json.dump({"control": anchor["control"], "candidate_executables":candidate["executables"], "tools":candidate["tools"]}, open(output, "w", encoding="utf-8"), indent=2, sort_keys=True)
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
	comparison_command=("$control_binary" --bench "${criterion_args[@]}")
	CRITERION_HOME="$criterion_root" "${comparison_command[@]}" >"$comparison_stdout" 2>"$comparison_stderr"
	python3 - "$comparison_commands" "${comparison_command[@]}" <<'PY'
import json,sys
json.dump([sys.argv[2:]], open(sys.argv[1], "w"), indent=2)
PY
	;;
elastic_cache_gate | funnel_cache_gate)
	stable_binary=$(jq -er --arg target "$target" '.candidate_executables[$target].absolute_path' "$validation")
	stable_hash=$(jq -er --arg target "$target" '.candidate_executables[$target].sha256' "$validation")
	actual_stable_hash=$(sha256sum -- "$stable_binary"); actual_stable_hash=${actual_stable_hash%% *}
	[[ $actual_stable_hash == "$stable_hash" ]] || { echo "error: candidate stable binary hash mismatch" >&2; exit 1; }
	comparison_command=("$stable_binary" --bench "${criterion_args[@]}")
	CRITERION_HOME="$criterion_root" "${comparison_command[@]}" >"$comparison_stdout" 2>"$comparison_stderr"
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
	local source=$1 output=$2 source_root=${3:-} before after copied
	[[ -f $source && ! -L $source ]] || { echo "error: invalid copy source: $source" >&2; exit 1; }
	[[ -z $source_root ]] || assert_contained "$source_root" "$source"
	assert_contained "$temporary" "$output"
	before=$(sha256sum -- "$source"); before=${before%% *}
	mkdir -p -- "$(dirname "$output")"; cp --preserve=mode,timestamps -- "$source" "$output"
	after=$(sha256sum -- "$source"); after=${after%% *}; copied=$(sha256sum -- "$output"); copied=${copied%% *}
	[[ $before == "$after" && $before == "$copied" ]] || { echo "error: hash changed while copying $source" >&2; exit 1; }
}
for benchmark in "${expected_ids[@]}"; do
	copy_verified "$criterion_root/$benchmark/change/estimates.json" "$temporary/change/$benchmark/change/estimates.json" "$criterion_root"
	copy_verified "$criterion_root/$benchmark/$anchor_run/estimates.json" "$temporary/absolute/anchor/$benchmark/estimates.json" "$criterion_root"
	copy_verified "$criterion_root/$benchmark/$candidate_run/estimates.json" "$temporary/absolute/candidate/$benchmark/estimates.json" "$criterion_root"
done

copy_bundle() {
	local label=$1 manifest=$2
	mkdir -p "$temporary/build"
	copy_verified "$manifest" "$temporary/build/$label-manifest.json"
	while IFS=$'\t' read -r name map; do
		copy_verified "$map" "$temporary/build/$label-link-maps/$name.map"
	done < <(
		python3 - "$manifest" <<'PY'
import json,sys
m=json.load(open(sys.argv[1]))
for name,item in sorted(m["executables"].items()): print(f'{name}\t{item["link_map"]["absolute_path"]}')
PY
	)
}
copy_bundle anchor "$anchor_manifest"; copy_bundle candidate "$candidate_manifest"

python3 - "$temporary/pair-manifest.json" "$temporary/build/anchor-manifest.json" "$temporary/build/candidate-manifest.json" "$validation" "$comparison_commands" "$original_command" "$start_ns" "$end_ns" "$start_iso" "$end_iso" "$target" "$anchor_run" "$candidate_run" "$REPO_ROOT" "$snapshot_tool" <<'PY'
import json,platform,sys
output, anchor_path, candidate_path, validation_path, commands_path, snapshot_command, start_ns, end_ns, start_iso, end_iso, target, anchor_run, candidate_run, runner_root, executor = sys.argv[1:]
anchor=json.load(open(anchor_path)); candidate=json.load(open(candidate_path)); validation=json.load(open(validation_path)); commands=json.load(open(commands_path))
payload={
 "target":target, "host":platform.node(), "snapshot_command":snapshot_command.rstrip(),
 "comparison_command":commands[0], "comparison_commands":commands,
 "offline_execution_count":1,"runner_root":runner_root,
 "executor":{"absolute_path":executor,"sha256":validation["tools"]["snapshot"]["sha256"]},
 "comparison_started_ns":int(start_ns), "comparison_finished_ns":int(end_ns),
 "comparison_started_at":start_iso, "comparison_finished_at":end_iso,
 "control":validation["control"],
 "anchor":{"run":anchor_run,"commit":anchor["commit"],"tree":anchor["tree"],"executable_hashes":{k:v["sha256"] for k,v in anchor["executables"].items()}},
 "candidate":{"run":candidate_run,"commit":candidate["commit"],"tree":candidate["tree"],"executable_hashes":{k:v["sha256"] for k,v in candidate["executables"].items()}},
}
json.dump(payload,open(output,"w"),indent=2,sort_keys=True); open(output,"a").write("\n")
PY
rm -f "$marker" "$validation" "$comparison_commands"
(
	cd "$temporary"
	find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS
	sha256sum -c SHA256SUMS
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
