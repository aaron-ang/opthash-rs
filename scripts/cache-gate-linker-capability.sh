#!/usr/bin/env bash
# Prove target-specific cache-gate linker augmentations on every required linker.

set -euo pipefail

normalize_failure_to_hold() {
	local status=$?
	trap - EXIT
	if [[ $status -ne 0 && $status -ne 3 ]]; then
		echo "HOLD: capability probe stopped with status $status" >&2
		exit 3
	fi
	exit "$status"
}
trap normalize_failure_to_hold EXIT

CACHE_GATE_REALPATH_TOOL=/usr/bin/realpath
CACHE_GATE_SHA256_TOOL=/usr/bin/sha256sum
for bootstrap_tool in "$CACHE_GATE_REALPATH_TOOL" "$CACHE_GATE_SHA256_TOOL"; do
	[[ -f $bootstrap_tool && -x $bootstrap_tool && ! -L $bootstrap_tool ]] || {
		echo "HOLD: trusted bootstrap tool is unavailable: $bootstrap_tool" >&2
		exit 3
	}
done

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$REPO_ROOT"
[[ -z $(git status --porcelain --untracked-files=normal) ]] || {
	echo "HOLD: capability producer worktree must be clean" >&2
	exit 3
}
producer_commit=$(git rev-parse HEAD)
producer_tree=$(git rev-parse 'HEAD^{tree}')

hold() {
	echo "HOLD: $*" >&2
	exit 3
}

[[ -z ${RUSTFLAGS:-} ]] || hold "RUSTFLAGS is unsupported for authenticated capability builds"
[[ -z ${CARGO_ENCODED_RUSTFLAGS:-} ]] || hold "CARGO_ENCODED_RUSTFLAGS is unsupported for authenticated capability builds"
[[ -z ${CACHE_GATE_LINK_FRAGMENT:-} ]] || hold "CACHE_GATE_LINK_FRAGMENT is reserved for manifest builds"
[[ -z ${CACHE_GATE_LINK_MAP:-} ]] || hold "CACHE_GATE_LINK_MAP is reserved for manifest builds"
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
unset CACHE_GATE_LINK_FRAGMENT CACHE_GATE_LINK_MAP

[[ $(uname -s) == Linux ]] || hold "cache-gate linker capability requires native Linux ELF"
case $(uname -m) in
aarch64 | arm64) arch=aarch64 ;;
x86_64 | amd64) arch=x86_64 ;;
*) hold "unsupported native architecture: $(uname -m)" ;;
esac
target_triple=$(rustc -vV | sed -n 's/^host: //p')
[[ $target_triple == "$arch"-*linux-gnu ]] || hold "rustc host is not native Linux ELF: $target_triple"
command -v readelf >/dev/null 2>&1 || hold "readelf is required"
command -v objdump >/dev/null 2>&1 || hold "objdump is required"

declare -A fragments=(
	[elastic]="$REPO_ROOT/benches/cache-gate-elastic-layout.ld"
	[funnel]="$REPO_ROOT/benches/cache-gate-funnel-layout.ld"
	[profile]="$REPO_ROOT/benches/cache-gate-profile-layout.ld"
)
for target in elastic funnel profile; do
	[[ -f ${fragments[$target]} ]] || hold "missing $target linker fragment"
done
elastic_sha=$("$CACHE_GATE_SHA256_TOOL" "${fragments[elastic]}"); elastic_sha=${elastic_sha%% *}
funnel_sha=$("$CACHE_GATE_SHA256_TOOL" "${fragments[funnel]}"); funnel_sha=${funnel_sha%% *}
profile_sha=$("$CACHE_GATE_SHA256_TOOL" "${fragments[profile]}"); profile_sha=${profile_sha%% *}
fragment_set_sha=$(printf 'elastic:%s\nfunnel:%s\nprofile:%s\n' "$elastic_sha" "$funnel_sha" "$profile_sha" | "$CACHE_GATE_SHA256_TOOL"); fragment_set_sha=${fragment_set_sha%% *}

output_root="$REPO_ROOT/target/cache-gate-linker/$arch"
validate_output_ancestry() {
	local component
	for component in "$REPO_ROOT/target" "$REPO_ROOT/target/cache-gate-linker" "$output_root"; do
		[[ ! -L $component ]] || hold "capability output ancestry contains symlink: $component"
		[[ ! -e $component || -d $component ]] || hold "capability output ancestry is not a directory: $component"
	done
}
validate_output_ancestry
[[ ! -e $output_root/capability.json && ! -L $output_root/capability.json ]] || hold "capability record already exists: $output_root/capability.json"
mkdir -p "$output_root"
validate_output_ancestry
[[ $("$CACHE_GATE_REALPATH_TOOL" -e -- "$output_root") == "$output_root" ]] || hold "capability output root is not canonical"
probe_root=$(mktemp -d "$output_root/.probe.XXXXXX")
validate_probe_root() {
	[[ $probe_root == "$output_root"/.probe.* ]] || hold "capability probe root name is invalid"
	[[ -d $probe_root && ! -L $probe_root ]] || hold "capability probe root is a symlink or non-directory"
	[[ $("$CACHE_GATE_REALPATH_TOOL" -e -- "$probe_root") == "$probe_root" ]] || hold "capability probe root is not canonical"
}
validate_probe_root

record_field() {
	python3 - "$1" "$2" <<'PY'
import json,sys
value=json.loads(open(sys.argv[1],encoding="utf-8").read())[sys.argv[2]]
if not isinstance(value,str) or not value:
    raise SystemExit(f"invalid linker record field: {sys.argv[2]}")
print(value)
PY
}

verify_linker_record() {
	local record=$1 label=$2
	if ! "$REPO_ROOT/scripts/cache-gate-elf-layout.py" verify-linker-record --record "$record"; then
		hold "$label linker identity/version changed"
	fi
}

inspect_linker_record() {
	local invocation=$1 argv0=$2 flavor=$3 output=$4 extraction_root=${5:-}
	local args=(inspect-linker-record --invocation-path "$invocation" --argv0 "$argv0" --flavor "$flavor" --output "$output")
	if [[ -n $extraction_root ]]; then args+=(--extraction-root "$extraction_root"); fi
	if ! "$REPO_ROOT/scripts/cache-gate-elf-layout.py" "${args[@]}"; then
		hold "$flavor linker identity/version probe failed"
	fi
	verify_linker_record "$output" "$flavor"
}

run_shape() {
	local flavor=$1 target=$2 linker_record=$3 fuse=$4
	local target_root="$probe_root/$flavor/$target" map="$probe_root/$flavor/$target.map"
	local link_args="$probe_root/$flavor/$target.link-args.txt" symbols="$probe_root/$flavor/$target.symbols.json"
	local layout="$probe_root/$flavor/$target.layout.json" binary
	local linker_trace="$probe_root/$flavor/$target.linker-trace.jsonl"
	local linker_execution="$probe_root/$flavor/$target.linker-execution.json"
	local cargo_trace="$probe_root/$flavor/$target.cargo-driver-trace.jsonl"
	local cargo_execution="$probe_root/$flavor/$target.cargo-driver-execution.json"
	local link_session="$flavor-$target-$$"
	local linker_payload linker_argv0
	linker_payload=$(record_field "$linker_record" payload_path) || hold "$flavor linker record has invalid payload"
	linker_argv0=$(record_field "$linker_record" argv0) || hold "$flavor linker record has invalid argv0"
	validate_probe_root
	verify_linker_record "$actual_record" actual
	if [[ $linker_record != "$actual_record" ]]; then verify_linker_record "$linker_record" "$flavor"; fi
	mkdir -p "$target_root"
	local flags="--cfg cache_gate_probe_$target --check-cfg=cfg(cache_gate_probe_elastic) --check-cfg=cfg(cache_gate_probe_funnel) --check-cfg=cfg(cache_gate_probe_profile)"
	if [[ $flavor == actual ]]; then
		flags+=" -C linker=$REPO_ROOT/scripts/cache-gate-link-wrapper.py"
	else
		local wrapper_dir="$probe_root/$flavor/linker-wrapper" wrapper="$probe_root/$flavor/linker-wrapper/ld.$fuse"
		mkdir -p "$wrapper_dir"
		if [[ ! -e $wrapper ]]; then
			cp -- "$REPO_ROOT/scripts/cache-gate-link-wrapper.py" "$wrapper"
			chmod 0755 "$wrapper"
		fi
		flags+=" -C linker=$REPO_ROOT/scripts/cache-gate-link-wrapper.py -C link-arg=-B$wrapper_dir -C link-arg=-fuse-ld=$fuse"
	fi
	flags+=" -C link-arg=-Wl,-T,${fragments[$target]} -C link-arg=-Wl,-Map,$map"
	if [[ $flavor == actual ]]; then
		CACHE_GATE_LINK_DRIVER="$linker_payload" CACHE_GATE_LINK_ARGV0="$linker_argv0" CACHE_GATE_LINK_TRACE="$linker_trace" \
			CACHE_GATE_LINK_ROLE=actual-driver CACHE_GATE_LINK_SESSION="$link_session" \
			RUSTFLAGS="$flags" CARGO_TARGET_DIR="$target_root" cargo rustc --release --locked \
			--manifest-path tools/cache-gate-link-probe/Cargo.toml --bin "$target" -- \
			-C codegen-units=1 --print link-args >"$link_args" 2>"$probe_root/$flavor/$target.cargo.stderr" || \
			hold "$flavor failed $target 2/2/4 capability link"
	else
		CACHE_GATE_LINK_DRIVER="$actual_payload" CACHE_GATE_LINK_ARGV0="$actual_argv0" CACHE_GATE_LINK_TRACE="$cargo_trace" \
			CACHE_GATE_LINK_ROLE=cargo-driver CACHE_GATE_LINK_SESSION="$link_session" \
			CACHE_GATE_INNER_LINK_DRIVER="$linker_payload" CACHE_GATE_INNER_LINK_ARGV0="$linker_argv0" CACHE_GATE_INNER_LINK_TRACE="$linker_trace" \
			CACHE_GATE_INNER_LINK_ROLE=explicit-linker \
			RUSTFLAGS="$flags" CARGO_TARGET_DIR="$target_root" cargo rustc --release --locked \
			--manifest-path tools/cache-gate-link-probe/Cargo.toml --bin "$target" -- \
			-C codegen-units=1 --print link-args >"$link_args" 2>"$probe_root/$flavor/$target.cargo.stderr" || \
			hold "$flavor failed $target 2/2/4 capability link"
	fi
	binary=$("$CACHE_GATE_REALPATH_TOOL" "$target_root/release/$target")
	[[ -x $binary && -s $map && -s $link_args ]] || hold "$flavor did not emit $target ELF/map/link argv"
	[[ -s $linker_trace ]] || hold "$flavor did not trace exact $target linker execution"
	"$REPO_ROOT/scripts/cache-gate-elf-layout.py" validate-linker-execution \
		--trace "$linker_trace" --linker-record "$linker_record" \
		--executable "$binary" --flavor "$flavor" --output "$linker_execution" || \
		hold "$flavor did not bind exact $target linker executable"
	if [[ $flavor != actual ]]; then
		[[ -s $cargo_trace ]] || hold "$flavor did not trace exact $target Cargo driver execution"
		"$REPO_ROOT/scripts/cache-gate-elf-layout.py" validate-linker-execution \
			--trace "$cargo_trace" --linker-record "$actual_record" \
			--executable "$binary" --flavor actual --output "$cargo_execution" || \
			hold "$flavor did not bind exact $target Cargo driver execution"
	fi
	file "$binary" | rg -q 'ELF' || hold "$flavor emitted non-ELF $target output"
	case "$target" in
	elastic)
		patterns=(elastic_cache_gate_insert_kernel elastic_cache_gate_get_kernel)
		;;
	funnel)
		patterns=(funnel_cache_gate_insert_kernel funnel_cache_gate_get_kernel)
		;;
	profile)
		patterns=(elastic_profile_insert_kernel elastic_profile_get_kernel funnel_profile_insert_kernel funnel_profile_get_kernel)
		;;
	esac
	extract_args=()
	for pattern in "${patterns[@]}"; do extract_args+=(--symbol "::$pattern$"); done
	"$REPO_ROOT/scripts/extract-hot-symbols.py" --binary "$binary" --arch "$arch" \
		"${extract_args[@]}" --output "$symbols"
	if ! CACHE_GATE_LINKER_CAPABILITY="$probe_root/provisional-capability.json" \
		"$REPO_ROOT/scripts/cache-gate-elf-layout.py" validate --binary "$binary" \
		--link-map "$map" --script "${fragments[$target]}" --symbols "$symbols" \
		--arch "$arch" --output "$layout"; then
		hold "$flavor failed structural $target 2/2/4 validation"
	fi
	verify_linker_record "$actual_record" actual
	if [[ $linker_record != "$actual_record" ]]; then verify_linker_record "$linker_record" "$flavor"; fi
	validate_probe_root
}

# First exercise Cargo's actual configured linker and resolve its absolute driver.
actual_target_root="$probe_root/actual-bootstrap"
mkdir -p "$actual_target_root"
actual_map="$probe_root/actual-bootstrap.map"
actual_args="$probe_root/actual-bootstrap.link-args.txt"
actual_flags="--cfg cache_gate_probe_elastic --check-cfg=cfg(cache_gate_probe_elastic) --check-cfg=cfg(cache_gate_probe_funnel) --check-cfg=cfg(cache_gate_probe_profile) -C link-arg=-Wl,-T,${fragments[elastic]} -C link-arg=-Wl,-Map,$actual_map"
if ! RUSTFLAGS="$actual_flags" CARGO_TARGET_DIR="$actual_target_root" cargo rustc --release --locked \
	--manifest-path tools/cache-gate-link-probe/Cargo.toml --bin elastic -- \
	-C codegen-units=1 --print link-args >"$actual_args" 2>"$probe_root/actual-bootstrap.cargo.stderr"; then
	hold "actual Cargo-configured linker does not support --print link-args/augmentation"
fi
actual_driver=$("$REPO_ROOT/scripts/cache-gate-elf-layout.py" resolve-cargo-linker \
	--link-args "$actual_args") || hold "cannot resolve actual Cargo linker command"
actual_driver=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$actual_driver")
[[ -f $actual_driver && ! -L $actual_driver && -x $actual_driver ]] || hold "actual Cargo linker is not canonical"
actual_record="$probe_root/actual-linker-record.json"
inspect_linker_record "$actual_driver" "$actual_driver" actual "$actual_record"
actual_payload=$(record_field "$actual_record" payload_path) || hold "actual linker record has invalid payload"
actual_argv0=$(record_field "$actual_record" argv0) || hold "actual linker record has invalid argv0"

# Derive target MAXPAGESIZE from actual link's executable LOAD alignment.
actual_binary=$("$CACHE_GATE_REALPATH_TOOL" "$actual_target_root/release/elastic")
max_page_size=$(readelf -lW "$actual_binary" | python3 -c 'import re,sys; values=[int(m.group(1),16) for line in sys.stdin for m in [re.match(r"^\s*LOAD\s+.*\s+(0x[0-9A-Fa-f]+)\s*$",line)] if m]; print(max(values) if values else 0)')
[[ $max_page_size =~ ^[1-9][0-9]*$ ]] || hold "cannot derive actual linker MAXPAGESIZE"

cat >"$probe_root/provisional-capability.json" <<EOF
{"accepted":true,"arch":"$arch","max_page_size":$max_page_size,"fragment_set_sha256":"$fragment_set_sha","fragments":{"elastic":{"absolute_path":"${fragments[elastic]}","sha256":"$elastic_sha"},"funnel":{"absolute_path":"${fragments[funnel]}","sha256":"$funnel_sha"},"profile":{"absolute_path":"${fragments[profile]}","sha256":"$profile_sha"}}}
EOF

for target in elastic funnel profile; do run_shape actual "$target" "$actual_record" actual; done

gnu_invocation=$(command -v ld.bfd || true)
[[ -n $gnu_invocation ]] || hold "native GNU ld.bfd is unavailable"
[[ $gnu_invocation == /* ]] || hold "native GNU ld.bfd invocation is not absolute"
gnu_argv0=$("$CACHE_GATE_REALPATH_TOOL" -e -- "$gnu_invocation")
gnu_record="$probe_root/gnu-linker-record.json"
inspect_linker_record "$gnu_invocation" "$gnu_argv0" gnu "$gnu_record"
for target in elastic funnel profile; do run_shape gnu "$target" "$gnu_record" bfd; done

lld_invocation=$(command -v ld.lld || true)
[[ -n $lld_invocation ]] || hold "native ld.lld is unavailable"
[[ $lld_invocation == /* ]] || hold "native ld.lld invocation is not absolute"
lld_extraction_root=
case $lld_invocation in
"$REPO_ROOT"/target/toolchains/*/root/*)
	relative_lld=${lld_invocation#"$REPO_ROOT/target/toolchains/"}
	toolchain_name=${relative_lld%%/root/*}
	lld_extraction_root="$REPO_ROOT/target/toolchains/$toolchain_name/root"
	;;
esac
lld_record="$probe_root/lld-linker-record.json"
inspect_linker_record "$lld_invocation" ld.lld lld "$lld_record" "$lld_extraction_root"
for target in elastic funnel profile; do run_shape lld "$target" "$lld_record" lld; done

validate_output_ancestry
validate_probe_root
[[ ! -e $output_root/capability.json && ! -L $output_root/capability.json ]] || hold "capability record appeared before publication: $output_root/capability.json"
if ! python3 - "$REPO_ROOT" "$probe_root" "$arch" "$target_triple" \
	"$actual_record" "$gnu_record" "$lld_record" \
	"$max_page_size" "$elastic_sha" "$funnel_sha" "$profile_sha" "$fragment_set_sha" \
	"$producer_commit" "$producer_tree" <<'PY'
import ctypes,errno,hashlib,json,os,stat,subprocess,sys
from pathlib import Path
(repo,probe,arch,triple,actual_record,gnu_record,lld_record,
 max_page,elastic_sha,funnel_sha,profile_sha,set_sha,producer_commit,
 producer_tree)=sys.argv[1:]
root=Path(probe)
def load_linker(path):
    path=Path(path)
    if path.parent!=root or path!=path.resolve(strict=True):
        raise RuntimeError("linker record path escapes exact probe root")
    return json.loads(path.read_text())
actual_linker=load_linker(actual_record)
gnu_linker=load_linker(gnu_record)
lld_linker=load_linker(lld_record)
def record(path):
    path=Path(path).resolve()
    return {"absolute_path":str(path),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
shapes={}
for flavor in ("actual","gnu","lld"):
    shapes[flavor]={}
    for target in ("elastic","funnel","profile"):
        shapes[flavor][target]={
            "binary":record(root/flavor/target/"release"/target),
            "link_argv":record(root/flavor/f"{target}.link-args.txt"),
            "link_map":record(root/flavor/f"{target}.map"),
            "layout":record(root/flavor/f"{target}.layout.json"),
            "symbols":record(root/flavor/f"{target}.symbols.json"),
        }
        execution=root/flavor/f"{target}.linker-execution.json"
        if execution.exists(): shapes[flavor][target]["linker_execution"]=record(execution)
        cargo_execution=root/flavor/f"{target}.cargo-driver-execution.json"
        if cargo_execution.exists(): shapes[flavor][target]["cargo_execution"]=record(cargo_execution)
payload={
 "accepted":True,"arch":arch,"target_triple":triple,"max_page_size":int(max_page),
 "producer":{"runner_root":str(Path(repo).resolve()),"commit":producer_commit,
   "tree":producer_tree,"empty_diff_assertion":True,"artifact_root":str(root)},
 "rustc_version":subprocess.check_output(["rustc","-vV"],text=True).strip(),
 "cargo_version":subprocess.check_output(["cargo","-V"],text=True).strip(),
 "linker":actual_linker,
 "required_linkers":{
   "gnu":gnu_linker,
   "lld":lld_linker,
 },
 "fragments":{
   "elastic":{"absolute_path":str(Path(repo)/"benches/cache-gate-elastic-layout.ld"),"sha256":elastic_sha},
   "funnel":{"absolute_path":str(Path(repo)/"benches/cache-gate-funnel-layout.ld"),"sha256":funnel_sha},
   "profile":{"absolute_path":str(Path(repo)/"benches/cache-gate-profile-layout.ld"),"sha256":profile_sha},
 },
 "fragment_set_sha256":set_sha,"shapes":shapes,
}
data=(json.dumps(payload,indent=2,sort_keys=True)+"\n").encode()
directory_flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
fds=[]
source_fd=None
published=False
try:
    repo_path=Path(repo)
    expected_probe=repo_path/"target"/"cache-gate-linker"/arch/root.name
    if repo_path!=repo_path.resolve(strict=True) or root!=expected_probe or not root.name.startswith(".probe."):
        raise RuntimeError("capability publication paths are not canonical")
    current=os.open(repo, directory_flags)
    fds.append(current)
    for component in ("target","cache-gate-linker",arch,root.name):
        current=os.open(component,directory_flags,dir_fd=current)
        fds.append(current)
    arch_fd=fds[-2]
    probe_fd=fds[-1]
    source_fd=os.open(
        "capability.json",
        os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
        0o600,
        dir_fd=probe_fd,
    )
    view=memoryview(data)
    while view:
        written=os.write(source_fd,view)
        if written<=0: raise OSError("short capability write")
        view=view[written:]
    os.fsync(source_fd)
    source_stat=os.fstat(source_fd)
    if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_nlink!=1:
        raise RuntimeError("capability source is not a private regular file")
    libc=ctypes.CDLL(None,use_errno=True)
    renameat2=libc.renameat2
    renameat2.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
    renameat2.restype=ctypes.c_int
    RENAME_NOREPLACE=1
    if renameat2(probe_fd,b"capability.json",arch_fd,b"capability.json",RENAME_NOREPLACE)!=0:
        value=ctypes.get_errno()
        raise OSError(value,os.strerror(value))
    published=True
    destination_stat=os.stat("capability.json",dir_fd=arch_fd,follow_symlinks=False)
    if (not stat.S_ISREG(destination_stat.st_mode) or
        (destination_stat.st_dev,destination_stat.st_ino)!=(source_stat.st_dev,source_stat.st_ino)):
        raise RuntimeError("published capability inode differs from authenticated source")
    os.fsync(probe_fd)
    os.fsync(arch_fd)
except Exception:
    if published:
        try:
            published_stat=os.stat("capability.json",dir_fd=arch_fd,follow_symlinks=False)
            if ((published_stat.st_dev,published_stat.st_ino)==
                (source_stat.st_dev,source_stat.st_ino)):
                os.unlink("capability.json",dir_fd=arch_fd)
                os.fsync(arch_fd)
        except OSError:
            pass
    raise
finally:
    if source_fd is not None: os.close(source_fd)
    for descriptor in reversed(fds): os.close(descriptor)
PY
then
	hold "secure capability publication failed"
fi
echo "$output_root/capability.json"
