#!/usr/bin/env bash
# Prove target-specific cache-gate linker augmentations on every required linker.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$REPO_ROOT"

hold() {
	echo "HOLD: $*" >&2
	exit 3
}

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
elastic_sha=$(sha256sum "${fragments[elastic]}"); elastic_sha=${elastic_sha%% *}
funnel_sha=$(sha256sum "${fragments[funnel]}"); funnel_sha=${funnel_sha%% *}
profile_sha=$(sha256sum "${fragments[profile]}"); profile_sha=${profile_sha%% *}
fragment_set_sha=$(printf 'elastic:%s\nfunnel:%s\nprofile:%s\n' "$elastic_sha" "$funnel_sha" "$profile_sha" | sha256sum); fragment_set_sha=${fragment_set_sha%% *}

output_root="$REPO_ROOT/target/cache-gate-linker/$arch"
[[ ! -e $output_root/capability.json ]] || hold "capability record already exists: $output_root/capability.json"
mkdir -p "$output_root"
probe_root=$(mktemp -d "$output_root/.probe.XXXXXX")

run_shape() {
	local flavor=$1 target=$2 explicit_linker=$3 fuse=$4
	local target_root="$probe_root/$flavor/$target" map="$probe_root/$flavor/$target.map"
	local link_args="$probe_root/$flavor/$target.link-args.txt" symbols="$probe_root/$flavor/$target.symbols.json"
	local layout="$probe_root/$flavor/$target.layout.json" binary
	local linker_trace="$probe_root/$flavor/$target.linker-trace.jsonl"
	local linker_execution="$probe_root/$flavor/$target.linker-execution.json"
	mkdir -p "$target_root"
	local flags="--cfg cache_gate_probe_$target --check-cfg=cfg(cache_gate_probe_elastic) --check-cfg=cfg(cache_gate_probe_funnel) --check-cfg=cfg(cache_gate_probe_profile)"
	if [[ -n $explicit_linker ]]; then
		local wrapper_dir="$probe_root/$flavor/linker-wrapper" wrapper="$probe_root/$flavor/linker-wrapper/ld.$fuse"
		mkdir -p "$wrapper_dir"
		if [[ ! -e $wrapper ]]; then
			cp -- "$REPO_ROOT/scripts/cache-gate-link-wrapper.py" "$wrapper"
			chmod 0755 "$wrapper"
		fi
		flags+=" -C link-arg=-B$wrapper_dir -C link-arg=-fuse-ld=$fuse"
	fi
	flags+=" -C link-arg=-Wl,-T,${fragments[$target]} -C link-arg=-Wl,-Map,$map"
	if [[ -n $explicit_linker ]]; then
		CACHE_GATE_LINK_DRIVER="$explicit_linker" CACHE_GATE_LINK_TRACE="$linker_trace" \
			RUSTFLAGS="$flags" CARGO_TARGET_DIR="$target_root" cargo rustc --release --locked \
			--manifest-path tools/cache-gate-link-probe/Cargo.toml --bin "$target" -- \
			-C codegen-units=1 --print link-args >"$link_args" 2>"$probe_root/$flavor/$target.cargo.stderr" || \
			hold "$flavor failed $target 2/2/4 capability link"
	elif ! RUSTFLAGS="$flags" CARGO_TARGET_DIR="$target_root" cargo rustc --release --locked \
		--manifest-path tools/cache-gate-link-probe/Cargo.toml --bin "$target" -- \
		-C codegen-units=1 --print link-args >"$link_args" 2>"$probe_root/$flavor/$target.cargo.stderr"; then
		hold "$flavor failed $target 2/2/4 capability link"
	fi
	binary=$(realpath "$target_root/release/$target")
	[[ -x $binary && -s $map && -s $link_args ]] || hold "$flavor did not emit $target ELF/map/link argv"
	if [[ -n $explicit_linker ]]; then
		[[ -s $linker_trace ]] || hold "$flavor did not trace exact $target linker execution"
		"$REPO_ROOT/scripts/cache-gate-elf-layout.py" validate-linker-execution \
			--trace "$linker_trace" --linker "$explicit_linker" \
			--executable "$binary" --flavor "$flavor" --output "$linker_execution" || \
			hold "$flavor did not bind exact $target linker executable"
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
actual_driver=$(python3 - "$actual_args" <<'PY'
import shlex,shutil,sys
line=open(sys.argv[1],encoding="utf-8").read().strip().splitlines()[-1]
tokens=shlex.split(line)
command=next((token for token in tokens if "=" not in token), "")
resolved=shutil.which(command) if command else None
if not resolved: raise SystemExit(1)
print(resolved)
PY
) || hold "cannot resolve actual Cargo linker command"
actual_version=$("$actual_driver" -Wl,--version 2>&1 | rg -m1 'GNU ld|LLD|lld' || true)
case "$actual_version" in
*"GNU ld"*) actual_flavor="GNU ld" ;;
*"LLD"* | *"lld"*) actual_flavor="LLD" ;;
*) hold "unsupported actual Cargo linker flavor: $actual_version" ;;
esac

# Derive target MAXPAGESIZE from actual link's executable LOAD alignment.
actual_binary=$(realpath "$actual_target_root/release/elastic")
max_page_size=$(readelf -lW "$actual_binary" | python3 -c 'import re,sys; values=[int(m.group(1),16) for line in sys.stdin for m in [re.match(r"^\s*LOAD\s+.*\s+(0x[0-9A-Fa-f]+)\s*$",line)] if m]; print(max(values) if values else 0)')
[[ $max_page_size =~ ^[1-9][0-9]*$ ]] || hold "cannot derive actual linker MAXPAGESIZE"

cat >"$probe_root/provisional-capability.json" <<EOF
{"accepted":true,"arch":"$arch","max_page_size":$max_page_size,"fragment_set_sha256":"$fragment_set_sha","fragments":{"elastic":{"absolute_path":"${fragments[elastic]}","sha256":"$elastic_sha"},"funnel":{"absolute_path":"${fragments[funnel]}","sha256":"$funnel_sha"},"profile":{"absolute_path":"${fragments[profile]}","sha256":"$profile_sha"}}}
EOF

for target in elastic funnel profile; do run_shape actual "$target" "" ""; done

gnu_ld=$(command -v ld.bfd || true)
[[ -n $gnu_ld ]] || hold "native GNU ld.bfd is unavailable"
gnu_ld=$(realpath "$gnu_ld")
gnu_version=$("$gnu_ld" --version | head -1)
[[ $gnu_version == *"GNU ld"* ]] || hold "ld.bfd is not GNU ld: $gnu_version"
for target in elastic funnel profile; do run_shape gnu "$target" "$gnu_ld" bfd; done

lld=$(command -v ld.lld || command -v lld || true)
[[ -n $lld ]] || hold "native LLD is unavailable"
lld=$(realpath "$lld")
lld_version=$("$lld" --version | head -1)
[[ $lld_version == *LLD* || $lld_version == *lld* ]] || hold "ld.lld is not LLD: $lld_version"
for target in elastic funnel profile; do run_shape lld "$target" "$lld" lld; done

python3 - "$probe_root/capability.json" "$REPO_ROOT" "$probe_root" "$arch" "$target_triple" \
	"$actual_driver" "$actual_flavor" "$actual_version" "$gnu_ld" "$gnu_version" "$lld" "$lld_version" \
	"$max_page_size" "$elastic_sha" "$funnel_sha" "$profile_sha" "$fragment_set_sha" <<'PY'
import hashlib,json,subprocess,sys
from pathlib import Path
(output,repo,probe,arch,triple,actual_driver,actual_flavor,actual_version,gnu,gnu_version,
 lld,lld_version,max_page,elastic_sha,funnel_sha,profile_sha,set_sha)=sys.argv[1:]
root=Path(probe)
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
payload={
 "accepted":True,"arch":arch,"target_triple":triple,"max_page_size":int(max_page),
 "rustc_version":subprocess.check_output(["rustc","-vV"],text=True).strip(),
 "cargo_version":subprocess.check_output(["cargo","-V"],text=True).strip(),
 "linker":{"absolute_path":actual_driver,"sha256":hashlib.sha256(Path(actual_driver).read_bytes()).hexdigest(),"flavor":actual_flavor,"version":actual_version},
 "required_linkers":{
   "gnu":{"absolute_path":gnu,"sha256":hashlib.sha256(Path(gnu).read_bytes()).hexdigest(),"flavor":"GNU ld","version":gnu_version},
   "lld":{"absolute_path":lld,"sha256":hashlib.sha256(Path(lld).read_bytes()).hexdigest(),"flavor":"LLD","version":lld_version},
 },
 "fragments":{
   "elastic":{"absolute_path":str(Path(repo)/"benches/cache-gate-elastic-layout.ld"),"sha256":elastic_sha},
   "funnel":{"absolute_path":str(Path(repo)/"benches/cache-gate-funnel-layout.ld"),"sha256":funnel_sha},
   "profile":{"absolute_path":str(Path(repo)/"benches/cache-gate-profile-layout.ld"),"sha256":profile_sha},
 },
 "fragment_set_sha256":set_sha,"shapes":shapes,
}
Path(output).write_text(json.dumps(payload,indent=2,sort_keys=True)+"\n")
PY
mv "$probe_root/capability.json" "$output_root/capability.json"
echo "$output_root/capability.json"
