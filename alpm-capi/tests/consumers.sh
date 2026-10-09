#!/usr/bin/env bash
# read-path equivalence for the Rust (alpm.rs/alpm-sys) and Go (go-alpm)
# consumers: each links libalpm.so.16 and is run against puck's lib and
# the real one on one fixture, output diffed. the pyalpm gate is a Rust
# #[test] (tests/pyalpm.rs); this covers the other two.
#
# alpm.rs is required and gates (exit 1 on diff). go-alpm is an optional
# external reference (yay's cgo binding): built/run best-effort, never
# gates. usage: alpm-capi/tests/consumers.sh   (from repo root)
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
pb=${PACMAN_BUILD:-$root/pacman/build}
hdr=$root/pacman/lib/libalpm
tmp=$root/.tmp/consumers
rc=0

if [ ! -e "$pb/libalpm.so.16" ]; then
	echo "no real libalpm at PACMAN_BUILD=$pb" >&2
	exit 1
fi

# puck's cdylib, exposed as libalpm.so + libalpm.so.16
cargo build -p alpm-capi --release --manifest-path "$root/Cargo.toml"
lib=$root/target/release/libalpm.so
rm -rf "$tmp" && mkdir -p "$tmp/lib" "$tmp/fix"
ln -sf "$lib" "$tmp/lib/libalpm.so"
ln -sf "$lib" "$tmp/lib/libalpm.so.16"
python3 -I "$here/mkfixture.py" "$tmp/fix" >/dev/null
fixroot=$tmp/fix/root fixdb=$tmp/fix/db

# ---- alpm.rs (required) ------------------------------------------------
cat > "$tmp/libalpm.pc" <<EOF
libdir=$tmp/lib
includedir=$hdr
Name: libalpm
Description: puck libalpm C ABI shim
Version: 16.0.1
Libs: -L\${libdir} -lalpm
Cflags: -I\${includedir}
EOF

echo "== alpm.rs (alpm-sys, pkgconf) =="
( cd "$here/alpmrs" && PKG_CONFIG_PATH=$tmp cargo build --quiet )
probe=$here/alpmrs/target/debug/alpmrs-probe
LD_LIBRARY_PATH=$pb "$probe" "$fixroot" "$fixdb" > "$tmp/rs_real.txt" 2>&1
LD_LIBRARY_PATH=$tmp/lib "$probe" "$fixroot" "$fixdb" > "$tmp/rs_puck.txt" 2>&1
if diff -u "$tmp/rs_real.txt" "$tmp/rs_puck.txt"; then
	echo "alpm.rs: IDENTICAL (puck == real)"
else
	echo "alpm.rs: DIVERGED" >&2
	rc=1
fi

# ---- go-alpm (optional reference) --------------------------------------
echo "== go-alpm (cgo, optional) =="
if command -v go >/dev/null; then
	if ( cd "$here/goalpm" \
		&& CGO_CFLAGS="-I$hdr -D_FILE_OFFSET_BITS=64" \
		   CGO_LDFLAGS="-L$tmp/lib -lalpm" GOFLAGS=-mod=mod \
		   go build -o "$tmp/goprobe" . ); then
		LD_LIBRARY_PATH=$pb "$tmp/goprobe" "$fixroot" "$fixdb" \
			> "$tmp/go_real.txt" 2>/dev/null
		LD_LIBRARY_PATH=$tmp/lib "$tmp/goprobe" "$fixroot" "$fixdb" \
			> "$tmp/go_puck.txt" 2>/dev/null
		echo "-- go-alpm diff (real vs puck); sync-db line differs: a"
		echo "-- go-alpm bug (garbage handle->dbpath) hits the real lib too"
		diff -u "$tmp/go_real.txt" "$tmp/go_puck.txt" || true
	else
		echo "go-alpm: build skipped (toolchain/cgo)"
	fi
else
	echo "go-alpm: skipped (no go toolchain)"
fi

rm -rf "$tmp"
exit "$rc"
