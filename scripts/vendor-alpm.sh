#!/usr/bin/env bash
# vendor/alpm = pristine ALPM submodule (alpm/) + our patch series
# usage: scripts/vendor-alpm.sh             regenerate vendor/alpm
#        scripts/vendor-alpm.sh --check     verify vendor/alpm is up to date
#        scripts/vendor-alpm.sh --diff NAME write edits made in vendor/alpm
#                                           as vendor/patches/NAME.patch
#
# patches live in vendor/patches/NNNN-<crate>-<what>.patch, applied in name
# order with `patch -p1` inside the vendored tree. one patch per corrected
# divergence from pacman (METHODOLOGY.md), written so it can go upstream.

set -euo pipefail

crates=(
	alpm-types alpm-parsers alpm-common
	alpm-db alpm-repo-db
	alpm-compress
)

if [ ! -f Cargo.toml ] || [ ! -f alpm/Cargo.toml ]; then
	echo "run from the repo root with the alpm submodule checked out" >&2
	exit 2
fi

mode=${1:-}
name=${2:-}
if [ "$mode" = "--diff" ] && [ -z "$name" ]; then
	echo "usage: $0 --diff NNNN-crate-what" >&2
	exit 2
fi

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
tree="$out/alpm"
mkdir "$tree"

for c in "${crates[@]}"; do
	cp -r "alpm/$c" "$tree/$c"
done
cp -r alpm/LICENSES "$tree/LICENSES"

# their workspace manifest with members cut down to what we vendor
members=$(printf '    "%s",\n' "${crates[@]}")
awk -v members="$members" '
	/^members = \[/ { print; print members; skip = 1; next }
	skip && /^\]/ { skip = 0 }
	!skip { print }
' alpm/Cargo.toml > "$tree/Cargo.toml"

for p in vendor/patches/*.patch; do
	[ -e "$p" ] || continue
	if ! patch -s -E -p1 -d "$tree" --no-backup-if-mismatch < "$p"; then
		echo "patch failed: $p" >&2
		exit 1
	fi
done

rev=$(git -C alpm rev-parse HEAD)
printf 'alpm submodule %s + vendor/patches\n' "$rev" > "$tree/VENDORED"

case "$mode" in
--check)
	if diff -r "$tree" vendor/alpm; then
		echo "vendor/alpm up to date"
		exit 0
	fi
	echo "vendor/alpm differs from alpm/ + vendor/patches" >&2
	exit 1 ;;
--diff)
	dst="vendor/patches/$name.patch"
	if [ -e "$dst" ]; then
		echo "$dst exists" >&2
		exit 1
	fi
	# a/ = expected tree, b/ = edited vendor/alpm, -p1 relative paths
	ln -s "$(pwd)/vendor/alpm" "$out/b"
	mv "$tree" "$out/a"
	# diff exits 1 when trees differ, that is the expected case here
	(cd "$out" && diff -ruN --exclude=VENDORED a b) > "$out/raw" || true
	# drop header timestamps so regenerated patches stay byte-stable
	sed -E 's/^((---|\+\+\+) [^\t]+)\t.*/\1/' "$out/raw" > "$dst"
	if [ ! -s "$dst" ]; then
		rm "$dst"
		echo "no edits in vendor/alpm" >&2
		exit 1
	fi
	echo "wrote $dst"
	exit 0 ;;
esac

rm -rf vendor/alpm
mkdir -p vendor
cp -r "$tree" vendor/alpm
n=$(find vendor/patches -name '*.patch' | wc -l)
echo "vendor/alpm regenerated: ${#crates[@]} crates, $n patches"
