#!/usr/bin/env bash
# private workspace copy for one port agent: /tmp/ratman-<name>
# usage: scripts/agent-copy.sh <name>...   (from the repo root)
#
# copies the working tree (uncommitted merges included) without target/,
# .git and the submodules; pacman/ and alpm/ become symlinks to this tree,
# so the C reference build and ALPM are shared read-only

set -euo pipefail

if [ ! -f Cargo.toml ] || [ ! -d pacman/build ]; then
	echo "run from the repo root, with pacman/build built" >&2
	exit 2
fi
if [ "$#" = 0 ]; then
	echo "usage: $0 <name>..." >&2
	exit 2
fi

src=$(pwd)
for name in "$@"; do
	dst="/tmp/ratman-$name"
	if [ -e "$dst" ]; then
		echo "$dst exists, remove it first" >&2
		exit 1
	fi
	mkdir "$dst"
	tar -C "$src" --exclude=./target --exclude=./.git \
		--exclude=./pacman --exclude=./alpm -cf - . | tar -C "$dst" -xf -
	ln -s "$src/pacman" "$dst/pacman"
	ln -s "$src/alpm" "$dst/alpm"
	echo "$dst"
done
