#!/usr/bin/env bash
# git worktree for one port unit: ../ratman-worktrees/<name>, branch unit/<name>
# usage: scripts/unit-worktree.sh <name>...          create (tree must be clean)
#        scripts/unit-worktree.sh --from REF <name>... create from REF
#        scripts/unit-worktree.sh --remove <name>... remove after merging
#
# the unit works and commits on its branch; merge back with `git merge`.
# submodules are cloned --shared from this checkout (no network, no object
# copies), the C reference build is shared through PACMAN_BUILD, and
# .cargo/config.toml points TMPDIR inside the worktree: nothing in /tmp.

set -euo pipefail

if [ ! -f Cargo.toml ] || [ ! -d pacman/build ]; then
	echo "run from the repo root, with pacman/build built" >&2
	exit 2
fi
root=$(pwd)
base="$(dirname "$root")/ratman-worktrees"

remove() {
	local name=$1 wt="$base/$1"
	git worktree remove --force "$wt"
	git branch -D "unit/$name"
}

create() {
	local name=$1 wt="$base/$1" sub sha
	if [ -e "$wt" ]; then
		echo "$wt exists" >&2
		exit 1
	fi
	git worktree add -q -b "unit/$name" "$wt" "$from"
	for sub in pacman alpm; do
		sha=$(git rev-parse "$from:$sub")
		git clone -q --shared --no-checkout "$root/$sub" "$wt/$sub"
		git -C "$wt/$sub" checkout -q "$sha"
	done
	mkdir -p "$wt/.cargo" "$wt/.tmp"
	cat > "$wt/.cargo/config.toml" <<-EOF
		# unit worktree, not committed (see .gitignore)
		[env]
		PACMAN_BUILD = "$root/pacman/build"
		TMPDIR = "$wt/.tmp"
	EOF
	echo "$wt (branch unit/$name from $from)"
}

from=HEAD
if [ "${1:-}" = "--from" ]; then
	from=$2
	shift 2
fi

if [ "${1:-}" = "--remove" ]; then
	shift
	for name in "$@"; do
		remove "$name"
	done
	exit 0
fi

if [ "$#" = 0 ]; then
	echo "usage: $0 <name>... | --remove <name>..." >&2
	exit 2
fi
if [ -n "$(git status --porcelain)" ]; then
	echo "working tree not clean: commit first" >&2
	exit 1
fi
mkdir -p "$base"
for name in "$@"; do
	create "$name"
done
