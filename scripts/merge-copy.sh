#!/usr/bin/env bash
# 3-way merge files from an old plain-copy unit (pre-worktree) into this tree
# usage: scripts/merge-copy.sh BASE_COMMIT COPY_DIR file...
#
# base = file at BASE_COMMIT (what the copy started from), theirs = the
# copy's file, ours = this tree. new files are copied. conflicts are left
# marked in the file and reported; exit 1 if any.

set -euo pipefail

base=$1 copy=$2
shift 2
tmp=$(mktemp -d "${TMPDIR:-.}/merge-copy.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

fail=0
for f in "$@"; do
	if [ ! -e "$copy/$f" ]; then
		echo "missing in copy: $f" >&2
		fail=1
		continue
	fi
	if ! git cat-file -e "$base:$f" 2>&1; then
		# new in the copy
		mkdir -p "$(dirname "$f")"
		cp "$copy/$f" "$f"
		echo "new: $f"
		continue
	fi
	git show "$base:$f" > "$tmp/base"
	if [ ! -e "$f" ]; then
		echo "deleted here, changed in copy: $f" >&2
		fail=1
		continue
	fi
	if git merge-file -L ours -L base -L theirs "$f" "$tmp/base" "$copy/$f"; then
		echo "merged: $f"
	else
		echo "CONFLICT: $f" >&2
		fail=1
	fi
done
exit "$fail"
