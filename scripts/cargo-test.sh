#!/usr/bin/env bash
# cargo test --release, at most CARGO_TEST_SLOTS runs (default 3) at a time
# across the main checkout and all unit worktrees. cargo runs one test
# binary at a time and test-runner.sh caps each at 4 GiB, so 3 slots stay
# within RAM; one slot left 12 cores idle while units queued for hours.
# usage: scripts/cargo-test.sh [cargo test args...]

set -euo pipefail

# the main checkout owns the slots, worktrees share its git common dir
common=$(git rev-parse --path-format=absolute --git-common-dir)
dir="$(dirname "$common")/.tmp"
slots=${CARGO_TEST_SLOTS:-3}
mkdir -p "$dir"

# take the first free slot, poll until one is. slot 0 is the old
# single lock, so units on an older copy of this script still count
waited=0
while :; do
	for ((i = 0; i < slots; i++)); do
		lock=$dir/cargo-test.lock
		[ "$i" = 0 ] || lock=$lock.$i
		exec 9> "$lock"
		if flock -n 9; then
			break 2
		fi
		exec 9>&-
	done
	if [ "$waited" = 0 ]; then
		echo "waiting for a cargo test slot ($slots busy)" >&2
		waited=1
	fi
	sleep 5
done
cargo test --release "$@"
