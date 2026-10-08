#!/usr/bin/env bash
# cargo test --release, one run at a time across the main checkout and all
# unit worktrees: parallel suites (C-linked difftests, fuzz) exhaust memory.
# the per-process caps are test-runner.sh, set as runner in .cargo/config
# usage: scripts/cargo-test.sh [cargo test args...]

set -euo pipefail

# the main checkout owns the lock, worktrees share its git common dir
common=$(git rev-parse --path-format=absolute --git-common-dir)
lock="$(dirname "$common")/.tmp/cargo-test.lock"
mkdir -p "$(dirname "$lock")"

exec 9> "$lock"
if ! flock -n 9; then
	echo "waiting for another cargo test run ($lock)" >&2
	flock 9
fi
cargo test --release "$@"
