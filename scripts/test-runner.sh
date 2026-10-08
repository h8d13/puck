#!/usr/bin/env bash
# cargo runner for test binaries (set by cargo-test.sh): caps each test
# process's address space and wall time. with large swap and no oomd a
# runaway loop (mutation check, resolver bug) never meets the OOM killer
# and swaps the machine to a halt; capped, it fails its test instead.
# TEST_MEM_KB, TEST_TIMEOUT (seconds) override the defaults.

set -euo pipefail
ulimit -v "${TEST_MEM_KB:-4194304}"
exec timeout "${TEST_TIMEOUT:-1800}" "$@"
