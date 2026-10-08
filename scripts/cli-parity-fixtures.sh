#!/usr/bin/env bash
# milestone 1 gate: C pacman vs the Rust binary on generated fixture roots
# (difftest/tests/cli_binary.rs), one line per command and world, then
# the equal count. fails on any difference outside the ones known()
# explains. pacman-conf (difftest/tests/pacman_conf.rs, generated config
# trees) and testpkg (difftest/tests/testpkg.rs, generated and signed
# packages) against their C binaries the same way, then upstream's
# scripts against both pacman-conf (scripts/pacman-conf-dropin.sh)
# usage: scripts/cli-parity-fixtures.sh   (from the repo root)
set -e
cargo build --release -p pacman-cli --bin puck --bin puck-conf
cargo build --release -p testpkg --bin testpkg
# through the machine-wide test lock, like every test run
scripts/cargo-test.sh -p difftest --test cli_binary --test pacman_conf \
	--test testpkg -- --nocapture --test-threads=1
scripts/pacman-conf-dropin.sh
