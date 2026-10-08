#!/usr/bin/env bash
# milestone 1 gate: C pacman vs the Rust binary on generated fixture roots
# (difftest/tests/cli_binary.rs), one line per command and world, then
# the equal count. fails on any difference outside the known unported
# operations
# usage: scripts/cli-parity-fixtures.sh   (from the repo root)
set -e
cargo build --release -p pacman-cli --bin pacman
cargo test --release -p difftest --test cli_binary -- --nocapture
