#!/usr/bin/env bash

bench_description='install into a fresh root (fakechroot + fakeroot)'

. "$(dirname "$0")/../bench-lib.sh"
. "$BENCH_DIR/t/lib-root.sh"

root_op empty cache -S $SMALL
bench_label='-S large'
root_op empty cache -S $LARGE
bench_label='-S --dbonly large'
root_op empty cache -S --dbonly $LARGE
bench_label='-S python (reinstall)'
root_op large cache -S python
bench_label="-U $SMALL (files)"
mapfile -t files < <(root_small_files)
root_op empty cache -U "${files[@]}"

bench_done
