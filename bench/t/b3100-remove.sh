#!/usr/bin/env bash

bench_description='remove from an installed root (fakechroot + fakeroot)'

. "$(dirname "$0")/../bench-lib.sh"
. "$BENCH_DIR/t/lib-root.sh"

root_op small cache -R $SMALL
root_op large cache -Rns python

bench_done
