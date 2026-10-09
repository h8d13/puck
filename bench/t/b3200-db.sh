#!/usr/bin/env bash

bench_description='local db, sync db and cache ops in a root (fakechroot + fakeroot)'

. "$(dirname "$0")/../bench-lib.sh"
. "$BENCH_DIR/t/lib-root.sh"

root_op large cache -D --asdeps python
root_op nosync mirror -Sy
root_op empty mirror -Sw python
root_op dlcache mirror -Sc

bench_done
