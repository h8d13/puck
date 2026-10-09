#!/usr/bin/env bash

bench_description='read-only ops on the sync dbs'

. "$(dirname "$0")/../bench-lib.sh"

bench_lazy_prereq SYNCDB 'ls /var/lib/pacman/sync/*.db'

bench_op SYNCDB -Qu
bench_op SYNCDB -Dk
bench_op SYNCDB -Ss python
bench_op SYNCDB -Si linux
# puck follows upstream master past bdedf621 (md5sum dropped from repo
# dbs): C pacman still prints "MD5 Sum" for old entries with %MD5SUM%
bench_expect_diff SYNCDB -Si
bench_op SYNCDB -Sl

bench_done
