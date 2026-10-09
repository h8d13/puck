#!/usr/bin/env bash

bench_description='read-only ops on the local db'

. "$(dirname "$0")/../bench-lib.sh"

bench_op -Q
bench_op -Qi
bench_op -Qs lib
bench_op -Qo /usr/bin/bash
bench_op -Qk
bench_op -Qkk pacman glibc bash
bench_op -T bash 'glibc>=2' nope

bench_done
