## Harness

`t/bNNNN-*.sh` are git `t/`-style scripts: each sources `bench-lib.sh`,
declares ops and prints TAP. Ops run as argv[0] `pacman` from a trash dir.
Pure bash; needs GNU `time`, plus `valgrind`, `perf` or `strace` for the
modes that use them.

- time mode (the default) compares C pacman and puck: median wall time,
  peak RSS, and whether rc, stdout and stderr match
- profiling modes look at puck alone (`--side=c` profiles the C reference
  instead): one headline number per op and its top functions or syscalls
  (`--top=N`)

```
bench/run.sh                          # every script, time mode
bench/t/b1000-query.sh -n 15          # one script, 15 runs per side
bench/t/b1000-query.sh --run=2,5-6 -v # some ops, show commands and runs
bench/t/b2000-sync.sh --valgrind      # memcheck: errors or definite leaks fail
bench/run.sh --valgrind=callgrind     # Ir counts (deterministic), top functions
bench/run.sh --valgrind=massif        # also dhat, cachegrind
bench/run.sh --perf -n 10             # perf stat, user-space counters
bench/run.sh --perf=record --top=10
bench/run.sh --strace
prove bench/t/b*.sh :: --perf         # same, through prove
```

`--help` on any script lists every option. Each tool's files stay in
`results/<script>/<op>/<side>.*`, for example `callgrind_annotate
results/b1000-query/2/puck.callgrind` or `perf report -i
results/b1000-query/2/puck.perf.data`. `results/<script>.tsv` has one
line per op and side. For symbols with source lines in perf and callgrind,
build with `CARGO_PROFILE_RELEASE_DEBUG=line-tables-only`.

Numbering: `b1xxx` local db reads, `b2xxx` sync db reads, `b3xxx` for
root-changing ops (a script redefines `bench_reset SIDE` to restore its
root before every run, untimed). `bench_expect_diff` marks an op whose
output is known to differ (`not ok ... # TODO`), like `test_expect_failure`.

## Read-only ops

```
op                                C time     C RSS   puck time  puck RSS   time    RSS out
-Q                               64.4 ms   19.2 MB     33.5 ms    7.6 MB  0.52x  0.40x same
-Qi                             127.6 ms   21.1 MB     94.7 ms    7.8 MB  0.74x  0.37x same
-Qs lib                          67.6 ms   21.1 MB     24.8 ms    7.7 MB  0.37x  0.36x same
-Qo /usr/bin/bash                71.8 ms   20.7 MB     39.1 ms    7.6 MB  0.54x  0.37x same
-Qu                             135.1 ms   63.0 MB    112.2 ms   58.3 MB  0.83x  0.93x same
-Qk                             220.2 ms   54.6 MB    222.6 ms   47.9 MB  1.01x  0.88x same
-Qkk pacman glibc bash           61.3 ms   21.2 MB     46.5 ms    8.2 MB  0.76x  0.38x same
-Dk                             105.8 ms   66.8 MB     94.0 ms   63.9 MB  0.89x  0.96x same
-Ss python                      146.2 ms   63.0 MB    118.1 ms   58.1 MB  0.81x  0.92x same
-Si linux                       136.3 ms   62.4 MB    110.8 ms   57.3 MB  0.81x  0.92x same
-Si                             319.9 ms   62.3 MB    281.5 ms   57.4 MB  0.88x  0.92x DIFF
-Sl                             140.1 ms   62.9 MB    113.9 ms   58.0 MB  0.81x  0.92x same
-T bash glibc>=2 nope            68.9 ms   21.0 MB     35.3 ms    7.7 MB  0.51x  0.37x same
```


`-Si` DIFF is expected: puck follows upstream master past `bdedf621` (md5sum dropped from repo dbs), which no pacman release or Arch snapshot ships yet, so C pacman still prints `MD5 Sum` under `Validated By` for old db entries that carry `%MD5SUM%`.
