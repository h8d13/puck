## Usage

```
bench/run.sh                          # C vs puck: time, RSS, same output
bench/t/b1000-query.sh -n 15 --run=2  # one script, one op, 15 runs
bench/run.sh --valgrind               # memcheck (puck)
bench/run.sh --valgrind=callgrind     # also massif, dhat, cachegrind
bench/run.sh --perf                   # perf stat; --perf=record for hotspots
bench/run.sh --strace
```

Profiling modes run puck only (`--side=c` for C) and list the top 5
functions or syscalls (`--top=N`). Raw files land in `results/`, `--help`
lists the rest. Ops live in `t/`.

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

## Downloads from a remote mirror

```
bench/dload-remote.sh -n 200 -r 2    # -Swdd of 200 small packages, C vs puck
```

Needs network, fakeroot and strace: wall time of each side into an
empty cache, then the same run under strace counting connects to the
mirror. Before connection reuse puck opened one TLS connection per file
(200 connects, 4.6 s); with it both sides open one per parallel stream
(5 connects, C 1.8 s, puck 2.0 s).
