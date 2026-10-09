## Usage

```
bench/run.sh                          # C vs puck: time, RSS, same output
prove bench/t/b*.sh :: -n 3           # same, prove's tally
bench/t/b1000-query.sh -n 15 --run=2  # one script, one op, 15 runs
bench/t/b3000-install.sh --run=1 -d   # a root op, trash dir kept
bench/run.sh --valgrind               # memcheck (puck)
bench/run.sh --valgrind=callgrind     # also massif, dhat, cachegrind
bench/run.sh --perf                   # perf stat; --perf=record for hotspots
bench/run.sh --strace                 # both sides with --side=both
```

Profiling modes run puck only (`--side=c` for C) and list the top 5
functions or syscalls (`--top=N`). Raw files land in `results/`, `--help`
lists the rest. Ops live in `t/`: `b1000`, `b2000` read the host's dbs
as the user; `b3000`-`b3200` change a root under fakechroot + fakeroot
(`t/lib-root.sh`: states made once with C pacman from the host's cache
and sync dbs, a fresh copy per run, no real root, no network). Every
run's rc, stdout, stderr and state (tree under faked ids, local db, log)
are compared, "not ok" when they differ. Time and peak RSS come from
`launch.c` (wait4's rusage), so the fakeroot wrappers count on both
sides alike. Adding an op: METHODOLOGY.md "Benchmarks".

## Numbers

puck from 7b42a16 against pacman 7.1.0, 7 runs, median. The host was
shared with other units' builds while this ran (load 6-8): absolute
times are high and noisier than usual, the ratios less so.

Read-only ops (`b1000-query`, `b2000-sync`):

```
op                           C time    C RSS    puck time  puck RSS   time    RSS out
-Q                          38.8 ms  19.5 MB      18.5 ms    7.9 MB  0.47x  0.40x same
-Qi                        177.4 ms  20.6 MB     155.0 ms    7.9 MB  0.87x  0.38x same
-Qs lib                     54.9 ms  20.8 MB      31.7 ms    7.9 MB  0.57x  0.37x same
-Qo /usr/bin/bash           38.3 ms  20.3 MB      18.5 ms    8.0 MB  0.48x  0.39x same
-Qk                        285.7 ms  35.2 MB     263.1 ms   24.9 MB  0.92x  0.70x same
-Qkk pacman glibc bash     134.7 ms  21.4 MB     102.3 ms    7.9 MB  0.75x  0.37x same
-T bash glibc>=2 nope       53.1 ms  20.5 MB      33.5 ms    7.9 MB  0.63x  0.38x same
-Qu                        274.0 ms  62.2 MB     235.0 ms   55.9 MB  0.85x  0.90x same
-Dk                        203.1 ms  41.1 MB     163.8 ms   33.4 MB  0.80x  0.81x same
-Ss python                 412.5 ms  62.7 MB     280.6 ms   56.0 MB  0.68x  0.89x same
-Si linux                  365.0 ms  61.9 MB     289.8 ms   55.6 MB  0.79x  0.89x same
-Si                        830.4 ms  61.9 MB     868.9 ms   55.7 MB  1.04x  0.89x DIFF
-Sl                        271.6 ms  62.3 MB     222.9 ms   55.9 MB  0.82x  0.89x same
```

Root-changing ops (`b3000-install`, `b3100-remove`, `b3200-db`), small
= less (14 pkgs), large = bash coreutils grep sed gawk findutils less
python (54 pkgs), every tree, db and log equal:

```
op                           C time    C RSS    puck time  puck RSS   time    RSS out
-S less                    7237.4 ms  97.1 MB    5694.1 ms   85.0 MB  0.78x  0.87x same
-S large                     12.57 s  98.9 MB    9736.6 ms   89.2 MB  0.77x  0.90x same
-S --dbonly large          1454.1 ms  98.9 MB    1481.7 ms   88.9 MB  1.01x  0.89x same
-S python (reinstall)      2233.0 ms  55.1 MB    2181.0 ms   42.8 MB  0.97x  0.77x same
-U less (files)            5575.2 ms  54.5 MB    4784.8 ms   43.3 MB  0.85x  0.79x same
-R less                     263.1 ms  19.5 MB     258.1 ms    6.3 MB  0.98x  0.32x same
-Rns python                 525.8 ms  21.0 MB     498.0 ms    8.2 MB  0.94x  0.39x same
-D --asdeps python          154.0 ms  19.1 MB     143.7 ms    5.8 MB  0.93x  0.30x same
-Sy                         180.4 ms  19.1 MB     190.5 ms    7.8 MB  1.05x  0.40x same
-Sw python                  554.9 ms  61.5 MB     547.5 ms   55.3 MB  0.98x  0.89x same
-Sc                         180.0 ms  21.2 MB     186.3 ms    8.0 MB  1.03x  0.37x same
```

`-S large` against `-S --dbonly large` is where install time goes:
extraction, scriptlets, hooks and ldconfig under fakechroot. `-Si` DIFF is expected: puck follows upstream
master past `bdedf621` (md5sum dropped from repo dbs), which no pacman
release or Arch snapshot ships yet, so C pacman still prints `MD5 Sum`
under `Validated By` for old db entries that carry `%MD5SUM%`.
