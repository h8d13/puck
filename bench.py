#!/usr/bin/env python3
# C pacman against puck on this host's real config and dbs: read-only ops
# as the user, alternating runs after one warmup each, median wall time
# and peak RSS (wait4). stdout and stderr are compared per op, so a fast
# wrong answer shows as DIFF.
#
# usage: ./bench.py [-n RUNS] [-c C_PACMAN] [-p PUCK] [-- OP ...]
#   PUCK defaults to target/release/puck (cargo build --release -p
#   pacman-cli), C_PACMAN to /usr/bin/pacman (the distro's optimized
#   build; pacman/build is a debug build). OPs after -- replace the
#   default set, each one shell-split: ./bench.py -- "-Si linux" -Qi
#
# both run with argv[0] "pacman" so usage and messages compare; run on a
# quiet machine, other load moves the medians. peak RSS comes from a tiny
# C launcher (built with cc into the temp dir): wait4's maxrss includes
# the forking parent's memory from before exec, ~11 MB for this python

import argparse
import os
import shlex
import statistics
import subprocess
import tempfile

DEFAULT_OPS = [
	"-Q",
	"-Qi",
	"-Qs lib",
	"-Qo /usr/bin/bash",
	"-Qu",
	"-Qk",
	"-Qkk pacman glibc bash",
	"-Dk",
	"-Ss python",
	"-Si linux",
	"-Si",
	"-Sl",
	"-T bash glibc>=2 nope",
]


# launcher: fork, exec argv[2..] with argv[0] "pacman" and stdout/stderr
# to argv[1].out/.err, then print "<status> <maxrss KiB> <wall ns>"
LAUNCHER = r'''
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
int main(int argc, char **argv)
{
	char out[4096], err[4096];
	struct timespec a, b;
	struct rusage ru;
	int st;
	snprintf(out, sizeof out, "%s.out", argv[1]);
	snprintf(err, sizeof err, "%s.err", argv[1]);
	clock_gettime(CLOCK_MONOTONIC, &a);
	pid_t pid = fork();
	if(pid == 0) {
		dup2(open(out, O_WRONLY | O_CREAT | O_TRUNC, 0600), 1);
		dup2(open(err, O_WRONLY | O_CREAT | O_TRUNC, 0600), 2);
		char *bin = argv[2];
		argv[2] = "pacman";
		execv(bin, argv + 2);
		_exit(127);
	}
	wait4(pid, &st, 0, &ru);
	clock_gettime(CLOCK_MONOTONIC, &b);
	printf("%d %ld %lld\n", st, ru.ru_maxrss,
		(b.tv_sec - a.tv_sec) * 1000000000LL + (b.tv_nsec - a.tv_nsec));
	return 0;
}
'''


def build_launcher(tmp):
	src, exe = os.path.join(tmp, "launch.c"), os.path.join(tmp, "launch")
	with open(src, "w") as f:
		f.write(LAUNCHER)
	subprocess.run(["cc", "-O2", "-o", exe, src], check=True)
	return exe


# one run: wall seconds, peak RSS KiB, exit status, stdout, stderr
def run(launcher, binary, args, tmp):
	base = os.path.join(tmp, "run")
	env = dict(os.environ, COLUMNS="80")
	r = subprocess.run([launcher, base, binary, *args], env=env,
		capture_output=True, check=True)
	st, rss, ns = (int(x) for x in r.stdout.split())
	data = []
	for ext in ("out", "err"):
		with open(f"{base}.{ext}", "rb") as f:
			data.append(f.read())
	return ns / 1e9, rss, st, data


def fmt_time(s):
	return f"{s * 1000:8.1f} ms" if s < 10 else f"{s:8.2f} s "


def main():
	ap = argparse.ArgumentParser(
		description="C pacman vs puck: time, peak RSS, same output")
	ap.add_argument("-p", "--puck", default="target/release/puck")
	ap.add_argument("-c", "--c-pacman", default="/usr/bin/pacman")
	ap.add_argument("-n", "--runs", type=int, default=7)
	ap.add_argument("ops", nargs="*")
	a = ap.parse_args()
	for b in (a.puck, a.c_pacman):
		if not os.access(b, os.X_OK):
			ap.error(f"{b} is not executable")
	ops = a.ops or DEFAULT_OPS

	print(f"{'op':28} {'C time':>11} {'C RSS':>9} {'puck time':>11} "
		f"{'puck RSS':>9} {'time':>6} {'RSS':>6} out")
	with tempfile.TemporaryDirectory() as tmp:
		launcher = build_launcher(tmp)
		for op in ops:
			args = shlex.split(op)
			run(launcher, a.c_pacman, args, tmp)
			run(launcher, a.puck, args, tmp)
			ct, cm, rt, rm = [], [], [], []
			same = True
			for _ in range(a.runs):
				w, m, cs, co = run(launcher, a.c_pacman, args, tmp)
				ct.append(w)
				cm.append(m)
				w, m, rs, ro = run(launcher, a.puck, args, tmp)
				rt.append(w)
				rm.append(m)
				same &= cs == rs and co == ro
			c, r = statistics.median(ct), statistics.median(rt)
			cr, rr = statistics.median(cm), statistics.median(rm)
			print(f"{op:28} {fmt_time(c)} {cr / 1024:6.1f} MB "
				f"{fmt_time(r)} {rr / 1024:6.1f} MB {r / c:5.2f}x "
				f"{rr / cr:5.2f}x {'same' if same else 'DIFF'}",
				flush=True)


if __name__ == "__main__":
	main()
