#!/usr/bin/env python3
# C pacman against puck on this host's real config and dbs: read-only ops
# as the user, alternating runs after one warmup each, median wall time
# and peak RSS (wait4). stdout and stderr are compared per op, so a fast
# wrong answer shows as DIFF.
#
# usage: ./bench.py [-n RUNS] [-c C_PACMAN] [PUCK] [-- OP ...]
#   PUCK defaults to target/release/puck (cargo build --release -p
#   pacman-cli), C_PACMAN to /usr/bin/pacman (the distro's optimized
#   build; pacman/build is a debug build). OPs after -- replace the
#   default set, each one shell-split: ./bench.py -- "-Si linux" -Qi
#
# both run with argv[0] "pacman" so usage and messages compare; run on a
# quiet machine, other load moves the medians

import argparse
import os
import shlex
import statistics
import tempfile
import time

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


# one run: wall seconds, peak RSS KiB, exit status, stdout, stderr
def run(binary, args, tmp):
	paths = [os.path.join(tmp, "out"), os.path.join(tmp, "err")]
	fds = [os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
		for p in paths]
	t = time.perf_counter()
	pid = os.fork()
	if pid == 0:
		os.dup2(fds[0], 1)
		os.dup2(fds[1], 2)
		env = dict(os.environ, COLUMNS="80")
		os.execve(binary, ["pacman", *args], env)
	_, status, ru = os.wait4(pid, 0)
	wall = time.perf_counter() - t
	data = []
	for fd, p in zip(fds, paths):
		os.close(fd)
		with open(p, "rb") as f:
			data.append(f.read())
	return wall, ru.ru_maxrss, os.waitstatus_to_exitcode(status), data


def fmt_time(s):
	return f"{s * 1000:8.1f} ms" if s < 10 else f"{s:8.2f} s "


def main():
	ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
	ap.add_argument("puck", nargs="?", default="target/release/puck")
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
		for op in ops:
			args = shlex.split(op)
			run(a.c_pacman, args, tmp)
			run(a.puck, args, tmp)
			ct, cm, rt, rm = [], [], [], []
			same = True
			for _ in range(a.runs):
				w, m, cs, co = run(a.c_pacman, args, tmp)
				ct.append(w)
				cm.append(m)
				w, m, rs, ro = run(a.puck, args, tmp)
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
