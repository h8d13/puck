#!/usr/bin/env python3
# C pacman against puck on operations that change a root: -S, -U, -R,
# --dbonly, -D, -Sy, -Sw, -Sc, run like pactest under fakechroot +
# fakeroot (no real root) with real packages from this host's cache and
# its core/extra sync dbs.
#
# usage: ./bench_trans.py [-n RUNS] [-c C_PACMAN] [-p PUCK] [-k] [OP ...]
#   PUCK defaults to target/release/puck, C_PACMAN to /usr/bin/pacman.
#   OP names pick from the table printed with -l; -k keeps the work dir.
#
# per op: median wall time, user and sys CPU, peak RSS (bench.py's C
# launcher; fakechroot/fakeroot are the same on both sides), syscalls
# from one `strace -f -c` pass each, and whether both sides left the
# same tree (types, modes, sizes, contents, links), local db (install
# dates masked), log (stamps cut), stdout and stderr. every run starts
# from a fresh copy of its state; copying is not timed.
#
# SigLevel Never and DisableSandbox on both sides: signatures need the
# host's root-only keyring, and the C sandbox does not start as non-root
# under fakeroot (UPSTREAM.md). scriptlets and hooks run in the root.

import argparse
import hashlib
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile

import bench

HOST_CACHE = "/var/cache/pacman/pkg"
HOST_SYNC = "/var/lib/pacman/sync"
REPOS = ("core", "extra")
SMALL = ["less"]
LARGE = ["bash", "coreutils", "grep", "sed", "gawk", "findutils", "less",
	"python"]

# name: (start state, argv after the common options, conf)
OPS = {
	"install-small": ("empty", ["-S", "--noconfirm", *SMALL], "cache"),
	"install-large": ("empty", ["-S", "--noconfirm", *LARGE], "cache"),
	"dbonly-large": ("empty", ["-S", "--noconfirm", "--dbonly", *LARGE],
		"cache"),
	"reinstall": ("large", ["-S", "--noconfirm", "python"], "cache"),
	"upgrade-files": ("empty", ["-U", "--noconfirm", "@SMALLFILES"],
		"cache"),
	"remove-small": ("small", ["-R", "--noconfirm", *SMALL], "cache"),
	"remove-recursive": ("large", ["-Rns", "--noconfirm", "python"],
		"cache"),
	"asdeps": ("large", ["-D", "--asdeps", "python"], "cache"),
	"refresh": ("nosync", ["-Sy"], "mirror"),
	"download": ("empty", ["-Sw", "--noconfirm", "python"], "mirror"),
	"clean": ("dlcache", ["-Sc", "--noconfirm"], "mirror"),
}


def sh(*args, **kw):
	return subprocess.run(args, check=True, **kw)


def rmtree(path):
	if os.path.lexists(path):
		# roots hold read-only dirs from packages
		sh("chmod", "-R", "u+rwX", path)
		shutil.rmtree(path)


# the files of a set's closure as an empty root would resolve it, from
# the host's sync dbs; (repo, filename)
def closure(work, names):
	d = os.path.join(work, "resolve")
	os.makedirs(os.path.join(d, "sync"), exist_ok=True)
	os.makedirs(os.path.join(d, "local"), exist_ok=True)
	for r in REPOS:
		shutil.copy(f"{HOST_SYNC}/{r}.db", f"{d}/sync/{r}.db")
	with open(f"{d}/local/ALPM_DB_VERSION", "w") as f:
		f.write("9\n")
	conf = os.path.join(d, "pacman.conf")
	with open(conf, "w") as f:
		f.write("[options]\nSigLevel = Never\n")
		for r in REPOS:
			f.write(f"[{r}]\nServer = file:///nonexistent\n")
	out = sh(bench_c, "-Sp", "--config", conf, "--dbpath", d,
		"--print-format", "%r %f", *names, capture_output=True,
		text=True).stdout
	return [tuple(l.split()) for l in out.splitlines() if l.strip()]


def write_conf(path, root, mirror, host_cache):
	with open(path, "w") as f:
		f.write("[options]\nSigLevel = Never\n")
		f.write("LocalFileSigLevel = Never\nDisableSandbox\n")
		f.write(f"CacheDir = {root}/cache/\n")
		if host_cache:
			f.write(f"CacheDir = {HOST_CACHE}/\n")
		for r in REPOS:
			f.write(f"[{r}]\nServer = file://{mirror}/{r}\n")


# a side's command line in root, with argv[0] pacman. fakeroot saves its
# faked modes and owners next to the root, the manifest reads them back:
# what lands on disk under fakeroot depends on which libc calls a side
# makes (chmod, fchmod, fchmodat, O_PATH), the faked view does not
def argv_for(binary, root, conf, args):
	common = ["--root", root, "--dbpath", f"{root}/db", "--config",
		conf, "--logfile", f"{root}/pacman.log"]
	return ["fakechroot", "fakeroot", "-s", f"{root}.faked", "bash",
		"-c", 'exec -a pacman "$0" "$@"', binary, *common, *args]


def fresh_root(work, state, name):
	root = os.path.join(work, name)
	rmtree(root)
	if os.path.exists(f"{root}.faked"):
		os.remove(f"{root}.faked")
	sh("cp", "-a", os.path.join(work, "states", state), root)
	return root


# the side's own root path, so both sides compare
def unroot(data, root):
	return data.replace(root.encode(), b"ROOT")


# what is compared of a finished root: tree, local db, log. the per-side
# pacman.conf is the harness's
def manifest(root):
	out = []
	for dirpath, dirs, files in os.walk(root):
		dirs.sort()
		for n in sorted(dirs + files):
			p = os.path.join(dirpath, n)
			rel = os.path.relpath(p, root)
			if rel == "pacman.conf":
				continue
			st = os.lstat(p)
			kind = f"{oct(st.st_mode)} {st.st_uid}:{st.st_gid}"
			if os.path.islink(p):
				out.append((rel, kind, os.readlink(p)))
			elif os.path.isfile(p):
				with open(p, "rb") as f:
					data = f.read()
				if rel == "pacman.log":
					data = re.sub(rb"^\[[^]]*\] ", b"", data,
						flags=re.M)
					data = unroot(data, root)
				elif rel.endswith("/desc"):
					data = re.sub(rb"%INSTALLDATE%\n[0-9]+",
						b"%INSTALLDATE%\nX", data)
				out.append((rel, kind,
					hashlib.sha256(data).hexdigest()))
			else:
				out.append((rel, kind, ""))
	return out


# manifest() as fakeroot shows root: run under the saved faked state
def faked_manifest(root):
	r = sh("fakeroot", "-i", f"{root}.faked", sys.executable,
		os.path.abspath(__file__), "--manifest-of", root,
		capture_output=True, text=True)
	return [tuple(x.split("\t")) for x in r.stdout.splitlines()]


def strace_counts(work, binary, state, conf, args):
	root = fresh_root(work, state, "trace")
	log = os.path.join(work, "strace.txt")
	argv = argv_for(binary, root, conf_path(work, root, conf), args)
	subprocess.run(["strace", "-f", "-c", "-o", log, *argv],
		capture_output=True)
	calls, top = 0, []
	for l in open(log):
		p = l.split()
		if len(p) >= 5 and p[0][0].isdigit() and p[-1] != "total":
			n = int(p[3])
			top.append((n, p[-1]))
		if p and p[-1] == "total":
			calls = int(p[3])
	top.sort(reverse=True)
	return calls, top[:4]


def conf_path(work, root, kind):
	path = os.path.join(root, "pacman.conf")
	write_conf(path, root, os.path.join(work, "mirror"), kind == "cache")
	return path


def expand(args, work):
	out = []
	for a in args:
		if a == "@SMALLFILES":
			out += [f"{HOST_CACHE}/{f}" for _, f in small_files]
		else:
			out.append(a)
	return out


def setup(work, c_pacman):
	global small_files
	large = closure(work, LARGE)
	small_files = closure(work, SMALL)
	# mirror: the sync dbs and every closure file, linked from the cache
	for r in REPOS:
		d = os.path.join(work, "mirror", r)
		os.makedirs(d, exist_ok=True)
		shutil.copy(f"{HOST_SYNC}/{r}.db", f"{d}/{r}.db")
	for r, f in large + small_files:
		for name in (f, f + ".sig"):
			src = os.path.join(HOST_CACHE, name)
			dst = os.path.join(work, "mirror", r, name)
			if os.path.exists(src) and not os.path.lexists(dst):
				os.symlink(src, dst)
	states = os.path.join(work, "states")
	empty = os.path.join(states, "empty")
	for d in ("db/sync", "db/local", "cache"):
		os.makedirs(os.path.join(empty, d), exist_ok=True)
	for r in REPOS:
		shutil.copy(f"{HOST_SYNC}/{r}.db", f"{empty}/db/sync/{r}.db")
	with open(f"{empty}/db/local/ALPM_DB_VERSION", "w") as f:
		f.write("9\n")
	sh("cp", "-a", empty, os.path.join(states, "nosync"))
	shutil.rmtree(os.path.join(states, "nosync", "db", "sync"))
	os.makedirs(os.path.join(states, "nosync", "db", "sync"))
	# installed states made once with C pacman, untimed
	for name, names in (("small", SMALL), ("large", LARGE)):
		root = os.path.join(states, name)
		sh("cp", "-a", empty, root)
		conf = conf_path(work, root, "cache")
		sh(*argv_for(c_pacman, root, conf, ["-S", "--noconfirm",
			*names]), capture_output=True)
		os.remove(conf)
	root = os.path.join(states, "dlcache")
	sh("cp", "-a", os.path.join(states, "small"), root)
	conf = conf_path(work, root, "mirror")
	sh(*argv_for(c_pacman, root, conf, ["-Sw", "--noconfirm",
		*LARGE]), capture_output=True)
	os.remove(conf)
	return len(large), len(small_files)


def main():
	ap = argparse.ArgumentParser(
		description="C pacman vs puck on root-changing ops")
	ap.add_argument("-p", "--puck", default="target/release/puck")
	ap.add_argument("-c", "--c-pacman", default="/usr/bin/pacman")
	ap.add_argument("-n", "--runs", type=int, default=5)
	ap.add_argument("-k", "--keep", action="store_true")
	ap.add_argument("-l", "--list", action="store_true")
	ap.add_argument("--manifest-of", help=argparse.SUPPRESS)
	ap.add_argument("ops", nargs="*")
	a = ap.parse_args()
	if a.manifest_of:
		for e in manifest(a.manifest_of):
			print("\t".join(e))
		return
	if a.list:
		for k, (state, args, conf) in OPS.items():
			print(f"{k:18} from {state:7} {' '.join(args)} ({conf})")
		return
	global bench_c
	bench_c = a.c_pacman
	puck = os.path.abspath(a.puck)
	ops = a.ops or list(OPS)
	base = os.environ.get("TMPDIR", os.path.join(os.getcwd(), ".tmp"))
	os.makedirs(base, exist_ok=True)
	work = tempfile.mkdtemp(prefix="bench-trans-", dir=base)
	try:
		nl, ns = setup(work, a.c_pacman)
		print(f"sets: small {SMALL} {ns} pkgs, large {nl} pkgs; "
			f"{a.runs} runs per side", flush=True)
		launcher = bench.build_launcher(work)
		print(f"{'op':17} {'C time':>9} {'C cpu':>7} {'C RSS':>7} "
			f"{'puck time':>9} {'cpu':>7} {'RSS':>7} {'time':>6} "
			f"{'RSS':>6} {'C calls':>7} {'puck calls':>8} result")
		for op in ops:
			state, args, conf = OPS[op]
			args = expand(args, work)
			res = {}
			for side, b in (("c", a.c_pacman), ("r", puck)):
				res[side] = {"t": [], "cpu": [], "rss": []}
			for i in range(a.runs):
				for side, b in (("c", a.c_pacman), ("r", puck)):
					root = fresh_root(work, state, side)
					argv = argv_for(b, root, conf_path(work,
						root, conf), args)
					w, rss, st, data, us, ss = bench.launch(
						launcher, shutil.which("fakechroot"),
						argv, work)
					r = res[side]
					r["t"].append(w)
					r["cpu"].append(us + ss)
					r["rss"].append(rss)
					if i == 0:
						r["st"] = st
						r["data"] = [unroot(d, root) for d in data]
						r["man"] = faked_manifest(root)
			c, r = res["c"], res["r"]
			cs = strace_counts(work, a.c_pacman, state, conf, args)
			rs = strace_counts(work, puck, state, conf, args)
			same = []
			if c["st"] != r["st"]:
				same.append(f"rc {c['st']}/{r['st']}")
			if c["data"][0] != r["data"][0]:
				same.append("stdout")
			if c["data"][1] != r["data"][1]:
				same.append("stderr")
			if c["man"] != r["man"]:
				cm, rm = set(c["man"]), set(r["man"])
				same.append(f"tree {len(cm ^ rm)}")
			med = statistics.median
			ct, rt = med(c["t"]), med(r["t"])
			cr, rr = med(c["rss"]), med(r["rss"])
			print(f"{op:17} {bench.fmt_time(ct)} "
				f"{med(c['cpu']):6.2f}s {cr / 1024:5.1f}MB "
				f"{bench.fmt_time(rt)} {med(r['cpu']):6.2f}s "
				f"{rr / 1024:5.1f}MB {rt / ct:5.2f}x {rr / cr:5.2f}x "
				f"{cs[0]:7} {rs[0]:8} "
				f"{'same' if not same else 'DIFF ' + ','.join(same)}",
				flush=True)
			print(f"{'':17} syscalls C {cs[1]}\n{'':17} "
				f"syscalls puck {rs[1]}", flush=True)
	finally:
		if a.keep:
			print(f"kept {work}", file=sys.stderr)
		else:
			rmtree(work)


if __name__ == "__main__":
	main()
