#!/usr/bin/env python3
# comparer for scripts/twin-root.sh: one step's C side against its Rust
# side, after both ran the same argv on their twin roots
# usage: twin-compare.py step STEPDIR CSIDE RSIDE [PREVSTEPDIR]
#          STEPDIR/{c,r}/{rc,stdout,stderr} from the runs, CSIDE/RSIDE
#          the side dirs (root/, caches; gnupg/ is skipped: gpg rewrites
#          its trustdb and random_seed on every use). writes
#          STEPDIR/report.txt (every diff), STEPDIR/keys (one per diff,
#          to tell new from carried at the next step), STEPDIR/result;
#          prints the grouped report with carried diffs counted only.
#          exit 1 on any diff, known ones included
#        twin-compare.py summary STEPSDIR
#          one line per step from the result files
# compared: rc, stdout, stderr (install dates masked), every path of the
# side dirs (type, mode, uid, gid, size, sha256, link, mtime, nlink,
# xattrs), the local db (%INSTALLDATE% masked), pacman.log (stamps
# normalised, their offsets compared apart)
# mtime: equal if identical; else an mtime inside a run window of the side
# (windows-<side>, written by twin-root.sh) stands for that window's
# label, so files stamped at run time are equal when stamped by the same
# step on both sides

import difflib
import hashlib
import os
import re
import stat
import sys

LOG = "root/var/log/pacman.log"
LOCALDB = "root/var/lib/pacman/local/"
STAMP = re.compile(rb"^\[\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d([+-]\d{4})?\]",
		   re.M)
INSTALLDATE = re.compile(rb"(%INSTALLDATE%\n)[^\n]*")
QI_DATE = re.compile(rb"^(Install Date +:).*$", re.M)
DLTMP = re.compile(r"^download-[A-Za-z0-9]{6}$")
# libarchive's error texts after the path (its reader's words, an fd
# number) cannot match the port's: cut like difftest's cut_archive_text
ARCHIVE_TEXT = re.compile(rb"^((?:error: )?(?:could not open file "
			  rb"|error while reading package )[^\n]*?: )[^\n]*$",
			  re.M)
# generated with run-time stamps or inode numbers inside: the java
# keystore of update-ca-trust (entry dates), ldconfig's aux-cache
NONDET = {
	"root/etc/ca-certificates/extracted/java-cacerts.jks",
	"root/var/cache/ldconfig/aux-cache",
}
# coarse kernel timestamps may trail the window start by a jiffy
SLACK = 0.1
TEXT_MAX = 65536

# diffs another unit owns: still diffs (the gate waits for those units),
# labelled so they are not mistaken for new divergences
def known(key):
	if key.startswith("tree:xattr:"):
		return "xattr unit: pax xattrs / file caps not applied"
	return None


def read(path):
	try:
		with open(path, "rb") as f:
			return f.read()
	except FileNotFoundError:
		return None


def windows(side):
	out = []
	data = read(os.path.join(os.path.dirname(side),
				 "windows-" + os.path.basename(side)))
	for line in (data or b"").decode().splitlines():
		label, start, end = line.split()
		out.append((label, float(start) - SLACK, float(end) + SLACK))
	return out


def sha256(path):
	h = hashlib.sha256()
	with open(path, "rb") as f:
		for chunk in iter(lambda: f.read(1 << 20), b""):
			h.update(chunk)
	return h.hexdigest()


def xattrs(path):
	out = {}
	try:
		names = os.listxattr(path, follow_symlinks=False)
	except OSError:
		return out
	for n in sorted(names):
		try:
			out[n] = os.getxattr(path, n,
					     follow_symlinks=False).hex()
		except OSError as e:
			out[n] = "<%s>" % e.strerror
	return out


def entry(top, rel, st):
	path = os.path.join(top, rel)
	e = {"path": rel, "mode": "%04o" % stat.S_IMODE(st.st_mode),
	     "uid": st.st_uid, "gid": st.st_gid, "mtime": st.st_mtime_ns,
	     "xattr": xattrs(path)}
	if stat.S_ISDIR(st.st_mode):
		e["type"] = "dir"
		return e
	e["nlink"] = st.st_nlink
	if stat.S_ISLNK(st.st_mode):
		e["type"] = "link"
		e["link"] = os.readlink(path)
	elif stat.S_ISREG(st.st_mode):
		e["type"] = "file"
		# the log and the local db are compared normalised instead;
		# NONDET content differs run to run by design
		if (rel != LOG and not rel.startswith(LOCALDB)
		    and rel not in NONDET):
			e["size"] = st.st_size
			e["sha256"] = sha256(path)
	else:
		e["type"] = "other %o" % stat.S_IFMT(st.st_mode)
	return e


# whole side dir, one filesystem: a mount left inside is not walked
# keyed by canonical path: mkdtemp's download-XXXXXX names become
# download-XXXXXX.<n>, numbered by mtime so both sides pair up by order
def snapshot(top):
	tree = {}
	dev = os.lstat(top).st_dev
	stack = [("", "")]
	while stack:
		real, canon = stack.pop()
		ents = []
		for d in os.scandir(os.path.join(top, real)):
			st = d.stat(follow_symlinks=False)
			ents.append((d.name, st))
		tmp = sorted((st.st_mtime_ns, n) for n, st in ents
			     if DLTMP.match(n))
		names = {n: "download-XXXXXX.%d" % i
			 for i, (_, n) in enumerate(tmp)}
		for name, st in ents:
			r = os.path.join(real, name)
			c = os.path.join(canon, names.get(name, name))
			if r == "gnupg":
				continue
			tree[c] = entry(top, r, st)
			if stat.S_ISDIR(st.st_mode) and st.st_dev == dev:
				stack.append((r, c))
	return tree


def localdb(top, tree):
	out = {}
	for rel, e in tree.items():
		if rel.startswith(LOCALDB) and e["type"] == "file":
			data = read(os.path.join(top, rel))
			if rel.endswith("/desc"):
				data = INSTALLDATE.sub(rb"\1<masked>", data)
			out[rel[len(LOCALDB):]] = data
	return out


def mtime_label(ns, wins):
	t = ns / 1e9
	for label, start, end in wins:
		if start <= t <= end:
			return "run:" + label
	return None


def fmt_mtime(ns, wins):
	s = "%d.%09d" % divmod(ns, 10**9)
	label = mtime_label(ns, wins)
	return "%s (%s)" % (s, label) if label else s


def udiff(a, b, name):
	a = a.decode(errors="replace").splitlines(keepends=True)
	b = b.decode(errors="replace").splitlines(keepends=True)
	lines = difflib.unified_diff(a, b, "C/" + name, "Rust/" + name,
				     n=2)
	return "".join(lines).rstrip("\n")


def is_text(data):
	return (data is not None and len(data) <= TEXT_MAX
		and b"\0" not in data)


class Step:
	def __init__(self, sdir, cside, rside):
		self.sdir, self.cside, self.rside = sdir, cside, rside
		self.cw, self.rw = windows(cside), windows(rside)
		# key -> detail text
		self.diffs = {}

	def add(self, key, detail):
		self.diffs[key] = detail

	def outputs(self):
		for f in ("rc", "stdout", "stderr"):
			c = read(os.path.join(self.sdir, "c", f)) or b""
			r = read(os.path.join(self.sdir, "r", f)) or b""
			c = QI_DATE.sub(rb"\1 <masked>", c)
			r = QI_DATE.sub(rb"\1 <masked>", r)
			c = ARCHIVE_TEXT.sub(rb"\1", c)
			r = ARCHIVE_TEXT.sub(rb"\1", r)
			if c == r:
				continue
			if f == "rc":
				self.add("rc", "C %s, Rust %s" % (
					c.decode().strip(), r.decode().strip()))
			else:
				self.add(f, udiff(c, r, f))

	def tree(self, ct, rt):
		for rel in sorted(set(ct) | set(rt)):
			c, r = ct.get(rel), rt.get(rel)
			if c is None or r is None:
				side = "C" if r is None else "Rust"
				e = c or r
				self.add("tree:only:" + rel, "only in %s (%s)"
					 % (side, e["type"]))
				continue
			self.entry(rel, c, r)

	def entry(self, rel, c, r):
		for a in ("type", "mode", "uid", "gid", "link", "nlink"):
			if c.get(a) != r.get(a):
				self.add("tree:%s:%s" % (a, rel), "C %s, Rust %s"
					 % (c.get(a), r.get(a)))
		if c.get("sha256") != r.get("sha256"):
			self.add("tree:content:" + rel, self.content(rel, c, r))
		if c["mtime"] != r["mtime"]:
			cl = mtime_label(c["mtime"], self.cw)
			rl = mtime_label(r["mtime"], self.rw)
			if cl is None or cl != rl:
				self.add("tree:mtime:" + rel, "C %s, Rust %s" % (
					fmt_mtime(c["mtime"], self.cw),
					fmt_mtime(r["mtime"], self.rw)))
		if c["xattr"] != r["xattr"]:
			names = sorted(set(c["xattr"]) | set(r["xattr"]))
			parts = ["%s: C %s, Rust %s" % (
				n, c["xattr"].get(n, "-"), r["xattr"].get(n, "-"))
				for n in names
				if c["xattr"].get(n) != r["xattr"].get(n)]
			self.add("tree:xattr:" + rel, "; ".join(parts))

	def content(self, rel, c, r):
		head = "size C %s, Rust %s" % (c.get("size"), r.get("size"))
		cd = read(os.path.join(self.cside, c["path"]))
		rd = read(os.path.join(self.rside, r["path"]))
		if is_text(cd) and is_text(rd):
			return head + "\n" + udiff(cd, rd, rel)
		return head

	def db(self, cdb, rdb):
		for name in sorted(set(cdb) | set(rdb)):
			c, r = cdb.get(name), rdb.get(name)
			if c == r:
				continue
			if c is None or r is None:
				self.add("localdb:" + name, "only in %s"
					 % ("C" if r is None else "Rust"))
			else:
				self.add("localdb:" + name, udiff(c, r, name))

	def log(self):
		c = read(os.path.join(self.cside, LOG)) or b""
		r = read(os.path.join(self.rside, LOG)) or b""
		co = sorted({m.group(1) or b"" for m in STAMP.finditer(c)})
		ro = sorted({m.group(1) or b"" for m in STAMP.finditer(r)})
		if co != ro:
			self.add("log-offset", "C %s, Rust %s" % (
				b" ".join(co).decode(), b" ".join(ro).decode()))
		c = STAMP.sub(b"[STAMP]", c)
		r = STAMP.sub(b"[STAMP]", r)
		if c != r:
			self.add("log", udiff(c, r, "pacman.log"))


GROUPS = ("rc", "stdout", "stderr", "log-offset", "log", "localdb",
	  "tree:only", "tree:type", "tree:mode", "tree:uid", "tree:gid",
	  "tree:link", "tree:nlink", "tree:content", "tree:mtime",
	  "tree:xattr")


def group_of(key):
	for g in GROUPS:
		if key == g or key.startswith(g + ":"):
			return g
	return "other"


def render(name, argv, diffs, carried, full):
	out = []
	new = [k for k in diffs if k not in carried]
	out.append("== %s: %s" % (name, "equal" if not diffs else
		   "%d diffs, %d new, %d carried" % (
			   len(diffs), len(new), len(diffs) - len(new))))
	out.append("argv: " + argv)
	for g in GROUPS + ("other",):
		keys = [k for k in diffs if group_of(k) == g]
		if not keys:
			continue
		out.append("-- %s (%d)" % (g, len(keys)))
		for k in keys:
			if k in carried and not full:
				continue
			sub = k[len(g) + 1:] if k != g else ""
			tag = known(k)
			mark = " [carried]" if k in carried else ""
			mark += " [known: %s]" % tag if tag else ""
			detail = diffs[k]
			if "\n" in detail:
				out.append("%s%s" % (sub or g, mark))
				out.append("\t" + detail.replace("\n", "\n\t"))
			else:
				out.append("%s%s: %s" % (sub, mark, detail)
					   if sub else "%s%s" % (detail, mark))
		hidden = sum(1 for k in keys if k in carried)
		if hidden and not full:
			out.append("(%d carried from the previous step, "
				   "listed in report.txt)" % hidden)
	return "\n".join(out) + "\n"


def step(sdir, cside, rside, prev):
	s = Step(sdir, cside, rside)
	s.outputs()
	ct, rt = snapshot(cside), snapshot(rside)
	s.tree(ct, rt)
	s.db(localdb(cside, ct), localdb(rside, rt))
	s.log()
	carried = set()
	if prev:
		carried = set((read(os.path.join(prev, "keys")) or b"")
			      .decode().splitlines())
	name = os.path.basename(sdir.rstrip("/"))
	argv = (read(os.path.join(sdir, "argv")) or b"").decode().strip()
	with open(os.path.join(sdir, "report.txt"), "w") as f:
		f.write(render(name, argv, s.diffs, carried, True))
	with open(os.path.join(sdir, "keys"), "w") as f:
		f.write("".join(k + "\n" for k in s.diffs))
	groups = {}
	for k in s.diffs:
		g = group_of(k)
		if k not in carried:
			groups[g] = groups.get(g, 0) + 1
	new = sum(groups.values())
	known_n = sum(1 for k in s.diffs if known(k))
	with open(os.path.join(sdir, "result"), "w") as f:
		if not s.diffs:
			f.write("equal\n")
		else:
			f.write("%d diffs (%d new, %d known): %s\n" % (
				len(s.diffs), new, known_n, " ".join(
					"%s=%d" % kv for kv in groups.items())))
	sys.stdout.write(render(name, argv, s.diffs, carried, False))
	return 1 if s.diffs else 0


def summary(steps):
	for name in sorted(os.listdir(steps)):
		res = read(os.path.join(steps, name, "result"))
		if res is not None:
			print("%-20s %s" % (name, res.decode().strip()))
	return 0


def main(argv):
	if len(argv) >= 4 and argv[0] == "step":
		prev = argv[4] if len(argv) > 4 else ""
		return step(argv[1], argv[2], argv[3], prev)
	if len(argv) == 2 and argv[0] == "summary":
		return summary(argv[1])
	sys.stderr.write("usage: twin-compare.py step STEPDIR CSIDE RSIDE "
			 "[PREVSTEPDIR] | summary STEPSDIR\n")
	return 2


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
