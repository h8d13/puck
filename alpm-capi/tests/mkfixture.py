#!/usr/bin/env python3
# build a fixture root both libalpm.so.16 implementations read the same
# way: an empty-rooted local db with two installed packages (varied
# fields) and one sync db. pacman's on-disk format, so puck and the real
# libalpm parse it identically. usage: mkfixture.py <dir>
import gzip, io, os, sys, tarfile


def section(key, *values):
	return "%" + key + "%\n" + "\n".join(values) + "\n\n"


def write_local(dbpath, name, ver, body):
	d = os.path.join(dbpath, "local", f"{name}-{ver}")
	os.makedirs(d, exist_ok=True)
	with open(os.path.join(d, "desc"), "w") as f:
		f.write(body)


def targz(path, entries):
	buf = io.BytesIO()
	with tarfile.open(fileobj=buf, mode="w") as tar:
		for member, data in entries:
			info = tarfile.TarInfo(member)
			info.size = len(data)
			tar.addfile(info, io.BytesIO(data))
	with open(path, "wb") as f:
		f.write(gzip.compress(buf.getvalue()))


def main(root_dir):
	root = os.path.join(root_dir, "root")
	dbpath = os.path.join(root_dir, "db")
	os.makedirs(root, exist_ok=True)
	os.makedirs(os.path.join(dbpath, "local"), exist_ok=True)
	os.makedirs(os.path.join(dbpath, "sync"), exist_ok=True)
	with open(os.path.join(dbpath, "local", "ALPM_DB_VERSION"), "w") as f:
		f.write("9\n")

	# alpha: explicit, single license/group/dep
	write_local(dbpath, "alpha", "1.0-1",
		section("NAME", "alpha") + section("VERSION", "1.0-1")
		+ section("DESC", "first package") + section("ARCH", "x86_64")
		+ section("BUILDDATE", "1700000000") + section("SIZE", "1234")
		+ section("REASON", "0") + section("LICENSE", "MIT")
		+ section("GROUPS", "base") + section("DEPENDS", "libc"))
	# beta: installed as dependency, multiple licenses/deps, versioned dep
	write_local(dbpath, "beta", "2.1-3",
		section("NAME", "beta") + section("VERSION", "2.1-3")
		+ section("DESC", "second package") + section("ARCH", "x86_64")
		+ section("BUILDDATE", "1710000000") + section("SIZE", "5678")
		+ section("REASON", "1") + section("LICENSE", "GPL", "MIT")
		+ section("GROUPS", "devel")
		+ section("DEPENDS", "alpha>=1.0", "libfoo"))

	# a sync db with one package
	gamma = (section("FILENAME", "gamma-3.0-1-x86_64.pkg.tar.zst")
		+ section("NAME", "gamma") + section("BASE", "gamma")
		+ section("VERSION", "3.0-1") + section("DESC", "sync package")
		+ section("ARCH", "x86_64") + section("BUILDDATE", "1720000000")
		+ section("ISIZE", "999") + section("DEPENDS", "beta>=2.0"))
	targz(os.path.join(dbpath, "sync", "testrepo.db"),
		[("gamma-3.0-1/desc", gamma.encode())])

	print(root)
	print(dbpath)


if __name__ == "__main__":
	main(sys.argv[1])
