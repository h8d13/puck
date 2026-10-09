#!/usr/bin/env python3
# pyalpm read-path driver: whichever libalpm.so.16 the loader binds (puck
# via LD_LIBRARY_PATH, or the real one) produces this output. run against
# both and diff. usage: driver.py <root> <dbpath>
import sys

import pyalpm


def dump_pkg(p):
	# pyalpm exposes depends as computed strings (alpm_dep_compute_string)
	print("  {}|{}|{}|{}|{}|{}|licenses={}|groups={}|depends={}".format(
		p.name, p.version, p.desc, p.isize, p.builddate, p.reason,
		",".join(p.licenses), ",".join(p.groups), ",".join(p.depends)))


def main(root, dbpath):
	print("version", pyalpm.version(), pyalpm.alpmversion())
	h = pyalpm.Handle(root, dbpath)
	print("root", h.root)
	print("dbpath", h.dbpath)

	local = h.get_localdb()
	print("localdb", local.name)
	for p in sorted(local.pkgcache, key=lambda p: p.name):
		dump_pkg(p)

	sync = h.register_syncdb("testrepo", 0)
	print("syncdb", sync.name)
	for p in sorted(sync.pkgcache, key=lambda p: p.name):
		dump_pkg(p)

	# a package by name
	g = sync.get_pkg("gamma")
	print("get_pkg", g.name, g.version)

	# vercmp, including the NULL/empty contract
	for a, b in [("1.0", "1.0"), ("1.0", "2.0"), ("2.0-1", "2.0-2"),
			("1:1.0", "2.0"), ("", "1.0"), ("1.0", "")]:
		print("vercmp", repr(a), repr(b), pyalpm.vercmp(a, b))


if __name__ == "__main__":
	main(sys.argv[1], sys.argv[2])
