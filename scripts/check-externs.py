#!/usr/bin/env python3
# one declaration per C symbol across difftest (METHODOLOGY.md): rustc only
# flags duplicates whose signatures differ, identical ones pass silently
# usage: scripts/check-externs.py   (from the repo root, exit 1 on duplicates)
import pathlib
import re
import sys

block = re.compile(r'extern "C"\s*\{(.*?)\n\}', re.S)
item = re.compile(r"^\s*(?:pub(?:\(crate\))?\s+)?(?:fn|static(?:\s+mut)?)"
	r"\s+(\w+)", re.M)

seen = {}
for f in sorted(pathlib.Path("difftest/src").glob("*.rs")):
	for b in block.finditer(f.read_text()):
		for m in item.finditer(b.group(1)):
			seen.setdefault(m.group(1), []).append(f.name)

dups = {k: v for k, v in seen.items() if len(v) > 1}
for name, files in sorted(dups.items()):
	print(f"{name}: {', '.join(files)}")
if dups:
	sys.exit(1)
print(f"externs ok: {len(seen)} symbols, one declaration each")
