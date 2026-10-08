#!/usr/bin/env bash
# upstream pactest suite against a pacman binary, with the arguments meson
# test passes (test/pacman/meson.build); per test result, then totals
# against the meson expectations (xfail_tests)
# usage: scripts/pactest.sh PACMAN_BIN [TEST...]   (from the repo root;
#        TEST: pactest files, default the pacman_tests list of
#        pacman/test/pacman/meson.build)
# needs fakechroot and fakeroot; temporary roots go to $TMPDIR (default
# .tmp/ of the checkout, never /tmp)

bin=$1
if [ ! -x "$bin" ]; then
	echo "usage: $0 PACMAN_BIN [TEST...]" >&2
	exit 2
fi
shift
bindir=$(cd "$(dirname "$bin")" && pwd)
if [ "$(basename "$bin")" != pacman ]; then
	echo "pactest looks for 'pacman' in the binary's directory" >&2
	exit 2
fi
export TMPDIR=${TMPDIR:-$PWD/.tmp}
mkdir -p "$TMPDIR"
suite=pacman/test/pacman
tests=("$@")
if [ ${#tests[@]} = 0 ]; then
	# the list up to its closing bracket, quotes stripped
	mapfile -t tests < <(sed -n "/^pacman_tests = \[/,/^\]/s/^ *'\(.*\)',\?$/\1/p" \
		"$suite/meson.build")
	tests=("${tests[@]/#/$suite/}")
fi
# meson.build xfail_tests (query006 only on 32 bit)
xfail=(deprange001.py replace110.py
	sync-update-package-removing-required-provides.py sync403.py
	sync406.py upgrade078.py)

ok=0 fail=0 xfailed=0 xpassed=0
log=$(mktemp)
trap 'rm -f "$log"' EXIT
for t in "${tests[@]}"; do
	name=$(basename "$t")
	RUNNING_UNDER_MESON=1 python3 "$suite/pactest.py" \
		--scriptlet-shell /bin/sh --bindir "$bindir" \
		--ldconfig /sbin/ldconfig --verbose "$t" > "$log" 2>&1
	# meson reads the TAP: a top level "not ok" fails the test
	rc=0
	grep -q '^not ok' "$log" && rc=1
	grep -q '^ok' "$log" || rc=1
	expect_fail=0
	for x in "${xfail[@]}"; do
		[ "$x" = "$name" ] && expect_fail=1
	done
	if [ $rc = 0 ] && [ $expect_fail = 0 ]; then
		ok=$((ok + 1)) res=ok
	elif [ $rc = 0 ]; then
		xpassed=$((xpassed + 1)) res="unexpected pass"
	elif [ $expect_fail = 1 ]; then
		xfailed=$((xfailed + 1)) res="expected fail"
	else
		fail=$((fail + 1)) res=FAIL
	fi
	echo "$res  $name"
done
echo "== ok $ok, expected fail $xfailed, fail $fail," \
	"unexpected pass $xpassed, total ${#tests[@]}"
