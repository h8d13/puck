#!/usr/bin/env bash
# upstream's full meson test suite against a directory of binaries: the
# pactest list (scripts/pactest.sh) on BINDIR/pacman, vercmptest on
# BINDIR/vercmp, and the two script tests. Totals compare with meson's
# baseline, 338 ok and 6 expected fail.
# usage: scripts/upstream-suite.sh [BINDIR]   (default target/release;
#        pacman/build for the C reference)
# the script tests use the C build's libmakepkg and makepkg-template: the
# bash/Perl scripts are kept as upstream ships them (PORTING.md)

set -u
bindir=${1:-target/release}
build=pacman/build
tests=pacman/test
for b in pacman vercmp; do
	if [ ! -x "$bindir/$b" ]; then
		echo "$bindir/$b missing (cargo build --release)" >&2
		exit 2
	fi
done

# meson counts each TAP test as one: ok unless a top level "not ok"
tap() {
	local name=$1 log
	shift
	log=$(bash "$@" 2>&1)
	if [ $? = 0 ] && ! grep -q '^not ok' <<< "$log"; then
		echo "ok    $name"
		tap_ok=$((tap_ok + 1))
	else
		echo "FAIL  $name"
		grep '^not ok\|^Bail' <<< "$log"
		tap_fail=$((tap_fail + 1))
	fi
}

tap_ok=0 tap_fail=0
tap vercmptest "$tests/util/vercmptest.sh" "$bindir/vercmp"
tap parseopts_test.sh "$tests/scripts/parseopts_test.sh" \
	"$build/scripts/libmakepkg/util/parseopts.sh"
tap makepkg-template_test.sh "$tests/scripts/makepkg-template_test.sh" \
	"$build/scripts/makepkg-template"

pt=$(scripts/pactest.sh "$bindir/pacman")
echo "$pt"
# "== ok N, expected fail X, fail F, unexpected pass U, total T"
read -r ok xfail fail xpass < <(sed -n \
	's/^== ok \([0-9]*\), expected fail \([0-9]*\), fail \([0-9]*\), unexpected pass \([0-9]*\),.*/\1 \2 \3 \4/p' \
	<<< "$pt")
ok=$((ok + tap_ok))
fail=$((fail + tap_fail))
echo "== upstream suite: ok $ok, expected fail $xfail, fail $fail," \
	"unexpected pass $xpass (meson baseline: ok 338, expected fail 6)"
[ "$ok" = 338 ] && [ "$xfail" = 6 ] && [ "$fail" = 0 ] && [ "$xpass" = 0 ]
