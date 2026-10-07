#!/usr/bin/env bash
# compare stdout, stderr and exit code of a C binary and its rust port
# usage: cli-parity.sh C_BIN RUST_BIN < argsfile
# argsfile: one invocation per line, args split on whitespace

c_bin=$1 rs_bin=$2
if [ ! -x "$c_bin" ] || [ ! -x "$rs_bin" ]; then
	echo "usage: $0 C_BIN RUST_BIN < argsfile" >&2
	exit 2
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fail=0 n=0
while read -r -a args; do
	n=$((n + 1))
	"$c_bin" "${args[@]}" > "$tmp/c.out" 2> "$tmp/c.err"
	c_rc=$?
	"$rs_bin" "${args[@]}" > "$tmp/r.out" 2> "$tmp/r.err"
	r_rc=$?
	if [ "$c_rc" != "$r_rc" ] ||
			! cmp -s "$tmp/c.out" "$tmp/r.out" ||
			! cmp -s "$tmp/c.err" "$tmp/r.err"; then
		fail=$((fail + 1))
		echo "DIFF [${args[*]}] rc c=$c_rc rust=$r_rc"
		diff "$tmp/c.out" "$tmp/r.out"
		diff "$tmp/c.err" "$tmp/r.err"
	fi
done

echo "$((n - fail))/$n identical"
[ "$fail" = 0 ]
