#!/usr/bin/env bash
# keep port source, unit tests and equivalence testing apart (METHODOLOGY.md)
# usage: scripts/check-separation.sh   (from the repo root, exit 1 on findings)

port_crates=(alpm-core pacman-common pacman-cli vercmp)

fail=0
report() {
	echo "== $1"
	printf '%s\n' "$2"
	fail=1
}

srcs=() tests=() manifests=()
for c in "${port_crates[@]}"; do
	srcs+=("$c/src")
	manifests+=("$c/Cargo.toml")
	[ -d "$c/tests" ] && tests+=("$c/tests")
done

# structural: test modules, C access, difftest in port source
out=$(grep -rnE '#\[cfg\(test\)\]|\bunsafe\b|extern "C"|\bdifftest\b' \
	"${srcs[@]}")
[ -n "$out" ] && report "test/C code in port source" "$out"

# port unit tests must not call C or difftest
out=$(grep -rnE 'extern "C"|\bdifftest\b|\bunsafe\b' "${tests[@]}")
[ -n "$out" ] && report "C/difftest in port unit tests" "$out"

out=$(grep -nE '^difftest' "${manifests[@]}")
[ -n "$out" ] && report "port crate depends on difftest" "$out"

if [ "$fail" = 0 ]; then
	echo "separation ok: ${port_crates[*]}"
fi
exit "$fail"
