#!/usr/bin/env bash
# every bench/t/bNNNN-*.sh in order with the same options, then a tally;
# exit 1 if any script failed. same as: prove bench/t/b*.sh :: OPTIONS
# usage: bench/run.sh [bench-lib.sh options]

dir=$(dirname "$0")
failed=()
for b in "$dir"/t/b[0-9][0-9][0-9][0-9]-*.sh; do
	"$b" "$@" || failed+=("$(basename "$b")")
	echo
done
if [ ${#failed[@]} -ne 0 ]; then
	echo "failed: ${failed[*]}"
	exit 1
fi
