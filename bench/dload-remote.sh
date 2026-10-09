#!/usr/bin/env bash
# C pacman vs puck downloading N small packages from one remote mirror
# with the built-in downloader (-Swdd into an empty cache): wall time,
# then the same run under strace counting TCP connects to the mirror.
# needs network, fakeroot and strace. the sync db is the host's copy.
# usage: bench/dload-remote.sh [-n N] [-m MIRROR] [-p PARALLEL] [-r RUNS]

set -euo pipefail

n=200
mirror='https://geo.mirror.pkgbuild.com/$repo/os/$arch'
parallel=5
runs=1
while getopts n:m:p:r: opt; do
	case $opt in
	n) n=$OPTARG ;;
	m) mirror=$OPTARG ;;
	p) parallel=$OPTARG ;;
	r) runs=$OPTARG ;;
	*) exit 2 ;;
	esac
done

top=$(cd "$(dirname "$0")/.." && pwd)
# the C reference build: PACMAN_BUILD, this checkout's, the main one's
if [ -z "${PACMAN_BUILD:-}" ]; then
	PACMAN_BUILD=$top/pacman/build
	if [ ! -x "$PACMAN_BUILD/pacman" ]; then
		common=$(git -C "$top" rev-parse --path-format=absolute \
			--git-common-dir)
		PACMAN_BUILD=$(dirname "$common")/pacman/build
	fi
fi
c=$PACMAN_BUILD/pacman
puck=$top/target/release/puck
work=${TMPDIR:-$top/.tmp}/bench-dload
rm -rf "$work"
mkdir -p "$work/root" "$work/db/sync" "$work/db/local" "$work/cache"
cp /var/lib/pacman/sync/extra.db "$work/db/sync/"
conf=$work/pacman.conf
cat > "$conf" <<EOF
[options]
RootDir = $work/root
DBPath = $work/db
CacheDir = $work/cache
LogFile = $work/pacman.log
Architecture = x86_64
SigLevel = Never
ParallelDownloads = $parallel
[extra]
Server = $mirror
EOF

# the first N packages under 100 KiB, by name: small bodies keep the
# per-connection cost visible
"$c" --config "$conf" -Si \
	| awk -v n="$n" '
		/^Name / { name = $3 }
		/^Download Size/ {
			if ($5 == "KiB" && $4 + 0 < 100 && picked < n) {
				print name; picked++
			}
		}' > "$work/pkgs"
mapfile -t pkgs < "$work/pkgs"
echo "packages: ${#pkgs[@]} (mirror $mirror, ParallelDownloads $parallel)"

run_side() {
	local name=$1 bin=$2 trace=$3 start end
	rm -rf "$work/cache" && mkdir "$work/cache"
	start=$(date +%s.%N)
	if [ "$trace" = 1 ]; then
		strace -f -e trace=connect -o "$work/$name.strace" \
			fakeroot "$bin" --config "$conf" -Swdd --noconfirm \
			--noprogressbar "${pkgs[@]}" > "$work/$name.out" 2>&1 \
			|| echo "$name: exit $?"
	else
		fakeroot "$bin" --config "$conf" -Swdd --noconfirm \
			--noprogressbar "${pkgs[@]}" > "$work/$name.out" 2>&1 \
			|| echo "$name: exit $?"
	fi
	end=$(date +%s.%N)
	echo "$end - $start" | bc
}

for i in $(seq "$runs"); do
	for side in c puck; do
		bin=$c
		[ "$side" = puck ] && bin=$puck
		wall=$(run_side "$side" "$bin" 0)
		got=$(ls "$work/cache" | wc -l)
		run_side "$side" "$bin" 1 > /dev/null
		conns=$(grep -c 'AF_INET.*htons(443)\|AF_INET.*htons(80)' \
			"$work/$side.strace" || true)
		printf '%-5s run %d: %6.2f s wall, %d files, %d connects\n' \
			"$side" "$i" "$wall" "$got" "$conns"
	done
done
