# sourced after bench-lib.sh by the scripts whose ops change a root (-S,
# -U, -R, -D, -Sy, -Sw, -Sc): they run like pactest under fakechroot +
# fakeroot (no real root), each run on a fresh copy of a prepared state,
# with real packages from this host's cache and its core/extra sync dbs.
#
# SigLevel Never and DisableSandbox on both sides: signatures need the
# host's root-only keyring, and the C sandbox does not start as non-root
# under fakeroot (UPSTREAM.md). scriptlets, hooks and ldconfig run in
# the root. --noconfirm on every op.
#
#   root_op STATE CONF ARG...   bench_op ARG... from a fresh copy of
#                               STATE: empty, nosync (no sync dbs),
#                               small ($SMALL installed), large ($LARGE
#                               installed), dlcache (small, $LARGE's
#                               files in the root's cache). CONF cache
#                               adds the host cache as a second CacheDir,
#                               mirror serves only file:// from the
#                               trash dir's mirror
#
# the ROOT prereq makes the states once with C pacman, untimed
# (setup.log in the trash dir says why when it fails). after every run
# bench_state lists the root's tree under faked ids, its local db and
# log (bench_tree), compared across sides with stdout and stderr

HOST_CACHE=/var/cache/pacman/pkg
HOST_SYNC=/var/lib/pacman/sync
REPOS='core extra'
SMALL=less
LARGE='bash coreutils grep sed gawk findutils less python'

# root_closure NAME...: "repo file" per package an empty root installs
# for NAME..., as C pacman resolves it on the host's sync dbs
root_closure () {
	local d=$TRASH/resolve r
	if [ ! -d "$d" ]; then
		mkdir -p "$d/sync" "$d/local"
		for r in $REPOS; do
			cp "$HOST_SYNC/$r.db" "$d/sync/"
		done
		echo 9 >"$d/local/ALPM_DB_VERSION"
		{
			printf '[options]\nSigLevel = Never\n'
			for r in $REPOS; do
				printf '[%s]\nServer = file:///nonexistent\n' "$r"
			done
		} >"$d/pacman.conf"
	fi
	"$BENCH_C" -Sp --config "$d/pacman.conf" --dbpath "$d" \
		--print-format '%r %f' "$@"
}

# root_write_conf PATH ROOT cache|mirror
root_write_conf () {
	local r
	{
		printf '[options]\nSigLevel = Never\nLocalFileSigLevel = Never\n'
		printf 'DisableSandbox\nCacheDir = %s/cache/\n' "$2"
		[ "$3" != cache ] || printf 'CacheDir = %s/\n' "$HOST_CACHE"
		for r in $REPOS; do
			printf '[%s]\nServer = file://%s/%s\n' "$r" "$TRASH/mirror" "$r"
		done
	} >"$1"
}

# root_pacman ROOT CONF ARG...: C pacman as fake root in ROOT (setup)
root_pacman () {
	local root=$1 conf=$2
	shift 2
	fakechroot fakeroot -s "$root.faked" "$BENCH_C" --root "$root" \
		--dbpath "$root/db" --config "$conf" --logfile "$root/pacman.log" \
		--noconfirm "$@"
}

root_rm () {
	[ ! -e "$1" ] || { chmod -R u+rwX "$1" && rm -rf "$1"; }
}

# the mirror and the states, in the trash dir
root_setup () (
	set -e
	local r f s
	[ ${#small_files[@]} -gt 0 ] && [ ${#large_files[@]} -gt 0 ]
	for r in $REPOS; do
		mkdir -p "mirror/$r"
		cp "$HOST_SYNC/$r.db" "mirror/$r/"
	done
	for s in "${small_files[@]}" "${large_files[@]}"; do
		r=${s%% *} f=${s#* }
		[ -f "$HOST_CACHE/$f" ] || { echo "not in $HOST_CACHE: $f"; exit 1; }
		ln -sf "$HOST_CACHE/$f" "mirror/$r/$f"
		[ ! -f "$HOST_CACHE/$f.sig" ] ||
			ln -sf "$HOST_CACHE/$f.sig" "mirror/$r/$f.sig"
	done
	mkdir -p states/empty/db/sync states/empty/db/local states/empty/cache
	for r in $REPOS; do
		cp "$HOST_SYNC/$r.db" "states/empty/db/sync/"
	done
	echo 9 >states/empty/db/local/ALPM_DB_VERSION
	cp -a states/empty states/nosync
	rm -f states/nosync/db/sync/*
	# the installed states: C pacman's work, once
	for s in small large; do
		cp -a states/empty "states/$s"
		root_write_conf setup.conf "$TRASH/states/$s" cache
		if [ "$s" = small ]; then set -- $SMALL; else set -- $LARGE; fi
		root_pacman "$TRASH/states/$s" setup.conf -S "$@"
	done
	cp -a states/small states/dlcache
	root_write_conf setup.conf "$TRASH/states/dlcache" mirror
	root_pacman "$TRASH/states/dlcache" setup.conf -Sw $LARGE
	rm -f setup.conf states/*.faked
)

mapfile -t small_files < <(root_closure $SMALL)
mapfile -t large_files < <(root_closure $LARGE)
echo "# small: $SMALL (${#small_files[@]} pkgs), large: $LARGE" \
	"(${#large_files[@]} pkgs)"
bench_lazy_prereq ROOT 'root_setup >setup.log 2>&1'

root_state= root_conf=
root_op () {
	root_state=$1 root_conf=$2
	shift 2
	bench_op ROOT "$@"
}

# the host cache paths of $SMALL's closure, for -U
root_small_files () {
	local s
	for s in "${small_files[@]}"; do
		printf '%s\n' "$HOST_CACHE/${s#* }"
	done
}

# a fresh copy of the op's state as root.SIDE, fakeroot's faked owners
# and modes saved next to it. what lands on disk under fakeroot depends
# on which libc calls a side makes (chmod, fchmodat, O_PATH), the faked
# view is what bench_tree reads back
bench_reset () {
	local root=$TRASH/root.$1 conf=$TRASH/root.$1.conf
	root_rm "$root"
	rm -f "$root.faked"
	cp -a "$TRASH/states/$root_state" "$root"
	root_write_conf "$conf" "$root" "$root_conf"
	bench_wrap=(fakechroot fakeroot -s "$root.faked")
	bench_pre=(--root "$root" --dbpath "$root/db" --config "$conf" \
		--logfile "$root/pacman.log" --noconfirm)
	bench_root=$root
}

bench_state () {
	bench_tree "$TRASH/root.$1" "$TRASH/root.$1.faked"
}
