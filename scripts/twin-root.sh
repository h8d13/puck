#!/usr/bin/env bash
# real-system equivalence gate (PORTING.md "3b", METHODOLOGY.md
# "Integration gates"): C pacman and the Rust port run the same real
# operations on twin roots inside one user namespace; after every step
# scripts/twin-compare.py diffs rc, output, the whole tree, the local db
# and pacman.log
# usage: scripts/twin-root.sh [--keep | --clean]   (from the repo root)
#   --keep   leave .tmp/twin for inspection (remove it with --clean)
#   --clean  only remove .tmp/twin; its files belong to mapped subuids,
#            so this runs inside the namespace too
# needs target/release/pacman, the C build (PACMAN_BUILD, else read from
# .cargo/config.toml, else pacman/build) and network for the mirrors
# exit 0 only if every step is equal; summary in .tmp/twin-results.txt
# TWIN_TIMEOUT (seconds, per pacman run) overrides the default 900

set -uo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
W=$repo/.tmp/twin

if [ -z "${TWIN_NS:-}" ]; then
	# pid namespace too: gpg-agent or a stray child dies with the session
	exec unshare --map-auto --map-root-user --mount --pid --fork \
		--kill-child -- env TWIN_NS=1 bash "$0" "$@"
fi

mode=${1:-run}
build=${PACMAN_BUILD:-}
if [ -z "$build" ] && [ -f "$repo/.cargo/config.toml" ]; then
	build=$(sed -n 's/^PACMAN_BUILD = "\(.*\)"$/\1/p' \
		"$repo/.cargo/config.toml")
fi
build=${build:-$repo/pacman/build}
CPAC=$build/pacman
RPAC=$repo/target/release/pacman
# a tmpfs on /mnt, private to the namespace, holds every path pacman
# sees: DownloadUser alpm must traverse them, and it cannot pass the 0700
# home the worktree lives in
MNT=/mnt
CUR=$MNT/cur
CONF=$W/pacman.conf
DLCONF=$W/pacman-dl.conf
HOSTCACHE=/var/cache/pacman/pkg
STEPS=$W/steps
RESULTS=$repo/.tmp/twin-results.txt

# rm stays on this filesystem: a bind left on a side dir is skipped,
# never descended into
clean() {
	if mountpoint -q "$MNT"; then
		umount -R "$MNT"
	fi
	[ -d "$W" ] || return 0
	chmod -R u+rwx "$W"
	rm -rf --one-file-system "$W"
}

if [ "$mode" = --clean ]; then
	clean
	exit
fi
if [ "$mode" != run ] && [ "$mode" != --keep ]; then
	echo "usage: $0 [--keep | --clean]" >&2
	exit 2
fi
for b in "$CPAC" "$RPAC" "$build/pacman-key" "$build/vercmp"; do
	if [ ! -x "$b" ]; then
		echo "missing $b" >&2
		exit 2
	fi
done
if ! getent passwd alpm; then
	echo "DownloadUser alpm unknown to getpwnam" >&2
	exit 2
fi

# every pacman, gpg and pacman-key run is capped: a runaway froze this
# machine before (METHODOLOGY.md "Unit workflow")
capped() {
	(
		ulimit -v 4194304
		exec timeout "${TWIN_TIMEOUT:-900}" "$@"
	)
}

# same argv[0] for both binaries: pacman.log records the command line.
# a zone off UTC, so date displays and log stamps show their zone
pac() {
	local bin=$1
	shift
	capped env -i PATH=/usr/bin LC_ALL=C TZ=Europe/Berlin \
		HOME="$W/home" bash -c 'exec -a pacman "$0" "$@"' "$bin" "$@"
}

# pacstrap's skeleton, so the first transaction finds its dirs. a fixed
# machine-id: systemd's scriptlet keeps an existing one instead of
# drawing a random id per side
mkroot() {
	local r=$1
	mkdir -m 0755 -p "$r"/var/{cache/pacman/pkg,lib/pacman,log} \
		"$r"/{dev,run,etc/pacman.d}
	mkdir -m 1777 -p "$r/tmp"
	mkdir -m 0555 -p "$r"/{sys,proc}
	echo 7477696e726f6f7400000000000000ff > "$r/etc/machine-id"
}

# side $1 is bound at $CUR for the command: both binaries see the same
# paths, so output, logs and db carry no side-specific path. A minimal
# /dev (arch-chroot's nodes; an rbind of the host's does not unmount
# cleanly) and a proc of the session's pid namespace serve scriptlets
# and hooks in the chroot
with_side() {
	local side=$1 rc n dev=$CUR/root/dev
	shift
	mount --bind "$W/$side" "$CUR" || return 1
	mount -t tmpfs -o mode=0755 dev "$dev"
	for n in null zero full random urandom tty; do
		: > "$dev/$n"
		mount --bind "/dev/$n" "$dev/$n"
	done
	ln -s /proc/self/fd "$dev/fd"
	ln -s /proc/self/fd/0 "$dev/stdin"
	ln -s /proc/self/fd/1 "$dev/stdout"
	ln -s /proc/self/fd/2 "$dev/stderr"
	mount -t proc proc "$CUR/root/proc"
	"$@"
	rc=$?
	umount -R "$CUR"
	return $rc
}

# run windows per side: twin-compare.py maps an mtime inside one to its
# label, so files stamped at run time compare by step, not by second
window() {
	local side=$1 label=$2 start rc
	shift 2
	start=$(date +%s.%N)
	"$@"
	rc=$?
	echo "$label $start $(date +%s.%N)" >> "$W/windows-$side"
	return $rc
}

# side command: one pacman run, output and rc kept in $out
run_side() {
	local side=$1 out=$2 input=$3 bin=$CPAC
	shift 3
	[ "$side" = r ] && bin=$RPAC
	pac "$bin" "$@" < "$input" > "$out/stdout" 2> "$out/stderr"
	echo $? > "$out/rc"
}

n=0 failed=() prev=
# step NAME INPUT ARGS...: C side, then Rust side, then the comparer;
# conf=FILE for another config than $CONF
step() {
	local name=$1 input=$2 dir side
	shift 2
	n=$((n + 1))
	dir=$STEPS/$(printf %02d $n)-$name
	mkdir -p "$dir"
	printf '%s\n' "--config ${conf:-$CONF} $*" > "$dir/argv"
	for side in c r; do
		mkdir -p "$dir/$side"
		window "$side" "$(basename "$dir")" \
			with_side "$side" run_side "$side" "$dir/$side" \
			"$input" --config "${conf:-$CONF}" "$@"
	done
	if ! capped python3 -I "$repo/scripts/twin-compare.py" step "$dir" \
		"$W/c" "$W/r" "$prev"; then
		failed+=("$(basename "$dir")")
	fi
	prev=$dir
}

# same edit on both sides, mtime pinned so the edit itself is no diff
edit() {
	local path=$1 line=$2 side
	for side in c r; do
		printf '%s\n' "$line" >> "$W/$side/root/$path"
		touch -d @1700000000 "$W/$side/root/$path"
	done
}

# make_pkg VERSION CONF_LINE: twin-backup, a local package with a backup
# file (makepkg's .PKGINFO and .MTREE layout, fixed dates). no cached
# repo package changes a backup file between builds, so .pacnew comes
# from two of these
make_pkg() {
	local v=$1 line=$2 d=$W/pkgs/build-$1
	local mtree=!all,use-set,type,uid,gid,mode,time,size,md5,sha256,link
	mkdir -p "$d/etc" "$d/usr/share/twin-backup"
	printf '%s\n' "$line" > "$d/etc/twin-backup.conf"
	echo "twin-root test package" > "$d/usr/share/twin-backup/README"
	cat > "$d/.PKGINFO" <<EOF
pkgname = twin-backup
pkgbase = twin-backup
pkgver = $v
pkgdesc = twin-root backup file test package
url = https://archlinux.org
builddate = 1700000000
packager = twin-root
size = 64
arch = any
license = GPL-2.0-or-later
backup = etc/twin-backup.conf
EOF
	find "$d" -exec touch -h -d @1700000000 {} +
	(
		cd "$d" || exit 1
		LANG=C bsdtar -cf - --format=mtree --options="$mtree" \
			.PKGINFO etc usr | gzip -c -f -n > .MTREE
		touch -d @1700000000 .MTREE
		bsdtar -cf - .MTREE .PKGINFO etc usr |
			zstd -q -o "$W/pkgs/twin-backup-$v-any.pkg.tar.zst"
	)
}

# newest build of $1 in the host cache older than the installed one;
# prints its file name
older_cached() {
	local p=$1 inst f v best= bestv=
	inst=$(with_side c pac "$CPAC" --config "$CONF" -Q "$p")
	inst=${inst#"$p "}
	[ -n "$inst" ] || return 1
	for f in "$HOSTCACHE/$p"-*.pkg.tar.zst; do
		[ -e "$f" ] || continue
		v=${f##*/}
		v=${v#"$p"-}
		v=${v%-*.pkg.tar.zst}
		# pkgver-pkgrel only: a longer name sharing the prefix has
		# more dashes
		[[ $v =~ ^[^-]+-[^-]+$ ]] || continue
		[ "$("$build/vercmp" "$v" "$inst")" -lt 0 ] || continue
		if [ -z "$best" ] ||
			[ "$("$build/vercmp" "$v" "$bestv")" -gt 0 ]; then
			best=${f##*/} bestv=$v
		fi
	done
	[ -n "$best" ] && echo "$best"
}

clean
mkdir -p "$W"/{c,r}/{cache,dlcache} "$W"/{home,prefetch,pkgs} "$STEPS"
mount -t tmpfs -o mode=0755 twin "$MNT" || exit 1
mkdir "$CUR" "$MNT"/{hostcache,prefetch}
mkroot "$W/c/root"
: > "$W/windows-c"
: > "$W/windows-r"
started=$(date +%s)

# read only: nothing is ever written to the host's cache
mount --bind -o ro "$HOSTCACHE" "$MNT/hostcache" || exit 1

# Arch's default options; every path pinned under $CUR (HookDir and
# GPGDir default to host paths even with RootDir set)
# write_conf FILE CACHEDIR...
write_conf() {
	local f=$1 d
	shift
	cat > "$f" <<EOF
[options]
RootDir = $CUR/root/
DBPath = $CUR/root/var/lib/pacman/
LogFile = $CUR/root/var/log/pacman.log
GPGDir = $CUR/gnupg/
HookDir = $CUR/root/etc/pacman.d/hooks/
EOF
	for d in "$@"; do
		echo "CacheDir = $d/" >> "$f"
	done
	cat >> "$f" <<EOF
HoldPkg = pacman glibc
Architecture = auto
CheckSpace
ParallelDownloads = 5
DownloadUser = alpm
SigLevel = Required DatabaseOptional
LocalFileSigLevel = Optional

[core]
Include = /etc/pacman.d/mirrorlist

[extra]
Include = /etc/pacman.d/mirrorlist
EOF
}
write_conf "$CONF" "$CUR/cache" "$MNT/prefetch" "$MNT/hostcache"
# the download phase: an empty cache only (--cachedir adds to the
# config's list, it does not replace it)
write_conf "$DLCONF" "$CUR/dlcache"

echo "== setup: keyring"
key() {
	capped env -i PATH=/usr/bin LC_ALL=C HOME="$W/home" \
		"$build/pacman-key" --config "$CONF" --gpgdir "$W/c/gnupg" "$@"
}
key --init || exit 1
key --populate archlinux || exit 1
capped gpgconf --homedir "$W/c/gnupg" --kill all
# one keyring for both: --init makes a random master key
cp -a "$W/c/gnupg" "$W/r/gnupg"

echo "== setup: sync and files dbs (C)"
setup_pac() {
	pac "$CPAC" --config "$CONF" --logfile "$W/setup.log" "$@"
}
window c setup-sync with_side c setup_pac -Syy || exit 1
window c setup-files with_side c setup_pac -Fyy || exit 1

# every package the steps install, fetched once: steps then read caches
# only, so a mirror update mid-run cannot split the sides
base1=(filesystem)
base2=(glibc bash coreutils pacman)
base3=(iputils less nano logrotate)
echo "== setup: prefetch into .tmp/twin/prefetch (host cache hits skip)"
mount --bind "$W/prefetch" "$MNT/prefetch" || exit 1
window c setup-prefetch with_side c setup_pac \
	--cachedir "$MNT/prefetch" --cachedir "$MNT/hostcache" \
	-Sw --noconfirm "${base1[@]}" "${base2[@]}" "${base3[@]}" || exit 1
mount -o remount,bind,ro "$MNT/prefetch" || exit 1
make_pkg 1-1 'value=1' || exit 1
make_pkg 2-1 'value=2' || exit 1
# the Rust side starts as a copy: same skeleton, dbs and mtimes, and
# whatever the C runs above created in the root (local db version file)
cp -a "$W/c/root" "$W/r/root"

nul=/dev/null
# -Sc asks per CacheDir (dlcache, cache, prefetch, host cache; the last
# two read only, kept), then about unused repositories
sc_answers=$W/sc-answers
printf 'y\ny\nn\nn\ny\n' > "$sc_answers"

step sy $nul -Sy
# download phase: empty caches, the mirrors, DownloadUser, sandbox
conf=$DLCONF step download $nul -Sw --noconfirm -dd which less iana-etc
step base-filesystem $nul -S --noconfirm "${base1[@]}"
step base-core $nul -S --noconfirm "${base2[@]}"
step base-extra $nul -S --noconfirm "${base3[@]}"
step qi $nul -Qi pacman iputils
step qii-backup $nul -Qii nano
step si $nul -Si iputils
# reinstall over an edited backup file: kept, no .pacnew (the package's
# file did not change)
edit etc/pacman.conf '# twin-root edit'
step reinstall-backup $nul -S --noconfirm pacman
step local-install $nul -U --noconfirm "$W/pkgs/twin-backup-1-1-any.pkg.tar.zst"
edit etc/twin-backup.conf 'edited=1'
step pacnew $nul -U --noconfirm "$W/pkgs/twin-backup-2-1-any.pkg.tar.zst"
step qii-pacnew $nul -Qii twin-backup
step pacsave $nul -R --noconfirm twin-backup
old=
for p in less gzip which bash; do
	old=$(older_cached "$p") && break
done
if [ -n "$old" ]; then
	step downgrade $nul -U --noconfirm "$MNT/hostcache/$old"
else
	echo "== no older build of less/gzip/which/bash cached: no -U step"
fi
# --nosave: the edited backup file goes, no .pacsave
edit etc/logrotate.conf '# twin-root edit'
step rns-nosave $nul -Rns --noconfirm logrotate
step qkk $nul -Qkk
step dk $nul -Dk
step sc "$sc_answers" -Sc --cachedir "$CUR/dlcache"
step fy $nul -Fy
step f $nul -F ping
step fl $nul -Fl iputils

took=$(($(date +%s) - started))
capped python3 -I "$repo/scripts/twin-compare.py" summary "$STEPS" \
	> "$RESULTS"
{
	echo "runtime ${took}s"
	du -sh "$W/c" "$W/r" "$W/prefetch"
} >> "$RESULTS"
cat "$RESULTS"
[ "$mode" = --keep ] || clean
[ ${#failed[@]} = 0 ]
