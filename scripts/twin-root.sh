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
# needs target/release/puck, the C build (PACMAN_BUILD, else read from
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
RPAC=$repo/target/release/puck
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
# risky-case steps (PORTING.md handover): a local repo for the replaces
# case, two Arch Linux Archive snapshots for the across-months -Syu
REPO=$MNT/twinrepo
TWINCONF=$W/twin.conf
ARCHOLD=$W/arch-old.conf
ARCHNEW=$W/arch-new.conf
ARCH_OLD_DATE=2024/03/01
ARCH_NEW_DATE=2024/12/01

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

# build_pkg NAME VER STAGE: a reproducible package from a staging dir
# (payload plus optional .INSTALL and a .PKGINFO.extra of depend/replaces/
# conflict lines), fixed dates like make_pkg. the mtree lists .PKGINFO and
# the payload, matching make_pkg
build_pkg() {
	local name=$1 ver=$2 stage=$3 members install=
	local mtree=!all,use-set,type,uid,gid,mode,time,size,md5,sha256,link
	{
		cat <<EOF
pkgname = $name
pkgbase = $name
pkgver = $ver
pkgdesc = twin-root fixture $name
url = https://archlinux.org
builddate = 1700000000
packager = twin-root
size = 64
arch = any
license = GPL-2.0-or-later
EOF
		[ -f "$stage/.PKGINFO.extra" ] && cat "$stage/.PKGINFO.extra"
	} > "$stage/.PKGINFO"
	rm -f "$stage/.PKGINFO.extra"
	find "$stage" -exec touch -h -d @1700000000 {} +
	(
		cd "$stage" || exit 1
		# payload top entries, metadata dot-files added explicitly
		members=$(ls -A | grep -vE '^\.(MTREE|INSTALL|PKGINFO)$')
		# word-split $members: names are controlled, no spaces
		LANG=C bsdtar -cf - --format=mtree --options="$mtree" \
			.PKGINFO $members | gzip -c -f -n > .MTREE
		touch -d @1700000000 .MTREE
		[ -f .INSTALL ] && install=.INSTALL
		bsdtar -cf - .MTREE .PKGINFO $install $members |
			zstd -q -o "$W/pkgs/$name-$ver-any.pkg.tar.zst"
	)
}

# the fixtures the risky steps install: a hook package, a keyring
# stand-in and its companion, a conflict pair, a replaces pair and the
# interrupt target. hooks ship under the system hook dir (libalpm
# prepends root+SYSHOOKDIR to the config's HookDir), so a PostTransaction
# hook fires on its own install
fixtures() {
	local d n
	# mkinitcpio/dkms-style: a shipped PostTransaction hook runs a
	# command in the chroot that regenerates a file from the targets
	d=$W/fx/twin-hook
	mkdir -p "$d/usr/share/libalpm/hooks" "$d/usr/share/twin-hook"
	echo payload > "$d/usr/share/twin-hook/data"
	cat > "$d/usr/share/libalpm/hooks/90-twin-hook.hook" <<'EOF'
[Trigger]
Operation = Install
Operation = Upgrade
Type = Package
Target = twin-hook

[Action]
Description = twin-root: regenerating image
When = PostTransaction
NeedsTargets
Exec = /usr/bin/bash -c 'echo "twin-hook fired for:"; cat; echo regenerated > /twin-initramfs.img'
EOF
	build_pkg twin-hook 1-1 "$d"

	# keyring stand-in (archlinux-keyring is a pacman dependency already
	# installed; a fixture avoids clobbering it and non-deterministic gpg
	# output): a PostTransaction hook runs a pacman-key-style populate
	d=$W/fx/twin-keyring
	mkdir -p "$d/usr/share/libalpm/hooks" "$d/usr/share/twin-keyring"
	echo keys > "$d/usr/share/twin-keyring/twin.gpg"
	cat > "$d/usr/share/libalpm/hooks/70-twin-keyring.hook" <<'EOF'
[Trigger]
Operation = Install
Operation = Upgrade
Type = Package
Target = twin-keyring

[Action]
Description = twin-root: appending keys from keyring
When = PostTransaction
Exec = /usr/bin/bash -c 'echo "==> Appending keys from twin.gpg..."; echo populated > /etc/pacman.d/twin-keyring.stamp'
EOF
	build_pkg twin-keyring 1-1 "$d"
	d=$W/fx/twin-extra
	mkdir -p "$d/usr/share/twin-extra"
	echo payload > "$d/usr/share/twin-extra/data"
	build_pkg twin-extra 1-1 "$d"

	# conflict pair: twin-cb conflicts with the installed twin-ca
	for n in twin-ca twin-cb; do
		d=$W/fx/$n
		mkdir -p "$d/usr/share/$n"
		echo payload > "$d/usr/share/$n/data"
		[ "$n" = twin-cb ] && echo 'conflict = twin-ca' \
			> "$d/.PKGINFO.extra"
		build_pkg "$n" 1-1 "$d"
	done

	# replaces pair: twin-new (served from the local repo) replaces the
	# installed twin-old on -Syu
	d=$W/fx/twin-old
	mkdir -p "$d/usr/share/twin-old"
	echo payload > "$d/usr/share/twin-old/data"
	build_pkg twin-old 1-1 "$d"
	d=$W/fx/twin-new
	mkdir -p "$d/usr/share/twin-new"
	echo payload > "$d/usr/share/twin-new/data"
	echo 'replaces = twin-old' > "$d/.PKGINFO.extra"
	build_pkg twin-new 2-1 "$d"

	# interrupt target: payload only; the pre-transaction block comes
	# from a pre-placed hook, not a shipped one
	d=$W/fx/twin-sig
	mkdir -p "$d/usr/share/twin-sig"
	echo payload > "$d/usr/share/twin-sig/data"
	build_pkg twin-sig 1-1 "$d"
}

# repo-add the local repo (its packages served from $REPO over file://)
repo_add() {
	capped env -i PATH=/usr/bin LC_ALL=C HOME="$W/home" \
		"$build/repo-add" "$REPO/twinrepo.db.tar.gz" "$@"
}

# write the same file into both roots with a pinned mtime, like edit();
# content on stdin, an optional chmod mode as $2
place_both() {
	local path=$1 mode=${2:-} side f d content
	content=$(cat)
	for side in c r; do
		f=$W/$side/root/$path
		mkdir -p "$(dirname "$f")"
		printf '%s\n' "$content" > "$f"
		[ -n "$mode" ] && chmod "$mode" "$f"
		touch -d @1700000000 "$f"
		# pin every dir the write just stamped, up to the root, so
		# both sides match: these stampings happen before the step
		# (outside its run window) and an interrupted run leaves them
		# untouched, so an unpinned per-side mtime would never mask
		d=$(dirname "$f")
		while [ "$d" != "$W/$side" ] && [ "$d" != / ]; do
			touch -d @1700000000 "$d"
			d=$(dirname "$d")
		done
	done
}

# write_repo_conf FILE: Arch defaults but only the local repo, unsigned,
# so the replaces case needs no network or keyring
write_repo_conf() {
	cat > "$1" <<EOF
[options]
RootDir = $CUR/root/
DBPath = $CUR/root/var/lib/pacman/
LogFile = $CUR/root/var/log/pacman.log
GPGDir = $CUR/gnupg/
HookDir = $CUR/root/etc/pacman.d/hooks/
CacheDir = $CUR/cache/
HoldPkg = pacman glibc
Architecture = auto
CheckSpace
SigLevel = Never
LocalFileSigLevel = Never

[twinrepo]
Server = file://$REPO
EOF
}

# write_arch_conf FILE DATE: the archive snapshot at DATE as core/extra;
# SigLevel Never keeps the across-time upgrade deterministic (old package
# signatures are a separate concern, covered by the signing difftests)
write_arch_conf() {
	cat > "$1" <<EOF
[options]
RootDir = $CUR/root/
DBPath = $CUR/root/var/lib/pacman/
LogFile = $CUR/root/var/log/pacman.log
GPGDir = $CUR/gnupg/
HookDir = $CUR/root/etc/pacman.d/hooks/
CacheDir = $CUR/cache/
HoldPkg = pacman glibc
Architecture = auto
CheckSpace
ParallelDownloads = 5
DownloadUser = alpm
SigLevel = Never
LocalFileSigLevel = Never

[core]
Server = https://archive.archlinux.org/repos/$2/core/os/\$arch

[extra]
Server = https://archive.archlinux.org/repos/$2/extra/os/\$arch
EOF
}

# interrupt runner (step_interrupt): a bg watcher waits for the chroot
# sentinel the pre-transaction hook writes, then SIGINTs the session; the
# foreground setsid -w run keeps the default SIGINT disposition (a bg job
# would have it ignored) and takes the signal with the whole group
run_interrupt() {
	local side=$1 out=$2 bin=$CPAC pf sent i l watcher
	shift 2
	[ "$side" = r ] && bin=$RPAC
	pf=$W/ipid-$side
	sent=$W/$side/root/.twin-started
	rm -f "$pf" "$sent"
	(
		for i in $(seq 1 1200); do
			[ -s "$pf" ] && [ -e "$sent" ] && break
			sleep 0.1
		done
		l=$(cat "$pf" 2>/dev/null)
		[ -n "$l" ] && kill -INT -- "-$l" 2>/dev/null
	) &
	watcher=$!
	setsid -w env -i PATH=/usr/bin LC_ALL=C TZ=Europe/Berlin \
		HOME="$W/home" TWIN_PIDFILE="$pf" \
		bash -c 'echo $$ > "$TWIN_PIDFILE"; ulimit -v 4194304
			exec -a pacman "$0" --config "'"$CONF"'" "$@"' \
		"$bin" "$@" < "$nul" > "$out/stdout" 2> "$out/stderr"
	echo $? > "$out/rc"
	kill "$watcher" 2>/dev/null
	wait "$watcher" 2>/dev/null
}

# step_interrupt NAME ARGS...: like step, but the run is interrupted by
# run_interrupt mid pre-transaction
step_interrupt() {
	local name=$1 dir side
	shift
	n=$((n + 1))
	dir=$STEPS/$(printf %02d $n)-$name
	mkdir -p "$dir"
	printf '%s\n' "--config $CONF $*" > "$dir/argv"
	for side in c r; do
		mkdir -p "$dir/$side"
		window "$side" "$(basename "$dir")" \
			with_side "$side" run_interrupt "$side" "$dir/$side" "$@"
	done
	if ! capped python3 -I "$repo/scripts/twin-compare.py" step "$dir" \
		"$W/c" "$W/r" "$prev"; then
		failed+=("$(basename "$dir")")
	fi
	prev=$dir
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
# the per-side cache dirs are made here (not copied c->r like the root),
# so their mtimes differ and fall outside every step window; pin them so
# the steps before the download phase compare them equal (a step writing
# into a cache re-stamps it within its own run window, masked)
touch -d @1700000000 "$W"/{c,r}/{cache,dlcache}
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
# the risky-case configs: local repo and the two archive snapshots
write_repo_conf "$TWINCONF"
write_arch_conf "$ARCHOLD" "$ARCH_OLD_DATE"
write_arch_conf "$ARCHNEW" "$ARCH_NEW_DATE"

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
# fixtures for the risky steps, plus the local repo (its package served
# from $REPO over file://)
fixtures || exit 1
mkdir -p "$REPO"
cp "$W/pkgs/twin-new-2-1-any.pkg.tar.zst" "$REPO/" || exit 1
repo_add "$REPO/twin-new-2-1-any.pkg.tar.zst" || exit 1
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

# --- risky real cases (PORTING.md handover "twin-root steps for risky
# real cases"): each a new step, compared like the rest ---

# mkinitcpio/dkms-style hook: a shipped PostTransaction hook runs a
# command in the chroot on install; compares its output and the file it
# regenerates
step hook-install $nul -U --noconfirm \
	"$W/pkgs/twin-hook-1-1-any.pkg.tar.zst"

# keyring refreshed in a multi-package transaction: the keyring stand-in
# ships a pacman-key-style populate hook, installed with another package
step keyring-txn $nul -U --noconfirm \
	"$W/pkgs/twin-keyring-1-1-any.pkg.tar.zst" \
	"$W/pkgs/twin-extra-1-1-any.pkg.tar.zst"

# replaces across an upgrade: twin-new (local repo) replaces the
# installed twin-old on -Syu (--noconfirm answers the replace question)
step replaces-install $nul -U --noconfirm \
	"$W/pkgs/twin-old-1-1-any.pkg.tar.zst"
conf=$TWINCONF step replaces $nul -Syu --noconfirm

# interactive conflict prompt, answered both ways: install twin-ca, then
# twin-cb (conflicts with twin-ca) declining then accepting the removal
step conflict-a $nul -U --noconfirm "$W/pkgs/twin-ca-1-1-any.pkg.tar.zst"
printf 'n\n' > "$W/conflict-no"
step conflict-no "$W/conflict-no" -U "$W/pkgs/twin-cb-1-1-any.pkg.tar.zst"
printf 'y\ny\n' > "$W/conflict-yes"
step conflict-yes "$W/conflict-yes" -U "$W/pkgs/twin-cb-1-1-any.pkg.tar.zst"

# -Syu across months of updates (Arch Linux Archive snapshots, both
# sides the same pinned mirrors): install an old tree, then upgrade from
# a newer snapshot. installed base is from the live mirror (newer than
# either snapshot), so -Syu only upgrades tree; the "local newer"
# warnings are identical on both sides
conf=$ARCHOLD step syu-old $nul -Sy --noconfirm tree
conf=$ARCHNEW step syu-new $nul -Syu --noconfirm

# interrupted commit: SIGINT the session during a pre-transaction hook
# (AbortOnFail, a deterministic edge before any extraction), then the
# recovery run. a true mid-extract SIGINT is left to the signal-edges
# note: the file the signal lands on differs between two binaries, so it
# cannot be gated byte for byte
place_both etc/pacman.d/hooks/00-twin-block.hook <<'EOF'
[Trigger]
Operation = Install
Type = Package
Target = twin-sig

[Action]
Description = twin-root: interruptible pre-transaction hook
When = PreTransaction
AbortOnFail
Exec = /usr/bin/bash /twin-block.sh
EOF
place_both twin-block.sh 0755 <<'EOF'
#!/usr/bin/bash
echo "twin-block: pre-transaction"
if [ ! -e /.twin-go ]; then
	: > /.twin-started
	sleep 60
fi
EOF
step_interrupt interrupt -U --noconfirm \
	"$W/pkgs/twin-sig-1-1-any.pkg.tar.zst"
place_both .twin-go </dev/null
step interrupt-recover $nul -U --noconfirm \
	"$W/pkgs/twin-sig-1-1-any.pkg.tar.zst"

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
