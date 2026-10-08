#!/usr/bin/env bash
# drop-in check of pacman-conf: upstream's scripts (the configured copies
# in PACMAN_BUILD) run against the C and the Rust pacman-conf, put first
# in PATH, on one fixture config; stdout, stderr and exit status compared
# per command. pacman-key and pacman-db-upgrade run whole, makepkg's
# call (inside run_pacman, behind sudo) runs as its one line. each run is
# capped like the test runner: 4 GiB address space, 60 s
# usage: scripts/pacman-conf-dropin.sh   (from the repo root, after
#        cargo build --release -p pacman-cli --bin puck-conf)

set -uo pipefail

# a unit worktree names the shared reference build in its cargo config
if [ -z "${PACMAN_BUILD:-}" ] && [ -f .cargo/config.toml ]; then
	PACMAN_BUILD=$(sed -n 's/^PACMAN_BUILD = "\(.*\)"$/\1/p' \
		.cargo/config.toml)
fi
build=${PACMAN_BUILD:-pacman/build}
rust=target/release/puck-conf
for f in "$build/pacman-conf" "$build/pacman-key" \
		"$build/pacman-db-upgrade" "$rust"; do
	if [ ! -x "$f" ]; then
		echo "missing $f" >&2
		exit 2
	fi
done

ulimit -v 4194304
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# both shims, then the fixture: a root with a local db, a keyring with
# one key and a file it signed
mkdir -p "$tmp/c" "$tmp/rs" "$tmp/root/db/local" "$tmp/gnupg"
ln -s "$(realpath "$build/pacman-conf")" "$tmp/c/pacman-conf"
ln -s "$(realpath "$rust")" "$tmp/rs/pacman-conf"
echo 9 > "$tmp/root/db/local/ALPM_DB_VERSION"
chmod 700 "$tmp/gnupg"
# an existing pubring.gpg keeps gpg on it instead of pubring.kbx:
# pacman-key's check_keyring reads pubring.gpg
touch "$tmp/gnupg/pubring.gpg"
gpg=(gpg --homedir "$tmp/gnupg" --batch --quiet --no-permission-warning)
"${gpg[@]}" --passphrase '' --quick-gen-key "Drop In <d@x.test>" \
	ed25519 sign never
echo data > "$tmp/data"
"${gpg[@]}" --detach-sign "$tmp/data"
# the first listing after key generation checks the trustdb and says
# so: done here, both sides then see the same keyring state
"${gpg[@]}" --check-trustdb
cat > "$tmp/pacman.conf" <<EOF
[options]
RootDir = $tmp/root
DBPath = $tmp/root/db/
GPGDir = $tmp/gnupg
Architecture = x86_64
[core]
Server = file:///srv/\$repo/\$arch
EOF
# no GPGDir: pacman-key falls back to pacman-conf's default
grep -v GPGDir "$tmp/pacman.conf" > "$tmp/nogpg.conf"
# no paths at all: dbpath follows --rootdir
printf '[options]\n' > "$tmp/nodb.conf"

# one command line through each shim, the fixture path shown as @
fail=0 n=0
compare() {
	local label=$1
	shift
	n=$((n + 1))
	for side in c rs; do
		PATH="$tmp/$side:/usr/bin:/bin" LC_ALL=C timeout 60 \
			"$@" > "$tmp/$side.out" 2> "$tmp/$side.err"
		echo $? > "$tmp/$side.rc"
		sed -i "s|$tmp|@|g" "$tmp/$side.out" "$tmp/$side.err"
	done
	if cmp -s "$tmp/c.rc" "$tmp/rs.rc" &&
			cmp -s "$tmp/c.out" "$tmp/rs.out" &&
			cmp -s "$tmp/c.err" "$tmp/rs.err"; then
		echo "equal  $label [$(cat "$tmp/c.rc")]"
		return
	fi
	fail=$((fail + 1))
	echo "DIFF   $label rc c=$(cat "$tmp/c.rc") rust=$(cat "$tmp/rs.rc")"
	diff "$tmp/c.out" "$tmp/rs.out"
	diff "$tmp/c.err" "$tmp/rs.err"
}

key=("$build/pacman-key" --config)
compare "pacman-key --list-keys" "${key[@]}" "$tmp/pacman.conf" --list-keys
compare "pacman-key --list-sigs" "${key[@]}" "$tmp/pacman.conf" --list-sigs
compare "pacman-key --finger" "${key[@]}" "$tmp/pacman.conf" --finger
compare "pacman-key --verify" "${key[@]}" "$tmp/pacman.conf" \
	--verify "$tmp/data.sig"
compare "pacman-key --init (non-root)" "${key[@]}" "$tmp/pacman.conf" --init
compare "pacman-key default gpgdir" "${key[@]}" "$tmp/nogpg.conf" --list-keys
compare "pacman-key missing config" "${key[@]}" "$tmp/nope.conf" --list-keys
compare "pacman-db-upgrade" "$build/pacman-db-upgrade" --nocolor \
	--config "$tmp/pacman.conf"
compare "pacman-db-upgrade -r" "$build/pacman-db-upgrade" --nocolor \
	--config "$tmp/nodb.conf" -r "$tmp/root"
compare "pacman-db-upgrade no db" "$build/pacman-db-upgrade" --nocolor \
	--config "$tmp/nodb.conf" -r "$tmp/nope"
# makepkg.sh.in run_pacman: the lock file path from the system config
compare "makepkg lockfile" bash -c \
	'lockfile="$(pacman-conf DBPath)/db.lck"; echo "$lockfile"'
# the completions' repo list
compare "completion --repo-list" pacman-conf --repo-list
compare "completion -c --repo-list" pacman-conf -c "$tmp/pacman.conf" \
	--repo-list

echo "$((n - fail))/$n identical"
[ "$fail" = 0 ]
