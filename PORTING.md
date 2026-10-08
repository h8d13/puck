# pacman-rust

Safe Rust port of pacman, file by file, checked against upstream C.

References (git submodules):
- `pacman/`: upstream pacman at `v7.1.0-18-ga6f7467d`, the C reference
- `alpm/`: official ALPM crates at `0eedcb8` (2026-10-03), used as
  dependencies where they already cover a pacman part (`METHODOLOGY.md`)

## Layout

- `alpm-core/`: port of `lib/libalpm`, `unsafe_code = "forbid"`
- `pacman-common/`: port of `src/common`
- `vercmp/`: port of `src/util/vercmp.c`
- `testpkg/`: port of `src/util/testpkg.c`
- `<crate>/tests/`: unit tests of the port, kept out of `src/`
- `difftest/`: equivalence tests, the one crate allowed to call C. It
  links upstream `libalpm_objlib.a` and `libcommon.a` statically, so
  internal (hidden) functions are comparable too. One module per C file.
- `scripts/cli-parity.sh`: stdout/stderr/exit diff of a C binary vs its port
- `scripts/cli-parity-fixtures.sh`: the milestone 1/2 gate, C `pacman` vs
  the Rust binary on generated worlds (difftest `cli_binary`)
- `scripts/pactest.sh <bin>`: upstream pactest (meson's list, args, xfail)
  on a binary
- `scripts/upstream-suite.sh [BINDIR]`: upstream's full meson suite (pactest,
  vercmptest, the two script tests) on a directory of binaries, the
  milestone 3 gate: exit 0 only at meson's 338 ok / 6 expected fail
  (`pacman/build` reproduces it)

Rules for every port unit: `METHODOLOGY.md`.

## Checks

```
# reference build (once, and after upstream pulls)
meson setup pacman/build pacman && ninja -C pacman/build

# unit tests, differential tests (PACMAN_BUILD overrides pacman/build)
cargo test --release
DIFFTEST_ITERS=5000000 cargo test --release -p difftest

# port crates free of test modules, C access and difftest
scripts/check-separation.sh
# one declaration per C symbol across difftest
scripts/check-externs.py
# vendor/alpm == alpm/ submodule + vendor/patches
scripts/vendor-alpm.sh --check

# upstream suites against the port
bash pacman/test/util/vercmptest.sh target/release/vercmp
scripts/cli-parity.sh pacman/build/vercmp target/release/vercmp \
	< scripts/vercmp.args
```

Upstream baseline (`meson test -C build`): 338 ok, 6 expected fail,
0 fail. Needs `fakechroot` and `fakeroot` installed (hooks, scriptlets,
ldconfig tests fail without them).

## Milestones

Each milestone ends in a binary-level gate against C pacman, on top of the
per-unit difftests.

### 1. Read-only queries

`-Q`, `-Qi`, `-Ql`, `-Qo`, `-Ss`, `-Si` on an existing local db and
already downloaded sync dbs.

| Part | State |
|---|---|
| version, deps strings, filelist, backup, xdata, error, util helpers, fnmatch | done |
| src/common (util-common, ini), frontend util.c display helpers | done |
| package model, pkghash, group | done |
| local db reader (`be_local.c`, owned desc/files reader) | done (reading side) |
| sync db reader (`be_sync.c`, owned desc/files reader, `alpm-compress`) | done (reading side) |
| pacman.conf (`conf.c`) | done (parsing, `setup_libalpm`, `register_repo`, XferCommand) |
| db layer and cache (`db.c`), handle (`handle.c`) | done (search, update, signature validation through the handle's keyring) |
| POSIX ERE for `-Ss`/`-Qs` (glibc regcomp/regexec, C.UTF-8) | done |
| `-Qk`/`-Qkk` (`check.c`) + local mtree reading (`alpm-core::mtree`, libarchive's reader) | done |
| argument parsing (`pacman.c` parseargs, glibc getopt_long) | done |
| frontend package display (`package.c`) | done |
| db search, `DbCaches` for `Handle`, `query.c` (-Q*), `deptest.c` (-T) | done |
| read-only `sync.c` (-Si, -Sl, -Sg) and `files.c` (-F, -Fl, -Fx) | done |
| `-Ss`, `setup_libalpm`, `callback.c`, main dispatch, `pacman` binary | done |
| `database.c` (-D, -Dk, -Dkk), db.c/backend log lines | done |

Gate: `scripts/cli-parity.sh` between C `pacman` and the Rust binary with
the same `--root`/`--dbpath`/`--config` on generated test roots and a
read-only copy of a real system db; byte-identical stdout, stderr, exit.
Now: `scripts/cli-parity-fixtures.sh` (-D runs under fakeroot with the
written db compared), 620/620 equal; pacman-conf 554/554; testpkg
binary 53/54 equal, 1 known (text file), testpkg module 550/550
(libarchive's texts cut after the path on both sides);
pacman-conf drop-in 13/13. On pacman, every run compares with the C's
GOTO_ERR lines (`got error <n> at <func> (<C file>: <line>)`) dropped
wherever they occur, and only those: they carry the C's source position
and are not logged by design (`is_goto_err` in `cli_binary.rs`).
**Gate met.**

### 2. Sync databases (`-Sy`)

| Part | State |
|---|---|
| downloads (`dload.c`): parallel, resume, mirrors, sandbox user | done (`reqwest`, sandbox helper wired into the Handle) |
| signature verification (`signing.c`) | done (`gpg` over `--status-fd`, argv checked against gpgme's; the Handle owns the keyring, sync dbs and packages validate through it) |
| db update/validation (`be_sync.c` writing side) | done (`alpm_db_update`, `-Sy`/`-Syy`/`-Fy` with progress bars, sandboxed) |

Gate: pactest sync/download tests against the Rust binary. `-Sy`/`-Syy`/
`-Fy` parity runs (fakeroot, `file://` mirror, fetched dbs compared) are
in the milestone 1 gate and equal. **Gate met**: every sync/download
pactest passes within the milestone 3 suite (master f46c525).

### 3. Transactions (`-S`, `-U`, `-R`)

| Part | State |
|---|---|
| package files (`be_package.c`: `.PKGINFO` and `.MTREE` readers owned, `alpm-compress`) | done (signatures: `.sig` and base64, every level) |
| deps resolution (`deps.c` rest + `graph.c`), `conflict.c`, `diskspace.c` | done |
| `hook.c`, scriptlets (`_alpm_runscriptlet`), `_alpm_run_chroot`, `_alpm_ldconfig` | done (on unified callbacks, take `&mut Handle`) |
| transaction prepare phase (`trans.c` model, `alpm_add/remove_pkg`, sysupgrade, sync/remove prepare, frontend prepare) | done |
| transaction commit phase (downloads, validation, add.c, remove.c, hooks, db writes) | done (`trans_commit`; frontend commits -S/-U/-R) |
| sandbox (landlock/seccomp, download helper) | done |
| local db writing | done |

Gate: upstream's full meson suite against the Rust binaries,
`scripts/upstream-suite.sh` (pactest's 341 tests, vercmptest and the two
script tests): meson's 338 ok / 6 expected fail, reproduced by
`pacman/build`. Progress: 135 ok (start of the owned readers) -> 203
(`.PKGINFO` reader, `-Sc`) -> 336 (local and sync db readers, master
18b884f) -> 337 (soft interrupt handler; unchanged by the owned mtree
reader) -> 338 ok / 6 xfail / 0 fail / 0 unexpected pass (dload
redirects without connection reuse), vercmptest and the script tests
included. **Gate met** on master f46c525: `scripts/upstream-suite.sh
target/release` exits 0.

### 3b. Real-system equivalence (rootless)

Twin roots, C vs Rust, real packages and mirrors in a user namespace
(METHODOLOGY.md "Integration gates"). Covers what pactest and fakeroot
do not: real package sets with hooks, scriptlets, capabilities and backup
files, real HTTPS mirrors, a real keyring, landlock and DownloadUser.

Gate: every step equal on `scripts/twin-root.sh`. State: harness done,
gate not met (diffs below, all owned or reported).

```
cargo build --release -p pacman-cli
scripts/twin-root.sh            # exit 0 only if every step is equal
scripts/twin-root.sh --keep     # keep .tmp/twin (steps/NN-*/report.txt)
scripts/twin-root.sh --clean    # remove a kept .tmp/twin
```

Setup (C only, then the Rust root starts as a copy): pacman-key keyring,
`-Syy`/`-Fyy` of core and extra, a `-Sw` prefetch of every package the
steps install (host cache hits skipped; the host cache itself is a read
only CacheDir). Steps, the same argv and env on both sides
(`LC_ALL=C`, `TZ=Europe/Berlin`); a diff carried from the step before
is counted, not repeated:

| Step | argv | Result (master 8ce1038) |
|---|---|---|
| sy | `-Sy` | log offset |
| download | `-Sw -dd which less iana-etc`, empty cache only | no new diff |
| base-filesystem | `-S filesystem` | no new diff |
| base-core | `-S glibc bash coreutils pacman` (112 packages, systemd, hooks) | optdepend markers, newuidmap/newgidmap caps |
| base-extra | `-S iputils less nano logrotate` | no new diff |
| qi | `-Qi pacman iputils` | Build Date zone |
| qii-backup / si | `-Qii nano`, `-Si iputils` | no new diff |
| reinstall-backup | edited `etc/pacman.conf`, `-S pacman` (kept, no .pacnew) | no new diff |
| local-install | `-U twin-backup-1-1` (unsigned local package) | no new diff |
| pacnew | edited backup file, `-U twin-backup-2-1` | no new diff |
| qii-pacnew | `-Qii twin-backup` | Build Date zone |
| pacsave | `-R twin-backup` | no new diff |
| downgrade | `-U` older `less` from the host cache | no new diff |
| rns-nosave | edited `etc/logrotate.conf`, `-Rns logrotate` | no new diff |
| qkk / dk | `-Qkk`, `-Dk` | no new diff |
| sc | `-Sc`, answers y y n n y | error text for download dirs |
| fy / f / fl | `-Fy`, `-F ping`, `-Fl iputils` | no new diff |

Diffs, latest run:
- pacman.log stamps: Rust UTC (+0000), C local (+0200); output unit.
  Normalised, the logs are equal.
- `security.capability` missing on usr/bin/newuidmap, newgidmap (shadow):
  fixed by the xattr unit (pax records and xattrs on extraction).
- optdepends after install/upgrade lack ` [installed]`/` [pending]`:
  `pacman-cli/src/callback.rs` runs with `Lookup for ()`, whose
  `installed()` (and `db_name()`, the provider list's repository
  headers) is still the pre-trans.c stub. Repro: `-S gzip` on a root
  with grep, C prints `grep: zegrep/... [installed]`. Needs the local
  db and the transaction's add list reachable from the callbacks
  (emitted in add.rs/remove.rs); open.
- `-Qi`/`-Qii` Build Date in UTC, C in local time (`package.rs`
  `format_date`): the log stamps' cause, no local zone; output unit.
- `-Sc` on a leftover `download-XXXXXX` dir: C logs libarchive's
  "Error reading fd 8", the port "Is a directory" (libarchive error
  texts are the port's, `be_package.rs` `open_archive`).

Harness choices: every pacman-visible path is under a tmpfs on /mnt
private to the session (DownloadUser alpm cannot traverse the 0700
home); a fixed etc/machine-id (systemd's scriptlet keeps it); content of
the java keystore and ldconfig's aux-cache not compared (dates, inode
numbers); `download-XXXXXX` names canonicalised. Runtime ~2-3 min warm
(network bound), ~620 MiB per root.

### 4. Drop-in

libalpm C ABI (`alpm.h`) exported from the Rust library so existing
front-ends (yay, paru via alpm.rs, pamac, pyalpm) keep working.

Gate: those front-ends' basic operations against the Rust libalpm.

## Owned readers (replacing ALPM parser patches)

ALPM's format parsers are spec-strict by design, pacman's readers are
lenient and byte based (METHODOLOGY.md). Bending the parsers with patches
grew a third of the series into whole pacman readers inside ALPM crates
that upstream will not take, and the typed values still could not hold
NULL/empty/bytes (pactest's sparse desc files and empty `.PKGINFO` values,
~200 tests). The readers are owned instead, translated from the C; the
reader patches and crate dependencies go once nothing uses them.

| Reader | C source | Owned in | Drops | State |
|---|---|---|---|---|
| local db desc/files | be_local.c `local_db_read`, READ_AND_STORE | `alpm-core::be_local` | 0201-0207, alpm-db | done |
| sync db desc/files | be_sync.c `sync_db_read`, `_alpm_archive_fgets` | `alpm-core::be_sync` | 0301-0305, alpm-repo-db | done |
| `.PKGINFO` | be_package.c `parse_descfile` | `alpm-core::be_package` | 0501-0506, alpm-pkginfo, alpm-package, alpm-buildinfo | done |
| `.MTREE` / local mtree | libarchive mtree reader (as pacman uses it) | `alpm-core::mtree` | 0401-0411, alpm-mtree | done |
| tar members (packages, sync dbs, `.INSTALL`) | libarchive `archive_read_support_format_tar.c` | `alpm-core::tar` | tar crate in alpm-core | done |
| alpm-types patches | port uses alpm-types only for `Checksum`/`digests::{Md5, Sha256}` (be_local, be_package, util); no patched type is used | - | 0101-0109 removed (0101, 0102, 0105-0107 kept as upstream reports); alpm-types itself if checksums go to md-5/sha2 directly | patches done; crate todo |

Kept and to report upstream: 0551 (gzip members), 0552 (content
sniffing), and real ALPM bugs whose patch is no longer applied, kept as
text in `vendor/upstream-reports/` (0101/0102 version ordering against
pacman's vercmp, 0105 `Unknown Packager`, 0106 relation backtracking,
0107 empty xdata value; alpm-mtree's 0401 `PathType` `PartialEq`, 0403
gzip members, 0411 `Error::Parse` display). UPSTREAM.md "ALPM findings" describes each.

## Dependencies

What the port links today and why. Changes land here with the unit that
makes them; METHODOLOGY.md has the rules.

| Crate | Used by | Why | Since |
|---|---|---|---|
| alpm-compress (vendored, 0551-0553) | util `Filter`, be_sync, be_local, add, mtree | the decoders (gzip/bzip2/xz/zstd) under libarchive's block filter | start |
| alpm-types (vendored, no patches) | be_local, be_package, util, difftest | `Checksum` md5/sha256 only | start; 0101-0109 dropped |
| alpm-parsers (vendored) | none directly | dependency of alpm-types | start |
| tar 0.4 | workspace table only, for alpm-compress | alpm-core reads tar with `alpm-core::tar` (libarchive's reader) | compress unit; dropped from alpm-core by the xattr unit |
| reqwest 0.13 blocking, rustls | dload | HTTP downloads (ALPM dev-scripts precedent) | dload unit |
| rustix 1.1 (`fs`, `process`, `termios`, `net`; `use-libc`) | util, diskspace, lock, sandbox, frontend util | statvfs, access, umask, getuid/geteuid, fchdir, tty width, tcflush, SCM_RIGHTS to the exec helper; fsetxattr/lsetxattr, utimensat with ns (`fs`) | handle unit, process unit, xattr unit |
| landlock 0.4, libseccomp 0.4 | sandbox | `alpm_sandbox_setup_child` | sandbox unit |
| signal-hook 0.4 (+ signal-hook-registry) | pacman-cli sighandler | SIGINT/SIGHUP soft interrupt (no safe handler API in std/rustix, none in ALPM; tokio's signals use the same registry) | signals unit |
| md-5, sha2, base64, time, unicode-width | through alpm-types / directly | precedent crates of ALPM | start |

Removed, with their patches: alpm-db (0201-0207), alpm-repo-db
(0301-0305), alpm-pkginfo (0501-0506), alpm-package, alpm-buildinfo,
alpm-mtree (0402, 0404-0410) and alpm-common (only its dependency).
The vendored tree went from 10 crates / 40 patches to 3 / 3; alpm-types
patches 0101-0109 dropped (no patched type left in use), five kept as
upstream reports, alpm-mtree's 0401, 0403, 0411 too.

## ALPM patches for parity

Ranges: 055x alpm-compress (01xx alpm-types, 02xx alpm-db, 03xx
alpm-repo-db, 04xx alpm-mtree and 05xx alpm-pkginfo gone: owned readers,
unused types). The reader patches
below leave with their owned reader (table above); new patches are real
ALPM bugs only. pacman bugs in `UPSTREAM.md` are not copied.

| Crate | Divergence to correct | Seen on real data | State |
|---|---|---|---|
| alpm-compress | `GzDecoder` reads one member (libarchive: all) | no | 0551 |
| alpm-compress | no content sniffing (the port duplicates it in be_sync and be_package) | `.db` files have no extension | 0552 (`from_magic`) |
| alpm-compress | `CompressionDecoder` decodes a `File` only; `.MTREE` data sits in memory | every package with an `.MTREE` | 0553 (`from_reader`, `get_ref`) |
| alpm-compress | truncated stream: libarchive fails the whole 64/128 KiB filter block the cut lands in (at open inside the first one), the decoders fail at the cut | rare (`-U` on a truncated download) | done in the port, no patch: every decoder fails every cut (UnexpectedEof); `util::Filter` redoes libarchive's blocks |
| alpm-compress | gzip-in-gzip, lz4, lzma archives and `.MTREE` streams | no (makepkg writes gzip) | open |
| all | non-UTF-8 text refused (pacman is byte based) | no | done: db, `.PKGINFO` and mtree readers owned (bytes) |

## Precedent audit

Hand-written parts checked against ALPM and the crates it depends on.

| Hand-written | Precedent | Verdict |
|---|---|---|
| `alpm-core::base64` | `base64` crate | done: crate decodes; base64.c framing and signing.c 3/4 check kept |
| `be_package` reader instead of alpm-package `PackageReader` | alpm-package | kept: needs a valid `PackageFileName` (pacman takes any name), parses `.BUILDINFO`, reads `.INSTALL` as String, iterator drops data entries; `.PKGINFO` read like parse_descfile (alpm-pkginfo validates the spec), `.MTREE` by `alpm-core::mtree`, uses alpm-compress; alpm-package dropped |
| `alpm-core::tar` instead of the tar crate | tar | kept: libarchive's pax semantics (binary values with '\n', last record wins, a warning ends pacman's loops, hdrcharset, ACL records setting the mode, GNU/Sun sparse maps), its framing (types without data, hard link sizes, checksums) and read-ahead blocks; the crate has none of these. entry mode/size come from it (be_package's own rules gone) |
| `util::Filter` + `tar::Reader` instead of alpm-compress `TarballReader` | alpm-compress | kept: libarchive's block-wise filter output sits between decoder and tar reader, `TarballReader` only wraps a `CompressionDecoder` |
| `pacman-cli::package::format_date_utc` | `time` crate | done: time does the calendar; `%c` field layout is a format! (no `formatting` feature) |
| glibc wcwidth table in `pacman-cli::util` | `unicode-width` | done: unicode-width, glibc -1 mapping |
| generated glibc class/towupper tables in `alpm-core::regex` | std `char` Unicode methods | done: std classes, `to_uppercase` when single-char; divergence counted (`class_divergence`, `towupper_divergence`) |
| `dload` http_date/parse_http_date + civil date | `time` crate | open: switch formatting, keep RFC 850/asctime parsing time lacks |
| `pacman-cli::getopt` | clap (ALPM CLIs) | kept: ops are combinable short flags anywhere (`-yS`, `pkg -S`), letters change meaning per op (two-pass parse), glibc error texts and ambiguity list, permuted argv/optind, POSIXLY_CORRECT; clap offers none of these |
| `backup::split_backup`, `package::parse_xdata` | `alpm-db`, alpm-types `ExtraData` | translated again for the owned db readers (bytes, NULL hash, the C's '=' split) |
| md5/sha256 | `md-5`, `sha2` | uses the crates |
| `version::vercmp`, `deps::dep_from_string` | alpm-types versions/relations | kept: ALPM takes validated values only, pacman compares/parses arbitrary strings (CLI, `vercmp`, -T); alpm-types' versions are no longer used anywhere |
| `pacman-common::ini` | alpm-parsers `custom_ini` | kept: `key=value` only, no sections/Include |
| `be_sync` compression sniffing | `alpm-compress` | done: `from_magic` (patch 0552), one `util::open_archive` for be_sync, be_package and unpack |
| `mtree::bid_filter` | alpm-compress `from_magic` (0552) | kept: libarchive's bidders check more than magic bytes (gzip header walk, bzip2 block magic, 8-byte zstd), a header they refuse is read raw (equal log texts on broken `.MTREE`); archives still use `from_magic` |
| `util::fnmatch`, `regex`, getopt, conf glob | none (ALPM CLIs use clap, no getopt_long semantics) | kept |

## ALPM overlap

| pacman part | ALPM crate | Plan |
|---|---|---|
| `version.c` vercmp | `alpm-types` version comparison | translated (pacman compares arbitrary strings) |
| `deps.c` dep strings | `alpm-types` relations | translated |
| xdata, base64, checksums | `alpm-types` (`ExtraData`, base64, md-5/sha2) | xdata translated with the readers; base64 crate; checksums via alpm-types `Checksum` |
| `be_local.c` desc/files | `alpm-db` | done: owned reader translated from the C, alpm-db dropped |
| `be_sync.c` | `alpm-repo-db` | done: owned reader translated from the C, alpm-repo-db dropped |
| `be_package.c` | `alpm-package`, `alpm-compress`, `alpm-pkginfo`, `alpm-mtree` | alpm-compress decoders; `.PKGINFO` and mtree readers translated (done) |
| filelist, pkghash, deps resolution, transactions, hooks, frontend | none | translate |

## Status

29576 lines of C (no symlinks). Complete: `version.c`, `vercmp.c`,
`base64.c`, `testpkg.c`, `pacman-conf.c`. Partial files list their ported functions.

| C file | Lines | Rust | Checked by |
|---|---|---|---|
| `lib/libalpm/version.c` | 260 | `alpm-core::version` | difftest fuzz, vercmptest 92/92 |
| `src/util/vercmp.c` | 63 | `vercmp` | vercmptest 92/92, cli-parity |
| `lib/libalpm/alpm_list.c` | 650 | - | replaced by `Vec`, no port |
| `lib/libalpm/rawstr.c` | 135 | - | no callers, not ported |
| `lib/libalpm/base64.c` | 196 | `alpm-core::base64` | via `base64` crate + base64.c framing: difftest by input class via `alpm_decode_signature` |
| `lib/libalpm/util.c` | 1657 | `alpm-core::util` (partial) | strip_newline, get_fullpath, hash_sdbm, strtoofft, parsedate, splitname, fnmatch, fnmatch_patterns: difftest fuzz; makepath(_mode), copyfile, read_file, files_in_directory: difftest fs fuzz (tree snapshots); compute_md5sum/sha256sum, test_checksum via alpm-types `Checksum`: difftest on temp files; realloc/greedy_grow replaced by Vec; open_archive (from_magic, `Filter`: libarchive's filter blocks and open read-ahead), unpack/unpack_single (archive_read_extract translation, logs through Callbacks): difftest `unpack` (trees, rc, pm_errno, log lines, libarchive texts cut; compressed archives cut at ~70 points per filter) |
| `lib/libalpm/pkghash.c` | 351 | `alpm-core::pkghash` | add, add_sorted, remove, find, growth: difftest sequence fuzz, bucket layout and list order compared every step; find_mut/iter_mut: unit tests, difftest through db |
| `lib/libalpm/filelist.c` | 147 | `alpm-core::filelist` | sort, contains, difference, intersection: difftest fuzz |
| `lib/libalpm/backup.c` | 100 | `alpm-core::backup` | backup_dup, needbackup: difftest fuzz; split_backup: difftest through the local db reader |
| `lib/libalpm/group.c` | 51 | `alpm-core::group` | difftest |
| `lib/libalpm/error.c` | 166 | `alpm-core::error` | strerror, all 56 values + out of range: difftest; alpm_errno waits for handle |
| `lib/libalpm/log.c` | 112 | - | |
| `lib/libalpm/package.c` | 868 | `alpm-core::package` (partial) | data model (`Package`, `PkgFrom`, `PkgReason`), dup, pkg_cmp, compare_versions, find, compute_requiredby/optionalfor (`DbCaches`), should_ignore (fixture handles + mirror fuzz): difftest via `#[repr(C)]` mirror (offsets checked through the C getters); handle/db/archive parts pending |
| `lib/libalpm/be_package.c` | 778 | `alpm-core::be_package` (partial) | pkg_load_internal (full and metadata-only walk, parse_descfile with _alpm_archive_fgets, .MTREE via `alpm-core::mtree` with archive fallback and its debug lines, file list, check_meta), pkg_load/pkg_validate at every level (.sig, base64 sig, sha256 skip), key import question, changelog, the C's load/validate log lines (not libarchive's texts): difftest on generated packages (gz/bz2/xz/zst/none, full on/off, every field + changelog + log lines + pm_errno), random-line `.PKGINFO` fuzz (every key, empty/blank values, separators, comments, duplicates, CRLF, nul/non-UTF-8 bytes, odd relations and numbers), nul bytes at data block ends, 512 KiB lines, ~140 pinned odd inputs all equal, fuzzed `.MTREE` text in every compression and cut `.MTREE` streams (lists, scriptlet, mtree log lines with libarchive's texts), real cached packages (`DIFFTEST_PKG_CORPUS`, 2559 files equal); gpgme/.sig pending |
| `lib/libalpm/be_local.c` | 1232 | `alpm-core::be_local` (partial) | register/validate (ALPM_DB_VERSION, creation), populate (check_meta lines), local_db_read (safe_fgets lines, READ_* macros, every section, INFRQ levels, log lines): difftest on byte-generated dbs (any sections in any order, unknown/repeated keys, blank lines, CRLF, nul bytes, non-UTF-8, lines over 1023 bytes, odd relations/reasons/validations, cut files; every field, cache order and counts, every log line), version-file fuzz, 100 pinned odd inputs, /var/lib/pacman read-only; local_db_prepare/write/remove, set_reason: difftest `be_local_write` (written trees byte for byte, modes, rc); mtree (`_cache_mtree_*` through `alpm-core::mtree`): difftest `check`; changelog pending; mtree open failures logged with libarchive's file reader texts (difftest `query`) |
| `lib/libalpm/be_sync.c` | 762 | `alpm-core::be_sync` (partial) | populate (tar walk past bad entries, load_pkg_for_entry, check_meta, validate_filename, error ranking), sync_db_read (`_alpm_archive_fgets` over libarchive's data blocks, READ_* macros, %FILES%, %DATA%, log lines), get_validation, db_path, sync_db_validate (missing file, signature, import retry) + `alpm-compress`: difftest on generated .db/.files in gz/bz2/xz/zst/none changed byte by byte (fields, cache order, table counts, pm_errno, log lines), block edges per filter, 54 pinned odd inputs, real sync db copies compared whole; alpm_db_update + get_sync_dir: difftest vs C on loopback mirrors with gpg-signed fixture dbs (sequences, edges, signatures, fuzz) |
| `lib/libalpm/db.c` | 773 | `alpm-core::db` (partial) | register/unregister, servers (sanitize_url), usage, siglevel, get_valid, pkgcache/get_pkg, groupcache/get_group (load_grpcache order), add/remove pkg in cache, load_pkg (lazy loads in place), dbext read at load, db_path, db_cmp: difftest op-sequence fuzz (results, errno, db state each step); search (difftest fuzz), load_all/walk/find_satisfier; log lines (db.c, be_local populate/read, be_sync populate): the op fuzz compares every line of each op and of the release; update pending |
| `lib/libalpm/log.c` | 112 | `alpm-core::log` | logaction (logfile, errno), leader format, syslog packet, local time (`local_offset`): difftest, stamps compared within `CLOCK_SLACK`, tz-probe against localtime(3) in 16 zones (DST edges by bisection), the binaries in 6 zones (`cli_binary` local_time) |
| `lib/libalpm/handle.c` | 1017 | `alpm-core::handle` (all but trans) | options, lock, logfile, callbacks, keyring, dload state: difftest option fuzz, lock, logaction; earlier: | alpm_initialize path checks/normalisation, dbext, architectures, siglevels, ignore/noupgrade/noextract lists + match: difftest; callbacks, lock, cachedirs, hookdirs, gpgdir, logfile, sandbox, downloads pending |
| `lib/libalpm/alpm.c` | 132 | - | |
| `lib/libalpm/signing.c` | 1201 | `alpm-core::signing` | decode_signature, checksig (.sig and base64), check_pgp_helper, process_siglist, key_in_keychain, key_import (keyring/question part; WKD/keyserver failure only), pkg/db_check_pgp_signature, extract_keyid, every `_alpm_log` line (debug included, `_alpm_access`'s via `util::alpm_access`): difftest vs gpgme-backed C on throwaway keyrings (all status/validity pairs, bad/garbage/truncated/armored sigs), results, rc, pm_errno, questions, logs at every level; init_gpgme's lines (`signing_init`); gpg_strerror's table vs gpgme_strerror for every code; gpg argv vs gpgme's; extract_keyid fuzz |
| `lib/libalpm/dload.c` | 1474 | `alpm-core::dload` (partial) | _alpm_download (reqwest, fetchcb path), resume/mirrors/cache servers/server error counting/.sig/max size/time condition, alpm_fetch_pkgurl, download dir + filecache helpers: difftest vs C on scripted 127.0.0.1 HTTP servers and file://; sandbox child behind `Sandbox`: fetch_pkgurl cases and db_update sequences sandboxed vs the C, the binaries under fakeroot with DownloadUser (`cli_binary` xfercommand) |
| `lib/libalpm/deps.c` | 926 | `alpm-core::deps` (partial) | dep_from_string, dep_compute_string, depcmp_provides (+ static dep_vercmp through it), depcmp_literal, depcmp, find_satisfier, checkdeps, sortbydeps, resolvedep/resolvedeps, find_dbs_satisfier, recursedeps: difftest on fixture handles (local + 3 sync dbs, ignore, assumeinstalled, NODEPVERSION, usage), questions/logs compared |
| `lib/libalpm/graph.c` | 38 | `alpm-core::graph` | via sortbydeps |
| `lib/libalpm/conflict.c` | 686 | `alpm-core::conflict` | innerconflicts, outerconflicts, checkconflicts, db_find_fileconflicts (both checks, skip_remove, progress, debug lines): difftest on fixture roots (files, dirs, symlinks) and local dbs, 2M fuzz |
| `lib/libalpm/diskspace.c` | 514 | `alpm-core::diskspace` | check_diskspace, check_downloadspace (+ mount list, fsinfo, match, sizes, check_mountpoint): difftest on fixture roots and root "/" (every log/progress line, f_bavail pinned from the C trace); getmntent parser vs glibc |
| `lib/libalpm/trans.c` | 452 | `alpm-core::trans` | alpm_trans_commit (state checks, hooks, log lines, events, remove/sync dispatch, interrupted, Committed): difftest `trans_commit`, hooks for real under fakechroot (Package/Path triggers per operation, NeedsTargets, Exec arguments, Depends before/after the install, AbortOnFail, reused and invalid sections, masking, ordering, output lines, NOHOOKS/DBONLY, fuzz); model, init/release/interrupt/getters, prepare dispatch, check_arch, sort: difftest `trans_prep` op sequences vs C (2000 cases, results, data lists, logs, events, questions, trans afterwards); _alpm_runscriptlet + grep: difftest under fakechroot |
| `lib/libalpm/sync.c` | 1360 | `alpm-core::sync` | `_alpm_sync_load` (download_files, check_keyring, check_validity, load_packages, prompt_to_delete), `_alpm_sync_check`, `_alpm_sync_commit`: difftest `trans_commit` vs C alpm_trans_commit on fixture worlds with a file:// mirror (installs, upgrades, cached, -U, DOWNLOADONLY, DBONLY, NODEPS, bad checksums, db/file mismatch, CORRUPTED_PKG yes/no, missing on the mirror, file conflicts, download space, replaces/conflicts removed; rc, pm_errno, data list, state, logs, events, questions, progress, download events, logfile, root, local db, cache), 2000-case fuzz; signed packages on a GpgFixture keyring (package Never/Required/Optional x TrustedOnly/TrustAll; trusted, marginal, unknown, revoked, other-data and garbage signatures; .sig on the mirror, in the cache, unreadable, %PGPSIG%; check_keyring's import question for a missing key, CORRUPTED_PKG for INVALID_SIG, a bad and a good package together); get_new_version, sysupgrade (literal, replacers), find_group_pkgs, compute_download_size, `_alpm_sync_prepare`, dbs_satisfier: difftest `trans_prep` |
| `lib/libalpm/add.c` | 718 | `alpm-core::add` | `_alpm_upgrade_packages` (`upgrade_packages`): difftest `trans_commit`; alpm_add_pkg: difftest `trans_prep`; commit_single_pkg with extract_single_file, extract_db_file, perform_extraction (archive_write_disk with OWNER/PERM/TIME/UNLINK/SECURE_SYMLINKS), try_rename, get_install_time, and the per-package step of `_alpm_upgrade_packages`: difftest `add_commit` vs C `_alpm_upgrade_packages` on one-package transactions (backup md5 states, .pacnew, NoUpgrade/NoExtract, dir/file/symlink changes, modes, SUID/SGID, root-owned entries, hard links, db files, DBONLY, reasons, truncated packages, SOURCE_DATE_EPOCH children, pax records (names, ns times, ids, xattrs, ACLs, sparse maps, malformed; fuzz), a fakeroot run for security.capability and ids incl. real packages; trees with archive times to the ns, owners, xattrs, local db, logs, events, progress, logfile, rc, pm_errno), scriptlets under fakechroot, 2M fuzz |
| `lib/libalpm/remove.c` | 798 | `alpm-core::remove` | `_alpm_remove_packages` (`remove_packages`): difftest `trans_commit`; alpm_remove_pkg, `_alpm_remove_prepare` (cascade, recurse, unneeded, optdepend events): difftest `trans_prep`; `_alpm_remove_single_package` with can_remove_file, shift_pacsave, unlink_file, should_skip_file, remove_package_files, dir_is_mountpoint: difftest `remove_commit` on fixture roots and local dbs (files, dirs, symlinks, /proc mountpoint, read-only dirs, .pacsave rotations, other owners, NoUpgrade, skip_remove, NOSAVE/DBONLY/NOSCRIPTLET, upgrade path; trees, local db, cache, logs, events, progress, logfile, pm_errno), scriptlets under fakechroot, 2M fuzz |
| `lib/libalpm/hook.c` | 679 | `alpm-core::hook` | parse/validate, dir scan and masking, triggers, Depends, AbortOnFail, NeedsTargets, run: difftest fuzz on root "/" and runs under fakechroot |
| `lib/libalpm/sandbox*.c` | 608 | `alpm-core::{sandbox,sandbox_fs,sandbox_syscalls}` | restrict_writes_to (8 variants incl. injected landlock failures), syscalls_filter (list parsed from the C, raw syscall probes): errno per probe in spawned children vs C; callback pipe writer + parent loop: byte-stream fuzz; helper download vs C _alpm_download; uid switch: unit tests (root); exec mode (XferCommand): `cli_binary` vs the C binary under fakeroot |
| regcomp/regexec (glibc, used by db.c, remove.c, files.c) | - | `alpm-core::regex` | difftest fuzz vs glibc (C.UTF-8, 4 flag sets) on agreeing characters; classes/towupper via std, divergence per class counted |
| `src/common/*.c` | 445 | `pacman-common::{util_common,ini}` | all of util-common.c and ini.c: difftest fuzz (safe_fgets on fmemopen + real file, llstat on /tmp tree, ini via recorded callback) |
| `src/pacman/*.c` | 10124 | - | excl. symlinks into `src/common` |
| `src/pacman/pacman.c` (in the above) | 1360 | `pacman-cli::{pacman,getopt}` (partial) | getopt_long: difftest per call vs libc (2M fuzz); parseargs, parsearg_*, checkargs_*, usage, version, needs_root, '-' stdin targets, main, cleanup, exit status, dispatch (-Q/-S/-R/-U/-F/-T, transactions up to the commit): difftest `cli_binary` vs the C binary (stdout/stderr/exit), parsed Config unit-tested; signals: soft interrupt handler installed in main, handle published after setup, removed in cleanup before the release: difftest `sighandler` |
| `src/pacman/sighandler.c` (in the above) | 146 | `pacman-cli::sighandler` (partial: no segv, winch handler) | soft_interrupt_handler, install/remove: difftest `sighandler` vs the C binary (SIGINT/SIGHUP before the handle, at a prepared transaction's prompt, from Pre/PostTransaction hooks, post_install, pre_remove; exit status, stdout, stderr, root tree, log) |
| `src/pacman/callback.c` (in the above) | 1155 | `pacman-cli::callback` | cb_event, cb_question, cb_progress (ILoveCandy), cb_download (multibar, total bar), cb_log (delayed under bars): difftest lockstep vs C (every event x 16 configs, 11 questions x 12 configs x 27 inputs, progress/download fuzz, fake coarse clock) |
| `src/pacman/check.c` (in the above) | 435 | `pacman-cli::check` | check_pkg_fast/full: difftest on fixture roots and dbs (all 22 message kinds); libarchive's mtree reader vs `alpm-core::mtree` (entries, stop, error text) per fixture, ~100 odd inputs, cut streams, fuzzed text (no signature, form D, nul, continuations, devices) and 804 real mtrees all equal |
| `src/pacman/query.c` (in the above) | 521 | `pacman-cli::query` | every -Q mode, filter and message: difftest vs C pacman_query on fixture roots, both with the frontend's log callback and stderr compared as one stream (op and libalpm lines in order, debug and function levels), desc/files/mtree missing or unreadable, empty/garbage/directory mtrees, -Qt load order on fresh worlds |
| `src/pacman/deptest.c` (in the above) | 57 | `pacman-cli::deptest` | difftest vs C pacman_deptest |
| `src/pacman/sync.c` (in the above) | 978 | `pacman-cli::sync` (partial) | sync_info, sync_list, sync_group, dispatch, check_syncdbs: difftest vs C pacman_sync (4 db states, warm caches); -Sy/-Syy: difftest vs C pacman_sync with the frontend callbacks (no bars); sync_trans/sync_prepare_execute: difftest `frontend_fuzz` (C never commits: --print or a declined question), the commit and its failure report through pactest; -Sc/-Scc (sync_cleancache, sync_cleandb_all, unlink_verbose under trans_init(0,0)): difftest `sync_clean` vs C pacman_sync with op_s_clean on seeded twin worlds (answers x -c/-cc/-ccc x CleanMethods x lock; rc, stdout, stderr, input read, tree with modes), PATH_MAX edges, cli_binary -Sc/-Scc under fakeroot |
| `src/pacman/remove.c`, `upgrade.c` | 309 | `pacman-cli::{remove,upgrade}` | difftest `frontend_fuzz` vs C pacman_remove/pacman_upgrade (rc, stdout, stderr, input consumed); -U url fetch wired, untested (network) |
| `src/pacman/database.c` (in the above) | 305 | `pacman-cli::database` | -D --asdeps/--asexplicit, -Dk, -Dkk: difftest vs C pacman_database on two copies of each fixture (ret, stdout, stderr, local db tree after), -Dkk on sync worlds; unit tests |
| `src/pacman/files.c` (in the above) | 341 | `pacman-cli::files` | -F, -Fx, -Fq, --machinereadable, -Fl: difftest vs C pacman_files on .files dbs; -Fy: same, with the frontend callbacks |
| `src/pacman/package.c` (in the above) | 587 | `pacman-cli::package` | dump_pkg_full (all origins, -i/-ii), dump_pkg_backups, dump_pkg_files, print_installed, print_groups, dump_pkg_search: difftest on a real C handle with refilled db caches and real files under the root, strftime %c vs `format_date_utc` fuzz + localtime limits; changelog and gpgme results: unit tests |
| `src/pacman/conf.c` (in the above) | 1468 | `pacman-cli::conf` (partial) | config model, parseconfigfile, setdefaults (include, siglevel, cleanmethod, usage, repeating options, $repo/$arch, sysroot), glob(3) subset: difftest on random config trees (return, stderr, whole config_t), glob vs libc; setup_libalpm, register_repo: difftest reading the handle back through every getter; XferCommand (download_with_xfercommand, systemvp): `cli_binary` xfercommand, C vs Rust binaries on loopback and file:// mirrors with fixture commands |
| `src/pacman/util.c` (in the above) | 1981 | `pacman-cli::util` (partial: all but trans_init/release, sync_syncdbs) | display_targets + table engine, print_packages (--print-format), optdepends lists, select/multiselect/yesno prompts (stdin via fmemopen), rmrf, rmrf_errno (the errno sync_cleandb prints): difftest; earlier helpers: | indentprint, strreplace, string_display, list_display(_linebreak), signature_display, humanize_size, arg_to_string, console cursor helpers: difftest fuzz; getcols (TIOCGWINSZ) and flush_term_input: tty-probe on a pty vs C; glibc mbstowcs: difftest; wcwidth via unicode-width, divergence per class counted, display difftests on agreeing characters |
| `src/util/testpkg.c` | 103 | `testpkg` | whole file (config.h paths and the siglevel as `Setup`): difftest `testpkg` binary vs C on generated packages (5 compressions, truncated, garbage, no/bad .PKGINFO, empty/junk .sig, unreadable, directory, missing, usage) and the gpg fixture's signed files against the system keyring; `run` vs the C load on a fixture handle at 9 package siglevels and 3 keyrings, signed and unsigned. Known: a text file (libarchive's mtree bidder reads it, "Package is invalid."; be_package refuses to open it, "Cannot open"), be_package's pinned "text file" |
| `src/pacman/pacman-conf.c` | 481 | `pacman-cli::pacman_conf`, `pacman-conf` binary | whole file on conf.rs parseconfigfile + setdefaults: difftest `pacman_conf` binary vs C (every option, every directive by case/quoting, [options] and repo dumps, --repo-list, includes, sysroot, -R, missing files, bad options, POSIXLY_CORRECT; conf generator trees with random command lines); `scripts/pacman-conf-dropin.sh`: pacman-key, pacman-db-upgrade, makepkg's lockfile line and the completions' --repo-list against both binaries. Not modelled: strdup out of memory, stdout/stderr interleaving on a terminal (stderr written first, as with pipes) |

Not ported, kept as upstream ships them: makepkg and libmakepkg,
repo-add/repo-remove, pacman-key, pacman-db-upgrade, the wrapper (bash)
and makepkg-template (Perl). They call `pacman` and `pacman-conf` as
binaries, so they double as a drop-in check: `makepkg -s`/`-i`,
`pacman-key --init`/`--populate` and `repo-add` against the Rust binaries.

## Notes

- `vercmp` works on bytes: C `ctype` runs in the C locale, so ASCII
  predicates match and bytes >= 0x80 count as separators. Input is cut at
  the first nul like a C string.
- NULL handling of `alpm_pkg_vercmp` is pinned in `difftest`
  (`c_null_contract`) for the future C ABI shim.
- `_alpm_hash_sdbm` sums plain `char`: signed on x86_64, unsigned on
  aarch64. Port uses `c_char` so hashes match per platform.
- `_alpm_strtoofft` returns `off_t`: port returns `Option<u64>`, the
  future C ABI shim maps `None` to -1 and casts.
- `_alpm_str_cmp` not ported, byte slices already order like `strcmp`.
- `alpm_dep_from_string`: first ": " starts the description (bare ':' is
  an epoch). Operator found by priority, not position: any '<', then '>',
  then '=' ("a>1<2" is name "a>1", LT "2"). "a=" gives version `Some("")`.
- `alpm_depend_t.mod` is `Depend::depmod` (`mod` is a keyword).
  `dep_vercmp` takes `Option` versions, `None` sorts first like
  `alpm_pkg_vercmp(NULL, ..)`. `depcmp_provides` checks `name_hash` before
  names like the C.
- `_alpm_split_backup` splits at the first tab (later tabs stay in the
  hash), no tab gives hash `None`. `_alpm_pkg_parse_xdata` splits at the
  first '=', empty name/value accepted.
- filelist `sort`/`contains`/`difference` order like `strcmp` (unsigned).
  `sort` is stable, so equal names get a fixed order where qsort leaves it
  unspecified; difftest compares names only. `_alpm_filelist_pathcmp`
  ("usr" == "usr/") compares plain `char`, port uses `c_char` so
  `intersection` matches per platform. Empty names count as files.
- `difference`/`intersection` return names borrowed from `self`, like the
  C list that does not own its strings.
- `alpm_strerror`: out of range and `ALPM_ERR_OK` give "unexpected
  error" like the C. difftest runs without `setlocale`, so gettext returns
  the msgid.
- `safe_fgets(size)`: one `fgets` per call, at most size-1 bytes, stops
  after a kept '\n'. Long lines come back in chunks (1023 bytes for
  be_local's 1024 buffer, 4095 for ini's PATH_MAX). NUL bytes returned raw,
  C callers see up to the first NUL. EINTR retry maps to
  `ErrorKind::Interrupted`.
- C-locale `isspace` is " \t\n\v\f\r": local `is_space`, since
  `is_ascii_whitespace` leaves out '\v'.
- `wordsplit`: `None` for the C EINVAL (unbalanced quote). `parse_ini`
  takes a closure, the line number counts `safe_fgets` chunks like the C.
- frontend display runs in C.UTF-8 on both sides; the port assumes a UTF-8
  locale where pacman follows the user's. `mbstowcs` is glibc's UTF-8
  decoder (1-6 byte forms, no overlongs/surrogates); invalid input keeps
  the valid prefix like the C. `wcwidth` is unicode-width per character
  (None/non-char = -1, L'\0' = 0, no string ligatures like wcswidth);
  differences to glibc counted in `cli_util::wcwidth_divergence`. Printing functions
  append to a `Vec<u8>` instead of stdout; difftest swaps the C `stdout`
  for an `open_memstream`. Frontend objects are packed into an archive in
  `OUT_DIR` by `difftest/build.rs` (minus `pacman.c.o`, only `main`).
- `strreplace` with an empty needle returns the input unchanged.
- `Package`: owned struct, NULL strings are `None`; handle, ops vtable,
  `origin_data.db`, `removes`, `oldpkg` not modelled. `dup()` copies only
  what `_alpm_pkg_dup` copies, `Clone` copies everything.
- `PkgHash<P: Borrow<Package>>` keeps the C bucket layout (prime sizes,
  f64 size/limit, rehash in old bucket order, backward shift on remove),
  so `find`/`remove` with duplicate names hit the same entry. Growth
  failure (~663930 entries) is `Err(pkg)`, not compared against C.
- `_alpm_fnmatch` = glibc `fnmatch(3)` flags 0 in the C locale,
  reimplemented byte based (glibc 2.44 quirks kept: class names only
  `a`-`y`, `[.x.]-]` as range start; `^` negates, POSIXLY_CORRECT unset).
  `fnmatch_patterns` returns `Option<bool>` (`None` = -1).
- `makepath_mode` chmods after mkdir (`mode & 01777` + inherited setgid)
  instead of the C's process-wide `umask(0)`. `copyfile` keeps the C
  behaviour: dest created even if src fails, no truncation, read errors
  count as success. `read_file` on an empty file is `System` like the C.
- `be_local` reads desc/files with `safe_fgets` into a 1024 byte line
  like the C: longer lines come in 1023 byte pieces, a nul ends the C
  string, '\r' stays, the end-of-file flag is sticky (glibc 2.28), so a
  last value not followed by a blank line is read again as a key. A
  failed section keeps what it read and sets the sticky `INFRQ_ERROR`;
  files read errors end the section like the C's NULL fgets.
- `be_sync` reads entries with `_alpm_archive_fgets` over the data
  blocks libarchive hands out: they end at every multiple of the
  filter's output block in the tar stream (64 KiB, 128 KiB for zstd,
  without a filter the fd read size `max(st_blksize, BUFSIZ)`,
  `util::Archive::block`); a line ends at '\n', or at a nul when the
  rest of the block has none. The 512 KiB line limit skips the first
  block like the C. READ_AND_SPLITDEP parses the current line where the
  C reads the header's freed pointer (UPSTREAM.md). The walk goes on past
  a failing entry with the C's log lines; the archive error line carries
  the port's text, `_alpm_open_archive`'s lines are not logged.
- `be_local` populate: stat-based `is_dir` (meson never defines
  `HAVE_STRUCT_DIRENT_D_TYPE`, so symlinks to dirs count), `add_sorted`
  for append + msort. `ALPM_DB_VERSION` parsed with fscanf `%zu`
  semantics.
- transaction targets are owned `TransPkg` copies plus a sync db index,
  the sync caches are never mutated (the C points into them, UPSTREAM.md);
  resolver and sort results are matched back by address. Removals and
  oldpkgs are re-dup'ed after prepare from fully loaded cache entries
  (the C's force-load in `_alpm_pkg_dup`). Re-adding a target dropped to
  unresolvable keeps its removes like the C. The prepare data list holds
  the reported entries only, no stale depmissing leftovers.
- frontend: one `util::Term` (stdin, ttys, cols, clocks as fn pointers)
  and `Output` with an optional sink, flushed before stdin reads, before
  `db_update` and after every callback; tests read the buffer. getuid
  and geteuid go through libc (rustix `use-libc`): fakeroot's LD_PRELOAD
  fakes libc's ids, not raw syscalls or /proc, so the binary and
  handle->user see uid 0 under fakeroot like the C (the FAKEROOTKEY
  emulation is gone). `Term::flush_input` is flush_term_input (tcflush
  of a terminal stdin) before each prompt read. Transaction prompts and
  callback prompts read stdin through separate buffers.
  `multibar_move_completed_up` is a flag every `Term` of the process
  shares (`run` hands one to each): the commit sets it like
  sync_prepare_execute, sync_syncdbs' reset is a no-op in one run. After
  '-' targets the C reopens the tty on stdin; std cannot swap fd 0. Write
  errors are dropped (the C dies of SIGPIPE). PACMAN_DEBUG stamps in local time.
- `be_sync::db_update` takes positions in `syncdbs()`, returns
  `Ok(true)` (C 0), `Ok(false)` (1, all up to date) or `Err` (-1). After
  several failed validations the errno is the last failure's, where the
  C can report `ALPM_ERR_OK` (UPSTREAM.md).
- `be_sync`: compression picked by magic bytes, desc and old split
  `depends` read entry by entry into the same package, any entry failure
  makes the db `DB_INVALID` like the C. Only the "no verification"
  validation path.
- `conf`: global `config` becomes an owned `Config`; pm_printf, isatty and
  uname go through a `Host` trait. `parseconfig` stops before
  `setup_libalpm` and keeps repos as data. glob is glibc GLOB_NOCHECK,
  sorted bytewise (glibc uses strcoll: matches the C locale only).
- `Handle`/`Db` return `Result<_, Errno>` instead of setting pm_errno.
  `Db` cache calls (`pkgcache`, `get_pkg`, `load_pkg`, `groupcache`,
  `get_group`) take handle->dbext at call time; the path is fixed at
  registration like the C's cached `_path`. `Db` calls that log take the
  `Callbacks` (handle->logcb), `Handle::dbs_mut` lends dbext, callbacks
  and the dbs together (`DbsMut`). RET_ERR/GOTO_ERR lines and be_sync's
  error lines (libarchive texts, the C reads on past a bad entry) are not
  logged. local lazy loads read one section per call like one getter per
  section, so the "loading package data" lines match.
- `database`: trans_init(0, 0)/trans_release are the db lock
  (`Handle::lock`/`handle_unlock`), the getters' lazy loads happen up
  front. checkdeps logs through the handle's callbacks, swapped out for
  the call because `DepsEnv` borrows the `Handle`.
- lazy loads (`load_pkg`, the group cache) write into the cache entry like
  the C. `Package` has no ops pointer, so every local cache entry
  lazy-loads through be_local (the C keeps default ops for a package added
  from a file; differs only for an added package without INFRQ_DESC).
- Group members are positions in the cache list; every cache change drops
  the group cache.
- `package.c` display: libalpm and system calls go through a `PkgEnv`
  trait (requiredby, satisfiers, db name, signatures, file probes, dates).
  Dates: the C uses `strftime("%c", localtime())` (LC_TIME, TZ); the port
  ships `format_date` (C.UTF-8 `%c` in the local zone, `format_date_at`
  for a fixed offset; None outside years -9999..9999 where the C still
  formats); in-process tests pin UTC through `PkgEnv::format_date`. Titles are untranslated msgids. Where the
  C crashes (md5 failure on a backup file, out-of-range dates) the port
  logs/prints "None" instead.
- `compute_requiredby`/`optionalfor` take a `DbCaches` trait (lazy, one
  scope at a time, `Db::pkgcache` needs `&mut`); no origin gives an empty
  list. `pkg_should_ignore` is plain fnmatch with no '!' negation, like
  the C (unlike NoUpgrade/NoExtract). `test_checksum` returns
  `Option<bool>` (`None` = -1). Frontend `PkgEnv: DbCaches`, the display
  computes reverse deps and satisfiers itself.
- `be_package`: compression by magic bytes like `be_sync`, a first tar
  header failure is an open failure (PKG_OPEN, libarchive picks the format
  while opening). Tar mode/size follow libarchive (type flag over
  permission bits, hard links no type bits and size 0, symlinks/devices
  size 0, regular entry ending in '/' is a dir). `.PKGINFO` is read in
  libarchive's data blocks (`util::Archive::block_size`: the filter's
  output blocks, the fd reads without one), so a nul ends a line exactly
  where `_alpm_archive_fgets` ends it (UPSTREAM.md); a cut plain tar hands
  out what arrived, then fails. A second `.PKGINFO` overwrites single
  values and appends lists like the C. With `full` off
  the walk reads one entry past `.PKGINFO`/`.MTREE` like the C. `.MTREE`
  is all or nothing, on failure the archive list stays. A cut package
  fails where libarchive's filter block fails (`util::Filter`); a
  `.CHANGELOG` whose data read fails is an error here, the C hands out
  what it read. `.MTREE` goes through the same filter blocks as the
  archive (`mtree::read_memory`).
- `regex`: glibc behaviour in C.UTF-8 only. pacman calls `setlocale(LC_ALL,
  "")`, so search depends on the user's locale (collation ranges, `[=e=]`,
  ASCII-only icase in C). Pike VM without backrefs (linear), memoized DFS
  with backrefs, capped at 2^20 states. Not mirrored (glibc bugs, fuzz
  skips them): icase texts with case pairs of different UTF-8 length,
  backrefs to repeated groups; approximated: backrefs + anchors without
  REG_NEWLINE, the non-NOSUB remove.c use, >2^20 instructions -> Space.
  Classes and towupper come from std `char` (the toolchain's Unicode).
- `mtree`: libarchive 3.8.9's mtree format reader translated (bid with
  `detect_form`, `readline`, `/set`/`/unset`, form D, duplicates merged,
  v1 relative paths and "..", escapes, every keyword, device packing
  checks, warning and error texts). The filter is picked like
  libarchive's bidders (`bid_filter`) and decoded through `util::Filter`
  over the data in memory (the local file is read whole): a cut stream
  fails the open
  inside the first block (128 KiB for text, the uudecode bidder's
  read-ahead), later the read failure ends the data like libarchive's
  readline (UPSTREAM). The data is one buffer: libarchive's line ends at
  read-ahead block boundaries are not modelled (UPSTREAM, practice none);
  `isprint` is the C locale's. In `check`, an entry with a warning ends
  the C walk (UPSTREAM bug), the port keeps checking; an mtree without
  sha256 is "information not available" (C: mismatch on a zero digest);
  the open failure's error log line is not printed. Output goes into
  `Output{stdout,stderr}`.
- `getopt` keeps glibc 2.44 semantics (optopt starts at 0, nextchar as an
  argv position). `parseargs` returns `Err(exit status)` where the C exits.
  `LIB_VERSION` hard-coded from meson, should sit next to
  `PACKAGE_VERSION`; `TRANS_FLAG_*` move to alpm-core with trans.c,
  `needs_root` to util.rs.
- `conflict`, `diskspace`, `deps` take handle state as parameters
  (local `PkgHash`, root, overwrite, `DepsEnv`) and report through
  per-unit traits until the callbacks unit lands; callers load packages
  first where the C lazy-loads. Mount table and statvfs go through
  `Mounts`.
- `query`: a shown local package reloads its cache entry where the C's
  getter lazy-loads (`Shown`): reason, find_requiredby's order (each
  entry's desc in list order, the target's own at its first depend not
  matching it literally), -Qi's scriptlet/backup through `PkgEnv`,
  files for -Ql/-Qk and -Qkk's first backup check through `CheckEnv`.
  the op's Output is flushed before each load and per package/target:
  the callbacks print at once like the C's unbuffered stderr, so the
  op's lines and libalpm's keep the C's order (separate pipes: the
  stdout/stderr interleave is not compared). `QueryEnv` carries
  `getcols()` and `PATH`. `sync`/`files` display copies of cache entries (one db
  borrowed at a time).
- `signing`: gpg(1) driven as gpgme's engine-gpg does (same binary,
  `--homedir`, status lines, colon listings); the signature goes over
  stdin, the file by path after a first read. gpgme's verify state
  (status, timestamps, validity reason, calc_sig_summary) is kept for
  the debug lines; gpg_strerror's texts come from libgpg-error's table
  (`signing/err_codes.rs`, `scripts/gpg-err-codes.py`). Divergences: no
  gpgme library, so "GPGME version:" says so; the engine file is the
  `gpg` found in PATH (gpgme asks gpgconf); system-error codes print as
  unassigned ones; a failed local key lookup (C -1) also logs gpg's
  stderr, or why gpg could not run, at debug level (gpgme drops it);
  the C's process-wide gpgme `init`
  (warning once per process, NOT_A_FILE leaking into later pm_errno) is
  per `Keyring`; a read error mid-file shows gpg's status, not gpgme's
  errno text; a key lookup failing partway returns Err instead of zeroed
  entries; FAILURE status lines ignored.
- `dload`: `Result<bool, Errno>` (Ok(true) = 0, Ok(false) = 1, Err = -1,
  Err(Errno::Ok) where the C fails without pm_errno). `DownloadState`
  (server error counts, the sticky interrupt) per handle. Divergences
  from curl: low-speed abort after 10 s without a byte (curl: under 1 B/s
  over 5 s for 10 s), curl 8.22 error texts copied where libalpm prints
  them (others reqwest's), no netrc, Basic auth from URL userinfo only,
  HTTP/1.1, no ftp://, rustls with the platform verifier, reqwest's proxy
  env handling, the url crate's normalised URL after a redirect,
  Last-Modified in RFC 1123/850/asctime forms only. Redirects are
  followed by hand like curl's FOLLOWLOCATION (any 3xx with a Location,
  10 follows, http(s) only, curl's texts for disabled/unknown schemes,
  connect/resolve errors naming the hop, url credentials kept on the
  same scheme/host/port). No connection is reused (no idle pool): a
  server answering HTTP/1.1 without `Connection: close` and then closing
  (pactest's) left hyper a dead pooled connection for the next hop or
  .sig, "Empty reply from server"; curl retries such a reused connection
  on a fresh one, reqwest cannot tell reused from fresh. Pinned in the
  dload difftest: on such a server curl gives up after 5 reconnects per
  transfer, so a same-host redirect loop ends in "Connection died, tried
  5 times before giving up" where the port follows all 10; chunked
  HTTP/1.0 responses are decoded by curl and a parse error to hyper.
- `unpack`: names joined to the prefix and modes set by chmod with the
  umask fixed at 022, the process cwd and umask are never touched. A
  directory entry carrying data ends the loop like libarchive's
  (UPSTREAM.md). Filtered archives are read through `Filter`
  (libarchive's 64 KiB output blocks, 128 KiB for zstd, and the open's
  read-ahead): a cut stream fails at open inside the first block, later
  a data read reaching the failed block fails the extraction and a
  header read ends it with success, like the C.
- `run_chroot`/`unpack` share one chdir check on effective ids
  (`AT_EACCESS`, like chdir).
- `hook`/`run_chroot`: chroot(8) (`/usr/bin/chroot`) instead of the C
  child's chroot()+exec, so argv[0] is cmd (`/sbin/ldconfig` for
  ldconfig) and a slash-less cmd gets `./`; root "/" spawns directly;
  chroot(8)'s own failure line is reworded to the C child's text (English
  messages only). The child's umask(0022) is set in the parent around
  the spawn (process wide for that moment); only SIGPIPE and the signal
  mask are reset. Output lines split
  like the C (2046-byte cut, NUL cuts, unterminated last line delivered
  twice as in the C).
- `sandbox`: the download child is a re-exec of the binary
  (`/proc/self/exe --alpm-sandbox-helper`) with `CommandExt::uid`/`gid`;
  the pacman binary's `main` must start with
  `if let Some(c) = alpm_core::sandbox::helper_entry() { exit(c) }`.
  Request over stdin, callbacks over stdout in the C pipe format.
  no_new_privs comes before landlock (needed unprivileged); getpwnam via
  `getent passwd`; parent sends SIGKILL after the loop (C: SIGTERM).
  `Handle` holds handle->user (getuid at initialize) and a `SandboxFor`
  (`sandbox::handle_sandbox`; tests swap in a pretend-root one):
  `with_downloader` (fetch_pkgurl, the sync commit's downloads) and
  `be_sync::downloader` get a `HelperSandbox` where `_alpm_use_sandbox`
  holds. finalize_download_file chowns to root only as root, like the C.
  A sandbox download dir nothing went through (fetch_pkgurl with every
  url cached, a failed fetchcb in db_update) is removed; the C keeps it
  (UPSTREAM.md). The helper's server error counts die with it like the
  forked child's, so a sandboxed handle never blocks a mirror across
  calls.
- XferCommand: `conf::XferCommand` is download_with_xfercommand (the
  fetchcb setup_libalpm registers; re-installed with the final config):
  the process cwd is changed and put back through fchdir like the C,
  the debug line shows the raw wait status. With DownloadUser it runs
  through the helper's exec mode (`--alpm-sandbox-exec`,
  `sandbox::SandboxExec`): the parent checks root and the user, spawns
  the helper as that user; the helper sets no_new_privs and execs argv.
  The helper's stdin is a socket bringing argv and the parent's stdin
  (SCM_RIGHTS, rustix `net`); an exec failure's errno comes back on it
  like the C's err_fd, so "fork failed!" shows as in the C. SIGINT and
  SIGQUIT count as ignored while a download helper or the command runs
  (`sandbox::IgnoreSignals`): sighandler.rs drops SIGINT then, and a
  SIGQUIT registration falls back to the default action only outside
  that window; decided a moment after delivery, on the signal thread.
- `remove` commit side: `remove_single_package(h, oldpkg, newpkg,
  targ_count, pkg_count)` reads flags and skip_remove from `h.trans()`,
  oldpkg is the `trans.remove` dup (every section loaded), newpkg's files
  sorted. Returns the dropped remove_package_files result: `Ok(failed
  files)`, `Err(PkgCantRemove)` is the pm_errno the C leaves on the
  upgrade path only (the removal path's `alpm_pkg_has_scriptlet` resets
  it). The debug lines of `_alpm_files_in_directory`, `_alpm_access` and
  `_alpm_db_remove_pkgfromcache` are logged in remove.rs. A backup entry
  without a hash counts as modified (C: strcmp on NULL); a `.pacsave.N`
  number read past the end of the name is 0. `path too long` branches
  are unreachable through the C's local db reader (lines over 1023 bytes
  split), the EROFS branch of can_remove_file needs a read-only mount:
  neither is difftested.
- `add` commit side: `commit_single_pkg(h, t, pkg_current, pkg_count)`
  and `upgrade_package` (any Err is TransAbort, the driver then marks
  the transaction interrupted and skips ldconfig) take a `TransPkg` the
  driver moved out of `trans.add`; flags come from `h.trans()`.
  archive_write_disk is translated for pacman's flags with a writer per
  entry (a directory's mode and times fixed up right after it), names
  absolute, hard link targets joined to root instead of chdir(root),
  umask taken as 0022 (modes come out exact either way), euid from
  `util::geteuid`. Entries come from libarchive's tar reader
  (`alpm-core::tar`): pax times to the nanosecond (atime too), pax
  uid/gid (no lookups are set, uname/gname unused), xattrs set like
  set_xattrs (before the mode when not root, last when root; POSIX ACL
  names skipped, xfsroot refused), hard links with data, data blocks at
  their offsets; ACLs and file flags are read, not restored (no
  ARCHIVE_EXTRACT_ACL/FFLAGS). lchmod is a no-op like glibc's on
  symlinks. libarchive's texts are copied, read errors included. Every
  header result other than ARCHIVE_OK ends the loop like the C's.
  Progress: an unfiltered tar's position is the entry's data start
  (exactly what libarchive consumed), a compressed one's is what the
  decoder had read from the file by `Filter`'s last block (equal for
  packages read in one go, coarser otherwise). The pm_errno a successful upgrade leaves from
  remove_single_package (PkgCantRemove) is not kept. The db.c/be_local
  log lines around prepare, write and the cache add are logged in add.rs.
- commit: `trans_commit` returns `CommitError { errno, data }`, data
  the file conflicts or the filenames load_packages refused. Sync
  targets are replaced in `trans.add` by their loaded files (origin
  File, `db` None, removes dropped) like the C. `upgrade_packages` lends
  `trans.add` out of the transaction for `add::upgrade_package`;
  `remove_packages` passes copies of `trans.remove` entries. pm_errno
  as the C leaves it: check_validity's is the last validation's (each
  resets it), load_packages' the last failed load's, PkgInvalid without
  one. The local files are loaded whole before the file conflict check
  (the C loads them as the check goes; only the FUNCTION lines move,
  which the difftest drops). The difftest drops debug lines inside
  downloads (dload's internals) and RET_ERR/GOTO_ERR's; init_gpgme runs
  before recording on both sides (once per process in the C). Another
  thread interrupts a commit through
  `Handle::interrupt()` (`Interrupt`): `set_state`/`trans_release`
  publish COMMITTING/INTERRUPTED, lock/unlock the held lock, and
  `trans::interrupted` sets a request into `trans.state` where the add
  and remove loops and the commit's end read it (C: the handler writes
  `trans->state` itself). Hooks run with the transaction off the handle
  but still count as committing, like the C.
- `sighandler`: signal-hook's self-pipe, a thread does the C handler's
  work in its order (cursor below the bars from the multibar cursor the
  callbacks publish, message, cursor shown, `trans_interrupt` or unlock
  and `_exit(128 + signum)`). Divergence: the thread decides a moment
  after delivery (C: at delivery), so a signal at a state edge (a hook
  ending, COMMITTING being set) can land on the other side.
  remove_soft_interrupt_handler is a flag read in signal context, the
  default action then runs. Not ported: segv_handler (signal-hook
  refuses SIGSEGV, safe Rust faults only on stack overflow, std's own
  handler reports it), winch_handler (getcols is uncached, nothing to
  reset; `flag::register_usize` would store the C's -1 once a cache
  exists). SIGINT/SIGQUIT are still not ignored around the sandboxed
  download and XferCommand (dload.c:936, conf.c:230): the soft handler
  runs there, the C ignores both.

Follow-ups raised by port units:

| Follow-up | Raised by | State |
|---|---|---|
| `PkgHash::find_mut`/`iter_mut`, lazy loads stick in cached packages | db | done |
| `be_sync::populate` takes the db path, `Db` uses the current dbext | db | done |
| shared fixture db generators in `difftest/src` (`fixtures.rs`) | db | done |
| `alpm_core::util::until_nul` pub, drop the copy in `pacman-cli` | frontend util | done |
| `compute_requiredby`/`optionalfor`, `alpm_find_satisfier`, `_alpm_depcmp` | pkgshow, package model | done |
| `impl DbCaches for Handle` | pkg follow-ups | done |
| `alpm_find_dbs_satisfier`/`resolvedep` | pkg follow-ups | done (`Questions` trait) |
| `alpm_pkg_should_ignore` | package model | done |
| `_alpm_needbackup` | leaves | done |
| checksums (`alpm_compute_md5sum`/`sha256sum`, `_alpm_test_checksum`) via alpm-types `Checksum` | util rest | done |
| fixture writer copied into `difftest/tests/deps_resolve.rs`, move to `fixtures.rs` | pkg follow-ups | done |
| db search (`_alpm_db_search`) on the ported regex | db | done |
| `LIB_VERSION` next to `PACKAGE_VERSION`, `needs_root` into util.rs, `TRANS_FLAG_*` with trans.c | args | todo |
| one `check_meta` (be_sync, be_package, package), test ustar builders onto `fixtures::ustar` | be_package | in progress: `package::check_meta` with its log lines, used by be_sync and be_local populate; be_package keeps its copy (sniff done via 0552) |
| precedent cleanup: base64, time, unicode-width, drop split_backup/parse_xdata, ALPM vs C difftest for vercmp/relations | audit | done |
| regex class/towupper tables -> std `char` methods, divergence counted like wcwidth | audit | done |
| handle callbacks + log.c: one `Callbacks` model wired into `Handle` (deps, conflict, diskspace, dload, signing, hooks, scriptlets, sandbox) | deps, conflict, diskspace | done |
| wire `HelperSandbox::for_handle` into `Handle::fetch_pkgurl` once `handle->user` (getuid) is ported | integrate | done: `Handle::user`, `SandboxFor` in `with_downloader` (fetch_pkgurl, sync commit downloads) |
| dload difftest umask race (C umask(0) process-wide vs parallel tests) | integrate | done: `difftest::umask_lock()` |
| rustix `process`/`termios` features: handle->user, getcols tty width, flush_term_input | handle, cliutil2 | done (`use-libc` backend for fakeroot, METHODOLOGY.md); pty difftest |
| local time offset for log stamps (UTC today) | handle | done: `log::local_offset` (time `local-offset`, METHODOLOGY.md) for pacman.log, syslog, PACMAN_DEBUG and `-Qi`/`-Si`/`%b` dates; %F's year unpadded like glibc; parse-time errors get their PACMAN_DEBUG stamp; difftests compare stamps (`stamped`) instead of stripping them, commits keep the zone (`strip_stamps`) |
| shared helpers into util: `llstat`, `strerror`, `PATH_MAX` once; frontend `pm_printf`/`Output`/`check_syncdbs`/`getcols` | conflict, diskspace, query, sync | done |
| `Handle` split borrow of local + sync caches (resolver and displays clone caches today) | deps, sync | in progress (integration) |
| XferCommand via a sandbox helper exec mode (`alpm_sandbox_setup_child` from conf.c) | sandbox | done: `conf::XferCommand`, `sandbox::SandboxExec` |
| conf difftest abort under long TMPDIR | sandbox, dbwrite reports | done: C one-byte heap overflow in `escape_chars` (UPSTREAM.md), fixture avoids it |
| `alpm_extract_keyid` wired into -Sii/-Qii `sig_keys` | sync | done: `SyncEnv::sig_keys` (-Qii shows no keys in the C either); generated sync dbs carry `%PGPSIG%` (`random_sig`), sync_ro and cli_binary -Sii compare keys and the format error lines |
| `Handle` owns `signing::Keyring` (gpgdir, known_keys) and implements `SigCallbacks`; `Db::register_sync` calls `be_sync::sync_db_validate` | signing | done |
| query.rs's new_version copy onto `alpm_core::sync::sync_get_new_version` | query | done |
| `pacman_sync` dispatches to `sync_trans` (needs a `Ui`), re-export `TRANS_FLAG_*` in pacman.rs | transprep | done |
| "found cached pkg" debug line into `util::filecache_find` (local wrapper in sync.rs) | transprep | done (dload's lookups log it too); `filecache_setup`'s /tmp fallback logs its "option 'cachedir'" line |
| conflict.rs `pkg_diff` onto `deps::list_diff`; deps_graph test reuses the trans_prep world generator | transprep | todo |
| `Handle` owns dload `DownloadState`/`Settings`/cachedirs; `filecache_*` into util | dload | with the callbacks unit |
| `alpm_db_update` (be_sync download + validate) | dload | done |
| drop `SyncCallbacks` and the `replace_callbacks` swap in sync.rs for `callback.rs` (progress bars, "is up to date", "failed to download") | dbupdate | done |
| `Question::SelectProvider` carries provider db names (today through `Lookup`); `Handle::replace_callbacks` has no frontend caller left | frontend | done: `DbPkgs::name`, `SelectProvider::dbs`; `Lookup::db_name` and `replace_callbacks` removed, deps_graph/trans_prep compare the dbs |
| sandbox in `be_sync::downloader` (like `fetch_pkgurl`) | dbupdate | done (`SyncParts::sandbox`) |
| `umask(0022)` around `alpm_db_update` (rustix process) | dbupdate | done, and run_chroot's child umask |
| be_package logs libarchive's open/read failures ("could not open file X: ..." for unknown formats and dirs, "error while reading package" for a cut first header, "could not parse package description file" for a cut `.PKGINFO`); `sync_clean` and difftest query filter them today | cleancache | done: header and data read failures log "error while reading package"; difftests cut libarchive's text after the path (`cut_archive_text`, twin-compare's `ARCHIVE_TEXT`) instead of dropping lines: sync_clean's filter and testpkg's log-only tallies gone, cli_binary's cache holds a non-package and a download dir |
| `be_package::changelog` without callbacks: -Qpc missed "opening archive" | qk | done (cli_binary `-Qpc --debug`) |
| optdepends' ` [installed]`/` [pending]` after install/upgrade: the binary's `Lookup for ()` had no lists | twin-root | done: `PackageOp::local`/`pending` (local cache, trans->add at DONE; the driver keeps satisfier copies of the targets in trans.add while it lends them out), `Lookup` removed |
| `-Sp` of an installed sync package whose local entry has no files list: the C fails ("could not open file .../files", invalid package), the port prints | output (cli_binary local_time) | todo (query/lazy-load owner) |
| one `logv(cb, ...)` helper (copies in hook.rs, deps.rs, trans.rs, util's `log_parts`) | integrate2 | in progress: `callbacks::logv`, used by db, be_local, be_sync |
| `-D` dispatch arm: `pacman_database(config, handle, targets, &mut o)` | m1close | done |
| setup_libalpm's server adds through `Handle::dbs_mut()` (`Db::add_server` takes the callbacks) | m1close | done |
| `multibar_move_completed_up` from the frontend (a Callbacks hook or a shared flag) | commit | done (`Term::move_completed_up`) |
| conflict.rs debug lines ("searching for file conflicts", ...), then drop the difftest's quiet window | commit | done |
| commit difftest with hooks (fakechroot) and signed packages (check_keyring, PKG_INVALID_SIG, MISSING_SIG) | commit | done (no port divergence found) |
| pactest's minimal sync db entries and empty `.PKGINFO` values, the main pactest blockers | commit | done (owned readers: `.PKGINFO`, db entries) |
| trans_commit `signed_keyring` diverged in 4 runs in a row (one window): the port asked no import question for a key missing from the keyring, then failed validation with PKG_INVALID_SIG (C: "required key missing", pm_errno 0). not reproduced in 21 later runs. `key_in_keychain` maps any gpg spawn/wait error to None, which check_keyring takes as "not missing" without a trace | hooksig | instrumented, not reproduced: the -1 path logs the C's "gpg error: %s" and then gpg's stderr (or why gpg could not run) at debug, and trans_commit now compares debug lines, so a recurrence shows the branch taken (C "key lookup failed, unknown key" vs the port's line). 22/22 `signed_keyring` and 22/22 `signing_gpg` runs passed (sigdebug) |
| query: -Qk/-Qkk lazy loads per package like the C (-Qkk loads files up front), op stderr flushed per package so callback lines interleave; then drop cli_binary's empty files lists | m1close | done: every -Q getter loads in place, flushed per load; cli_binary's empty lists gone |
| -S/-Sp/-Sup/-Spdd load every local desc up front: an unreadable local desc logs "could not open file" where the C never reads it (`-Sp nope`, `-Sup`); cli_binary leaves unreadable descs to difftest query | qk | todo |
| query's `check_signature` stub onto `signing::pkg_check_pgp_signature` (handle keyring and callbacks): -Qpi with a `.sig`, and checksig's debug lines once signing logs them | qk | done: results mapped onto util's `SigResult`, difftest query runs -Qpi with debug |
| `be_package::changelog` takes the callbacks (-Qpc's "opening archive" debug line); difftest query runs -Qpc without debug | qk | todo |
| signing debug lines (`_alpm_access` "is not readable", "sig path ... could not be opened", "missing required signature") | m1close | done: every signing.c line ported, trans_commit's `SIGNING_DEBUG`/`sig_unreadable` and db_update's positive debug list dropped, cli_binary's `known()` narrowed to the GOTO_ERR lines |
| difftest C log callbacks (deps_graph, dload, diskspace, db_update) onto `handle::record_log` | m1close | todo |
| `DepsEnv` without `&Handle` (assumeinstalled, ignore lists), so checkdeps logs without swapping the callbacks | m1close | todo |
| difftest: `read_deps` pub(crate) (drops conflict's `CDepend`), `SyncWorld` into fixtures.rs | conflict, sync | todo |
| be_sync: a non-archive db must fail at open (DB_OPEN, db invalid) like libarchive, not LIBARCHIVE | query | done |
| `%DATA%` in repo dbs, gzip multi-member, `Packager` default, backup `(null)` | db readers | ALPM side, see `UPSTREAM.md` |
| xattrs and pax mtime/uid/gid on extraction | addcommit | done (xattr unit): `alpm-core::tar`, add.rs set_xattrs/times; difftest add_commit pax cases, fuzz_pax, fakeroot run (`security.capability`, ids; `DIFFTEST_CAP_PKGS` real packages) |
| NFC composition of pax strings (libarchive `archive_string_normalize_C`, its Unicode 6.0 tables) and non-UTF-8 locales | xattr | todo: pinned (`pax_composed_divergence`, `under_c_locale`); makepkg writes such names with hdrcharset=BINARY, which skips the conversion |
| one geteuid/getuid helper (add.rs `euid`, sandbox `System::uid` read /proc/self/status) or rustix `process` | addcommit | done: `util::getuid`/`geteuid` (dload's Umask reader stays: no getumask without setting it) |
| dload's internal debug lines (url, maxsize, time condition, tempfile, curl result, response code), so `-Sy --debug` with the built-in downloader matches | process | done: every dload.c debug line, CURLcodes carried by `Code::Failed`, a client-side unmet time condition is response code 304 like curl; dload/db_update difftests keep debug lines (RET_ERR's left out), db_update's `DLOAD_DEBUG`, trans_commit's download quiet window and cli_binary's sandbox `--debug` skip dropped |
| `_alpm_upgrade_packages` loop over trans.add, interrupted state, ldconfig | addcommit | with alpm_trans_commit |
| test generators still limited to what alpm-db/alpm-repo-db/alpm-pkginfo accepted (db_search.rs, diskspace.rs, check.rs, be_local_write.rs, sync_clean.rs, be_package.rs "per the alpm-pkginfo spec"): widen to what the C reads, drop the comments | stale sweep | done: `fixtures::loose_sections` (sparse, empty, blank, unknown desc sections), files lists without parents/sorting, odd `.PKGINFO` lines, random packages read back by set_reason, odd deps_graph relations; cli_binary's empty files lists went with the -Qkk row above |

Divergences below are the remaining ones; the ALPM parser and type
divergences left with the owned readers.

## Divergences from pacman (precedent crates)

| Divergence | Effect |
|---|---|
| dates before -9999 or after 9999: C formats, port prints "None" | `-Qi`/`-Si` display only |
| pax strings in a UTF-8 locale: libarchive composes decomposed sequences (NFC), the port keeps them; other locales are not modelled (the C locale fails non-ASCII UTF-8 names with ARCHIVE_WARN) | names with hdrcharset UTF-8 only; makepkg marks them BINARY |
| a pax record name past its 512-byte window: the port sees up to the block end, libarchive's copy buffer may hold less or more | "overlarge attribute name" on names past 512 bytes only |
| fifos made with mknodat, libarchive's mkfifo (glibc's internal mknodat) | none on a system; under fakeroot only the port's is faked |
| wcwidth: unassigned code points -1 in glibc, 1/2/0 in unicode-width (814641), 84 marks zero width in unicode-width, 8 ambiguous (U+3248-324F), 3 special rules | `string_length`/wrapping differ for such text; the C returns `(size_t)-1` for unassigned |

## Divergences from pacman (ALPM parsers)

Where the ALPM crates read pacman's files differently. Leaves with the
owned readers (table "Owned readers"): each unit removes what its reader
fixes. The local and sync db readers are owned and difftested equal,
real dbs included (before: urls normalized in 82/804 local and
1330/15334 sync entries, `(null)` backups dropped, `Unknown Packager`
refused).

Package files (`.PKGINFO` and `.MTREE` have owned readers, equal on every
input): archives with the `S` type without GNU header refused,
gzip-in-gzip, lz4, lzma not opened (libarchive does; the same for lz4/
lzma `.MTREE` and local mtree streams).

Upstream findings made while porting are kept apart in `UPSTREAM.md`.
