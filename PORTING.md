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
- `<crate>/tests/`: unit tests of the port, kept out of `src/`
- `difftest/`: equivalence tests, the one crate allowed to call C. It
  links upstream `libalpm_objlib.a` and `libcommon.a` statically, so
  internal (hidden) functions are comparable too. One module per C file.
- `scripts/cli-parity.sh`: stdout/stderr/exit diff of a C binary vs its port

Rules for every port unit: `METHODOLOGY.md`.

## Checks

```
# reference build (once, and after upstream pulls)
meson setup pacman/build pacman && ninja -C pacman/build

# unit tests, differential tests (PACMAN_BUILD overrides pacman/build)
cargo test --release
DIFFTEST_ITERS=5000000 cargo test --release -p difftest

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
| local db reader (`be_local.c` via `alpm-db`) | in progress |
| sync db reader (`be_sync.c` via `alpm-repo-db`, `alpm-compress`) | in progress |
| pacman.conf (`conf.c`) | in progress |
| db layer and cache (`db.c`), minimal handle (`handle.c`) | todo |
| frontend query/package display (`query.c`, `package.c`, `pacman.c` args) | todo |

Gate: `scripts/cli-parity.sh` between C `pacman` and the Rust binary with
the same `--root`/`--dbpath`/`--config` on generated test roots and a
read-only copy of a real system db; byte-identical stdout, stderr, exit.

### 2. Sync databases (`-Sy`)

| Part | State |
|---|---|
| downloads (`dload.c`): parallel, resume, mirrors, sandbox user | todo, needs an HTTP crate decision (none in ALPM) |
| signature verification (`signing.c`) | todo, needs an OpenPGP crate decision |
| db update/validation (`be_sync.c` writing side) | todo |

Gate: pactest sync/download tests against the Rust binary.

### 3. Transactions (`-S`, `-U`, `-R`)

| Part | State |
|---|---|
| package files (`be_package.c` via `alpm-package`, `alpm-compress`) | todo |
| deps resolution (`deps.c` rest), `conflict.c`, `diskspace.c` | todo |
| `trans.c`, `sync.c`, `add.c`, `remove.c`, `hook.c`, scriptlets (chroot) | todo |
| sandbox (landlock/seccomp), local db writing | todo |

Gate: the full pactest suite (`meson test` baseline 338 ok, 6 expected
fail) run against the Rust binary.

### 4. Drop-in

libalpm C ABI (`alpm.h`) exported from the Rust library so existing
front-ends (yay, paru via alpm.rs, pamac, pyalpm) keep working.

Gate: those front-ends' basic operations against the Rust libalpm.

## ALPM overlap

| pacman part | ALPM crate | Plan |
|---|---|---|
| `version.c` vercmp | `alpm-types` version comparison | keep port (pacman compares arbitrary strings), difftest ALPM vs C on versions ALPM parses |
| `deps.c` dep strings | `alpm-types` relations | same as above |
| xdata, base64, checksums | `alpm-types` (`ExtraData`, base64, md-5/sha2) | use ALPM / its crates, no hand-written hashes |
| `be_local.c` desc/files | `alpm-db` | use `alpm-db`, difftest against C `local_db_read` |
| `be_sync.c` | `alpm-repo-db` | use `alpm-repo-db` |
| `be_package.c` | `alpm-package`, `alpm-compress`, `alpm-pkginfo`, `alpm-mtree` | use ALPM |
| filelist, pkghash, deps resolution, transactions, hooks, frontend | none | translate |

## Status

29576 lines of C (no symlinks). Complete: `version.c`, `vercmp.c`,
`base64.c`. Partial files list their ported functions.

| C file | Lines | Rust | Checked by |
|---|---|---|---|
| `lib/libalpm/version.c` | 260 | `alpm-core::version` | difftest fuzz, vercmptest 92/92 |
| `src/util/vercmp.c` | 63 | `vercmp` | vercmptest 92/92, cli-parity |
| `lib/libalpm/alpm_list.c` | 650 | - | replaced by `Vec`, no port |
| `lib/libalpm/rawstr.c` | 135 | - | no callers, not ported |
| `lib/libalpm/base64.c` | 196 | `alpm-core::base64` | difftest fuzz via `alpm_decode_signature` |
| `lib/libalpm/util.c` | 1657 | `alpm-core::util` (partial) | strip_newline, get_fullpath, hash_sdbm, strtoofft, parsedate, splitname, fnmatch, fnmatch_patterns: difftest fuzz; makepath(_mode), copyfile, read_file, files_in_directory: difftest fs fuzz (tree snapshots); checksums via md-5/sha2 pending; realloc/greedy_grow replaced by Vec |
| `lib/libalpm/pkghash.c` | 351 | `alpm-core::pkghash` | add, add_sorted, remove, find, growth: difftest sequence fuzz, bucket layout and list order compared every step |
| `lib/libalpm/filelist.c` | 147 | `alpm-core::filelist` | sort, contains, difference, intersection: difftest fuzz |
| `lib/libalpm/backup.c` | 100 | `alpm-core::backup` (partial) | split_backup, backup_dup: difftest fuzz; needbackup waits for package.c |
| `lib/libalpm/group.c` | 51 | `alpm-core::group` | difftest |
| `lib/libalpm/graph.c` | 38 | - | |
| `lib/libalpm/error.c` | 166 | `alpm-core::error` | strerror, all 56 values + out of range: difftest; alpm_errno waits for handle |
| `lib/libalpm/log.c` | 112 | - | |
| `lib/libalpm/package.c` | 868 | `alpm-core::package` (partial) | data model (`Package`, `PkgFrom`, `PkgReason`), dup, pkg_cmp, compare_versions, find, parse_xdata: difftest via `#[repr(C)]` mirror (offsets checked through the C getters); handle/db/archive parts pending |
| `lib/libalpm/be_package.c` | 778 | - | |
| `lib/libalpm/be_local.c` | 1232 | - | |
| `lib/libalpm/be_sync.c` | 762 | - | |
| `lib/libalpm/db.c` | 773 | - | |
| `lib/libalpm/handle.c` | 1017 | - | |
| `lib/libalpm/alpm.c` | 132 | - | |
| `lib/libalpm/signing.c` | 1201 | `alpm-core::signing` (partial) | `alpm_decode_signature`: difftest fuzz |
| `lib/libalpm/dload.c` | 1474 | - | |
| `lib/libalpm/deps.c` | 926 | `alpm-core::deps` (partial) | dep_from_string, dep_compute_string, depcmp_provides (+ static dep_vercmp through it): difftest fuzz |
| `lib/libalpm/conflict.c` | 686 | - | |
| `lib/libalpm/diskspace.c` | 514 | - | |
| `lib/libalpm/trans.c` | 452 | - | |
| `lib/libalpm/sync.c` | 1360 | - | |
| `lib/libalpm/add.c` | 718 | - | |
| `lib/libalpm/remove.c` | 798 | - | |
| `lib/libalpm/hook.c` | 679 | - | |
| `lib/libalpm/sandbox*.c` | 608 | - | |
| `src/common/*.c` | 445 | `pacman-common::{util_common,ini}` | all of util-common.c and ini.c: difftest fuzz (safe_fgets on fmemopen + real file, llstat on /tmp tree, ini via recorded callback) |
| `src/pacman/*.c` | 10124 | - | excl. symlinks into `src/common` |
| `src/pacman/util.c` (in the above) | 1981 | `pacman-cli::util` (partial) | indentprint, strreplace, string_display, list_display(_linebreak), signature_display, humanize_size, arg_to_string, console cursor helpers: difftest fuzz; glibc mbstowcs/wcwidth: difftest, wcwidth over every code point |
| `src/util/testpkg.c` | 103 | - | |

Not in scope: makepkg, repo-add, pacman-key and the other bash scripts.

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
  the valid prefix like the C. `wcwidth` is a table dumped from glibc 2.44
  (`dump_width_runs` ignored test regenerates it). Printing functions
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

Upstream findings made while porting are kept apart in `UPSTREAM.md`.
