# Upstream findings

Behaviour in the C reference noticed while porting. Kept out of the port
source; the port implements the in-bounds/defined behaviour only, and
`difftest` avoids or pins these cases explicitly.

Reference: `pacman/` at `v7.1.0-18-ga6f7467d`. Nothing here has been
reported upstream yet.

## Practice

Every finding states who controls the input that triggers it:

- **real**: ordinary use can hit it (normal packages, normal config)
- **packager**: only metadata/packages a packager or repo produces, which
  makepkg/repo-add output never contains; needs a broken or hand-crafted
  package, or a crafted repo db (db signatures default to optional)
- **local**: only hand-edited local state (`/var/lib/pacman`, config)
- **api**: only external libalpm callers; pacman's own callers never pass it
- **env**: only resource or environment failure (OOM, disk full, signals,
  FIPS, threads)
- **none**: dead code, cosmetic, or unreachable

| Finding | Practice |
|---|---|
| `_alpm_filelist_pathcmp` signed `char` | real (rare) |
| `_alpm_pkg_dup` copies a subset | real, long-lived API users |
| local db lines over 1023 bytes split | real (rare) |
| Include matching nothing is fatal | real |
| `READ_AND_SPLITDEP` reads a freed buffer | packager |
| `-Qii` crashes on a backup path that is now a directory | local |
| `-Si`/`-Qip` crash on huge build dates | packager |
| `.pacsave` rotation regex built from an unescaped file name | real (rare) |
| `.pacsave` shift loop runs to the highest number found | local |
| backup entry without a hash crashes the remove | local |
| unremovable package forgotten with its files left | env |
| `-Fx -l` conflict check is dead | real |
| `_alpm_pkg_check_meta` name check swapped | packager |
| `string_length` buffer one byte short | packager |
| `_alpm_splitname` precondition | packager / local |
| `_alpm_copyfile` write offset | env |
| `alpm_decode_signature` newline-only | api |
| `_alpm_filelist_intersection` empty names | none |
| `rawstr.c` no callers | none |
| `alpm_db_update` fails with `ALPM_ERR_OK` | real |
| `%BACKUP%` written with a `(null)` hash | real |
| stale `.sig` kept after a sync | real (rare) |
| minor sections | per bullet |

## `_alpm_filelist_pathcmp` compares signed `char`

Practice: **real (rare)**. Needs two packages in one transaction shipping
the same path with a byte >= 0x80 (UTF-8 file names exist in real
packages), on x86_64. Consistent on aarch64.

filelist.c:78 returns `*p1 - *p2` on plain `char` (signed on x86_64), but
the lists it walks are sorted with `strcmp` (unsigned): be_package.c:662,
be_sync.c:695, be_local.c:886. With bytes >= 0x80 the merge in
`_alpm_filelist_intersection` advances the wrong side, e.g.
A=["a","\xc3"], B=["\xc3"] gives no intersection. Used by conflict.c:442
(target vs target file conflicts), so such a conflict is missed. Fix idea:
compare as `unsigned char`.

- port: mirrors the C via `c_char`
- difftest: edge case pins it

## `_alpm_pkg_dup` copies a subset

Practice: **real, long-lived API users**. The cache entry is per process;
pacman exits after the transaction, so it is not visible there. Long-lived
libalpm users (daemons, GUIs) reading the just-installed package would see
the missing fields (not verified end to end).

package.c:588-641 does not copy `base64_sig`, `download_size`,
`checkdepends`, `makedepends`, `xdata`; `_alpm_pkg_free` frees them. Used
by `_alpm_db_add_pkgincache` (db.c:622).

- port: `dup()` mirrors the subset, `Clone` is complete

## local db lines over 1023 bytes split

Practice: **real (rare)**. Needs a description or a file path over 1023
bytes in an installed package; long paths exist in some packages.

be_local.c:713 reads `desc`/`files` through `line[1024]`: a long desc is
truncated and its tail parsed as an unknown key (swallowing lines up to
the next blank line), a long path becomes two file entries, which then
take part in ownership queries and conflict checks.

- port: splits like the C (owned reader, difftest `be_local`)

## Include matching nothing is fatal

Practice: **real**. `Include = /etc/pacman.d/*.conf` with no match.

conf.c:1237-1254: with `GLOB_NOCHECK` and no errfunc, the GLOB_NOMATCH and
GLOB_ABORTED branches are dead and the "Ignore include failures" comment
is wrong: the pattern comes back verbatim and fails with "could not be
read".

## `READ_AND_SPLITDEP` reads a freed buffer

Practice: **packager**. Needs a relation line in a sync db longer than
`_alpm_archive_fgets`'s buffer (about one archive block); repo-add output
never has lines that long, a crafted db can.

be_sync.c:552-555 parses `line`, captured at the section header
(be_sync.c:599), instead of `buf.line`. When a longer line makes
`_alpm_archive_fgets` grow its buffer (util.c:1283-1291) the old one is
freed, so `alpm_dep_from_string(line)` reads freed memory. Applies to
every relation section. Fix idea: use `buf.line` like READ_AND_STORE_ALL.

- port: parses the current line (the fix idea)
- difftest: lines of 512 bytes and more never inside a relation section

## `-Qii` crashes on a backup path that is now a directory

Practice: **local**. A backup file (e.g. under `/etc`) replaced by a
directory, or a read error on it.

src/pacman/package.c:394-415, 430: `access(R_OK)` passes on a directory,
`alpm_compute_md5sum` fails, `get_backup_file_status` logs and returns
NULL, and `dump_pkg_backups` calls `strlen(NULL)`.

- port: logs the error and skips the entry
- difftest: no backup path is a directory

## `-Si`/`-Qip` crash on huge build dates

Practice: **packager**. A `%BUILDDATE%`/builddate around 7e16 or more;
`_alpm_parsedate` accepts any long long.

src/pacman/package.c:202-209 passes `localtime()`'s NULL (year past int)
to `strftime`.

- port: prints "None"
- difftest: only dates `localtime` accepts

## `.pacsave` rotation regex built from an unescaped file name

Practice: **real (rare)**: a backup file whose name contains ERE
metacharacters.

remove.c:371-372 (used at 547) builds a regex from the basename without
escaping. `+`, `*`, `{}` change which files match, and `strtoul` (390)
reads the number at a fixed offset. A name that fails to compile (`[`, a
lone `{`) jumps to cleanup without shifting, then the caller renames the
file to `.pacsave`, overwriting an existing `.pacsave`: an older saved
config is lost. Error paths after a successful regcomp (375, 402, 410)
skip `regfree`. **env** for the leak.

A match shorter than the basename (`*`, `?`, `{0,}` in the name: `a*b`
matches `b.pacsave.1`) puts the `strtoul` offset past the end of
`d_name`, which then reads stale bytes of the dirent buffer. **real
(rare)**, same names.

- port: same regex; a number past the end of the name reads as 0
- difftest: metacharacter names that cannot match shorter (`a.conf`,
  `c+.conf`, `[x`), decoys the unescaped regex matches

## `.pacsave` shift loop runs to the highest number found

Practice: **local**. Needs a hand-made `<file>.pacsave.<N>` next to a
modified backup file.

remove.c:399 renames once per number from the highest `N` down to 1,
missing ones included: `x.pacsave.4000000000` makes four billion
`rename` calls (the removal hangs). `N` at `ULONG_MAX` wraps
`log_max + 1` to 0, nothing shifts and `.pacsave` overwrites an existing
`.pacsave.1`.

- port: same loop
- difftest: numbers up to 7

## backup entry without a hash crashes the remove

Practice: **local**. Needs a `%BACKUP%` line without a tab in the local
`files` (pacman itself writes `(null)`, see below).

remove.c:536 `strcmp(filehash, backup->hash)` with the NULL hash
`_alpm_split_backup` gives such a line, once the file's md5 computes.

- port: the file counts as modified (saved as `.pacsave`)
- difftest: never feeds the C that entry

## unremovable package forgotten with its files left

Practice: **env**: a file of the package on a read-only mount (EROFS).
Not reproduced end to end (the difftest has no read-only mount), read
from the code.

`remove_package_files` returns -1 with `ALPM_ERR_PKG_CANT_REMOVE` before
touching anything (remove.c:628), but `_alpm_remove_single_package`
drops that result (718, "TODO check returned errors"), then logs
"removed", runs post_remove and deletes the db entry: the files stay on
disk, owned by no package, and the transaction reports success. The -1
checks of its callers (remove.c:781, add.c:508) are dead, and on the
removal path `alpm_pkg_has_scriptlet` (727) resets pm_errno. Files that
fail to unlink later are only counted, with the same outcome.

- port: same behaviour, the files result returned
- difftest: unlink/rmdir/rename failures in 0555 dirs compared

## `-Fx -l` conflict check is dead

Practice: **real**. Ordinary flags reach it; the effect is missing
validation only.

pacman.c:878 `checkargs_files` tests `op_q_search`, which -F never sets
(should be `op_f_regex`), so `--regex --list` is never rejected.

## `_alpm_pkg_check_meta` name check swapped

Practice: **packager**. makepkg refuses invalid package names, so only a
hand-crafted package or repo entry has one; the check meant to catch that
case does not work.

package.c:843 calls `_alpm_fnmatch(pkg->name, "[![:alnum:]+_.@-]")`, but
`_alpm_fnmatch` is `fnmatch(pattern, string, 0)` (util.c:1557): the name is
used as the pattern. The invalid-character check effectively never fires
(and the bracket would only match a one-character string anyway).
Found independently by four port units (package model, util.c,
be_sync, be_local); it runs as a hard error in be_sync.c:360 and
be_package.c:667.

## `src/pacman/util.c` `string_length` buffer one byte short

Practice: **packager**. Needs an ESC byte in displayed metadata (name,
description, ...) that is not a complete colour sequence; pacman's own
colour strings are complete, official metadata has no ESC.

util.c:463 allocates `strlen(s)` bytes for the colour-stripped copy, then
writes its terminator: one byte past the buffer whenever `s` holds ESC but
no complete `\033[<digit>[0-9;]*m` sequence gets stripped.

- port: no buffer, slices
- difftest: input filtered to complete sequences (`string_length_in_bounds`)

## `_alpm_splitname` precondition

Practice: **packager / local**. Entries written by pacman and repo-add are
`name-pkgver-pkgrel`, always two '-'. Only a crafted sync db entry or a
hand-made directory in the local db breaks it.

The backwards scans for '-' have no lower bound, so the function relies on
input having two '-' before the first '/' and a non-empty target.

- port: returns `None` otherwise
- difftest: `c_splitname` asserts the precondition, fuzz filters to it

## `_alpm_copyfile` write offset

Practice: **env**. Needs short writes (disk full, signals, some network
filesystems); regular local files normally write fully.

util.c:183 `write(out, buf + nwrite, nread)` uses the last write's count as
offset instead of a running total: wrong bytes after a second partial
write, and `buf - 1` after an EINTR (`nwrite == -1`). Also no `O_TRUNC`
(util.c:166, old tail kept), dest created with mode 0000 when src fails,
and other read errors end the loop with success.

- port: mirrors the observable C behaviour on regular files
- difftest: tmpfs regular files only, no short writes

## `alpm_decode_signature` on newline-only input

Practice: **api**. libalpm reads `%PGPSIG%` as one stripped line and never
passes such input.

`base64_decode` returns 0 early when no symbol is present without setting
`*dlen`, so `alpm_decode_signature` reports `len * 3 / 4` bytes of an
uninitialized buffer as success (e.g. `"\n\n\n\n"` gives 3 bytes).

- port: returns empty
- difftest: `c_decode_signature` does not read the buffer in that case

## `_alpm_filelist_intersection` on empty names

Practice: **none**. File lists never contain empty names.

filelist.c:101 indexes `strlen(name) - 1`, out of range for an empty name
when pathcmp returns 0 (""/"" or ""/"/").

- port: empty name counts as a file
- difftest: `c_filelist_intersection` asserts no empty names

## `rawstr.c` has no callers

Practice: **none** (cleanup).

`_alpm_raw_cmp` never had a caller, `_alpm_raw_ncmp` lost its last one in
`5e9bff62` (Content-Disposition removal). Delete the file and its `util.h`
declarations. No existing MR found for it.

## `deps.c` minor

- `dep_vercmp` switch `default:` (deps.c:399-408) and
  `alpm_dep_compute_string` `default: opr = ""` (deps.c:897-899) only
  reachable with out-of-range mods; ANY is handled before the switch.
  **none**
- `alpm_dep_from_string` finds operators by priority, not position; the
  comment at deps.c:497 describes the order loosely. Malformed input is
  accepted silently, including an empty name ("<=1"). **packager**

## `backup.c` minor

- `_alpm_split_backup` (backup.c:41-52): the `str ?` guard is only
  reachable with a NULL input, which returns success with a NULL name.
  **api**
- the tab case strdups the whole string, then both halves again. **none**

## `src/common` minor

- `safe_fgets` (util-common.c ~138) checks `errno == EINTR` without
  clearing errno first: with a stale EINTR and an `fgets` that returns NULL
  without setting errno (size <= 0) it loops. No in-tree caller passes
  size <= 0; difftest zeroes errno before each call. **none**
- `wordsplit` passes plain `char` to `isspace` (negative for bytes >= 0x80,
  UB in ISO C, tolerated by glibc). `strtrim` casts correctly. **none on
  glibc**
- `parse_ini`: `strdup` for the section name is not NULL-checked **env**;
  the doc comment says empty key/value and callback on read errors, the
  code passes NULL and ends silently on read errors **none**; lines over
  PATH_MAX-1 are split and parsed as separate lines **local**
- `error.c`: no case for `ALPM_ERR_OK`; `TRANS_NULL` and
  `TRANS_NOT_INITIALIZED` share one message. **none**

## `src/pacman/util.c` minor

- `strreplace` empty needle loops (util.c:378-383); callers use fixed
  needles. **none**
- plain `char` into `isdigit` (466, 470) **none on glibc**; `%d` for
  `unsigned` in console_cursor_move_* (1957, 1963) **none**; NULL into
  `%s` in signature_display when uid and fingerprint are both NULL
  (870-872) **packager** (keyring/signature data); unchecked `vasprintf`
  in pm_vasprintf (~1854) and malloc/realloc (505, 1353) **env**
- invalid multibyte input: `mbstowcs` returning -1 passes the `!len`
  check, so indentprint/string_length handle only the valid prefix
  (322, 487/495), e.g. a Latin-1 description under a UTF-8 locale is cut
  off; `wcwidth` -1 added to `size_t` (340, 353, 488), e.g. a tab in a
  description, breaks wrapping / makes widths SIZE_MAX. Display only.
  **packager** (plausible in old or third-party packages)
- strtol into int (parseindex 1447, getcols 239, plus unsigned short
  return): user typed selection numbers, `COLUMNS`. **local**, harmless
- table_calc_widths assumes rows no wider than the header (650); callers
  always match. **none**
- signature_display "None" without newline (816-817). **none**
- dead: 331 `p == NULL` after `p++`, 476 `t++`, 628 `size_t <= 0`,
  util.h:72 `str_cmp` declared, never defined. **none**

## `package.c` / `pkghash.c` minor

- dup cleanup with `files.count == 0` leaks partially copied files
  (package.c:619-629). **env** (OOM)
- `_alpm_pkghash_create` double -> unsigned conversion past UINT_MAX
  (pkghash.c:74); callers pass db size estimates, difftest asserts against
  it. **none**
- remove/find/`alpm_pkg_find` `strcmp` a NULL name after a hash match
  (pkghash.c:301, 351, package.c:787); package names are always set.
  **api**

## `util.c` minor

- read loops test `> 0 || errno == EINTR` without resetting errno
  (177, 1078, 1137): a stale EINTR at EOF loops. **env**
- `umask(0000)` in makepath_mode is process-wide (118). **env** (threaded
  API users)
- checksum read-error path skips `EVP_MD_CTX_destroy`, `EVP_DigestInit_ex`
  unchecked (1073/1093, 1132/1152). **env** (read errors, FIPS without MD5)
- `_alpm_read_file` fails on empty files (1649), e.g. an empty `.sig`
  reports "system error" instead of a signature error. **real**, harmless
  wrong message
- `_alpm_greedy_grow` returns `data` instead of `*data` when no growth is
  needed (1600); callers only NULL-check. **none**

## `be_sync.c` / `be_local.c` minor

- duplicate single-value sections overwrite without freeing (be_sync.c
  READ_AND_STORE 539-542, be_local.c:690), a second file list leaks the
  first (be_sync.c:694). **packager / local**
- same package name in two sync db dirs is merged into one package; any
  non-directory entry creates a package before its file name is checked,
  a top-level `README` invalidates the whole db (be_sync.c:587).
  **packager**
- `_alpm_archive_fgets` ends a line at NUL only when the block has no
  '\n', so results depend on block boundaries (util.c:1263-1266).
  **packager**
- `_alpm_strtoofft` does not range-check: 2^63..2^64-1 become negative
  (util.c:1435). **packager**
- `local_db_read` loops `while(!feof(fp))`, and a `safe_fgets` NULL at
  the end leaves `line` as it was: a desc whose last value is not
  followed by a blank line reads that value again as a key, logging
  "unknown key" (`%DESC%\nfoo\n`), or storing a key-like value twice
  (`%BASE%\n%DESC%\n` sets desc to "%DESC%") (be_local.c:748-755,
  685-688). pacman writes a blank line after every section. **local**
- every READ_* macro of `sync_db_read` treats the end of the entry data
  as an error (be_sync.c:533-555): a list, `%FILES%` or a value running
  into the end of a desc without its blank line (or final newline)
  invalidates the whole db. repo-add writes the blank lines.
  **packager**
- `_alpm_archive_fgets` checks `max_line_size` only once the line buffer
  exists, so a line over 512 KiB is accepted when it sits in the first
  data block it is read from (util.c:1269-1273), refused elsewhere.
  **packager**
- `_alpm_pkg_check_meta`'s "invalid package metadata (name or version
  missing)" has no '\n' (package.c:835); its length check cannot fire for
  local entries, whose directory names are at most NAME_MAX.
  **none**
- `HAVE_STRUCT_DIRENT_D_TYPE` is never defined by meson, the d_type
  shortcut is dead and a symlink to a dir in `local/` becomes a package
  (be_local.c:392). **local**
- `local_db_read(pkg, INFRQ_BASE)` in populate loads nothing, the
  "corrupted database entry" path is dead (be_local.c:627). **none**
- `local_db_add_version` failing inside `local_db_create` returns without
  setting pm_errno: `alpm_initialize` fails with `ALPM_ERR_OK`
  (be_local.c:422-424, 449-451). **env**
- `is_dir` truncates paths at PATH_MAX (be_local.c:399); the version file
  is read with fscanf `%zu`, so `+9`, ` 9junk` read as 9 (be_local.c:507).
  **local**
- stale comment "between 3 and PATH_MAX characters" (be_sync.c:506), no
  zstd case in `estimate_package_count` (be_sync.c:387-412). **none**

## `db.c` / `handle.c` minor

- the group cache built while a pkgcache load failed stays empty after a
  later successful load: `load_grpcache` marks it loaded anyway (db.c:700,
  735) and `_alpm_db_free_pkgcache` returns early on a NULL pkgcache
  (db.c:566), so neither reload nor `alpm_db_update` (be_sync.c:239) clears
  it. pacman updates before touching groups. **api** (long-lived users)
- a package listing the same group twice creates two groups of that name
  (db.c:714-731), `-Qg`/`-Sg` show it twice. **packager**
- `canonicalize_path("")` indexes `path[len - 1]` with len 0
  (handle.c:424, 429), reachable through `add_cachedir("")`,
  `add_hookdir("")`, `set_gpgdir("")`. **api**
- `alpm_db_get_valid` reports DB_INVALID_SIG for any invalid sync db,
  content errors included (be_sync.c:79-81, 475). **none**
- `sanitize_url("/")` stores an empty server URL (db.c:181). **local**
- `_alpm_db_path` caches the path with the dbext of registration time,
  `sync_db_populate` divides the size estimate by 4 on the dbext of load
  time (db.c:402-432, be_sync.c:450): changing dbext in between sizes the
  table for the wrong file. pacman sets dbext before registering.
  **api**
- `alpm_db_set_servers`/`set_cache_servers` free the old list before
  validating, a bad URL leaves a partial list (db.c:144, 164);
  `alpm_option_set_logfile` dereferences the handle before CHECK_HANDLE
  (handle.c:572); `alpm_option_add_architecture` has no CHECK_HANDLE and
  pushes an unchecked strdup (handle.c:819). **api / env**

## `src/pacman/database.c` minor

- `pacman_database` overwrites the `-Dk` result with the reason change's
  (database.c:300-302); checkargs_database refuses `-k` with
  `--asdeps`/`--asexplicit` (pacman.c:590-595). **none**
- `file->name[strlen(file->name) - 1]` reads before an empty name
  (database.c:197); the local `%FILES%` reader stops at an empty line
  (be_local.c:865-866). **none**
- `all_files` from an unchecked `malloc` (database.c:189). **env**
- paths built with `snprintf(path, PATH_MAX, ...)` are cut silently, a
  dbpath near PATH_MAX reports present desc/files as missing
  (database.c:122, 135, 140). **env**
- the owners of a file listed twice print in the order glibc's `qsort`
  leaves equal names (database.c:221): stable through its merge sort,
  not when it falls back to quicksort for big lists. **none**
- `-D` prints "install reason has been set" also when the reason was
  already that one (database.c:72-83, be_local.c:1189-1192). **none**
- `local_db_read` never sets INFRQ_BASE (be_local.c:740-919): populate's
  INFRQ_BASE read logs a "loading package data" line per package
  (be_local.c:627), and a sync populate failure logs "freeing package
  cache" for a cache never marked loaded (be_sync.c:477, 484). **none**

## `src/pacman/package.c` / `signing.c` minor

- uninitialized `siglist` freed when the package file is gone between load
  and display (package.c:365-378, signing.c:550-552). **env**
- `alpm_extract_keyid` reads `sig[pos + 1]` one byte past the signature
  when the hashed area ends at len-1 (signing.c:1188) and `blen - hlen -
  8` can underflow (1197); 4-byte lengths shift a signed int, a top byte
  >= 0x80 is UB and can wrap `pos` backwards (1052, 1112, 1143), reached
  from `alpm_pkg_load` on a crafted `.sig` before verification.
  **packager**
- the `-1` "unset date" check never matches, missing dates print as
  1970-01-01 instead of "None" (package.c:202, 206). **packager / local**,
  cosmetic
- "Extended Data   :" is a literal, not translated or aligned
  (package.c:363); Installed Size reuses the download size unit
  (package.c:318-326). **real**, cosmetic
- `dump_pkg_backups` (exported) uses titles only filled by
  `dump_pkg_full` (package.c:189-196, 383-386); `printf(_("None"))` uses a
  translation as format string (package.c:241). **none**

## `package.c` / `util.c` follow-up minor

- an uppercase `%SHA256SUM%` fails package validation in C
  (`_alpm_test_checksum` strcmp, util.c:1198-1218, be_package.c:321);
  the port reads the sum as written and compares bytes, failing alike.
  **packager** (repo-add writes lowercase)
- IgnorePkg/IgnoreGroup use `alpm_list_find` + `_alpm_fnmatch`, so a
  leading '!' is a literal, while NoUpgrade/NoExtract negate with it
  (package.c:795-812). **local**, inconsistency
- `compute_requiredby` dereferences `origin_data.db` for unset origins
  (package.c:507-508); pm_errno after success reflects the last db searched
  (package.c:470-490). **api**

## `be_package.c` minor

- metadata-only load misses `.INSTALL` after `.PKGINFO` unless it is in
  the dotfile run right after it: the `.PKGINFO`/`.MTREE` branches
  `continue` before the break check (be_package.c:606-607, 613).
  makepkg puts `.INSTALL` first. **packager**
- a second `.PKGINFO` entry is parsed into the same package, overwriting
  without freeing and appending lists (be_package.c:192-215). **packager**
- a `./.INSTALL` mtree line before a later mtree parse error leaves
  `scriptlet` set while the file list falls back (be_package.c:497).
  **packager**
- a failed mtree build sets pm_errno LIBARCHIVE, the load still succeeds
  (be_package.c:454-509, 612). **api**
- hard links in the archive-scan path get mode 0644 without type bits
  (be_package.c:419, from libarchive). **packager**, cosmetic
- the swapped `_alpm_pkg_check_meta` check lets `pkgname = f*` load
  (be_package.c:667). See above. **packager**
- a nul byte in `.PKGINFO` ends a line only when no '\n' follows in the
  same libarchive data block (`_alpm_archive_fgets`, util.c:1263-1266),
  so `a = b\0c = d\n` reads as one line or two depending on compression
  and where the entry sits in the archive. **packager**
- `size = ` past `LLONG_MAX` is cast to a negative `off_t` (util.c:1435,
  be_package.c:220), up to `ULLONG_MAX` (which gives -1). **packager**
- an `xdata` value without '=' refuses the whole package with only
  "could not parse package description file", no line naming the cause
  (be_package.c:248-251). **packager**, message only
- a line whose first space does not start " = " (`key\t= v`, an indented
  key) is dropped with a debug line only (be_package.c:182-186); unknown
  key lines read before `pkgname` name the package "error"
  (be_package.c:254). **packager**, cosmetic
- the first `_alpm_archive_fgets` allocation skips the `max_line_size`
  check (util.c:1269-1279): a first line inside the first data block may
  pass 512 KiB. Data blocks stay below that (64/128 KiB filters, fd reads
  of st_blksize), so **none**
- `_alpm_pkg_check_meta`'s "invalid package metadata (name or version
  missing)" lacks its '\n' (package.c:835). **none** from be_package (the
  load refuses both before)

## `src/pacman/check.c` minor

- `strcmp(link, archive_entry_symlink(entry))` gets NULL for a link entry
  without `link=` (check.c:145). **packager** (makepkg writes `link=`)
- `archive_entry_digest` never returns NULL, so "checksum information not
  available" is dead and a missing sha256 shows as a mismatch
  (check.c:183-197, 226). **packager / real (old mtrees)**
- `_cache_mtree_next` turns ARCHIVE_WARN into -1, so `-Qkk` stops silently
  at the first warning and prints totals as if complete (be_local.c:296-
  309). **packager**
- a gzip'd local mtree cut past the open's read-ahead reads as a shorter
  complete one (libarchive's `readline`, below): `-Qkk` checks part of
  the files and reports success. **env** (pacman writes the file; disk
  full or a crash cuts it)
- build_filelist_from_mtree logs a failed `.MTREE` at debug level only
  and keeps the archive's list; a cut `.MTREE` past its first filter
  block gives a partial list with no message at all (be_package.c:
  483-500). **packager**
- NoExtract for `.INSTALL`/`.CHANGELOG` is matched at `filepath + rootlen`
  of a dbpath-based path: wrong string, and uninitialized bytes when that
  path is shorter than root (check.c:34, 351). **local**
- any top-level packaged dotfile is skipped by `-Qkk`, not only metadata
  (check.c:333-347). **packager**
- fast type-mismatch warning ignores `-q` (check.c:275); "path too long"
  unreachable with a normal root (check.c:264). **none**
- VLA sized from `lstat` `st_size + 1` (check.c:135-136). **env**

## `src/pacman/pacman.c` minor

- -F falls back to `parsearg_trans`, accepting `-d`, `-p`, `--dbonly`,
  `--noscriptlet`, `--print-format`, ... that do nothing for -F
  (pacman.c:847); usage shows `--sysroot` without `<path>` (217). **real**,
  cosmetic
- `--config`/`--logfile` cut at PATH_MAX by strndup (432, 495). **local**
- `-Qs`/`-Qo` conflict message names `--upgrade` (677); `{"force",
  OP_FORCE}` has no handler and widens abbreviation ambiguity (1019);
  `--ask=-1` wraps (396); only the first `-` target reads stdin (~1232).
  **none**
- with POSIXLY_CORRECT set getopt stops at the first non-option, `pacman
  pkg -S` fails. **env**

## regex (glibc, as pacman uses it)

- search results depend on the locale (pacman.c:266 `setlocale(LC_ALL,
  "")`, db.c:465, files.c:127): in C.UTF-8 `pacman -Ss '[à-ü]'` fails with
  an invalid-regex error. **env**
- escaped letters never match under REG_ICASE (the escaped byte keeps its
  case, the text is upper-cased): `pacman -Ss 'python\d'` finds nothing.
  **real** (user search terms)
- REG_ICASE loses matches after characters whose upper case has another
  UTF-8 length (`B` vs "ɐb"). **real (rare)**
- `(a*)\1+*` overflows the regexec stack, `(.)**{1,2}\1` is
  exponential: `-Ss`/`-Fx` with such a term crashes or hangs (user's own
  process). **none**
- backrefs to repeated groups miss matches, anchors inside `{m,n}` copies
  only count once. **none**

## `conflict.c` / `diskspace.c` / `deps.c` / query / sync minor

- conflict: on `ALPM_ERR_MEMORY` (or a stale one, never reset) the file
  conflict list is freed with `alpm_conflict_free`, passing strings as
  packages (conflict.c:470-472, 653-655). **env**
- conflict: a conflict is silently dropped when the local package's
  metadata cannot load (`_alpm_pkg_dup` fails, conflict.c:52-53). **local**
- conflict: `pathlen` from snprintf is the untruncated length, root + path
  >= PATH_MAX with an existing cut prefix reads/writes past the stack
  buffer (conflict.c:516, 529, 540). **packager**; unchecked malloc
  (608-609) **env**
- diskspace: `_alpm_check_downloadspace` rounds with `+ 1` instead of `- 1`
  (diskspace.c:415), one or two extra blocks per file. **real**, small
  and conservative
- diskspace: dotfiles are charged to `root + dbpath` with an absolute
  dbpath ("//var/lib/pacman/"), never matching a separate `/var` mount
  (diskspace.c:319-322). **real** (/var on its own partition), small
- diskspace: freed space credited from `st_size`, so hard-linked or sparse
  files over-credit and the check can pass before the disk fills
  (diskspace.c:285). **real (rare)**
- diskspace: f_blocks/f_bavail (f_frsize units) mixed with f_bsize, and
  division by f_bsize without a zero check (diskspace.c:285, 344, 355-360);
  empty table returns -1 without pm_errno (390, 444). **env**
- diskspace: empty `mount_dir` under-reads (diskspace.c:216, hand-edited
  regular-file mtab) **local**; signed block sums can overflow on absurd
  sizes (286, 345) **packager**; `mnt_dir == NULL` check dead (114) **none**
- deps: a nested `_alpm_resolvedeps` failure leaves depmissing entries in
  `*data` after the local fallback recovers (deps.c:836, 845-846); sync.c
  later appends `alpm_conflict_t` to the same list and the frontend reads
  every entry as a conflict (sync.c:552, 624; src/pacman/sync.c:789-790).
  **packager** (crafted repo metadata); seen live in 4/2000 trans_prep
  fuzz cases
- deps: NODEPVERSION overwrites `depend->mod` in place on cached packages
  and the report loses the version constraint (deps.c:330-381) **api**;
  pm_errno after a failed `_alpm_resolvedeps` can be OK (309, 811, 839),
  cycles only logged at DEBUG (184-193) **none**
- query: `search_path` strips trailing '/' with `plen == 0`, touching the
  byte before the PATH copy for an empty or all-slash first component
  (query.c:60-61). **env**
- query: `-Qo` resolves into `char rpath[PATH_MAX]` with unbounded
  strcpy/strcat before the length check (query.c:124-128, 158, 190-192,
  205). **local** (own command line)
- db search returns 0 with pm_errno left set when a cache fails to load
  (db.c:452). **api**
- files: name search uses `strrchr(name, '/')`, so top-level package
  files never match `-F`/`-Fx` (files.c:183). **packager**
- signing: `parse_subpacket` reads `sig[spos]` with `spos == len` after
  the length check (signing.c:1055), 1-byte over-read on a crafted
  `%PGPSIG%` via -Sii (suspected, not probed). **packager**
- sync: NULL repo to `printf("%s")` and NULL db in `sync_list`, both
  unreachable through `check_syncdbs` (sync.c:443, 487-493) **none**;
  unchecked malloc/strdup (files.c:135, sync.c:409) **env**

## `signing.c` minor

- gpgme's engine home is fixed by the first handle's gpgdir (static
  `init`, signing.c:146-196): later handles and `set_gpgdir` changes are
  ignored, the keyring warning and NOT_A_FILE come once and NOT_A_FILE
  survives successful checks. **api**
- `siglist->count` is set before the per-signature key lookups, a failure
  partway returns -1 with zeroed (VALID/FULL) entries that be_sync.c:117
  hands to `_alpm_process_siglist` (signing.c:621, 659). **env**
- `key_import_wkd` treats a -1 lookup error as imported (signing.c:284).
  **env**
- an expired db-signing key that the keyserver still serves imports with
  result 0, so the validate retry loop asks again for every yes
  (be_sync.c:109-123; not verified, needs network). **real (rare)**
- an empty `.sig` fails `fread` of 0 bytes, `pacman -U` stops with
  "failed to read signature file" even at Optional (be_package.c:704,
  730-736). **real (rare)**; `.sig` over 16384 bytes refused **packager**
- the package is fully loaded and freed once per unknown key
  (be_package.c:744-748). **real**, cost only
- two debug lines report `gpg_err` after it was left at
  GPG_ERR_NO_ERROR, "gpg error: Success": a keyserver import whose
  result is not 0 (signing.c:424-425, the import's own code is not
  shown) and a WKD lookup that found a key other than the wanted one
  (signing.c:284-294). **none**, the debug text only
- every helper failure, corrupt `.sig` included, reports PKG_INVALID_SIG
  (be_package.c:341). **real**, message only

## `alpm_db_update` can fail with `ALPM_ERR_OK`

Practice: **real**. Arch's default `SigLevel = Required DatabaseOptional`
with the official dbs shipping no `.sig`: any custom repo listed before
them that fails validation triggers it.

In the validation loop (be_sync.c:255) a db failing with DB_INVALID_SIG
sets pm_errno, then a later db with a missing optional signature goes
through `_alpm_check_pgp_helper`, which sets `pm_errno = ALPM_ERR_OK`
(signing.c:817). The update returns -1 and pacman prints "failed to
synchronize all databases (unexpected error)".

- port: keeps the last failure's errno
- difftest: `errno_reset_pinned`

## stale `.sig` kept after a sync

Practice: **real (rare)**. Needs a repo with optional signatures that
stops serving (or fails on) its `.sig`.

be_sync.c:207-209 queues the signature with dload's optional flag: a 404
or server error on the `.sig` leaves the previous sync's `<db>.sig` in
place, the new db is checked against it and turns invalid.

- port: same behaviour
- difftest: `signatures` ("optional missing")

## `%BACKUP%` written with a `(null)` hash

Practice: **real**. 15/804 entries in a real local db carry it.

be_local.c:1118 prints `%s` of `backup->hash`, NULL when the package had
no md5 for that file; glibc writes `(null)`. The reader then keeps
`(null)` as the hash string.

- port: writes `(null)` like the C, the reader keeps it as the hash
- difftest: `be_local_write`

## local db writing and `_alpm_unpack` minor

- no write error checked in `_alpm_local_db_write` (`fprintf`/`fputs`
  984-1130, `fclose` 845/906/926): a full disk leaves a short desc/files
  and returns 0. **env**
- `umask` around prepare/write (be_local.c:941/984) and `umask(0022)` +
  `chdir(prefix)` in `_alpm_unpack` (util.c:351/360) are process-wide.
  **env** (threaded API users)
- `alpm_pkg_set_reason` has no range check, writes `%u` of any value;
  the reader logs "unknown install reason" (be_local.c:1179-1196, 1038).
  **api**
- `archive_read_extract(..., 0)` without SECURE_NODOTDOT /
  NOABSOLUTEPATHS / SYMLINKS (util.c:407): absolute or `..` entries land
  outside the prefix. The only caller filters to `.INSTALL` (trans.c:379).
  **none**, cheap hardening
- `archive_read_extract2` turns header/write failures into ARCHIVE_WARN:
  an `.INSTALL` that cannot be created gives a warning, `_alpm_unpack`
  returns 0, `grep()` fails to open it and the scriptlet is skipped with
  retval 0 (util.c:407-418, trans.c:379/392). **env**
- libarchive reads a directory entry's data (type '5', or a regular
  entry ending in '/') as the next header, ending extraction quietly with
  success. **packager**
- `_alpm_unpack` and the add.c extraction loops stop at any header
  result other than ARCHIVE_OK, ARCHIVE_FATAL included (util.c:367,
  add.c:550/564): a compressed package cut where a header lies in the
  failed 64/128 KiB filter block extracts the entries before it and
  returns success. **none**: pacman loads every package in full first
  (`-U`, sync), and that walk fails on any cut with LIBARCHIVE; only a
  file changing between load and commit gets here (**env**)

## add.c commit minor

- an intervening symlink is unlinked silently: with UNLINK |
  SECURE_SYMLINKS (add.c:118-123) extracting `usr/lib/y` over a `usr/lib`
  symlink to a directory replaces the link with a real directory;
  conflict.c (~521) only flags it when the package lists the `usr/lib/`
  entry, which makepkg always does. **packager**, or real with
  `--overwrite`
- the commit hangs on a fifo: `alpm_compute_md5sum` opens a backup path,
  its `.pacnew` or a symlink to a fifo and `open(2)` blocks forever
  (add.c:335, 357-358). **packager** (port: same)
- pm_errno PKG_CANT_REMOVE from the remove step survives a successful
  upgrade (add.c:508, remove.c:718). **api**
- the -1 check after `_alpm_remove_single_package` is dead, it always
  returns 0 (add.c:508-511). **none**

## `sighandler.c` minor

- the soft handler calls printf/`fflush`, `alpm_trans_interrupt` and
  `alpm_unlock` in signal context (sighandler.c:52-74), not
  async-signal-safe (a signal mid-printf holds stdio's lock). **env**
- CURSOR_SHOW is written to stdout even when it is not a terminal
  (sighandler.c:63): Ctrl-C with redirected output leaves `\x1b[?25h`.
  **real**, cosmetic (port matches)
- "SIGINT sent, abort by alerting curl" is stale: `dload_interrupted` is
  only set for the max file size (dload.c:267-270, 281). **none**

## `pacman-conf.c` / `testpkg.c` minor

- `DisableSandboxFilesystem` cannot be queried: the `DisableSandbox` test
  appears twice (pacman-conf.c:415-418), `pacman-conf
  DisableSandboxFilesystem` warns "unknown directive" and exits 1.
  **real (rare)**
- `--repo-list --repo nope` prints nothing and exits 0, `--repo nope`
  alone fails (pacman-conf.c:126-135). **none**
- testpkg always opens the built-in DBPATH/GPGDIR, never pacman.conf's
  `GPGDir`; without `/var/lib/pacman` "cannot initialize alpm"
  (testpkg.c:63-71). **env**
- dead checks: `if(!config)` after `parse_opts` (pacman-conf.c:461-464),
  `alpm_release == -1` (testpkg.c:98-100). **none**

## `src/pacman/sync.c` -Sc minor

- `sync_cleandb` reads an uninitialised `st_mode` after a failed `stat`
  (sync.c:93-97), a dangling symlink in the sync dir. **local** (port:
  not a directory)
- failures cancel out in the exit status: `unlink_verbose` returns -1,
  an unreadable cache dir or failed `trans_release` adds +1 (sync.c:41-53,
  115, 126, 256, 302, 306, 207, 917); one of each exits 0. **env**
- an `rmrf` failure in `sync_cleandb` is printed with a leftover errno
  and not counted, `-Sc` exits 0 after "could not remove" (sync.c:98-102).
  **env**
- PATH_MAX overflow in `sync_cleandb` prints and carries on with the
  truncated path (sync.c:86-90). **none** (port mirrors it)
- `sync_cleancache` means to skip what does not load as a package at
  debug level (sync.c:260-267), but `alpm_pkg_load` has already logged
  "could not open file ...: Error reading fd N" (util.c:291) as an error
  for every directory, e.g. the leftover `download-XXXXXX` dirs (`dload.c`
  minor). **real**, cosmetic

## transaction prepare minor

- targets are the sync cache objects, mutated in place (sync.c:188-189,
  492, add.c:105, removes, oldpkg): a reason set in one prepare survives
  into the next transaction on the same handle, a target dropped to
  unresolvable comes back with its old removes. **api** (long-lived
  handles; pacman exits after one transaction)
- duplicate-filename check `strcmp`s NULL filenames (sync.c:474), a sync
  entry without %FILENAME%. **packager**
- replace check reads the union as a db for a file target (sync.c:173),
  always "cannot replace", right by accident. **none**
- `_alpm_pkg_dup` returns 1 on a failed force-load (package.c:580-586),
  callers test `== -1`: `alpm_remove_pkg` succeeds with pm_errno set
  (remove.c:75, 104). **local**
- "nothing to do" leaves the transaction initialized (trans.c:122-125), a
  later commit fails TRANS_NOT_PREPARED. **api**
- `alpm_trans_init` accepts any flag mix (trans.c:45-67); `if(data)` after
  `ASSERT(data != NULL)` (trans.c:115, 129). **none**

## `be_sync.c` minor

- the "removing invalid file" branch of `get_sync_dir` is dead: `stat`
  on `sync/` with the trailing '/' fails ENOTDIR for a regular file, and
  `_alpm_makepath` accepts EEXIST; the update fails later opening `.part`
  files, with no warning (be_sync.c:53-66). **local**
- `alpm_db_update` unlocks a lock the caller already holds:
  `_alpm_handle_lock` returns 0 when locked (handle.c:124) and cleanup
  always unlocks (be_sync.c:163, 271), removing a transaction's lock
  file. **api**
- `ASSERT(dbs != NULL)` runs before pm_errno is reset: an empty list
  returns -1 with a stale errno (be_sync.c:149-150). **api**
- "skip validation to preserve the download error" comment is stale, a
  failed download already left at line 233 (be_sync.c:254). **none**

## `dload.c` minor

- `ASSERT(chown(...), return)` returns when chown succeeds
  (dload.c:1194): with DownloadUser set (Arch's pacman.conf sets it),
  later payloads lose If-Modified-Since (dbs re-downloaded) and their
  `.part` files are not moved (resume lost). **real**
- "delete zero length downloads" fstats an unflushed FILE (dload.c:599-
  601): a last failed attempt under one stdio block unlinks a `.part`
  that has data. **real**, harmless
- the `dload_interrupted` static is set when a resumed download passes
  max_size and never cleared (dload.c:253, 268, 281, 560-562, 717): every
  later download in the process fails. **real (rare)**
- queueing a `.sig` runs `alpm_option_get_dbext`, whose CHECK_HANDLE
  resets pm_errno: with parallel downloads an earlier failure can end as
  -1 with ALPM_ERR_OK, "unexpected error" (dload.c:620). **real**, hit
  once by the db_update fuzz (timing dependent)
- a `.part` with `max_size == initial_size` is neither started nor
  renamed, stays `.part` forever (dload.c:785-789). **real (rare)**
- with the sandbox, the mkdtemp'd `download-XXXXXX` dir is left behind on
  early error paths, e.g. `-Sy` while the db is locked (be_sync.c:156,
  163, 271; sync.c:783, 885; dload.c:1283-1295; util.c:996-1002). **real**
  Also without an error: `alpm_fetch_pkgurl` with every url already
  cached never reaches `_alpm_download`, the only remover (dload.c:1339,
  1409, 1447), so each `-U <cached url>` leaves an empty dir in the
  cachedir; and a failing fetchcb returns through RET_ERR before the
  removal (dload.c:1284 vs 1294). **real**
  The same for `-S`/`-Su` with every package already cached:
  `download_files` makes the dir before `find_dl_candidates`, and with no
  files `_alpm_download` never runs (sync.c:782-797); each such
  transaction adds one empty dir to the first cachedir (twin-root: one
  per install step). **real**
  Seen on a real system: 58 leftover `download-*` dirs in
  `/var/cache/pacman/pkg` (Arch default DownloadUser, C pacman 7.1).
- sandboxed downloads count server errors in the forked child's copy of
  the handle (dload.c:920-1060): a mirror failing during `-Sy` is not
  remembered for the package downloads of the same `-Syu`, unlike
  without the sandbox. **real**, cosmetic
- `_alpm_filecache_setup` tests `stat(tmpdir) && S_ISDIR` inverted, a valid
  TMPDIR is never used (util.c:944) **env**; a CacheDir that is a regular
  file is accepted (util.c:911-916) **local**
- only the first URL is validated, a retry server without "//" leaves the
  hostname buffer uninitialized for "failed retrieving file"
  (dload.c:451-455, 517, 535, 778) **local**; the .sig `curl_add_payload`
  result is ignored (669-670) and `alpm_fetch_pkgurl` fails without
  pm_errno when `create_tempfile` fails (1396-1399) **env**; server
  errors persist for the handle's lifetime (136-222) **api**; warning
  format puts "\n" before strerror (util.c:875) **none**

## hooks, run_chroot, scriptlets

- an unterminated last output line is delivered twice: the read at EOF
  does not reset `*buf_size`, the leftover flush sends it again
  (util.c:556-561, 760-764; read-error branch 566-569). Any scriptlet or
  hook ending in `printf 'x'` duplicates its last line. **real**
- the stdin feed races the child: a NeedsTargets hook exiting early logs
  "unable to write to pipe (Broken pipe)" or not depending on timing
  (util.c:490-518, 727-756). **real (rare)**
- `Operation`/`Type`/`When` without `=` pass NULL to strcmp (hook.c:177,
  190, 209); `Target` without `=` stores NULL that fnmatch dereferences
  (hook.c:197-200, util.c:1537); empty `Exec =` passes validation and
  execv(NULL) (hook.c:235, 521). **packager** (hooks ship in packages)
- `AbortOnFail`/`NeedsTargets` values are ignored, `AbortOnFail = false`
  enables it (hook.c:226-229). **packager / local**, cosmetic
- a hook that fails to parse does not mask the same-named hook in a lower
  priority dir: an admin override with a typo silently runs the packaged
  hook (hook.c:605-611). **local**
- `grep` loops on `!feof` and spins on a read error; a name split across
  1023-byte chunks or after a `#` skips the scriptlet silently
  (trans.c:316-325). **env / packager**
- `chdir(root)` failure reports success without running (util.c:628-633)
  **env**; the forked child calls non-async-signal-safe functions
  (util.c:691-701) **api**

## sandbox

- `ret = errno` after `seccomp_load` fails: without errno set the download
  runs unfiltered while logging "...: 0!" (sandbox_syscalls.c:156, 165).
  **env**
- a kernel without Landlock makes every sandboxed download fail unless
  DisableSandboxFilesystem is set (sandbox_fs.c:111-115). **real** (by
  design)
- `alpm_sandbox_setup_child` fails its root and getpwnam checks silently
  (sandbox.c:56-57); callback type read without EINTR retry (dload.c:1000).
  **api**
- `alpm_sandbox_setup_child` restricts writes (landlock) before it sets
  no_new_privs (sandbox.c:58-66): `landlock_restrict_self` needs one of
  no_new_privs or CAP_SYS_ADMIN, so it only works as real root. Under
  fakeroot every sandboxed download fails ("restricting filesystem
  access failed ... Operation not permitted"); with
  DisableSandboxFilesystem it works. **env**
- XferCommand switches to DownloadUser whenever it is set (conf.c:247,
  `config->sandboxuser`), not where `_alpm_use_sandbox` holds: with
  DisableSandbox the download dir is the root-owned sync dir or cachedir
  (util.c:964, 1005), the command runs as DownloadUser and cannot write
  there. **local** (DownloadUser is in Arch's default pacman.conf).
  download_with_xfercommand returns 0 (success) after a failed argv
  calloc (conf.c:322-329, ret starts at 0). **env**
- SIGTERM sent after every normal EOF, unknown callback types skipped
  (dload.c:1000-1022); 0-byte pipe writes refused (sandbox.c:84, 108);
  chroot/pivot_root listed twice (sandbox_syscalls.c:43/95, 52/100);
  `ruleset_fd` leaked on early returns (sandbox_fs.c:140, 157). **none**

## `escape_chars` writes its nul past the buffer

Practice: **local**. `--sysroot` (or an Include pattern under sysroot
with GLOB_NOESCAPE) whose path contains `\`, `*`, `?` or `[`.

conf.c:1111-1150 allocates `len + escaped` bytes and writes the
terminating nul one byte past them. On glibc it corrupts the heap when
that size is 16k+8 (no chunk slack): `free(): invalid size` aborts.
Found through the conf difftest aborting only with longer TMPDIR paths.

- port: no buffer
- difftest: odd-root fixture names padded so the size avoids 16k+8

## `handle.c` / `log.c` / frontend `util.c` minor

- `alpm_option_get/set_disable_sandbox` declared in alpm.h:2314/2321 but
  not exported (no SYMEXPORT, handle.c:971, 984). **api**
- `alpm_logaction` ignores `fflush`'s result, a full disk on a line under
  the stdio buffer returns 0 (log.c:94); fd leaked when fdopen fails
  (log.c:65). **env**
- add/remove assumeinstalled compare different name_hash sources
  (handle.c:758, 785); `set_sandboxuser` drops the old user before
  validating (606-617); parallel_downloads returned as int (363-366).
  **api**
- `multiselect_question` keeps the grown buffer and its last bytes after
  an invalid answer: a long invalid selection can swallow the next line
  (util.c:1567-1609). **real (rare)**
- `multiselect_parse` ties "deselect all first" to strtok's first token,
  a whitespace-only first token keeps everything selected (util.c:1486).
  **real (rare)**
- `print_packages` passes `localtime()` unchecked to strftime
  (util.c:1224-1230, same as the -Si build date crash) **packager**;
  `pkg_get_location` with a NULL filename prints "(null)" or crashes in
  strdup (util.c:1118-1137) **packager**
- `select_display` NULL handling (1427-1440), `target_cmp` returns 0/1
  (1043), `parseindex("")` is 0 (1447-1448). **none**

## `callback.c` minor

- `bar->eta = (total_size - sync_xfered) / rate` converts a negative
  double to unsigned (callback.c:940), undefined: whenever the size is
  unknown (no Content-Length) or ETA > UINT_MAX; x86_64 wraps ("--:--"),
  aarch64 saturates ("00:00"). `(off_t)bar->rate` (851) same class.
  **real**, display only. The port reproduces x86_64.
- "name (n/m)" buffer sized by the digits of `howmany`, a larger
  `downloaded` count is cut ("Total (10/4") (806-810). **none**
- singular SELECT_PROVIDER line lacks the plural's ':' (521-522); libalpm
  only asks with more than one provider. **none**
- `parseindex` stores strtol's long in an int: "4294967298" selects entry
  2 (util.c). **real (rare)**, user input

## `src/pacman/conf.c` minor

- CacheServer `file://` URLs do not get the sysroot, Server ones do
  (conf.c:1344). **real (rare)**, with `--sysroot`
- `resolve_path` message has a stray leading quote and no `_()`
  (util.c:1977). **real**, cosmetic
- Include order follows the locale (glibc glob sorts with strcoll).
  **real (rare)**
- repeated XferCommand leaks the old argv/string; a wordsplit failure
  keeps the old command and a stale argc (conf.c:727, 737). **local**
- on an invalid value `process_usage` and CleanMethod keep the valid
  bits, `process_siglevel` drops everything (conf.c:548, 573-580, 1051).
  **local**
- `setdefaults` truncates at PATH_MAX (conf.c:1382, 1392) **local**;
  indexes `rootdir[len-1]` without a length check (conf.c:1373-1377),
  unreachable through realpath **none**; unchecked strdup/calloc
  (conf.c:600, 717, 722, 1073, 1076, 1287-1288) and ignored
  `prepend_sysroot` result (conf.c:1429) **env**
- `config_free` frees the global's repos instead of its argument's
  (conf.c:142-143); pacman always passes the global. **none**
- `section->name` dangles after an include with a header, only ever
  NULL-checked (conf.c:1282, 1300); `replace_server_vars` reads the
  global instead of its parameter (conf.c:823). **none**
- `register_repo`'s result is ignored (conf.c:964-966): a section that
  fails to register (duplicate, `[local]`, a '/' in the name) is reported
  and pacman carries on. **local**
- "Failed to pass %s entry to libalpm" lacks its newline (conf.c:1005),
  `--assume-installed 'foo>1'` reaches it and exits 255. **real**,
  cosmetic
- `'sandboxuser' (%s) does not exist` debug log lacks its newline
  (handle.c:617). **none**
- `_getumask` (umask(0) then restore) is not thread safe (dload.c:69-72),
  concurrent calls chmod 0666. **api** (threaded users; the dload difftest
  flake)

To be written up and reported through pacman's usual channels by the
maintainer of this repo, not from here.

# libarchive findings

`archive_read_support_format_mtree.c` at libarchive 3.8.9, met while
translating it (`alpm-core::mtree`). Same practice labels, judged by
what pacman reads (bsdtar's `.MTREE`, copied as the local `mtree`).

- `readline` returns 0 (end of data) whenever `__archive_read_ahead`
  gives NULL, a failed filter included; its `bytes_read < 0` check after
  that is dead. A stream cut past the open's read-ahead reads as a
  shorter complete file. **env**
- a nul byte stops `readline`'s scan for good (`for (u = ...; *u; ++u)`
  restarts at it): the rest of the data is appended to that one line,
  dropped at the end of data when under 64 KiB, "Line too long"
  otherwise. **packager / local**
- `readline` resumes its scan after a backslash that ended a read-ahead
  block, so a `\` and the `\n` after it split across two blocks end the
  line instead of joining it (also `\` `\r` | `\n`). `detect_form`'s `next_line` returns 0
  or the tail's length for a last line without newline depending on
  whether its earlier read-ahead already covered the data, which decides
  the bid on data without signature. Neither is modelled (the port sees
  one buffer). **none** (bsdtar writes no continuation lines, pacman's
  files have the signature)
- `read_mtree` runs `detect_form` even after the `#mtree` signature: if
  the first entry lines put the path last (NetBSD's `mtree -D`), the
  whole file is read that way. **packager**
- the non-printable check uses `isprint` in the caller's locale (pacman
  calls `setlocale(LC_ALL, "")`): in a single-byte locale such as
  ISO-8859-1, bytes from 0xa0 pass and the line is read. The port keeps
  the C/UTF-8 result. **env**
- "Non-printable character 0x%02X" is overwritten by "Can't parse line
  %ju" before it can be read. **none**
- a path listed again takes the `/set` keywords current at that line
  too, so `./a uid=3` followed by `./a type=dir` under `/set uid=0`
  ends with uid 0: later lines override with defaults, not only with
  what they spell out. **packager**
- the freebsd device format accepts a negative minor whose int32 value
  matches (`device=freebsd,1,-65281`), the `(int32_t)` read-back sign
  extends. **none**

# ALPM findings

Applied in `vendor/patches/` today: gzip members 0551, content sniffing
0552, decoder over any reader 0553. Kept as reports in
`vendor/upstream-reports/`, no longer applied: version ordering
0101/0102, `Unknown Packager` 0105, relation backtracking 0106, empty
xdata value 0107, alpm-mtree `PathType` `PartialEq` 0401, gzip members
in its helper 0403, `Error::Parse` display 0411 (alpm-mtree is no longer
used: `alpm-core::mtree`; 0402, 0404-0410 bent it into libarchive's
reader and are gone). The alpm-db/alpm-repo-db/alpm-pkginfo findings
below came from patches dropped with the owned readers (PORTING.md
"Owned readers"); they stay valid as reports. Further notes from the patch work:

- alpm-mtree `Error::Parse` display broken (`error-parse` wants `$source`,
  code passes `error`). **api**, to report

- strict desc parsers allow one blank line between sections only,
  against the spec. **packager**
- alpm-db-files' "Empty lines are ignored" contradicts upstream's own
  `empty_line_in_list_of_paths` fixture. **none** (spec wording)
- keeping `(null)` backups needs an exemption from the not-in-`%FILES%`
  check, pacman writes them for exactly those paths. **real** (2/804)
- layer strings swapped between alpm-db and alpm-repo-db ("alpm-repo-desc
  file value section" in alpm-db and the reverse). **none**

Issues in the ALPM crates (`alpm/` at `0eedcb8`) met while using them for
pacman's formats. Same practice labels, judged against real databases.

- alpm-types `Version`/`FullVersion` Ord treats an explicit epoch 0 as
  greater than no epoch (pkg_generic.rs:195-201, pkg_full.rs `cmp`), while
  libalpm treats a missing epoch as "0" (version.c:54-62). **packager**
- alpm-types `Version` Ord counts a pkgrel present on one side only, where
  libalpm skips the release (pkg_generic.rs:211, version.c:251):
  `foo>=1.5-3` is satisfied by `foo=1.5` in libalpm, not in ALPM
  (requirement.rs:86-98). **packager**
- alpm-types `OptionalDependency` starts the description at ':' + any
  whitespace and trims it, empty becomes None (relation/base.rs:380-397);
  libalpm splits at the first ": " and keeps the raw text. **packager**
- alpm-types prints pkgrel without leading zeros (`1.0-01` -> `1.0-1`).
  **none**
- regex classes via std vs glibc: unassigned code points graph/print/
  punct in std (814730), non-ASCII Nd digits alpha in glibc only (760),
  no-break spaces, U+0085, U+2028/9, titlecase letters, 27 Greek
  ypogegrammeni letters under icase. **real (rare)** for -Ss/-Qs
- alpm-types `Packager` rejects `Unknown Packager`, makepkg's default,
  so the whole desc becomes unreadable. **real** (1 of 804 local packages)
- alpm-db files: backups sorted by path, entries with hash `(null)`
  dropped (real local db: 15 and 2 of 804). **real**
- alpm-types `Url` normalizes (empty path gets '/'), no round trip.
  **real** (82/804 local, 1330/15334 sync)
- alpm-types `RelationOrSoname` rejects valid relation names with 2+
  chars before `.so` followed by a letter (`foo.sound`, `d1.so62r`): the
  SonameV1 branch fails without backtracking (relation/composite.rs:46-50).
  **packager** (no such name in current repos). Found by both db units.
- alpm-types `ExtraDataEntry::parser_until`: an empty value swallows the
  next line (`a=\nb=c` -> key `a`, value `b=c`). **packager**
- alpm-db desc v2 detected by `contains("%XDATA%")` anywhere
  (desc/schema.rs:64), so a v1 desc mentioning it in a text field fails.
  **packager**
- alpm-db files: spec says empty lines are ignored, the parser ends
  `%FILES%` at the first blank line and errors on the rest. **local**
- alpm-repo-db has no `%DATA%` (xdata) section, which pacman 7 reads.
  **real** once repos ship xdata
- alpm-repo-db `RepoFilesV1` dedups/sorts paths as `PathBuf` components,
  `usr` and `usr/` count as duplicates. **packager**
- alpm-mtree sorts entries by path (`paths_from_parsed_content`,
  `sort_unstable`): file order lost on 386/804 real mtrees, duplicates
  kept. **real** (output order)
- alpm-mtree `mode` parser takes 3-4 digits (docs: 3-5); bsdtar writes
  `mode=%o`, so permissions 0000 or below 0100 (`mode=0`, `mode=44`)
  reject the whole mtree. **real (rare)**
- alpm-mtree `PathType` has no `PartialEq`. **api**, to report
- alpm-mtree drops `size` for dirs/links, refuses char/block/fifo types
  and file lines without `size`, which libarchive reads. **packager**
- alpm-pkginfo needs `pkgtype` as first xdata, refuses unknown keys
  (incl. `basever`, ignored by pacman) and `url = `. **packager**; an
  empty `$url` in a PKGBUILD would make it **real** (0 of 1250 cached
  packages have one)
- alpm-package `PackageReader` needs a valid file name, parses
  `.BUILDINFO`, needs UTF-8 `.INSTALL`. **api**
- alpm-mtree's gzip helper is private, reading `.MTREE` from bytes needs
  the `alpm_common::MetadataFile` trait; it reads one gzip member
  (`GzDecoder`). **api**, to report
- alpm-compress `CompressionDecoder` only decodes a `File`: compressed
  data in memory (a package's `.MTREE`) cannot use it. 0553 makes it
  generic over a `BufRead` (`from_reader`, `get_ref`), `new` unchanged.
  **api**
- tar (via alpm-compress) refuses the `S` type without a GNU header.
  **packager**
- alpm-compress gzip uses `GzDecoder`, reads only the first member
  (libarchive and gzip read all; `MultiGzDecoder` would match).
  **packager**
- alpm-compress decoders are not lenient on cut streams: gzip, bzip2,
  xz and zstd return UnexpectedEof at every cut point of a stream
  (flate2 1.1.10 `zio::read`/`read_into`, liblzma 0.4.8 "premature eof",
  bzip2 0.6.1, zstd "incomplete frame"). The parity gap was libarchive
  handing data on in whole filter blocks, handled in the port
  (`util::Filter`). **none**
- alpm-compress `TarballReader` only wraps a `CompressionDecoder` (built
  from a `File`): a tarball cannot be read through another `Read` layer
  or from memory, so the port uses the tar crate directly. **api**
- alpm-compress bzip2 uses `BzDecoder::new`, single stream (bzip2 0.6.1
  `multi: false`); libarchive reads concatenated streams (pbzip2
  output). From source, not exercised. **packager** (makepkg's
  `COMPRESSBZ2` set to a parallel bzip2)

## transaction commit minor

- sync.c:942 check_keyring: `keyinfo->uid = strdup(pkg->packager)` on a
  sync entry without `%PACKAGER%` is strdup(NULL). Practice: **packager**
  (a crafted repo db with package signatures required). The port passes
  no uid.
- sync.c:804 download_files: a failed CALLOC of the download sizes jumps
  to `finish` with ret still 0, so the downloads are skipped and the load
  goes on as if they had worked. Practice: **env** (OOM).
- sync.c:1080 check_validity: pm_errno is whatever the last validated
  package left (each `_alpm_pkg_validate_internal` resets it): an early
  bad package followed by a good one reports PKG_INVALID instead of its
  own error. Practice: **real** (message only; the per-package lines are
  right).
- remove.c:752 `_alpm_remove_single_package` always returns 0, so the
  failure branches of `_alpm_remove_packages` (TRANS_ABORT, ldconfig
  skipped) and sync.c:1347 ("could not commit removal transaction") are
  dead. Practice: **none**.
- sync.c download_files leaves the transaction DOWNLOADING after a failed
  load, so `alpm_trans_interrupt` refuses it until release. Practice:
  **api**.
