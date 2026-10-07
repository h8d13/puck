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
| `_alpm_pkg_check_meta` name check swapped | packager |
| `string_length` buffer one byte short | packager |
| `_alpm_splitname` precondition | packager / local |
| `_alpm_copyfile` write offset | env |
| `alpm_decode_signature` newline-only | api |
| `_alpm_filelist_intersection` empty names | none |
| `rawstr.c` no callers | none |
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

## `_alpm_pkg_check_meta` name check swapped

Practice: **packager**. makepkg refuses invalid package names, so only a
hand-crafted package or repo entry has one; the check meant to catch that
case does not work.

package.c:843 calls `_alpm_fnmatch(pkg->name, "[![:alnum:]+_.@-]")`, but
`_alpm_fnmatch` is `fnmatch(pattern, string, 0)` (util.c:1557): the name is
used as the pattern. The invalid-character check effectively never fires
(and the bracket would only match a one-character string anyway).
Found independently by two port units (package model, util.c).

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

To be written up and reported through pacman's usual channels by the
maintainer of this repo, not from here.
