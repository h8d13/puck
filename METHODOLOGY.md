# Porting methodology

How a C file of pacman becomes safe Rust here. Every port unit follows this,
whoever writes it.

## Three separate places

| What | Where | May call C |
|---|---|---|
| port source | `alpm-core/src/<cfile>.rs`, `pacman-common/src/<cfile>.rs` | no, `unsafe_code = "forbid"` |
| unit tests of the port | `<crate>/tests/<cfile>.rs` | no |
| equivalence tests | `difftest/src/<cfile>.rs` (C wrappers), `difftest/tests/<cfile>.rs` | yes, only here |

- Module name = C file stem (`lib/libalpm/deps.c` -> `deps.rs`).
- No `#[cfg(test)]` modules inside port source.
- Test helpers (binaries, probe programs, fixture writers) live in
  difftest, never in port crates, even when only used by hand.
- Port source comments explain translation (C locale, nul termination,
  buffer semantics). Upstream bugs or oddities never go in port source:
  report them back, they land in `UPSTREAM.md`.

## Translating

- Keep the C behaviour for every input where the C is well defined. Follow
  the C logic, but write idiomatic safe Rust (slices, `Option`/`Result`,
  owned structs instead of `alpm_list_t`).
- Strings are `&[u8]`/`Vec<u8>`, not `str`: the C is byte based. Inputs are
  cut with `util::until_nul` where the C sees a C string.
- `ctype` in the C runs in the C locale: use the `is_ascii_*` predicates.
- Platform-dependent C types keep their C alias (`c_char`, `c_ulong`).
- NULL handling of exported functions belongs to a future C ABI layer:
  pin it in difftest, do not model it in the Rust API.
- Where the C is undefined (out of bounds, uninitialized memory), the port
  does the safe thing and difftest must never feed the C that input.
- Dependencies: only what the official ALPM crates (`alpm/`) already use.
  Crates ALPM itself depends on count as precedent (base64, md-5, sha2,
  time, unicode-width, url, tar, compression, winnow): never hand-write
  what one of them implements. Keeping a port next to a precedent needs a
  stated reason (e.g. pacman semantics the crate cannot express) in
  `PORTING.md`.
- Use an ALPM crate where its semantics are pacman's: the alpm-compress
  decoders, checksums. ALPM's format parsers (`alpm-db`, `alpm-repo-db`,
  `alpm-pkginfo`, `alpm-mtree`, `alpm-package`) validate the spec
  strictly: required fields, typed values, UTF-8. pacman reads its files
  leniently and byte for byte, so pacman's readers are translated from
  the C like any other unit (be_local/be_sync desc and files,
  be_package's parse_descfile, libarchive's mtree reader), difftested
  equal on every input the C reads. ALPM types are used only where their
  value set is the C's.
- `vendor/patches/` (applied to the pristine `alpm/` submodule by
  `scripts/vendor-alpm.sh` into `vendor/alpm`) holds real ALPM bugs and
  missing capability of general use only, each written to go upstream
  (gzip members, content sniffing). Never a patch that bends a strict
  parser into pacman's semantics: own that reader instead. pacman bugs
  recorded in `UPSTREAM.md` are not copied.

## System-level decisions

Where pacman needs things the 10 core ALPM crates do not cover, the choice
follows the wider ALPM workspace, then parity:

| Need | Choice | Why |
|---|---|---|
| HTTP downloads (`dload.c`) | `reqwest` 0.13, blocking, rustls | ALPM `dev-scripts` uses exactly this |
| OpenPGP verification and keys (`signing.c`) | drive `gpg` over `--status-fd` like gpgme does | same engine, keyring (`/etc/pacman.d/gnupg`) and trust model as pacman; ALPM's VOA/rpgp stack cannot read gnupg keyboxes or trustdb |
| `statvfs` (`diskspace.c`), `umask` | `rustix` safe API | in ALPM's lockfile |
| getuid/geteuid, fchdir, tty width and tcflush, fd passing (`SCM_RIGHTS`) | `rustix` `process`, `termios`, `net` | same crate; `use-libc` backend so ids go through libc like the C's (fakeroot's LD_PRELOAD fakes libc, not raw syscalls) |
| chroot exec (scriptlets, hooks, ldconfig) | spawn `chroot(8)` via `std::process::Command` | no `pre_exec` (unsafe); works under fakechroot like the C's `chroot()` |
| run downloads and XferCommand as DownloadUser | spawned helper process (the binary re-executed), `CommandExt::uid`/`gid` | safe std, instead of the C's fork + setuid |
| landlock (`sandbox_fs.c`) | `landlock` crate | the Landlock maintainers' binding |
| seccomp (`sandbox_syscalls.c`) | `libseccomp` crate | binding to the same C library pacman links |
| lock file | `OpenOptions::create_new` | safe std (O_CREAT\|O_EXCL) |
| tar members, pax records, xattrs and ns times on extraction (libarchive's tar reader, archive_write_disk) | `alpm-core::tar` translated from libarchive 3.8.9; `rustix` `fs` for `fsetxattr`/`lsetxattr`, `futimens`/`utimensat`, `openat` O_PATH | the tar crate splits pax records on '\n' (binary xattr values lost), keeps a key's first record where libarchive keeps the last, has no pax sparse maps or ACL records and frames members its own way; `fs` is already enabled, no new feature, libc backend so fakeroot fakes the xattr calls |
| signal handlers (`sighandler.c`) | `signal-hook` 0.4: self-pipe `Signals` read by a thread, `flag::register_conditional_default` | std/rustix have no safe handler API, no ALPM crate installs one; the established binding (its registry also backs tokio's signals). the handler only writes to the pipe or reads a flag, the C handler's work runs on the thread |

No `unsafe` outside difftest: when something seems to need it, look for the
std/rustix safe API or an established binding crate first (the ALPM
pattern), and record the choice here before use.

## Equivalence testing (difftest)

- The C reference is `pacman/build` (meson), linked statically from
  `libalpm_objlib.a` and `libcommon.a`. Non-static internal functions are
  callable; `static` ones are tested through their callers.
- One wrapper per C function in `difftest/src/<cfile>.rs`: takes Rust
  types, calls C, copies results out, frees C memory, returns Rust types.
  Every `unsafe` block gets a `// SAFETY:` comment. C structs read via
  `#[repr(C)]` mirrors declared in that same module. libc/stdio items
  used by several modules (`CFile`, `CList`, `fclose`, `free`,
  `alpm_list_add`, `alpm_list_free`) are declared once
  in `difftest/src/lib.rs`, handle/db items (`CHash`, `CDb`,
  `alpm_initialize`, the `ALPM` lock, ...) in `difftest/src/handle.rs`;
  rustc flags clashing extern signatures.
- Tests in `difftest/tests/<cfile>.rs`:
  - fixed edge cases, then fuzz with `difftest::Rng` and `difftest::iters()`
  - alphabets built from the characters the C special-cases
  - assert messages show the input
  - if inputs are filtered (C preconditions), assert a minimum compared count
- Tests running C that sets the umask (dload, makepath,
  `local_db_prepare`/`write`, unpack), or comparing file modes next to
  it, take `difftest::umask_lock()` before any C handle (`ALPM` lock),
  never while holding one.
- Mutation check before reporting done: break 2+ branches of the port one
  at a time, confirm a difftest fails, restore.

## Style

Tabs, 80 columns (`rustfmt.toml`), inline `//` comments for the why,
short and lowercase like the existing files. `cargo fmt --check`,
`cargo clippy --all-targets` clean, no warnings.

## Integration gates

Unit difftests prove functions; milestones in `PORTING.md` prove the
binary. A milestone counts as reached only when its gate passes (CLI
parity against C pacman, then pactest). Units are picked in milestone
order.

Real-system equivalence, rootless (`scripts/twin-root.sh`, PORTING.md
"3b"): C pacman and the Rust binary run the same real operations on twin
roots inside one `unshare --map-auto --map-root-user --mount --pid`
session. uid 0 inside, the subuid range mapped (chown to any packaged
owner, DownloadUser `alpm`), `security.capability` and `user.*` xattrs
settable, chroot and mounts allowed, host network shared; the pid
namespace takes gpg-agent and any stray child down with the session.
Each side is bound in turn at one path on a tmpfs over /mnt, private to
the session: both binaries see identical paths, and `alpm` can traverse
them (it cannot pass a 0700 home). Inputs are made identical: the C side
runs the setup (keyring, sync and files dbs, a `-Sw` prefetch of every
package the steps install) and the Rust root starts as its copy; the host
package cache is a read-only extra CacheDir. Downloads are compared in
their own phase on empty caches. After every step: rc, stdout, stderr,
the whole tree (type, mode, owner, size, sha256, link, mtime, nlink,
xattrs), the local db (install dates masked), pacman.log (stamps
normalised, offsets compared apart). mtimes are exact, except that a
time inside a recorded run window stands for that step, so files stamped
at run time match when the same step stamped them. Randomness is pinned
or masked, never tolerated broadly (fixed machine-id; the java keystore
and ldconfig's aux-cache, dates and inode numbers inside, skip content).
No real root, and nothing outside `.tmp/` is written.

## Unit workflow

- `scripts/unit-worktree.sh <name>` (clean tree, so commit first) makes
  `../ratman-worktrees/<name>` on branch `unit/<name>`: submodules cloned
  `--shared`, the C reference build shared via `PACMAN_BUILD`, `TMPDIR`
  inside the worktree (`.cargo/config.toml`). Nothing goes to /tmp: tests
  use `std::env::temp_dir()`, logs go to `.tmp/`.
- Several units share one machine. The worktree config caps cargo at
  `jobs = 2` and `RUST_TEST_THREADS=2`, and runs every test binary under
  `scripts/test-runner.sh` (4 GiB address space, 30 min; the main
  checkout's `.cargo/config.toml` sets the same runner). With large swap
  and no oomd, a runaway test never meets the OOM killer and freezes the
  machine; capped, it aborts and fails. Run tests through
  `scripts/cargo-test.sh`, which allows one suite at a time machine wide.
- Waiting on a background run: never `until ! pgrep -f '<text>'`. The
  waiter's own command line contains `<text>`, so pgrep always finds
  it and the loop never ends (six such loops ran for hours). Wait on a
  sentinel the run writes (`cmd; echo "rc=$?" >> log`, then
  `until grep -q '^rc=' log`), or run it in the foreground.
- Mutation checks that can loop (a removed loop exit, a dropped push)
  run under the same caps. `TEST_TIMEOUT=<s>` may be raised for long
  fuzz runs (2M iterations); `TEST_MEM_KB` is never raised.
- The unit commits on its branch; it is merged with `git merge`, then
  `scripts/unit-worktree.sh --remove <name>`.

## Done means

- committed on the unit branch, the worktree's `.tmp/` emptied (corpora
  meant to be reused are named in the report)
- `scripts/cargo-test.sh` (cargo test --release) green for the whole
  workspace
- vendored crates a unit patched: `cargo test` inside `vendor/alpm` with
  the runner config (`--config "target.'cfg(all())'.runner = [...]"`,
  `-j 2`), `-- --skip crazy_threads`: alpm-compress's zstd cases ask
  for 99999 threads, which cannot fit under the 4 GiB cap. Remove
  `vendor/alpm/target` and `Cargo.lock` after
- `scripts/check-separation.sh` passes (no test modules, C access or
  difftest in port crates)
- `scripts/check-externs.py` passes (one declaration per C symbol in
  difftest; rustc only flags duplicates whose signatures differ)
- `DIFFTEST_ITERS=2000000 scripts/cargo-test.sh -p difftest --test <cfile>`
- mutation check done
- nothing left without an owner: files, tests, patches, scripts, crate
  dependencies, generator limits and doc rows that only existed for what
  the unit replaced are removed in the same unit (a dropped crate takes
  its patches, its pins and the comments explaining its limits)
- `PORTING.md` row(s) and notes updated
- upstream findings listed separately in the report, each with its
  practice class from `UPSTREAM.md` (real, packager, local, api, env,
  none) and why
