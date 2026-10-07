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
  Before porting a C file, check whether ALPM implements it (formats:
  `alpm-db`, `alpm-repo-db`, `alpm-pkginfo`, `alpm-mtree`,
  `alpm-buildinfo`, `alpm-package`, `alpm-compress`; types, versions,
  relations, checksums: `alpm-types`). If it does, use the ALPM crate
  instead of translating, and difftest ALPM against the C on the inputs
  ALPM accepts. Where ALPM differs from pacman, correct it: one patch per
  divergence in `vendor/patches/` (applied to the pristine `alpm/`
  submodule by `scripts/vendor-alpm.sh` into `vendor/alpm`, which the
  workspace builds against), with the difftest flipped from "pinned
  divergence" to "equal". pacman bugs recorded in `UPSTREAM.md` are not
  copied. Crates ALPM itself depends on count as precedent
  too (base64, md-5, sha2, time, unicode-width, url, tar, compression,
  winnow): never hand-write what one of them implements. Keeping a port
  next to a precedent needs a stated reason (e.g. pacman semantics the
  crate cannot express) in `PORTING.md`.

## System-level decisions

Where pacman needs things the 10 core ALPM crates do not cover, the choice
follows the wider ALPM workspace, then parity:

| Need | Choice | Why |
|---|---|---|
| HTTP downloads (`dload.c`) | `reqwest` 0.13, blocking, rustls | ALPM `dev-scripts` uses exactly this |
| OpenPGP verification and keys (`signing.c`) | drive `gpg` over `--status-fd` like gpgme does | same engine, keyring (`/etc/pacman.d/gnupg`) and trust model as pacman; ALPM's VOA/rpgp stack cannot read gnupg keyboxes or trustdb |
| `statvfs` (`diskspace.c`), `umask` | `rustix` safe API | in ALPM's lockfile |
| chroot exec (scriptlets, hooks, ldconfig) | spawn `chroot(8)` via `std::process::Command` | no `pre_exec` (unsafe); works under fakechroot like the C's `chroot()` |
| run downloads as DownloadUser | spawned helper process, `CommandExt::uid`/`gid` | safe std, instead of the C's fork + setuid |
| landlock (`sandbox_fs.c`) | `landlock` crate | the Landlock maintainers' binding |
| seccomp (`sandbox_syscalls.c`) | `libseccomp` crate | binding to the same C library pacman links |
| lock file | `OpenOptions::create_new` | safe std (O_CREAT\|O_EXCL) |

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

## Done means

- nothing left behind in /tmp: fixtures, logs and probe programs created
  for the unit are removed (corpora meant to be reused are named in the
  report)
- `cargo test --release` green for the whole workspace
- `scripts/check-separation.sh` passes (no test modules, C access or
  difftest in port crates)
- `scripts/check-externs.py` passes (one declaration per C symbol in
  difftest; rustc only flags duplicates whose signatures differ)
- `DIFFTEST_ITERS=2000000 cargo test --release -p difftest --test <cfile>`
- mutation check done
- `PORTING.md` row(s) and notes updated
- upstream findings listed separately in the report, each with its
  practice class from `UPSTREAM.md` (real, packager, local, api, env,
  none) and why
