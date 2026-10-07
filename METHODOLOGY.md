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
  ALPM accepts. Differences go in `PORTING.md` as divergences, they are
  not patched around.

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
  in `difftest/src/lib.rs`; rustc flags clashing extern signatures.
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

- `cargo test --release` green for the whole workspace
- `DIFFTEST_ITERS=2000000 cargo test --release -p difftest --test <cfile>`
- mutation check done
- `PORTING.md` row(s) and notes updated
- upstream findings listed separately in the report, each with its
  practice class from `UPSTREAM.md` (real, packager, local, api, env,
  none) and why
