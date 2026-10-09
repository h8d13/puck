# Why ask for `puck`

- Bindings are only ever as good as the underlying code, i.e. how many open issues
and open merge requests (that are well-founded) there are, plus other yet-to-be-discovered details.

- Rust dependencies are pinned and built in (only `glibc`, `libgcc`, `libseccomp` and `liblzma`
are linked dynamically) instead of linking `libarchive`, `curl` and `gpgme`. Any improvement
to upstream projects can be ported without too much difficulty, so ongoing work by
contributors directly benefits this project.

- Speed, memory usage, syscall counts and overall correctness are attractive factors
when it comes to the very tool that orchestrates your operating system and maintains it.

- This project follows [ALPM](https://alpm.archlinux.page/) as its reference for crate choices (the
`alpm/` submodule), whose development was
[officially announced](https://lists.archlinux.org/archives/list/arch-dev-public@lists.archlinux.org/thread/MZLH43574GGP7QQ7RKAAIRFT5LJPCEB4/)
as funded by [the Sovereign Tech Agency](https://www.sovereign.tech/)'s Sovereign Tech Fund:
financing for four developers to work on the ALPM project part-time over the course of 15 months.

- ALPM is explicitly [not a package manager](https://alpm.archlinux.page/faq.html). It provides
spec-backed parsers and writers for the file formats, but not the transaction engine on top:
dependency resolution, conflicts/replaces, downloads, install/remove/upgrade, hooks and locking.
That engine is the part `puck` ports. No ALPM crate is linked: the port uses the same
dependency crates ALPM does (codecs, digests) directly, and its readers are translated from
the C to stay lenient byte for byte where ALPM's parsers validate the spec.

- File-by-file porting keeps behaviour traceable to upstream. Every Rust module maps to a C
source file, so regressions can be checked with differential tests against `pacman` on the
same root, database and package set.

- Drop-in compatibility: same `pacman.conf`, `mirrorlist`, local database, sync databases,
hooks and cache layout. Nothing to migrate, and you can switch back to `pacman` at any time.

- Signature verification without `gpgme`: `puck` drives `gpg` over `--status-fd` the way gpgme
does, on the same keyring (`/etc/pacman.d/gnupg`) with the same trust model, so `pacman-key`
and the existing keyring keep working unchanged.

- Self-sufficient in a broken system. A partial upgrade that breaks `libarchive`, `curl` or
`libcrypto` can leave `pacman` unable to run (the reason `pacman-static` exists). With almost
everything built in, `puck` keeps working when the libraries around it don't.

- Memory safety where it matters most: a root-privileged process that downloads, decompresses
and parses archives and metadata from the network.

- Typed data past the readers. `desc`, `.PKGINFO`, `.MTREE` and version strings are read
exactly as `pacman` reads them, then carried as typed values instead of loose `char *`
through the transaction.

- The download stage runs as `DownloadUser` under landlock and `libseccomp`, like `pacman`'s
sandbox, so a hostile mirror reaches less.

- License-compatible stack: every dependency is `MIT`/`Apache-2.0`-class (`cargo deny check`
enforces the allowlist), usable by GPL-licensed `puck`, which follows `pacman`'s license as a port.

---

> Most of the documentation in this folder are artifacts from AI porting.

Written by Opus 5.5 in about 48H non-stop and ~100M tokens, Fable 5.1 agent supervising
sub-agents (through `git-worktree`). All artifacts were left in the repo on purpose...
