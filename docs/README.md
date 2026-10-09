# Why ask for `puck`

- Bindings are only ever as good as the underlying code, i.e. how many open issues
and open merge requests (that are well-founded) there are, plus other yet-to-be-discovered details.

- Rust dependencies are pinned and built in (only `glibc`, `libgcc`, `libseccomp` and `liblzma`
are linked dynamically) instead of linking `libarchive`, `curl` and `gpgme`. Any improvement
to upstream projects can be ported without too much difficulty, so ongoing work by
contributors directly benefits this project.

- Speed, memory usage, syscall counts and overall correctness are attractive factors
when it comes to the very tool that orchestrates your operating system and maintains it.

- This project references [ALPM](https://alpm.archlinux.page/) as a spec reference and
reuses the same dependency crates ALPM does (digests, codecs); it owns its readers rather
than linking the ALPM crates. ALPM's development was
[officially announced](https://lists.archlinux.org/archives/list/arch-dev-public@lists.archlinux.org/thread/MZLH43574GGP7QQ7RKAAIRFT5LJPCEB4/)
as funded by [the Sovereign Tech Agency](https://www.sovereign.tech/)'s Sovereign Tech Fund:
four developers on the ALPM project part-time over 15 months.

- ALPM is explicitly [not a package manager](https://alpm.archlinux.page/faq.html). It provides
spec-backed parsers and writers for the file formats, but not the transaction engine on top:
dependency resolution, conflicts/replaces, downloads, install/remove/upgrade, hooks and locking.
That engine is the part `puck` ports.

- File-by-file porting keeps behaviour traceable to upstream. Every Rust module maps to a C
source file, so regressions can be checked with differential tests against `pacman` on the
same root, database and package set.

- Drop-in compatibility: same `pacman.conf`, `mirrorlist`, local database, sync databases,
hooks and cache layout. Nothing to migrate, and can switch back to `pacman` at any time.

- Signature verification without a stateful GnuPG keyring. [VOA](https://voa.archlinux.page/)
replaces `gpgme` and the `pacman-key` init/populate dance, which is a long-standing source of
"invalid or corrupted package (PGP signature)" breakage.

- Over time `puck` could link more internally and approach a fully static build.

- Memory safety where it matters most: a root-privileged process that downloads, decompresses
and parses archives and metadata from the network.

- Every ported function is differential-tested against `pacman` on the same root, database
and packages, and the benches compare time, memory and syscall counts on real operations.

- `libseccomp` sandboxing of the riskier stages could be expanded still as new goals.

---

> Most of the documentation in this folder are artifacts from AI porting.

Written by Opus 5.5 in about 48H non-stop and ~100M tokens, Fable 5.1 agent supervising
sub-agents (through `git-worktree`). All artifacts were left in the repo on purpose...
