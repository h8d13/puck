# Why ask for `puck`

- Bindings are only ever as good as the underlying code. I.e: how many open issues
open merge requests (that are founded), and other yet-to-be discovered details...

- Rust deps pinned and built in (only `glibc`, `libgcc`, `libseccomp` and `liblzma` are
linked dynamically) instead of linking `libarchive`, `curl`, `gpgme`, + any improvement
to upstream projects, can be ported without too much difficulty. This means that
ongoing developments by contributors directly benefits this project.

- Speed, memory usage, syscall counts, and correctness overall are attractive factors
when it comes to the very tool that orchastrates your operating system and maitains it.

---

> Most of the documentation in this folder are artifacts from AI porting.

Written by Opus 5.5 in about 48H non-stop and ~100M tokens, Fable 5.1 agent supervising
sub-agents (through `git-worktree`). All artifacts were left in the repo on purpose...
