# saruman

Rust port of `pacman`, file by file, checked against the upstream C with
differential tests.

Builds on the official Arch ALPM crates where they already cover a part.

Testing needs rust toolchain + `fakechroot fakeroot`

## Setup

```
git clone --recurse-submodules git@github.com:h8d13/ratman.git
cd ratman
meson setup pacman/build pacman && ninja -C pacman/build
cargo test --release
```

Building the C reference follows upstream: `pacman/doc/index.asciidoc`
(install section), options in `pacman/meson_options.txt`.

## Layout

- `pacman/`, `alpm/`: submodules, upstream pacman (C reference) and ALPM
- `alpm-core/`, `pacman-common/`, `pacman-cli/`, `vercmp/`: the port
- `difftest/`: equivalence tests against the C, the only crate calling C

## Docs

- `PORTING.md`: status per C file, milestones, ALPM overlap, notes
- `METHODOLOGY.md`: rules every port unit follows
- `UPSTREAM.md`: findings in the C reference, with practical reach

---

Used: Anthropic Claude Opus 5.5: ~20M tokens.
