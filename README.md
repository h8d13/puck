# puck

> https://en.wikipedia.org/wiki/Pac-Man

[Rust](https://rust-lang.org/) port of [`pacman`](https://gitlab.archlinux.org/pacman/pacman), file by file, checked against the upstream C with
differential tests.

## Setup

```
cargo build --release -p pacman-cli
./target/release/puck --help
```

### Testing / Dev

Needs rust toolchain (+ `cargo-deny`, `pre-commit`, `fakechroot`, `fakeroot`)

```shell
git clone --recurse-submodules git@github.com:h8d13/puck.git
cd puck
meson setup pacman/build pacman && ninja -C pacman/build
cargo test --release -p something --test specific-test
```

Building the C reference follows upstream: `pacman/doc/index.asciidoc`
(install section), options in `pacman/meson_options.txt`.

## Layout

- `pacman/`, `alpm/`, `justpkg/`: submodules, upstreams/references
- `difftest/`: equivalence tests against the C, the only crate calling `unsafe`
- `scripts`, `bench/`, `docs/`: utilities, profiling and clanker documentation
- `alpm-core/`, `pacman-common/`, `vercmp/`, `pacman-cli/`: the port

---
