# puck

> https://en.wikipedia.org/wiki/Pac-Man

## Setup

```
cargo build --release -p pacman-cli
./target/release/puck --help
```

Rust port of `pacman`, file by file, checked against the upstream C with
differential tests.


### Testing

Needs rust toolchain + `fakechroot fakeroot`

```shell
git clone --recurse-submodules git@github.com:h8d13/puck.git
cd puck
meson setup pacman/build pacman && ninja -C pacman/build
cargo test --release -p something --test specific-test
```

Building the C reference follows upstream: `pacman/doc/index.asciidoc`
(install section), options in `pacman/meson_options.txt`.

## Layout

- `pacman/`, `alpm/`: submodules, upstreams
- `alpm-core/`, `pacman-common/`, `pacman-cli/`, `vercmp/`: the port
- `difftest/`: equivalence tests against the C, the only crate calling `unsafe`

---
