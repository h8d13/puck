# Maintainer: h8d13 <hadrien.loge@gmail.com>

pkgname=puck-git
_pkgname=puck
pkgver=0.1.0.r325.g973b153
pkgrel=1
pkgdesc="Rust port of pacman"
arch=('x86_64')
url="https://github.com/h8d13/puck"
license=('GPL-2.0-or-later')
depends=(
  'glibc'
  'libgcc'
  'libseccomp'
  'xz'
  # its config, dbs, keyring and hooks are pacman's
  'pacman'
)
makedepends=('cmake' 'git' 'rust')
optdepends=('gnupg: signature checks, like pacman')
# private for now: ssh with the maintainer's key, "git+$url.git" once public
source=("$_pkgname::git+ssh://git@github.com/h8d13/puck.git")
b2sums=('SKIP')

# Use debug
export CARGO_PROFILE_RELEASE_DEBUG=2 CARGO_PROFILE_RELEASE_STRIP=false

# Use LTO
export CARGO_PROFILE_RELEASE_LTO=true CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1

# aws-lc-sys (reqwest's rustls): its cc builder puts makepkg's -O2 after
# jitterentropy's required -O0, cmake keeps per-file flags
export AWS_LC_SYS_CMAKE_BUILDER=1

# zstd-sys, aws-lc-sys: rustc's linker cannot read GCC-only LTO objects
CFLAGS+=' -ffat-lto-objects'

pkgver() {
  cd "$_pkgname"

  # the workspace version, then commits since the first one
  local ver
  ver=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml)
  printf "%s.r%s.g%s" "$ver" "$(git rev-list --count HEAD)" \
    "$(git rev-parse --short=7 HEAD)"
}

prepare() {
  cd "$_pkgname"

  cargo fetch --locked --target host-tuple
}

build() {
  cd "$_pkgname"

  cargo build --release --frozen -p pacman-cli
}

check() {
  echo "somechecks here"
}

package() {
  cd "$_pkgname"

  install -vDm755 -t "$pkgdir/usr/bin" target/release/puck
  install -vDm755 -t "$pkgdir/usr/bin" target/release/puck-conf

  install -vDm644 -t "$pkgdir/usr/share/doc/$pkgname" README.md
}
