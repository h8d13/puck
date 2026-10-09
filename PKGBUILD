# Maintainer: h8d13 <hadrien.loge@gmail.com>

pkgname=puck-git
_pkgname=puck
# the pacman release the scripts, man pages and configs come from
# (pacman/meson.build project version): what provides= promises
_pacman_ver=7.1.0
pkgver=0.1.0.r325.g973b153
pkgrel=1
pkgdesc="Rust port of pacman, with upstream's makepkg, pacman-key and repo-add"
# x86_64 only until the suites run on aarch64 (PORTING.md handover row
# "aarch64 and other arches": hash_sdbm/pathcmp follow the platform's char)
arch=('x86_64')
url="https://github.com/h8d13/puck"
license=('GPL-2.0-or-later')
depends=(
  # the binaries
  'glibc'
  'gcc-libs'
  'libseccomp' 'libseccomp.so'
  'xz' 'liblzma.so'
  # the scripts (upstream's makepkg, pacman-key, repo-add, ...)
  'bash'
  'coreutils'
  'gawk'
  'gettext'
  'grep'
  'perl'
  # hard, not optional: SigLevel defaults to Required, so every sync db
  # and package goes through gpg, and pacman-key is gpg throughout
  'gnupg'
)
makedepends=(
  'asciidoc'
  'cargo'
  'cmake'
  'git'
  'meson'
  # meson configures all of libalpm, shipped or not
  'curl'
  'gpgme'
  'libarchive'
  'openssl'
)
checkdepends=('python')
optdepends=(
  'base-devel: required to use makepkg'
  'curl: makepkg source downloads (DLAGENTS in makepkg.conf)'
  'pacman-mirrorlist: mirrors to Include from pacman.conf'
  'perl-locale-gettext: translation support in makepkg-template'
)
provides=("pacman=$_pacman_ver")
conflicts=('pacman')
backup=('etc/pacman.conf'
        'etc/makepkg.conf'
        'etc/makepkg.conf.d/fortran.conf'
        'etc/makepkg.conf.d/rust.conf')
# private for now: ssh with the maintainer's key, "git+$url.git" once public
#source=("$_pkgname::git+https://github.com/h8d13/puck.git"
source=("$_pkgname::git+ssh://git@github.com/h8d13/puck.git"
        # pacman/ submodule: makepkg's git sources fetch no submodules
        'pacman::git+https://gitlab.archlinux.org/pacman/pacman.git')
b2sums=('SKIP'
        'SKIP')

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

  # the recorded pacman/ commit, checked out from makepkg's clone
  git submodule init pacman
  git config submodule.pacman.url "$srcdir/pacman"
  git -c protocol.file.allow=always submodule update pacman

  cargo fetch --locked --target host-tuple
}

build() {
  cd "$_pkgname"

  cargo build --release --frozen -p pacman-cli -p vercmp -p testpkg

  # upstream's scripts, man pages and configs, with the options Arch's
  # pacman package builds them with. doxygen stays off: libalpm's man3
  # pages document a library that does not ship
  meson setup --prefix=/usr --buildtype=plain -Ddoc=enabled \
        pacman/build pacman
  meson compile -C pacman/build
}

check() {
  cd "$_pkgname"

  # port layering, one extern declaration per C symbol
  scripts/check-separation.sh
  python scripts/check-externs.py

  # unit tests of the port crates. difftest (links the C objects, runs
  # under fakeroot/fakechroot), pactest and twin-root are not run here:
  # scripts/cargo-test.sh and PORTING.md gates cover them
  cargo test --release --frozen -p pacman-common -p vercmp -p alpm-core

  # upstream's vercmp suite on the port's binary
  bash pacman/test/util/vercmptest.sh target/release/vercmp

  # upstream's own tests of two scripts that ship
  meson test -C pacman/build parseopts_test.sh makepkg-template_test.sh

  # pacman-key, pacman-db-upgrade, makepkg's lockfile line and the
  # completions' --repo-list: the C pacman-conf against the port's
  PACMAN_BUILD=pacman/build scripts/pacman-conf-dropin.sh
}

package() {
  cd "$_pkgname"

  # upstream's scripts, completions, man pages, configs and locales
  DESTDIR="$pkgdir" meson install -C pacman/build

  # the C binaries, libalpm (no C ABI yet: PORTING.md "Handover") and
  # their message catalogs make way for the port; rmdir fails loudly
  # should meson one day put more under lib/ or include/
  rm "$pkgdir"/usr/bin/{pacman,pacman-conf,testpkg,vercmp}
  rm "$pkgdir"/usr/lib/libalpm.so* "$pkgdir"/usr/lib/pkgconfig/libalpm.pc
  rmdir "$pkgdir"/usr/lib/pkgconfig "$pkgdir"/usr/lib
  rm "$pkgdir"/usr/include/{alpm,alpm_list}.h
  rmdir "$pkgdir"/usr/include
  rm "$pkgdir"/usr/share/locale/*/LC_MESSAGES/{pacman,libalpm}.mo
  # languages with no pacman-scripts.mo leave empty directories behind
  find "$pkgdir/usr/share/locale" -depth -type d -empty -delete

  # the port under pacman's names: makepkg, pacman-key, pacman-db-upgrade
  # and the completions call pacman and pacman-conf by name
  install -Dm755 target/release/puck "$pkgdir/usr/bin/pacman"
  install -Dm755 target/release/puck-conf "$pkgdir/usr/bin/pacman-conf"
  install -Dm755 -t "$pkgdir/usr/bin" target/release/{vercmp,testpkg}

  install -Dm644 -t "$pkgdir/usr/share/doc/$pkgname" README.md
}
