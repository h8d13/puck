// unit tests for alpm_core::be_package, on uncompressed packages written
// here
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use alpm_core::be_package::{
	Error, Reason, changelog, pkg_load, pkg_load_internal,
	pkg_validate_internal,
};
use alpm_core::error::Errno;
use alpm_core::package::{
	PKG_VALIDATION_NONE, PKG_VALIDATION_SHA256SUM, Package, PkgFrom,
};

const PKGINFO: &[u8] = b"\
pkgname = foo
pkgbase = foo
xdata = pkgtype=pkg
pkgver = 1:1.0-2
pkgdesc = a package
url = https://example.org/
builddate = 1720811171
packager = John Doe <john@example.org>
size = 2358
arch = any
license = MIT
depend = bar>=1.0
optdepend = baz: for baz
backup = etc/foo.conf
xdata = k=v
";

// <tmp>/<name>.pkg.tar, removed on drop
struct Pkg(PathBuf);

impl Pkg {
	fn new(name: &str, entries: &[(&[u8], u8, &[u8])]) -> Self {
		let path = std::env::temp_dir().join(format!(
			"alpm-core-be-package-{}-{name}.pkg.tar",
			std::process::id()
		));
		fs::write(&path, ustar(entries)).unwrap();
		Pkg(path)
	}

	fn path(&self) -> &[u8] {
		self.0.as_os_str().as_bytes()
	}
}

impl Drop for Pkg {
	fn drop(&mut self) {
		fs::remove_file(&self.0).unwrap();
	}
}

fn octal(field: &mut [u8], v: u64) {
	let w = field.len() - 1;
	let s = format!("{v:0w$o}");
	field[..w].copy_from_slice(s.as_bytes());
}

// (name, type flag, data), short names only
fn ustar(entries: &[(&[u8], u8, &[u8])]) -> Vec<u8> {
	let mut out = Vec::new();
	for &(name, kind, data) in entries {
		let mut h = [0u8; 512];
		h[..name.len()].copy_from_slice(name);
		octal(&mut h[100..108], 0o644);
		octal(&mut h[108..116], 0);
		octal(&mut h[116..124], 0);
		octal(&mut h[124..136], data.len() as u64);
		octal(&mut h[136..148], 0);
		h[156] = kind;
		h[257..263].copy_from_slice(b"ustar\0");
		h[263..265].copy_from_slice(b"00");
		h[148..156].fill(b' ');
		let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
		octal(&mut h[148..155], sum);
		out.extend_from_slice(&h);
		out.extend_from_slice(data);
		out.resize(out.len().next_multiple_of(512), 0);
	}
	out.resize(out.len() + 1024, 0);
	out
}

fn names(p: &Package) -> Vec<&[u8]> {
	p.files.files.iter().map(|f| &f.name[..]).collect()
}

#[test]
fn metadata_fields() {
	let pkg = Pkg::new(
		"meta",
		&[(b".PKGINFO", b'0', PKGINFO), (b".INSTALL", b'0', b"")],
	);
	let p = pkg_load(pkg.path(), false).unwrap();
	assert_eq!(p.name.as_deref(), Some(&b"foo"[..]));
	assert_eq!(p.version.as_deref(), Some(&b"1:1.0-2"[..]));
	assert_eq!(p.isize, 2358);
	assert_eq!(p.depends[0].name, b"bar");
	assert_eq!(p.optdepends[0].desc.as_deref(), Some(&b"for baz"[..]));
	assert_eq!(p.backup[0].name, b"etc/foo.conf");
	assert_eq!(p.backup[0].hash, None);
	assert_eq!(p.xdata.len(), 2);
	assert_eq!(p.scriptlet, 1);
	assert_eq!(p.origin, Some(PkgFrom::File(pkg.path().to_vec())));
	assert_eq!(p.validation, PKG_VALIDATION_NONE);
	assert!(p.files.files.is_empty());
}

#[test]
fn file_list() {
	let pkg = Pkg::new(
		"files",
		&[
			(b"usr/bin/b", b'0', b"xy"),
			(b".PKGINFO", b'0', PKGINFO),
			(b"usr", b'5', b""),
			(b".hidden", b'0', b""),
			(b"usr/bin/a", b'2', b""),
		],
	);
	let p = pkg_load_internal(&mut (), pkg.path(), true).unwrap();
	assert_eq!(names(&p), [&b"usr/"[..], b"usr/bin/a", b"usr/bin/b"]);
	assert_eq!(p.files.files[2].size, 2);
	assert_eq!(p.files.files[0].mode, 0o40644);
	assert_eq!(p.files.files[1].mode, 0o120644);
}

#[test]
fn errors() {
	assert!(matches!(
		pkg_load_internal(&mut (), b"", true),
		Err(Error::WrongArgs)
	));
	let e = pkg_load(b"/nonexistent/x.pkg.tar", true).unwrap_err();
	assert_eq!(e.errno(), Errno::PkgNotFound);
	let pkg = Pkg::new("nometa", &[(b"a", b'0', b"x")]);
	let e = pkg_load(pkg.path(), true).unwrap_err();
	assert!(matches!(e, Error::Invalid(Reason::Missing)));
	assert_eq!(e.errno(), Errno::PkgInvalid);
}

#[test]
fn check_meta_length() {
	let name = "a".repeat(250);
	let info = String::from_utf8_lossy(PKGINFO)
		.replace("pkgname = foo", &format!("pkgname = {name}"));
	let pkg = Pkg::new("long", &[(b".PKGINFO", b'0', info.as_bytes())]);
	let e = pkg_load(pkg.path(), false).unwrap_err();
	assert!(matches!(e, Error::Invalid(Reason::Meta)));
}

#[test]
fn validate_and_changelog() {
	let pkg = Pkg::new(
		"log",
		&[
			(b".PKGINFO", b'0', PKGINFO),
			(b".CHANGELOG", b'0', b"log\n"),
		],
	);
	let p = pkg_load(pkg.path(), false).unwrap();
	assert_eq!(changelog(&p).unwrap(), b"log\n");
	let bad = Package {
		sha256sum: Some(b"00".to_vec()),
		..Package::default()
	};
	assert!(matches!(
		pkg_validate_internal(pkg.path(), Some(&bad)),
		Err(Error::Checksum)
	));
	let sum = alpm_types::Sha256Checksum::calculate_from(
		fs::read(&pkg.0).unwrap(),
	);
	let good = Package {
		sha256sum: Some(sum.to_string().into_bytes()),
		..Package::default()
	};
	assert_eq!(
		pkg_validate_internal(pkg.path(), Some(&good)).unwrap(),
		PKG_VALIDATION_SHA256SUM
	);
	let nolog = Pkg::new("nolog", &[(b".PKGINFO", b'0', PKGINFO)]);
	let p = pkg_load(nolog.path(), false).unwrap();
	assert!(matches!(changelog(&p), Err(Error::NotFound)));
}

// signature levels where no gpg runs: a missing .sig is refused unless
// optional, an optional one gives empty results
#[test]
fn signature_levels_without_sig() {
	use alpm_core::be_package::{pkg_load_level, pkg_validate};
	use alpm_core::signing::{Keyring, SIG_PACKAGE, SIG_PACKAGE_OPTIONAL};
	let pkg = Pkg::new("unsigned", &[(b".PKGINFO", b'0', PKGINFO)]);
	let mut kr = Keyring::new(b"/nonexistent/");
	kr.set_gpg("/nonexistent/gpg");
	let cb = &mut ();
	let r = pkg_validate(&mut kr, cb, pkg.path(), None, SIG_PACKAGE);
	assert!(matches!(r, Err(Error::MissingSig)));
	assert_eq!(r.unwrap_err().errno(), Errno::PkgMissingSig);
	let level = SIG_PACKAGE | SIG_PACKAGE_OPTIONAL;
	let v = pkg_validate(&mut kr, cb, pkg.path(), None, level).unwrap();
	assert_eq!(v.validation, PKG_VALIDATION_NONE);
	assert_eq!(v.siglist, Some(Vec::new()));
	let p = pkg_load_level(&mut kr, cb, pkg.path(), false, level).unwrap();
	assert_eq!(p.validation, PKG_VALIDATION_NONE);
	// an empty .sig cannot be read for the key step
	let sig = [pkg.path(), b".sig"].concat();
	let sig = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&sig));
	fs::write(&sig, b"").unwrap();
	let r = pkg_load_level(&mut kr, cb, pkg.path(), false, level);
	fs::remove_file(&sig).unwrap();
	assert!(matches!(r, Err(Error::SigFile)));
}
