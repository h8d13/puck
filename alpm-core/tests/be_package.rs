// unit tests for alpm_core::be_package, on uncompressed packages written
// here
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use alpm_core::be_package::{
	Error, Reason, changelog, pkg_load, pkg_load_internal,
	pkg_validate_internal,
};
use alpm_core::digest::{Digest, Sha256, hex};
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

// (name, type flag, data), short names only; mtime 0
fn ustar(entries: &[(&[u8], u8, &[u8])]) -> Vec<u8> {
	let mut b = tar::Builder::new(Vec::new());
	for &(name, kind, data) in entries {
		let mut h = tar::Header::new_ustar();
		// raw name bytes, set_path would normalise them
		h.as_old_mut().name[..name.len()].copy_from_slice(name);
		h.set_mode(0o644);
		h.set_size(data.len() as u64);
		h.set_entry_type(tar::EntryType::new(kind));
		h.set_cksum();
		b.append(&h, data).unwrap();
	}
	b.into_inner().unwrap()
}

fn names(p: &Package) -> Vec<&[u8]> {
	p.files.files.iter().map(|f| f.name()).collect()
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
	assert_eq!(&*p.depends[0].name, b"bar");
	assert_eq!(p.optdepends[0].desc.as_deref(), Some(&b"for baz"[..]));
	assert_eq!(&*p.backup[0].name, b"etc/foo.conf");
	assert_eq!(p.backup[0].hash, None);
	assert_eq!(p.xdata.len(), 2);
	assert_eq!(p.scriptlet, 1);
	assert_eq!(p.origin, Some(PkgFrom::File(pkg.path().to_vec().into())));
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
	assert_eq!(changelog(&mut (), &p).unwrap(), b"log\n");
	let bad = Package {
		sha256sum: Some(b"00"[..].into()),
		..Package::default()
	};
	assert!(matches!(
		pkg_validate_internal(pkg.path(), Some(&bad)),
		Err(Error::Checksum)
	));
	let sum = hex(&Sha256::digest(fs::read(&pkg.0).unwrap()));
	let good = Package {
		sha256sum: Some(sum.into()),
		..Package::default()
	};
	assert_eq!(
		pkg_validate_internal(pkg.path(), Some(&good)).unwrap(),
		PKG_VALIDATION_SHA256SUM
	);
	let nolog = Pkg::new("nolog", &[(b".PKGINFO", b'0', PKGINFO)]);
	let p = pkg_load(nolog.path(), false).unwrap();
	assert!(matches!(changelog(&mut (), &p), Err(Error::NotFound)));
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
