// unit tests for alpm_core::package
use alpm_core::package::*;

fn xdata(name: &[u8], value: &[u8]) -> Option<PkgXData> {
	Some(PkgXData {
		name: name.to_vec(),
		value: value.to_vec(),
	})
}

#[test]
fn parse_xdata_cases() {
	assert_eq!(parse_xdata(b"pkgtype=split"), xdata(b"pkgtype", b"split"));
	assert_eq!(parse_xdata(b"a=b=c"), xdata(b"a", b"b=c"));
	assert_eq!(parse_xdata(b"=x"), xdata(b"", b"x"));
	assert_eq!(parse_xdata(b"x="), xdata(b"x", b""));
	assert_eq!(parse_xdata(b"noeq"), None);
	assert_eq!(parse_xdata(b""), None);
	assert_eq!(parse_xdata(b"a\0=b"), None);
}

fn named(name: &[u8]) -> Package {
	Package {
		name_hash: alpm_core::util::hash_sdbm(name),
		name: Some(name.to_vec()),
		..Package::default()
	}
}

#[test]
fn dup_drops_uncopied_fields() {
	let p = Package {
		base64_sig: Some(b"sig".to_vec()),
		download_size: 3,
		checkdepends: vec![alpm_core::deps::dep_from_string(b"a")],
		makedepends: vec![alpm_core::deps::dep_from_string(b"b")],
		xdata: vec![PkgXData::default()],
		origin: Some(PkgFrom::File(b"/x".to_vec())),
		reason: PkgReason::Depend,
		size: 9,
		..named(b"foo")
	};
	let d = p.dup();
	assert_eq!(d.base64_sig, None);
	assert_eq!(d.download_size, 0);
	assert!(d.checkdepends.is_empty() && d.makedepends.is_empty());
	assert!(d.xdata.is_empty());
	assert_eq!(
		d,
		Package {
			base64_sig: None,
			download_size: 0,
			checkdepends: Vec::new(),
			makedepends: Vec::new(),
			xdata: Vec::new(),
			..p
		}
	);
}

#[test]
fn cmp_and_versions() {
	use std::cmp::Ordering::*;
	assert_eq!(pkg_cmp(&named(b"a"), &named(b"b")), Less);
	assert_eq!(pkg_cmp(&named(b"b\xc3"), &named(b"bz")), Greater);
	assert_eq!(pkg_cmp(&named(b"a\0x"), &named(b"a")), Equal);
	let v = |s: Option<&[u8]>| Package {
		version: s.map(<[u8]>::to_vec),
		..Package::default()
	};
	assert_eq!(
		pkg_compare_versions(&v(Some(b"1.1")), &v(Some(b"1.0"))),
		Greater
	);
	assert_eq!(pkg_compare_versions(&v(None), &v(Some(b""))), Less);
	assert_eq!(pkg_compare_versions(&v(None), &v(None)), Equal);
}

#[test]
fn find_checks_hash_then_name() {
	let mut stale = named(b"a");
	stale.name_hash ^= 1;
	let pkgs = [stale, named(b"b"), named(b"a")];
	assert!(std::ptr::eq(pkg_find(&pkgs, b"a").unwrap(), &pkgs[2]));
	assert!(std::ptr::eq(pkg_find(&pkgs, b"b\0c").unwrap(), &pkgs[1]));
	assert!(pkg_find(&pkgs, b"c").is_none());
	assert!(pkg_find(&[Package::default()], b"").is_none());
}
