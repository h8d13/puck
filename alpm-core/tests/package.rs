// unit tests for alpm_core::internals::package
use alpm_core::internals::package::*;

fn named(name: &[u8]) -> Package {
	Package {
		name_hash: alpm_core::internals::util::hash_sdbm(name),
		name: Some(name.into()),
		..Package::default()
	}
}

#[test]
fn dup_drops_uncopied_fields() {
	let p = Package {
		base64_sig: Some(b"sig"[..].into()),
		download_size: 3,
		checkdepends: vec![
			alpm_core::internals::deps::dep_from_string(b"a"),
		]
		.into(),
		makedepends: vec![alpm_core::internals::deps::dep_from_string(
			b"b",
		)]
		.into(),
		xdata: vec![PkgXData::default()].into(),
		origin: Some(PkgFrom::File(b"/x"[..].into())),
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
			checkdepends: Vec::new().into(),
			makedepends: Vec::new().into(),
			xdata: Vec::new().into(),
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
		version: s.map(Box::from),
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

// local cache, sync caches; names as given (already cache ordered)
struct Caches(Vec<Package>, Vec<Vec<Package>>);

impl DbCaches for Caches {
	fn local_cache(&mut self) -> Vec<&Package> {
		self.0.iter().collect()
	}

	fn sync_caches(&mut self) -> Vec<Vec<&Package>> {
		self.1.iter().map(|c| c.iter().collect()).collect()
	}
}

fn user(name: &[u8], dep: &[u8], opt: bool) -> Package {
	let d = vec![alpm_core::internals::deps::dep_from_string(dep)];
	match opt {
		false => Package {
			depends: d.into(),
			..named(name)
		},
		true => Package {
			optdepends: d.into(),
			..named(name)
		},
	}
}

#[test]
fn requiredby_cases() {
	let mut caches = Caches(
		vec![user(b"z", b"foo", false), user(b"b", b"foo", false)],
		vec![
			vec![
				user(b"y", b"foo", false),
				user(b"c", b"foo", true),
			],
			vec![
				user(b"x", b"foo", false),
				user(b"y", b"foo", false),
			],
		],
	);
	let mut p = named(b"foo");
	// local and file origins: local cache order, no sort
	p.origin = Some(PkgFrom::LocalDb);
	assert_eq!(compute_requiredby(&p, &mut caches), [b"z", b"b"]);
	p.origin = Some(PkgFrom::File(b"/x"[..].into()));
	assert_eq!(compute_requiredby(&p, &mut caches), [b"z", b"b"]);
	assert!(compute_optionalfor(&p, &mut caches).is_empty());
	// sync: every sync db, deduped, sorted
	p.origin = Some(PkgFrom::SyncDb);
	assert_eq!(compute_requiredby(&p, &mut caches), [b"x", b"y"]);
	assert_eq!(compute_optionalfor(&p, &mut caches), [b"c"]);
	p.origin = None;
	assert!(compute_requiredby(&p, &mut caches).is_empty());
}

#[test]
fn should_ignore_cases() {
	let dir = std::env::temp_dir().join(format!(
		"alpm-core-package-{}-ignore",
		std::process::id()
	));
	std::fs::create_dir_all(dir.join("db")).unwrap();
	let path = |s: &str| {
		use std::os::unix::ffi::OsStrExt;
		dir.join(s).as_os_str().as_bytes().to_vec()
	};
	let mut h = alpm_core::internals::handle::Handle::initialize(
		&path(""),
		&path("db"),
	)
	.unwrap();
	let mut p = named(b"foo");
	p.groups = vec![b"kde-apps"[..].into()].into();
	assert!(!pkg_should_ignore(&h, &p));
	h.set_ignorepkgs(&[b"f*"]);
	assert!(pkg_should_ignore(&h, &p));
	// no '!' negation: a literal pattern here
	h.set_ignorepkgs(&[b"!foo"]);
	assert!(!pkg_should_ignore(&h, &p));
	h.set_ignoregroups(&[b"kde*"]);
	assert!(pkg_should_ignore(&h, &p));
	std::fs::remove_dir_all(&dir).unwrap();
}
