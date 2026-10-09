// port of lib/libalpm/package.c, the alpm_pkg_t data model, its pure
// helpers, reverse dependencies, the ignore check, xdata parsing and the
// metadata check.
//
// not modelled: handle, ops vtable, origin_data.db, removes and oldpkg.
// the alpm_pkg_get_* accessors are plain field reads with default_pkg_ops;
// lazy loading (local db infolevel, force_load) waits for the db backends.
// _alpm_pkg_free is Drop, _alpm_file_copy is File::clone.

use std::cmp::Ordering;
use std::ffi::{c_int, c_ulong};

use crate::backup::Backup;
use crate::callbacks::{Callbacks, LogLevel, logv};
use crate::deps::{Depend, depcmp};
use crate::filelist::FileList;
use crate::handle::Handle;
use crate::util::{fnmatch, hash_sdbm, until_nul};
use crate::version::vercmp;

/// alpm_pkg_xdata_t
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PkgXData {
	pub name: Box<[u8]>,
	pub value: Box<[u8]>,
}

// limits.h on linux
pub(crate) const NAME_MAX: usize = 255;

/// _alpm_pkg_parse_xdata: "name=value" split at the first '=', None
/// without one
pub fn parse_xdata(s: &[u8]) -> Option<PkgXData> {
	let s = until_nul(s);
	let sep = s.iter().position(|&c| c == b'=')?;
	Some(PkgXData {
		name: s[..sep].into(),
		value: s[sep + 1..].into(),
	})
}

// parse_xdata over lines onto xdata up to the first line without '=',
// returned: the entries before it stay, like the C's
pub(crate) fn extend_xdata(
	xdata: &mut Vec<PkgXData>,
	lines: Vec<Vec<u8>>,
) -> Result<(), Vec<u8>> {
	for l in lines {
		xdata.push(parse_xdata(&l).ok_or(l)?);
	}
	Ok(())
}

/// alpm_pkgreason_t, discriminants as in alpm.h
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PkgReason {
	#[default]
	Explicit = 0,
	Depend = 1,
	Unknown = 2,
}

/// alpm_pkgfrom_t with origin_data folded in. the db pointer of the two db
/// origins waits for the db backends
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PkgFrom {
	/// path the package was loaded from, origin_data.file
	File(Box<[u8]>),
	LocalDb,
	SyncDb,
}

/// alpm_pkgvalidation_t ALPM_PKG_VALIDATION_UNKNOWN, for
/// `Package::validation`
pub const PKG_VALIDATION_UNKNOWN: c_int = 0;
/// ALPM_PKG_VALIDATION_NONE
pub const PKG_VALIDATION_NONE: c_int = 1 << 0;
/// ALPM_PKG_VALIDATION_MD5SUM
pub const PKG_VALIDATION_MD5SUM: c_int = 1 << 1;
/// ALPM_PKG_VALIDATION_SHA256SUM
pub const PKG_VALIDATION_SHA256SUM: c_int = 1 << 2;
/// ALPM_PKG_VALIDATION_SIGNATURE
pub const PKG_VALIDATION_SIGNATURE: c_int = 1 << 3;

/// alpm_pkg_t, Default is _alpm_pkg_new (calloc). NULL strings are None.
/// alpm_time_t and off_t are 64 bit in the meson build
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Package {
	/// _alpm_hash_sdbm of name, set by hand like the C: a stale hash
	/// changes lookups the same way
	pub name_hash: c_ulong,
	pub filename: Option<Box<[u8]>>,
	pub base: Option<Box<[u8]>>,
	pub name: Option<Box<[u8]>>,
	pub version: Option<Box<[u8]>>,
	pub desc: Option<Box<[u8]>>,
	pub url: Option<Box<[u8]>>,
	pub packager: Option<Box<[u8]>>,
	pub sha256sum: Option<Box<[u8]>>,
	pub base64_sig: Option<Box<[u8]>>,
	pub arch: Option<Box<[u8]>>,
	pub builddate: i64,
	pub installdate: i64,
	pub size: i64,
	pub isize: i64,
	pub download_size: i64,
	pub licenses: Box<[Box<[u8]>]>,
	pub replaces: Box<[Depend]>,
	pub groups: Box<[Box<[u8]>]>,
	pub backup: Box<[Backup]>,
	pub depends: Box<[Depend]>,
	pub optdepends: Box<[Depend]>,
	pub checkdepends: Box<[Depend]>,
	pub makedepends: Box<[Depend]>,
	pub conflicts: Box<[Depend]>,
	pub provides: Box<[Depend]>,
	pub files: FileList,
	/// None while unset, calloc leaves the C enum at 0
	pub origin: Option<PkgFrom>,
	pub reason: PkgReason,
	/// C int, nonzero when the package has an install scriptlet
	pub scriptlet: c_int,
	pub xdata: Box<[PkgXData]>,
	/// alpm_dbinfrq_t bits
	pub infolevel: c_int,
	/// PKG_VALIDATION_* bits
	pub validation: c_int,
}

impl Package {
	/// a package with its name (hash set) and version, the rest as
	/// `_alpm_pkg_new` leaves it
	pub fn new(name: &[u8], version: &[u8]) -> Package {
		Package {
			name_hash: hash_sdbm(name),
			name: Some(name.into()),
			version: Some(version.into()),
			..Package::default()
		}
	}

	/// name as strcmp sees it. the C dereferences NULL names, None reads
	/// as empty here
	pub fn name_bytes(&self) -> &[u8] {
		until_nul(self.name.as_deref().unwrap_or_default())
	}

	/// _alpm_pkg_dup without the handle/ops/db pointers. the C copies a
	/// subset: base64_sig, download_size, checkdepends, makedepends and
	/// xdata come back empty, Clone copies everything
	pub fn dup(&self) -> Package {
		Package {
			base64_sig: None,
			download_size: 0,
			checkdepends: Box::default(),
			makedepends: Box::default(),
			xdata: Box::default(),
			..self.clone()
		}
	}
}

/// _alpm_pkg_cmp: strcmp on the names
pub fn pkg_cmp(a: &Package, b: &Package) -> Ordering {
	a.name_bytes().cmp(b.name_bytes())
}

/// _alpm_pkg_compare_versions: alpm_pkg_vercmp, a NULL version sorts
/// before any other, two NULLs are equal
pub fn pkg_compare_versions(spkg: &Package, localpkg: &Package) -> Ordering {
	match (&spkg.version, &localpkg.version) {
		(Some(a), Some(b)) => vercmp(a, b),
		(a, b) => a.is_some().cmp(&b.is_some()),
	}
}

// the C checks the stored hash before strcmp, a NULL name never matches
// here where the C would crash
pub(crate) fn has_name(pkg: &Package, name: &[u8], hash: c_ulong) -> bool {
	pkg.name_hash == hash
		&& pkg.name.as_deref().map(until_nul) == Some(name)
}

/// alpm_pkg_find: first package named needle
pub fn pkg_find<'a, I>(haystack: I, needle: &[u8]) -> Option<&'a Package>
where
	I: IntoIterator<Item = &'a Package>,
{
	let (needle, hash) = (until_nul(needle), hash_sdbm(needle));
	haystack.into_iter().find(|p| has_name(p, needle, hash))
}

/// the db caches compute_requiredby walks, each in its pkgcache list
/// order. packages must have their depends/optdepends loaded (the C getters
/// lazy-load local entries). a cache that does not load is a NULL list in
/// the C, an empty one here
pub trait DbCaches {
	/// handle->db_local
	fn local_cache(&mut self) -> Vec<&Package>;
	/// handle->dbs_sync, registration order
	fn sync_caches(&mut self) -> Vec<Vec<&Package>>;
}

// find_requiredby: names of packages in cache with a (opt)depend pkg
// satisfies, first occurrence kept
fn find_requiredby(
	pkg: &Package,
	cache: &[&Package],
	optional: bool,
	reqs: &mut Vec<Vec<u8>>,
) {
	for cachepkg in cache {
		let deps = match optional {
			false => &cachepkg.depends,
			true => &cachepkg.optdepends,
		};
		for dep in deps {
			if !depcmp(pkg, dep) {
				continue;
			}
			let name = cachepkg.name_bytes();
			if !reqs.iter().any(|r| r == name) {
				reqs.push(name.to_vec());
			}
		}
	}
}

// compute_requiredby: file and local packages search the local db in
// cache order, sync packages every sync db, then sorted like strcmp. the
// C reads origin_data.db for an unset origin, None gives nothing here
fn compute(
	pkg: &Package,
	caches: &mut impl DbCaches,
	optional: bool,
) -> Vec<Vec<u8>> {
	let mut reqs = Vec::new();
	match pkg.origin {
		None => {}
		Some(PkgFrom::File(_) | PkgFrom::LocalDb) => {
			let cache = caches.local_cache();
			find_requiredby(pkg, &cache, optional, &mut reqs);
		}
		Some(PkgFrom::SyncDb) => {
			for cache in caches.sync_caches() {
				find_requiredby(
					pkg, &cache, optional, &mut reqs,
				);
			}
			reqs.sort();
		}
	}
	reqs
}

/// alpm_pkg_compute_requiredby
pub fn compute_requiredby(
	pkg: &Package,
	caches: &mut impl DbCaches,
) -> Vec<Vec<u8>> {
	compute(pkg, caches, false)
}

/// alpm_pkg_compute_optionalfor
pub fn compute_optionalfor(
	pkg: &Package,
	caches: &mut impl DbCaches,
) -> Vec<Vec<u8>> {
	compute(pkg, caches, true)
}

/// alpm_pkg_should_ignore (DepsOpts::should_ignore)
pub fn pkg_should_ignore(handle: &Handle, pkg: &Package) -> bool {
	handle.deps_opts().should_ignore(pkg)
}

/// _alpm_pkg_check_meta on a package with this name and version, every
/// failed check logged. true is the C's 0. the name is the fnmatch
/// pattern, the character class the string, as in the C
pub fn check_meta(name: &[u8], version: &[u8], cb: &mut dyn Callbacks) -> bool {
	let (name, version) = (until_nul(name), until_nul(version));
	if name.is_empty() || version.is_empty() {
		// the C's message has no '\n'
		let msg = b"invalid package metadata (name or version missing)";
		cb.log(LogLevel::Error, msg);
		return false;
	}
	let mut ok = true;
	let mut fail = |why: &[u8]| {
		ok = false;
		let parts: [&[u8]; 6] = [
			b"invalid metadata for package ",
			name,
			b"-",
			version,
			b" (",
			why,
		];
		logv(cb, LogLevel::Error, &parts);
	};
	if matches!(name[0], b'-' | b'.') {
		fail(b"package name cannot start with '.' or '-')\n");
	}
	if fnmatch(name, b"[![:alnum:]+_.@-]") {
		fail(b"package name contains invalid characters)\n");
	}
	let dashes = version.iter().filter(|&&c| c == b'-').count();
	if dashes >= 2 {
		fail(b"package version contains invalid characters)\n");
	}
	if version.contains(&b'/') {
		fail(b"package version contains invalid characters)\n");
	}
	if name.len() + version.len() + 1 > NAME_MAX {
		fail(b"package name and version too long)\n");
	}
	ok
}
