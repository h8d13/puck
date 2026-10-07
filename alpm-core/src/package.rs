// port of lib/libalpm/package.c, the alpm_pkg_t data model, its pure
// helpers, reverse dependencies and the ignore check.
//
// not modelled: handle, ops vtable, origin_data.db, removes and oldpkg.
// the alpm_pkg_get_* accessors are plain field reads with default_pkg_ops;
// lazy loading (local db infolevel, force_load) waits for the db backends.
// _alpm_pkg_free is Drop, _alpm_file_copy is File::clone.

use std::cmp::Ordering;
use std::ffi::{c_int, c_ulong};

use crate::backup::Backup;
use crate::deps::{Depend, depcmp};
use crate::filelist::FileList;
use crate::handle::Handle;
use crate::util::{fnmatch, hash_sdbm, until_nul};
use crate::version::vercmp;

// alpm_pkg_xdata_t
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PkgXData {
	pub name: Vec<u8>,
	pub value: Vec<u8>,
}

// alpm_pkgreason_t, discriminants as in alpm.h
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PkgReason {
	#[default]
	Explicit = 0,
	Depend = 1,
	Unknown = 2,
}

// alpm_pkgfrom_t with origin_data folded in. the db pointer of the two db
// origins waits for the db backends
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PkgFrom {
	// path the package was loaded from, origin_data.file
	File(Vec<u8>),
	LocalDb,
	SyncDb,
}

// alpm_pkgvalidation_t bits for Package::validation
pub const PKG_VALIDATION_UNKNOWN: c_int = 0;
pub const PKG_VALIDATION_NONE: c_int = 1 << 0;
pub const PKG_VALIDATION_MD5SUM: c_int = 1 << 1;
pub const PKG_VALIDATION_SHA256SUM: c_int = 1 << 2;
pub const PKG_VALIDATION_SIGNATURE: c_int = 1 << 3;

// alpm_pkg_t, Default is _alpm_pkg_new (calloc). NULL strings are None.
// alpm_time_t and off_t are 64 bit in the meson build
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Package {
	// _alpm_hash_sdbm of name, set by hand like the C: a stale hash
	// changes lookups the same way
	pub name_hash: c_ulong,
	pub filename: Option<Vec<u8>>,
	pub base: Option<Vec<u8>>,
	pub name: Option<Vec<u8>>,
	pub version: Option<Vec<u8>>,
	pub desc: Option<Vec<u8>>,
	pub url: Option<Vec<u8>>,
	pub packager: Option<Vec<u8>>,
	pub sha256sum: Option<Vec<u8>>,
	pub base64_sig: Option<Vec<u8>>,
	pub arch: Option<Vec<u8>>,
	pub builddate: i64,
	pub installdate: i64,
	pub size: i64,
	pub isize: i64,
	pub download_size: i64,
	pub licenses: Vec<Vec<u8>>,
	pub replaces: Vec<Depend>,
	pub groups: Vec<Vec<u8>>,
	pub backup: Vec<Backup>,
	pub depends: Vec<Depend>,
	pub optdepends: Vec<Depend>,
	pub checkdepends: Vec<Depend>,
	pub makedepends: Vec<Depend>,
	pub conflicts: Vec<Depend>,
	pub provides: Vec<Depend>,
	pub files: FileList,
	// None while unset, calloc leaves the C enum at 0
	pub origin: Option<PkgFrom>,
	pub reason: PkgReason,
	// C int, nonzero when the package has an install scriptlet
	pub scriptlet: c_int,
	pub xdata: Vec<PkgXData>,
	// alpm_dbinfrq_t bits
	pub infolevel: c_int,
	// PKG_VALIDATION_* bits
	pub validation: c_int,
}

impl Package {
	// name as strcmp sees it. the C dereferences NULL names, None reads
	// as empty here
	pub fn name_bytes(&self) -> &[u8] {
		until_nul(self.name.as_deref().unwrap_or_default())
	}

	// _alpm_pkg_dup without the handle/ops/db pointers. the C copies a
	// subset: base64_sig, download_size, checkdepends, makedepends and
	// xdata come back empty, Clone copies everything
	pub fn dup(&self) -> Package {
		Package {
			base64_sig: None,
			download_size: 0,
			checkdepends: Vec::new(),
			makedepends: Vec::new(),
			xdata: Vec::new(),
			..self.clone()
		}
	}
}

// _alpm_pkg_cmp: strcmp on the names
pub fn pkg_cmp(a: &Package, b: &Package) -> Ordering {
	a.name_bytes().cmp(b.name_bytes())
}

// _alpm_pkg_compare_versions: alpm_pkg_vercmp, a NULL version sorts
// before any other, two NULLs are equal
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

// alpm_pkg_find: first package named needle
pub fn pkg_find<'a, I>(haystack: I, needle: &[u8]) -> Option<&'a Package>
where
	I: IntoIterator<Item = &'a Package>,
{
	let (needle, hash) = (until_nul(needle), hash_sdbm(needle));
	haystack.into_iter().find(|p| has_name(p, needle, hash))
}

// the db caches compute_requiredby walks, each in its pkgcache list
// order. packages must have their depends/optdepends loaded (the C getters
// lazy-load local entries). a cache that does not load is a NULL list in
// the C, an empty one here
pub trait DbCaches {
	// handle->db_local
	fn local_cache(&mut self) -> Vec<&Package>;
	// handle->dbs_sync, registration order
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
		let name = cachepkg.name_bytes();
		for dep in deps {
			if depcmp(pkg, dep) && !reqs.iter().any(|r| r == name) {
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

// alpm_pkg_compute_requiredby
pub fn compute_requiredby(
	pkg: &Package,
	caches: &mut impl DbCaches,
) -> Vec<Vec<u8>> {
	compute(pkg, caches, false)
}

// alpm_pkg_compute_optionalfor
pub fn compute_optionalfor(
	pkg: &Package,
	caches: &mut impl DbCaches,
) -> Vec<Vec<u8>> {
	compute(pkg, caches, true)
}

// alpm_pkg_should_ignore: the name or one of the groups matches an
// ignorepkg/ignoregroup entry as an fnmatch pattern (alpm_list_find with
// _alpm_fnmatch, so no '!' negation). groups as given, the C getter
// lazy-loads them for local packages
pub fn pkg_should_ignore(handle: &Handle, pkg: &Package) -> bool {
	let matches =
		|pats: &[Vec<u8>], s: &[u8]| pats.iter().any(|p| fnmatch(p, s));
	matches(handle.ignorepkgs(), pkg.name_bytes())
		|| pkg.groups.iter().any(|g| matches(handle.ignoregroups(), g))
}
