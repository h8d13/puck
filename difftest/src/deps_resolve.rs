// reverse dependencies, satisfiers and the ignore check (package.c,
// deps.c) on a real C handle over a fixture: root, a local db and sync db
// files written by the caller. packages come from the C db caches, so
// their depends/optdepends/provides/groups go through the C readers and
// lazy loading
use std::ffi::{CStr, c_void};

use alpm_core::package::{Package, PkgFrom};

use crate::cstr;
use crate::deps::alpm_find_satisfier;
use crate::handle::{
	ALPM, CDb, alpm_db_get_pkgcache, alpm_errno, alpm_get_localdb,
	alpm_initialize, alpm_option_set_ignoregroups,
	alpm_option_set_ignorepkgs, alpm_register_syncdb, alpm_release,
};
use crate::package::{
	CPkg, CPkgBox, alpm_pkg_compute_optionalfor,
	alpm_pkg_compute_requiredby, alpm_pkg_get_name, alpm_pkg_should_ignore,
	list_data, take_strs, with_strs,
};

pub struct CResolve {
	h: *mut c_void,
	local: *mut CDb,
	sync: Vec<*mut CDb>,
}

// what compute_requiredby/optionalfor gave for one package
pub type Reqs = (Vec<Vec<u8>>, Vec<Vec<u8>>);

fn name(p: *mut CPkg) -> Vec<u8> {
	// SAFETY: p is a live package with a handle (pm_errno is written)
	let n = unsafe { alpm_pkg_get_name(p) };
	assert!(!n.is_null(), "cached package without a name");
	// SAFETY: nul-terminated string owned by the package
	unsafe { CStr::from_ptr(n) }.to_bytes().to_vec()
}

fn reqs(p: *mut CPkg) -> Reqs {
	// SAFETY: p is live with a handle and a db or file origin
	unsafe {
		(
			take_strs(alpm_pkg_compute_requiredby(p)),
			take_strs(alpm_pkg_compute_optionalfor(p)),
		)
	}
}

impl CResolve {
	// root and dbpath must exist; sync dbs registered in this order with
	// siglevel 0 (no signature checks), a missing file fails to load
	pub fn new(root: &[u8], dbpath: &[u8], syncdbs: &[&str]) -> Self {
		let (root, dbpath) = (cstr(root), cstr(dbpath));
		let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		let mut err = 0;
		// SAFETY: valid C strings, err is writable
		let h = unsafe {
			alpm_initialize(
				root.as_ptr(),
				dbpath.as_ptr(),
				&mut err,
			)
		};
		assert!(!h.is_null(), "alpm_initialize: {err}");
		let sync = syncdbs
			.iter()
			.map(|n| {
				let n = cstr(n.as_bytes());
				// SAFETY: h is live, n a valid name
				let db = unsafe {
					alpm_register_syncdb(h, n.as_ptr(), 0)
				};
				assert!(!db.is_null());
				db
			})
			.collect();
		// SAFETY: h is live
		let local = unsafe { alpm_get_localdb(h) };
		CResolve { h, local, sync }
	}

	fn db(&self, db: Option<usize>) -> *mut CDb {
		db.map_or(self.local, |i| self.sync[i])
	}

	// the cache list of db (None: local), empty when it fails to load
	fn cache(&self, db: Option<usize>) -> Vec<*mut CPkg> {
		// SAFETY: the db belongs to the live handle
		let list = unsafe { alpm_db_get_pkgcache(self.db(db)) };
		list_data(list).into_iter().map(|p| p.cast()).collect()
	}

	// names in cache list order
	pub fn names(&self, db: Option<usize>) -> Vec<Vec<u8>> {
		self.cache(db).into_iter().map(name).collect()
	}

	// requiredby/optionalfor of every cached package of db, cache order
	pub fn requiredby(&self, db: Option<usize>) -> Vec<Reqs> {
		self.cache(db).into_iter().map(reqs).collect()
	}

	// requiredby/optionalfor of a file package on this handle.
	// C precondition: origin File, names set
	pub fn requiredby_file(&self, pkg: &Package) -> Reqs {
		assert!(matches!(pkg.origin, Some(PkgFrom::File(_))));
		assert!(pkg.name.is_some(), "strdup of a NULL name");
		let b = CPkgBox::new(pkg);
		// SAFETY: b.0 is live and owned here
		unsafe { (*b.0).handle = self.h };
		let r = reqs(b.0);
		// SAFETY: h is live
		assert_eq!(unsafe { alpm_errno(self.h) }, 0);
		r
	}

	// alpm_find_satisfier over the cache list of db, the name found
	pub fn find_satisfier(
		&self,
		db: Option<usize>,
		depstring: &[u8],
	) -> Option<Vec<u8>> {
		// SAFETY: the db belongs to the live handle
		let list = unsafe { alpm_db_get_pkgcache(self.db(db)) };
		let s = cstr(depstring);
		// SAFETY: list is the db's own cache, s a valid C string
		let p = unsafe { alpm_find_satisfier(list, s.as_ptr()) };
		(!p.is_null()).then(|| name(p))
	}

	// alpm_pkg_should_ignore for every cached package of db, with these
	// ignorepkg/ignoregroup lists set on the handle
	pub fn should_ignore(
		&self,
		db: Option<usize>,
		ignorepkg: &[Vec<u8>],
		ignoregroup: &[Vec<u8>],
	) -> Vec<bool> {
		// SAFETY: h is live, the set calls dup the strings
		unsafe {
			with_strs(ignorepkg, |l| {
				alpm_option_set_ignorepkgs(self.h, l)
			});
			with_strs(ignoregroup, |l| {
				alpm_option_set_ignoregroups(self.h, l)
			});
		}
		self.cache(db)
			.into_iter()
			// SAFETY: cached package of the live handle
			.map(|p| unsafe { alpm_pkg_should_ignore(self.h, p) } != 0)
			.collect()
	}
}

impl Drop for CResolve {
	fn drop(&mut self) {
		let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		// SAFETY: h came from alpm_initialize, nothing of it is used
		// afterwards
		unsafe { alpm_release(self.h) };
	}
}
