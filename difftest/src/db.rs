// C side of lib/libalpm/db.c and the handle options of handle.c, through
// the exported API plus the cache internals (_alpm_db_path,
// _alpm_db_add_pkgincache, _alpm_db_remove_pkgfromcache,
// _alpm_db_free_pkgcache, _alpm_db_cmp). the lazy getters of cached
// packages load them in place (local_db_read).
//
// a CHandle is one alpm_initialize'd handle holding the ALPM lock. dbs
// are named like the Rust side: "local" is the local db (no sync db can
// take that name). calls that report through pm_errno return it next to
// their result; pm_errno is reset first (alpm_option_get_root's
// CHECK_HANDLE), so a call leaving it alone reads 0.
use std::cmp::Ordering;
use std::ffi::{CString, c_char, c_int, c_void};
use std::ptr;
use std::sync::MutexGuard;

use alpm_core::be_local::{INFRQ_DESC, INFRQ_FILES, INFRQ_SCRIPTLET};
use alpm_core::group::Group;
use alpm_core::package::Package;

use crate::group::CGroup;
use crate::handle::*;
use crate::package::{CPkg, CPkgBox, field, list_data, read_pkg, read_strs};
use crate::package::{
	alpm_pkg_get_desc, alpm_pkg_get_files, alpm_pkg_has_scriptlet,
};
use crate::{CList, alpm_list_add, alpm_list_free, cstr};

unsafe extern "C" {}

pub struct CHandle {
	h: *mut c_void,
	_guard: MutexGuard<'static, ()>,
}

impl Drop for CHandle {
	fn drop(&mut self) {
		// SAFETY: h came from alpm_initialize, no transaction, nothing
		// from it is used afterwards; the lock is released after
		unsafe { alpm_release(self.h) };
	}
}

// the handle string list options, one set of four functions each
#[derive(Clone, Copy, Debug)]
pub enum StrList {
	Arch,
	NoUpgrade,
	NoExtract,
	IgnorePkg,
	IgnoreGroup,
}

type Getter = unsafe extern "C" fn(*mut c_void) -> *mut CList;
type Setter = unsafe extern "C" fn(*mut c_void, *mut CList) -> c_int;
type StrOp = unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int;
type DbStrOp = unsafe extern "C" fn(*mut CDb, *const c_char) -> c_int;
type DbSet = unsafe extern "C" fn(*mut CDb, *mut CList) -> c_int;
type DbGet = unsafe extern "C" fn(*const CDb) -> *mut CList;

impl StrList {
	fn ops(self) -> (Getter, StrOp, Setter, StrOp) {
		match self {
			StrList::Arch => (
				alpm_option_get_architectures,
				alpm_option_add_architecture,
				alpm_option_set_architectures,
				alpm_option_remove_architecture,
			),
			StrList::NoUpgrade => (
				alpm_option_get_noupgrades,
				alpm_option_add_noupgrade,
				alpm_option_set_noupgrades,
				alpm_option_remove_noupgrade,
			),
			StrList::NoExtract => (
				alpm_option_get_noextracts,
				alpm_option_add_noextract,
				alpm_option_set_noextracts,
				alpm_option_remove_noextract,
			),
			StrList::IgnorePkg => (
				alpm_option_get_ignorepkgs,
				alpm_option_add_ignorepkg,
				alpm_option_set_ignorepkgs,
				alpm_option_remove_ignorepkg,
			),
			StrList::IgnoreGroup => (
				alpm_option_get_ignoregroups,
				alpm_option_add_ignoregroup,
				alpm_option_set_ignoregroups,
				alpm_option_remove_ignoregroup,
			),
		}
	}
}

// a C list over the strings, freed (nodes only) by the caller
fn str_list(strs: &[CString]) -> *mut CList {
	strs.iter().fold(ptr::null_mut(), |list, s| {
		// SAFETY: list is NULL or built by alpm_list_add; the strings
		// outlive the list, the C copies them
		unsafe { alpm_list_add(list, s.as_ptr().cast_mut().cast()) }
	})
}

// C call taking a temporary list of strings
fn with_list<R>(strs: &[Vec<u8>], f: impl FnOnce(*mut CList) -> R) -> R {
	let strs: Vec<CString> = strs.iter().map(|s| cstr(s)).collect();
	let list = str_list(&strs);
	let r = f(list);
	// SAFETY: nodes from str_list, the data belongs to strs
	unsafe { alpm_list_free(list) };
	r
}

fn copy(p: *const c_char) -> Vec<u8> {
	field(p).expect("C returned NULL")
}

impl CHandle {
	// alpm_initialize, Err is the alpm_errno_t it reports
	pub fn new(root: &[u8], dbpath: &[u8]) -> Result<CHandle, c_int> {
		let guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		let (root, dbpath) = (cstr(root), cstr(dbpath));
		let mut err = 0;
		// SAFETY: valid C strings, err is writable
		let h = unsafe {
			alpm_initialize(
				root.as_ptr(),
				dbpath.as_ptr(),
				&mut err,
			)
		};
		if h.is_null() {
			return Err(err);
		}
		Ok(CHandle { h, _guard: guard })
	}

	// pm_errno back to ALPM_ERR_OK
	fn reset(&self) {
		// SAFETY: h is live, CHECK_HANDLE only writes pm_errno
		unsafe { alpm_option_get_root(self.h) };
	}

	fn errno(&self) -> c_int {
		// SAFETY: h is live
		unsafe { alpm_errno(self.h) }
	}

	// the live handle, for wrappers of other C files
	pub(crate) fn raw(&self) -> *mut c_void {
		self.h
	}

	// f with pm_errno reset before, its result and pm_errno after
	pub(crate) fn call<R>(&self, f: impl FnOnce() -> R) -> (R, c_int) {
		self.reset();
		let r = f();
		(r, self.errno())
	}

	fn syncdb_ptrs(&self) -> Vec<*mut CDb> {
		// SAFETY: h is live, the list stays owned by the handle
		let list = unsafe { alpm_get_syncdbs(self.h) };
		list_data(list).into_iter().map(|p| p.cast()).collect()
	}

	fn db_name(db: *mut CDb) -> Vec<u8> {
		// SAFETY: db is a live registered db
		copy(unsafe { alpm_db_get_name(db) })
	}

	// the db of that name, None when not registered
	fn find_db(&self, name: &[u8]) -> Option<*mut CDb> {
		if name == b"local" {
			// SAFETY: h is live
			let db = unsafe { alpm_get_localdb(self.h) };
			return (!db.is_null()).then_some(db);
		}
		let ptrs = self.syncdb_ptrs();
		ptrs.into_iter().find(|&d| Self::db_name(d) == name)
	}

	fn db(&self, name: &[u8]) -> *mut CDb {
		self.find_db(name).expect("db not registered")
	}

	pub fn has_db(&self, name: &[u8]) -> bool {
		self.find_db(name).is_some()
	}

	// alpm_get_syncdbs, names in list order
	pub fn syncdb_names(&self) -> Vec<Vec<u8>> {
		let ptrs = self.syncdb_ptrs();
		ptrs.into_iter().map(Self::db_name).collect()
	}

	pub fn root(&self) -> Vec<u8> {
		// SAFETY: h is live, the string is owned by the handle
		copy(unsafe { alpm_option_get_root(self.h) })
	}

	pub fn dbpath(&self) -> Vec<u8> {
		// SAFETY: h is live, the string is owned by the handle
		copy(unsafe { alpm_option_get_dbpath(self.h) })
	}

	pub fn dbext(&self) -> Vec<u8> {
		// SAFETY: h is live, the string is owned by the handle
		copy(unsafe { alpm_option_get_dbext(self.h) })
	}

	pub fn set_dbext(&self, dbext: &[u8]) -> (c_int, c_int) {
		let dbext = cstr(dbext);
		// SAFETY: h is live, the C copies dbext
		self.call(|| unsafe {
			alpm_option_set_dbext(self.h, dbext.as_ptr())
		})
	}

	// alpm_register_syncdb: whether a db came back
	pub fn register_syncdb(
		&self,
		name: &[u8],
		level: c_int,
	) -> (bool, c_int) {
		let name = cstr(name);
		// SAFETY: h is live, the C copies name; the db stays owned by
		// the handle
		self.call(|| unsafe {
			!alpm_register_syncdb(self.h, name.as_ptr(), level)
				.is_null()
		})
	}

	pub fn unregister_all_syncdbs(&self) -> (c_int, c_int) {
		// SAFETY: h is live, the dbs are freed and not used after
		self.call(|| unsafe { alpm_unregister_all_syncdbs(self.h) })
	}

	// alpm_db_unregister on a registered db
	pub fn unregister(&self, name: &[u8]) -> (c_int, c_int) {
		let db = self.db(name);
		// SAFETY: db is registered, freed by the call, not used after
		self.call(|| unsafe { alpm_db_unregister(db) })
	}

	fn db_list(&self, name: &[u8], get: DbGet) -> Vec<Vec<u8>> {
		let db = self.db(name);
		// SAFETY: db is live, the list stays owned by it
		read_strs(unsafe { get(db) })
	}

	pub fn servers(&self, name: &[u8], cache: bool) -> Vec<Vec<u8>> {
		match cache {
			false => self.db_list(name, alpm_db_get_servers),
			true => self.db_list(name, alpm_db_get_cache_servers),
		}
	}

	fn db_str_op(
		&self,
		name: &[u8],
		f: DbStrOp,
		s: &[u8],
	) -> (c_int, c_int) {
		let (db, s) = (self.db(name), cstr(s));
		// SAFETY: db is live, the C copies or compares s
		self.call(|| unsafe { f(db, s.as_ptr()) })
	}

	pub fn add_server(
		&self,
		name: &[u8],
		url: &[u8],
		cache: bool,
	) -> (c_int, c_int) {
		let f = match cache {
			false => alpm_db_add_server,
			true => alpm_db_add_cache_server,
		};
		self.db_str_op(name, f, url)
	}

	pub fn remove_server(
		&self,
		name: &[u8],
		url: &[u8],
		cache: bool,
	) -> (c_int, c_int) {
		let f = match cache {
			false => alpm_db_remove_server,
			true => alpm_db_remove_cache_server,
		};
		self.db_str_op(name, f, url)
	}

	pub fn set_servers(
		&self,
		name: &[u8],
		urls: &[Vec<u8>],
		cache: bool,
	) -> (c_int, c_int) {
		let f: DbSet = match cache {
			false => alpm_db_set_servers,
			true => alpm_db_set_cache_servers,
		};
		let db = self.db(name);
		// SAFETY: db is live, the C copies every url of the list
		with_list(urls, |list| self.call(|| unsafe { f(db, list) }))
	}

	pub fn usage(&self, name: &[u8]) -> c_int {
		let (db, mut usage) = (self.db(name), 0);
		// SAFETY: db is live, usage writable
		assert_eq!(unsafe { alpm_db_get_usage(db, &mut usage) }, 0);
		usage
	}

	pub fn set_usage(&self, name: &[u8], usage: c_int) {
		let db = self.db(name);
		// SAFETY: db is live
		assert_eq!(unsafe { alpm_db_set_usage(db, usage) }, 0);
	}

	pub fn siglevel(&self, name: &[u8]) -> c_int {
		let db = self.db(name);
		// SAFETY: db is live
		unsafe { alpm_db_get_siglevel(db) }
	}

	pub fn valid(&self, name: &[u8]) -> (c_int, c_int) {
		let db = self.db(name);
		// SAFETY: db is live; no signature level is set on the dbs
		// tests register, so validate never reaches gpgme
		self.call(|| unsafe { alpm_db_get_valid(db) })
	}

	// _alpm_db_path, set when the db was registered
	pub fn path(&self, name: &[u8]) -> Vec<u8> {
		let db = self.db(name);
		// SAFETY: db is live, the path is cached in it
		copy(unsafe { _alpm_db_path(db) })
	}

	// the loaded cache list, without loading it
	fn cache_ptrs(db: *mut CDb) -> Vec<*mut CPkg> {
		// SAFETY: db is live, pkgcache NULL or its hash
		let hash = unsafe { (*db).pkgcache };
		if hash.is_null() {
			return Vec::new();
		}
		// SAFETY: hash is live
		let list = unsafe { (*hash).list };
		list_data(list).into_iter().map(|p| p.cast()).collect()
	}

	// alpm_db_get_pkgcache: packages in list order, read through the
	// mirror (lazy fields as loaded so far)
	pub fn pkgcache(&self, name: &[u8]) -> (Vec<Package>, c_int) {
		let db = self.db(name);
		// SAFETY: db is live, the list stays owned by the cache
		let (list, e) =
			self.call(|| unsafe { alpm_db_get_pkgcache(db) });
		let pkgs = list_data(list);
		(pkgs.into_iter().map(|p| read_pkg(p.cast())).collect(), e)
	}

	// alpm_db_get_pkg
	pub fn get_pkg(
		&self,
		name: &[u8],
		pkg: &[u8],
	) -> (Option<Package>, c_int) {
		let (db, pkg) = (self.db(name), cstr(pkg));
		// SAFETY: db is live, the package stays owned by the cache
		let (p, e) = self
			.call(|| unsafe { alpm_db_get_pkg(db, pkg.as_ptr()) });
		((!p.is_null()).then(|| read_pkg(p)), e)
	}

	// alpm_db_get_pkg, then one getter per INFRQ_* bit of inforeq
	// (desc, files, has_scriptlet) on the cached package: what they
	// loaded stays in it. pm_errno is the get_pkg one, the getters reset
	// it
	pub fn load_pkg(
		&self,
		name: &[u8],
		pkg: &[u8],
		inforeq: c_int,
	) -> (Option<Package>, c_int) {
		let (db, pkg) = (self.db(name), cstr(pkg));
		// SAFETY: db is live, the package stays owned by the cache
		let (p, e) = self
			.call(|| unsafe { alpm_db_get_pkg(db, pkg.as_ptr()) });
		if p.is_null() {
			return (None, e);
		}
		// SAFETY: p is a live cache entry with its db's ops, the
		// results point into it and are not kept
		unsafe {
			if inforeq & INFRQ_DESC != 0 {
				alpm_pkg_get_desc(p);
			}
			if inforeq & INFRQ_FILES != 0 {
				alpm_pkg_get_files(p);
			}
			if inforeq & INFRQ_SCRIPTLET != 0 {
				alpm_pkg_has_scriptlet(p);
			}
		}
		(Some(read_pkg(p)), e)
	}

	// entries, buckets, limit of the loaded package cache, without
	// loading it
	pub fn cache_counts(
		&self,
		name: &[u8],
	) -> Option<(usize, usize, usize)> {
		let db = self.db(name);
		// SAFETY: db is live, pkgcache NULL or its hash
		let hash = unsafe { (*db).pkgcache };
		if hash.is_null() {
			return None;
		}
		// SAFETY: hash is live
		let h = unsafe { &*hash };
		Some((h.entries as usize, h.buckets as usize, h.limit as usize))
	}

	// group with members as positions in the cache list
	fn read_group(db: *mut CDb, g: *const CGroup) -> Group<usize> {
		let cache = Self::cache_ptrs(db);
		// SAFETY: g is a live group of the db's group cache
		let g = unsafe { &*g };
		let members = list_data(g.packages).into_iter().map(|p| {
			let p = p.cast::<CPkg>();
			cache.iter().position(|&c| c == p).expect("not cached")
		});
		Group {
			name: copy(g.name),
			packages: members.collect(),
		}
	}

	// alpm_db_get_groupcache
	pub fn groupcache(&self, name: &[u8]) -> (Vec<Group<usize>>, c_int) {
		let db = self.db(name);
		// SAFETY: db is live, the list stays owned by the db
		let (list, e) =
			self.call(|| unsafe { alpm_db_get_groupcache(db) });
		let groups = list_data(list).into_iter();
		(
			groups.map(|g| Self::read_group(db, g.cast()))
				.collect(),
			e,
		)
	}

	// alpm_db_get_group
	pub fn get_group(
		&self,
		name: &[u8],
		grp: &[u8],
	) -> (Option<Group<usize>>, c_int) {
		let (db, grp) = (self.db(name), cstr(grp));
		// SAFETY: db is live, the group stays owned by the db
		let (g, e) = self.call(|| unsafe {
			alpm_db_get_group(db, grp.as_ptr())
		});
		((!g.is_null()).then(|| Self::read_group(db, g)), e)
	}

	// _alpm_db_add_pkgincache of a mirror-built package, and where its
	// copy landed in the cache list with every field
	pub fn add_pkg_in_cache(
		&self,
		name: &[u8],
		pkg: &Package,
	) -> (c_int, c_int, Option<(usize, Package)>) {
		let db = self.db(name);
		let before = Self::cache_ptrs(db);
		let b = CPkgBox::new(pkg);
		// SAFETY: db and b live; the C stores a dup, b stays ours
		let (r, e) = self
			.call(|| unsafe { _alpm_db_add_pkgincache(db, b.0) });
		let after = Self::cache_ptrs(db);
		let new = after.iter().position(|p| !before.contains(p));
		(r, e, new.map(|i| (i, read_pkg(after[i]))))
	}

	// _alpm_db_remove_pkgfromcache, key matched by name and name_hash
	pub fn remove_pkg_from_cache(
		&self,
		name: &[u8],
		key: &Package,
	) -> (c_int, c_int) {
		let db = self.db(name);
		let b = CPkgBox::new(key);
		// SAFETY: db and b live, the C frees the cached entry only
		self.call(|| unsafe { _alpm_db_remove_pkgfromcache(db, b.0) })
	}

	pub fn free_pkgcache(&self, name: &[u8]) {
		let db = self.db(name);
		// SAFETY: db is live, the cache is not referenced elsewhere
		unsafe { _alpm_db_free_pkgcache(db) };
	}

	// _alpm_db_cmp of two registered dbs
	pub fn db_cmp(&self, a: &[u8], b: &[u8]) -> Ordering {
		let (a, b) = (self.db(a), self.db(b));
		// SAFETY: both live, only the names are read
		unsafe { _alpm_db_cmp(a.cast(), b.cast()) }.cmp(&0)
	}

	pub fn default_siglevel(&self) -> c_int {
		// SAFETY: h is live
		unsafe { alpm_option_get_default_siglevel(self.h) }
	}

	pub fn set_default_siglevel(&self, level: c_int) -> (c_int, c_int) {
		// SAFETY: h is live
		self.call(|| unsafe {
			alpm_option_set_default_siglevel(self.h, level)
		})
	}

	// local (true) or remote file siglevel
	pub fn file_siglevel(&self, local: bool) -> c_int {
		// SAFETY: h is live
		unsafe {
			match local {
				true => alpm_option_get_local_file_siglevel(
					self.h,
				),
				false => alpm_option_get_remote_file_siglevel(
					self.h,
				),
			}
		}
	}

	pub fn set_file_siglevel(
		&self,
		local: bool,
		level: c_int,
	) -> (c_int, c_int) {
		// SAFETY: h is live
		self.call(|| unsafe {
			match local {
				true => alpm_option_set_local_file_siglevel(
					self.h, level,
				),
				false => alpm_option_set_remote_file_siglevel(
					self.h, level,
				),
			}
		})
	}

	pub fn strlist(&self, which: StrList) -> Vec<Vec<u8>> {
		// SAFETY: h is live, the list stays owned by the handle
		read_strs(unsafe { (which.ops().0)(self.h) })
	}

	pub fn strlist_add(&self, which: StrList, s: &[u8]) -> (c_int, c_int) {
		let s = cstr(s);
		// SAFETY: h is live, the C copies s
		self.call(|| unsafe { (which.ops().1)(self.h, s.as_ptr()) })
	}

	pub fn strlist_set(
		&self,
		which: StrList,
		strs: &[Vec<u8>],
	) -> (c_int, c_int) {
		// SAFETY: h is live, the C copies the strings
		with_list(strs, |l| {
			self.call(|| unsafe { (which.ops().2)(self.h, l) })
		})
	}

	pub fn strlist_remove(
		&self,
		which: StrList,
		s: &[u8],
	) -> (c_int, c_int) {
		let s = cstr(s);
		// SAFETY: h is live, s only compared
		self.call(|| unsafe { (which.ops().3)(self.h, s.as_ptr()) })
	}

	// alpm_option_match_noupgrade (true) or _noextract
	pub fn match_list(&self, noupgrade: bool, path: &[u8]) -> c_int {
		let path = cstr(path);
		// SAFETY: h is live, path only read
		unsafe {
			match noupgrade {
				true => alpm_option_match_noupgrade(
					self.h,
					path.as_ptr(),
				),
				false => alpm_option_match_noextract(
					self.h,
					path.as_ptr(),
				),
			}
		}
	}
}
