// C side of alpm_db_search (_alpm_db_search, lib/libalpm/db.c) on a real
// handle over a fixture root the test wrote (local db, sync db files).
// the lazy getters it calls load each searched package in place. regcomp
// runs in C.UTF-8 (cli_util::init), the locale the port's regex models
use std::ffi::{CStr, c_int, c_void};
use std::ptr;

use crate::cli_util::init;
use crate::handle::{
	ALPM, CDb, alpm_db_get_name, alpm_db_set_usage, alpm_errno,
	alpm_get_localdb, alpm_get_syncdbs, alpm_initialize,
	alpm_option_get_root, alpm_register_syncdb, alpm_release,
};
use crate::package::{alpm_pkg_get_name, list_data};
use crate::{CList, alpm_list_add, alpm_list_free, cstr};

unsafe extern "C" {
	fn alpm_db_search(
		db: *mut CDb,
		needles: *const CList,
		ret: *mut *mut CList,
	) -> c_int;
}

// return value, names of the result list in order, pm_errno after
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CSearch {
	pub ret: c_int,
	pub names: Vec<Vec<u8>>,
	pub errno: c_int,
}

pub struct SearchWorld {
	h: *mut c_void,
}

impl SearchWorld {
	// alpm_initialize on root and dbpath (existing dirs), then the sync
	// dbs registered in order with siglevel 0 and their usage
	pub fn open(
		root: &[u8],
		dbpath: &[u8],
		sync: &[(&[u8], c_int)],
	) -> Self {
		init();
		let (root, dbpath) = (cstr(root), cstr(dbpath));
		let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		let mut err = 0;
		// SAFETY: valid C strings, err is writable; the handle copies
		// the names
		unsafe {
			let h = alpm_initialize(
				root.as_ptr(),
				dbpath.as_ptr(),
				&mut err,
			);
			assert!(!h.is_null(), "alpm_initialize: {err}");
			for (name, usage) in sync {
				let n = cstr(name);
				let db = alpm_register_syncdb(h, n.as_ptr(), 0);
				assert!(!db.is_null(), "register {name:?}");
				alpm_db_set_usage(db, *usage);
			}
			SearchWorld { h }
		}
	}

	fn db(&self, name: &[u8]) -> *mut CDb {
		if name == b"local" {
			// SAFETY: live handle
			return unsafe { alpm_get_localdb(self.h) };
		}
		// SAFETY: live handle, the list and names belong to it
		let dbs = list_data(unsafe { alpm_get_syncdbs(self.h) });
		let named = |d: &*mut c_void| {
			// SAFETY: d is a registered db of the live handle
			let n = unsafe {
				CStr::from_ptr(alpm_db_get_name(d.cast()))
			};
			n.to_bytes() == name
		};
		dbs.into_iter()
			.find(named)
			.expect("db not registered")
			.cast()
	}

	// alpm_db_search on the db of that name ("local" or a sync db),
	// pm_errno reset first like the call does
	pub fn search(&self, db: &[u8], needles: &[Vec<u8>]) -> CSearch {
		let db = self.db(db);
		let strs: Vec<_> = needles.iter().map(|n| cstr(n)).collect();
		let list = strs.iter().fold(ptr::null_mut(), |l, s| {
			// SAFETY: l is NULL or from alpm_list_add, the strings
			// outlive the list
			unsafe {
				alpm_list_add(l, s.as_ptr().cast_mut().cast())
			}
		});
		let mut res: *mut CList = ptr::null_mut();
		// SAFETY: db belongs to the live handle, list holds valid C
		// strings, res starts NULL. the result nodes are freed, the
		// packages stay owned by the cache; get_root only resets
		// pm_errno
		unsafe {
			alpm_option_get_root(self.h);
			let ret = alpm_db_search(db, list, &mut res);
			let errno = alpm_errno(self.h);
			let names = list_data(res)
				.into_iter()
				.map(|p| {
					let n = alpm_pkg_get_name(p.cast());
					CStr::from_ptr(n).to_bytes().to_vec()
				})
				.collect();
			alpm_list_free(res);
			alpm_list_free(list);
			CSearch { ret, names, errno }
		}
	}
}

impl Drop for SearchWorld {
	fn drop(&mut self) {
		let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		// SAFETY: h came from alpm_initialize, nothing of it is used
		// afterwards
		unsafe { alpm_release(self.h) };
	}
}
