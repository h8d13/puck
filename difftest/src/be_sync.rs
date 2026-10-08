// C side of lib/libalpm/be_sync.c, through the exported API: a handle on
// a fixture root, one sync db registered without signature checks, its
// package cache read through the package mirror, the _alpm_log lines of
// the cache load recorded
use std::ffi::c_int;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use alpm_core::package::Package;

use crate::handle::{
	ALPM, CDb, CLogs, alpm_db_get_pkgcache, alpm_errno, alpm_initialize,
	alpm_option_set_dbext, alpm_option_set_logcb, alpm_register_syncdb,
	alpm_release, record_log,
};
use crate::package::alpm_pkg_get_validation;
use crate::package::{CPkg, list_data, read_pkg};
use crate::{CList, cstr};

unsafe extern "C" {}

// a loaded sync db: cache list order, alpm_pkg_get_validation per
// package (called after the copy, so Package::validation is the raw
// field), and the table's entries, buckets, limit
#[derive(Debug)]
pub struct CSyncDb {
	pub pkgs: Vec<Package>,
	pub validation: Vec<c_int>,
	pub counts: (usize, usize, usize),
}

fn path_cstr(p: &Path) -> std::ffi::CString {
	cstr(p.as_os_str().as_bytes())
}

fn read_cache(db: *mut CDb, list: *mut CList) -> CSyncDb {
	let ptrs: Vec<*mut CPkg> =
		list_data(list).into_iter().map(|p| p.cast()).collect();
	let pkgs = ptrs.iter().map(|&p| read_pkg(p)).collect();
	// SAFETY: every pointer is a live package of the db cache
	let validation = ptrs
		.iter()
		.map(|&p| unsafe { alpm_pkg_get_validation(p) })
		.collect();
	// SAFETY: db is live, pkgcache set by the successful populate
	let h = unsafe { &*(*db).pkgcache };
	CSyncDb {
		pkgs,
		validation,
		counts: (
			h.entries as usize,
			h.buckets as usize,
			h.limit as usize,
		),
	}
}

// alpm_db_get_pkgcache of <dbpath>/sync/<treename><dbext>, Err is the
// pm_errno it leaves, next to the lines it logged. root and dbpath must
// exist. siglevel 0: no signature checks, sync_db_validate only looks
// for the file
pub fn c_sync_db_load(
	root: &Path,
	dbpath: &Path,
	treename: &[u8],
	dbext: &[u8],
) -> (Result<CSyncDb, c_int>, CLogs) {
	let (root, dbpath) = (path_cstr(root), path_cstr(dbpath));
	let (treename, dbext) = (cstr(treename), cstr(dbext));
	let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
	let mut err = 0;
	// SAFETY: valid C strings, err receives the failure code
	let h = unsafe {
		alpm_initialize(root.as_ptr(), dbpath.as_ptr(), &mut err)
	};
	assert!(!h.is_null(), "alpm_initialize failed: {err}");
	let mut logs = CLogs::new();
	let ctx: *mut CLogs = &mut logs;
	// SAFETY: h is a live handle, strings valid for the calls; the
	// cache is copied out before alpm_release frees it. logs outlives
	// the callback, which is unset before the release
	let out = unsafe {
		assert_eq!(alpm_option_set_dbext(h, dbext.as_ptr()), 0);
		let db = alpm_register_syncdb(h, treename.as_ptr(), 0);
		assert!(!db.is_null(), "register failed: {}", alpm_errno(h));
		alpm_option_set_logcb(h, Some(record_log), ctx.cast());
		let list = alpm_db_get_pkgcache(db);
		let out = match alpm_errno(h) {
			0 => Ok(read_cache(db, list)),
			e => Err(e),
		};
		alpm_option_set_logcb(h, None, std::ptr::null_mut());
		alpm_release(h);
		out
	};
	(out, logs)
}
