// C side of lib/libalpm/be_local.c, reached through the public handle API:
// alpm_initialize registers and validates the local db, the pkgcache
// populates it, the lazy getters run local_db_read. every _alpm_log line
// after alpm_initialize is recorded.
use std::ffi::{c_int, c_void};

use alpm_core::internals::package::Package;

use crate::cstr;
use crate::handle::{
	_alpm_db_get_pkgcache_hash, ALPM, CLogs, alpm_db_get_pkgcache,
	alpm_errno, alpm_get_localdb, alpm_initialize, alpm_option_set_logcb,
	alpm_release, record_log,
};
use crate::package::{CPkg, list_data, read_pkg};
use crate::package::{
	alpm_pkg_get_desc, alpm_pkg_get_files, alpm_pkg_has_scriptlet,
};

unsafe extern "C" {}

// which lazy loads run, in this order. INFRQ_ERROR is sticky, so a failed
// section hides the ones after it on both sides
#[derive(Clone, Copy, Debug)]
pub struct Loads {
	pub desc: bool,
	pub files: bool,
	pub scriptlet: bool,
}

impl Loads {
	pub const ALL: Loads = Loads {
		desc: true,
		files: true,
		scriptlet: true,
	};
}

#[derive(Debug)]
pub struct CLocalDb {
	// pkgcache list order, every field read through the mirror after the
	// loads (getters only return the fields they loaded)
	pub pkgs: Vec<Package>,
	// pkgcache entries, buckets, limit
	pub counts: (usize, usize, usize),
}

// Err is the alpm_errno_t of alpm_initialize (validate) or of the
// pkgcache (populate), next to the log lines of the populate and loads.
// root and dbpath must be existing directories
pub fn c_local_db(
	root: &[u8],
	dbpath: &[u8],
	loads: Loads,
) -> (Result<CLocalDb, c_int>, CLogs) {
	let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
	let (root, dbpath) = (cstr(root), cstr(dbpath));
	let mut err = 0;
	// SAFETY: valid C strings, err is writable
	let h = unsafe {
		alpm_initialize(root.as_ptr(), dbpath.as_ptr(), &mut err)
	};
	if h.is_null() {
		return (Err(err), CLogs::new());
	}
	let mut logs = CLogs::new();
	let ctx: *mut CLogs = &mut logs;
	// SAFETY: h is live, logs outlives the handle; nothing else
	// touches logs while the C runs
	unsafe { alpm_option_set_logcb(h, Some(record_log), ctx.cast()) };
	let r = read_localdb(h, loads);
	// SAFETY: h is live, the release lines are not wanted
	unsafe { alpm_option_set_logcb(h, None, std::ptr::null_mut()) };
	// SAFETY: h came from alpm_initialize, no transaction, no lock held;
	// nothing from it is used afterwards
	unsafe { alpm_release(h) };
	(r, logs)
}

fn read_localdb(h: *mut c_void, loads: Loads) -> Result<CLocalDb, c_int> {
	// SAFETY: h is a live handle, initialize registered the local db
	let db = unsafe { alpm_get_localdb(h) };
	assert!(!db.is_null());
	// SAFETY: db is live, the list stays owned by its cache
	let list = unsafe { alpm_db_get_pkgcache(db) };
	// an empty cache is NULL too
	// SAFETY: h is live
	let errno = unsafe { alpm_errno(h) };
	if list.is_null() && errno != 0 {
		return Err(errno);
	}
	// SAFETY: the cache is loaded, this only returns it
	let hash = unsafe { &*_alpm_db_get_pkgcache_hash(db) };
	let counts = (
		hash.entries as usize,
		hash.buckets as usize,
		hash.limit as usize,
	);
	let pkgs = list_data(list)
		.into_iter()
		.map(|p| {
			let p = p.cast::<CPkg>();
			// SAFETY: p is a live package of the cache with the local
			// ops, the getters load into it
			unsafe {
				if loads.desc {
					alpm_pkg_get_desc(p);
				}
				if loads.files {
					alpm_pkg_get_files(p);
				}
				if loads.scriptlet {
					alpm_pkg_has_scriptlet(p);
				}
			}
			read_pkg(p)
		})
		.collect();
	Ok(CLocalDb { pkgs, counts })
}
