// C side of the writing half of lib/libalpm/be_local.c: internal
// _alpm_local_db_prepare/_alpm_local_db_write/_alpm_local_db_remove and
// alpm_pkg_set_reason, run as an op sequence on one alpm_initialize'd
// handle. packages are built through the package mirror; set_reason goes
// to the cached package of that name like pacman's -D does. every op
// returns its rc and pm_errno (reset before the op)
use std::ffi::{OsStr, c_int};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use alpm_core::package::{Package, PkgReason};

use crate::cstr;
use crate::db::CHandle;
use crate::handle::{CDb, alpm_db_get_pkg, alpm_get_localdb};
use crate::package::{CPkg, CPkgBox, alpm_pkg_get_reason};

unsafe extern "C" {
	fn _alpm_local_db_prepare(db: *mut CDb, info: *mut CPkg) -> c_int;
	fn _alpm_local_db_write(
		db: *mut CDb,
		info: *mut CPkg,
		inforeq: c_int,
	) -> c_int;
	fn _alpm_local_db_remove(db: *mut CDb, info: *mut CPkg) -> c_int;
	fn alpm_pkg_set_reason(pkg: *mut CPkg, reason: c_int) -> c_int;
}

// how a Break op replaces the local db dir between ops
#[derive(Clone, Copy, Debug)]
pub enum Break {
	// rm -rf local/
	Remove,
	// local/ becomes a regular file
	File,
	// local/ becomes a symlink to a missing path
	Dangling,
}

#[derive(Clone, Debug)]
pub enum WriteOp {
	Prepare(Package),
	Write(Package, c_int),
	Remove(Package),
	// alpm_db_get_pkg(localdb, name) then alpm_pkg_set_reason on it
	SetReason(Vec<u8>, PkgReason),
	// alpm_pkg_set_reason on a package that is not from the local db
	SetReasonDetached(Package, PkgReason),
	// fixture change, not a C call: same on both sides
	Break(Break),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpResult {
	pub rc: c_int,
	pub errno: c_int,
	// set_reason: alpm_pkg_get_reason afterwards, None when no package
	pub reason: Option<c_int>,
}

// what a Break does to local/, the dir of dbpath
pub fn break_local(local: &Path, how: Break) {
	if let Ok(m) = fs::symlink_metadata(local) {
		if m.is_dir() {
			fs::remove_dir_all(local).unwrap();
		} else {
			fs::remove_file(local).unwrap();
		}
	}
	match how {
		Break::Remove => {}
		Break::File => fs::write(local, "not a db\n").unwrap(),
		Break::Dangling => {
			std::os::unix::fs::symlink("missing/dir", local)
				.unwrap()
		}
	}
}

// the ops in order on a handle over root/dbpath. Err is the
// alpm_errno_t of alpm_initialize
pub fn c_local_db_ops(
	root: &[u8],
	dbpath: &[u8],
	ops: &[WriteOp],
) -> Result<Vec<OpResult>, c_int> {
	let h = CHandle::new(root, dbpath)?;
	// SAFETY: h is live, initialize registered the local db
	let db = unsafe { alpm_get_localdb(h.raw()) };
	assert!(!db.is_null());
	let local = Path::new(OsStr::from_bytes(dbpath)).join("local");
	let mut out = Vec::new();
	for op in ops {
		out.push(run(&h, db, &local, op));
	}
	Ok(out)
}

fn plain((rc, errno): (c_int, c_int)) -> OpResult {
	OpResult {
		rc,
		errno,
		reason: None,
	}
}

fn run(h: &CHandle, db: *mut CDb, local: &Path, op: &WriteOp) -> OpResult {
	match op {
		WriteOp::Prepare(pkg) => {
			let p = CPkgBox::new(pkg);
			// SAFETY: db is the live local db, p a live package with
			// name and version set (pkgpath reads them)
			plain(h.call(|| unsafe {
				_alpm_local_db_prepare(db, p.0)
			}))
		}
		WriteOp::Write(pkg, inforeq) => {
			let p = CPkgBox::new(pkg);
			// SAFETY: as above, the C only reads the package
			plain(h.call(|| unsafe {
				_alpm_local_db_write(db, p.0, *inforeq)
			}))
		}
		WriteOp::Remove(pkg) => {
			let p = CPkgBox::new(pkg);
			// SAFETY: as above
			plain(h.call(|| unsafe {
				_alpm_local_db_remove(db, p.0)
			}))
		}
		WriteOp::SetReason(name, reason) => {
			let name = cstr(name);
			// SAFETY: db is live, name a valid C string
			let (p, errno) = h.call(|| unsafe {
				alpm_db_get_pkg(db, name.as_ptr())
			});
			if p.is_null() {
				return OpResult {
					rc: -1,
					errno,
					reason: None,
				};
			}
			// SAFETY: p is a cached package of the local db, its
			// handle is h; the getter lazy-loads into it
			let (rc, errno) = h.call(|| unsafe {
				alpm_pkg_set_reason(p, *reason as c_int)
			});
			// SAFETY: as above
			let reason = unsafe { alpm_pkg_get_reason(p) };
			OpResult {
				rc,
				errno,
				reason: Some(reason),
			}
		}
		WriteOp::SetReasonDetached(pkg, reason) => {
			let p = CPkgBox::new(pkg);
			// the ASSERTs set pm_errno on pkg->handle: make it h
			// SAFETY: p.0 is the live mirror-built package
			unsafe { (*p.0).handle = h.raw() };
			// SAFETY: p is live with h as handle, the asserts return
			// before anything is written
			plain(h.call(|| unsafe {
				alpm_pkg_set_reason(p.0, *reason as c_int)
			}))
		}
		WriteOp::Break(how) => {
			break_local(local, *how);
			plain((0, 0))
		}
	}
}
