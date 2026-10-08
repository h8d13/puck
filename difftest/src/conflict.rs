// C side of lib/libalpm/conflict.c on a real handle over a fixture (root
// with real files, local db): the exported alpm_checkconflicts and the
// internal _alpm_innerconflicts, _alpm_outerconflicts and
// _alpm_db_find_fileconflicts. targets and removed packages are Rust
// Packages pushed through the package mirror with their handle set to
// the fixture handle; local packages come from the C local db reader.
use std::ffi::{c_char, c_int, c_void};
use std::ptr;
use std::sync::MutexGuard;

use alpm_core::callbacks::LogLevel;
use alpm_core::conflict::{
	Conflict, FileConflict, FileConflictType, FileConflicts,
};
use alpm_core::package::Package;

use crate::handle::log_message;
use crate::handle::{
	ALPM, CDb, alpm_db_get_pkgcache, alpm_get_localdb, alpm_initialize,
	alpm_option_set_logcb, alpm_option_set_overwrite_files,
	alpm_option_set_progresscb, alpm_release, alpm_trans_init,
	alpm_trans_release,
};
use crate::package::{
	CDepend, CPkg, CPkgBox, field, list_data, read_dep, read_pkg,
};
use crate::package::{read_strs, with_strs};
use crate::{CList, alpm_list_add, alpm_list_free, cstr};

// alpm_conflict_t
#[repr(C)]
struct CConflictT {
	package1: *mut CPkg,
	package2: *mut CPkg,
	reason: *mut CDepend,
}

// alpm_fileconflict_t
#[repr(C)]
pub(crate) struct CFileConflict {
	pub(crate) target: *mut c_char,
	pub(crate) conflict_type: c_int,
	pub(crate) file: *mut c_char,
	pub(crate) ctarget: *mut c_char,
}

// leading fields of struct _alpm_handle_t, handle.h, up to trans (before
// any ifdef'd member)
#[repr(C)]
struct CHandleHead {
	_db_local: *mut c_void,
	_dbs_sync: *mut CList,
	_logstream: *mut c_void,
	trans: *mut CTrans,
}

// alpm_trans_t, trans.h. the state enum is an int
#[repr(C)]
struct CTrans {
	_flags: c_int,
	_state: c_int,
	_unresolvable: *mut CList,
	_add: *mut CList,
	_remove: *mut CList,
	skip_remove: *mut CList,
}

// ALPM_TRANS_FLAG_NOLOCK: no lock file under the fixture dbpath
const TRANS_FLAG_NOLOCK: c_int = 1 << 17;

unsafe extern "C" {
	fn alpm_checkconflicts(
		handle: *mut c_void,
		pkglist: *mut CList,
	) -> *mut CList;
	fn _alpm_innerconflicts(
		handle: *mut c_void,
		packages: *mut CList,
	) -> *mut CList;
	fn _alpm_outerconflicts(
		db: *mut CDb,
		packages: *mut CList,
	) -> *mut CList;
	fn _alpm_db_find_fileconflicts(
		handle: *mut c_void,
		upgrade: *mut CList,
		rem: *mut CList,
	) -> *mut CList;
	fn alpm_conflict_free(conflict: *mut CConflictT);
	pub(crate) fn alpm_fileconflict_free(conflict: *mut CFileConflict);
}

// one ALPM_PROGRESS_* callback: progress, pkg, percent, howmany, current
pub type ProgressEvent = (c_int, Vec<u8>, c_int, usize, usize);

// what the file conflict check reports: progress, debug lines
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FcRecs {
	pub progress: Vec<ProgressEvent>,
	pub debug: Vec<Vec<u8>>,
}

// alpm_cb_log keeping the ALPM_LOG_DEBUG lines in the FcRecs behind ctx
// (the lazy loads' FUNCTION lines are the C's own)
unsafe extern "C" fn record_log(
	ctx: *mut c_void,
	level: c_int,
	fmt: *const c_char,
	args: *mut c_void,
) {
	if level != LogLevel::Debug as c_int {
		return;
	}
	// SAFETY: fmt and args are the pair this callback got
	let msg = unsafe { log_message(fmt, args) };
	// SAFETY: ctx is find_fileconflicts' FcRecs
	let recs = unsafe { &mut *ctx.cast::<FcRecs>() };
	recs.debug.push(msg);
}

// alpm_cb_progress recording into the FcRecs behind ctx
unsafe extern "C" fn record(
	ctx: *mut c_void,
	progress: c_int,
	pkg: *const c_char,
	percent: c_int,
	howmany: usize,
	current: usize,
) {
	// SAFETY: ctx is the FcRecs find_fileconflicts set, alive for the
	// call
	let recs = unsafe { &mut *ctx.cast::<FcRecs>() };
	let pkg = field(pkg).expect("progress with a NULL package name");
	recs.progress
		.push((progress, pkg, percent, howmany, current));
}

// copies a conflict list out and frees it, conflicts and nodes
pub(crate) fn take_conflicts(list: *mut CList) -> Vec<Conflict> {
	let data = list_data(list);
	let out = data
		.iter()
		.map(|&p| {
			// SAFETY: each entry is a live alpm_conflict_t, its
			// reason points into a package that is still alive
			let c = unsafe { &*p.cast::<CConflictT>() };
			Conflict {
				package1: read_pkg(c.package1),
				package2: read_pkg(c.package2),
				reason: read_dep(c.reason),
			}
		})
		.collect();
	for p in data {
		// SAFETY: allocated by conflict_new, freed once
		unsafe { alpm_conflict_free(p.cast()) };
	}
	// SAFETY: nodes only, the data was freed above
	unsafe { alpm_list_free(list) };
	out
}

fn take_fileconflicts(list: *mut CList) -> Vec<FileConflict> {
	let data = list_data(list);
	let out =
		data.iter()
			.map(|&p| {
				// SAFETY: each entry is a live alpm_fileconflict_t
				let c = unsafe { &*p.cast::<CFileConflict>() };
				FileConflict {
				target: field(c.target).unwrap(),
				conflict_type: match c.conflict_type {
					1 => FileConflictType::Target,
					2 => FileConflictType::Filesystem,
					t => panic!("unknown fileconflict type {t}"),
				},
				file: field(c.file).unwrap(),
				ctarget: field(c.ctarget).unwrap(),
			}
			})
			.collect();
	for p in data {
		// SAFETY: allocated by add_fileconflict, freed once
		unsafe { alpm_fileconflict_free(p.cast()) };
	}
	// SAFETY: nodes only
	unsafe { alpm_list_free(list) };
	out
}

// C packages for one call: the same &Package (by address) becomes the
// same C package, so pointer comparisons in the C match std::ptr::eq on
// the Rust side. handle set to the fixture handle
struct CPkgs {
	h: *mut c_void,
	boxes: Vec<(*const Package, CPkgBox)>,
}

// list nodes over packages owned elsewhere, freed on drop
struct Nodes(*mut CList);

impl Drop for Nodes {
	fn drop(&mut self) {
		// SAFETY: nodes from alpm_list_add, the data is not owned
		unsafe { alpm_list_free(self.0) };
	}
}

impl CPkgs {
	fn new(h: *mut c_void) -> Self {
		CPkgs {
			h,
			boxes: Vec::new(),
		}
	}

	fn get(&mut self, p: &Package) -> *mut CPkg {
		let key: *const Package = p;
		if let Some((_, b)) = self.boxes.iter().find(|(k, _)| *k == key)
		{
			return b.0;
		}
		let b = CPkgBox::new(p);
		// SAFETY: b.0 is live and owned here
		unsafe { (*b.0).handle = self.h };
		let c = b.0;
		self.boxes.push((key, b));
		c
	}

	// C precondition: names set
	fn list(&mut self, pkgs: &[&Package]) -> Nodes {
		assert!(pkgs.iter().all(|p| p.name.is_some()), "NULL name");
		let mut list = ptr::null_mut();
		for p in pkgs {
			let c = self.get(p);
			// SAFETY: list is NULL or built by alpm_list_add, the
			// package outlives the list
			list = unsafe { alpm_list_add(list, c.cast()) };
		}
		Nodes(list)
	}
}

pub struct CConflictHandle {
	h: *mut c_void,
	local: *mut CDb,
	_guard: MutexGuard<'static, ()>,
}

impl Drop for CConflictHandle {
	fn drop(&mut self) {
		// SAFETY: h came from alpm_initialize, no transaction is left
		// open, nothing of it is used afterwards
		unsafe { alpm_release(self.h) };
	}
}

impl CConflictHandle {
	// root and dbpath must exist, the local db under dbpath
	pub fn new(root: &[u8], dbpath: &[u8]) -> Self {
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
		assert!(!h.is_null(), "alpm_initialize: {err}");
		// SAFETY: h is live
		let local = unsafe { alpm_get_localdb(h) };
		CConflictHandle {
			h,
			local,
			_guard: guard,
		}
	}

	// names of the local cache, list order
	pub fn local_names(&self) -> Vec<Vec<u8>> {
		// SAFETY: the db belongs to the live handle
		let list = unsafe { alpm_db_get_pkgcache(self.local) };
		list_data(list)
			.into_iter()
			// SAFETY: cached packages, name is the first string
			.map(|p| read_pkg(p.cast()).name.unwrap())
			.collect()
	}

	// f on a C list over pkgs
	fn with_pkgs<R>(
		&self,
		pkgs: &[&Package],
		f: impl FnOnce(*mut CList) -> R,
	) -> R {
		let mut c = CPkgs::new(self.h);
		let l = c.list(pkgs);
		f(l.0)
	}

	pub fn checkconflicts(&self, pkgs: &[&Package]) -> Vec<Conflict> {
		// SAFETY: h is live, the list holds live packages
		self.with_pkgs(pkgs, |l| {
			take_conflicts(unsafe {
				alpm_checkconflicts(self.h, l)
			})
		})
	}

	pub fn innerconflicts(&self, pkgs: &[&Package]) -> Vec<Conflict> {
		// SAFETY: as above
		self.with_pkgs(pkgs, |l| {
			take_conflicts(unsafe {
				_alpm_innerconflicts(self.h, l)
			})
		})
	}

	// against the handle's local db
	pub fn outerconflicts(&self, pkgs: &[&Package]) -> Vec<Conflict> {
		// SAFETY: the local db belongs to h, the list is live
		self.with_pkgs(pkgs, |l| {
			take_conflicts(unsafe {
				_alpm_outerconflicts(self.local, l)
			})
		})
	}

	// on a fresh NOLOCK transaction (skip_remove read from it) with the
	// overwrite globs and recording progress and log callbacks set.
	// C preconditions: names set, no empty file names, root + path
	// below PATH_MAX where it exists on disk
	pub fn find_fileconflicts(
		&self,
		upgrade: &[&Package],
		rem: &[&Package],
		overwrite: &[Vec<u8>],
	) -> (FileConflicts, FcRecs) {
		let all = upgrade.iter().chain(rem);
		assert!(all.clone().all(|p| p.name.is_some()), "NULL name");
		assert!(
			all.flat_map(|p| &p.files.files)
				.all(|f| !f.name.is_empty()),
			"empty file name"
		);
		let mut recs = FcRecs::default();
		let mut c = CPkgs::new(self.h);
		let (up, rm) = (c.list(upgrade), c.list(rem));
		let ctx: *mut FcRecs = &mut recs;
		// SAFETY: h is live without a transaction; the globs are
		// copied; ctx outlives the call, the callbacks are unset after
		let (list, skip) = unsafe {
			assert_eq!(
				alpm_trans_init(self.h, TRANS_FLAG_NOLOCK),
				0
			);
			with_strs(overwrite, |l| {
				alpm_option_set_overwrite_files(self.h, l)
			});
			alpm_option_set_progresscb(
				self.h,
				Some(record),
				ctx.cast(),
			);
			alpm_option_set_logcb(
				self.h,
				Some(record_log),
				ctx.cast(),
			);
			let list =
				_alpm_db_find_fileconflicts(self.h, up.0, rm.0);
			alpm_option_set_logcb(self.h, None, ptr::null_mut());
			alpm_option_set_progresscb(
				self.h,
				None,
				ptr::null_mut(),
			);
			let trans = (*self.h.cast::<CHandleHead>()).trans;
			let skip = read_strs((*trans).skip_remove);
			assert_eq!(alpm_trans_release(self.h), 0);
			(list, skip)
		};
		let conflicts = take_fileconflicts(list);
		(
			FileConflicts {
				conflicts,
				skip_remove: skip,
			},
			recs,
		)
	}
}
