// C side of lib/libalpm/diskspace.c: the internal _alpm_check_diskspace
// and _alpm_check_downloadspace from the static archive on a real handle,
// and glibc getmntent(3) for the mount table parser.
//
// the C reads the running system's mount table (MOUNTED) and statvfs, so
// both sides see the same mounts; callers keep fixtures on /tmp. the
// transaction is set by hand: trans->add holds mirror packages,
// trans->remove the handle's own local cache entries.
use std::ffi::{c_char, c_int, c_void};
use std::ptr;
use std::sync::Mutex;

use alpm_core::diskspace::MountEntry;
use alpm_core::package::Package;

use crate::handle::log_message;
use crate::handle::{
	ALPM, CHandleHead, CTrans, alpm_db_get_pkg, alpm_db_get_pkgcache,
	alpm_errno, alpm_get_localdb, alpm_initialize, alpm_option_get_root,
	alpm_option_set_logcb, alpm_option_set_noextracts,
	alpm_option_set_progresscb, alpm_release,
};
use crate::package::{
	CPkg, CPkgBox, alpm_pkg_get_files, list_data, text, with_strs,
};
use crate::{CFile, alpm_list_add, alpm_list_free, cstr};

// struct mntent, mntent.h
#[repr(C)]
struct CMntent {
	mnt_fsname: *mut c_char,
	mnt_dir: *mut c_char,
	mnt_type: *mut c_char,
	mnt_opts: *mut c_char,
	mnt_freq: c_int,
	mnt_passno: c_int,
}

unsafe extern "C" {
	fn _alpm_check_diskspace(handle: *mut c_void) -> c_int;
	fn _alpm_check_downloadspace(
		handle: *mut c_void,
		cachedir: *const c_char,
		num_files: usize,
		file_sizes: *const i64,
	) -> c_int;

	fn setmntent(file: *const c_char, mode: *const c_char) -> *mut CFile;
	fn getmntent(stream: *mut CFile) -> *mut CMntent;
	fn endmntent(stream: *mut CFile) -> c_int;
}

// getmntent returns a static buffer: one reader at a time, the C checks
// (which call it) included
static MNTENT: Mutex<()> = Mutex::new(());

// a logcb or progresscb call, in call order
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CbEvent {
	// alpm_loglevel_t, the formatted message
	Log(c_int, Vec<u8>),
	// progress kind, pkg, percent, howmany, current
	Progress(c_int, Vec<u8>, c_int, usize, usize),
}

unsafe extern "C" fn log_cb(
	ctx: *mut c_void,
	level: c_int,
	fmt: *const c_char,
	args: *mut c_void,
) {
	// SAFETY: fmt and args are the pair this callback got
	let msg = unsafe { log_message(fmt, args) };
	// SAFETY: ctx is the events Vec of the CSpace running this call
	let events = unsafe { &mut *ctx.cast::<Vec<CbEvent>>() };
	events.push(CbEvent::Log(level, msg));
}

unsafe extern "C" fn progress_cb(
	ctx: *mut c_void,
	kind: c_int,
	pkg: *const c_char,
	percent: c_int,
	howmany: usize,
	current: usize,
) {
	// SAFETY: as in log_cb
	let events = unsafe { &mut *ctx.cast::<Vec<CbEvent>>() };
	events.push(CbEvent::Progress(
		kind,
		text(pkg),
		percent,
		howmany,
		current,
	));
}

// return value, pm_errno when it is -1, callback events
pub type CSpaceResult = (c_int, Option<c_int>, Vec<CbEvent>);

// a C handle on root/dbpath with logcb and progresscb recording
pub struct CSpace {
	h: *mut c_void,
	// the callbacks' ctx: boxed so the Vec stays put when CSpace moves
	#[allow(clippy::box_collection)]
	events: Box<Vec<CbEvent>>,
}

impl CSpace {
	// root and dbpath must exist
	pub fn new(root: &[u8], dbpath: &[u8]) -> Self {
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
		let mut events = Box::new(Vec::new());
		let ctx = (&raw mut *events).cast::<c_void>();
		// SAFETY: h is live, ctx outlives it (dropped after release)
		unsafe {
			alpm_option_set_logcb(h, Some(log_cb), ctx);
			alpm_option_set_progresscb(h, Some(progress_cb), ctx);
		}
		CSpace { h, events }
	}

	// loads the local package cache and every file list, dropping what
	// that logs: the checks then only log diskspace.c's own lines
	pub fn load_local(&mut self) {
		// SAFETY: h is live, the cache list belongs to its local db
		let list = unsafe {
			alpm_db_get_pkgcache(alpm_get_localdb(self.h))
		};
		for p in list_data(list) {
			// SAFETY: p is a live local cache entry
			unsafe { alpm_pkg_get_files(p.cast()) };
		}
		self.events.clear();
	}

	pub fn set_noextracts(&mut self, list: &[Vec<u8>]) {
		// SAFETY: h is live, the set call dups the strings
		unsafe {
			with_strs(list, |l| {
				alpm_option_set_noextracts(self.h, l)
			})
		};
	}

	// the local cache entry named name, NULL when missing
	fn local_pkg(&self, name: &[u8]) -> *mut CPkg {
		let n = cstr(name);
		// SAFETY: h is live, the local db belongs to it
		unsafe { alpm_db_get_pkg(alpm_get_localdb(self.h), n.as_ptr()) }
	}

	// pm_errno after ret, events since the last call. RET_ERR's debug
	// trace (function, file and line of the C) is dropped, the port has
	// no such line
	fn finish(&mut self, ret: c_int) -> CSpaceResult {
		// SAFETY: h is live
		let errno = (ret != 0).then(|| unsafe { alpm_errno(self.h) });
		let mut events = std::mem::take(&mut *self.events);
		events.retain(|e| {
			!matches!(e, CbEvent::Log(4, m)
				if m.starts_with(b"returning error "))
		});
		(ret, errno, events)
	}

	fn reset_errno(&self) {
		// SAFETY: h is live, CHECK_HANDLE only writes pm_errno
		unsafe { alpm_option_get_root(self.h) };
	}

	// _alpm_check_diskspace with trans->add = mirrors of add (names set)
	// and trans->remove = the local packages named in remove (present)
	pub fn check(
		&mut self,
		add: &[Package],
		remove: &[&[u8]],
	) -> CSpaceResult {
		let boxes: Vec<CPkgBox> =
			add.iter().map(CPkgBox::new).collect();
		let add = boxes.iter().fold(ptr::null_mut(), |l, b| {
			// SAFETY: l is NULL or built here, b outlives the list
			unsafe { alpm_list_add(l, b.0.cast()) }
		});
		let remove = remove.iter().fold(ptr::null_mut(), |l, n| {
			let p = self.local_pkg(n);
			assert!(!p.is_null(), "no local {n:?}");
			// SAFETY: as above, p is owned by the local cache
			unsafe { alpm_list_add(l, p.cast()) }
		});
		let mut trans = CTrans {
			flags: 0,
			state: 1,
			unresolvable: ptr::null_mut(),
			add,
			remove,
			skip_remove: ptr::null_mut(),
		};
		self.reset_errno();
		let _guard = MNTENT.lock().unwrap_or_else(|e| e.into_inner());
		let head = self.h.cast::<CHandleHead>();
		// SAFETY: h is a live handle, trans lives across the call and is
		// unset before anything else can see it
		let ret = unsafe {
			(*head).trans = &raw mut trans;
			let ret = _alpm_check_diskspace(self.h);
			(*head).trans = ptr::null_mut();
			ret
		};
		// SAFETY: nodes built above, data owned elsewhere
		unsafe {
			alpm_list_free(trans.add);
			alpm_list_free(trans.remove);
		}
		drop(boxes);
		self.finish(ret)
	}

	// _alpm_check_downloadspace
	pub fn check_download(
		&mut self,
		cachedir: &[u8],
		sizes: &[i64],
	) -> CSpaceResult {
		let dir = cstr(cachedir);
		self.reset_errno();
		let _guard = MNTENT.lock().unwrap_or_else(|e| e.into_inner());
		// SAFETY: h is live, sizes has sizes.len() entries
		let ret = unsafe {
			_alpm_check_downloadspace(
				self.h,
				dir.as_ptr(),
				sizes.len(),
				sizes.as_ptr(),
			)
		};
		self.finish(ret)
	}
}

impl Drop for CSpace {
	fn drop(&mut self) {
		let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		// SAFETY: h came from alpm_initialize, trans is NULL again,
		// nothing of it is used afterwards
		unsafe { alpm_release(self.h) };
	}
}

// every entry glibc getmntent(3) returns for the file at path
pub fn c_getmntent(path: &[u8]) -> Vec<MountEntry> {
	let (path, mode) = (cstr(path), cstr(b"r"));
	let _guard = MNTENT.lock().unwrap_or_else(|e| e.into_inner());
	// SAFETY: valid C strings
	let f = unsafe { setmntent(path.as_ptr(), mode.as_ptr()) };
	assert!(!f.is_null(), "setmntent {path:?}");
	let mut out = Vec::new();
	loop {
		// SAFETY: f is open, the entry is valid until the next call
		let e = unsafe { getmntent(f) };
		if e.is_null() {
			break;
		}
		// SAFETY: e points to getmntent's static entry
		let e = unsafe { &*e };
		out.push(MountEntry {
			fsname: text(e.mnt_fsname),
			dir: text(e.mnt_dir),
			kind: text(e.mnt_type),
			opts: text(e.mnt_opts),
		});
	}
	// SAFETY: f came from setmntent, closed once
	unsafe { endmntent(f) };
	out
}
