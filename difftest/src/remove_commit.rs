// C side of the commit half of lib/libalpm/remove.c:
// _alpm_remove_single_package (and through it the static can_remove_file,
// shift_pacsave, unlink_file, should_skip_file, remove_package_files,
// dir_is_mountpoint) on a real handle over a fixture root and local db.
// the target goes into a NOLOCK transaction through alpm_remove_pkg, so
// oldpkg is the dup pacman's own commit gets; skip_remove is set by hand,
// newpkg (upgrade path) built through the package mirror.
//
// rust_remove_single is the same on an alpm_core Handle. both record log
// lines, the remove events, progress and the logfile, then the local
// cache names; log lines the port does not make are dropped on the C side
// (ALPM_LOG_FUNCTION of the db backend, RET_ERR's debug line).
use std::cell::RefCell;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::fs;
use std::path::Path;
use std::ptr;
use std::rc::Rc;

use alpm_core::be_local::INFRQ_ALL;
use alpm_core::callbacks::{Callbacks, Event, LogLevel, Progress};
use alpm_core::handle::Handle;
use alpm_core::package::Package;
use alpm_core::remove::{remove_pkg, remove_single_package};
use alpm_core::trans::{TRANS_FLAG_NOLOCK, trans_init, trans_release};

use crate::handle::{
	ALPM, CHandleHead, CTrans, alpm_db_get_pkg, alpm_db_get_pkgcache,
	alpm_errno, alpm_get_localdb, alpm_initialize, alpm_option_get_root,
	alpm_option_set_eventcb, alpm_option_set_logcb,
	alpm_option_set_logfile, alpm_option_set_noupgrades,
	alpm_option_set_progresscb, alpm_release, alpm_trans_init,
	alpm_trans_release,
};
use crate::hook::strip_stamps;
use crate::package::{
	CPkg, CPkgBox, alpm_pkg_get_desc, alpm_pkg_get_files,
	alpm_pkg_has_scriptlet, field, list_data, read_pkg, with_strs,
};
use crate::trans_prep::alpm_remove_pkg;
use crate::{alpm_list_add, cstr, strdup, vsnprintf};

unsafe extern "C" {
	fn _alpm_remove_single_package(
		handle: *mut c_void,
		oldpkg: *mut CPkg,
		newpkg: *mut CPkg,
		targ_count: usize,
		pkg_count: usize,
	) -> c_int;
}

// one callback in call order
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RmRec {
	Log(c_int, Vec<u8>),
	// PACKAGE_OPERATION_START/DONE: event type, operation, old, new
	Op(c_int, c_int, Option<Vec<u8>>, Option<Vec<u8>>),
	// PACSAVE_CREATED: oldpkg name, file
	Pacsave(Vec<u8>, Vec<u8>),
	Scriptlet(Vec<u8>),
	// progress, pkg, percent, howmany, current
	Progress(c_int, Vec<u8>, c_int, usize, usize),
}

// a case: the local package removed, with the handle and trans state
#[derive(Clone, Debug, Default)]
pub struct RmCase {
	pub flags: c_int,
	pub noupgrade: Vec<Vec<u8>>,
	pub skip_remove: Vec<Vec<u8>>,
	pub target: Vec<u8>,
	pub newpkg: Option<Package>,
	pub targ_count: usize,
	pub pkg_count: usize,
}

// what one call gave
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RmOutcome {
	pub rc: c_int,
	pub errno: c_int,
	pub recs: Vec<RmRec>,
	// logfile text without timestamps
	pub logfile: Vec<u8>,
	// the local cache names afterwards, list order
	pub cache: Vec<Vec<u8>>,
}

const LOG_DEBUG: c_int = 1 << 2;
const LOG_FUNCTION: c_int = 1 << 3;
const EVENT_OP_START: c_int = 11;
const EVENT_OP_DONE: c_int = 12;
const EVENT_SCRIPTLET_INFO: c_int = 17;
const EVENT_PACSAVE_CREATED: c_int = 33;

fn bytes(p: *const c_char) -> Option<Vec<u8>> {
	// SAFETY: NULL or a nul-terminated string alive for the callback
	(!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

fn pkg_name(p: *const CPkg) -> Option<Vec<u8>> {
	(!p.is_null()).then(|| read_pkg(p).name.expect("package without name"))
}

// the recorder behind the C callbacks' ctx; mute during the setup
#[derive(Default)]
struct CRec {
	recs: Vec<RmRec>,
	mute: bool,
}

unsafe extern "C" fn log_cb(
	ctx: *mut c_void,
	level: c_int,
	fmt: *const c_char,
	args: *mut c_void,
) {
	let mut buf = vec![0 as c_char; 16384];
	// SAFETY: fmt and args are _alpm_log's printf pair, used once; buf
	// is writable for its length. ctx is the boxed CRec of the call
	let (n, rec) = unsafe {
		let n = vsnprintf(buf.as_mut_ptr(), buf.len(), fmt, args);
		(n, &mut *ctx.cast::<CRec>())
	};
	assert!(n >= 0 && (n as usize) < buf.len(), "log message cut");
	let msg = bytes(buf.as_ptr()).unwrap();
	let errline =
		level == LOG_DEBUG && msg.starts_with(b"returning error ");
	if rec.mute || level == LOG_FUNCTION || errline {
		return;
	}
	rec.recs.push(RmRec::Log(level, msg));
}

// alpm_event_package_operation_t, alpm_event_pacsave_created_t,
// alpm_event_scriptlet_info_t
#[repr(C)]
struct CEvOp {
	kind: c_int,
	operation: c_int,
	oldpkg: *const CPkg,
	newpkg: *const CPkg,
}

#[repr(C)]
struct CEvPacsave {
	kind: c_int,
	oldpkg: *const CPkg,
	file: *const c_char,
}

#[repr(C)]
struct CEvLine {
	kind: c_int,
	line: *const c_char,
}

unsafe extern "C" fn event_cb(ctx: *mut c_void, event: *mut c_void) {
	// SAFETY: every event starts with its type; ctx is the CRec
	let (rec, kind) =
		unsafe { (&mut *ctx.cast::<CRec>(), *event.cast::<c_int>()) };
	if rec.mute {
		return;
	}
	// SAFETY: the casts follow kind, the pointers live for the call
	let r = unsafe {
		match kind {
			EVENT_OP_START | EVENT_OP_DONE => {
				let e = &*event.cast::<CEvOp>();
				let (o, n) = (
					pkg_name(e.oldpkg),
					pkg_name(e.newpkg),
				);
				RmRec::Op(kind, e.operation, o, n)
			}
			EVENT_PACSAVE_CREATED => {
				let e = &*event.cast::<CEvPacsave>();
				let old = pkg_name(e.oldpkg).unwrap();
				RmRec::Pacsave(old, bytes(e.file).unwrap())
			}
			EVENT_SCRIPTLET_INFO => {
				let e = &*event.cast::<CEvLine>();
				RmRec::Scriptlet(bytes(e.line).unwrap())
			}
			k => panic!("unexpected event {k}"),
		}
	};
	rec.recs.push(r);
}

unsafe extern "C" fn progress_cb(
	ctx: *mut c_void,
	progress: c_int,
	pkg: *const c_char,
	percent: c_int,
	howmany: usize,
	current: usize,
) {
	// SAFETY: ctx is the CRec of the call
	let rec = unsafe { &mut *ctx.cast::<CRec>() };
	if rec.mute {
		return;
	}
	let pkg = field(pkg).expect("progress with a NULL package name");
	rec.recs.push(RmRec::Progress(
		progress, pkg, percent, howmany, current,
	));
}

// the logfile text since the last read, emptied
fn take_log(logfile: &Path) -> Vec<u8> {
	let log = fs::read(logfile).unwrap_or_default();
	if !log.is_empty() {
		fs::write(logfile, b"").unwrap();
	}
	strip_stamps(&log)
}

// _alpm_remove_single_package on handle root/dbpath for case. the
// local db must hold the target
pub fn c_remove_single(
	root: &[u8],
	dbpath: &[u8],
	logfile: &Path,
	case: &RmCase,
) -> RmOutcome {
	let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
	let (root, dbpath) = (cstr(root), cstr(dbpath));
	let mut err = 0;
	// SAFETY: valid C strings, err is writable
	let h = unsafe {
		alpm_initialize(root.as_ptr(), dbpath.as_ptr(), &mut err)
	};
	assert!(!h.is_null(), "alpm_initialize: {err}");
	let mut rec = Box::new(CRec {
		recs: Vec::new(),
		mute: true,
	});
	let ctx = (&raw mut *rec).cast::<c_void>();
	let path = cstr(logfile.as_os_str().as_encoded_bytes());
	let newpkg = case.newpkg.as_ref().map(CPkgBox::new);
	let target = cstr(&case.target);
	// SAFETY: h is live until the release at the end; ctx outlives it.
	// the set calls copy their strings. the local cache entries are
	// live packages of h; trans->remove holds the dup alpm_remove_pkg
	// made, skip_remove gets strdup'd strings the release frees
	let (rc, errno, cache) = unsafe {
		alpm_option_set_logcb(h, Some(log_cb), ctx);
		alpm_option_set_eventcb(h, Some(event_cb), ctx);
		alpm_option_set_progresscb(h, Some(progress_cb), ctx);
		alpm_option_set_logfile(h, path.as_ptr());
		with_strs(&case.noupgrade, |l| {
			alpm_option_set_noupgrades(h, l)
		});
		let db = alpm_get_localdb(h);
		// every section loaded up front, like the Rust side
		for p in list_data(alpm_db_get_pkgcache(db)) {
			alpm_pkg_get_desc(p.cast());
			alpm_pkg_get_files(p.cast());
			alpm_pkg_has_scriptlet(p.cast());
		}
		let flags = case.flags | TRANS_FLAG_NOLOCK;
		assert_eq!(alpm_trans_init(h, flags), 0);
		let pkg = alpm_db_get_pkg(db, target.as_ptr());
		assert!(!pkg.is_null(), "target not in the local db");
		assert_eq!(alpm_remove_pkg(h, pkg), 0);
		let trans: *mut CTrans = (*h.cast::<CHandleHead>()).trans;
		for s in &case.skip_remove {
			let s = strdup(cstr(s).as_ptr());
			(*trans).skip_remove =
				alpm_list_add((*trans).skip_remove, s.cast());
		}
		let oldpkg = (*(*trans).remove).data.cast::<CPkg>();
		let newp = match &newpkg {
			Some(b) => {
				(*b.0).handle = h;
				b.0
			}
			None => ptr::null_mut(),
		};
		let _ = take_log(logfile);
		rec.mute = false;
		alpm_option_get_root(h);
		let rc = _alpm_remove_single_package(
			h,
			oldpkg,
			newp,
			case.targ_count,
			case.pkg_count,
		);
		let errno = alpm_errno(h);
		rec.mute = true;
		let cache = list_data(alpm_db_get_pkgcache(db))
			.into_iter()
			.map(|p| pkg_name(p.cast()).unwrap())
			.collect();
		assert_eq!(alpm_trans_release(h), 0);
		alpm_release(h);
		(rc, errno, cache)
	};
	RmOutcome {
		rc,
		errno,
		recs: std::mem::take(&mut rec.recs),
		logfile: take_log(logfile),
		cache,
	}
}

// the Rust side's callbacks, recording like the C ones
struct RustRec(Rc<RefCell<Vec<RmRec>>>);

impl Callbacks for RustRec {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		let r = RmRec::Log(level as c_int, msg.to_vec());
		self.0.borrow_mut().push(r);
	}

	fn event(&mut self, event: &Event<'_>) {
		let name = |p: Option<&Package>| {
			p.map(|p| p.name.clone().unwrap())
		};
		let r = match event {
			Event::PackageOperationStart(op)
			| Event::PackageOperationDone(op) => RmRec::Op(
				event.kind(),
				op.operation as c_int,
				name(op.oldpkg),
				name(op.newpkg),
			),
			Event::PacsaveCreated { oldpkg, file } => {
				RmRec::Pacsave(
					oldpkg.name.clone().unwrap(),
					file.to_vec(),
				)
			}
			Event::ScriptletInfo { line } => {
				RmRec::Scriptlet(line.to_vec())
			}
			e => panic!("unexpected event {}", e.kind()),
		};
		self.0.borrow_mut().push(r);
	}

	fn progress(
		&mut self,
		progress: Progress,
		pkg: &[u8],
		percent: c_int,
		howmany: usize,
		current: usize,
	) {
		let r = RmRec::Progress(
			progress as c_int,
			pkg.to_vec(),
			percent,
			howmany,
			current,
		);
		self.0.borrow_mut().push(r);
	}
}

// remove_single_package on an alpm_core Handle, recorded like
// c_remove_single. errno is the pm_errno the C leaves: the Err on the
// upgrade path
pub fn rust_remove_single(
	root: &[u8],
	dbpath: &[u8],
	logfile: &Path,
	case: &RmCase,
) -> RmOutcome {
	let mut h = Handle::initialize(root, dbpath).unwrap();
	let recs = Rc::new(RefCell::new(Vec::new()));
	h.set_callbacks(Box::new(RustRec(recs.clone())));
	h.set_logfile(logfile.as_os_str().as_encoded_bytes());
	h.set_noupgrades(&case.noupgrade);
	let dbext = h.dbext().to_vec();
	let db = h.localdb_mut().unwrap();
	db.load_all(&dbext, INFRQ_ALL).unwrap();
	let pkg = db.get_pkg(&dbext, &case.target).unwrap().clone();
	trans_init(&mut h, case.flags | TRANS_FLAG_NOLOCK).unwrap();
	remove_pkg(&mut h, &pkg).unwrap();
	let trans = h.trans_mut().unwrap();
	trans.skip_remove = case.skip_remove.clone();
	let oldpkg = trans.remove[0].clone();
	recs.borrow_mut().clear();
	let _ = take_log(logfile);
	let r = remove_single_package(
		&mut h,
		&oldpkg,
		case.newpkg.as_ref(),
		case.targ_count,
		case.pkg_count,
	);
	let errno = match (&case.newpkg, &r) {
		(Some(_), Err(e)) => *e as c_int,
		_ => 0,
	};
	let db = h.localdb().unwrap();
	let cache = db
		.loaded_pkgcache()
		.map(|c| c.iter().map(|p| p.name.clone().unwrap()).collect())
		.unwrap_or_default();
	trans_release(&mut h).unwrap();
	let recs = std::mem::take(&mut *recs.borrow_mut());
	RmOutcome {
		rc: 0,
		errno,
		recs,
		logfile: take_log(logfile),
		cache,
	}
}
