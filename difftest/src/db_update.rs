// C side of be_sync.c's alpm_db_update, and of -Sy/-Fy (sync_syncdbs
// through pacman_sync/pacman_files, frontend objects), plus the Rust side
// set up the same way.
//
// an UpdSetup describes a handle: dbext, gpgdir, default siglevel, parallel
// downloads, the import key answer and the sync dbs (name, siglevel,
// servers, usage). CUpdate builds it on a C handle with recording
// log/event/question/download callbacks, RUpdate on an alpm_core Handle
// with an UpdRecorder. kept logs: all but function lines and the debug
// lines carrying __FILE__/__LINE__.
use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr;
use std::rc::Rc;
use std::sync::MutexGuard;

use alpm_core::callbacks::{
	Callbacks, DownloadEvent, Event, LogLevel, Question,
};
use alpm_core::handle::Handle;
use pacman_cli::conf::Config;

use crate::callback::{cb_download, cb_event, cb_log};
use crate::cli_util::init;
use crate::files_op::pacman_files;
use crate::fixtures::TempRoot;
use crate::handle::*;
use crate::package::{CPkg, list_data, read_pkg};
use crate::signing::{
	GPGME_PROTOCOL_OPENPGP, gpgme_check_version, gpgme_set_engine_info,
};
use crate::sync_ro::{
	CRun, FrontHandle, gen_pkgs, pacman_sync, run_op, sync_tar,
};
use crate::trans_commit::{sig_unreadable, signing_debug};
use crate::{CList, Rng, alpm_list_add, alpm_list_free, cstr, vsnprintf};

unsafe extern "C" {
	fn alpm_db_update(
		handle: *mut c_void,
		dbs: *mut CList,
		force: c_int,
	) -> c_int;
	// src/pacman/callback.c, what setup_libalpm installs
}

const QUESTION_IMPORT_KEY: c_int = 1 << 6;
const EVENT_DATABASE_MISSING: c_int = 27;

// debug lines left out: RET_ERR/GOTO_ERR's carry the C's file and
// line, signing.c's own (its _alpm_access of the .sig included) are not
// ported yet (PORTING.md follow-up)
fn kept(level: LogLevel, msg: &[u8]) -> bool {
	match level {
		LogLevel::Error | LogLevel::Warning => true,
		LogLevel::Debug => {
			!msg.starts_with(b"returning error ")
				&& !msg.starts_with(b"got error ")
				&& !signing_debug(msg) && !sig_unreadable(msg)
		}
		LogLevel::Function => false,
	}
}

// what the callbacks saw, in order
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdRecord {
	pub logs: Vec<(LogLevel, Vec<u8>)>,
	// alpm_event_type_t, the dbname of DATABASE_MISSING
	pub events: Vec<(c_int, Option<Vec<u8>>)>,
	// import key questions: uid, fingerprint
	pub questions: Vec<(Option<Vec<u8>>, Vec<u8>)>,
	pub downloads: Vec<(Vec<u8>, DownloadEvent)>,
}

// the Rust side's callbacks, the record shared with the test
#[derive(Clone, Default)]
pub struct UpdRecorder {
	pub rec: Rc<RefCell<UpdRecord>>,
	pub answer: bool,
}

impl Callbacks for UpdRecorder {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		if kept(level, msg) {
			self.rec.borrow_mut().logs.push((level, msg.to_vec()));
		}
	}

	fn event(&mut self, event: &Event<'_>) {
		let name = match event {
			Event::DatabaseMissing { dbname } => {
				Some(dbname.to_vec())
			}
			_ => None,
		};
		self.rec.borrow_mut().events.push((event.kind(), name));
	}

	fn question(&mut self, q: &mut Question<'_>) {
		let Question::ImportKey {
			import,
			uid,
			fingerprint,
		} = q
		else {
			panic!("db update asks import_key only: {q:?}");
		};
		let item = (uid.map(<[u8]>::to_vec), fingerprint.to_vec());
		self.rec.borrow_mut().questions.push(item);
		*import = c_int::from(self.answer);
	}

	fn download(&mut self, filename: &[u8], event: DownloadEvent) {
		let item = (filename.to_vec(), event);
		self.rec.borrow_mut().downloads.push(item);
	}
}

// one sync db of an UpdSetup
#[derive(Clone, Debug)]
pub struct DbSpec {
	pub name: String,
	pub siglevel: c_int,
	pub servers: Vec<Vec<u8>>,
	pub usage: c_int,
}

#[derive(Clone, Debug)]
pub struct UpdSetup {
	pub dbext: Vec<u8>,
	// handle->gpgdir with its '/', None leaves it unset
	pub gpgdir: Option<Vec<u8>>,
	pub default_siglevel: c_int,
	pub parallel: u32,
	pub answer: bool,
	pub dbs: Vec<DbSpec>,
}

pub type NameVersion = (Vec<u8>, Vec<u8>);

// a db after a call: alpm_db_get_valid and its pm_errno, then the
// package cache (name, version per package in list order) or the
// pm_errno alpm_db_get_pkgcache left
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DbState {
	pub valid: (c_int, c_int),
	pub cache: Result<Vec<NameVersion>, c_int>,
}

// a tar sync db of 1..5 generated packages from seed, and the
// (name, version) pairs in it; files adds the file lists of a .files db
pub fn sync_db(seed: u64, files: bool) -> (Vec<u8>, Vec<(String, String)>) {
	let pkgs = gen_pkgs(&mut Rng::new(seed), 1, 5);
	let names = pkgs
		.iter()
		.map(|p| (p.name.clone(), p.version.clone()))
		.collect();
	(sync_tar(&pkgs, files), names)
}

fn bytes(p: *const c_char) -> Vec<u8> {
	if p.is_null() {
		return Vec::new();
	}
	// SAFETY: libalpm passes nul-terminated strings
	unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
}

struct Ctx {
	rec: UpdRecord,
	answer: bool,
}

#[repr(C)]
struct CCompleted {
	total: i64,
	result: c_int,
}

#[repr(C)]
struct CEventMissing {
	kind: c_int,
	dbname: *const c_char,
}

#[repr(C)]
struct CQuestionImportKey {
	kind: c_int,
	import: c_int,
	uid: *const c_char,
	fingerprint: *const c_char,
}

unsafe extern "C" fn dl_cb(
	ctx: *mut c_void,
	filename: *const c_char,
	event: c_int,
	data: *mut c_void,
) {
	// SAFETY: ctx is the CUpdate's boxed Ctx, data the
	// alpm_download_event_*_t of that event type
	let (ctx, ev) = unsafe {
		let ev = match event {
			0 => DownloadEvent::Init {
				optional: *data.cast::<c_int>() != 0,
			},
			1 => {
				let p = data.cast::<[i64; 2]>();
				DownloadEvent::Progress {
					downloaded: (*p)[0],
					total: (*p)[1],
				}
			}
			2 => DownloadEvent::Retry {
				resume: *data.cast::<c_int>() != 0,
			},
			_ => {
				let c = &*data.cast::<CCompleted>();
				DownloadEvent::Completed {
					total: c.total,
					result: c.result,
				}
			}
		};
		(&mut *ctx.cast::<Ctx>(), ev)
	};
	ctx.rec.downloads.push((bytes(filename), ev));
}

unsafe extern "C" fn log_cb(
	ctx: *mut c_void,
	level: c_int,
	fmt: *const c_char,
	args: *mut c_void,
) {
	let level = match level {
		1 => LogLevel::Error,
		2 => LogLevel::Warning,
		4 => LogLevel::Debug,
		_ => return,
	};
	let mut buf = vec![0 as c_char; 8192];
	// SAFETY: fmt and args are the printf pair _alpm_log got, used once;
	// buf is writable for its length. ctx is the boxed Ctx
	let ctx = unsafe {
		vsnprintf(buf.as_mut_ptr(), buf.len(), fmt, args);
		&mut *ctx.cast::<Ctx>()
	};
	let msg = bytes(buf.as_ptr());
	if kept(level, &msg) {
		ctx.rec.logs.push((level, msg));
	}
}

unsafe extern "C" fn event_cb(ctx: *mut c_void, event: *mut c_void) {
	// SAFETY: event starts with its type, DATABASE_MISSING carries
	// alpm_event_database_missing_t. ctx is the boxed Ctx
	let (ctx, e) = unsafe {
		(&mut *ctx.cast::<Ctx>(), &*event.cast::<CEventMissing>())
	};
	let name = (e.kind == EVENT_DATABASE_MISSING).then(|| bytes(e.dbname));
	ctx.rec.events.push((e.kind, name));
}

unsafe extern "C" fn question_cb(ctx: *mut c_void, q: *mut c_void) {
	// SAFETY: q starts with its type, import key questions are
	// alpm_question_import_key_t. ctx is the boxed Ctx
	let (ctx, q) = unsafe {
		(
			&mut *ctx.cast::<Ctx>(),
			&mut *q.cast::<CQuestionImportKey>(),
		)
	};
	assert_eq!(q.kind, QUESTION_IMPORT_KEY, "db update asks import_key");
	let uid = (!q.uid.is_null()).then(|| bytes(q.uid));
	ctx.rec.questions.push((uid, bytes(q.fingerprint)));
	q.import = c_int::from(ctx.answer);
}

// a C handle on a fixture built from an UpdSetup, holding the ALPM lock
pub struct CUpdate {
	h: *mut c_void,
	ctx: Box<Ctx>,
	dbs: Vec<*mut CDb>,
	gpgdir: Option<CString>,
	_guard: MutexGuard<'static, ()>,
}

impl Drop for CUpdate {
	fn drop(&mut self) {
		// SAFETY: h came from alpm_initialize, nothing uses it after; the
		// callbacks' ctx outlives it
		unsafe { alpm_release(self.h) };
	}
}

impl CUpdate {
	pub fn new(fx: &TempRoot, s: &UpdSetup) -> CUpdate {
		let guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		let (root, dbpath) = (cstr(&fx.root()), cstr(&fx.dbpath()));
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
		let mut ctx = Box::new(Ctx {
			rec: UpdRecord::default(),
			answer: s.answer,
		});
		let c: *mut Ctx = &mut *ctx;
		let ext = cstr(&s.dbext);
		// SAFETY: h is live; ctx is boxed and dropped after the handle;
		// the C copies the strings
		unsafe {
			alpm_option_set_dlcb(h, Some(dl_cb), c.cast());
			alpm_option_set_logcb(h, Some(log_cb), c.cast());
			alpm_option_set_eventcb(h, Some(event_cb), c.cast());
			alpm_option_set_questioncb(
				h,
				Some(question_cb),
				c.cast(),
			);
			alpm_option_set_dbext(h, ext.as_ptr());
			alpm_option_set_parallel_downloads(h, s.parallel);
			let level = s.default_siglevel;
			assert_eq!(
				alpm_option_set_default_siglevel(h, level),
				0
			);
		}
		let gpgdir = s.gpgdir.as_deref().map(cstr);
		let mut u = CUpdate {
			h,
			ctx,
			dbs: Vec::new(),
			gpgdir,
			_guard: guard,
		};
		if let Some(g) = &u.gpgdir {
			// SAFETY: h is live, the C copies g
			unsafe {
				gpgme_check_version(ptr::null());
				alpm_option_set_gpgdir(u.h, g.as_ptr());
			}
		}
		u.engine();
		for d in &s.dbs {
			u.register(d);
		}
		u
	}

	// gpgme's engine pointed at the gpgdir: init_gpgme sets it once per
	// process, from whichever handle came first
	fn engine(&self) {
		let Some(g) = &self.gpgdir else {
			return;
		};
		// SAFETY: gpgme copies the string
		unsafe {
			gpgme_set_engine_info(
				GPGME_PROTOCOL_OPENPGP,
				ptr::null(),
				g.as_ptr(),
			);
		}
	}

	fn register(&mut self, d: &DbSpec) {
		let name = cstr(d.name.as_bytes());
		// SAFETY: h is live, the C copies the strings
		unsafe {
			let db = alpm_register_syncdb(
				self.h,
				name.as_ptr(),
				d.siglevel,
			);
			assert!(!db.is_null(), "register {}", d.name);
			for s in &d.servers {
				let s = cstr(s);
				assert_eq!(
					alpm_db_add_server(db, s.as_ptr()),
					0
				);
			}
			alpm_db_set_usage(db, d.usage);
			self.dbs.push(db);
		}
		// registration validated: its events are not the update's
		self.ctx.rec = UpdRecord::default();
	}

	// pm_errno to ALPM_ERR_OK through a getter's CHECK_HANDLE
	fn reset_errno(&self) {
		// SAFETY: h is live
		unsafe { alpm_option_get_root(self.h) };
	}

	// alpm_db_update on the dbs at those positions: return value,
	// pm_errno, what the callbacks saw
	pub fn update(
		&mut self,
		dbs: &[usize],
		force: bool,
	) -> (c_int, c_int, UpdRecord) {
		let list = dbs.iter().fold(ptr::null_mut(), |l, &i| {
			// SAFETY: l is NULL or built here; the dbs outlive it
			unsafe { alpm_list_add(l, self.dbs[i].cast()) }
		});
		self.engine();
		self.reset_errno();
		// SAFETY: h live, a list of its dbs (NULL when empty)
		let ret = unsafe { alpm_db_update(self.h, list, force.into()) };
		// SAFETY: h is live; nodes from alpm_list_add, data the handle's
		let errno = unsafe {
			let e = alpm_errno(self.h);
			alpm_list_free(list);
			e
		};
		(ret, errno, std::mem::take(&mut self.ctx.rec))
	}

	// every db's state, in registration order
	pub fn states(&mut self) -> Vec<DbState> {
		let dbs = self.dbs.clone();
		let out = dbs.into_iter().map(|db| self.state(db)).collect();
		self.ctx.rec = UpdRecord::default();
		out
	}

	fn state(&self, db: *mut CDb) -> DbState {
		self.engine();
		self.reset_errno();
		// SAFETY: db belongs to the live handle; the cache packages are
		// copied out while it lives
		unsafe {
			let rc = alpm_db_get_valid(db);
			let valid = (rc, alpm_errno(self.h));
			self.reset_errno();
			let list = alpm_db_get_pkgcache(db);
			let cache = match alpm_errno(self.h) {
				0 => Ok(list_data(list)
					.into_iter()
					.map(|p| name_version(p.cast()))
					.collect()),
				e => Err(e),
			};
			DbState { valid, cache }
		}
	}
}

fn name_version(p: *const CPkg) -> (Vec<u8>, Vec<u8>) {
	let pkg = read_pkg(p);
	let v = pkg.version.clone().unwrap_or_default();
	(pkg.name_bytes().to_vec(), v)
}

// the Rust side: a Handle on its own fixture, built like CUpdate
pub struct RUpdate {
	pub h: Handle,
	rec: Rc<RefCell<UpdRecord>>,
}

impl RUpdate {
	pub fn new(fx: &TempRoot, s: &UpdSetup) -> RUpdate {
		let mut h =
			Handle::initialize(&fx.root(), &fx.dbpath()).unwrap();
		let cb = UpdRecorder {
			rec: Rc::default(),
			answer: s.answer,
		};
		let rec = cb.rec.clone();
		h.set_callbacks(Box::new(cb));
		h.set_dbext(&s.dbext);
		h.set_parallel_downloads(s.parallel).unwrap();
		h.set_default_siglevel(s.default_siglevel).unwrap();
		if let Some(g) = &s.gpgdir {
			h.set_gpgdir(g);
		}
		for d in &s.dbs {
			h.register_syncdb(d.name.as_bytes(), d.siglevel)
				.unwrap();
			let dbs = h.dbs_mut();
			let db = dbs.sync.last_mut().expect("just registered");
			for srv in &d.servers {
				db.add_server(dbs.cb, srv).unwrap();
			}
			db.set_usage(d.usage);
		}
		rec.take();
		RUpdate { h, rec }
	}

	// be_sync::db_update, mapped like the C call
	pub fn update(
		&mut self,
		dbs: &[usize],
		force: bool,
	) -> (c_int, c_int, UpdRecord) {
		let ret =
			alpm_core::be_sync::db_update(&mut self.h, dbs, force);
		let (ret, errno) = match ret {
			Ok(true) => (0, 0),
			Ok(false) => (1, 0),
			Err(e) => (-1, e as c_int),
		};
		(ret, errno, self.rec.take())
	}

	pub fn states(&mut self) -> Vec<DbState> {
		let dbs = self.h.dbs_mut();
		let (dbext, cb) = (dbs.dbext, dbs.cb);
		let out =
			dbs.sync.iter_mut()
				.map(|db| {
					let valid = match db.valid() {
						Ok(()) => (0, 0),
						Err(e) => (-1, e as c_int),
					};
					let cache = match db.pkgcache(dbext, cb)
					{
						Ok(c) => {
							Ok(c.iter()
								.map(|p| {
									let v = p.version.clone();
									(p.name_bytes().to_vec(), v.unwrap_or_default())
								})
								.collect())
						}
						Err(e) => Err(e as c_int),
					};
					DbState { valid, cache }
				})
				.collect();
		self.rec.take();
		out
	}
}

// a FrontHandle (siglevel 0 repos) with servers and the frontend's own
// callbacks (cb_log, cb_event, cb_download), as setup_libalpm leaves it
pub fn front_handle(
	fx: &TempRoot,
	dbext: &[u8],
	repos: &[&str],
	servers: &[Vec<Vec<u8>>],
) -> FrontHandle {
	// the callbacks read config, also when alpm_release logs
	init();
	let fh = FrontHandle::open(&fx.root(), &fx.dbpath(), dbext, repos);
	let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
	let (h, dbs) = fh.raw();
	// SAFETY: h and its dbs are live; the callbacks are the frontend's
	// own, reading the C config like in pacman; the C copies the urls
	unsafe {
		for (&db, list) in dbs.iter().zip(servers) {
			for s in list {
				let s = cstr(s);
				assert_eq!(
					alpm_db_add_server(db, s.as_ptr()),
					0
				);
			}
		}
		alpm_option_set_logcb(h, Some(cb_log), ptr::null_mut());
		alpm_option_set_eventcb(h, Some(cb_event), ptr::null_mut());
		alpm_option_set_dlcb(h, Some(cb_download), ptr::null_mut());
	}
	fh
}

// pacman_sync(targets) with -y/-yy in cfg (downloads allowed), COLUMNS=0:
// no progress bars, like a pipe
pub fn c_pacman_sync_refresh<S: AsRef<[u8]>>(
	fh: &FrontHandle,
	cfg: &Config,
	targets: &[S],
	cols: u16,
) -> CRun {
	assert!(cfg.op_s_sync != 0 && cfg.op_s_clean == 0);
	run_op(fh, cfg, cols, targets, pacman_sync)
}

// pacman_files(targets) with -Fy
pub fn c_pacman_files_refresh<S: AsRef<[u8]>>(
	fh: &FrontHandle,
	cfg: &Config,
	targets: &[S],
	cols: u16,
) -> CRun {
	assert!(cfg.op_s_sync != 0);
	run_op(fh, cfg, cols, targets, pacman_files)
}
