// C side of lib/libalpm/hook.c (_alpm_hook_run, the static parser,
// validation and matching through it), _alpm_run_chroot/_alpm_ldconfig
// of util.c and _alpm_runscriptlet of trans.c, on a real handle over a
// fixture. logcb, eventcb and the logfile (alpm_logaction) are recorded;
// the transaction is set by hand from Rust Packages.
//
// RustHookHandle is the same on an alpm_core Handle: HookRecorder as its
// Callbacks, recording the same way, and a logfile of its own, so the
// tests compare HookRec lists and logfile text directly.
use std::cell::RefCell;
use std::ffi::{CString, c_char, c_int, c_void};
use std::fs;
use std::path::PathBuf;
use std::ptr;
use std::rc::Rc;
use std::sync::MutexGuard;

use alpm_core::callbacks::{Callbacks, Event, HookRun, HookWhen, LogLevel};
use alpm_core::handle::Handle;
use alpm_core::package::{DbCaches, Package};
use alpm_core::trans::TRANS_FLAG_NOLOCK;

use crate::handle::log_message;
use crate::handle::{
	ALPM, CHandleHead, alpm_db_get_pkgcache, alpm_get_localdb,
	alpm_initialize, alpm_option_set_eventcb, alpm_option_set_hookdirs,
	alpm_option_set_logcb, alpm_option_set_logfile,
	alpm_option_set_noextracts, alpm_release, alpm_trans_init,
	alpm_trans_release,
};
use crate::package::{
	CPkgBox, alpm_pkg_get_provides, field, list_data, with_strs,
};
use crate::{alpm_list_add, alpm_list_free, cstr};

type IoCb = unsafe extern "C" fn(*mut c_void, isize, *mut c_void) -> isize;

unsafe extern "C" {
	fn _alpm_hook_run(handle: *mut c_void, when: c_int) -> c_int;
	fn _alpm_run_chroot(
		handle: *mut c_void,
		cmd: *const c_char,
		argv: *const *mut c_char,
		stdin_cb: Option<IoCb>,
		stdin_ctx: *mut c_void,
	) -> c_int;
	fn _alpm_ldconfig(handle: *mut c_void) -> c_int;
	fn _alpm_runscriptlet(
		handle: *mut c_void,
		filepath: *const c_char,
		script: *const c_char,
		ver: *const c_char,
		oldver: *const c_char,
		is_archive: c_int,
	) -> c_int;
}

// one callback in call order: _alpm_log (level, message) and the events
// hook.c and util.c send
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HookRec {
	Log(c_int, Vec<u8>),
	Scriptlet(Vec<u8>),
	HookStart(c_int),
	HookDone(c_int),
	// name, desc, position, total
	RunStart(Vec<u8>, Option<Vec<u8>>, usize, usize),
	RunDone(Vec<u8>, Option<Vec<u8>>, usize, usize),
}

// a HookRec with its texts as (lossy) strings, for assert messages
pub fn show_rec(r: &HookRec) -> String {
	let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
	match r {
		HookRec::Log(l, m) => format!("log {l} {:?}", s(m)),
		HookRec::Scriptlet(m) => format!("line {:?}", s(m)),
		HookRec::HookStart(w) => format!("hook start {w}"),
		HookRec::HookDone(w) => format!("hook done {w}"),
		HookRec::RunStart(n, d, p, t) => {
			let d = d.as_deref().map(s);
			format!("run start {:?} {d:?} {p}/{t}", s(n))
		}
		HookRec::RunDone(n, d, p, t) => {
			let d = d.as_deref().map(s);
			format!("run done {:?} {d:?} {p}/{t}", s(n))
		}
	}
}

// the Rust side's callbacks: logs and the events hook.c and util.c send
// as HookRec, shared with the RustHookHandle that reads them back
#[derive(Debug, Default)]
pub struct HookRecorder(Rc<RefCell<Vec<HookRec>>>);

impl Callbacks for HookRecorder {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		let rec = HookRec::Log(level as c_int, msg.to_vec());
		self.0.borrow_mut().push(rec);
	}

	fn event(&mut self, event: &Event<'_>) {
		let rec = hook_rec(event).unwrap_or_else(|| {
			panic!("unexpected event {}", event.kind())
		});
		self.0.borrow_mut().push(rec);
	}
}

// a scriptlet line or hook event as HookRec, None for other events
pub fn hook_rec(event: &Event<'_>) -> Option<HookRec> {
	let run = |r: &HookRun| {
		let desc = r.desc.map(<[u8]>::to_vec);
		(r.name.to_vec(), desc, r.position, r.total)
	};
	let rec = match event {
		Event::ScriptletInfo { line } => {
			HookRec::Scriptlet(line.to_vec())
		}
		Event::HookStart { when } => HookRec::HookStart(*when as c_int),
		Event::HookDone { when } => HookRec::HookDone(*when as c_int),
		Event::HookRunStart(r) => {
			let (n, d, p, t) = run(r);
			HookRec::RunStart(n, d, p, t)
		}
		Event::HookRunDone(r) => {
			let (n, d, p, t) = run(r);
			HookRec::RunDone(n, d, p, t)
		}
		_ => return None,
	};
	Some(rec)
}

// a Rust Handle on root/dbpath with a HookRecorder and a logfile, the
// counterpart of CHookHandle
pub struct RustHookHandle {
	pub h: Handle,
	logfile: PathBuf,
	recs: Rc<RefCell<Vec<HookRec>>>,
}

impl RustHookHandle {
	// root and dbpath must exist, logfile is created on first use
	pub fn new(root: &[u8], dbpath: &[u8], logfile: PathBuf) -> Self {
		let mut h = Handle::initialize(root, dbpath).unwrap();
		let recs = Rc::new(RefCell::new(Vec::new()));
		h.set_callbacks(Box::new(HookRecorder(recs.clone())));
		h.set_logfile(logfile.as_os_str().as_encoded_bytes());
		// the local descs loaded up front like CHookHandle's
		h.local_cache();
		recs.borrow_mut().clear();
		RustHookHandle { h, logfile, recs }
	}

	pub fn set_hookdirs(&mut self, dirs: &[Vec<u8>]) {
		self.h.set_hookdirs(dirs);
		self.recs.borrow_mut().clear();
	}

	pub fn set_noextracts(&mut self, list: &[Vec<u8>]) {
		self.h.set_noextracts(list);
		self.recs.borrow_mut().clear();
	}

	// the records and logfile text since the last call, with the C
	// return value of the call: 0 for ok, fail otherwise
	pub fn take(&mut self, ok: bool, fail: c_int) -> CHookResult {
		let log = fs::read(&self.logfile).unwrap_or_default();
		if !log.is_empty() {
			fs::write(&self.logfile, b"").unwrap();
		}
		let recs = std::mem::take(&mut *self.recs.borrow_mut());
		(if ok { 0 } else { fail }, recs, strip_stamps(&log))
	}
}

// alpm_event_scriptlet_info_t, alpm_event_hook_t, alpm_event_hook_run_t
#[repr(C)]
struct CScriptletInfo {
	kind: c_int,
	line: *const c_char,
}

#[repr(C)]
struct CEventHook {
	kind: c_int,
	when: c_int,
}

#[repr(C)]
struct CEventHookRun {
	kind: c_int,
	name: *const c_char,
	desc: *const c_char,
	position: usize,
	total: usize,
}

// ALPM_EVENT_* of the events recorded
const EVENT_SCRIPTLET_INFO: c_int = 17;
const EVENT_HOOK_START: c_int = 34;
const EVENT_HOOK_DONE: c_int = 35;
const EVENT_HOOK_RUN_START: c_int = 36;
const EVENT_HOOK_RUN_DONE: c_int = 37;

unsafe extern "C" fn log_cb(
	ctx: *mut c_void,
	level: c_int,
	fmt: *const c_char,
	args: *mut c_void,
) {
	// SAFETY: fmt and args are the pair this callback got
	let msg = unsafe { log_message(fmt, args) };
	// SAFETY: ctx is the boxed Vec of HookRec
	let recs = unsafe { &mut *ctx.cast::<Vec<HookRec>>() };
	recs.push(HookRec::Log(level, msg));
}

unsafe extern "C" fn event_cb(ctx: *mut c_void, event: *mut c_void) {
	// SAFETY: every event starts with its type, which says the struct;
	// ctx is the boxed Vec of CHookHandle
	let (recs, kind) = unsafe {
		(&mut *ctx.cast::<Vec<HookRec>>(), *event.cast::<c_int>())
	};
	// SAFETY: a live event of the C
	let rec = unsafe { c_hook_rec(event) };
	recs.push(rec.unwrap_or_else(|| panic!("unexpected event {kind}")));
}

// a C scriptlet line or hook event as HookRec, None for other events.
// SAFETY: event is a live alpm_event_t
pub(crate) unsafe fn c_hook_rec(event: *mut c_void) -> Option<HookRec> {
	// SAFETY: every event starts with its type, which says the struct
	let kind = unsafe { *event.cast::<c_int>() };
	// SAFETY: the casts follow kind
	let rec = unsafe {
		match kind {
			EVENT_SCRIPTLET_INFO => {
				let e = &*event.cast::<CScriptletInfo>();
				HookRec::Scriptlet(field(e.line).unwrap())
			}
			EVENT_HOOK_START | EVENT_HOOK_DONE => {
				let e = &*event.cast::<CEventHook>();
				match kind {
					EVENT_HOOK_START => {
						HookRec::HookStart(e.when)
					}
					_ => HookRec::HookDone(e.when),
				}
			}
			EVENT_HOOK_RUN_START | EVENT_HOOK_RUN_DONE => {
				let e = &*event.cast::<CEventHookRun>();
				let name = field(e.name).unwrap();
				let desc = field(e.desc);
				match kind {
					EVENT_HOOK_RUN_START => {
						HookRec::RunStart(
							name, desc, e.position,
							e.total,
						)
					}
					_ => HookRec::RunDone(
						name, desc, e.position, e.total,
					),
				}
			}
			_ => return None,
		}
	};
	Some(rec)
}

// alpm_logaction's leaders as their zone, "[+zzzz]": the clock moves
// between the C's run and the port's (whole commits), the zone is
// compared. handle_opts' stamped finds them
pub fn strip_stamps(log: &[u8]) -> Vec<u8> {
	crate::handle_opts::stamped(log).text
}

// what one C call gave: return value, callbacks, logfile text without
// timestamps
pub type CHookResult = (c_int, Vec<HookRec>, Vec<u8>);

// a transaction target as hook.c reads it: the package and its oldpkg
pub type CTarget<'a> = (&'a Package, Option<&'a Package>);

// a C handle on root/dbpath with logcb, eventcb and a logfile
pub struct CHookHandle {
	h: *mut c_void,
	logfile: PathBuf,
	// the callbacks' ctx: boxed so the Vec stays put when the handle moves
	#[allow(clippy::box_collection)]
	recs: Box<Vec<HookRec>>,
	_guard: MutexGuard<'static, ()>,
}

impl Drop for CHookHandle {
	fn drop(&mut self) {
		// SAFETY: h came from alpm_initialize, no transaction is open
		unsafe { alpm_release(self.h) };
	}
}

impl CHookHandle {
	// root and dbpath must exist, logfile is created on first use
	pub fn new(root: &[u8], dbpath: &[u8], logfile: PathBuf) -> Self {
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
		let mut recs = Box::new(Vec::new());
		let ctx = (&raw mut *recs).cast::<c_void>();
		let path = cstr(logfile.as_os_str().as_encoded_bytes());
		// SAFETY: h is live, ctx outlives it (dropped after release),
		// the logfile path is copied
		unsafe {
			alpm_option_set_logcb(h, Some(log_cb), ctx);
			alpm_option_set_eventcb(h, Some(event_cb), ctx);
			alpm_option_set_logfile(h, path.as_ptr());
		}
		let mut c = CHookHandle {
			h,
			logfile,
			recs,
			_guard: guard,
		};
		c.load_local();
		c
	}

	// the local cache and every desc loaded up front, so Depends
	// lookups log nothing
	fn load_local(&mut self) {
		// SAFETY: h is live, the cache list belongs to its local db
		let list = unsafe {
			alpm_db_get_pkgcache(alpm_get_localdb(self.h))
		};
		for p in list_data(list) {
			// SAFETY: p is a live local cache entry
			unsafe { alpm_pkg_get_provides(p.cast()) };
		}
		self.recs.clear();
	}

	pub fn set_hookdirs(&mut self, dirs: &[Vec<u8>]) {
		// SAFETY: h is live, the set call dups the strings
		with_strs(dirs, |l| unsafe {
			alpm_option_set_hookdirs(self.h, l)
		});
		self.recs.clear();
	}

	pub fn set_noextracts(&mut self, list: &[Vec<u8>]) {
		// SAFETY: as above
		with_strs(list, |l| unsafe {
			alpm_option_set_noextracts(self.h, l)
		});
		self.recs.clear();
	}

	// the records and logfile text since the last call
	fn take(&mut self, ret: c_int) -> CHookResult {
		let log = fs::read(&self.logfile).unwrap_or_default();
		if !log.is_empty() {
			fs::write(&self.logfile, b"").unwrap();
		}
		(ret, std::mem::take(&mut *self.recs), strip_stamps(&log))
	}

	// _alpm_hook_run on a NOLOCK transaction holding add (oldpkg wired)
	// and remove. C preconditions: names set, no Operation/Type/When
	// without a value in the hook files, no Target without one when a
	// transaction has packages
	pub fn hook_run(
		&mut self,
		add: &[CTarget],
		remove: &[&Package],
		when: HookWhen,
	) -> CHookResult {
		let pkgs =
			add.iter().map(|t| t.0).chain(remove.iter().copied());
		assert!(pkgs.clone().all(|p| p.name.is_some()), "NULL name");
		let boxes: Vec<CPkgBox> = add
			.iter()
			.map(|(p, old)| {
				let b = CPkgBox::new(p);
				if let Some(old) = old {
					let o = CPkgBox::new(old);
					// SAFETY: b is live; _alpm_pkg_free frees
					// oldpkg with it, so o is handed over
					unsafe { (*b.0).oldpkg = o.0 };
					std::mem::forget(o);
				}
				b
			})
			.collect();
		let rboxes: Vec<CPkgBox> =
			remove.iter().map(|p| CPkgBox::new(p)).collect();
		let list = |bs: &[CPkgBox]| {
			bs.iter().fold(ptr::null_mut(), |l, b| {
				// SAFETY: l is NULL or built by alpm_list_add,
				// the packages outlive the list
				unsafe { alpm_list_add(l, b.0.cast()) }
			})
		};
		let (al, rl) = (list(&boxes), list(&rboxes));
		// SAFETY: h is live without a transaction; the lists are put
		// in and taken out again before the release, which would
		// free their packages
		let ret = unsafe {
			assert_eq!(
				alpm_trans_init(self.h, TRANS_FLAG_NOLOCK),
				0
			);
			let trans = (*self.h.cast::<CHandleHead>()).trans;
			(*trans).add = al;
			(*trans).remove = rl;
			let ret = _alpm_hook_run(self.h, when as c_int);
			(*trans).add = ptr::null_mut();
			(*trans).remove = ptr::null_mut();
			assert_eq!(alpm_trans_release(self.h), 0);
			alpm_list_free(al);
			alpm_list_free(rl);
			ret
		};
		self.take(ret)
	}

	// _alpm_run_chroot, stdin fed from the bytes when given. cmd None is
	// NULL (only valid where the child's execv sees it)
	pub fn run_chroot(
		&mut self,
		cmd: Option<&[u8]>,
		argv: &[Vec<u8>],
		stdin: Option<&[u8]>,
	) -> CHookResult {
		let cmd = cmd.map(cstr);
		let args: Vec<CString> = argv.iter().map(|a| cstr(a)).collect();
		let mut ptrs: Vec<*mut c_char> =
			args.iter().map(|a| a.as_ptr().cast_mut()).collect();
		ptrs.push(ptr::null_mut());
		let mut feed = Feed(stdin.unwrap_or_default());
		let (cb, ctx): (Option<IoCb>, *mut c_void) = match stdin {
			Some(_) => (Some(feed_cb), (&raw mut feed).cast()),
			None => (None, ptr::null_mut()),
		};
		let cmd_ptr = cmd.as_ref().map_or(ptr::null(), |c| c.as_ptr());
		// SAFETY: h is live; argv is NULL terminated, its strings and
		// feed outlive the call
		let ret = unsafe {
			_alpm_run_chroot(
				self.h,
				cmd_ptr,
				ptrs.as_ptr(),
				cb,
				ctx,
			)
		};
		self.take(ret)
	}

	pub fn ldconfig(&mut self) -> CHookResult {
		// SAFETY: h is live
		let ret = unsafe { _alpm_ldconfig(self.h) };
		self.take(ret)
	}

	pub fn runscriptlet(
		&mut self,
		filepath: &[u8],
		script: &[u8],
		ver: &[u8],
		oldver: Option<&[u8]>,
		is_archive: bool,
	) -> CHookResult {
		let (f, s, v) = (cstr(filepath), cstr(script), cstr(ver));
		let old = oldver.map(cstr);
		let old_ptr = old.as_ref().map_or(ptr::null(), |o| o.as_ptr());
		// SAFETY: h is live, the strings outlive the call
		let ret = unsafe {
			_alpm_runscriptlet(
				self.h,
				f.as_ptr(),
				s.as_ptr(),
				v.as_ptr(),
				old_ptr,
				c_int::from(is_archive),
			)
		};
		self.take(ret)
	}
}

// the stdin bytes still to hand out
struct Feed<'a>(&'a [u8]);

// _alpm_cb_io: up to len bytes, 0 when done
unsafe extern "C" fn feed_cb(
	buf: *mut c_void,
	len: isize,
	ctx: *mut c_void,
) -> isize {
	// SAFETY: ctx is the Feed of run_chroot, buf has len writable bytes
	let feed = unsafe { &mut *ctx.cast::<Feed>() };
	let n = feed.0.len().min(len as usize);
	// SAFETY: as above, n <= len and n <= the Feed's length
	unsafe { ptr::copy_nonoverlapping(feed.0.as_ptr(), buf.cast(), n) };
	feed.0 = &feed.0[n..];
	n as isize
}
