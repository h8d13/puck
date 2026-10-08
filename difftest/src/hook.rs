// C side of lib/libalpm/hook.c (_alpm_hook_run, the static parser,
// validation and matching through it), _alpm_run_chroot/_alpm_ldconfig
// of util.c and _alpm_runscriptlet of trans.c, on a real handle over a
// fixture. logcb, eventcb and the logfile (alpm_logaction) are recorded;
// the transaction is set by hand from Rust Packages.
//
// HookRecorder is the Rust side's HookCb, recording the same way, so the
// tests compare HookRec lists and logfile text directly.
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fs;
use std::path::PathBuf;
use std::ptr;
use std::sync::MutexGuard;

use alpm_core::deps::LogLevel;
use alpm_core::hook::{HookCb, HookEvent, HookWhen};
use alpm_core::package::Package;
use alpm_core::util::ChrootCb;

use crate::handle::{
	ALPM, CHandleHead, alpm_db_get_pkgcache, alpm_get_localdb,
	alpm_initialize, alpm_option_set_eventcb, alpm_option_set_logcb,
	alpm_option_set_noextracts, alpm_release, alpm_trans_init,
	alpm_trans_release,
};
use crate::package::{CPkgBox, alpm_pkg_get_provides, list_data, with_strs};
use crate::{CList, alpm_list_add, alpm_list_free, cstr, vsnprintf};

// ALPM_TRANS_FLAG_NOLOCK: no lock file under the fixture dbpath
const TRANS_FLAG_NOLOCK: c_int = 1 << 17;

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
	fn alpm_option_set_logfile(
		handle: *mut c_void,
		logfile: *const c_char,
	) -> c_int;
	fn alpm_option_set_hookdirs(
		handle: *mut c_void,
		hookdirs: *mut CList,
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

// the Rust side's callbacks: recs as HookRec, logaction lines as the
// logfile has them without the timestamp
#[derive(Debug, Default)]
pub struct HookRecorder {
	pub recs: Vec<HookRec>,
	pub actions: Vec<u8>,
}

impl ChrootCb for HookRecorder {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		self.recs.push(HookRec::Log(level as c_int, msg.to_vec()));
	}

	fn logaction(&mut self, prefix: &[u8], msg: &[u8]) {
		self.actions.push(b'[');
		self.actions.extend_from_slice(prefix);
		self.actions.extend_from_slice(b"] ");
		self.actions.extend_from_slice(msg);
	}

	fn scriptlet_info(&mut self, line: &[u8]) {
		self.recs.push(HookRec::Scriptlet(line.to_vec()));
	}
}

impl HookCb for HookRecorder {
	fn hook_event(&mut self, ev: HookEvent<'_>) {
		let run = |name: &[u8], desc: Option<&[u8]>| {
			(name.to_vec(), desc.map(<[u8]>::to_vec))
		};
		self.recs.push(match ev {
			HookEvent::Start(w) => HookRec::HookStart(w as c_int),
			HookEvent::Done(w) => HookRec::HookDone(w as c_int),
			HookEvent::RunStart {
				name,
				desc,
				position,
				total,
			} => {
				let (n, d) = run(name, desc);
				HookRec::RunStart(n, d, position, total)
			}
			HookEvent::RunDone {
				name,
				desc,
				position,
				total,
			} => {
				let (n, d) = run(name, desc);
				HookRec::RunDone(n, d, position, total)
			}
		});
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

fn bytes(p: *const c_char) -> Option<Vec<u8>> {
	// SAFETY: NULL or a nul-terminated string alive for the callback
	(!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

unsafe extern "C" fn log_cb(
	ctx: *mut c_void,
	level: c_int,
	fmt: *const c_char,
	args: *mut c_void,
) {
	let mut buf = vec![0 as c_char; 16384];
	// SAFETY: fmt and args are _alpm_log's printf pair, used once; buf
	// is writable for its length. ctx is the boxed Vec of CHookHandle
	let (n, recs) = unsafe {
		let n = vsnprintf(buf.as_mut_ptr(), buf.len(), fmt, args);
		(n, &mut *ctx.cast::<Vec<HookRec>>())
	};
	assert!(n >= 0 && (n as usize) < buf.len(), "log message cut");
	recs.push(HookRec::Log(level, bytes(buf.as_ptr()).unwrap()));
}

unsafe extern "C" fn event_cb(ctx: *mut c_void, event: *mut c_void) {
	// SAFETY: every event starts with its type, which says the struct;
	// ctx is the boxed Vec of CHookHandle
	let (recs, kind) = unsafe {
		(&mut *ctx.cast::<Vec<HookRec>>(), *event.cast::<c_int>())
	};
	// SAFETY: the casts follow kind, see above
	let rec = unsafe {
		match kind {
			EVENT_SCRIPTLET_INFO => {
				let e = &*event.cast::<CScriptletInfo>();
				HookRec::Scriptlet(bytes(e.line).unwrap())
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
				let name = bytes(e.name).unwrap();
				let desc = bytes(e.desc);
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
			k => panic!("unexpected event {k}"),
		}
	};
	recs.push(rec);
}

// "[%FT%T%z] " leaders of alpm_logaction dropped, wherever they sit (a
// line cut at a nul runs into the next entry)
pub fn strip_stamps(log: &[u8]) -> Vec<u8> {
	// [2026-10-08T01:43:00+0200]
	const SHAPE: &[u8] = b"[dddd-dd-ddTdd:dd:dd+dddd] ";
	let fits = |w: &[u8]| {
		w.iter().zip(SHAPE).all(|(&c, &s)| match s {
			b'd' => c.is_ascii_digit(),
			b'+' => c == b'+' || c == b'-',
			_ => c == s,
		})
	};
	let mut out = Vec::new();
	let mut i = 0;
	while i < log.len() {
		if log.len() - i >= SHAPE.len()
			&& fits(&log[i..i + SHAPE.len()])
		{
			i += SHAPE.len();
			continue;
		}
		out.push(log[i]);
		i += 1;
	}
	out
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
