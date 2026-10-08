// C side of the rest of lib/libalpm/handle.c and log.c: option getters
// and setters, the lock (_alpm_handle_lock, alpm_unlock,
// _alpm_handle_unlock), alpm_logaction, and what logcb/eventcb see
// (debug lines of the setters, DATABASE_MISSING at registration).
//
// a COpts is one alpm_initialize'd handle holding the ALPM lock, its
// callbacks record into a boxed RefCell. calls reporting through pm_errno
// return it next to their result, reset first like db.rs.
use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_ushort, c_void};
use std::ptr;
use std::sync::MutexGuard;

use alpm_core::deps::Depend;

use crate::handle::*;
use crate::package::{CDepend, field, read_deps, read_strs};
use crate::pkg_show::{Tm, strftime};
use crate::util_common::{errno, set_errno};
use crate::{CList, alpm_list_add, alpm_list_free, cstr, opt_ptr, vsnprintf};

// ALPM_EVENT_DATABASE_MISSING
const EVENT_DATABASE_MISSING: c_int = 27;

unsafe extern "C" {
	fn gmtime_r(t: *const i64, tm: *mut Tm) -> *mut Tm;
	// what log.c, util.c and package.c call: rereads TZ every time
	fn localtime(t: *const i64) -> *mut Tm;
}

// what logcb and eventcb were given, in order
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OptsRecord {
	// level, formatted message
	pub logs: Vec<(c_int, Vec<u8>)>,
	// event type, dbname for DATABASE_MISSING (empty otherwise)
	pub events: Vec<(c_int, Vec<u8>)>,
}

// leading fields of alpm_event_database_missing_t
#[repr(C)]
struct CEventDbMissing {
	kind: c_int,
	dbname: *const c_char,
}

unsafe extern "C" fn log_cb(
	ctx: *mut c_void,
	level: c_int,
	fmt: *const c_char,
	args: *mut c_void,
) {
	let mut buf = vec![0 as c_char; 8192];
	// SAFETY: fmt and args are the printf pair _alpm_log got, used once;
	// buf is writable for its length. ctx is the COpts's boxed record
	unsafe {
		vsnprintf(buf.as_mut_ptr(), buf.len(), fmt, args);
		let rec = &*ctx.cast::<RefCell<OptsRecord>>();
		let msg = CStr::from_ptr(buf.as_ptr()).to_bytes().to_vec();
		rec.borrow_mut().logs.push((level, msg));
	}
}

unsafe extern "C" fn event_cb(ctx: *mut c_void, event: *mut c_void) {
	// SAFETY: event starts with its type; DATABASE_MISSING carries
	// alpm_event_database_missing_t. ctx is the boxed record
	unsafe {
		let e = &*event.cast::<CEventDbMissing>();
		let name = match e.kind {
			EVENT_DATABASE_MISSING => field(e.dbname).unwrap(),
			_ => Vec::new(),
		};
		let rec = &*ctx.cast::<RefCell<OptsRecord>>();
		rec.borrow_mut().events.push((e.kind, name));
	}
}

pub struct COpts {
	h: *mut c_void,
	rec: Box<RefCell<OptsRecord>>,
	_guard: MutexGuard<'static, ()>,
}

impl Drop for COpts {
	fn drop(&mut self) {
		// SAFETY: h came from alpm_initialize, no transaction; the
		// record outlives the release (its callbacks may log)
		unsafe { alpm_release(self.h) };
	}
}

// a C list over the strings, nodes freed by the caller
fn with_list<R>(strs: &[Vec<u8>], f: impl FnOnce(*mut CList) -> R) -> R {
	let strs: Vec<CString> = strs.iter().map(|s| cstr(s)).collect();
	let list = strs.iter().fold(ptr::null_mut(), |l, s| {
		// SAFETY: l is NULL or from alpm_list_add, the strings outlive
		// the list and the C copies them
		unsafe { alpm_list_add(l, s.as_ptr().cast_mut().cast()) }
	});
	let r = f(list);
	// SAFETY: nodes from alpm_list_add above, data owned by strs
	unsafe { alpm_list_free(list) };
	r
}

// alpm_depend_t over owned strings, read only by the C
struct DepBox {
	_strs: [Option<CString>; 3],
	c: CDepend,
}

impl DepBox {
	fn new(d: &Depend) -> DepBox {
		let strs = [
			Some(cstr(&d.name)),
			d.version.as_deref().map(cstr),
			d.desc.as_deref().map(cstr),
		];
		let c = CDepend {
			name: opt_ptr(&strs[0]).cast_mut(),
			version: opt_ptr(&strs[1]).cast_mut(),
			desc: opt_ptr(&strs[2]).cast_mut(),
			name_hash: d.name_hash,
			depmod: d.depmod as c_int,
		};
		DepBox { _strs: strs, c }
	}

	fn ptr(&self) -> *const c_void {
		ptr::from_ref(&self.c).cast()
	}
}

type GetStr = unsafe extern "C" fn(*mut c_void) -> *const c_char;
type GetInt = unsafe extern "C" fn(*mut c_void) -> c_int;
type GetList = unsafe extern "C" fn(*mut c_void) -> *mut CList;
type StrOp = unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int;
type SetList = unsafe extern "C" fn(*mut c_void, *mut CList) -> c_int;
type SetUshort = unsafe extern "C" fn(*mut c_void, c_ushort) -> c_int;

// the string list options with add/set/remove
#[derive(Clone, Copy, Debug)]
pub enum DirList {
	Cache,
	Hook,
	Overwrite,
}

impl DirList {
	fn ops(self) -> (GetList, StrOp, SetList, StrOp) {
		match self {
			DirList::Cache => (
				alpm_option_get_cachedirs,
				alpm_option_add_cachedir,
				alpm_option_set_cachedirs,
				alpm_option_remove_cachedir,
			),
			DirList::Hook => (
				alpm_option_get_hookdirs,
				alpm_option_add_hookdir,
				alpm_option_set_hookdirs,
				alpm_option_remove_hookdir,
			),
			DirList::Overwrite => (
				alpm_option_get_overwrite_files,
				alpm_option_add_overwrite_file,
				alpm_option_set_overwrite_files,
				alpm_option_remove_overwrite_file,
			),
		}
	}
}

// the int options
#[derive(Clone, Copy, Debug)]
pub enum IntOpt {
	UseSyslog,
	CheckSpace,
}

// the unsigned short flags
#[derive(Clone, Copy, Debug)]
pub enum FlagOpt {
	DlTimeout,
	Sandbox,
	SandboxFs,
	SandboxSyscalls,
}

impl FlagOpt {
	fn ops(self) -> (GetInt, SetUshort) {
		match self {
			FlagOpt::DlTimeout => (
				alpm_option_get_disable_dl_timeout,
				alpm_option_set_disable_dl_timeout,
			),
			FlagOpt::Sandbox => (
				alpm_option_get_disable_sandbox,
				alpm_option_set_disable_sandbox,
			),
			FlagOpt::SandboxFs => (
				alpm_option_get_disable_sandbox_filesystem,
				alpm_option_set_disable_sandbox_filesystem,
			),
			FlagOpt::SandboxSyscalls => (
				alpm_option_get_disable_sandbox_syscalls,
				alpm_option_set_disable_sandbox_syscalls,
			),
		}
	}
}

impl COpts {
	// alpm_initialize with logcb and eventcb recording
	pub fn new(root: &[u8], dbpath: &[u8]) -> Result<COpts, c_int> {
		let guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		let (root, dbpath) = (cstr(root), cstr(dbpath));
		let mut err = 0;
		// SAFETY: valid C strings, err writable
		let h = unsafe {
			alpm_initialize(
				root.as_ptr(),
				dbpath.as_ptr(),
				&mut err,
			)
		};
		if h.is_null() {
			return Err(err);
		}
		let rec = Box::new(RefCell::new(OptsRecord::default()));
		let ctx = ptr::from_ref(&*rec).cast_mut().cast();
		// SAFETY: h is live, ctx is the boxed record that outlives h
		unsafe {
			alpm_option_set_logcb(h, Some(log_cb), ctx);
			alpm_option_set_eventcb(h, Some(event_cb), ctx);
		}
		Ok(COpts {
			h,
			rec,
			_guard: guard,
		})
	}

	// what the callbacks saw since the last take
	pub fn take_record(&self) -> OptsRecord {
		std::mem::take(&mut *self.rec.borrow_mut())
	}

	fn call<R>(&self, f: impl FnOnce() -> R) -> (R, c_int) {
		// SAFETY: h is live, CHECK_HANDLE only resets pm_errno
		unsafe { alpm_option_get_root(self.h) };
		let r = f();
		// SAFETY: h is live
		(r, unsafe { alpm_errno(self.h) })
	}

	fn get_str(&self, f: GetStr) -> Option<Vec<u8>> {
		// SAFETY: h is live, the string stays owned by the handle
		field(unsafe { f(self.h) })
	}

	fn str_op(&self, f: StrOp, s: Option<&[u8]>) -> (c_int, c_int) {
		let s = s.map(cstr);
		// SAFETY: h is live, the C copies or compares s
		self.call(|| unsafe { f(self.h, opt_ptr(&s)) })
	}

	pub fn list(&self, which: DirList) -> Vec<Vec<u8>> {
		// SAFETY: h is live, the list stays owned by the handle
		read_strs(unsafe { (which.ops().0)(self.h) })
	}

	pub fn list_add(&self, which: DirList, s: &[u8]) -> (c_int, c_int) {
		self.str_op(which.ops().1, Some(s))
	}

	pub fn list_set(
		&self,
		which: DirList,
		strs: &[Vec<u8>],
	) -> (c_int, c_int) {
		let set = which.ops().2;
		// SAFETY: h is live, the C copies the strings
		with_list(strs, |l| self.call(|| unsafe { set(self.h, l) }))
	}

	pub fn list_remove(&self, which: DirList, s: &[u8]) -> (c_int, c_int) {
		self.str_op(which.ops().3, Some(s))
	}

	pub fn gpgdir(&self) -> Option<Vec<u8>> {
		self.get_str(alpm_option_get_gpgdir)
	}

	pub fn set_gpgdir(&self, dir: &[u8]) -> (c_int, c_int) {
		self.str_op(alpm_option_set_gpgdir, Some(dir))
	}

	pub fn logfile(&self) -> Option<Vec<u8>> {
		self.get_str(alpm_option_get_logfile)
	}

	pub fn set_logfile(&self, f: &[u8]) -> (c_int, c_int) {
		self.str_op(alpm_option_set_logfile, Some(f))
	}

	pub fn lockfile(&self) -> Option<Vec<u8>> {
		self.get_str(alpm_option_get_lockfile)
	}

	pub fn sandboxuser(&self) -> Option<Vec<u8>> {
		self.get_str(alpm_option_get_sandboxuser)
	}

	pub fn set_sandboxuser(&self, user: Option<&[u8]>) -> (c_int, c_int) {
		self.str_op(alpm_option_set_sandboxuser, user)
	}

	pub fn int_opt(&self, which: IntOpt) -> c_int {
		// SAFETY: h is live
		unsafe {
			match which {
				IntOpt::UseSyslog => {
					alpm_option_get_usesyslog(self.h)
				}
				IntOpt::CheckSpace => {
					alpm_option_get_checkspace(self.h)
				}
			}
		}
	}

	pub fn set_int_opt(&self, which: IntOpt, v: c_int) -> (c_int, c_int) {
		// SAFETY: h is live
		self.call(|| unsafe {
			match which {
				IntOpt::UseSyslog => {
					alpm_option_set_usesyslog(self.h, v)
				}
				IntOpt::CheckSpace => {
					alpm_option_set_checkspace(self.h, v)
				}
			}
		})
	}

	pub fn flag(&self, which: FlagOpt) -> c_int {
		// SAFETY: h is live
		unsafe { (which.ops().0)(self.h) }
	}

	pub fn set_flag(&self, which: FlagOpt, v: c_ushort) -> (c_int, c_int) {
		// SAFETY: h is live
		self.call(|| unsafe { (which.ops().1)(self.h, v) })
	}

	pub fn parallel_downloads(&self) -> c_int {
		// SAFETY: h is live
		unsafe { alpm_option_get_parallel_downloads(self.h) }
	}

	pub fn set_parallel_downloads(&self, n: c_uint) -> (c_int, c_int) {
		// SAFETY: h is live
		self.call(|| unsafe {
			alpm_option_set_parallel_downloads(self.h, n)
		})
	}

	pub fn set_dbext(&self, dbext: &[u8]) -> (c_int, c_int) {
		self.str_op(alpm_option_set_dbext, Some(dbext))
	}

	pub fn assumeinstalled(&self) -> Vec<Depend> {
		// SAFETY: h is live, the list stays owned by the handle
		read_deps(unsafe { alpm_option_get_assumeinstalled(self.h) })
	}

	pub fn add_assumeinstalled(&self, dep: &Depend) -> (c_int, c_int) {
		let d = DepBox::new(dep);
		// SAFETY: h is live, the C dups the dep
		self.call(|| unsafe {
			alpm_option_add_assumeinstalled(self.h, d.ptr())
		})
	}

	pub fn set_assumeinstalled(&self, deps: &[Depend]) -> (c_int, c_int) {
		let boxes: Vec<DepBox> = deps.iter().map(DepBox::new).collect();
		let list = boxes.iter().fold(ptr::null_mut(), |l, d| {
			// SAFETY: l is NULL or from alpm_list_add; the C dups
			// every dep, the boxes outlive the call
			unsafe { alpm_list_add(l, d.ptr().cast_mut()) }
		});
		// SAFETY: h is live
		let r = self.call(|| unsafe {
			alpm_option_set_assumeinstalled(self.h, list)
		});
		// SAFETY: nodes from alpm_list_add, data owned by boxes
		unsafe { alpm_list_free(list) };
		r
	}

	pub fn remove_assumeinstalled(&self, dep: &Depend) -> (c_int, c_int) {
		let d = DepBox::new(dep);
		// SAFETY: h is live, the dep is only compared
		self.call(|| unsafe {
			alpm_option_remove_assumeinstalled(self.h, d.ptr())
		})
	}

	// _alpm_handle_lock: its result and errno (0 when it succeeded)
	pub fn lock(&self) -> (c_int, c_int) {
		set_errno(0);
		// SAFETY: h is live, lockfile set by alpm_initialize
		let r = unsafe { _alpm_handle_lock(self.h) };
		(r, if r == 0 { 0 } else { errno() })
	}

	// alpm_unlock: result, pm_errno and errno after a failure
	pub fn unlock(&self) -> (c_int, c_int, c_int) {
		set_errno(0);
		// SAFETY: h is live
		let (r, e) = self.call(|| unsafe { alpm_unlock(self.h) });
		(r, e, if r == 0 { 0 } else { errno() })
	}

	// _alpm_handle_unlock
	pub fn handle_unlock(&self) -> c_int {
		// SAFETY: h is live
		unsafe { _alpm_handle_unlock(self.h) }
	}

	// alpm_logaction(h, prefix, "%s", msg), None prefix is NULL
	pub fn logaction(
		&self,
		prefix: Option<&[u8]>,
		msg: &[u8],
	) -> (c_int, c_int) {
		let (prefix, msg) = (prefix.map(cstr), cstr(msg));
		// SAFETY: h is live, "%s" takes the one string argument
		self.call(|| unsafe {
			alpm_logaction(
				self.h,
				opt_ptr(&prefix),
				c"%s".as_ptr(),
				msg.as_ptr(),
			)
		})
	}

	// alpm_register_syncdb: whether a db came back
	pub fn register_syncdb(
		&self,
		name: &[u8],
		level: c_int,
	) -> (bool, c_int) {
		let name = cstr(name);
		// SAFETY: h is live, the C copies name
		self.call(|| unsafe {
			!alpm_register_syncdb(self.h, name.as_ptr(), level)
				.is_null()
		})
	}
}

// strftime(fmt, localtime(&secs)) and tm_gmtoff, None where localtime
// fails. localtime's static buffer: callers keep to one thread (the
// tz-probe binary)
pub fn c_localtime(secs: i64, fmt: &CStr) -> Option<(Vec<u8>, i64)> {
	let mut buf = [0 as c_char; 64];
	// SAFETY: localtime's result is read before the next call; buf holds
	// 64 bytes, strftime stays within it and returns the length
	unsafe {
		let tm = localtime(&secs);
		if tm.is_null() {
			return None;
		}
		let n = strftime(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), tm);
		let s = std::slice::from_raw_parts(buf.as_ptr().cast(), n);
		Some((s.to_vec(), (*tm).tm_gmtoff))
	}
}

// strftime(fmt) of the broken-down time of secs + utcoff with tm_gmtoff
// set to utcoff: what localtime gives in a zone of that offset
pub fn c_strftime_at(secs: i64, utcoff: i32, fmt: &CStr) -> Vec<u8> {
	let t = secs + i64::from(utcoff);
	let mut buf = [0 as c_char; 64];
	// SAFETY: tm written by gmtime_r, buf holds 64 bytes; strftime
	// stays within it and returns the length
	unsafe {
		let mut tm: Tm = std::mem::zeroed();
		assert!(!gmtime_r(&t, &mut tm).is_null(), "gmtime_r {t}");
		tm.tm_gmtoff = utcoff.into();
		let n = strftime(
			buf.as_mut_ptr(),
			buf.len(),
			fmt.as_ptr(),
			&tm,
		);
		std::slice::from_raw_parts(buf.as_ptr().cast(), n).to_vec()
	}
}

// text with its clock readings cut out: alpm_logaction's leader
// "[YYYY-MM-DDTHH:MM:SS+zzzz]" (anywhere: a line cut at a nul runs into
// the next entry) keeps its zone as "[+zzzz]", PACMAN_DEBUG's
// "[HH:MM:SS] " at a line start becomes "[] ". times holds what each
// showed: the instant (unix seconds) of a leader, the second of the day
// of a debug stamp
#[derive(Clone, Debug)]
pub struct Stamped {
	pub text: Vec<u8>,
	pub times: Vec<Shown>,
}

#[derive(Clone, Copy, Debug)]
pub enum Shown {
	Instant(i64),
	DaySecond(i64),
}

// C and Rust read the clock a run apart: equal within this many seconds
pub const CLOCK_SLACK: i64 = 30;

impl PartialEq for Stamped {
	fn eq(&self, other: &Stamped) -> bool {
		let close = |a: &Shown, b: &Shown| match (*a, *b) {
			(Shown::Instant(a), Shown::Instant(b)) => {
				(a - b).abs() <= CLOCK_SLACK
			}
			(Shown::DaySecond(a), Shown::DaySecond(b)) => {
				let d = (a - b).rem_euclid(86_400);
				d <= CLOCK_SLACK || 86_400 - d <= CLOCK_SLACK
			}
			_ => false,
		};
		self.text == other.text
			&& self.times.len() == other.times.len()
			&& self.times
				.iter()
				.zip(&other.times)
				.all(|(a, b)| close(a, b))
	}
}

impl Eq for Stamped {}

fn digits(w: &[u8]) -> Option<i64> {
	let ok = !w.is_empty() && w.iter().all(u8::is_ascii_digit);
	ok.then(|| w.iter().fold(0, |n, &c| n * 10 + i64::from(c - b'0')))
}

// "[HH:MM:SS] " as its second of the day
fn debug_stamp_at(w: &[u8]) -> Option<i64> {
	let shape =
		w.len() >= 11
			&& w[0] == b'[' && w[3] == b':'
			&& w[6] == b':' && w[9] == b']'
			&& w[10] == b' ';
	if !shape {
		return None;
	}
	let (h, m, s) =
		(digits(&w[1..3])?, digits(&w[4..6])?, digits(&w[7..9])?);
	Some(h * 3600 + m * 60 + s)
}

// "[YYYY-MM-DDTHH:MM:SS+zzzz]" as its instant, and the zone part
fn leader_at(w: &[u8]) -> Option<(i64, &[u8])> {
	const SHAPE: &[u8] = b"[dddd-dd-ddTdd:dd:dd+dddd]";
	let w = w.get(..SHAPE.len())?;
	let fits = w.iter().zip(SHAPE).all(|(&c, &p)| match p {
		b'd' => c.is_ascii_digit(),
		b'+' => c == b'+' || c == b'-',
		p => c == p,
	});
	if !fits {
		return None;
	}
	let n = |a: usize, b: usize| digits(&w[a..b]).expect("shape");
	let month = time::Month::try_from(n(6, 8) as u8).ok()?;
	let date = time::Date::from_calendar_date(
		n(1, 5) as i32,
		month,
		n(9, 11) as u8,
	)
	.ok()?;
	let days = i64::from(date.to_julian_day()) - 2_440_588;
	let local =
		days * 86_400 + n(12, 14) * 3600 + n(15, 17) * 60 + n(18, 20);
	let off = n(21, 23) * 3600 + n(23, 25) * 60;
	let off = if w[20] == b'-' { -off } else { off };
	Some((local - off, &w[20..25]))
}

pub fn stamped(s: &[u8]) -> Stamped {
	let mut out = Stamped {
		text: Vec::new(),
		times: Vec::new(),
	};
	let mut i = 0;
	while i < s.len() {
		let line_start = i == 0 || s[i - 1] == b'\n';
		if let Some(t) =
			line_start.then(|| debug_stamp_at(&s[i..])).flatten()
		{
			out.text.extend_from_slice(b"[] ");
			out.times.push(Shown::DaySecond(t));
			i += 11;
			continue;
		}
		if let Some((t, zone)) = leader_at(&s[i..]) {
			out.text.extend_from_slice(
				&[b"[", zone, b"]"].concat(),
			);
			out.times.push(Shown::Instant(t));
			i += 26;
			continue;
		}
		out.text.push(s[i]);
		i += 1;
	}
	out
}
