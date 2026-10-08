// C side of src/pacman/callback.c (frontend objects, see build.rs) next
// to the port, both driven by the same calls
//
// the C callbacks keep their state in statics and read the global
// `config`, getcols(), stdin and the monotonic clock. one Rust Frontend
// lives next to them for the whole test process (World), every call goes
// to both under FRONTEND, so their states stay in step whatever order
// the tests run in. per call: the config fields the callbacks read are
// copied into `config`, COLUMNS is set (cache reset), stdin is an
// fmemopen of the given input, stdout and stderr are memstreams, and
// CLOCK_MONOTONIC_COARSE (get_time_ms) reads a fake clock: clock_gettime
// is interposed below, the other clocks go to the kernel. the Rust side
// gets the same through its Term.
use std::ffi::{CString, c_char, c_int, c_long, c_void};
use std::io::Cursor;
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicU16, Ordering};

use alpm_core::callbacks::{
	DownloadEvent, Event, LogLevel, Progress, Question,
};
use alpm_core::conflict::Conflict;
use alpm_core::deps::Depend;
use alpm_core::package::{Package, PkgFrom};
use pacman_cli::callback::Frontend;
use pacman_cli::conf::Config;
use pacman_cli::util::{Output, Term};

use crate::cli_util::{FRONTEND, config, init};
use crate::cli_util2::stdin;
use crate::conf::ColStrC;
use crate::package::{CDepend, CPkg, CPkgBox};
use crate::pkg_show::{c_strftime_c, columns_cache_reset};
use crate::sandbox::syscall;
use crate::util_common::fmemopen;
use crate::{
	CList, alpm_list_add, alpm_list_free, c_free, cstr, fclose, fflush,
	open_memstream, stderr, stdout,
};

const CLOCK_MONOTONIC_COARSE: c_int = 6;
#[cfg(target_arch = "x86_64")]
const SYS_CLOCK_GETTIME: c_long = 228;
#[cfg(target_arch = "aarch64")]
const SYS_CLOCK_GETTIME: c_long = 113;

#[repr(C)]
pub struct Timespec {
	tv_sec: i64,
	tv_nsec: c_long,
}

unsafe extern "C" {
	pub(crate) fn cb_event(ctx: *mut c_void, event: *mut c_void);
	pub(crate) fn cb_question(ctx: *mut c_void, question: *mut c_void);
	pub(crate) fn cb_progress(
		ctx: *mut c_void,
		event: c_int,
		pkgname: *const c_char,
		percent: c_int,
		howmany: usize,
		current: usize,
	);
	pub(crate) fn cb_download(
		ctx: *mut c_void,
		filename: *const c_char,
		event: c_int,
		data: *mut c_void,
	);
	// va_list passed as a pointer: valid on x86_64 and aarch64
	pub(crate) fn cb_log(
		ctx: *mut c_void,
		level: c_int,
		fmt: *const c_char,
		args: *mut c_void,
	);
	fn multibar_move_completed_up(value: bool);
	fn console_cursor_move_end();
}

// milliseconds CLOCK_MONOTONIC_COARSE reports
static FAKE_MS: AtomicI64 = AtomicI64::new(0);

/// clock_gettime for the whole test binary: the fake clock for
/// CLOCK_MONOTONIC_COARSE (only callback.c's get_time_ms asks for it),
/// the kernel for every other clock (std uses MONOTONIC and REALTIME)
///
/// # Safety
/// callers pass a valid timespec, like for the libc function
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_gettime(clk: c_int, ts: *mut Timespec) -> c_int {
	if clk != CLOCK_MONOTONIC_COARSE {
		// SAFETY: the raw syscall takes the same arguments
		return unsafe { syscall(SYS_CLOCK_GETTIME, clk, ts) } as c_int;
	}
	let ms = FAKE_MS.load(Ordering::SeqCst);
	// SAFETY: see above
	unsafe {
		(*ts).tv_sec = ms.div_euclid(1000);
		(*ts).tv_nsec = (ms.rem_euclid(1000) * 1_000_000) as c_long;
	}
	0
}

// columns getcols reports to both sides for the call
static COLS: AtomicU16 = AtomicU16::new(0);

fn cols() -> u16 {
	COLS.load(Ordering::SeqCst)
}

fn fake_ms() -> i64 {
	FAKE_MS.load(Ordering::SeqCst)
}

// the Rust side's process: the call's input, the same columns and fake
// clock as the C. fmemopen streams and memstreams have no fd: no
// terminal
fn cap_term() -> Term<Cursor<Vec<u8>>> {
	Term {
		cols,
		now_ms: fake_ms,
		..Term::new(Cursor::new(Vec::new()), false, false)
	}
}

type World = Frontend<Cursor<Vec<u8>>>;

static WORLD: Mutex<Option<World>> = Mutex::new(None);

// the process state of one call
#[derive(Clone, Debug)]
pub struct CbSetup {
	pub config: Config,
	pub cols: u16,
	pub now_ms: i64,
	pub input: Vec<u8>,
}

// one callback invocation
pub enum Call<'a> {
	Event(Event<'a>),
	Question(Question<'a>),
	Progress {
		event: Progress,
		pkgname: &'a [u8],
		percent: c_int,
		howmany: usize,
		current: usize,
	},
	Download {
		filename: &'a [u8],
		event: DownloadEvent,
	},
	Log {
		level: LogLevel,
		msg: &'a [u8],
	},
	MoveCompletedUp(bool),
	MoveEnd,
}

// what one side printed, and the question's answer
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CbRun {
	pub stdout: Vec<u8>,
	pub stderr: Vec<u8>,
	pub answer: c_int,
}

// memory the C structs of a call point into, alive for the call. the
// boxes keep each struct at its address while the Vec grows
#[allow(clippy::vec_box)]
#[derive(Default)]
struct Keep {
	strs: Vec<CString>,
	pkgs: Vec<CPkgBox>,
	deps: Vec<Box<CDepend>>,
	dbs: Vec<Box<CDbName>>,
	lists: Vec<*mut CList>,
	boxes: Vec<Box<[u64]>>,
}

impl Drop for Keep {
	fn drop(&mut self) {
		for &l in &self.lists {
			// SAFETY: built by alpm_list_add over data owned here
			unsafe { alpm_list_free(l) };
		}
	}
}

// the leading fields of struct _alpm_db_t alpm_db_get_name reads
#[repr(C)]
struct CDbName {
	handle: *mut c_void,
	treename: *const c_char,
}

impl Keep {
	fn str(&mut self, s: &[u8]) -> *const c_char {
		let c = cstr(s);
		let p = c.as_ptr();
		self.strs.push(c);
		p
	}

	fn opt_str(&mut self, s: Option<&[u8]>) -> *const c_char {
		s.map_or(ptr::null(), |s| self.str(s))
	}

	fn pkg(&mut self, p: &Package) -> *mut CPkg {
		let b = CPkgBox::new(p);
		let raw = b.0;
		self.pkgs.push(b);
		raw
	}

	fn opt_pkg(&mut self, p: Option<&Package>) -> *mut CPkg {
		p.map_or(ptr::null_mut(), |p| self.pkg(p))
	}

	fn db(&mut self, name: &[u8]) -> *mut c_void {
		let treename = self.str(name);
		let mut d = Box::new(CDbName {
			handle: ptr::null_mut(),
			treename,
		});
		let raw: *mut CDbName = &mut *d;
		self.dbs.push(d);
		raw.cast()
	}

	// a package of a sync db: alpm_pkg_get_db finds the db
	fn sync_pkg(&mut self, p: &Package, db: &[u8]) -> *mut CPkg {
		let pkg = Package {
			origin: Some(PkgFrom::SyncDb),
			..p.clone()
		};
		let c = self.pkg(&pkg);
		let db = self.db(db);
		// SAFETY: c is a live package built just now, origin_data of
		// a sync package is the db pointer (not freed by the C)
		unsafe { (*c).origin_data = db };
		c
	}

	fn dep(&mut self, d: &Depend) -> *mut CDepend {
		let name = self.str(&d.name).cast_mut();
		let version = self.opt_str(d.version.as_deref()).cast_mut();
		let desc = self.opt_str(d.desc.as_deref()).cast_mut();
		let mut b = Box::new(CDepend {
			name,
			version,
			desc,
			name_hash: d.name_hash,
			depmod: d.depmod as c_int,
		});
		let raw: *mut CDepend = &mut *b;
		self.deps.push(b);
		raw
	}

	fn list(&mut self, items: Vec<*mut c_void>) -> *mut CList {
		let l = items.into_iter().fold(ptr::null_mut(), |l, x| {
			// SAFETY: l is NULL or built here, x stays owned by Keep
			unsafe { alpm_list_add(l, x) }
		});
		self.lists.push(l);
		l
	}

	// a C struct as 8 byte words: fields are int (4 bytes, paired) or
	// pointers/size_t/off_t (8). the union the C reads is larger, but
	// the callbacks only read the member the type names
	fn words(&mut self, w: Vec<u64>) -> *mut c_void {
		let mut b = w.into_boxed_slice();
		let raw = b.as_mut_ptr().cast();
		self.boxes.push(b);
		raw
	}
}

// type and the first int of a struct in one word (little endian)
fn pair(a: c_int, b: c_int) -> u64 {
	u64::from(a as u32) | (u64::from(b as u32) << 32)
}

fn ptr_word<T>(p: *const T) -> u64 {
	p as usize as u64
}

// the alpm_event_t of e
fn c_event(e: &Event<'_>, k: &mut Keep) -> *mut c_void {
	let t = e.kind();
	let w = match *e {
		Event::PackageOperationStart(op)
		| Event::PackageOperationDone(op) => {
			let old = k.opt_pkg(op.oldpkg);
			let new = k.opt_pkg(op.newpkg);
			vec![
				pair(t, op.operation as c_int),
				ptr_word(old),
				ptr_word(new),
			]
		}
		Event::OptdepRemoval { pkg, optdep } => {
			let p = k.pkg(pkg);
			let d = k.dep(optdep);
			vec![u64::from(t as u32), ptr_word(p), ptr_word(d)]
		}
		Event::ScriptletInfo { line } => {
			vec![u64::from(t as u32), ptr_word(k.str(line))]
		}
		Event::DatabaseMissing { dbname } => {
			vec![u64::from(t as u32), ptr_word(k.str(dbname))]
		}
		Event::PacnewCreated {
			from_noupgrade,
			oldpkg,
			newpkg,
			file,
		} => {
			let old = k.opt_pkg(oldpkg);
			let new = k.pkg(newpkg);
			vec![
				pair(t, c_int::from(from_noupgrade)),
				ptr_word(old),
				ptr_word(new),
				ptr_word(k.str(file)),
			]
		}
		Event::PacsaveCreated { oldpkg, file } => {
			let old = k.pkg(oldpkg);
			vec![
				u64::from(t as u32),
				ptr_word(old),
				ptr_word(k.str(file)),
			]
		}
		Event::HookStart { when } | Event::HookDone { when } => {
			vec![pair(t, when as c_int)]
		}
		Event::HookRunStart(r) | Event::HookRunDone(r) => vec![
			u64::from(t as u32),
			ptr_word(k.str(r.name)),
			ptr_word(k.opt_str(r.desc)),
			r.position as u64,
			r.total as u64,
		],
		Event::PkgRetrieveStart { num, total_size }
		| Event::PkgRetrieveDone { num, total_size }
		| Event::PkgRetrieveFailed { num, total_size } => {
			vec![u64::from(t as u32), num as u64, total_size as u64]
		}
		_ => vec![u64::from(t as u32)],
	};
	k.words(w)
}

// the alpm_question_t of q (answer at the second int)
fn c_question(q: &Question<'_>, k: &mut Keep) -> *mut c_void {
	let head = pair(q.kind(), q.answer());
	let w = match *q {
		Question::InstallIgnorepkg { pkg, .. } => {
			vec![head, ptr_word(k.pkg(pkg))]
		}
		Question::ReplacePkg {
			oldpkg,
			newpkg,
			newdb,
			..
		} => {
			let old = k.pkg(oldpkg);
			let new = k.pkg(newpkg);
			let db = k.db(newdb.name());
			vec![head, ptr_word(old), ptr_word(new), ptr_word(db)]
		}
		Question::ConflictPkg { conflict, .. } => {
			vec![head, ptr_word(c_conflict(conflict, k))]
		}
		Question::CorruptedPkg {
			filepath, reason, ..
		} => vec![
			head,
			ptr_word(k.str(filepath)),
			u64::from(reason as c_int as u32),
		],
		Question::RemovePkgs { packages, .. } => {
			let items = packages
				.iter()
				.map(|p| k.pkg(p).cast())
				.collect();
			vec![head, ptr_word(k.list(items))]
		}
		Question::SelectProvider {
			providers,
			dbs,
			depend,
			..
		} => {
			let items = providers
				.iter()
				.zip(dbs)
				.map(|(p, db)| k.sync_pkg(p, db).cast())
				.collect();
			let l = k.list(items);
			vec![head, ptr_word(l), ptr_word(k.dep(depend))]
		}
		Question::ImportKey {
			uid, fingerprint, ..
		} => vec![
			head,
			ptr_word(k.opt_str(uid)),
			ptr_word(k.str(fingerprint)),
		],
	};
	k.words(w)
}

fn c_conflict(c: &Conflict, k: &mut Keep) -> *mut c_void {
	let p1 = k.pkg(&c.package1);
	let p2 = k.pkg(&c.package2);
	let r = k.dep(&c.reason);
	k.words(vec![ptr_word(p1), ptr_word(p2), ptr_word(r)])
}

// the C data of a download event and its type
fn c_download(e: DownloadEvent, k: &mut Keep) -> (c_int, *mut c_void) {
	match e {
		DownloadEvent::Init { optional } => {
			(0, k.words(vec![u64::from(optional)]))
		}
		DownloadEvent::Progress { downloaded, total } => {
			(1, k.words(vec![downloaded as u64, total as u64]))
		}
		DownloadEvent::Retry { resume } => {
			(2, k.words(vec![u64::from(resume)]))
		}
		DownloadEvent::Completed { total, result } => (
			3,
			k.words(vec![total as u64, u64::from(result as u32)]),
		),
	}
}

// '%' doubled: the message goes in as the format, no argument read
fn as_format(msg: &[u8]) -> Vec<u8> {
	let mut f = Vec::with_capacity(msg.len());
	for &c in msg {
		f.push(c);
		if c == b'%' {
			f.push(b'%');
		}
	}
	f
}

// the config_t fields callback.c reads, and colstr
#[derive(Clone, Copy)]
struct Fields {
	op: u16,
	print: u16,
	noprogressbar: u16,
	chomp: u16,
	op_s_downloadonly: u16,
	op_s_sync: u16,
	noconfirm: u16,
	noask: u16,
	ask: u32,
	logmask: u16,
	colstr: ColStrC,
}

impl Fields {
	fn of(cc: &crate::conf::ConfigC) -> Fields {
		Fields {
			op: cc.op,
			print: cc.print,
			noprogressbar: cc.noprogressbar,
			chomp: cc.chomp,
			op_s_downloadonly: cc.op_s_downloadonly,
			op_s_sync: cc.op_s_sync,
			noconfirm: cc.noconfirm,
			noask: cc.noask,
			ask: cc.ask,
			logmask: cc.logmask,
			colstr: cc.colstr,
		}
	}

	fn put(self, cc: &mut crate::conf::ConfigC) {
		cc.op = self.op;
		cc.print = self.print;
		cc.noprogressbar = self.noprogressbar;
		cc.chomp = self.chomp;
		cc.op_s_downloadonly = self.op_s_downloadonly;
		cc.op_s_sync = self.op_s_sync;
		cc.noconfirm = self.noconfirm;
		cc.noask = self.noask;
		cc.ask = self.ask;
		cc.logmask = self.logmask;
		cc.colstr = self.colstr;
	}
}

// sets the fields from c, returns the old ones
//
// SAFETY (caller): FRONTEND held, config valid
unsafe fn set_config(c: &Config, colstr: &[CString; 10]) -> Fields {
	// SAFETY: see above
	let cc = unsafe { &mut *config };
	let old = Fields::of(cc);
	cc.op = c.op;
	cc.print = c.print;
	cc.noprogressbar = c.noprogressbar;
	cc.chomp = c.chomp;
	cc.op_s_downloadonly = c.op_s_downloadonly;
	cc.op_s_sync = c.op_s_sync;
	cc.noconfirm = c.noconfirm;
	cc.noask = c.noask;
	cc.ask = c.ask;
	cc.logmask = c.logmask;
	cc.colstr = ColStrC {
		colon: colstr[0].as_ptr(),
		title: colstr[1].as_ptr(),
		repo: colstr[2].as_ptr(),
		version: colstr[3].as_ptr(),
		groups: colstr[4].as_ptr(),
		meta: colstr[5].as_ptr(),
		warn: colstr[6].as_ptr(),
		err: colstr[7].as_ptr(),
		faint: colstr[8].as_ptr(),
		nocolor: colstr[9].as_ptr(),
	};
	old
}

// the C callback for call, its data built in k
//
// SAFETY (caller): FRONTEND held, streams and config set up
unsafe fn call_c(call: &Call<'_>, k: &mut Keep) -> c_int {
	let ctx = ptr::null_mut();
	// SAFETY: every pointer handed over points into k, alive for the
	// call; the C reads them only. for questions the answer is read
	// back from the struct the C wrote
	unsafe {
		match call {
			Call::Event(e) => cb_event(ctx, c_event(e, k)),
			Call::Question(q) => {
				let p = c_question(q, k);
				cb_question(ctx, p);
				return *p.cast::<c_int>().add(1);
			}
			Call::Progress {
				event,
				pkgname,
				percent,
				howmany,
				current,
			} => cb_progress(
				ctx,
				*event as c_int,
				k.str(pkgname),
				*percent,
				*howmany,
				*current,
			),
			Call::Download { filename, event } => {
				let (t, data) = c_download(*event, k);
				cb_download(ctx, k.str(filename), t, data);
			}
			Call::Log { level, msg } => {
				let fmt = k.str(&as_format(msg));
				let mut va = [0u64; 4];
				cb_log(
					ctx,
					*level as c_int,
					fmt,
					va.as_mut_ptr().cast(),
				);
			}
			Call::MoveCompletedUp(v) => {
				multibar_move_completed_up(*v)
			}
			Call::MoveEnd => console_cursor_move_end(),
		}
	}
	0
}

fn call_rust(w: &mut World, call: &mut Call<'_>) -> c_int {
	use alpm_core::callbacks::Callbacks;
	match call {
		Call::Event(e) => w.event(e),
		Call::Question(q) => {
			w.question(q);
			return q.answer();
		}
		Call::Progress {
			event,
			pkgname,
			percent,
			howmany,
			current,
		} => w.progress(*event, pkgname, *percent, *howmany, *current),
		Call::Download { filename, event } => {
			w.download(filename, *event)
		}
		Call::Log { level, msg } => w.log(*level, msg),
		Call::MoveCompletedUp(v) => w.multibar_move_completed_up(*v),
		Call::MoveEnd => w.console_cursor_move_end(),
	}
	0
}

// runs call on the C callbacks and the shared Rust Frontend with the
// same setup: (C, Rust). a question's answer field is reset to its
// value before the Rust call. C preconditions: download events only for
// files the bars know (Frontend::multibar) when bars are on, valid
// UTF-8 texts whose characters glibc and unicode-width size alike
pub fn cb_both(setup: &CbSetup, mut call: Call<'_>) -> (CbRun, CbRun) {
	init();
	// TZ=UTC once
	c_strftime_c(0);
	let _guard = FRONTEND.lock().unwrap_or_else(|e| e.into_inner());
	let mut world = WORLD.lock().unwrap_or_else(|e| e.into_inner());
	let w = world.get_or_insert_with(|| {
		Frontend::new(Config::new(), cap_term())
	});
	let cs = &setup.config.colstr;
	let colstr = [
		cs.colon, cs.title, cs.repo, cs.version, cs.groups, cs.meta,
		cs.warn, cs.err, cs.faint, cs.nocolor,
	]
	.map(cstr);
	let answer0 = match &call {
		Call::Question(q) => q.answer(),
		_ => 0,
	};
	FAKE_MS.store(setup.now_ms, Ordering::SeqCst);
	COLS.store(setup.cols, Ordering::SeqCst);
	let mut k = Keep::default();
	let (mut obuf, mut osize) = (ptr::null_mut(), 0usize);
	let (mut ebuf, mut esize) = (ptr::null_mut(), 0usize);
	let mut input = setup.input.clone();
	// fmemopen wants a buffer even for no input
	input.push(0);
	// SAFETY: FRONTEND serializes config, the std streams, stdin and
	// COLUMNS for every frontend call of this crate. the colstr strings
	// and k outlive the call, config is reset before they drop. the
	// memstreams and the fmemopen stream replace the streams only while
	// the callback runs, their buffers are malloc'd (memstreams, valid
	// for size bytes after fclose) or ours (input, alive until fclose)
	let c = unsafe {
		std::env::set_var("COLUMNS", setup.cols.to_string());
		columns_cache_reset();
		let old = set_config(&setup.config, &colstr);
		let out = open_memstream(&mut obuf, &mut osize);
		let err = open_memstream(&mut ebuf, &mut esize);
		let inp = fmemopen(
			input.as_mut_ptr().cast(),
			setup.input.len(),
			c"r".as_ptr(),
		);
		assert!(!out.is_null() && !err.is_null() && !inp.is_null());
		let (real_out, real_err, real_in) = (stdout, stderr, stdin);
		fflush(real_out);
		fflush(real_err);
		stdout = out;
		stderr = err;
		stdin = inp;
		let answer = call_c(&call, &mut k);
		fflush(out);
		fflush(err);
		stdout = real_out;
		stderr = real_err;
		stdin = real_in;
		fclose(out);
		fclose(err);
		fclose(inp);
		old.put(&mut *config);
		let o = std::slice::from_raw_parts(obuf.cast::<u8>(), osize)
			.to_vec();
		let e = std::slice::from_raw_parts(ebuf.cast::<u8>(), esize)
			.to_vec();
		c_free(obuf.cast());
		c_free(ebuf.cast());
		CbRun {
			stdout: o,
			stderr: e,
			answer,
		}
	};
	if let Call::Question(q) = &mut call {
		q.set_answer(answer0);
	}
	w.config = setup.config.clone();
	w.out = Output::default();
	w.term.stdin = Cursor::new(setup.input.clone());
	let answer = call_rust(w, &mut call);
	let out = std::mem::take(&mut w.out);
	let r = CbRun {
		stdout: out.stdout,
		stderr: out.stderr,
		answer,
	};
	(c, r)
}

// the files the Rust bars know, in bar order (the C knows the same)
pub fn cb_active_bars() -> Vec<Vec<u8>> {
	let world = WORLD.lock().unwrap_or_else(|e| e.into_inner());
	world.as_ref().map_or_else(Vec::new, |w| {
		w.multibar()
			.active
			.iter()
			.map(|b| b.filename.clone())
			.collect()
	})
}
