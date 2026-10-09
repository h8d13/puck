// C side of lib/libalpm/sandbox.c, sandbox_fs.c, sandbox_syscalls.c, and
// the probes the sandbox tests run in their child processes.
//
// a CSandbox is one alpm_initialize'd handle whose log and download
// callbacks record every call (all log levels, the raw event values) as
// CbRec, the same shape SbRecorder gives on the Rust side. the pipe
// protocol runs on a scratch file: the C reads it through its fd, the
// parent loop of curl_download_internal_sandboxed (static, in dload.c)
// is copied here around the two exported process functions.
//
// restrictions are only ever applied in a child process spawned for one
// probe run, never in the test harness itself.
use std::ffi::{CString, c_char, c_int, c_long, c_uint, c_void};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;
use std::ptr;
use std::sync::MutexGuard;

use alpm_core::callbacks::{Callbacks, DownloadEvent, LogLevel};

use crate::cstr;
use crate::handle::log_message;
use crate::handle::{
	ALPM, alpm_initialize, alpm_option_set_dlcb, alpm_option_set_logcb,
	alpm_release,
};
use crate::package::text;

unsafe extern "C" {
	fn _alpm_sandbox_fs_restrict_writes_to(
		handle: *mut c_void,
		path: *const c_char,
	) -> bool;
	fn _alpm_sandbox_syscalls_filter(handle: *mut c_void) -> bool;
	fn alpm_sandbox_setup_child(
		handle: *mut c_void,
		sandboxuser: *const c_char,
		sandbox_path: *const c_char,
		restrict_syscalls: bool,
	) -> c_int;
	fn _alpm_sandbox_process_cb_log(
		handle: *mut c_void,
		callback_pipe: c_int,
	) -> bool;
	fn _alpm_sandbox_process_cb_download(
		handle: *mut c_void,
		callback_pipe: c_int,
	) -> bool;
	fn _alpm_sandbox_cb_log(
		ctx: *mut c_void,
		level: c_int,
		fmt: *const c_char,
		args: *mut c_void,
	);
	fn _alpm_sandbox_cb_dl(
		ctx: *mut c_void,
		filename: *const c_char,
		event: c_int,
		data: *mut c_void,
	);
	fn _alpm_log(handle: *mut c_void, flag: c_int, fmt: *const c_char, ...);

	// libc
	pub(crate) fn syscall(number: c_long, ...) -> c_long;
	fn prctl(option: c_int, ...) -> c_int;
	fn mkfifo(path: *const c_char, mode: c_uint) -> c_int;

	// libseccomp, for failures injected into the landlock calls
	fn seccomp_init(def_action: u32) -> *mut c_void;
	fn seccomp_rule_add_array(
		ctx: *mut c_void,
		action: u32,
		syscall: c_int,
		arg_cnt: c_uint,
		arg_array: *const ScmpArgCmp,
	) -> c_int;
	fn seccomp_load(ctx: *mut c_void) -> c_int;
	fn seccomp_release(ctx: *mut c_void);
	fn seccomp_syscall_resolve_name(name: *const c_char) -> c_int;
}

// struct scmp_arg_cmp, seccomp.h
#[repr(C)]
struct ScmpArgCmp {
	arg: c_uint,
	op: c_int,
	datum_a: u64,
	datum_b: u64,
}

const PR_SET_NO_NEW_PRIVS: c_int = 38;
const SCMP_ACT_ALLOW: u32 = 0x7fff_0000;
const SCMP_ACT_ERRNO: u32 = 0x0005_0000;
const SCMP_CMP_EQ: c_int = 4;

// _alpm_sandbox_callback_context
#[repr(C)]
struct CbContext {
	callback_pipe: c_int,
}

// a callback as both sides see it: log level and text, or the download
// file name, event type and the event's two values (bools as 0/1)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CbRec {
	Log(c_int, Vec<u8>),
	Dl(Vec<u8>, c_int, i64, i64),
}

impl CbRec {
	pub fn download(name: &[u8], e: DownloadEvent) -> CbRec {
		let (kind, a, b) = match e {
			DownloadEvent::Init { optional } => {
				(0, optional.into(), 0)
			}
			DownloadEvent::Progress { downloaded, total } => {
				(1, downloaded, total)
			}
			DownloadEvent::Retry { resume } => {
				(2, resume.into(), 0)
			}
			DownloadEvent::Completed { total, result } => {
				(3, total, result.into())
			}
		};
		CbRec::Dl(name.to_vec(), kind, a, b)
	}
}

// the Rust side's callbacks, recording like the C ones
#[derive(Default)]
pub struct SbRecorder(pub Vec<CbRec>);

impl Callbacks for SbRecorder {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		self.0.push(CbRec::Log(level as c_int, msg.to_vec()));
	}

	fn download(&mut self, filename: &[u8], event: DownloadEvent) {
		self.0.push(CbRec::download(filename, event));
	}
}

unsafe extern "C" fn log_cb(
	ctx: *mut c_void,
	level: c_int,
	fmt: *const c_char,
	args: *mut c_void,
) {
	// SAFETY: fmt and args are the pair this callback got
	let msg = unsafe { log_message(fmt, args) };
	// SAFETY: ctx is the CSandbox's boxed SbRecorder
	let rec = unsafe { &mut *ctx.cast::<SbRecorder>() };
	rec.0.push(CbRec::Log(level, msg));
}

unsafe extern "C" fn dl_cb(
	ctx: *mut c_void,
	filename: *const c_char,
	event: c_int,
	data: *mut c_void,
) {
	// SAFETY: data is the alpm_download_event_*_t of the event type:
	// an int first (init, retry) or off_t fields (progress, completed)
	let (a, b) = unsafe {
		match event {
			0 | 2 => (*data.cast::<c_int>() as i64, 0),
			1 => {
				let p = data.cast::<[i64; 2]>();
				((*p)[0], (*p)[1])
			}
			_ => {
				let p = data.cast::<i64>();
				(*p, *p.add(1).cast::<c_int>() as i64)
			}
		}
	};
	// SAFETY: ctx is the CSandbox's boxed SbRecorder
	let rec = unsafe { &mut *ctx.cast::<SbRecorder>() };
	rec.0.push(CbRec::Dl(text(filename), event, a, b));
}

// the alpm_download_event_*_t of kind: zeroed (padding included),
// 8-aligned, an int in the first 4 bytes or off_t fields
fn event_data(kind: c_int, a: i64, b: i64) -> [u64; 2] {
	let int = |v: i64| {
		let mut w = [0u8; 8];
		w[..4].copy_from_slice(&(v as c_int).to_ne_bytes());
		u64::from_ne_bytes(w)
	};
	match kind {
		1 => [a as u64, b as u64],
		3 => [a as u64, int(b)],
		_ => [int(a), 0],
	}
}

pub struct CSandbox {
	h: *mut c_void,
	// boxed: the C keeps its address
	rec: Box<SbRecorder>,
	_guard: MutexGuard<'static, ()>,
}

impl Drop for CSandbox {
	fn drop(&mut self) {
		// SAFETY: h came from alpm_initialize, nothing uses it after
		unsafe { alpm_release(self.h) };
	}
}

impl CSandbox {
	// a handle on <dir>/root and <dir>/db with recording callbacks
	pub fn new(dir: &Path) -> CSandbox {
		let guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		fs::create_dir_all(dir.join("root")).unwrap();
		fs::create_dir_all(dir.join("db")).unwrap();
		let p = |rel: &str| cstr(dir.join(rel).as_os_str().as_bytes());
		let (root, db) = (p("root"), p("db"));
		let mut err = 0;
		// SAFETY: valid C strings, err is writable
		let h = unsafe {
			alpm_initialize(root.as_ptr(), db.as_ptr(), &mut err)
		};
		assert!(!h.is_null(), "alpm_initialize: {err}");
		let mut rec = Box::new(SbRecorder::default());
		let c: *mut SbRecorder = &mut *rec;
		// SAFETY: h is live, rec is boxed and outlives the handle
		unsafe {
			alpm_option_set_logcb(h, Some(log_cb), c.cast());
			alpm_option_set_dlcb(h, Some(dl_cb), c.cast());
		}
		CSandbox {
			h,
			rec,
			_guard: guard,
		}
	}

	pub fn take(&mut self) -> Vec<CbRec> {
		std::mem::take(&mut self.rec.0)
	}

	// _alpm_sandbox_fs_restrict_writes_to
	pub fn restrict_writes_to(&mut self, path: &[u8]) -> bool {
		let p = cstr(path);
		// SAFETY: h is live, p a C string
		unsafe {
			_alpm_sandbox_fs_restrict_writes_to(self.h, p.as_ptr())
		}
	}

	// _alpm_sandbox_syscalls_filter
	pub fn syscalls_filter(&mut self) -> bool {
		// SAFETY: h is live
		unsafe { _alpm_sandbox_syscalls_filter(self.h) }
	}

	// alpm_sandbox_setup_child; only called where getuid() != 0, so it
	// stops at its root check and never switches users
	pub fn setup_child(
		&mut self,
		user: &[u8],
		path: Option<&[u8]>,
		restrict_syscalls: bool,
	) -> c_int {
		let u = cstr(user);
		let p = path.map(cstr);
		let pp = p.as_ref().map_or(ptr::null(), |p| p.as_ptr());
		// SAFETY: h is live, u a C string, pp NULL or a C string
		unsafe {
			alpm_sandbox_setup_child(
				self.h,
				u.as_ptr(),
				pp,
				restrict_syscalls,
			)
		}
	}

	// the parent loop of curl_download_internal_sandboxed over stream:
	// the callbacks made and how many bytes were consumed. scratch is a
	// file path to hold the stream
	pub fn process_stream(
		&mut self,
		stream: &[u8],
		scratch: &Path,
	) -> (Vec<CbRec>, u64) {
		fs::write(scratch, stream).unwrap();
		let mut f = File::open(scratch).unwrap();
		let fd = f.as_raw_fd();
		loop {
			// one read() of the type, like the C
			let mut t = [0u8; 4];
			match f.read(&mut t) {
				Ok(4) => {}
				_ => break,
			}
			// SAFETY: h is live, fd an open file the C reads from
			let ok = match u32::from_ne_bytes(t) {
				1 => unsafe {
					_alpm_sandbox_process_cb_download(
						self.h, fd,
					)
				},
				0 => unsafe {
					_alpm_sandbox_process_cb_log(self.h, fd)
				},
				_ => true,
			};
			if !ok {
				break;
			}
		}
		let used = f.stream_position().unwrap();
		(self.take(), used)
	}

	// the C child's callbacks: logs through _alpm_log with
	// _alpm_sandbox_cb_log as logcb, downloads through
	// _alpm_sandbox_cb_dl, written to scratch and read back
	pub fn write_stream(
		&mut self,
		recs: &[CbRec],
		scratch: &Path,
	) -> Vec<u8> {
		let f = File::create(scratch).unwrap();
		let mut ctx = CbContext {
			callback_pipe: f.as_raw_fd(),
		};
		let c: *mut CbContext = &mut ctx;
		// SAFETY: h is live, ctx outlives every log call below
		unsafe {
			alpm_option_set_logcb(
				self.h,
				Some(_alpm_sandbox_cb_log),
				c.cast(),
			);
		}
		for r in recs {
			match r {
				CbRec::Log(level, msg) => {
					let m = CString::new(msg.clone())
						.unwrap();
					// SAFETY: h is live, "%s" with one C string
					unsafe {
						_alpm_log(
							self.h,
							*level,
							c"%s".as_ptr(),
							m.as_ptr(),
						)
					};
				}
				CbRec::Dl(name, kind, a, b) => {
					let mut data =
						event_data(*kind, *a, *b);
					let n = CString::new(name.clone())
						.unwrap();
					// SAFETY: ctx holds an open fd, n a C string,
					// data the event struct of kind
					unsafe {
						_alpm_sandbox_cb_dl(
							c.cast(),
							n.as_ptr(),
							*kind,
							data.as_mut_ptr()
								.cast(),
						)
					};
				}
			}
		}
		let r: *mut SbRecorder = &mut *self.rec;
		// SAFETY: h is live, back to the recording callback
		unsafe {
			alpm_option_set_logcb(self.h, Some(log_cb), r.cast())
		};
		drop(f);
		fs::read(scratch).unwrap()
	}
}

// prctl(PR_SET_NO_NEW_PRIVS, 1): landlock_restrict_self needs it
// without CAP_SYS_ADMIN
pub fn no_new_privs() -> bool {
	// SAFETY: plain prctl with integer arguments
	unsafe {
		prctl(
			PR_SET_NO_NEW_PRIVS,
			1 as c_long,
			0 as c_long,
			0 as c_long,
			0 as c_long,
		) == 0
	}
}

// seccomp_syscall_resolve_name, negative where the arch lacks it
pub fn syscall_nr(name: &str) -> c_int {
	let n = cstr(name.as_bytes());
	// SAFETY: n is a C string
	unsafe { seccomp_syscall_resolve_name(n.as_ptr()) }
}

// loads a filter making each named syscall fail with its errno, when
// its third argument equals the value if one is given
pub fn inject_errors(rules: &[(&str, c_int, Option<u64>)]) {
	// SAFETY: the context is used and released here only; the arg
	// arrays live across their calls
	unsafe {
		let ctx = seccomp_init(SCMP_ACT_ALLOW);
		assert!(!ctx.is_null());
		for &(name, errno, arg2) in rules {
			let cmp = ScmpArgCmp {
				arg: 2,
				op: SCMP_CMP_EQ,
				datum_a: arg2.unwrap_or(0),
				datum_b: 0,
			};
			let (cnt, args) = match arg2 {
				Some(_) => (1, &cmp as *const ScmpArgCmp),
				None => (0, ptr::null()),
			};
			let action = SCMP_ACT_ERRNO | errno as u32;
			let rc = seccomp_rule_add_array(
				ctx,
				action,
				syscall_nr(name),
				cnt,
				args,
			);
			assert_eq!(rc, 0, "rule for {name}");
		}
		assert_eq!(seccomp_load(ctx), 0);
		seccomp_release(ctx);
	}
}

fn errno_of<T>(r: io::Result<T>) -> i32 {
	match r {
		Ok(_) => 0,
		Err(e) => e.raw_os_error().unwrap_or(-1),
	}
}

// arguments that are harmless whether the syscall is filtered or not,
// as any user: mostly bad pointers (1), else no-ops and queries
fn probe_args(name: &str) -> [c_long; 6] {
	match name {
		// query, no change
		"personality" => [0xffff_ffff, 0, 0, 0, 0, 0],
		// lowering to the current level, clearing no ports
		"iopl" | "ioperm" => [0; 6],
		// bad fds, unknown flags (no KEXEC_FILE_UNLOAD)
		"kexec_file_load" => [-1, -1, 0, 0, 1 << 30, 0],
		"finit_module" => [-1, 1, 0, 0, 0, 0],
		// no such operation
		"keyctl" => [-1, 0, 0, 0, 0, 0],
		// read 0 bytes of the LDT
		"modify_ldt" => [0, 1, 0, 0, 0, 0],
		_ => [1; 6],
	}
}

// each named syscall the arch has, issued raw: 0 or its errno.
// chroot is issued through std as well
pub fn syscall_probes(names: &[String]) -> Vec<(String, i32)> {
	let mut out = Vec::new();
	for name in names {
		let nr = syscall_nr(name);
		if nr < 0 {
			continue;
		}
		let a = probe_args(name);
		// SAFETY: arguments per probe_args, none points to memory
		let r = unsafe {
			syscall(
				nr as c_long,
				a[0],
				a[1],
				a[2],
				a[3],
				a[4],
				a[5],
			)
		};
		let e = match r {
			-1 => io::Error::last_os_error()
				.raw_os_error()
				.unwrap(),
			_ => 0,
		};
		out.push((name.clone(), e));
	}
	let r = std::os::unix::fs::chroot("/nonexistent-difftest");
	out.push(("std chroot".into(), errno_of(r)));
	out
}

// the files the fs probes work on: a/ is the writable dir, b/ outside
pub fn fs_probe_setup(a: &Path, b: &Path) {
	for d in [a.join("emptydir"), a.join("sub"), b.to_path_buf()] {
		fs::create_dir_all(d).unwrap();
	}
	for f in ["f_in", "del", "f_ren", "f_mv", "f_out"] {
		fs::write(a.join(f), b"data").unwrap();
	}
	for f in ["f_out", "del"] {
		fs::write(b.join(f), b"data").unwrap();
	}
}

fn write_open(p: &Path, truncate: bool) -> io::Result<File> {
	OpenOptions::new().write(true).truncate(truncate).open(p)
}

fn make_fifo(p: &Path) -> io::Result<()> {
	let c = cstr(p.as_os_str().as_bytes());
	// SAFETY: c is a C string
	match unsafe { mkfifo(c.as_ptr(), 0o644) } {
		0 => Ok(()),
		_ => Err(io::Error::last_os_error()),
	}
}

// writes inside and outside a/, reads, exec: 0 or the errno per probe
pub fn fs_probes(a: &Path, b: &Path) -> Vec<(&'static str, i32)> {
	let probes: Vec<(&str, io::Result<()>)> = vec![
		("create inside", File::create(a.join("new")).map(drop)),
		("write inside", write_open(&a.join("f_in"), false).map(drop)),
		(
			"ftruncate inside",
			write_open(&a.join("f_in"), false)
				.and_then(|f| f.set_len(1)),
		),
		(
			"O_TRUNC inside",
			write_open(&a.join("f_in"), true).map(drop),
		),
		("mkdir inside", fs::create_dir(a.join("d"))),
		("rmdir inside", fs::remove_dir(a.join("emptydir"))),
		("unlink inside", fs::remove_file(a.join("del"))),
		("symlink inside", symlink("x", a.join("sym"))),
		("mkfifo inside", make_fifo(&a.join("fifo"))),
		(
			"rename in dir",
			fs::rename(a.join("f_ren"), a.join("f_ren2")),
		),
		(
			"rename across dirs inside",
			fs::rename(a.join("f_mv"), a.join("sub/f_mv")),
		),
		("link in dir", fs::hard_link(a.join("f_in"), a.join("ln"))),
		(
			"link across dirs inside",
			fs::hard_link(a.join("f_in"), a.join("sub/ln")),
		),
		("mkdir nested", fs::create_dir(a.join("sub/deep"))),
		(
			"create nested",
			File::create(a.join("sub/deep/f")).map(drop),
		),
		("create outside", File::create(b.join("new")).map(drop)),
		(
			"write outside",
			write_open(&b.join("f_out"), false).map(drop),
		),
		(
			"O_TRUNC outside",
			write_open(&b.join("f_out"), true).map(drop),
		),
		("read outside", fs::read(b.join("f_out")).map(drop)),
		(
			"readdir outside",
			fs::read_dir(b).and_then(|mut d| {
				d.try_for_each(|e| e.map(drop))
			}),
		),
		("mkdir outside", fs::create_dir(b.join("d"))),
		("unlink outside", fs::remove_file(b.join("del"))),
		(
			"rename out of the dir",
			fs::rename(a.join("f_in"), b.join("moved")),
		),
		(
			"write /dev/null",
			write_open(Path::new("/dev/null"), false).map(drop),
		),
		("read /etc/passwd", fs::read("/etc/passwd").map(drop)),
		("exec", Command::new("/usr/bin/true").status().map(drop)),
	];
	probes.into_iter().map(|(n, r)| (n, errno_of(r))).collect()
}

// one probe result per line
pub fn probe_lines<N: AsRef<str>>(r: &[(N, i32)]) -> String {
	let mut s = String::new();
	for (n, e) in r {
		s.push_str(&format!("{}\t{e}\n", n.as_ref()));
	}
	s
}

// pretends to be root (getuid 0), every sandbox user is the current
// user: the parent side runs as it would as root, the helper as us
pub struct RootHost;

impl alpm_core::sandbox::Host for RootHost {
	fn uid(&self) -> u32 {
		0
	}

	fn getpwnam(
		&self,
		_user: &[u8],
	) -> Result<(u32, u32), Option<io::Error>> {
		let uid = rustix::process::getuid().as_raw();
		Ok((uid, rustix::process::getgid().as_raw()))
	}

	fn raise(&mut self, _sig: c_int) {}
}

// target/<profile>/deps/<test>-<hash> -> target/<profile>/<name>
pub fn sibling_bin(name: &str) -> std::path::PathBuf {
	let exe = std::env::current_exe().unwrap();
	exe.parent().unwrap().parent().unwrap().join(name)
}

// run_chroot's child for a Rust handle in tests: Handle's default,
// /proc/self/exe, is the test binary here
pub fn test_chroot_helper() -> std::path::PathBuf {
	sibling_bin("sandbox-helper")
}

// a HelperSandbox running difftest's sandbox-helper (instead of
// /proc/self/exe, it ends itself after 60 s) on RootHost
pub fn test_helper(
	user: &[u8],
	disable_fs: bool,
	disable_syscalls: bool,
) -> alpm_core::sandbox::HelperSandbox {
	let mut sb = alpm_core::sandbox::HelperSandbox::new(
		user,
		disable_fs,
		disable_syscalls,
	);
	sb.program = sibling_bin("sandbox-helper");
	sb.host = Box::new(RootHost);
	sb
}

// Handle::set_sandbox_for of tests: _alpm_use_sandbox as for root, the
// download in test_helper
pub fn test_sandbox_for(
	h: &alpm_core::handle::Handle,
) -> Option<Box<dyn alpm_core::dload::Sandbox>> {
	let user = h.sandboxuser()?;
	let fs = h.disable_sandbox_filesystem() != 0;
	let sc = h.disable_sandbox_syscalls() != 0;
	alpm_core::sandbox::use_sandbox(0, Some(user), fs, sc)
		.then(|| Box::new(test_helper(user, fs, sc)) as _)
}
