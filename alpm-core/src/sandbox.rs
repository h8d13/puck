// port of lib/libalpm/sandbox.c, plus the sandboxed download of dload.c
// (curl_download_internal_sandboxed) as a dload::Sandbox
//
// the C forks, restricts the child (landlock, no_new_privs, seccomp),
// switches it to the DownloadUser and runs curl there; the parent reads
// the child's log and download callbacks from a pipe. here the child is
// a helper process: the running binary (helper_program) executed again
// with HELPER_ARG, as the DownloadUser through CommandExt::uid/gid (std
// calls setgid, setgroups(0), setuid before the exec, the C's order).
// the request
// (handle options, server error counts, payloads) goes over the helper's
// stdin, the callbacks come back over its stdout in the C's pipe format.
// a thread cannot be used: uid, landlock and seccomp would apply to the
// whole process or to its threads, not to one download.
//
// the binary provides the entry: pacman's main starts with
//	if let Some(code) = alpm_core::sandbox::helper_entry() {
//		std::process::exit(code);
//	}
//
// steps the C runs in the child as root run in the helper as the
// DownloadUser: chdir, no_new_privs (first, landlock_restrict_self needs
// it without CAP_SYS_ADMIN), landlock, seccomp. getuid() == 0 and
// getpwnam are checked by the parent before spawning. SIGINT/SIGQUIT
// count as ignored in the parent while the helper runs (IgnoreSignals).
use std::ffi::{OsStr, OsString, c_int};
use std::fs::{self, File};
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::net::Shutdown;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use rustix::fs::{Access, access};
use rustix::net::{
	RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags,
	SendAncillaryBuffer, SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};

use crate::callbacks::{Callbacks, DownloadEvent, LogLevel};
use crate::dload::{
	DownloadState, Payload, Sandbox, Settings, download_internal,
};
use crate::error::Errno;
use crate::handle::Handle;
use crate::sandbox_fs::restrict_writes_to;
use crate::sandbox_syscalls::syscalls_filter;
use crate::util::{PATH_MAX, getuid, until_nul};

/// argv[1] of the helper: a download, a command to exec as the sandbox
/// user (EXEC_ARG), or the child of util::run_chroot (CHROOT_ARG ROOT CMD
/// ARGV...)
pub const HELPER_ARG: &str = "--alpm-sandbox-helper";
pub const EXEC_ARG: &str = "--alpm-sandbox-exec";
pub const CHROOT_ARG: &str = "--alpm-chroot-exec";

/// _alpm_sandbox_callback_t
pub const CB_LOG: u32 = 0;
pub const CB_DOWNLOAD: u32 = 1;

// alpm_download_event_type_t
const DL_INIT: u32 = 0;
const DL_PROGRESS: u32 = 1;
const DL_RETRY: u32 = 2;
const DL_COMPLETED: u32 = 3;

// the alpm_download_event_*_t structs, for their C sizes (padding
// included): the pipe carries them raw
#[repr(C)]
struct EventInit(c_int);
#[repr(C)]
struct EventProgress(i64, i64);
#[repr(C)]
struct EventRetry(c_int);
#[repr(C)]
struct EventCompleted(i64, c_int);

/// _alpm_use_sandbox: handle->user root and a sandbox user. the
/// DownloadUser child and its private download dir stay when both
/// restrictions are disabled, setup_child skips each on its own
pub fn use_sandbox(user: u32, sandboxuser: Option<&[u8]>) -> bool {
	user == 0 && sandboxuser.is_some()
}

/// _alpm_sandbox_cb_log and _alpm_sandbox_cb_dl, the callbacks of the
/// child: every message goes to the pipe. the C child sets eventcb to
/// NULL, events are dropped. write errors are ignored like the C's
pub struct CallbackWriter<W: Write>(pub W);

impl<W: Write> CallbackWriter<W> {
	// the type in a write of its own like the C: a write of at most
	// PIPE_BUF bytes is atomic, so the reader's single read() of the
	// type never sees part of it
	fn send(&mut self, kind: u32, body: &[u8]) {
		if self.0.write_all(&kind.to_ne_bytes()).is_ok() {
			let _ = self.0.write_all(body);
		}
	}
}

impl<W: Write> Callbacks for CallbackWriter<W> {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		// vsnprintf gave 0 bytes: nothing sent. the int size bounds
		// the message
		let Ok(size) = c_int::try_from(msg.len()) else {
			return;
		};
		if size == 0 {
			return;
		}
		let body = [
			&(level as c_int).to_ne_bytes()[..],
			&size.to_ne_bytes(),
			msg,
		]
		.concat();
		self.send(CB_LOG, &body);
	}

	fn download(&mut self, filename: &[u8], event: DownloadEvent) {
		let mut body = Vec::new();
		let (kind, size) = match event {
			DownloadEvent::Init { optional } => {
				body.extend(c_int::from(optional).to_ne_bytes());
				(DL_INIT, size_of::<EventInit>())
			}
			DownloadEvent::Progress { downloaded, total } => {
				body.extend(downloaded.to_ne_bytes());
				body.extend(total.to_ne_bytes());
				(DL_PROGRESS, size_of::<EventProgress>())
			}
			DownloadEvent::Retry { resume } => {
				body.extend(c_int::from(resume).to_ne_bytes());
				(DL_RETRY, size_of::<EventRetry>())
			}
			DownloadEvent::Completed { total, result } => {
				body.extend(total.to_ne_bytes());
				body.extend(result.to_ne_bytes());
				(DL_COMPLETED, size_of::<EventCompleted>())
			}
		};
		// struct padding as zeros, the C copies the caller's struct as is
		body.resize(size, 0);
		let name = until_nul(filename);
		let msg = [
			&kind.to_ne_bytes()[..],
			&body,
			&name.len().to_ne_bytes(),
			name,
		]
		.concat();
		self.send(CB_DOWNLOAD, &msg);
	}
}

// read_from_pipe: all of buf, EINTR retried, EOF is an error
fn read_u32(r: &mut dyn Read) -> Option<u32> {
	let mut b = [0; 4];
	r.read_exact(&mut b).ok()?;
	Some(u32::from_ne_bytes(b))
}

// exactly n bytes, without allocating n up front (n comes from the
// stream)
fn read_n(r: &mut dyn Read, n: u64) -> Option<Vec<u8>> {
	let mut v = Vec::new();
	r.take(n).read_to_end(&mut v).ok()?;
	(v.len() as u64 == n).then_some(v)
}

fn level_of(raw: u32) -> Option<LogLevel> {
	Some(match raw {
		1 => LogLevel::Error,
		2 => LogLevel::Warning,
		4 => LogLevel::Debug,
		8 => LogLevel::Function,
		_ => return None,
	})
}

/// _alpm_sandbox_process_cb_log: level, int size (> 0), the text, logged
/// through "%s" (cut at a nul). a level that is no alpm_loglevel_t value
/// is read and dropped: the C passes it on to logcb
pub fn process_cb_log(r: &mut dyn Read, cb: &mut dyn Callbacks) -> bool {
	let Some(level) = read_u32(r) else {
		return false;
	};
	let Some(size) = read_u32(r) else {
		return false;
	};
	let size = size as c_int;
	if size <= 0 {
		return false;
	}
	let Some(msg) = read_n(r, size as u64) else {
		return false;
	};
	if let Some(level) = level_of(level) {
		cb.log(level, until_nul(&msg));
	}
	true
}

/// _alpm_sandbox_process_cb_download: event type, its struct, size_t
/// name length (< PATH_MAX), the name (cut at a nul), then dlcb. an
/// empty name breaks the stream: read_from_pipe refuses 0 bytes
pub fn process_cb_download(r: &mut dyn Read, cb: &mut dyn Callbacks) -> bool {
	let Some(kind) = read_u32(r) else {
		return false;
	};
	let size = match kind {
		DL_INIT => size_of::<EventInit>(),
		DL_PROGRESS => size_of::<EventProgress>(),
		DL_RETRY => size_of::<EventRetry>(),
		DL_COMPLETED => size_of::<EventCompleted>(),
		_ => return false,
	};
	let Some(raw) = read_n(r, size as u64) else {
		return false;
	};
	let int = |at: usize| {
		let b: [u8; 4] = raw[at..at + 4].try_into().unwrap();
		c_int::from_ne_bytes(b)
	};
	let long = |at: usize| {
		let b: [u8; 8] = raw[at..at + 8].try_into().unwrap();
		i64::from_ne_bytes(b)
	};
	let event = match kind {
		DL_INIT => DownloadEvent::Init {
			optional: int(0) != 0,
		},
		DL_PROGRESS => DownloadEvent::Progress {
			downloaded: long(0),
			total: long(8),
		},
		DL_RETRY => DownloadEvent::Retry {
			resume: int(0) != 0,
		},
		_ => DownloadEvent::Completed {
			total: long(0),
			result: int(8),
		},
	};
	let mut b = [0; size_of::<usize>()];
	if r.read_exact(&mut b).is_err() {
		return false;
	}
	let len = usize::from_ne_bytes(b);
	if len >= PATH_MAX || len == 0 {
		return false;
	}
	let Some(name) = read_n(r, len as u64) else {
		return false;
	};
	cb.download(until_nul(&name), event);
	true
}

/// the parent loop of curl_download_internal_sandboxed: callbacks until
/// the stream ends or breaks. the type comes from one read() like the C
/// (a short or failed read ends the loop), unknown types are skipped.
/// the C's loop only ends in error, so it has nothing to return
pub fn process_callbacks(r: &mut dyn Read, cb: &mut dyn Callbacks) {
	loop {
		let mut b = [0; 4];
		match r.read(&mut b) {
			Ok(4) => {}
			_ => return,
		}
		let ok = match u32::from_ne_bytes(b) {
			CB_DOWNLOAD => process_cb_download(r, cb),
			CB_LOG => process_cb_log(r, cb),
			_ => true,
		};
		if !ok {
			return;
		}
	}
}

/// what the helper needs from the parent besides the payloads: the
/// forked C child has its handle and payloads by copy
#[derive(Debug, Default)]
pub struct Request {
	/// handle->sandboxuser, for the error message
	pub user: Vec<u8>,
	/// temporary_localpath: chdir, the one writable dir
	pub localpath: Vec<u8>,
	pub disable_filesystem: bool,
	pub disable_syscalls: bool,
	pub settings: Settings,
	pub state: DownloadState,
}

// length-prefixed fields, native endian (same machine)
struct Enc(Vec<u8>);

impl Enc {
	fn u64(&mut self, v: u64) {
		self.0.extend(v.to_ne_bytes());
	}

	fn bytes(&mut self, b: &[u8]) {
		self.u64(b.len() as u64);
		self.0.extend(b);
	}

	fn opt(&mut self, b: &Option<Vec<u8>>) {
		self.u64(b.is_some().into());
		if let Some(b) = b {
			self.bytes(b);
		}
	}

	fn list(&mut self, l: &[Vec<u8>]) {
		self.u64(l.len() as u64);
		for b in l {
			self.bytes(b);
		}
	}
}

struct Dec<'a>(&'a [u8]);

impl Dec<'_> {
	fn u64(&mut self) -> Option<u64> {
		let (h, t) = self.0.split_first_chunk::<8>()?;
		self.0 = t;
		Some(u64::from_ne_bytes(*h))
	}

	fn bool(&mut self) -> Option<bool> {
		Some(self.u64()? != 0)
	}

	fn i64(&mut self) -> Option<i64> {
		Some(self.u64()? as i64)
	}

	fn bytes(&mut self) -> Option<Vec<u8>> {
		let n = usize::try_from(self.u64()?).ok()?;
		let (h, t) = self.0.split_at_checked(n)?;
		self.0 = t;
		Some(h.to_vec())
	}

	fn opt(&mut self) -> Option<Option<Vec<u8>>> {
		Some(match self.bool()? {
			true => Some(self.bytes()?),
			false => None,
		})
	}

	fn list(&mut self) -> Option<Vec<Vec<u8>>> {
		let n = self.u64()?;
		(0..n).map(|_| self.bytes()).collect()
	}
}

impl Request {
	/// the request and the public part of the payloads (the rest is
	/// transfer state the download sets)
	pub fn encode(&self, payloads: &[Payload]) -> Vec<u8> {
		let mut e = Enc(Vec::new());
		e.bytes(&self.user);
		e.bytes(&self.localpath);
		e.u64(self.disable_filesystem.into());
		e.u64(self.disable_syscalls.into());
		let s = &self.settings;
		e.u64(s.parallel_downloads.into());
		e.u64(s.disable_dl_timeout.into());
		e.bytes(&s.dbext);
		e.opt(&s.user_agent);
		e.u64(self.state.is_interrupted().into());
		e.u64(self.state.hosts().len() as u64);
		for (host, errors) in self.state.hosts() {
			e.bytes(host);
			e.u64(*errors as i64 as u64);
		}
		e.u64(payloads.len() as u64);
		for p in payloads {
			e.bytes(&p.remote_name);
			e.bytes(&p.tempfile_name);
			e.opt(&p.destfile_name);
			e.opt(&p.fileurl);
			e.opt(&p.filepath);
			e.list(&p.cache_servers);
			e.list(&p.servers);
			e.u64(p.mtime_existing_file as u64);
			e.u64(p.max_size as u64);
			for b in [
				p.force,
				p.allow_resume,
				p.errors_ok,
				p.unlink_on_fail,
				p.download_signature,
				p.signature_optional,
			] {
				e.u64(b.into());
			}
		}
		e.0
	}

	/// None for a malformed request
	pub fn decode(b: &[u8]) -> Option<(Request, Vec<Payload>)> {
		let mut d = Dec(b);
		let user = d.bytes()?;
		let localpath = d.bytes()?;
		let disable_filesystem = d.bool()?;
		let disable_syscalls = d.bool()?;
		let settings = Settings {
			parallel_downloads: u32::try_from(d.u64()?).ok()?,
			disable_dl_timeout: d.bool()?,
			dbext: d.bytes()?,
			user_agent: d.opt()?,
		};
		let interrupted = d.bool()?;
		let mut hosts = Vec::new();
		for _ in 0..d.u64()? {
			let host = d.bytes()?;
			hosts.push((host, d.i64()? as i32));
		}
		let state = DownloadState::from_hosts(hosts, interrupted);
		let mut payloads = Vec::new();
		for _ in 0..d.u64()? {
			let mut p = Payload::default();
			p.remote_name = d.bytes()?;
			p.tempfile_name = d.bytes()?;
			p.destfile_name = d.opt()?;
			p.fileurl = d.opt()?;
			p.filepath = d.opt()?;
			p.cache_servers = d.list()?;
			p.servers = d.list()?;
			p.mtime_existing_file = d.i64()?;
			p.max_size = d.i64()?;
			p.force = d.bool()?;
			p.allow_resume = d.bool()?;
			p.errors_ok = d.bool()?;
			p.unlink_on_fail = d.bool()?;
			p.download_signature = d.bool()?;
			p.signature_optional = d.bool()?;
			payloads.push(p);
		}
		if !d.0.is_empty() {
			return None;
		}
		let req = Request {
			user,
			localpath,
			disable_filesystem,
			disable_syscalls,
			settings,
			state,
		};
		Some((req, payloads))
	}
}

/// the system side of the helper's setup, a trait so the order is
/// testable without the kernel
pub trait ChildOps {
	// chdir(path)
	fn chdir(&mut self, path: &[u8]) -> bool;
	// prctl(PR_SET_NO_NEW_PRIVS), failure is fine like in the C
	fn no_new_privs(&mut self);
	// _alpm_sandbox_fs_restrict_writes_to
	fn restrict_writes_to(
		&mut self,
		cb: &mut dyn Callbacks,
		path: &[u8],
	) -> bool;
	// _alpm_sandbox_syscalls_filter
	fn syscalls_filter(&mut self, cb: &mut dyn Callbacks) -> bool;
}

/// the running process
pub struct Kernel;

impl ChildOps for Kernel {
	fn chdir(&mut self, path: &[u8]) -> bool {
		std::env::set_current_dir(os(path)).is_ok()
	}

	fn no_new_privs(&mut self) {
		// a RestrictSelf without a ruleset only sets no_new_privs
		let _ = landlock::RestrictSelf::default().apply();
	}

	fn restrict_writes_to(
		&mut self,
		cb: &mut dyn Callbacks,
		path: &[u8],
	) -> bool {
		restrict_writes_to(cb, path)
	}

	fn syscalls_filter(&mut self, cb: &mut dyn Callbacks) -> bool {
		syscalls_filter(cb)
	}
}

/// the arguments of alpm_sandbox_setup_child past the user, and the
/// handle flags it reads
#[derive(Clone, Copy, Debug, Default)]
pub struct Setup<'a> {
	/// restrict writes to this dir
	pub sandbox_path: Option<&'a [u8]>,
	pub restrict_syscalls: bool,
	pub disable_filesystem: bool,
	pub disable_syscalls: bool,
}

/// alpm_sandbox_setup_child after the user switch: no_new_privs, then
/// landlock and seccomp as far as enabled. false when one of them failed
pub fn setup_child(
	ops: &mut dyn ChildOps,
	cb: &mut dyn Callbacks,
	s: &Setup,
) -> bool {
	ops.no_new_privs();
	if let Some(path) = s.sandbox_path
		&& !s.disable_filesystem
		&& !ops.restrict_writes_to(cb, path)
	{
		return false;
	}
	!(s.restrict_syscalls
		&& !s.disable_syscalls
		&& !ops.syscalls_filter(cb))
}

fn switch_failed(cb: &mut dyn Callbacks, user: &[u8]) {
	let m = [
		&b"switching to sandbox user '"[..],
		until_nul(user),
		b"' failed!\n",
	]
	.concat();
	cb.log(LogLevel::Error, &m);
}

/// the C child after the fork: chdir, setup, curl_download_internal.
/// exit status 0 downloaded, 1 nothing to do, 2 error
pub fn run_helper(
	ops: &mut dyn ChildOps,
	cb: &mut dyn Callbacks,
	mut req: Request,
	payloads: &mut [Payload],
) -> i32 {
	if !ops.chdir(&req.localpath) {
		let m = [
			&b"could not chdir to download directory "[..],
			until_nul(&req.localpath),
			b"\n",
		]
		.concat();
		cb.log(LogLevel::Error, &m);
		return 2;
	}
	let setup = Setup {
		sandbox_path: Some(&req.localpath),
		restrict_syscalls: true,
		disable_filesystem: req.disable_filesystem,
		disable_syscalls: req.disable_syscalls,
	};
	if !setup_child(ops, cb, &setup) {
		switch_failed(cb, &req.user);
		return 2;
	}
	match download_internal(&req.settings, &mut req.state, cb, payloads) {
		Ok(true) => 0,
		Ok(false) => 1,
		Err(_) => 2,
	}
}

/// the helper process: request on stdin, callbacks on stdout
pub fn helper_main() -> i32 {
	let mut input = Vec::new();
	if io::stdin().lock().read_to_end(&mut input).is_err() {
		return 2;
	}
	// unbuffered: a copy of fd 1 instead of the line-buffered Stdout
	let Ok(out) = io::stdout().as_fd().try_clone_to_owned() else {
		return 2;
	};
	let mut cb = CallbackWriter(File::from(out));
	let Some((req, mut payloads)) = Request::decode(&input) else {
		cb.log(LogLevel::Error, b"invalid sandbox helper request\n");
		return 2;
	};
	run_helper(&mut Kernel, &mut cb, req, &mut payloads)
}

// Some(exit status) when this process is the helper. a parent decides
// its helper program here, at startup: before its cwd moves
pub fn helper_entry() -> Option<i32> {
	let arg = std::env::args_os().nth(1);
	let code = match arg.as_deref().and_then(OsStr::to_str) {
		Some(HELPER_ARG) => helper_main(),
		Some(EXEC_ARG) => exec_main(),
		Some(CHROOT_ARG) => crate::util::chroot_main(),
		_ => {
			helper_program();
			return None;
		}
	};
	Some(code)
}

static PROGRAM: OnceLock<PathBuf> = OnceLock::new();

// the program run again as a helper, decided once per process. the C
// forks: its child is the running image whatever became of the file.
// "/proc/self/exe" comes closest (the same image after the file was
// replaced, pacman upgrading itself; no directory for the DownloadUser
// to traverse) and is kept while /proc is mounted. without /proc (a
// chroot entered by hand, some containers) exec of the link fails
// ENOENT, so the file's path is taken from argv[0] as execvp would,
// while the cwd is still the one argv[0] is relative to. nothing found:
// the link stays, the spawn reports its ENOENT
pub fn helper_program() -> &'static Path {
	PROGRAM.get_or_init(|| {
		let link = PathBuf::from("/proc/self/exe");
		match fs::read_link(&link) {
			Ok(_) => link,
			Err(_) => exe_path().unwrap_or(link),
		}
	})
}

// the running binary's file: std's current_exe (readlink of
// /proc/self/exe), else argv[0] resolved like execvp
pub fn exe_path() -> io::Result<PathBuf> {
	if let Ok(p) = std::env::current_exe() {
		return Ok(p);
	}
	let arg0 = std::env::args_os().next().unwrap_or_default();
	let cwd = std::env::current_dir()?;
	exe_from_argv0(&arg0, &cwd, std::env::var_os("PATH").as_deref())
		.ok_or(io::ErrorKind::NotFound.into())
}

// execvp's lookup of arg0 made absolute against cwd: with a '/' it is
// the file itself, otherwise the first executable regular file of
// that name in a PATH entry (an empty entry is cwd; unset, confstr's
// "/bin:/usr/bin"). an empty arg0 is nothing (execvp: ENOENT)
pub fn exe_from_argv0(
	arg0: &OsStr,
	cwd: &Path,
	path: Option<&OsStr>,
) -> Option<PathBuf> {
	if arg0.is_empty() {
		return None;
	}
	if arg0.as_bytes().contains(&b'/') {
		return Some(cwd.join(arg0));
	}
	let path = path.unwrap_or(OsStr::new("/bin:/usr/bin"));
	std::env::split_paths(path)
		.map(|dir| cwd.join(dir).join(arg0))
		.find(|p| {
			fs::metadata(p).is_ok_and(|m| m.is_file())
				&& access(p, Access::EXEC_OK).is_ok()
		})
}

// the helper in exec mode, after the parent's switch to the sandbox
// user: the request socket on stdin brings argv and the parent's stdin.
// no_new_privs, then execvp(argv[0], argv) on that stdin; a failed exec
// sends its errno back over the socket (the C's err_fd) and exits 127
fn exec_main() -> i32 {
	let Ok(sock) = io::stdin().as_fd().try_clone_to_owned() else {
		return 127;
	};
	let mut sock = UnixStream::from(sock);
	let mut space =
		[MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
	let mut anc = RecvAncillaryBuffer::new(&mut space);
	let mut buf = vec![0; 4096];
	let flags = RecvFlags::CMSG_CLOEXEC;
	let got = recvmsg(
		&sock,
		&mut [IoSliceMut::new(&mut buf)],
		&mut anc,
		flags,
	);
	let Ok(got) = got else {
		return 127;
	};
	let mut stdin = None;
	for m in anc.drain() {
		if let RecvAncillaryMessage::ScmRights(mut fds) = m {
			stdin = stdin.or(fds.next());
		}
	}
	buf.truncate(got.bytes);
	if sock.read_to_end(&mut buf).is_err() {
		return 127;
	}
	let Some(argv) = Dec(&buf).list().filter(|a| !a.is_empty()) else {
		return 127;
	};
	Kernel.no_new_privs();
	let mut cmd = Command::new(OsStr::from_bytes(&argv[0]));
	cmd.args(argv[1..].iter().map(|a| OsStr::from_bytes(a)));
	// no stdin to hand on (fd 0 closed in the parent): none here either
	cmd.stdin(stdin.map_or_else(Stdio::null, Stdio::from));
	let e = cmd.exec();
	let errno = e.raw_os_error().unwrap_or(0);
	let _ = sock.write_all(&errno.to_ne_bytes());
	127
}

/// why a sandboxed command did not run
#[derive(Debug)]
pub enum ExecError {
	/// alpm_sandbox_setup_child failed: not root, no such user
	Setup,
	/// the helper or the command could not be started: fork, setuid,
	/// execvp errno
	Spawn(io::Error),
}

/// systemvp's child with alpm_sandbox_setup_child(handle, user, NULL,
/// false): argv run as user with no_new_privs, no write or syscall
/// restriction (XferCommand). the helper in exec mode does the child's
/// part. stdin, stdout and stderr are ours; `argv[0]` is searched in PATH
pub struct SandboxExec {
	/// the helper and its arguments (this binary, EXEC_ARG)
	pub program: PathBuf,
	pub args: Vec<OsString>,
	// environment the command inherits through the helper (the C's
	// setenv of HTTP_USER_AGENT)
	pub env: Vec<(OsString, OsString)>,
	pub host: Box<dyn Host>,
}

impl Default for SandboxExec {
	fn default() -> Self {
		SandboxExec {
			program: helper_program().to_path_buf(),
			args: vec![EXEC_ARG.into()],
			env: Vec::new(),
			host: Box::new(System),
		}
	}
}

impl SandboxExec {
	/// the wait status (waitpid's) of argv run as user. the C child's
	/// getuid() and getpwnam checks are made here before spawning
	pub fn run(
		&mut self,
		user: &[u8],
		argv: &[Vec<u8>],
	) -> Result<ExitStatus, ExecError> {
		if self.host.uid() != 0 {
			return Err(ExecError::Setup);
		}
		let Ok((uid, gid)) = self.host.getpwnam(user) else {
			return Err(ExecError::Setup);
		};
		let (mut ours, theirs) =
			UnixStream::pair().map_err(ExecError::Spawn)?;
		let mut child = Command::new(&self.program)
			.args(&self.args)
			.envs(self.env.iter().map(|(k, v)| (k, v)))
			.uid(uid)
			.gid(gid)
			.stdin(OwnedFd::from(theirs))
			.spawn()
			.map_err(ExecError::Spawn)?;
		let mut e = Enc(Vec::new());
		e.list(argv);
		// a helper gone early shows in its status
		let _ = send_with_stdin(&mut ours, &e.0);
		let _ = ours.shutdown(Shutdown::Write);
		let status = child.wait().map_err(ExecError::Spawn)?;
		let mut b = [0; 4];
		match ours.read_exact(&mut b) {
			Ok(()) => {
				let errno = i32::from_ne_bytes(b);
				let e = io::Error::from_raw_os_error(errno);
				Err(ExecError::Spawn(e))
			}
			Err(_) => Ok(status),
		}
	}
}

// the request, our stdin attached (SCM_RIGHTS) to its first bytes; a
// stdin that cannot be passed (closed) is left out
fn send_with_stdin(sock: &mut UnixStream, req: &[u8]) -> io::Result<()> {
	let stdin = io::stdin();
	let fds = [stdin.as_fd()];
	let mut space =
		[MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
	let mut anc = SendAncillaryBuffer::new(&mut space);
	anc.push(SendAncillaryMessage::ScmRights(&fds));
	let iov = [IoSlice::new(req)];
	let sent = match sendmsg(&*sock, &iov, &mut anc, SendFlags::empty()) {
		Ok(n) => n,
		Err(rustix::io::Errno::BADF) => 0,
		Err(e) => return Err(e.into()),
	};
	sock.write_all(&req[sent..])
}

fn os(p: &[u8]) -> &Path {
	Path::new(OsStr::from_bytes(until_nul(p)))
}

// SIGINT and SIGQUIT ignored by this process while a download or
// command child runs (the C's sigaction SIG_IGN around fork and waitpid;
// the child gets the default action back): the frontend's signal
// handling reads these, a handler in safe Rust cannot change the
// disposition. QUIT_DEFAULT is the flag a SIGQUIT registration falls back
// to the default action on
static IGNORED: AtomicBool = AtomicBool::new(false);
static QUIT_DEFAULT: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// true while a sandboxed command runs and SIGINT/SIGQUIT are ignored
/// in the parent (the frontend's handler leaves them to the child)
pub fn signals_ignored() -> bool {
	IGNORED.load(Ordering::SeqCst)
}

/// true while SIGQUIT keeps its default action
pub fn quit_default() -> Arc<AtomicBool> {
	let f = QUIT_DEFAULT.get_or_init(|| Arc::new(AtomicBool::new(true)));
	Arc::clone(f)
}

/// the ignoring window, closed on drop
pub struct IgnoreSignals(());

impl IgnoreSignals {
	/// start ignoring, until the value drops
	pub fn new() -> Self {
		IGNORED.store(true, Ordering::SeqCst);
		quit_default().store(false, Ordering::SeqCst);
		IgnoreSignals(())
	}
}

impl Default for IgnoreSignals {
	fn default() -> Self {
		Self::new()
	}
}

impl Drop for IgnoreSignals {
	fn drop(&mut self) {
		quit_default().store(true, Ordering::SeqCst);
		IGNORED.store(false, Ordering::SeqCst);
	}
}

/// what the parent asks the system, a trait for tests that do not run
/// as root
pub trait Host {
	// getuid()
	fn uid(&self) -> u32;
	// getpwnam(user): uid and gid. Err(None) when there is no such user,
	// Err(Some(e)) when the lookup failed
	fn getpwnam(
		&self,
		user: &[u8],
	) -> Result<(u32, u32), Option<io::Error>>;
	// kill(getpid(), sig)
	fn raise(&mut self, sig: c_int);
}

/// the running system. getpwnam through getent(1), which asks NSS like
/// the C; kill through kill(1)
pub struct System;

impl Host for System {
	fn uid(&self) -> u32 {
		getuid()
	}

	fn getpwnam(
		&self,
		user: &[u8],
	) -> Result<(u32, u32), Option<io::Error>> {
		let user = until_nul(user);
		let out = Command::new("getent")
			.arg("passwd")
			.arg(OsStr::from_bytes(user))
			.stdin(Stdio::null())
			.stderr(Stdio::null())
			.output()
			.map_err(Some)?;
		// 2: no such key
		match out.status.code() {
			Some(0) => {}
			Some(2) => return Err(None),
			_ => {
				let e = io::Error::other(format!(
					"getent {}",
					out.status
				));
				return Err(Some(e));
			}
		}
		// getent also takes a numeric uid, getpwnam does not
		let line = out.stdout.split(|&c| c == b'\n').next();
		let f: Vec<&[u8]> = line
			.unwrap_or_default()
			.split(|&c| c == b':')
			.collect();
		let num = |b: &[u8]| std::str::from_utf8(b).ok()?.parse().ok();
		match f[..] {
			[name, _, uid, gid, ..] if name == user => {
				match (num(uid), num(gid)) {
					(Some(u), Some(g)) => Ok((u, g)),
					_ => Err(None),
				}
			}
			_ => Err(None),
		}
	}

	fn raise(&mut self, sig: c_int) {
		let _ = Command::new("kill")
			.arg(format!("-{sig}"))
			.arg(std::process::id().to_string())
			.status();
	}
}

/// the sandbox of a handle's downloads (its default SandboxFor): a
/// HelperSandbox where _alpm_use_sandbox holds for handle->user
pub fn handle_sandbox(handle: &Handle) -> Option<Box<dyn Sandbox>> {
	let sb = HelperSandbox::for_handle(handle, handle.user())?;
	Some(Box::new(sb))
}

/// the dload::Sandbox of a handle with a DownloadUser
pub struct HelperSandbox {
	/// handle->sandboxuser
	pub user: Vec<u8>,
	pub disable_filesystem: bool,
	pub disable_syscalls: bool,
	// the helper and its arguments, by default helper_program with
	// HELPER_ARG
	pub program: PathBuf,
	pub args: Vec<OsString>,
	pub host: Box<dyn Host>,
}

impl HelperSandbox {
	pub fn new(
		user: &[u8],
		disable_filesystem: bool,
		disable_syscalls: bool,
	) -> Self {
		HelperSandbox {
			user: until_nul(user).to_vec(),
			disable_filesystem,
			disable_syscalls,
			program: helper_program().to_path_buf(),
			args: vec![HELPER_ARG.into()],
			host: Box::new(System),
		}
	}

	/// _alpm_use_sandbox on the handle's sandboxuser and flags, uid
	/// standing for handle->user: None when downloads run unsandboxed
	pub fn for_handle(handle: &Handle, uid: u32) -> Option<Self> {
		let user = handle.sandboxuser()?;
		let fs = handle.disable_sandbox_filesystem() != 0;
		let sc = handle.disable_sandbox_syscalls() != 0;
		use_sandbox(uid, Some(user))
			.then(|| HelperSandbox::new(user, fs, sc))
	}

	// the parent's half: spawn, request, callbacks, exit status. the C
	// fork/pipe failures and waitpid failure fail without pm_errno
	fn run(
		&mut self,
		(uid, gid): (u32, u32),
		cb: &mut dyn Callbacks,
		req: &[u8],
	) -> (Result<bool, Errno>, c_int) {
		let _quiet = IgnoreSignals::new();
		let child = Command::new(&self.program)
			.args(&self.args)
			.uid(uid)
			.gid(gid)
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.spawn();
		let Ok(mut child) = child else {
			return (Err(Errno::Ok), 0);
		};
		// the helper reads all of it before writing: no deadlock. a
		// helper gone early shows in its exit status
		if let Some(mut stdin) = child.stdin.take() {
			let _ = stdin.write_all(req);
		}
		if let Some(mut out) = child.stdout.take() {
			process_callbacks(&mut out, cb);
		}
		// the C's kill(pid, SIGTERM) after the loop, which always ends
		// in error. the helper exits right after closing its stdout,
		// a signal then no longer changes its status. std only sends
		// SIGKILL
		let _ = child.kill();
		let Ok(status) = child.wait() else {
			return (Err(Errno::Ok), 0);
		};
		if let Some(sig) = status.signal() {
			return (Err(Errno::Retrieve), sig);
		}
		// exit 1: the C also sets pm_errno to RETRIEVE, Ok(false)
		// cannot carry it
		let r = match status.code() {
			Some(0) => Ok(true),
			Some(2) | None => Err(Errno::Retrieve),
			Some(_) => Ok(false),
		};
		(r, 0)
	}
}

impl Sandbox for HelperSandbox {
	fn user(&self) -> &[u8] {
		&self.user
	}

	fn lookup(&self) -> Result<(u32, u32), Option<io::Error>> {
		self.host.getpwnam(&self.user)
	}

	fn download(
		&mut self,
		settings: &Settings,
		state: &DownloadState,
		cb: &mut dyn Callbacks,
		payloads: &mut [Payload],
		temporary_localpath: &[u8],
	) -> (Result<bool, Errno>, c_int) {
		// alpm_sandbox_setup_child's checks, done by the C child after
		// its chdir: a failure exits 2 there
		let ids = match self.host.uid() {
			0 => self.lookup().ok(),
			_ => None,
		};
		let Some(ids) = ids else {
			switch_failed(cb, &self.user);
			return (Err(Errno::Retrieve), 0);
		};
		let req = Request {
			user: self.user.clone(),
			localpath: until_nul(temporary_localpath).to_vec(),
			disable_filesystem: self.disable_filesystem,
			disable_syscalls: self.disable_syscalls,
			settings: settings.clone(),
			state: state.clone(),
		};
		self.run(ids, cb, &req.encode(payloads))
	}

	fn raise(&mut self, sig: c_int) {
		self.host.raise(sig);
	}
}
