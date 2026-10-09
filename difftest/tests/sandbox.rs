// alpm_core::internals::sandbox{,_fs,_syscalls} against the C sandbox.c,
// sandbox_fs.c and sandbox_syscalls.c.
//
// restrictions run in child processes: this test binary spawned again
// with SANDBOX_PROBE set runs probe_child only, applies the C or the
// Rust restriction (or none) to itself, probes writes, exec and the
// denied syscalls, and writes the outcome (return value, logs, errno
// per probe) to a file opened before. failures of the landlock calls
// are injected with a seccomp filter loaded first. the pipe protocol is
// compared on byte streams: the C child's writers against
// CallbackWriter, the C parent loop against process_callbacks. the
// helper download runs the real helper (src/bin/sandbox-helper.rs) as
// the current user against C _alpm_download without a sandbox.
use std::env;
use std::ffi::{OsString, c_int};
use std::fs::{self, File};
use std::io::{self, Cursor, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use alpm_core::internals::callbacks::{Callbacks, DownloadEvent, LogLevel};
use alpm_core::internals::dload::{DownloadState, Payload, Sandbox, Settings};
use alpm_core::internals::error::Errno;
use alpm_core::internals::sandbox::{
	CallbackWriter, HELPER_ARG, HelperSandbox, Host, System,
	process_callbacks,
};
use alpm_core::internals::sandbox_fs::restrict_writes_to;
use alpm_core::internals::sandbox_syscalls::{
	DENIED_SYSCALLS, syscalls_filter,
};
use difftest::{
	CDload, CSandbox, CbRec, Recorder, Reply, Rng, SbRecorder, Server,
	TempRoot, fs_probe_setup, fs_probes, inject_errors, iters,
	no_new_privs, probe_lines, syscall_probes, unsandbox,
};

const ENOSYS: c_int = 38;
const EOPNOTSUPP: c_int = 95;
const EINVAL: c_int = 22;
const ENOMEM: c_int = 12;
const EPERM: i32 = 1;
const EACCES: i32 = 13;

// the names in denied_syscalls[] of the C source the reference was
// built from (PACMAN_BUILD/..), in order
fn c_denied_syscalls() -> Vec<String> {
	let root = env::var_os("PACMAN_BUILD").map_or_else(
		|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../pacman"),
		|b| PathBuf::from(b).join(".."),
	);
	let src = root.join("lib/libalpm/sandbox_syscalls.c");
	let s = fs::read_to_string(&src).unwrap();
	let start = s.find("denied_syscalls[] = {").unwrap();
	let body = &s[start..start + s[start..].find("};").unwrap()];
	body.lines()
		.filter_map(|l| {
			let l = l.trim();
			let l = l.strip_prefix('"')?;
			Some(l[..l.find('"')?].to_string())
		})
		.collect()
}

fn dedup(v: &[String]) -> Vec<String> {
	let mut out: Vec<String> = Vec::new();
	for n in v {
		if !out.contains(n) {
			out.push(n.clone());
		}
	}
	out
}

// logs on one line, text readable (paths get replaced)
fn show(logs: &[CbRec]) -> String {
	let v: Vec<String> = logs
		.iter()
		.map(|r| match r {
			CbRec::Log(l, m) => {
				format!("{l} {:?}", String::from_utf8_lossy(m))
			}
			CbRec::Dl(..) => format!("{r:?}"),
		})
		.collect();
	format!("{v:?}")
}

// the child: runs only when spawned by probe()
#[test]
fn probe_child() {
	let Ok(spec) = env::var("SANDBOX_PROBE") else {
		return;
	};
	let dir = PathBuf::from(env::var("SANDBOX_DIR").unwrap());
	// opened before any restriction
	let mut out = File::create(dir.join("out")).unwrap();
	let parts: Vec<&str> = spec.split(':').collect();
	let (kind, side, variant) = (parts[0], parts[1], parts[2]);
	let mut c = (side == "c").then(|| CSandbox::new(&dir.join("h")));
	let (a, b) = (dir.join("a"), dir.join("b"));
	let res = match kind {
		"fs" => {
			fs_probe_setup(&a, &b);
			match variant {
				"nonnp" => {}
				"nosupport" => inject_errors(&[(
					"landlock_create_ruleset",
					ENOSYS,
					None,
				)]),
				"notenabled" => inject_errors(&[(
					"landlock_create_ruleset",
					EOPNOTSUPP,
					None,
				)]),
				// flags 0 is creation, the ABI query passes
				"createfail" => inject_errors(&[(
					"landlock_create_ruleset",
					EINVAL,
					Some(0),
				)]),
				"addrulefail" => inject_errors(&[(
					"landlock_add_rule",
					ENOMEM,
					None,
				)]),
				_ => assert!(no_new_privs()),
			}
			let path = match variant {
				"missing" => dir.join("none"),
				"notdir" => a.join("f_in"),
				_ => a.clone(),
			};
			let p = path.as_os_str().as_bytes();
			let (ok, logs) = match c.as_mut() {
				Some(c) => (c.restrict_writes_to(p), c.take()),
				None if side == "rust" => {
					let mut r = SbRecorder::default();
					(restrict_writes_to(&mut r, p), r.0)
				}
				None => (true, Vec::new()),
			};
			let probes = probe_lines(&fs_probes(&a, &b));
			format!("{ok}\n{}\n{probes}", show(&logs))
		}
		"sys" => {
			assert!(no_new_privs());
			let (ok, logs) = match c.as_mut() {
				Some(c) => (c.syscalls_filter(), c.take()),
				None if side == "rust" => {
					let mut r = SbRecorder::default();
					(syscalls_filter(&mut r), r.0)
				}
				None => (true, Vec::new()),
			};
			let names = dedup(&c_denied_syscalls());
			let probes = probe_lines(&syscall_probes(&names));
			format!("{ok}\n{}\n{probes}", show(&logs))
		}
		_ => {
			// alpm_sandbox_setup_child as non-root
			let c = c.as_mut().unwrap();
			let p = a.as_os_str().as_bytes();
			let r = c.setup_child(b"root", Some(p), true);
			format!("{r}\n{}\n", show(&c.take()))
		}
	};
	out.write_all(res.as_bytes()).unwrap();
}

// return value, logs, then "probe\terrno" lines
struct Outcome {
	head: String,
	probes: Vec<(String, i32)>,
}

fn probe(spec: &str) -> Outcome {
	let fx = TempRoot::new("sandbox-probe");
	let me = env::current_exe().unwrap();
	let out = Command::new(me)
		.args(["probe_child", "--exact", "--test-threads=1", "-q"])
		.env("SANDBOX_PROBE", spec)
		.env("SANDBOX_DIR", fx.dir())
		.output()
		.unwrap();
	assert!(
		out.status.success(),
		"{spec}: {}\n{}",
		out.status,
		String::from_utf8_lossy(&out.stderr)
	);
	let text = fs::read_to_string(fx.dir().join("out")).unwrap();
	let text = text.replace(&*fx.dir().to_string_lossy(), "<dir>");
	let mut lines = text.lines();
	let head =
		format!("{}\n{}", lines.next().unwrap(), lines.next().unwrap());
	let probes = lines
		.map(|l| {
			let (n, e) = l.split_once('\t').unwrap();
			(n.to_string(), e.parse().unwrap())
		})
		.collect();
	Outcome { head, probes }
}

#[test]
fn denied_list_matches_c() {
	let c = c_denied_syscalls();
	assert!(c.len() > 70, "{c:?}");
	assert_eq!(DENIED_SYSCALLS, c);
}

#[test]
fn syscalls_filter_vs_c() {
	let c = probe("sys:c:-");
	let r = probe("sys:rust:-");
	let none = probe("sys:none:-");
	assert_eq!(c.head, r.head);
	assert_eq!(c.probes, r.probes);
	assert!(c.head.starts_with("true\n"), "{}", c.head);
	assert!(c.head.contains("successfully restricted"), "{}", c.head);
	// every syscall of the arch denied with EPERM, std's chroot too
	for (n, e) in &c.probes {
		assert_eq!(*e, EPERM, "{n}");
	}
	// the probes tell a missing rule apart
	let differ = none.probes.iter().filter(|(_, e)| *e != EPERM).count();
	assert!(differ >= 20, "{:?}", none.probes);
	assert!(c.probes.len() >= 40, "{}", c.probes.len());
}

#[test]
fn restrict_writes_vs_c() {
	let variants = [
		"ok",
		"nonnp",
		"nosupport",
		"notenabled",
		"createfail",
		"addrulefail",
		"missing",
		"notdir",
	];
	for v in variants {
		let c = probe(&format!("fs:c:{v}"));
		let r = probe(&format!("fs:rust:{v}"));
		assert_eq!(c.head, r.head, "{v}");
		assert_eq!(c.probes, r.probes, "{v}");
		let ok = v == "ok";
		assert_eq!(c.head.starts_with("true\n"), ok, "{v}: {}", c.head);
	}
	let c = probe("fs:c:ok");
	let none = probe("fs:none:-");
	let get = |o: &Outcome, n: &str| {
		o.probes.iter().find(|(p, _)| p == n).unwrap().1
	};
	for (n, want) in [
		("create inside", 0),
		("O_TRUNC inside", 0),
		("rename in dir", 0),
		("read outside", 0),
		("create outside", EACCES),
		("write /dev/null", EACCES),
		("exec", EACCES),
	] {
		assert_eq!(get(&c, n), want, "{n}");
	}
	for (n, e) in &none.probes {
		assert_eq!(*e, 0, "unrestricted {n}");
	}
	let denied = c.probes.iter().filter(|(_, e)| *e != 0).count();
	assert!(denied >= 10, "{:?}", c.probes);
}

// alpm_sandbox_setup_child refuses before anything else without root;
// the Rust parent refuses the same way before spawning
#[test]
fn setup_child_needs_root() {
	if System.uid() == 0 {
		return;
	}
	let c = probe("setup:c:-");
	assert_eq!(c.head, "-1\n[]");
	let mut sb = HelperSandbox::new(b"root", false, false);
	let mut rec = Recorder::default();
	let state = DownloadState::default();
	let r = sb.download(
		&Settings::default(),
		&state,
		&mut rec,
		&mut [],
		b"/nonexistent/",
	);
	assert_eq!(r, (Err(Errno::Retrieve), 0));
	let want = b"switching to sandbox user 'root' failed!\n".to_vec();
	assert_eq!(rec.0.logs, [(LogLevel::Error, want)]);
}

const LEVELS: [LogLevel; 4] = [
	LogLevel::Error,
	LogLevel::Warning,
	LogLevel::Debug,
	LogLevel::Function,
];

fn text(rng: &mut Rng, nul: bool) -> Vec<u8> {
	let alpha: &[u8] = if nul {
		b"ab\n%s\0\xff\x01 "
	} else {
		b"ab\n%s\xff\x01 "
	};
	let max = if rng.below(50) == 0 { 6000 } else { 40 };
	rng.bytes(alpha, max)
}

fn event(rng: &mut Rng) -> DownloadEvent {
	let v = |rng: &mut Rng| match rng.below(4) {
		0 => 0,
		1 => -1,
		2 => i64::MAX,
		_ => rng.next_u64() as i64,
	};
	match rng.below(4) {
		0 => DownloadEvent::Init {
			optional: rng.below(2) == 0,
		},
		1 => DownloadEvent::Progress {
			downloaded: v(rng),
			total: v(rng),
		},
		2 => DownloadEvent::Retry {
			resume: rng.below(2) == 0,
		},
		_ => DownloadEvent::Completed {
			total: v(rng),
			result: [-1, 0, 1][rng.below(3)],
		},
	}
}

// the child's writers: C _alpm_sandbox_cb_log/_dl bytes against
// CallbackWriter
#[test]
fn pipe_writer_vs_c() {
	let fx = TempRoot::new("sandbox-writer");
	let mut c = CSandbox::new(fx.dir());
	let scratch = fx.dir().join("pipe");
	let mut rng = Rng::new(0x5a4d);
	for _ in 0..iters() / 10 {
		let mut w = CallbackWriter(Vec::new());
		let mut recs = Vec::new();
		for _ in 0..rng.below(6) {
			if rng.below(2) == 0 {
				let l = LEVELS[rng.below(4)];
				let m = text(&mut rng, false);
				w.log(l, &m);
				recs.push(CbRec::Log(l as c_int, m));
			} else {
				let n = text(&mut rng, false);
				let e = event(&mut rng);
				w.download(&n, e);
				recs.push(CbRec::download(&n, e));
			}
		}
		let cb = c.write_stream(&recs, &scratch);
		assert_eq!(cb, w.0, "{recs:?}");
	}
}

fn ne32(v: u32) -> [u8; 4] {
	v.to_ne_bytes()
}

// a callback stream: valid messages, odd values and corruption
fn stream(rng: &mut Rng) -> Vec<u8> {
	let mut s = Vec::new();
	for _ in 0..rng.below(6) {
		match rng.below(10) {
			0..=3 => {
				let level = match rng.below(6) {
					0..=3 => 1 << rng.below(4),
					4 => [0, 3, 16][rng.below(3)],
					_ => rng.next_u64() as u32,
				};
				let m = text(rng, true);
				let size = match rng.below(12) {
					0 => 0,
					1 => u32::MAX,
					2 => m.len() as u32 + 3,
					_ => m.len() as u32,
				};
				s.extend(ne32(0));
				s.extend(ne32(level));
				s.extend(ne32(size));
				s.extend(&m);
			}
			4..=7 => {
				let kind = match rng.below(8) {
					0 => 4,
					1 => rng.next_u64() as u32,
					_ => rng.below(4) as u32,
				};
				let size =
					[4, 16, 4, 16, 8][kind.min(4) as usize];
				let name = match rng.below(20) {
					0 => vec![b'x'; 4095 + rng.below(2)],
					_ => text(rng, true),
				};
				let len = match rng.below(15) {
					0 => usize::MAX,
					1 => name.len() + 2,
					_ => name.len(),
				};
				s.extend(ne32(1));
				s.extend(ne32(kind));
				for _ in 0..size {
					s.push(rng.next_u64() as u8);
				}
				s.extend(len.to_ne_bytes());
				s.extend(&name);
			}
			8 => s.extend(ne32([2, 7, u32::MAX][rng.below(3)])),
			_ => {
				for _ in 0..rng.below(8) {
					s.push(rng.next_u64() as u8);
				}
			}
		}
	}
	if !s.is_empty() && rng.below(4) == 0 {
		s.truncate(rng.below(s.len()));
	}
	if !s.is_empty() && rng.below(4) == 0 {
		let i = rng.below(s.len());
		s[i] ^= 1 << rng.below(8);
	}
	s
}

// what the Rust side can express: logs with an alpm_loglevel_t value,
// the init/retry ints as bools (the frontend tests them for truth)
fn expressible(r: &CbRec) -> Option<CbRec> {
	match r {
		CbRec::Log(l, _) if !matches!(l, 1 | 2 | 4 | 8) => None,
		CbRec::Dl(n, k @ (0 | 2), a, b) => {
			Some(CbRec::Dl(n.clone(), *k, (*a != 0).into(), *b))
		}
		_ => Some(r.clone()),
	}
}

// the parent: C process functions in dload.c's loop against
// process_callbacks. the Rust side drops logs with a level that is no
// alpm_loglevel_t value (the C hands them to logcb), counted
#[test]
fn pipe_parent_vs_c() {
	let fx = TempRoot::new("sandbox-parent");
	let mut c = CSandbox::new(fx.dir());
	let scratch = fx.dir().join("pipe");
	let mut rng = Rng::new(0x9e37);
	let (mut calls, mut odd_levels) = (0, 0);
	// a file round trip per stream on the C side
	let n = iters() / 4;
	for _ in 0..n {
		let s = stream(&mut rng);
		let (crec, cused) = c.process_stream(&s, &scratch);
		let mut r = SbRecorder::default();
		let mut cur = Cursor::new(&s[..]);
		process_callbacks(&mut cur, &mut r);
		let kept: Vec<CbRec> =
			crec.iter().filter_map(expressible).collect();
		odd_levels += crec.len() - kept.len();
		calls += kept.len();
		assert_eq!(kept, r.0, "{s:?}");
		assert_eq!(cused, cur.position(), "{s:?}");
	}
	assert!(calls > n / 2, "{calls}");
	println!("callbacks compared {calls}, odd levels dropped {odd_levels}");
}

// pretends to be root, the sandbox user is the current one
struct RootHost((u32, u32));

impl Host for RootHost {
	fn uid(&self) -> u32 {
		0
	}

	fn getpwnam(&self, _: &[u8]) -> Result<(u32, u32), Option<io::Error>> {
		Ok(self.0)
	}

	fn raise(&mut self, _: c_int) {}
}

// the helper program the parent side runs: /proc/self/exe while /proc
// is mounted (the running image, as the C's fork), the same default in
// a HelperSandbox, a SandboxExec and a Handle
#[test]
fn helper_program_with_proc() {
	use alpm_core::SandboxExec;
	use alpm_core::internals::sandbox::{exe_path, helper_program};
	assert!(fs::read_link("/proc/self/exe").is_ok(), "no /proc here");
	assert_eq!(helper_program(), Path::new("/proc/self/exe"));
	assert_eq!(exe_path().unwrap(), env::current_exe().unwrap());
	let sb = HelperSandbox::new(b"me", false, false);
	assert_eq!(sb.program, helper_program());
	assert_eq!(SandboxExec::default().program, helper_program());
	let fx = TempRoot::new("sandbox-program");
	let h = alpm_core::Handle::initialize(&fx.root(), &fx.dbpath())
		.unwrap();
	assert_eq!(h.chroot_helper(), helper_program());
}

// execvp's lookup of argv[0], on a tree of executables and decoys
#[test]
fn exe_from_argv0_cases() {
	use alpm_core::internals::sandbox::exe_from_argv0;
	use std::ffi::OsStr;
	let fx = TempRoot::new("sandbox-argv0");
	let dir = fx.dir();
	let exec = |rel: &str| {
		let p = dir.join(rel);
		fs::create_dir_all(p.parent().unwrap()).unwrap();
		fs::write(&p, "#!/bin/sh\n").unwrap();
		fs::set_permissions(&p, fs::Permissions::from_mode(0o755))
			.unwrap();
	};
	exec("a/tool");
	exec("b/tool");
	exec("a/plain");
	fs::set_permissions(
		dir.join("a/plain"),
		fs::Permissions::from_mode(0o644),
	)
	.unwrap();
	fs::create_dir_all(dir.join("a/dirtool")).unwrap();
	exec("b/dirtool");
	exec("here");
	let (a, b) = (dir.join("a"), dir.join("b"));
	let path = |dirs: &[&Path]| {
		env::join_paths(dirs.iter().map(|d| d.as_os_str())).unwrap()
	};
	let ab = path(&[&a, &b]);
	let find = |arg0: &str, path: Option<&OsStr>| {
		exe_from_argv0(OsStr::new(arg0), dir, path)
	};
	// a '/' names the file, relative to cwd, absolute as is; no check
	// of the file (execv reports it)
	assert_eq!(find("a/tool", Some(&ab)), Some(a.join("tool")));
	assert_eq!(find("./missing", Some(&ab)), Some(dir.join("missing")));
	let abs = a.join("tool").display().to_string();
	assert_eq!(find(&abs, None), Some(a.join("tool")));
	// PATH order, non-executables and directories passed over
	assert_eq!(find("tool", Some(&ab)), Some(a.join("tool")));
	assert_eq!(find("tool", Some(&path(&[&b, &a]))), Some(b.join("tool")));
	assert_eq!(find("plain", Some(&ab)), None);
	assert_eq!(find("dirtool", Some(&ab)), Some(b.join("dirtool")));
	assert_eq!(find("missing", Some(&ab)), None);
	// an empty entry is cwd; entries are made absolute against cwd
	let empty_first = OsString::from(format!(":{}", a.display()));
	assert_eq!(find("here", Some(&empty_first)), Some(dir.join("here")));
	assert_eq!(find("tool", Some(OsStr::new("a:b"))), Some(a.join("tool")));
	// no PATH: /bin:/usr/bin
	assert_eq!(find("sh", None), Some(PathBuf::from("/bin/sh")));
	assert_eq!(find("", Some(&ab)), None);
}

// helper_download_vs_c again where /proc is not mounted, and the
// resolution of the helper program there
#[test]
fn without_proc() {
	if difftest::without_proc() {
		return;
	}
	let out = difftest::rerun_without_proc(
		&["helper_download_vs_c", "helper_program_without_proc"],
		None,
		&[],
	);
	print!("{}", String::from_utf8_lossy(&out.stdout));
	eprint!("{}", String::from_utf8_lossy(&out.stderr));
	assert!(out.status.success(), "run without /proc: {}", out.status);
	let stdout = String::from_utf8_lossy(&out.stdout);
	assert!(stdout.contains("2 passed"), "the tests did not all run");
}

// in the rerun: this binary by its argv[0] stands in for
// /proc/self/exe, in every default
#[test]
fn helper_program_without_proc() {
	use alpm_core::SandboxExec;
	use alpm_core::internals::sandbox::{exe_path, helper_program};
	if !difftest::without_proc() {
		return;
	}
	assert!(!Path::new("/proc/self").exists(), "/proc is mounted");
	assert!(env::current_exe().is_err());
	let exe = exe_path().unwrap();
	assert!(exe.is_absolute(), "{}", exe.display());
	assert_eq!(exe, PathBuf::from(env::args_os().next().unwrap()));
	assert_eq!(helper_program(), exe);
	assert_eq!(HelperSandbox::new(b"me", false, false).program, exe);
	assert_eq!(SandboxExec::default().program, exe);
}

fn helper(fs_off: bool, sys_off: bool, ids: (u32, u32)) -> HelperSandbox {
	let mut sb = HelperSandbox::new(b"me", fs_off, sys_off);
	sb.program = env!("CARGO_BIN_EXE_sandbox-helper").into();
	sb.args = vec![OsString::from(HELPER_ARG)];
	sb.host = Box::new(RootHost(ids));
	sb
}

fn dir_bytes(p: &Path) -> Vec<u8> {
	[p.as_os_str().as_bytes(), b"/"].concat()
}

fn payloads(dir: &[u8], srv: &Server) -> Vec<Payload> {
	let mut out = Vec::new();
	for (name, optional) in [("core.db", false), ("gone.db", true)] {
		let mut p = Payload::default();
		p.remote_name = name.into();
		p.filepath = Some(name.into());
		p.servers = vec![srv.base().into_bytes()];
		p.destfile_name = Some([dir, name.as_bytes()].concat());
		p.tempfile_name = [dir, name.as_bytes(), b".part"].concat();
		p.errors_ok = optional;
		out.push(p);
	}
	let mut p = Payload::default();
	let name = "pkg-1-1-any.pkg.tar.zst";
	p.remote_name = name.into();
	p.fileurl = Some(srv.url(&format!("/{name}")));
	p.destfile_name = Some([dir, name.as_bytes()].concat());
	p.tempfile_name = [dir, name.as_bytes(), b".part"].concat();
	p.allow_resume = true;
	p.download_signature = true;
	p.signature_optional = true;
	out.push(p);
	out
}

// last progress event per file run only: curl's timing differs
fn reduce(ev: &[(Vec<u8>, DownloadEvent)]) -> Vec<(Vec<u8>, DownloadEvent)> {
	let mut out: Vec<(Vec<u8>, DownloadEvent)> = Vec::new();
	for (name, e) in ev {
		if matches!(e, DownloadEvent::Progress { .. })
			&& let Some(i) =
				out.iter().rposition(|(n, _)| n == name)
			&& matches!(out[i].1, DownloadEvent::Progress { .. })
		{
			out.remove(i);
		}
		out.push((name.clone(), *e));
	}
	out
}

fn files(dir: &Path) -> Vec<(Vec<u8>, Vec<u8>)> {
	let mut v: Vec<_> = fs::read_dir(dir)
		.unwrap()
		.flatten()
		.map(|e| {
			let n = e.file_name().as_bytes().to_vec();
			(n, fs::read(e.path()).unwrap_or_default())
		})
		.collect();
	v.sort();
	v
}

fn body(n: usize, seed: u8) -> Vec<u8> {
	(0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
		.collect()
}

// the sandboxed download in the real helper (landlock, seccomp,
// no_new_privs on) gives what the C gives without a sandbox
#[test]
fn helper_download_vs_c() {
	let srv = Server::start();
	let file = |b: Vec<u8>| Reply::File {
		body: b,
		ranges: true,
		mtime: Some(1_000_000_000),
	};
	srv.route("/core.db", vec![file(body(3000, 1))]);
	srv.route("/pkg-1-1-any.pkg.tar.zst", vec![file(body(70_000, 2))]);
	let fx = TempRoot::new("sandbox-dl");
	fs::write(fx.dir().join("me"), b"").unwrap();
	let md = fs::metadata(fx.dir().join("me")).unwrap();
	let ids = (md.uid(), md.gid());
	for (fs_off, sys_off) in [(false, false), (true, false), (false, true)]
	{
		let (cd, rd) = (fx.dir().join("c"), fx.dir().join("r"));
		for d in [&cd, &rd] {
			let _ = fs::remove_dir_all(d);
			fs::create_dir(d).unwrap();
		}
		srv.reset();
		let (cret, cerr, crec) = {
			let mut h = CDload::new(&fx);
			let d = dir_bytes(&cd);
			h.download(&payloads(&d, &srv), &d, &d)
		};
		let creq = srv.requests();
		srv.reset();
		let mut sb = helper(fs_off, sys_off, ids);
		let mut rec = Recorder::default();
		let state = DownloadState::default();
		let d = dir_bytes(&rd);
		let (r, sig) = sb.download(
			&Settings::default(),
			&state,
			&mut rec,
			&mut payloads(&d, &srv),
			&d,
		);
		let case = format!("fs off {fs_off}, syscalls off {sys_off}");
		assert_eq!(sig, 0, "{case}");
		let rret = match r {
			Ok(true) => 0,
			Ok(false) => 1,
			Err(_) => -1,
		};
		assert_eq!((rret, cret), (0, 0), "{case}: {r:?} {cerr}");
		let norm = |logs: &[(LogLevel, Vec<u8>)], dir: &[u8]| {
			logs.iter()
				.map(|(l, m)| {
					let m = String::from_utf8_lossy(m);
					let d = String::from_utf8_lossy(dir);
					(*l, m.replace(&*d, "<dir>/"))
				})
				.collect::<Vec<_>>()
		};
		// the C downloads in place, the helper's setup lines are its own
		unsandbox(&mut rec.0.logs);
		assert_eq!(
			norm(&rec.0.logs, &d),
			norm(&crec.logs, &dir_bytes(&cd)),
			"{case}"
		);
		assert_eq!(
			reduce(&rec.0.downloads),
			reduce(&crec.downloads),
			"{case}"
		);
		assert_eq!(files(&rd), files(&cd), "{case}");
		assert_eq!(srv.requests(), creq, "{case}");
		// the helper had a copy of the state, like the forked child
		assert!(state.hosts().is_empty());
	}
	// the helper cannot chdir: logged through the pipe, exit 2
	let mut sb = helper(false, false, ids);
	let mut rec = Recorder::default();
	let missing = dir_bytes(&fx.dir().join("missing"));
	let r = sb.download(
		&Settings::default(),
		&DownloadState::default(),
		&mut rec,
		&mut [],
		&missing,
	);
	assert_eq!(r, (Err(Errno::Retrieve), 0));
	let want = [
		&b"could not chdir to download directory "[..],
		&missing,
		b"\n",
	]
	.concat();
	assert_eq!(rec.0.logs, [(LogLevel::Error, want)]);
}
