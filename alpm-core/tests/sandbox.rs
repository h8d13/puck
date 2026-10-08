// unit tests of alpm_core::sandbox: use_sandbox, the callback pipe format
// (writer -> parent loop), the helper request, the setup order with a
// recording ChildOps, the parent side of HelperSandbox against sh(1)
// stand-ins and a Host that pretends to be root
use std::ffi::c_int;
use std::fs;
use std::io::{self, Cursor};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use alpm_core::callbacks::{Callbacks, DownloadEvent, LogLevel};
use alpm_core::dload::{DownloadState, Payload, Sandbox, Settings};
use alpm_core::error::Errno;
use alpm_core::handle::Handle;
use alpm_core::sandbox::{
	CB_DOWNLOAD, CB_LOG, CallbackWriter, ChildOps, HelperSandbox, Host,
	Request, Setup, System, process_callbacks, run_helper, setup_child,
	use_sandbox,
};

struct Tmp(PathBuf);

impl Tmp {
	fn new(tag: &str) -> Tmp {
		static N: AtomicUsize = AtomicUsize::new(0);
		let n = N.fetch_add(1, Ordering::Relaxed);
		let d = std::env::temp_dir().join(format!(
			"sandbox-unit-{tag}-{}-{n}",
			std::process::id()
		));
		let _ = fs::remove_dir_all(&d);
		fs::create_dir_all(&d).unwrap();
		Tmp(d)
	}

	fn p(&self, rel: &str) -> PathBuf {
		self.0.join(rel)
	}
}

impl Drop for Tmp {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}

#[derive(Debug, PartialEq, Eq)]
enum Seen {
	Log(LogLevel, Vec<u8>),
	Dl(Vec<u8>, DownloadEvent),
}

#[derive(Default)]
struct Rec(Vec<Seen>);

impl Callbacks for Rec {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		self.0.push(Seen::Log(level, msg.to_vec()));
	}

	fn download(&mut self, filename: &[u8], event: DownloadEvent) {
		self.0.push(Seen::Dl(filename.to_vec(), event));
	}
}

fn log(level: LogLevel, m: &str) -> Seen {
	Seen::Log(level, m.as_bytes().to_vec())
}

#[test]
fn use_sandbox_table() {
	let u = Some(&b"alpm"[..]);
	assert!(use_sandbox(0, u, false, false));
	assert!(use_sandbox(0, u, true, false));
	assert!(use_sandbox(0, u, false, true));
	assert!(!use_sandbox(0, u, true, true));
	assert!(!use_sandbox(1000, u, false, false));
	assert!(!use_sandbox(0, None, false, false));
}

#[test]
fn for_handle_reads_user_and_flags() {
	let t = Tmp::new("handle");
	fs::create_dir(t.p("root")).unwrap();
	fs::create_dir(t.p("db")).unwrap();
	let path = |rel| t.p(rel).into_os_string().into_encoded_bytes();
	let mut h = Handle::initialize(&path("root"), &path("db")).unwrap();
	assert!(HelperSandbox::for_handle(&h, 0).is_none());
	assert!(h.set_sandboxuser(Some(b"root")));
	h.set_disable_sandbox_syscalls(1);
	let sb = HelperSandbox::for_handle(&h, 0).unwrap();
	assert_eq!(sb.user, b"root");
	assert!(!sb.disable_filesystem && sb.disable_syscalls);
	assert!(HelperSandbox::for_handle(&h, 1000).is_none());
	h.set_disable_sandbox(1);
	assert!(HelperSandbox::for_handle(&h, 0).is_none());
}

const EVENTS: [DownloadEvent; 6] = [
	DownloadEvent::Init { optional: true },
	DownloadEvent::Init { optional: false },
	DownloadEvent::Progress {
		downloaded: 5,
		total: -1,
	},
	DownloadEvent::Retry { resume: true },
	DownloadEvent::Completed {
		total: i64::MAX,
		result: -1,
	},
	DownloadEvent::Completed {
		total: 0,
		result: 1,
	},
];

// writer then parent: everything back, empty messages never sent
#[test]
fn pipe_round_trip() {
	let mut w = CallbackWriter(Vec::new());
	let mut want = Vec::new();
	for (i, lvl) in [
		LogLevel::Error,
		LogLevel::Warning,
		LogLevel::Debug,
		LogLevel::Function,
	]
	.into_iter()
	.enumerate()
	{
		let m = format!("message {i}\n");
		w.log(lvl, m.as_bytes());
		want.push(log(lvl, &m));
		w.log(lvl, b"");
	}
	for (i, e) in EVENTS.iter().enumerate() {
		let name = format!("file{i}.db");
		w.download(name.as_bytes(), *e);
		want.push(Seen::Dl(name.into_bytes(), *e));
	}
	// the C child sends strlen(filename) bytes
	w.download(b"a\0b", EVENTS[0]);
	want.push(Seen::Dl(b"a".to_vec(), EVENTS[0]));
	let mut rec = Rec::default();
	let mut r = Cursor::new(&w.0[..]);
	process_callbacks(&mut r, &mut rec);
	assert_eq!(rec.0, want);
	assert_eq!(r.position() as usize, w.0.len());
}

// the byte layout of the C structs on 64-bit Linux
#[test]
fn pipe_layout() {
	let mut w = CallbackWriter(Vec::new());
	w.log(LogLevel::Warning, b"hi");
	let mut want = Vec::new();
	for v in [CB_LOG, 2, 2] {
		want.extend(v.to_ne_bytes());
	}
	want.extend(b"hi");
	assert_eq!(w.0, want);
	let mut w = CallbackWriter(Vec::new());
	let ev = DownloadEvent::Completed {
		total: 7,
		result: 1,
	};
	w.download(b"f", ev);
	let mut want = Vec::new();
	want.extend(CB_DOWNLOAD.to_ne_bytes());
	want.extend(3u32.to_ne_bytes());
	want.extend(7i64.to_ne_bytes());
	want.extend(1i32.to_ne_bytes());
	want.extend([0; 4]);
	want.extend(1usize.to_ne_bytes());
	want.extend(b"f");
	assert_eq!(w.0, want);
}

fn le(parts: &[&[u8]]) -> Vec<u8> {
	parts.concat()
}

// stream, callbacks the parent made, bytes it consumed
fn parent(stream: &[u8]) -> (Vec<Seen>, usize) {
	let mut rec = Rec::default();
	let mut r = Cursor::new(stream);
	process_callbacks(&mut r, &mut rec);
	(rec.0, r.position() as usize)
}

#[test]
fn pipe_parent_edges() {
	let n = |v: u32| v.to_ne_bytes();
	let ok_log = le(&[&n(CB_LOG), &n(1), &n(3), b"abc"]);
	let ok = log(LogLevel::Error, "abc");
	// unknown types are skipped, the loop goes on
	let s = le(&[&n(7), &ok_log]);
	assert_eq!(parent(&s), (vec![log(LogLevel::Error, "abc")], s.len()));
	// a short type read ends the loop
	let s = le(&[&ok_log, &[1, 0]]);
	assert_eq!(parent(&s), (vec![ok], s.len()));
	// size 0 and negative sizes break the stream after the size
	for size in [0, u32::MAX] {
		let s = le(&[&n(CB_LOG), &n(1), &n(size), b"abc", &ok_log]);
		assert_eq!(parent(&s), (vec![], 12));
	}
	// a short text breaks it
	let s = le(&[&n(CB_LOG), &n(1), &n(9), b"abc"]);
	assert_eq!(parent(&s), (vec![], s.len()));
	// the text is cut at a nul; unknown levels are dropped, not fatal
	let s = le(&[&n(CB_LOG), &n(2), &n(3), b"a\0c", &n(CB_LOG), &n(3)]);
	let s = le(&[&s, &n(1), b"x", &ok_log]);
	let (seen, used) = parent(&s);
	assert_eq!(seen[0], log(LogLevel::Warning, "a"));
	assert_eq!(seen[1], log(LogLevel::Error, "abc"));
	assert_eq!(used, s.len());
	// unknown event types and names of PATH_MAX bytes break it
	let s = le(&[&n(CB_DOWNLOAD), &n(4), &ok_log]);
	assert_eq!(parent(&s), (vec![], 8));
	let dl = |len: usize| {
		le(&[
			&n(CB_DOWNLOAD),
			&n(2),
			&n(1),
			&len.to_ne_bytes(),
			&vec![b'x'; len],
		])
	};
	let s = dl(4095);
	let name = vec![b'x'; 4095];
	let ev = DownloadEvent::Retry { resume: true };
	assert_eq!(parent(&s), (vec![Seen::Dl(name, ev)], s.len()));
	assert_eq!(parent(&dl(4096)), (vec![], 20));
	assert_eq!(parent(&le(&[&dl(0), &ok_log])), (vec![], 20));
}

fn payload(i: usize) -> Payload {
	let mut p = Payload::default();
	p.remote_name = format!("r{i}").into_bytes();
	p.tempfile_name = format!("/t/r{i}.part").into_bytes();
	p.destfile_name =
		i.is_multiple_of(2).then(|| format!("/t/r{i}").into());
	p.fileurl = i.is_multiple_of(3).then(|| b"http://h/x".to_vec());
	p.filepath = Some(vec![0, 255, b'\n']);
	p.cache_servers = vec![b"c".to_vec(); i];
	p.servers = vec![b"s1".to_vec(), Vec::new()];
	p.mtime_existing_file = -(i as i64);
	p.max_size = i as i64 * 1000;
	p.force = i & 1 != 0;
	p.allow_resume = i & 2 != 0;
	p.errors_ok = i & 4 != 0;
	p.unlink_on_fail = i & 8 != 0;
	p.download_signature = i & 16 != 0;
	p.signature_optional = i & 32 != 0;
	p
}

fn key(p: &Payload) -> String {
	format!(
		"{:?}",
		(
			&p.remote_name,
			&p.tempfile_name,
			&p.destfile_name,
			&p.fileurl,
			&p.filepath,
			&p.cache_servers,
			&p.servers,
			p.mtime_existing_file,
			p.max_size,
			[
				p.force,
				p.allow_resume,
				p.errors_ok,
				p.unlink_on_fail,
				p.download_signature,
				p.signature_optional
			],
		)
	)
}

#[test]
fn request_round_trip() {
	let hosts = vec![(b"a.org".to_vec(), 2), (b"disk".to_vec(), -1)];
	let req = Request {
		user: b"alpm".to_vec(),
		localpath: b"/var/cache/download-x/".to_vec(),
		disable_filesystem: true,
		disable_syscalls: false,
		settings: Settings {
			parallel_downloads: 5,
			disable_dl_timeout: true,
			dbext: b".files".to_vec(),
		},
		state: DownloadState::from_hosts(hosts.clone(), true),
	};
	let payloads: Vec<Payload> = (0..64).map(payload).collect();
	let b = req.encode(&payloads);
	let (r, p) = Request::decode(&b).unwrap();
	assert_eq!(format!("{r:?}"), format!("{req:?}"));
	assert_eq!(r.state.hosts(), &hosts[..]);
	assert!(r.state.is_interrupted());
	let keys = |v: &[Payload]| v.iter().map(key).collect::<Vec<_>>();
	assert_eq!(keys(&p), keys(&payloads));
	// every truncation and trailing bytes are refused
	for n in 0..b.len() {
		assert!(Request::decode(&b[..n]).is_none(), "cut at {n}");
	}
	assert!(Request::decode(&[&b[..], &[0]].concat()).is_none());
}

// ChildOps recording the order, results scripted
#[derive(Default)]
struct Ops {
	steps: Vec<String>,
	chdir_fails: bool,
	fs_fails: bool,
	sys_fails: bool,
}

impl ChildOps for Ops {
	fn chdir(&mut self, path: &[u8]) -> bool {
		self.steps.push(format!(
			"chdir {}",
			String::from_utf8_lossy(path)
		));
		!self.chdir_fails
	}

	fn no_new_privs(&mut self) {
		self.steps.push("nnp".into());
	}

	fn restrict_writes_to(
		&mut self,
		cb: &mut dyn Callbacks,
		path: &[u8],
	) -> bool {
		self.steps
			.push(format!("fs {}", String::from_utf8_lossy(path)));
		cb.log(LogLevel::Debug, b"fs\n");
		!self.fs_fails
	}

	fn syscalls_filter(&mut self, cb: &mut dyn Callbacks) -> bool {
		self.steps.push("sys".into());
		cb.log(LogLevel::Debug, b"sys\n");
		!self.sys_fails
	}
}

// path, restrict_syscalls, disable_fs, disable_sys, fs fails, sys fails,
// steps, result
type Case = (
	bool,
	bool,
	bool,
	bool,
	bool,
	bool,
	&'static [&'static str],
	bool,
);

#[test]
fn setup_order_and_flags() {
	let cases: &[Case] = &[
		(
			true,
			true,
			false,
			false,
			false,
			false,
			&["nnp", "fs /d", "sys"],
			true,
		),
		(true, true, true, false, false, false, &["nnp", "sys"], true),
		(
			true,
			true,
			false,
			true,
			false,
			false,
			&["nnp", "fs /d"],
			true,
		),
		(true, true, true, true, false, false, &["nnp"], true),
		(
			false,
			true,
			false,
			false,
			false,
			false,
			&["nnp", "sys"],
			true,
		),
		(
			true,
			false,
			false,
			false,
			false,
			false,
			&["nnp", "fs /d"],
			true,
		),
		// XferCommand's call: no path, no filter
		(false, false, false, false, false, false, &["nnp"], true),
		(
			true,
			true,
			false,
			false,
			true,
			false,
			&["nnp", "fs /d"],
			false,
		),
		(
			true,
			true,
			false,
			false,
			false,
			true,
			&["nnp", "fs /d", "sys"],
			false,
		),
		(true, true, true, false, true, true, &["nnp", "sys"], false),
	];
	for &(path, sys, dfs, dsys, ffail, sfail, steps, ok) in cases {
		let mut ops = Ops {
			fs_fails: ffail,
			sys_fails: sfail,
			..Ops::default()
		};
		let s = Setup {
			sandbox_path: path.then_some(&b"/d"[..]),
			restrict_syscalls: sys,
			disable_filesystem: dfs,
			disable_syscalls: dsys,
		};
		let mut rec = Rec::default();
		let r = setup_child(&mut ops, &mut rec, &s);
		assert_eq!((&ops.steps[..] == steps, r), (true, ok), "{s:?}");
	}
}

fn req(user: &[u8], dfs: bool, dsys: bool) -> Request {
	Request {
		user: user.to_vec(),
		localpath: b"/tmp/dl/".to_vec(),
		disable_filesystem: dfs,
		disable_syscalls: dsys,
		..Request::default()
	}
}

#[test]
fn helper_steps() {
	// chdir first, its failure logged and fatal before any restriction
	let mut ops = Ops {
		chdir_fails: true,
		..Ops::default()
	};
	let mut rec = Rec::default();
	let r = run_helper(
		&mut ops,
		&mut rec,
		req(b"alpm", false, false),
		&mut [],
	);
	assert_eq!(r, 2);
	assert_eq!(ops.steps, ["chdir /tmp/dl/"]);
	let want = "could not chdir to download directory /tmp/dl/\n";
	assert_eq!(rec.0, [log(LogLevel::Error, want)]);
	// a failed restriction ends in the C's message
	let mut ops = Ops {
		sys_fails: true,
		..Ops::default()
	};
	let mut rec = Rec::default();
	let r = run_helper(
		&mut ops,
		&mut rec,
		req(b"alpm", false, false),
		&mut [],
	);
	assert_eq!(r, 2);
	assert_eq!(ops.steps, ["chdir /tmp/dl/", "nnp", "fs /tmp/dl/", "sys"]);
	assert_eq!(
		rec.0,
		[
			log(LogLevel::Debug, "fs\n"),
			log(LogLevel::Debug, "sys\n"),
			log(
				LogLevel::Error,
				"switching to sandbox user 'alpm' failed!\n"
			),
		]
	);
	// nothing to download: Ok(false), exit 1
	let mut ops = Ops::default();
	let mut rec = Rec::default();
	let r = run_helper(
		&mut ops,
		&mut rec,
		req(b"alpm", true, true),
		&mut [],
	);
	assert_eq!((r, ops.steps.len()), (1, 2));
}

// a Host for a test user: root or not, lookup result, raised signals
struct FakeHost {
	root: bool,
	ids: Option<(u32, u32)>,
}

impl Host for FakeHost {
	fn uid(&self) -> u32 {
		if self.root { 0 } else { 1000 }
	}

	fn getpwnam(&self, _: &[u8]) -> Result<(u32, u32), Option<io::Error>> {
		self.ids.ok_or(None)
	}

	fn raise(&mut self, _: c_int) {}
}

fn own_ids(t: &Tmp) -> (u32, u32) {
	let f = t.p("me");
	fs::write(&f, b"").unwrap();
	let md = fs::metadata(&f).unwrap();
	(md.uid(), md.gid())
}

// a HelperSandbox running sh -c script as the current user
fn sh(script: &str, root: bool, ids: Option<(u32, u32)>) -> HelperSandbox {
	let mut sb = HelperSandbox::new(b"alpm", false, false);
	sb.program = "sh".into();
	sb.args = vec!["-c".into(), script.into()];
	sb.host = Box::new(FakeHost { root, ids });
	sb
}

fn sandboxed(sb: &mut HelperSandbox) -> ((Result<bool, Errno>, c_int), Rec) {
	let mut rec = Rec::default();
	let state = DownloadState::default();
	let r = sb.download(
		&Settings::default(),
		&state,
		&mut rec,
		&mut [],
		b"/nonexistent/",
	);
	(r, rec)
}

#[test]
fn parent_exit_status() {
	let t = Tmp::new("status");
	let ids = Some(own_ids(&t));
	// not root, no such user: the C child's setup fails, exit 2. the
	// helper is never spawned (that would give Err(Errno::Ok))
	let want = "switching to sandbox user 'alpm' failed!\n";
	for (root, ids) in [(false, ids), (true, None)] {
		let mut sb = sh("", root, ids);
		sb.program = t.p("missing");
		let (r, rec) = sandboxed(&mut sb);
		assert_eq!(r, (Err(Errno::Retrieve), 0));
		assert_eq!(rec.0, [log(LogLevel::Error, want)]);
	}
	for (script, want) in [
		("exit 0", (Ok(true), 0)),
		("exit 1", (Ok(false), 0)),
		("exit 3", (Ok(false), 0)),
		("exit 2", (Err(Errno::Retrieve), 0)),
		("kill -TERM $$", (Err(Errno::Retrieve), 15)),
		("kill -INT $$", (Err(Errno::Retrieve), 2)),
	] {
		let (r, rec) = sandboxed(&mut sh(script, true, ids));
		assert_eq!(r, want, "{script}");
		assert!(rec.0.is_empty());
	}
	// fork/exec failure: -1 without pm_errno
	let mut sb = sh("", true, ids);
	sb.program = t.p("missing");
	assert_eq!(sandboxed(&mut sb).0, (Err(Errno::Ok), 0));
}

#[test]
fn parent_reads_stream() {
	let t = Tmp::new("stream");
	let ids = Some(own_ids(&t));
	let mut w = CallbackWriter(Vec::new());
	w.log(LogLevel::Warning, b"from the child\n");
	w.download(b"core.db", EVENTS[2]);
	fs::write(t.p("stream"), &w.0).unwrap();
	let script =
		format!("cat > {0}/req; cat {0}/stream; exit 0", t.0.display());
	let (r, rec) = sandboxed(&mut sh(&script, true, ids));
	assert_eq!(r, (Ok(true), 0));
	assert_eq!(
		rec.0,
		[
			log(LogLevel::Warning, "from the child\n"),
			Seen::Dl(b"core.db".to_vec(), EVENTS[2]),
		]
	);
	// the helper got the request for temporary_localpath
	let (req, payloads) =
		Request::decode(&fs::read(t.p("req")).unwrap()).unwrap();
	assert_eq!(req.localpath, b"/nonexistent/");
	assert_eq!(req.user, b"alpm");
	assert!(payloads.is_empty());
}

#[test]
fn system_host() {
	let t = Tmp::new("host");
	let (uid, _) = own_ids(&t);
	assert_eq!(System.uid(), uid);
	assert_eq!(System.getpwnam(b"root").unwrap(), (0, 0));
	assert!(matches!(System.getpwnam(b"no-such-user-x"), Err(None)));
	// getent takes uids, getpwnam does not
	let name = uid.to_string();
	assert!(matches!(System.getpwnam(name.as_bytes()), Err(None)));
}
