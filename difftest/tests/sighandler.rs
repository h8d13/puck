// sighandler.c's soft interrupt handler, C pacman (PACMAN_BUILD) against
// the Rust binary: SIGINT/SIGHUP before the handle exists, at a prompt
// of a prepared transaction, from PreTransaction and PostTransaction
// hooks, and from scriptlets of an install and a removal. the -U/-R runs
// go under fakechroot fakeroot like pactest (pmtest.py), the signal
// comes from a hook or scriptlet (kill $PPID) or from here once pacman
// waits. compared: exit status, stdout, stderr, the root tree (lock
// file, local db with install dates masked, scriptlet traces) and the
// log lines without their stamps. each run has a deadline
use std::fs;
use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use difftest::{
	Node, TempRoot, c_pacman, rust_pacman, snapshot, tar_dir, tar_file,
	ustar,
};

const DEADLINE: Duration = Duration::from_secs(60);

// a hook or scriptlet body signalling pacman, then giving the signal
// thread time (the C handles it at delivery); to-parent is read by
// pacman after the signal like in scriptlet-signal-handling.py
fn signal_body(sig: &str, trace: &str) -> String {
	format!("kill -{sig} $PPID; sleep 1; echo to-parent; echo ok > {trace}")
}

struct Pkg {
	name: &'static str,
	install: Option<String>,
}

fn pkg(name: &'static str) -> Pkg {
	Pkg {
		name,
		install: None,
	}
}

fn with_install(name: &'static str, func: &str, body: &str) -> Pkg {
	Pkg {
		name,
		install: Some(format!("{func}() {{\n\t{body}\n}}\n")),
	}
}

fn package_file(dir: &Path, p: &Pkg) -> PathBuf {
	let info = format!(
		"pkgname = {0}\npkgbase = {0}\npkgver = 1-1\n\
		pkgdesc = {0}\nbuilddate = 1700000000\n\
		packager = A B <a@b.org>\nsize = 1\narch = any\n",
		p.name
	);
	let mut entries = vec![tar_file(".PKGINFO", info.as_bytes())];
	if let Some(i) = &p.install {
		entries.push(tar_file(".INSTALL", i.as_bytes()));
	}
	entries.push(tar_dir("usr/"));
	entries.push(tar_file(&format!("usr/{}", p.name), b"x"));
	let path = dir.join(format!("{}-1-1-any.pkg.tar", p.name));
	fs::write(&path, ustar(&entries)).unwrap();
	path
}

fn hook(name: &str, when: &str, exec: &str) -> (String, String) {
	let text =
		format!("[Trigger]\nOperation = Install\nOperation = Remove\n\
		Type = Package\nTarget = *\n\n\
		[Action]\nWhen = {when}\nExec = /bin/sh -c '{exec}'\n");
	(format!("{name}.hook"), text)
}

// pmtest's root: /bin/sh and sleep for the scriptlets, an empty local
// db, hooks, SigLevel Never for the unsigned packages
struct World {
	tmp: TempRoot,
}

impl World {
	fn new(hooks: &[(String, String)]) -> Self {
		let tmp = TempRoot::new("sighandler");
		let root = tmp.dir().join("root");
		for d in [
			"bin",
			"usr/bin",
			"tmp",
			"etc/pacman.d/hooks",
			"var/lib/pacman/local",
			"var/cache/pacman/pkg",
			"var/log",
		] {
			fs::create_dir_all(root.join(d)).unwrap();
		}
		fs::copy("/bin/sh", root.join("bin/sh")).unwrap();
		fs::copy("/usr/bin/sleep", root.join("usr/bin/sleep")).unwrap();
		let local = root.join("var/lib/pacman/local");
		fs::write(local.join("ALPM_DB_VERSION"), "9\n").unwrap();
		fs::write(
			root.join("etc/pacman.conf"),
			"[options]\nSigLevel = Never\n",
		)
		.unwrap();
		for (name, text) in hooks {
			let dir = root.join("etc/pacman.d/hooks");
			fs::write(dir.join(name), text).unwrap();
		}
		World { tmp }
	}

	fn root(&self) -> PathBuf {
		self.tmp.dir().join("root")
	}

	fn args(&self, op: &[&str]) -> Vec<String> {
		let r = self.root();
		let r = r.display();
		let mut a: Vec<String> = [
			format!("--config={r}/etc/pacman.conf"),
			format!("--root={r}"),
			format!("--dbpath={r}/var/lib/pacman"),
			format!("--cachedir={r}/var/cache/pacman/pkg"),
			format!("--hookdir={r}/etc/pacman.d/hooks"),
			format!("--logfile={r}/var/log/pacman.log"),
		]
		.into();
		a.extend(op.iter().map(|s| s.to_string()));
		a
	}

	fn packages(&self, pkgs: &[Pkg]) -> Vec<String> {
		let dir = self.tmp.dir();
		let files = pkgs.iter().map(|p| package_file(dir, p));
		files.map(|f| f.display().to_string()).collect()
	}
}

#[derive(Clone, Copy)]
enum Kill {
	// the signal comes from the root's hooks or scriptlets
	Inside,
	// sent once pacman has run this long
	After(&'static str, u64),
	// sent once stderr shows the text (a prompt without --noconfirm)
	OnStderr(&'static str, &'static str),
}

#[derive(Debug, PartialEq, Eq)]
struct Outcome {
	code: Option<i32>,
	signal: Option<i32>,
	out: String,
	err: String,
	// "path kind mode [contents]" lines, root's bin dirs left out
	tree: Vec<String>,
	log: Vec<String>,
}

fn reader(
	mut r: impl Read + Send + 'static,
) -> (Arc<Mutex<Vec<u8>>>, JoinHandle<()>) {
	let buf = Arc::new(Mutex::new(Vec::new()));
	let b = Arc::clone(&buf);
	let t = thread::spawn(move || {
		let mut chunk = [0; 4096];
		loop {
			match r.read(&mut chunk) {
				Ok(0) | Err(_) => break,
				Ok(n) => {
					b.lock().unwrap()
						.extend_from_slice(&chunk[..n])
				}
			}
		}
	});
	(buf, t)
}

// pacman (C) or puck (the port) below pid (fakechroot and fakeroot are
// shell scripts running it)
fn find_pacman(pid: u32) -> Option<u32> {
	let comm = fs::read_to_string(format!("/proc/{pid}/comm"));
	if comm.is_ok_and(|c| matches!(c.trim_end(), "pacman" | "puck")) {
		return Some(pid);
	}
	let path = format!("/proc/{pid}/task/{pid}/children");
	let children = fs::read_to_string(path).unwrap_or_default();
	let mut kids = children.split_whitespace();
	kids.find_map(|c| find_pacman(c.parse().unwrap()))
}

fn send(child: &Child, sig: &str) {
	let start = Instant::now();
	let pid = loop {
		if let Some(pid) = find_pacman(child.id()) {
			break pid;
		}
		assert!(start.elapsed() < DEADLINE, "pacman never started");
		thread::sleep(Duration::from_millis(10));
	};
	let st = Command::new("kill")
		.args(["-s", sig, &pid.to_string()])
		.status()
		.unwrap();
	assert!(st.success(), "kill -s {sig} {pid}");
}

// whether buf showed text before the deadline
fn shows(buf: &Mutex<Vec<u8>>, text: &str) -> bool {
	let start = Instant::now();
	while !String::from_utf8_lossy(&buf.lock().unwrap()).contains(text) {
		if start.elapsed() > DEADLINE {
			return false;
		}
		thread::sleep(Duration::from_millis(10));
	}
	true
}

fn flatten(path: &str, n: &Node, out: &mut Vec<String>) {
	let line = match n {
		Node::File(mode, _, data) => {
			let text = String::from_utf8_lossy(data);
			format!("{path} file {mode:o} {text:?}")
		}
		Node::Dir(mode, entries) => {
			for (name, e) in entries.iter().flatten() {
				let name = String::from_utf8_lossy(name);
				let sub = format!("{path}/{name}");
				if sub != "/bin" && sub != "/usr/bin" {
					flatten(&sub, e, out);
				}
			}
			format!("{path} dir {mode:o}")
		}
		other => format!("{path} {other:?}"),
	};
	out.push(line);
}

// the install date and the log stamps differ between the two runs
fn masked_tree(root: &Path) -> Vec<String> {
	let local = root.join("var/lib/pacman/local");
	for e in fs::read_dir(&local).unwrap() {
		let desc = e.unwrap().path().join("desc");
		let Ok(text) = fs::read_to_string(&desc) else {
			continue;
		};
		let mut lines: Vec<&str> = text.split('\n').collect();
		if let Some(i) =
			lines.iter().position(|l| *l == "%INSTALLDATE%")
		{
			lines[i + 1] = "0";
		}
		fs::write(&desc, lines.join("\n")).unwrap();
	}
	let log = root.join("var/log/pacman.log");
	let _ = fs::rename(&log, root.join("../pacman.log"));
	let mut lines = Vec::new();
	flatten("", &snapshot(root), &mut lines);
	lines
}

// the lines without their stamps; in "Running" the binary is pacman,
// the world's dir W
fn log_lines(w: &World, bin: &Path) -> Vec<String> {
	let text = fs::read_to_string(w.tmp.dir().join("pacman.log"));
	let text = text.unwrap_or_default();
	let bin = bin.display().to_string();
	let dir = w.tmp.dir().display().to_string();
	let unstamp = |l: &str| match l.split_once("] ") {
		Some((_, rest)) => {
			rest.replace(&bin, "pacman").replace(&dir, "W")
		}
		None => l.to_string(),
	};
	text.lines().map(unstamp).collect()
}

fn run(
	bin: &Path,
	w: &World,
	args: &[String],
	fake: bool,
	kill: Kill,
) -> Outcome {
	let mut c = match fake {
		true => {
			let mut c = Command::new("fakechroot");
			c.arg("fakeroot").arg(bin);
			c
		}
		false => Command::new(bin),
	};
	let mut child = c
		.args(args)
		.current_dir(w.tmp.dir())
		.env_clear()
		.env("LC_ALL", "C.UTF-8")
		.env("TZ", "UTC")
		.env("COLUMNS", "80")
		.env("PATH", "/usr/bin:/bin")
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.unwrap();
	// stdin stays open: prompts and "-" targets wait on it
	let stdin = child.stdin.take();
	let (out, out_t) = reader(child.stdout.take().unwrap());
	let (err, err_t) = reader(child.stderr.take().unwrap());
	match kill {
		Kill::Inside => {}
		Kill::After(sig, ms) => {
			thread::sleep(Duration::from_millis(ms));
			send(&child, sig);
		}
		Kill::OnStderr(sig, text) => {
			if !shows(&err, text) {
				let _ = child.kill();
				panic!(
					"{}: no {text:?} on stderr",
					bin.display()
				);
			}
			send(&child, sig);
		}
	}
	let start = Instant::now();
	let status = loop {
		if let Some(st) = child.try_wait().unwrap() {
			break st;
		}
		if start.elapsed() > DEADLINE {
			let _ = child.kill();
			panic!("{} did not exit", bin.display());
		}
		thread::sleep(Duration::from_millis(10));
	};
	drop(stdin);
	out_t.join().unwrap();
	err_t.join().unwrap();
	let root = w.root();
	let text = |b: &Mutex<Vec<u8>>| {
		String::from_utf8_lossy(&b.lock().unwrap()).into_owned()
	};
	Outcome {
		code: status.code(),
		signal: status.signal(),
		out: text(&out),
		err: text(&err),
		tree: masked_tree(&root),
		log: log_lines(w, bin),
	}
}

// a case: the world (hooks, packages installed by C pacman first), the
// operation and how the signal comes; both binaries in fresh worlds
struct Case {
	hooks: Vec<(String, String)>,
	installed: Vec<Pkg>,
	op: Vec<&'static str>,
	targets: Vec<Pkg>,
	fake: bool,
	kill: Kill,
}

fn outcome(bin: &Path, case: &Case) -> Outcome {
	let w = World::new(&case.hooks);
	if !case.installed.is_empty() {
		let files = w.packages(&case.installed);
		let mut op = vec!["-U", "--noconfirm"];
		op.extend(files.iter().map(String::as_str));
		let o = run(&c_pacman(), &w, &w.args(&op), true, Kill::Inside);
		assert_eq!(o.code, Some(0), "setup: {o:?}");
		fs::remove_file(w.root().join("../pacman.log")).unwrap();
	}
	let files = w.packages(&case.targets);
	let names = case.targets.iter().map(|p| p.name.to_string());
	// -U takes the package files, the others the names
	let targets: Vec<String> = match case.op.contains(&"-U") {
		true => files,
		false => names.collect(),
	};
	let mut op = case.op.clone();
	op.extend(targets.iter().map(String::as_str));
	let o = run(bin, &w, &w.args(&op), case.fake, case.kill);
	// the lock is gone in every case
	assert!(!w.root().join("var/lib/pacman/db.lck").exists(), "{o:?}");
	o
}

fn compare(label: &str, case: Case) -> Outcome {
	let c = outcome(&c_pacman(), &case);
	let r = outcome(&rust_pacman(), &case);
	assert_eq!(c, r, "{label}");
	println!("{label}: equal, exit {:?}", c.code);
	c
}

fn has(o: &Outcome, file: &str) -> bool {
	let path = format!("/{file} ");
	o.tree.iter().any(|l| l.starts_with(&path))
}

const LOCAL: &str = "var/lib/pacman/local";

// no handle yet: pacman reads the "-" targets of stdin
#[test]
fn before_handle() {
	for (sig, code) in [("INT", 130), ("HUP", 129)] {
		let o = compare(
			&format!("{sig} before the handle"),
			Case {
				hooks: Vec::new(),
				installed: Vec::new(),
				op: vec!["-Q", "-"],
				targets: Vec::new(),
				fake: false,
				kill: Kill::After(sig, 300),
			},
		);
		assert_eq!(o.code, Some(code));
	}
}

// a prepared transaction asking to proceed: not interruptible, the lock
// goes and pacman exits
#[test]
fn prompt() {
	for (sig, code) in [("INT", 130), ("HUP", 129)] {
		let o = compare(
			&format!("{sig} at the prompt"),
			Case {
				hooks: Vec::new(),
				installed: Vec::new(),
				op: vec!["-U"],
				targets: vec![pkg("a")],
				fake: true,
				kill: Kill::OnStderr(sig, "[Y/n]"),
			},
		);
		assert_eq!(o.code, Some(code));
		assert!(!has(&o, &format!("{LOCAL}/a-1-1")));
	}
}

// PreTransaction hooks run before the commit: exit, nothing installed
#[test]
fn pre_hook() {
	let o = compare(
		"INT from a PreTransaction hook",
		Case {
			hooks: vec![hook(
				"pre",
				"PreTransaction",
				&signal_body("INT", "pre"),
			)],
			installed: Vec::new(),
			op: vec!["-U", "--noconfirm"],
			targets: vec![pkg("a")],
			fake: true,
			kill: Kill::Inside,
		},
	);
	assert_eq!(o.code, Some(130));
	assert!(!has(&o, &format!("{LOCAL}/a-1-1")));
}

// PostTransaction hooks run while the commit is still COMMITTING: the
// transaction is interrupted, pacman finishes
#[test]
fn post_hook() {
	let o = compare(
		"INT from a PostTransaction hook",
		Case {
			hooks: vec![hook(
				"post",
				"PostTransaction",
				&signal_body("INT", "post"),
			)],
			installed: Vec::new(),
			op: vec!["-U", "--noconfirm"],
			targets: vec![pkg("a")],
			fake: true,
			kill: Kill::Inside,
		},
	);
	assert_eq!(o.code, Some(0));
	assert!(has(&o, "post") && has(&o, &format!("{LOCAL}/a-1-1")));
}

// a post_install scriptlet interrupts: its package completes, the next
// one is not installed, the PostTransaction hooks are skipped
#[test]
fn install_scriptlet() {
	for sig in ["INT", "HUP"] {
		let body = signal_body(sig, "handled");
		let o = compare(
			&format!("{sig} from post_install"),
			Case {
				hooks: vec![hook(
					"post",
					"PostTransaction",
					"echo ok > post",
				)],
				installed: Vec::new(),
				op: vec!["-U", "--noconfirm"],
				targets: vec![
					with_install(
						"a",
						"post_install",
						&body,
					),
					pkg("b"),
				],
				fake: true,
				kill: Kill::Inside,
			},
		);
		assert_eq!(o.code, Some(0));
		assert!(has(&o, "handled")
			&& has(&o, &format!("{LOCAL}/a-1-1")));
		assert!(!has(&o, &format!("{LOCAL}/b-1-1")) && !has(&o, "post"));
		assert!(o
			.log
			.iter()
			.any(|l| l == "[ALPM] transaction interrupted"));
	}
}

// a pre_remove scriptlet interrupts: that package goes, the next stays.
// the removal runs in reverse target order
#[test]
fn remove_scriptlet() {
	let body = signal_body("INT", "handled");
	let o = compare(
		"INT from pre_remove",
		Case {
			hooks: Vec::new(),
			installed: vec![
				with_install("a", "pre_remove", &body),
				pkg("b"),
			],
			op: vec!["-R", "--noconfirm"],
			targets: vec![pkg("b"), pkg("a")],
			fake: true,
			kill: Kill::Inside,
		},
	);
	assert_eq!(o.code, Some(0));
	assert!(has(&o, "handled") && !has(&o, &format!("{LOCAL}/a-1-1")));
	assert!(has(&o, &format!("{LOCAL}/b-1-1")));
}
