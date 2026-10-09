// alpm_core::util::{run_chroot, ldconfig}, trans::runscriptlet and
// hook::hook_run against the C, for real in a chroot of a fixture root,
// both under fakechroot(1) as pacman's own test suite runs them
// (pmtest.py). `under_fakechroot` re-runs this binary's fc_* tests under
// fakechroot; outside it they return at once. the root holds a copy of
// /bin/sh and of the configured SCRIPTLET_SHELL at its own path, as
// pmtest.py places it (dynamically linked, fakechroot loads the host
// libraries); the ldconfig stub sits at LDCONFIG.
// compared per case: return value, log lines and events in order, the
// logfile lines, and the root tree afterwards (paths, types, modes,
// contents).
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use alpm_core::callbacks::HookWhen;
use alpm_core::hook::{AddTarget, Targets, hook_run};
use alpm_core::package::Package;
use alpm_core::trans::runscriptlet;
use alpm_core::util::{LDCONFIG, SCRIPTLET_SHELL, ldconfig, run_chroot};
use difftest::{
	CHookHandle, CHookResult, COMPS, Rng, RustHookHandle, TempRoot, iters,
	tar_file, ustar, write_db,
};

const CHILD: &str = "DIFFTEST_IN_FAKECHROOT";

fn in_child() -> bool {
	std::env::var_os(CHILD).is_some()
}

#[test]
fn under_fakechroot() {
	if in_child() {
		return;
	}
	let exe = std::env::current_exe().unwrap();
	let out = Command::new("fakechroot")
		.arg(exe)
		.args(["fc_", "--nocapture", "--test-threads=1"])
		.env(CHILD, "1")
		// chroot_denied's C chdir(root) moves this process's cwd for
		// a moment, into a root removed after
		.current_dir(env!("CARGO_MANIFEST_DIR"))
		// the host's /proc inside the chroot (fc_fixed's signals)
		.env("FAKECHROOT_EXCLUDE_PATH", "/proc")
		.output()
		.expect("fakechroot not found");
	print!("{}", String::from_utf8_lossy(&out.stdout));
	eprint!("{}", String::from_utf8_lossy(&out.stderr));
	assert!(out.status.success(), "fakechroot run: {}", out.status);
	let stdout = String::from_utf8_lossy(&out.stdout);
	assert!(stdout.contains("5 passed"), "fc_ tests did not all run");
}

fn pick<T: Copy>(rng: &mut Rng, items: &[T]) -> T {
	items[rng.below(items.len())]
}

// an absolute path of config.h placed under root
fn under_root(r: &Path, abs: &[u8]) -> PathBuf {
	r.join(OsStr::from_bytes(&abs[1..]))
}

// a TempRoot whose root/ is rebuilt for each side of a case
struct Fix {
	tmp: TempRoot,
	// handle->root, with the '/' alpm_initialize appends
	root: Vec<u8>,
}

impl Fix {
	fn new(tag: &str) -> Self {
		let tmp = TempRoot::new(tag);
		tmp.reset_local();
		let root = [&tmp.root()[..], b"/"].concat();
		let fix = Fix { tmp, root };
		fix.reset();
		fix
	}

	fn rootdir(&self) -> std::path::PathBuf {
		self.tmp.dir().join("root")
	}

	fn c(&self) -> CHookHandle {
		CHookHandle::new(
			&self.tmp.root(),
			&self.tmp.dbpath(),
			self.tmp.dir().join("log"),
		)
	}

	fn r(&self) -> RustHookHandle {
		RustHookHandle::new(
			&self.tmp.root(),
			&self.tmp.dbpath(),
			self.tmp.dir().join("log-rs"),
		)
	}

	// root/ with bin/sh, the scriptlet shell and tmp/ only
	fn reset(&self) {
		let r = self.rootdir();
		if fs::symlink_metadata(&r).is_ok() {
			chmod_all(&r);
			fs::remove_dir_all(&r).unwrap();
		}
		fs::create_dir_all(r.join("bin")).unwrap();
		fs::create_dir(r.join("tmp")).unwrap();
		fs::copy("/bin/sh", r.join("bin/sh")).unwrap();
		let shell = under_root(&r, SCRIPTLET_SHELL);
		if shell != r.join("bin/sh") {
			fs::create_dir_all(shell.parent().unwrap()).unwrap();
			fs::copy(OsStr::from_bytes(SCRIPTLET_SHELL), shell)
				.unwrap();
		}
	}
}

impl Drop for Fix {
	fn drop(&mut self) {
		let r = self.rootdir();
		if r.exists() {
			chmod_all(&r);
		}
	}
}

// directories made traversable again so the tree can be removed
fn chmod_all(dir: &Path) {
	let Ok(m) = fs::symlink_metadata(dir) else {
		return;
	};
	if !m.is_dir() {
		return;
	}
	fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
	for e in fs::read_dir(dir).unwrap() {
		chmod_all(&e.unwrap().path());
	}
}

// every path below dir with its type, mode and content (the shells
// skipped)
fn tree(dir: &Path) -> Vec<String> {
	let mut out = Vec::new();
	walk(dir, dir, &mut out);
	out.sort();
	out
}

fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
	let Ok(rd) = fs::read_dir(dir) else { return };
	for e in rd.map(Result::unwrap) {
		let p = e.path();
		let rel = p.strip_prefix(base).unwrap().display().to_string();
		if rel == "bin/sh" || rel.as_bytes() == &SCRIPTLET_SHELL[1..] {
			continue;
		}
		let m = fs::symlink_metadata(&p).unwrap();
		let mode = m.permissions().mode();
		if m.is_dir() {
			out.push(format!("{rel}/ {mode:o}"));
			walk(base, &p, out);
		} else if m.is_symlink() {
			out.push(format!(
				"{rel} -> {:?}",
				fs::read_link(&p).unwrap()
			));
		} else {
			let data = fs::read(&p).unwrap_or_default();
			let data = String::from_utf8_lossy(&data);
			out.push(format!("{rel} {mode:o} {data:?}"));
		}
	}
}

// the random part of root/tmp/alpm_XXXXXX made fixed
fn untemp(v: &[u8]) -> Vec<u8> {
	let mut out = Vec::new();
	let mut i = 0;
	while i < v.len() {
		if v[i..].starts_with(b"alpm_") && v.len() - i >= 11 {
			out.extend_from_slice(b"alpm_XXXXXX");
			i += 11;
			continue;
		}
		out.push(v[i]);
		i += 1;
	}
	out
}

fn normalize(r: CHookResult) -> CHookResult {
	use difftest::HookRec;
	let recs = r
		.1
		.into_iter()
		.map(|x| match x {
			HookRec::Log(l, m) => HookRec::Log(l, untemp(&m)),
			HookRec::Scriptlet(m) => HookRec::Scriptlet(untemp(&m)),
			x => x,
		})
		.collect();
	(r.0, recs, untemp(&r.2))
}

fn show(r: &CHookResult) -> String {
	let recs: Vec<String> = r.1.iter().map(difftest::show_rec).collect();
	format!(
		"ret {}\n{}\nlog: {}",
		r.0,
		recs.join("\n"),
		String::from_utf8_lossy(&r.2)
	)
}

// runs one case on a fresh root for each side; setup prepares the root
fn both(
	fix: &Fix,
	c: &mut CHookHandle,
	setup: &dyn Fn(&Path),
	cside: &mut dyn FnMut(&mut CHookHandle) -> CHookResult,
	rside: &mut dyn FnMut() -> CHookResult,
	what: &str,
) {
	fix.reset();
	setup(&fix.rootdir());
	let cr = normalize(cside(c));
	let ctree = tree(&fix.rootdir());
	fix.reset();
	setup(&fix.rootdir());
	let rr = normalize(rside());
	let rtree = tree(&fix.rootdir());
	assert_eq!(cr, rr, "{what}\nC:\n{}\nRust:\n{}", show(&cr), show(&rr));
	assert_eq!(ctree, rtree, "{what}");
}

// pinned C behaviour, each also compared with the port
#[test]
fn fc_fixed() {
	if !in_child() {
		return;
	}
	use difftest::HookRec::{Log, Scriptlet};
	let fix = Fix::new("fc-fixed");
	let (mut c, mut r) = (fix.c(), fix.r());
	let line = |s: &str| Scriptlet(s.as_bytes().to_vec());
	let long = "0".repeat(2046);
	let cases: [(&str, &str, Vec<difftest::HookRec>); 6] = [
		// an unterminated last line is delivered twice
		(
			"/bin/sh",
			"printf 'tail'",
			vec![line("tail\n"), line("tail\n")],
		),
		// a nul ends the line, its '\n' with it
		("/bin/sh", "printf 'a\\0b\\n'", vec![line("a")]),
		// 2046 bytes without '\n' make a line
		(
			"/bin/sh",
			"printf '%02047d\\n' 0",
			vec![line(&format!("{long}\n")), line("0\n")],
		),
		// the child's execv failure
		(
			"/nonexistent",
			"",
			vec![line(
				"call to execv failed (No such file or directory)\n",
			)],
		),
		// relative to the chroot's "/", not searched in PATH
		(
			"sh",
			"",
			vec![line(
				"call to execv failed (No such file or directory)\n",
			)],
		),
		("/bin/sh", "kill -TERM $$", vec![]),
	];
	for (cmd, script, lines) in cases {
		let argv: Vec<Vec<u8>> = [cmd, "-c", script]
			.iter()
			.map(|s| s.as_bytes().to_vec())
			.collect();
		let args: Vec<&[u8]> = argv.iter().map(|a| &a[..]).collect();
		fix.reset();
		let cr = c.run_chroot(Some(cmd.as_bytes()), &argv, None);
		let got: Vec<_> =
			cr.1.iter()
				.filter(|r| matches!(r, Scriptlet(_)))
				.cloned()
				.collect();
		assert_eq!(got, lines, "{cmd} {script}\n{}", show(&cr));
		let ok =
			run_chroot(&mut r.h, Some(cmd.as_bytes()), &args, None);
		assert_eq!(cr, r.take(ok, 1), "{cmd} {script}");
	}
	// the child runs under umask(0022) whatever the process has (the
	// fc_ tests run on one thread, nothing else sees the mask)
	let old =
		rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
	let argv = vec![b"/bin/sh".to_vec(), b"-c".to_vec(), b"umask".to_vec()];
	let args: Vec<&[u8]> = argv.iter().map(|a| &a[..]).collect();
	fix.reset();
	let cr = c.run_chroot(Some(b"/bin/sh"), &argv, None);
	let ok = run_chroot(&mut r.h, Some(b"/bin/sh"), &args, None);
	rustix::process::umask(old);
	assert!(cr.1.contains(&line("0022\n")), "{}", show(&cr));
	assert_eq!(cr, r.take(ok, 1), "umask");
	// argv[0] is the caller's, not cmd (ldconfig prefixes its messages
	// with it): sh reading its script from stdin shows it as $0. "sh"
	// is relative to the chroot's "/"
	let echo0 = Some(&b"echo \"$0\"\n"[..]);
	for (cmd, arg0) in
		[("/bin/sh", "x"), ("bin/sh", "ldconfig"), ("sh", "sh")]
	{
		fix.reset();
		fs::copy("/bin/sh", fix.rootdir().join("sh")).unwrap();
		let argv = vec![arg0.as_bytes().to_vec()];
		let cr = c.run_chroot(Some(cmd.as_bytes()), &argv, echo0);
		let ok = run_chroot(
			&mut r.h,
			Some(cmd.as_bytes()),
			&[arg0.as_bytes()],
			echo0,
		);
		let want = line(&format!("{arg0}\n"));
		assert!(cr.1.contains(&want), "{cmd} {arg0}\n{}", show(&cr));
		assert_eq!(cr, r.take(ok, 1), "{cmd} argv[0] {arg0}");
	}
	// _alpm_reset_signals: dispositions the process ignores are back
	// to default in the child (SIGHUP 1, SIGUSR1 10; not SIGCHLD, the
	// C's waitpid would find no child). the shell's own SigIgn (bash
	// ignores SIGQUIT) is the run without them
	let status = "while read -r k v; do \
		[ \"$k\" = SigIgn: ] && echo \"$v\"; done < /proc/self/status";
	let argv = vec![b"/bin/sh".to_vec(), b"-c".to_vec(), status.into()];
	let args: Vec<&[u8]> = argv.iter().map(|a| &a[..]).collect();
	fix.reset();
	let plain = c.run_chroot(Some(b"/bin/sh"), &argv, None);
	let sigs = [1, 10];
	for sig in sigs {
		difftest::c_ignore_signal(sig, true);
	}
	let cr = c.run_chroot(Some(b"/bin/sh"), &argv, None);
	let ok = run_chroot(&mut r.h, Some(b"/bin/sh"), &args, None);
	for sig in sigs {
		difftest::c_ignore_signal(sig, false);
	}
	assert_eq!(cr, plain, "C signals\n{}", show(&cr));
	assert_eq!(cr, r.take(ok, 1), "signals");
	// a file of no known format: execv fails, no /bin/sh fallback
	// (execvp's)
	fix.reset();
	let f = fix.rootdir().join("noformat");
	fs::write(&f, "echo ran\n").unwrap();
	fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
	let cr = c.run_chroot(Some(b"/noformat"), &[b"/noformat".into()], None);
	let ok =
		run_chroot(&mut r.h, Some(b"/noformat"), &[b"/noformat"], None);
	let enoexec = line("call to execv failed (Exec format error)\n");
	assert!(cr.1.contains(&enoexec), "{}", show(&cr));
	assert_eq!(cr, r.take(ok, 1), "ENOEXEC");
	let term = Log(
		1,
		b"command terminated by signal 15: Terminated\n".to_vec(),
	);
	fix.reset();
	let argv = vec![
		b"/bin/sh".to_vec(),
		b"-c".to_vec(),
		b"kill -TERM $$".to_vec(),
	];
	assert!(c
		.run_chroot(Some(b"/bin/sh"), &argv, None)
		.1
		.contains(&term));
}

// outside fakechroot the C child's chroot() fails for a user without
// CAP_SYS_CHROOT (as root it runs): its text, from the helper here
#[test]
fn chroot_denied() {
	if in_child() {
		return;
	}
	let fix = Fix::new("chroot-denied");
	let (mut c, mut r) = (fix.c(), fix.r());
	let argv =
		vec![b"/bin/sh".to_vec(), b"-c".to_vec(), b"echo in".to_vec()];
	let args: Vec<&[u8]> = argv.iter().map(|a| &a[..]).collect();
	let cr = c.run_chroot(Some(b"/bin/sh"), &argv, None);
	let ok = run_chroot(&mut r.h, Some(b"/bin/sh"), &args, None);
	if rustix::process::geteuid().as_raw() != 0 {
		let denied = difftest::HookRec::Scriptlet(
			b"could not change the root directory \
			(Operation not permitted)\n"
				.to_vec(),
		);
		assert!(cr.1.contains(&denied), "{}", show(&cr));
	}
	assert_eq!(cr, r.take(ok, 1));
}

// the helper on a root run_chroot's own chdir would have refused: the
// C child's chroot() failure text, exit 1 (sandbox-helper's watchdog
// bounds it)
#[test]
fn chroot_helper_no_root() {
	if in_child() {
		return;
	}
	let out = Command::new(difftest::test_chroot_helper())
		.args([
			alpm_core::sandbox::CHROOT_ARG,
			"/nonexistent-root/",
			"/bin/sh",
			"sh",
		])
		.output()
		.unwrap();
	assert_eq!(out.status.code(), Some(1));
	assert_eq!(out.stdout, b"");
	assert_eq!(
		String::from_utf8_lossy(&out.stderr),
		"could not change the root directory \
		(No such file or directory)\n"
	);
}

const SNIPPETS: [&str; 18] = [
	"echo hello world",
	"echo err >&2",
	"printf 'no newline'",
	"printf 'a\\0b\\n'",
	"printf '%02100d\\n' 0",
	"printf '%04093d' 0",
	"printf '%02046d' 0",
	"printf '%02045d\\n' 0",
	"while IFS= read -r l; do echo \"in:$l\"; done",
	"echo x > /tmp/made",
	"umask",
	"pwd",
	"echo \"$0 $1 $#\"",
	"exit 3",
	"kill -TERM $$",
	"kill -KILL $$",
	"echo out; echo err >&2; echo out2",
	"printf 'x\\n\\n\\ny'",
];

const CMDS: [&str; 7] = [
	"/bin/sh",
	"/bin/sh",
	"/bin/sh",
	"bin/sh",
	"sh",
	"/nonexistent",
	"/tmp",
];

fn script(rng: &mut Rng) -> String {
	let parts: Vec<&str> = (0..1 + rng.below(4))
		.map(|_| pick(rng, &SNIPPETS))
		.collect();
	parts.join("; ")
}

fn stdin_data(rng: &mut Rng, reads: bool) -> Option<Vec<u8>> {
	if !reads {
		return None;
	}
	match rng.below(4) {
		0 => None,
		1 => Some(Vec::new()),
		2 => {
			// several PIPE_BUF chunks
			let line = "y".repeat(rng.below(5000));
			Some(format!("{line}\nz\n")
				.repeat(1 + rng.below(30))
				.into_bytes())
		}
		_ => Some(b"one\ntwo\nlast-no-newline".to_vec()),
	}
}

#[test]
fn fc_run_chroot() {
	if !in_child() {
		return;
	}
	let fix = Fix::new("fc-run");
	let (mut c, mut r) = (fix.c(), fix.r());
	let mut rng = Rng::new(0xc4a007);
	for _ in 0..(iters() / 500).max(60) {
		let cmd = pick(&mut rng, &CMDS);
		let mut body = script(&mut rng);
		// the C's stdin writes race a child exiting before reading
		// (EPIPE logged or not): only children reading it all get one
		let reads = rng.below(2) == 0 && cmd.ends_with("bin/sh");
		if reads {
			body = format!("{}; {body}", SNIPPETS[8]);
		}
		let argv: Vec<Vec<u8>> = [cmd, "-c", &body, "name", "arg1"]
			.iter()
			.map(|s| s.as_bytes().to_vec())
			.collect();
		let stdin = stdin_data(&mut rng, reads);
		let what = format!(
			"cmd {cmd} script {body:?} stdin {:?}",
			stdin.as_ref().map(Vec::len)
		);
		let args: Vec<&[u8]> = argv.iter().map(|a| &a[..]).collect();
		both(
			&fix,
			&mut c,
			&|_| {},
			&mut |c| {
				c.run_chroot(
					Some(cmd.as_bytes()),
					&argv,
					stdin.as_deref(),
				)
			},
			&mut || {
				let ok = run_chroot(
					&mut r.h,
					Some(cmd.as_bytes()),
					&args,
					stdin.as_deref(),
				);
				r.take(ok, 1)
			},
			&what,
		);
	}
	// a root that is gone: the C logs and reports success
	let argv = vec![b"/bin/sh".to_vec()];
	fix.reset();
	fs::remove_dir_all(fix.rootdir()).unwrap();
	let cr = c.run_chroot(Some(b"/bin/sh"), &argv, None);
	let ok = run_chroot(&mut r.h, Some(b"/bin/sh"), &[b"/bin/sh"], None);
	assert_eq!(cr, r.take(ok, 1));
}

#[test]
fn fc_ldconfig() {
	if !in_child() {
		return;
	}
	let fix = Fix::new("fc-ldconfig");
	let (mut c, mut r) = (fix.c(), fix.r());
	let stub = "#!/bin/sh\necho \"stub $# $0\"\n: > /etc/ld.so.cache\n";
	for conf in [false, true] {
		for mode in [None, Some(0o755), Some(0o644)] {
			let setup = |r: &Path| {
				fs::create_dir_all(r.join("etc")).unwrap();
				if conf {
					fs::write(r.join("etc/ld.so.conf"), "")
						.unwrap();
				}
				if let Some(m) = mode {
					let p = under_root(r, LDCONFIG);
					fs::create_dir_all(p.parent().unwrap())
						.unwrap();
					fs::write(&p, stub).unwrap();
					let perm =
						fs::Permissions::from_mode(m);
					fs::set_permissions(&p, perm).unwrap();
				}
			};
			both(
				&fix,
				&mut c,
				&setup,
				&mut |c| c.ldconfig(),
				&mut || {
					let ok = ldconfig(&mut r.h);
					r.take(ok, 1)
				},
				&format!("conf {conf} mode {mode:?}"),
			);
		}
	}
}

const SCRIPTS: [&str; 7] = [
	"post_install",
	"pre_upgrade",
	"post_upgrade",
	"pre_remove",
	"post_remove",
	"pre_install",
	"",
];

fn install_text(rng: &mut Rng) -> String {
	let mut s = String::new();
	for _ in 0..rng.below(5) {
		let f = pick(rng, &SCRIPTS);
		match rng.below(7) {
			0 => s += &format!("# {f}() {{ echo commented; }}\n"),
			1 => {
				// the name across the end of grep's first 1023
				// byte chunk of the line
				let pad = "p".repeat(1023 - 4 - rng.below(8));
				s += &format!(
					": {pad}; {f}() {{ echo split; }}\n"
				);
			}
			2 => {
				s += &format!(
					"{f}() {{ echo \"$1 $2\" > /tmp/{f}; exit 4; }}\n"
				)
			}
			// $0 is SCRIPTLET_SHELL (trans.c's arg0): the port's
			// path must be the reference's
			3 => s += &format!("{f}() {{ echo \"$0\"; }}\n"),
			_ => {
				s += &format!(
					"{f}() {{\n\techo \"{f} $1 $2\"\n\
					\techo e >&2\n}}\n"
				)
			}
		}
	}
	s
}

#[test]
fn fc_runscriptlet() {
	if !in_child() {
		return;
	}
	let fix = Fix::new("fc-scriptlet");
	let (mut c, mut r) = (fix.c(), fix.r());
	let mut rng = Rng::new(0x5c41);
	let src = fix.tmp.dir().join("install");
	let pkgfile = fix.tmp.dir().join("pkg.tar");
	for _ in 0..(iters() / 500).max(60) {
		let text = install_text(&mut rng);
		let script = pick(&mut rng, &SCRIPTS);
		let oldver = (rng.below(2) == 0).then_some(&b"0.9-1"[..]);
		let is_archive = rng.below(3) == 0;
		let file = match rng.below(8) {
			0 => fix.tmp.dir().join("missing"),
			_ if is_archive => pkgfile.clone(),
			_ => src.clone(),
		};
		let _ = fs::remove_file(&src);
		fs::write(&src, &text).unwrap();
		if rng.below(10) == 0 {
			fs::set_permissions(
				&src,
				fs::Permissions::from_mode(0o000),
			)
			.unwrap();
		}
		let mut entries = vec![tar_file(".PKGINFO", b"pkgname = x\n")];
		if rng.below(4) != 0 {
			entries.push(tar_file(".INSTALL", text.as_bytes()));
		}
		write_db(&pkgfile, pick(&mut rng, &COMPS), &ustar(&entries));
		let no_tmp = rng.below(4) == 0;
		let setup = |r: &Path| {
			if no_tmp {
				fs::remove_dir(r.join("tmp")).unwrap();
			}
		};
		let fpath = file.as_os_str().as_encoded_bytes().to_vec();
		let what = format!(
			"script {script:?} archive {is_archive} file {} no_tmp \
			{no_tmp} oldver {oldver:?}\n{text}",
			file.display()
		);
		both(
			&fix,
			&mut c,
			&setup,
			&mut |c| {
				c.runscriptlet(
					&fpath,
					script.as_bytes(),
					b"1.0-1",
					oldver,
					is_archive,
				)
			},
			&mut || {
				let ok = runscriptlet(
					&mut r.h,
					&fpath,
					script.as_bytes(),
					b"1.0-1",
					oldver,
					is_archive,
				);
				r.take(ok, 1)
			},
			&what,
		);
		fs::set_permissions(&src, fs::Permissions::from_mode(0o644))
			.unwrap();
	}
}

// hooks in root/etc/pacman.d/hooks and root/usr/share/libalpm/hooks,
// Exec inside the chroot
#[test]
fn fc_hooks() {
	if !in_child() {
		return;
	}
	let fix = Fix::new("fc-hooks");
	let (mut c, mut r) = (fix.c(), fix.r());
	let sys = [&fix.root[..], b"usr/share/libalpm/hooks/"].concat();
	let etc = [&fix.root[..], b"etc/pacman.d/hooks/"].concat();
	let dirs = vec![sys, etc];
	c.set_hookdirs(&dirs);
	r.set_hookdirs(&dirs);
	let mut rng = Rng::new(0x400c5);
	let names = ["a", "b", "foo"];
	let paths = ["usr/bin/x", "etc/conf", "usr/lib/l.so"];
	for _ in 0..(iters() / 500).max(60) {
		let mut hooks = Vec::new();
		for _ in 0..1 + rng.below(4) {
			let dir = pick(
				&mut rng,
				&[
					"usr/share/libalpm/hooks",
					"etc/pacman.d/hooks",
				],
			);
			let name = pick(
				&mut rng,
				&["10-a.hook", "20-b.hook", "z.hook"],
			);
			let mask = rng.below(6) == 0;
			let ty = pick(&mut rng, &["Package", "Path"]);
			let target = match ty {
				"Package" => {
					pick(&mut rng, &["a", "*", "!b", "foo"])
				}
				_ => pick(
					&mut rng,
					&[
						"usr/*",
						"etc/conf",
						"!usr/bin/x",
						"*",
					],
				),
			};
			let op = pick(
				&mut rng,
				&["Install", "Upgrade", "Remove"],
			);
			let when = pick(
				&mut rng,
				&["PreTransaction", "PostTransaction"],
			);
			let abort = if rng.below(3) == 0 {
				"AbortOnFail\n"
			} else {
				""
			};
			let execs = [
				"/bin/sh -c 'while IFS= read -r l; \
				do echo \"t:$l\"; done; : > /tmp/ran'",
				"/bin/sh -c 'echo failing; exit 1'",
				"/nonexistent arg",
				"bin/sh -c 'pwd; echo $0' zero",
			];
			let i = rng.below(execs.len());
			// targets only for the Exec reading them (see fc_run_chroot)
			let needs = match i == 0 && rng.below(2) == 0 {
				true => "NeedsTargets\n",
				false => "",
			};
			let exec = execs[i];
			let text = format!(
				"[Trigger]\nOperation = {op}\nType = {ty}\n\
				Target = {target}\n[Action]\n\
				Description = {name} in {dir}\nWhen = {when}\n\
				{needs}{abort}Exec = {exec}\n"
			);
			hooks.push((dir, name, mask, text));
		}
		let setup = |r: &Path| {
			for (dir, name, mask, text) in &hooks {
				let d = r.join(dir);
				fs::create_dir_all(&d).unwrap();
				let p = d.join(name);
				let _ = fs::remove_file(&p);
				if *mask {
					symlink("/dev/null", &p).unwrap();
				} else {
					fs::write(&p, text).unwrap();
				}
			}
		};
		let pkg = |rng: &mut Rng| {
			let name = pick(rng, &names).as_bytes().to_vec();
			let mut p = Package {
				name: Some(name.into()),
				..Package::default()
			};
			for f in paths.iter().filter(|_| rng.below(2) == 0) {
				p.files.files.push(
					alpm_core::filelist::File::new(
						f.as_bytes().to_vec(),
						0,
						0o100644,
					),
				);
			}
			p
		};
		let adds: Vec<Package> =
			(0..rng.below(3)).map(|_| pkg(&mut rng)).collect();
		let olds: Vec<Option<Package>> = adds
			.iter()
			.map(|_| (rng.below(2) == 0).then(|| pkg(&mut rng)))
			.collect();
		let removes: Vec<Package> =
			(0..rng.below(2)).map(|_| pkg(&mut rng)).collect();
		let when = match rng.below(2) {
			0 => HookWhen::PreTransaction,
			_ => HookWhen::PostTransaction,
		};
		let ct: Vec<(&Package, Option<&Package>)> = adds
			.iter()
			.zip(&olds)
			.map(|(p, o)| (p, o.as_ref()))
			.collect();
		let rt: Vec<AddTarget> = ct
			.iter()
			.map(|&(pkg, oldpkg)| AddTarget { pkg, oldpkg })
			.collect();
		let rem: Vec<&Package> = removes.iter().collect();
		let what = format!(
			"{when:?} hooks {:?}",
			hooks.iter()
				.map(|h| (h.0, h.1, h.2))
				.collect::<Vec<_>>()
		);
		both(
			&fix,
			&mut c,
			&setup,
			&mut |c| {
				let r = c.hook_run(&ct, &rem, when);
				(if r.0 == 0 { 0 } else { 1 }, r.1, r.2)
			},
			&mut || {
				let targets = Targets {
					add: &rt,
					remove: &rem,
				};
				let ok = hook_run(&mut r.h, &targets, when);
				r.take(ok, 1)
			},
			&what,
		);
	}
}
