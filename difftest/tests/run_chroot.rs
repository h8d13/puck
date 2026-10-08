// alpm_core::util::{run_chroot, ldconfig}, trans::runscriptlet and
// hook::hook_run against the C, for real in a chroot of a fixture root,
// both under fakechroot(1) as pacman's own test suite runs them
// (pmtest.py). `under_fakechroot` re-runs this binary's fc_* tests under
// fakechroot; outside it they return at once. the root holds a copy of
// /bin/sh (dynamically linked, fakechroot loads the host libraries).
// compared per case: return value, log lines and events in order, the
// logfile lines, and the root tree afterwards (paths, types, modes,
// contents).
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;

use alpm_core::hook::{AddTarget, HookEnv, HookWhen, hook_run};
use alpm_core::package::Package;
use alpm_core::trans::runscriptlet;
use alpm_core::util::{ldconfig, run_chroot};
use difftest::{
	CHookHandle, CHookResult, COMPS, HookRecorder, Rng, TempRoot, iters,
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

	// root/ with bin/sh and tmp/ only
	fn reset(&self) {
		let r = self.rootdir();
		if fs::symlink_metadata(&r).is_ok() {
			chmod_all(&r);
			fs::remove_dir_all(&r).unwrap();
		}
		fs::create_dir_all(r.join("bin")).unwrap();
		fs::create_dir(r.join("tmp")).unwrap();
		fs::copy("/bin/sh", r.join("bin/sh")).unwrap();
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

// every path below dir with its type, mode and content (bin/sh skipped)
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
		if rel == "bin/sh" {
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

fn rust(rec: HookRecorder, ok: bool) -> CHookResult {
	(if ok { 0 } else { 1 }, rec.recs, rec.actions)
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
	let mut c = fix.c();
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
		// the child's execv failure, from chroot(8) on the Rust side
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
		let mut rec = HookRecorder::default();
		let ok = run_chroot(
			&fix.root,
			Some(cmd.as_bytes()),
			&args,
			None,
			&mut rec,
		);
		assert_eq!(cr, rust(rec, ok), "{cmd} {script}");
	}
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
	let mut c = fix.c();
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
				let mut rec = HookRecorder::default();
				let ok = run_chroot(
					&fix.root,
					Some(cmd.as_bytes()),
					&args,
					stdin.as_deref(),
					&mut rec,
				);
				rust(rec, ok)
			},
			&what,
		);
	}
	// a root that is gone: the C logs and reports success
	let argv = vec![b"/bin/sh".to_vec()];
	fix.reset();
	fs::remove_dir_all(fix.rootdir()).unwrap();
	let cr = c.run_chroot(Some(b"/bin/sh"), &argv, None);
	let mut rec = HookRecorder::default();
	let ok = run_chroot(
		&fix.root,
		Some(b"/bin/sh"),
		&[b"/bin/sh"],
		None,
		&mut rec,
	);
	assert_eq!(cr, rust(rec, ok));
}

#[test]
fn fc_ldconfig() {
	if !in_child() {
		return;
	}
	let fix = Fix::new("fc-ldconfig");
	let mut c = fix.c();
	let stub = "#!/bin/sh\necho \"stub $# $0\"\n: > /etc/ld.so.cache\n";
	for conf in [false, true] {
		for mode in [None, Some(0o755), Some(0o644)] {
			let setup = |r: &Path| {
				fs::create_dir_all(r.join("etc")).unwrap();
				fs::create_dir_all(r.join("sbin")).unwrap();
				if conf {
					fs::write(r.join("etc/ld.so.conf"), "")
						.unwrap();
				}
				if let Some(m) = mode {
					let p = r.join("sbin/ldconfig");
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
					let mut rec = HookRecorder::default();
					let ok = ldconfig(&fix.root, &mut rec);
					rust(rec, ok)
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
		match rng.below(6) {
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
	let mut c = fix.c();
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
				let mut rec = HookRecorder::default();
				let ok = runscriptlet(
					&fix.root,
					&fpath,
					script.as_bytes(),
					b"1.0-1",
					oldver,
					is_archive,
					&mut rec,
				);
				rust(rec, ok)
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
	let mut c = fix.c();
	let sys = [&fix.root[..], b"usr/share/libalpm/hooks/"].concat();
	let etc = [&fix.root[..], b"etc/pacman.d/hooks/"].concat();
	let dirs = vec![sys, etc];
	c.set_hookdirs(&dirs);
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
				name: Some(name),
				..Package::default()
			};
			for f in paths.iter().filter(|_| rng.below(2) == 0) {
				p.files.files.push(alpm_core::filelist::File {
					name: f.as_bytes().to_vec(),
					size: 0,
					mode: 0o100644,
				});
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
				let mut rec = HookRecorder::default();
				let env = HookEnv {
					root: &fix.root,
					hookdirs: &dirs,
					noextract: &[],
					local: &[],
					add: &rt,
					remove: &rem,
				};
				let ok = hook_run(&env, when, &mut rec);
				rust(rec, ok)
			},
			&what,
		);
	}
}
