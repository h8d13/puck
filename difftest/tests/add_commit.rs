// alpm_core::add::upgrade_package (commit_single_pkg and the extraction
// under it) against the C _alpm_upgrade_packages with one package in the
// transaction. compared per case: rc, pm_errno, log lines, events and
// progress in order, the logfile, the root tree (types, modes, link
// counts, contents, link targets, archive mtimes) and the local db
// written (%INSTALLDATE% masked). run as the invoking user: entries owned
// by that user chown as a no-op on both sides, others fail the same way.
use alpm_core::util::compute_md5sum;
use difftest::{
	AC_SDE_EXACT, AcCase, AcFs, AcNode, AcOld, AcRec, AcResult, Comp, Rng,
	TarNode, TempRoot, c_upgrade, force_remove, iters, rust_upgrade,
	umask_lock,
};

fn file(name: &str, mode: u32, data: &[u8]) -> TarNode {
	TarNode {
		name: name.as_bytes().to_vec(),
		kind: b'0',
		mode,
		link: Vec::new(),
		data: data.to_vec(),
	}
}

fn dir(name: &str, mode: u32) -> TarNode {
	TarNode {
		name: name.as_bytes().to_vec(),
		kind: b'5',
		mode,
		link: Vec::new(),
		data: Vec::new(),
	}
}

fn link(name: &str, kind: u8, target: &str) -> TarNode {
	TarNode {
		name: name.as_bytes().to_vec(),
		kind,
		mode: 0o777,
		link: target.as_bytes().to_vec(),
		data: Vec::new(),
	}
}

fn case(nodes: Vec<TarNode>) -> AcCase {
	AcCase {
		name: "foo".to_string(),
		version: "1.0-1".to_string(),
		nodes,
		backup: Vec::new(),
		comp: Comp::None,
		owner: None,
		root: Vec::new(),
		old: None,
		noupgrade: Vec::new(),
		noextract: Vec::new(),
		flags: 0,
		stale_oldpkg: false,
		cut: None,
	}
}

// a tree as one line per path
fn flat(node: &AcNode, path: &str, out: &mut Vec<String>) {
	let line = match node {
		AcNode::File(m, n, data, t) => format!(
			"{path} file {m:o} nlink {n} mtime {t} {:?}",
			String::from_utf8_lossy(data)
		),
		AcNode::Dir(m, None) => format!("{path} dir {m:o} unreadable"),
		AcNode::Dir(m, Some(es)) => {
			out.push(format!("{path} dir {m:o}"));
			for (name, n) in es {
				let name = String::from_utf8_lossy(name);
				flat(n, &format!("{path}/{name}"), out);
			}
			return;
		}
		AcNode::Link(t, m) => format!(
			"{path} -> {} mtime {m}",
			String::from_utf8_lossy(t)
		),
		AcNode::Special(m) => format!("{path} special {m:o}"),
		AcNode::Unreadable(m) => format!("{path} unreadable {m:o}"),
	};
	out.push(line);
}

fn show(r: &AcResult) -> String {
	let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
	let mut lines = vec![format!("rc {} errno {}", r.rc, r.errno)];
	for x in &r.recs {
		lines.push(match x {
			AcRec::Log(l, m) => format!("log {l} {:?}", s(m)),
			AcRec::Op(done, op, old, new) => format!(
				"op done={done} {op} {:?} {:?}",
				old.as_deref().map(s),
				new.as_deref().map(s)
			),
			AcRec::Pacnew(nu, old, new, f) => format!(
				"pacnew noupgrade={nu} {:?} {} {}",
				old.as_deref().map(s),
				s(new),
				s(f)
			),
			AcRec::Pacsave(old, f) => {
				format!("pacsave {} {}", s(old), s(f))
			}
			AcRec::Scriptlet(l) => format!("scriptlet {:?}", s(l)),
			AcRec::Progress(k, p, pc, n, i) => {
				format!("progress {k} {} {pc} {i}/{n}", s(p))
			}
			AcRec::Event(k) => format!("event {k}"),
		});
	}
	lines.push(format!("logfile {:?}", s(&r.logfile)));
	flat(&r.root, "root", &mut lines);
	flat(&r.local, "local", &mut lines);
	lines.join("\n")
}

// the lines of a (C) and b (Rust) from the first difference on
fn diff(a: &str, b: &str) -> String {
	let (a, b): (Vec<&str>, Vec<&str>) =
		(a.lines().collect(), b.lines().collect());
	let first = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
	let from = first.saturating_sub(3);
	let mut out = vec!["--- C".to_string()];
	out.extend(a[from..].iter().take(12).map(|l| format!("  {l}")));
	out.push("--- Rust".to_string());
	out.extend(b[from..].iter().take(12).map(|l| format!("  {l}")));
	out.join("\n")
}

// both sides on the case, which must agree
fn compare(tag: &str, c: &AcCase) -> AcResult {
	let _umask = umask_lock();
	let fx = TempRoot::new(tag);
	let log = fx.dir().join("pacman.log");
	let cres = c_upgrade(&fx, c, &log);
	let rres = rust_upgrade(&fx, c, &log);
	// directories a package left without write permission
	force_remove(&fx.dir().join("root"));
	if cres != rres {
		panic!(
			"{tag}: C and Rust differ\n{}",
			diff(&show(&cres), &show(&rres))
		);
	}
	cres
}

fn has_log(r: &AcResult, needle: &str) -> bool {
	r.recs.iter().any(|x| {
		matches!(x, AcRec::Log(_, m)
			if String::from_utf8_lossy(m).contains(needle))
	})
}

fn md5(data: &[u8]) -> String {
	let dir = std::env::temp_dir().join(format!(
		"difftest-ac-md5-{}-{:?}",
		std::process::id(),
		std::thread::current().id()
	));
	std::fs::write(&dir, data).unwrap();
	let sum = compute_md5sum(dir.as_os_str().as_encoded_bytes()).unwrap();
	std::fs::remove_file(&dir).unwrap();
	String::from_utf8(sum).unwrap()
}

fn fs_file(path: &str, data: &[u8]) -> AcFs {
	AcFs::File(path.as_bytes().to_vec(), 0o644, data.to_vec())
}

fn old(version: &str, files: &[&str]) -> AcOld {
	AcOld {
		version: version.to_string(),
		files: files.iter().map(|f| f.to_string()).collect(),
		backup: Vec::new(),
		asdep: false,
		install: false,
	}
}

#[test]
fn install_fresh() {
	let c = case(vec![
		dir("usr/", 0o755),
		dir("usr/bin/", 0o755),
		file("usr/bin/foo", 0o755, b"#!/bin/sh\n"),
		dir("etc/", 0o755),
		file("etc/foo.conf", 0o644, b"a=1\n"),
		link("usr/bin/bar", b'2', "foo"),
		link("usr/bin/baz", b'1', "usr/bin/foo"),
	]);
	let r = compare("ac-fresh", &c);
	assert_eq!(r.rc, 0, "{}", show(&r));
	let gz = AcCase {
		comp: Comp::Gzip,
		..c
	};
	let r = compare("ac-fresh-gz", &gz);
	assert_eq!(r.rc, 0, "{}", show(&r));
}

const CONF: &str = "etc/foo.conf";

// etc/foo.conf as a backup file, upgraded from 1.0-1 to 2.0-1 with the
// original (old package's hash), new (in the package) and current (on
// disk, None missing) contents
fn backup_case(
	orig: Option<&[u8]>,
	new: &[u8],
	current: Option<&[u8]>,
) -> AcCase {
	let mut c = case(vec![dir("etc/", 0o755), file(CONF, 0o644, new)]);
	c.version = "2.0-1".to_string();
	c.backup = vec![CONF.to_string()];
	let mut o = old("1.0-1", &["etc/", CONF]);
	o.backup = vec![(CONF.to_string(), orig.map(md5))];
	c.old = Some(o);
	c.root = vec![AcFs::Dir(b"etc".to_vec(), 0o755)];
	if let Some(cur) = current {
		c.root.push(fs_file(CONF, cur));
	}
	c
}

fn pacnews(r: &AcResult) -> usize {
	r.recs.iter()
		.filter(|x| matches!(x, AcRec::Pacnew(..)))
		.count()
}

#[test]
fn backup_md5_states() {
	// unchanged on disk: the new file replaces it
	let r = compare("ac-bk1", &backup_case(Some(b"o"), b"n", Some(b"o")));
	assert!(has_log(&r, "action: installing new file"), "{}", show(&r));
	// user-modified, package unchanged: left alone
	let r = compare("ac-bk2", &backup_case(Some(b"o"), b"o", Some(b"m")));
	assert!(has_log(&r, "leaving existing file"), "{}", show(&r));
	// all three differ: .pacnew
	let r = compare("ac-bk3", &backup_case(Some(b"o"), b"n", Some(b"m")));
	assert_eq!(pacnews(&r), 1, "{}", show(&r));
	// new == current
	let r = compare("ac-bk4", &backup_case(Some(b"o"), b"n", Some(b"n")));
	assert!(has_log(&r, "action: installing new file"), "{}", show(&r));
	// missing on disk: extracted directly
	let r = compare("ac-bk5", &backup_case(Some(b"o"), b"n", None));
	assert!(!has_log(&r, "checking hashes"), "{}", show(&r));
	// (null) original hash
	let r = compare("ac-bk6", &backup_case(None, b"n", Some(b"m")));
	assert_eq!(pacnews(&r), 1, "{}", show(&r));
	let r = compare("ac-bk7", &backup_case(None, b"n", Some(b"n")));
	assert_eq!(pacnews(&r), 0, "{}", show(&r));
	// a .pacnew already there stays when the local file is kept
	let mut c = backup_case(Some(b"o"), b"o", Some(b"m"));
	c.root.push(fs_file("etc/foo.conf.pacnew", b"stale"));
	compare("ac-bk8", &c);
	// reinstall and downgrade with a modified file
	let mut c = backup_case(Some(b"o"), b"n", Some(b"m"));
	c.version = "1.0-1".to_string();
	compare("ac-bk9", &c);
	c.version = "0.5-1".to_string();
	compare("ac-bk10", &c);
}

#[test]
fn backup_retroactive_and_install() {
	// the old package did not list it: no original hash
	let mut c = backup_case(Some(b"o"), b"n", Some(b"m"));
	c.old.as_mut().unwrap().backup.clear();
	let r = compare("ac-retro", &c);
	assert_eq!(pacnews(&r), 1, "{}", show(&r));
	// a fresh install over an unowned file listed as backup
	let mut c = backup_case(Some(b"o"), b"n", Some(b"m"));
	c.old = None;
	let r = compare("ac-retro-new", &c);
	assert_eq!(pacnews(&r), 1, "{}", show(&r));
	// same content: no .pacnew
	let mut c = backup_case(Some(b"o"), b"n", Some(b"n"));
	c.old = None;
	compare("ac-retro-same", &c);
}

#[test]
fn noupgrade_noextract() {
	let mut c = backup_case(Some(b"o"), b"n", Some(b"o"));
	c.noupgrade = vec![CONF.as_bytes().to_vec()];
	let r = compare("ac-noupgrade", &c);
	assert_eq!(pacnews(&r), 1, "{}", show(&r));
	// negated: upgraded normally
	c.noupgrade.push(b"!etc/*".to_vec());
	let r = compare("ac-noupgrade-neg", &c);
	assert_eq!(pacnews(&r), 0, "{}", show(&r));
	// a missing file in NoUpgrade is extracted
	let mut c = backup_case(Some(b"o"), b"n", None);
	c.noupgrade = vec![b"etc/*".to_vec()];
	compare("ac-noupgrade-missing", &c);
	let mut c = case(vec![
		dir("etc/", 0o755),
		file(CONF, 0o644, b"x"),
		dir("usr/", 0o755),
		file("usr/a", 0o644, b"a"),
	]);
	c.noextract = vec![b"etc/*".to_vec(), b"usr/".to_vec()];
	let r = compare("ac-noextract", &c);
	assert!(has_log(&r, "is in NoExtract"), "{}", show(&r));
}

#[test]
fn type_changes() {
	// case 4: a directory over a file
	let mut c = case(vec![dir("usr/", 0o755), file("usr/a", 0o644, b"a")]);
	c.root = vec![fs_file("usr", b"file")];
	let r = compare("ac-dir-over-file", &c);
	assert_eq!(r.rc, 0, "{}", show(&r));
	// case 5: a file over a directory fails the package
	let mut c = case(vec![dir("etc/", 0o755), file(CONF, 0o644, b"x")]);
	c.root = vec![AcFs::Dir(CONF.as_bytes().to_vec(), 0o755)];
	let r = compare("ac-file-over-dir", &c);
	assert_eq!(r.rc, -1, "{}", show(&r));
	// case 6: directory permissions differ
	let mut c = case(vec![dir("usr/", 0o755), dir("usr/lib/", 0o700)]);
	c.root = vec![AcFs::Dir(b"usr/lib".to_vec(), 0o750)];
	let r = compare("ac-dir-perms", &c);
	assert!(has_log(&r, "permissions differ"), "{}", show(&r));
	// a symlink in the way of a directory entry, and one in the middle
	// of a path
	let mut c = case(vec![
		dir("usr/", 0o755),
		dir("usr/share/", 0o755),
		file("usr/share/x", 0o644, b"x"),
		file("usr/lib/y", 0o644, b"y"),
	]);
	c.root = vec![
		AcFs::Dir(b"usr/real".to_vec(), 0o755),
		AcFs::Link(b"usr/share".to_vec(), b"real".to_vec()),
		AcFs::Link(b"usr/lib".to_vec(), b"real".to_vec()),
	];
	compare("ac-symlinks", &c);
	// a symlink over a file and a file over a symlink
	let mut c = case(vec![
		dir("etc/", 0o755),
		link("etc/a", b'2', "b"),
		file("etc/c", 0o600, b"c"),
	]);
	c.root = vec![
		fs_file("etc/a", b"was a file"),
		AcFs::Link(b"etc/c".to_vec(), b"a".to_vec()),
	];
	compare("ac-link-file", &c);
}

#[test]
fn modes_owners_nodes() {
	let nodes = vec![
		dir("usr/", 0o755),
		dir("usr/sgid/", 0o2775),
		dir("usr/sticky/", 0o1777),
		file("usr/suid", 0o4755, b"s"),
		file("usr/sgid/f", 0o2755, b"g"),
		file("usr/ro", 0o444, b"r"),
		file("usr/empty", 0o600, b""),
		TarNode {
			name: b"usr/fifo".to_vec(),
			kind: b'6',
			mode: 0o640,
			link: Vec::new(),
			data: Vec::new(),
		},
		TarNode {
			name: b"usr/null".to_vec(),
			kind: b'3',
			mode: 0o666,
			link: Vec::new(),
			data: Vec::new(),
		},
	];
	compare("ac-modes", &case(nodes.clone()));
	// owned by root: chown fails, SUID/SGID dropped with a warning
	let mut c = case(nodes);
	c.owner = Some((0, 0));
	let r = compare("ac-modes-root", &c);
	assert!(has_log(&r, "Can't set user=0/group=0"), "{}", show(&r));
}

#[test]
fn links_and_db_files() {
	let mut c = case(vec![
		file(
			".INSTALL",
			0o755,
			b"# no functions here
",
		),
		file(
			".CHANGELOG",
			0o600,
			b"log
",
		),
		file(
			".BUILDINFO",
			0o644,
			b"x
",
		),
		dir("usr/", 0o755),
		link("usr/hard", b'1', "usr/missing"),
		link("usr/self", b'1', "usr/self"),
		file("usr/a", 0o644, b"a"),
		link("usr/b", b'1', "usr/a"),
	]);
	let r = compare("ac-links", &c);
	assert!(has_log(&r, "does not exist"), "{}", show(&r));
	c.flags = 1 << 6; // DBONLY
	compare("ac-dbonly", &c);
	c.flags = 1 << 10; // NOSCRIPTLET
	compare("ac-noscriptlet", &c);
}

#[test]
fn upgrade_reasons_and_removal() {
	let mut c =
		case(vec![dir("usr/", 0o755), file("usr/new", 0o644, b"n")]);
	c.version = "2.0-1".to_string();
	let mut o = old("1.0-1", &["usr/", "usr/gone", "usr/olddir/"]);
	o.asdep = true;
	c.old = Some(o);
	c.root = vec![
		fs_file("usr/gone", b"g"),
		AcFs::Dir(b"usr/olddir".to_vec(), 0o755),
	];
	let r = compare("ac-upgrade", &c);
	assert!(has_log(&r, "removing old package first"), "{}", show(&r));
	for flags in [1 << 8, 1 << 14, 1 << 2] {
		c.flags = flags;
		compare("ac-upgrade-flags", &c);
	}
	// oldpkg set without an installed package: an install
	let mut c = case(vec![file("a", 0o644, b"a")]);
	c.stale_oldpkg = true;
	compare("ac-stale", &c);
}

#[test]
fn broken_packages() {
	// a regular file entry cut short: the data read fails
	let mut c = case(vec![
		file("a", 0o644, b"a"),
		file("big", 0o644, &[7u8; 3000]),
		file("after", 0o644, b"z"),
	]);
	c.cut = Some(3 * 512 + 1024);
	let r = compare("ac-cut", &c);
	assert_eq!(r.rc, -1, "{}", show(&r));
	// cut inside a header: the loop ends there
	c.cut = Some(2 * 512 + 100);
	compare("ac-cut-header", &c);
	// the package file gone
	c.cut = Some(0);
	compare("ac-cut-empty", &c);
}

// get_install_time: each SOURCE_DATE_EPOCH value in a child run of
// sde_child (the environment is process wide)
const SDE_CHILD: &str = "DIFFTEST_SDE_CHILD";

#[test]
fn source_date_epoch() {
	if std::env::var_os(SDE_CHILD).is_some() {
		return;
	}
	let exe = std::env::current_exe().unwrap();
	for (value, exact) in [
		("1234", true),
		(" +77", true),
		("-1", true),
		("18446744073709551615", true),
		("12x", false),
		("", false),
		("18446744073709551616", false),
	] {
		let mut cmd = std::process::Command::new(&exe);
		cmd.args(["sde_child", "--exact", "--test-threads=1"])
			.env(SDE_CHILD, "1")
			.env("SOURCE_DATE_EPOCH", value);
		if exact {
			cmd.env(AC_SDE_EXACT, "1");
		}
		let out = cmd.output().unwrap();
		let stdout = String::from_utf8_lossy(&out.stdout);
		assert!(
			out.status.success() && stdout.contains("1 passed"),
			"SOURCE_DATE_EPOCH={value:?}\n{stdout}\n{}",
			String::from_utf8_lossy(&out.stderr)
		);
	}
}

#[test]
fn sde_child() {
	if std::env::var_os(SDE_CHILD).is_none() {
		return;
	}
	compare("ac-sde", &case(vec![file("a", 0o644, b"a")]));
}

// ---- fuzz ----

const PATHS: [&str; 7] = ["a", "a/b", "a/c", "a/b/d", "b", "b/a", "c"];
const DATA: [&[u8]; 4] = [b"o", b"n", b"m", b""];
const FILE_MODES: [u32; 7] =
	[0o644, 0o600, 0o755, 0o444, 0o4755, 0o2755, 0o640];
const DIR_MODES: [u32; 5] = [0o755, 0o700, 0o2755, 0o1777, 0o750];
const VERSIONS: [&str; 3] = ["0.5-1", "1.0-1", "2.0-1"];
const PATTERNS: [&str; 6] = ["a/*", "!a/b", "*", "a/b", "c", "!*"];

fn pick<T: Copy>(rng: &mut Rng, items: &[T]) -> T {
	items[rng.below(items.len())]
}

fn subset<'a>(rng: &mut Rng, items: &[&'a str], keep: usize) -> Vec<&'a str> {
	items.iter()
		.copied()
		.filter(|_| rng.below(keep) == 0)
		.collect()
}

fn parents(path: &str) -> Vec<String> {
	let mut out = Vec::new();
	let mut p = String::new();
	for part in path.split('/') {
		if !p.is_empty() {
			out.push(format!("{p}/"));
			p.push('/');
		}
		p.push_str(part);
	}
	out
}

fn gen_nodes(rng: &mut Rng) -> (Vec<TarNode>, Vec<String>) {
	let mut nodes = Vec::new();
	let mut files = Vec::new();
	let mut paths = subset(rng, &PATHS, 2);
	// archive order is not always parents first
	if rng.below(3) == 0 {
		paths.reverse();
	}
	for p in paths {
		if rng.below(2) == 0 {
			for d in parents(p) {
				if !nodes.iter().any(|n: &TarNode| {
					n.name == d.as_bytes()
				}) {
					nodes.push(dir(
						&d,
						pick(rng, &DIR_MODES),
					));
				}
			}
		}
		let node = match rng.below(10) {
			0..=4 => {
				files.push(p.to_string());
				file(
					p,
					pick(rng, &FILE_MODES),
					pick(rng, &DATA),
				)
			}
			5 | 6 => dir(&format!("{p}/"), pick(rng, &DIR_MODES)),
			7 => link(
				p,
				b'2',
				pick(rng, &["b", "../c", "a/b", "x"]),
			),
			// no fifos: md5 of a backup path that leads to one
			// blocks both sides in open(2)
			_ => link(p, b'1', pick(rng, &PATHS)),
		};
		if !nodes.iter().any(|n| n.name == node.name) {
			nodes.push(node);
		}
	}
	(nodes, files)
}

fn gen_root(rng: &mut Rng) -> Vec<AcFs> {
	let mut out = Vec::new();
	let mut taken: Vec<String> = Vec::new();
	for p in subset(rng, &PATHS, 2) {
		// the parents must be directories
		if taken.iter().any(|t| p.starts_with(&format!("{t}/"))) {
			continue;
		}
		let path = p.as_bytes().to_vec();
		match rng.below(5) {
			0 | 1 => {
				out.push(AcFs::File(
					path,
					pick(rng, &FILE_MODES),
					pick(rng, &DATA).to_vec(),
				));
				taken.push(p.to_string());
			}
			2 | 3 => {
				out.push(AcFs::Dir(path, pick(rng, &DIR_MODES)))
			}
			_ => {
				let t = pick(
					rng,
					&["a", "../c", "b/a", "nowhere"],
				);
				out.push(AcFs::Link(
					path,
					t.as_bytes().to_vec(),
				));
				taken.push(p.to_string());
			}
		}
	}
	out
}

fn gen_old(rng: &mut Rng, new_files: &[String]) -> AcOld {
	let mut files: Vec<String> = Vec::new();
	let mut plain: Vec<String> = Vec::new();
	let mut chosen = subset(rng, &PATHS, 2);
	chosen.extend(new_files
		.iter()
		.map(|s| s.as_str())
		.filter(|_| rng.below(2) == 0));
	for p in chosen {
		files.extend(parents(p));
		match rng.below(3) {
			0 => files.push(format!("{p}/")),
			_ => {
				files.push(p.to_string());
				plain.push(p.to_string());
			}
		}
	}
	files.sort();
	files.dedup();
	// a path both as file and directory is not a valid list
	let dirs: Vec<String> =
		files.iter().filter(|f| f.ends_with('/')).cloned().collect();
	files.retain(|f| f.ends_with('/') || !dirs.contains(&format!("{f}/")));
	plain.retain(|p| files.contains(p));
	plain.sort();
	plain.dedup();
	let mut backup = Vec::new();
	for p in &plain {
		if rng.below(2) == 0 {
			continue;
		}
		let h = match rng.below(5) {
			0 => None,
			_ => Some(md5(pick(rng, &DATA))),
		};
		backup.push((p.clone(), h));
	}
	AcOld {
		version: pick(rng, &VERSIONS).to_string(),
		files,
		backup,
		asdep: rng.below(2) == 0,
		install: rng.below(4) == 0,
	}
}

fn gen_case(rng: &mut Rng) -> AcCase {
	let (nodes, files) = gen_nodes(rng);
	let mut c = case(nodes);
	c.version = pick(rng, &VERSIONS).to_string();
	c.backup = files
		.iter()
		.filter(|_| rng.below(2) == 0)
		.cloned()
		.collect();
	c.comp = match rng.below(4) {
		0 => Comp::Gzip,
		_ => Comp::None,
	};
	if rng.below(8) == 0 {
		c.owner = Some((0, 0));
	}
	c.root = gen_root(rng);
	if rng.below(3) != 0 {
		c.old = Some(gen_old(rng, &files));
	}
	let pats = |rng: &mut Rng| -> Vec<Vec<u8>> {
		match rng.below(3) {
			0 => subset(rng, &PATTERNS, 3)
				.iter()
				.map(|p| p.as_bytes().to_vec())
				.collect(),
			_ => Vec::new(),
		}
	};
	c.noupgrade = pats(rng);
	c.noextract = pats(rng);
	c.flags = match rng.below(12) {
		0 => 1 << 2,  // NOSAVE
		1 => 1 << 8,  // ALLDEPS
		2 => 1 << 14, // ALLEXPLICIT
		3 => 1 << 6,  // DBONLY
		_ => 0,
	};
	c.stale_oldpkg = rng.below(20) == 0;
	c
}

// every case runs C and Rust and builds two trees: a hundredth of iters()
#[test]
fn fuzz_commit() {
	let mut rng = Rng::new(0xadd_c0de);
	let n = (iters() / 200).max(200);
	let (mut failed, mut pacnew) = (0, 0);
	// branches every run must reach
	let marks = [
		"action: installing new file",
		"leaving existing file in place",
		"is in NoExtract",
		"not overwriting dir with file",
		"overwriting file with dir",
		"directory permissions differ",
		"Can't set user=0/group=0",
		"removing old package first",
		"is in skip_remove",
		"warning given when extracting",
		"extracting db files",
	];
	let mut seen = vec![0; marks.len()];
	for i in 0..n {
		let c = gen_case(&mut rng);
		let r = compare(&format!("ac-fuzz-{i}"), &c);
		failed += usize::from(r.rc != 0);
		pacnew += pacnews(&r);
		for (m, k) in marks.iter().zip(&mut seen) {
			*k += usize::from(has_log(&r, m));
		}
	}
	// both outcomes and the backup paths are reached
	assert!(failed > 0 && failed < n, "failed {failed} of {n}");
	assert!(pacnew > 0, "no .pacnew in {n} cases");
	for (m, k) in marks.iter().zip(&seen) {
		assert!(*k > 0, "{m:?} never reached in {n} cases");
	}
}

// ---- scriptlets, for real under fakechroot(1) ----

const FC_CHILD: &str = "DIFFTEST_IN_FAKECHROOT";

fn in_fakechroot() -> bool {
	std::env::var_os(FC_CHILD).is_some()
}

// re-runs this binary's fc_ tests under fakechroot, like run_chroot.rs
#[test]
fn under_fakechroot() {
	if in_fakechroot() || std::env::var_os(SDE_CHILD).is_some() {
		return;
	}
	let exe = std::env::current_exe().unwrap();
	let out = std::process::Command::new("fakechroot")
		.arg(exe)
		.args(["fc_", "--test-threads=1"])
		.env(FC_CHILD, "1")
		.output()
		.expect("fakechroot not found");
	let stdout = String::from_utf8_lossy(&out.stdout);
	assert!(
		out.status.success() && stdout.contains("1 passed"),
		"fakechroot run: {}\n{stdout}\n{}",
		out.status,
		String::from_utf8_lossy(&out.stderr)
	);
}

const INSTALL: &[u8] = b"pre_install() { echo pre \"$@\"; }
post_install() { echo post \"$@\"; }
pre_upgrade() { echo preup \"$@\"; }
post_upgrade() { echo postup \"$@\"; exit 3; }
";

#[test]
fn fc_scriptlets() {
	if !in_fakechroot() {
		return;
	}
	let sh = std::fs::read("/bin/sh").unwrap();
	let mut c = case(vec![
		file(".INSTALL", 0o644, INSTALL),
		dir("usr/", 0o755),
		file("usr/a", 0o644, b"a"),
	]);
	c.root = vec![
		AcFs::File(b"bin/sh".to_vec(), 0o755, sh),
		AcFs::Dir(b"tmp".to_vec(), 0o1777),
	];
	let r = compare("ac-fc-install", &c);
	let lines = r.recs.iter().filter(|x| matches!(x, AcRec::Scriptlet(_)));
	assert_eq!(lines.count(), 2, "{}", show(&r));
	let mut o = old("0.5-1", &["usr/", "usr/a"]);
	o.install = true;
	c.old = Some(o);
	let r = compare("ac-fc-upgrade", &c);
	let postup = AcRec::Scriptlet(b"postup 1.0-1 0.5-1\n".to_vec());
	assert!(r.recs.contains(&postup), "{}", show(&r));
	c.flags = 1 << 10; // NOSCRIPTLET
	compare("ac-fc-noscriptlet", &c);
}
