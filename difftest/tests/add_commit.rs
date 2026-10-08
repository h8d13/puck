// alpm_core::add::upgrade_package (commit_single_pkg and the extraction
// under it) against the C _alpm_upgrade_packages with one package in the
// transaction. compared per case: rc, pm_errno, log lines, events and
// progress in order, the logfile, the root tree (types, modes, link
// counts, contents, link targets, archive mtimes) and the local db
// written (%INSTALLDATE% masked). run as the invoking user: entries owned
// by that user chown as a no-op on both sides, others fail the same way.
use alpm_core::util::compute_md5sum;
use difftest::{
	AC_C_LOCALE, AC_SDE_EXACT, AcCase, AcFs, AcMeta, AcNode, AcOld, AcRec,
	AcResult, Comp, Rng, TarNode, TempRoot, ac_owner, c_upgrade,
	ext_member, force_remove, iters, pax_record, rust_upgrade, umask_lock,
	ustar_entries,
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
		tail: Vec::new(),
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
		file: None,
	}
}

// owner, archive times and xattrs of a line
fn meta(m: &AcMeta) -> String {
	let t = |t: Option<(i64, i64)>| match t {
		Some((s, ns)) => format!("{s}.{ns:09}"),
		None => "run".to_string(),
	};
	let mut out = format!(
		"{}:{} mtime {} atime {}",
		m.owner.0,
		m.owner.1,
		t(m.mtime),
		t(m.atime)
	);
	for (k, v) in &m.xattrs {
		out += &format!(" {}={:?}", String::from_utf8_lossy(k), v);
	}
	out
}

// a tree as one line per path
fn flat(node: &AcNode, path: &str, out: &mut Vec<String>) {
	let line = match node {
		AcNode::File(m, n, data, md) => format!(
			"{path} file {m:o} nlink {n} {} {:?}",
			meta(md),
			String::from_utf8_lossy(data)
		),
		AcNode::Dir(m, None, md) => {
			format!("{path} dir {m:o} {} unreadable", meta(md))
		}
		AcNode::Dir(m, Some(es), md) => {
			out.push(format!("{path} dir {m:o} {}", meta(md)));
			for (name, n) in es {
				let name = String::from_utf8_lossy(name);
				flat(n, &format!("{path}/{name}"), out);
			}
			return;
		}
		AcNode::Link(t, md) => format!(
			"{path} -> {} {}",
			String::from_utf8_lossy(t),
			meta(md)
		),
		AcNode::Special(m, md) => {
			format!("{path} special {m:o} {}", meta(md))
		}
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
	compare_by(tag, c, |_| true)
}

// both sides on the case, C first
fn run_pair(tag: &str, c: &AcCase) -> (AcResult, AcResult) {
	let _umask = umask_lock();
	let fx = TempRoot::new(tag);
	let log = fx.dir().join("pacman.log");
	let cres = c_upgrade(&fx, c, &log);
	let rres = rust_upgrade(&fx, c, &log);
	// directories a package left without write permission
	force_remove(&fx.dir().join("root"));
	(cres, rres)
}

// compare on the records keep() takes
fn compare_by(tag: &str, c: &AcCase, keep: fn(&AcRec) -> bool) -> AcResult {
	let (mut cres, mut rres) = run_pair(tag, c);
	cres.recs.retain(keep);
	rres.recs.retain(keep);
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

// ---- pax headers (libarchive's pax_attribute and set_xattrs) ----

// a member written by hand: the 'x' body before it (None: no header),
// then the entry
#[derive(Clone, Debug)]
struct Member {
	pax: Option<Vec<u8>>,
	node: TarNode,
}

fn rec(key: &str, value: &[u8]) -> Vec<u8> {
	pax_record(key.as_bytes(), value)
}

fn with_pax(records: &[Vec<u8>], node: TarNode) -> Member {
	Member {
		pax: Some(records.concat()),
		node,
	}
}

fn plain(node: TarNode) -> Member {
	Member { pax: None, node }
}

// a name in an mtree line: bytes past printable ASCII and '\' as \ooo
fn mtree_name(name: &[u8]) -> String {
	name.iter()
		.map(|&c| match c {
			b'!'..=b'~' if c != b'\\' => (c as char).to_string(),
			_ => format!("\\{c:03o}"),
		})
		.collect()
}

// the file list of the package: path and mtree type
type Listed<'a> = &'a [(&'a [u8], &'a str)];

// a package of members behind a prefix the load reads: .MTREE with the
// file list (the load stops one entry after it, like for makepkg's
// packages) and a plain directory. a member libarchive warns about then
// reaches the extraction loop only
fn pax_case(members: &[Member], listed: Listed) -> AcCase {
	let mut mtree = String::from("#mtree\n./f type=dir\n");
	for (p, t) in listed {
		mtree += &format!("./{} type={t}\n", mtree_name(p));
	}
	let mut c = case(vec![
		file(".MTREE", 0o644, mtree.as_bytes()),
		dir("f/", 0o755),
	]);
	for m in members {
		if let Some(body) = &m.pax {
			c.tail.extend(ext_member(b'x', body));
		}
		c.tail.extend(ustar_entries(
			std::slice::from_ref(&m.node),
			ac_owner(),
		));
	}
	c
}

// the node at path under the root, None when missing
fn find<'a>(r: &'a AcResult, path: &[&[u8]]) -> Option<&'a AcNode> {
	let mut n = &r.root;
	for part in path {
		let AcNode::Dir(_, Some(es), _) = n else {
			return None;
		};
		n = &es.iter().find(|(name, _)| name == part)?.1;
	}
	Some(n)
}

fn node_meta(n: &AcNode) -> Option<&AcMeta> {
	match n {
		AcNode::File(.., m)
		| AcNode::Dir(.., m)
		| AcNode::Link(_, m)
		| AcNode::Special(_, m) => Some(m),
		AcNode::Unreadable(_) => None,
	}
}

fn meta_of<'a>(r: &'a AcResult, name: &[u8]) -> &'a AcMeta {
	find(r, &[name]).and_then(node_meta).unwrap_or_else(|| {
		panic!("{} missing\n{}", String::from_utf8_lossy(name), show(r))
	})
}

#[test]
fn pax_names() {
	let long = format!("d/{}", "a".repeat(140));
	let lp = long.as_bytes();
	let members = [
		with_pax(&[rec("path", lp)], file("x", 0o644, b"long")),
		with_pax(&[rec("linkpath", lp)], link("s", b'2', "t")),
		with_pax(&[rec("linkpath", lp)], link("h", b'1', "z")),
		// a link name on a regular entry makes it a hard link, its
		// data written through it
		with_pax(&[rec("linkpath", lp)], file("r", 0o644, b"data")),
		// a nul ends the value, an empty path keeps the header's
		with_pax(&[rec("path", b"n\0ul")], file("x2", 0o644, b"n")),
		with_pax(&[rec("path", b"")], file("e", 0o644, b"e")),
		// the last record of a key wins
		with_pax(
			&[rec("path", b"first"), rec("path", b"last")],
			file("x3", 0o644, b"l"),
		),
	];
	let listed: Listed = &[
		(lp, "file"),
		(b"s", "link"),
		(b"h", "file"),
		(b"r", "file"),
		(b"n", "file"),
		(b"e", "file"),
		(b"last", "file"),
	];
	let r = compare("ac-pax-names", &pax_case(&members, listed));
	assert_eq!(r.rc, 0, "{}", show(&r));
	let t = find(&r, &[b"d", &lp[2..]]);
	assert!(matches!(t, Some(AcNode::File(_, 3, d, _)) if d == b"data"));
	// GNU long names before or after the pax header: the later wins
	let longname = [lp, b"\0"].concat();
	for (tag, order) in [("ac-pax-gnu-l", true), ("ac-pax-gnu-x", false)] {
		let mut c = pax_case(&[], &[(lp, "file"), (b"other", "file")]);
		let l = ext_member(b'L', &longname);
		let x = ext_member(b'x', &rec("path", b"other"));
		let (a, b) = if order { (l, x) } else { (x, l) };
		c.tail = [a, b].concat();
		c.tail.extend(ustar_entries(
			&[file("y", 0o644, b"y")],
			ac_owner(),
		));
		compare(tag, &c);
	}
}

#[test]
fn pax_times() {
	let t = |k: &str, v: &str| rec(k, v.as_bytes());
	let members = [
		with_pax(
			&[
				t("mtime", "1600000000.123456789"),
				t("atime", "1500000000.5"),
			],
			file("a", 0o644, b"a"),
		),
		with_pax(&[t("mtime", ".5")], file("b", 0o644, b"b")),
		with_pax(&[t("mtime", "1.")], file("c", 0o644, b"c")),
		with_pax(
			&[t("mtime", "1600000000.1234567891")],
			file("e", 0o644, b"e"),
		),
		// the sign is the seconds' only: -1 s + 0.5 s
		with_pax(&[t("mtime", "-1.5")], file("g", 0o644, b"g")),
		with_pax(&[t("mtime", "")], file("h", 0o644, b"h")),
		with_pax(
			&[t("mtime", "1600000000"), t("atime", "1.000000001")],
			dir("dd/", 0o755),
		),
		with_pax(&[t("mtime", "1500000000.25")], link("l", b'2', "a")),
		with_pax(&[t("ctime", "1.5")], file("k", 0o644, b"k")),
		// malformed: ARCHIVE_WARN, the walk ends here
		with_pax(&[t("mtime", "16x")], file("i", 0o644, b"i")),
		plain(file("j", 0o644, b"j")),
	];
	let names = ["a", "b", "c", "e", "g", "h", "dd", "l", "k", "i", "j"];
	let listed: Vec<(&[u8], &str)> = names
		.iter()
		.map(|n| {
			let t = match *n {
				"dd" => "dir",
				"l" => "link",
				_ => "file",
			};
			(n.as_bytes(), t)
		})
		.collect();
	let r = compare("ac-pax-times", &pax_case(&members, &listed));
	assert_eq!(r.rc, 0, "{}", show(&r));
	let a = meta_of(&r, b"a");
	assert_eq!(a.mtime, Some((1_600_000_000, 123_456_789)), "{a:?}");
	assert_eq!(a.atime, Some((1_500_000_000, 500_000_000)), "{a:?}");
	assert_eq!(meta_of(&r, b"g").mtime, Some((-1, 500_000_000)));
	assert!(find(&r, &[b"i"]).is_none() && find(&r, &[b"j"]).is_none());
}

#[test]
fn pax_owners() {
	let (u, g) = ac_owner();
	let (us, gs) = (u.to_string(), g.to_string());
	let members = [
		with_pax(
			&[
				rec("uid", us.as_bytes()),
				rec("gid", gs.as_bytes()),
				rec("uname", b"nobody"),
				rec("gname", b"nobody"),
			],
			file("a", 0o644, b"a"),
		),
		// chown fails for the invoking user, with the pax numbers
		with_pax(&[rec("uid", b"0")], file("b", 0o4755, b"b")),
		with_pax(&[rec("uid", b"4294967296")], file("c", 0o644, b"c")),
		with_pax(&[rec("gid", b" 12abc")], file("d", 0o2755, b"d")),
		// negative: ARCHIVE_WARN ends the walk
		with_pax(&[rec("uid", b"-1")], file("e", 0o644, b"e")),
		plain(file("f", 0o644, b"f")),
	];
	let listed: Listed = &[
		(b"a", "file"),
		(b"b", "file"),
		(b"c", "file"),
		(b"d", "file"),
		(b"e", "file"),
		(b"f", "file"),
	];
	let r = compare("ac-pax-owners", &pax_case(&members, listed));
	assert!(has_log(&r, "Can't set user=4294967296/"), "{}", show(&r));
	assert!(find(&r, &[b"e"]).is_none(), "{}", show(&r));
}

// a version 2 file capability: cap_net_raw in the permitted set
const CAP_NET_RAW: [u8; 20] = [
	1, 0, 0, 2, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn xattr(name: &str, value: &[u8]) -> Vec<u8> {
	rec(&format!("SCHILY.xattr.{name}"), value)
}

// the xattr members both pax_xattrs and the fakeroot run extract
fn xattr_members() -> (Vec<Member>, Vec<(&'static [u8], &'static str)>) {
	let members = vec![
		with_pax(
			&[
				// the last record of a name is set last and stays
				xattr("user.a", b"v\n\0w"),
				xattr("user.b", b""),
				rec("LIBARCHIVE.xattr.user.%63", b"Ymlu"),
				xattr("user.a", b"second"),
			],
			file("a", 0o644, b"a"),
		),
		with_pax(&[xattr("user.r", b"ro")], file("ro", 0o444, b"r")),
		with_pax(&[xattr("user.d", b"dir")], dir("d/", 0o755)),
		with_pax(&[xattr("user.s", b"x")], link("s", b'2', "a")),
		// a hard link without data has no metadata of its own
		with_pax(&[xattr("user.h", b"x")], link("h", b'1', "a")),
		with_pax(
			&[
				xattr("security.capability", &CAP_NET_RAW),
				rec(
					"RHT.security.selinux",
					b"system_u:object_r:bin_t",
				),
				xattr("trusted.t", b"t"),
				xattr("system.posix_acl_access", b"skipped"),
			],
			file("c", 0o755, b"c"),
		),
		// xfsroot is refused without a call, and without a warning
		with_pax(&[xattr("xfsroot.x", b"x")], file("e", 0o644, b"e")),
	];
	let listed = vec![
		(&b"a"[..], "file"),
		(b"ro", "file"),
		(b"d", "dir"),
		(b"s", "link"),
		(b"h", "file"),
		(b"c", "file"),
		(b"e", "file"),
	];
	(members, listed)
}

#[test]
fn pax_xattrs() {
	let (mut members, mut listed) = xattr_members();
	// a fifo takes no user xattrs. libarchive makes it with mkfifo,
	// which glibc implements without the mknodat fakeroot wraps: not
	// in the fakeroot run
	let fifo = TarNode {
		kind: b'6',
		..file("fifo", 0o644, b"")
	};
	members.push(with_pax(&[xattr("user.f", b"f")], fifo));
	listed.push((b"fifo", "fifo"));
	// a name past 128 bytes: ARCHIVE_WARN ends the walk
	let long = format!("user.{}", "n".repeat(124));
	members.push(with_pax(&[xattr(&long, b"v")], file("u", 0o644, b"u")));
	members.push(plain(file("v", 0o644, b"v")));
	listed.extend([(&b"u"[..], "file"), (b"v", "file")]);
	let r = compare("ac-pax-xattrs", &pax_case(&members, &listed));
	assert_eq!(r.rc, 0, "{}", show(&r));
	let a = &meta_of(&r, b"a").xattrs;
	let want: [(&[u8], &[u8]); 3] = [
		(b"user.a", b"second"),
		(b"user.b", b""),
		(b"user.c", b"bin"),
	];
	let want: Vec<(Vec<u8>, Vec<u8>)> =
		want.iter().map(|(k, v)| (k.to_vec(), v.to_vec())).collect();
	assert_eq!(*a, want, "{}", show(&r));
	assert!(!meta_of(&r, b"d").xattrs.is_empty(), "{}", show(&r));
	assert!(
		has_log(&r, "Cannot restore extended attributes: user.s"),
		"{}",
		show(&r)
	);
	assert!(find(&r, &[b"u"]).is_none(), "{}", show(&r));
}

#[test]
fn pax_charsets() {
	let cesu = b"j\xed\xa0\x80\xed\xb0\x80";
	let joined = b"j\xf0\x90\x80\x80";
	let ok: [Member; 3] = [
		with_pax(
			&[
				rec("hdrcharset", b"BINARY"),
				rec("path", b"bin\xff"),
			],
			file("x", 0o644, b"b"),
		),
		with_pax(&[rec("path", cesu)], file("y", 0o644, b"j")),
		with_pax(&[rec("path", b"ok\xc3\xa9")], file("z", 0o644, b"o")),
	];
	let listed: Listed = &[
		(b"bin\xff", "file"),
		(joined, "file"),
		(b"ok\xc3\xa9", "file"),
		(b"bad\xff", "file"),
		(b"w", "file"),
	];
	let r = compare("ac-pax-charset", &pax_case(&ok, listed));
	assert!(find(&r, &[joined]).is_some(), "{}", show(&r));
	// not UTF-8 without BINARY, an unknown charset, a bad uname: the
	// header returns ARCHIVE_WARN and the walk ends
	for (i, records) in [
		vec![rec("path", b"bad\xff")],
		vec![rec("hdrcharset", b"latin1"), rec("path", b"w")],
		vec![rec("uname", b"\xc3"), rec("path", b"w")],
		vec![rec("linkpath", b"\xed\xb0\x80"), rec("path", b"w")],
	]
	.into_iter()
	.enumerate()
	{
		let members = [
			with_pax(&records, file("x", 0o644, b"x")),
			plain(file("w", 0o644, b"w")),
		];
		let tag = format!("ac-pax-charset-{i}");
		let r = compare(&tag, &pax_case(&members, listed));
		assert!(find(&r, &[b"w"]).is_none(), "{tag}\n{}", show(&r));
	}
}

#[test]
fn pax_malformed() {
	let bodies: [&[u8]; 12] = [
		b"abc\n",
		b"99 path=x\n",
		b"6 =abc\n",
		b"10 pathxx\n",
		b"4 a=",
		b"9 path=ab",
		b"",
		b"12 path=a\0b\n",
		b"9 a=b\n11 path=w\n",
		b"00000000000000000000000000009 path=x\n",
		b"999999999999 path=x\n",
		b"11 size=x\n",
	];
	let listed: Listed = &[
		(b"x", "file"),
		(b"a", "file"),
		(b"w", "file"),
		(b"z", "file"),
	];
	for (i, body) in bodies.iter().enumerate() {
		let members = [
			Member {
				pax: Some(body.to_vec()),
				node: file("x", 0o644, b"x"),
			},
			plain(file("z", 0o644, b"z")),
		];
		compare(
			&format!("ac-pax-bad-{i}"),
			&pax_case(&members, listed),
		);
	}
	// headers: two 'x' for one entry, a global 'g', an 'x' at the end
	let x = ext_member(b'x', &rec("path", b"a"));
	let g = ext_member(b'g', &rec("comment", b"global"));
	let z = ustar_entries(&[file("z", 0o644, b"z")], ac_owner());
	for (i, tail) in [
		[x.clone(), x.clone(), z.clone()].concat(),
		[g.clone(), z.clone()].concat(),
		[g.clone(), g, z.clone()].concat(),
		x.clone(),
	]
	.into_iter()
	.enumerate()
	{
		let mut c = pax_case(&[], listed);
		c.tail = tail;
		compare(&format!("ac-pax-hdr-{i}"), &c);
	}
}

#[test]
fn pax_sizes() {
	let listed: Listed = &[(b"x", "file"), (b"z", "file")];
	for (i, size) in ["3", "1", "600", "0", "-1", "99999999999999999999"]
		.iter()
		.enumerate()
	{
		let members = [
			with_pax(
				&[rec("size", size.as_bytes())],
				file("x", 0o644, b"abc"),
			),
			plain(file("z", 0o644, b"z")),
		];
		compare(
			&format!("ac-pax-size-{i}"),
			&pax_case(&members, listed),
		);
	}
}

#[test]
fn pax_acls() {
	let acl = |k: &str, v: &str| {
		rec(&format!("SCHILY.acl.{k}"), v.as_bytes())
	};
	let members = [
		// the access ACL's owner, group and other entries are the mode
		with_pax(
			&[acl("access", "user::rw-,group::r--,other::---")],
			file("a", 0o644, b"a"),
		),
		with_pax(
			&[acl(
				"access",
				"user::rwx,user:1000:r-x:1000,group::r-x,\
				 mask::rwx,other::r-x",
			)],
			file("m", 0o600, b"m"),
		),
		// a default ACL alone leaves a mode of 0
		with_pax(
			&[acl(
				"default",
				"default:user::rwx,default:other::r-x",
			)],
			dir("d/", 0o755),
		),
		with_pax(
			&[acl("ace", "owner@:rwxp--aARWcCos:-------:allow")],
			file("n", 0o644, b"n"),
		),
		// a malformed entry: "Parse error", the walk ends
		with_pax(&[acl("access", "user::rwq")], file("e", 0o644, b"e")),
		plain(file("z", 0o644, b"z")),
	];
	let listed: Listed = &[
		(b"a", "file"),
		(b"m", "file"),
		(b"d", "dir"),
		(b"n", "file"),
		(b"e", "file"),
		(b"z", "file"),
	];
	let r = compare("ac-pax-acl", &pax_case(&members, listed));
	assert!(
		matches!(find(&r, &[b"a"]), Some(AcNode::File(0o640, ..))),
		"{}",
		show(&r)
	);
	assert!(find(&r, &[b"z"]).is_none(), "{}", show(&r));
	// SCHILY.acl.default alone (bsdtar's record for a directory with a
	// default ACL) sets perm_is_set with nothing in it: mode 0
	assert!(
		matches!(find(&r, &[b"d"]), Some(AcNode::Dir(0, ..))),
		"{}",
		show(&r)
	);
	// POSIX.1e and NFSv4 entries in one entry: ARCHIVE_FAILED
	let mixed = [
		with_pax(
			&[
				acl("access", "user:7:rwx"),
				acl("ace", "everyone@:r:-:allow"),
			],
			file("a", 0o644, b"a"),
		),
		plain(file("z", 0o644, b"z")),
	];
	compare("ac-pax-acl-mixed", &pax_case(&mixed, listed));
}

#[test]
fn pax_odd_members() {
	let listed: Listed = &[
		(b"._x", "file"),
		(b"x", "file"),
		(b"sp", "file"),
		(b"sol", "file"),
		(b"z", "file"),
	];
	// an AppleDouble "._" entry is the next entry's metadata
	let members = [
		plain(file("._x", 0o644, b"mac metadata")),
		plain(file("x", 0o644, b"x")),
		plain(file("._y", 0o644, b"")),
		plain(file("._y2", 0o644, b"twice")),
		plain(file("z", 0o644, b"z")),
	];
	compare("ac-pax-mac", &pax_case(&members, listed));
	// a GNU sparse 1.0 file: the map ahead of its data
	let map = b"1\n100\n5\n";
	let mut data = map.to_vec();
	data.resize(512, 0);
	data.extend_from_slice(b"hello");
	let sparse = with_pax(
		&[
			rec("GNU.sparse.major", b"1"),
			rec("GNU.sparse.minor", b"0"),
			rec("GNU.sparse.name", b"sp"),
			rec("GNU.sparse.realsize", b"1000"),
		],
		file("GNUSparseFile.0/sp", 0o644, &data),
	);
	let r = compare("ac-pax-sparse", &pax_case(&[sparse], listed));
	let sp = find(&r, &[b"sp"]);
	assert!(
		matches!(sp, Some(AcNode::File(_, _, d, _)) if d.len() == 1000
			&& &d[100..105] == b"hello"),
		"{}",
		show(&r)
	);
	// GNU sparse 0.1 and Sun holes maps
	let sparse01 = with_pax(
		&[
			rec("GNU.sparse.map", b"0,2,10,3"),
			rec("GNU.sparse.size", b"20"),
		],
		file("sp", 0o644, b"abcde"),
	);
	let sun = with_pax(
		&[
			rec("SUN.holesdata", b" 4 6 8 10"),
			rec("SCHILY.realsize", b"12"),
		],
		file("sol", 0o644, b"0123456789ab"),
	);
	compare("ac-pax-sparse01", &pax_case(&[sparse01, sun], listed));
	// a map covering less than the data: the rest is consumed at the
	// data's end and again by the next header's skip, which then reads
	// inside the archive
	let short = with_pax(
		&[rec("GNU.sparse.map", b"0,2"), rec("GNU.sparse.size", b"9")],
		file("sp", 0o644, b"abcde"),
	);
	let after = plain(file("z", 0o644, b"z"));
	let r = compare(
		"ac-pax-sparse-short",
		&pax_case(&[short, after], listed),
	);
	assert!(find(&r, &[b"z"]).is_none(), "{}", show(&r));
	// a Solaris ACL header: its access entries are the mode
	let mut c = pax_case(&[], listed);
	let text = b"1000003\0user::rwx,group::r-x,other::--x\0";
	c.tail = ext_member(b'A', text);
	c.tail.extend(ustar_entries(&[file("sol", 0o600, b"s")], ac_owner()));
	compare("ac-pax-solaris", &c);
}

// pinned divergence: in a UTF-8 locale libarchive composes a pax path to
// NFC (archive_string_normalize_C, Unicode 6.0 tables), the port keeps
// it. the composed name is not the one in the package's file list
#[test]
fn pax_composed_divergence() {
	let nfd = b"e\xcc\x81";
	let members = [with_pax(&[rec("path", nfd)], file("x", 0o644, b"x"))];
	let c = pax_case(&members, &[(nfd, "file")]);
	let (cres, rres) = run_pair("ac-pax-nfc", &c);
	let skipped = "skipping extraction of \u{e9}";
	assert!(has_log(&cres, skipped), "{}", show(&cres));
	assert!(find(&rres, &[nfd]).is_some(), "{}", show(&rres));
}

// pinned divergence: in the C locale libarchive cannot convert a UTF-8
// pax path to ASCII, the header returns ARCHIVE_WARN and the extraction
// loop ends quietly; the port models a UTF-8 locale only. a child run,
// the C locale is process wide
#[test]
fn under_c_locale() {
	if std::env::var_os(AC_C_LOCALE).is_some()
		|| in_fakechroot()
		|| std::env::var_os(SDE_CHILD).is_some()
		|| std::env::var_os(FR_CHILD).is_some()
	{
		return;
	}
	let exe = std::env::current_exe().unwrap();
	let out = std::process::Command::new(exe)
		.current_dir(child_cwd())
		.args(["cl_", "--test-threads=1"])
		.env(AC_C_LOCALE, "1")
		.output()
		.unwrap();
	let stdout = String::from_utf8_lossy(&out.stdout);
	assert!(
		out.status.success() && stdout.contains("test result: ok"),
		"C locale run: {}\n{stdout}\n{}",
		out.status,
		String::from_utf8_lossy(&out.stderr)
	);
}

#[test]
fn cl_utf8_path() {
	if std::env::var_os(AC_C_LOCALE).is_none() {
		return;
	}
	let members = [
		with_pax(&[rec("path", b"\xc3\xa9")], file("x", 0o644, b"x")),
		plain(file("z", 0o644, b"z")),
	];
	let listed: Listed = &[(b"\xc3\xa9", "file"), (b"z", "file")];
	let (cres, rres) = run_pair("ac-cl-utf8", &pax_case(&members, listed));
	assert_eq!(cres.rc, 0, "{}", show(&cres));
	assert!(find(&cres, &[b"z"]).is_none(), "{}", show(&cres));
	assert!(find(&rres, &[b"z"]).is_some(), "{}", show(&rres));
}

// random pax records over a few members, sometimes corrupted
fn gen_record(rng: &mut Rng, names: &[&str]) -> Vec<u8> {
	let s = |v: &str| v.as_bytes().to_vec();
	let pick_s = |rng: &mut Rng, xs: &[&str]| s(pick(rng, xs));
	match rng.below(16) {
		0 => rec("path", &pick_s(rng, names)),
		1 => rec("linkpath", &pick_s(rng, names)),
		2 | 3 => {
			let key = pick(rng, &["mtime", "atime", "ctime"]);
			let v = pick(
				rng,
				&[
					"1600000000.123456789",
					".5",
					"1.",
					"-1.5",
					"",
					"1e9",
					"1600000000.1234567891",
					"99999999999999999999",
					"+5",
					"1500000000.000000001",
				],
			);
			rec(key, v.as_bytes())
		}
		4 => {
			let (u, _) = ac_owner();
			let us = u.to_string();
			let key = pick(rng, &["uid", "gid"]);
			let v = pick(
				rng,
				&[us.as_str(), "0", "-1", "12x", " 7"],
			);
			rec(key, v.as_bytes())
		}
		5 => {
			let key = pick(rng, &["uname", "gname"]);
			rec(key, pick(rng, &[&b"root"[..], b"\xff", b""]))
		}
		6..=8 => {
			let name =
				pick(rng, &["user.a", "user.b", "user.a\0x"]);
			let v: &[u8] =
				pick(rng, &[&b"v"[..], b"\n\0\n", b"", b"x=y"]);
			xattr(name, v)
		}
		9 => rec(
			pick(
				rng,
				&[
					"LIBARCHIVE.xattr.user.%41",
					"LIBARCHIVE.xattr.u",
				],
			),
			pick(rng, &[&b"YWJj"[..], b"Y=", b"!!"]),
		),
		10 => xattr(
			pick(
				rng,
				&[
					"security.capability",
					"trusted.t",
					"xfsroot.x",
				],
			),
			&CAP_NET_RAW,
		),
		11 => rec("hdrcharset", pick(rng, &[&b"BINARY"[..], b"utf8"])),
		12 => rec(
			pick(rng, &["SCHILY.acl.access", "SCHILY.acl.default"]),
			pick(
				rng,
				&[
					&b"user::rwx,group::---,other::r--"[..],
					b"u::r,g::w,o::x",
					b"user:9:q",
					b"#c\nother:rw",
				],
			),
		),
		13 => rec(
			pick(
				rng,
				&[
					"comment",
					"SCHILY.fflags",
					"SCHILY.nlink",
					"x",
				],
			),
			b"1",
		),
		14 => rec("size", pick(rng, &[&b"1"[..], b"0", b"-1", b"5"])),
		// raw bytes: malformed records
		_ => pick(
			rng,
			&[
				&b"abc\n"[..],
				b"99 a=b\n",
				b"5 =ab\n",
				b"4 a=",
				b"7 a=bc",
			],
		)
		.to_vec(),
	}
}

// the members of a fuzz case, the file list from the names they may get
fn gen_pax(rng: &mut Rng) -> AcCase {
	const NAMES: [&str; 6] = ["a", "b", "c", "dir", "dir/x", "._a"];
	let mut members = Vec::new();
	for _ in 0..1 + rng.below(5) {
		let name = pick(rng, &NAMES);
		let node = match rng.below(5) {
			0 => dir(&format!("{name}/"), 0o755),
			1 => link(name, b'2', pick(rng, &NAMES)),
			2 => link(name, b'1', pick(rng, &NAMES)),
			_ => file(
				name,
				pick(rng, &FILE_MODES),
				pick(rng, &DATA),
			),
		};
		let pax = (rng.below(4) != 0).then(|| {
			let mut body: Vec<u8> = (0..1 + rng.below(4))
				.flat_map(|_| gen_record(rng, &NAMES))
				.collect();
			// a byte flipped or the body cut
			match rng.below(8) {
				0 if !body.is_empty() => {
					let i = rng.below(body.len());
					body[i] ^= 1 << rng.below(8);
				}
				1 => body.truncate(rng.below(body.len() + 1)),
				_ => {}
			}
			body
		});
		members.push(Member { pax, node });
	}
	let listed: Vec<(&[u8], &str)> = NAMES
		.iter()
		.map(|n| match *n {
			"dir" => (n.as_bytes(), "dir"),
			_ => (n.as_bytes(), "file"),
		})
		.collect();
	pax_case(&members, &listed)
}

// both sides on random pax headers: a hundredth of iters()
#[test]
fn fuzz_pax() {
	let mut rng = Rng::new(0x9a7_2025);
	let n = (iters() / 200).max(200);
	let (mut xattrs, mut stopped, mut nanos) = (0, 0, 0);
	for i in 0..n {
		let c = gen_pax(&mut rng);
		let r = compare(&format!("ac-pax-fuzz-{i}"), &c);
		let mut lines = Vec::new();
		flat(&r.root, "root", &mut lines);
		let text = lines.join("\n");
		xattrs += usize::from(text.contains(" user."));
		nanos += usize::from(lines.iter().any(|l| l.contains(".5000")));
		let members =
			c.tail.windows(5).filter(|w| w == b"ustar").count();
		let extracted = lines.len();
		stopped += usize::from(extracted < members);
	}
	// xattrs set, sub-second times, and walks a header warning ended
	assert!(xattrs > 0 && nanos > 0, "xattrs {xattrs} nanos {nanos}");
	assert!(stopped > 0, "no walk ended early in {n} cases");
}

// ---- security.* xattrs and owners, under fakeroot(1) ----

const FR_CHILD: &str = "DIFFTEST_IN_FAKEROOT";

// re-runs this binary's fr_ tests under fakeroot: libfakeroot fakes the
// ids, chown and the whole xattr family (libc calls, which the port
// makes through rustix's libc backend), not utimensat
#[test]
fn under_fakeroot() {
	if std::env::var_os(FR_CHILD).is_some()
		|| in_fakechroot()
		|| std::env::var_os(SDE_CHILD).is_some()
	{
		return;
	}
	let exe = std::env::current_exe().unwrap();
	let out = std::process::Command::new("fakeroot")
		.current_dir(child_cwd())
		.arg(exe)
		.args(["fr_", "--test-threads=1", "--nocapture"])
		.env(FR_CHILD, "1")
		.output()
		.expect("fakeroot not found");
	let stdout = String::from_utf8_lossy(&out.stdout);
	assert!(
		out.status.success() && stdout.contains("test result: ok"),
		"fakeroot run: {}\n{stdout}\n{}",
		out.status,
		String::from_utf8_lossy(&out.stderr)
	);
	// fr_real_packages' report, seen with --nocapture
	eprint!("{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn fr_capabilities() {
	if std::env::var_os(FR_CHILD).is_none() {
		return;
	}
	let (mut members, mut listed) = xattr_members();
	let ids = [rec("uid", b"1234"), rec("gid", b"4321")];
	members.push(with_pax(&ids, file("o", 0o4755, b"o")));
	members.push(with_pax(
		&[rec("uid", b"4294967297")],
		file("w", 0o644, b"w"),
	));
	listed.extend([(&b"o"[..], "file"), (b"w", "file")]);
	let mut c = pax_case(&members, &listed);
	c.owner = Some((0, 0));
	let r = compare("ac-fr-caps", &c);
	assert_eq!(r.rc, 0, "{}", show(&r));
	let caps = &meta_of(&r, b"c").xattrs;
	let cap = (b"security.capability".to_vec(), CAP_NET_RAW.to_vec());
	assert!(caps.contains(&cap), "{}", show(&r));
	assert_eq!(meta_of(&r, b"o").owner, (1234, 4321), "{}", show(&r));
	// past 2^32 the id wraps: uid 1
	assert_eq!(meta_of(&r, b"w").owner.0, 1, "{}", show(&r));
}

// directory modes outside mkdir's (read-only, sticky, setgid, group
// write) come from the close-time fixup: fakeroot must see that chmod,
// as it sees libarchive's, or its faked modes stay at mkdir's
#[test]
fn fr_dir_modes() {
	if std::env::var_os(FR_CHILD).is_none() {
		return;
	}
	let members = [
		plain(dir("ro/", 0o555)),
		plain(dir("tmp/", 0o1777)),
		plain(dir("games/", 0o775)),
		plain(dir("sgid/", 0o2755)),
		plain(file("ro/f", 0o644, b"f")),
	];
	let listed: &[(&[u8], &str)] = &[
		(b"ro", "dir"),
		(b"tmp", "dir"),
		(b"games", "dir"),
		(b"sgid", "dir"),
		(b"ro/f", "file"),
	];
	let r = compare("ac-fr-dir-modes", &pax_case(&members, listed));
	assert_eq!(r.rc, 0, "{}", show(&r));
	for (name, mode) in [
		(&b"ro"[..], 0o555),
		(b"tmp", 0o1777),
		(b"games", 0o775),
		(b"sgid", 0o2755),
	] {
		let Some(AcNode::Dir(m, ..)) = find(&r, &[name]) else {
			panic!("{name:?} not a dir\n{}", show(&r));
		};
		assert_eq!(m & 0o7777, mode, "{name:?}\n{}", show(&r));
	}
}

// the files of a tree carrying a security.capability xattr
fn capabilities(n: &AcNode, path: &str, out: &mut Vec<String>) {
	if let AcNode::Dir(_, Some(es), _) = n {
		for (name, n) in es {
			let p = format!(
				"{path}/{}",
				String::from_utf8_lossy(name)
			);
			capabilities(n, &p, out);
		}
	}
	let caps = node_meta(n).is_some_and(|m| {
		m.xattrs.iter().any(|(k, _)| k == b"security.capability")
	});
	if caps {
		out.push(path.to_string());
	}
}

// DIFFTEST_CAP_PKGS: real package files (comma separated, e.g. shadow,
// gstreamer from the cache) installed by both sides, scriptlets off
#[test]
fn fr_real_packages() {
	if std::env::var_os(FR_CHILD).is_none() {
		return;
	}
	let Ok(list) = std::env::var("DIFFTEST_CAP_PKGS") else {
		return;
	};
	for (i, path) in list.split(',').filter(|p| !p.is_empty()).enumerate() {
		let mut c = case(Vec::new());
		c.file = Some(path.into());
		c.flags = 1 << 10; // NOSCRIPTLET
		// progress of a compressed package read in many blocks is
		// approximate (PORTING.md)
		let not_progress =
			|r: &AcRec| !matches!(r, AcRec::Progress(..));
		let r = compare_by(
			&format!("ac-fr-real-{i}"),
			&c,
			not_progress,
		);
		let mut caps = Vec::new();
		capabilities(&r.root, "", &mut caps);
		eprintln!("{path}: rc {} capabilities {caps:?}", r.rc);
	}
}

// a cwd for child runs: the C chdir()s the whole process into a case's
// root during a commit, a child spawned then would inherit a cwd that is
// removed afterwards
fn child_cwd() -> std::path::PathBuf {
	std::env::temp_dir()
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
		cmd.current_dir(child_cwd())
			.args(["sde_child", "--exact", "--test-threads=1"])
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
		.current_dir(child_cwd())
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
