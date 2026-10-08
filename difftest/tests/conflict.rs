// alpm_core::conflict against the C on real handles. each fixture writes
// a root with real files, directories and symlinks plus a local db, read
// by a C handle and by the Rust be_local reader (every entry loaded
// INFRQ_ALL, as the C getters and _alpm_pkg_dup load them). targets are
// Rust Packages pushed into the C through the package mirror. compared:
// conflict lists (order, every field, the dup'ed packages), skip_remove
// and the progress events.
use std::ffi::c_int;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use alpm_core::backup::Backup;
use alpm_core::be_local::{INFRQ_ALL, LocalDb};
use alpm_core::callbacks::{Callbacks, Progress};
use alpm_core::conflict::{
	Conflict, FileCheck, FileConflictType, FileConflicts, checkconflicts,
	innerconflicts, outerconflicts,
};
use alpm_core::deps::dep_from_string;
use alpm_core::filelist::{File, FileList};
use alpm_core::package::{Package, PkgFrom};
use alpm_core::pkghash::PkgHash;
use alpm_core::util::hash_sdbm;
use difftest::{
	CConflictHandle, LocalEntry, ProgressEvent, Rng, TempRoot, iters,
};

const NAMES: [&str; 6] = ["a", "b", "foo", "bar", "lib-x", "z9"];
const VERSIONS: [&str; 4] = ["1.0-1", "1.5-2", "2:1.0-1", "1.0.1-1"];
const DEP_VERSIONS: [&str; 5] = ["1.0", "1.0-1", "1.5", "2:1.0", "0.9"];
const OPS: [&str; 6] = ["", "=", ">=", "<=", ">", "<"];
const MD5: &str = "d41d8cd98f00b204e9800998ecf8427e";

// path nodes, parents first. non-ASCII names sort last for strcmp but
// first for the signed pathcmp of the target-target check
const TREE: [&str; 20] = [
	"usr",
	"usr/bin",
	"usr/bin/x",
	"usr/bin/é",
	"usr/lib",
	"usr/lib/l.so",
	"usr/lib/m",
	"usr/lib/m/n",
	"usr/z",
	"usr/é",
	"etc",
	"etc/conf",
	"etc/d",
	"etc/d/x",
	"lib",
	"lib/k",
	"opt",
	"opt/s",
	"é",
	"é/f",
];

// overwrite globs; "@" becomes the root (rooted form)
const GLOBS: [&str; 14] = [
	"*",
	"usr/*",
	"usr/bin/?",
	"!usr/bin/x",
	"etc/*",
	"é*",
	"*é",
	"@usr/*",
	"@etc/conf",
	"!*",
	"usr/lib/m",
	"lib",
	"\\!x",
	"*/x",
];

fn pick<T: Copy>(rng: &mut Rng, items: &[T]) -> T {
	items[rng.below(items.len())]
}

fn parent(node: &str) -> Option<&str> {
	node.rfind('/').map(|i| &node[..i])
}

fn is_ancestor(a: &str, b: &str) -> bool {
	b.len() > a.len() && b.starts_with(a) && b.as_bytes()[a.len()] == b'/'
}

// a file list closed under parents: picked nodes, their ancestors as
// directories, leaves as files or directories. sorted like strcmp
fn gen_files(rng: &mut Rng, density: usize) -> Vec<Vec<u8>> {
	let picked: Vec<&str> = TREE
		.iter()
		.copied()
		.filter(|_| rng.below(10) < density)
		.collect();
	let mut names = Vec::new();
	for node in TREE {
		let leaf = picked.contains(&node);
		let anc = picked.iter().any(|p| is_ancestor(node, p));
		if !leaf && !anc {
			continue;
		}
		let dir = anc || rng.below(3) == 0;
		let slash = if dir { "/" } else { "" };
		names.push(format!("{node}{slash}").into_bytes());
	}
	names.sort();
	names
}

fn filelist(names: &[Vec<u8>]) -> FileList {
	FileList {
		files: names
			.iter()
			.map(|n| File {
				name: n.clone(),
				..File::default()
			})
			.collect(),
	}
}

fn relation(rng: &mut Rng) -> String {
	let (name, op) = (pick(rng, &NAMES), pick(rng, &OPS));
	match op {
		"" => name.to_string(),
		_ => format!("{name}{op}{}", pick(rng, &DEP_VERSIONS)),
	}
}

fn provision(rng: &mut Rng) -> String {
	let name = pick(rng, &NAMES);
	match rng.below(3) {
		0 => format!("{name}={}", pick(rng, &DEP_VERSIONS)),
		_ => name.to_string(),
	}
}

fn some<T>(rng: &mut Rng, n: usize, f: impl Fn(&mut Rng) -> T) -> Vec<T> {
	(0..rng.below(n)).map(|_| f(rng)).collect()
}

// one generated package, written to the local db or used as a target
#[derive(Clone, Debug, Default)]
struct Gen {
	name: String,
	version: String,
	files: Vec<Vec<u8>>,
	backup: Vec<Vec<u8>>,
	conflicts: Vec<String>,
	provides: Vec<String>,
	// local only: leave the files file out (reading it fails)
	no_files: bool,
}

fn gen_pkg(rng: &mut Rng, name: &str, density: usize) -> Gen {
	let files = gen_files(rng, density);
	let backup = files
		.iter()
		.filter(|f| f.last() != Some(&b'/') && rng.below(4) == 0)
		.cloned()
		.collect();
	Gen {
		name: name.to_string(),
		version: pick(rng, &VERSIONS).to_string(),
		files,
		backup,
		conflicts: some(rng, 3, relation),
		provides: some(rng, 3, provision),
		no_files: false,
	}
}

fn section(out: &mut String, key: &str, values: &[String]) {
	if !values.is_empty() {
		write!(out, "%{key}%\n{}\n\n", values.join("\n")).unwrap();
	}
}

fn local_entry(g: &Gen) -> LocalEntry {
	let mut desc = format!(
		"%NAME%\n{0}\n\n%VERSION%\n{1}\n\n%BASE%\n{0}\n\n\
		%DESC%\nA package\n\n%URL%\nhttps://example.org/\n\n\
		%ARCH%\nx86_64\n\n%BUILDDATE%\n1700000000\n\n\
		%INSTALLDATE%\n1700000001\n\n%PACKAGER%\nA B <a@b.org>\n\n\
		%SIZE%\n42\n\n%VALIDATION%\npgp\n\n",
		g.name, g.version
	);
	section(&mut desc, "CONFLICTS", &g.conflicts);
	section(&mut desc, "PROVIDES", &g.provides);
	let utf8 = |v: &Vec<u8>| String::from_utf8(v.clone()).unwrap();
	let mut files = String::new();
	let names: Vec<String> = g.files.iter().map(utf8).collect();
	section(&mut files, "FILES", &names);
	let backup: Vec<String> =
		g.backup.iter()
			.map(|b| format!("{}\t{MD5}", utf8(b)))
			.collect();
	section(&mut files, "BACKUP", &backup);
	LocalEntry {
		dir: format!("{}-{}", g.name, g.version),
		desc: Some(desc.into_bytes()),
		files: (!g.no_files).then(|| files.into_bytes()),
		install: false,
	}
}

fn target(g: &Gen, origin: PkgFrom) -> Package {
	let deps = |v: &[String]| {
		v.iter().map(|s| dep_from_string(s.as_bytes())).collect()
	};
	Package {
		name_hash: hash_sdbm(g.name.as_bytes()),
		name: Some(g.name.as_bytes().to_vec()),
		version: Some(g.version.as_bytes().to_vec()),
		filename: Some(format!("{}.pkg.tar", g.name).into_bytes()),
		files: filelist(&g.files),
		backup: g
			.backup
			.iter()
			.map(|b| Backup {
				name: b.clone(),
				hash: Some(MD5.as_bytes().to_vec()),
			})
			.collect(),
		conflicts: deps(&g.conflicts),
		provides: deps(&g.provides),
		origin: Some(origin),
		..Package::default()
	}
}

// what is on disk at a node
#[derive(Clone, Copy, Debug, PartialEq)]
enum Node {
	Absent,
	File,
	Dir,
	// symlink to the i-th directory node
	LinkDir(usize),
	LinkFile,
	Dangling,
}

// a random tree under root: children only below real directories,
// symlinks made last so their targets exist
fn gen_fs(rng: &mut Rng) -> Vec<Node> {
	let mut nodes = vec![Node::Absent; TREE.len()];
	for (i, node) in TREE.iter().enumerate() {
		let up =
			parent(node).map(|p| TREE.iter().position(|n| *n == p));
		if let Some(Some(p)) = up
			&& nodes[p] != Node::Dir
		{
			continue;
		}
		nodes[i] = match rng.below(12) {
			0..=2 => Node::Absent,
			3..=4 => Node::File,
			5..=8 => Node::Dir,
			9 => Node::LinkDir(0),
			10 => Node::LinkFile,
			_ => Node::Dangling,
		};
	}
	let dirs: Vec<usize> =
		(0..TREE.len()).filter(|&i| nodes[i] == Node::Dir).collect();
	for n in nodes.iter_mut() {
		if *n == Node::LinkDir(0) {
			*n = match dirs.is_empty() {
				true => Node::Dangling,
				false => Node::LinkDir(pick(rng, &dirs)),
			};
		}
	}
	nodes
}

fn write_fs(root: &Path, nodes: &[Node]) {
	for (node, kind) in TREE.iter().zip(nodes) {
		let p = root.join(node);
		match kind {
			Node::File => fs::write(&p, "x").unwrap(),
			Node::Dir => fs::create_dir(&p).unwrap(),
			_ => {}
		}
	}
	for (node, kind) in TREE.iter().zip(nodes) {
		let p = root.join(node);
		match *kind {
			Node::LinkDir(t) => {
				symlink(root.join(TREE[t]), &p).unwrap()
			}
			Node::LinkFile => {
				symlink(root.join("etc/conf"), &p).unwrap()
			}
			Node::Dangling => {
				symlink(root.join("nowhere"), &p).unwrap()
			}
			_ => {}
		}
	}
}

// fixture: TempRoot with the local db written, both sides' views
struct Fix {
	tmp: TempRoot,
	// handle->root, with the '/' alpm_initialize appends
	root: Vec<u8>,
	cache: PkgHash<Package>,
}

impl Fix {
	fn new(local: &[Gen], fs_nodes: &[Node]) -> Self {
		let tmp = TempRoot::new("conflict");
		tmp.reset_local();
		let entries: Vec<LocalEntry> =
			local.iter().map(local_entry).collect();
		tmp.write_local(&entries);
		write_fs(&tmp.dir().join("root"), fs_nodes);
		let db = LocalDb::register(&tmp.dbpath()).unwrap();
		let mut cache = db.populate(&mut ()).unwrap();
		for p in cache.iter_mut() {
			let _ = db.read(p, INFRQ_ALL, &mut ());
		}
		let root = [&tmp.root()[..], b"/"].concat();
		Fix { tmp, root, cache }
	}

	fn c(&self) -> CConflictHandle {
		let c = CConflictHandle::new(
			&self.tmp.root(),
			&self.tmp.dbpath(),
		);
		let names: Vec<Vec<u8>> = self
			.cache
			.iter()
			.map(|p| p.name.clone().unwrap())
			.collect();
		assert_eq!(c.local_names(), names, "local caches differ");
		c
	}

	fn local(&self, name: &str) -> &Package {
		self.cache.find(name.as_bytes()).unwrap()
	}

	fn globs(&self, globs: &[&str]) -> Vec<Vec<u8>> {
		let root = String::from_utf8(self.root.clone()).unwrap();
		globs.iter()
			.map(|g| g.replace('@', &root).into_bytes())
			.collect()
	}
}

#[derive(Default)]
struct Recorder(Vec<ProgressEvent>);

impl Callbacks for Recorder {
	fn progress(
		&mut self,
		progress: Progress,
		pkg: &[u8],
		percent: c_int,
		howmany: usize,
		current: usize,
	) {
		let ev = (
			progress as c_int,
			pkg.to_vec(),
			percent,
			howmany,
			current,
		);
		self.0.push(ev);
	}
}

fn rust_files(
	fix: &Fix,
	upgrade: &[&Package],
	rem: &[&Package],
	overwrite: &[Vec<u8>],
) -> (FileConflicts, Vec<ProgressEvent>) {
	let check = FileCheck {
		root: &fix.root,
		local: &fix.cache,
		overwrite,
	};
	let mut rec = Recorder::default();
	let r = check.find_fileconflicts(upgrade, rem, &mut rec);
	(r, rec.0)
}

fn show(p: &[&Package]) -> Vec<(String, Vec<String>)> {
	p.iter().map(|p| {
		let name = String::from_utf8_lossy(p.name_bytes()).into();
		let files = p
			.files
			.files
			.iter()
			.map(|f| String::from_utf8_lossy(&f.name).into())
			.collect();
		(name, files)
	})
	.collect()
}

// both sides, compared; the Rust result for extra asserts
fn cmp_files(
	fix: &Fix,
	c: &CConflictHandle,
	upgrade: &[&Package],
	rem: &[&Package],
	overwrite: &[Vec<u8>],
) -> FileConflicts {
	let want = c.find_fileconflicts(upgrade, rem, overwrite);
	let got = rust_files(fix, upgrade, rem, overwrite);
	assert_eq!(
		got,
		want,
		"upgrade {:?}\nrem {:?}\noverwrite {:?}",
		show(upgrade),
		show(rem),
		overwrite
			.iter()
			.map(|g| String::from_utf8_lossy(g))
			.collect::<Vec<_>>()
	);
	got.0
}

fn cmp_deps(
	fix: &Fix,
	c: &CConflictHandle,
	pkgs: &[&Package],
) -> [Vec<Conflict>; 2] {
	let names: Vec<_> = pkgs
		.iter()
		.map(|p| {
			(
				p.name.clone(),
				p.conflicts.clone(),
				p.provides.clone(),
				p.version.clone(),
			)
		})
		.collect();
	let inner = innerconflicts(pkgs, &mut ());
	assert_eq!(inner, c.innerconflicts(pkgs), "inner {names:?}");
	assert_eq!(
		checkconflicts(pkgs, &mut ()),
		c.checkconflicts(pkgs),
		"check {names:?}"
	);
	let outer = outerconflicts(&fix.cache, pkgs, &mut ());
	assert_eq!(outer, c.outerconflicts(pkgs), "outer {names:?}");
	[inner, outer]
}

fn mk(name: &str, files: &[&str]) -> Gen {
	let mut files: Vec<Vec<u8>> =
		files.iter().map(|f| f.as_bytes().to_vec()).collect();
	files.sort();
	Gen {
		name: name.into(),
		version: "1.0-1".into(),
		files,
		..Gen::default()
	}
}

fn tgt(name: &str, files: &[&str]) -> Package {
	target(&mk(name, files), PkgFrom::File(b"/x.pkg.tar".to_vec()))
}

fn files_of(r: &FileConflicts) -> Vec<(String, String, FileConflictType)> {
	r.conflicts
		.iter()
		.map(|c| {
			let s = |v: &[u8]| {
				String::from_utf8(v.to_vec()).unwrap()
			};
			(s(&c.target), s(&c.ctarget), c.conflict_type)
		})
		.collect()
}

fn rel(fix: &Fix, r: &FileConflicts) -> Vec<String> {
	r.conflicts
		.iter()
		.map(|c| {
			String::from_utf8(c.file[fix.root.len()..].to_vec())
				.unwrap()
		})
		.collect()
}

fn on_disk(entries: &[(&str, Node)]) -> Vec<Node> {
	TREE.iter()
		.map(|n| {
			entries.iter()
				.find(|(e, _)| e == n)
				.map_or(Node::Absent, |(_, k)| *k)
		})
		.collect()
}

#[test]
fn dep_conflict_cases() {
	// L conflicts with T, T conflicts with L: both directions, one entry
	// each, the local package first in the db-vs-targets pass
	let mut l = mk("a", &[]);
	l.conflicts = vec!["foo".into()];
	let mut l2 = mk("b", &[]);
	l2.provides = vec!["virt=1.0".into()];
	let fix = Fix::new(&[l, l2], &[]);
	let c = fix.c();
	let mut t = mk("foo", &[]);
	t.conflicts = vec!["virt>=1.0".into()];
	let t = target(&t, PkgFrom::SyncDb);
	let [inner, outer] = cmp_deps(&fix, &c, &[&t]);
	assert!(inner.is_empty());
	let pairs: Vec<_> = outer
		.iter()
		.map(|c| (c.package1.name_bytes(), c.package2.name_bytes()))
		.collect();
	assert_eq!(
		pairs,
		[(&b"foo"[..], &b"b"[..]), (b"foo", b"a")],
		"targets vs db first, then db vs targets"
	);

	// targets among themselves, both ways deduped by name pair
	let mut x = mk("x", &[]);
	x.conflicts = vec!["y".into()];
	let mut y = mk("y", &[]);
	y.conflicts = vec!["x".into(), "y".into()];
	let (x, y) = (target(&x, PkgFrom::SyncDb), target(&y, PkgFrom::SyncDb));
	let [inner, _] = cmp_deps(&fix, &c, &[&x, &y, &x]);
	assert_eq!(inner.len(), 2);

	// a target replacing the local package of its own name is skipped
	let mut a = mk("a", &[]);
	a.conflicts = vec!["a".into(), "foo".into()];
	let a = target(&a, PkgFrom::SyncDb);
	cmp_deps(&fix, &c, &[&a]);
	cmp_deps(&fix, &c, &[]);
}

#[test]
fn dep_conflict_unloadable_local_is_dropped() {
	let mut l = mk("a", &[]);
	l.conflicts = vec!["foo".into()];
	l.no_files = true;
	let fix = Fix::new(&[l], &[]);
	let c = fix.c();
	let t = target(&mk("foo", &[]), PkgFrom::SyncDb);
	let [_, outer] = cmp_deps(&fix, &c, &[&t]);
	assert!(outer.is_empty(), "_alpm_pkg_dup fails, conflict dropped");
}

#[test]
fn file_conflict_cases() {
	let mut old = mk("a", &["usr/", "usr/z"]);
	old.backup = vec![];
	let owner = mk("b", &["etc/", "etc/conf", "etc/d/", "etc/d/x"]);
	let lone = mk("lib-x", &["usr/", "usr/lib/", "usr/lib/m"]);
	let bin = mk("z9", &["usr/", "usr/bin/"]);
	let fs = on_disk(&[
		("usr", Node::Dir),
		("usr/z", Node::File),
		("usr/bin", Node::Dir),
		("usr/bin/x", Node::File),
		("usr/lib", Node::Dir),
		("usr/lib/m", Node::File),
		("usr/é", Node::File),
		("etc", Node::Dir),
		("etc/conf", Node::File),
		("etc/d", Node::Dir),
		("etc/d/x", Node::File),
		("lib", Node::LinkDir(4)),
		("opt", Node::File),
	]);
	let fix = Fix::new(&[old, owner, lone, bin], &fs);
	let c = fix.c();
	let none: &[Vec<u8>] = &[];

	// unowned file on disk, owned file, directory over an owned file
	let t = tgt(
		"foo",
		&["usr/", "usr/bin/", "usr/bin/x", "etc/", "etc/conf"],
	);
	let r = cmp_files(&fix, &c, &[&t], &[], none);
	assert_eq!(rel(&fix, &r), ["etc/conf", "usr/bin/x"]);
	assert_eq!(
		files_of(&r)[0],
		("foo".into(), "b".into(), FileConflictType::Filesystem)
	);

	// overwrite: plain and rooted globs, negation wins when last
	let g = fix.globs(&["usr/*", "@etc/conf"]);
	let r = cmp_files(&fix, &c, &[&t], &[], &g);
	assert!(r.conflicts.is_empty());
	let g = fix.globs(&["*", "!*bin/x"]);
	let r = cmp_files(&fix, &c, &[&t], &[], &g);
	assert_eq!(rel(&fix, &r), ["usr/bin/x"]);

	// removed package owns the file
	let r = cmp_files(&fix, &c, &[&t], &[fix.local("b")], none);
	assert_eq!(rel(&fix, &r), ["usr/bin/x"]);

	// dir over a file: the old version of the target had it as a file,
	// so it and everything inside is fine; another owner is a conflict
	// reported without the '/'
	let t = tgt("a", &["usr/", "usr/z/", "usr/z/q"]);
	let r = cmp_files(&fix, &c, &[&t], &[], none);
	assert!(r.conflicts.is_empty());
	let t = tgt("foo", &["usr/", "usr/lib/", "usr/lib/m/", "usr/lib/m/n"]);
	let r = cmp_files(&fix, &c, &[&t], &[], none);
	assert_eq!(rel(&fix, &r), ["usr/lib/m"]);
	assert_eq!(files_of(&r)[0].1, "lib-x");
	// the owner of that file is removed: the '/' entries inside skipped
	let r = cmp_files(&fix, &c, &[&t], &[fix.local("lib-x")], none);
	assert!(r.conflicts.is_empty());

	// file over a directory: owned only by the removed package, with
	// every entry below it, fine; an unowned entry below makes it stay
	let t = tgt("foo", &["etc/", "etc/d"]);
	let r = cmp_files(&fix, &c, &[&t], &[fix.local("b")], none);
	assert!(r.conflicts.is_empty(), "removed package owns etc/d/");
	let r = cmp_files(&fix, &c, &[&t], &[], none);
	assert_eq!(rel(&fix, &r), ["etc/d"]);
	let t = tgt("foo", &["usr/", "usr/bin"]);
	let r = cmp_files(&fix, &c, &[&t], &[fix.local("z9")], none);
	assert_eq!(rel(&fix, &r), ["usr/bin"], "usr/bin/x is unowned");

	// symlinked dir: lib -> usr/lib is no directory for llstat
	let t = tgt("foo", &["lib/", "lib/m"]);
	let r = cmp_files(&fix, &c, &[&t], &[], none);
	assert_eq!(rel(&fix, &r), ["lib", "lib/m"]);
	// overwrite does not cover a directory, a link to one it does
	let g = fix.globs(&["*"]);
	let r = cmp_files(&fix, &c, &[&t], &[], &g);
	assert!(r.conflicts.is_empty());

	// the file changes hands: the old owner is upgraded too
	let t1 = tgt("foo", &["usr/", "usr/z"]);
	let t2 = tgt("a", &["usr/"]);
	let r = cmp_files(&fix, &c, &[&t1, &t2], &[], none);
	assert!(r.conflicts.is_empty());
	assert_eq!(r.skip_remove, [b"usr/z".to_vec()]);
	// the same package twice is skipped as itself (pointer compare)
	let r = cmp_files(&fix, &c, &[&t1, &t1], &[], none);
	assert_eq!(rel(&fix, &r), ["usr/z", "usr/z", "usr/z"]);

	// unowned file in the backup list of the new package
	let mut g = mk("foo", &["opt"]);
	g.backup = vec![b"opt".to_vec()];
	let t = target(&g, PkgFrom::SyncDb);
	let r = cmp_files(&fix, &c, &[&t], &[], none);
	assert!(r.conflicts.is_empty());

	// target vs target, a local-origin p2 reports as filesystem
	let t1 = tgt("x", &["srv/", "srv/s"]);
	let mut t2 = tgt("y", &["srv/", "srv/s/"]);
	let r = cmp_files(&fix, &c, &[&t1, &t2], &[], none);
	assert_eq!(rel(&fix, &r), ["srv/s"]);
	t2.origin = Some(PkgFrom::LocalDb);
	let r = cmp_files(&fix, &c, &[&t1, &t2], &[], &fix.globs(&["*"]));
	assert_eq!(
		files_of(&r),
		[("x".into(), "y".into(), FileConflictType::Filesystem)],
		"dir-file pair stays under overwrite"
	);
	cmp_files(&fix, &c, &[], &[], none);
}

// _alpm_filelist_pathcmp compares signed char: "z" sorts after "é"
// there, unlike strcmp, so the merge misses the shared "é" on x86_64
#[test]
fn file_conflict_non_ascii_pathcmp() {
	let fix = Fix::new(&[], &[]);
	let c = fix.c();
	let none: &[Vec<u8>] = &[];
	let t1 = tgt("x", &["usr/", "usr/z", "usr/é"]);
	let t2 = tgt("y", &["usr/", "usr/é"]);
	let r = cmp_files(&fix, &c, &[&t1, &t2], &[], none);
	let signed = (0x80u8 as std::ffi::c_char) < 0;
	assert_eq!(rel(&fix, &r).is_empty(), signed);
	let t3 = tgt("z9", &["usr/", "usr/é"]);
	let r = cmp_files(&fix, &c, &[&t2, &t3], &[], none);
	assert_eq!(rel(&fix, &r), ["usr/é"]);
}

// snprintf cuts root + path at PATH_MAX - 1 in the conflict; the cut
// path does not exist, so the filesystem check never reads past it
#[test]
fn file_conflict_long_path() {
	let fix = Fix::new(&[], &[]);
	let c = fix.c();
	let long = format!("q/{}", "y".repeat(4200));
	let t1 = tgt("x", &["q/", &long]);
	let t2 = tgt("y", &["q/", &long]);
	let r = cmp_files(&fix, &c, &[&t1, &t2], &[], &[]);
	assert_eq!(r.conflicts[0].file.len(), 4095);
}

// fixtures scale with iters(): one per 500, 25 target sets each
#[test]
fn fuzz() {
	let fixtures = (iters() / 500).max(20);
	let mut rng = Rng::new(0xc0f1_1c75);
	let (mut compared, mut found, mut skips, mut deps) = (0, 0, 0, 0);
	for _ in 0..fixtures {
		let mut names = NAMES.to_vec();
		names.retain(|_| rng.below(2) == 0);
		let local: Vec<Gen> = names
			.iter()
			.map(|n| {
				let mut g = gen_pkg(&mut rng, n, 3);
				g.no_files = rng.below(25) == 0;
				g
			})
			.collect();
		let fs_nodes = gen_fs(&mut rng);
		let fix = Fix::new(&local, &fs_nodes);
		let c = fix.c();
		let rem_pool: Vec<&Package> = fix.cache.iter().collect();
		for _ in 0..25 {
			let gens: Vec<Gen> = (0..rng.below(4))
				.map(|_| {
					let name = pick(&mut rng, &NAMES);
					gen_pkg(&mut rng, name, 3)
				})
				.collect();
			let targets: Vec<Package> = gens
				.iter()
				.map(|g| {
					let origin = match rng.below(8) {
						0 => PkgFrom::LocalDb,
						1..=3 => PkgFrom::SyncDb,
						_ => PkgFrom::File(
							b"/t".to_vec(),
						),
					};
					target(g, origin)
				})
				.collect();
			let mut upgrade: Vec<&Package> =
				targets.iter().collect();
			if !upgrade.is_empty() && rng.below(10) == 0 {
				upgrade.push(upgrade[0]);
			}
			let rem: Vec<&Package> = rem_pool
				.iter()
				.copied()
				.filter(|_| rng.below(4) == 0)
				.collect();
			let globs: Vec<&str> = GLOBS
				.iter()
				.copied()
				.filter(|_| rng.below(6) == 0)
				.collect();
			let overwrite = fix.globs(&globs);
			let r = cmp_files(&fix, &c, &upgrade, &rem, &overwrite);
			let [inner, outer] = cmp_deps(&fix, &c, &upgrade);
			compared += 1;
			found += r.conflicts.len();
			skips += r.skip_remove.len();
			deps += inner.len() + outer.len();
		}
	}
	eprintln!(
		"{compared} sets: {found} file, {deps} dep conflicts, {skips} skips"
	);
	// the generators must reach every outcome
	assert!(found > compared / 2, "{found} file conflicts in {compared}");
	assert!(skips > 0 && deps > compared / 4, "{skips} {deps}");
}
