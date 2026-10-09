// alpm_core::internals::remove::remove_single_package against the C's
// _alpm_remove_single_package on fixture roots and local dbs: files,
// directories, symlinks (to dirs, files, nowhere, /proc as a
// mountpoint), read-only directories, backup files modified or not with
// existing .pacsave rotations, files owned by other packages, NoUpgrade,
// skip_remove, NOSAVE/DBONLY/NOSCRIPTLET and the upgrade path (newpkg).
// compared per case: rc, pm_errno, log lines, events and progress in
// order, the logfile, the local cache afterwards, and the root and local
// db trees. scriptlets run in the fc_ tests, re-run under fakechroot(1)
// like run_chroot.rs.
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;

use alpm_core::filelist::{File, FileList};
use alpm_core::internals::backup::Backup;
use alpm_core::internals::package::{Package, PkgFrom};
use alpm_core::internals::trans::{
	TRANS_FLAG_DBONLY, TRANS_FLAG_NOSAVE, TRANS_FLAG_NOSCRIPTLET,
};
use alpm_core::internals::util::{SCRIPTLET_SHELL, compute_md5sum, hash_sdbm};
use difftest::{
	LocalEntry, RmCase, RmOutcome, RmRec, Rng, TempRoot, c_remove_single,
	force_remove, iters, rust_remove_single, snapshot, umask_lock,
};

const CHILD: &str = "DIFFTEST_IN_FAKECHROOT";
const NAMES: [&str; 3] = ["a", "b", "c"];
const VERSIONS: [&str; 3] = ["1.0-1", "2:0.5-3", "1.0.1-1"];

// path nodes, parents first. backup names carry ERE metacharacters for
// shift_pacsave's unescaped regex ('.' any byte, '+', '[' fails to
// compile); none of them can match a name shorter than itself, where
// the C reads past the name (UPSTREAM.md)
const TREE: [&str; 17] = [
	"etc",
	"etc/a.conf",
	"etc/c+.conf",
	"etc/[x",
	"etc/d",
	"etc/d/x.conf",
	"etc/d/y",
	"usr",
	"usr/bin",
	"usr/bin/t",
	"usr/lib",
	"usr/lib/l.so",
	"usr/lib/m",
	"usr/lib/m/n",
	"opt",
	"opt/o",
	"mnt",
];
const MNT: usize = 16;

// siblings shift_pacsave may count, per backup basename: the rotation
// itself plus names the unescaped regex also matches
fn decoys(base: &str) -> Vec<String> {
	let mut v: Vec<String> = [".pacsave", ".pacsave.1", ".pacsave.2"]
		.iter()
		.chain(&[
			".pacsave.4",
			".pacsave.007",
			".pacsave.x",
			".pacsave.1a",
		])
		.map(|s| format!("{base}{s}"))
		.collect();
	match base {
		"a.conf" => v.push("aXconf.pacsave.6".into()),
		"c+.conf" => v.push("ccc.conf.pacsave.5".into()),
		"[x" => v.push("x.pacsave.3".into()),
		_ => {}
	}
	v
}

fn pick<T: Copy>(rng: &mut Rng, items: &[T]) -> T {
	items[rng.below(items.len())]
}

fn parent(node: &str) -> Option<&str> {
	node.rfind('/').map(|i| &node[..i])
}

fn is_ancestor(a: &str, b: &str) -> bool {
	b.len() > a.len() && b.starts_with(a) && b.as_bytes()[a.len()] == b'/'
}

// a file list closed under parents, sorted like strcmp. mnt is always a
// directory entry
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
		let dir = anc || node == "mnt" || rng.below(4) == 0;
		let slash = if dir { "/" } else { "" };
		names.push(format!("{node}{slash}").into_bytes());
	}
	names.sort();
	names
}

fn is_file(name: &[u8]) -> bool {
	name.last() != Some(&b'/')
}

// what is on disk at a node
#[derive(Clone, Copy, Debug, PartialEq)]
enum Node {
	Absent,
	File,
	Dir,
	// symlink to the i-th node
	LinkDir(usize),
	LinkFile,
	Dangling,
	// mnt only: symlink to /proc, a mountpoint once followed
	Proc,
}

#[derive(Clone, Debug)]
struct Gen {
	name: &'static str,
	version: &'static str,
	files: Vec<Vec<u8>>,
	backup: Vec<Vec<u8>>,
	// per backup: the recorded md5 differs from the file
	modified: Vec<bool>,
}

#[derive(Clone, Debug)]
struct World {
	// [0] is the target
	pkgs: Vec<Gen>,
	nodes: Vec<Node>,
	// dir nodes holding a file no package owns
	stray: Vec<usize>,
	// dir nodes made 0555 after the tree is written
	readonly: Vec<usize>,
	// names written next to a backup file (node, sibling names)
	saves: Vec<(usize, Vec<String>)>,
	install: Option<String>,
	salt: u64,
}

fn gen_pkg(rng: &mut Rng, name: &'static str, density: usize) -> Gen {
	let files = gen_files(rng, density);
	let backup: Vec<Vec<u8>> = files
		.iter()
		.filter(|f| is_file(f) && rng.below(2) == 0)
		.cloned()
		.collect();
	let modified = backup.iter().map(|_| rng.below(2) == 0).collect();
	Gen {
		name,
		version: pick(rng, &VERSIONS),
		files,
		backup,
		modified,
	}
}

fn gen_nodes(rng: &mut Rng) -> Vec<Node> {
	let mut nodes = vec![Node::Absent; TREE.len()];
	for (i, node) in TREE.iter().enumerate() {
		let up =
			parent(node).map(|p| TREE.iter().position(|n| *n == p));
		if let Some(Some(p)) = up
			&& nodes[p] != Node::Dir
		{
			continue;
		}
		let r = rng.below(14);
		nodes[i] = match r {
			_ if i == MNT => match r {
				0..=4 => Node::Proc,
				5..=9 => Node::Dir,
				_ => Node::Absent,
			},
			0..=1 => Node::Absent,
			2..=5 => Node::File,
			6..=10 => Node::Dir,
			11 => Node::LinkDir(0),
			12 => Node::LinkFile,
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

fn gen_world(rng: &mut Rng, install: bool) -> World {
	let n = 1 + rng.below(3);
	let pkgs: Vec<Gen> = NAMES[..n]
		.iter()
		.map(|&name| {
			let density = 2 + rng.below(6);
			gen_pkg(rng, name, density)
		})
		.collect();
	let nodes = gen_nodes(rng);
	let dirs: Vec<usize> =
		(0..TREE.len()).filter(|&i| nodes[i] == Node::Dir).collect();
	let some = |rng: &mut Rng, of: usize| {
		dirs.iter()
			.copied()
			.filter(|_| rng.below(of) == 0)
			.collect()
	};
	let stray = some(rng, 3);
	let readonly = some(rng, 6);
	let mut saves = Vec::new();
	for (i, node) in TREE.iter().enumerate() {
		let in_dir = parent(node).is_none_or(|p| {
			let p = TREE.iter().position(|n| *n == p).unwrap();
			nodes[p] == Node::Dir
		});
		if !in_dir || i == MNT || rng.below(2) == 0 {
			continue;
		}
		let base = node.rsplit('/').next().unwrap();
		let names: Vec<String> = decoys(base)
			.into_iter()
			.filter(|_| rng.below(3) == 0)
			.collect();
		saves.push((i, names));
	}
	let install = install.then(|| {
		let mut s = String::new();
		for f in ["pre_remove", "post_remove", "post_install"] {
			if rng.below(3) != 0 {
				writeln!(
					s,
					"{f}() {{ echo \"{f} $1 $2\"; \
					echo {f} > /tmp/{f}; }}"
				)
				.unwrap();
			}
		}
		s
	});
	World {
		pkgs,
		nodes,
		stray,
		readonly,
		saves,
		install,
		salt: rng.next_u64() % 1000,
	}
}

fn write_root(root: &Path, w: &World) {
	force_remove(root);
	fs::create_dir(root).unwrap();
	for (node, kind) in TREE.iter().zip(&w.nodes) {
		let p = root.join(node);
		match kind {
			Node::File => {
				fs::write(&p, format!("{node} {}", w.salt))
					.unwrap()
			}
			Node::Dir => fs::create_dir(&p).unwrap(),
			_ => {}
		}
	}
	for (node, kind) in TREE.iter().zip(&w.nodes) {
		let p = root.join(node);
		match *kind {
			Node::LinkDir(t) => {
				symlink(root.join(TREE[t]), &p).unwrap()
			}
			Node::LinkFile => {
				symlink(root.join("etc/a.conf"), &p).unwrap()
			}
			Node::Dangling => {
				symlink(root.join("nowhere"), &p).unwrap()
			}
			Node::Proc => symlink("/proc", &p).unwrap(),
			_ => {}
		}
	}
	// the host's shell at the reference's SCRIPTLET_SHELL for the
	// install scriptlet. a world whose tree holds a file or a dangling
	// link where the shell's directory goes keeps it: both sides then
	// fail to exec the same way
	if w.install.is_some() {
		fs::create_dir(root.join("tmp")).unwrap();
		let sh = root.join(OsStr::from_bytes(&SCRIPTLET_SHELL[1..]));
		if fs::create_dir_all(sh.parent().unwrap()).is_ok() {
			fs::copy(OsStr::from_bytes(SCRIPTLET_SHELL), sh)
				.unwrap();
		}
	}
	for &d in &w.stray {
		fs::write(root.join(TREE[d]).join("stray"), "s").unwrap();
	}
	for (i, names) in &w.saves {
		let dir = match parent(TREE[*i]) {
			Some(p) => root.join(p),
			None => root.to_path_buf(),
		};
		for n in names {
			fs::write(dir.join(n), n).unwrap();
		}
	}
	for &d in &w.readonly {
		let p = root.join(TREE[d]);
		fs::set_permissions(&p, fs::Permissions::from_mode(0o555))
			.unwrap();
	}
}

const OTHER_MD5: &str = "0123456789abcdef0123456789abcdef";

// the md5 a backup entry records: the file's own unless modified
fn backup_hash(root: &Path, name: &[u8], modified: bool) -> String {
	let path = root.join(String::from_utf8_lossy(name).as_ref());
	let sum = compute_md5sum(path.as_os_str().as_encoded_bytes());
	match (modified, sum) {
		(false, Some(s)) => String::from_utf8(s).unwrap(),
		_ => OTHER_MD5.to_string(),
	}
}

fn section(out: &mut String, key: &str, values: &[String]) {
	if !values.is_empty() {
		write!(out, "%{key}%\n{}\n\n", values.join("\n")).unwrap();
	}
}

fn local_entry(root: &Path, g: &Gen) -> LocalEntry {
	let desc = format!(
		"%NAME%\n{0}\n\n%VERSION%\n{1}\n\n%BASE%\n{0}\n\n\
		%DESC%\nA package\n\n%ARCH%\nx86_64\n\n\
		%BUILDDATE%\n1700000000\n\n%INSTALLDATE%\n1700000001\n\n\
		%PACKAGER%\nA B <a@b.org>\n\n%SIZE%\n42\n\n",
		g.name, g.version
	);
	let utf8 = |v: &Vec<u8>| String::from_utf8(v.clone()).unwrap();
	let mut files = String::new();
	let names: Vec<String> = g.files.iter().map(utf8).collect();
	section(&mut files, "FILES", &names);
	let backup: Vec<String> = g
		.backup
		.iter()
		.zip(&g.modified)
		.map(|(b, &m)| {
			format!("{}\t{}", utf8(b), backup_hash(root, b, m))
		})
		.collect();
	section(&mut files, "BACKUP", &backup);
	LocalEntry {
		dir: format!("{}-{}", g.name, g.version),
		desc: Some(desc.into_bytes()),
		files: Some(files.into_bytes()),
		install: false,
	}
}

// root and local db for w, from scratch
fn write_world(tmp: &TempRoot, w: &World) {
	let root = tmp.dir().join("root");
	write_root(&root, w);
	tmp.reset_local();
	let entries: Vec<LocalEntry> =
		w.pkgs.iter()
			.enumerate()
			.map(|(i, g)| {
				// only the target carries the install file
				let mut e = local_entry(&root, g);
				e.install = i == 0 && w.install.is_some();
				e
			})
			.collect();
	tmp.write_local(&entries);
	// the target's install file holds the generated scriptlets
	if let Some(text) = &w.install {
		let g = &w.pkgs[0];
		let dir = tmp.local().join(format!("{}-{}", g.name, g.version));
		fs::write(dir.join("install"), text).unwrap();
	}
}

// the upgrading package: some of the target's files plus others, some
// backups
fn gen_newpkg(rng: &mut Rng, w: &World) -> Package {
	let mut names: Vec<Vec<u8>> = w.pkgs[0]
		.files
		.iter()
		.filter(|_| rng.below(2) == 0)
		.cloned()
		.collect();
	names.extend(gen_files(rng, 2));
	names.sort();
	names.dedup();
	let backup = names
		.iter()
		.filter(|n| is_file(n) && rng.below(2) == 0)
		.map(|n| Backup {
			name: n.clone().into(),
			hash: Some(OTHER_MD5.as_bytes().into()),
		})
		.collect();
	let files = names
		.into_iter()
		.map(|name| File::new(name, 0, 0))
		.collect();
	Package {
		name_hash: hash_sdbm(b"a"),
		name: Some(b"a"[..].into()),
		version: Some(b"9.0-1"[..].into()),
		filename: Some(b"a-9.0-1.pkg.tar"[..].into()),
		files: FileList { files },
		backup,
		origin: Some(PkgFrom::File(b"a-9.0-1.pkg.tar"[..].into())),
		..Package::default()
	}
}

fn gen_case(rng: &mut Rng, w: &World, scriptlets: bool) -> RmCase {
	let target = &w.pkgs[0];
	let mut flags = 0;
	for f in [TRANS_FLAG_NOSAVE, TRANS_FLAG_DBONLY, TRANS_FLAG_NOSCRIPTLET]
	{
		if rng.below(4) == 0 {
			flags |= f;
		}
	}
	if !scriptlets {
		// a scriptlet only runs under fakechroot
		flags |= TRANS_FLAG_NOSCRIPTLET;
	}
	if rng.below(3) != 0 {
		flags &= !TRANS_FLAG_DBONLY;
	}
	let mut noupgrade = Vec::new();
	for _ in 0..rng.below(3) {
		let pat = match rng.below(4) {
			0 => b"etc/*".to_vec(),
			_ if target.files.is_empty() => b"etc/*".to_vec(),
			_ => {
				let i = rng.below(target.files.len());
				target.files[i].clone()
			}
		};
		let neg = rng.below(3) == 0;
		noupgrade
			.push([if neg { &b"!"[..] } else { b"" }, &pat]
				.concat());
	}
	let skip_remove = target
		.files
		.iter()
		.filter(|_| rng.below(8) == 0)
		.cloned()
		.collect();
	let newpkg = (rng.below(3) == 0).then(|| gen_newpkg(rng, w));
	let targ_count = 1 + rng.below(3);
	RmCase {
		flags,
		noupgrade,
		skip_remove,
		target: target.name.as_bytes().to_vec(),
		newpkg,
		targ_count,
		pkg_count: targ_count + rng.below(2),
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

fn normalize(mut o: RmOutcome) -> RmOutcome {
	for r in &mut o.recs {
		match r {
			RmRec::Log(_, m) | RmRec::Scriptlet(m) => {
				*m = untemp(m)
			}
			_ => {}
		}
	}
	o.logfile = untemp(&o.logfile);
	o
}

fn show(o: &RmOutcome) -> String {
	let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
	let mut out = format!("rc {} errno {}\n", o.rc, o.errno);
	for r in &o.recs {
		let line = match r {
			RmRec::Log(l, m) => format!("log {l} {:?}", s(m)),
			RmRec::Scriptlet(m) => format!("line {:?}", s(m)),
			r => format!("{r:?}"),
		};
		out += &line;
		out.push('\n');
	}
	out += &format!("log: {}\ncache: {:?}", s(&o.logfile), o.cache);
	out
}

// branch markers counted over a fuzz run, each must show up
const MARKS: [&str; 16] = [
	"keeping directory",
	"(contains files)",
	"(in new package)",
	"(owned by ",
	"removed directory",
	"directory removal of",
	"does not exist",
	"unlinking ",
	"cannot remove ",
	"transaction is set to NOSAVE",
	"is in skip_remove",
	"could not rename",
	"removing old package first",
	"is not writable",
	"pacsave",
	"progress",
];

fn count_marks(o: &RmOutcome, seen: &mut BTreeMap<&'static str, usize>) {
	for r in &o.recs {
		let text = match r {
			RmRec::Log(_, m) => {
				String::from_utf8_lossy(m).into_owned()
			}
			RmRec::Pacsave(..) => "pacsave".into(),
			RmRec::Progress(..) => "progress".into(),
			_ => continue,
		};
		for m in MARKS {
			if text.contains(m) {
				*seen.entry(m).or_default() += 1;
			}
		}
	}
}

// one case on a fresh world for each side
fn both(tmp: &TempRoot, w: &World, case: &RmCase) -> RmOutcome {
	let _umask = umask_lock();
	let root = tmp.root();
	let dbpath = tmp.dbpath();
	let rootdir = tmp.dir().join("root");
	let log = tmp.dir().join("log");
	write_world(tmp, w);
	let c = normalize(c_remove_single(&root, &dbpath, &log, case));
	let (croot, clocal) = (snapshot(&rootdir), snapshot(&tmp.local()));
	write_world(tmp, w);
	let r = normalize(rust_remove_single(&root, &dbpath, &log, case));
	let (rroot, rlocal) = (snapshot(&rootdir), snapshot(&tmp.local()));
	let what = format!("{w:#?}\n{case:#?}");
	assert_eq!(c, r, "{what}\nC:\n{}\nRust:\n{}", show(&c), show(&r));
	assert_eq!(croot, rroot, "root tree\n{what}");
	assert_eq!(clocal, rlocal, "local db\n{what}");
	c
}

// a TempRoot whose root/ may hold read-only dirs: made removable first,
// also when a case panics
struct Fix(TempRoot);

impl Drop for Fix {
	fn drop(&mut self) {
		force_remove(&self.0.dir().join("root"));
	}
}

fn in_child() -> bool {
	std::env::var_os(CHILD).is_some()
}

#[test]
fn fuzz() {
	let fix = Fix(TempRoot::new("rmcommit"));
	let tmp = &fix.0;
	let mut rng = Rng::new(0x5e7a);
	let mut seen = BTreeMap::new();
	let n = (iters() / 100).max(500);
	for _ in 0..n {
		let w = gen_world(&mut rng, false);
		let case = gen_case(&mut rng, &w, false);
		let out = both(tmp, &w, &case);
		count_marks(&out, &mut seen);
	}
	for m in MARKS {
		assert!(seen.contains_key(m), "never hit {m:?}: {seen:?}");
	}
}

// pinned: rotation with gaps and decoys, the regcomp failure of "[x"
// overwriting its .pacsave, a dir kept for another owner, /proc as a
// mountpoint, NOSAVE, DBONLY
#[test]
fn fixed() {
	let fix = Fix(TempRoot::new("rmcommit-fixed"));
	let tmp = &fix.0;
	let files = |v: &[&str]| -> Vec<Vec<u8>> {
		let mut v: Vec<Vec<u8>> =
			v.iter().map(|s| s.as_bytes().to_vec()).collect();
		v.sort();
		v
	};
	let a = Gen {
		name: "a",
		version: "1.0-1",
		files: files(&[
			"etc/",
			"etc/a.conf",
			"etc/[x",
			"etc/c+.conf",
			"mnt/",
		]),
		backup: files(&["etc/[x", "etc/a.conf", "etc/c+.conf"]),
		modified: vec![true, true, true],
	};
	let b = Gen {
		name: "b",
		version: "1.0-1",
		files: files(&["etc/"]),
		backup: Vec::new(),
		modified: Vec::new(),
	};
	let mut nodes = vec![Node::Absent; TREE.len()];
	for i in [0, 1, 2, 3] {
		nodes[i] = Node::File;
	}
	nodes[0] = Node::Dir;
	nodes[MNT] = Node::Proc;
	let all = |base: &str| decoys(base);
	let w = World {
		pkgs: vec![a, b],
		nodes,
		stray: Vec::new(),
		readonly: Vec::new(),
		saves: vec![
			(1, all("a.conf")),
			(2, all("c+.conf")),
			(3, all("[x")),
		],
		install: None,
		salt: 7,
	};
	for flags in [0, TRANS_FLAG_NOSAVE, TRANS_FLAG_DBONLY] {
		let case = RmCase {
			flags: flags | TRANS_FLAG_NOSCRIPTLET,
			target: b"a".to_vec(),
			targ_count: 1,
			pkg_count: 1,
			..RmCase::default()
		};
		let out = both(tmp, &w, &case);
		let saved =
			out.recs.iter()
				.any(|r| matches!(r, RmRec::Pacsave(..)));
		assert_eq!(saved, flags == 0, "{}", show(&out));
	}
}

// re-runs the fc_ tests of this binary under fakechroot
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
	assert!(stdout.contains("1 passed"), "fc_ tests did not all run");
}

// pre_remove/post_remove from the local db's install file
#[test]
fn fc_scriptlets() {
	if !in_child() {
		return;
	}
	let fix = Fix(TempRoot::new("rmcommit-fc"));
	let tmp = &fix.0;
	let mut rng = Rng::new(0x5c47);
	let mut ran = 0;
	for _ in 0..(iters() / 2000).max(60) {
		let w = gen_world(&mut rng, true);
		let case = gen_case(&mut rng, &w, true);
		let out = both(tmp, &w, &case);
		ran +=
			out.recs.iter()
				.filter(|r| matches!(r, RmRec::Scriptlet(_)))
				.count();
	}
	assert!(ran > 0, "no scriptlet ran");
}
