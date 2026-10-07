// alpm_core::util file helpers against util.c: the C and the port each run
// the same ops in their own copy of a fixture tree, then return values and
// the resulting trees (paths, types, modes, contents) are compared
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use alpm_core::util::{
	ReadFileError, copyfile, files_in_directory, makepath, makepath_mode,
	read_file,
};
use difftest::{
	ALPM_ERR_MEMORY, ALPM_ERR_NOT_A_FILE, ALPM_ERR_SYSTEM, Rng, c_copyfile,
	c_files_in_directory, c_makepath, c_makepath_mode, c_read_file,
	c_umask, iters,
};

// the C flips the process umask inside makepath: one test at a time
static SERIAL: Mutex<()> = Mutex::new(());

// fs ops are slower than string fuzz
fn fs_iters() -> usize {
	(iters() / 50).max(200)
}

// root under /tmp, removed (permissions forced) on drop
struct Sandbox(PathBuf);

impl Sandbox {
	fn new(name: &str) -> Self {
		let dir = std::env::temp_dir().join(format!(
			"difftest-util-fs-{}-{name}",
			std::process::id()
		));
		if dir.exists() {
			force_remove(&dir);
		}
		fs::create_dir(&dir).unwrap();
		Sandbox(dir)
	}
}

impl Drop for Sandbox {
	fn drop(&mut self) {
		force_remove(&self.0);
	}
}

// rm -rf through directories the ops left without permissions
fn force_remove(path: &Path) {
	let Ok(meta) = fs::symlink_metadata(path) else {
		return;
	};
	if !meta.is_dir() {
		fs::remove_file(path).unwrap();
		return;
	}
	fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
	for e in fs::read_dir(path).unwrap() {
		force_remove(&e.unwrap().path());
	}
	fs::remove_dir(path).unwrap();
}

#[derive(Debug, PartialEq)]
enum Node {
	File(u32, Vec<u8>),
	// mode, None when the listing failed (no permission)
	Dir(u32, Option<Vec<(Vec<u8>, Node)>>),
	Link(Vec<u8>),
	Unreadable(u32),
}

fn snapshot(path: &Path) -> Node {
	let meta = fs::symlink_metadata(path).unwrap();
	let mode = meta.permissions().mode() & 0o7777;
	if meta.file_type().is_symlink() {
		let t = fs::read_link(path).unwrap();
		return Node::Link(t.as_os_str().as_bytes().to_vec());
	}
	if meta.is_file() {
		return match fs::read(path) {
			Ok(data) => Node::File(mode, data),
			Err(_) => Node::Unreadable(mode),
		};
	}
	let Ok(rd) = fs::read_dir(path) else {
		return Node::Dir(mode, None);
	};
	let mut entries: Vec<_> = rd
		.map(|e| {
			let e = e.unwrap();
			let name = e.file_name().as_bytes().to_vec();
			(name, snapshot(&e.path()))
		})
		.collect();
	entries.sort_by(|a, b| a.0.cmp(&b.0));
	Node::Dir(mode, Some(entries))
}

const FILE_MODES: &[u32] = &[
	0o644, 0o600, 0o755, 0o000, 0o4755, 0o2644, 0o444, 0o1644, 0o200,
];

const DIR_MODES: &[u32] = &[
	0o755, 0o700, 0o777, 0o1777, 0o2755, 0o4755, 0o500, 0o000, 0o070,
	0o751, 0o3777,
];

fn content(rng: &mut Rng) -> Vec<u8> {
	// mostly small, some past the 8192-byte copy buffer
	let max = [1, 3, 70, 9000, 20000][rng.below(5)];
	(0..rng.below(max)).map(|_| rng.next_u64() as u8).collect()
}

// fixture description, built identically in both trees
struct Fixture {
	files: Vec<(&'static str, u32, Vec<u8>)>,
	dir_mode: u32,
}

fn fixture(rng: &mut Rng) -> Fixture {
	let names = ["a", "b", "d/f", "d/g", "x"];
	let mut files = Vec::new();
	for name in names {
		if rng.below(4) != 0 {
			let mode = FILE_MODES[rng.below(FILE_MODES.len())];
			files.push((name, mode, content(rng)));
		}
	}
	let dir_mode = [0o755, 0o755, 0o700, 0o555][rng.below(4)];
	Fixture { files, dir_mode }
}

fn build(root: &Path, fx: &Fixture) {
	fs::create_dir(root).unwrap();
	fs::create_dir(root.join("d")).unwrap();
	fs::create_dir(root.join("e")).unwrap();
	symlink("d", root.join("l")).unwrap();
	symlink("nowhere", root.join("dangling")).unwrap();
	for (name, mode, data) in &fx.files {
		let p = root.join(name);
		fs::write(&p, data).unwrap();
		fs::set_permissions(&p, fs::Permissions::from_mode(*mode))
			.unwrap();
	}
	let mode = fs::Permissions::from_mode(fx.dir_mode);
	fs::set_permissions(root.join("d"), mode).unwrap();
}

// relative paths inside the tree, never ".."
fn rel_path(rng: &mut Rng) -> Vec<u8> {
	const PARTS: &[&[u8]] = &[
		b"a",
		b"b",
		b"d",
		b"e",
		b"f",
		b"g",
		b"l",
		b"x",
		b"n",
		b"m",
		b".",
		b"",
		b"dangling",
		b"d/f",
	];
	let mut out = Vec::new();
	for i in 0..1 + rng.below(4) {
		if i > 0 {
			out.push(b'/');
		}
		out.extend(PARTS[rng.below(PARTS.len())]);
	}
	if rng.below(5) == 0 {
		out.push(b'/');
	}
	out
}

fn join(root: &Path, rel: &[u8]) -> Vec<u8> {
	[root.as_os_str().as_bytes(), b"/", rel].concat()
}

fn rust_read_file(path: &[u8]) -> Result<Vec<u8>, i32> {
	read_file(path).map_err(|e| match e {
		ReadFileError::NotAFile => ALPM_ERR_NOT_A_FILE,
		ReadFileError::Memory => ALPM_ERR_MEMORY,
		ReadFileError::System => ALPM_ERR_SYSTEM,
	})
}

// one op on both trees, results compared; returns a label for stats
fn run_op(rng: &mut Rng, c: &Path, r: &Path) -> &'static str {
	let a = rel_path(rng);
	let b = rel_path(rng);
	let (ca, ra) = (join(c, &a), join(r, &a));
	let (cb, rb) = (join(c, &b), join(r, &b));
	let ctx = format!("{:?} {:?}", String::from_utf8_lossy(&a), b);
	match rng.below(5) {
		0 => {
			let mode = if rng.below(4) == 0 {
				rng.next_u64() as u32 & 0o7777
			} else {
				DIR_MODES[rng.below(DIR_MODES.len())]
			};
			let ok = c_makepath_mode(&ca, mode) == 0;
			assert_eq!(
				ok,
				makepath_mode(&ra, mode).is_ok(),
				"{ctx} {mode:o}"
			);
			if ok {
				"makepath_mode ok"
			} else {
				"makepath_mode err"
			}
		}
		1 => {
			let ok = c_makepath(&ca) == 0;
			assert_eq!(ok, makepath(&ra).is_ok(), "{ctx}");
			if ok { "makepath ok" } else { "makepath err" }
		}
		2 => {
			let ok = c_copyfile(&ca, &cb) == 0;
			assert_eq!(ok, copyfile(&ra, &rb).is_ok(), "{ctx}");
			if ok { "copyfile ok" } else { "copyfile err" }
		}
		3 => {
			let res = c_read_file(&ca);
			assert_eq!(res, rust_read_file(&ra), "{ctx}");
			if res.is_ok() {
				"read_file ok"
			} else {
				"read_file err"
			}
		}
		_ => {
			let full = rng.below(2) == 0;
			let n = c_files_in_directory(&ca, full);
			let rust = files_in_directory(&ra, full)
				.map_or(-1, |n| n as isize);
			assert_eq!(n, rust, "{ctx} full={full}");
			if n < 0 {
				"files_in_directory err"
			} else {
				"files_in_directory"
			}
		}
	}
}

fn compare_trees(c: &Path, r: &Path, what: &str) {
	assert_eq!(snapshot(c), snapshot(r), "trees differ after {what}");
}

#[test]
fn fixed_cases() {
	let _guard = SERIAL.lock().unwrap();
	// nonzero umask: the C runs mkdir under umask 0, the port must match
	c_umask(0o027);
	let sb = Sandbox::new("fixed");
	let (c, r) = (sb.0.join("c"), sb.0.join("r"));
	let fx = Fixture {
		files: vec![
			("a", 0o4755, b"0123456789".to_vec()),
			("b", 0o600, b"xy".to_vec()),
			("x", 0o644, Vec::new()),
			("d/f", 0o000, b"secret".to_vec()),
		],
		dir_mode: 0o2755,
	};
	build(&c, &fx);
	build(&r, &fx);
	for rel in [
		&b"n/m//q/"[..],
		b"e//n",
		b"a/n",
		b"a",
		b"d/n/m",
		b"l/k",
		b"dangling/q",
		b"",
	] {
		let mode = 0o1777;
		let ok = c_makepath_mode(&join(&c, rel), mode) == 0;
		assert_eq!(ok, makepath_mode(&join(&r, rel), mode).is_ok());
	}
	assert_ne!(c_makepath(b""), 0);
	assert!(makepath(b"").is_err());
	for (src, dest) in [
		(&b"a"[..], &b"b"[..]),
		(b"b", b"a"),
		(b"missing", b"created"),
		(b"d/f", b"copy"),
		(b"d", b"dircopy"),
		(b"a", b"e"),
		(b"x", b"l/new"),
	] {
		let ok = c_copyfile(&join(&c, src), &join(&c, dest)) == 0;
		assert_eq!(
			ok,
			copyfile(&join(&r, src), &join(&r, dest)).is_ok(),
			"{src:?} {dest:?}"
		);
	}
	for rel in [&b"a"[..], b"x", b"d", b"d/f", b"missing", b"l"] {
		let (cp, rp) = (join(&c, rel), join(&r, rel));
		assert_eq!(c_read_file(&cp), rust_read_file(&rp), "{rel:?}");
		for full in [false, true] {
			let rust = files_in_directory(&rp, full)
				.map_or(-1, |n| n as isize);
			assert_eq!(
				c_files_in_directory(&cp, full),
				rust,
				"{rel:?}"
			);
		}
	}
	compare_trees(&c, &r, "fixed ops");
}

#[test]
fn fuzz_fs_ops() {
	let _guard = SERIAL.lock().unwrap();
	c_umask(0o027);
	let sb = Sandbox::new("fuzz");
	let mut rng = Rng::new(0xf11e);
	let mut stats = std::collections::BTreeMap::new();
	for i in 0..fs_iters() {
		let (c, r) = (
			sb.0.join(format!("c{i}")),
			sb.0.join(format!("r{i}")),
		);
		let fx = fixture(&mut rng);
		build(&c, &fx);
		build(&r, &fx);
		let mut ops = Vec::new();
		for _ in 0..1 + rng.below(4) {
			let label = run_op(&mut rng, &c, &r);
			*stats.entry(label).or_insert(0usize) += 1;
			ops.push(label);
		}
		compare_trees(&c, &r, &format!("{ops:?}"));
		force_remove(&c);
		force_remove(&r);
	}
	// every op and outcome reached
	assert_eq!(stats.len(), 10, "{stats:?}");
	let min = stats.values().min().unwrap();
	assert!(*min > fs_iters() / 100, "{stats:?}");
}
