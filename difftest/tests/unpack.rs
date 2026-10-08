// alpm_core::util::unpack against util.c's _alpm_unpack (libarchive's
// archive_read_extract): the C and the port each extract the same archive
// into their own copy of a fixture tree; return value, pm_errno, the log
// lines (libarchive's error texts cut) and the resulting tree (types,
// modes, link counts, contents, link targets) are compared
use std::ffi::c_int;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

use alpm_core::callbacks::{Callbacks, LogLevel};
use alpm_core::error::Errno;
use alpm_core::util::{unpack, unpack_single};
use difftest::{
	COMPS, Comp, FILTERED, Node, Rng, TarNode, TempRoot, c_unpack,
	force_remove, iters, snapshot, umask_lock, ustar_nodes, write_db,
};

fn fs_iters() -> usize {
	(iters() / 50).max(200)
}

fn bytes(p: &Path) -> Vec<u8> {
	p.as_os_str().as_bytes().to_vec()
}

#[derive(PartialEq, Eq)]
struct Outcome {
	rc: c_int,
	errno: c_int,
	// level, normalized message
	logs: Vec<(c_int, Vec<u8>)>,
}

impl Outcome {
	fn warned(&self) -> bool {
		self.logs
			.iter()
			.any(|(l, _)| *l == LogLevel::Warning as c_int)
	}
}

impl std::fmt::Debug for Outcome {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		let logs: Vec<_> = self
			.logs
			.iter()
			.map(|(l, m)| (l, String::from_utf8_lossy(m)))
			.collect();
		write!(f, "rc {} errno {} logs {logs:#?}", self.rc, self.errno)
	}
}

// the port's logs, as the C's logcb sees them
#[derive(Default)]
struct Logs(Vec<(c_int, Vec<u8>)>);

impl Callbacks for Logs {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		self.0.push((level as c_int, msg.to_vec()));
	}
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
	hay.windows(needle.len()).position(|w| w == needle)
}

// the side's dir made fixed, the error text after an entry or archive
// name cut: libarchive's texts are not the port's. RET_ERR's debug line
// (C source position) dropped
fn norm_logs(logs: Vec<(c_int, Vec<u8>)>, w: &Path) -> Vec<(c_int, Vec<u8>)> {
	let w = bytes(w);
	let cuts: [(&[u8], &[u8]); 3] = [
		(b"could not open file ", b": "),
		(b"warning given when extracting ", b" ("),
		(b"could not extract ", b" ("),
	];
	logs.into_iter()
		.filter(|(_, msg)| !msg.starts_with(b"returning error "))
		.map(|(level, msg)| {
			let mut m = Vec::new();
			let mut rest = &msg[..];
			while let Some(i) = find(rest, &w) {
				m.extend_from_slice(&rest[..i]);
				m.extend_from_slice(b"W");
				rest = &rest[i + w.len()..];
			}
			m.extend_from_slice(rest);
			for (head, sep) in cuts {
				if !m.starts_with(head) {
					continue;
				}
				if let Some(i) = find(&m[head.len()..], sep) {
					m.truncate(head.len() + i + sep.len());
				}
			}
			(level, m)
		})
		.collect()
}

// the entries of a plain archive, for assert messages
fn describe(case: &Case) -> String {
	let walk = match (&case.nodes, &case.archive) {
		(Some(n), _) => tar_walk(&ustar_nodes(n)),
		(None, Some(a)) => tar_walk(a),
		(None, None) => vec!["no archive".into()],
	};
	walk.join("\n")
}

// header names/types/links of a ustar byte string, as far as it parses
fn tar_walk(a: &[u8]) -> Vec<String> {
	let mut out = Vec::new();
	let mut off = 0;
	while off + 512 <= a.len() {
		let h = &a[off..off + 512];
		if h.iter().all(|&b| b == 0) {
			break;
		}
		let field = |r: std::ops::Range<usize>| {
			let f = &h[r];
			let end =
				f.iter().position(|&b| b == 0)
					.unwrap_or(f.len());
			String::from_utf8_lossy(&f[..end]).into_owned()
		};
		let size = usize::from_str_radix(field(124..136).trim(), 8)
			.unwrap_or(0);
		out.push(format!(
			"  {:?} type {} mode {} link {:?} size {size}",
			field(0..100),
			h[156] as char,
			field(100..108),
			field(157..257)
		));
		off += 512 + size.next_multiple_of(512);
	}
	out
}

#[derive(Clone)]
struct Case {
	what: String,
	// archive bytes as written to w/pkg
	archive: Option<Vec<u8>>,
	// relative to w/
	prefix: &'static str,
	list: Option<Vec<Vec<u8>>>,
	breakfirst: bool,
	// the entries, for assert messages of compressed archives
	nodes: Option<Vec<TarNode>>,
}

impl std::fmt::Debug for Case {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		let list = self.list.as_ref().map(|l| {
			l.iter().map(|s| {
				String::from_utf8_lossy(s).into_owned()
			})
			.collect::<Vec<_>>()
		});
		write!(
			f,
			"{} ({} bytes) prefix {:?} list {list:?} breakfirst {}",
			self.what,
			self.archive.as_ref().map_or(0, |a| a.len()),
			self.prefix,
			self.breakfirst
		)
	}
}

// a tree as one line per path, for readable assert messages
fn listing(node: &Node, path: &str, out: &mut Vec<String>) {
	let text = |d: &[u8]| String::from_utf8_lossy(d).into_owned();
	match node {
		Node::Dir(mode, entries) => {
			out.push(format!("{path}/ dir {mode:o}"));
			for (name, n) in entries.iter().flatten() {
				listing(
					n,
					&format!("{path}/{}", text(name)),
					out,
				);
			}
		}
		Node::File(mode, nlink, data) => {
			let short = data.len() <= 40;
			out.push(match short {
				true => format!(
					"{path} file {mode:o} links {nlink} {:?}",
					text(data)
				),
				false => format!(
					"{path} file {mode:o} links {nlink} {} bytes {:?}...{:?}",
					data.len(),
					text(&data[..20]),
					text(&data[data.len() - 20..])
				),
			})
		}
		Node::Link(t) => out.push(format!("{path} -> {}", text(t))),
		n => out.push(format!("{path} {n:?}")),
	}
}

fn lines(node: &Node) -> Vec<String> {
	let mut out = Vec::new();
	listing(node, "", &mut out);
	out
}

impl Case {
	fn new(what: &str, archive: Vec<u8>) -> Case {
		Case {
			what: what.into(),
			archive: Some(archive),
			prefix: "p",
			list: None,
			breakfirst: false,
			nodes: None,
		}
	}

	fn list(self, list: &[&str], breakfirst: bool) -> Case {
		Case {
			list: Some(list
				.iter()
				.map(|s| s.as_bytes().to_vec())
				.collect()),
			breakfirst,
			..self
		}
	}
}

// w/ holding p/ (the prefix, before setup) and pkg
fn prepare(
	t: &TempRoot,
	case: &Case,
	setup: &dyn Fn(&Path),
) -> std::path::PathBuf {
	let w = t.dir().join("w");
	fs::create_dir_all(w.join("p")).unwrap();
	if let Some(a) = &case.archive {
		fs::write(w.join("pkg"), a).unwrap();
	}
	setup(&w.join("p"));
	w
}

fn rust_side(w: &Path, case: &Case) -> Outcome {
	let mut logs = Logs::default();
	let r = unpack(
		&mut logs,
		&bytes(&w.join("pkg")),
		&bytes(&w.join(case.prefix)),
		case.list.as_deref().unwrap_or_default(),
		case.breakfirst,
	);
	let (rc, errno) = match &r {
		Ok(()) => (0, 0),
		Err(e) => (1, e.errno().map_or(0, |e| e as c_int)),
	};
	Outcome {
		rc,
		errno,
		logs: norm_logs(logs.0, w),
	}
}

fn c_side(t: &TempRoot, w: &Path, case: &Case) -> Outcome {
	let c = c_unpack(
		&t.root(),
		&t.dbpath(),
		&bytes(&w.join("pkg")),
		&bytes(&w.join(case.prefix)),
		case.list.as_deref(),
		case.breakfirst,
	);
	Outcome {
		rc: c.rc,
		errno: c.errno,
		logs: norm_logs(c.logs, w),
	}
}

// both sides on fresh fixtures: outcomes and trees, C first
fn run_both(case: &Case, setup: &dyn Fn(&Path)) -> [(Outcome, Node); 2] {
	// the C changes cwd and umask of the process
	let _umask = umask_lock();
	let (ct, rt) = (TempRoot::new("unpack-c"), TempRoot::new("unpack-r"));
	let (cw, rw) = (prepare(&ct, case, setup), prepare(&rt, case, setup));
	let c = c_side(&ct, &cw, case);
	let r = rust_side(&rw, case);
	let (cs, rs) = (snapshot(&cw), snapshot(&rw));
	force_remove(&cw);
	force_remove(&rw);
	[(c, cs), (r, rs)]
}

fn compare(case: &Case, setup: &dyn Fn(&Path)) -> Outcome {
	let [(c, cs), (r, rs)] = run_both(case, setup);
	let nodes = describe(case);
	assert_eq!(
		c,
		r,
		"results for {case:?}\n{nodes}\nC tree {:#?}",
		lines(&cs)
	);
	assert_eq!(
		lines(&cs),
		lines(&rs),
		"trees for {case:?}\n{nodes}\n{c:?}"
	);
	assert_eq!(cs, rs, "trees for {case:?}\n{nodes}");
	c
}

fn none(_: &Path) {}

type Setup = Box<dyn Fn(&Path)>;

fn node(name: &str, kind: u8, mode: u32, link: &str, data: &[u8]) -> TarNode {
	TarNode {
		name: name.as_bytes().to_vec(),
		kind,
		mode,
		link: link.as_bytes().to_vec(),
		data: data.to_vec(),
	}
}

fn file(name: &str, data: &str) -> TarNode {
	node(name, b'0', 0o755, "", data.as_bytes())
}

fn dir(name: &str) -> TarNode {
	node(name, b'5', 0o700, "", b"")
}

fn link(name: &str, target: &str) -> TarNode {
	node(name, b'2', 0o777, target, b"")
}

fn hard(name: &str, target: &str) -> TarNode {
	node(name, b'1', 0o644, target, b"")
}

fn tar(nodes: &[TarNode]) -> Vec<u8> {
	ustar_nodes(nodes)
}

// a package as makepkg lays it out
fn package() -> Vec<TarNode> {
	vec![
		file(".PKGINFO", "pkgname = foo\n"),
		file(".BUILDINFO", "format = 2\n"),
		file(".MTREE", "#mtree\n"),
		file(".INSTALL", "post_install() {\n\ttrue\n}\n"),
		dir("usr/"),
		dir("usr/bin/"),
		file("usr/bin/foo", "#!/bin/sh\n"),
		link("usr/bin/bar", "foo"),
		hard("usr/bin/baz", "usr/bin/foo"),
		dir("etc/"),
		file("etc/foo.conf", "a=b\n"),
	]
}

#[test]
fn package_cases() {
	let pkg = tar(&package());
	compare(&Case::new("all", pkg.clone()), &none);
	// trans.c's scriptlet extraction
	let one = Case::new("install", pkg.clone()).list(&[".INSTALL"], true);
	compare(&one, &none);
	for (what, list, first) in [
		("usr/", &["usr/"][..], false),
		("usr/ first", &["usr/"], true),
		("usr without slash", &["usr"], false),
		("two", &["etc/", ".MTREE"], false),
		("none", &["nothing"], false),
		("empty list", &[], false),
	] {
		compare(&Case::new(what, pkg.clone()).list(list, first), &none);
	}
	let all_first = Case {
		breakfirst: true,
		..Case::new("breakfirst without list", pkg.clone())
	};
	compare(&all_first, &none);
	// rust convenience wrapper
	let _umask = umask_lock();
	let t = TempRoot::new("unpack-single");
	let w = prepare(&t, &Case::new("single", pkg), &none);
	let mut logs = Logs::default();
	unpack_single(
		&mut logs,
		&bytes(&w.join("pkg")),
		&bytes(&w.join("p")),
		b".INSTALL",
	)
	.unwrap();
	let logs: Vec<_> = logs.0.iter().map(|(_, m)| m.as_slice()).collect();
	assert_eq!(
		logs[1..],
		[&b"extracting: .INSTALL\n"[..]],
		"{:?}",
		logs.iter()
			.map(|m| String::from_utf8_lossy(m))
			.collect::<Vec<_>>()
	);
	let names: Vec<_> = fs::read_dir(w.join("p"))
		.unwrap()
		.map(|e| e.unwrap().file_name())
		.collect();
	assert_eq!(names, [".INSTALL"]);
	force_remove(&w);
}

fn compressed(comp: Comp, raw: &[u8]) -> Vec<u8> {
	let _umask = umask_lock();
	let t = TempRoot::new("unpack-comp");
	let p = t.dir().join("a");
	write_db(&p, comp, raw);
	fs::read(&p).unwrap()
}

#[test]
fn compressions() {
	let raw = tar(&package());
	for comp in COMPS {
		let data = compressed(comp, &raw);
		compare(&Case::new(&format!("{comp:?}"), data), &none);
	}
}

// a package spanning several of libarchive's filter blocks (64 KiB, 128
// KiB for zstd; bzip2 decodes in 900 KiB blocks of its own): headers at
// and across block boundaries, random sizes between them. the data is
// random so the compressed stream grows with it and cuts land all over
// the archive
fn big_package() -> Vec<TarNode> {
	const BLOCK: usize = 64 * 1024;
	let mut rng = Rng::new(0x5107_c0de);
	let mut nodes = vec![file(".PKGINFO", "pkgname = foo\n"), dir("usr/")];
	// tar offset of the next header
	let mut off: usize = 3 * 512;
	for i in 0.. {
		if off > 1300 * 1024 {
			break;
		}
		// the next header at a block boundary, or straddling one
		let next = (off + 512 + 20000).next_multiple_of(BLOCK);
		let len = match i % 4 {
			0 => next - off - 512,
			1 => next - off - 512 - 256,
			_ => rng.below(9000),
		};
		let data: Vec<u8> =
			(0..len).map(|_| rng.next_u64() as u8).collect();
		off += 512 + len.next_multiple_of(512);
		let name = format!("usr/f{i}");
		nodes.push(node(&name, b'0', 0o644, "", &data));
	}
	nodes.push(dir("etc/"));
	nodes.push(file("etc/foo.conf", "a=b\n"));
	nodes
}

// cut points: the start, evenly spread, random, and the stream's tail
// (gzip's trailer, xz's index and footer, zstd's checksum)
fn cuts(len: usize, rng: &mut Rng) -> Vec<usize> {
	let mut v: Vec<usize> = [1, 2, 10, 100].into();
	v.extend((1..48).map(|i| len * i / 48));
	v.extend((0..16).map(|_| rng.below(len)));
	v.extend([1, 4, 8, 9, 12, 20, 64].map(|d| len - d));
	v
}

// a compressed package cut short. libarchive's filter fails the block
// the stream ends in: inside the first one the C fails to open
// (PKG_OPEN); later, a data read reaching it fails the extraction and a
// header read reaching it ends the loop like the archive's end (rc 0,
// the entries before it extracted)
#[test]
fn compressed_cuts() {
	let mut rng = Rng::new(0x0c07_5eed);
	let raw = tar(&big_package());
	let mut outcomes = std::collections::BTreeSet::new();
	for comp in FILTERED {
		let data = compressed(comp, &raw);
		for (i, n) in cuts(data.len(), &mut rng).into_iter().enumerate()
		{
			let what =
				format!("{comp:?} cut at {n}/{}", data.len());
			let mut case = Case::new(&what, data[..n].to_vec());
			// odd cases skip the usr/ data (archive_read_data_skip)
			if i % 2 == 1 {
				case = case.list(&[".PKGINFO", "etc/"], false);
			}
			let out = compare(&case, &none);
			outcomes.insert((out.rc, out.errno, out.logs.len()));
		}
	}
	// open failures, failed extractions and early ends all seen
	assert!(outcomes.len() >= 3, "{outcomes:?}");
}

#[test]
fn open_and_prefix_failures() {
	let pkg = tar(&package());
	let missing = Case {
		archive: None,
		..Case::new("no archive", Vec::new())
	};
	assert_eq!(compare(&missing, &none).errno, Errno::PkgOpen as c_int);
	compare(&Case::new("empty file", Vec::new()), &none);
	compare(
		&Case::new("garbage", b"this is not an archive\n".repeat(40)),
		&none,
	);
	compare(&Case::new("zeros", vec![0; 4096]), &none);
	// archive is a directory: the first read fails at open
	let as_dir = Case {
		archive: None,
		..Case::new("archive is a dir", Vec::new())
	};
	compare(&as_dir, &|p| {
		fs::create_dir(p.parent().unwrap().join("pkg")).unwrap()
	});
	for (what, prefix) in
		[("missing prefix", "nope"), ("prefix is the archive", "pkg")]
	{
		let case = Case {
			prefix,
			..Case::new(what, pkg.clone())
		};
		compare(&case, &none);
	}
	let locked = |p: &Path| {
		fs::set_permissions(p, fs::Permissions::from_mode(0o600))
			.unwrap()
	};
	compare(&Case::new("prefix not searchable", pkg.clone()), &locked);
	let ro = |p: &Path| {
		fs::set_permissions(p, fs::Permissions::from_mode(0o555))
			.unwrap()
	};
	compare(&Case::new("prefix read-only", pkg), &ro);
}

#[test]
fn name_cases() {
	let names = [
		"./a",
		"a//b",
		"a/./b",
		"a/.",
		".",
		"./",
		"a/",
		"./.INSTALL",
		"//",
		"a/b/c/d",
		"a/b/",
		"",
	];
	for n in names {
		compare(
			&Case::new(
				&format!("file {n:?}"),
				tar(&[file(n, "x")]),
			),
			&none,
		);
		compare(
			&Case::new(&format!("dir {n:?}"), tar(&[dir(n)])),
			&none,
		);
	}
	let long = format!("{}/{}", "d".repeat(120), "f".repeat(120));
	compare(
		&Case::new(
			"long names",
			tar(&[file(&long, "x"), link("l", &long)]),
		),
		&none,
	);
	// a regular entry named like a directory is one
	compare(
		&Case::new(
			"regular with slash",
			tar(&[node("a/", b'0', 0o644, "", b"")]),
		),
		&none,
	);
	// modes: pacman forces 0644/0755, the rest loses suid/sgid/sticky
	// and the umask
	for mode in [0o4755, 0o2777, 0o1777, 0o000, 0o777] {
		let nodes = [
			node("f", b'0', mode, "", b"data"),
			node("d", b'5', mode, "", b""),
			node("p", b'6', mode, "", b""),
		];
		compare(
			&Case::new(&format!("mode {mode:o}"), tar(&nodes)),
			&none,
		);
	}
	// mknod needs CAP_MKNOD: both fail as non-root
	compare(
		&Case::new(
			"devices",
			tar(&[
				node("c", b'3', 0o644, "", b""),
				node("b", b'4', 0o644, "", b""),
			]),
		),
		&none,
	);
}

#[test]
fn in_the_way() {
	let one = |n: TarNode| tar(&[n]);
	let setups: Vec<(&str, Setup)> = vec![
		(
			"file",
			Box::new(|p: &Path| {
				fs::write(p.join("a"), "old").unwrap()
			}),
		),
		(
			"empty dir",
			Box::new(|p: &Path| {
				fs::create_dir(p.join("a")).unwrap()
			}),
		),
		(
			"full dir",
			Box::new(|p: &Path| {
				fs::create_dir(p.join("a")).unwrap();
				fs::write(p.join("a/x"), "x").unwrap();
			}),
		),
		(
			"dir 0700",
			Box::new(|p: &Path| {
				fs::create_dir(p.join("a")).unwrap();
				fs::set_permissions(
					p.join("a"),
					fs::Permissions::from_mode(0o700),
				)
				.unwrap();
			}),
		),
		(
			"dangling link",
			Box::new(|p: &Path| {
				symlink("nowhere", p.join("a")).unwrap()
			}),
		),
		(
			"link to dir",
			Box::new(|p: &Path| {
				fs::create_dir(p.join("t")).unwrap();
				symlink("t", p.join("a")).unwrap();
			}),
		),
		(
			"link to file",
			Box::new(|p: &Path| {
				fs::write(p.join("t"), "t").unwrap();
				symlink("t", p.join("a")).unwrap();
			}),
		),
		(
			"locked dir",
			Box::new(|p: &Path| {
				fs::create_dir(p.join("a")).unwrap();
				fs::set_permissions(
					p.join("a"),
					fs::Permissions::from_mode(0o000),
				)
				.unwrap();
			}),
		),
	];
	let entries = [
		("file", one(file("a", "new"))),
		("dir", one(dir("a"))),
		("link", one(link("a", "elsewhere"))),
		("file below", one(file("a/b", "new"))),
		("dir below", one(dir("a/b/c"))),
		("fifo", one(node("a", b'6', 0o644, "", b""))),
		("hard link", tar(&[file("src", "s"), hard("a", "src")])),
	];
	for (sw, setup) in &setups {
		for (ew, archive) in &entries {
			let case = Case::new(
				&format!("{ew} over {sw}"),
				archive.clone(),
			);
			compare(&case, setup.as_ref());
		}
	}
}

#[test]
fn link_cases() {
	let cases: Vec<(&str, Vec<TarNode>)> = vec![
		("hard to missing", vec![hard("a/b", "nope")]),
		("hard to dir", vec![dir("d"), hard("h", "d")]),
		("hard empty target", vec![hard("h", "")]),
		("hard to symlink", vec![link("s", "x"), hard("h", "s")]),
		("hard dotted target", vec![file("f", "x"), hard("h", "./f")]),
		("hard onto itself", vec![file("f", "x"), hard("f", "f")]),
		(
			"hard onto itself dotted",
			vec![file("f", "x"), hard("f", "./f")],
		),
		(
			"hard onto itself dotted name",
			vec![file("f", "x"), hard("./f", "f")],
		),
		(
			"hard again",
			vec![file("f", "x"), hard("g", "f"), hard("g", "f")],
		),
		("hard to itself below", vec![hard("a/g", "a/g")]),
		(
			"hard to itself spelled",
			vec![hard("a//g", "a/g"), hard("b/", "b")],
		),
		("hard through file", vec![file("f", "x"), hard("h", "f/x")]),
		// the parent is the file in the target: left alone
		(
			"hard through own parent",
			vec![file("f", "x"), hard("f/h", "f/x")],
		),
		(
			"hard through dir link",
			vec![
				dir("d"),
				file("d/f", "x"),
				link("s", "d"),
				hard("h", "s/f"),
			],
		),
		(
			"hard through file link",
			vec![file("f", "x"), link("s", "f"), hard("h", "s/x")],
		),
		(
			"hard through dangling link",
			vec![link("s", "nope"), hard("a/h", "s/x")],
		),
		("hard trailing slash", vec![file("f", "x"), hard("h", "f/")]),
		(
			"hard below missing dir",
			vec![file("f", "x"), hard("a/b/h", "f")],
		),
		("symlink empty target", vec![link("a/s", "")]),
		(
			"through symlink",
			vec![dir("d"), link("s", "d"), file("s/f", "x")],
		),
		("symlink loop", vec![link("s", "s"), file("s/f", "x")]),
		("symlink then file", vec![link("s", "t"), file("s", "x")]),
	];
	for (what, nodes) in cases {
		compare(&Case::new(what, tar(&nodes)), &none);
	}
}

// libarchive reads a directory entry (type '5', or a regular one named
// like a directory) as one without data, so its data is read as the next
// header and the loop ends there (UPSTREAM.md)
#[test]
fn dir_with_data() {
	for kind in *b"50" {
		let nodes =
			[node("a/", kind, 0o644, "", b"data"), file("b", "x")];
		let case = Case::new("dir with data", tar(&nodes));
		let [(c, cs), (r, rs)] = run_both(&case, &none);
		assert_eq!(c, r);
		assert_eq!(lines(&cs), lines(&rs));
		let dirs = ["/ dir 755", "/p/ dir 755", "/p/a/ dir 755"];
		assert_eq!(lines(&rs)[..3], dirs);
		assert!(lines(&rs)[3].starts_with("/pkg "), "{:?}", lines(&rs));
	}
}

#[test]
fn archive_self() {
	// the archive inside the prefix, an entry of its name: refused
	let nodes = [file("x", "x"), file("pkg", "overwrite")];
	let case = Case {
		prefix: ".",
		..Case::new("self", tar(&nodes))
	};
	compare(&case, &none);
}

// random archives over random existing trees

const PARTS: [&str; 6] = ["a", "b", "c", ".", "", ".INSTALL"];
const TARGETS: [&str; 7] = ["a", "b", "a/b", "c", "x", ".", "./a"];

fn random_name(rng: &mut Rng) -> String {
	let n = 1 + rng.below(3);
	let mut parts: Vec<&str> =
		(0..n).map(|_| PARTS[rng.below(PARTS.len())]).collect();
	if rng.below(5) == 0 {
		parts.insert(0, ".");
	}
	let mut s = parts.join("/");
	if rng.below(4) == 0 {
		s.push('/');
	}
	s
}

const MODES: [u32; 6] = [0o644, 0o755, 0o4755, 0o600, 0o000, 0o1777];

fn random_node(rng: &mut Rng) -> TarNode {
	let name = random_name(rng);
	let mode = MODES[rng.below(MODES.len())];
	let target = TARGETS[rng.below(TARGETS.len())];
	match rng.below(10) {
		0..=3 => {
			// libarchive reads a regular entry named like a directory
			// as one without data: its data would be read as headers
			let data = match name.ends_with('/') {
				true => Vec::new(),
				false => rng.bytes(b"ab\n\x00", 1500),
			};
			node(&name, b'0', mode, "", &data)
		}
		4..=5 => node(&name, b'5', mode, "", b""),
		6..=7 => node(&name, b'2', mode, target, b""),
		8 => node(&name, b'1', mode, target, b""),
		_ => node(&name, b'6', mode, "", b""),
	}
}

#[derive(Clone, Debug)]
enum Pre {
	File(String, u32),
	Dir(String, u32),
	Link(String, &'static str),
}

fn random_pre(rng: &mut Rng) -> Vec<Pre> {
	let n = rng.below(5);
	(0..n).map(|_| {
		let name =
			["a", "b", "c", "a/b", "b/c"][rng.below(5)].to_string();
		match rng.below(4) {
			0 => Pre::File(name, [0o644, 0o444][rng.below(2)]),
			1 => Pre::Dir(
				name,
				[0o755, 0o555, 0o000, 0o2755][rng.below(4)],
			),
			_ => Pre::Link(name, TARGETS[rng.below(TARGETS.len())]),
		}
	})
	.collect()
}

// builds what it can: a parent may be missing or locked
fn build_pre(p: &Path, pre: &[Pre]) {
	for x in pre {
		let r =
			match x {
				Pre::File(n, m) => fs::write(p.join(n), n)
					.and_then(|_| {
						fs::set_permissions(p.join(n), fs::Permissions::from_mode(*m))
					}),
				Pre::Dir(n, m) => fs::create_dir(p.join(n))
					.and_then(|_| {
						fs::set_permissions(p.join(n), fs::Permissions::from_mode(*m))
					}),
				Pre::Link(n, t) => symlink(t, p.join(n)),
			};
		let _ = r;
	}
}

#[test]
fn fuzz_extract() {
	let mut rng = Rng::new(0x0a4c_be11);
	let lists: [&[&str]; 4] =
		[&["a/"], &[".INSTALL"], &["a", "b/"], &["./"]];
	let mut compared_failures = 0;
	for i in 0..fs_iters() {
		let n = 1 + rng.below(6);
		let nodes: Vec<TarNode> =
			(0..n).map(|_| random_node(&mut rng)).collect();
		let mut archive = tar(&nodes);
		let comp = COMPS[rng.below(COMPS.len())];
		if !matches!(comp, Comp::None) {
			let _umask = umask_lock();
			let t = TempRoot::new("unpack-fz");
			let p = t.dir().join("a");
			write_db(&p, comp, &archive);
			archive = fs::read(&p).unwrap();
		}
		// plain archives cut anywhere: data reads fail or headers end.
		// compressed ones see compressed_cuts
		if matches!(comp, Comp::None) && rng.below(6) == 0 {
			archive.truncate(rng.below(archive.len()));
		}
		let mut case =
			Case::new(&format!("fuzz {i} {comp:?}"), archive);
		case.nodes = Some(nodes);
		if rng.below(3) == 0 {
			case = case.list(
				lists[rng.below(lists.len())],
				rng.below(2) == 0,
			);
		}
		let pre = random_pre(&mut rng);
		let out = compare(&case, &|p| build_pre(p, &pre));
		if out.rc != 0 || out.warned() {
			compared_failures += 1;
		}
	}
	assert!(
		compared_failures * 10 >= fs_iters(),
		"few failure paths: {compared_failures}"
	);
}
