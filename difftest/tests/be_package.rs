// alpm_core::be_package against the C alpm_pkg_load: package files built
// under TMPDIR (a makepkg-like .PKGINFO or random lines parse_descfile
// reads, file trees with dirs, symlinks and odd names, .MTREE, .INSTALL,
// .CHANGELOG, every compression alpm-compress has), loaded by both with
// full on and off; every field, the changelog, pm_errno and the log
// lines compared. odd inputs pin each divergence left; copies of real
// cached packages give counts
use std::ffi::c_int;
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use alpm_compress::compression::{
	Bzip2CompressionLevel, CompressionEncoder, CompressionSettings,
	GzipCompressionLevel, XzCompressionLevel, ZstdCompressionLevel,
	ZstdThreads,
};
use alpm_core::be_package::{
	Error, changelog, pkg_load, pkg_load_level, pkg_validate_internal,
};
use alpm_core::callbacks::{Callbacks, LogLevel};
use alpm_core::package::Package;
use alpm_core::signing::Keyring;
use difftest::{
	COMPS, CPkgHandle, Comp, Rng, TarNode, cut_archive_text, iters,
	pax_record, ustar_nodes,
};

// alpm_loglevel_t and message of each log line
type CLogs = Vec<(c_int, Vec<u8>)>;

// one archive per iteration, compressed and loaded four times
fn pkg_iters() -> usize {
	(iters() / 100).max(100)
}

// root/, db/ and pkg/ under a fresh /tmp dir, removed on drop
struct Fixture(PathBuf);

impl Fixture {
	fn new() -> Self {
		static N: AtomicUsize = AtomicUsize::new(0);
		let n = N.fetch_add(1, Ordering::Relaxed);
		let dir = std::env::temp_dir().join(format!(
			"difftest-be-package-{}-{n}",
			std::process::id()
		));
		if dir.exists() {
			fs::remove_dir_all(&dir).unwrap();
		}
		for d in ["root", "db", "pkg"] {
			fs::create_dir_all(dir.join(d)).unwrap();
		}
		Fixture(dir)
	}

	fn handle(&self) -> CPkgHandle {
		CPkgHandle::new(&self.0.join("root"), &self.0.join("db"))
	}

	fn pkg(&self, name: &str) -> PathBuf {
		self.0.join("pkg").join(name)
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).unwrap();
	}
}

fn bytes(p: &Path) -> &[u8] {
	p.as_os_str().as_bytes()
}

// what a load gives on either side: the package and its changelog, or
// pm_errno, and the lines it logged
#[derive(Debug, PartialEq)]
struct Outcome {
	r: Result<(Package, Option<Vec<u8>>), i32>,
	logs: CLogs,
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
	hay.windows(needle.len()).position(|w| w == needle)
}

// the C's lines the port does not log: RET_ERR/GOTO_ERR's debug lines (C
// source position)
fn c_only(msg: &[u8]) -> bool {
	msg.starts_with(b"returning error ") || msg.starts_with(b"got error ")
}

fn norm(logs: CLogs) -> CLogs {
	logs.into_iter()
		.filter(|(_, m)| !c_only(m))
		.map(|(l, m)| (l, cut_archive_text(&m)))
		.collect()
}

fn load_c(h: &CPkgHandle, path: &Path, full: bool) -> Outcome {
	let (r, logs) = h.load_logged(bytes(path), full);
	Outcome {
		r: r.map(|l| (l.pkg, l.changelog)),
		logs: norm(logs),
	}
}

// the port's lines, as the C's logcb sees them
#[derive(Default)]
struct Logs(CLogs);

impl Callbacks for Logs {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		self.0.push((level as c_int, msg.to_vec()));
	}
}

fn load_rust(path: &Path, full: bool) -> Outcome {
	let (mut kr, mut cb) = (Keyring::new(b""), Logs::default());
	let r = pkg_load_level(&mut kr, &mut cb, bytes(path), full, 0);
	let r = r.map_err(|e| e.errno() as i32).map(|pkg| {
		// the C side's changelog lines are taken apart (loaded)
		let log = match changelog(&mut (), &pkg) {
			Ok(log) => Some(log),
			Err(Error::NotFound) => None,
			Err(e) => {
				panic!("changelog of {}: {e:?}", path.display())
			}
		};
		(pkg, log)
	});
	Outcome {
		r,
		logs: norm(cb.0),
	}
}

fn lossy(b: &[u8]) -> String {
	String::from_utf8_lossy(b).into_owned()
}

fn show_logs(logs: &CLogs) -> String {
	let lines: Vec<_> = logs.iter().map(|(l, m)| (l, lossy(m))).collect();
	format!("{lines:#?}")
}

// field name and printable value, to show which fields differ
fn fields(p: &Package) -> Vec<(&'static str, String)> {
	let o = |s: &Option<Vec<u8>>| format!("{:?}", s.as_deref().map(lossy));
	let l = |v: &[Vec<u8>]| {
		format!("{:?}", v.iter().map(|s| lossy(s)).collect::<Vec<_>>())
	};
	let d = |v: &[alpm_core::deps::Depend]| {
		format!(
			"{:?}",
			v.iter().map(alpm_core::deps::dep_compute_string)
				.map(|s| lossy(&s))
				.collect::<Vec<_>>()
		)
	};
	vec![
		("name_hash", p.name_hash.to_string()),
		("filename", o(&p.filename)),
		("base", o(&p.base)),
		("name", o(&p.name)),
		("version", o(&p.version)),
		("desc", o(&p.desc)),
		("url", o(&p.url)),
		("packager", o(&p.packager)),
		("arch", o(&p.arch)),
		("builddate", p.builddate.to_string()),
		("size", p.size.to_string()),
		("isize", p.isize.to_string()),
		("licenses", l(&p.licenses)),
		("groups", l(&p.groups)),
		("replaces", d(&p.replaces)),
		("depends", d(&p.depends)),
		("optdepends", d(&p.optdepends)),
		("checkdepends", d(&p.checkdepends)),
		("makedepends", d(&p.makedepends)),
		("conflicts", d(&p.conflicts)),
		("provides", d(&p.provides)),
		(
			"deps raw",
			format!(
				"{:?}",
				(
					&p.depends,
					&p.optdepends,
					&p.provides,
					&p.conflicts,
					&p.replaces
				)
			),
		),
		(
			"backup",
			format!(
				"{:?}",
				p.backup.iter()
					.map(|b| (
						lossy(&b.name),
						b.hash.as_deref().map(lossy)
					))
					.collect::<Vec<_>>()
			),
		),
		(
			"files",
			format!(
				"{:?}",
				p.files.files
					.iter()
					.map(|f| (
						lossy(&f.name),
						f.size,
						format!("{:o}", f.mode)
					))
					.collect::<Vec<_>>()
			),
		),
		(
			"xdata",
			format!(
				"{:?}",
				p.xdata.iter()
					.map(|x| (
						lossy(&x.name),
						lossy(&x.value)
					))
					.collect::<Vec<_>>()
			),
		),
		(
			"rest",
			format!(
				"{:?}",
				(
					&p.origin,
					p.reason,
					p.scriptlet,
					p.infolevel,
					p.validation,
					&p.sha256sum,
					&p.base64_sig,
					p.installdate,
					p.download_size
				)
			),
		),
	]
}

// the differing fields of two outcomes, for assert messages
fn diff(c: &Outcome, r: &Outcome) -> String {
	let logs = if c.logs == r.logs {
		String::new()
	} else {
		format!(
			"  logs:\n    C {}\n    R {}\n",
			show_logs(&c.logs),
			show_logs(&r.logs)
		)
	};
	logs + &match (&c.r, &r.r) {
		(Ok((a, la)), Ok((b, lb))) => {
			let mut out = String::new();
			for ((k, x), (_, y)) in fields(a).iter().zip(fields(b))
			{
				if *x != y {
					out += &format!(
						"  {k}:\n    C {x}\n    R {y}\n"
					);
				}
			}
			if la != lb {
				out += &format!(
					"  changelog: C {la:?} R {lb:?}\n"
				);
			}
			out
		}
		(Ok(_), Err(e)) => format!("  C ok, R errno {e}\n"),
		(Err(e), Ok(_)) => format!("  C errno {e}, R ok\n"),
		(Err(a), Err(b)) => format!("  errno C {a} R {b}\n"),
	}
}

// how two outcomes relate, the form the pinned cases are written in
fn observe(c: &Outcome, r: &Outcome) -> String {
	match (&c.r, &r.r) {
		_ if c == r => "same".into(),
		(Ok(_), Err(35)) => "rust invalid".into(),
		(Ok(_), Err(51)) => "rust libarchive".into(),
		(Ok(_), Err(39)) => "rust open".into(),
		(Err(51), Ok(_)) => "c libarchive".into(),
		(Ok((a, la)), Ok((b, lb))) => {
			let mut keys: Vec<&str> = fields(a)
				.into_iter()
				.zip(fields(b))
				.filter(|((k, x), (_, y))| {
					*k != "deps raw" && x != y
				})
				.map(|((k, _), _)| k)
				.collect();
			if la != lb {
				keys.push("changelog");
			}
			if c.logs != r.logs {
				keys.push("logs");
			}
			format!("fields {}", keys.join(","))
		}
		(Err(a), Err(b)) if a == b => "logs".into(),
		(a, b) => format!(
			"errno C {:?} R {:?}",
			a.as_ref().err(),
			b.as_ref().err()
		),
	}
}

// a pinned case: what the C and the port give for full off and on
fn pin(h: &CPkgHandle, path: &Path, what: &str, want: [&str; 2]) {
	for (full, want) in [false, true].into_iter().zip(want) {
		let (c, r) = (load_c(h, path, full), load_rust(path, full));
		let got = observe(&c, &r);
		assert_eq!(
			got,
			want,
			"{what}, full {full}\n{}rust error {:?}",
			diff(&c, &r),
			pkg_load(bytes(path), full).err()
		);
	}
}

fn assert_same(h: &CPkgHandle, path: &Path, what: &dyn std::fmt::Debug) {
	for full in [false, true] {
		let (c, r) = (load_c(h, path, full), load_rust(path, full));
		assert!(
			c == r,
			"full {full}\n{}rust error {:?}\ninput {what:#?}",
			diff(&c, &r),
			pkg_load(bytes(path), full).err(),
		);
	}
}

// tar entry kinds, with what libarchive needs for each
#[derive(Clone, Debug)]
enum Kind {
	File(Vec<u8>),
	Dir,
	Symlink(Vec<u8>),
	Hardlink(Vec<u8>),
	Char,
	Block,
	Fifo,
	// raw type flag with data, for the odd ones
	Raw(u8, Vec<u8>),
}

#[derive(Clone, Debug)]
struct Entry {
	name: Vec<u8>,
	mode: u32,
	kind: Kind,
}

fn file(name: &[u8], data: &[u8]) -> Entry {
	Entry {
		name: name.to_vec(),
		mode: 0o644,
		kind: Kind::File(data.to_vec()),
	}
}

fn dir(name: &[u8]) -> Entry {
	Entry {
		name: name.to_vec(),
		mode: 0o755,
		kind: Kind::Dir,
	}
}

fn entry(name: &[u8], mode: u32, kind: Kind) -> Entry {
	Entry {
		name: name.to_vec(),
		mode,
		kind,
	}
}

// fixtures' tar entry of e
fn node(e: &Entry) -> TarNode {
	let (kind, link, data): (u8, &[u8], &[u8]) = match &e.kind {
		Kind::File(d) => (b'0', b"", d),
		Kind::Dir => (b'5', b"", b""),
		Kind::Symlink(t) => (b'2', t, b""),
		Kind::Hardlink(t) => (b'1', t, b""),
		Kind::Char => (b'3', b"", b""),
		Kind::Block => (b'4', b"", b""),
		Kind::Fifo => (b'6', b"", b""),
		Kind::Raw(f, d) => (*f, b"", d),
	};
	TarNode {
		name: e.name.clone(),
		kind,
		mode: e.mode,
		link: link.to_vec(),
		data: data.to_vec(),
	}
}

fn ustar(entries: &[Entry]) -> Vec<u8> {
	ustar_nodes(&entries.iter().map(node).collect::<Vec<_>>())
}

// fast levels, the fuzz writes thousands of archives
fn compress(path: &Path, comp: Comp, data: &[u8]) {
	let settings = match comp {
		Comp::None => CompressionSettings::None,
		Comp::Gzip => CompressionSettings::Gzip {
			compression_level: GzipCompressionLevel::new(1)
				.unwrap(),
		},
		Comp::Bzip2 => CompressionSettings::Bzip2 {
			compression_level: Bzip2CompressionLevel::new(1)
				.unwrap(),
		},
		Comp::Xz => CompressionSettings::Xz {
			compression_level: XzCompressionLevel::new(0).unwrap(),
		},
		Comp::Zstd => CompressionSettings::Zstd {
			compression_level: ZstdCompressionLevel::new(1)
				.unwrap(),
			threads: ZstdThreads::new(1),
		},
	};
	let f = fs::File::create(path).unwrap();
	let mut enc = CompressionEncoder::new(f, &settings).unwrap();
	enc.write_all(data).unwrap();
	enc.finish().unwrap();
}

fn write_pkg(path: &Path, comp: Comp, entries: &[Entry]) {
	compress(path, comp, &ustar(entries));
}

// gzip'd .MTREE text, the way makepkg ships it
fn gzip(fx: &Fixture, data: &[u8]) -> Vec<u8> {
	let p = fx.0.join("mtree.gz");
	compress(&p, Comp::Gzip, data);
	fs::read(p).unwrap()
}

const PKGINFO: &str = "\
# Generated by makepkg 7.0.0
pkgname = foo
pkgbase = foo
xdata = pkgtype=pkg
pkgver = 1.0-1
pkgdesc = a package
url = https://example.org/
builddate = 1720811171
packager = John Doe <john@example.org>
size = 2358
arch = x86_64
license = MIT
depend = bar>=1.0
";

// the C's file stats for a plain package
#[test]
fn fixed_minimal() {
	let fx = Fixture::new();
	let h = fx.handle();
	let path = fx.pkg("foo-1.0-1-x86_64.pkg.tar");
	let entries = vec![
		file(b".PKGINFO", PKGINFO.as_bytes()),
		dir(b"usr/"),
		dir(b"usr/bin/"),
		file(b"usr/bin/foo", b"#!/bin/sh\n"),
	];
	for comp in COMPS {
		write_pkg(&path, comp, &entries);
		assert_same(&h, &path, &(comp, &entries));
	}
}

// copies of real packages (DIFFTEST_PKG_CORPUS, default the dir the
// port unit copied the 20 smallest cached packages to): every one loads
// the same on both sides, or the divergence is listed
#[test]
fn real_packages() {
	let dir = std::env::var_os("DIFFTEST_PKG_CORPUS").map_or_else(
		|| std::env::temp_dir().join("ratman-pkgfile-corpus"),
		PathBuf::from,
	);
	let Ok(rd) = fs::read_dir(&dir) else {
		eprintln!("no package corpus at {}, skipped", dir.display());
		return;
	};
	let fx = Fixture::new();
	let h = fx.handle();
	let (mut same, mut diverged) = (0, Vec::new());
	let mut paths: Vec<PathBuf> = rd.map(|e| e.unwrap().path()).collect();
	paths.sort();
	for path in &paths {
		for full in [false, true] {
			let (c, r) =
				(load_c(&h, path, full), load_rust(path, full));
			if c == r {
				same += 1;
			} else {
				let why = pkg_load(bytes(path), full).err();
				eprintln!(
					"{} full {full}: {why:?}\n{}",
					path.display(),
					diff(&c, &r)
				);
				diverged.push(path.clone());
			}
		}
	}
	eprintln!(
		"real packages: {} files, {same} loads same, {} diverged",
		paths.len(),
		diverged.len()
	);
	assert!(diverged.is_empty());
}

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

fn word(rng: &mut Rng, alphabet: &[u8], min: usize, max: usize) -> String {
	let n = min + rng.below(max - min + 1);
	(0..n).map(|_| rng.pick(alphabet) as char).collect()
}

fn pick<'a>(rng: &mut Rng, items: &[&'a str]) -> &'a str {
	items[rng.below(items.len())]
}

// first byte not '-' or '.', which check_meta refuses. now and then
// long enough for check_meta's NAME_MAX
fn pkgname(rng: &mut Rng) -> String {
	let first = word(rng, b"abcxyz0189@_+", 1, 1);
	let max = if rng.below(20) == 0 { 260 } else { 14 };
	first + &word(rng, b"abcdxyz0189@._+-", 0, max)
}

fn pkgver(rng: &mut Rng) -> String {
	word(rng, b"abcxyz0123456789._+", 1, 8)
}

fn full_version(rng: &mut Rng) -> String {
	let epoch = match rng.below(4) {
		0 => format!("{}:", rng.below(30)),
		_ => String::new(),
	};
	// a leading zero is kept as read
	let zero = if rng.below(4) == 0 { "0" } else { "" };
	let rel = match rng.below(4) {
		0 => format!("{zero}{}.{}", 1 + rng.below(9), rng.below(9)),
		_ => format!("{zero}{}", 1 + rng.below(20)),
	};
	format!("{epoch}{}-{rel}", pkgver(rng))
}

// a relation as makepkg writes it: name, optionally an operator and a
// version with optional epoch and pkgrel, names sometimes with ".so"
// (raw_value has the odd ones)
fn relation(rng: &mut Rng) -> String {
	let so = if rng.below(8) == 0 { ".so" } else { "" };
	let name = word(rng, b"abcxyz0189_+-", 1, 1).replace('-', "a")
		+ so + &word(rng, LOWER, 0, 8);
	if rng.below(2) == 0 {
		return name;
	}
	let op = pick(rng, &["<", "<=", "=", ">=", ">"]);
	let ver = match rng.below(3) {
		0 => pkgver(rng),
		_ => full_version(rng),
	};
	format!("{name}{op}{ver}")
}

fn optdepend(rng: &mut Rng) -> String {
	let name = word(rng, LOWER, 1, 8);
	match rng.below(2) {
		0 => name,
		// libalpm keeps the description after ": " as is
		_ => format!(
			"{name}: {}{}{}{}",
			pick(rng, &["", "", " "]),
			word(rng, ALNUM, 1, 6),
			pick(rng, &[" ", "  "]),
			word(rng, ALNUM, 0, 6)
		),
	}
}

fn soname(rng: &mut Rng) -> String {
	let lib = word(rng, LOWER, 2, 6);
	match rng.below(2) {
		0 => format!("lib:lib{lib}.so.{}", rng.below(9)),
		_ => format!("lib{lib}.so={}-64", rng.below(9)),
	}
}

// a makepkg-like .PKGINFO, lines shuffled (xdata in any order), comments
// and blank lines in between, then what makepkg does not write and the C
// reads anyway: any line left out, empty or doubled values, other
// separators, trailing blanks, CRLF, unknown keys, random lines
fn gen_pkginfo(rng: &mut Rng, name: &str, version: &str) -> Vec<u8> {
	let mut lines = vec![
		format!("pkgname = {name}"),
		format!(
			"pkgbase = {}",
			if rng.below(2) == 0 {
				name.to_string()
			} else {
				pkgname(rng)
			}
		),
		format!("pkgver = {version}"),
		// runs of blanks, upper case urls and makepkg's default
		// packager are kept as read
		format!(
			"pkgdesc = {}{}{}",
			word(rng, ALNUM, 1, 8),
			pick(rng, &[" ", " ", "  ", " \t"]),
			word(rng, ALNUM, 1, 8)
		),
		match rng.below(4) {
			0 => format!(
				"url = HTTPS://{}.ORG",
				word(rng, LOWER, 1, 6)
			),
			_ => format!(
				"url = https://{}.org/{}",
				word(rng, LOWER, 1, 6),
				word(rng, LOWER, 0, 4)
			),
		},
		format!("builddate = {}", rng.next_u64() % 4_000_000_000),
		match rng.below(6) {
			0 => "packager = Unknown Packager".into(),
			_ => format!(
				"packager = {} {} <{}@example.org>",
				word(rng, LOWER, 1, 5),
				word(rng, LOWER, 1, 5),
				word(rng, LOWER, 1, 5)
			),
		},
		format!("size = {}", rng.next_u64() >> rng.below(64)),
		format!(
			"arch = {}",
			pick(
				rng,
				&[
					"any", "x86_64", "aarch64", "i686",
					"armv7h", "riscv64"
				]
			)
		),
	];
	if rng.below(2) == 0 {
		lines.push(format!(
			"xdata = pkgtype={}",
			pick(rng, &["pkg", "split", "debug", "src"])
		));
		for _ in 0..rng.below(3) {
			lines.push(format!(
				"xdata = {}={}",
				word(rng, LOWER, 1, 5),
				word(rng, ALNUM, 1, 5)
			));
		}
	}
	let many = |rng: &mut Rng,
	            key: &str,
	            f: &dyn Fn(&mut Rng) -> String,
	            out: &mut Vec<String>| {
		for _ in 0..rng.below(4) {
			out.push(format!("{key} = {}", f(rng)));
		}
	};
	many(
		rng,
		"license",
		&|r| {
			pick(
				r,
				&[
					"MIT",
					"GPL-3.0-or-later",
					"Apache-2.0",
					"LicenseRef-custom",
					"BSD-3-Clause",
				],
			)
			.to_string()
		},
		&mut lines,
	);
	many(rng, "group", &|r| word(r, LOWER, 1, 8), &mut lines);
	many(rng, "replaces", &relation, &mut lines);
	many(rng, "conflict", &relation, &mut lines);
	many(
		rng,
		"provides",
		&|r| {
			if r.below(4) == 0 {
				soname(r)
			} else {
				relation(r)
			}
		},
		&mut lines,
	);
	many(
		rng,
		"backup",
		&|r| {
			format!(
				"etc/{}/{}.conf",
				word(r, LOWER, 1, 5),
				word(r, ALNUM, 1, 5)
			)
		},
		&mut lines,
	);
	many(
		rng,
		"depend",
		&|r| {
			if r.below(4) == 0 {
				soname(r)
			} else {
				relation(r)
			}
		},
		&mut lines,
	);
	many(rng, "optdepend", &optdepend, &mut lines);
	many(rng, "makedepend", &relation, &mut lines);
	many(rng, "checkdepend", &relation, &mut lines);
	// shuffle, list keys keep their relative order on both sides
	for i in (1..lines.len()).rev() {
		lines.swap(i, rng.below(i + 1));
	}
	// keys pacman ignores
	if rng.below(8) == 0 {
		let unknown = [
			"basever = 1",
			"foo = bar",
			"PKGNAME = x",
			" pkgname = y",
		];
		let at = rng.below(lines.len() + 1);
		lines.insert(at, pick(rng, &unknown).into());
	}
	let mut out = Vec::new();
	for l in lines {
		match rng.below(10) {
			0 => out.extend_from_slice(b"# a comment\n"),
			1 => out.push(b'\n'),
			_ => {}
		}
		let mut l = l.into_bytes();
		let sep = find(&l, b" = ");
		match (rng.below(40), sep) {
			(0, _) => continue,
			(1, Some(at)) => l.truncate(at + 3),
			(2, _) => {
				out.extend_from_slice(&[&l[..], b"\n"].concat())
			}
			(3, Some(at)) => {
				let other =
					pick(rng, &["=", " =", "  = ", "\t= "]);
				l.splice(at..at + 3, other.bytes());
			}
			(4, _) => l.push(b'\r'),
			(5, _) => l.extend_from_slice(b" \t"),
			_ => {}
		}
		out.extend_from_slice(&l);
		out.push(b'\n');
	}
	if rng.below(8) == 0 {
		out.extend_from_slice(&gen_raw_pkginfo(rng));
	}
	out
}

// path components: specials the mtree escapes, a multibyte char, dots
fn component(rng: &mut Rng) -> Vec<u8> {
	let mut c = Vec::new();
	for _ in 0..1 + rng.below(8) {
		match rng.below(12) {
			0 => c.extend_from_slice("é".as_bytes()),
			1 => c.push(rng.pick(b" #=\\~@+-_.")),
			_ => c.push(rng.pick(ALNUM)),
		}
	}
	c
}

// mtree path escaping: octal for what would end or confuse the token
fn mtree_escape(name: &[u8]) -> String {
	let mut out = String::new();
	for &b in name {
		if b <= b' ' || b >= 0x7f || matches!(b, b'\\' | b'#' | b'=') {
			out += &format!("\\{b:03o}");
		} else {
			out.push(b as char);
		}
	}
	out
}

// one data entry of the tree with its mtree line, None for kinds the
// mtree has no type for
fn mtree_line(e: &Entry) -> Option<String> {
	let name = e.name.strip_suffix(b"/").unwrap_or(&e.name);
	let path = format!("./{}", mtree_escape(name));
	let props = match &e.kind {
		Kind::Dir => format!("type=dir mode={:o}", e.mode),
		Kind::File(d) => format!(
			"type=file mode={:o} size={} sha256digest={}",
			e.mode,
			d.len(),
			"0".repeat(64)
		),
		Kind::Symlink(t) => {
			format!("type=link mode=777 link={}", mtree_escape(t))
		}
		Kind::Char => "type=char mode=600".into(),
		Kind::Block => "type=block mode=600".into(),
		Kind::Fifo => "type=fifo mode=600".into(),
		_ => return None,
	};
	Some(format!("{path} time=1700000000.0 {props}\n"))
}

fn gen_mtree(rng: &mut Rng, data: &[Entry], install: bool) -> String {
	let mut out =
		String::from("#mtree\n/set type=file uid=0 gid=0 mode=644\n");
	out += "./.PKGINFO time=1700000000.0 size=1 sha256digest=";
	out += &"0".repeat(64);
	out.push('\n');
	if install {
		out += "./.INSTALL time=1700000000.0 size=1 sha256digest=";
		out += &"0".repeat(64);
		out.push('\n');
	}
	for e in data {
		if rng.below(20) == 0 {
			continue;
		}
		out += &mtree_line(e).unwrap_or_default();
	}
	out
}

// a file tree: dirs with trailing '/', files, symlinks, the odd hard link,
// device or fifo, now and then a "./" prefixed or dot-named entry
fn gen_tree(rng: &mut Rng) -> Vec<Entry> {
	let mut dirs: Vec<Vec<u8>> = vec![Vec::new()];
	let mut out = Vec::new();
	for _ in 0..rng.below(12) {
		let parent = dirs[rng.below(dirs.len())].clone();
		let mut name = [&parent[..], &component(rng)].concat();
		if rng.below(30) == 0 {
			// past 100 bytes: GNU longname
			name.extend_from_slice(&[b'l'; 120]);
		}
		let mode = 0o644 | (rng.below(8) as u32) << 6;
		let e = match rng.below(14) {
			0..=3 => {
				name.push(b'/');
				dirs.push(name.clone());
				entry(&name, 0o755, Kind::Dir)
			}
			4 => {
				let mut t = component(rng);
				if rng.below(5) == 0 {
					t.extend_from_slice(&[b't'; 110]);
				}
				entry(&name, 0o777, Kind::Symlink(t))
			}
			5 if !out.is_empty() => {
				let Entry { name: t, .. } =
					&out[rng.below(out.len())];
				entry(&name, mode, Kind::Hardlink(t.clone()))
			}
			6 => entry(
				&name,
				0o600,
				[Kind::Char, Kind::Block, Kind::Fifo]
					[rng.below(3)]
				.clone(),
			),
			7 if rng.below(3) == 0 => entry(
				&[b"./", &name[..]].concat(),
				mode,
				Kind::File(b"x".to_vec()),
			),
			_ => {
				let data = vec![b'd'; rng.below(700)];
				entry(&name, mode, Kind::File(data))
			}
		};
		// now and then a path twice: one mtree entry, two in the tar
		let key = |e: &Entry| {
			e.name.strip_suffix(b"/").unwrap_or(&e.name).to_vec()
		};
		if rng.below(20) == 0 || out.iter().all(|o| key(o) != key(&e)) {
			out.push(e);
		}
	}
	out
}

// a whole package, the input kept for assert messages
#[derive(Debug)]
struct Gen {
	comp: Comp,
	entries: Vec<Entry>,
}

fn gen_pkg(rng: &mut Rng, fx: &Fixture) -> Gen {
	let name = pkgname(rng);
	let version = if name.len() > 200 {
		format!("{}{}-1", pkgver(rng), word(rng, ALNUM, 0, 60))
	} else {
		full_version(rng)
	};
	let tree = gen_tree(rng);
	let install = rng.below(3) == 0;
	let mut meta = Vec::new();
	if rng.below(40) != 0 {
		meta.push(file(
			b".PKGINFO",
			&gen_pkginfo(rng, &name, &version),
		));
	}
	if rng.below(2) == 0 {
		meta.push(file(b".BUILDINFO", b"format = 2\njunk\n"));
	}
	if install {
		meta.push(file(b".INSTALL", b"post_install() { :; }\n"));
	}
	if rng.below(3) == 0 {
		let log = word(rng, ALNUM, 0, 40).repeat(1 + rng.below(300));
		meta.push(file(b".CHANGELOG", log.as_bytes()));
	}
	if rng.below(2) == 0 {
		let listed = install && rng.below(2) == 0;
		let mtree = gen_mtree(rng, &tree, listed);
		meta.push(file(b".MTREE", &gzip(fx, mtree.as_bytes())));
	}
	if rng.below(10) == 0 {
		meta.push(file(b".hidden", b"skipped"));
	}
	// metadata first like makepkg, or anywhere
	let mut entries = Vec::new();
	if rng.below(2) == 0 {
		for i in (1..meta.len()).rev() {
			meta.swap(i, rng.below(i + 1));
		}
		entries.extend(meta);
		entries.extend(tree);
	} else {
		entries.extend(tree);
		for m in meta {
			let at = rng.below(entries.len() + 1);
			entries.insert(at, m);
		}
	}
	Gen {
		comp: COMPS[rng.below(COMPS.len())],
		entries,
	}
}

#[test]
fn fuzz_packages() {
	let fx = Fixture::new();
	let h = fx.handle();
	let mut rng = Rng::new(0xbe9a);
	let path = fx.pkg("fuzz.pkg.tar");
	let (mut loaded, mut mtree) = (0, 0);
	for _ in 0..pkg_iters() {
		let g = gen_pkg(&mut rng, &fx);
		write_pkg(&path, g.comp, &g.entries);
		assert_same(&h, &path, &g);
		if let Ok((p, _)) = load_rust(&path, true).r {
			loaded += 1;
			mtree += usize::from(
				g.entries.iter().any(|e| e.name == b".MTREE")
					&& !p.files.files.is_empty(),
			);
		}
	}
	eprintln!(
		"fuzz_packages: {} packages, {loaded} loaded, {mtree} with an mtree list",
		pkg_iters()
	);
	assert!(loaded * 2 > pkg_iters());
}

// PKGINFO with one line replaced (key match) or added
fn pkginfo_with(edits: &[(&str, Option<&str>)], extra: &[&str]) -> Vec<u8> {
	let mut out = Vec::new();
	for line in PKGINFO.lines() {
		let key = line.split(" = ").next().unwrap();
		match edits.iter().find(|(k, _)| *k == key) {
			Some((_, None)) => continue,
			Some((_, Some(v))) => {
				out.extend_from_slice(v.as_bytes())
			}
			None => out.extend_from_slice(line.as_bytes()),
		}
		out.push(b'\n');
	}
	for l in extra {
		out.extend_from_slice(l.as_bytes());
		out.push(b'\n');
	}
	out
}

// a one-entry package of info in every compression, loaded alike
fn assert_pkginfo(h: &CPkgHandle, path: &Path, what: &str, info: &[u8]) {
	let entries = [file(b".PKGINFO", info), file(b"a", b"x")];
	for comp in COMPS {
		write_pkg(path, comp, &entries);
		assert_same(h, path, &(what, comp, lossy(info)));
	}
}

// .PKGINFO inputs around parse_descfile's lines, keys and values and the
// checks after it: one line changed against PKGINFO, or whole files
#[test]
fn fixed_pkginfo() {
	let fx = Fixture::new();
	let h = fx.handle();
	let path = fx.pkg("odd.pkg.tar");
	let w = |k: &str, v: &str| pkginfo_with(&[(k, Some(v))], &[]);
	let drop = |k: &str| pkginfo_with(&[(k, None)], &[]);
	let add = |l: &str| pkginfo_with(&[], &[l]);
	let mut non_utf8 = w("pkgdesc", "pkgdesc = caf");
	let at = non_utf8.windows(3).position(|x| x == b"caf").unwrap();
	non_utf8.insert(at + 3, 0xe9);
	let mut cases: Vec<(&str, Vec<u8>)> = vec![
		("empty url", w("url", "url = ")),
		("trailing space", w("pkgname", "pkgname = foo ")),
		("crlf", PKGINFO.replace('\n', "\r\n").into_bytes()),
		("crlf version", w("pkgver", "pkgver = 1.0-1\r")),
		("non-utf8", non_utf8),
		("name with '*'", w("pkgname", "pkgname = f*")),
		("relation without version", add("depend = a>=")),
		("relation with desc", add("depend = a: desc")),
		("relation only desc", add("depend = : desc")),
		("relation operators", add("conflict = a<=>1")),
		("empty relation", add("provides = ")),
		("optdepend without space", add("optdepend = a:b")),
		("absolute backup", add("backup = /etc/foo")),
		("directory backup", add("backup = etc/foo/")),
		("empty backup", add("backup = ")),
		("size with '+'", w("size", "size = +5")),
		("size empty", w("size", "size = ")),
		("size junk", w("size", "size = 5k")),
		("size leading zeros", w("size", "size = 000123")),
		("size negative", w("size", "size = -1")),
		("size past i64", w("size", "size = 9223372036854775808")),
		("size u64 max", w("size", "size = 18446744073709551615")),
		("size past u64", w("size", "size = 18446744073709551616")),
		("xdata spaces", add("xdata = a = b ")),
		(
			"pkgtype not first",
			w("xdata", "xdata = a=b")
				.into_iter()
				.chain(b"xdata = pkgtype=pkg\n".iter().copied())
				.collect(),
		),
		("xdata without pkgtype", w("xdata", "xdata = a=b")),
		("xdata empty value", add("xdata = a=")),
		("xdata empty name", add("xdata = =b")),
		("xdata only '='", add("xdata = =")),
		("unknown key", add("foo = bar")),
		("unknown empty key", add(" = bar")),
		("basever", add("basever = 1")),
		("pkgtype key", add("pkgtype = pkg")),
		("duplicate pkgdesc", add("pkgdesc = second")),
		("duplicate pkgname", add("pkgname = bar")),
		("duplicate pkgver", add("pkgver = 2-1")),
		("no url", drop("url")),
		("no packager", drop("packager")),
		("no pkgdesc", drop("pkgdesc")),
		("no pkgbase", drop("pkgbase")),
		("no builddate", drop("builddate")),
		("no size", drop("size")),
		("no arch", drop("arch")),
		("no xdata", drop("xdata")),
		("builddate junk", w("builddate", "builddate = 5x")),
		("builddate empty", w("builddate", "builddate = ")),
		("builddate '+'", w("builddate", "builddate = +5")),
		("builddate blank", w("builddate", "builddate =  7")),
		("builddate trailing", w("builddate", "builddate = 7 ")),
		("negative builddate", w("builddate", "builddate = -5")),
		(
			"builddate past i64",
			w("builddate", "builddate = 9223372036854775808"),
		),
		(
			"builddate i64 min",
			w("builddate", "builddate = -9223372036854775808"),
		),
		("syntax error line", add("garbage")),
		("key=value", add("group=foo")),
		("key =value", add("group =foo")),
		("key= value", add("group= foo")),
		("key = at the end", add("group =")),
		("key two spaces", add("group  = x")),
		("key tab", add("group\t= x")),
		("value tab", add("group = \tx")),
		("indented key", add("  group = x")),
		("space in key", add("a b = c")),
		("indented comment", add(" # x = y")),
		("comment no space", add("#x = y")),
		("empty pkgdesc", w("pkgdesc", "pkgdesc = ")),
		("blank pkgdesc", w("pkgdesc", "pkgdesc =  ")),
		("empty packager", w("packager", "packager = ")),
		("url without path", w("url", "url = https://a.org")),
		("url case", w("url", "url = HTTPS://A.org/x?y#z")),
		("desc whitespace", w("pkgdesc", "pkgdesc = a  b \t c ")),
		(
			"Unknown Packager",
			w("packager", "packager = Unknown Packager"),
		),
		("packager without name", w("packager", "packager = <a@b.c>")),
		("depend with .so", add("depend = foo.sound")),
		("depend pkgrel zero", add("depend = a=1-01")),
		("optdepend spaces", add("optdepend = a:  x  y ")),
		("uppercase arch", w("arch", "arch = X86_64")),
		("unknown arch", w("arch", "arch = foo")),
		("empty arch", w("arch", "arch = ")),
		("non-SPDX license", w("license", "license = GPL")),
		(
			"license expression",
			w("license", "license = MIT OR Apache-2.0"),
		),
		("empty license", w("license", "license = ")),
		("group with space", add("group = a b")),
		("empty group", add("group = ")),
		("epoch 0", w("pkgver", "pkgver = 0:1-1")),
		("uppercase name", w("pkgname", "pkgname = Foo")),
		(
			"leading blank lines",
			[b"\n  \n", PKGINFO.as_bytes()].concat(),
		),
		("no final newline", PKGINFO.trim_end().as_bytes().to_vec()),
		("empty", Vec::new()),
		("only newline", b"\n".to_vec()),
		// nul bytes: a nul ends key and value as C strings, a line
		// starting with one is empty
		("nul in value", add("group = a\0b")),
		("nul in key", add("gro\0up = a")),
		("nul before separator", add("a\0b = c")),
		("nul starting a line", add("\0group = a")),
		(
			"nul after last newline",
			[PKGINFO.as_bytes(), b"a\0b = c"].concat(),
		),
		("nul in name", w("pkgname", "pkgname = foo\0bar")),
		// refused by both, each with its error line
		("xdata without '='", add("xdata = ab")),
		(
			"xdata without '=' after unknown key",
			[PKGINFO.as_bytes(), b"foo = 1\nxdata = ab\nbar = 2\n"]
				.concat(),
		),
		("version without '-'", w("pkgver", "pkgver = 1.0")),
		("empty version", w("pkgver", "pkgver = ")),
		("no version", drop("pkgver")),
		("empty name", w("pkgname", "pkgname = ")),
		("no name", drop("pkgname")),
		("name nul", w("pkgname", "pkgname = \0foo")),
		("version with two '-'", w("pkgver", "pkgver = 1-0-1")),
		("version with '/'", w("pkgver", "pkgver = 1/0-1")),
		("name starting with '.'", w("pkgname", "pkgname = .foo")),
		("name starting with '-'", w("pkgname", "pkgname = -foo")),
		(
			"several meta errors",
			pkginfo_with(
				&[
					("pkgname", Some("pkgname = -foo")),
					("pkgver", Some("pkgver = 1-2/3-4")),
				],
				&[],
			),
		),
	];
	// name and version over NAME_MAX together
	let long = format!("pkgname = {}", "a".repeat(250));
	cases.push(("too long", w("pkgname", &long)));
	let long = format!("pkgname = {}", "a".repeat(248));
	cases.push(("NAME_MAX", w("pkgname", &long)));
	for (what, info) in cases {
		assert_pkginfo(&h, &path, what, &info);
	}
}

// line lengths around parse_descfile's 512 KiB limit and lines over
// libarchive's data blocks: the first line is read without the check as
// long as it sits in the first block
#[test]
fn fixed_pkginfo_long_lines() {
	let fx = Fixture::new();
	let h = fx.handle();
	let path = fx.pkg("long.pkg.tar");
	const MAX: usize = 512 * 1024;
	let line = |n: usize| {
		let head = b"pkgdesc = ";
		[&head[..], &vec![b'd'; n - head.len()][..], b"\n"].concat()
	};
	let cases: Vec<(&str, Vec<u8>)> = vec![
		(
			"desc of 100k",
			[PKGINFO.as_bytes(), &line(100_000)].concat(),
		),
		("max - 1", [PKGINFO.as_bytes(), &line(MAX - 1)].concat()),
		("max", [PKGINFO.as_bytes(), &line(MAX)].concat()),
		(
			"first line max - 1",
			[&line(MAX - 1), PKGINFO.as_bytes()].concat(),
		),
		("first line max", [&line(MAX), PKGINFO.as_bytes()].concat()),
		(
			"unknown keys then max",
			[PKGINFO.as_bytes(), b"foo = 1\n", &line(MAX + 5)]
				.concat(),
		),
		(
			"no newline, max",
			[PKGINFO.as_bytes(), &line(MAX)[..MAX]].concat(),
		),
	];
	for (what, info) in cases {
		assert_pkginfo(&h, &path, what, &info);
	}
}

// a big .PKGINFO with nul bytes near libarchive's data block ends: a
// block without a '\n' after the nul ends the line there, one with a
// '\n' later keeps it in the line. placed after a file of random size to
// move the block ends, and cut short in a plain tar
#[test]
fn fuzz_pkginfo_blocks() {
	let fx = Fixture::new();
	let h = fx.handle();
	let path = fx.pkg("blocks.pkg.tar");
	let mut rng = Rng::new(0xb10c);
	let n = (iters() / 2000).max(40);
	for i in 0..n {
		let mut info = PKGINFO.as_bytes().to_vec();
		let size = 4096 + rng.below(300_000);
		while info.len() < size {
			let key = word(&mut rng, LOWER, 1, 6);
			let val = word(&mut rng, ALNUM, 0, 2000);
			info.extend_from_slice(
				format!("{key} = {val}").as_bytes(),
			);
			info.push(match rng.below(6) {
				0 => 0,
				_ => b'\n',
			});
		}
		let pad = rng.below(140_000);
		let mut entries = vec![file(b".PKGINFO", &info)];
		if rng.below(2) == 0 {
			entries.insert(0, file(b"pad", &vec![b'p'; pad]));
		}
		let comp = COMPS[i % COMPS.len()];
		write_pkg(&path, comp, &entries);
		if matches!(comp, Comp::None) && rng.below(3) == 0 {
			// the .PKGINFO data cut short
			let data = fs::read(&path).unwrap();
			let start = 512 + entries.len().saturating_sub(1)
				* (512 + pad.next_multiple_of(512));
			let cut = start + rng.below(info.len());
			fs::write(&path, &data[..cut]).unwrap();
		}
		assert_same(&h, &path, &(comp, size, pad));
	}
}

const PKGINFO_KEYS: [&str; 25] = [
	"pkgname",
	"pkgbase",
	"pkgver",
	"basever",
	"pkgdesc",
	"group",
	"url",
	"license",
	"builddate",
	"packager",
	"arch",
	"size",
	"depend",
	"optdepend",
	"makedepend",
	"checkdepend",
	"conflict",
	"replaces",
	"provides",
	"backup",
	"xdata",
	"pkgtype",
	"foo",
	"PKGNAME",
	"",
];

// a value for key: numbers strtoll/strtoull treat differently, odd
// relations, xdata with and without '=', text with blanks and bytes
// past ASCII
fn raw_value(rng: &mut Rng, key: &str) -> Vec<u8> {
	let num = [
		"",
		" ",
		"0",
		"5",
		"+5",
		"-5",
		" 7",
		"7 ",
		"1e3",
		"0x10",
		"007",
		"1720811171",
		"9223372036854775807",
		"9223372036854775808",
		"18446744073709551615",
		"99999999999999999999",
		"-9223372036854775808",
	];
	let rel = [
		"",
		":",
		": d",
		"a>=",
		"a<",
		"a: ",
		"a: d",
		"a=1: d",
		"<1",
		"a<=>1",
		"a::b",
		"a: b: c",
		"foo.sound",
		"lib:libx.so.1",
		"a=1:2-3",
		"a>=1-01",
	];
	let xdata = ["pkgtype=pkg", "a=b", "=", "a=", "=b", "a = b", "ab"];
	let v = match key {
		"builddate" | "size" => pick(rng, &num).to_string(),
		"depend" | "optdepend" | "makedepend" | "checkdepend"
		| "conflict" | "replaces" | "provides" => match rng.below(3) {
			0 => pick(rng, &rel).to_string(),
			1 => optdepend(rng),
			_ => relation(rng),
		},
		// mostly with '=', a failed one ends the load
		"xdata" if rng.below(8) == 0 => "ab".into(),
		"xdata" => pick(rng, &xdata[..6]).to_string(),
		"pkgname" => match rng.below(6) {
			0 => pick(rng, &["", "-a", ".a", "a*", "a/b", "é"])
				.into(),
			_ => pkgname(rng),
		},
		"pkgver" => match rng.below(6) {
			0 => pick(rng, &["", "1", "1-2-3", "1/2-3", "1-"])
				.into(),
			_ => full_version(rng),
		},
		_ => match rng.below(5) {
			0 => String::new(),
			1 => pick(rng, &[" ", "  ", "\t", "é", " a "]).into(),
			_ => word(rng, b"ab yz09:=<>#-./", 0, 12),
		},
	};
	v.into_bytes()
}

// a .PKGINFO of random lines parse_descfile reads: every key it knows
// and unknown ones, empty and blank values, separators that are and are
// not " = ", comments, blank lines, duplicates, CRLF, nul and non-UTF-8
// bytes, no final newline. most have a name and version that load
fn gen_raw_pkginfo(rng: &mut Rng) -> Vec<u8> {
	let mut lines: Vec<Vec<u8>> = Vec::new();
	if rng.below(12) != 0 {
		lines.push(format!("pkgname = {}", pkgname(rng)).into_bytes());
	}
	if rng.below(12) != 0 {
		let v = full_version(rng);
		lines.push(format!("pkgver = {v}").into_bytes());
	}
	for _ in 0..rng.below(24) {
		let key = pick(rng, &PKGINFO_KEYS);
		let sep = match rng.below(16) {
			0 => "=",
			1 => " =",
			2 => "= ",
			3 => "  = ",
			4 => "\t= ",
			5 => " =\t",
			_ => " = ",
		};
		let head = match rng.below(20) {
			0 => " ",
			1 => "#",
			2 => "# ",
			_ => "",
		};
		let value = raw_value(rng, key);
		let line = [head.as_bytes(), key.as_bytes(), sep.as_bytes()];
		lines.push([&line.concat()[..], &value].concat());
	}
	for _ in 0..rng.below(3) {
		lines.push(Vec::new());
	}
	for i in (1..lines.len()).rev() {
		lines.swap(i, rng.below(i + 1));
	}
	let mut out = Vec::new();
	for mut line in lines {
		// a byte that is no ASCII, a nul, a CR
		match rng.below(30) {
			0 => line.insert(rng.below(line.len() + 1), 0),
			1 => line.insert(rng.below(line.len() + 1), 0xff),
			2 => line.insert(rng.below(line.len() + 1), 0x80),
			3 | 4 => line.push(b'\r'),
			_ => {}
		}
		out.extend_from_slice(&line);
		out.push(b'\n');
	}
	if rng.below(10) == 0 {
		out.pop();
	}
	out
}

#[test]
fn fuzz_pkginfo() {
	let fx = Fixture::new();
	let h = fx.handle();
	let path = fx.pkg("raw.pkg.tar");
	let mut rng = Rng::new(0x9a7f);
	let n = (iters() / 50).max(200);
	let mut loaded = 0;
	for _ in 0..n {
		let info = gen_raw_pkginfo(&mut rng);
		let mut entries =
			vec![file(b".PKGINFO", &info), file(b"a", b"x")];
		if rng.below(10) == 0 {
			// a second .PKGINFO reads into the same package
			let second = gen_raw_pkginfo(&mut rng);
			entries.push(file(b".PKGINFO", &second));
		}
		let comp = COMPS[rng.below(COMPS.len())];
		write_pkg(&path, comp, &entries);
		assert_same(&h, &path, &(comp, &entries));
		loaded += usize::from(load_rust(&path, false).r.is_ok());
	}
	eprintln!("fuzz_pkginfo: {n} files, {loaded} loaded");
	assert!(loaded * 4 > n, "{loaded} of {n} loaded");
}

// a pax 'x' member with these records, for the entry after it
fn pax(records: &[(&str, &[u8])]) -> Entry {
	let body: Vec<u8> = records
		.iter()
		.flat_map(|(k, v)| pax_record(k.as_bytes(), v))
		.collect();
	entry(b"pax", 0o644, Kind::Raw(b'x', body))
}

fn mtree_of(fx: &Fixture, text: &str) -> Entry {
	file(b".MTREE", &gzip(fx, text.as_bytes()))
}

const MTREE_HEAD: &str = "#mtree\n/set type=file uid=0 gid=0 mode=644\n";

// archive layouts: odd tar entries (type flags, directories and hard
// links with data), .MTREE variants, and the walk rules
#[test]
fn fixed_archive() {
	let fx = Fixture::new();
	let h = fx.handle();
	let path = fx.pkg("odd.pkg.tar");
	let info = file(b".PKGINFO", PKGINFO.as_bytes());
	let sha = "0".repeat(64);
	let f = |n: &str| format!("./{n} time=1.0 size=3 sha256digest={sha}\n");
	let cases: Vec<(&str, Vec<Entry>, [&str; 2])> = vec![
		(
			"dir with data",
			vec![
				info.clone(),
				entry(
					b"d/",
					0o755,
					Kind::Raw(b'5', b"abc".to_vec()),
				),
			],
			["same", "same"],
		),
		(
			"slash file no data",
			vec![
				info.clone(),
				entry(b"r/", 0o644, Kind::Raw(b'0', vec![])),
			],
			["same", "same"],
		),
		(
			"slash file data",
			vec![
				info.clone(),
				entry(
					b"r/",
					0o644,
					Kind::Raw(b'0', b"abc".to_vec()),
				),
			],
			["same", "same"],
		),
		(
			"type X",
			vec![
				info.clone(),
				entry(
					b"rx",
					0o644,
					Kind::Raw(b'X', b"abcd".to_vec()),
				),
				file(b"b", b"x"),
			],
			["same", "same"],
		),
		(
			"type Z",
			vec![
				info.clone(),
				entry(
					b"rz",
					0o644,
					Kind::Raw(b'Z', b"abcd".to_vec()),
				),
				file(b"b", b"x"),
			],
			["same", "same"],
		),
		(
			"type S",
			vec![
				info.clone(),
				entry(
					b"rs",
					0o644,
					Kind::Raw(b'S', b"abcd".to_vec()),
				),
				file(b"b", b"x"),
			],
			["same", "same"],
		),
		(
			"hardlink data",
			vec![
				info.clone(),
				entry(
					b"h",
					0o644,
					Kind::Raw(b'1', b"xyz".to_vec()),
				),
			],
			["same", "same"],
		),
		(
			"dot prefix",
			vec![info.clone(), file(b"./usr/x", b"a"), dir(b"./")],
			["same", "same"],
		),
		(
			"dot pkginfo",
			vec![
				file(b"./.PKGINFO", PKGINFO.as_bytes()),
				file(b"a", b"x"),
			],
			["same", "same"],
		),
		(
			"two pkginfo",
			vec![
				info.clone(),
				file(
					b".PKGINFO",
					pkginfo_with(
						&[(
							"pkgdesc",
							Some("pkgdesc = two"),
						)],
						&["group = g"],
					)
					.as_slice(),
				),
				file(b"a", b"x"),
			],
			["same", "same"],
		),
		("no pkginfo", vec![file(b"a", b"x")], ["same", "same"]),
		("empty tar", vec![], ["same", "same"]),
		(
			"mtree dup",
			vec![
				mtree_of(
					&fx,
					&format!(
						"{MTREE_HEAD}{}./a time=1.0 type=dir mode=755\n",
						f("a")
					),
				),
				info.clone(),
				file(b"a", b"abc"),
			],
			["same", "same"],
		),
		(
			"mtree no uid",
			vec![
				mtree_of(
					&fx,
					&format!(
						"#mtree\n/set type=file gid=0 mode=644\n{}",
						f("a")
					),
				),
				info.clone(),
				file(b"a", b"abc"),
			],
			["same", "same"],
		),
		(
			"mtree no sha",
			vec![
				mtree_of(
					&fx,
					&format!(
						"{MTREE_HEAD}./a time=1.0 size=3\n"
					),
				),
				info.clone(),
				file(b"a", b"abc"),
			],
			["same", "same"],
		),
		(
			"mtree no size",
			vec![
				mtree_of(
					&fx,
					&format!(
						"{MTREE_HEAD}./a time=1.0 sha256digest={sha}\n"
					),
				),
				info.clone(),
				file(b"a", b"abc"),
			],
			["same", "same"],
		),
		(
			"mtree non-utf8",
			vec![
				mtree_of(
					&fx,
					&format!("{MTREE_HEAD}{}", f("a\\377")),
				),
				info.clone(),
				file(b"a\xff", b"abc"),
			],
			["same", "same"],
		),
		(
			"mtree \\s",
			vec![
				mtree_of(
					&fx,
					&format!("{MTREE_HEAD}{}", f("a\\sb")),
				),
				info.clone(),
				file(b"a b", b"abc"),
			],
			["same", "same"],
		),
		(
			"mtree plain",
			vec![
				file(
					b".MTREE",
					format!("{MTREE_HEAD}{}", f("a"))
						.as_bytes(),
				),
				info.clone(),
				file(b"a", b"abc"),
			],
			["same", "same"],
		),
		// gzip members read one after the other, like libarchive
		(
			"mtree gzip members",
			vec![
				file(
					b".MTREE",
					&[
						gzip(
							&fx,
							MTREE_HEAD.as_bytes(),
						),
						gzip(&fx, f("a").as_bytes()),
					]
					.concat(),
				),
				info.clone(),
				file(b"a", b"abc"),
				file(b"b", b"abc"),
			],
			["same", "same"],
		),
		(
			"mtree garbage",
			vec![
				file(b".MTREE", b"\x1f\x8bnot gzip"),
				info.clone(),
				file(b"a", b"abc"),
			],
			["same", "same"],
		),
		// the C marks the scriptlet from a .MTREE it then drops for
		// the archive list (UPSTREAM.md)
		(
			"mtree install",
			vec![
				mtree_of(
					&fx,
					&format!(
						"{MTREE_HEAD}./.INSTALL time=1.0 size=3 sha256digest={sha}\nbroken line\n"
					),
				),
				info.clone(),
				file(b"a", b"abc"),
			],
			["same", "same"],
		),
		(
			"mtree char dev",
			vec![
				mtree_of(
					&fx,
					&format!(
						"{MTREE_HEAD}./c time=1.0 type=char mode=600\n{}",
						f("a")
					),
				),
				info.clone(),
				file(b"a", b"abc"),
			],
			["same", "same"],
		),
		(
			"mtree md5 only",
			vec![
				mtree_of(
					&fx,
					&format!(
						"{MTREE_HEAD}./a time=1.0 size=3 md5digest={}\n",
						"0".repeat(32)
					),
				),
				info.clone(),
				file(b"a", b"abc"),
			],
			["same", "same"],
		),
		(
			"mtree dir size",
			vec![
				mtree_of(
					&fx,
					&format!(
						"{MTREE_HEAD}./d time=1.0 type=dir mode=755 size=9\n"
					),
				),
				info.clone(),
				dir(b"d/"),
			],
			["same", "same"],
		),
		(
			"mtree link size",
			vec![
				mtree_of(
					&fx,
					&format!(
						"{MTREE_HEAD}./l time=1.0 type=link mode=777 link=a size=9\n"
					),
				),
				info.clone(),
				dir(b"d/"),
			],
			["same", "same"],
		),
		(
			"mtree mode 4",
			vec![
				mtree_of(
					&fx,
					&format!(
						"{MTREE_HEAD}./a time=1.0 mode=4755 size=3 sha256digest={sha}\n"
					),
				),
				info.clone(),
				file(b"a", b"abc"),
			],
			["same", "same"],
		),
		(
			"mtree after pkginfo",
			vec![
				info.clone(),
				mtree_of(
					&fx,
					&format!("{MTREE_HEAD}{}", f("z")),
				),
				file(b"a", b"abc"),
			],
			["same", "same"],
		),
		(
			"mtree late",
			vec![
				info.clone(),
				file(b"a", b"abc"),
				mtree_of(
					&fx,
					&format!("{MTREE_HEAD}{}", f("z")),
				),
				file(b"b", b"abc"),
			],
			["same", "same"],
		),
		// pax headers: the name and size the walk sees, a record
		// libarchive warns about
		(
			"pax path pkginfo",
			vec![
				pax(&[("path", b".PKGINFO")]),
				file(b"other", PKGINFO.as_bytes()),
				file(b"a", b"x"),
			],
			["same", "same"],
		),
		(
			"pax size",
			vec![
				info.clone(),
				pax(&[("size", b"1")]),
				file(b"a", b"abc"),
				file(b"b", b"x"),
			],
			["same", "same"],
		),
		(
			"pax malformed",
			vec![
				info.clone(),
				entry(
					b"x",
					0o644,
					Kind::Raw(b'x', b"abc\n".to_vec()),
				),
				file(b"a", b"abc"),
			],
			["same", "same"],
		),
		(
			"pax first",
			vec![
				pax(&[("mtime", b"1x")]),
				info.clone(),
				file(b"a", b"abc"),
			],
			["same", "same"],
		),
	];
	for (what, entries, want) in cases {
		write_pkg(&path, Comp::None, &entries);
		pin(&h, &path, what, want);
	}
}

// errors around the file itself and compressions alpm-compress does not
// read the way libarchive does
#[test]
fn fixed_files() {
	let fx = Fixture::new();
	let h = fx.handle();
	let path = fx.pkg("f.pkg.tar");
	let entries = [
		file(b".PKGINFO", PKGINFO.as_bytes()),
		dir(b"usr/"),
		file(b"usr/a", &[b'a'; 3000]),
		file(b"usr/b", b"b"),
	];
	let tar = ustar(&entries);

	pin(&h, &fx.pkg("missing"), "missing file", ["same"; 2]);
	pin(&h, &fx.0.join("pkg"), "directory", ["same"; 2]);
	fs::write(&path, b"").unwrap();
	pin(&h, &path, "empty file", ["same"; 2]);
	fs::write(&path, b"not an archive at all, just text\n".repeat(40))
		.unwrap();
	pin(&h, &path, "text file", ["same"; 2]);
	fs::write(&path, [0u8; 2048]).unwrap();
	pin(&h, &path, "zero blocks", ["same"; 2]);

	// truncated plain tar: libarchive seeks over the data of the file
	// the walk stopped on
	compress(&path, Comp::None, &tar[..tar.len() - 1024 - 512 - 512]);
	pin(&h, &path, "plain tar without end blocks", ["same", "same"]);

	// two gzip members: read one after the other, like libarchive
	let (a, b) = (fx.0.join("m1"), fx.0.join("m2"));
	let split = 512 * 3;
	compress(&a, Comp::Gzip, &tar[..split]);
	compress(&b, Comp::Gzip, &tar[split..]);
	fs::write(
		&path,
		[fs::read(&a).unwrap(), fs::read(&b).unwrap()].concat(),
	)
	.unwrap();
	pin(&h, &path, "two gzip members", ["same", "same"]);

	// gzip inside gzip: libarchive stacks filters, alpm-compress one
	compress(&a, Comp::Gzip, &tar);
	compress(&path, Comp::Gzip, &fs::read(&a).unwrap());
	pin(&h, &path, "gzip in gzip", ["rust open"; 2]);
}

// a package over several of libarchive's 64/128 KiB filter blocks, with
// headers at and across block boundaries and random data between them
// (see unpack's big_package)
fn big_package() -> Vec<Entry> {
	const BLOCK: usize = 64 * 1024;
	let mut rng = Rng::new(0xb16_9ac);
	let mut entries =
		vec![file(b".PKGINFO", PKGINFO.as_bytes()), dir(b"usr/")];
	let mut off: usize = 512 + PKGINFO.len().next_multiple_of(512) + 512;
	for i in 0.. {
		if off > 1300 * 1024 {
			break;
		}
		let next = (off + 512 + 20000).next_multiple_of(BLOCK);
		let len = match i % 4 {
			0 => next - off - 512,
			1 => next - off - 512 - 256,
			_ => rng.below(9000),
		};
		let data: Vec<u8> =
			(0..len).map(|_| rng.next_u64() as u8).collect();
		off += 512 + len.next_multiple_of(512);
		entries.push(file(format!("usr/f{i}").as_bytes(), &data));
	}
	entries.push(file(b".INSTALL", b"post_install() {\n\ttrue\n}\n"));
	entries
}

// a compressed package cut short, at the start, evenly spread, at random
// and in the stream's tail: libarchive fails the filter block the stream
// ends in. inside the first one the open fails (PKG_OPEN), later the
// full walk meets it in a header or data skip (LIBARCHIVE), with full off
// the walk stops before it
#[test]
fn compressed_cuts() {
	let fx = Fixture::new();
	let h = fx.handle();
	let path = fx.pkg("cut.pkg.tar");
	let tar = ustar(&big_package());
	let mut rng = Rng::new(0x0c07_5eed);
	let mut errnos = std::collections::BTreeSet::new();
	for comp in [Comp::Gzip, Comp::Bzip2, Comp::Xz, Comp::Zstd] {
		compress(&path, comp, &tar);
		let data = fs::read(&path).unwrap();
		let len = data.len();
		let mut cuts: Vec<usize> = vec![1, 2, 10, 100];
		cuts.extend((1..48).map(|i| len * i / 48));
		cuts.extend((0..16).map(|_| rng.below(len)));
		cuts.extend([1, 4, 8, 9, 12, 20, 64].map(|d| len - d));
		for n in cuts {
			fs::write(&path, &data[..n]).unwrap();
			assert_same(
				&h,
				&path,
				&format!("{comp:?} cut at {n}/{len}"),
			);
			for full in [false, true] {
				let c = load_c(&h, &path, full);
				errnos.insert((full, c.r.err()));
			}
		}
	}
	// loads, open and libarchive errors all seen
	assert!(errnos.len() >= 3, "{errnos:?}");
}

// lz4 and lzma (.tar.lz4 is a makepkg PKGEXT): libarchive reads them,
// alpm-compress has no decoder. through the system tools when present
#[test]
fn fixed_other_compressions() {
	let fx = Fixture::new();
	let h = fx.handle();
	let tarfile = fx.0.join("p.tar");
	fs::write(
		&tarfile,
		ustar(&[
			file(b".PKGINFO", PKGINFO.as_bytes()),
			file(b"a", b"x"),
		]),
	)
	.unwrap();
	let tools: [(&str, &[&str], &str); 2] = [
		("lz4", &["-q", "-c"], "p.tar.lz4"),
		("xz", &["--format=lzma", "-c"], "p.tar.lzma"),
	];
	for (tool, args, out) in tools {
		let Ok(o) = std::process::Command::new(tool)
			.args(args)
			.arg(&tarfile)
			.output()
		else {
			eprintln!("{tool} not found, skipped");
			continue;
		};
		assert!(o.status.success(), "{tool}: {}", lossy(&o.stderr));
		let path = fx.pkg(out);
		fs::write(&path, o.stdout).unwrap();
		// read as a plain tar, the first header fails
		pin(&h, &path, tool, ["rust open"; 2]);
	}
}

// _alpm_pkg_validate_internal's checksum part
#[test]
fn fixed_validate() {
	use alpm_types::Sha256Checksum;
	let fx = Fixture::new();
	let h = fx.handle();
	let path = fx.pkg("v.pkg.tar");
	write_pkg(&path, Comp::Zstd, &[file(b".PKGINFO", PKGINFO.as_bytes())]);
	let sum = Sha256Checksum::calculate_from(fs::read(&path).unwrap())
		.to_string();
	let sync = |s: Option<&str>| Package {
		sha256sum: s.map(|s| s.as_bytes().to_vec()),
		..Package::default()
	};
	let upper = sum.to_uppercase();
	let syncs = [
		None,
		Some(sync(None)),
		Some(sync(Some(&sum))),
		Some(sync(Some(&upper))),
		Some(sync(Some(&sum[1..]))),
		Some(sync(Some(""))),
	];
	let missing = fx.pkg("missing");
	let dir = fx.0.join("pkg");
	for p in [&path, &missing, &dir] {
		for s in &syncs {
			let c = h.validate(bytes(p), s.as_ref());
			let r = pkg_validate_internal(bytes(p), s.as_ref())
				.map_err(|e| e.errno() as i32);
			assert_eq!(c, r, "{} {s:?}", p.display());
		}
	}
	assert_eq!(
		h.validate(b"", None),
		pkg_validate_internal(b"", None).map_err(|e| e.errno() as i32)
	);
}

// a keyword libarchive's mtree reader reads oddly, warns about or that
// changes the entry
fn odd_keyword(rng: &mut Rng) -> String {
	let sha = "a".repeat(64);
	let v = [
		"uid=1".to_string(),
		"mode=0".into(),
		"mode=0104755".into(),
		"mode=u+x".into(),
		"size=-5".into(),
		"size=12x".into(),
		"size=9".into(),
		"type=dir".into(),
		"type=char".into(),
		"type=fifo".into(),
		"type=block".into(),
		"type=link".into(),
		"type=bogus".into(),
		"foo=1".into(),
		"foo".into(),
		"nochange".into(),
		"link=a\\sb".into(),
		format!("sha256digest={}", sha.to_uppercase()),
		format!("sha256={sha}"),
		"md5digest=abc".into(),
		"device=linux,1,2".into(),
		"device=foo,1".into(),
		"time=1.5".into(),
	];
	v[rng.below(v.len())].clone()
}

// .MTREE text over a tree: makepkg's lines, mutated, duplicated or mixed
// with /set, /unset, comments, relative paths and the odd broken line
fn gen_odd_mtree(rng: &mut Rng, tree: &[Entry]) -> Vec<u8> {
	let mut out = String::from(match rng.below(12) {
		0 => "",
		1 => "#mtree v2.0\n",
		_ => "#mtree\n",
	});
	if rng.below(4) != 0 {
		out += "/set type=file uid=0 gid=0 mode=644\n";
	}
	if rng.below(4) == 0 {
		out += "./.INSTALL time=1.0 size=1\n";
	}
	let mut lines: Vec<String> = Vec::new();
	for e in tree {
		let Some(mut l) = mtree_line(e) else {
			continue;
		};
		if rng.below(4) == 0 {
			l.pop();
			for _ in 0..1 + rng.below(2) {
				l = format!("{l} {}", odd_keyword(rng));
			}
			l.push('\n');
		}
		if rng.below(8) == 0 {
			l = l.replacen(" type=", " \\\n type=", 1);
		}
		lines.push(l);
	}
	for _ in 0..rng.below(4) {
		let extra = match rng.below(10) {
			0 => "/unset uid\n".to_string(),
			1 => "/unset all\n".into(),
			2 => "/set type=dir mode=755\n".into(),
			3 => "# comment\n".into(),
			4 => "usr type=dir\n".into(),
			5 => "..\n".into(),
			6 => "./a\\040b type=file size=3\n".into(),
			7 => "/foo\n".into(),
			8 => "./z\0 type=file\n".into(),
			_ => format!("./d type=dir {}\n", odd_keyword(rng)),
		};
		lines.insert(rng.below(lines.len() + 1), extra);
	}
	if !lines.is_empty() && rng.below(6) == 0 {
		let dup = lines[rng.below(lines.len())].clone();
		lines.push(dup);
	}
	out.extend(lines);
	if rng.below(10) == 0 {
		out = out.replace('\n', "\r\n");
	}
	out.into_bytes()
}

// packages whose .MTREE libarchive reads oddly, in every compression the
// port knows: the file list (mtree or archive fallback), the scriptlet
// and the mtree log lines compared
#[test]
fn fuzz_mtree_packages() {
	let fx = Fixture::new();
	let h = fx.handle();
	let mut rng = Rng::new(0x03a7_e9ac);
	let path = fx.pkg("mtree.pkg.tar");
	let mtree_path = fx.0.join("mtree");
	let (mut listed, mut fallback) = (0, 0);
	for _ in 0..pkg_iters() {
		let tree = gen_tree(&mut rng);
		let text = gen_odd_mtree(&mut rng, &tree);
		compress(&mtree_path, COMPS[rng.below(COMPS.len())], &text);
		let mut entries = vec![
			file(b".PKGINFO", PKGINFO.as_bytes()),
			file(b".MTREE", &fs::read(&mtree_path).unwrap()),
		];
		entries.extend(tree);
		write_pkg(&path, Comp::None, &entries);
		assert_same(&h, &path, &lossy(&text));
		let logs = load_c(&h, &path, true).logs;
		let done = |(_, m): &(c_int, Vec<u8>)| {
			m.starts_with(b"finished mtree reading")
		};
		match logs.iter().any(done) {
			true => listed += 1,
			false => fallback += 1,
		}
	}
	eprintln!(
		"fuzz_mtree_packages: {} packages, {listed} mtree lists, \
		{fallback} archive lists",
		pkg_iters()
	);
	assert!(listed * 5 > pkg_iters() && fallback * 5 > pkg_iters());
}

// a .MTREE over several filter blocks, cut short: inside the first
// block libarchive's open fails (archive list), past it the failed read
// ends the data and the list is what came before
#[test]
fn mtree_cuts() {
	let fx = Fixture::new();
	let h = fx.handle();
	let path = fx.pkg("cut.pkg.tar");
	let mtree_path = fx.0.join("mtree");
	let mut rng = Rng::new(0x3e7_c07);
	let mut text = String::from(MTREE_HEAD);
	for i in 0..6000 {
		let w = word(&mut rng, ALNUM, 0, 40);
		text += &format!(
			"./usr/{w}{i} time={i}.0 size={} sha256digest={}\n",
			rng.below(99999),
			"0".repeat(64)
		);
	}
	let mut lists = std::collections::BTreeSet::new();
	for comp in [Comp::Gzip, Comp::Bzip2, Comp::Xz, Comp::Zstd] {
		compress(&mtree_path, comp, text.as_bytes());
		let data = fs::read(&mtree_path).unwrap();
		let len = data.len();
		let mut cuts: Vec<usize> = vec![1, 2, 10, 100];
		cuts.extend((1..24).map(|i| len * i / 24));
		cuts.extend((0..6).map(|_| rng.below(len)));
		cuts.extend([1, 4, 8, 20].map(|d| len - d));
		for n in cuts {
			let entries = [
				file(b".PKGINFO", PKGINFO.as_bytes()),
				file(b".MTREE", &data[..n]),
				file(b"usr/a", b"abc"),
			];
			write_pkg(&path, Comp::None, &entries);
			assert_same(
				&h,
				&path,
				&format!("{comp:?} cut at {n}/{len}"),
			);
			if let Ok((p, _)) = load_c(&h, &path, true).r {
				lists.insert(p.files.files.len());
			}
		}
	}
	// the archive's list, partial and whole mtree lists
	assert!(lists.len() >= 3, "{lists:?}");
}
