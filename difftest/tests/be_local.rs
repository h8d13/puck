// alpm_core::be_local against be_local.c: random local databases are
// written under /tmp, loaded by the C (alpm_initialize, pkgcache, lazy
// getters) and by the port, every package field compared. valid alpm-db
// input must match exactly; pacman-accepted odd input is pinned as the
// divergence list (PORTING.md)
use std::ffi::c_int;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::Path;

use alpm_core::be_local::{
	INFRQ_DESC, INFRQ_ERROR, INFRQ_FILES, INFRQ_SCRIPTLET, LocalDb,
};
use alpm_core::package::Package;
use difftest::{CLocalDb, Loads, LocalEntry, Rng, TempRoot, c_local_db, iters};

// one db holds several packages and three files each, far heavier than a
// string case
fn db_iters() -> usize {
	(iters() / 20).max(100)
}

type Loaded = Result<CLocalDb, c_int>;

fn rust_local_db(dbpath: &[u8], loads: Loads) -> Loaded {
	let db = LocalDb::register(dbpath).map_err(|e| e.errno() as c_int)?;
	let cache = db.populate().map_err(|e| e.errno() as c_int)?;
	let counts = (cache.len(), cache.buckets(), cache.limit());
	let pkgs = cache
		.iter()
		.map(|p| {
			let mut p = p.clone();
			// errors show up as INFRQ_ERROR in infolevel
			for (on, bit) in [
				(loads.desc, INFRQ_DESC),
				(loads.files, INFRQ_FILES),
				(loads.scriptlet, INFRQ_SCRIPTLET),
			] {
				if on {
					let _ = db.read(&mut p, bit);
				}
			}
			p
		})
		.collect();
	Ok(CLocalDb { pkgs, counts })
}

// the read error of the port for this package, for assert messages
fn port_error(dbpath: &[u8], pkg: &Package) -> String {
	let db = LocalDb::register(dbpath).unwrap();
	let mut p = Package {
		infolevel: 0,
		..pkg.clone()
	};
	match db.read(&mut p, INFRQ_DESC | INFRQ_FILES) {
		Ok(()) => "none".into(),
		Err(e) => format!("{e:?}"),
	}
}

// names of the Package fields that differ
fn diff_fields(a: &Package, b: &Package) -> Vec<&'static str> {
	let mut out = Vec::new();
	macro_rules! cmp {
		($($f:ident),*) => {$(
			if a.$f != b.$f {
				out.push(stringify!($f));
			}
		)*};
	}
	cmp!(
		name_hash,
		filename,
		base,
		name,
		version,
		desc,
		url,
		packager,
		sha256sum,
		base64_sig,
		arch,
		builddate,
		installdate,
		size,
		isize,
		download_size,
		licenses,
		replaces,
		groups,
		backup,
		depends,
		optdepends,
		checkdepends,
		makedepends,
		conflicts,
		provides,
		files,
		origin,
		reason,
		scriptlet,
		xdata,
		validation
	);
	// the error bit is reported apart, the loaded bits are fields
	if a.infolevel & !INFRQ_ERROR != b.infolevel & !INFRQ_ERROR {
		out.push("infolevel");
	}
	out
}

fn s(b: &Option<Vec<u8>>) -> String {
	b.as_ref().map_or("NULL".into(), |b| {
		format!("{:?}", String::from_utf8_lossy(b))
	})
}

// both sides on the same tree, full equality
fn assert_same(sb: &TempRoot, loads: Loads, what: &dyn Fn() -> String) {
	let c = c_local_db(&sb.root(), &sb.dbpath(), loads);
	let r = rust_local_db(&sb.dbpath(), loads);
	match (&c, &r) {
		(Ok(c), Ok(r)) => {
			let names = |v: &[Package]| -> Vec<String> {
				v.iter().map(|p| {
					format!(
						"{}-{}",
						s(&p.name),
						s(&p.version)
					)
				})
				.collect()
			};
			assert_eq!(
				names(&c.pkgs),
				names(&r.pkgs),
				"{}",
				what()
			);
			assert_eq!(c.counts, r.counts, "{}", what());
			for (cp, rp) in c.pkgs.iter().zip(&r.pkgs) {
				assert!(
					cp == rp,
					"{} differs in {:?}\nport error: {}\n{}",
					s(&cp.name),
					diff_fields(cp, rp),
					port_error(&sb.dbpath(), rp),
					what()
				);
			}
		}
		(Err(c), Err(r)) => assert_eq!(c, r, "{}", what()),
		_ => panic!("C {c:?}\nrust {r:?}\n{}", what()),
	}
}

// valid alpm-db generators. they include text alpm-types normalizes or
// reads specially (pkgrel leading zeros, runs of spaces, urls without
// path or in uppercase, ".so" in names, packagers without email), which
// has to come out as the C reads it

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

fn word(rng: &mut Rng, alphabet: &[u8], min: usize, max: usize) -> String {
	let n = min + rng.below(max - min + 1);
	(0..n).map(|_| rng.pick(alphabet) as char).collect()
}

fn pick<'a>(rng: &mut Rng, v: &[&'a str]) -> &'a str {
	v[rng.below(v.len())]
}

// sometimes with ".so" inside, which alpm-types tries as a soname first
fn pkgname(rng: &mut Rng) -> String {
	let first = rng.pick(b"abcdefghijklmnopqrstuvwxyz0123456789_@+");
	let rest =
		word(rng, b"abcdefghijklmnopqrstuvwxyz0123456789@._+-", 0, 10);
	let so = if rng.below(8) == 0 { ".so" } else { "" };
	format!("{}{so}{rest}", first as char)
}

// positive integer without leading zero
fn number(rng: &mut Rng, max: u64) -> u64 {
	1 + rng.next_u64() % max
}

fn pkgver(rng: &mut Rng) -> String {
	let first = rng.pick(ALNUM) as char;
	format!("{first}{}", word(rng, b"0123456789abcxyz._+~", 0, 6))
}

// sometimes with a leading zero
fn pkgrel(rng: &mut Rng) -> String {
	let zero = if rng.below(4) == 0 { "0" } else { "" };
	match rng.below(3) {
		0 => format!("{zero}{}.{}", number(rng, 20), number(rng, 9)),
		_ => format!("{zero}{}", number(rng, 30)),
	}
}

fn epoch(rng: &mut Rng) -> String {
	match rng.below(4) {
		0 => format!("{}:", number(rng, 30)),
		_ => String::new(),
	}
}

fn full_version(rng: &mut Rng) -> String {
	format!("{}{}-{}", epoch(rng), pkgver(rng), pkgrel(rng))
}

fn relation(rng: &mut Rng) -> String {
	let name = pkgname(rng);
	if rng.below(2) == 0 {
		return name;
	}
	let op = pick(rng, &["<", "<=", "=", ">=", ">"]);
	let rel = match rng.below(2) {
		0 => format!("-{}", pkgrel(rng)),
		_ => String::new(),
	};
	format!("{name}{op}{}{}{rel}", epoch(rng), pkgver(rng))
}

// a relation or an alpm soname (v1 "name.so=ver-bits", v2 "prefix:soname")
fn relation_or_soname(rng: &mut Rng) -> String {
	match rng.below(5) {
		0 => format!(
			"lib{}.so={}-{}",
			word(rng, LOWER, 1, 6),
			number(rng, 9),
			pick(rng, &["32", "64"])
		),
		1 => format!(
			"{}:lib{}.so.{}",
			pick(rng, &["lib", "usr"]),
			word(rng, LOWER, 1, 6),
			number(rng, 9)
		),
		_ => relation(rng),
	}
}

// words, sometimes apart by runs of blanks
fn sentence(rng: &mut Rng, max_words: usize) -> String {
	let n = rng.below(max_words + 1);
	let words: Vec<String> = (0..n)
		.map(|_| word(rng, b"abcXYZ019,.()'!-/#&", 1, 8))
		.collect();
	words.join(pick(rng, &[" ", " ", "  ", " \t"]))
}

fn optdepend(rng: &mut Rng) -> String {
	let name = match rng.below(4) {
		0 => relation(rng),
		_ => pkgname(rng),
	};
	match rng.below(2) {
		0 => name,
		// libalpm keeps the description after ": " as is
		_ => format!(
			"{name}: {}{}",
			pick(rng, &["", "", " "]),
			word(rng, ALNUM, 0, 6)
		),
	}
}

fn url(rng: &mut Rng) -> String {
	match rng.below(6) {
		0 => String::new(),
		// url::Url adds a '/' path and lowercases
		1 => format!(
			"{}://{}.ORG",
			pick(rng, &["HTTPS", "http"]),
			word(rng, LOWER, 1, 8)
		),
		_ => format!(
			"{}://{}.{}/{}",
			pick(rng, &["https", "http", "ftp"]),
			word(rng, LOWER, 1, 8),
			pick(rng, &["org", "com", "io"]),
			word(rng, b"abc012/_-~", 0, 10)
		),
	}
}

// a User ID, sometimes makepkg's default or an email address only
fn packager(rng: &mut Rng) -> String {
	let email = format!(
		"<{}@{}.org>",
		word(rng, LOWER, 1, 6),
		word(rng, LOWER, 1, 6)
	);
	match rng.below(6) {
		0 => "Unknown Packager".into(),
		1 => email,
		_ => format!(
			"{} {} {email}",
			word(rng, ALNUM, 1, 6),
			word(rng, ALNUM, 1, 6)
		),
	}
}

fn md5(rng: &mut Rng) -> String {
	word(rng, b"0123456789abcdef", 32, 32)
}

// one desc file as an ordered list of sections, None for v2 xdata off
struct Desc {
	sections: Vec<(String, Vec<String>)>,
}

impl Desc {
	fn text(&self) -> String {
		let mut out = String::new();
		for (key, lines) in &self.sections {
			writeln!(out, "%{key}%").unwrap();
			for l in lines {
				writeln!(out, "{l}").unwrap();
			}
			out.push('\n');
		}
		out
	}

	fn set(&mut self, key: &str, lines: Vec<String>) {
		match self.sections.iter_mut().find(|(k, _)| k == key) {
			Some(sec) => sec.1 = lines,
			None => self.sections.push((key.into(), lines)),
		}
	}

	fn remove(&mut self, key: &str) {
		self.sections.retain(|(k, _)| k != key);
	}
}

fn list<F: FnMut(&mut Rng) -> String>(
	rng: &mut Rng,
	max: usize,
	mut f: F,
) -> Vec<String> {
	(0..rng.below(max + 1)).map(|_| f(rng)).collect()
}

fn gen_desc(rng: &mut Rng, name: &str, version: &str) -> Desc {
	let one = |v: String| vec![v];
	let mut sections = vec![
		("NAME".to_string(), one(name.into())),
		("VERSION".into(), one(version.into())),
		("BASE".into(), one(pkgname(rng))),
		("DESC".into(), one(sentence(rng, 6))),
		("URL".into(), one(url(rng))),
		(
			"ARCH".into(),
			one(pick(
				rng,
				&["x86_64", "any", "aarch64", "i686", "armv7h"],
			)
			.into()),
		),
		(
			"BUILDDATE".into(),
			one((rng.next_u64() % 4_000_000_000).to_string()),
		),
		("INSTALLDATE".into(), one((rng.next_u64() >> 1).to_string())),
		("PACKAGER".into(), one(packager(rng))),
	];
	let mut vals = vec!["none", "md5", "sha256", "pgp"];
	let n = 1 + rng.below(vals.len());
	let mut validation = Vec::new();
	for _ in 0..n {
		validation.push(vals.remove(rng.below(vals.len())).to_string());
	}
	sections.push(("VALIDATION".into(), validation));
	if rng.below(3) != 0 {
		sections.push((
			"SIZE".into(),
			one((rng.next_u64() >> rng.below(64)).to_string()),
		));
	}
	if rng.below(2) == 0 {
		sections.push((
			"REASON".into(),
			one(pick(rng, &["0", "1"]).into()),
		));
	}
	let licenses = &[
		"MIT",
		"GPL-3.0-or-later",
		"Apache-2.0 OR MIT",
		"custom:foo",
		"LicenseRef-bar",
		"BSD-3-Clause",
		"LGPL-2.1-only WITH GCC-exception-3.1",
	];
	let lists: [(&str, Vec<String>); 7] = [
		("GROUPS", list(rng, 3, pkgname)),
		("LICENSE", list(rng, 3, |r| pick(r, licenses).into())),
		("REPLACES", list(rng, 3, relation)),
		("DEPENDS", list(rng, 5, relation_or_soname)),
		("OPTDEPENDS", list(rng, 3, optdepend)),
		("CONFLICTS", list(rng, 3, relation)),
		("PROVIDES", list(rng, 3, relation_or_soname)),
	];
	for (key, vals) in lists {
		if !vals.is_empty() {
			sections.push((key.into(), vals));
		}
	}
	if rng.below(2) == 0 {
		let mut x = vec![format!(
			"pkgtype={}",
			pick(rng, &["pkg", "debug", "split", "src"])
		)];
		x.extend(list(rng, 3, |r| {
			format!(
				"{}={}",
				word(r, LOWER, 1, 6),
				word(r, ALNUM, 1, 6)
			)
		}));
		let at = rng.below(x.len());
		x.swap(0, at);
		sections.push(("XDATA".into(), x));
	}
	// section order is free in both readers
	for i in (1..sections.len()).rev() {
		sections.swap(i, rng.below(i + 1));
	}
	Desc { sections }
}

// "." and ".." are path components of their own, blank lines end a
// section for alpm-db: left to odd_inputs
fn segment(rng: &mut Rng) -> String {
	loop {
		let s = word(rng, b"abcz019._-+@ ", 1, 5);
		if s != "." && s != ".." && !s.trim().is_empty() {
			return s;
		}
	}
}

// %FILES% with every parent listed, shuffled (both sides sort), and a
// %BACKUP% of some files in alpm-db's order (Path ordering)
fn gen_files(rng: &mut Rng) -> String {
	let mut paths: Vec<String> = Vec::new();
	let mut files: Vec<String> = Vec::new();
	for _ in 0..rng.below(12) {
		let depth = rng.below(4);
		let mut prefix = String::new();
		for _ in 0..depth {
			let seg = segment(rng);
			prefix = format!("{prefix}{seg}/");
			if !paths.contains(&prefix) {
				paths.push(prefix.clone());
			}
		}
		let f = format!("{prefix}{}", segment(rng));
		if !paths.contains(&f) && !paths.contains(&format!("{f}/")) {
			paths.push(f.clone());
			files.push(f);
		}
	}
	// a file named like a listed directory collides in Path terms
	files.retain(|f| !paths.contains(&format!("{f}/")));
	paths.retain(|p| p.ends_with('/') || files.contains(p));
	if paths.is_empty() {
		return String::new();
	}
	for i in (1..paths.len()).rev() {
		paths.swap(i, rng.below(i + 1));
	}
	let mut out = String::from("%FILES%\n");
	for p in &paths {
		writeln!(out, "{p}").unwrap();
	}
	out.push('\n');
	let mut backup: Vec<&String> =
		files.iter().filter(|_| rng.below(3) == 0).collect();
	if !backup.is_empty() {
		backup.sort_by(|a, b| Path::new(a).cmp(Path::new(b)));
		out.push_str("%BACKUP%\n");
		for b in backup {
			writeln!(out, "{b}\t{}", md5(rng)).unwrap();
		}
		out.push('\n');
	}
	out
}

fn dump(entries: &[LocalEntry]) -> String {
	let text = |t: &Option<Vec<u8>>| match t {
		Some(t) => String::from_utf8_lossy(t).into_owned(),
		None => "(missing)\n".into(),
	};
	let mut out = String::new();
	for e in entries {
		writeln!(
			out,
			"== {}\n-- desc\n{}-- files\n{}",
			e.dir,
			text(&e.desc),
			text(&e.files)
		)
		.unwrap();
	}
	out
}

fn gen_entry(rng: &mut Rng) -> LocalEntry {
	let name = pkgname(rng);
	let version = full_version(rng);
	let desc = gen_desc(rng, &name, &version);
	LocalEntry {
		dir: format!("{name}-{version}"),
		// missing files fail on both sides
		desc: (rng.below(40) != 0).then(|| desc.text().into_bytes()),
		files: (rng.below(40) != 0)
			.then(|| gen_files(rng).into_bytes()),
		install: rng.below(3) == 0,
	}
}

fn random_loads(rng: &mut Rng) -> Loads {
	match rng.below(4) {
		0 => Loads {
			desc: rng.below(2) == 0,
			files: rng.below(2) == 0,
			scriptlet: rng.below(2) == 0,
		},
		_ => Loads::ALL,
	}
}

#[test]
fn fixed_layout() {
	let sb = TempRoot::new("be-local-fixed");
	sb.reset_local();
	let mut rng = Rng::new(7);
	let mut entries = Vec::new();
	for dir in ["dup-1-1", "dup-2-1", "a-b-c-1-1", "x-1:2.0-3"] {
		let (name, ver) = alpm_core::util::splitname(dir.as_bytes())
			.map(|(n, v)| {
				(
					String::from_utf8(n.to_vec()).unwrap(),
					String::from_utf8(v.to_vec()).unwrap(),
				)
			})
			.unwrap();
		entries.push(LocalEntry {
			dir: dir.into(),
			desc: Some(gen_desc(&mut rng, &name, &ver)
				.text()
				.into_bytes()),
			files: Some(gen_files(&mut rng).into_bytes()),
			install: false,
		});
	}
	sb.write_local(&entries);
	let local = sb.local();
	// not directories, or names splitname rejects
	fs::write(local.join("file-1-1"), "").unwrap();
	for bad in ["nodash", "one-dash", "-1-1", "trailing-1-"] {
		fs::create_dir(local.join(bad)).unwrap();
	}
	// d_type DT_LNK: skipped like a file
	symlink(local.join("x-1:2.0-3"), local.join("link-1-1")).unwrap();
	// no desc, no files
	fs::create_dir(local.join("empty-1-1")).unwrap();
	assert_same(&sb, Loads::ALL, &|| dump(&entries));
	for (desc, files, scriptlet) in [
		(false, true, false),
		(false, false, true),
		(true, false, false),
		(false, false, false),
	] {
		let loads = Loads {
			desc,
			files,
			scriptlet,
		};
		assert_same(&sb, loads, &|| dump(&entries));
	}
}

#[test]
fn fuzz_valid() {
	let sb = TempRoot::new("be-local-valid");
	let mut rng = Rng::new(0x10ca1);
	let mut compared = 0;
	for _ in 0..db_iters() {
		sb.reset_local();
		let n = rng.below(9);
		let mut entries: Vec<LocalEntry> = Vec::new();
		for _ in 0..n {
			let mut e = gen_entry(&mut rng);
			// same name, other version: a duplicate entry
			if !entries.is_empty() && rng.below(8) == 0 {
				let prev = &entries[rng.below(entries.len())];
				let (name, _) = alpm_core::util::splitname(
					prev.dir.as_bytes(),
				)
				.unwrap();
				let name = String::from_utf8(name.to_vec())
					.unwrap();
				let version = full_version(&mut rng);
				e.dir = format!("{name}-{version}");
				e.desc = Some(gen_desc(
					&mut rng, &name, &version,
				)
				.text()
				.into_bytes());
			}
			if entries.iter().any(|x| x.dir == e.dir) {
				continue;
			}
			entries.push(e);
		}
		sb.write_local(&entries);
		let loads = random_loads(&mut rng);
		assert_same(&sb, loads, &|| dump(&entries));
		compared += entries.len();
	}
	assert!(compared > db_iters(), "only {compared} packages");
}

// a fresh db per version file content: validate and the files it leaves
#[test]
fn validate_version_file() {
	let mut cases: Vec<Option<Vec<u8>>> = [
		"9\n",
		"9",
		" \n\t9abc",
		"+9",
		"09",
		"8\n",
		"",
		"abc",
		"-",
		"-0",
		"18446744073709551625",
		"99999999999999999999999",
		"-18446744073709551607",
		"9.0",
		"0x9",
		"\x0b9",
	]
	.iter()
	.map(|s| Some(s.as_bytes().to_vec()))
	.collect();
	// no version file at all
	cases.push(None);
	let mut rng = Rng::new(99);
	for _ in 0..(iters() / 1000).max(200) {
		cases.push(Some(rng.bytes(b" \t\n+-0189x", 6)));
	}
	for (i, case) in cases.iter().enumerate() {
		for with_pkg in [false, true] {
			let (c, r) = (
				TempRoot::new("be-local-ver-c"),
				TempRoot::new("be-local-ver-r"),
			);
			for sb in [&c, &r] {
				fs::create_dir(sb.local()).unwrap();
				if let Some(v) = case {
					fs::write(
						sb.local().join(
							"ALPM_DB_VERSION",
						),
						v,
					)
					.unwrap();
				}
				if with_pkg {
					fs::create_dir(
						sb.local().join("p-1-1"),
					)
					.unwrap();
				}
			}
			let cr = c_local_db(&c.root(), &c.dbpath(), Loads::ALL);
			let rr = rust_local_db(&r.dbpath(), Loads::ALL);
			let what = format!("case {i} {case:?} pkg {with_pkg}");
			assert_eq!(
				cr.as_ref().err(),
				rr.as_ref().err(),
				"{what}"
			);
			assert_eq!(
				listing(&c.local()),
				listing(&r.local()),
				"{what}"
			);
		}
	}
}

fn listing(dir: &Path) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
	let mut v: Vec<_> = fs::read_dir(dir)
		.unwrap()
		.map(|e| {
			let e = e.unwrap();
			let name = e.file_name().as_bytes().to_vec();
			(name, fs::read(e.path()).ok())
		})
		.collect();
	v.sort();
	v
}

#[test]
fn validate_layouts() {
	// local/ missing: created with a version file
	let (c, r) = (
		TempRoot::new("be-local-lay-c"),
		TempRoot::new("be-local-lay-r"),
	);
	let cr = c_local_db(&c.root(), &c.dbpath(), Loads::ALL);
	let rr = rust_local_db(&r.dbpath(), Loads::ALL);
	assert_eq!(cr.as_ref().err(), rr.as_ref().err());
	assert!(rr.is_ok());
	assert_eq!(listing(&c.local()), listing(&r.local()));
	// local/ a regular file: opendir fails with ENOTDIR
	let (c, r) = (
		TempRoot::new("be-local-lay-c"),
		TempRoot::new("be-local-lay-r"),
	);
	for sb in [&c, &r] {
		fs::write(sb.local(), "").unwrap();
	}
	let cr = c_local_db(&c.root(), &c.dbpath(), Loads::ALL);
	let rr = rust_local_db(&r.dbpath(), Loads::ALL);
	assert!(cr.is_err());
	assert_eq!(cr.err(), rr.err());
	// version file is a directory: fopen works, fscanf fails
	let (c, r) = (
		TempRoot::new("be-local-lay-c"),
		TempRoot::new("be-local-lay-r"),
	);
	for sb in [&c, &r] {
		fs::create_dir_all(sb.local().join("ALPM_DB_VERSION")).unwrap();
	}
	let cr = c_local_db(&c.root(), &c.dbpath(), Loads::ALL);
	let rr = rust_local_db(&r.dbpath(), Loads::ALL);
	assert!(cr.is_err());
	assert_eq!(cr.err(), rr.err());
}

// pacman-accepted input outside the alpm-db formats, one package each.
// expected: the fields that differ, "" when both agree. ERR marks a port
// read error (alpm-db rejects the file)
const BASE_DESC: &str = "%NAME%\nfoo\n\n%VERSION%\n1.0-1\n\n%BASE%\nfoo\n\n\
	%DESC%\nA package\n\n%URL%\nhttps://example.org/\n\n%ARCH%\nx86_64\n\n\
	%BUILDDATE%\n1700000000\n\n%INSTALLDATE%\n1700000001\n\n\
	%PACKAGER%\nA B <a@b.org>\n\n%SIZE%\n42\n\n%VALIDATION%\npgp\n\n\
	%DEPENDS%\nbar>=1.0\n\n";
const BASE_FILES: &str = "%FILES%\netc/\netc/foo.conf\nusr/\nusr/bin/\n\
	usr/bin/foo\n\n%BACKUP%\netc/foo.conf\td41d8cd98f00b204e9800998ecf8427e\n\n";

fn desc_with(f: impl Fn(&mut Desc)) -> String {
	let mut d = Desc {
		sections: Vec::new(),
	};
	for block in BASE_DESC.trim_end().split("\n\n") {
		let mut lines = block.lines();
		let key = lines.next().unwrap().trim_matches('%').to_string();
		d.sections.push((key, lines.map(String::from).collect()));
	}
	f(&mut d);
	d.text()
}

fn one(v: &str) -> Vec<String> {
	vec![v.to_string()]
}

#[allow(clippy::type_complexity)]
fn odd_cases() -> Vec<(&'static str, Vec<u8>, Vec<u8>, &'static str)> {
	let long = "x".repeat(1500);
	let desc = |f: &dyn Fn(&mut Desc)| desc_with(f).into_bytes();
	let base_f = BASE_FILES.as_bytes().to_vec();
	let base_d = BASE_DESC.as_bytes().to_vec();
	let files = |s: &str| s.as_bytes().to_vec();
	vec![
		(
			"desc crlf",
			BASE_DESC.replace('\n', "\r\n").into_bytes(),
			base_f.clone(),
			"ERR",
		),
		(
			"desc line > 1023",
			desc(&|d| d.set("DESC", one(&long))),
			base_f.clone(),
			"desc",
		),
		(
			"unknown key",
			desc(&|d| d.set("FOO", one("bar"))),
			base_f.clone(),
			"ERR",
		),
		(
			"reason 2",
			desc(&|d| d.set("REASON", one("2"))),
			base_f.clone(),
			"ERR",
		),
		(
			"reason abc",
			desc(&|d| d.set("REASON", one("abc"))),
			base_f.clone(),
			"ERR",
		),
		(
			"no validation",
			desc(&|d| d.remove("VALIDATION")),
			base_f.clone(),
			"ERR",
		),
		(
			"no base",
			desc(&|d| d.remove("BASE")),
			base_f.clone(),
			"ERR",
		),
		("no url", desc(&|d| d.remove("URL")), base_f.clone(), "ERR"),
		(
			"no packager",
			desc(&|d| d.remove("PACKAGER")),
			base_f.clone(),
			"ERR",
		),
		(
			"no builddate",
			desc(&|d| d.remove("BUILDDATE")),
			base_f.clone(),
			"ERR",
		),
		(
			"no arch",
			desc(&|d| d.remove("ARCH")),
			base_f.clone(),
			"ERR",
		),
		(
			"empty url",
			desc(&|d| d.set("URL", one(""))),
			base_f.clone(),
			"",
		),
		(
			"desc spaces",
			desc(&|d| d.set("DESC", one(" a  b\tc "))),
			base_f.clone(),
			"",
		),
		(
			"desc empty",
			desc(&|d| d.set("DESC", one(""))),
			base_f.clone(),
			"",
		),
		(
			"desc not utf-8",
			{
				let mut v = desc(&|d| d.set("DESC", one("@")));
				let at =
					v.iter().position(|&c| c == b'@')
						.unwrap();
				v[at] = 0xff;
				v
			},
			base_f.clone(),
			"ERR",
		),
		(
			"makedepends",
			desc(&|d| d.set("MAKEDEPENDS", one("gcc"))),
			base_f.clone(),
			"ERR",
		),
		(
			"checkdepends",
			desc(&|d| d.set("CHECKDEPENDS", one("chk"))),
			base_f.clone(),
			"ERR",
		),
		(
			"groups twice",
			{
				let mut s = desc_with(|d| {
					d.set("GROUPS", one("g1"))
				});
				s.push_str("%GROUPS%\ng2\n\n");
				s.into_bytes()
			},
			base_f.clone(),
			"ERR",
		),
		(
			"xdata no pkgtype",
			desc(&|d| d.set("XDATA", one("a=b"))),
			base_f.clone(),
			"ERR",
		),
		(
			"xdata spaces",
			desc(&|d| {
				d.set(
					"XDATA",
					vec![
						"pkgtype=pkg".into(),
						"a = b".into(),
					],
				)
			}),
			base_f.clone(),
			"xdata",
		),
		(
			"xdata empty value",
			desc(&|d| {
				d.set(
					"XDATA",
					vec!["pkgtype=pkg".into(), "a=".into()],
				)
			}),
			base_f.clone(),
			"",
		),
		(
			"xdata empty value mid",
			desc(&|d| {
				d.set(
					"XDATA",
					vec![
						"pkgtype=pkg".into(),
						"a=".into(),
						"b=c".into(),
					],
				)
			}),
			base_f.clone(),
			"",
		),
		(
			"xdata no =",
			desc(&|d| {
				d.set(
					"XDATA",
					vec!["pkgtype=pkg".into(), "a".into()],
				)
			}),
			base_f.clone(),
			"ERR,CERR",
		),
		(
			"size +5",
			desc(&|d| d.set("SIZE", one("+5"))),
			base_f.clone(),
			"isize",
		),
		(
			"size -1",
			desc(&|d| d.set("SIZE", one("-1"))),
			base_f.clone(),
			"ERR",
		),
		(
			"size huge",
			desc(&|d| d.set("SIZE", one("18446744073709551615"))),
			base_f.clone(),
			"",
		),
		(
			"builddate text",
			desc(&|d| d.set("BUILDDATE", one("x1"))),
			base_f.clone(),
			"ERR",
		),
		(
			"validation foo",
			desc(&|d| d.set("VALIDATION", one("foo"))),
			base_f.clone(),
			"ERR",
		),
		(
			"validation md5",
			desc(&|d| d.set("VALIDATION", one("md5"))),
			base_f.clone(),
			"",
		),
		(
			"unknown packager",
			desc(&|d| d.set("PACKAGER", one("Unknown Packager"))),
			base_f.clone(),
			"",
		),
		(
			"url normalized",
			desc(&|d| d.set("URL", one("HTTPS://Example.ORG"))),
			base_f.clone(),
			"",
		),
		(
			"url dot segment",
			desc(&|d| d.set("URL", one("https://a.org/x/./y"))),
			base_f.clone(),
			"",
		),
		(
			"url invalid",
			desc(&|d| d.set("URL", one("not a url"))),
			base_f.clone(),
			"ERR",
		),
		(
			"license lowercase or",
			desc(&|d| d.set("LICENSE", one("MIT or Apache-2.0"))),
			base_f.clone(),
			"",
		),
		(
			"license deprecated",
			desc(&|d| d.set("LICENSE", one("GPL-2.0+"))),
			base_f.clone(),
			"",
		),
		(
			"dep trailing space",
			desc(&|d| d.set("DEPENDS", one("bar>=1.0 "))),
			base_f.clone(),
			"ERR",
		),
		(
			"dep two ops",
			desc(&|d| d.set("DEPENDS", one("a<1>2"))),
			base_f.clone(),
			"ERR",
		),
		(
			"dep empty version",
			desc(&|d| d.set("DEPENDS", one("a>="))),
			base_f.clone(),
			"ERR",
		),
		(
			"dep name with .so",
			desc(&|d| d.set("DEPENDS", one("d1.so62r"))),
			base_f.clone(),
			"",
		),
		(
			"dep with desc",
			desc(&|d| d.set("DEPENDS", one("a: x"))),
			base_f.clone(),
			"ERR",
		),
		(
			"optdep no space",
			desc(&|d| d.set("OPTDEPENDS", one("a:desc"))),
			base_f.clone(),
			"ERR",
		),
		(
			"optdep spaces",
			desc(&|d| d.set("OPTDEPENDS", one("a:  two  words "))),
			base_f.clone(),
			"",
		),
		(
			"arch upper",
			desc(&|d| d.set("ARCH", one("X86_64"))),
			base_f.clone(),
			"",
		),
		(
			"arch ANY",
			desc(&|d| d.set("ARCH", one("ANY"))),
			base_f.clone(),
			"arch",
		),
		(
			"name mismatch",
			desc(&|d| d.set("NAME", one("other"))),
			base_f.clone(),
			"",
		),
		(
			"version no pkgrel",
			desc(&|d| d.set("VERSION", one("1.0"))),
			base_f.clone(),
			"ERR",
		),
		(
			"desc mentions %XDATA%",
			desc(&|d| d.set("DESC", one("see %XDATA%"))),
			base_f.clone(),
			"ERR",
		),
		("empty desc file", Vec::new(), base_f.clone(), "ERR"),
		(
			"header leading space",
			{
				BASE_DESC
					.replace("%ARCH%", " %ARCH%")
					.into_bytes()
			},
			base_f.clone(),
			"arch",
		),
		(
			"no final newline",
			base_d.trim_ascii_end().to_vec(),
			base_f.clone(),
			"",
		),
		(
			"nul in desc",
			desc(&|d| d.set("DESC", one("a\0b"))),
			base_f.clone(),
			"desc",
		),
		(
			"files crlf",
			base_d.clone(),
			BASE_FILES.replace('\n', "\r\n").into_bytes(),
			"backup,files",
		),
		(
			"backup (null)",
			base_d.clone(),
			files(&BASE_FILES.replace(
				"d41d8cd98f00b204e9800998ecf8427e",
				"(null)",
			)),
			"backup",
		),
		(
			"backup no tab",
			base_d.clone(),
			files(&BASE_FILES.replace(
				"\td41d8cd98f00b204e9800998ecf8427e",
				"",
			)),
			"ERR",
		),
		(
			"backup not in files",
			base_d.clone(),
			files(&BASE_FILES.replace(
				"etc/foo.conf\td41",
				"etc/bar.conf\td41",
			)),
			"ERR",
		),
		(
			"backup unsorted",
			base_d.clone(),
			files(&BASE_FILES.replace(
				"%BACKUP%\n",
				"%BACKUP%\nusr/bin/foo\t00000000000000000000000000000000\n",
			)),
			"backup",
		),
		(
			"backup md5 upper",
			base_d.clone(),
			files(&BASE_FILES.replace(
				"d41d8cd98f00b204e9800998ecf8427e",
				"D41D8CD98F00B204E9800998ECF8427E",
			)),
			"backup",
		),
		(
			"backup md5 short",
			base_d.clone(),
			files(&BASE_FILES.replace(
				"d41d8cd98f00b204e9800998ecf8427e",
				"abc",
			)),
			"ERR",
		),
		(
			"backup only",
			base_d.clone(),
			files("%BACKUP%\netc/foo.conf\tabc\n\n"),
			"ERR",
		),
		(
			"files blank line inside",
			base_d.clone(),
			files("%FILES%\nusr/\n\nusr/bin/\n\n"),
			"ERR",
		),
		(
			"files absolute",
			base_d.clone(),
			files("%FILES%\n/etc/\n/etc/x\n\n"),
			"ERR",
		),
		(
			"files no parent",
			base_d.clone(),
			files("%FILES%\nusr/bin/foo\n\n"),
			"ERR",
		),
		(
			"files duplicate",
			base_d.clone(),
			files("%FILES%\nusr/\nusr/\n\n"),
			"ERR",
		),
		(
			"files dir and file",
			base_d.clone(),
			files("%FILES%\nusr\nusr/\n\n"),
			"ERR",
		),
		(
			"files dot segment",
			base_d.clone(),
			files("%FILES%\nusr/\nusr/./\n\n"),
			"ERR",
		),
		(
			"files blank path",
			base_d.clone(),
			files("%FILES%\nusr/\n \nusr/bin/\n\n"),
			"ERR",
		),
		(
			"files long path",
			base_d.clone(),
			files(&format!("%FILES%\n{long}\n\n")),
			"files",
		),
		(
			"files not utf-8",
			base_d.clone(),
			b"%FILES%\nusr/\nusr/\xff\n\n".to_vec(),
			"ERR",
		),
		(
			"files unknown section",
			base_d.clone(),
			files(&format!("{BASE_FILES}%FOO%\nbar\n\n")),
			"ERR",
		),
		(
			"files leading blank",
			base_d.clone(),
			files(&format!("\n{BASE_FILES}")),
			"ERR",
		),
		(
			"files sorted by strcmp",
			base_d.clone(),
			files(
				"%FILES%\nusr/\nusr/lib-x\nusr/lib/\nusr/lib/a\n\n",
			),
			"",
		),
	]
}

#[test]
fn odd_inputs() {
	let sb = TempRoot::new("be-local-odd");
	let mut report = String::new();
	let mut wrong = Vec::new();
	for (label, desc, files, expect) in odd_cases() {
		sb.reset_local();
		sb.write_local(&[LocalEntry {
			dir: "foo-1.0-1".into(),
			desc: Some(desc),
			files: Some(files),
			install: false,
		}]);
		// desc and files independently: a desc error hides files
		let mut got = Vec::new();
		for loads in [
			Loads {
				desc: true,
				files: false,
				scriptlet: false,
			},
			Loads {
				desc: false,
				files: true,
				scriptlet: false,
			},
		] {
			let c = c_local_db(&sb.root(), &sb.dbpath(), loads)
				.unwrap();
			let r = rust_local_db(&sb.dbpath(), loads).unwrap();
			let (c, r) = (&c.pkgs[0], &r.pkgs[0]);
			// a port error leaves the section empty, every field
			// the C read differs then
			match r.infolevel & INFRQ_ERROR != 0 {
				true => got.push("ERR"),
				false => got.extend(diff_fields(c, r)),
			}
			if c.infolevel & INFRQ_ERROR != 0 {
				got.push("CERR");
			}
		}
		let got = got.join(",");
		writeln!(report, "{label:28} {got}").unwrap();
		if got != expect {
			wrong.push(format!(
				"{label}: expected {expect:?} got {got:?}"
			));
		}
	}
	eprintln!("{report}");
	assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

// the real local db, strictly read only: alpm_initialize only reads
// ALPM_DB_VERSION when it exists, no transaction or lock is taken.
// mismatches are counted per field and classified, not asserted
#[test]
fn system_local_db() {
	let dbpath = b"/var/lib/pacman/";
	if !Path::new("/var/lib/pacman/local/ALPM_DB_VERSION").exists() {
		eprintln!("no /var/lib/pacman/local, skipped");
		return;
	}
	let c = c_local_db(b"/", dbpath, Loads::ALL).unwrap();
	let r = rust_local_db(dbpath, Loads::ALL).unwrap();
	assert_eq!(c.counts, r.counts);
	assert_eq!(c.pkgs.len(), r.pkgs.len());
	let mut by_field: Vec<(&str, usize, String)> = Vec::new();
	let (mut mismatched, mut errs) = (0, 0);
	// url: only a '/' appended; backup: only reordered, or "(null)"
	// entries dropped (then sorted)
	let (mut url_slash, mut bk_order, mut bk_null) = (0, 0, 0);
	for (cp, rp) in c.pkgs.iter().zip(&r.pkgs) {
		assert_eq!(cp.name, rp.name);
		assert_eq!(cp.version, rp.version);
		let d = diff_fields(cp, rp);
		mismatched += usize::from(!d.is_empty());
		if rp.infolevel & INFRQ_ERROR != 0 {
			errs += 1;
			let e = port_error(dbpath, rp);
			eprintln!("port error {}: {e}", s(&rp.name));
			continue;
		}
		let slash = |u: &Option<Vec<u8>>| {
			u.as_ref().map(|u| [&u[..], b"/"].concat())
		};
		if cp.url != rp.url && slash(&cp.url) == rp.url {
			url_slash += 1;
		}
		let mut sorted = cp.backup.clone();
		sorted.sort_by(|a, b| a.name.cmp(&b.name));
		let null = Some(b"(null)".to_vec());
		if cp.backup != rp.backup && sorted == rp.backup {
			bk_order += 1;
		} else if cp.backup != rp.backup {
			sorted.retain(|b| b.hash != null);
			bk_null += usize::from(sorted == rp.backup);
		}
		for f in d {
			match by_field.iter_mut().find(|x| x.0 == f) {
				Some(x) => x.1 += 1,
				None => by_field.push((f, 1, s(&cp.name))),
			}
		}
	}
	eprintln!(
		"/var/lib/pacman: {} packages, {mismatched} with mismatches, \
		{errs} port read errors",
		c.pkgs.len()
	);
	for (f, n, first) in &by_field {
		eprintln!("  {f:12} {n:5} (first: {first})");
	}
	eprintln!(
		"  url only '/' appended: {url_slash}, backup only reordered: \
		{bk_order}, backup \"(null)\" dropped: {bk_null}"
	);
	// alpm-types keeps the url as read (vendor/patches)
	assert_eq!(url_slash, 0);
}
