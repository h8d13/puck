// alpm_core::be_local against be_local.c: random local databases are
// written under the temp dir, loaded by the C (alpm_initialize, pkgcache,
// lazy getters) and by the port; every package field, the cache order and
// counts and every log line compared. desc/files are generated as bytes:
// any subset of sections in any order, unknown and repeated keys, blank
// lines, CRLF, nul bytes, non-UTF-8, lines over the C's 1023 byte pieces,
// odd relations and values, files without a final blank line or newline
use std::cell::RefCell;
use std::ffi::c_int;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::Path;

use alpm_core::be_local::{INFRQ_DESC, INFRQ_FILES, INFRQ_SCRIPTLET, LocalDb};
use alpm_core::callbacks::{Callbacks, LogLevel};
use alpm_core::package::Package;
use difftest::{CLocalDb, Loads, LocalEntry, Rng, TempRoot, c_local_db, iters};

// one db holds several packages and three files each, far heavier than a
// string case
fn db_iters() -> usize {
	(iters() / 20).max(100)
}

type Logs = Vec<(c_int, Vec<u8>)>;
type Loaded = (Result<CLocalDb, c_int>, Logs);

// the port's log lines
struct Rec(RefCell<Logs>);

impl Callbacks for &Rec {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		self.0.borrow_mut().push((level as c_int, msg.to_vec()));
	}
}

// db.c's lines around the populate, the port calls be_local directly
fn modelled(line: &(c_int, Vec<u8>)) -> bool {
	const NOT: [&[u8]; 4] = [
		b"loading package cache for repository",
		b"failed to load package cache for repository",
		b"returning error ",
		b"got error ",
	];
	!NOT.iter().any(|p| line.1.starts_with(p))
}

fn rust_local_db(dbpath: &[u8], loads: Loads) -> Loaded {
	let rec = Rec(RefCell::new(Vec::new()));
	let r = (|| {
		let db = LocalDb::register(dbpath)
			.map_err(|e| e.errno() as c_int)?;
		let cache = db
			.populate(&mut &rec)
			.map_err(|e| e.errno() as c_int)?;
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
						let _ = db.read(
							&mut p, bit, &mut &rec,
						);
					}
				}
				p
			})
			.collect();
		Ok(CLocalDb { pkgs, counts })
	})();
	(r, rec.0.into_inner())
}

fn c_side(root: &[u8], dbpath: &[u8], loads: Loads) -> Loaded {
	let (r, logs) = c_local_db(root, dbpath, loads);
	(r, logs.into_iter().filter(modelled).collect())
}

// the read error of the port for this package, for assert messages
fn port_error(dbpath: &[u8], pkg: &Package) -> String {
	let db = LocalDb::register(dbpath).unwrap();
	let mut p = Package {
		infolevel: 0,
		..pkg.clone()
	};
	match db.read(&mut p, INFRQ_DESC | INFRQ_FILES, &mut ()) {
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
		validation,
		infolevel
	);
	out
}

fn s(b: &Option<Box<[u8]>>) -> String {
	b.as_ref().map_or("NULL".into(), |b| {
		format!("{:?}", String::from_utf8_lossy(b))
	})
}

fn lines(l: &Logs) -> Vec<(c_int, String)> {
	l.iter().map(|(lv, m)| (*lv, String::from_utf8_lossy(m).into()))
		.collect()
}

// both sides on the same tree, full equality: the packages compared
fn assert_same(
	sb: &TempRoot,
	loads: Loads,
	what: &dyn Fn() -> String,
) -> usize {
	let (c, clog) = c_side(&sb.root(), &sb.dbpath(), loads);
	let (r, rlog) = rust_local_db(&sb.dbpath(), loads);
	let n = match (&c, &r) {
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
			c.pkgs.len()
		}
		(Err(c), Err(r)) => {
			assert_eq!(c, r, "{}", what());
			0
		}
		_ => panic!("C {c:?}\nrust {r:?}\n{}", what()),
	};
	assert_eq!(lines(&clog), lines(&rlog), "log lines\n{}", what());
	n
}

// byte generators. text values mix in the bytes the reader special-cases
// ('\n' ends a line, '\r' stays, a nul ends the C string, '%' starts keys)
// and non-UTF-8; long ones cross the 1023 byte pieces of safe_fgets
const TEXT: &[u8] = b"abcxyz019 \t%:=<>-./_\r\0\xff\xc3\xa9";
const NAME: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789@._+-";
const DIGIT: &[u8] = b"0123456789";

fn word(rng: &mut Rng, alphabet: &[u8], min: usize, max: usize) -> Vec<u8> {
	let n = min + rng.below(max - min + 1);
	(0..n).map(|_| rng.pick(alphabet)).collect()
}

fn pick<'a>(rng: &mut Rng, v: &[&'a [u8]]) -> &'a [u8] {
	v[rng.below(v.len())]
}

// a value line: mostly plain, sometimes odd bytes, sometimes long
fn text(rng: &mut Rng) -> Vec<u8> {
	match rng.below(12) {
		0 => word(rng, TEXT, 1000, 2200),
		1 => {
			// around the piece edge: 1022..=1024 bytes before '\n'
			let n = 1022 + rng.below(3);
			word(rng, b"ab", n, n)
		}
		2..5 => word(rng, TEXT, 0, 12),
		_ => word(rng, NAME, 1, 12),
	}
}

fn number(rng: &mut Rng) -> Vec<u8> {
	match rng.below(10) {
		0 => pick(
			rng,
			&[b"", b"-1", b"+5", b" 7", b"7 ", b"x1", b"0x10"],
		)
		.to_vec(),
		1 => pick(
			rng,
			&[
				b"18446744073709551615",
				b"18446744073709551616",
				b"9223372036854775807",
				b"9223372036854775808",
				b"-9223372036854775808",
				b"99999999999999999999999",
			],
		)
		.to_vec(),
		_ => word(rng, DIGIT, 1, 10),
	}
}

fn version(rng: &mut Rng) -> Vec<u8> {
	let mut v = word(rng, DIGIT, 1, 3);
	if rng.below(3) == 0 {
		v.extend(b".");
		v.extend(word(rng, DIGIT, 1, 2));
	}
	if rng.below(4) == 0 {
		v.splice(0..0, b"1:".iter().copied());
	}
	v.extend(b"-");
	v.extend(word(rng, DIGIT, 1, 2));
	v
}

// what alpm_dep_from_string takes apart: operators, versions, ": " and
// ':' descriptions, sonames, empty and spaced parts
fn relation(rng: &mut Rng) -> Vec<u8> {
	let mut r = word(rng, NAME, 0, 8);
	if rng.below(2) == 0 {
		r.extend(pick(
			rng,
			&[b"=", b">=", b"<=", b">", b"<", b"<>", b"=="],
		));
		if rng.below(5) != 0 {
			r.extend(version(rng));
		}
	}
	match rng.below(6) {
		0 => {
			r.extend(pick(rng, &[b": ", b":", b":  ", b": : "]));
			r.extend(word(rng, TEXT, 0, 10));
		}
		1 => r.extend(pick(rng, &[b" ", b"\r", b".so", b".so=1-64"])),
		_ => {}
	}
	r
}

const SINGLE: [&str; 9] = [
	"BASE",
	"DESC",
	"URL",
	"ARCH",
	"PACKAGER",
	"BUILDDATE",
	"INSTALLDATE",
	"SIZE",
	"REASON",
];
const LISTS: [&str; 4] = ["GROUPS", "LICENSE", "VALIDATION", "XDATA"];
const RELATIONS: [&str; 7] = [
	"REPLACES",
	"DEPENDS",
	"OPTDEPENDS",
	"MAKEDEPENDS",
	"CHECKDEPENDS",
	"CONFLICTS",
	"PROVIDES",
];

// the value lines of a section
fn values(rng: &mut Rng, key: &str, name: &[u8], ver: &[u8]) -> Vec<Vec<u8>> {
	let n = match rng.below(10) {
		0 => 0,
		1 => 2 + rng.below(3),
		_ => 1,
	};
	let one = |rng: &mut Rng| -> Vec<u8> {
		match key {
			"NAME" if rng.below(4) != 0 => name.to_vec(),
			"VERSION" if rng.below(4) != 0 => ver.to_vec(),
			"BUILDDATE" | "INSTALLDATE" | "SIZE" => number(rng),
			"REASON" => pick(
				rng,
				&[b"0", b"1", b"2", b"abc", b"", b" 1", b"01"],
			)
			.to_vec(),
			"VALIDATION" => pick(
				rng,
				&[
					b"none", b"sha256", b"pgp", b"md5",
					b"foo", b"PGP",
				],
			)
			.to_vec(),
			"XDATA" => match rng.below(6) {
				0 => word(rng, TEXT, 0, 6),
				_ => [
					word(rng, NAME, 0, 6),
					b"=".to_vec(),
					word(rng, TEXT, 0, 8),
				]
				.concat(),
			},
			k if RELATIONS.contains(&k) => relation(rng),
			_ => text(rng),
		}
	};
	let lists = LISTS.contains(&key) || RELATIONS.contains(&key);
	let n = if lists { rng.below(4) } else { n };
	(0..n).map(|_| one(rng)).collect()
}

// a header the C does not know: case, blanks, CR, stray '%'
fn unknown_key(rng: &mut Rng) -> Vec<u8> {
	pick(
		rng,
		&[
			b"%FOO%",
			b"%name%",
			b"%NAME% ",
			b" %DESC%",
			b"%DESC%\r",
			b"NAME",
			b"%%",
			b"%",
			b"%FILES%",
			b"%BACKUP%",
		],
	)
	.to_vec()
}

// one desc file: random sections in random order, each ending in a blank
// line or not, some repeated, extra blank lines, then whole-file changes
fn gen_desc(rng: &mut Rng, name: &[u8], ver: &[u8]) -> Vec<u8> {
	let mut keys: Vec<String> = ["NAME", "VERSION"]
		.iter()
		.chain(&SINGLE)
		.chain(&LISTS)
		.chain(&RELATIONS)
		.filter(|_| rng.below(3) != 0)
		.map(|k| format!("%{k}%"))
		.collect();
	for _ in 0..rng.below(3) {
		keys.push(String::from_utf8_lossy(&unknown_key(rng)).into());
	}
	// a repeated value overwrites, a repeated list appends
	if !keys.is_empty() && rng.below(4) == 0 {
		let again = keys[rng.below(keys.len())].clone();
		keys.push(again);
	}
	for i in (1..keys.len()).rev() {
		keys.swap(i, rng.below(i + 1));
	}
	let mut out = Vec::new();
	for k in &keys {
		// unknown_key's bytes are ASCII, lossy keeps them
		let key = k.trim_matches('%');
		out.extend(k.as_bytes());
		out.push(b'\n');
		for v in values(rng, key, name, ver) {
			out.extend(v);
			out.push(b'\n');
		}
		match rng.below(8) {
			0 => {}
			1 => out.extend(b"\n\n"),
			_ => out.push(b'\n'),
		}
	}
	finish(rng, out)
}

// whole-file changes: CRLF, no final newline, cut anywhere, empty
fn finish(rng: &mut Rng, mut out: Vec<u8>) -> Vec<u8> {
	match rng.below(16) {
		0 => {
			let mut crlf = Vec::new();
			for &c in &out {
				if c == b'\n' {
					crlf.push(b'\r');
				}
				crlf.push(c);
			}
			crlf
		}
		1 => {
			while out.last() == Some(&b'\n') {
				out.pop();
			}
			out
		}
		2 if !out.is_empty() => {
			out.truncate(rng.below(out.len()));
			out
		}
		3 => Vec::new(),
		_ => out,
	}
}

fn path(rng: &mut Rng) -> Vec<u8> {
	match rng.below(10) {
		0 => text(rng),
		1 => pick(rng, &[b"/etc/x", b"usr", b"usr/", b"./a", b" "])
			.to_vec(),
		_ => {
			let parts = 1 + rng.below(3);
			let mut p = Vec::new();
			for i in 0..parts {
				if i > 0 {
					p.push(b'/');
				}
				p.extend(word(rng, NAME, 1, 6));
			}
			if rng.below(3) == 0 {
				p.push(b'/');
			}
			p
		}
	}
}

// a backup line: path, tab, md5; no tab is a NULL hash, more tabs stay
// in the hash
fn backup(rng: &mut Rng) -> Vec<u8> {
	let p = path(rng);
	let hash = match rng.below(6) {
		0 => return p,
		1 => b"(null)".to_vec(),
		2 => word(rng, TEXT, 0, 8),
		3 => b"a\tb".to_vec(),
		_ => word(rng, b"0123456789abcdef", 32, 32),
	};
	[p, b"\t".to_vec(), hash].concat()
}

// %FILES% and %BACKUP% in any order, sometimes twice, blank lines inside
// (the C stops the section there), unknown sections and stray lines
fn gen_files(rng: &mut Rng) -> Vec<u8> {
	let mut out = Vec::new();
	if rng.below(8) == 0 {
		out.extend(b"stray\n\n");
	}
	for _ in 0..rng.below(4) {
		let key: &[u8] = match rng.below(8) {
			0 => b"%FOO%",
			1 => b"%BACKUP%",
			2 => b"%FILES%\r",
			_ => b"%FILES%",
		};
		let backups = key == b"%BACKUP%";
		out.extend(key);
		out.push(b'\n');
		for _ in 0..rng.below(8) {
			out.extend(match backups {
				true => backup(rng),
				false => path(rng),
			});
			out.push(b'\n');
			if rng.below(20) == 0 {
				out.push(b'\n');
			}
		}
		if rng.below(5) != 0 {
			out.push(b'\n');
		}
	}
	finish(rng, out)
}

fn dump(entries: &[LocalEntry]) -> String {
	let text = |t: &Option<Vec<u8>>| match t {
		Some(t) => format!("{:?}\n", String::from_utf8_lossy(t)),
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
	let name = word(rng, NAME, 1, 8);
	let name = match name[0] {
		b'-' | b'.' if rng.below(2) == 0 => [b"a", &name[..]].concat(),
		_ => name,
	};
	let ver = version(rng);
	let dir = [&name[..], b"-", &ver].concat();
	LocalEntry {
		// NAME is ASCII, version digits
		dir: String::from_utf8(dir).unwrap(),
		// missing files fail on both sides
		desc: (rng.below(40) != 0).then(|| gen_desc(rng, &name, &ver)),
		files: (rng.below(40) != 0).then(|| gen_files(rng)),
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
	for dir in ["dup-1-1", "dup-2-1", "a-b-c-1-1", "x-1:2.0-3", ".h-1-1"] {
		let (name, ver) =
			alpm_core::util::splitname(dir.as_bytes()).unwrap();
		entries.push(LocalEntry {
			dir: dir.into(),
			desc: Some(gen_desc(&mut rng, name, ver)),
			files: Some(gen_files(&mut rng)),
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
	// names check_meta warns about; its length check needs a name
	// longer than a file name can be
	fs::create_dir(local.join("-x-1-1")).unwrap();
	fs::create_dir(local.join("*-1-1")).unwrap();
	// stat follows the link: a directory
	symlink(local.join("x-1:2.0-3"), local.join("link-1-1")).unwrap();
	// no desc, no files
	fs::create_dir(local.join("empty-1-1")).unwrap();
	// desc a directory: fopen works, the first read fails
	fs::create_dir_all(local.join("dirdesc-1-1/desc")).unwrap();
	fs::create_dir_all(local.join("dirdesc-1-1/files")).unwrap();
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
fn fuzz_bytes() {
	let sb = TempRoot::new("be-local-fuzz");
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
				let ver = version(&mut rng);
				let dir = [name, b"-", &ver].concat();
				e.dir = String::from_utf8(dir).unwrap();
			}
			if entries.iter().any(|x| x.dir == e.dir) {
				continue;
			}
			entries.push(e);
		}
		sb.write_local(&entries);
		let loads = random_loads(&mut rng);
		compared += assert_same(&sb, loads, &|| dump(&entries));
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
			let cr = c_side(&c.root(), &c.dbpath(), Loads::ALL);
			let rr = rust_local_db(&r.dbpath(), Loads::ALL);
			let what = format!("case {i} {case:?} pkg {with_pkg}");
			assert_eq!(
				cr.0.as_ref().err(),
				rr.0.as_ref().err(),
				"{what}"
			);
			// the two trees differ in the paths logged
			let c_dir = c.dir().to_str().unwrap();
			let r_dir = r.dir().to_str().unwrap();
			let rebased: Vec<_> = lines(&cr.1)
				.into_iter()
				.map(|(l, m)| (l, m.replace(c_dir, r_dir)))
				.collect();
			assert_eq!(rebased, lines(&rr.1), "{what}");
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
	let cr = c_side(&c.root(), &c.dbpath(), Loads::ALL).0;
	let rr = rust_local_db(&r.dbpath(), Loads::ALL).0;
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
	let cr = c_side(&c.root(), &c.dbpath(), Loads::ALL).0;
	let rr = rust_local_db(&r.dbpath(), Loads::ALL).0;
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
	let cr = c_side(&c.root(), &c.dbpath(), Loads::ALL).0;
	let rr = rust_local_db(&r.dbpath(), Loads::ALL).0;
	assert!(cr.is_err());
	assert_eq!(cr.err(), rr.err());
}

// inputs the ALPM parsers refused or read otherwise (the divergences
// pinned before the owned reader), and the C's own corners, one package
// each: every one equal now
const BASE_DESC: &str = "%NAME%\nfoo\n\n%VERSION%\n1.0-1\n\n%BASE%\nfoo\n\n\
	%DESC%\nA package\n\n%URL%\nhttps://example.org/\n\n%ARCH%\nx86_64\n\n\
	%BUILDDATE%\n1700000000\n\n%INSTALLDATE%\n1700000001\n\n\
	%PACKAGER%\nA B <a@b.org>\n\n%SIZE%\n42\n\n%VALIDATION%\npgp\n\n\
	%DEPENDS%\nbar>=1.0\n\n";
const BASE_FILES: &str = "%FILES%\netc/\netc/foo.conf\nusr/\nusr/bin/\n\
	usr/bin/foo\n\n%BACKUP%\netc/foo.conf\td41d8cd98f00b204e9800998ecf8427e\n\n";

// a desc as ordered sections
struct Desc {
	sections: Vec<(String, Vec<String>)>,
}

impl Desc {
	fn text(&self) -> String {
		let mut out = String::new();
		for (key, lines) in &self.sections {
			out.push_str(&format!(
				"%{key}%\n{}\n\n",
				lines.join("\n")
			));
		}
		out
	}

	fn set(&mut self, key: &str, lines: Vec<String>) {
		match self.sections.iter_mut().find(|(k, _)| k == key) {
			Some(s) => s.1 = lines,
			None => self.sections.push((key.into(), lines)),
		}
	}

	fn remove(&mut self, key: &str) {
		self.sections.retain(|(k, _)| k != key);
	}
}

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

fn odd_cases() -> Vec<(&'static str, Vec<u8>, Vec<u8>)> {
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
		),
		(
			"desc line > 1023",
			desc(&|d| d.set("DESC", one(&long))),
			base_f.clone(),
		),
		(
			"unknown key",
			desc(&|d| d.set("FOO", one("bar"))),
			base_f.clone(),
		),
		(
			"reason 2",
			desc(&|d| d.set("REASON", one("2"))),
			base_f.clone(),
		),
		(
			"reason abc",
			desc(&|d| d.set("REASON", one("abc"))),
			base_f.clone(),
		),
		(
			"no validation",
			desc(&|d| d.remove("VALIDATION")),
			base_f.clone(),
		),
		("no base", desc(&|d| d.remove("BASE")), base_f.clone()),
		("no url", desc(&|d| d.remove("URL")), base_f.clone()),
		(
			"no packager",
			desc(&|d| d.remove("PACKAGER")),
			base_f.clone(),
		),
		(
			"no builddate",
			desc(&|d| d.remove("BUILDDATE")),
			base_f.clone(),
		),
		("no arch", desc(&|d| d.remove("ARCH")), base_f.clone()),
		(
			"empty url",
			desc(&|d| d.set("URL", one(""))),
			base_f.clone(),
		),
		(
			"desc spaces",
			desc(&|d| d.set("DESC", one(" a  b\tc "))),
			base_f.clone(),
		),
		(
			"desc empty",
			desc(&|d| d.set("DESC", one(""))),
			base_f.clone(),
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
		),
		(
			"makedepends",
			desc(&|d| d.set("MAKEDEPENDS", one("gcc"))),
			base_f.clone(),
		),
		(
			"checkdepends",
			desc(&|d| d.set("CHECKDEPENDS", one("chk"))),
			base_f.clone(),
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
		),
		(
			"xdata no pkgtype",
			desc(&|d| d.set("XDATA", one("a=b"))),
			base_f.clone(),
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
		),
		(
			"size +5",
			desc(&|d| d.set("SIZE", one("+5"))),
			base_f.clone(),
		),
		(
			"size -1",
			desc(&|d| d.set("SIZE", one("-1"))),
			base_f.clone(),
		),
		(
			"size huge",
			desc(&|d| d.set("SIZE", one("18446744073709551615"))),
			base_f.clone(),
		),
		(
			"builddate text",
			desc(&|d| d.set("BUILDDATE", one("x1"))),
			base_f.clone(),
		),
		(
			"validation foo",
			desc(&|d| d.set("VALIDATION", one("foo"))),
			base_f.clone(),
		),
		(
			"validation md5",
			desc(&|d| d.set("VALIDATION", one("md5"))),
			base_f.clone(),
		),
		(
			"unknown packager",
			desc(&|d| d.set("PACKAGER", one("Unknown Packager"))),
			base_f.clone(),
		),
		(
			"url normalized",
			desc(&|d| d.set("URL", one("HTTPS://Example.ORG"))),
			base_f.clone(),
		),
		(
			"url dot segment",
			desc(&|d| d.set("URL", one("https://a.org/x/./y"))),
			base_f.clone(),
		),
		(
			"url invalid",
			desc(&|d| d.set("URL", one("not a url"))),
			base_f.clone(),
		),
		(
			"license lowercase or",
			desc(&|d| d.set("LICENSE", one("MIT or Apache-2.0"))),
			base_f.clone(),
		),
		(
			"license deprecated",
			desc(&|d| d.set("LICENSE", one("GPL-2.0+"))),
			base_f.clone(),
		),
		(
			"dep trailing space",
			desc(&|d| d.set("DEPENDS", one("bar>=1.0 "))),
			base_f.clone(),
		),
		(
			"dep two ops",
			desc(&|d| d.set("DEPENDS", one("a<1>2"))),
			base_f.clone(),
		),
		(
			"dep empty version",
			desc(&|d| d.set("DEPENDS", one("a>="))),
			base_f.clone(),
		),
		(
			"dep name with .so",
			desc(&|d| d.set("DEPENDS", one("d1.so62r"))),
			base_f.clone(),
		),
		(
			"dep with desc",
			desc(&|d| d.set("DEPENDS", one("a: x"))),
			base_f.clone(),
		),
		(
			"optdep no space",
			desc(&|d| d.set("OPTDEPENDS", one("a:desc"))),
			base_f.clone(),
		),
		(
			"optdep spaces",
			desc(&|d| d.set("OPTDEPENDS", one("a:  two  words "))),
			base_f.clone(),
		),
		(
			"arch upper",
			desc(&|d| d.set("ARCH", one("X86_64"))),
			base_f.clone(),
		),
		(
			"arch ANY",
			desc(&|d| d.set("ARCH", one("ANY"))),
			base_f.clone(),
		),
		(
			"name mismatch",
			desc(&|d| d.set("NAME", one("other"))),
			base_f.clone(),
		),
		(
			"version no pkgrel",
			desc(&|d| d.set("VERSION", one("1.0"))),
			base_f.clone(),
		),
		(
			"desc mentions %XDATA%",
			desc(&|d| d.set("DESC", one("see %XDATA%"))),
			base_f.clone(),
		),
		("empty desc file", Vec::new(), base_f.clone()),
		(
			"header leading space",
			{
				BASE_DESC
					.replace("%ARCH%", " %ARCH%")
					.into_bytes()
			},
			base_f.clone(),
		),
		(
			"no final newline",
			base_d.trim_ascii_end().to_vec(),
			base_f.clone(),
		),
		(
			"nul in desc",
			desc(&|d| d.set("DESC", one("a\0b"))),
			base_f.clone(),
		),
		(
			"files crlf",
			base_d.clone(),
			BASE_FILES.replace('\n', "\r\n").into_bytes(),
		),
		(
			"backup (null)",
			base_d.clone(),
			files(&BASE_FILES.replace(
				"d41d8cd98f00b204e9800998ecf8427e",
				"(null)",
			)),
		),
		(
			"backup no tab",
			base_d.clone(),
			files(&BASE_FILES.replace(
				"\td41d8cd98f00b204e9800998ecf8427e",
				"",
			)),
		),
		(
			"backup not in files",
			base_d.clone(),
			files(&BASE_FILES.replace(
				"etc/foo.conf\td41",
				"etc/bar.conf\td41",
			)),
		),
		(
			"backup unsorted",
			base_d.clone(),
			files(&BASE_FILES.replace(
				"%BACKUP%\n",
				"%BACKUP%\nusr/bin/foo\t00000000000000000000000000000000\n",
			)),
		),
		(
			"backup md5 upper",
			base_d.clone(),
			files(&BASE_FILES.replace(
				"d41d8cd98f00b204e9800998ecf8427e",
				"D41D8CD98F00B204E9800998ECF8427E",
			)),
		),
		(
			"backup md5 short",
			base_d.clone(),
			files(&BASE_FILES.replace(
				"d41d8cd98f00b204e9800998ecf8427e",
				"abc",
			)),
		),
		(
			"backup only md5 short",
			base_d.clone(),
			files("%BACKUP%\netc/foo.conf\tabc\n\n"),
		),
		(
			"files blank line inside",
			base_d.clone(),
			files("%FILES%\nusr/\n\nusr/bin/\n\n"),
		),
		(
			"files absolute",
			base_d.clone(),
			files("%FILES%\n/etc/\n/etc/x\n\n"),
		),
		(
			"files no parent",
			base_d.clone(),
			files("%FILES%\nusr/bin/foo\n\n"),
		),
		(
			"files duplicate",
			base_d.clone(),
			files("%FILES%\nusr/\nusr/\n\n"),
		),
		(
			"files dir and file",
			base_d.clone(),
			files("%FILES%\nusr\nusr/\n\n"),
		),
		(
			"files dot segment",
			base_d.clone(),
			files("%FILES%\nusr/\nusr/./\n\n"),
		),
		(
			"files blank path",
			base_d.clone(),
			files("%FILES%\nusr/\n \nusr/bin/\n\n"),
		),
		(
			"files long path",
			base_d.clone(),
			files(&format!("%FILES%\n{long}\n\n")),
		),
		(
			"files not utf-8",
			base_d.clone(),
			b"%FILES%\nusr/\nusr/\xff\n\n".to_vec(),
		),
		(
			"files unknown section",
			base_d.clone(),
			files(&format!("{BASE_FILES}%FOO%\nbar\n\n")),
		),
		(
			"files leading blank",
			base_d.clone(),
			files(&format!("\n{BASE_FILES}")),
		),
		("no desc", desc(&|d| d.remove("DESC")), base_f.clone()),
		(
			"no installdate",
			desc(&|d| d.remove("INSTALLDATE")),
			base_f.clone(),
		),
		(
			"url twice",
			{
				let mut s = desc_with(|_| {});
				s.push_str("%URL%\nhttps://b.org/x\n\n");
				s.into_bytes()
			},
			base_f.clone(),
		),
		(
			"validation twice",
			{
				let mut s = desc_with(|_| {});
				s.push_str("%VALIDATION%\nsha256\n\n");
				s.into_bytes()
			},
			base_f.clone(),
		),
		(
			"header line in a list",
			desc(&|d| {
				d.set(
					"GROUPS",
					vec!["g1".into(), "%URL%".into()],
				)
			}),
			base_f.clone(),
		),
		(
			"stray line after a value",
			BASE_DESC
				.replace(
					"%ARCH%\nx86_64\n",
					"%ARCH%\nx86_64\nany\n",
				)
				.into_bytes(),
			base_f.clone(),
		),
		(
			"backup only",
			base_d.clone(),
			files(
				"%BACKUP%\netc/foo.conf\td41d8cd98f00b204e9800998ecf8427e\n\n",
			),
		),
		(
			"files twice",
			base_d.clone(),
			files(&format!("{BASE_FILES}%FILES%\nopt/\n\n")),
		),
		(
			"backup twice",
			base_d.clone(),
			files(&format!(
				"{BASE_FILES}%BACKUP%\nusr/bin/foo\t(null)\n\n"
			)),
		),
		(
			"files sorted by strcmp",
			base_d.clone(),
			files(
				"%FILES%\nusr/\nusr/lib-x\nusr/lib/\nusr/lib/a\n\n",
			),
		),
	]
}

// the C's corners on top of the old divergence list
fn corner_cases() -> Vec<(&'static str, Vec<u8>, Vec<u8>)> {
	let base_f = BASE_FILES.as_bytes().to_vec();
	let d = |s: &str| s.as_bytes().to_vec();
	vec![
		// the last value without a blank line: the NULL fgets at the
		// end keeps it in the buffer, read once more as a key
		("last value again", d("%DESC%\nfoo\n"), base_f.clone()),
		("last value a key", d("%BASE%\n%DESC%\n"), base_f.clone()),
		("header at the end", d("%DESC%"), base_f.clone()),
		(
			"header and newline at the end",
			d("%URL%\n"),
			base_f.clone(),
		),
		("list at the end", d("%GROUPS%\na\nb"), base_f.clone()),
		("reason 0", d("%REASON%\n0\n\n"), base_f.clone()),
		("reason empty", d("%REASON%\n\n"), base_f.clone()),
		(
			"reason twice",
			d("%REASON%\n1\n\n%REASON%\nx\n\n"),
			base_f.clone(),
		),
		(
			"1023 byte line",
			format!("%DESC%\n{}\n\n", "d".repeat(1023))
				.into_bytes(),
			base_f.clone(),
		),
		(
			"1022 byte line",
			format!("%DESC%\n{}\n\n", "d".repeat(1022))
				.into_bytes(),
			base_f.clone(),
		),
		(
			"long key line",
			format!("{}\nx\n\n", "%".repeat(2050)).into_bytes(),
			base_f.clone(),
		),
		("nul key", d("%DESC%\0junk\nx\n\n"), base_f.clone()),
		(
			"nul only line",
			d("%GROUPS%\na\n\0b\nc\n\n"),
			base_f.clone(),
		),
		("xdata =", d("%XDATA%\n=\na=b=c\n\n"), base_f.clone()),
		("files nul", d(""), d("%FILES%\na\0b\n\0\nc\n\n")),
		("files at the end", d(""), d("%FILES%\na\nb")),
		("backup no tab", d(""), d("%BACKUP%\netc/x\n\n")),
		("backup two tabs", d(""), d("%BACKUP%\na\tb\tc\n\n")),
		("backup empty hash", d(""), d("%BACKUP%\na\t\n\t\n\n")),
		(
			"files long path",
			d(""),
			format!("%FILES%\n{}\n\n", "p".repeat(2500))
				.into_bytes(),
		),
	]
}

#[test]
fn odd_inputs() {
	let sb = TempRoot::new("be-local-odd");
	let cases = odd_cases().into_iter().chain(corner_cases());
	for (label, desc, files) in cases {
		sb.reset_local();
		let entries = [LocalEntry {
			dir: "foo-1.0-1".into(),
			desc: Some(desc),
			files: Some(files),
			install: false,
		}];
		sb.write_local(&entries);
		let what = || format!("{label}\n{}", dump(&entries));
		// desc and files apart too: a desc error hides files
		for loads in [
			Loads::ALL,
			Loads {
				desc: false,
				files: true,
				scriptlet: false,
			},
		] {
			assert_same(&sb, loads, &what);
		}
	}
}

// the real local db, strictly read only: alpm_initialize only reads
// ALPM_DB_VERSION when it exists, no transaction or lock is taken
#[test]
fn system_local_db() {
	let dbpath = b"/var/lib/pacman/";
	if !Path::new("/var/lib/pacman/local/ALPM_DB_VERSION").exists() {
		eprintln!("no /var/lib/pacman/local, skipped");
		return;
	}
	let n = assert_same_at(b"/", dbpath);
	eprintln!("/var/lib/pacman: {n} packages equal");
}

// assert_same on an existing root and dbpath
fn assert_same_at(root: &[u8], dbpath: &[u8]) -> usize {
	let (c, clog) = c_side(root, dbpath, Loads::ALL);
	let (r, rlog) = rust_local_db(dbpath, Loads::ALL);
	let (c, r) = (c.unwrap(), r.unwrap());
	assert_eq!(c.counts, r.counts);
	assert_eq!(c.pkgs.len(), r.pkgs.len());
	for (cp, rp) in c.pkgs.iter().zip(&r.pkgs) {
		assert!(
			cp == rp,
			"{} differs in {:?}",
			s(&cp.name),
			diff_fields(cp, rp)
		);
	}
	assert_eq!(lines(&clog), lines(&rlog));
	c.pkgs.len()
}
