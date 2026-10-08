// alpm_core::be_sync against the C sync db backend: repo dbs generated
// under the temp dir (desc/files as repo-add writes them, then changed
// byte by byte: sections left out, repeated or unknown, blank lines, CRLF,
// nul bytes, non-UTF-8, long lines, cut texts; every compression
// alpm-compress has), loaded by both: every field, the validation getter,
// the cache order, the table counts, pm_errno and the log lines compared.
// odd inputs and data blocks cut at libarchive's block edges are pinned
// cases, copies of the real sync dbs compared whole
use std::cell::RefCell;
use std::ffi::c_int;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use alpm_core::be_sync::{self, get_validation, populate};
use alpm_core::callbacks::{Callbacks, LogLevel};
use alpm_core::handle::Handle;
use alpm_core::package::Package;
use difftest::{
	CHandle, COMPS, CSyncDb, Comp, Rng, TarEntry, TempRoot, c_sync_db_load,
	iters, section, tar_dir, tar_file, ustar, write_db,
};

// one db per iteration, a C handle each: far slower than string fuzz
fn db_iters() -> usize {
	(iters() / 100).max(100)
}

// what a load gives, comparable across both sides: packages with
// validation getter result, (entries, buckets, limit), or the pm_errno
type Outcome = Result<(Vec<(Package, i32)>, (usize, usize, usize)), i32>;
type Logs = Vec<(c_int, Vec<u8>)>;

// the port's log lines
struct Rec(RefCell<Logs>);

impl Callbacks for &Rec {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		self.0.borrow_mut().push((level as c_int, msg.to_vec()));
	}
}

// lines left out of the compare. not logged by the port: db.c's around the populate (the port
// calls be_sync directly), RET_ERR/GOTO_ERR, and the lines carrying
// libarchive's texts (_alpm_open_archive's); the archive error the port
// logs with its own text
fn modelled(line: &(c_int, Vec<u8>)) -> bool {
	const NOT: [&[u8]; 7] = [
		b"loading package cache for repository",
		b"failed to load package cache for repository",
		b"freeing package cache for repository",
		b"returning error ",
		b"got error ",
		b"could not read db '",
		b"could not open file ",
	];
	!NOT.iter().any(|p| line.1.starts_with(p))
}

fn load_c(fx: &TempRoot, tree: &str, ext: &str) -> (Outcome, Logs) {
	let (db, logs) = c_sync_db_load(
		&fx.dir().join("root"),
		&fx.dir().join("db"),
		tree.as_bytes(),
		ext.as_bytes(),
	);
	let logs = logs.into_iter().filter(modelled).collect();
	let out = db.map(|db| {
		let CSyncDb {
			pkgs,
			validation,
			counts,
		} = db;
		(pkgs.into_iter().zip(validation).collect(), counts)
	});
	(out, logs)
}

fn load_rust(fx: &TempRoot, tree: &str, ext: &str) -> (Outcome, Logs) {
	let path =
		be_sync::db_path(&fx.dbpath(), tree.as_bytes(), ext.as_bytes());
	let rec = Rec(RefCell::new(Vec::new()));
	let out = populate(&path, ext.as_bytes(), tree.as_bytes(), &mut &rec)
		.map_err(|e| e.errno() as i32)
		.map(|cache| {
			let counts =
				(cache.len(), cache.buckets(), cache.limit());
			let pkgs = cache
				.iter()
				.map(|p| (p.clone(), get_validation(p)));
			(pkgs.collect(), counts)
		});
	// the archive error line is the port's text
	let logs = rec.0.into_inner().into_iter().filter(modelled).collect();
	(out, logs)
}

// one generated package: entry names and texts
struct Gen {
	dir: String,
	desc: String,
	// old split format: relations in a separate depends entry
	depends: Option<String>,
	files: Option<String>,
}

fn pick<'a>(rng: &mut Rng, items: &[&'a str]) -> &'a str {
	items[rng.below(items.len())]
}

fn word(rng: &mut Rng, alphabet: &[u8], min: usize, max: usize) -> String {
	let n = min + rng.below(max - min + 1);
	(0..n).map(|_| rng.pick(alphabet) as char).collect()
}

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGIT: &[u8] = b"0123456789";
const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789ABCXYZ";
const NAME: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789@._+-";

// alpm package name: alnum or _@+ first, never - or .
fn pkg_name(rng: &mut Rng) -> String {
	let first =
		rng.pick(b"abcdefghijklmnopqrstuvwxyz0123456789_@+") as char;
	format!("{first}{}", word(rng, NAME, 0, 12))
}

fn pkgver(rng: &mut Rng) -> String {
	let parts = 1 + rng.below(3);
	let mut v = word(rng, DIGIT, 1, 3);
	for _ in 1..parts {
		v.push(rng.pick(b"._+") as char);
		v.push_str(&word(rng, ALNUM, 1, 3));
	}
	v
}

fn full_version(rng: &mut Rng) -> String {
	let epoch = match rng.below(4) {
		0 => format!("{}:", 1 + rng.below(9)),
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

fn description(rng: &mut Rng) -> String {
	let words: Vec<String> = (0..1 + rng.below(6))
		.map(|_| match rng.below(8) {
			0 => "caf\u{e9}".to_string(),
			1 => "(GTK+)".to_string(),
			2 => "50%".to_string(),
			_ => word(rng, ALNUM, 1, 8),
		})
		.collect();
	// runs of blanks are kept as read
	words.join(pick(rng, &[" ", " ", "  ", " \t"]))
}

// relation lines stay far below 512 bytes, the smallest first data block
// libarchive hands out: READ_AND_SPLITDEP parses a stale `line` once a
// longer line makes _alpm_archive_fgets reallocate its buffer
fn relation(rng: &mut Rng) -> String {
	let name = pkg_name(rng);
	match rng.below(10) {
		0 => format!("lib{}.so=1-64", word(rng, LOWER, 1, 6)),
		1 => format!(
			"lib:lib{}.so.{}",
			word(rng, LOWER, 1, 6),
			rng.below(9)
		),
		2..5 => name,
		_ => {
			let op = pick(rng, &["=", ">=", "<=", ">", "<"]);
			let ver = match rng.below(3) {
				0 => full_version(rng),
				_ => pkgver(rng),
			};
			format!("{name}{op}{ver}")
		}
	}
}

// plain package relation, no sonames
fn pkg_relation(rng: &mut Rng) -> String {
	let name = pkg_name(rng);
	match rng.below(3) {
		0 => name,
		_ => {
			let op = pick(rng, &["=", ">=", "<=", ">", "<"]);
			format!("{name}{op}{}", pkgver(rng))
		}
	}
}

fn optdepend(rng: &mut Rng) -> String {
	let name = pkg_name(rng);
	match rng.below(3) {
		0 => name,
		// libalpm keeps the description after ": " as is
		_ => format!(
			"{name}: {}{}",
			pick(rng, &["", "", " "]),
			description(rng)
		),
	}
}

fn base64(rng: &mut Rng, n: usize) -> String {
	const T: &[u8] =
		b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	let bytes: Vec<u8> = (0..n).map(|_| rng.next_u64() as u8).collect();
	let mut s = String::new();
	for c in bytes.chunks(3) {
		let v = c.iter().fold(0u32, |a, &b| a << 8 | u32::from(b))
			<< (8 * (3 - c.len()));
		for i in 0..4 {
			if i <= c.len() {
				s.push(T[(v >> (18 - 6 * i) & 63) as usize]
					as char);
			} else {
				s.push('=');
			}
		}
	}
	s
}

fn list(rng: &mut Rng, max: usize, f: fn(&mut Rng) -> String) -> Vec<String> {
	(0..rng.below(max + 1)).map(|_| f(rng)).collect()
}

// relative paths, pacman checks none of it: parents sometimes missing,
// duplicates and file/dir twins ("usr", "usr/") sometimes
fn file_list(rng: &mut Rng) -> Vec<String> {
	let mut out: Vec<String> = Vec::new();
	let mut dirs: Vec<String> = vec![String::new()];
	for _ in 0..rng.below(12) {
		let parent = dirs[rng.below(dirs.len())].clone();
		let leaf = word(rng, b"abcxyz019._-+", 1, 6);
		let is_dir = rng.below(3) == 0;
		let p = format!(
			"{parent}{leaf}{}",
			if is_dir { "/" } else { "" }
		);
		if is_dir {
			dirs.push(p.clone());
			if rng.below(10) == 0 {
				continue;
			}
		}
		match rng.below(12) {
			0 => out.push(p.clone()),
			1 => out.push(format!("{parent}{leaf}")),
			_ => {}
		}
		out.push(p);
	}
	out
}

fn license(rng: &mut Rng) -> String {
	let all = [
		"MIT",
		"GPL-2.0-or-later",
		"Apache-2.0 WITH LLVM-exception",
		"MIT OR Apache-2.0",
		"LicenseRef-custom",
		"custom:none",
	];
	pick(rng, &all).to_string()
}

fn gen_pkg(rng: &mut Rng, name: String, files_db: bool) -> Gen {
	let version = full_version(rng);
	let arch = pick(rng, &["x86_64", "any", "aarch64", "i686", "riscv64"]);
	let ext = pick(rng, &["zst", "xz", "gz", "bz2"]);
	let one = |s: String| vec![s];
	let mut fixed = vec![
		section(
			"FILENAME",
			&one(format!("{name}-{version}-{arch}.pkg.tar.{ext}")),
		),
		section("NAME", &one(name.clone())),
		section(
			"BASE",
			&one(match rng.below(3) {
				0 => pkg_name(rng),
				_ => name.clone(),
			}),
		),
		section("VERSION", &one(version.clone())),
		section("CSIZE", &one(format!("{}", rng.next_u64() >> 1))),
		section("ISIZE", &one(format!("{}", rng.next_u64() >> 1))),
		section(
			"SHA256SUM",
			&one(word(rng, b"0123456789abcdef", 64, 64)),
		),
		section("ARCH", &one(arch.to_string())),
		section(
			"BUILDDATE",
			&one(match rng.below(5) {
				0 => format!("-{}", rng.below(1 << 30)),
				_ => format!("{}", rng.next_u64() >> 24),
			}),
		),
		section(
			"PACKAGER",
			&one(match rng.below(6) {
				// makepkg's default
				0 => "Unknown Packager".into(),
				_ => format!(
					"{} {} <{}@{}.org>",
					word(rng, ALNUM, 1, 8),
					word(rng, ALNUM, 1, 8),
					word(rng, LOWER, 1, 8),
					word(rng, LOWER, 1, 8)
				),
			}),
		),
	];
	if rng.below(4) != 0 {
		fixed.push(section("DESC", &one(description(rng))));
	}
	if rng.below(3) != 0 {
		let path =
			list(rng, 3, |r| word(r, b"abcz09_-", 1, 6)).join("/");
		let host = word(rng, LOWER, 1, 8);
		// url::Url adds the '/' of an empty path and lowercases
		let url = match rng.below(4) {
			0 => format!("HTTPS://{host}.ORG"),
			_ => format!("https://{host}.org/{path}"),
		};
		fixed.push(section("URL", &one(url)));
	}
	match rng.below(5) {
		0 => {}
		1 => fixed.push(section(
			"MD5SUM",
			&one(word(rng, b"0123456789abcdef", 32, 32)),
		)),
		_ => {
			let n = 8 + rng.below(90);
			fixed.push(section("PGPSIG", &one(base64(rng, n))));
		}
	}
	fixed.push(section("GROUPS", &list(rng, 2, |r| word(r, NAME, 1, 8))));
	fixed.push(section("LICENSE", &list(rng, 2, license)));
	let rels = [
		section("REPLACES", &list(rng, 2, pkg_relation)),
		section("CONFLICTS", &list(rng, 2, pkg_relation)),
		section("PROVIDES", &list(rng, 3, relation)),
		section("DEPENDS", &list(rng, 4, relation)),
		section("OPTDEPENDS", &list(rng, 2, optdepend)),
		section("MAKEDEPENDS", &list(rng, 2, pkg_relation)),
		section("CHECKDEPENDS", &list(rng, 2, pkg_relation)),
	];
	let split = rng.below(5) == 0;
	if !split {
		fixed.extend(rels.iter().cloned());
	}
	// repo-add always writes these, pacman reads a db without them
	for key in [
		"FILENAME",
		"BASE",
		"CSIZE",
		"ISIZE",
		"SHA256SUM",
		"ARCH",
		"BUILDDATE",
		"PACKAGER",
	] {
		if rng.below(12) == 0 {
			let head = format!("%{key}%\n");
			fixed.retain(|s| !s.starts_with(&head));
		}
	}
	// an empty list, extra data and an unknown key, read or skipped by
	// pacman
	if rng.below(8) == 0 {
		let key = pick(
			rng,
			&["GROUPS", "LICENSE", "DEPENDS", "PROVIDES"],
		);
		fixed.push(format!("%{key}%\n\n"));
	}
	if rng.below(8) == 0 {
		let mut data = list(rng, 3, |r| {
			format!(
				"{}={}",
				word(r, LOWER, 1, 6),
				word(r, ALNUM, 1, 6)
			)
		});
		data.insert(0, "pkgtype=pkg".into());
		fixed.push(section("DATA", &data));
	}
	if rng.below(8) == 0 {
		let key = format!("X{}", word(rng, b"ABCXYZ_", 1, 6));
		let vals = list(rng, 3, |r| word(r, b"abc%XY =", 1, 8));
		fixed.push(format!("%{key}%\n{}\n", vals.join("\n")));
	}
	// a repeated value overwrites, a repeated list appends
	if !fixed.is_empty() && rng.below(8) == 0 {
		let again = fixed[rng.below(fixed.len())].clone();
		fixed.push(again);
	}
	// pacman reads sections in any order
	if rng.below(3) == 0 {
		for i in (1..fixed.len()).rev() {
			fixed.swap(i, rng.below(i + 1));
		}
	}
	let files = files_db.then(|| {
		let paths = file_list(rng);
		match paths.is_empty() {
			true => "%FILES%\n".to_string(),
			false => format!("%FILES%\n{}\n\n", paths.join("\n")),
		}
	});
	let mut desc = fixed.concat();
	// blank lines between sections are skipped by pacman
	if rng.below(6) == 0 {
		desc = desc.replace("\n\n%", "\n\n\n%");
	}
	Gen {
		dir: format!("{name}-{version}"),
		desc,
		depends: split.then(|| rels.concat()),
		files,
	}
}

// archive entries of a generated db, packages in random order, directory
// entries sometimes left out
fn gen_db(rng: &mut Rng, files_db: bool) -> (Vec<TarEntry>, Vec<Gen>) {
	let n = match rng.below(20) {
		0 => 50 + rng.below(150),
		_ => rng.below(8),
	};
	let mut names: Vec<String> = (0..n).map(|_| pkg_name(rng)).collect();
	names.sort();
	names.dedup();
	for i in (1..names.len()).rev() {
		names.swap(i, rng.below(i + 1));
	}
	let pkgs: Vec<Gen> = names
		.into_iter()
		.map(|n| gen_pkg(rng, n, files_db))
		.collect();
	let mut entries = Vec::new();
	for g in &pkgs {
		if rng.below(4) != 0 {
			entries.push(tar_dir(&format!("{}/", g.dir)));
		}
		let desc =
			tar_file(&format!("{}/desc", g.dir), g.desc.as_bytes());
		let mut own = vec![desc];
		if let Some(d) = &g.depends {
			own.push(tar_file(
				&format!("{}/depends", g.dir),
				d.as_bytes(),
			));
		}
		if let Some(f) = &g.files {
			own.push(tar_file(
				&format!("{}/files", g.dir),
				f.as_bytes(),
			));
		}
		if rng.below(4) == 0 {
			own.reverse();
		}
		entries.extend(own);
	}
	(entries, pkgs)
}

fn describe(entries: &[TarEntry]) -> String {
	let mut s = String::new();
	for e in entries {
		s.push_str(&format!(
			"--- {}\n",
			String::from_utf8_lossy(&e.name)
		));
		s.push_str(&String::from_utf8_lossy(&e.data));
	}
	s
}

fn lines(l: &Logs) -> Vec<(c_int, String)> {
	l.iter().map(|(lv, m)| (*lv, String::from_utf8_lossy(m).into()))
		.collect()
}

fn assert_same(
	c: &(Outcome, Logs),
	r: &(Outcome, Logs),
	ctx: &dyn Fn() -> String,
) {
	match (&c.0, &r.0) {
		(Ok((cp, cc)), Ok((rp, rc))) => {
			let names = |p: &[(Package, i32)]| -> Vec<String> {
				p.iter().map(|(p, _)| {
					String::from_utf8_lossy(p.name_bytes())
						.into_owned()
				})
				.collect()
			};
			assert_eq!(
				names(cp),
				names(rp),
				"cache order\n{}",
				ctx()
			);
			for (a, b) in cp.iter().zip(rp) {
				assert_eq!(
					a,
					b,
					"package, fields {:?}\n{}",
					diff_fields(&a.0, &b.0),
					ctx()
				);
			}
			assert_eq!(
				cc,
				rc,
				"entries, buckets, limit\n{}",
				ctx()
			);
		}
		(c, r) => assert_eq!(c, r, "outcome\n{}", ctx()),
	}
	assert_eq!(lines(&c.1), lines(&r.1), "log lines\n{}", ctx());
}

type Both = ((Outcome, Logs), (Outcome, Logs), String);

// C and rust outcomes, plus the rust error in full
fn run_case(entries: &[TarEntry], comp: Comp, ext: &str) -> Both {
	let fx = TempRoot::new("be-sync");
	write_db(&fx.sync_file("repo", ext), comp, &ustar(entries));
	let path = be_sync::db_path(&fx.dbpath(), b"repo", ext.as_bytes());
	let why = match populate(&path, ext.as_bytes(), b"repo", &mut ()) {
		Err(e) => format!("{e:?}"),
		Ok(_) => String::new(),
	};
	(load_c(&fx, "repo", ext), load_rust(&fx, "repo", ext), why)
}

// the lines of a text, split at '\n' (the last one after the final
// '\n', empty when the text ends in one)
fn split_lines(data: &[u8]) -> Vec<Vec<u8>> {
	data.split(|&c| c == b'\n').map(<[u8]>::to_vec).collect()
}

const RELATION_KEYS: [&[u8]; 7] = [
	b"%REPLACES%",
	b"%DEPENDS%",
	b"%OPTDEPENDS%",
	b"%MAKEDEPENDS%",
	b"%CHECKDEPENDS%",
	b"%CONFLICTS%",
	b"%PROVIDES%",
];

// a value line of 512 bytes or more, sometimes over a filter block
fn long_line(rng: &mut Rng) -> Vec<u8> {
	let n = match rng.below(4) {
		0 => 64 * 1024 + rng.below(80 * 1024),
		_ => 512 + rng.below(9000),
	};
	(0..n).map(|_| rng.pick(b"abcxyz019 :=%-")).collect()
}

// byte-level changes to an entry text. lines of 512 bytes and more only
// go into texts whose sections all keep their blank line, right after a
// header that starts no relation list: READ_AND_SPLITDEP parses the
// freed line buffer once a longer line grows it (UPSTREAM.md), so a
// relation section never holds one
fn mutate(rng: &mut Rng, data: &[u8]) -> Vec<u8> {
	let mut lines = split_lines(data);
	if rng.below(3) == 0 {
		let heads: Vec<usize> = (0..lines.len())
			.filter(|&i| {
				let l = &lines[i];
				l.starts_with(b"%")
					&& !RELATION_KEYS.contains(&&l[..]) && (i == 0
					|| lines[i - 1].is_empty())
			})
			.collect();
		if !heads.is_empty() {
			let at = heads[rng.below(heads.len())] + 1;
			let long = long_line(rng);
			lines.insert(at, long);
		}
		return lines.join(&b'\n');
	}
	for _ in 0..1 + rng.below(4) {
		if lines.is_empty() {
			break;
		}
		let i = rng.below(lines.len());
		match rng.below(9) {
			0 => lines[i].push(b'\r'),
			1 => {
				let at = rng.below(lines[i].len() + 1);
				let b = rng.pick(b"\0\xff\xc3%:= \t");
				lines[i].insert(at, b);
			}
			// a blank line gone: the next section joins this one
			2 if lines[i].is_empty() => {
				lines.remove(i);
			}
			3 => {
				let l = lines[i].clone();
				lines.insert(i, l);
			}
			4 => lines.insert(i, Vec::new()),
			5 => {
				let key = pick(
					rng,
					&["%FOO%", "%name%", "%DESC% ", "%%"],
				);
				let unknown = [
					key.as_bytes().to_vec(),
					b"x".to_vec(),
				];
				lines.splice(i..i, unknown);
			}
			6 => {
				// no final newline, or cut anywhere
				let mut t = lines.join(&b'\n');
				match rng.below(2) {
					0 => {
						while t.last() == Some(&b'\n') {
							t.pop();
						}
					}
					_ => t.truncate(rng.below(t.len() + 1)),
				}
				return t;
			}
			_ => {}
		}
	}
	lines.join(&b'\n')
}

// the texts of the db, some of them changed
fn mutate_db(rng: &mut Rng, entries: &mut [TarEntry]) {
	for e in entries {
		let read = [&b"/desc"[..], b"/depends", b"/files"];
		let text = read.iter().any(|f| e.name.ends_with(f));
		if text && rng.below(3) == 0 {
			e.data = mutate(rng, &e.data);
		}
	}
}

fn fuzz(seed: u64, files_db: bool) {
	let mut rng = Rng::new(seed);
	let ext = if files_db { ".files" } else { ".db" };
	let (mut pkgs, mut refused) = (0, 0);
	for _ in 0..db_iters() {
		let (mut entries, _) = gen_db(&mut rng, files_db);
		mutate_db(&mut rng, &mut entries);
		let comp = COMPS[rng.below(COMPS.len())];
		let (c, r, why) = run_case(&entries, comp, ext);
		let ctx = || {
			format!("{comp:?} {ext} {why}\n{}", describe(&entries))
		};
		assert_same(&c, &r, &ctx);
		match &c.0 {
			Ok((p, _)) => pkgs += p.len(),
			Err(_) => refused += 1,
		}
	}
	eprintln!("{pkgs} packages compared, {refused} dbs refused");
	assert!(pkgs > db_iters(), "too few packages compared: {pkgs}");
	assert!(refused > db_iters() / 50, "too few refused: {refused}");
}

#[test]
fn fuzz_db() {
	fuzz(0x5eed, false);
}

#[test]
fn fuzz_files_db() {
	fuzz(0xf11e5, true);
}

#[test]
fn every_compression() {
	let mut rng = Rng::new(7);
	let (entries, _) = gen_db(&mut rng, true);
	for comp in COMPS {
		let (c, r, _) = run_case(&entries, comp, ".files");
		assert_same(&c, &r, &|| format!("{comp:?}"));
		assert!(c.0.is_ok());
	}
}

#[test]
fn missing_db() {
	let fx = TempRoot::new("be-sync");
	let c = load_c(&fx, "nope", ".db");
	// the C's db is missing since registration and never opens the
	// file; the port's populate is that of a file gone since then
	assert_eq!(c.0, load_rust(&fx, "nope", ".db").0);
	assert_eq!(c.0, Err(alpm_core::error::Errno::DbNotFound as i32));
}

#[test]
fn db_path() {
	assert_eq!(
		be_sync::db_path(b"/var/lib/pacman/", b"core", b".files"),
		b"/var/lib/pacman/sync/core.files"
	);
}

// field names of Package that differ
fn diff_fields(c: &Package, r: &Package) -> Vec<&'static str> {
	let mut out = Vec::new();
	macro_rules! cmp {
		($($f:ident),*) => {$(
			if c.$f != r.$f {
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
		size,
		isize,
		licenses,
		replaces,
		groups,
		depends,
		optdepends,
		checkdepends,
		makedepends,
		conflicts,
		provides,
		files,
		origin,
		xdata,
		validation
	);
	out
}

// copies of the real sync dbs, read only, compared whole
#[test]
fn real_sync_dbs() {
	let Ok(dir) = fs::read_dir("/var/lib/pacman/sync") else {
		eprintln!("no /var/lib/pacman/sync, skipped");
		return;
	};
	let mut paths: Vec<PathBuf> = dir.map(|e| e.unwrap().path()).collect();
	paths.sort();
	for path in paths {
		let name =
			path.file_name().unwrap().to_str().unwrap().to_string();
		let Some((tree, ext)) = name
			.strip_suffix(".db")
			.map(|t| (t, ".db"))
			.or_else(|| {
				name.strip_suffix(".files")
					.map(|t| (t, ".files"))
			})
		else {
			continue;
		};
		let fx = TempRoot::new("be-sync");
		fs::copy(&path, fx.sync_file(tree, ext)).unwrap();
		let c = load_c(&fx, tree, ext);
		let r = load_rust(&fx, tree, ext);
		assert_same(&c, &r, &|| name.clone());
		let n = c.0.as_ref().map_or(0, |(p, _)| p.len());
		eprintln!("{name}: {n} packages equal");
	}
}

// smallest desc both accept
fn desc(name: &str, version: &str) -> String {
	format!(
		"%FILENAME%\n{name}-{version}-any.pkg.tar.zst\n\n\
		%NAME%\n{name}\n\n%BASE%\n{name}\n\n%VERSION%\n{version}\n\n\
		%CSIZE%\n1\n\n%ISIZE%\n2\n\n%SHA256SUM%\n{}\n\n\
		%ARCH%\nany\n\n%BUILDDATE%\n3\n\n\
		%PACKAGER%\nA B <a@b.org>\n\n",
		"ab".repeat(32)
	)
}

// foo-1-1 with desc text d
fn foo(d: &str) -> Vec<TarEntry> {
	vec![tar_dir("foo-1-1/"), tar_file("foo-1-1/desc", d.as_bytes())]
}

fn foo_with(extra: &str) -> Vec<TarEntry> {
	foo(&format!("{}{extra}", desc("foo", "1-1")))
}

// inputs pacman accepts or refuses in its own way, the ALPM parser
// divergences pinned before the owned reader among them: all equal
#[test]
fn odd_inputs() {
	let base = desc("foo", "1-1");
	let md5 = format!("%MD5SUM%\n{}\n\n", "0".repeat(32));
	let long = format!("%DESC%\n{}\n\n", "x".repeat(600 * 1024));
	let cases: Vec<(&str, Vec<TarEntry>)> = vec![
		("minimal", foo(&base)),
		("url no path", foo_with("%URL%\nhttps://a.org\n\n")),
		(
			"url upper, dot segment",
			foo_with("%URL%\nHTTPS://A.org/x/./y\n\n"),
		),
		(
			"unknown packager",
			foo(&base.replace("A B <a@b.org>", "Unknown Packager")),
		),
		(
			"packager email only",
			foo(&base.replace("A B <a@b.org>", "<a@b.org>")),
		),
		("url with path", foo_with("%URL%\nhttps://a.org/x\n\n")),
		("unknown key", foo_with("%FOO%\nbar\n\n")),
		("xdata", foo_with("%DATA%\npkgtype=pkg\n\n")),
		("no %BASE%", foo(&base.replace("%BASE%\nfoo\n\n", ""))),
		(
			"no %PACKAGER%",
			foo(&base.replace("%PACKAGER%\nA B <a@b.org>\n\n", "")),
		),
		("empty desc", foo("")),
		("desc spaces", foo_with("%DESC%\n a  b \n\n")),
		("desc empty value", foo_with("%DESC%\n\n")),
		("crlf", foo(&base.replace('\n', "\r\n"))),
		(
			"not utf-8",
			vec![tar_file(
				"foo-1-1/desc",
				&[base.as_bytes(), b"%DESC%\n\xff\n\n"]
					.concat(),
			)],
		),
		(
			"section twice",
			foo_with("%DEPENDS%\na\n\n%DEPENDS%\nb\n\n"),
		),
		("same name twice", {
			let mut e = foo(&base);
			e.push(tar_file(
				"foo-2-1/desc",
				desc("foo", "2-1").as_bytes(),
			));
			e
		}),
		("%FILES% in desc", foo_with("%FILES%\nusr/\n\n")),
		("md5 without pgpsig", foo_with(&md5)),
		("csize text", foo(&base.replace("%CSIZE%\n1", "%CSIZE%\nx"))),
		(
			"sha256 upper",
			foo(&base.replace(&"ab".repeat(32), &"AB".repeat(32))),
		),
		("empty %GROUPS%", foo_with("%GROUPS%\n\n")),
		("blank lines", foo(&base.replace("\n\n", "\n\n\n"))),
		("optdepend no space", foo_with("%OPTDEPENDS%\na:b\n\n")),
		(
			"dep name with .so",
			foo_with("%DEPENDS%\nfoo.sound\nd1.so62r\n\n"),
		),
		(
			"dep pkgrel leading zero",
			foo_with("%DEPENDS%\na=1-01\nb<2-1.01\n\n"),
		),
		(
			"optdepend spaces",
			foo_with("%OPTDEPENDS%\na:  x  y \nb: \n\n"),
		),
		("dep bad version", foo_with("%DEPENDS%\na>=\n\n")),
		("long line", foo_with(&long)),
		("name mismatch", foo(&desc("bar", "1-1"))),
		("version mismatch", foo(&desc("foo", "2-1"))),
		("top-level file", vec![tar_file("foo-1-1", b"x")]),
		("unknown file", vec![tar_file("foo-1-1/mtree", b"x")]),
		(
			"nested desc",
			vec![tar_file("foo-1-1/a/desc", base.as_bytes())],
		),
		("bad entry name", vec![tar_file("foo/x", b"")]),
		("name starts with -", vec![tar_file("-foo-1-1/x", b"")]),
		// check_meta's character class only refuses names that match it
		// as a glob pattern
		("name is a glob", vec![tar_file("*-1-1/x", b"")]),
		("name with !", vec![tar_file("a!b-1-1/x", b"")]),
		(
			"long name",
			vec![tar_file(
				&format!("{}-1-1/x", "a".repeat(260)),
				b"",
			)],
		),
		("regular entry ending in /", vec![tar_file("foo-1-1/", b"")]),
		(
			"files absolute",
			vec![tar_file("foo-1-1/files", b"%FILES%\n/usr/\n")],
		),
		(
			"files no parent",
			vec![tar_file(
				"foo-1-1/files",
				b"%FILES%\nusr/bin/x\n",
			)],
		),
		("files in a .db", {
			let mut e = foo(&base);
			e.push(tar_file(
				"foo-1-1/files",
				b"%FILES%\nusr/\nusr/x\n",
			));
			e
		}),
		(
			"files without desc",
			vec![tar_file("foo-1-1/files", b"%FILES%\nusr/\n")],
		),
		(
			"depends without desc",
			vec![tar_file("foo-1-1/depends", b"%DEPENDS%\na\n\n")],
		),
		(
			"files dir and file",
			vec![tar_file(
				"foo-1-1/files",
				b"%FILES%\nusr\nusr/\n",
			)],
		),
		(
			"files duplicate",
			vec![tar_file(
				"foo-1-1/files",
				b"%FILES%\nusr/\nusr/\n",
			)],
		),
		(
			"files blank line inside",
			vec![tar_file(
				"foo-1-1/files",
				b"%FILES%\nusr/\n\nopt/\n",
			)],
		),
		(
			"files crlf",
			vec![tar_file("foo-1-1/files", b"%FILES%\r\nusr/\r\n")],
		),
		(
			"files after unknown key",
			vec![tar_file(
				"foo-1-1/files",
				b"%FOO%\nx\n\n%FILES%\nusr/\n",
			)],
		),
		("data without pkgtype", foo_with("%DATA%\na=b\n\n")),
		("header line in a list", foo_with("%GROUPS%\ng\n%URL%\n\n")),
		("empty archive", vec![]),
		// _alpm_strtoofft's unsigned long long wraps through off_t
		(
			"sizes past i64::MAX",
			foo(&base
				.replace(
					"%CSIZE%\n1",
					"%CSIZE%\n18446744073709551615",
				)
				.replace(
					"%ISIZE%\n2",
					"%ISIZE%\n9223372036854775808",
				)),
		),
	];
	for (label, entries) in cases {
		let (c, r, why) = run_case(&entries, Comp::None, ".db");
		eprintln!(
			"{label}: C {} / rust {} {why}",
			brief(&c.0),
			brief(&r.0)
		);
		assert_same(&c, &r, &|| {
			format!("{label}\n{}", describe(&entries))
		});
	}
}

fn brief(o: &Outcome) -> String {
	match o {
		Ok((p, _)) => format!("{} pkgs", p.len()),
		Err(e) => format!("errno {e}"),
	}
}

// archive level: what libarchive and alpm-compress/tar make of broken or
// unusual files
#[test]
fn odd_archives() {
	let good = ustar(&foo(&desc("foo", "1-1")));
	let bar = ustar(&[tar_file(
		"bar-1-1/desc",
		desc("bar", "1-1").as_bytes(),
	)]);
	let fx = TempRoot::new("be-sync");
	let p = fx.sync_file("t", ".db");
	let gz = |tar: &[u8]| {
		write_db(&p, Comp::Gzip, tar);
		fs::read(&p).unwrap()
	};
	// two gzip members, the first without the tar end blocks
	let mut two = gz(&good[..good.len() - 1024]);
	two.extend(gz(&bar));
	// a short stream, see compressed_cuts
	let mut truncated = gz(&good);
	truncated.truncate(truncated.len() / 2);
	let mut short_tar = good.clone();
	short_tar.truncate(700);
	let cases: Vec<(&str, Vec<u8>)> = vec![
		("empty file", Vec::new()),
		// refused at open (the first tar header): the db is invalid
		("garbage", b"not an archive at all\n".repeat(40)),
		("two gzip members", two),
		("truncated gzip", truncated),
		("truncated tar", short_tar),
		("no end blocks", good[..good.len() - 1024].to_vec()),
	];
	for (label, bytes) in cases {
		let fx = TempRoot::new("be-sync");
		fs::write(fx.sync_file("t", ".db"), &bytes).unwrap();
		let c = load_c(&fx, "t", ".db");
		let r = load_rust(&fx, "t", ".db");
		eprintln!("{label}: C {} / rust {}", brief(&c.0), brief(&r.0));
		assert_same(&c, &r, &|| label.into());
		assert_eq!(validity(&fx, "t"), c_validity(&fx, "t"), "{label}");
	}
}

// a db over several of libarchive's 64/128 KiB filter blocks: a desc per
// package, then an unknown entry both skip, sized to put the next header
// at or across a block boundary or at random, its data random so the
// compressed stream grows with it
fn big_db() -> Vec<TarEntry> {
	const BLOCK: usize = 64 * 1024;
	let mut rng = Rng::new(0xb16d_b5ed);
	let mut entries = Vec::new();
	let mut off: usize = 0;
	for i in 0.. {
		if off > 1300 * 1024 {
			break;
		}
		let name = format!("p{i:03}");
		let d = desc(&name, "1-1");
		entries.push(tar_file(
			&format!("{name}-1-1/desc"),
			d.as_bytes(),
		));
		off += 512 + d.len().next_multiple_of(512) + 512;
		let next = (off + 512 + 20000).next_multiple_of(BLOCK);
		let len = match i % 4 {
			0 => next - off,
			1 => next - off - 256,
			_ => rng.below(9000),
		};
		let pad: Vec<u8> =
			(0..len).map(|_| rng.next_u64() as u8).collect();
		entries.push(tar_file(&format!("{name}-1-1/pad"), &pad));
		off += len.next_multiple_of(512);
	}
	entries
}

// a compressed db cut short, at the start, evenly spread, at random and in
// the stream's tail: libarchive fails the filter block the stream ends
// in. inside the first one the open fails, later the walk meets it in a
// header or the data of a desc (both LIBARCHIVE or invalid entries, the
// cache dropped)
#[test]
fn compressed_cuts() {
	let tar = ustar(&big_db());
	let mut rng = Rng::new(0x0c07_5eed);
	let mut errnos = std::collections::BTreeSet::new();
	for comp in [Comp::Gzip, Comp::Bzip2, Comp::Xz, Comp::Zstd] {
		let fx = TempRoot::new("be-sync");
		let p = fx.sync_file("t", ".db");
		write_db(&p, comp, &tar);
		let data = fs::read(&p).unwrap();
		let len = data.len();
		let mut cuts: Vec<usize> = vec![1, 2, 10, 100];
		cuts.extend((1..48).map(|i| len * i / 48));
		cuts.extend((0..16).map(|_| rng.below(len)));
		cuts.extend([1, 4, 8, 9, 12, 20, 64].map(|d| len - d));
		for n in cuts {
			fs::write(&p, &data[..n]).unwrap();
			let c = load_c(&fx, "t", ".db");
			let r = load_rust(&fx, "t", ".db");
			let what = format!("{comp:?} cut at {n}/{len}");
			assert_same(&c, &r, &|| what.clone());
			assert_eq!(
				validity(&fx, "t"),
				c_validity(&fx, "t"),
				"{what}"
			);
			errnos.insert(c.0.err());
		}
	}
	assert!(errnos.len() >= 2, "{errnos:?}");
}

// a db registered on a handle after its cache load failed or not:
// pkgcache errno, then alpm_db_get_valid
fn validity(fx: &TempRoot, tree: &str) -> (c_int, (c_int, c_int)) {
	let mut h = Handle::initialize(&fx.path("root"), &fx.dbpath()).unwrap();
	h.register_syncdb(tree.as_bytes(), 0).unwrap();
	let ext = h.dbext().to_vec();
	let db = h
		.syncdbs_mut()
		.iter_mut()
		.find(|d| d.name() == tree.as_bytes())
		.unwrap();
	let e = db.pkgcache(&ext, &mut ()).err().map_or(0, |e| e as c_int);
	let valid = match db.valid() {
		Ok(()) => (0, 0),
		Err(e) => (-1, e as c_int),
	};
	(e, valid)
}

fn c_validity(fx: &TempRoot, tree: &str) -> (c_int, (c_int, c_int)) {
	let c = CHandle::new(&fx.path("root"), &fx.dbpath()).unwrap();
	c.register_syncdb(tree.as_bytes(), 0);
	let (_, e) = c.pkgcache(tree.as_bytes());
	(e, c.valid(tree.as_bytes()))
}

// the bytes a block edge splits differently: nul bytes before and
// without a '\n', empty lines, a list and a relation
const EDGE: &[u8] = b"%DESC%\na\0b\nc\0\0d\n\n%GROUPS%\ng\0h\ni\n\0\nj\n\n\
	%NAME%\nx\0\n\n%DEPENDS%\nq\0r\ns\n\n%URL%\nu\0v\n\n";

// entries whose desc data starts 512 bytes before a block edge of
// archive_read_data_block (util::Archive::block), with a filler line
// moving EDGE so the edge falls on each of its bytes. a pad entry before
// each desc (an unknown file, skipped) puts it there
fn edge_db(block: usize) -> Vec<TarEntry> {
	let mut rng = Rng::new(0xed9e);
	let mut entries = Vec::new();
	let mut off: usize = 0;
	for d in 0..=EDGE.len() {
		let name = format!("p{d:03}-1-1");
		// the pad's data start; the desc's data then starts 512
		// bytes before an edge
		let start = off + 512 + 512;
		let pad = (start + 1024).next_multiple_of(block) - 1024 - start;
		let data: Vec<u8> =
			(0..pad).map(|_| rng.next_u64() as u8).collect();
		entries.push(tar_file(&format!("{name}/pad"), &data));
		off = start + pad;
		let fill = 512 - d - 8;
		let mut desc = b"%PAD%\n".to_vec();
		desc.extend(vec![b'x'; fill]);
		desc.extend(b"\n\n");
		desc.extend(EDGE);
		off += 512 + desc.len().next_multiple_of(512);
		entries.push(tar_file(&format!("{name}/desc"), &desc));
	}
	entries
}

#[test]
fn block_edges() {
	for comp in COMPS {
		let block = match comp {
			Comp::Zstd => 128 * 1024,
			Comp::None => {
				// the fd reads: st_blksize, at least BUFSIZ
				let fx = TempRoot::new("be-sync");
				let p = fx.sync_file("t", ".db");
				fs::write(&p, b"").unwrap();
				let blk = fs::metadata(&p).unwrap().blksize();
				blk.max(8192) as usize
			}
			_ => 64 * 1024,
		};
		let entries = edge_db(block);
		let (c, r, why) = run_case(&entries, comp, ".db");
		assert_same(&c, &r, &|| format!("{comp:?} {why}"));
		let n = c.0.as_ref().map_or(0, |(p, _)| p.len());
		assert_eq!(n, EDGE.len() + 1, "{comp:?} {why}");
	}
}
