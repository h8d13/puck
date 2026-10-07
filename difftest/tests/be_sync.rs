// alpm_core::be_sync against the C sync db backend: repo dbs generated
// under /tmp (valid desc/files per the alpm-repo-db spec, every
// compression alpm-compress has), loaded by both, every field, the
// validation getter, the cache order and the table counts compared. odd
// inputs the C accepts pin each divergence; copies of the real sync dbs
// give counts
use std::fs;
use std::path::PathBuf;

use alpm_core::be_sync::{self, get_validation, populate};
use alpm_core::package::Package;
use difftest::{
	COMPS, CSyncDb, Comp, Rng, TarEntry, TempRoot, c_sync_db_load, iters,
	section, tar_dir, tar_file, ustar, write_db,
};

// one db per iteration, a C handle each: far slower than string fuzz
fn db_iters() -> usize {
	(iters() / 100).max(100)
}

// what a load gives, comparable across both sides: packages with
// validation getter result, (entries, buckets, limit), or the pm_errno
type Outcome = Result<(Vec<(Package, i32)>, (usize, usize, usize)), i32>;

fn load_c(fx: &TempRoot, tree: &str, ext: &str) -> Outcome {
	let db = c_sync_db_load(
		&fx.dir().join("root"),
		&fx.dir().join("db"),
		tree.as_bytes(),
		ext.as_bytes(),
	)?;
	let CSyncDb {
		pkgs,
		validation,
		counts,
	} = db;
	Ok((pkgs.into_iter().zip(validation).collect(), counts))
}

fn load_rust(fx: &TempRoot, tree: &str, ext: &str) -> Outcome {
	let path =
		be_sync::db_path(&fx.dbpath(), tree.as_bytes(), ext.as_bytes());
	let cache = populate(&path, ext.as_bytes())
		.map_err(|e| e.errno() as i32)?;
	let counts = (cache.len(), cache.buckets(), cache.limit());
	let pkgs = cache.iter().map(|p| (p.clone(), get_validation(p)));
	Ok((pkgs.collect(), counts))
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
	let rel = match rng.below(4) {
		0 => format!("{}.{}", 1 + rng.below(9), rng.below(9)),
		_ => format!("{}", 1 + rng.below(20)),
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
	words.join(" ")
}

// relation lines stay far below 512 bytes, the smallest first data block
// libarchive hands out: READ_AND_SPLITDEP parses a stale `line` once a
// longer line makes _alpm_archive_fgets reallocate its buffer
fn relation(rng: &mut Rng) -> String {
	// alpm-types refuses names like "foo.sound" here, see odd_inputs
	let mut name = pkg_name(rng);
	while name.contains(".so") {
		name = pkg_name(rng);
	}
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
		_ => format!("{name}: {}", description(rng)),
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

// relative paths with every parent listed, no duplicates
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
		let twin = format!("{parent}{leaf}");
		let clash = out.iter().any(|o| o.trim_end_matches('/') == twin);
		if clash || leaf == "." || leaf == ".." {
			continue;
		}
		if is_dir {
			dirs.push(p.clone());
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
			&one(format!(
				"{} {} <{}@{}.org>",
				word(rng, ALNUM, 1, 8),
				word(rng, ALNUM, 1, 8),
				word(rng, LOWER, 1, 8),
				word(rng, LOWER, 1, 8)
			)),
		),
	];
	if rng.below(4) != 0 {
		fixed.push(section("DESC", &one(description(rng))));
	}
	if rng.below(3) != 0 {
		let path =
			list(rng, 3, |r| word(r, b"abcz09_-", 1, 6)).join("/");
		let host = word(rng, LOWER, 1, 8);
		fixed.push(section(
			"URL",
			&one(format!("https://{host}.org/{path}")),
		));
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
	// v1 needs %PGPSIG% alongside %MD5SUM%
	if fixed.iter().any(|s| s.starts_with("%MD5SUM%")) {
		fixed.push(section("PGPSIG", &one(base64(rng, 20))));
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
	Gen {
		dir: format!("{name}-{version}"),
		desc: fixed.concat(),
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

fn assert_same(c: &Outcome, r: &Outcome, ctx: &dyn Fn() -> String) {
	match (c, r) {
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
				assert_eq!(a, b, "package\n{}", ctx());
			}
			assert_eq!(
				cc,
				rc,
				"entries, buckets, limit\n{}",
				ctx()
			);
		}
		_ => assert_eq!(c, r, "outcome\n{}", ctx()),
	}
}

// C and rust outcomes, plus the rust error in full
fn run_case(
	entries: &[TarEntry],
	comp: Comp,
	ext: &str,
) -> (Outcome, Outcome, String) {
	let fx = TempRoot::new("be-sync");
	write_db(&fx.sync_file("repo", ext), comp, &ustar(entries));
	let path = be_sync::db_path(&fx.dbpath(), b"repo", ext.as_bytes());
	let why = match populate(&path, ext.as_bytes()) {
		Err(e) => format!("{e:?}"),
		Ok(_) => String::new(),
	};
	(load_c(&fx, "repo", ext), load_rust(&fx, "repo", ext), why)
}

fn fuzz(seed: u64, files_db: bool) {
	let mut rng = Rng::new(seed);
	let ext = if files_db { ".files" } else { ".db" };
	let mut pkgs = 0;
	for _ in 0..db_iters() {
		let (entries, gens) = gen_db(&mut rng, files_db);
		let comp = COMPS[rng.below(COMPS.len())];
		let (c, r, why) = run_case(&entries, comp, ext);
		let ctx = || {
			format!("{comp:?} {ext} {why}\n{}", describe(&entries))
		};
		assert_same(&c, &r, &ctx);
		assert!(c.is_ok(), "valid db refused: {c:?}\n{}", ctx());
		pkgs += gens.len();
	}
	assert!(pkgs > db_iters(), "too few packages compared: {pkgs}");
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
		assert!(c.is_ok());
	}
}

#[test]
fn missing_db() {
	let fx = TempRoot::new("be-sync");
	let c = load_c(&fx, "nope", ".db");
	assert_eq!(c, load_rust(&fx, "nope", ".db"));
	assert_eq!(c, Err(alpm_core::error::Errno::DbNotFound as i32));
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

// copies of the real sync dbs, read only: counts of packages per
// differing field. no assertion on the fields, the divergences are
// listed in PORTING.md
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
		let path = be_sync::db_path(
			&fx.dbpath(),
			tree.as_bytes(),
			ext.as_bytes(),
		);
		let r = populate(&path, ext.as_bytes());
		let (cp, _) = c.as_ref().expect("C refused a real db");
		let r = match r {
			Ok(r) => r,
			Err(e) => {
				eprintln!(
					"{name}: C {} packages, rust {e:?}",
					cp.len()
				);
				continue;
			}
		};
		let rp: Vec<&Package> = r.iter().collect();
		let mut fields: std::collections::BTreeMap<&str, usize> =
			Default::default();
		let mut differing = 0;
		let mut urls = Vec::new();
		// url diffs that are only the '/' url::Url adds to an empty path
		let mut slash = 0;
		for ((c, _), r) in cp.iter().zip(&rp) {
			assert_eq!(c.name, r.name, "{name}: cache order");
			let d = diff_fields(c, r);
			let added =
				c.url.as_ref().map(|u| [&u[..], b"/"].concat());
			slash += usize::from(c.url != r.url && added == r.url);
			if d.contains(&"url")
				&& c.url != r.url && added != r.url
			{
				let show = |p: &Package| {
					String::from_utf8_lossy(
						p.url.as_deref()
							.unwrap_or_default(),
					)
					.into_owned()
				};
				urls.push(format!(
					"{} -> {}",
					show(c),
					show(r)
				));
			}
			differing += usize::from(!d.is_empty());
			for f in d {
				*fields.entry(f).or_default() += 1;
			}
		}
		assert_eq!(cp.len(), rp.len(), "{name}: package count");
		eprintln!(
			"{name}: {} packages, {} identical, {differing} differ {:?}, \
			{slash} url diffs are a trailing '/'",
			cp.len(),
			cp.len() - differing,
			fields
		);
		for u in &urls {
			eprintln!("  url {u}");
		}
		assert!(urls.is_empty(), "{name}: other url normalization");
		let known = fields.keys().all(|&f| f == "url");
		assert!(known, "{name}: new divergence {fields:?}");
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

#[derive(Debug, PartialEq)]
enum Expect {
	Same,
	Diverge,
}

// inputs pacman accepts or refuses in its own way. Same: both sides agree
// (outcome and every field). Diverge: the documented C vs alpm-repo-db
// (or libarchive vs alpm-compress) differences
#[test]
fn odd_inputs() {
	use Expect::*;
	let base = desc("foo", "1-1");
	let md5 = format!("%MD5SUM%\n{}\n\n", "0".repeat(32));
	let long = format!("%DESC%\n{}\n\n", "x".repeat(600 * 1024));
	let cases: Vec<(&str, Vec<TarEntry>, Expect)> = vec![
		("minimal", foo(&base), Same),
		("url no path", foo_with("%URL%\nhttps://a.org\n\n"), Diverge),
		(
			"url with path",
			foo_with("%URL%\nhttps://a.org/x\n\n"),
			Same,
		),
		("unknown key", foo_with("%FOO%\nbar\n\n"), Diverge),
		("xdata", foo_with("%DATA%\npkgtype=pkg\n\n"), Diverge),
		(
			"no %BASE%",
			foo(&base.replace("%BASE%\nfoo\n\n", "")),
			Diverge,
		),
		(
			"no %PACKAGER%",
			foo(&base.replace("%PACKAGER%\nA B <a@b.org>\n\n", "")),
			Diverge,
		),
		("empty desc", foo(""), Diverge),
		("desc spaces", foo_with("%DESC%\n a  b \n\n"), Diverge),
		("desc empty value", foo_with("%DESC%\n\n"), Diverge),
		("crlf", foo(&base.replace('\n', "\r\n")), Diverge),
		(
			"not utf-8",
			vec![tar_file(
				"foo-1-1/desc",
				&[base.as_bytes(), b"%DESC%\n\xff\n\n"]
					.concat(),
			)],
			Diverge,
		),
		(
			"section twice",
			foo_with("%DEPENDS%\na\n\n%DEPENDS%\nb\n\n"),
			Diverge,
		),
		(
			"same name twice",
			{
				let mut e = foo(&base);
				e.push(tar_file(
					"foo-2-1/desc",
					desc("foo", "2-1").as_bytes(),
				));
				e
			},
			Diverge,
		),
		("%FILES% in desc", foo_with("%FILES%\nusr/\n\n"), Diverge),
		("md5 without pgpsig", foo_with(&md5), Diverge),
		(
			"csize text",
			foo(&base.replace("%CSIZE%\n1", "%CSIZE%\nx")),
			Diverge,
		),
		(
			"sha256 upper",
			foo(&base.replace(&"ab".repeat(32), &"AB".repeat(32))),
			Diverge,
		),
		("empty %GROUPS%", foo_with("%GROUPS%\n\n"), Diverge),
		("blank lines", foo(&base.replace("\n\n", "\n\n\n")), Diverge),
		(
			"optdepend no space",
			foo_with("%OPTDEPENDS%\na:b\n\n"),
			Diverge,
		),
		// RelationOrSoname: SonameV1 fails without backtracking
		(
			"dep name with .so",
			foo_with("%DEPENDS%\nfoo.sound\n\n"),
			Diverge,
		),
		("dep bad version", foo_with("%DEPENDS%\na>=\n\n"), Diverge),
		("long line", foo_with(&long), Diverge),
		("name mismatch", foo(&desc("bar", "1-1")), Same),
		("version mismatch", foo(&desc("foo", "2-1")), Same),
		("top-level file", vec![tar_file("foo-1-1", b"x")], Same),
		("unknown file", vec![tar_file("foo-1-1/mtree", b"x")], Same),
		(
			"nested desc",
			vec![tar_file("foo-1-1/a/desc", base.as_bytes())],
			Same,
		),
		("bad entry name", vec![tar_file("foo/x", b"")], Same),
		(
			"name starts with -",
			vec![tar_file("-foo-1-1/x", b"")],
			Same,
		),
		// check_meta's character class only refuses names that match it
		// as a glob pattern
		("name is a glob", vec![tar_file("*-1-1/x", b"")], Same),
		("name with !", vec![tar_file("a!b-1-1/x", b"")], Same),
		(
			"long name",
			vec![tar_file(
				&format!("{}-1-1/x", "a".repeat(260)),
				b"",
			)],
			Same,
		),
		(
			"regular entry ending in /",
			vec![tar_file("foo-1-1/", b"")],
			Same,
		),
		(
			"files absolute",
			vec![tar_file("foo-1-1/files", b"%FILES%\n/usr/\n")],
			Diverge,
		),
		(
			"files no parent",
			vec![tar_file(
				"foo-1-1/files",
				b"%FILES%\nusr/bin/x\n",
			)],
			Diverge,
		),
		(
			"files in a .db",
			{
				let mut e = foo(&base);
				e.push(tar_file(
					"foo-1-1/files",
					b"%FILES%\nusr/\nusr/x\n",
				));
				e
			},
			Same,
		),
		(
			"files without desc",
			vec![tar_file("foo-1-1/files", b"%FILES%\nusr/\n")],
			Same,
		),
		(
			"depends without desc",
			vec![tar_file("foo-1-1/depends", b"%DEPENDS%\na\n\n")],
			Diverge,
		),
		("empty archive", vec![], Same),
	];
	let mut report = Vec::new();
	for (label, entries, expect) in cases {
		let (c, r, why) = run_case(&entries, Comp::None, ".db");
		let got = if c == r { Same } else { Diverge };
		let detail = match (&c, &r) {
			(Ok((cp, _)), Ok((rp, _))) if got == Diverge => {
				let d = cp.iter().zip(rp);
				let d = d.flat_map(|((a, _), (b, _))| {
					diff_fields(a, b)
				});
				format!("{:?}", d.collect::<Vec<_>>())
			}
			_ => why.chars().take(200).collect(),
		};
		report.push(format!(
			"{label}: C {} / rust {} {detail}",
			brief(&c),
			brief(&r)
		));
		assert_eq!(got, expect, "{label}\nC {c:?}\nrust {r:?}");
	}
	for line in report {
		eprintln!("{line}");
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
	use Expect::*;
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
	let mut truncated = gz(&good);
	truncated.truncate(truncated.len() / 2);
	let mut short_tar = good.clone();
	short_tar.truncate(700);
	let cases: Vec<(&str, Vec<u8>, Expect)> = vec![
		("empty file", Vec::new(), Same),
		// errno only: libarchive refuses at open, tar at the first header
		("garbage", b"not an archive at all\n".repeat(40), Diverge),
		("two gzip members", two, Diverge),
		("truncated gzip", truncated, Diverge),
		("truncated tar", short_tar, Same),
		("no end blocks", good[..good.len() - 1024].to_vec(), Same),
	];
	for (label, bytes, expect) in cases {
		let fx = TempRoot::new("be-sync");
		fs::write(fx.sync_file("t", ".db"), &bytes).unwrap();
		let c = load_c(&fx, "t", ".db");
		let r = load_rust(&fx, "t", ".db");
		let got = if c == r { Same } else { Diverge };
		eprintln!("{label}: C {} / rust {}", brief(&c), brief(&r));
		assert_eq!(got, expect, "{label}\nC {c:?}\nrust {r:?}");
	}
}
