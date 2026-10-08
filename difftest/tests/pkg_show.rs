// pacman_cli::package against src/pacman/package.c, both sides in
// C.UTF-8 with TZ=UTC. the C runs on a real handle (PkgWorld) whose db
// caches hold the same random packages the Rust env answers from
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use alpm_core::backup::Backup;
use alpm_core::deps::{DepMod, Depend, dep_compute_string, find_satisfier};
use alpm_core::error::Errno;
use alpm_core::filelist::{File, FileList};
use alpm_core::package::{
	DbCaches, Package, PkgFrom, PkgReason, PkgXData, compute_optionalfor,
	compute_requiredby, pkg_find,
};
use alpm_core::util::hash_sdbm;
use alpm_types::Md5Checksum;
use difftest::{
	CShown, PkgWorld, Rng, SYNC_DBS, c_print_groups, c_strftime_c,
	encode_base64, iters, random_sig, sig_packet, utc_date, widths_agree,
};
use pacman_cli::package::{
	FileProbe, PkgEnv, dump_pkg_backups, dump_pkg_files, dump_pkg_full,
	dump_pkg_search, print_groups, print_installed,
};
use pacman_cli::util::{ColStr, SigResult};

// fresh dir under /tmp: PkgWorld in world/, a package file for the file
// origin next to it, removed on drop (after the world)
struct Fx {
	base: PathBuf,
	world: Option<PkgWorld>,
}

impl Fx {
	fn new(name: &str) -> Self {
		static N: AtomicUsize = AtomicUsize::new(0);
		let n = N.fetch_add(1, Ordering::Relaxed);
		let base = std::env::temp_dir().join(format!(
			"difftest-pkg-show-{name}-{}-{n}",
			std::process::id()
		));
		if base.exists() {
			fs::remove_dir_all(&base).unwrap();
		}
		fs::create_dir(&base).unwrap();
		fs::write(base.join("pkg.tar"), b"not checked\n").unwrap();
		let world = PkgWorld::new(&base.join("world"));
		let fx = Fx {
			base,
			world: Some(world),
		};
		fx.backup_files();
		fx
	}

	fn w(&self) -> &PkgWorld {
		self.world.as_ref().unwrap()
	}

	fn w_mut(&mut self) -> &mut PkgWorld {
		self.world.as_mut().unwrap()
	}

	fn pkgfile(&self) -> Vec<u8> {
		self.base.join("pkg.tar").as_os_str().as_bytes().to_vec()
	}

	fn root(&self) -> PathBuf {
		Path::new(std::ffi::OsStr::from_bytes(self.w().root()))
			.to_path_buf()
	}

	// one file per backup state, see BACKUP_NAMES
	fn backup_files(&self) {
		let etc = self.root().join("etc");
		fs::create_dir(&etc).unwrap();
		fs::write(etc.join("a"), b"alpha\n").unwrap();
		fs::write(etc.join("b"), b"").unwrap();
		fs::write(etc.join("f"), b"file, not a dir\n").unwrap();
		fs::write(etc.join("locked"), b"secret\n").unwrap();
		let mode = fs::Permissions::from_mode(0o000);
		fs::set_permissions(etc.join("locked"), mode).unwrap();
		symlink("loop", etc.join("loop")).unwrap();
		symlink("a", etc.join("link")).unwrap();
	}
}

impl Drop for Fx {
	fn drop(&mut self) {
		self.world = None;
		fs::remove_dir_all(&self.base).unwrap();
	}
}

// readable (a, b, link, locked as root), EACCES (locked), ENOENT,
// ENOTDIR and ELOOP ([unknown]). no directories, see dump_full
const BACKUP_NAMES: &[&[u8]] = &[
	b"etc/a",
	b"etc/b",
	b"etc/link",
	b"etc/locked",
	b"etc/none",
	b"none/x",
	b"etc/f/x",
	b"etc/loop",
	b"etc/a\xc3 b",
];

fn md5(b: &[u8]) -> Vec<u8> {
	Md5Checksum::calculate_from(b).to_string().into_bytes()
}

// pieces of display text: words, spaces, wide (2), combining (0), non
// printable (tab, C1 control), invalid UTF-8 and a whole colour sequence.
// no broken ESC sequences: list items go through string_length. only
// characters glibc and unicode-width give the same width (tokens_agree)
const TOKENS: &[&[u8]] = &[
	b"a",
	b"bc",
	b"defgh",
	b"ijklmnopqrst",
	b" ",
	b" ",
	b"  ",
	"\u{3042}".as_bytes(),
	"e\u{301}".as_bytes(),
	b"\t",
	"\u{85}".as_bytes(),
	b"\xff",
	b"\xc3",
	b"\x1b[1m",
	b"=",
	b":",
];

const NAMES: &[&[u8]] = &[b"a", b"b", b"foo", b"lib-x", b"\xc3\xa9t\xc3\xa9"];
const VERSIONS: &[&[u8]] = &[b"1", b"1.0", b"2:1-1", b"1.5-2"];
const MODS: [DepMod; 6] = [
	DepMod::Any,
	DepMod::Eq,
	DepMod::Ge,
	DepMod::Le,
	DepMod::Gt,
	DepMod::Lt,
];
const REASONS: [PkgReason; 3] =
	[PkgReason::Explicit, PkgReason::Depend, PkgReason::Unknown];
const COLS: [u16; 10] = [0, 1, 10, 17, 18, 30, 50, 80, 120, 300];

#[test]
fn tokens_agree() {
	for t in TOKENS {
		assert!(widths_agree(t), "{}", lossy(t));
	}
}

fn text(rng: &mut Rng, max: usize) -> Vec<u8> {
	(0..rng.below(max))
		.flat_map(|_| TOKENS[rng.below(TOKENS.len())])
		.copied()
		.collect()
}

fn opt_text(rng: &mut Rng, max: usize) -> Option<Vec<u8>> {
	(rng.below(5) != 0).then(|| text(rng, max))
}

fn some_of<T>(rng: &mut Rng, n: usize, f: impl Fn(&mut Rng) -> T) -> Vec<T> {
	(0..rng.below(n)).map(|_| f(rng)).collect()
}

fn pick<T: Copy>(rng: &mut Rng, xs: &[T]) -> T {
	xs[rng.below(xs.len())]
}

// names and versions from small sets, so dependencies resolve often
fn random_dep(rng: &mut Rng) -> Depend {
	let name = pick(rng, NAMES).to_vec();
	let depmod = pick(rng, &MODS);
	Depend {
		name_hash: hash_sdbm(&name),
		name: name.into(),
		version: (depmod != DepMod::Any || rng.below(4) == 0)
			.then(|| pick(rng, VERSIONS).into()),
		desc: (rng.below(4) == 0).then(|| text(rng, 4)).map(Box::from),
		depmod,
	}
}

fn deps(rng: &mut Rng) -> Vec<Depend> {
	some_of(rng, 4, random_dep)
}

fn named(name: &[u8], version: &[u8]) -> Package {
	Package {
		name_hash: hash_sdbm(name),
		name: Some(name.into()),
		version: Some(version.into()),
		..Package::default()
	}
}

// a db cache: unique names, random relations
fn random_cache(rng: &mut Rng) -> Vec<Package> {
	let mut names: Vec<&[u8]> = NAMES.to_vec();
	names.retain(|_| rng.below(2) == 0);
	names.into_iter()
		.map(|n| Package {
			depends: deps(rng).into(),
			optdepends: deps(rng).into(),
			provides: deps(rng).into(),
			groups: some_of(rng, 3, |r| text(r, 3).into()).into(),
			desc: opt_text(rng, 12).map(Box::from),
			..named(n, pick(rng, VERSIONS))
		})
		.collect()
}

// dates both sides format (time's years -9999 to 9999, see date_range),
// -1 for unset
fn random_date(rng: &mut Rng) -> i64 {
	match rng.below(6) {
		0 => -1,
		1 => 0,
		2 => rng.below(4_000_000_000) as i64,
		3 => -(rng.below(70_000_000_000) as i64),
		4 => {
			TIME_MIN + rng.below((TIME_MAX - TIME_MIN) as usize)
				as i64
		}
		_ => 1_700_000_000 + rng.below(100_000_000) as i64,
	}
}

fn random_size(rng: &mut Rng) -> i64 {
	match rng.below(4) {
		0 => rng.below(4096) as i64,
		1 => rng.below(1 << 40) as i64,
		2 => -(rng.below(1 << 30) as i64),
		_ => rng.next_u64() as i64,
	}
}

fn random_backup(rng: &mut Rng) -> Backup {
	let name = pick(rng, BACKUP_NAMES).to_vec();
	let hash = match rng.below(5) {
		0 => None,
		1 => Some(md5(b"alpha\n")),
		2 => Some(md5(b"")),
		3 => Some(md5(b"secret\n")),
		_ => Some(text(rng, 6)),
	};
	Backup {
		name: name.into(),
		hash: hash.map(Box::from),
	}
}

// the package dump_pkg_full shows, with the keys of its signature
fn random_pkg(rng: &mut Rng, fx: &Fx, extra: bool) -> (Package, Vec<Vec<u8>>) {
	let origin = match rng.below(if extra { 3 } else { 4 }) {
		0 => Some(PkgFrom::LocalDb),
		1 => Some(PkgFrom::SyncDb),
		2 => Some(PkgFrom::File(fx.pkgfile().into())),
		_ => None,
	};
	let file = matches!(origin, Some(PkgFrom::File(_)));
	let (sig, keys) = if file {
		(None, Vec::new())
	} else {
		random_sig(rng)
	};
	let name = if rng.below(4) == 0 {
		text(rng, 4)
	} else {
		pick(rng, NAMES).to_vec()
	};
	let pkg = Package {
		name_hash: hash_sdbm(&name),
		name: Some(name.into()),
		filename: file.then(|| fx.pkgfile()).map(Box::from),
		version: (rng.below(6) != 0)
			.then(|| pick(rng, VERSIONS).into()),
		desc: opt_text(rng, 30).map(Box::from),
		url: opt_text(rng, 6).map(Box::from),
		packager: opt_text(rng, 6).map(Box::from),
		sha256sum: opt_text(rng, 4).map(Box::from),
		base64_sig: sig.map(Box::from),
		arch: opt_text(rng, 3).map(Box::from),
		builddate: random_date(rng),
		installdate: random_date(rng),
		size: random_size(rng),
		isize: random_size(rng),
		licenses: some_of(rng, 5, |r| text(r, 4).into()).into(),
		groups: some_of(rng, 4, |r| text(r, 3).into()).into(),
		replaces: deps(rng).into(),
		depends: some_of(rng, 8, random_dep).into(),
		optdepends: some_of(rng, 6, random_dep).into(),
		conflicts: deps(rng).into(),
		provides: deps(rng).into(),
		backup: some_of(rng, 6, random_backup).into(),
		origin,
		reason: pick(rng, &REASONS),
		scriptlet: if rng.below(2) == 0 {
			0
		} else {
			rng.next_u64() as i32
		},
		xdata: some_of(rng, 4, |r| PkgXData {
			name: text(r, 3).into(),
			value: text(r, 5).into(),
		})
		.into(),
		validation: rng.below(16) as i32,
		..Package::default()
	};
	(pkg, keys)
}

fn colstr(rng: &mut Rng) -> ColStr<'static> {
	if rng.below(2) == 0 {
		ColStr::COLOR
	} else {
		ColStr::PLAIN
	}
}

// the Rust side of what the C asked libalpm: the db caches the world
// holds (reverse deps and satisfiers are computed from them), the db, the
// keys the signature was built from, real files under the fixture root
struct Env<'a> {
	// local, core, extra as given to set_caches
	caches: [&'a [Package]; 3],
	db: usize,
	keys: Vec<Vec<u8>>,
	root: Vec<u8>,
	errors: Vec<Vec<u8>>,
}

impl<'a> Env<'a> {
	fn new(fx: &Fx, caches: [&'a [Package]; 3]) -> Self {
		Env {
			caches,
			db: 0,
			keys: Vec::new(),
			root: fx.w().root().to_vec(),
			errors: Vec::new(),
		}
	}
}

// _alpm_db_add_pkgincache keeps the cache list sorted by name
fn cache_list(pkgs: &[Package]) -> Vec<&Package> {
	let mut list: Vec<&Package> = pkgs.iter().collect();
	list.sort_by(|a, b| a.name_bytes().cmp(b.name_bytes()));
	list
}

impl DbCaches for Env<'_> {
	fn local_cache(&mut self) -> Vec<&Package> {
		cache_list(self.caches[0])
	}

	fn sync_caches(&mut self) -> Vec<Vec<&Package>> {
		vec![cache_list(self.caches[1]), cache_list(self.caches[2])]
	}
}

impl PkgEnv for Env<'_> {
	fn db_name(&mut self, _: &Package) -> Option<Vec<u8>> {
		Some(SYNC_DBS[self.db].as_bytes().to_vec())
	}

	// the C side's TZ=UTC
	fn format_date(&mut self, t: i64) -> Option<Vec<u8>> {
		utc_date(t)
	}

	fn sig_keys(&mut self, _: &Package, _: &[u8]) -> Vec<Vec<u8>> {
		self.keys.clone()
	}

	// the only result the C can reach here, see PkgWorld::dump_full
	fn check_signature(
		&mut self,
		_: &Package,
	) -> Result<Vec<SigResult>, Errno> {
		Err(Errno::SigMissing)
	}

	fn root(&mut self) -> Vec<u8> {
		self.root.clone()
	}

	fn probe_file(&mut self, path: &[u8]) -> FileProbe {
		use std::io::ErrorKind::*;
		match fs::read(std::ffi::OsStr::from_bytes(path)) {
			Ok(b) => FileProbe::Readable(Some(md5(&b))),
			Err(e) if e.kind() == PermissionDenied => {
				FileProbe::Denied
			}
			Err(e) if e.kind() == NotFound => FileProbe::Missing,
			Err(_) => FileProbe::Failed,
		}
	}

	fn changelog(&mut self, _: &Package) -> Option<Vec<u8>> {
		None
	}

	fn error(&mut self, msg: &[u8]) {
		self.errors.push(msg.to_vec());
	}
}

fn lossy(b: &[u8]) -> String {
	String::from_utf8_lossy(b).into_owned()
}

#[track_caller]
fn same(c: &[u8], r: &[u8], what: &dyn std::fmt::Debug) {
	assert!(c == r, "{what:?}\nC:\n{}\nrust:\n{}", lossy(c), lossy(r));
}

// first and last second of the years time covers (-9999 to 9999). the C
// goes on to tm_year past int: there it formats and the port gives None
const TIME_MIN: i64 = -377_705_116_800;
const TIME_MAX: i64 = 253_402_300_799;

// port and C agree inside time's range, outside it the port has None
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum DateClass {
	Same,
	// C formats, port None (years past 9999 or before -9999)
	OnlyC,
	// localtime fails, both None
	Neither,
}

#[track_caller]
fn date_class(t: i64) -> DateClass {
	let (c, r) = (c_strftime_c(t), utc_date(t));
	let class = match (&c, &r) {
		(Some(_), Some(_)) => DateClass::Same,
		(Some(_), None) => DateClass::OnlyC,
		(None, None) => DateClass::Neither,
		(None, Some(_)) => panic!("{t}: port formats, C cannot"),
	};
	let show = |s: &Option<Vec<u8>>| s.as_deref().map(lossy);
	if class == DateClass::Same {
		assert_eq!(show(&c), show(&r), "{t}");
	}
	assert_eq!(
		class == DateClass::OnlyC,
		!(TIME_MIN..=TIME_MAX).contains(&t) && c.is_some(),
		"{t}"
	);
	class
}

#[test]
fn date_fixed() {
	use DateClass::*;
	let cases = [
		(0, Same),
		(-1, Same),
		(1, Same),
		(86_399, Same),
		(86_400, Same),
		(951_782_400, Same),
		(1_700_000_000, Same),
		(-62_135_596_800, Same),
		(-62_135_596_801, Same),
		(-62_167_219_200, Same),
		(-62_198_755_200, Same),
		(-30_000_000_000, Same),
		(-80_000_000_000, Same),
		(253_402_300_799, Same),
		(253_402_300_800, OnlyC),
		(i64::from(i32::MAX), Same),
		(i64::from(i32::MIN), Same),
		(i64::MAX, Neither),
		(i64::MIN, Neither),
	];
	for (t, want) in cases {
		assert_eq!(date_class(t), want, "{t}");
	}
	assert_eq!(utc_date(0).unwrap(), b"Thu Jan  1 00:00:00 1970".to_vec());
}

// time's range and the localtime limits, found on the C, plus one past
#[test]
fn date_range() {
	use DateClass::*;
	for (t, want) in [
		(TIME_MIN, Same),
		(TIME_MAX, Same),
		(TIME_MIN - 1, OnlyC),
		(TIME_MAX + 1, OnlyC),
	] {
		assert_eq!(date_class(t), want, "{t}");
	}
	assert_eq!(
		c_strftime_c(TIME_MAX + 1).unwrap(),
		b"Sat Jan  1 00:00:00 10000".to_vec()
	);
	let edge = |mut ok: i64, mut bad: i64| {
		while ok.abs_diff(bad) > 1 {
			let mid = ok + (bad - ok) / 2;
			if c_strftime_c(mid).is_some() {
				ok = mid;
			} else {
				bad = mid;
			}
		}
		(ok, bad)
	};
	for (ok, bad) in [edge(0, i64::MAX), edge(0, i64::MIN)] {
		assert_eq!(date_class(ok), OnlyC, "{ok}");
		assert_eq!(date_class(bad), Neither, "{bad}");
		assert_eq!(date_class(bad + (bad - ok)), Neither, "{bad}");
	}
}

#[test]
fn date_fuzz() {
	let mut rng = Rng::new(0xda7e);
	let mut seen = std::collections::BTreeMap::new();
	let n = iters();
	for _ in 0..n {
		let t = match rng.below(4) {
			0 => rng.next_u64() as i64,
			1 => (rng.next_u64() >> 8) as i64 - (1 << 55),
			2 => (rng.next_u64() >> 28) as i64 - (1 << 35),
			_ => (rng.next_u64() >> 31) as i64 - (1 << 32),
		};
		*seen.entry(date_class(t)).or_insert(0usize) += 1;
	}
	println!("{seen:?}");
	// per 1000 inputs, about 3/4 of the rates measured with 200000
	for (k, per_1000) in [
		(DateClass::Same, 370),
		(DateClass::OnlyC, 180),
		(DateClass::Neither, 180),
	] {
		let got = seen.get(&k).copied().unwrap_or(0);
		assert!(got * 1000 >= n * per_1000, "{k:?}: {got} of {n}");
	}
}

// caches: what the world's caches were set to (local, core, extra)
fn run_full(
	fx: &Fx,
	rng: &mut Rng,
	pkg: &Package,
	keys: Vec<Vec<u8>>,
	extra: bool,
	caches: [&[Package]; 3],
) -> CShown {
	let (db, cols, cs) = (rng.below(2), pick(rng, &COLS), colstr(rng));
	let shown = fx.w().dump_full(pkg, db, extra, cols, &cs);
	let mut env = Env::new(fx, caches);
	env.db = db;
	env.keys = keys;
	let local = pkg.origin == Some(PkgFrom::LocalDb);
	// the values the C got from libalpm, recomputed by the port
	if extra || local {
		let (r, o) = (&shown.required_by, &shown.optional_for);
		assert_eq!(r, &compute_requiredby(pkg, &mut env), "{pkg:?}");
		assert_eq!(o, &compute_optionalfor(pkg, &mut env), "{pkg:?}");
	}
	if local {
		let installed: Vec<Vec<u8>> = pkg
			.optdepends
			.iter()
			.map(dep_compute_string)
			.filter(|s| {
				find_satisfier(env.local_cache(), s).is_some()
			})
			.collect();
		assert_eq!(shown.installed, installed, "{pkg:?}");
	}
	let mut out = Vec::new();
	dump_pkg_full(&mut out, &mut env, pkg, extra, cols, &cs);
	let what = (pkg, extra, cols, cs.title, &shown.required_by);
	same(&shown.out, &out, &what);
	assert!(env.errors.is_empty());
	shown
}

// how often the fuzz reached the parts that need a db or the root
#[derive(Default, Debug)]
struct Reached {
	required_by: usize,
	installed: usize,
	keys: usize,
	backups: usize,
	file: usize,
}

// one package per origin with every list set and -i/-ii, against fixed
// caches where the reverse dependencies and satisfiers resolve
#[test]
fn full_fixed() {
	let mut fx = Fx::new("fixed");
	let dep = |n: &[u8]| Depend {
		name_hash: hash_sdbm(n),
		name: n.into(),
		version: None,
		desc: None,
		depmod: DepMod::Any,
	};
	let user = |n: &[u8]| Package {
		depends: vec![dep(b"foo")].into(),
		optdepends: vec![dep(b"foo")].into(),
		..named(n, b"1")
	};
	let local = [user(b"b"), user(b"a"), named(b"bar", b"2")];
	let sync = [user(b"z"), user(b"c")];
	fx.w_mut().set_caches(&local, [&sync[..], &sync[..1]]);
	let caches = [&local[..], &sync[..], &sync[..1]];
	let base = Package {
		desc: Some(
			b"a package with a long description to wrap"[..].into()
		),
		licenses: vec![b"GPL"[..].into(), b"MIT"[..].into()].into(),
		optdepends: vec![dep(b"bar"), dep(b"nope")].into(),
		backup: BACKUP_NAMES
			.iter()
			.map(|n| Backup {
				name: n[..].into(),
				hash: Some(md5(b"alpha\n").into()),
			})
			.collect(),
		xdata: vec![PkgXData {
			name: b"pkgtype"[..].into(),
			value: b"pkg"[..].into(),
		}]
		.into(),
		builddate: 1_700_000_000,
		installdate: 1_700_000_100,
		size: 123_456,
		isize: 9_876_543,
		validation: 4 | 8,
		..named(b"foo", b"1.0-1")
	};
	let origins = [
		Some(PkgFrom::LocalDb),
		Some(PkgFrom::SyncDb),
		Some(PkgFrom::File(fx.pkgfile().into())),
	];
	let mut rng = Rng::new(1);
	for origin in origins {
		for extra in [false, true] {
			let file = matches!(origin, Some(PkgFrom::File(_)));
			let (sig, keys) = if file {
				(None, Vec::new())
			} else {
				let (p, k) = sig_packet(&mut rng);
				(Some(encode_base64(&p)), k)
			};
			let pkg = Package {
				filename: file
					.then(|| fx.pkgfile())
					.map(Box::from),
				base64_sig: sig.map(Box::from),
				origin: origin.clone(),
				..base.clone()
			};
			run_full(&fx, &mut rng, &pkg, keys, extra, caches);
		}
	}
}

// each case refills three db caches and runs the C up to six times
// (localtime twice, reverse deps twice, satisfiers, the dump): iters()/5
#[test]
fn full_fuzz() {
	let mut fx = Fx::new("full");
	let mut rng = Rng::new(0x5ee);
	let n = iters() / 5;
	let mut seen = Reached::default();
	for _ in 0..n {
		let local = random_cache(&mut rng);
		let sync = [random_cache(&mut rng), random_cache(&mut rng)];
		fx.w_mut().set_caches(&local, [&sync[0], &sync[1]]);
		let extra = rng.below(2) == 0;
		let (pkg, keys) = random_pkg(&mut rng, &fx, extra);
		let sync_extra = extra && pkg.origin == Some(PkgFrom::SyncDb);
		seen.keys += usize::from(sync_extra && !keys.is_empty());
		let caches = [&local[..], &sync[0], &sync[1]];
		let shown = run_full(&fx, &mut rng, &pkg, keys, extra, caches);
		seen.required_by += usize::from(!shown.required_by.is_empty());
		seen.installed += usize::from(!shown.installed.is_empty());
		let local_extra = extra && pkg.origin == Some(PkgFrom::LocalDb);
		seen.backups +=
			usize::from(local_extra && !pkg.backup.is_empty());
		seen.file += usize::from(matches!(
			pkg.origin,
			Some(PkgFrom::File(_))
		));
	}
	let min = n / 30;
	let r = &seen;
	let counts = [r.required_by, r.installed, r.keys, r.backups, r.file];
	assert!(counts.iter().all(|&c| c >= min), "{n} cases: {seen:?}");
}

#[test]
fn backups_fuzz() {
	let fx = Fx::new("backups");
	let mut rng = Rng::new(0xbac);
	for _ in 0..iters() / 4 {
		let pkg = Package {
			backup: some_of(&mut rng, 8, random_backup).into(),
			..named(b"foo", b"1")
		};
		let (cols, cs) = (pick(&mut rng, &COLS), colstr(&mut rng));
		let c = fx.w().dump_backups(&pkg, cols, &cs);
		let mut env = Env::new(&fx, [&[]; 3]);
		let mut out = Vec::new();
		dump_pkg_backups(&mut out, &mut env, &pkg, cols, &cs);
		same(&c, &out, &(&pkg.backup, cols));
	}
}

#[test]
fn files_fuzz() {
	let fx = Fx::new("files");
	let mut rng = Rng::new(0xf11e);
	for _ in 0..iters() / 4 {
		let files = some_of(&mut rng, 6, |r| File {
			name: text(r, 5),
			size: 0,
			mode: 0,
		});
		let pkg = Package {
			files: FileList { files },
			..named(&text(&mut rng, 4), b"1")
		};
		let (quiet, cs) = (rng.below(2) == 0, colstr(&mut rng));
		let c = fx.w().dump_files(&pkg, quiet, &cs);
		let mut out = Vec::new();
		dump_pkg_files(&mut out, &pkg, fx.w().root(), quiet, &cs);
		same(&c, &out, &(&pkg.files, quiet));
	}
}

#[test]
fn groups_installed_fuzz() {
	let mut fx = Fx::new("installed");
	let mut rng = Rng::new(0x9e0);
	for _ in 0..iters() / 4 {
		let local = random_cache(&mut rng);
		fx.w_mut().set_caches(&local, [&[], &[]]);
		let pkg = Package {
			groups: some_of(&mut rng, 4, |r| text(r, 3).into())
				.into(),
			..named(pick(&mut rng, NAMES), pick(&mut rng, VERSIONS))
		};
		let cs = colstr(&mut rng);
		let mut out = Vec::new();
		print_groups(&mut out, &pkg, &cs);
		same(&c_print_groups(&pkg, &cs), &out, &pkg.groups);
		let c = fx.w().print_installed(&pkg, &cs);
		let mut out = Vec::new();
		let lpkg = pkg_find(&local, pkg.name_bytes());
		print_installed(&mut out, lpkg, &pkg, &cs);
		same(&c, &out, &(&pkg, &local));
	}
}

// alpm_db_get_pkg on the local cache
fn finder<'a>(
	local: &'a [Package],
) -> impl Fn(&[u8]) -> Option<&'a Package> + 'a {
	move |n| pkg_find(local, n)
}

#[test]
fn search_fuzz() {
	let mut fx = Fx::new("search");
	let mut rng = Rng::new(0x5ea);
	for _ in 0..iters() / 10 {
		let local = random_cache(&mut rng);
		let sync = [random_cache(&mut rng), random_cache(&mut rng)];
		fx.w_mut().set_caches(&local, [&sync[0], &sync[1]]);
		let db = rng.below(2);
		let (status, quiet) = (rng.below(2) == 0, rng.below(4) == 0);
		let (cols, cs) = (pick(&mut rng, &COLS), colstr(&mut rng));
		let (ret, c) = fx.w().search(db, status, quiet, cols, &cs);
		// the cache list is sorted by name
		let mut results: Vec<&Package> = sync[db].iter().collect();
		results.sort_by(|a, b| a.name_bytes().cmp(b.name_bytes()));
		let find = finder(&local);
		let mut out = Vec::new();
		let name = SYNC_DBS[db].as_bytes();
		let found = dump_pkg_search(
			&mut out,
			name,
			&results,
			status.then_some(&find),
			quiet,
			cols,
			&cs,
		);
		assert_eq!(ret, i32::from(!found), "{results:?}");
		same(&c, &out, &(&results, status, quiet, cols));
	}
}
