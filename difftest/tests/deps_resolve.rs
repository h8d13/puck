// alpm_core::package::{compute_requiredby, compute_optionalfor,
// pkg_should_ignore} and alpm_core::deps::find_satisfier against the C on
// real handles. each case writes a fixture (local db, sync dbs "core" and
// "extra", "gone" registered without a file) read by a C handle and by
// the Rust Handle + be_local reader; every cached package and some file
// packages are compared. should_ignore also runs on mirror packages.
use std::fs;
use std::os::unix::ffi::OsStrExt;

use alpm_core::be_local::{INFRQ_DESC, LocalDb};
use alpm_core::deps::{dep_from_string, find_satisfier};
use alpm_core::handle::Handle;
use alpm_core::package::{
	DbCaches, Package, PkgFrom, compute_optionalfor, compute_requiredby,
	pkg_should_ignore,
};
use alpm_core::util::hash_sdbm;
use difftest::{
	CResolve, Comp, LocalEntry, Rng, TarEntry, TempRoot,
	c_pkg_should_ignore, iters, section, tar_dir, tar_file, ustar,
	write_db,
};

const SYNC: [&str; 3] = ["core", "extra", "gone"];
const NAMES: [&str; 7] = ["a", "b", "foo", "bar", "lib-x", "z9", "q.r"];
const PKG_VERSIONS: [&str; 4] = ["1.0-1", "1.5-2", "2:1.0-1", "1.0.1-1"];
const DEP_VERSIONS: [&str; 6] = ["1.0", "1.0-1", "1.5", "2:1.0", "0.9", "1"];
const OPS: [&str; 6] = ["", "=", ">=", "<=", ">", "<"];
const GROUPS: [&str; 4] = ["g1", "g2", "base", "kde-apps"];
// fnmatch specials over names and groups; '!' is literal here (no
// _alpm_fnmatch_patterns negation)
const PATTERNS: [&str; 14] = [
	"foo",
	"f*",
	"*",
	"lib-?",
	"g1",
	"g[12]",
	"!foo",
	"[!a]*",
	"kde*",
	"x",
	"*.r",
	"base",
	"[[:digit:]]*",
	"\\*",
];

// one fixture per case: fewer than iters()
fn cases() -> usize {
	(iters() / 500).max(40)
}

// one generated package, relations as desc lines
#[derive(Clone, Debug, Default)]
struct Pkg {
	name: &'static str,
	version: &'static str,
	depends: Vec<String>,
	optdepends: Vec<String>,
	provides: Vec<String>,
	groups: Vec<String>,
}

fn pick<T: Copy>(rng: &mut Rng, items: &[T]) -> T {
	items[rng.below(items.len())]
}

fn relation(rng: &mut Rng) -> String {
	let (name, op) = (pick(rng, &NAMES), pick(rng, &OPS));
	match op {
		"" => name.to_string(),
		_ => format!("{name}{op}{}", pick(rng, &DEP_VERSIONS)),
	}
}

// mostly unversioned or "=ver" (the only versioned provisions the C
// matches against versioned deps), some ">=ver"
fn provision(rng: &mut Rng) -> String {
	let name = pick(rng, &NAMES);
	let ver = pick(rng, &DEP_VERSIONS);
	match rng.below(4) {
		0 | 1 => name.to_string(),
		2 => format!("{name}={ver}"),
		_ => format!("{name}>={ver}"),
	}
}

fn some<T>(rng: &mut Rng, n: usize, f: impl Fn(&mut Rng) -> T) -> Vec<T> {
	(0..rng.below(n)).map(|_| f(rng)).collect()
}

// a db's packages: unique names, random relations
fn gen_pkgs(rng: &mut Rng) -> Vec<Pkg> {
	let mut names = NAMES.to_vec();
	names.retain(|_| rng.below(3) != 0);
	names.into_iter()
		.map(|name| Pkg {
			name,
			version: pick(rng, &PKG_VERSIONS),
			depends: some(rng, 4, relation),
			optdepends: some(rng, 3, |r| match r.below(2) {
				0 => relation(r),
				_ => format!("{}: for x", relation(r)),
			}),
			provides: some(rng, 3, provision),
			groups: {
				let mut g = GROUPS.to_vec();
				g.retain(|_| rng.below(3) == 0);
				g.into_iter().map(String::from).collect()
			},
		})
		.collect()
}

fn relations(p: &Pkg) -> String {
	[
		section("GROUPS", &p.groups),
		section("DEPENDS", &p.depends),
		section("OPTDEPENDS", &p.optdepends),
		section("PROVIDES", &p.provides),
	]
	.concat()
}

fn local_desc(p: &Pkg) -> String {
	let s = format!(
		"%NAME%\n{0}\n\n%VERSION%\n{1}\n\n%BASE%\n{0}\n\n\
		%DESC%\nA package\n\n%URL%\nhttps://example.org/\n\n\
		%ARCH%\nx86_64\n\n%BUILDDATE%\n1700000000\n\n\
		%INSTALLDATE%\n1700000001\n\n%PACKAGER%\nA B <a@b.org>\n\n\
		%SIZE%\n42\n\n%VALIDATION%\npgp\n\n",
		p.name, p.version
	);
	s + &relations(p)
}

fn sync_desc(p: &Pkg) -> String {
	let s = format!(
		"%FILENAME%\n{0}-{1}-any.pkg.tar.zst\n\n\
		%NAME%\n{0}\n\n%BASE%\n{0}\n\n%VERSION%\n{1}\n\n\
		%CSIZE%\n1\n\n%ISIZE%\n2\n\n%SHA256SUM%\n{2}\n\n\
		%ARCH%\nany\n\n%BUILDDATE%\n3\n\n\
		%PACKAGER%\nA B <a@b.org>\n\n",
		p.name,
		p.version,
		"ab".repeat(32)
	);
	s + &relations(p)
}

// uncompressed sync db
fn sync_db(pkgs: &[Pkg]) -> Vec<u8> {
	let mut entries: Vec<TarEntry> = Vec::new();
	for p in pkgs {
		let dir = format!("{}-{}/", p.name, p.version);
		entries.push(tar_dir(&dir));
		let desc = sync_desc(p);
		entries.push(tar_file(&format!("{dir}desc"), desc.as_bytes()));
	}
	ustar(&entries)
}

fn write_fixture(fx: &TempRoot, local: &[Pkg], sync: &[Vec<Pkg>; 2]) {
	fx.reset_local();
	let entries: Vec<LocalEntry> = local
		.iter()
		.map(|p| LocalEntry {
			dir: format!("{}-{}", p.name, p.version),
			desc: Some(local_desc(p).into_bytes()),
			..LocalEntry::default()
		})
		.collect();
	fx.write_local(&entries);
	for (name, pkgs) in SYNC.iter().zip(sync) {
		write_db(
			&fx.sync_file(name, ".db"),
			Comp::None,
			&sync_db(pkgs),
		);
	}
}

// the Rust side: Handle on the same fixture, local entries loaded with
// be_local (the cache keeps only the base fields until lazy loads stick)
struct Caches {
	handle: Handle,
	local: Vec<Package>,
	sync: Vec<Vec<Package>>,
}

impl DbCaches for Caches {
	fn local_cache(&mut self) -> Vec<&Package> {
		self.local.iter().collect()
	}

	fn sync_caches(&mut self) -> Vec<Vec<&Package>> {
		self.sync.iter().map(|c| c.iter().collect()).collect()
	}
}

fn rust_side(fx: &TempRoot) -> Caches {
	let mut handle = Handle::initialize(&fx.root(), &fx.dbpath()).unwrap();
	for name in SYNC {
		handle.register_syncdb(name.as_bytes(), 0).unwrap();
	}
	let reader = LocalDb::register(handle.dbpath()).unwrap();
	let dbext = handle.dbext().to_vec();
	let db = handle.localdb_mut().unwrap();
	let mut local: Vec<Package> =
		db.pkgcache(&dbext).unwrap().iter().cloned().collect();
	for p in &mut local {
		reader.read(p, INFRQ_DESC).unwrap();
	}
	// a cache that fails to load (gone) is an empty list, like NULL
	let sync = handle
		.syncdbs_mut()
		.iter_mut()
		.map(|d| match d.pkgcache(&dbext) {
			Ok(c) => c.iter().cloned().collect(),
			Err(_) => Vec::new(),
		})
		.collect();
	Caches {
		handle,
		local,
		sync,
	}
}

fn names(pkgs: &[Package]) -> Vec<Vec<u8>> {
	pkgs.iter().map(|p| p.name_bytes().to_vec()).collect()
}

fn rust_reqs(
	pkg: &Package,
	caches: &mut Caches,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
	(
		compute_requiredby(pkg, caches),
		compute_optionalfor(pkg, caches),
	)
}

// what the cases reached
#[derive(Default, Debug)]
struct Seen {
	local_reqs: usize,
	sync_reqs: usize,
	sync_dedup: usize,
	file_reqs: usize,
	satisfied: usize,
	satisfied_later: usize,
	ignored: usize,
	not_ignored: usize,
}

fn file_pkg(rng: &mut Rng, fx: &TempRoot) -> Package {
	let name = pick(rng, &NAMES);
	let path = fx.path("root/x.pkg.tar.zst");
	Package {
		name_hash: hash_sdbm(name.as_bytes()),
		name: Some(name.as_bytes().to_vec()),
		version: Some(pick(rng, &PKG_VERSIONS).as_bytes().to_vec()),
		provides: some(rng, 3, |r| {
			dep_from_string(provision(r).as_bytes())
		}),
		origin: Some(PkgFrom::File(path)),
		..Package::default()
	}
}

fn compare_reqs(c: &CResolve, rs: &mut Caches, seen: &mut Seen) {
	let local = rs.local.clone();
	for (p, cr) in local.iter().zip(c.requiredby(None)) {
		assert_eq!(p.origin, Some(PkgFrom::LocalDb));
		assert_eq!(cr, rust_reqs(p, rs), "local {p:?}");
		seen.local_reqs += usize::from(!cr.0.is_empty());
	}
	for db in 0..SYNC.len() {
		let pkgs = rs.sync[db].clone();
		for (p, cr) in pkgs.iter().zip(c.requiredby(Some(db))) {
			assert_eq!(p.origin, Some(PkgFrom::SyncDb));
			assert_eq!(cr, rust_reqs(p, rs), "sync {p:?}");
			seen.sync_reqs += usize::from(!cr.0.is_empty());
			// a dependent in both core and extra listed once
			let both = |n: &Vec<u8>| {
				rs.sync[0].iter().any(|q| q.name_bytes() == n)
					&& rs.sync[1]
						.iter()
						.any(|q| q.name_bytes() == n)
			};
			seen.sync_dedup += usize::from(cr.0.iter().any(both));
		}
	}
}

fn compare_satisfiers(
	c: &CResolve,
	rs: &mut Caches,
	rng: &mut Rng,
	seen: &mut Seen,
) {
	for _ in 0..12 {
		let db = rng.below(SYNC.len() + 1).checked_sub(1);
		let s = relation(rng);
		let cached = match db {
			None => &rs.local,
			Some(i) => &rs.sync[i],
		};
		let r = find_satisfier(cached, s.as_bytes());
		let r = r.map(|p| p.name_bytes().to_vec());
		assert_eq!(c.find_satisfier(db, s.as_bytes()), r, "{s} {db:?}");
		seen.satisfied += usize::from(r.is_some());
		let first = cached.first().map(|p| p.name_bytes().to_vec());
		seen.satisfied_later += usize::from(r.is_some() && r != first);
	}
}

fn patterns(rng: &mut Rng) -> Vec<Vec<u8>> {
	some(rng, 3, |r| pick(r, &PATTERNS).as_bytes().to_vec())
}

fn compare_ignore(
	c: &CResolve,
	rs: &mut Caches,
	rng: &mut Rng,
	seen: &mut Seen,
) {
	for _ in 0..3 {
		let (pkgs, groups) = (patterns(rng), patterns(rng));
		rs.handle.set_ignorepkgs(&pkgs);
		rs.handle.set_ignoregroups(&groups);
		for db in [None, Some(0), Some(1)] {
			let cached = match db {
				None => &rs.local,
				Some(i) => &rs.sync[i],
			};
			let r: Vec<bool> = cached
				.iter()
				.map(|p| pkg_should_ignore(&rs.handle, p))
				.collect();
			let what = (&pkgs, &groups, names(cached));
			assert_eq!(
				c.should_ignore(db, &pkgs, &groups),
				r,
				"{what:?}"
			);
			seen.ignored += r.iter().filter(|&&b| b).count();
			seen.not_ignored += r.iter().filter(|&&b| !b).count();
		}
	}
}

#[test]
fn fixture_fuzz() {
	let mut rng = Rng::new(0x2e5);
	let n = cases();
	let mut seen = Seen::default();
	for _ in 0..n {
		let fx = TempRoot::new("resolve");
		let local = gen_pkgs(&mut rng);
		let sync = [gen_pkgs(&mut rng), gen_pkgs(&mut rng)];
		write_fixture(&fx, &local, &sync);
		let c = CResolve::new(&fx.root(), &fx.dbpath(), &SYNC);
		let mut rs = rust_side(&fx);
		assert_eq!(c.names(None), names(&rs.local));
		for db in 0..SYNC.len() {
			assert_eq!(c.names(Some(db)), names(&rs.sync[db]));
		}
		compare_reqs(&c, &mut rs, &mut seen);
		for _ in 0..3 {
			let p = file_pkg(&mut rng, &fx);
			let cr = c.requiredby_file(&p);
			assert_eq!(cr, rust_reqs(&p, &mut rs), "file {p:?}");
			seen.file_reqs += usize::from(!cr.0.is_empty());
		}
		compare_satisfiers(&c, &mut rs, &mut rng, &mut seen);
		compare_ignore(&c, &mut rs, &mut rng, &mut seen);
	}
	let s = &seen;
	let counts = [
		s.local_reqs,
		s.sync_reqs,
		s.sync_dedup,
		s.file_reqs,
		s.satisfied,
		s.satisfied_later,
		s.ignored,
		s.not_ignored,
	];
	assert!(counts.iter().all(|&k| k >= n / 4), "{n} cases: {seen:?}");
}

// mirror packages: arbitrary names and groups, patterns from the
// fnmatch specials
#[test]
fn should_ignore_fuzz() {
	let dir = std::env::temp_dir()
		.join(format!("difftest-ignore-{}", std::process::id()));
	fs::create_dir_all(dir.join("db")).unwrap();
	let p = |s: &str| dir.join(s).as_os_str().as_bytes().to_vec();
	let mut h = Handle::initialize(&p(""), &p("db")).unwrap();
	let mut rng = Rng::new(0x16e);
	let alphabet = b"ab*?[]!-^\\:.\xc3";
	let n = iters() / 4;
	let (mut by_name, mut by_group) = (0usize, 0usize);
	for _ in 0..n {
		let strs =
			|r: &mut Rng, k| some(r, k, |r| r.bytes(alphabet, 5));
		let (ipkg, igrp) = (strs(&mut rng, 3), strs(&mut rng, 3));
		let name = rng.bytes(alphabet, 4);
		let pkg = Package {
			name_hash: hash_sdbm(&name),
			name: Some(name),
			groups: strs(&mut rng, 3),
			..Package::default()
		};
		h.set_ignorepkgs(&ipkg);
		h.set_ignoregroups(&igrp);
		let r = pkg_should_ignore(&h, &pkg);
		let what = (&ipkg, &igrp, &pkg.name, &pkg.groups);
		assert_eq!(
			c_pkg_should_ignore(&ipkg, &igrp, &pkg),
			r,
			"{what:?}"
		);
		let named = ipkg
			.iter()
			.any(|q| alpm_core::util::fnmatch(q, pkg.name_bytes()));
		by_name += usize::from(named);
		by_group += usize::from(r && !named);
	}
	fs::remove_dir_all(&dir).unwrap();
	assert!(
		by_name >= n / 50 && by_group >= n / 50,
		"{by_name} {by_group}/{n}"
	);
}
