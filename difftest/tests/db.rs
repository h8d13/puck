// alpm_core::{handle, db} against the C handle and db layer: fixture
// roots under /tmp with a local db and sync db files (valid, missing,
// broken), driven through the same operation sequences on a C handle and
// a Rust Handle. every result and pm_errno is compared, cached packages
// field by field (lazy loads stay in the cache entry on both sides), then
// the registered dbs, their servers, usage, siglevel and path. the fuzz
// compares the log lines of every op and of the release too.
use std::cell::RefCell;
use std::ffi::c_int;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::symlink;

use alpm_core::be_local::{
	INFRQ_ALL, INFRQ_DESC, INFRQ_ERROR, INFRQ_FILES, INFRQ_SCRIPTLET,
};
use alpm_core::callbacks::{Callbacks, LogLevel};
use alpm_core::db::{Db, SIG_USE_DEFAULT, db_cmp};
use alpm_core::error::Errno;
use alpm_core::group::Group;
use alpm_core::handle::Handle;
use alpm_core::package::{Package, PkgFrom};
use alpm_core::util::hash_sdbm;
use difftest::{
	CHandle, LocalEntry, Rng, StrList, TarEntry, TempRoot, iters, section,
	tar_dir, tar_file, ustar,
};

type Logs = Vec<(c_int, Vec<u8>)>;

thread_local! {
	// what the Rust side logged: the handle and the Db calls
	static LOGS: RefCell<Logs> = const { RefCell::new(Vec::new()) };
}

// the Rust handle's callbacks, and the ones every Db call here takes:
// log lines go to LOGS
struct Rec;

impl Callbacks for Rec {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		let line = (level as c_int, msg.to_vec());
		LOGS.with(|l| l.borrow_mut().push(line));
	}
}

// the port logs be_sync's archive error with its own text, left out
// like the C's
fn take_rust_logs() -> Logs {
	let logs = LOGS.with(|l| std::mem::take(&mut *l.borrow_mut()));
	logs.into_iter().filter(modelled).collect()
}

// C lines the port does not log: RET_ERR/GOTO_ERR (C file and line),
// and be_sync's error lines carrying libarchive texts
fn modelled(line: &(c_int, Vec<u8>)) -> bool {
	const NOT: [&[u8]; 4] = [
		b"returning error ",
		b"got error ",
		b"could not read db '",
		b"could not open file ",
	];
	let m = &line.1;
	// be_local's open failures are modelled, be_sync's are not
	let local_open = m.starts_with(b"could not open file ")
		&& !m.windows(6).any(|w| w == b"/sync/");
	local_open || !NOT.iter().any(|p| m.starts_with(p))
}

fn c_logs(c: Logs) -> Logs {
	c.into_iter().filter(modelled).collect()
}

// one fixture and two handles per case, each case a sequence of ops
fn cases() -> usize {
	(iters() / 50).max(50)
}

const OPS: usize = 80;

// fresh local/ with a version file and these packages
fn write_local(fx: &TempRoot, pkgs: &[Pkg]) {
	fx.reset_local();
	let entries: Vec<LocalEntry> = pkgs
		.iter()
		.map(|p| LocalEntry {
			dir: format!("{}-{}", p.name, p.version),
			desc: p.desc.then(|| local_desc(p).into_bytes()),
			files: p.files.then(|| local_files(p).into_bytes()),
			install: p.install,
		})
		.collect();
	fx.write_local(&entries);
}

fn write_sync(fx: &TempRoot, file: &str, bytes: &[u8]) {
	fs::write(fx.dir().join("db/sync").join(file), bytes).unwrap();
}

// one generated package. desc/files false: local entry without that
// file, its lazy load fails. install: local entry with a scriptlet
#[derive(Clone, Debug)]
struct Pkg {
	name: String,
	version: String,
	groups: Vec<String>,
	desc: bool,
	files: bool,
	install: bool,
}

impl Pkg {
	// local and sync entry with a desc only
	fn plain(name: &str, groups: &[&str]) -> Pkg {
		Pkg {
			name: name.into(),
			version: "1-1".into(),
			groups: groups.iter().map(|g| g.to_string()).collect(),
			desc: true,
			files: false,
			install: false,
		}
	}
}

fn local_desc(p: &Pkg) -> String {
	format!(
		"%NAME%\n{0}\n\n%VERSION%\n{1}\n\n%BASE%\n{0}\n\n\
		%DESC%\nA package\n\n%URL%\nhttps://example.org/\n\n\
		%ARCH%\nx86_64\n\n%BUILDDATE%\n1700000000\n\n\
		%INSTALLDATE%\n1700000001\n\n%PACKAGER%\nA B <a@b.org>\n\n\
		%SIZE%\n42\n\n%VALIDATION%\npgp\n\n{2}",
		p.name,
		p.version,
		section("GROUPS", &p.groups)
	)
}

fn local_files(p: &Pkg) -> String {
	format!(
		"%FILES%\netc/\netc/{0}.conf\nusr/\nusr/bin/\nusr/bin/{0}\n\n\
		%BACKUP%\netc/{0}.conf\td41d8cd98f00b204e9800998ecf8427e\n\n",
		p.name
	)
}

fn sync_desc(p: &Pkg) -> String {
	format!(
		"%FILENAME%\n{0}-{1}-any.pkg.tar.zst\n\n\
		%NAME%\n{0}\n\n%BASE%\n{0}\n\n%VERSION%\n{1}\n\n\
		%CSIZE%\n1\n\n%ISIZE%\n2\n\n%SHA256SUM%\n{2}\n\n\
		%ARCH%\nany\n\n%BUILDDATE%\n3\n\n\
		%PACKAGER%\nA B <a@b.org>\n\n{3}",
		p.name,
		p.version,
		"ab".repeat(32),
		section("GROUPS", &p.groups)
	)
}

// uncompressed sync db (be_sync covers the compressions)
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

// %NAME%, %VERSION% and the groups only, like pactest writes them
fn sparse_db(pkgs: &[Pkg]) -> Vec<u8> {
	let entries: Vec<TarEntry> = pkgs
		.iter()
		.map(|p| {
			let desc = format!(
				"%NAME%\n{}\n\n%VERSION%\n{}\n\n{}",
				p.name,
				p.version,
				section("GROUPS", &p.groups)
			);
			let dir = format!("{}-{}", p.name, p.version);
			tar_file(&format!("{dir}/desc"), desc.as_bytes())
		})
		.collect();
	ustar(&entries)
}

const PKG_NAMES: [&str; 8] = ["a", "b", "foo", "bar", "baz", "x-y", "z9", "q"];
const GROUPS: [&str; 4] = ["g1", "g2", "base", "kde"];
const TREES: [&str; 9] = [
	"core", "extra", "multilib", "gone", "local", "", "a/b", "c", "d",
];
const URLS: [&str; 12] = [
	"",
	"/",
	"//",
	"a",
	"a/",
	"a//",
	"http://m.org/$repo/os/$arch",
	"http://m.org/$repo/os/$arch/",
	"file:///srv/repo/",
	"file:///srv/repo",
	" ",
	"x/y/",
];

fn pick<'a>(rng: &mut Rng, items: &[&'a str]) -> &'a str {
	items[rng.below(items.len())]
}

fn gen_groups(rng: &mut Rng) -> Vec<String> {
	// repeats on purpose: load_grpcache's duplicate handling
	(0..rng.below(4))
		.map(|_| pick(rng, &GROUPS).to_string())
		.collect()
}

fn gen_pkgs(rng: &mut Rng, max: usize) -> Vec<Pkg> {
	let mut names: Vec<&str> = PKG_NAMES.to_vec();
	(0..rng.below(max + 1))
		.map(|_| {
			let name = names.remove(rng.below(names.len()));
			Pkg {
				name: name.to_string(),
				version: format!(
					"{}.{}-1",
					rng.below(3),
					rng.below(10)
				),
				groups: gen_groups(rng),
				desc: rng.below(8) != 0,
				files: rng.below(4) != 0,
				install: rng.below(3) == 0,
			}
		})
		.collect()
}

// sync db files of a case: valid, absent, truncated tar (archive error
// on both sides, see be_sync odd_archives), empty file
fn gen_sync_files(rng: &mut Rng, fx: &TempRoot, dbext: &str) -> String {
	let mut log = String::new();
	for tree in ["core", "extra", "multilib", "c", "d"] {
		let file = format!("{tree}{dbext}");
		match rng.below(10) {
			0 => writeln!(log, "{file}: absent").unwrap(),
			// pactest's entries: the sections a test sets only
			3 => {
				let pkgs = gen_pkgs(rng, 5);
				write_sync(fx, &file, &sparse_db(&pkgs));
				writeln!(log, "{file}: sparse {pkgs:?}")
					.unwrap();
			}
			// an entry the reader refuses: the db goes invalid
			4 => {
				let pkgs = gen_pkgs(rng, 3);
				let mut tar = sync_db(&pkgs);
				let at = tar
					.windows(10)
					.position(|w| w == b"%PACKAGER%");
				if let Some(at) = at {
					tar[at..at + 10].copy_from_slice(
						b"%DATA%\nx\n\n",
					);
				}
				write_sync(fx, &file, &tar);
				writeln!(log, "{file}: bad entry {pkgs:?}")
					.unwrap();
			}
			1 => {
				let mut tar = sync_db(&gen_pkgs(rng, 2));
				tar.truncate(700);
				write_sync(fx, &file, &tar);
				writeln!(log, "{file}: truncated").unwrap();
			}
			2 => {
				write_sync(fx, &file, b"");
				writeln!(log, "{file}: empty").unwrap();
			}
			_ => {
				let pkgs = gen_pkgs(rng, 5);
				write_sync(fx, &file, &sync_db(&pkgs));
				writeln!(log, "{file}: {pkgs:?}").unwrap();
			}
		}
	}
	log
}

// results as (C return, pm_errno)
fn unit(r: Result<(), Errno>) -> (c_int, c_int) {
	match r {
		Ok(()) => (0, 0),
		Err(e) => (-1, e as c_int),
	}
}

fn found(r: Result<bool, Errno>) -> (c_int, c_int) {
	match r {
		Ok(true) => (0, 0),
		Ok(false) => (1, 0),
		Err(e) => (-1, e as c_int),
	}
}

// Rust groups as positions in the cache list, by address like the C
// alpm_list_find_ptr. the cache is only read again when a group holds
// members, so a failed load is not retried here
fn positions(
	db: &mut Db,
	dbext: &[u8],
	groups: Vec<Group<*const Package>>,
) -> Vec<Group<usize>> {
	let any = groups.iter().any(|g| !g.packages.is_empty());
	let list: Vec<*const Package> = match any {
		true => db
			.pkgcache(dbext, &mut Rec)
			.unwrap()
			.iter()
			.map(|p| p as *const _)
			.collect(),
		false => Vec::new(),
	};
	let pos = |p: &*const Package| {
		list.iter().position(|q| std::ptr::eq(*q, *p)).unwrap()
	};
	groups.into_iter()
		.map(|g| Group {
			packages: g.packages.iter().map(pos).collect(),
			name: g.name,
		})
		.collect()
}

fn raw(g: Group<&Package>) -> Group<*const Package> {
	Group {
		name: g.name,
		packages: g
			.packages
			.into_iter()
			.map(|p| p as *const _)
			.collect(),
	}
}

fn rust_groupcache(db: &mut Db, dbext: &[u8]) -> (Vec<Group<usize>>, c_int) {
	let (groups, e) = match db.groupcache(dbext, &mut Rec) {
		Ok(g) => (g.into_iter().map(raw).collect(), 0),
		Err(e) => (Vec::new(), e as c_int),
	};
	(positions(db, dbext, groups), e)
}

fn rust_get_group(
	db: &mut Db,
	dbext: &[u8],
	name: &[u8],
) -> (Option<Group<usize>>, c_int) {
	let (g, e) = match db.get_group(dbext, &mut Rec, name) {
		Ok(g) => (g.map(raw), 0),
		Err(e) => (None, e as c_int),
	};
	let g = g.map(|g| positions(db, dbext, vec![g]).remove(0));
	(g, e)
}

// a cached package or the pm_errno of the lookup
fn pkg_or_err(r: Result<&Package, Errno>) -> (Option<Package>, c_int) {
	match r {
		Ok(p) => (Some(p.clone()), 0),
		Err(e) => (None, e as c_int),
	}
}

fn cache_err(r: Result<(), alpm_core::db::CacheError>) -> (c_int, c_int) {
	match r {
		Ok(()) => (0, 0),
		Err(e) => (-1, e.errno().map_or(0, |e| e as c_int)),
	}
}

// C and Rust values equal, the op log on failure. both are evaluated
// before the log is borrowed
macro_rules! check {
	($b:expr, $what:expr, $c:expr, $r:expr $(,)?) => {{
		let (c, r) = ($c, $r);
		assert_eq!(c, r, "{}\nops:\n{}", $what, $b.log);
	}};
}

// a C handle and a Rust handle on the same fixture
struct Both {
	c: CHandle,
	r: Handle,
	log: String,
	seen: Seen,
}

// how often the interesting outcomes came up, so the fuzz can assert it
// compared more than errors
#[derive(Default, Debug)]
struct Seen {
	pkg_hits: usize,
	loaded: usize,
	groups: usize,
	added: usize,
	removed: usize,
	registered: usize,
	// log lines compared, by level
	errors: usize,
	debug: usize,
	function: usize,
}

impl Both {
	fn new(fx: &TempRoot, dbpath: &[u8]) -> Both {
		let root = fx.path("root");
		let c = CHandle::new(&root, dbpath).expect("C initialize");
		let mut r =
			Handle::initialize(&root, dbpath).expect("initialize");
		r.set_callbacks(Box::new(Rec));
		take_rust_logs();
		Both {
			c,
			r,
			log: String::new(),
			seen: Seen::default(),
		}
	}

	// handle->dbext now, what a cache load reads
	fn ext(&self) -> Vec<u8> {
		self.r.dbext().to_vec()
	}

	fn db(&mut self, name: &str) -> &mut Db {
		let r = &mut self.r;
		let db = match name {
			"local" => r.localdb_mut(),
			_ => r.syncdbs_mut()
				.iter_mut()
				.find(|d| d.name() == name.as_bytes()),
		};
		db.expect("db not registered")
	}

	// registered db names, local first
	fn names(&self) -> Vec<String> {
		let local = self.r.localdb().map(|_| "local".to_string());
		let sync = self.r.syncdbs().iter();
		let sync = sync
			.map(|d| String::from_utf8(d.name().to_vec()).unwrap());
		local.into_iter().chain(sync).collect()
	}

	// the lines both sides logged since the last compare
	fn compare_logs(&mut self, what: &str) {
		let c = c_logs(self.c.take_logs());
		for (level, _) in &c {
			match *level {
				1 => self.seen.errors += 1,
				4 => self.seen.debug += 1,
				8 => self.seen.function += 1,
				_ => {}
			}
		}
		let lines = |l: &Logs| -> Vec<(c_int, String)> {
			l.iter().map(|(lv, m)| {
				(*lv, String::from_utf8_lossy(m).into())
			})
			.collect()
		};
		let r = take_rust_logs();
		check!(self, &format!("{what} logs"), lines(&c), lines(&r));
	}

	// everything observable without loading a cache
	fn compare_state(&self) {
		let c = &self.c;
		let syncs: Vec<Vec<u8>> =
			self.r.syncdbs()
				.iter()
				.map(|d| d.name().to_vec())
				.collect();
		check!(self, "syncdbs", c.syncdb_names(), syncs);
		check!(
			self,
			"localdb",
			c.has_db(b"local"),
			self.r.localdb().is_some()
		);
		let dbs = self.r.localdb().into_iter().chain(self.r.syncdbs());
		let default = self.r.default_siglevel();
		for db in dbs {
			let n = match db.is_local() {
				true => &b"local"[..],
				false => db.name(),
			};
			let what = String::from_utf8_lossy(n);
			check!(
				self,
				&format!("{what} servers"),
				c.servers(n, false),
				db.servers().to_vec()
			);
			check!(
				self,
				&format!("{what} cache servers"),
				c.servers(n, true),
				db.cache_servers().to_vec(),
			);
			check!(
				self,
				&format!("{what} usage"),
				c.usage(n),
				db.usage()
			);
			check!(
				self,
				&format!("{what} siglevel"),
				c.siglevel(n),
				db.siglevel(default)
			);
			check!(
				self,
				&format!("{what} path"),
				c.path(n),
				db.path().to_vec()
			);
		}
		check!(self, "default siglevel", c.default_siglevel(), default);
	}
}

// what load_pkg asks for, one getter per bit
const INFOREQS: [c_int; 5] = [
	INFRQ_DESC,
	INFRQ_FILES,
	INFRQ_SCRIPTLET,
	INFRQ_DESC | INFRQ_FILES,
	INFRQ_DESC | INFRQ_FILES | INFRQ_SCRIPTLET,
];

const DBEXTS: [&str; 3] = [".db", ".files", ""];

// alpm_initialize's dbext, for the fixed cases that keep it
const DBEXT: &[u8] = b".db";

// siglevels without ALPM_SIG_DATABASE: database checks need gpgme and a
// keyring, not ported
const LEVELS: [c_int; 5] = [0, SIG_USE_DEFAULT, 1, 3, SIG_USE_DEFAULT | 5];

fn gen_add_pkg(rng: &mut Rng) -> Package {
	let name = pick(rng, &PKG_NAMES);
	Package {
		name_hash: hash_sdbm(name.as_bytes()),
		name: Some(name.as_bytes().to_vec()),
		version: Some(format!("9.{}-1", rng.below(5)).into_bytes()),
		desc: Some(b"added".to_vec()),
		groups: gen_groups(rng)
			.into_iter()
			.map(String::into_bytes)
			.collect(),
		makedepends: Vec::new(),
		base64_sig: (rng.below(2) == 0).then(|| b"c2ln".to_vec()),
		download_size: rng.below(100) as i64,
		// loaded like a package from a file or sync db
		infolevel: INFRQ_ALL,
		origin: match rng.below(4) {
			0 => None,
			1 => Some(PkgFrom::File(
				b"/tmp/x.pkg.tar.zst".to_vec(),
			)),
			2 => Some(PkgFrom::LocalDb),
			_ => Some(PkgFrom::SyncDb),
		},
		..Package::default()
	}
}

// one random op on both sides, results compared
fn step(b: &mut Both, rng: &mut Rng) {
	let names = b.names();
	let db = names.get(rng.below(names.len().max(1))).cloned();
	let op = rng.below(26);
	let n = db.clone().unwrap_or_default();
	let nb = n.as_bytes();
	writeln!(b.log, "op {op} on {n:?}").unwrap();
	match (op, &db) {
		(0 | 1, _) => {
			let tree = pick(rng, &TREES);
			let level = LEVELS[rng.below(LEVELS.len())];
			writeln!(b.log, "  register {tree:?} {level:#x}")
				.unwrap();
			let c = b.c.register_syncdb(tree.as_bytes(), level);
			let r = match b
				.r
				.register_syncdb(tree.as_bytes(), level)
			{
				Ok(_) => (true, 0),
				Err(e) => (false, e as c_int),
			};
			check!(b, "register", c, r);
			b.seen.registered += usize::from(c.0);
		}
		(2, Some(_)) if rng.below(4) == 0 => {
			let c = b.c.unregister(nb);
			let r = match n.as_str() {
				"local" => b.r.unregister_localdb(),
				_ => b.r.unregister_syncdb(nb),
			};
			check!(b, "unregister", c, unit(r));
		}
		(3, _) if rng.below(8) == 0 => {
			let c = b.c.unregister_all_syncdbs();
			b.r.unregister_all_syncdbs();
			check!(b, "unregister all", c, (0, 0));
		}
		(4, Some(_)) => {
			let (url, cache) =
				(pick(rng, &URLS), rng.below(2) == 0);
			writeln!(b.log, "  add {url:?} cache {cache}").unwrap();
			let c = b.c.add_server(nb, url.as_bytes(), cache);
			let db = b.db(&n);
			let r = match cache {
				false => {
					db.add_server(&mut Rec, url.as_bytes())
				}
				true => db.add_cache_server(
					&mut Rec,
					url.as_bytes(),
				),
			};
			check!(b, "add server", c, unit(r));
		}
		(5, Some(_)) => {
			let (url, cache) =
				(pick(rng, &URLS), rng.below(2) == 0);
			writeln!(b.log, "  remove {url:?} cache {cache}")
				.unwrap();
			let c = b.c.remove_server(nb, url.as_bytes(), cache);
			let db = b.db(&n);
			let r = match cache {
				false => db.remove_server(
					&mut Rec,
					url.as_bytes(),
				),
				true => db.remove_cache_server(
					&mut Rec,
					url.as_bytes(),
				),
			};
			check!(b, "remove server", c, found(r));
		}
		(6, Some(_)) => {
			let urls: Vec<Vec<u8>> = (0..rng.below(4))
				.map(|_| pick(rng, &URLS).as_bytes().to_vec())
				.collect();
			let cache = rng.below(2) == 0;
			writeln!(b.log, "  set {urls:?} cache {cache}")
				.unwrap();
			let c = b.c.set_servers(nb, &urls, cache);
			let db = b.db(&n);
			let r = match cache {
				false => db.set_servers(&mut Rec, &urls),
				true => db.set_cache_servers(&mut Rec, &urls),
			};
			check!(b, "set servers", c, unit(r));
		}
		(7, Some(_)) => {
			let usage = match rng.below(3) {
				0 => rng.below(16) as c_int,
				1 => -(rng.below(5) as c_int),
				_ => rng.next_u64() as c_int,
			};
			b.c.set_usage(nb, usage);
			b.db(&n).set_usage(usage);
		}
		(8 | 9, Some(_)) => {
			let (c, ce) = b.c.pkgcache(nb);
			let ext = b.ext();
			let (r, re, counts) = match b
				.db(&n)
				.pkgcache(&ext, &mut Rec)
			{
				Ok(cache) => (
					cache.iter().cloned().collect(),
					0,
					Some((
						cache.len(),
						cache.buckets(),
						cache.limit(),
					)),
				),
				Err(e) => (Vec::new(), e as c_int, None),
			};
			check!(b, "pkgcache", (c, ce), (r, re));
			check!(b, "counts", b.c.cache_counts(nb), counts);
		}
		(10 | 20 | 21, Some(_)) => {
			let name = match rng.below(6) {
				0 => "",
				1 => "missing",
				_ => pick(rng, &PKG_NAMES),
			};
			writeln!(b.log, "  get_pkg {name:?}").unwrap();
			let c = b.c.get_pkg(nb, name.as_bytes());
			let ext = b.ext();
			let r = pkg_or_err(b.db(&n).get_pkg(
				&ext,
				&mut Rec,
				name.as_bytes(),
			));
			b.seen.pkg_hits += usize::from(c.0.is_some());
			check!(b, "get_pkg", c, r);
		}
		(11 | 12, Some(_)) => {
			let c = b.c.groupcache(nb);
			b.seen.groups += c.0.len();
			let ext = b.ext();
			let r = rust_groupcache(b.db(&n), &ext);
			check!(b, "groupcache", c, r);
		}
		(13, Some(_)) => {
			let grp = match rng.below(5) {
				0 => "",
				1 => "nogroup",
				_ => pick(rng, &GROUPS),
			};
			writeln!(b.log, "  get_group {grp:?}").unwrap();
			let c = b.c.get_group(nb, grp.as_bytes());
			let ext = b.ext();
			let r = rust_get_group(b.db(&n), &ext, grp.as_bytes());
			check!(b, "get_group", c, r);
		}
		(14 | 15, Some(_)) => {
			let pkg = gen_add_pkg(rng);
			writeln!(b.log, "  add {pkg:?}").unwrap();
			let (cr, ce, new) = b.c.add_pkg_in_cache(nb, &pkg);
			let r = cache_err(
				b.db(&n).add_pkg_in_cache(&mut Rec, &pkg),
			);
			check!(b, "add pkg", (cr, ce), r);
			b.seen.added += usize::from(new.is_some());
			if let Some((i, cpkg)) = new {
				let ext = b.ext();
				let cache =
					b.db(&n).pkgcache(&ext, &mut Rec)
						.unwrap();
				let rpkg = cache.iter().nth(i).unwrap().clone();
				check!(b, "added entry", cpkg, rpkg);
			}
		}
		(16 | 22, Some(_)) => {
			let name = pick(rng, &PKG_NAMES);
			let mut key = Package {
				name_hash: hash_sdbm(name.as_bytes()),
				name: Some(name.as_bytes().to_vec()),
				..Package::default()
			};
			if rng.below(8) == 0 {
				// stale hash: the C matches name and hash
				key.name_hash ^= 1;
			}
			writeln!(b.log, "  remove {name:?} {}", key.name_hash)
				.unwrap();
			let c = b.c.remove_pkg_from_cache(nb, &key);
			b.seen.removed += usize::from(c.0 == 0);
			let r =
				b.db(&n).remove_pkg_from_cache(&mut Rec, &key)
					.map(drop);
			check!(b, "remove pkg", c, cache_err(r));
		}
		(17, Some(_)) if rng.below(3) == 0 => {
			b.c.free_pkgcache(nb);
			b.db(&n).free_pkgcache(&mut Rec);
		}
		(18, Some(_)) => {
			let c = b.c.valid(nb);
			check!(b, "valid", c, unit(b.db(&n).valid()));
		}
		(19, _) if names.len() >= 2 => {
			let x = &names[rng.below(names.len())];
			let y = &names[rng.below(names.len())];
			let c = b.c.db_cmp(x.as_bytes(), y.as_bytes());
			let find = |s: &str| -> &Db {
				let r = &b.r;
				match s {
					"local" => r.localdb().unwrap(),
					_ => r.syncdbs()
						.iter()
						.find(|d| {
							d.name() == s.as_bytes()
						})
						.unwrap(),
				}
			};
			check!(b, "db_cmp", c, db_cmp(find(x), find(y)));
		}
		(23 | 24, Some(_)) => {
			let name = match rng.below(6) {
				0 => "",
				1 => "missing",
				_ => pick(rng, &PKG_NAMES),
			};
			let inforeq = INFOREQS[rng.below(INFOREQS.len())];
			writeln!(b.log, "  load_pkg {name:?} {inforeq:#x}")
				.unwrap();
			let c = b.c.load_pkg(nb, name.as_bytes(), inforeq);
			let ext = b.ext();
			let db = b.db(&n);
			let r = pkg_or_err(db.load_pkg(
				&ext,
				&mut Rec,
				name.as_bytes(),
				inforeq,
			));
			b.seen.loaded += usize::from(c.0.is_some());
			check!(b, "load_pkg", c, r);
			// the same cache entry, read again
			let c = b.c.get_pkg(nb, name.as_bytes());
			let r = pkg_or_err(b.db(&n).get_pkg(
				&ext,
				&mut Rec,
				name.as_bytes(),
			));
			check!(b, "get_pkg after load", c, r);
		}
		(25, _) if rng.below(2) == 0 => {
			let dbext = pick(rng, &DBEXTS);
			writeln!(b.log, "  set dbext {dbext:?}").unwrap();
			let c = b.c.set_dbext(dbext.as_bytes());
			b.r.set_dbext(dbext.as_bytes());
			check!(b, "set dbext", c, (0, 0));
		}
		_ => {}
	}
	b.compare_logs(&format!("op {op}"));
	b.compare_state();
}

#[test]
fn fuzz_sequences() {
	let mut rng = Rng::new(0xdb5eed);
	let mut seen = Seen::default();
	for case in 0..cases() {
		let fx = TempRoot::new("db");
		let local = gen_pkgs(&mut rng, 6);
		write_local(&fx, &local);
		// sync files are named for this dbext, ops may change it later
		let dbext = pick(&mut rng, &DBEXTS);
		let files = gen_sync_files(&mut rng, &fx, dbext);
		let dbpath = [&b""[..], b"/", b"//"][rng.below(3)];
		let dbpath = [fx.path("db"), dbpath.to_vec()].concat();
		let mut b = Both::new(&fx, &dbpath);
		writeln!(
			b.log,
			"case {case} dbext {dbext:?}\nlocal {local:?}\n{files}"
		)
		.unwrap();
		check!(b, "set dbext", b.c.set_dbext(dbext.as_bytes()), (0, 0));
		b.r.set_dbext(dbext.as_bytes());
		if rng.below(4) == 0 {
			let level = [0, 1, 7][rng.below(3)];
			b.c.set_default_siglevel(level);
			b.r.set_default_siglevel(level).unwrap();
		}
		b.compare_state();
		b.compare_logs("setup");
		for _ in 0..OPS {
			step(&mut b, &mut rng);
		}
		seen.pkg_hits += b.seen.pkg_hits;
		seen.loaded += b.seen.loaded;
		seen.groups += b.seen.groups;
		seen.added += b.seen.added;
		seen.removed += b.seen.removed;
		seen.registered += b.seen.registered;
		seen.errors += b.seen.errors;
		seen.debug += b.seen.debug;
		seen.function += b.seen.function;
		// alpm_release: unlock, then the dbs unregistered
		let Both { c, r, log, .. } = b;
		let c = c_logs(c.release_logs());
		drop(r);
		let r = take_rust_logs();
		assert_eq!(c, r, "release logs\nops:\n{log}");
	}
	eprintln!("{} cases of {OPS} ops: {seen:?}", cases());
	let n = cases();
	assert!(seen.pkg_hits > n && seen.groups > n, "{seen:?}");
	assert!(seen.loaded > n, "{seen:?}");
	assert!(seen.added > n && seen.removed > n / 2, "{seen:?}");
	assert!(seen.registered > n, "{seen:?}");
	assert!(seen.errors > n / 4 && seen.debug > 10 * n, "{seen:?}");
	assert!(seen.function > n, "{seen:?}");
}

// alpm_initialize: what root and dbpath become, and its errors
#[test]
fn initialize_paths() {
	let fx = TempRoot::new("db");
	write_local(&fx, &[]);
	fs::write(fx.dir().join("file"), "").unwrap();
	symlink(fx.dir().join("root"), fx.dir().join("rootlink")).unwrap();
	symlink(fx.dir().join("db"), fx.dir().join("dblink")).unwrap();
	symlink(fx.dir().join("nowhere"), fx.dir().join("dangling")).unwrap();
	let p = |rel: &str| fx.path(rel);
	let cases: Vec<(Vec<u8>, Vec<u8>)> = vec![
		(p("root"), p("db")),
		(p("root/"), p("db//")),
		(p("rootlink"), p("dblink/")),
		(p("root/../root/."), p("db/./")),
		(b"/".to_vec(), p("db")),
		(b".".to_vec(), p("db")),
		(b"".to_vec(), p("db")),
		(p("nope"), p("db")),
		(p("file"), p("db")),
		(p("dangling"), p("db")),
		(p("root"), b"".to_vec()),
		(p("root"), p("nope")),
		(p("root"), p("file")),
		(p("nope"), p("nope")),
	];
	for (root, dbpath) in cases {
		let what = format!(
			"{:?} {:?}",
			String::from_utf8_lossy(&root),
			String::from_utf8_lossy(&dbpath)
		);
		let c = CHandle::new(&root, &dbpath)
			.map(|h| (h.root(), h.dbpath(), h.dbext()));
		let r = Handle::initialize(&root, &dbpath)
			.map(|h| {
				(
					h.root().to_vec(),
					h.dbpath().to_vec(),
					h.dbext().to_vec(),
				)
			})
			.map_err(|e| e as c_int);
		assert_eq!(c, r, "{what}");
	}
}

// local db errors through alpm_initialize: missing local/ is created,
// a file or a wrong version refused
#[test]
fn initialize_local_db() {
	type Setup = fn(&TempRoot);
	let setups: [(&str, Setup); 4] = [
		("missing", |_| {}),
		("file", |fx| {
			fs::write(fx.dir().join("db/local"), "").unwrap()
		}),
		("version", |fx| {
			write_local(fx, &[]);
			fs::write(
				fx.dir().join("db/local/ALPM_DB_VERSION"),
				"8\n",
			)
			.unwrap();
		}),
		("empty", |fx| {
			fs::create_dir(fx.dir().join("db/local")).unwrap()
		}),
	];
	for (what, setup) in setups {
		let fx = TempRoot::new("db");
		let (root, dbpath) = (fx.path("root"), fx.path("db"));
		setup(&fx);
		let c = CHandle::new(&root, &dbpath)
			.map(|h| h.has_db(b"local"));
		let made = fs::read_dir(fx.dir().join("db")).unwrap().count();
		// reset what the C created or left
		let _ = fs::remove_dir_all(fx.dir().join("db/local"));
		let _ = fs::remove_file(fx.dir().join("db/local"));
		setup(&fx);
		let r = Handle::initialize(&root, &dbpath)
			.map(|h| h.localdb().is_some())
			.map_err(|e| e as c_int);
		assert_eq!(c, r, "{what}");
		let made_r = fs::read_dir(fx.dir().join("db")).unwrap().count();
		assert_eq!(made, made_r, "{what}");
	}
}

// names refused or taken, registration order, re-registration
#[test]
fn register_names() {
	let fx = TempRoot::new("db");
	write_local(&fx, &[]);
	let mut b = Both::new(&fx, &fx.path("db"));
	let seq: [&[u8]; 12] = [
		b"core", b"", b"local", b"a/b", b"/", b"core", b"extra",
		b"Core", b"core ", b"lo", b"extra", b"localx",
	];
	for name in seq {
		let c = b.c.register_syncdb(name, 0);
		let r = match b.r.register_syncdb(name, 0) {
			Ok(_) => (true, 0),
			Err(e) => (false, e as c_int),
		};
		check!(
			b,
			&format!("{:?}", String::from_utf8_lossy(name)),
			c,
			r
		);
		b.compare_state();
	}
	check!(
		b,
		"unreg",
		b.c.unregister(b"core"),
		unit(b.r.unregister_syncdb(b"core"))
	);
	check!(b, "again", b.c.register_syncdb(b"core", 0), (true, 0));
	b.r.register_syncdb(b"core", 0).unwrap();
	b.compare_state();
	check!(
		b,
		"local",
		b.c.unregister(b"local"),
		unit(b.r.unregister_localdb())
	);
	b.compare_state();
	// "local" stays reserved without a local db
	check!(
		b,
		"reserved",
		b.c.register_syncdb(b"local", 0),
		(false, Errno::DbNotNull as c_int)
	);
	assert_eq!(
		b.r.register_syncdb(b"local", 0).err(),
		Some(Errno::DbNotNull)
	);
	check!(b, "all", b.c.unregister_all_syncdbs(), (0, 0));
	b.r.unregister_all_syncdbs();
	b.compare_state();
}

// sanitize_url: one trailing '/' dropped, "/" stored as ""; set stops at
// the first empty url
#[test]
fn server_urls() {
	let fx = TempRoot::new("db");
	write_local(&fx, &[]);
	let mut b = Both::new(&fx, &fx.path("db"));
	b.c.register_syncdb(b"core", 0);
	b.r.register_syncdb(b"core", 0).unwrap();
	for url in URLS {
		for db in ["core", "local"] {
			let c = b.c.add_server(
				db.as_bytes(),
				url.as_bytes(),
				false,
			);
			let r = unit(b
				.db(db)
				.add_server(&mut Rec, url.as_bytes()));
			check!(b, url, c, r);
		}
	}
	b.compare_state();
	assert_eq!(b.db("core").servers()[0], b"");
	for url in ["a//", "a/", "/", "/", "", "zz"] {
		let c = b.c.remove_server(b"core", url.as_bytes(), false);
		let r = found(b
			.db("core")
			.remove_server(&mut Rec, url.as_bytes()));
		check!(b, url, c, r);
		b.compare_state();
	}
	let urls: Vec<Vec<u8>> =
		vec![b"x/".to_vec(), b"".to_vec(), b"y".to_vec()];
	let c = b.c.set_servers(b"core", &urls, true);
	check!(
		b,
		"set",
		c,
		unit(b.db("core").set_cache_servers(&mut Rec, &urls))
	);
	b.compare_state();
	assert_eq!(b.db("core").cache_servers(), [b"x".to_vec()]);
}

// a package naming a group twice lands in two groups of that name; a
// later package joins the first
#[test]
fn duplicate_group_entries() {
	let fx = TempRoot::new("db");
	let pkgs = [
		Pkg::plain("a", &["g", "g", "h", "g"]),
		Pkg::plain("b", &["g", "h"]),
	];
	write_local(&fx, &pkgs);
	write_sync(&fx, "core.db", &sync_db(&pkgs));
	let mut b = Both::new(&fx, &fx.path("db"));
	b.c.register_syncdb(b"core", 0);
	b.r.register_syncdb(b"core", 0).unwrap();
	let g = |name: &str, packages: &[usize]| Group {
		name: name.as_bytes().to_vec(),
		packages: packages.to_vec(),
	};
	let want = vec![
		g("g", &[0, 1]),
		g("g", &[0]),
		g("h", &[0, 1]),
		g("g", &[0]),
	];
	for db in ["local", "core"] {
		let c = b.c.groupcache(db.as_bytes());
		check!(b, db, &c, &rust_groupcache(b.db(db), DBEXT));
		check!(b, db, c, (want.clone(), 0));
		let c = b.c.get_group(db.as_bytes(), b"g");
		check!(b, db, c, rust_get_group(b.db(db), DBEXT, b"g"));
	}
}

// a group cache built while the package cache failed stays empty after
// the cache loads (_alpm_db_free_pkgcache skips it without a cache)
#[test]
fn stale_group_cache() {
	let fx = TempRoot::new("db");
	write_local(&fx, &[]);
	let pkgs = vec![Pkg::plain("a", &["g"])];
	let good = sync_db(&pkgs);
	write_sync(&fx, "core.db", &good[..700]);
	let mut b = Both::new(&fx, &fx.path("db"));
	b.c.register_syncdb(b"core", 0);
	b.r.register_syncdb(b"core", 0).unwrap();
	let c = b.c.groupcache(b"core");
	check!(b, "broken", &c, &rust_groupcache(b.db("core"), DBEXT));
	assert_eq!(c, (Vec::new(), Errno::Libarchive as c_int));
	write_sync(&fx, "core.db", &good);
	let c = b.c.pkgcache(b"core");
	assert_eq!((c.0.len(), c.1), (1, 0));
	assert_eq!(
		b.db("core").pkgcache(DBEXT, &mut Rec).map(|p| p.len()),
		Ok(1)
	);
	for _ in 0..2 {
		let c = b.c.groupcache(b"core");
		check!(b, "stale", &c, &rust_groupcache(b.db("core"), DBEXT));
		assert_eq!(c, (Vec::new(), 0));
	}
	// freeing a loaded cache drops the group cache with it
	b.c.free_pkgcache(b"core");
	b.db("core").free_pkgcache(&mut Rec);
	let c = b.c.groupcache(b"core");
	check!(b, "rebuilt", &c, &rust_groupcache(b.db("core"), DBEXT));
	assert_eq!(c.0.len(), 1);
}

// _alpm_db_path is fixed at registration, a later dbext only moves dbs
// registered after it
#[test]
fn dbext_and_paths() {
	let fx = TempRoot::new("db");
	write_local(&fx, &[]);
	let mut b = Both::new(&fx, &fx.path("db"));
	for (tree, ext) in [("core", ".files"), ("extra", ""), ("c", ".db.tar")]
	{
		b.c.register_syncdb(tree.as_bytes(), 0);
		b.r.register_syncdb(tree.as_bytes(), 0).unwrap();
		check!(b, "dbext", b.c.set_dbext(ext.as_bytes()), (0, 0));
		b.r.set_dbext(ext.as_bytes());
		check!(b, "get dbext", b.c.dbext(), b.r.dbext().to_vec());
		b.compare_state();
	}
}

// invalid sync dbs: a bad entry or an unopenable file invalidates for
// good, missing files stay missing
#[test]
fn invalid_sync_dbs() {
	let fx = TempRoot::new("db");
	write_local(&fx, &[]);
	let bad = Pkg::plain("a", &[]);
	let mut tar = sync_db(&[bad]);
	// %FILENAME% with a '/', _alpm_validate_filename refuses it
	let at = tar.windows(5).position(|w| w == b"\na-1-").unwrap();
	tar[at + 2] = b'/';
	write_sync(&fx, "core.db", &tar);
	symlink(fx.dir().join("nowhere"), fx.dir().join("db/sync/extra.db"))
		.unwrap();
	let mut b = Both::new(&fx, &fx.path("db"));
	for tree in ["core", "extra", "gone"] {
		b.c.register_syncdb(tree.as_bytes(), 0);
		b.r.register_syncdb(tree.as_bytes(), 0).unwrap();
		let n = tree.as_bytes();
		for _ in 0..2 {
			check!(
				b,
				"valid",
				b.c.valid(n),
				unit(b.db(tree).valid())
			);
			let c = b.c.pkgcache(n);
			let r = b
				.db(tree)
				.pkgcache(DBEXT, &mut Rec)
				.map(|p| p.len());
			check!(
				b,
				tree,
				(c.0.len(), c.1),
				(
					r.unwrap_or(0),
					r.err().map_or(0, |e| e as c_int)
				)
			);
			check!(
				b,
				"groups",
				b.c.groupcache(n),
				rust_groupcache(b.db(tree), DBEXT)
			);
			let c = b.c.get_pkg(n, b"a").1;
			check!(
				b,
				"get_pkg",
				c,
				b.db(tree)
					.get_pkg(DBEXT, &mut Rec, b"a")
					.err()
					.unwrap() as c_int
			);
		}
	}
}

// handle string lists, siglevels and the fnmatch helpers
#[test]
fn handle_options() {
	let fx = TempRoot::new("db");
	write_local(&fx, &[]);
	let mut b = Both::new(&fx, &fx.path("db"));
	let mut rng = Rng::new(0x0b7);
	let lists = [
		StrList::Arch,
		StrList::NoUpgrade,
		StrList::NoExtract,
		StrList::IgnorePkg,
		StrList::IgnoreGroup,
	];
	let words: [&[u8]; 9] = [
		b"",
		b"x86_64",
		b"etc/*",
		b"!etc/foo",
		b"\\!x",
		b"*",
		b"a",
		b"a",
		b"usr/",
	];
	for i in 0..iters() / 10 {
		let which = lists[rng.below(lists.len())];
		let w = words[rng.below(words.len())];
		let r = &mut b.r;
		let (c, rr) = match rng.below(4) {
			0 => {
				let c = b.c.strlist_add(which, w);
				match which {
					StrList::Arch => r.add_architecture(w),
					StrList::NoUpgrade => {
						r.add_noupgrade(w)
					}
					StrList::NoExtract => {
						r.add_noextract(w)
					}
					StrList::IgnorePkg => {
						r.add_ignorepkg(w)
					}
					StrList::IgnoreGroup => {
						r.add_ignoregroup(w)
					}
				}
				(c, (0, 0))
			}
			1 => {
				let c = b.c.strlist_remove(which, w);
				let removed = match which {
					StrList::Arch => {
						r.remove_architecture(w)
					}
					StrList::NoUpgrade => {
						r.remove_noupgrade(w)
					}
					StrList::NoExtract => {
						r.remove_noextract(w)
					}
					StrList::IgnorePkg => {
						r.remove_ignorepkg(w)
					}
					StrList::IgnoreGroup => {
						r.remove_ignoregroup(w)
					}
				};
				(c, (removed as c_int, 0))
			}
			2 if rng.below(4) == 0 => {
				let set: Vec<Vec<u8>> = (0..rng.below(3))
					.map(|_| {
						words[rng.below(words.len())]
							.to_vec()
					})
					.collect();
				let c = b.c.strlist_set(which, &set);
				match which {
					StrList::Arch => {
						r.set_architectures(&set)
					}
					StrList::NoUpgrade => {
						r.set_noupgrades(&set)
					}
					StrList::NoExtract => {
						r.set_noextracts(&set)
					}
					StrList::IgnorePkg => {
						r.set_ignorepkgs(&set)
					}
					StrList::IgnoreGroup => {
						r.set_ignoregroups(&set)
					}
				}
				(c, (0, 0))
			}
			_ => {
				let path = words[rng.below(words.len())];
				let m = |x: Option<bool>| {
					x.map_or(-1, c_int::from)
				};
				let c = (
					b.c.match_list(true, path),
					b.c.match_list(false, path),
				);
				let r = (
					m(r.match_noupgrade(path)),
					m(r.match_noextract(path)),
				);
				(c, r)
			}
		};
		check!(b, &format!("op {i} {which:?} {w:?}"), c, rr);
		let r = &b.r;
		let want = match which {
			StrList::Arch => r.architectures(),
			StrList::NoUpgrade => r.noupgrades(),
			StrList::NoExtract => r.noextracts(),
			StrList::IgnorePkg => r.ignorepkgs(),
			StrList::IgnoreGroup => r.ignoregroups(),
		};
		check!(
			b,
			&format!("list {which:?}"),
			b.c.strlist(which),
			want.to_vec()
		);
	}
	for level in [0, 1, 0x7ff, SIG_USE_DEFAULT, SIG_USE_DEFAULT | 1, -1] {
		let c = b.c.set_default_siglevel(level);
		check!(b, "default", c, unit(b.r.set_default_siglevel(level)));
		for local in [true, false] {
			let file = [SIG_USE_DEFAULT | 2, 4, 0][rng.below(3)];
			check!(
				b,
				"file",
				b.c.set_file_siglevel(local, file),
				(0, 0)
			);
			match local {
				true => b.r.set_local_file_siglevel(file),
				false => b.r.set_remote_file_siglevel(file),
			}
		}
		check!(
			b,
			"default get",
			b.c.default_siglevel(),
			b.r.default_siglevel()
		);
		check!(
			b,
			"local get",
			b.c.file_siglevel(true),
			b.r.local_file_siglevel()
		);
		check!(
			b,
			"remote get",
			b.c.file_siglevel(false),
			b.r.remote_file_siglevel()
		);
	}
}

// lazy loads of a cached package stay in the cache entry: getters on the
// C alpm_pkg_t and load_pkg on the Rust Db, then the entry read again
// through get_pkg, the cache list and the group cache
#[test]
fn load_cached_package() {
	let fx = TempRoot::new("db");
	let full = Pkg {
		files: true,
		install: true,
		..Pkg::plain("a", &["g"])
	};
	let bare = Pkg {
		desc: false,
		..Pkg::plain("b", &[])
	};
	write_local(&fx, &[full, Pkg::plain("c", &["g"]), bare]);
	let mut b = Both::new(&fx, &fx.path("db"));
	let loads = [
		("a", INFRQ_DESC),
		("a", INFRQ_FILES | INFRQ_SCRIPTLET),
		("c", INFRQ_FILES),
		("c", INFRQ_DESC),
		("b", INFRQ_DESC),
		("b", INFRQ_DESC | INFRQ_FILES),
	];
	for (name, inforeq) in loads {
		let what = format!("{name} {inforeq:#x}");
		let c = b.c.load_pkg(b"local", name.as_bytes(), inforeq);
		let db = b.db("local");
		let r = pkg_or_err(db.load_pkg(
			DBEXT,
			&mut Rec,
			name.as_bytes(),
			inforeq,
		));
		check!(b, &what, &c, &r);
		let again = b.c.get_pkg(b"local", name.as_bytes());
		check!(b, &what, &again, &c);
		let r = pkg_or_err(b.db("local").get_pkg(
			DBEXT,
			&mut Rec,
			name.as_bytes(),
		));
		check!(b, &what, again, r);
	}
	let c = b.c.pkgcache(b"local");
	let r = b.db("local").pkgcache(DBEXT, &mut Rec).unwrap();
	let r: Vec<Package> = r.iter().cloned().collect();
	check!(b, "cache", &c, &(r.clone(), 0));
	let level = |name: &[u8]| {
		let p = r.iter().find(|p| p.name_bytes() == name).unwrap();
		p.infolevel
	};
	let all = INFRQ_DESC | INFRQ_FILES | INFRQ_SCRIPTLET;
	assert_eq!(level(b"a"), all);
	assert_ne!(level(b"c") & INFRQ_ERROR, 0);
	assert_ne!(level(b"b") & INFRQ_ERROR, 0);
	let c = b.c.groupcache(b"local");
	check!(b, "groups", &c, &rust_groupcache(b.db("local"), DBEXT));
	assert_eq!(c.0.len(), 1);
}

// _alpm_db_path is fixed at registration, the populate size estimate
// reads handle->dbext when the cache loads: core registered as .db and
// loaded under .files (sized for a quarter, then grown), extra the other
// way. same file, so only the dbext at load tells the tables apart
#[test]
fn dbext_at_load_time() {
	let fx = TempRoot::new("db");
	write_local(&fx, &[]);
	let pkgs: Vec<Pkg> =
		(0..60).map(|i| Pkg::plain(&format!("p{i}"), &[])).collect();
	let tar = sync_db(&pkgs);
	write_sync(&fx, "core.db", &tar);
	write_sync(&fx, "extra.files", &tar);
	let mut b = Both::new(&fx, &fx.path("db"));
	let set = |b: &mut Both, ext: &str| {
		check!(b, ext, b.c.set_dbext(ext.as_bytes()), (0, 0));
		b.r.set_dbext(ext.as_bytes());
	};
	let load = |b: &mut Both, tree: &str| {
		let n = tree.as_bytes();
		let c = b.c.pkgcache(n);
		let ext = b.ext();
		let r = b.db(tree).pkgcache(&ext, &mut Rec).unwrap();
		let counts = (r.len(), r.buckets(), r.limit());
		let r: Vec<Package> = r.iter().cloned().collect();
		check!(b, tree, c, (r, 0));
		check!(b, tree, b.c.cache_counts(n), Some(counts));
		counts
	};
	b.c.register_syncdb(b"core", 0);
	b.r.register_syncdb(b"core", 0).unwrap();
	set(&mut b, ".files");
	b.c.register_syncdb(b"extra", 0);
	b.r.register_syncdb(b"extra", 0).unwrap();
	b.compare_state();
	let core = load(&mut b, "core");
	set(&mut b, ".db");
	let extra = load(&mut b, "extra");
	b.compare_state();
	assert_eq!((core.0, extra.0), (60, 60));
	assert_ne!(core.1, extra.1, "{core:?} {extra:?}");
}
