// alpm_core::db::Db::search against C alpm_db_search: fixture roots
// under /tmp with a local db and sync dbs of random packages (names,
// descriptions, provides, groups), searched with random needle lists
// (regex specials, case, the strstr name fallback, invalid patterns)
// on a C handle and a Rust Handle over the same files. return, result
// names in order and, on failure, pm_errno are compared
use std::ffi::c_int;
use std::fmt::Write as _;
use std::fs;

use alpm_core::be_local::{INFRQ_DESC, INFRQ_ERROR};
use alpm_core::db::{DB_USAGE_ALL, DB_USAGE_SEARCH, Db};
use alpm_core::error::Errno;
use alpm_core::handle::Handle;
use difftest::{
	CSearch, LocalEntry, Rng, SearchWorld, TempRoot, iters, section,
	tar_dir, tar_file, ustar,
};

// one fixture per case, many needle lists on it
fn cases() -> usize {
	(iters() / 1000).max(20)
}

const LISTS: usize = 100;

#[derive(Clone, Debug)]
struct Pkg {
	name: String,
	desc: Option<String>,
	provides: Vec<String>,
	groups: Vec<String>,
}

const NAME_FIRST: &[u8] = b"abcxyz019";
const NAME_REST: &[u8] = b"abcxyz019+-_";
// no double, leading or trailing spaces: alpm-db normalizes them
const WORDS: &[&str] = &[
	"a", "ab", "abc", "Ab", "X", "xyz", "foo", "Foo", "BAR", "b+c", "x^y",
	"a$b", "é", "É", "c++", "1.0", "(x)", "[y]", "q|r", "-z",
];

fn gen_name(rng: &mut Rng) -> String {
	let mut s = vec![rng.pick(NAME_FIRST)];
	s.extend(rng.bytes(NAME_REST, 6));
	String::from_utf8(s).unwrap()
}

fn gen_pkgs(rng: &mut Rng, max: usize) -> Vec<Pkg> {
	let mut pkgs: Vec<Pkg> = Vec::new();
	for _ in 0..rng.below(max + 1) {
		let name = gen_name(rng);
		if pkgs.iter().any(|p| p.name == name) {
			continue;
		}
		let desc = (rng.below(5) != 0).then(|| {
			let n = 1 + rng.below(4);
			let w: Vec<&str> = (0..n)
				.map(|_| WORDS[rng.below(WORDS.len())])
				.collect();
			w.join(" ")
		});
		let provides = (0..rng.below(3))
			.map(|_| match rng.below(2) {
				0 => gen_name(rng),
				_ => format!("{}=1.0", gen_name(rng)),
			})
			.collect();
		let groups = (0..rng.below(3)).map(|_| gen_name(rng)).collect();
		pkgs.push(Pkg {
			name,
			desc,
			provides,
			groups,
		});
	}
	pkgs
}

fn desc_section(p: &Pkg) -> String {
	match &p.desc {
		Some(d) => format!("%DESC%\n{d}\n\n"),
		None => String::new(),
	}
}

// alpm-db refuses a local desc without %DESC%, the C reads NULL
fn local_desc(p: &Pkg) -> String {
	let desc = p.desc.as_deref().unwrap_or("x");
	format!(
		"%NAME%\n{0}\n\n%VERSION%\n1-1\n\n%BASE%\n{0}\n\n%DESC%\n{1}\n\n\
		%URL%\nhttps://example.org/\n\n%ARCH%\nx86_64\n\n\
		%BUILDDATE%\n1700000000\n\n%INSTALLDATE%\n1700000001\n\n\
		%PACKAGER%\nA B <a@b.org>\n\n%SIZE%\n42\n\n\
		%VALIDATION%\npgp\n\n{2}{3}",
		p.name,
		desc,
		section("GROUPS", &p.groups),
		section("PROVIDES", &p.provides)
	)
}

fn sync_desc(p: &Pkg) -> String {
	format!(
		"%FILENAME%\n{0}-1-1-any.pkg.tar.zst\n\n%NAME%\n{0}\n\n\
		%BASE%\n{0}\n\n%VERSION%\n1-1\n\n{1}%CSIZE%\n1\n\n%ISIZE%\n2\n\n\
		%SHA256SUM%\n{2}\n\n%ARCH%\nany\n\n%BUILDDATE%\n3\n\n\
		%PACKAGER%\nA B <a@b.org>\n\n{3}{4}",
		p.name,
		desc_section(p),
		"ab".repeat(32),
		section("GROUPS", &p.groups),
		section("PROVIDES", &p.provides)
	)
}

fn sync_db(pkgs: &[Pkg]) -> Vec<u8> {
	let mut entries = Vec::new();
	for p in pkgs {
		let dir = format!("{}-1-1/", p.name);
		entries.push(tar_dir(&dir));
		let desc = sync_desc(p);
		entries.push(tar_file(&format!("{dir}desc"), desc.as_bytes()));
	}
	ustar(&entries)
}

fn write_local(fx: &TempRoot, pkgs: &[Pkg]) {
	fx.reset_local();
	let entries: Vec<LocalEntry> = pkgs
		.iter()
		.map(|p| LocalEntry {
			dir: format!("{}-1-1", p.name),
			desc: Some(local_desc(p).into_bytes()),
			files: None,
			install: false,
		})
		.collect();
	fx.write_local(&entries);
}

// needle bytes: regex specials, case pairs, letters of the names
const NEEDLE: &[u8] = b"abcxyzABCXYZ019+-_.*?^$[](){}| ";

fn gen_needle(rng: &mut Rng, names: &[&str]) -> Vec<u8> {
	match rng.below(10) {
		// a known name, a piece of it, or with case changed
		0 if !names.is_empty() => {
			let n = names[rng.below(names.len())].as_bytes();
			let (a, b) =
				(rng.below(n.len()), rng.below(n.len() + 1));
			n[a.min(b)..a.max(b)].to_vec()
		}
		1 => WORDS[rng.below(WORDS.len())].as_bytes().to_vec(),
		// escapes that are not back-references
		2 => {
			let e = rng.pick(b"wWsSbB<>.+*");
			[b"\\".as_slice(), &[e], &rng.bytes(b"abcx", 3)]
				.concat()
		}
		3 => "é".as_bytes().to_vec(),
		_ => rng.bytes(NEEDLE, 6),
	}
}

fn rust_search(h: &mut Handle, db: &str, needles: &[Vec<u8>]) -> CSearch {
	let dbext = h.dbext().to_vec();
	let db: &mut Db = match db {
		"local" => h.localdb_mut().unwrap(),
		name => h
			.syncdbs_mut()
			.iter_mut()
			.find(|d| d.name() == name.as_bytes())
			.unwrap(),
	};
	match db.search(&dbext, needles) {
		Ok(pkgs) => CSearch {
			ret: 0,
			names: pkgs
				.iter()
				.map(|p| p.name_bytes().to_vec())
				.collect(),
			errno: 0,
		},
		Err(e) => CSearch {
			ret: -1,
			names: Vec::new(),
			errno: e as c_int,
		},
	}
}

// sync dbs of a case: name, usage, file content (None: absent)
type SyncSpec = (&'static str, c_int, Option<Vec<u8>>);

struct Case {
	fx: TempRoot,
	c: SearchWorld,
	r: Handle,
	names: Vec<String>,
	log: String,
}

fn open_case(local: &[Pkg], sync: &[SyncSpec], log: String) -> Case {
	let fx = TempRoot::new("db-search");
	write_local(&fx, local);
	for (name, _, data) in sync {
		if let Some(d) = data {
			fs::write(fx.sync_file(name, ".db"), d).unwrap();
		}
	}
	let reg: Vec<(&[u8], c_int)> =
		sync.iter().map(|(n, u, _)| (n.as_bytes(), *u)).collect();
	let c = SearchWorld::open(&fx.root(), &fx.dbpath(), &reg);
	let mut r = Handle::initialize(&fx.root(), &fx.dbpath()).unwrap();
	for (name, usage, _) in sync {
		r.register_syncdb(name.as_bytes(), 0)
			.unwrap()
			.set_usage(*usage);
	}
	// the generators stay inside what alpm-db/alpm-repo-db read
	let dbext = r.dbext().to_vec();
	let ldb = r.localdb_mut().unwrap();
	for p in local {
		let pkg = ldb.load_pkg(&dbext, p.name.as_bytes(), INFRQ_DESC);
		let level = pkg.map(|p| p.infolevel).unwrap_or(INFRQ_ERROR);
		assert_eq!(level & INFRQ_ERROR, 0, "alpm-db refuses {p:?}");
	}
	for db in r.syncdbs_mut() {
		let e = db.pkgcache(&dbext).err();
		assert!(
			matches!(
				e,
				None | Some(Errno::DbNotFound
					| Errno::Libarchive
					| Errno::DbInvalid | Errno::DbOpen)
			),
			"{:?} {e:?}",
			db.name()
		);
	}
	let names = local.iter().map(|p| p.name.clone()).collect();
	Case {
		fx,
		c,
		r,
		names,
		log,
	}
}

impl Case {
	fn check(&mut self, db: &str, needles: &[Vec<u8>]) -> CSearch {
		let c = self.c.search(db.as_bytes(), needles);
		let r = rust_search(&mut self.r, db, needles);
		let ctx = || {
			format!(
				"db {db} needles {:?}\n{}\nat {:?}",
				needles.iter()
					.map(|n| String::from_utf8_lossy(n))
					.collect::<Vec<_>>(),
				self.log,
				self.fx.dir()
			)
		};
		assert_eq!((c.ret, &c.names), (r.ret, &r.names), "{}", ctx());
		if c.ret != 0 {
			assert_eq!(c.errno, r.errno, "{}", ctx());
		}
		c
	}
}

fn pkg(
	name: &str,
	desc: Option<&str>,
	provides: &[&str],
	groups: &[&str],
) -> Pkg {
	Pkg {
		name: name.into(),
		desc: desc.map(str::to_string),
		provides: provides.iter().map(|s| s.to_string()).collect(),
		groups: groups.iter().map(|s| s.to_string()).collect(),
	}
}

fn needles(list: &[&str]) -> Vec<Vec<u8>> {
	list.iter().map(|s| s.as_bytes().to_vec()).collect()
}

// fixed cases: strstr fallback, desc/provides/groups, AND, order, case,
// errors, usage, failing caches
#[test]
fn fixed() {
	let local = vec![
		pkg("a+b", Some("plain text"), &[], &[]),
		pkg("c++", Some("C"), &["libfoo=1.0"], &["devel"]),
		pkg("zeta", Some("Uses FOO and a+b"), &["bar"], &[]),
		pkg("alpha", Some("x^y marks"), &[], &["base", "devel"]),
		pkg("x-y", Some("é accent"), &["xy"], &["kde"]),
	];
	let sync = vec![
		("core", DB_USAGE_ALL, Some(sync_db(&local[..3]))),
		(
			"nosearch",
			DB_USAGE_ALL & !DB_USAGE_SEARCH,
			Some(sync_db(&local)),
		),
		("gone", DB_USAGE_ALL, None),
		("broken", DB_USAGE_ALL, Some(b"not a tar".repeat(100))),
	];
	let mut case = open_case(&local, &sync, String::new());
	let fixed: &[(&str, &[&str])] = &[
		("local", &["a+b"]),
		("local", &["x^y"]),
		("local", &["c++"]),
		("local", &["libfoo"]),
		("local", &["devel"]),
		("local", &["foo"]),
		("local", &["FOO", "zeta"]),
		("local", &["É"]),
		("local", &["^a"]),
		("local", &[""]),
		("local", &[]),
		("local", &["(", "a"]),
		("core", &["a"]),
		("nosearch", &["a"]),
		("nosearch", &["("]),
		("gone", &["a"]),
		("broken", &["a"]),
		("broken", &["["]),
	];
	for (db, list) in fixed {
		case.check(db, &needles(list));
	}
	// the regex a+b misses "a+b", strstr finds it
	let got = case.check("local", &needles(&["a+b"]));
	assert_eq!(got.names, needles(&["a+b"]));
	// cache list order (by name), every match kept
	let got = case.check("local", &needles(&[""]));
	assert_eq!(got.names, needles(&["a+b", "alpha", "c++", "x-y", "zeta"]));
	// provides and groups, AND over needles
	let got = case.check("local", &needles(&["libfoo"]));
	assert_eq!(got.names, needles(&["c++"]));
	let got = case.check("local", &needles(&["^kde$", "x"]));
	assert_eq!(got.names, needles(&["x-y"]));
	// invalid regexes fail with ALPM_ERR_INVALID_REGEX
	let bad = case.check("local", &needles(&["a", "("]));
	assert_eq!((bad.ret, bad.errno), (-1, Errno::InvalidRegex as c_int));
	let bad = case.check("gone", &needles(&["("]));
	assert_eq!(bad.ret, -1);
}

#[test]
fn fuzz() {
	let mut rng = Rng::new(0x5ea_4c4);
	let mut compared = 0usize;
	for _ in 0..cases() {
		let local = gen_pkgs(&mut rng, 12);
		let mut log = format!("local {local:?}\n");
		let mut sync: Vec<SyncSpec> = Vec::new();
		for name in ["core", "extra"] {
			let usage = match rng.below(4) {
				0 => DB_USAGE_ALL & !DB_USAGE_SEARCH,
				_ => DB_USAGE_ALL,
			};
			let data = match rng.below(8) {
				0 => None,
				1 => Some(b"junk".to_vec()),
				_ => {
					let pkgs = gen_pkgs(&mut rng, 12);
					writeln!(
						log,
						"{name} {usage} {pkgs:?}"
					)
					.unwrap();
					Some(sync_db(&pkgs))
				}
			};
			sync.push((name, usage, data));
		}
		let mut case = open_case(&local, &sync, log);
		let names: Vec<String> = case.names.clone();
		let names: Vec<&str> =
			names.iter().map(String::as_str).collect();
		for _ in 0..LISTS {
			let n = rng.below(4);
			let list: Vec<Vec<u8>> = (0..n)
				.map(|_| gen_needle(&mut rng, &names))
				.collect();
			let db = ["local", "core", "extra"][rng.below(3)];
			case.check(db, &list);
			compared += 1;
		}
	}
	assert!(compared >= cases() * LISTS);
}
