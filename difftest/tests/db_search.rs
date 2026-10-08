// alpm_core::db::Db::search against C alpm_db_search: fixture roots
// under /tmp with a local db and sync dbs of random packages (names,
// descriptions, provides, groups), searched with random needle lists
// (regex specials, case, the strstr name fallback, invalid patterns)
// on a C handle and a Rust Handle over the same files. return, result
// names in order and, on failure, pm_errno are compared
use std::ffi::c_int;
use std::fmt::Write as _;
use std::fs;

use alpm_core::db::{DB_USAGE_ALL, DB_USAGE_SEARCH, Db};
use alpm_core::error::Errno;
use alpm_core::handle::Handle;
use difftest::{
	CSearch, LocalEntry, Rng, SearchWorld, TempRoot, iters, loose_sections,
	section, tar_dir, tar_file, ustar,
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
const WORDS: &[&str] = &[
	"a", "ab", "abc", "Ab", "X", "xyz", "foo", "Foo", "BAR", "b+c", "x^y",
	"a$b", "é", "É", "c++", "1.0", "(x)", "[y]", "q|r", "-z",
];

fn gen_name(rng: &mut Rng) -> String {
	let mut s = vec![rng.pick(NAME_FIRST)];
	s.extend(rng.bytes(NAME_REST, 6));
	String::from_utf8(s).unwrap()
}

// words joined by runs of blanks, now and then blanks around or no
// word at all: the readers keep the line as it is
fn gen_desc(rng: &mut Rng) -> String {
	const BLANKS: [&str; 5] = [" ", " ", "  ", "\t", " \t"];
	let mut d = String::new();
	for i in 0..rng.below(5) {
		if i > 0 || rng.below(6) == 0 {
			d += BLANKS[rng.below(BLANKS.len())];
		}
		d += WORDS[rng.below(WORDS.len())];
	}
	if rng.below(6) == 0 {
		d += BLANKS[rng.below(BLANKS.len())];
	}
	d
}

fn gen_pkgs(rng: &mut Rng, max: usize) -> Vec<Pkg> {
	let mut pkgs: Vec<Pkg> = Vec::new();
	for _ in 0..rng.below(max + 1) {
		let name = gen_name(rng);
		if pkgs.iter().any(|p| p.name == name) {
			continue;
		}
		let desc = (rng.below(5) != 0).then(|| gen_desc(rng));
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

// the sections search reads, the others loose
fn local_desc(rng: &mut Rng, p: &Pkg) -> String {
	let rest = loose_sections(
		rng,
		&[
			("BASE", &p.name),
			("URL", "https://example.org/"),
			("ARCH", "x86_64"),
			("BUILDDATE", "1700000000"),
			("INSTALLDATE", "1700000001"),
			("PACKAGER", "A B <a@b.org>"),
			("SIZE", "42"),
			("VALIDATION", "pgp"),
		],
	);
	format!(
		"%NAME%\n{0}\n\n%VERSION%\n1-1\n\n{1}{rest}{2}{3}",
		p.name,
		desc_section(p),
		section("GROUPS", &p.groups),
		section("PROVIDES", &p.provides)
	)
}

fn sync_desc(rng: &mut Rng, p: &Pkg) -> String {
	let sum = "ab".repeat(32);
	let rest = loose_sections(
		rng,
		&[
			("BASE", &p.name),
			("CSIZE", "1"),
			("ISIZE", "2"),
			("SHA256SUM", &sum),
			("ARCH", "any"),
			("BUILDDATE", "3"),
			("PACKAGER", "A B <a@b.org>"),
		],
	);
	format!(
		"%FILENAME%\n{0}-1-1-any.pkg.tar.zst\n\n%NAME%\n{0}\n\n\
		%VERSION%\n1-1\n\n{1}{rest}{2}{3}",
		p.name,
		desc_section(p),
		section("GROUPS", &p.groups),
		section("PROVIDES", &p.provides)
	)
}

fn sync_db(rng: &mut Rng, pkgs: &[Pkg]) -> Vec<u8> {
	let mut entries = Vec::new();
	for p in pkgs {
		let dir = format!("{}-1-1/", p.name);
		entries.push(tar_dir(&dir));
		let desc = sync_desc(rng, p);
		entries.push(tar_file(&format!("{dir}desc"), desc.as_bytes()));
	}
	ustar(&entries)
}

fn write_local(rng: &mut Rng, fx: &TempRoot, pkgs: &[Pkg]) {
	fx.reset_local();
	let entries: Vec<LocalEntry> = pkgs
		.iter()
		.map(|p| LocalEntry {
			dir: format!("{}-1-1", p.name),
			desc: Some(local_desc(rng, p).into_bytes()),
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
	match db.search(&dbext, &mut (), needles) {
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

fn open_case(
	rng: &mut Rng,
	local: &[Pkg],
	sync: &[SyncSpec],
	log: String,
) -> Case {
	let fx = TempRoot::new("db-search");
	write_local(rng, &fx, local);
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
	let mut rng = Rng::new(0x5ea_f1d);
	let sync = vec![
		("core", DB_USAGE_ALL, Some(sync_db(&mut rng, &local[..3]))),
		(
			"nosearch",
			DB_USAGE_ALL & !DB_USAGE_SEARCH,
			Some(sync_db(&mut rng, &local)),
		),
		("gone", DB_USAGE_ALL, None),
		("broken", DB_USAGE_ALL, Some(b"not a tar".repeat(100))),
	];
	let mut case = open_case(&mut rng, &local, &sync, String::new());
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
					Some(sync_db(&mut rng, &pkgs))
				}
			};
			sync.push((name, usage, data));
		}
		let mut case = open_case(&mut rng, &local, &sync, log);
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
