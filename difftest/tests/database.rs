// pacman_cli::database against C pacman_database: -Dk on generated local
// dbs (dependencies, provides, conflicts, files owned twice, entries
// without desc or files, stray entries), -Dkk on the generated sync
// worlds of sync_ro, -D --asdeps/--asexplicit on targets in and out of
// the local db (alone and after -Dk). each case runs on two copies of
// the fixture, one per side: return value, stdout, stderr and the local
// db tree afterwards compared
use std::fmt::Write as _;
use std::fs;

use alpm_core::internals::handle::Handle;
use alpm_core::internals::trans::{TRANS_FLAG_ALLDEPS, TRANS_FLAG_ALLEXPLICIT};
use difftest::{
	CRun, FrontHandle, LocalEntry, Node, Rng, SyncWorld, TempRoot,
	c_pacman_database, iters, section, snapshot, umask_lock,
};
use pacman_cli::conf::{ColStr, Config, LOG_ERROR, LOG_WARNING};
use pacman_cli::database::pacman_database;
use pacman_cli::util::Output;

// two fixtures and two handles per case
fn cases() -> usize {
	(iters() / 100).max(100)
}

const NAMES: [&str; 7] = ["a", "b", "c", "foo", "bar", "lib-x", "q2"];
// provided only, never a package name
const VIRTUAL: [&str; 2] = ["virt", "libx.so"];
const FILES: [&str; 6] = [
	"usr/bin/x",
	"usr/bin/y",
	"usr/lib/libx.so",
	"etc/x.conf",
	"README",
	"usr/share/doc/a",
];

fn pick<'a>(rng: &mut Rng, items: &[&'a str]) -> &'a str {
	items[rng.below(items.len())]
}

fn version(rng: &mut Rng) -> String {
	format!("{}.{}-{}", rng.below(3), rng.below(3), 1 + rng.below(2))
}

// a relation on a package or virtual name, versioned now and then
fn relation(rng: &mut Rng) -> String {
	let name = match rng.below(4) {
		0 => pick(rng, &VIRTUAL),
		_ => pick(rng, &NAMES),
	};
	match rng.below(3) {
		0 => {
			let op = pick(rng, &["=", ">=", "<=", ">", "<"]);
			format!("{name}{op}{}.{}", rng.below(3), rng.below(3))
		}
		_ => name.to_string(),
	}
}

fn relations(rng: &mut Rng, max: usize) -> Vec<String> {
	(0..rng.below(max + 1)).map(|_| relation(rng)).collect()
}

// files with every parent directory listed, sorted and unique
fn file_list(rng: &mut Rng) -> Vec<String> {
	let mut out = Vec::new();
	for _ in 0..rng.below(4) {
		let f = pick(rng, &FILES);
		let mut parent = String::new();
		for part in f.split_inclusive('/') {
			parent.push_str(part);
			out.push(parent.clone());
		}
	}
	out.sort();
	out.dedup();
	out
}

// clean: no relations, so -Dk finds nothing
fn desc(rng: &mut Rng, name: &str, version: &str, clean: bool) -> String {
	let one = |s: &str| vec![s.to_string()];
	let reason = match rng.below(3) {
		0 => String::new(),
		n => section("REASON", &one(&(n - 1).to_string())),
	};
	format!(
		"%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%BASE%\n{name}\n\n\
		%DESC%\nA package\n\n%URL%\nhttps://example.org/x\n\n\
		%ARCH%\nx86_64\n\n%BUILDDATE%\n1700000000\n\n\
		%INSTALLDATE%\n1700000001\n\n%PACKAGER%\nA B <a@b.org>\n\n\
		%SIZE%\n42\n\n{reason}%VALIDATION%\npgp\n\n{}{}{}",
		section("DEPENDS", &relations(rng, 3 * usize::from(!clean))),
		section("PROVIDES", &relations(rng, usize::from(!clean))),
		section("CONFLICTS", &relations(rng, usize::from(!clean))),
	)
}

// local/ entries: some names installed, now and then an entry without
// desc or files, a plain file or an oddly named directory. log
// describes them
fn gen_local(rng: &mut Rng, log: &mut String) -> Vec<LocalEntry> {
	let clean = rng.below(5) == 0;
	let broken = !clean && rng.below(4) == 0;
	let mut entries = Vec::new();
	for name in NAMES {
		if rng.below(3) == 0 {
			continue;
		}
		let version = version(rng);
		let files = match clean {
			true => vec![format!("{name}.txt")],
			false => file_list(rng),
		};
		let files = match files.is_empty() {
			true => "%FILES%\n".to_string(),
			false => format!("%FILES%\n{}\n\n", files.join("\n")),
		};
		let mut e = LocalEntry {
			dir: format!("{name}-{version}"),
			desc: Some(
				desc(rng, name, &version, clean).into_bytes()
			),
			files: Some(files.into_bytes()),
			install: false,
		};
		if broken && rng.below(3) == 0 {
			match rng.below(2) {
				0 => e.desc = None,
				_ => e.files = None,
			}
		}
		log_entry(log, &e);
		entries.push(e);
	}
	if broken && rng.below(2) == 0 {
		// splitname refuses it, populate skips it, -Dk still checks it
		let e = LocalEntry {
			dir: "noversion".to_string(),
			..LocalEntry::default()
		};
		log_entry(log, &e);
		entries.push(e);
	}
	entries
}

fn log_entry(log: &mut String, e: &LocalEntry) {
	let text = |t: &Option<Vec<u8>>| {
		t.as_deref()
			.map(|t| String::from_utf8_lossy(t).into_owned())
	};
	let (desc, files) = (text(&e.desc), text(&e.files));
	writeln!(log, "{}:\n  desc {desc:?}\n  files {files:?}", e.dir)
		.unwrap();
}

// the fixture's directory in printed paths replaced by <dir>
fn strip(run: CRun, fx: &TempRoot) -> CRun {
	let dir = fx.dir().as_os_str().as_encoded_bytes();
	let cut = |v: Vec<u8>| -> Vec<u8> {
		let mut out = Vec::new();
		let mut rest = &v[..];
		while let Some(i) =
			rest.windows(dir.len()).position(|w| w == dir)
		{
			out.extend_from_slice(&rest[..i]);
			out.extend_from_slice(b"<dir>");
			rest = &rest[i + dir.len()..];
		}
		out.extend_from_slice(rest);
		out
	};
	CRun {
		ret: run.ret,
		stdout: cut(run.stdout),
		stderr: cut(run.stderr),
	}
}

// one fixture per side with the same local db
struct Pair {
	c: TempRoot,
	r: TempRoot,
}

impl Pair {
	fn new(entries: &[LocalEntry], stray: bool) -> Pair {
		// file modes follow the umask the C may be changing
		let _umask = umask_lock();
		let p = Pair {
			c: TempRoot::new("database-c"),
			r: TempRoot::new("database-r"),
		};
		for fx in [&p.c, &p.r] {
			fx.reset_local();
			fx.write_local(entries);
			if stray {
				fs::write(fx.local().join("README"), "x")
					.unwrap();
			}
		}
		p
	}

	fn each(&self, f: impl Fn(&TempRoot)) {
		f(&self.c);
		f(&self.r);
	}
}

fn targets_text(targets: &[Vec<u8>]) -> Vec<String> {
	targets.iter()
		.map(|t| String::from_utf8_lossy(t).into_owned())
		.collect()
}

fn describe(cfg: &Config, targets: &[Vec<u8>], log: &str) -> String {
	format!(
		"check {} flags {:#x} quiet {} logmask {} targets {:?}\n{log}",
		cfg.op_q_check,
		cfg.flags,
		cfg.quiet,
		cfg.logmask,
		targets_text(targets)
	)
}

// a tree as "path mode contents" lines, for readable diffs
fn lines(node: &Node, path: &str, out: &mut Vec<String>) {
	match node {
		Node::Dir(mode, Some(entries)) => {
			out.push(format!("{path}/ {mode:o}"));
			for (name, n) in entries {
				let name = String::from_utf8_lossy(name);
				lines(n, &format!("{path}/{name}"), out);
			}
		}
		Node::File(mode, _, data) => {
			let data = String::from_utf8_lossy(data);
			out.push(format!("{path} {mode:o} {data:?}"));
		}
		n => out.push(format!("{path} {n:?}")),
	}
}

fn tree(fx: &TempRoot) -> Vec<String> {
	let mut out = Vec::new();
	lines(&snapshot(fx.dir()), "", &mut out);
	out
}

fn panic_on(c: &CRun, r: &CRun, what: &str) {
	if let Some(d) = c.diff(r) {
		panic!("{d}\n{what}");
	}
}

// -Dk and -D on a Pair, setup run on both fixtures after the handles
// exist. the stdout of the C, to count what was compared
fn compare_local(
	p: &Pair,
	cfg: &Config,
	targets: &[Vec<u8>],
	setup: &dyn Fn(&TempRoot),
	log: &str,
) -> CRun {
	// set_reason writes under the C's umask(0022)
	let _umask = umask_lock();
	let fh = FrontHandle::open(&p.c.root(), &p.c.dbpath(), b".db", &[]);
	let mut h = Handle::initialize(&p.r.root(), &p.r.dbpath()).unwrap();
	p.each(setup);
	let c = strip(c_pacman_database(&fh, cfg, targets), &p.c);
	let mut out = Output::default();
	let ret = pacman_database(cfg, &mut h, targets, &mut out);
	drop(fh);
	drop(h);
	let r = CRun {
		ret,
		stdout: out.stdout,
		stderr: out.stderr,
	};
	let r = strip(r, &p.r);
	let what = describe(cfg, targets, log);
	panic_on(&c, &r, &what);
	// the trees as written, the lock gone on both sides
	assert_eq!(tree(&p.c), tree(&p.r), "db trees\n{what}");
	c
}

fn config(rng: &mut Rng) -> Config {
	let mut cfg = Config::new();
	if rng.below(3) == 0 {
		cfg.colstr = ColStr::COLOR;
	}
	cfg.logmask = match rng.below(6) {
		0 => 0,
		1 => LOG_WARNING,
		_ => LOG_ERROR | LOG_WARNING,
	};
	cfg.quiet = u16::from(rng.below(4) == 0);
	cfg
}

fn reason_flags(rng: &mut Rng) -> i32 {
	match rng.below(4) {
		0 => TRANS_FLAG_ALLDEPS,
		1 => TRANS_FLAG_ALLEXPLICIT,
		2 => TRANS_FLAG_ALLDEPS | TRANS_FLAG_ALLEXPLICIT,
		_ => 0,
	}
}

fn targets(rng: &mut Rng) -> Vec<Vec<u8>> {
	(0..rng.below(4))
		.map(|_| match rng.below(8) {
			0 => String::new(),
			1 => "missing".to_string(),
			2 => "virt".to_string(),
			_ => pick(rng, &NAMES).to_string(),
		})
		.map(String::into_bytes)
		.collect()
}

#[test]
fn edges() {
	let mut rng = Rng::new(0xd0);
	let mut log = String::new();
	let entries = gen_local(&mut rng, &mut log);
	let none: &dyn Fn(&TempRoot) = &|_| {};
	let names: Vec<Vec<u8>> =
		NAMES.iter().map(|n| n.as_bytes().to_vec()).collect();
	for flags in [0, TRANS_FLAG_ALLDEPS, TRANS_FLAG_ALLEXPLICIT] {
		for check in [0, 1] {
			for t in [&names[..], &[], &[b"".to_vec()]] {
				let p = Pair::new(&entries, false);
				let mut cfg = Config::new();
				cfg.flags = flags;
				cfg.op_q_check = check;
				compare_local(&p, &cfg, t, none, &log);
			}
		}
	}
	let mut cfg = Config::new();
	cfg.flags = TRANS_FLAG_ALLDEPS;
	// lock held: trans_init fails, nothing written
	let p = Pair::new(&entries, false);
	let lock = |fx: &TempRoot| {
		fs::write(fx.dir().join("db/db.lck"), "").unwrap();
	};
	compare_local(&p, &cfg, &names, &lock, &log);
	// local/ gone after the handles opened it
	cfg.flags = 0;
	cfg.op_q_check = 1;
	let p = Pair::new(&entries, true);
	let gone = |fx: &TempRoot| {
		fs::rename(fx.local(), fx.dir().join("db/gone")).unwrap();
	};
	compare_local(&p, &cfg, &[], &gone, &log);
	// stray plain file: both its desc and files missing
	let p = Pair::new(&entries, true);
	compare_local(&p, &cfg, &[], none, &log);
}

// files shared by three packages: reported pairwise in package order
#[test]
fn files_owned_thrice() {
	let mut entries = Vec::new();
	for name in ["a", "b", "c"] {
		let files = "%FILES%\nusr/\nusr/bin/\nusr/bin/x\n\n";
		entries.push(LocalEntry {
			dir: format!("{name}-1.0-1"),
			desc: Some(format!(
				"%NAME%\n{name}\n\n%VERSION%\n1.0-1\n\n\
					%CONFLICTS%\nb\n\n"
			)
			.into_bytes()),
			files: Some(files.as_bytes().to_vec()),
			install: false,
		});
	}
	let p = Pair::new(&entries, false);
	let mut cfg = Config::new();
	cfg.op_q_check = 1;
	let c = compare_local(&p, &cfg, &[], &|_| {}, "thrice");
	let err = String::from_utf8_lossy(&c.stderr).into_owned();
	assert_eq!(err.matches("file owned by").count(), 2, "{err}");
	assert!(err.contains("'a' conflicts with 'b'"), "{err}");
}

// every message -Dk and -D print, counted by the fuzz
const KINDS: [&[u8]; 6] = [
	b"description file is missing",
	b"file list is missing",
	b"dependency for",
	b"conflicts with",
	b"file owned by",
	b"could not set install reason",
];

#[test]
fn fuzz_local() {
	let mut rng = Rng::new(0xdb_0001);
	let (mut errors, mut written, mut ok) = (0, 0, 0);
	let mut kinds = [0; KINDS.len()];
	for _ in 0..cases() {
		let mut log = String::new();
		let entries = gen_local(&mut rng, &mut log);
		let stray = rng.below(10) == 0;
		let p = Pair::new(&entries, stray);
		let mut cfg = config(&mut rng);
		cfg.op_q_check = u16::from(rng.below(2) == 0);
		cfg.flags = reason_flags(&mut rng);
		let t = targets(&mut rng);
		let c = compare_local(&p, &cfg, &t, &|_| {}, &log);
		errors += usize::from(!c.stderr.is_empty());
		written += usize::from(
			c.stdout.windows(7).any(|w| w == b"reason "),
		);
		ok += usize::from(c.stdout.starts_with(b"No database"));
		for (k, n) in KINDS.iter().zip(&mut kinds) {
			let has = c.stderr.windows(k.len()).any(|w| w == *k);
			*n += usize::from(has);
		}
	}
	let n = cases();
	eprintln!("{n} cases: {errors} with errors, {written} set, {ok} ok");
	eprintln!("messages: {kinds:?}");
	assert!(
		errors > n / 4 && written > n / 8 && ok > n / 20,
		"{errors} {written} {ok}"
	);
	assert!(kinds.iter().all(|&k| k > n / 50), "{kinds:?}");
}

// -Dkk: the sync dbs' dependencies, one fixture for both sides (nothing
// is written)
#[test]
fn fuzz_sync() {
	let mut rng = Rng::new(0xdb_0002);
	let (mut missing, mut ok) = (0, 0);
	for _ in 0..cases() {
		let w = SyncWorld::generate(&mut rng, "database-sync");
		let mut cfg = config(&mut rng);
		cfg.op_q_check = 2;
		let fh = w.c_handle(b".db");
		let c = c_pacman_database::<&[u8]>(&fh, &cfg, &[]);
		let mut h = Handle::initialize(&w.fx.root(), &w.fx.dbpath())
			.unwrap();
		for r in &w.repos {
			h.register_syncdb(r.as_bytes(), 0).unwrap();
		}
		let mut out = Output::default();
		let ret = pacman_database(&cfg, &mut h, &[], &mut out);
		let r = CRun {
			ret,
			stdout: out.stdout,
			stderr: out.stderr,
		};
		panic_on(&c, &r, &describe(&cfg, &[], &w.log));
		missing += usize::from(c.ret != 0);
		ok += usize::from(c.ret == 0);
	}
	let n = cases();
	eprintln!("{n} cases: {missing} with missing deps, {ok} ok");
	assert!(missing > n / 4 && ok > n / 20, "{missing} {ok}");
}
