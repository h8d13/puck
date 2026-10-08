// unit tests of pacman_cli::callback and the util.rs prompts: optdepend
// status lists, unknown download files and pinned outputs of the common paths

use alpm_core::callbacks::{
	Callbacks, DownloadEvent, Event, LogLevel, PackageOp, PackageOperation,
	Question,
};
use alpm_core::deps::dep_from_string;
use alpm_core::package::Package;
use alpm_core::util::hash_sdbm;
use pacman_cli::callback::Frontend;
use pacman_cli::conf::{Config, LOG_DEBUG, LOG_ERROR, LOG_WARNING};
use pacman_cli::util::{Output, Term, debug_stamp};
use std::cell::Cell;
use std::io::Cursor;

thread_local! {
	static NOW: Cell<i64> = const { Cell::new(1 << 30) };
}

fn now_ms() -> i64 {
	NOW.with(Cell::get)
}

// a pipe for stdin, 80 columns, a settable monotonic clock and a fixed
// wall clock (3723 s is 01:02:03)
fn term(input: &[u8]) -> Term<Cursor<Vec<u8>>> {
	Term {
		cols: || 80,
		now_ms,
		now_secs: || 3723,
		..Term::new(Cursor::new(input.to_vec()), true, false)
	}
}

fn pkg(name: &str, optdeps: &[&str]) -> Package {
	Package {
		// depcmp looks at the hash first
		name_hash: hash_sdbm(name.as_bytes()),
		name: Some(name.as_bytes().into()),
		version: Some(b"1-1"[..].into()),
		optdepends: optdeps
			.iter()
			.map(|d| dep_from_string(d.as_bytes()))
			.collect(),
		..Package::default()
	}
}

fn s(b: &[u8]) -> &str {
	std::str::from_utf8(b).unwrap()
}

#[test]
fn optdepends_with_status() {
	let mut f = Frontend::new(Config::new(), term(b""));
	let p = pkg("p", &["x: for x", "y", "z"]);
	// "x" is installed, "z" comes with the transaction
	let (x, z) = (pkg("x", &[]), pkg("z", &[]));
	let op = PackageOp {
		operation: PackageOperation::Install,
		oldpkg: None,
		newpkg: Some(&p),
		local: &[&x],
		pending: &[&z],
	};
	f.event(&Event::PackageOperationDone(op));
	assert_eq!(
		s(&f.out.stdout),
		"Optional dependencies for p\n    x: for x [installed]\n    y\n    \
		z [pending]\n"
	);
	// the status goes after the computed dep string, desc included:
	// only "x" itself matches here
	let q = pkg("q", &["x"]);
	f.out = Output::default();
	let op = PackageOp {
		operation: PackageOperation::Upgrade,
		oldpkg: Some(&p),
		newpkg: Some(&q),
		local: &[&x],
		pending: &[],
	};
	f.event(&Event::PackageOperationDone(op));
	assert_eq!(
		s(&f.out.stdout),
		"New optional dependencies for q\n    x [installed]\n"
	);
}

#[test]
fn provider_prompt() {
	let (a, b, c) = (pkg("a", &[]), pkg("b", &[]), pkg("c", &[]));
	let providers = [&a, &b, &c];
	let dep = dep_from_string(b"sh");
	let term = term(b"9\n3\n");
	let mut f = Frontend::new(Config::new(), term);
	let mut q = Question::SelectProvider {
		use_index: 0,
		providers: &providers,
		dbs: &[b"core", b"core", b"extra"],
		depend: &dep,
	};
	f.question(&mut q);
	assert_eq!(q.answer(), 2);
	assert_eq!(
		s(&f.out.stdout),
		":: There are 3 providers available for sh:\n\
		:: Repository core\n   1) a  2) b\n\
		:: Repository extra\n   3) c\n"
	);
	assert_eq!(
		s(&f.out.stderr),
		"\nEnter a number (default=1): \
		error: invalid value: 9 is not between 1 and 3\n\
		\nEnter a number (default=1): "
	);
}

#[test]
fn yes_no_and_ask() {
	let a = pkg("a", &[]);
	let ask = |input: &[u8], cfg: Config| {
		let mut f = Frontend::new(cfg, term(input));
		let mut q = Question::InstallIgnorepkg {
			install: 0,
			pkg: &a,
		};
		f.question(&mut q);
		(q.answer(), f.out)
	};
	assert_eq!(ask(b"\n", Config::new()).0, 1);
	assert_eq!(ask(b"no\n", Config::new()).0, 0);
	assert_eq!(ask(b"YeS\n", Config::new()).0, 1);
	// end of input: no
	assert_eq!(ask(b"", Config::new()).0, 0);
	let mut cfg = Config::new();
	cfg.noconfirm = 1;
	let (answer, o) = ask(b"n\n", cfg.clone());
	assert_eq!(answer, 1);
	assert_eq!(
		s(&o.stdout),
		":: a is in IgnorePkg/IgnoreGroup. Install anyway? [Y/n] \n"
	);
	cfg.noask = 1;
	cfg.ask = 1;
	assert_eq!(ask(b"", cfg).0, 0);
}

#[test]
fn download_unknown_file_ignored() {
	let mut f = Frontend::new(Config::new(), term(b""));
	let ev = DownloadEvent::Progress {
		downloaded: 1,
		total: 2,
	};
	f.download(b"never-started.db", ev);
	let done = DownloadEvent::Completed {
		total: 2,
		result: 0,
	};
	f.download(b"never-started.db", done);
	assert_eq!(f.out, Output::default());
	// .sig files have no bar at all
	f.download(b"x.db.sig", DownloadEvent::Init { optional: true });
	assert!(f.multibar().active.is_empty());
}

#[test]
fn unknown_size_eta() {
	let mut f = Frontend::new(Config::new(), term(b""));
	f.download(b"core.db", DownloadEvent::Init { optional: false });
	NOW.with(|n| n.set(n.get() + 1000));
	let ev = DownloadEvent::Progress {
		downloaded: 4096,
		total: 0,
	};
	f.download(b"core.db", ev);
	let out = s(&f.out.stdout).to_string();
	// (0 - 4096) / rate converts like x86_64: far beyond an hour
	assert!(out.contains("--:--"), "{out:?}");
	assert!(out.starts_with(" core\n"), "{out:?}");
}

#[test]
fn log_lines() {
	let mut cfg = Config::new();
	cfg.logmask = LOG_ERROR | LOG_WARNING | LOG_DEBUG;
	let mut f = Frontend::new(cfg, term(b""));
	f.log(LogLevel::Debug, b"d\n");
	f.log(LogLevel::Function, b"hidden\n");
	f.log(LogLevel::Error, b"");
	// stamped with the clock (3723 s, local time: tz-probe checks it)
	let want = [&debug_stamp(3723)[..], b"debug: d\n"].concat();
	assert_eq!(s(&f.out.stderr), s(&want));
	// delayed while a retrieve runs, unstamped, flushed at its end
	f.out = Output::default();
	f.event(&Event::DbRetrieveStart);
	f.log(LogLevel::Warning, b"w\n");
	assert!(f.out.stderr.is_empty());
	f.event(&Event::DbRetrieveDone);
	assert_eq!(s(&f.out.stderr), "warning: w\n");
}

// multibar_move_completed_up set from outside through the flag the Term
// shares (sync's commit holds another Term with it): the completed bar
// moves to the top, where finished bars leave the UI
#[test]
fn move_completed_up_shared_flag() {
	let run = |up: bool| {
		let t = Term {
			cols: || 80,
			now_ms,
			..Term::new(Cursor::new(Vec::new()), false, true)
		};
		let flag = t.move_completed_up.clone();
		let mut f = Frontend::new(Config::new(), t);
		flag.store(up, std::sync::atomic::Ordering::Relaxed);
		let names: [&[u8]; 3] = [b"a.pkg", b"b.pkg", b"c.pkg"];
		for n in names {
			f.download(n, DownloadEvent::Init { optional: false });
		}
		let done = DownloadEvent::Completed {
			total: 2,
			result: 0,
		};
		f.download(names[2], done);
		let bars = f.multibar().active.iter();
		bars.map(|b| s(&b.filename).to_owned()).collect::<Vec<_>>()
	};
	assert_eq!(run(false), ["a.pkg", "b.pkg", "c.pkg"]);
	assert_eq!(run(true), ["b.pkg", "a.pkg"]);
}
