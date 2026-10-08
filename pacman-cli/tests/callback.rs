// unit tests of pacman_cli::callback and the util.rs prompts: Lookup
// hooks, unknown download files and pinned outputs of the common paths
use std::collections::VecDeque;

use alpm_core::callbacks::{
	Callbacks, DownloadEvent, Event, LogLevel, PackageOp, PackageOperation,
	Question,
};
use alpm_core::deps::dep_from_string;
use alpm_core::package::Package;
use pacman_cli::callback::{Frontend, Lookup};
use pacman_cli::conf::{Config, LOG_DEBUG, LOG_ERROR, LOG_WARNING};
use pacman_cli::util::{Output, Term};

struct T {
	o: Output,
	input: VecDeque<u8>,
	cols: u16,
	now: i64,
}

impl T {
	fn new(input: &[u8], cols: u16) -> T {
		T {
			o: Output::default(),
			input: input.iter().copied().collect(),
			cols,
			now: 1 << 30,
		}
	}
}

impl Term for T {
	fn out(&mut self, s: &[u8]) {
		self.o.stdout.extend_from_slice(s);
	}

	fn err(&mut self, s: &[u8]) {
		self.o.stderr.extend_from_slice(s);
	}

	fn read_line(&mut self, size: usize) -> Option<Vec<u8>> {
		let mut line = Vec::new();
		while line.len() + 1 < size {
			let c = self.input.pop_front()?;
			line.push(c);
			if c == b'\n' {
				break;
			}
		}
		Some(line)
	}

	fn stdin_is_tty(&mut self) -> bool {
		true
	}

	fn stdout_is_tty(&mut self) -> bool {
		false
	}

	fn cols(&mut self) -> u16 {
		self.cols
	}

	fn now_ms(&mut self) -> i64 {
		self.now
	}

	fn now_secs(&mut self) -> i64 {
		3723
	}
}

fn pkg(name: &str, optdeps: &[&str]) -> Package {
	Package {
		name: Some(name.as_bytes().to_vec()),
		version: Some(b"1-1".to_vec()),
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

struct Installed;

impl Lookup for Installed {
	fn db_name(&mut self, pkg: &Package) -> Vec<u8> {
		match pkg.name_bytes() {
			b"a" | b"b" => b"core".to_vec(),
			_ => b"extra".to_vec(),
		}
	}

	fn optdep_status(&mut self, dep: &[u8]) -> Option<&'static [u8]> {
		(dep == b"x").then_some(b" [installed]")
	}
}

#[test]
fn optdepends_with_status() {
	let mut f = Frontend::with_lookup(
		Config::new(),
		T::new(b"", 80),
		Installed,
	);
	let p = pkg("p", &["x: for x", "y"]);
	let op = PackageOp {
		operation: PackageOperation::Install,
		oldpkg: None,
		newpkg: Some(&p),
	};
	f.event(&Event::PackageOperationDone(op));
	assert_eq!(
		s(&f.term.o.stdout),
		"Optional dependencies for p\n    x: for x\n    y\n"
	);
	// the status goes after the computed dep string, desc included:
	// only "x" itself matches here
	let q = pkg("q", &["x"]);
	f.term.o = Output::default();
	let op = PackageOp {
		operation: PackageOperation::Upgrade,
		oldpkg: Some(&p),
		newpkg: Some(&q),
	};
	f.event(&Event::PackageOperationDone(op));
	assert_eq!(
		s(&f.term.o.stdout),
		"New optional dependencies for q\n    x [installed]\n"
	);
}

#[test]
fn provider_prompt() {
	let (a, b, c) = (pkg("a", &[]), pkg("b", &[]), pkg("c", &[]));
	let providers = [&a, &b, &c];
	let dep = dep_from_string(b"sh");
	let term = T::new(b"9\n3\n", 80);
	let mut f = Frontend::with_lookup(Config::new(), term, Installed);
	let mut q = Question::SelectProvider {
		use_index: 0,
		providers: &providers,
		depend: &dep,
	};
	f.question(&mut q);
	assert_eq!(q.answer(), 2);
	assert_eq!(
		s(&f.term.o.stdout),
		":: There are 3 providers available for sh:\n\
		:: Repository core\n   1) a  2) b\n\
		:: Repository extra\n   3) c\n"
	);
	assert_eq!(
		s(&f.term.o.stderr),
		"\nEnter a number (default=1): \
		error: invalid value: 9 is not between 1 and 3\n\
		\nEnter a number (default=1): "
	);
}

#[test]
fn yes_no_and_ask() {
	let a = pkg("a", &[]);
	let ask = |input: &[u8], cfg: Config| {
		let mut f = Frontend::new(cfg, T::new(input, 80));
		let mut q = Question::InstallIgnorepkg {
			install: 0,
			pkg: &a,
		};
		f.question(&mut q);
		(q.answer(), f.term.o)
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
	let mut f = Frontend::new(Config::new(), T::new(b"", 80));
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
	assert_eq!(f.term.o, Output::default());
	// .sig files have no bar at all
	f.download(b"x.db.sig", DownloadEvent::Init { optional: true });
	assert!(f.multibar().active.is_empty());
}

#[test]
fn unknown_size_eta() {
	let mut f = Frontend::new(Config::new(), T::new(b"", 80));
	f.download(b"core.db", DownloadEvent::Init { optional: false });
	f.term.now += 1000;
	let ev = DownloadEvent::Progress {
		downloaded: 4096,
		total: 0,
	};
	f.download(b"core.db", ev);
	let out = s(&f.term.o.stdout).to_string();
	// (0 - 4096) / rate converts like x86_64: far beyond an hour
	assert!(out.contains("--:--"), "{out:?}");
	assert!(out.starts_with(" core\n"), "{out:?}");
}

#[test]
fn log_lines() {
	let mut cfg = Config::new();
	cfg.logmask = LOG_ERROR | LOG_WARNING | LOG_DEBUG;
	let mut f = Frontend::new(cfg, T::new(b"", 80));
	f.log(LogLevel::Debug, b"d\n");
	f.log(LogLevel::Function, b"hidden\n");
	f.log(LogLevel::Error, b"");
	// stamped with the clock: 3723 s is 01:02:03
	assert_eq!(s(&f.term.o.stderr), "[01:02:03] debug: d\n");
	// delayed while a retrieve runs, unstamped, flushed at its end
	f.term.o = Output::default();
	f.event(&Event::DbRetrieveStart);
	f.log(LogLevel::Warning, b"w\n");
	assert!(f.term.o.stderr.is_empty());
	f.event(&Event::DbRetrieveDone);
	assert_eq!(s(&f.term.o.stderr), "warning: w\n");
}
