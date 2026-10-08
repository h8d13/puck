// pacman_cli::callback against the C callbacks of callback.c: events,
// questions (answers read from the same stdin), progress bars, the
// multibar download display and log lines, fed the same calls in the
// same order, stdout/stderr/answer compared after every call. the C
// keeps its state in statics, so every test drives the one shared pair
// (difftest::cb_both) and only compares, never assumes a start state
use std::ffi::c_int;

use alpm_core::callbacks::{
	DownloadEvent, Event, HookRun, HookWhen, LogLevel, PackageOp,
	PackageOperation, Progress, Question,
};
use alpm_core::conflict::Conflict;
use alpm_core::deps::{Depend, dep_from_string};
use alpm_core::error::Errno;
use alpm_core::handle::Handle;
use alpm_core::package::Package;
use difftest::{
	Call, CbRun, CbSetup, Rng, TempRoot, cb_active_bars, cb_both, iters,
	unstamp, widths_agree,
};
use pacman_cli::conf::{
	ColStr, Config, LOG_DEBUG, LOG_ERROR, LOG_FUNCTION, LOG_WARNING,
};
use pacman_cli::pacman::{PM_OP_FILES, PM_OP_SYNC};

fn lossy(b: &[u8]) -> String {
	String::from_utf8_lossy(b).into_owned()
}

fn check(setup: &CbSetup, call: Call<'_>, what: &str) -> CbRun {
	let (mut c, mut r) = cb_both(setup, call);
	c.stderr = unstamp(&c.stderr);
	r.stderr = unstamp(&r.stderr);
	assert!(
		c == r,
		"{what}\ncols {} now {} input {:?}\n\
		C out {:?}\nR out {:?}\nC err {:?}\nR err {:?}\n\
		C answer {} R answer {}",
		setup.cols,
		setup.now_ms,
		lossy(&setup.input),
		lossy(&c.stdout),
		lossy(&r.stdout),
		lossy(&c.stderr),
		lossy(&r.stderr),
		c.answer,
		r.answer
	);
	c
}

fn setup(config: Config, cols: u16, now_ms: i64) -> CbSetup {
	CbSetup {
		config,
		cols,
		now_ms,
		input: Vec::new(),
	}
}

fn pkg(name: &str, version: &str, optdeps: &[&str]) -> Package {
	Package {
		name: Some(name.as_bytes().to_vec()),
		version: Some(version.as_bytes().to_vec()),
		optdepends: optdeps
			.iter()
			.map(|d| dep_from_string(d.as_bytes()))
			.collect(),
		..Package::default()
	}
}

fn configs() -> Vec<Config> {
	let mut out = Vec::new();
	for i in 0..16 {
		let mut c = Config::new();
		c.noprogressbar = u16::from(i & 1 != 0);
		c.print = u16::from(i & 2 != 0 && i & 8 == 0);
		c.op = if i & 4 != 0 { PM_OP_FILES } else { PM_OP_SYNC };
		c.op_s_sync = u16::from(i & 8 != 0);
		if i & 3 == 3 {
			c.colstr = ColStr::COLOR;
		}
		c.logmask =
			[3, 1, 0, LOG_ERROR | LOG_WARNING | LOG_DEBUG][i % 4];
		out.push(c);
	}
	out
}

#[test]
fn events() {
	let a = pkg("alpha", "1.0-1", &["opt1: for x", "opt2>=2", "zed"]);
	let b = pkg("alpha", "2.0-1", &["opt2>=2", "new: thing", "abc"]);
	let none = pkg("bare", "1", &[]);
	let dep = dep_from_string(b"python>=3: scripting");
	let run = HookRun {
		name: b"hook-name",
		desc: Some(b"Updating things"),
		position: 3,
		total: 12,
	};
	let nodesc = HookRun {
		desc: None,
		position: 7,
		total: 7,
		..run
	};
	let op = |operation, old: Option<&'static Package>, new| PackageOp {
		operation,
		oldpkg: old,
		newpkg: new,
	};
	let a: &'static Package = Box::leak(Box::new(a));
	let b: &'static Package = Box::leak(Box::new(b));
	let none: &'static Package = Box::leak(Box::new(none));
	let events: Vec<Event<'_>> = vec![
		Event::CheckdepsStart,
		Event::CheckdepsDone,
		Event::FileconflictsStart,
		Event::FileconflictsDone,
		Event::ResolvedepsStart,
		Event::ResolvedepsDone,
		Event::InterconflictsStart,
		Event::InterconflictsDone,
		Event::TransactionStart,
		Event::TransactionDone,
		Event::PackageOperationStart(op(
			PackageOperation::Install,
			None,
			Some(a),
		)),
		Event::PackageOperationStart(op(
			PackageOperation::Upgrade,
			Some(a),
			Some(b),
		)),
		Event::PackageOperationStart(op(
			PackageOperation::Reinstall,
			Some(a),
			Some(a),
		)),
		Event::PackageOperationStart(op(
			PackageOperation::Downgrade,
			Some(b),
			Some(a),
		)),
		Event::PackageOperationStart(op(
			PackageOperation::Remove,
			Some(a),
			None,
		)),
		Event::PackageOperationDone(op(
			PackageOperation::Install,
			None,
			Some(a),
		)),
		Event::PackageOperationDone(op(
			PackageOperation::Install,
			None,
			Some(none),
		)),
		Event::PackageOperationDone(op(
			PackageOperation::Upgrade,
			Some(a),
			Some(b),
		)),
		Event::PackageOperationDone(op(
			PackageOperation::Downgrade,
			Some(b),
			Some(a),
		)),
		Event::PackageOperationDone(op(
			PackageOperation::Upgrade,
			Some(a),
			Some(a),
		)),
		Event::PackageOperationDone(op(
			PackageOperation::Remove,
			Some(a),
			None,
		)),
		Event::IntegrityStart,
		Event::IntegrityDone,
		Event::LoadStart,
		Event::LoadDone,
		Event::ScriptletInfo {
			line: b"scriptlet says hi\n",
		},
		Event::DiskspaceStart,
		Event::DiskspaceDone,
		Event::OptdepRemoval {
			pkg: a,
			optdep: &dep,
		},
		Event::DatabaseMissing { dbname: b"core" },
		Event::KeyringStart,
		Event::KeyringDone,
		Event::KeyDownloadStart,
		Event::KeyDownloadDone,
		Event::PacnewCreated {
			from_noupgrade: false,
			oldpkg: Some(a),
			newpkg: b,
			file: b"etc/foo.conf",
		},
		Event::PacsaveCreated {
			oldpkg: a,
			file: b"etc/bar.conf",
		},
		Event::HookStart {
			when: HookWhen::PreTransaction,
		},
		Event::HookStart {
			when: HookWhen::PostTransaction,
		},
		Event::HookDone {
			when: HookWhen::PostTransaction,
		},
		Event::HookRunStart(run),
		Event::HookRunStart(nodesc),
		Event::HookRunDone(run),
		// the delayed output: pacnew/pacsave while a retrieve runs
		Event::DbRetrieveStart,
		Event::PacnewCreated {
			from_noupgrade: true,
			oldpkg: None,
			newpkg: b,
			file: b"etc/delayed.conf",
		},
		Event::PacsaveCreated {
			oldpkg: a,
			file: b"etc/delayed2.conf",
		},
		Event::DbRetrieveDone,
		Event::DbRetrieveStart,
		Event::DbRetrieveFailed,
		Event::PkgRetrieveStart {
			num: 1,
			total_size: 100,
		},
		Event::PkgRetrieveFailed {
			num: 1,
			total_size: 100,
		},
	];
	for cfg in configs() {
		for cols in [0, 80] {
			for e in &events {
				let s = setup(cfg.clone(), cols, 5_000_000);
				check(&s, Call::Event(*e), &format!("{e:?}"));
			}
		}
	}
}

// what the questions are asked with, on stdin
const ANSWERS: &[&[u8]] = &[
	b"",
	b"\n",
	b"y\n",
	b"Y\n",
	b"yes\n",
	b"YeS\n",
	b"n\n",
	b"no\n",
	b"NO",
	b"  y  \n",
	b"\ty\t\n",
	b"x\n",
	b"yess\n",
	b"y es\n",
	b"0123456789012345678901234567890123456789\ny\n",
	b"\xc3\xa9\n",
	b"\xff\n",
];

// what the questions point at
struct Asked<'a> {
	a: &'a Package,
	b: &'a Package,
	db: &'a alpm_core::db::Db,
	c1: &'a Conflict,
	c2: &'a Conflict,
	pkgs1: &'a [&'a Package],
	pkgs3: &'a [&'a Package],
	dep: &'a Depend,
}

fn questions_with<'a>(q: &Asked<'a>) -> Vec<Question<'a>> {
	let Asked {
		a,
		b,
		db,
		c1,
		c2,
		pkgs1,
		pkgs3,
		dep,
	} = *q;
	vec![
		Question::InstallIgnorepkg { install: 0, pkg: a },
		Question::ReplacePkg {
			replace: 0,
			oldpkg: a,
			newpkg: b,
			newdb: db,
		},
		Question::ConflictPkg {
			remove: 0,
			conflict: c1,
		},
		Question::ConflictPkg {
			remove: 0,
			conflict: c2,
		},
		Question::CorruptedPkg {
			remove: 0,
			filepath: b"/var/cache/pacman/pkg/a-1-1-x86_64.pkg.tar.zst",
			reason: Errno::PkgInvalidChecksum,
		},
		Question::RemovePkgs {
			skip: 0,
			packages: pkgs1,
		},
		Question::RemovePkgs {
			skip: 0,
			packages: pkgs3,
		},
		Question::ImportKey {
			import: 0,
			uid: None,
			fingerprint: b"ABCDEF0123456789",
		},
		Question::ImportKey {
			import: 0,
			uid: Some(b"Some One <one@example.org>"),
			fingerprint: b"ABCDEF0123456789",
		},
		Question::SelectProvider {
			use_index: 0,
			providers: pkgs3,
			dbs: &[b"core", b"core", b"extra"],
			depend: dep,
		},
		Question::SelectProvider {
			use_index: 0,
			providers: pkgs1,
			dbs: &[b"core"],
			depend: dep,
		},
	]
}

#[test]
fn questions() {
	let fx = TempRoot::new("cb-questions");
	let mut h = Handle::initialize(&fx.root(), &fx.dbpath()).unwrap();
	h.register_syncdb(b"extra", 0).unwrap();
	let a = pkg("alpha", "1.0-1", &[]);
	let b = pkg("beta", "2.0-1", &[]);
	let c = pkg("gamma-long-name", "3:1.2.3-4", &[]);
	let c1 = Conflict {
		package1: a.clone(),
		package2: b.clone(),
		reason: dep_from_string(b"beta"),
	};
	let c2 = Conflict {
		package1: a.clone(),
		package2: b.clone(),
		reason: dep_from_string(b"virtual>=2"),
	};
	let pkgs1 = [&a];
	let pkgs3 = [&a, &b, &c];
	let dep = dep_from_string(b"sh>=1");
	let db = &h.syncdbs()[0];
	let asked = Asked {
		a: &a,
		b: &b,
		db,
		c1: &c1,
		c2: &c2,
		pkgs1: &pkgs1,
		pkgs3: &pkgs3,
		dep: &dep,
	};
	let n = questions_with(&asked).len();
	let selects: &[&[u8]] = &[
		b"2\n",
		b"3\n",
		b"0\n1\n",
		b"4\n",
		b"abc\n2\n",
		b"-1\n",
		b"4294967298\n",
		b"2x\n",
		b" 2 \n",
		b"+2\n",
	];
	let mut cfgs = Vec::new();
	for i in 0..12 {
		let mut cfg = Config::new();
		cfg.noconfirm = u16::from(i & 1 != 0);
		cfg.print = u16::from(i == 6);
		cfg.op_s_downloadonly = u16::from(i == 4);
		if i & 2 != 0 {
			cfg.noask = 1;
			cfg.ask = [0x7f, 0x01, 0x24, 0x40][i / 3 % 4];
		}
		if i == 10 {
			cfg.colstr = ColStr::COLOR;
		}
		if i == 8 {
			cfg.logmask = 0;
		}
		cfgs.push(cfg);
	}
	for cfg in &cfgs {
		for qi in 0..n {
			let inputs: Vec<&[u8]> = ANSWERS
				.iter()
				.chain(selects)
				.copied()
				.collect();
			for input in inputs {
				let qs = questions_with(&asked);
				let q = qs.into_iter().nth(qi).unwrap();
				let what = format!("{q:?}");
				let s = CbSetup {
					input: input.to_vec(),
					..setup(cfg.clone(), 60, 1_000)
				};
				check(&s, Call::Question(q), &what);
			}
		}
	}
}

const PROGRESS: [Progress; 10] = [
	Progress::AddStart,
	Progress::UpgradeStart,
	Progress::DowngradeStart,
	Progress::ReinstallStart,
	Progress::RemoveStart,
	Progress::ConflictsStart,
	Progress::DiskspaceStart,
	Progress::IntegrityStart,
	Progress::KeyringStart,
	Progress::LoadStart,
];

// names with characters glibc and unicode-width size alike
fn name(rng: &mut Rng) -> Vec<u8> {
	let parts: [&str; 8] =
		["a", "pkg", "-", "é", "漢字", "x", "ü", "long-name-part"];
	loop {
		let mut s = String::new();
		for _ in 0..rng.below(12) {
			s.push_str(parts[rng.below(parts.len())]);
		}
		if widths_agree(s.as_bytes()) {
			return s.into_bytes();
		}
	}
}

#[test]
fn progress() {
	let mut rng = Rng::new(0x9e37);
	let mut now = 10_000_000i64;
	let mut percent = 0;
	let mut current = 1usize;
	let mut howmany = 3usize;
	let mut pkgname = name(&mut rng);
	for i in 0..iters() / 4 {
		let mut cfg = Config::new();
		cfg.noprogressbar = u16::from(rng.below(20) == 0);
		cfg.chomp = u16::from(rng.below(3) == 0);
		let cols = [0, 20, 49, 50, 80, 83, 120, 200, 300][rng.below(9)];
		now += [0, 50, 199, 200, 201, 1000][rng.below(6)];
		match rng.below(10) {
			0 => {
				percent = 0;
				current += 1;
				pkgname = name(&mut rng);
			}
			1 => percent = 100,
			2 => howmany = [1, 9, 10, 99, 100, 12345][rng.below(6)],
			3 => pkgname = Vec::new(),
			_ => {
				percent = (percent + rng.below(30) as c_int)
					.min(100)
			}
		}
		if rng.below(30) == 0 {
			current = rng.below(200);
		}
		let event = PROGRESS[rng.below(10)];
		let s = setup(cfg, cols, now);
		let call = Call::Progress {
			event,
			pkgname: &pkgname,
			percent,
			howmany,
			current,
		};
		let what = format!(
			"step {i} {event:?} {:?} {percent} {current}/{howmany}",
			lossy(&pkgname)
		);
		check(&s, call, &what);
	}
}

fn filename(rng: &mut Rng) -> Vec<u8> {
	let base = [
		"core",
		"extra.files",
		"a-1-1-x86_64.pkg.tar.zst",
		"漢字-2-1-any.pkg.tar.xz",
		"very-long-package-name-that-needs-cutting-1.2.3-4-x86_64.pkg.tar.zst",
		"x.db",
		"b.db.sig",
		"plain",
	][rng.below(8)];
	format!("{base}{}", rng.below(4)).into_bytes()
}

#[test]
fn download() {
	let mut rng = Rng::new(0x51ed);
	let mut now = 50_000_000i64;
	let mut sizes: Vec<(Vec<u8>, i64, i64)> = Vec::new();
	for i in 0..iters() / 4 {
		let mut cfg = Config::new();
		cfg.noprogressbar = u16::from(rng.below(40) == 0);
		cfg.chomp = u16::from(rng.below(4) == 0);
		let cols = [0, 50, 80, 120, 200][rng.below(5)];
		cfg.logmask = 3;
		now += [0, 10, 199, 200, 250, 1500, 70_000][rng.below(7)];
		let s = setup(cfg, cols, now);
		let bars = cb_active_bars();
		let known = |rng: &mut Rng| -> Option<Vec<u8>> {
			(!bars.is_empty())
				.then(|| bars[rng.below(bars.len())].clone())
		};
		let what = format!("step {i}");
		match rng.below(14) {
			0 | 1 => {
				let f = filename(&mut rng);
				sizes.retain(|x| x.0 != f);
				sizes.push((
					f.clone(),
					0,
					1 + rng.below(1 << 30) as i64,
				));
				let e = DownloadEvent::Init {
					optional: rng.below(2) == 0,
				};
				check(
					&s,
					Call::Download {
						filename: &f,
						event: e,
					},
					&what,
				);
			}
			2..=6 => {
				let Some(f) = known(&mut rng) else { continue };
				let entry = sizes.iter_mut().find(|x| x.0 == f);
				let (got, total) = match entry {
					Some(x) => {
						x.1 = (x.1
							+ rng.below(1 << 24)
								as i64)
							.min(x.2);
						(x.1, x.2)
					}
					None => (0, 0),
				};
				let total = if rng.below(10) == 0 {
					0
				} else {
					total
				};
				let got = if total == 0 {
					got.min(rng.below(5000) as i64)
				} else {
					got
				};
				let e = DownloadEvent::Progress {
					downloaded: got,
					total,
				};
				check(
					&s,
					Call::Download {
						filename: &f,
						event: e,
					},
					&what,
				);
			}
			7 => {
				let Some(f) = known(&mut rng) else { continue };
				if let Some(x) =
					sizes.iter_mut().find(|x| x.0 == f)
				{
					x.1 = 0;
				}
				let e = DownloadEvent::Retry {
					resume: rng.below(2) == 0,
				};
				check(
					&s,
					Call::Download {
						filename: &f,
						event: e,
					},
					&what,
				);
			}
			8 | 9 => {
				let Some(f) = known(&mut rng) else { continue };
				let total = sizes
					.iter()
					.find(|x| x.0 == f)
					.map_or(0, |x| x.2);
				let e = DownloadEvent::Completed {
					total,
					result: [0, 0, 1, -1][rng.below(4)],
				};
				check(
					&s,
					Call::Download {
						filename: &f,
						event: e,
					},
					&what,
				);
			}
			10 => {
				let e = match rng.below(4) {
					0 => Event::PkgRetrieveStart {
						num: rng.below(5),
						total_size: rng.below(1 << 31)
							as i64,
					},
					1 => Event::PkgRetrieveDone {
						num: 2,
						total_size: 1,
					},
					2 => Event::DbRetrieveStart,
					_ => Event::DbRetrieveDone,
				};
				check(&s, Call::Event(e), &what);
			}
			11 => {
				let v = rng.below(2) == 0;
				check(&s, Call::MoveCompletedUp(v), &what);
			}
			12 => {
				let msg = format!("log line {i} 100%\n");
				let call = Call::Log {
					level: LogLevel::Error,
					msg: msg.as_bytes(),
				};
				check(&s, call, &what);
			}
			_ => {
				check(&s, Call::MoveEnd, &what);
			}
		}
	}
}

#[test]
fn logs() {
	let levels = [
		LogLevel::Error,
		LogLevel::Warning,
		LogLevel::Debug,
		LogLevel::Function,
	];
	let msgs: &[&[u8]] =
		&[b"", b"plain\n", b"100% done %s %d\n", b"no newline"];
	for logmask in [0, 1, 3, 7, 15, LOG_FUNCTION] {
		for colors in [false, true] {
			for progress in [false, true] {
				let mut cfg = Config::new();
				cfg.logmask = logmask;
				if colors {
					cfg.colstr = ColStr::COLOR;
				}
				let s = setup(cfg, 80, 1);
				// on_progress: a retrieve start delays log lines
				let e = match progress {
					true => Event::DbRetrieveStart,
					false => Event::DbRetrieveDone,
				};
				check(&s, Call::Event(e), "progress state");
				for level in levels {
					for msg in msgs {
						let call = Call::Log {
							level,
							msg,
						};
						check(
							&s,
							call,
							&format!(
								"{level:?} {}",
								lossy(msg)
							),
						);
					}
				}
				check(
					&s,
					Call::Event(Event::DbRetrieveDone),
					"flush",
				);
			}
		}
	}
}
