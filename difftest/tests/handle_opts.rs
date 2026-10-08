// alpm_core::{handle, log} against handle.c and log.c: the option
// setters/getters (results, pm_errno, debug lines, whole state after each
// step) on fixture roots, the lock between a C and a Rust handle on one
// dbpath, alpm_logaction's file output (stamps within CLOCK_SLACK of
// each other, their format against strftime separately, local time in
// every zone through tz-probe) and its errors, the DATABASE_MISSING
// event.
use std::cell::RefCell;
use std::ffi::c_int;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::Command;
use std::rc::Rc;

use alpm_core::callbacks::{Callbacks, Event, LogLevel};
use alpm_core::deps::{DepMod, Depend, dep_from_string};
use alpm_core::error::Errno;
use alpm_core::handle::Handle;
use alpm_core::log::{LogTime, leader, syslog_message};
use difftest::{
	COpts, DirList, FlagOpt, IntOpt, OptsRecord, Rng, TempRoot,
	c_strftime_at, iters, stamped,
};

// what the Rust callbacks saw, shared with the test
#[derive(Clone, Default)]
struct Shared(Rc<RefCell<OptsRecord>>);

impl Callbacks for Shared {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		let l = (level as c_int, msg.to_vec());
		self.0.borrow_mut().logs.push(l);
	}

	fn event(&mut self, event: &Event<'_>) {
		let name = match event {
			Event::DatabaseMissing { dbname } => dbname.to_vec(),
			_ => Vec::new(),
		};
		self.0.borrow_mut().events.push((event.kind(), name));
	}
}

// a C and a Rust handle on one fixture
struct Both {
	fx: TempRoot,
	c: COpts,
	r: Handle,
	rec: Shared,
}

fn err(e: Errno) -> c_int {
	e as c_int
}

// RET_ERR's debug line names C source lines, the port does not log it
fn c_record(c: &COpts) -> OptsRecord {
	let mut rec = c.take_record();
	rec.logs.retain(|(_, m)| !m.starts_with(b"returning error "));
	rec
}

impl Both {
	fn new(tag: &str) -> Both {
		let fx = TempRoot::new(tag);
		let c = COpts::new(&fx.root(), &fx.dbpath()).unwrap();
		let mut r =
			Handle::initialize(&fx.root(), &fx.dbpath()).unwrap();
		let rec = Shared::default();
		r.set_callbacks(Box::new(rec.clone()));
		Both { fx, c, r, rec }
	}

	fn compare_record(&self, what: &str) {
		let r = std::mem::take(&mut *self.rec.0.borrow_mut());
		assert_eq!(c_record(&self.c), r, "{what}");
	}

	fn compare_state(&self, what: &str) {
		let (c, r) = (&self.c, &self.r);
		assert_eq!(c.list(DirList::Cache), r.cachedirs(), "{what}");
		assert_eq!(c.list(DirList::Hook), r.hookdirs(), "{what}");
		let ow = c.list(DirList::Overwrite);
		assert_eq!(ow, r.overwrite_files(), "{what}");
		assert_eq!(c.gpgdir().as_deref(), r.gpgdir(), "{what}");
		assert_eq!(c.logfile().as_deref(), r.logfile(), "{what}");
		assert_eq!(
			c.lockfile().as_deref(),
			Some(r.lockfile()),
			"{what}"
		);
		let user = c.sandboxuser();
		assert_eq!(user.as_deref(), r.sandboxuser(), "{what}");
		let syslog = c.int_opt(IntOpt::UseSyslog);
		assert_eq!(syslog, r.usesyslog(), "{what}");
		let space = c.int_opt(IntOpt::CheckSpace);
		assert_eq!(space, r.checkspace(), "{what}");
		let flags = [
			c.flag(FlagOpt::DlTimeout),
			c.flag(FlagOpt::Sandbox),
			c.flag(FlagOpt::SandboxFs),
			c.flag(FlagOpt::SandboxSyscalls),
		];
		let rflags = [
			c_int::from(r.disable_dl_timeout()),
			r.disable_sandbox(),
			c_int::from(r.disable_sandbox_filesystem()),
			c_int::from(r.disable_sandbox_syscalls()),
		];
		assert_eq!(flags, rflags, "{what}");
		// int getter of an unsigned field
		let par = r.parallel_downloads() as c_int;
		assert_eq!(c.parallel_downloads(), par, "{what}");
		let ai = c.assumeinstalled();
		assert_eq!(ai, r.assumeinstalled(), "{what}");
	}
}

const DIRS: [&[u8]; 9] = [
	b"/",
	b"//",
	b"a",
	b"a/",
	b"/var/cache/pacman/pkg",
	b"/var/cache/pacman/pkg/",
	b"x//y",
	b"\xc3",
	b"/tmp/c",
];
const GLOBS: [&[u8]; 5] = [b"", b"usr/*", b"etc/x", b"usr/*", b"!a"];
const USERS: [Option<&[u8]>; 5] = [
	Some(b"root"),
	Some(b"nobody"),
	Some(b"zz-no-such-user"),
	Some(b""),
	None,
];
const DEPS: [&[u8]; 8] = [
	b"a", b"a=1", b"a>=1", b"a<2", b"b=1:2-3", b"c: d", b"a=1: d", b"b",
];
const INTS: [c_int; 5] = [0, 1, -1, 7, c_int::MAX];
const FLAGS: [u16; 4] = [0, 1, 2, u16::MAX];
const STREAMS: [u32; 4] = [0, 1, 2, u32::MAX];

fn pick<T: Copy>(rng: &mut Rng, items: &[T]) -> T {
	items[rng.below(items.len())]
}

fn strs(rng: &mut Rng, items: &[&[u8]]) -> Vec<Vec<u8>> {
	(0..rng.below(4))
		.map(|_| pick(rng, items).to_vec())
		.collect()
}

// a dep as a caller builds it: parsed, or by hand without name_hash
fn dep(rng: &mut Rng) -> Depend {
	let mut d = dep_from_string(pick(rng, &DEPS));
	if rng.below(4) == 0 {
		d.name_hash = 0;
	}
	if rng.below(8) == 0 {
		d.depmod = pick(rng, &[DepMod::Le, DepMod::Gt, DepMod::Any]);
	}
	d
}

fn flag(which: usize) -> FlagOpt {
	[
		FlagOpt::DlTimeout,
		FlagOpt::Sandbox,
		FlagOpt::SandboxFs,
		FlagOpt::SandboxSyscalls,
	][which]
}

fn set_rust_flag(r: &mut Handle, which: usize, v: u16) {
	match which {
		0 => r.set_disable_dl_timeout(v),
		1 => r.set_disable_sandbox(v),
		2 => r.set_disable_sandbox_filesystem(v),
		_ => r.set_disable_sandbox_syscalls(v),
	}
}

fn list_of(i: usize) -> DirList {
	[DirList::Cache, DirList::Hook, DirList::Overwrite][i]
}

// one random option call on both sides: (C result, pm_errno) against
// the Rust result mapped the same way
fn step(b: &mut Both, rng: &mut Rng) -> (String, (c_int, c_int)) {
	let (c, r) = (&b.c, &mut b.r);
	let ok = (0, 0);
	let flagv = |x: bool| (c_int::from(x), 0);
	let res =
		|x: Result<(), Errno>| x.map_or_else(|e| (-1, err(e)), |_| ok);
	let (what, cr, rr) = match rng.below(14) {
		k @ 0..=2 => {
			let which = list_of(k);
			let items: &[&[u8]] = match which {
				DirList::Overwrite => &GLOBS,
				_ => &DIRS,
			};
			let s = pick(rng, items);
			let what = format!("{which:?} add {s:?}");
			let cr = c.list_add(which, s);
			match which {
				DirList::Cache => r.add_cachedir(s),
				DirList::Hook => r.add_hookdir(s),
				DirList::Overwrite => r.add_overwrite_file(s),
			}
			(what, cr, ok)
		}
		k @ 3..=5 => {
			let which = list_of(k - 3);
			let items: &[&[u8]] = match which {
				DirList::Overwrite => &GLOBS,
				_ => &DIRS,
			};
			let list = strs(rng, items);
			let what = format!("{which:?} set {list:?}");
			let cr = c.list_set(which, &list);
			match which {
				DirList::Cache => r.set_cachedirs(&list),
				DirList::Hook => r.set_hookdirs(&list),
				DirList::Overwrite => {
					r.set_overwrite_files(&list)
				}
			}
			(what, cr, ok)
		}
		k @ 6..=7 => {
			let which = list_of(rng.below(3));
			let items: &[&[u8]] = match which {
				DirList::Overwrite => &GLOBS,
				_ => &DIRS,
			};
			let s = pick(rng, items);
			let what = format!("{which:?} remove {s:?} ({k})");
			let cr = c.list_remove(which, s);
			let rr = match which {
				DirList::Cache => r.remove_cachedir(s),
				DirList::Hook => r.remove_hookdir(s),
				DirList::Overwrite => {
					r.remove_overwrite_file(s)
				}
			};
			(what, cr, flagv(rr))
		}
		8 => match rng.below(3) {
			0 => {
				let s = pick(rng, &DIRS);
				let cr = c.set_gpgdir(s);
				r.set_gpgdir(s);
				(format!("gpgdir {s:?}"), cr, ok)
			}
			1 => {
				let s = pick(rng, &DIRS);
				let cr = c.set_logfile(s);
				r.set_logfile(s);
				(format!("logfile {s:?}"), cr, ok)
			}
			_ => {
				let s = pick(
					rng,
					&[&b".db"[..], b".files", b""],
				);
				let cr = c.set_dbext(s);
				r.set_dbext(s);
				(format!("dbext {s:?}"), cr, ok)
			}
		},
		9 => {
			let u = pick(rng, &USERS);
			let cr = c.set_sandboxuser(u);
			let rr = (c_int::from(!r.set_sandboxuser(u)), 0);
			(format!("sandboxuser {u:?}"), cr, rr)
		}
		10 => {
			let v = pick(rng, &INTS);
			match rng.below(2) {
				0 => {
					let cr = c.set_int_opt(
						IntOpt::UseSyslog,
						v,
					);
					r.set_usesyslog(v);
					(format!("usesyslog {v}"), cr, ok)
				}
				_ => {
					let cr = c.set_int_opt(
						IntOpt::CheckSpace,
						v,
					);
					r.set_checkspace(v);
					(format!("checkspace {v}"), cr, ok)
				}
			}
		}
		11 => {
			let (which, v) = (rng.below(4), pick(rng, &FLAGS));
			let cr = c.set_flag(flag(which), v);
			set_rust_flag(r, which, v);
			(format!("{:?} {v}", flag(which)), cr, ok)
		}
		12 => {
			let n = pick(rng, &STREAMS);
			let cr = c.set_parallel_downloads(n);
			let rr = res(r.set_parallel_downloads(n));
			(format!("parallel {n}"), cr, rr)
		}
		_ => match rng.below(3) {
			0 => {
				let d = dep(rng);
				let cr = c.add_assumeinstalled(&d);
				let rr = res(r.add_assumeinstalled(&d));
				(format!("assume add {d:?}"), cr, rr)
			}
			1 => {
				let ds: Vec<Depend> = (0..rng.below(4))
					.map(|_| dep(rng))
					.collect();
				let cr = c.set_assumeinstalled(&ds);
				let rr = res(r.set_assumeinstalled(&ds));
				(format!("assume set {ds:?}"), cr, rr)
			}
			_ => {
				let d = dep(rng);
				let cr = c.remove_assumeinstalled(&d);
				let rr = flagv(r.remove_assumeinstalled(&d));
				(format!("assume remove {d:?}"), cr, rr)
			}
		},
	};
	assert_eq!(cr, rr, "{what}");
	(what, cr)
}

#[derive(Default, Debug)]
struct Seen {
	removed: usize,
	refused: usize,
	no_user: usize,
	logs: usize,
}

#[test]
fn option_fuzz() {
	let mut rng = Rng::new(0x4a2d);
	let n = (iters() / 100).max(50);
	let mut seen = Seen::default();
	for case in 0..n {
		let mut b = Both::new("opts");
		b.compare_state(&format!("case {case} initial"));
		b.compare_record("initialize");
		for i in 0..60 {
			let (what, cr) = step(&mut b, &mut rng);
			let what = format!("case {case} step {i}: {what}");
			let c_rec = c_record(&b.c);
			seen.logs += c_rec.logs.len();
			let r_rec = std::mem::take(&mut *b.rec.0.borrow_mut());
			assert_eq!(c_rec, r_rec, "{what}");
			b.compare_state(&what);
			seen.removed += usize::from(
				what.contains("remove") && cr == (1, 0),
			);
			seen.refused += usize::from(cr.0 == -1);
			seen.no_user += usize::from(
				what.contains("sandboxuser")
					&& b.r.sandboxuser().is_none(),
			);
		}
		drop(b);
	}
	eprintln!("{n} cases: {seen:?}");
	assert!(seen.removed > n && seen.no_user > n / 4, "{seen:?}");
	assert!(seen.logs > n && seen.refused > n / 4, "{seen:?}");
}

#[test]
fn initial_hookdir_and_lockfile() {
	let b = Both::new("init");
	let hook = [b.r.root(), b"usr/share/libalpm/hooks/"].concat();
	assert_eq!(b.r.hookdirs(), [hook]);
	let lock = [&b.fx.dbpath()[..], b"db.lck"].concat();
	assert_eq!(b.r.lockfile(), lock);
	b.compare_state("initial");
}

fn mode(path: &[u8]) -> Option<u32> {
	use std::os::unix::ffi::OsStrExt;
	let md = fs::symlink_metadata(std::ffi::OsStr::from_bytes(path));
	md.ok().map(|m| m.permissions().mode() & 0o7777)
}

fn io_errno(r: std::io::Result<()>) -> c_int {
	r.err().and_then(|e| e.raw_os_error()).unwrap_or(0)
}

// one lockfile, a C and a Rust handle taking turns
#[test]
fn lock_exclusive() {
	let mut b = Both::new("lock");
	let lockfile = b.r.lockfile().to_vec();
	// C holds it: the Rust handle gets EEXIST
	assert_eq!(b.c.lock(), (0, 0));
	assert_eq!(mode(&lockfile), Some(0));
	assert_eq!(io_errno(b.r.lock()), 17);
	assert!(!b.r.is_locked());
	// a second lock by the holder is a no-op
	assert_eq!(b.c.lock(), (0, 0));
	assert_eq!(b.c.unlock(), (0, 0, 0));
	assert_eq!(mode(&lockfile), None);
	// unlocking without the lock does nothing
	assert_eq!(b.c.unlock(), (0, 0, 0));
	assert!(b.r.unlock().is_ok());
	// Rust holds it now: same file, same mode, the C refused
	assert!(b.r.lock().is_ok());
	assert!(b.r.lock().is_ok());
	assert_eq!(mode(&lockfile), Some(0));
	assert_eq!(b.c.lock(), (-1, 17));
	assert!(b.r.unlock().is_ok());
	assert_eq!(mode(&lockfile), None);
	b.compare_record("lock turns");
}

// _alpm_handle_unlock: a vanished lockfile warns and logs, an
// unremovable one fails
#[test]
fn unlock_missing_and_stuck() {
	let mut b = Both::new("unlock");
	let lockfile = b.r.lockfile().to_vec();
	let (clog, rlog) = (b.fx.path("c.log"), b.fx.path("r.log"));
	b.c.set_logfile(&clog);
	b.r.set_logfile(&rlog);
	// the debug lines name different files
	b.c.take_record();
	b.rec.0.borrow_mut().logs.clear();
	let rm = |p: &[u8]| {
		use std::os::unix::ffi::OsStrExt;
		fs::remove_file(std::ffi::OsStr::from_bytes(p)).unwrap()
	};

	assert_eq!(b.c.lock(), (0, 0));
	rm(&lockfile);
	assert_eq!(b.c.handle_unlock(), 0);
	assert!(b.r.lock().is_ok());
	rm(&lockfile);
	assert!(b.r.handle_unlock());
	b.compare_record("missing lock");
	assert_eq!(stamped(&read(&clog)), stamped(&read(&rlog)));
	assert!(read(&rlog).ends_with(
		&[b"warning: lock file missing ", &lockfile[..], b"\n"]
			.concat()
	));

	// a read-only dbpath keeps the file: EACCES, unless root
	let db = b.fx.dir().join("db");
	fs::set_permissions(&db, fs::Permissions::from_mode(0o555)).unwrap();
	let probe = db.join("probe");
	if fs::write(&probe, b"").is_ok() {
		eprintln!("running as root, stuck lockfile skipped");
		fs::remove_file(&probe).unwrap();
		fs::set_permissions(&db, fs::Permissions::from_mode(0o755))
			.unwrap();
		return;
	}
	fs::set_permissions(&db, fs::Permissions::from_mode(0o755)).unwrap();
	assert_eq!(b.c.lock(), (0, 0));
	fs::set_permissions(&db, fs::Permissions::from_mode(0o555)).unwrap();
	assert_eq!(b.c.unlock(), (-1, err(Errno::System), 13));
	fs::set_permissions(&db, fs::Permissions::from_mode(0o755)).unwrap();
	// the C dropped the fd, the file stays: the Rust handle cannot lock
	assert_eq!(io_errno(b.r.lock()), 17);
	rm(&lockfile);
	assert!(b.r.lock().is_ok());
	fs::set_permissions(&db, fs::Permissions::from_mode(0o555)).unwrap();
	assert_eq!(io_errno(b.r.unlock()), 13);
	fs::set_permissions(&db, fs::Permissions::from_mode(0o755)).unwrap();
	rm(&lockfile);
	b.compare_record("stuck lock");

	// handle_unlock on a stuck file: warning, logaction, -1
	assert_eq!(b.c.lock(), (0, 0));
	fs::set_permissions(&db, fs::Permissions::from_mode(0o555)).unwrap();
	assert_eq!(b.c.handle_unlock(), -1);
	fs::set_permissions(&db, fs::Permissions::from_mode(0o755)).unwrap();
	rm(&lockfile);
	assert!(b.r.lock().is_ok());
	fs::set_permissions(&db, fs::Permissions::from_mode(0o555)).unwrap();
	assert!(!b.r.handle_unlock());
	fs::set_permissions(&db, fs::Permissions::from_mode(0o755)).unwrap();
	rm(&lockfile);
	b.compare_record("stuck handle_unlock");
	assert_eq!(stamped(&read(&clog)), stamped(&read(&rlog)));
}

// the lockfile's directory is made first
#[test]
fn lock_makes_dir() {
	let mut b = Both::new("lockdir");
	let lockfile = b.r.lockfile().to_vec();
	let db = b.fx.dir().join("db");
	fs::remove_dir_all(&db).unwrap();
	assert_eq!(b.c.lock(), (0, 0));
	assert_eq!(b.c.unlock(), (0, 0, 0));
	fs::remove_dir_all(&db).unwrap();
	assert!(b.r.lock().is_ok());
	assert_eq!(mode(&lockfile), Some(0));
	assert!(b.r.unlock().is_ok());
	// a dangling symlink as the dir: makepath fails on both
	fs::remove_dir_all(&db).unwrap();
	symlink("/nonexistent/dir", &db).unwrap();
	assert_eq!(b.c.lock().0, -1);
	assert!(b.r.lock().is_err());
	fs::remove_file(&db).unwrap();
}

fn read(path: &[u8]) -> Vec<u8> {
	use std::os::unix::ffi::OsStrExt;
	fs::read(std::ffi::OsStr::from_bytes(path)).unwrap_or_default()
}

const PREFIXES: [Option<&[u8]>; 5] = [
	None,
	Some(b""),
	Some(b"ALPM"),
	Some(b"PACMAN"),
	Some(b"a b"),
];

#[test]
fn logaction_fuzz() {
	let mut rng = Rng::new(0x1a9);
	let n = (iters() / 2000).max(20);
	let mut lines = 0;
	for case in 0..n {
		let mut b = Both::new("logaction");
		let names = ["a.log", "b.log", "sub/c.log"];
		fs::create_dir_all(b.fx.dir().join("c/sub")).unwrap();
		fs::create_dir_all(b.fx.dir().join("r/sub")).unwrap();
		for i in 0..30 {
			if i == 0 || rng.below(8) == 0 {
				let name = pick(&mut rng, &names);
				b.c.set_logfile(
					&b.fx.path(&format!("c/{name}")),
				);
				b.r.set_logfile(
					&b.fx.path(&format!("r/{name}")),
				);
				b.c.take_record();
				b.rec.0.borrow_mut().logs.clear();
			}
			let prefix = pick(&mut rng, &PREFIXES);
			let mut msg = rng.bytes(b"ab \n%[]-:T0\xc3", 40);
			if rng.below(20) == 0 {
				msg = rng.bytes(b"xyz\n", 5000);
			}
			let what = format!("case {case} {prefix:?} {msg:?}");
			let cr = b.c.logaction(prefix, &msg);
			let rr =
				b.r.logaction(prefix.unwrap_or_default(), &msg);
			assert_eq!(cr, (0, 0), "{what}");
			assert_eq!(rr, Ok(()), "{what}");
			lines += 1;
		}
		for name in names {
			let c = read(&b.fx.path(&format!("c/{name}")));
			let r = read(&b.fx.path(&format!("r/{name}")));
			let (c, r) = (stamped(&c), stamped(&r));
			assert_eq!(c, r, "case {case} {name}");
		}
	}
	assert!(lines >= n * 30);
}

// logfile errors: errno for open failures, a full device hides short
// lines in stdio's buffer
#[test]
fn logaction_errors() {
	let mut b = Both::new("logerr");
	let check = |b: &mut Both, path: &[u8], msg: &[u8], want| {
		b.c.set_logfile(path);
		b.r.set_logfile(path);
		let cr = b.c.logaction(Some(b"ALPM"), msg);
		let rr =
			b.r.logaction(b"ALPM", msg)
				.map_or_else(|e| (-1, err(e)), |_| (0, 0));
		let what = String::from_utf8_lossy(path).into_owned();
		assert_eq!(cr, want, "C {what}");
		assert_eq!(rr, want, "Rust {what}");
		// the next call opens again
		let cr = b.c.logaction(None, b"again\n");
		let rr =
			b.r.logaction(b"", b"again\n")
				.map_or_else(|e| (-1, err(e)), |_| (0, 0));
		assert_eq!(cr, rr, "again {what}");
	};
	let missing = b.fx.path("nodir/x.log");
	check(&mut b, &missing, b"m\n", (-1, err(Errno::NotADir)));
	let dir = b.fx.path("db");
	check(&mut b, &dir, b"m\n", (-1, err(Errno::System)));
	check(&mut b, b"/dev/full", b"short\n", (0, 0));
	let long = vec![b'x'; 5000];
	check(&mut b, b"/dev/full", &long, (-1, err(Errno::System)));
	let ro = b.fx.dir().join("ro");
	fs::create_dir(&ro).unwrap();
	fs::set_permissions(&ro, fs::Permissions::from_mode(0o555)).unwrap();
	if fs::write(ro.join("probe"), b"").is_err() {
		let p = b.fx.path("ro/x.log");
		check(&mut b, &p, b"m\n", (-1, err(Errno::Badperms)));
	}
	fs::set_permissions(&ro, fs::Permissions::from_mode(0o755)).unwrap();
	b.c.take_record();
}

// _alpm_log_leader and the vsyslog header against strftime
#[test]
fn stamp_format() {
	let mut rng = Rng::new(0x57a);
	for _ in 0..iters() {
		// years -6700 to 10700: %F's unpadded and negative years
		let secs = (rng.next_u64() % (1 << 39)) as i64 - (1 << 38);
		let utcoff = rng.below(28 * 3600 + 1) as i32 - 14 * 3600;
		let t = LogTime { secs, utcoff };
		let stamp = c_strftime_at(secs, utcoff, c"[%FT%T%z] [");
		let want = [&stamp[..], b"ALPM] "].concat();
		assert_eq!(leader(t, b"ALPM"), want, "{t:?}");
		let head = c_strftime_at(secs, utcoff, c"%h %e %T ");
		let want = [b"<12>", &head[..], b"pacman: msg\n"].concat();
		assert_eq!(
			syslog_message(t, b"pacman", b"msg\n"),
			want,
			"{t:?}"
		);
	}
}

// the zones local time is checked in: no TZ (/etc/localtime), empty
// (UTC), DST both ways and at :30, offsets at :30/:45, Chatham's +1345,
// Casablanca's Ramadan shifts, Lord Howe's 30 min DST, POSIX rule and
// offset strings, a file path and an unknown name (UTC to glibc)
const ZONES: [Option<&str>; 16] = [
	None,
	Some(""),
	Some("UTC"),
	Some("Europe/Brussels"),
	Some(":Europe/Dublin"),
	Some("America/New_York"),
	Some("America/St_Johns"),
	Some("America/Sao_Paulo"),
	Some("Asia/Kathmandu"),
	Some("Pacific/Chatham"),
	Some("Africa/Casablanca"),
	Some("Australia/Lord_Howe"),
	Some("EST5EDT,M3.2.0,M11.1.0"),
	Some("<+0330>-3:30"),
	Some("/usr/share/zoneinfo/Asia/Tokyo"),
	Some("Nowhere/Zone"),
];

// alpm_core::log::local_offset, the leader, the syslog header, the
// PACMAN_DEBUG stamp and -Qi's %c date against localtime(3) in each
// zone: tz-probe runs once per TZ (glibc reads it once a process)
#[test]
fn local_time_zones() {
	let mut edges = 0;
	for tz in ZONES {
		let mut cmd = Command::new(env!("CARGO_BIN_EXE_tz-probe"));
		cmd.env_clear().env("LC_ALL", "C");
		if let Some(tz) = tz {
			cmd.env("TZ", tz);
		}
		let o = cmd.output().unwrap();
		let out = String::from_utf8_lossy(&o.stdout);
		let err = String::from_utf8_lossy(&o.stderr);
		assert!(o.status.success(), "TZ={tz:?}\n{out}{err}");
		let last = out.lines().last().unwrap_or_default();
		println!("TZ={tz:?}: {last}");
		let n: Vec<usize> = last
			.split(' ')
			.filter_map(|w| w.parse().ok())
			.collect();
		assert!(n.len() == 2 && n[0] >= 5000, "TZ={tz:?}: {last}");
		edges += n[1];
	}
	// the DST zones' rules were read (tzdata present)
	assert!(edges > 1000, "{edges} transitions");
}

// registration: a missing db file sends DATABASE_MISSING with its name,
// both log "registering sync database"
#[test]
fn register_events() {
	let mut b = Both::new("events");
	fs::write(b.fx.sync_file("core", ".db"), b"").unwrap();
	b.compare_record("before");
	for (name, level) in [("core", 0), ("extra", 0), ("gone", 1 << 30)] {
		let cr = b.c.register_syncdb(name.as_bytes(), level);
		let rr = b.r.register_syncdb(name.as_bytes(), level).is_ok();
		assert_eq!(cr, (rr, 0), "{name}");
		b.compare_record(name);
	}
	let missing = b.r.syncdbs().iter().filter(|d| d.valid().is_ok());
	assert_eq!(missing.count(), 3);
}
