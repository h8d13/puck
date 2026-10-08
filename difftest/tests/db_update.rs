// alpm_core::be_sync::db_update against the C alpm_db_update, and -Sy/-Fy
// against C pacman_sync/pacman_files: a C and a Rust handle, each on its
// own fixture root, download from the same scripted HTTP mirrors on
// 127.0.0.1 (generated sync dbs, signatures from a throwaway keyring).
// every step compared: return value, pm_errno, events, import questions,
// error/warning logs and be_sync's debug lines, download callback events
// (progress runs reduced to their last event), the requests each side
// sent, the files under db/sync (contents, server mtimes, leftovers), and
// each db's validity and package cache after the step. caches are loaded
// between steps, so a missing invalidation shows as stale packages.
use std::ffi::c_int;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::MutexGuard;
use std::sync::atomic::{AtomicU16, Ordering};

use alpm_core::callbacks::{DownloadEvent, LogLevel};
use alpm_core::db::{DB_USAGE_ALL, DB_USAGE_SEARCH, SIG_DATABASE};
use alpm_core::error::Errno;
use alpm_core::handle::Handle;
use alpm_core::signing::{SIG_DATABASE_OPTIONAL, SIG_DATABASE_UNKNOWN_OK};
use difftest::{
	CRun, CUpdate, DbSpec, DbState, GpgFixture, Home, RUpdate, Reply, Req,
	Rng, Server, TempRoot, UpdRecord, UpdSetup, c_pacman_files_refresh,
	c_pacman_sync_refresh, front_handle, iters, sync_db, test_sandbox_for,
	umask_lock,
};
use pacman_cli::callback::Frontend;
use pacman_cli::conf::{ColStr, Config};
use pacman_cli::files::pacman_files;
use pacman_cli::sync::pacman_sync;
use pacman_cli::util::{Output, Term};
use rustix::fs::Mode;
use rustix::process::umask;

const T0: i64 = 1_000_000_000;
const DAY: i64 = 86_400;
const REQUIRED: c_int = SIG_DATABASE;
const OPTIONAL: c_int = SIG_DATABASE | SIG_DATABASE_OPTIONAL;

// name, contents, mtime when a server set it, permission bits
type Files = Vec<(Vec<u8>, Vec<u8>, Option<i64>, u32)>;

// one side of a step, normalized for comparison. logs as text for the
// assert messages, rec holds the rest
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
	ret: c_int,
	errno: c_int,
	logs: Vec<(LogLevel, String)>,
	rec: UpdRecord,
	requests: Vec<Req>,
	files: Files,
	states: Vec<DbState>,
}

// progress events of a file between two of its other events: only the
// last one stays (curl's progress timing is not deterministic)
fn reduce_progress(
	ev: &[(Vec<u8>, DownloadEvent)],
) -> Vec<(Vec<u8>, DownloadEvent)> {
	let mut out: Vec<(Vec<u8>, DownloadEvent)> = Vec::new();
	for (name, e) in ev {
		if matches!(e, DownloadEvent::Progress { .. }) {
			let prev = out.iter().rposition(|(n, _)| n == name);
			if let Some(i) = prev
				&& matches!(
					out[i].1,
					DownloadEvent::Progress { .. }
				) {
				out.remove(i);
			}
		}
		out.push((name.clone(), *e));
	}
	out
}

// files under dir (db/sync): mtimes kept only when a server set them
fn snapshot(dir: &Path) -> Files {
	let mut out = Vec::new();
	let Ok(rd) = fs::read_dir(dir) else {
		return out;
	};
	for e in rd.flatten() {
		let md = e.metadata().unwrap();
		let data = match md.is_file() {
			true => fs::read(e.path()).unwrap(),
			false => b"<dir>".to_vec(),
		};
		let mtime = (md.mtime() < 1_500_000_000).then_some(md.mtime());
		let name = e.file_name().as_bytes().to_vec();
		out.push((name, data, mtime, md.mode() & 0o7777));
	}
	out.sort();
	out
}

// the logs as text with the fixture dir replaced, the record without
// them, its progress runs reduced
fn norm(
	rec: UpdRecord,
	fx: &TempRoot,
	sorted: bool,
) -> (Vec<(LogLevel, String)>, UpdRecord) {
	let dir = fx.dir().display().to_string();
	let mut logs: Vec<_> =
		rec.logs.iter()
			.map(|(l, m)| {
				let s = String::from_utf8_lossy(m);
				(*l, s.replace(&dir, "<fx>"))
			})
			.collect();
	let mut downloads = reduce_progress(&rec.downloads);
	// per file order is fixed, the order between files is not
	downloads.sort_by(|a, b| a.0.cmp(&b.0));
	if sorted {
		logs.sort();
	}
	let rec = UpdRecord {
		logs: Vec::new(),
		downloads,
		..rec
	};
	(logs, rec)
}

fn text(b: &[u8]) -> String {
	String::from_utf8_lossy(b).into_owned()
}

// the fields where c and r part, files and names as text
fn diff(c: &Outcome, r: &Outcome) -> Option<String> {
	let files = |o: &Outcome| -> Vec<String> {
		let f = o.files.iter();
		f.map(|(n, d, t, m)| {
			format!("{} {}B {t:?} {m:o}", text(n), d.len())
		})
		.collect()
	};
	let states = |o: &Outcome| -> Vec<String> {
		let st = o.states.iter();
		st.map(|d| {
			let cache = d.cache.as_ref().map(|c| {
				let c = c.iter();
				c.map(|(n, v)| {
					format!("{}-{}", text(n), text(v))
				})
				.collect::<Vec<_>>()
			});
			format!("valid {:?} cache {cache:?}", d.valid)
		})
		.collect()
	};
	let dl = |o: &Outcome| -> Vec<String> {
		let d = o.rec.downloads.iter();
		d.map(|(n, e)| format!("{} {e:?}", text(n))).collect()
	};
	let parts = [
		("ret", format!("{:?}", c.ret), format!("{:?}", r.ret)),
		("errno", format!("{:?}", c.errno), format!("{:?}", r.errno)),
		("logs", format!("{:#?}", c.logs), format!("{:#?}", r.logs)),
		(
			"events",
			format!("{:?}", c.rec.events),
			format!("{:?}", r.rec.events),
		),
		(
			"questions",
			format!("{:?}", c.rec.questions),
			format!("{:?}", r.rec.questions),
		),
		(
			"downloads",
			format!("{:#?}", dl(c)),
			format!("{:#?}", dl(r)),
		),
		(
			"requests",
			format!("{:#?}", c.requests),
			format!("{:#?}", r.requests),
		),
		(
			"files",
			format!("{:#?}", files(c)),
			format!("{:#?}", files(r)),
		),
		(
			"contents",
			format!("{:?}", c.files),
			format!("{:?}", r.files),
		),
		(
			"states",
			format!("{:#?}", states(c)),
			format!("{:#?}", states(r)),
		),
	];
	let d: Vec<String> = parts
		.iter()
		.filter(|(_, a, b)| a != b)
		.map(|(what, a, b)| format!("{what}:\nC {a}\nRust {b}"))
		.collect();
	(!d.is_empty()).then(|| d.join("\n"))
}

fn requests(servers: &[&Server]) -> Vec<Req> {
	let mut r: Vec<Req> =
		servers.iter().flat_map(|s| s.requests()).collect();
	r.sort();
	for s in servers {
		s.reset();
	}
	r
}

// a C and a Rust handle built from one setup, each on its own root.
// alpm_db_update sets the umask: the lock is taken before the C handle's
// and dropped after it, with the process mask put back
struct Pair {
	cfx: TempRoot,
	rfx: TempRoot,
	// None only while renew swaps it
	c: Option<CUpdate>,
	r: RUpdate,
	sorted: bool,
	// set when sandboxed: the handles are made anew for every step
	setup: Option<UpdSetup>,
	oldmask: Option<Mode>,
	_umask: MutexGuard<'static, ()>,
}

impl Drop for Pair {
	fn drop(&mut self) {
		if let Some(m) = self.oldmask {
			umask(m);
		}
	}
}

impl Pair {
	fn new(s: &UpdSetup, prep: &dyn Fn(&TempRoot)) -> Pair {
		let guard = umask_lock();
		let (cfx, rfx) =
			(TempRoot::new("dbupd-c"), TempRoot::new("dbupd-r"));
		prep(&cfx);
		prep(&rfx);
		let c = CUpdate::new(&cfx, s);
		let r = RUpdate::new(&rfx, s);
		Pair {
			cfx,
			rfx,
			c: Some(c),
			r,
			sorted: s.parallel > 1,
			setup: None,
			oldmask: None,
			_umask: guard,
		}
	}

	// the Rust side downloads in the sandbox helper (as for root, the
	// helper as the current user), the C side plainly: the C sandbox
	// needs real root. the helper's server error counts die with it
	// (the C's forked child): fresh handles on both sides every step
	// keep the plain C from counting across steps. the process umask is
	// 077 meanwhile, the C's umask(0022) has to show in the modes
	fn sandboxed(mut self, s: &UpdSetup) -> Pair {
		self.setup = Some(s.clone());
		self.renew();
		self.oldmask = Some(umask(Mode::from_raw_mode(0o077)));
		self
	}

	fn renew(&mut self) {
		let Some(s) = &self.setup else {
			return;
		};
		// the C handle (and the ALPM lock) goes before the next
		self.c = None;
		self.c = Some(CUpdate::new(&self.cfx, s));
		self.r = RUpdate::new(&self.rfx, s);
		assert!(self.r.h.set_sandboxuser(Some(b"root")));
		self.r.h.set_sandbox_for(test_sandbox_for);
	}

	// one update on both sides, C first
	fn step(
		&mut self,
		servers: &[&Server],
		dbs: &[usize],
		force: bool,
	) -> (Outcome, Outcome) {
		for s in servers {
			s.reset();
		}
		self.renew();
		let c = self.c.as_mut().expect("set outside renew");
		let (ret, errno, rec) = c.update(dbs, force);
		let (logs, rec) = norm(rec, &self.cfx, self.sorted);
		let c = Outcome {
			ret,
			errno,
			logs,
			rec,
			requests: requests(servers),
			files: snapshot(&self.cfx.dir().join("db/sync")),
			states: c.states(),
		};
		let (ret, errno, rec) = self.r.update(dbs, force);
		let (logs, rec) = norm(rec, &self.rfx, self.sorted);
		let r = Outcome {
			ret,
			errno,
			logs,
			rec,
			requests: requests(servers),
			files: snapshot(&self.rfx.dir().join("db/sync")),
			states: self.r.states(),
		};
		(c, r)
	}

	// step, asserting both sides equal; the C outcome comes back
	fn check(
		&mut self,
		what: &str,
		servers: &[&Server],
		dbs: &[usize],
		force: bool,
	) -> Outcome {
		let (c, r) = self.step(servers, dbs, force);
		if let Some(d) = diff(&c, &r) {
			panic!("{what}: dbs {dbs:?} force {force}\n{d}");
		}
		c
	}
}

fn file(body: &[u8], mtime: i64) -> Reply {
	Reply::File {
		body: body.to_vec(),
		ranges: false,
		mtime: Some(mtime),
	}
}

fn not_found() -> Reply {
	Reply::Status(404, b"<html>404</html>\n".to_vec())
}

fn spec(name: &str, siglevel: c_int, servers: Vec<Vec<u8>>) -> DbSpec {
	DbSpec {
		name: name.to_string(),
		siglevel,
		servers,
		usage: DB_USAGE_ALL,
	}
}

fn setup(dbs: Vec<DbSpec>, parallel: u32) -> UpdSetup {
	UpdSetup {
		dbext: b".db".to_vec(),
		gpgdir: None,
		default_siglevel: 0,
		parallel,
		answer: false,
		dbs,
	}
}

fn no_prep(_: &TempRoot) {}

// first sync, up to date, forced, changed upstream, mirror fallback,
// failures, subsets and usage, sequentially and in parallel, the Rust
// side plain and sandboxed
#[test]
fn sequences() {
	for (parallel, sandbox) in
		[(1, false), (2, false), (1, true), (2, true)]
	{
		let srv = Server::start();
		let (m1, m2) = (srv.url("/m1"), srv.url("/m2"));
		let s = setup(
			vec![
				spec("core", 0, vec![m1.clone(), m2.clone()]),
				spec("extra", 0, vec![m1.clone(), m2.clone()]),
			],
			parallel,
		);
		let mut p = Pair::new(&s, &no_prep);
		if sandbox {
			p = p.sandboxed(&s);
		}
		let sv = [&srv];
		let (core0, n0) = sync_db(1, false);
		let (core1, n1) = sync_db(2, false);
		let (extra0, _) = sync_db(3, false);
		assert_ne!(n0, n1, "core versions must differ");

		// nothing there yet: both dbs fetched from m1
		srv.route("/m1/core.db", vec![file(&core0, T0)]);
		srv.route("/m1/extra.db", vec![file(&extra0, T0)]);
		let o = p.check("first sync", &sv, &[0, 1], false);
		assert_eq!(o.ret, 0);
		assert!(o.states[0]
			.cache
			.as_ref()
			.is_ok_and(|c| c.len() == n0.len()));

		// If-Modified-Since: 304 for both
		let o = p.check("up to date", &sv, &[0, 1], false);
		assert_eq!(o.ret, 1);
		assert!(o.requests.iter().all(|r| r.ims.is_some()), "{o:?}");

		// -Syy: no If-Modified-Since
		let o = p.check("forced", &sv, &[0, 1], true);
		assert_eq!(o.ret, 0);
		assert!(o.requests.iter().all(|r| r.ims.is_none()), "{o:?}");

		// core changed upstream: the loaded cache must follow
		srv.route("/m1/core.db", vec![file(&core1, T0 + DAY)]);
		let o = p.check("changed", &sv, &[0, 1], false);
		let names: Vec<(Vec<u8>, Vec<u8>)> = n1
			.iter()
			.map(|(n, v)| {
				(n.clone().into_bytes(), v.clone().into_bytes())
			})
			.collect();
		let mut sorted = o.states[0].cache.clone().unwrap();
		sorted.sort();
		let mut want = names.clone();
		want.sort();
		assert_eq!(sorted, want);

		// m1 refuses core: m2 serves it
		for status in [404, 500] {
			let body = b"<html>no</html>\n".to_vec();
			srv.route(
				"/m1/core.db",
				vec![Reply::Status(status, body)],
			);
			srv.route(
				"/m2/core.db",
				vec![file(&core0, T0 + 2 * DAY)],
			);
			let o = p.check(
				"fallback",
				&sv,
				&[0, 1],
				status == 500,
			);
			assert_eq!(o.ret, 0, "{status}");
		}

		// every mirror fails for extra: the update fails as a whole
		srv.route("/m1/extra.db", vec![not_found()]);
		srv.route("/m2/extra.db", vec![not_found()]);
		let o = p.check("all fail", &sv, &[0, 1], true);
		assert_eq!(o.ret, -1);

		// cut short, then a subset, then the db list empty
		let cut = Reply::Truncated {
			body: extra0.clone(),
			sent: 600,
		};
		srv.route("/m1/extra.db", vec![cut]);
		p.check("truncated", &sv, &[1], true);
		srv.route("/m1/extra.db", vec![file(&extra0, T0)]);
		p.check("subset", &sv, &[1], false);
		// one db twice races its own files; sandboxed, the helper's
		// exit 2 is RETRIEVE where the plain C can leave ALPM_ERR_OK
		// (UPSTREAM.md) and the rename error names the temporary dir
		if !sandbox {
			p.check("subset twice", &sv, &[1, 1], true);
		}
		let o = p.check("no dbs", &sv, &[], false);
		assert_eq!((o.ret, o.errno), (-1, 0));
	}
}

// dbs not used for syncing, dbs without servers, the lock, the sync dir
#[test]
fn edges() {
	let srv = Server::start();
	let m1 = srv.url("/m1");
	let sv = [&srv];
	let (core0, _) = sync_db(4, false);
	srv.route("/m1/core.db", vec![file(&core0, T0)]);
	srv.route("/m1/extra.db", vec![file(&core0, T0)]);

	// usage without SYNC: skipped; all skipped is success, no events
	let mut s = setup(
		vec![
			spec("core", 0, vec![m1.clone()]),
			spec("extra", 0, vec![m1.clone()]),
		],
		1,
	);
	s.dbs[0].usage = DB_USAGE_SEARCH;
	let mut p = Pair::new(&s, &no_prep);
	let o = p.check("usage", &sv, &[0, 1], false);
	assert_eq!(o.ret, 0);
	let o = p.check("usage only", &sv, &[0], false);
	assert_eq!((o.ret, o.rec.events.len()), (0, 0));
	drop(p);

	// no servers: SERVER_NONE, even after a db that has some
	let s = setup(
		vec![
			spec("core", 0, vec![m1.clone()]),
			spec("extra", 0, vec![]),
		],
		1,
	);
	let mut p = Pair::new(&s, &no_prep);
	let o = p.check("no servers", &sv, &[0, 1], false);
	assert_eq!((o.ret, o.errno), (-1, Errno::ServerNone as c_int));
	drop(p);

	// the lock is taken: HANDLE_LOCK, the other holder's file stays
	let s = setup(vec![spec("core", 0, vec![m1.clone()])], 1);
	let lock = |fx: &TempRoot| {
		fs::write(fx.dir().join("db/db.lck"), b"").unwrap()
	};
	let mut p = Pair::new(&s, &lock);
	let o = p.check("locked", &sv, &[0], false);
	assert_eq!((o.ret, o.errno), (-1, Errno::HandleLock as c_int));
	assert!(p.cfx.dir().join("db/db.lck").exists());
	assert!(p.rfx.dir().join("db/db.lck").exists());
	drop(p);

	// no sync dir: made (debug line); a file in its place
	let gone = |fx: &TempRoot| {
		fs::remove_dir(fx.dir().join("db/sync")).unwrap()
	};
	let mut p = Pair::new(&s, &gone);
	let o = p.check("no sync dir", &sv, &[0], false);
	assert_eq!(o.ret, 0);
	drop(p);
	let blocked = |fx: &TempRoot| {
		let d = fx.dir().join("db/sync");
		fs::remove_dir(&d).unwrap();
		fs::write(&d, b"not a dir").unwrap();
	};
	let mut p = Pair::new(&s, &blocked);
	let o = p.check("sync is a file", &sv, &[0], false);
	assert_eq!(o.ret, -1);
	drop(p);

	// a .files db
	let mut s = setup(vec![spec("core", 0, vec![m1.clone()])], 1);
	s.dbext = b".files".to_vec();
	let (files0, _) = sync_db(5, true);
	srv.route("/m1/core.files", vec![file(&files0, T0)]);
	let mut p = Pair::new(&s, &no_prep);
	let o = p.check(".files", &sv, &[0], false);
	assert_eq!(o.ret, 0);
	assert!(o.requests.iter().all(|r| r.path.ends_with("core.files")));
	p.check(".files up to date", &sv, &[0], false);
}

// signed dbs: the bodies and their signatures from the gpg fixture
struct Signed {
	body: Vec<Vec<u8>>,
	// "full" signatures of each body, then one by a key not in the
	// keyring
	sig: Vec<Vec<u8>>,
	stranger: Vec<u8>,
}

impl Signed {
	fn new(gfx: &GpgFixture, seeds: &[u64], files: bool) -> Signed {
		let tmp = gfx.dir().join("tosign");
		let mut body = Vec::new();
		let mut sig = Vec::new();
		for &seed in seeds {
			let (b, _) = sync_db(seed, files);
			fs::write(&tmp, &b).unwrap();
			sig.push(gfx.sign_file(&["full"], &tmp));
			body.push(b);
		}
		let stranger = gfx.sign_file(&["stranger"], &tmp);
		fs::remove_file(tmp).unwrap();
		Signed {
			body,
			sig,
			stranger,
		}
	}
}

fn sig(bytes: &[u8]) -> Reply {
	Reply::File {
		body: bytes.to_vec(),
		ranges: false,
		mtime: None,
	}
}

fn sig_setup(gfx: &GpgFixture, dbs: Vec<DbSpec>, answer: bool) -> UpdSetup {
	UpdSetup {
		gpgdir: Some(gfx.home(Home::Pgp)),
		answer,
		..setup(dbs, 1)
	}
}

// required, optional and default levels; good, missing, bad and unknown
// signatures; the import question both ways
#[test]
fn signatures() {
	let gfx = GpgFixture::new("dbupd-gpg");
	let sd = Signed::new(&gfx, &[11, 12], false);
	let srv = Server::start();
	let m1 = srv.url("/m1");
	let sv = [&srv];
	let core = |b: usize, s: Reply| {
		srv.route(
			"/m1/core.db",
			vec![file(&sd.body[b], T0 + b as i64)],
		);
		srv.route("/m1/core.db.sig", vec![s]);
	};
	let extra = |b: usize, s: Reply| {
		srv.route(
			"/m1/extra.db",
			vec![file(&sd.body[b], T0 + b as i64)],
		);
		srv.route("/m1/extra.db.sig", vec![s]);
	};
	for answer in [false, true] {
		let mut s = sig_setup(
			&gfx,
			vec![
				spec("core", REQUIRED, vec![m1.clone()]),
				spec("extra", OPTIONAL, vec![m1.clone()]),
				spec("multilib", 1 << 30, vec![m1.clone()]),
			],
			answer,
		);
		s.default_siglevel = REQUIRED | SIG_DATABASE_UNKNOWN_OK;
		srv.route("/m1/multilib.db", vec![file(&sd.body[0], T0)]);
		srv.route("/m1/multilib.db.sig", vec![sig(&sd.sig[0])]);
		let mut p = Pair::new(&s, &no_prep);

		core(0, sig(&sd.sig[0]));
		extra(0, sig(&sd.sig[0]));
		let o = p.check("good", &sv, &[0, 1, 2], false);
		assert_eq!(o.ret, 0, "{o:#?}");

		// a required .sig missing fails the download
		core(1, not_found());
		let o = p.check("required missing", &sv, &[0, 1, 2], false);
		assert_eq!(o.ret, -1);

		// signature of the other body: core invalid
		core(1, sig(&sd.sig[0]));
		let o = p.check("bad", &sv, &[0, 1, 2], false);
		assert_eq!(
			(o.ret, o.errno),
			(-1, Errno::DbInvalidSig as c_int)
		);
		assert!(o.states[0].valid.0 == -1);

		// an invalid db is fetched without If-Modified-Since
		core(1, sig(&sd.sig[1]));
		let o = p.check("invalid refetched", &sv, &[0, 1, 2], false);
		assert_eq!(o.ret, 0);
		let core_req =
			o.requests.iter().find(|r| r.path == "/m1/core.db");
		assert!(core_req.is_some_and(|r| r.ims.is_none()), "{o:?}");

		// optional, no .sig upstream: the one of the last sync stays
		// and fails the new db (UPSTREAM.md)
		extra(1, not_found());
		let o = p.check("optional missing", &sv, &[0, 1, 2], false);
		assert_eq!(o.ret, -1, "{o:#?}");
		assert!(p.cfx.sync_file("extra", ".db.sig").exists());
		extra(1, sig(&sd.sig[0]));
		p.check("optional bad", &sv, &[0, 1, 2], true);

		// a key the keyring lacks: the import question, then the
		// lookup fails without network. unknown trust is fine for
		// multilib (default level), the key still has to be known
		core(1, sig(&sd.stranger));
		extra(1, sig(&sd.sig[1]));
		let o = p.check("unknown key", &sv, &[0, 1, 2], true);
		assert_eq!(o.rec.questions.len(), 1, "{o:?}");
		srv.route("/m1/multilib.db.sig", vec![sig(&sd.stranger)]);
		core(1, sig(&sd.sig[1]));
		p.check("unknown key default", &sv, &[0, 1, 2], true);
		srv.route("/m1/multilib.db.sig", vec![sig(&sd.sig[0])]);
		p.check("recovered", &sv, &[0, 1, 2], true);
	}
}

// UPSTREAM.md: a later db with a missing optional signature resets the
// pm_errno an earlier failed validation set (signing.c:817), the C fails
// with ALPM_ERR_OK. the port keeps DB_INVALID_SIG; all else equal
#[test]
fn errno_reset_pinned() {
	let gfx = GpgFixture::new("dbupd-errno");
	let sd = Signed::new(&gfx, &[21, 22], false);
	let srv = Server::start();
	let m1 = srv.url("/m1");
	let s = sig_setup(
		&gfx,
		vec![
			spec("core", REQUIRED, vec![m1.clone()]),
			spec("extra", OPTIONAL, vec![m1.clone()]),
		],
		false,
	);
	srv.route("/m1/core.db", vec![file(&sd.body[0], T0)]);
	srv.route("/m1/core.db.sig", vec![sig(&sd.sig[1])]);
	srv.route("/m1/extra.db", vec![file(&sd.body[1], T0)]);
	let mut p = Pair::new(&s, &no_prep);
	let (mut c, r) = p.step(&[&srv], &[0, 1], false);
	assert_eq!((c.ret, c.errno), (-1, 0));
	assert_eq!((r.ret, r.errno), (-1, Errno::DbInvalidSig as c_int));
	// the C's debug line names the errno it ends with
	let unexpected = "failed to sync dbs: unexpected error\n";
	let fixed = "failed to sync dbs: invalid or corrupted database (PGP \
		signature)\n";
	for l in &mut c.logs {
		if l.1 == unexpected {
			l.1 = fixed.to_string();
		}
	}
	c.errno = r.errno;
	assert_eq!(c, r);
	// the other order keeps the errno on both sides
	let (c, r) = p.step(&[&srv], &[1, 0], true);
	assert_eq!(c, r);
	assert_eq!(c.errno, Errno::DbInvalidSig as c_int);
}

// what a fuzz db serves next
#[derive(Clone, Copy, Debug)]
enum Serve {
	// body n with its mtime, signed
	Body(usize),
	// body n, a bad signature
	BadSig(usize),
	// body n, no signature
	NoSig(usize),
	// m1 404, m2 body n
	Fallback(usize),
	// m1 and m2 500
	Fail,
	// m1 truncated body n
	Cut(usize),
}

fn route_db(srv: &Server, sd: &Signed, ext: &str, name: &str, how: Serve) {
	let path = |m: &str, sfx: &str| format!("/{m}/{name}{ext}{sfx}");
	let mt = |b: usize| T0 + b as i64 * DAY;
	let both = |p: &str, r: Vec<Reply>| {
		srv.route(&path("m1", p), r.clone());
		srv.route(&path("m2", p), r);
	};
	let fail = Reply::Status(500, b"<html>500</html>\n".to_vec());
	match how {
		Serve::Body(b) | Serve::BadSig(b) | Serve::NoSig(b) => {
			both("", vec![file(&sd.body[b], mt(b))]);
			match how {
				Serve::Body(_) => {
					both(".sig", vec![sig(&sd.sig[b])])
				}
				Serve::BadSig(_) => {
					let other =
						&sd.sig[(b + 1) % sd.sig.len()];
					both(".sig", vec![sig(other)]);
				}
				_ => both(".sig", vec![not_found()]),
			}
		}
		Serve::Fallback(b) => {
			srv.route(&path("m1", ""), vec![not_found()]);
			srv.route(
				&path("m2", ""),
				vec![file(&sd.body[b], mt(b))],
			);
			both(".sig", vec![sig(&sd.sig[b])]);
		}
		Serve::Fail => both("", vec![fail]),
		Serve::Cut(b) => {
			let cut = Reply::Truncated {
				body: sd.body[b].clone(),
				sent: sd.body[b].len() / 2,
			};
			both("", vec![cut]);
			both(".sig", vec![sig(&sd.sig[b])]);
		}
	}
}

fn fuzz_serve(rng: &mut Rng, n: usize) -> Serve {
	let b = rng.below(n);
	// no non-archive bodies: the be_sync reader fails those at the
	// first header (LIBARCHIVE), the C at open (DB_OPEN), PORTING.md
	match rng.below(11) {
		0 => Serve::BadSig(b),
		1 => Serve::NoSig(b),
		2 => Serve::Fallback(b),
		3 => Serve::Fail,
		4 => Serve::Cut(b),
		_ => Serve::Body(b),
	}
}

const LEVELS: [c_int; 4] = [0, REQUIRED, OPTIONAL, 1 << 30];
const FUZZ_REPOS: [&str; 3] = ["core", "extra", "multilib"];

// random setups and step sequences: siglevels, mirrors, parallel
// downloads, force, subsets, .db or .files
#[test]
fn fuzz() {
	let gfx = GpgFixture::new("dbupd-fuzz");
	let sdb = Signed::new(&gfx, &[31, 32, 33], false);
	let sfiles = Signed::new(&gfx, &[34, 35], true);
	let srv = Server::start();
	let (m1, m2) = (srv.url("/m1"), srv.url("/m2"));
	let mut rng = Rng::new(0xdb0d);
	let n = (iters() / 4000).max(30);
	let mut steps = 0;
	for i in 0..n {
		let files = rng.below(4) == 0;
		let (ext, sd) = match files {
			true => (".files", &sfiles),
			false => (".db", &sdb),
		};
		let ndb = 1 + rng.below(FUZZ_REPOS.len());
		let dbs: Vec<DbSpec> = FUZZ_REPOS[..ndb]
			.iter()
			.map(|name| {
				let level = LEVELS[rng.below(LEVELS.len())];
				spec(name, level, vec![m1.clone(), m2.clone()])
			})
			.collect();
		let mut s = sig_setup(&gfx, dbs, rng.below(2) == 0);
		s.dbext = ext.as_bytes().to_vec();
		s.parallel = 1 + rng.below(3) as u32;
		s.default_siglevel = LEVELS[rng.below(3)];
		let log = format!(
			"case {i}: dbext {ext} parallel {} default {:#x} answer {}\n{:?}",
			s.parallel,
			s.default_siglevel,
			s.answer,
			s.dbs.iter()
				.map(|d| (&d.name, d.siglevel))
				.collect::<Vec<_>>()
		);
		let mut p = Pair::new(&s, &no_prep);
		for _ in 0..1 + rng.below(4) {
			let mut plan = Vec::new();
			for name in &FUZZ_REPOS[..ndb] {
				let how = fuzz_serve(&mut rng, sd.body.len());
				route_db(&srv, sd, ext, name, how);
				plan.push(how);
			}
			let sel: Vec<usize> = match rng.below(4) {
				0 => (0..ndb)
					.filter(|_| rng.below(2) == 0)
					.collect(),
				_ => (0..ndb).collect(),
			};
			let force = rng.below(3) == 0;
			let (c, r) = p.step(&[&srv], &sel, force);
			// the C errno reset (errno_reset_pinned) is not mirrored.
			// a failure among parallel downloads stops new ones: which
			// were started by then is timing, on both sides
			let reset = c.errno == 0
				&& r.errno == Errno::DbInvalidSig as c_int;
			if reset || (s.parallel > 1 && c.ret == -1) {
				assert_eq!(c.ret, r.ret, "{log}\n{plan:?}");
				continue;
			}
			if let Some(d) = diff(&c, &r) {
				panic!(
					"{log}\nplan {plan:?} sel {sel:?} force {force}\n{d}"
				);
			}
			steps += 1;
		}
	}
	assert!(steps >= n, "only {steps} steps compared");
}

// -Sy/-Syy/-Fy through pacman_sync/pacman_files, both with the
// frontend's callbacks (callback.c, pacman_cli::callback::Frontend):
// without progress bars (COLUMNS=0, a pipe) and with them (COLUMNS set,
// --noprogressbar off; CLOCK_MONOTONIC_COARSE stays at the difftest's
// fake 0 on both sides, so only the final stats draw). the Rust op and
// its callbacks write through one sink, in order like the C streams
thread_local! {
	static SINK: std::cell::RefCell<Output> =
		std::cell::RefCell::new(Output::default());
}

fn sink(o: &mut Output) {
	SINK.with(|s| {
		let mut s = s.borrow_mut();
		s.stdout.append(&mut o.stdout);
		s.stderr.append(&mut o.stderr);
	});
}

static FRONT_COLS: AtomicU16 = AtomicU16::new(0);

fn front_cols() -> u16 {
	FRONT_COLS.load(Ordering::SeqCst)
}

struct Front {
	cfx: TempRoot,
	rfx: TempRoot,
	dbext: Vec<u8>,
	servers: Vec<Vec<Vec<u8>>>,
}

const FRONT_REPOS: [&str; 2] = ["core", "extra"];

impl Front {
	fn new(dbext: &[u8], servers: Vec<Vec<Vec<u8>>>) -> Front {
		let (cfx, rfx) =
			(TempRoot::new("dbupd-fc"), TempRoot::new("dbupd-fr"));
		Front {
			cfx,
			rfx,
			dbext: dbext.to_vec(),
			servers,
		}
	}

	fn rust_handle(&self, cfg: &Config) -> Handle {
		let fx = &self.rfx;
		let mut h =
			Handle::initialize(&fx.root(), &fx.dbpath()).unwrap();
		let term = Term {
			cols: front_cols,
			..Term::new(&b""[..], false, false)
		};
		let mut cb = Frontend::new(cfg.clone(), term);
		cb.out.sink = Some(sink);
		h.set_callbacks(Box::new(cb));
		h.set_dbext(&self.dbext);
		for (r, list) in FRONT_REPOS.iter().zip(&self.servers) {
			let db = h.register_syncdb(r.as_bytes(), 0).unwrap();
			for s in list {
				db.add_server(&mut (), s).unwrap();
			}
		}
		h
	}

	// one op on fresh handles over the two roots
	fn run(&self, srv: &Server, cfg: &Config, files: bool) -> CRun {
		self.run_cols(srv, cfg, files, 0)
	}

	fn run_cols(
		&self,
		srv: &Server,
		cfg: &Config,
		files: bool,
		cols: u16,
	) -> CRun {
		// both sides' db updates set the umask
		let _umask = umask_lock();
		srv.reset();
		FRONT_COLS.store(cols, Ordering::SeqCst);
		let c = {
			let fh = front_handle(
				&self.cfx,
				&self.dbext,
				&FRONT_REPOS,
				&self.servers,
			);
			let none: [&[u8]; 0] = [];
			match files {
				true => c_pacman_files_refresh(
					&fh, cfg, &none, cols,
				),
				false => c_pacman_sync_refresh(
					&fh, cfg, &none, cols,
				),
			}
		};
		let creq = requests(&[srv]);
		let mut h = self.rust_handle(cfg);
		let mut out = Output {
			sink: Some(sink),
			..Output::default()
		};
		let none: [&[u8]; 0] = [];
		let ret = match files {
			true => pacman_files(cfg, &mut h, &none, &mut out),
			false => pacman_sync(cfg, &mut h, &none, 0, &mut out)
				.unwrap(),
		};
		out.flush();
		drop(h);
		let all = SINK.with(|s| std::mem::take(&mut *s.borrow_mut()));
		let r = CRun {
			ret,
			stdout: all.stdout,
			stderr: all.stderr,
		};
		let rreq = requests(&[srv]);
		if let Some(d) = c.diff(&r) {
			panic!(
				"{d}\nconfig -y{} list {}",
				cfg.op_s_sync, cfg.op_q_list
			);
		}
		assert_eq!(creq, rreq);
		let cs = snapshot(&self.cfx.dir().join("db/sync"));
		assert_eq!(cs, snapshot(&self.rfx.dir().join("db/sync")));
		c
	}
}

fn front_cfg(level: u16, color: bool) -> Config {
	let mut cfg = Config::new();
	cfg.op_s_sync = level;
	if color {
		cfg.colstr = ColStr::COLOR;
	}
	cfg
}

#[test]
fn frontend() {
	let srv = Server::start();
	let (m1, m2) = (srv.url("/m1"), srv.url("/m2"));
	let both = vec![m1.clone(), m2.clone()];
	let (core0, _) = sync_db(41, false);
	let (extra0, _) = sync_db(42, false);
	srv.route("/m1/core.db", vec![file(&core0, T0)]);
	srv.route("/m1/extra.db", vec![file(&extra0, T0)]);
	let f = Front::new(b".db", vec![both.clone(), both.clone()]);
	for color in [false, true] {
		let o = f.run(&srv, &front_cfg(1, color), false);
		assert_eq!(o.ret, 0, "{o:?}");
		let want: &[u8] = match color {
			false => b":: Synchronizing package databases...\n",
			true => {
				b"\x1b[1;34m::\x1b[0;1m Synchronizing package \
				databases...\n\x1b[0m"
			}
		};
		let dl = b" core downloading...\n extra downloading...\n";
		assert_eq!(o.stdout, [want, dl].concat(), "{o:?}");
		f.run(&srv, &front_cfg(1, color), false);
		f.run(&srv, &front_cfg(2, color), false);
	}
	// -Syl: the fresh dbs listed
	let mut cfg = front_cfg(1, false);
	cfg.op_q_list = 1;
	let o = f.run(&srv, &cfg, false);
	assert!(!o.stdout.is_empty());
	// m1 fails core, then every mirror fails extra
	srv.route("/m1/core.db", vec![not_found()]);
	srv.route("/m2/core.db", vec![file(&core0, T0 + DAY)]);
	f.run(&srv, &front_cfg(1, false), false);
	srv.route("/m1/extra.db", vec![not_found()]);
	let o = f.run(&srv, &front_cfg(2, true), false);
	assert_eq!(o.ret, 1);
	// a repo without servers
	let lone = Front::new(b".db", vec![both.clone(), Vec::new()]);
	let o = lone.run(&srv, &front_cfg(1, false), false);
	assert_eq!(o.ret, 1);

	// -Fy on .files dbs
	let (files0, _) = sync_db(43, true);
	srv.route("/m1/core.files", vec![file(&files0, T0)]);
	srv.route("/m1/extra.files", vec![file(&files0, T0)]);
	let ff = Front::new(b".files", vec![both.clone(), both]);
	let o = ff.run(&srv, &front_cfg(1, false), true);
	assert_eq!(o.ret, 0, "{o:?}");
	ff.run(&srv, &front_cfg(2, false), true);
	let mut cfg = front_cfg(1, false);
	cfg.op_q_list = 1;
	ff.run(&srv, &cfg, true);

	// progress bars: one per db, the final line of each, "is up to
	// date" on a second refresh, "failed to download" when every mirror
	// fails
	let (core1, _) = sync_db(44, false);
	srv.route("/m1/core.db", vec![file(&core1, T0)]);
	srv.route("/m1/extra.db", vec![file(&extra0, T0)]);
	let fb = Front::new(b".db", vec![m1s(&srv), m1s(&srv)]);
	for cols in [80, 120, 50] {
		let mut cfg = front_cfg(1, cols == 120);
		cfg.noprogressbar = 0;
		let o = fb.run_cols(&srv, &cfg, false, cols);
		assert!(has(&o.stdout, b" core"), "{o:?}");
		let o = fb.run_cols(&srv, &cfg, false, cols);
		assert!(has(&o.stdout, b"is up to date"), "{o:?}");
		let mut cfg = front_cfg(2, false);
		cfg.noprogressbar = 0;
		fb.run_cols(&srv, &cfg, false, cols);
	}
	srv.route("/m1/extra.db", vec![not_found()]);
	let mut cfg = front_cfg(2, false);
	cfg.noprogressbar = 0;
	let o = fb.run_cols(&srv, &cfg, false, 80);
	assert!(has(&o.stdout, b"failed to download"), "{o:?}");
}

fn m1s(srv: &Server) -> Vec<Vec<u8>> {
	vec![srv.url("/m1")]
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
	hay.windows(needle.len()).any(|w| w == needle)
}
