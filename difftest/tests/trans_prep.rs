// the transaction prepare phase against the C on real handles. each case
// writes a world (local db, three sync dbs, a cache dir with cached and
// partial packages, package files) and runs a few transactions, each on
// fresh handles: random op sequences (init with random flags, adds of
// sync, file and wrong-origin packages, removals, sysupgrade, group
// lookups, prepare, interrupt, release, a held lock), the same on both
// sides. compared per op: return value or pm_errno, prepare's data list,
// log lines, events, questions (sequence and payload, same scripted
// answers), and handle->trans afterwards (flags, state, add with reason,
// db, removes, download size and oldpkg, unresolvable, remove).
//
// the C side runs its whole sequence first (the db lock is shared), then
// the Rust side.
//
// frontend_fuzz runs pacman_sync/pacman_remove/pacman_upgrade against
// sync_trans/pacman_remove/pacman_upgrade on generated worlds, with
// --print or an input that never says yes where the C would commit;
// compared: return value, stdout, stderr, input consumed, and the world
// left as it was.
use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::c_int;
use std::fs;
use std::io::Cursor;
use std::rc::Rc;

use alpm_core::callbacks::{Callbacks, Event, LogLevel, Question};
use alpm_core::db::{
	DB_USAGE_ALL, DB_USAGE_INSTALL, DB_USAGE_SEARCH, DB_USAGE_UPGRADE,
};
use alpm_core::handle::Handle;
use alpm_core::trans::{
	PrepareData, TRANS_FLAG_CASCADE, TRANS_FLAG_DOWNLOADONLY,
	TRANS_FLAG_NEEDED, TRANS_FLAG_NOCONFLICTS, TRANS_FLAG_NODEPS,
	TRANS_FLAG_NODEPVERSION, TRANS_FLAG_NOLOCK, TRANS_FLAG_RECURSE,
	TRANS_FLAG_RECURSEALL, TRANS_FLAG_UNNEEDED, Trans,
};
use alpm_core::{add, remove, sync, trans};
use difftest::{
	CTx, FrontOp, Rng, TP_GROUPS, TP_SYNC, TempRoot, TpAdd, TpAsk, TpCalls,
	TpData, TpEvent, TpId, TpRet, TpSetup, TpView, TpWorld, UNPORTED_DEBUG,
	c_front, gen_world, iters, tp_cachedir, tree_snapshot, utc_date,
	write_world,
};
use pacman_cli::conf::{ColStr, Config, LOG_ERROR, LOG_WARNING};
use pacman_cli::pacman::{PM_OP_REMOVE, PM_OP_SYNC, PM_OP_UPGRADE};
use pacman_cli::util::{Output, Term, Ui};

const USAGES: [c_int; 6] = [
	DB_USAGE_ALL,
	DB_USAGE_ALL,
	DB_USAGE_ALL,
	DB_USAGE_SEARCH,
	DB_USAGE_INSTALL,
	DB_USAGE_UPGRADE,
];
const IGNORE: [&str; 5] = ["a", "c*", "[ef]", "v?", "x"];
const ANSWERS: [c_int; 5] = [0, 1, 1, 2, -1];
const FLAGS: [c_int; 10] = [
	TRANS_FLAG_NODEPS,
	TRANS_FLAG_NODEPVERSION,
	TRANS_FLAG_CASCADE,
	TRANS_FLAG_RECURSE,
	TRANS_FLAG_RECURSEALL,
	TRANS_FLAG_UNNEEDED,
	TRANS_FLAG_NEEDED,
	TRANS_FLAG_DOWNLOADONLY,
	TRANS_FLAG_NOCONFLICTS,
	TRANS_FLAG_NOLOCK,
];

fn cases() -> usize {
	(iters() / 100).max(60)
}

fn pick<T: Clone>(rng: &mut Rng, items: &[T]) -> T {
	items[rng.below(items.len())].clone()
}

fn answers(rng: &mut Rng) -> Vec<c_int> {
	(0..rng.below(6)).map(|_| pick(rng, &ANSWERS)).collect()
}

fn gen_setup(rng: &mut Rng, fx: &TempRoot) -> TpSetup {
	let pats = |r: &mut Rng, items: &[&str]| {
		let mut v = items.to_vec();
		v.retain(|_| r.below(5) == 0);
		v.into_iter().map(|s| s.as_bytes().to_vec()).collect()
	};
	TpSetup {
		ignorepkg: pats(rng, &IGNORE),
		ignoregroup: pats(rng, &TP_GROUPS),
		arches: match rng.below(3) {
			0 => vec![b"x86_64".to_vec()],
			_ => Vec::new(),
		},
		usage: TP_SYNC.iter().map(|_| pick(rng, &USAGES)).collect(),
		cachedir: tp_cachedir(fx),
	}
}

// ---- the Rust side ----

#[derive(Default)]
struct Shared {
	answers: VecDeque<c_int>,
	calls: TpCalls,
}

// the handle's callbacks: scripted answers, same records as the C
struct Script(Rc<RefCell<Shared>>);

fn name(p: &alpm_core::package::Package) -> Vec<u8> {
	p.name.as_deref().unwrap_or_default().to_vec()
}

impl Callbacks for Script {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		// what the C side drops too
		let unported = level == LogLevel::Debug
			&& UNPORTED_DEBUG.iter().any(|p| msg.starts_with(p));
		if level == LogLevel::Function || unported {
			return;
		}
		let mut s = self.0.borrow_mut();
		s.calls.logs.push((level as c_int, msg.to_vec()));
	}

	fn event(&mut self, e: &Event<'_>) {
		let ev = match e {
			Event::OptdepRemoval { pkg, optdep } => {
				TpEvent::OptdepRemoval(
					name(pkg),
					(*optdep).clone(),
				)
			}
			e => TpEvent::Kind(e.kind()),
		};
		self.0.borrow_mut().calls.events.push(ev);
	}

	fn question(&mut self, q: &mut Question<'_>) {
		let asked = match q {
			Question::InstallIgnorepkg { pkg, .. } => {
				TpAsk::InstallIgnorepkg(name(pkg))
			}
			Question::ReplacePkg {
				oldpkg,
				newpkg,
				newdb,
				..
			} => TpAsk::Replace(
				name(oldpkg),
				name(newpkg),
				newdb.name().to_vec(),
			),
			Question::ConflictPkg { conflict, .. } => {
				TpAsk::Conflict(
					name(&conflict.package1),
					name(&conflict.package2),
					conflict.reason.clone(),
				)
			}
			Question::RemovePkgs { packages, .. } => {
				TpAsk::RemovePkgs(
					packages.iter()
						.map(|p| name(p))
						.collect(),
				)
			}
			Question::SelectProvider {
				providers,
				dbs,
				depend,
				..
			} => TpAsk::SelectProvider(
				providers.iter().map(|p| name(p)).collect(),
				dbs.iter().map(|d| d.to_vec()).collect(),
				(*depend).clone(),
			),
			_ => unreachable!("not asked while preparing"),
		};
		let mut s = self.0.borrow_mut();
		s.calls.asked.push(asked);
		if let Some(a) = s.answers.pop_front() {
			q.set_answer(a);
		}
	}
}

fn rust_handle(fx: &TempRoot, setup: &TpSetup) -> Handle {
	let mut h = Handle::initialize(&fx.root(), &fx.dbpath()).unwrap();
	h.set_ignorepkgs(&setup.ignorepkg);
	h.set_ignoregroups(&setup.ignoregroup);
	h.set_architectures(&setup.arches);
	h.add_cachedir(&setup.cachedir);
	for (n, &u) in TP_SYNC.iter().zip(&setup.usage) {
		h.register_syncdb(n.as_bytes(), 0).unwrap().set_usage(u);
	}
	h
}

struct RustTx {
	h: Handle,
	rec: Rc<RefCell<Shared>>,
}

fn errno(e: alpm_core::error::Errno) -> c_int {
	e as c_int
}

impl RustTx {
	fn new(fx: &TempRoot, setup: &TpSetup) -> Self {
		let mut h = rust_handle(fx, setup);
		// the caches loaded before the callbacks, like the C side
		let dbs = h.dbs_mut();
		for db in dbs.local.into_iter().chain(dbs.sync.iter_mut()) {
			let _ = db.pkgcache(dbs.dbext, &mut ());
			let _ = db.groupcache(dbs.dbext, &mut ());
		}
		let rec = Rc::new(RefCell::new(Shared::default()));
		h.set_callbacks(Box::new(Script(rec.clone())));
		RustTx { h, rec }
	}

	fn run<R>(
		&mut self,
		answers: &[c_int],
		f: impl FnOnce(&mut Handle) -> R,
	) -> (R, TpCalls) {
		{
			let mut s = self.rec.borrow_mut();
			s.answers = answers.iter().copied().collect();
			s.calls = TpCalls::default();
		}
		let r = f(&mut self.h);
		(r, std::mem::take(&mut self.rec.borrow_mut().calls))
	}

	fn pkg(
		&mut self,
		db: Option<usize>,
		n: &[u8],
	) -> alpm_core::package::Package {
		let dbs = self.h.dbs_mut();
		let db = match db {
			None => dbs.local.unwrap(),
			Some(i) => &mut dbs.sync[i],
		};
		db.get_pkg(dbs.dbext, dbs.cb, n)
			.expect("fixture package")
			.clone()
	}

	fn view(&self) -> Option<TpView> {
		self.h.trans().map(view_of)
	}
}

fn view_of(t: &Trans) -> TpView {
	TpView {
		flags: t.flags,
		state: t.state as c_int,
		add: t.add
			.iter()
			.map(|a| TpAdd {
				name: name(&a.pkg),
				version: a
					.pkg
					.version
					.as_deref()
					.unwrap_or_default()
					.to_vec(),
				reason: a.pkg.reason as c_int,
				db: a.db,
				removes: a.removes.iter().map(name).collect(),
				download_size: a.pkg.download_size,
				oldpkg: a.oldpkg.as_ref().map(|o| {
					o.version
						.as_deref()
						.unwrap_or_default()
						.to_vec()
				}),
			})
			.collect(),
		unresolvable: t
			.unresolvable
			.iter()
			.map(|u| name(&u.pkg))
			.collect(),
		remove: t
			.remove
			.iter()
			.map(|p| {
				let v = p
					.version
					.as_deref()
					.unwrap_or_default();
				(name(p), v.to_vec(), p.reason as c_int)
			})
			.collect(),
	}
}

fn data_of(d: PrepareData) -> TpData {
	match d {
		PrepareData::None => TpData::None,
		PrepareData::InvalidArch(v) => TpData::Arch(v),
		PrepareData::Missing(v) => TpData::Missing(v),
		PrepareData::Conflicts(v) => {
			TpData::Conflicts(
				v.into_iter()
					.map(|c| {
						let (p1, p2) = (
							c.package1, c.package2,
						);
						(
						p1.name.unwrap_or_default().into_vec(),
						p1.version.unwrap_or_default().into_vec(),
						p2.name.unwrap_or_default().into_vec(),
						p2.version.unwrap_or_default().into_vec(),
						c.reason,
					)
					})
					.collect(),
			)
		}
	}
}

// ---- ops ----

#[derive(Clone, Debug)]
enum Op {
	Init(c_int),
	// init while another process holds the lock file
	InitLocked(c_int),
	AddDb(Option<usize>, Vec<u8>, Vec<c_int>),
	AddFile(usize),
	Remove(Option<usize>, Vec<u8>),
	Sysupgrade(bool, Vec<c_int>),
	Groups(Vec<usize>, Vec<u8>, Vec<c_int>),
	Prepare(Vec<c_int>),
	Interrupt,
	Flags,
	Release,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Out {
	Ret(TpRet),
	File(Result<(), Option<c_int>>),
	Groups(Vec<TpId>),
	Prepare(TpRet, TpData),
	Flags(Result<c_int, c_int>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Step {
	out: Out,
	calls: TpCalls,
	view: Option<TpView>,
}

// the world's packages by db, for picking targets
struct Pools {
	local: Vec<Vec<u8>>,
	sync: Vec<Vec<Vec<u8>>>,
	files: usize,
}

impl Pools {
	fn of(w: &TpWorld, missing: Option<usize>) -> Self {
		let names = |ps: &[difftest::TpPkg]| {
			ps.iter().map(|p| p.name.as_bytes().to_vec()).collect()
		};
		let mut sync: Vec<Vec<Vec<u8>>> =
			w.sync.iter().map(|s| names(s)).collect();
		if let Some(m) = missing {
			sync[m].clear();
		}
		Pools {
			local: names(&w.local),
			sync,
			files: w.files.len(),
		}
	}

	fn sync_target(&self, rng: &mut Rng) -> Option<(usize, Vec<u8>)> {
		let dbs: Vec<usize> = (0..self.sync.len())
			.filter(|&i| !self.sync[i].is_empty())
			.collect();
		if dbs.is_empty() {
			return None;
		}
		let db = pick(rng, &dbs);
		Some((db, pick(rng, &self.sync[db])))
	}
}

fn gen_flags(rng: &mut Rng) -> c_int {
	let mut f = 0;
	for flag in FLAGS {
		if rng.below(5) == 0 {
			f |= flag;
		}
	}
	f
}

fn gen_ops(rng: &mut Rng, p: &Pools) -> Vec<Op> {
	let mut ops = Vec::new();
	if rng.below(15) == 0 {
		ops.push(Op::Prepare(Vec::new()));
	}
	let kind = rng.below(10);
	let mut flags = gen_flags(rng);
	if (6..9).contains(&kind) {
		// removals: the -Rs/-Rc/-Ru planning
		for (f, odds) in [
			(TRANS_FLAG_RECURSE, 2),
			(TRANS_FLAG_CASCADE, 3),
			(TRANS_FLAG_UNNEEDED, 3),
		] {
			if rng.below(odds) == 0 {
				flags |= f;
			}
		}
	}
	ops.push(match rng.below(15) {
		0 => Op::InitLocked(flags),
		_ => Op::Init(flags),
	});
	if rng.below(12) == 0 {
		ops.push(Op::Init(flags));
	}
	if rng.below(6) == 0 {
		ops.push(Op::Flags);
	}
	let n = rng.below(5);
	for _ in 0..n {
		let op = match (kind, rng.below(12)) {
			(_, 0) if !p.local.is_empty() => {
				Op::AddDb(None, pick(rng, &p.local), Vec::new())
			}
			(_, 1) => match p.sync_target(rng) {
				Some((db, n)) => Op::Remove(Some(db), n),
				None => continue,
			},
			(0..4, _) => match p.sync_target(rng) {
				Some((db, n)) => {
					Op::AddDb(Some(db), n, answers(rng))
				}
				None => continue,
			},
			(4..6, _) if p.files > 0 => {
				Op::AddFile(rng.below(p.files))
			}
			(6..9, _) if !p.local.is_empty() => {
				Op::Remove(None, pick(rng, &p.local))
			}
			_ => match p.sync_target(rng) {
				Some((db, n)) => {
					Op::AddDb(Some(db), n, answers(rng))
				}
				None => continue,
			},
		};
		ops.push(op);
	}
	if kind < 4 && rng.below(2) == 0 {
		ops.push(Op::Sysupgrade(rng.below(2) == 0, answers(rng)));
	}
	if rng.below(5) == 0 {
		let mut dbs: Vec<usize> = (0..TP_SYNC.len()).collect();
		dbs.retain(|_| rng.below(3) != 0);
		let g = pick(rng, &TP_GROUPS).as_bytes().to_vec();
		ops.push(Op::Groups(dbs, g, answers(rng)));
	}
	ops.push(Op::Prepare(answers(rng)));
	match rng.below(8) {
		0 => ops.push(Op::Prepare(answers(rng))),
		1 => ops.push(Op::Interrupt),
		2 => {
			if let Some((db, n)) = p.sync_target(rng) {
				ops.push(Op::AddDb(Some(db), n, Vec::new()));
			}
		}
		_ => {}
	}
	ops.push(Op::Release);
	if rng.below(8) == 0 {
		ops.push(Op::Release);
	}
	ops
}

// the lock file the db lock creates, taken by "another process"
fn lockfile(fx: &TempRoot) -> std::path::PathBuf {
	fx.dir().join("db/db.lck")
}

fn run_c(
	c: &CTx,
	fx: &TempRoot,
	paths: &[Vec<u8>],
	op: &Op,
) -> (Out, TpCalls, usize) {
	let mut stale = 0;
	let (out, calls) = match op {
		Op::Init(f) => {
			let (r, c) = c.init(*f);
			(Out::Ret(r), c)
		}
		Op::InitLocked(f) => {
			fs::write(lockfile(fx), b"").unwrap();
			let (r, c) = c.init(*f);
			fs::remove_file(lockfile(fx)).unwrap();
			(Out::Ret(r), c)
		}
		Op::AddDb(db, n, a) => {
			let (r, c) = c.add_db(*db, n, a);
			(Out::Ret(r), c)
		}
		Op::AddFile(i) => {
			let (r, c) = c.add_file(&paths[*i]);
			(Out::File(r), c)
		}
		Op::Remove(db, n) => {
			let (r, c) = c.remove(*db, n);
			(Out::Ret(r), c)
		}
		Op::Sysupgrade(d, a) => {
			let (r, c) = c.sysupgrade(*d, a);
			(Out::Ret(r), c)
		}
		Op::Groups(dbs, g, a) => {
			let (r, c) = c.group_pkgs(dbs, g, a);
			(Out::Groups(r), c)
		}
		Op::Prepare(a) => {
			let ((r, d, s), c) = c.prepare(a);
			stale = s;
			(Out::Prepare(r, d), c)
		}
		Op::Interrupt => (Out::Ret(c.interrupt()), TpCalls::default()),
		Op::Flags => (Out::Flags(c.flags()), TpCalls::default()),
		Op::Release => {
			let (r, c) = c.release();
			(Out::Ret(r), c)
		}
	};
	(out, calls, stale)
}

fn run_rust(
	r: &mut RustTx,
	fx: &TempRoot,
	paths: &[Vec<u8>],
	op: &Op,
) -> (Out, TpCalls) {
	match op {
		Op::Init(f) => {
			let (x, c) = r.run(&[], |h| trans::trans_init(h, *f));
			(Out::Ret(x.map_err(|e| errno(e.errno()))), c)
		}
		Op::InitLocked(f) => {
			fs::write(lockfile(fx), b"").unwrap();
			let (x, c) = r.run(&[], |h| trans::trans_init(h, *f));
			fs::remove_file(lockfile(fx)).unwrap();
			(Out::Ret(x.map_err(|e| errno(e.errno()))), c)
		}
		Op::AddDb(db, n, a) => {
			let pkg = r.pkg(*db, n);
			let (x, c) = r.run(a, |h| add::add_pkg(h, pkg, *db));
			(Out::Ret(x.map_err(errno)), c)
		}
		Op::AddFile(i) => {
			let Ok(pkg) = alpm_core::be_package::pkg_load(
				&paths[*i], true,
			) else {
				return (
					Out::File(Err(None)),
					TpCalls::default(),
				);
			};
			let (x, c) = r.run(&[], |h| add::add_pkg(h, pkg, None));
			(Out::File(x.map_err(|e| Some(errno(e)))), c)
		}
		Op::Remove(db, n) => {
			let pkg = r.pkg(*db, n);
			let (x, c) =
				r.run(&[], |h| remove::remove_pkg(h, &pkg));
			(Out::Ret(x.map_err(errno)), c)
		}
		Op::Sysupgrade(d, a) => {
			let (x, c) = r.run(a, |h| sync::sync_sysupgrade(h, *d));
			(Out::Ret(x.map_err(errno)), c)
		}
		Op::Groups(dbs, g, a) => {
			let (x, c) =
				r.run(a, |h| sync::find_group_pkgs(h, dbs, g));
			let ids = x
				.into_iter()
				.map(|t| (t.db, name(&t.pkg)))
				.collect();
			(Out::Groups(ids), c)
		}
		Op::Prepare(a) => {
			let (x, c) = r.run(a, trans::trans_prepare);
			let out = match x {
				Ok(()) => Out::Prepare(Ok(()), TpData::None),
				Err(e) => Out::Prepare(
					Err(errno(e.errno)),
					data_of(e.data),
				),
			};
			(out, c)
		}
		Op::Interrupt => {
			let x = trans::trans_interrupt(&mut r.h);
			(Out::Ret(x.map_err(errno)), TpCalls::default())
		}
		Op::Flags => {
			let x = trans::trans_get_flags(&r.h).map_err(errno);
			(Out::Flags(x), TpCalls::default())
		}
		Op::Release => {
			let (x, c) = r.run(&[], trans::trans_release);
			(Out::Ret(x.map_err(errno)), c)
		}
	}
}

#[derive(Default, Debug)]
struct Seen {
	prepared: usize,
	targets: usize,
	removals: usize,
	unsatisfied: usize,
	conflicting: usize,
	inner_dropped: usize,
	outer_asked: usize,
	elected: usize,
	replace_asked: usize,
	replaced: usize,
	ignore_asked: usize,
	provider_asked: usize,
	skip_asked: usize,
	pulled: usize,
	cascaded: usize,
	recursed: usize,
	unneeded: usize,
	needed_skip: usize,
	downgrades: usize,
	invalid_arch: usize,
	dup_filename: usize,
	dl_partial: usize,
	cached: usize,
	optdep_events: usize,
	state_errors: usize,
	lock_failed: usize,
	db_missing: usize,
	groups: usize,
	stale: usize,
}

fn observe(seen: &mut Seen, op: &Op, s: &Step) {
	let logs = |needle: &[u8]| {
		s.calls.logs.iter().any(|(_, m)| {
			m.windows(needle.len()).any(|w| w == needle)
		})
	};
	let asked = |f: fn(&TpAsk) -> bool| s.calls.asked.iter().any(f);
	seen.outer_asked +=
		usize::from(asked(|a| matches!(a, TpAsk::Conflict(..))));
	seen.replace_asked +=
		usize::from(asked(|a| matches!(a, TpAsk::Replace(..))));
	seen.ignore_asked += usize::from(asked(|a| {
		matches!(a, TpAsk::InstallIgnorepkg(..))
	}));
	seen.provider_asked +=
		usize::from(asked(|a| matches!(a, TpAsk::SelectProvider(..))));
	seen.skip_asked +=
		usize::from(asked(|a| matches!(a, TpAsk::RemovePkgs(..))));
	seen.inner_dropped += usize::from(logs(b"from target list because"));
	seen.elected += usize::from(logs(b"for removal\n"));
	seen.replaced += usize::from(logs(b"to the removes list of"))
		+ usize::from(
			logs(b"adding package")
				&& asked(|a| matches!(a, TpAsk::Replace(..))),
		);
	seen.pulled += usize::from(logs(b"pulling dependency"));
	seen.cascaded += usize::from(logs(b" in target list\n"));
	seen.recursed += usize::from(
		logs(b"to the targets\n") && matches!(op, Op::Prepare(_)),
	);
	seen.unneeded += usize::from(logs(b"from target list\n"));
	seen.needed_skip += usize::from(logs(b"is up to date -- skipping"));
	seen.downgrades += usize::from(logs(b"downgrading from version"));
	seen.dl_partial += usize::from(logs(b"using (package - .part) size"));
	seen.cached += usize::from(logs(b"found cached pkg"));
	seen.optdep_events += usize::from(
		s.calls.events
			.iter()
			.any(|e| matches!(e, TpEvent::OptdepRemoval(..))),
	);
	let err = |e: alpm_core::error::Errno| e as c_int;
	use alpm_core::error::Errno;
	match &s.out {
		Out::Prepare(Ok(()), _) => {
			seen.prepared += 1;
			if let Some(v) = &s.view {
				seen.targets += usize::from(!v.add.is_empty());
				seen.removals +=
					usize::from(!v.remove.is_empty());
			}
		}
		Out::Prepare(Err(e), _)
			if *e == err(Errno::UnsatisfiedDeps) =>
		{
			seen.unsatisfied += 1;
		}
		Out::Prepare(Err(e), _)
			if *e == err(Errno::ConflictingDeps) =>
		{
			seen.conflicting += 1;
		}
		Out::Prepare(Err(e), _) if *e == err(Errno::PkgInvalidArch) => {
			seen.invalid_arch += 1;
		}
		Out::Prepare(Err(e), _)
			if *e == err(Errno::TransDupFilename) =>
		{
			seen.dup_filename += 1;
		}
		Out::Prepare(Err(e), _) if *e == err(Errno::DbNotFound) => {
			seen.db_missing += 1;
		}
		Out::Ret(Err(e)) | Out::Prepare(Err(e), _)
			if [
				err(Errno::TransNull),
				err(Errno::TransNotInitialized),
				err(Errno::TransNotNull),
				err(Errno::TransType),
			]
			.contains(e) =>
		{
			seen.state_errors += 1;
		}
		Out::Ret(Err(e)) if *e == err(Errno::HandleLock) => {
			seen.lock_failed += 1;
		}
		Out::Groups(g) => seen.groups += usize::from(!g.is_empty()),
		_ => {}
	}
}

// calls with readable log lines
fn show(c: &TpCalls) -> String {
	let mut s = String::new();
	for (level, m) in &c.logs {
		s += &format!("  {level} {:?}\n", String::from_utf8_lossy(m));
	}
	s + &format!("  events {:?}\n  asked {:?}\n", c.events, c.asked)
}

#[test]
fn prepare_fuzz() {
	let mut rng = Rng::new(0x7a45);
	let n = cases();
	let mut seen = Seen::default();
	for _ in 0..n {
		let fx = TempRoot::new("transprep");
		let world = gen_world(&mut rng, false);
		let paths = write_world(&fx, &world, &mut rng);
		let missing =
			(rng.below(8) == 0).then(|| rng.below(TP_SYNC.len()));
		if let Some(m) = missing {
			fs::remove_file(fx.sync_file(TP_SYNC[m], ".db"))
				.unwrap();
		}
		let pools = Pools::of(&world, missing);
		let setup = gen_setup(&mut rng, &fx);
		for _ in 0..3 {
			let ops = gen_ops(&mut rng, &pools);
			let c = CTx::new(&fx, &setup, true);
			let mut csteps = Vec::new();
			for op in &ops {
				let (out, calls, stale) =
					run_c(&c, &fx, &paths, op);
				seen.stale += usize::from(stale > 0);
				csteps.push(Step {
					out,
					calls,
					view: c.view(),
				});
			}
			drop(c);
			let mut r = RustTx::new(&fx, &setup);
			for (op, cs) in ops.iter().zip(&csteps) {
				let (out, calls) =
					run_rust(&mut r, &fx, &paths, op);
				let rs = Step {
					out,
					calls,
					view: r.view(),
				};
				let what = (&ops, &setup, &world);
				assert_eq!(
					cs.out, rs.out,
					"result of {op:?}\n{what:#?}"
				);
				assert!(
					cs.calls == rs.calls,
					"calls of {op:?}\nC:\n{}Rust:\n{}{what:#?}",
					show(&cs.calls),
					show(&rs.calls)
				);
				assert_eq!(
					cs.view, rs.view,
					"trans after {op:?}\n{what:#?}"
				);
				observe(&mut seen, op, &rs);
			}
		}
	}
	eprintln!("{n} cases: {seen:#?}");
	let s = &seen;
	let counts = [
		s.prepared,
		s.targets,
		s.removals,
		s.unsatisfied,
		s.conflicting,
		s.inner_dropped,
		s.outer_asked,
		s.elected,
		s.replace_asked,
		s.replaced,
		s.ignore_asked,
		s.provider_asked,
		s.skip_asked,
		s.pulled,
		s.cascaded,
		s.recursed,
		s.unneeded,
		s.needed_skip,
		s.downgrades,
		s.invalid_arch,
		s.dup_filename,
		s.dl_partial,
		s.cached,
		s.optdep_events,
		s.state_errors,
		s.lock_failed,
		s.db_missing,
		s.groups,
	];
	assert!(counts.iter().all(|&k| k >= n / 80), "{n} cases: {seen:#?}");
}

// ---- frontend ----

fn front_config(rng: &mut Rng, op: FrontOp) -> Config {
	let mut cfg = Config::new();
	if rng.below(3) == 0 {
		cfg.colstr = ColStr::COLOR;
	}
	cfg.logmask = match rng.below(6) {
		0 => LOG_ERROR,
		_ => LOG_ERROR | LOG_WARNING,
	};
	cfg.op = match op {
		FrontOp::Sync => PM_OP_SYNC,
		FrontOp::Remove => PM_OP_REMOVE,
		FrontOp::Upgrade => PM_OP_UPGRADE,
	};
	let allowed: &[c_int] = match op {
		FrontOp::Remove => &[
			TRANS_FLAG_NODEPS,
			TRANS_FLAG_CASCADE,
			TRANS_FLAG_RECURSE,
			TRANS_FLAG_RECURSEALL,
			TRANS_FLAG_UNNEEDED,
			TRANS_FLAG_NOLOCK,
		],
		_ => &[
			TRANS_FLAG_NODEPS,
			TRANS_FLAG_NEEDED,
			TRANS_FLAG_DOWNLOADONLY,
			TRANS_FLAG_NOCONFLICTS,
			TRANS_FLAG_NOLOCK,
		],
	};
	for &f in allowed {
		if rng.below(5) == 0 {
			cfg.flags |= f;
		}
	}
	cfg.op_s_downloadonly =
		u16::from(cfg.flags & TRANS_FLAG_DOWNLOADONLY != 0);
	cfg.print = u16::from(rng.below(3) == 0);
	// a yes to the last question would commit: only with --print
	cfg.noconfirm = u16::from(cfg.print != 0 && rng.below(2) == 0);
	cfg.print_format = match rng.below(3) {
		0 => Some(b"%n %v %r %s %l %D".to_vec()),
		_ => None,
	};
	cfg.verbosepkglists = u16::from(rng.below(2) == 0);
	if op == FrontOp::Sync {
		cfg.op_s_upgrade = pick(rng, &[0, 0, 1, 2]);
	}
	if op == FrontOp::Remove && rng.below(3) == 0 {
		cfg.holdpkg =
			vec![pick(rng, &[&b"a"[..], b"[b-d]", b"*"]).to_vec()];
	}
	cfg
}

fn front_targets(
	rng: &mut Rng,
	op: FrontOp,
	w: &TpWorld,
	paths: &[Vec<u8>],
) -> Vec<Vec<u8>> {
	let local: Vec<&str> = w.local.iter().map(|p| p.name).collect();
	let sync: Vec<&str> = w.sync.iter().flatten().map(|p| p.name).collect();
	let n = match rng.below(5) {
		0 => 0,
		_ => 1 + rng.below(3),
	};
	(0..n).map(|_| {
		let t = match (op, rng.below(10)) {
			(_, 0) => pick(rng, &TP_GROUPS).to_string(),
			(_, 1) => "zz".to_string(),
			(FrontOp::Sync, 2) => format!(
				"{}/{}",
				pick(rng, &TP_SYNC),
				pick(rng, &["a", "b", "c", "d"])
			),
			(FrontOp::Sync, 3) => "nodb/a".to_string(),
			(FrontOp::Sync, 4) if !paths.is_empty() => {
				return pick(rng, paths);
			}
			(FrontOp::Sync, 5) => {
				pick(rng, &["v1", "v2", "libx"]).to_string()
			}
			(FrontOp::Sync, _) if !sync.is_empty() => {
				pick(rng, &sync).to_string()
			}
			(FrontOp::Remove, 2) if !local.is_empty() => {
				format!("local/{}", pick(rng, &local))
			}
			(FrontOp::Remove, _) if !local.is_empty() => {
				pick(rng, &local).to_string()
			}
			(FrontOp::Upgrade, 2) => {
				"/nonexistent.pkg.tar.gz".to_string()
			}
			(FrontOp::Upgrade, _) if !paths.is_empty() => {
				return pick(rng, paths);
			}
			_ => "a".to_string(),
		};
		t.into_bytes()
	})
	.collect()
}

// answers that never say yes (or default to it): multiselect picks and
// noes
fn front_input(rng: &mut Rng) -> Vec<u8> {
	let lines = ["1", "2", "1-2", "^1", "n", "x", "3", "no"];
	let mut s = String::new();
	for _ in 0..rng.below(4) {
		s.push_str(pick(rng, &lines));
		s.push('\n');
	}
	s.into_bytes()
}

fn rust_front(
	op: FrontOp,
	h: &mut Handle,
	cfg: &Config,
	targets: &[Vec<u8>],
	cols: u16,
	input: &[u8],
) -> (i32, Output, usize) {
	let mut out = Output::default();
	let mut term = Term::new(Cursor::new(input.to_vec()), false, false);
	let r = {
		let mut ui = Ui {
			config: cfg,
			term: &mut term,
			cols,
			out: &mut out,
			format_date: &utc_date,
			explicit_adds: Vec::new(),
			explicit_removes: Vec::new(),
		};
		match op {
			FrontOp::Sync => {
				let pre = pacman_cli::sync::pacman_sync(
					cfg, h, targets, cols, ui.out,
				);
				match pre {
					Ok(ret) => ret,
					Err(_) => pacman_cli::sync::sync_trans(
						&mut ui, h, targets,
					),
				}
			}
			FrontOp::Remove => pacman_cli::remove::pacman_remove(
				&mut ui, h, targets,
			),
			FrontOp::Upgrade => {
				pacman_cli::upgrade::pacman_upgrade(
					&mut ui, h, targets,
				)
			}
		}
	};
	(r, out, term.stdin.position() as usize)
}

#[derive(Default, Debug)]
struct FrontSeen {
	runs: usize,
	failed: usize,
	listed: usize,
	printed: usize,
	broken: usize,
	in_conflict: usize,
	group_menu: usize,
	declined: usize,
	nothing: usize,
}

#[test]
fn frontend_fuzz() {
	let mut rng = Rng::new(0xf20e);
	let n = (iters() / 1000).max(40);
	let mut seen = FrontSeen::default();
	for _ in 0..n {
		let fx = TempRoot::new("transfront");
		let world = gen_world(&mut rng, true);
		let paths = write_world(&fx, &world, &mut rng);
		let setup = TpSetup {
			arches: match rng.below(4) {
				0 => vec![b"x86_64".to_vec()],
				_ => Vec::new(),
			},
			usage: vec![DB_USAGE_ALL; TP_SYNC.len()],
			cachedir: tp_cachedir(&fx),
			..TpSetup::default()
		};
		for _ in 0..4 {
			let op = pick(
				&mut rng,
				&[
					FrontOp::Sync,
					FrontOp::Remove,
					FrontOp::Upgrade,
				],
			);
			let cfg = front_config(&mut rng, op);
			let targets =
				front_targets(&mut rng, op, &world, &paths);
			let input = front_input(&mut rng);
			let cols = pick(&mut rng, &[0, 80, 200]);
			let before = tree_snapshot(fx.dir());
			let tx = CTx::new(&fx, &setup, false);
			let (cret, cio) =
				c_front(op, &tx, &cfg, &targets, cols, &input);
			drop(tx);
			assert_eq!(
				before,
				tree_snapshot(fx.dir()),
				"the C changed the world: {op:?} {targets:?}"
			);
			let mut h = rust_handle(&fx, &setup);
			let (r, out, consumed) = rust_front(
				op, &mut h, &cfg, &targets, cols, &input,
			);
			drop(h);
			let what = (
				op,
				&targets,
				String::from_utf8_lossy(&input),
				&cfg.flags,
				cfg.print,
				cfg.op_s_upgrade,
				&world,
			);
			assert_eq!(
				cret,
				r,
				"ret {what:#?}\n{}",
				String::from_utf8_lossy(&cio.out.stderr)
			);
			assert_eq!(
				String::from_utf8_lossy(&cio.out.stdout),
				String::from_utf8_lossy(&out.stdout),
				"stdout {what:#?}"
			);
			assert_eq!(
				String::from_utf8_lossy(&cio.out.stderr),
				String::from_utf8_lossy(&out.stderr),
				"stderr {what:#?}"
			);
			assert_eq!(
				cio.consumed, consumed,
				"input read {what:#?}"
			);
			let has = |s: &[u8], n: &[u8]| {
				s.windows(n.len()).any(|w| w == n)
			};
			let (o, e) = (&out.stdout, &out.stderr);
			seen.runs += 1;
			seen.failed +=
				usize::from(has(e, b"failed to prepare"));
			seen.listed += usize::from(has(o, b"Packages ("));
			seen.printed += usize::from(
				cfg.print != 0 && cret == 0 && !o.is_empty(),
			);
			seen.broken += usize::from(
				has(o, b"breaks dependency")
					|| has(o, b"unable to satisfy"),
			);
			seen.in_conflict +=
				usize::from(has(o, b"are in conflict"));
			seen.group_menu += usize::from(has(o, b"in group"));
			seen.declined += usize::from(
				has(e, b"Proceed with")
					|| has(e, b"remove these packages"),
			);
			seen.nothing +=
				usize::from(has(o, b"there is nothing to do"));
		}
	}
	eprintln!("{n} cases: {seen:#?}");
	let s = &seen;
	let counts = [
		s.failed,
		s.listed,
		s.printed,
		s.broken,
		s.in_conflict,
		s.group_menu,
		s.declined,
		s.nothing,
	];
	assert!(counts.iter().all(|&k| k >= n / 20), "{n} cases: {seen:#?}");
}
