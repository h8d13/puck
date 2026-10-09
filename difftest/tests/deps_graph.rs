// alpm_core::deps::{checkdeps, sortbydeps, find_dbs_satisfier,
// resolvedeps, recursedeps} against the C on real handles. each case
// writes a trans_prep world (gen_world: a local db and three sync dbs
// over a small name set, so dependency cycles, several providers and
// name clashes between dbs are common), sets ignore lists,
// assumeinstalled, NODEPVERSION and db usage on both handles, then runs
// random calls. compared: results in
// order, missing-dep lists, questions asked (sequence and payload) with
// the same scripted answers, log lines (level and text).
//
// the C db backends log lazy loads at ALPM_LOG_FUNCTION, deps.c never
// does: those lines are dropped from the C side.
use std::collections::VecDeque;
use std::ffi::c_int;
use std::ptr;

use alpm_core::be_local::INFRQ_DESC;
use alpm_core::callbacks::{Callbacks, LogLevel, Question};
use alpm_core::db::{
	DB_USAGE_ALL, DB_USAGE_INSTALL, DB_USAGE_SEARCH, DB_USAGE_UPGRADE,
};
use alpm_core::deps::{
	DbPkgs, DepMissing, DepsEnv, checkdeps, dep_from_string,
	find_dbs_satisfier, recursedeps, resolvedeps, sortbydeps,
};
use alpm_core::error::Errno;
use alpm_core::handle::Handle;
use alpm_core::package::Package;
use alpm_core::pkghash::PkgHash;
use difftest::{
	Asked, CGraph, Calls, LOG_FUNCTION, PkgId, Rng, Setup, TP_DEP_VERSIONS,
	TP_GROUPS, TP_SYNC, TP_VIRTUAL, TempRoot, TpWorld, gen_world, iters,
	tp_any_name, tp_relation, write_world,
};

const IGNORE: [&str; 5] = ["a", "c*", "[ef]", "v?", "x"];
const USAGES: [c_int; 7] = [
	DB_USAGE_ALL,
	DB_USAGE_ALL,
	DB_USAGE_ALL,
	0,
	DB_USAGE_SEARCH,
	DB_USAGE_INSTALL,
	DB_USAGE_UPGRADE,
];
// install answers and provider indexes, some out of range
const ANSWERS: [c_int; 6] = [0, 1, 2, -1, 3, 0];

// one fixture per case, many calls each
fn cases() -> usize {
	(iters() / 200).max(40)
}

fn pick<T: Copy>(rng: &mut Rng, items: &[T]) -> T {
	items[rng.below(items.len())]
}

fn some<T>(rng: &mut Rng, n: usize, f: impl Fn(&mut Rng) -> T) -> Vec<T> {
	(0..rng.below(n)).map(|_| f(rng)).collect()
}

// a trans_prep world (odd relations included) with some ">=ver"
// provisions (those match no versioned dep)
fn gen_deps_world(rng: &mut Rng) -> TpWorld {
	let mut w = gen_world(rng, false);
	let all = w.local.iter_mut().chain(w.sync.iter_mut().flatten());
	for p in all.chain(w.files.iter_mut()) {
		if rng.below(5) == 0 {
			let ver = pick(rng, &TP_DEP_VERSIONS);
			let name = tp_any_name(rng);
			p.provides.push(format!("{name}>={ver}"));
		}
	}
	w
}

fn gen_setup(rng: &mut Rng) -> Setup {
	let pats = |r: &mut Rng, items: &[&str]| {
		let mut v = items.to_vec();
		v.retain(|_| r.below(4) == 0);
		v.into_iter().map(|s| s.as_bytes().to_vec()).collect()
	};
	Setup {
		ignorepkg: pats(rng, &IGNORE),
		ignoregroup: pats(rng, &TP_GROUPS),
		assumeinstalled: some(rng, 3, |r| {
			let name = tp_any_name(r);
			let s = match r.below(2) {
				0 => name.to_string(),
				_ => format!(
					"{name}={}",
					pick(r, &TP_DEP_VERSIONS)
				),
			};
			dep_from_string(s.as_bytes())
		}),
		nodepversion: rng.below(4) == 0,
		local_usage: match rng.below(6) {
			0 => DB_USAGE_SEARCH,
			_ => DB_USAGE_ALL,
		},
		usage: TP_SYNC.iter().map(|_| pick(rng, &USAGES)).collect(),
	}
}

// the Rust handle of a fixture, caches loaded, local entries lazy-loaded
struct RustSide {
	handle: Handle,
}

impl RustSide {
	fn new(fx: &TempRoot, setup: &Setup) -> Self {
		let mut handle =
			Handle::initialize(&fx.root(), &fx.dbpath()).unwrap();
		for name in TP_SYNC {
			handle.register_syncdb(name.as_bytes(), 0).unwrap();
		}
		handle.set_ignorepkgs(&setup.ignorepkg);
		handle.set_ignoregroups(&setup.ignoregroup);
		handle.set_assumeinstalled(&setup.assumeinstalled).unwrap();
		let dbext = handle.dbext().to_vec();
		let db = handle.localdb_mut().unwrap();
		let names: Vec<Vec<u8>> = db
			.pkgcache(&dbext, &mut ())
			.unwrap()
			.iter()
			.map(|p| p.name_bytes().to_vec())
			.collect();
		for n in &names {
			db.load_pkg(&dbext, &mut (), n, INFRQ_DESC).unwrap();
		}
		for d in handle.syncdbs_mut() {
			d.pkgcache(&dbext, &mut ()).unwrap();
		}
		RustSide { handle }
	}

	fn local(&self) -> &PkgHash<Package> {
		let db = self.handle.localdb().unwrap();
		db.loaded_pkgcache().expect("loaded")
	}

	fn sync(&self) -> Vec<&PkgHash<Package>> {
		let dbs = self.handle.syncdbs().iter();
		dbs.map(|d| d.loaded_pkgcache().expect("loaded")).collect()
	}

	fn cache(&self, db: Option<usize>) -> &PkgHash<Package> {
		db.map_or(self.local(), |i| self.sync()[i])
	}

	fn get(&self, id: &PkgId) -> &Package {
		self.cache(id.0).find(&id.1).expect("fixture id")
	}

	fn id(&self, p: &Package) -> PkgId {
		let dbs = std::iter::once(None)
			.chain((0..TP_SYNC.len()).map(Some));
		for db in dbs {
			if self.cache(db).iter().any(|q| ptr::eq(q, p)) {
				return (db, p.name_bytes().to_vec());
			}
		}
		panic!("package outside the caches: {p:?}")
	}

	fn ids(&self, db: Option<usize>) -> Vec<PkgId> {
		let c = self.cache(db).iter();
		c.map(|p| (db, p.name_bytes().to_vec())).collect()
	}
}

// the Rust callbacks: same scripted answers, same records as the C
struct Script<'r> {
	rs: &'r RustSide,
	answers: VecDeque<c_int>,
	calls: Calls,
}

impl<'r> Script<'r> {
	fn new(rs: &'r RustSide, answers: &[c_int]) -> Self {
		Script {
			rs,
			answers: answers.iter().copied().collect(),
			calls: Calls::default(),
		}
	}
}

impl Callbacks for Script<'_> {
	fn question(&mut self, q: &mut Question<'_>) {
		let answer = self.answers.pop_front();
		match q {
			Question::InstallIgnorepkg { install, pkg } => {
				let a = Asked::InstallIgnorepkg(
					self.rs.id(pkg),
				);
				self.calls.asked.push(a);
				if let Some(a) = answer {
					*install = a;
				}
			}
			Question::SelectProvider {
				use_index,
				providers,
				dbs,
				depend,
			} => {
				let ids: Vec<PkgId> = providers
					.iter()
					.map(|p| self.rs.id(p))
					.collect();
				// each provider names the db it was found in
				let want: Vec<&[u8]> =
					ids.iter()
						.map(|id| match id.0 {
							None => &b"local"[..],
							Some(i) => TP_SYNC[i]
								.as_bytes(),
						})
						.collect();
				assert_eq!(*dbs, &want[..], "provider dbs");
				let a = Asked::SelectProvider(
					ids,
					(*depend).clone(),
				);
				self.calls.asked.push(a);
				if let Some(a) = answer {
					*use_index = a;
				}
			}
			_ => unreachable!("deps asks two questions"),
		}
	}

	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		self.calls.logs.push((level as c_int, msg.to_vec()));
	}
}

fn c_calls(mut calls: Calls) -> Calls {
	calls.logs.retain(|(level, _)| *level != LOG_FUNCTION);
	calls
}

// a few ids with replacement from pool
fn pick_ids(rng: &mut Rng, pool: &[PkgId], max: usize) -> Vec<PkgId> {
	if pool.is_empty() {
		return Vec::new();
	}
	some(rng, max, |r| pool[r.below(pool.len())].clone())
}

// a random subset in pool order
fn subset(rng: &mut Rng, pool: &[PkgId]) -> Vec<PkgId> {
	let mut v = pool.to_vec();
	v.retain(|_| rng.below(4) != 0);
	v
}

fn answers(rng: &mut Rng) -> Vec<c_int> {
	some(rng, 5, |r| pick(r, &ANSWERS))
}

#[derive(Default, Debug)]
struct Seen {
	missing: usize,
	broken: usize,
	nodepversion_missing: usize,
	reordered: usize,
	cycles: usize,
	found: usize,
	not_found: usize,
	ignored: usize,
	ignore_asked: usize,
	provider_asked: usize,
	provider_none: usize,
	resolved: usize,
	pulled: usize,
	unresolved: usize,
	removed: usize,
	removed_explicit: usize,
}

struct Case<'a> {
	c: &'a CGraph,
	rs: &'a RustSide,
	setup: &'a Setup,
	local: Vec<PkgId>,
	sync: Vec<PkgId>,
	all: Vec<PkgId>,
}

impl Case<'_> {
	fn pkgs(&self, ids: &[PkgId]) -> Vec<&Package> {
		ids.iter().map(|id| self.rs.get(id)).collect()
	}

	fn ids(&self, pkgs: &[&Package]) -> Vec<PkgId> {
		pkgs.iter().map(|p| self.rs.id(p)).collect()
	}

	fn with_env<R>(&self, f: impl FnOnce(&DepsEnv) -> R) -> R {
		let dbs: Vec<DbPkgs> =
			self.rs.sync()
				.into_iter()
				.zip(&self.setup.usage)
				.zip(TP_SYNC)
				.map(|((cache, &usage), name)| DbPkgs {
					usage,
					cache,
					name: name.as_bytes(),
				})
				.collect();
		let env = DepsEnv {
			opts: self.rs.handle.deps_opts(),
			nodepversion: self.setup.nodepversion,
			local: DbPkgs {
				usage: self.setup.local_usage,
				cache: self.rs.local(),
				name: b"local",
			},
			sync: &dbs,
		};
		f(&env)
	}

	fn checkdeps(&self, rng: &mut Rng, seen: &mut Seen) {
		let pkglist = match rng.below(3) {
			0 => subset(rng, &self.local),
			_ => self.local.clone(),
		};
		let rem = pick_ids(rng, &self.local, 3);
		let upgrade = pick_ids(rng, &self.all, 4);
		let reversedeps = rng.below(2) == 0;
		let (cr, cc) =
			self.c.checkdeps(&pkglist, &rem, &upgrade, reversedeps);
		let mut s = Script::new(self.rs, &[]);
		let r: Vec<DepMissing> = self.with_env(|env| {
			checkdeps(
				env,
				&self.pkgs(&pkglist),
				&self.pkgs(&rem),
				&self.pkgs(&upgrade),
				reversedeps,
				&mut s,
			)
		});
		let what = (&pkglist, &rem, &upgrade, reversedeps, self.setup);
		assert_eq!(cr, r, "checkdeps {what:?}");
		assert_eq!(c_calls(cc), s.calls, "checkdeps calls {what:?}");
		seen.missing += usize::from(!r.is_empty());
		seen.broken +=
			usize::from(r.iter().any(|m| m.causingpkg.is_some()));
		seen.nodepversion_missing +=
			usize::from(self.setup.nodepversion && !r.is_empty());
	}

	fn sortbydeps(&self, rng: &mut Rng, seen: &mut Seen) {
		let targets = pick_ids(rng, &self.all, 7);
		let ignore = pick_ids(rng, &self.local, 3);
		let reverse = rng.below(2) == 0;
		let (cr, cc) = self.c.sortbydeps(&targets, &ignore, reverse);
		let mut s = Script::new(self.rs, &[]);
		let r = self.with_env(|env| {
			self.ids(&sortbydeps(
				env,
				&self.pkgs(&targets),
				&self.pkgs(&ignore),
				reverse,
				&mut s,
			))
		});
		let what = (&targets, &ignore, reverse);
		assert_eq!(cr, r, "sortbydeps {what:?}");
		assert_eq!(c_calls(cc), s.calls, "sortbydeps calls {what:?}");
		let mut expect = targets.clone();
		if reverse {
			expect.reverse();
		}
		seen.reordered += usize::from(r != expect);
		let cycle = |l: &(c_int, Vec<u8>)| {
			l.1.starts_with(b"dependency cycle")
		};
		seen.cycles += usize::from(s.calls.logs.iter().any(cycle));
	}

	fn find_dbs_satisfier(&self, rng: &mut Rng, seen: &mut Seen) {
		let mut dbs: Vec<Option<usize>> = std::iter::once(None)
			.chain((0..TP_SYNC.len()).map(Some))
			.collect();
		dbs.retain(|d| rng.below(3 + 3 * usize::from(d.is_none())) > 1);
		if rng.below(4) == 0 {
			dbs.reverse();
		}
		// virtual names reach the provider question
		let dep = match rng.below(2) {
			0 => pick(rng, &TP_VIRTUAL).to_string(),
			_ => tp_relation(rng),
		};
		let ans = answers(rng);
		let (cr, cc) =
			self.c.find_dbs_satisfier(&dbs, dep.as_bytes(), &ans);
		let mut s = Script::new(self.rs, &ans);
		let r = self.with_env(|env| {
			let views: Vec<DbPkgs> = dbs
				.iter()
				.map(|&d| match d {
					None => env.local,
					Some(i) => env.sync[i],
				})
				.collect();
			find_dbs_satisfier(env, &views, dep.as_bytes(), &mut s)
				.map(|p| self.rs.id(p))
		});
		let r = r.map_err(|e| e as c_int);
		let what = (&dbs, &dep, &ans, self.setup);
		assert_eq!(cr, r, "find_dbs_satisfier {what:?}");
		let cc = c_calls(cc);
		// RET_ERR logs where the C asserts a non-NULL list
		if !dbs.is_empty() {
			assert_eq!(
				cc, s.calls,
				"find_dbs_satisfier calls {what:?}"
			);
		}
		let a = &s.calls.asked;
		seen.found += usize::from(r.is_ok());
		let err = |e: Errno| Err(e as c_int);
		seen.not_found += usize::from(r == err(Errno::PkgNotFound));
		seen.ignored += usize::from(r == err(Errno::PkgIgnored));
		seen.ignore_asked += a
			.iter()
			.filter(|q| matches!(q, Asked::InstallIgnorepkg(_)))
			.count();
		let provider = a
			.iter()
			.any(|q| matches!(q, Asked::SelectProvider(..)));
		seen.provider_asked += usize::from(provider);
		seen.provider_none += usize::from(provider && r.is_err());
	}

	fn resolvedeps(&self, rng: &mut Rng, seen: &mut Seen) {
		let localpkgs = match rng.below(3) {
			0 => subset(rng, &self.local),
			_ => self.local.clone(),
		};
		// mostly sync targets, like sync.c
		let pool = match (rng.below(5), self.sync.is_empty()) {
			(0, _) | (_, true) => &self.all,
			_ => &self.sync,
		};
		if pool.is_empty() {
			return;
		}
		let pkg = pool[rng.below(pool.len())].clone();
		let preferred = pick_ids(rng, &self.sync, 3);
		let packages = pick_ids(rng, &self.sync, 3);
		let rem = pick_ids(rng, &self.local, 3);
		let ans = answers(rng);
		let ((cret, cpkgs, cdata), cc) = self.c.resolvedeps(
			&localpkgs, &pkg, &preferred, &packages, &rem, &ans,
		);
		let mut s = Script::new(self.rs, &ans);
		let mut data = Vec::new();
		let (ret, after) = self.with_env(|env| {
			let mut pkgs = self.pkgs(&packages);
			let ret = resolvedeps(
				env,
				&self.pkgs(&localpkgs),
				self.rs.get(&pkg),
				&self.pkgs(&preferred),
				&mut pkgs,
				&self.pkgs(&rem),
				&mut data,
				&mut s,
			);
			(ret, self.ids(&pkgs))
		});
		let what =
			(&localpkgs, &pkg, &preferred, &packages, &rem, &ans);
		assert_eq!(cret == 0, ret.is_ok(), "resolvedeps {what:?}");
		assert_eq!(cpkgs, after, "resolvedeps packages {what:?}");
		assert_eq!(cdata, data, "resolvedeps data {what:?}");
		assert_eq!(c_calls(cc), s.calls, "resolvedeps calls {what:?}");
		let provider =
			|q: &Asked| matches!(q, Asked::SelectProvider(..));
		seen.provider_asked +=
			s.calls.asked.iter().filter(|q| provider(q)).count();
		seen.resolved += usize::from(ret.is_ok());
		seen.pulled += usize::from(after.len() > packages.len() + 1);
		seen.unresolved += usize::from(!data.is_empty());
	}

	fn recursedeps(&self, rng: &mut Rng, seen: &mut Seen) {
		let targs = pick_ids(rng, &self.local, 4);
		let explicit = rng.below(2) == 0;
		let ((cret, cnames), cc) = self.c.recursedeps(&targs, explicit);
		assert_eq!(cret, 0);
		let mut s = Script::new(self.rs, &[]);
		let mut list: Vec<Package> = targs
			.iter()
			.map(|id| self.rs.get(id).clone())
			.collect();
		recursedeps(self.rs.local(), &mut list, explicit, &mut s);
		let names: Vec<Vec<u8>> =
			list.iter().map(|p| p.name_bytes().to_vec()).collect();
		let what = (&targs, explicit);
		assert_eq!(cnames, names, "recursedeps {what:?}");
		assert_eq!(c_calls(cc), s.calls, "recursedeps calls {what:?}");
		let added = &list[targs.len()..];
		seen.removed += usize::from(!added.is_empty());
		let asexplicit = added.iter().any(|p| {
			p.reason == alpm_core::package::PkgReason::Explicit
		});
		seen.removed_explicit += usize::from(asexplicit);
	}
}

#[test]
fn fixture_fuzz() {
	let mut rng = Rng::new(0xde95);
	let n = cases();
	let mut seen = Seen::default();
	for _ in 0..n {
		let fx = TempRoot::new("depsgraph");
		let world = gen_deps_world(&mut rng);
		write_world(&fx, &world, &mut rng);
		let setup = gen_setup(&mut rng);
		let c = CGraph::new(&fx.root(), &fx.dbpath(), &TP_SYNC, &setup);
		let rs = RustSide::new(&fx, &setup);
		let local = rs.ids(None);
		let sync: Vec<PkgId> = (0..TP_SYNC.len())
			.flat_map(|i| rs.ids(Some(i)))
			.collect();
		let all = [&local[..], &sync[..]].concat();
		let case = Case {
			c: &c,
			rs: &rs,
			setup: &setup,
			local,
			sync,
			all,
		};
		for _ in 0..10 {
			case.checkdeps(&mut rng, &mut seen);
			case.sortbydeps(&mut rng, &mut seen);
			for _ in 0..3 {
				case.find_dbs_satisfier(&mut rng, &mut seen);
			}
			case.resolvedeps(&mut rng, &mut seen);
			case.recursedeps(&mut rng, &mut seen);
		}
	}
	let s = &seen;
	let counts = [
		s.missing,
		s.broken,
		s.nodepversion_missing,
		s.reordered,
		s.cycles,
		s.found,
		s.not_found,
		s.ignored,
		s.ignore_asked,
		s.provider_asked,
		s.provider_none,
		s.resolved,
		s.pulled,
		s.unresolved,
		s.removed,
		s.removed_explicit,
	];
	eprintln!("{n} cases: {seen:?}");
	// provider questions need two uninstalled providers: the rarest
	assert!(counts.iter().all(|&k| k >= n / 10), "{n} cases: {seen:?}");
}
