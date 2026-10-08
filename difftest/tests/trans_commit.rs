// alpm_core::trans::trans_commit against the C's alpm_trans_commit on
// fixture worlds (local db + root files, a sync db on a file:// mirror,
// a cache dir, package files): removals, installs and upgrades from the
// mirror or the cache, -U files, DOWNLOADONLY, DBONLY, packages that
// fail the checksum or differ from their db entry (CORRUPTED_PKG yes and
// no), a package missing from the mirror, file conflicts, no disk space,
// replaced and conflicting packages removed by the sync commit. compared
// per case: prepare and commit rc/pm_errno, data list, trans state, the
// kept records (difftest::kept), the logfile, the root, local db and
// cache trees.
use std::collections::BTreeMap;
use std::ffi::c_int;

use difftest::{
	Rng, TcCase, TcOp, TcPkg, TcRec, TcResult, TcWorld, TempRoot, c_commit,
	iters, rust_commit, umask_lock,
};

const DOWNLOADONLY: c_int = 1 << 9;
const DBONLY: c_int = 1 << 6;
const NODEPS: c_int = 1;
const NOSAVE: c_int = 1 << 2;

fn pkg(name: &str, version: &str, files: &[&str]) -> TcPkg {
	TcPkg {
		name: name.into(),
		version: version.into(),
		files: files.iter().map(|f| f.to_string()).collect(),
		isize: 100,
		on_mirror: true,
		..TcPkg::default()
	}
}

fn show(r: &TcResult) -> String {
	let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
	let mut out = format!(
		"prepare {} commit {:?} state {} data {:?}\n",
		r.prepare, r.commit, r.state, r.data
	);
	for rec in &r.recs {
		let line = match rec {
			TcRec::Log(l, m) => format!("log {l} {:?}", s(m)),
			r => format!("{r:?}"),
		};
		out += &line;
		out.push('\n');
	}
	out += &format!("logfile:\n{}", s(&r.logfile));
	out
}

// first differing line of two shows, with context
fn diff(a: &str, b: &str) -> String {
	let (la, lb): (Vec<&str>, Vec<&str>) =
		(a.lines().collect(), b.lines().collect());
	let i = la.iter().zip(&lb).take_while(|(x, y)| x == y).count();
	let from = i.saturating_sub(3);
	format!(
		"first difference at line {i}\nC:\n{}\nRust:\n{}",
		la[from..la.len().min(i + 3)].join("\n"),
		lb[from..lb.len().min(i + 3)].join("\n"),
	)
}

// the case on both sides; the C result
fn compare(fx: &TempRoot, case: &TcCase) -> TcResult {
	let _umask = umask_lock();
	let c = c_commit(fx, case);
	let r = rust_commit(fx, case);
	let (sc, sr) = (show(&c), show(&r));
	assert!(sc == sr, "{case:#?}\n{}\nC full:\n{sc}", diff(&sc, &sr));
	assert_eq!(c.root, r.root, "root tree\n{case:#?}\n{sc}");
	assert_eq!(c.local, r.local, "local db\n{case:#?}\n{sc}");
	assert_eq!(c.cache, r.cache, "cache dir\n{case:#?}\n{sc}");
	c
}

fn case(world: TcWorld, op: TcOp) -> TcCase {
	TcCase {
		world,
		op,
		flags: 0,
		checkspace: false,
		answers: Vec::new(),
	}
}

fn sync(names: &[&str]) -> TcOp {
	TcOp::Sync(names.iter().map(|n| n.to_string()).collect())
}

fn base_world() -> TcWorld {
	TcWorld {
		local: vec![
			pkg("a", "1.0-1", &["usr/", "usr/a"]),
			pkg("b", "1.0-1", &["usr/", "usr/b", "etc/", "etc/b"]),
		],
		sync: vec![
			pkg("a", "2.0-1", &["usr/", "usr/a", "usr/a2"]),
			pkg("c", "1.0-1", &["usr/", "usr/c"]),
		],
		files: vec![pkg("d", "1.0-1", &["opt/", "opt/d"])],
		stray: Vec::new(),
	}
}

fn commit_rc(r: &TcResult) -> Option<(c_int, c_int)> {
	r.commit
}

#[test]
fn remove() {
	let fx = TempRoot::new("tcommit-rm");
	let w = base_world();
	for flags in [0, DBONLY, NOSAVE] {
		let mut c = case(w.clone(), TcOp::Remove(vec!["b".into()]));
		c.flags = flags;
		let r = compare(&fx, &c);
		assert_eq!(commit_rc(&r), Some((0, 0)), "{}", show(&r));
	}
	let c = case(w, TcOp::Remove(vec!["a".into(), "b".into()]));
	compare(&fx, &c);
}

#[test]
fn install_and_upgrade() {
	let fx = TempRoot::new("tcommit-sync");
	let mut w = base_world();
	let r = compare(&fx, &case(w.clone(), sync(&["c"])));
	assert_eq!(commit_rc(&r), Some((0, 0)), "{}", show(&r));
	compare(&fx, &case(w.clone(), sync(&["a", "c"])));
	compare(&fx, &case(w.clone(), TcOp::Sysupgrade));
	// from the cache, with nothing on the mirror
	w.sync[0].cached = true;
	w.sync[0].on_mirror = false;
	let r = compare(&fx, &case(w.clone(), sync(&["a"])));
	assert_eq!(commit_rc(&r), Some((0, 0)), "{}", show(&r));
	let r = compare(&fx, &case(w, TcOp::Upgrade(vec![0])));
	assert_eq!(commit_rc(&r), Some((0, 0)), "{}", show(&r));
}

#[test]
fn flags() {
	let fx = TempRoot::new("tcommit-flags");
	let w = base_world();
	for flags in [DOWNLOADONLY, DBONLY, NODEPS] {
		let mut c = case(w.clone(), sync(&["a", "c"]));
		c.flags = flags;
		let r = compare(&fx, &c);
		assert_eq!(commit_rc(&r), Some((0, 0)), "{}", show(&r));
	}
}

#[test]
fn invalid_packages() {
	let fx = TempRoot::new("tcommit-bad");
	for answer in [0, 1] {
		let mut w = base_world();
		w.sync[0].bad_sum = true;
		let mut c = case(w, sync(&["a", "c"]));
		c.answers = vec![answer];
		let r = compare(&fx, &c);
		assert_eq!(commit_rc(&r).map(|x| x.0), Some(-1));
		let mut w = base_world();
		w.sync[1].mismatch = true;
		let mut c = case(w, sync(&["a", "c"]));
		c.answers = vec![answer];
		let r = compare(&fx, &c);
		assert!(!matches!(r.data, difftest::TcData::None));
	}
	// not on the mirror and not cached
	let mut w = base_world();
	w.sync[1].on_mirror = false;
	let r = compare(&fx, &case(w, sync(&["c"])));
	assert_eq!(commit_rc(&r).map(|x| x.0), Some(-1));
}

#[test]
fn conflicts_and_space() {
	let fx = TempRoot::new("tcommit-conf");
	let mut w = base_world();
	w.stray = vec!["usr/c".into()];
	let r = compare(&fx, &case(w.clone(), sync(&["c"])));
	assert!(matches!(r.data, difftest::TcData::Conflicts(_)));
	// owned by another package
	w.stray.clear();
	w.sync[1].files.push("etc/b".into());
	w.sync[1].files.insert(1, "etc/".into());
	compare(&fx, &case(w, sync(&["c"])));
	// a download no disk takes
	let mut w = base_world();
	w.sync[1].csize = Some(1 << 60);
	let mut c = case(w, sync(&["c"]));
	c.checkspace = true;
	let r = compare(&fx, &c);
	assert_eq!(commit_rc(&r).map(|x| x.0), Some(-1));
}

#[test]
fn replaces_and_conflicts_removed() {
	let fx = TempRoot::new("tcommit-repl");
	let mut w = base_world();
	w.sync[1].replaces = vec!["b".into()];
	let mut c = case(w.clone(), TcOp::Sysupgrade);
	c.answers = vec![1];
	compare(&fx, &c);
	let mut w = base_world();
	w.sync[1].conflicts = vec!["b".into()];
	let mut c = case(w, sync(&["c"]));
	c.answers = vec![1];
	let r = compare(&fx, &c);
	assert_eq!(commit_rc(&r), Some((0, 0)), "{}", show(&r));
}

// ---- fuzz ----

const NAMES: [&str; 4] = ["a", "b", "c", "d"];
const VERSIONS: [&str; 3] = ["1.0-1", "2.0-1", "1.5-2"];
const PATHS: [&str; 5] = ["usr/x", "usr/y", "etc/z", "opt/w", "usr/a"];

fn pick<T: Copy>(rng: &mut Rng, items: &[T]) -> T {
	items[rng.below(items.len())]
}

fn gen_pkg(rng: &mut Rng, name: &str) -> TcPkg {
	let mut files: Vec<String> = Vec::new();
	for p in PATHS {
		if rng.below(3) == 0 {
			let dir = format!("{}/", &p[..p.find('/').unwrap()]);
			if !files.contains(&dir) {
				files.push(dir);
			}
			files.push(p.to_string());
		}
	}
	// parents first, sorted like a package's list
	files.sort();
	let mut p = pkg(name, pick(rng, &VERSIONS), &[]);
	p.files = files;
	let other = |rng: &mut Rng| vec![pick(rng, &NAMES).to_string()];
	if rng.below(5) == 0 {
		p.depends = other(rng);
	}
	if rng.below(6) == 0 {
		p.conflicts = other(rng);
	}
	if rng.below(6) == 0 {
		p.replaces = other(rng);
	}
	if rng.below(6) == 0 {
		p.provides = other(rng);
	}
	p.on_mirror = rng.below(8) != 0;
	p.cached = rng.below(3) == 0;
	p.bad_sum = rng.below(10) == 0;
	p.mismatch = rng.below(10) == 0;
	p
}

fn gen_case(rng: &mut Rng) -> TcCase {
	let mut w = TcWorld::default();
	for n in NAMES {
		if rng.below(2) == 0 {
			let mut p = gen_pkg(rng, n);
			p.depends.clear();
			w.local.push(p);
		}
		if rng.below(2) == 0 {
			w.sync.push(gen_pkg(rng, n));
		}
	}
	// two local packages never own one path: the root holds one copy
	let mut owned: Vec<String> = Vec::new();
	for p in &mut w.local {
		p.files.retain(|f| f.ends_with('/') || !owned.contains(f));
		owned.extend(p.files.iter().cloned());
	}
	let name = pick(rng, &NAMES);
	w.files = vec![gen_pkg(rng, name)];
	if rng.below(4) == 0 {
		w.stray = vec![pick(rng, &PATHS).to_string()];
	}
	let names = |list: &[TcPkg], rng: &mut Rng| -> Vec<String> {
		list.iter()
			.filter(|_| rng.below(2) == 0)
			.map(|p| p.name.clone())
			.collect()
	};
	let op = match rng.below(4) {
		0 if !w.local.is_empty() => TcOp::Remove(names(&w.local, rng)),
		1 => TcOp::Sysupgrade,
		2 => TcOp::Upgrade(vec![0]),
		_ => TcOp::Sync(names(&w.sync, rng)),
	};
	let flags = pick(rng, &[0, 0, 0, DBONLY, DOWNLOADONLY, NODEPS]);
	let answers = (0..4).map(|_| pick(rng, &[0, 1])).collect();
	TcCase {
		world: w,
		op,
		flags,
		checkspace: rng.below(2) == 0,
		answers,
	}
}

// what a run reached, counted over the fuzz
fn mark(r: &TcResult, seen: &mut BTreeMap<&'static str, usize>) {
	let mut hit = |k: &'static str| *seen.entry(k).or_default() += 1;
	match r.commit {
		None => hit("prepare failed"),
		Some((0, _)) => hit("committed"),
		Some(_) => hit("commit failed"),
	}
	for rec in &r.recs {
		match rec {
			TcRec::Ask(8, _) => hit("corrupted question"),
			TcRec::Retrieve(23, ..) => hit("retrieve failed"),
			TcRec::Op(true, 5, ..) => hit("removed"),
			TcRec::Op(true, 2, ..) => hit("upgraded"),
			_ => {}
		}
	}
	if matches!(r.data, difftest::TcData::Conflicts(_)) {
		hit("file conflicts");
	}
	if matches!(r.data, difftest::TcData::Invalid(_)) {
		hit("invalid");
	}
}

#[test]
fn fuzz() {
	let fx = TempRoot::new("tcommit-fuzz");
	let mut rng = Rng::new(0xc0337);
	let mut seen = BTreeMap::new();
	let n = (iters() / 1000).max(150);
	for _ in 0..n {
		let c = gen_case(&mut rng);
		let r = compare(&fx, &c);
		mark(&r, &mut seen);
	}
	for k in [
		"committed",
		"commit failed",
		"corrupted question",
		"retrieve failed",
		"removed",
		"upgraded",
		"file conflicts",
		"invalid",
	] {
		assert!(seen.contains_key(k), "never hit {k:?}: {seen:?}");
	}
}
