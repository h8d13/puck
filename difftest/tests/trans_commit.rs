// alpm_core::trans::trans_commit against the C's alpm_trans_commit on
// fixture worlds (local db + root files, a sync db on a file:// mirror,
// a cache dir, package files): removals, installs and upgrades from the
// mirror or the cache, -U files, DOWNLOADONLY, DBONLY, packages that
// fail the checksum or differ from their db entry (CORRUPTED_PKG yes and
// no), a package missing from the mirror, file conflicts, no disk space,
// replaced and conflicting packages removed by the sync commit; hooks
// (fc_ tests, re-run under fakechroot(1) by under_fakechroot). compared
// per case: prepare and commit rc/pm_errno, data list, trans state, the
// kept records (difftest::kept), the logfile, the root, local db and
// cache trees.
use std::collections::BTreeMap;
use std::ffi::c_int;

use difftest::{
	HookRec, Rng, TcCase, TcHook, TcOp, TcPkg, TcRec, TcResult, TcWorld,
	TempRoot, c_commit, iters, rust_commit, umask_lock,
};

const DOWNLOADONLY: c_int = 1 << 9;
const DBONLY: c_int = 1 << 6;
const NODEPS: c_int = 1;
const NOSAVE: c_int = 1 << 2;
const NOHOOKS: c_int = 1 << 7;

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
		hooks: Vec::new(),
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
		hooks: Vec::new(),
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

// ---- hooks, for real in a chroot of the root under fakechroot(1) ----

const FC_CHILD: &str = "DIFFTEST_IN_FAKECHROOT";

fn in_fakechroot() -> bool {
	std::env::var_os(FC_CHILD).is_some()
}

// re-runs this binary's fc_ tests under fakechroot, capped in time like
// the test binary itself
#[test]
fn under_fakechroot() {
	if in_fakechroot() {
		return;
	}
	let exe = std::env::current_exe().unwrap();
	let out = std::process::Command::new("timeout")
		.args(["1500", "fakechroot"])
		.arg(exe)
		.args(["fc_", "--test-threads=1"])
		.env(FC_CHILD, "1")
		.output()
		.expect("timeout/fakechroot not found");
	let stdout = String::from_utf8_lossy(&out.stdout);
	assert!(
		out.status.success() && stdout.contains("3 passed"),
		"fakechroot run: {}\n{stdout}\n{}",
		out.status,
		String::from_utf8_lossy(&out.stderr)
	);
}

fn hook(dir: usize, name: &str, text: &str) -> TcHook {
	TcHook {
		dir,
		name: name.into(),
		text: text.into(),
	}
}

// reads every target line (an early exit races the C's stdin feed)
const READ_TARGETS: &str =
	"/bin/sh -c 'while IFS= read -r l; do echo \"$0:$l\"; done'";

// a hook of one trigger: operations, type, targets, then the action
// lines
fn trigger(ops: &[&str], ty: &str, targets: &[&str], action: &str) -> String {
	let mut t = String::from("[Trigger]\n");
	for op in ops {
		t += &format!("Operation = {op}\n");
	}
	t += &format!("Type = {ty}\n");
	for target in targets {
		t += &format!("Target = {target}\n");
	}
	t + "[Action]\n" + action
}

// the fixed hook set over base_world: Package and Path triggers on
// each operation, NeedsTargets, Exec with arguments, Depends before and
// after the install, reused sections, a failing command, a hook masked
// by the second dir, one writing into the root
fn fixed_hooks() -> Vec<TcHook> {
	let all = ["Install", "Upgrade", "Remove"];
	let pkgs = trigger(
		&["Install", "Upgrade"],
		"Package",
		&["*"],
		&format!("Description = packages in\nWhen = PreTransaction\n\
			NeedsTargets\nExec = {READ_TARGETS} pkg\n"),
	);
	let paths = trigger(
		&all,
		"Path",
		&["usr/*", "!usr/a"],
		&format!("When = PostTransaction\nNeedsTargets\n\
			Exec = {READ_TARGETS} path\n"),
	);
	let args = trigger(
		&["Remove"],
		"Package",
		&["b"],
		"When = PreTransaction\nExec = /bin/sh -c \
		'echo \"args:$0:$1:$2\"' zero \"one two\" three\n",
	);
	let dep = |when: &str, dep: &str| {
		trigger(
			&["Install"],
			"Package",
			&["c"],
			&format!("When = {when}\nDepends = {dep}\n\
				Exec = /bin/sh -c 'echo dep {when}'\n"),
		)
	};
	let reused = "[Trigger]\nOperation = Upgrade\nType = Package\n\
		Target = a\n[Action]\nWhen = PreTransaction\n\
		Exec = /bin/sh -c 'echo first'\n[Trigger]\n\
		Operation = Install\nType = Path\nTarget = usr/c\n\
		[Action]\nWhen = PostTransaction\n\
		Exec = /bin/sh -c 'echo reused'\n\
		Description = reused sections\n";
	let fail = |code: u8| {
		trigger(
			&all,
			"Package",
			&["*"],
			&format!("When = PostTransaction\nExec = /bin/sh -c \
				'echo oops >&2; exit {code}'\n"),
		)
	};
	let write = trigger(
		&["Install", "Upgrade"],
		"Path",
		&["usr/a2"],
		"When = PostTransaction\n\
		Exec = /bin/sh -c 'read -r l < /usr/a2; echo \"$l\" > /out'\n",
	);
	vec![
		hook(0, "10-pkg.hook", &pkgs),
		hook(0, "20-path.hook", &paths),
		hook(1, "15-args.hook", &args),
		hook(1, "30-dep.hook", &dep("PostTransaction", "c")),
		hook(0, "31-dep-pre.hook", &dep("PreTransaction", "c>=1")),
		hook(0, "40-reuse.hook", reused),
		hook(0, "60-fail.hook", &fail(2)),
		hook(1, "60-fail.hook", &fail(3)),
		hook(1, "70-write.hook", &write),
	]
}

// the hooks that ran, in order
fn ran(r: &TcResult) -> Vec<String> {
	r.recs.iter()
		.filter_map(|x| match x {
			TcRec::Hook(HookRec::RunStart(n, ..)) => {
				Some(String::from_utf8_lossy(n).into_owned())
			}
			_ => None,
		})
		.collect()
}

fn hook_lines(r: &TcResult) -> Vec<String> {
	r.recs.iter()
		.filter_map(|x| match x {
			TcRec::Hook(HookRec::Scriptlet(l)) => {
				Some(String::from_utf8_lossy(l).into_owned())
			}
			_ => None,
		})
		.collect()
}

#[test]
fn fc_hooks_fixed() {
	if !in_fakechroot() {
		return;
	}
	let fx = TempRoot::new("tcommit-fc-hooks");
	let ops = [
		sync(&["a", "c"]),
		TcOp::Sysupgrade,
		TcOp::Remove(vec!["b".into()]),
		TcOp::Upgrade(vec![0]),
	];
	for op in ops {
		for flags in [0, NOHOOKS, DBONLY] {
			let mut c = case(base_world(), op.clone());
			c.hooks = fixed_hooks();
			c.flags = flags;
			let r = compare(&fx, &c);
			assert_eq!(commit_rc(&r), Some((0, 0)), "{}", show(&r));
			assert_eq!(flags == NOHOOKS, ran(&r).is_empty());
		}
	}
	// what ran for the install and upgrade, and what it printed
	let mut c = case(base_world(), sync(&["a", "c"]));
	c.hooks = fixed_hooks();
	let r = compare(&fx, &c);
	assert_eq!(
		ran(&r),
		[
			"10-pkg.hook",
			"31-dep-pre.hook",
			"20-path.hook",
			"30-dep.hook",
			"40-reuse.hook",
			"60-fail.hook",
			"70-write.hook",
		],
		"{}",
		show(&r)
	);
	let lines = hook_lines(&r);
	let want = [
		"pkg:a\n",
		"pkg:c\n",
		"path:usr/a2\n",
		"dep PostTransaction\n",
	];
	for w in want {
		assert!(lines.iter().any(|l| l == w), "{}", show(&r));
	}
	let out = std::fs::read(fx.dir().join("root/out")).unwrap();
	assert_eq!(out, b"a-2.0-1:usr/a2\n");
}

#[test]
fn fc_hooks_abort() {
	if !in_fakechroot() {
		return;
	}
	let fx = TempRoot::new("tcommit-fc-abort");
	let abort = |when: &str| {
		trigger(
			&["Install", "Upgrade", "Remove"],
			"Package",
			&["*"],
			&format!("When = {when}\nAbortOnFail\n\
				Exec = /bin/sh -c 'echo abort; exit 1'\n"),
		)
	};
	// a hook that does not parse fails every PreTransaction run
	let bad = "[Trigger]\nOperation = Install\nType = Package\n\
		Target = *\n[Bogus]\n[Action]\nWhen = PostTransaction\n\
		Exec = /bin/sh -c 'echo never'\n";
	for op in [sync(&["c"]), TcOp::Remove(vec!["b".into()])] {
		let mut c = case(base_world(), op.clone());
		c.hooks = vec![hook(1, "50-bad.hook", bad)];
		let r = compare(&fx, &c);
		assert_eq!(
			commit_rc(&r).map(|x| x.0),
			Some(-1),
			"{}",
			show(&r)
		);
		let mut c = case(base_world(), op);
		c.hooks = vec![hook(
			0,
			"00-abort.hook",
			&abort("PreTransaction"),
		)];
		let r = compare(&fx, &c);
		assert_eq!(
			commit_rc(&r).map(|x| x.0),
			Some(-1),
			"{}",
			show(&r)
		);
		// a PostTransaction AbortOnFail only warns, the failure is
		// ignored
		c.hooks = vec![hook(
			1,
			"00-abort.hook",
			&abort("PostTransaction"),
		)];
		let r = compare(&fx, &c);
		assert_eq!(commit_rc(&r), Some((0, 0)), "{}", show(&r));
	}
}

// random hook sets from the pieces above on random transactions
#[test]
fn fc_hooks_fuzz() {
	if !in_fakechroot() {
		return;
	}
	let fx = TempRoot::new("tcommit-fc-fuzz");
	let mut rng = Rng::new(0x400c);
	let names = ["10-a.hook", "20-b.hook", "z.hook"];
	let pkg_targets = ["a", "b", "c", "d", "*", "!b"];
	let path_targets = ["usr/*", "etc/*", "opt/*", "*", "!usr/x"];
	let n = (iters() / 4000).max(40);
	let (mut ran_total, mut seen) = (0, BTreeMap::new());
	for _ in 0..n {
		let mut c = gen_case(&mut rng);
		for _ in 0..1 + rng.below(4) {
			let ops: Vec<&str> = ["Install", "Upgrade", "Remove"]
				.into_iter()
				.filter(|_| rng.below(2) == 0)
				.collect();
			let ops = match ops.is_empty() {
				true => vec!["Install"],
				false => ops,
			};
			let ty = pick(&mut rng, &["Package", "Path"]);
			let target = match ty {
				"Package" => pick(&mut rng, &pkg_targets),
				_ => pick(&mut rng, &path_targets),
			};
			let when = pick(
				&mut rng,
				&["PreTransaction", "PostTransaction"],
			);
			let mut action = format!("When = {when}\n");
			if rng.below(4) == 0 {
				action += "AbortOnFail\n";
			}
			if rng.below(5) == 0 {
				let dep = pick(&mut rng, &["a", "c>=2", "d"]);
				action += &format!("Depends = {dep}\n");
			}
			action += match rng.below(3) {
				0 => {
					"NeedsTargets\nExec = /bin/sh -c 'while \
					IFS= read -r l; do echo \"t:$l\"; done'\n"
				}
				1 => "Exec = /bin/sh -c 'echo fail; exit 1'\n",
				_ => "Exec = /bin/sh -c 'echo \"$0\"' ok\n",
			};
			let text = trigger(&ops, ty, &[target], &action);
			let name = pick(&mut rng, &names);
			c.hooks.push(hook(rng.below(2), name, &text));
		}
		let r = compare(&fx, &c);
		ran_total += ran(&r).len();
		mark(&r, &mut seen);
	}
	// gen_case commits packages in about a third of the cases
	let msg = format!("{ran_total} hooks ran in {n} cases: {seen:?}");
	assert!(ran_total > n / 4, "{msg}");
}
