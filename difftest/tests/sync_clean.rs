// -Sc/-Scc: pacman_cli::sync (pacman_sync, then sync_clean like the
// dispatch) against C pacman_sync with op_s_clean, on CleanWorlds made
// twice from one seed (the C cleans one, the Rust side the other). random
// answers (y, n, empty, other, end of input) and --noconfirm, -c/-cc/-ccc,
// every CleanMethod, color, debug logging, a held db lock. compared:
// return value, stdout, stderr, input consumed and the whole fixture tree
// afterwards. both outputs are normalized: the fixture dir to "@", the
// PACMAN_DEBUG stamps cut, lines carrying libarchive's texts dropped
// (be_package does not log those), debug lines not from
// sync.c dropped (libalpm's own are compared in their units)
use std::cell::RefCell;
use std::fs;
use std::io::Cursor;
use std::path::Path;

use alpm_core::internals::handle::Handle;
use difftest::{
	CleanWorld, Comp, Node, Rng, c_pacman_sync_clean, cut_archive_text,
	iters, snapshot, umask_lock, utc_date, write_package,
};
use pacman_cli::callback::Frontend;
use pacman_cli::conf::{
	ColStr, Config, LOG_DEBUG, LOG_ERROR, LOG_WARNING, PM_CLEAN_KEEPCUR,
	PM_CLEAN_KEEPINST,
};
use pacman_cli::pacman::PM_OP_SYNC;
use pacman_cli::sync::{Deferred, pacman_sync, sync_clean};
use pacman_cli::util::{Output, Term, Ui};

// the Rust op and its callbacks write through one sink, in order like
// the C streams
thread_local! {
	static SINK: RefCell<Output> = RefCell::new(Output::default());
}

fn sink(o: &mut Output) {
	SINK.with(|s| {
		let mut s = s.borrow_mut();
		s.stdout.append(&mut o.stdout);
		s.stderr.append(&mut o.stderr);
	});
}

fn pick<T: Copy>(rng: &mut Rng, items: &[T]) -> T {
	items[rng.below(items.len())]
}

// what one side returned, printed (normalized) and read
#[derive(Debug, PartialEq, Eq)]
struct Run {
	ret: i32,
	stdout: String,
	stderr: String,
	consumed: usize,
}

// the Handle setup_libalpm would leave: repos, cache dirs, then the
// frontend's callbacks
fn rust_run(w: &CleanWorld, cfg: &Config, input: &[u8]) -> Run {
	let mut h = Handle::initialize(&w.fx.root(), &w.fx.dbpath()).unwrap();
	for r in &w.repos {
		h.register_syncdb(r.as_bytes(), 0).unwrap();
	}
	for d in &w.cachedirs {
		h.add_cachedir(d);
	}
	let mut cb =
		Frontend::new(cfg.clone(), Term::new(&b""[..], false, false));
	cb.out.sink = Some(sink);
	h.set_callbacks(Box::new(cb));
	let mut out = Output {
		sink: Some(sink),
		..Output::default()
	};
	let mut term = Term::new(Cursor::new(input.to_vec()), false, false);
	let ret = {
		let mut ui = Ui {
			config: cfg,
			term: &mut term,
			cols: 0,
			out: &mut out,
			format_date: &utc_date,
			explicit_adds: Vec::new(),
			explicit_removes: Vec::new(),
		};
		let none: [&[u8]; 0] = [];
		match pacman_sync(cfg, &mut h, &none, 0, ui.out) {
			Err(Deferred::Clean) => sync_clean(&mut ui, &mut h),
			other => panic!("-Sc reached {other:?}"),
		}
	};
	out.flush();
	// the C side's handle is released after its capture too
	let all = SINK.with(|s| std::mem::take(&mut *s.borrow_mut()));
	drop(h);
	SINK.with(|s| std::mem::take(&mut *s.borrow_mut()));
	let dir = dir_str(w);
	Run {
		ret,
		stdout: norm(&all.stdout, &dir),
		stderr: norm(&all.stderr, &dir),
		consumed: term.stdin.position() as usize,
	}
}

fn c_run(w: &CleanWorld, cfg: &Config, input: &[u8]) -> Run {
	let fh = w.c_handle();
	let (ret, io) = c_pacman_sync_clean(&fh, cfg, input);
	drop(fh);
	let dir = dir_str(w);
	Run {
		ret,
		stdout: norm(&io.out.stdout, &dir),
		stderr: norm(&io.out.stderr, &dir),
		consumed: io.consumed,
	}
}

fn dir_str(w: &CleanWorld) -> String {
	w.fx.dir().display().to_string()
}

// "[HH:MM:SS] " before stamped lines: both read the clock
fn unstamp(line: &str) -> &str {
	let b = line.as_bytes();
	let stamped =
		b.len() >= 11
			&& b[0] == b'[' && b[3] == b':'
			&& b[6] == b':' && b[9] == b']';
	if stamped { &line[11..] } else { line }
}

// sync.c's own debug lines, the rest of debug is libalpm's
fn kept(line: &str) -> bool {
	if !line.starts_with("debug: ") {
		return true;
	}
	line.ends_with(", could not load as package\n")
		|| line.ends_with(" found in local db\n")
		|| line.ends_with(" found in sync db\n")
}

// libarchive's texts cut (cut_archive_text)
fn lossy_cut(line: &str) -> String {
	String::from_utf8_lossy(&cut_archive_text(line.as_bytes())).into_owned()
}

fn is_stamp(s: &str) -> bool {
	unstamp(s).len() != s.len()
}

// a message starting mid-line (after a prompt whose answer was not
// echoed) put on its own line, so the filters see whole messages. the
// split is marked by a nul, norm joins it back
fn split_messages(s: &str) -> String {
	let heads = [
		"\x1b[1;31merror: ",
		"\x1b[1;33mwarning: ",
		"error: ",
		"warning: ",
		"debug: ",
	];
	let mut out = String::new();
	let (mut i, mut fresh) = (0, true);
	while i < s.len() {
		let rest = &s[i..];
		let head = match is_stamp(rest) {
			true => Some(11),
			false => heads
				.iter()
				.find(|h| rest.starts_with(*h))
				.map(|h| h.len()),
		};
		if let Some(n) = head {
			if !fresh {
				out.push_str("\0\n");
			}
			out.push_str(&rest[..n]);
			(i, fresh) = (i + n, true);
			continue;
		}
		let c = rest.chars().next().expect("i < len");
		out.push(c);
		(i, fresh) = (i + c.len_utf8(), c == '\n');
	}
	out
}

fn norm(s: &[u8], dir: &str) -> String {
	let s = String::from_utf8_lossy(s).replace(dir, "@");
	let kept: String = split_messages(&s)
		.split_inclusive('\n')
		.map(unstamp)
		.filter(|l| kept(l))
		.map(lossy_cut)
		.collect();
	kept.replace("\0\n", "")
}

fn clean_cfg(rng: &mut Rng) -> Config {
	let mut cfg = Config::new();
	cfg.op = PM_OP_SYNC;
	cfg.op_s_clean = pick(rng, &[1, 1, 2, 3]);
	cfg.cleanmethod = pick(
		rng,
		&[
			0,
			PM_CLEAN_KEEPINST,
			PM_CLEAN_KEEPCUR,
			PM_CLEAN_KEEPINST | PM_CLEAN_KEEPCUR,
		],
	);
	cfg.noconfirm = u16::from(rng.below(6) == 0);
	if rng.below(4) == 0 {
		cfg.colstr = ColStr::COLOR;
	}
	cfg.logmask = match rng.below(6) {
		0 => LOG_ERROR,
		1 | 2 => LOG_ERROR | LOG_WARNING | LOG_DEBUG,
		_ => LOG_ERROR | LOG_WARNING,
	};
	cfg
}

// answers for the prompts: one per cache dir and the db question, some
// cut short
fn answers(rng: &mut Rng) -> Vec<u8> {
	let lines = ["y", "n", "", "yes", "NO", "x", "Y"];
	let mut s = String::new();
	for _ in 0..rng.below(6) {
		s.push_str(pick(rng, &lines));
		s.push('\n');
	}
	if rng.below(8) == 0 {
		s.push('y');
	}
	s.into_bytes()
}

#[derive(Debug, Default)]
struct Seen {
	removed: usize,
	found_local: usize,
	found_sync: usize,
	unlink_failed: usize,
	rmrf_failed: usize,
	no_cachedir: usize,
	locked: usize,
	debug: usize,
	negative: usize,
}

fn tree(w: &CleanWorld) -> Node {
	snapshot(w.fx.dir())
}

fn count(s: &str, pat: &str) -> usize {
	s.matches(pat).count()
}

#[test]
fn fuzz() {
	let mut rng = Rng::new(0x5c1ea4);
	let n = (iters() / 400).max(300);
	let mut seen = Seen::default();
	for i in 0..n {
		let seed = rng.next_u64();
		let cfg = clean_cfg(&mut rng);
		let input = answers(&mut rng);
		let locked = rng.below(12) == 0;
		// modes are compared
		let _umask = umask_lock();
		let cw = CleanWorld::generate(seed, "clean-c");
		let rw = CleanWorld::generate(seed, "clean-r");
		if locked {
			for w in [&cw, &rw] {
				fs::write(w.fx.dir().join("db/db.lck"), b"")
					.unwrap();
			}
		}
		let before = tree(&cw);
		assert_eq!(before, tree(&rw), "worlds of one seed differ");
		let c = c_run(&cw, &cfg, &input);
		let r = rust_run(&rw, &cfg, &input);
		let what = format!(
			"case {i}: -S{} cleanmethod {} noconfirm {} logmask {} \
			input {:?} locked {locked}\n{}",
			"c".repeat(cfg.op_s_clean.into()),
			cfg.cleanmethod,
			cfg.noconfirm,
			cfg.logmask,
			String::from_utf8_lossy(&input),
			cw.log
		);
		assert_eq!(c.ret, r.ret, "ret {what}\n{c:#?}\n{r:#?}");
		assert_eq!(c.stdout, r.stdout, "stdout {what}");
		assert_eq!(c.stderr, r.stderr, "stderr {what}");
		assert_eq!(c.consumed, r.consumed, "input read {what}");
		let after = tree(&cw);
		assert_eq!(after, tree(&rw), "trees {what}");
		let e = &c.stderr;
		seen.removed += usize::from(after != before);
		seen.found_local += count(e, " found in local db\n");
		seen.found_sync += count(e, " found in sync db\n");
		seen.unlink_failed += count(e, ": Permission denied\n");
		seen.rmrf_failed += count(e, ": Directory not empty\n");
		seen.no_cachedir +=
			count(e, "could not access cache directory");
		seen.locked +=
			usize::from(e.contains("could not lock database"));
		seen.debug += count(e, "debug: ");
		seen.negative += usize::from(c.ret < 0);
	}
	eprintln!("{n} cases: {seen:#?}");
	let s = &seen;
	let counts = [
		s.removed,
		s.found_local,
		s.found_sync,
		s.unlink_failed,
		s.rmrf_failed,
		s.no_cachedir,
		s.locked,
		s.debug,
		s.negative,
	];
	assert!(counts.iter().all(|&k| k >= n / 100), "{n} cases: {seen:#?}");
}

// a dir of entries moved under a deep path afterwards: the full paths of
// the entries could not be created directly
fn deep_cachedir(w: &CleanWorld, len: usize, names: &[(String, bool)]) {
	let flat = w.fx.dir().join("flat");
	fs::create_dir(&flat).unwrap();
	for (name, pkg) in names {
		let p = flat.join(name);
		match pkg {
			true => write_package(&p, "zz", "1.0-1", Comp::None),
			false => fs::write(p, b"sig").unwrap(),
		}
	}
	let dir = String::from_utf8(w.cachedirs[0].clone()).unwrap();
	let parent = Path::new(&dir).parent().unwrap();
	fs::create_dir_all(parent).unwrap();
	fs::rename(&flat, &dir).unwrap();
	assert_eq!(dir.len() + 1, len);
}

// cache paths around PATH_MAX: 4096 is skipped, 4095 and 4092 are
// removed without their .sig, 4091 with it
#[test]
fn path_max() {
	let _umask = umask_lock();
	let worlds = [
		CleanWorld::generate(1, "clean-pm-c"),
		CleanWorld::generate(1, "clean-pm-r"),
	];
	let mut cfg = Config::new();
	cfg.op = PM_OP_SYNC;
	cfg.op_s_clean = 1;
	cfg.noconfirm = 1;
	let mut runs = Vec::new();
	let mut trees = Vec::new();
	for (i, w) in worlds.into_iter().enumerate() {
		let mut w = w;
		// one cache dir of 3900 bytes with its '/'
		let base = w.fx.dir().join("deep").display().to_string();
		let mut dir = base;
		while dir.len() < 3899 - 201 {
			dir.push('/');
			dir.push_str(&"d".repeat(200));
		}
		dir.push('/');
		dir.push_str(&"e".repeat(3899 - dir.len()));
		w.cachedirs = vec![dir.into_bytes()];
		let mut names = Vec::new();
		for total in [4091, 4092, 4095, 4096] {
			let name =
				format!("{:x<1$}", "zz-1.0-1-", total - 3900);
			names.push((format!("{name}.sig"), false));
			names.push((name, true));
		}
		deep_cachedir(&w, 3900, &names);
		let r = match i {
			0 => c_run(&w, &cfg, b""),
			_ => rust_run(&w, &cfg, b""),
		};
		let left: Vec<usize> =
			flat_names(&w).iter().map(|n| n.len() + 3900).collect();
		runs.push(r);
		trees.push(left);
	}
	assert_eq!(runs[0], runs[1]);
	assert_eq!(trees[0], trees[1]);
	assert!(
		runs[0].stderr.contains(": path exceeds PATH_MAX\n"),
		"{:?}",
		runs[0]
	);
}

// names left in the deep cache dir, sorted
fn flat_names(w: &CleanWorld) -> Vec<String> {
	let dir = String::from_utf8(w.cachedirs[0].clone()).unwrap();
	let mut v: Vec<String> = fs::read_dir(&dir)
		.unwrap()
		.map(|e| e.unwrap().file_name().into_string().unwrap())
		.collect();
	v.sort();
	v
}
