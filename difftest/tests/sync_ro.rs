// pacman_cli::sync against C pacman_sync for -Si/-Sii, -Sl, -Sg/-Sgg, -Ss and
// the dispatch errors: generated worlds under /tmp (repos sharing names
// with each other and the local db, broken and missing db files), the
// same flags in both configs, a C handle and a Rust Handle over the same
// files. return value, stdout and stderr compared
use alpm_core::handle::Handle;
use difftest::{
	CRun, GROUPS, NAMES, REPOS, Rng, SyncWorld, c_pacman_sync, iters,
	sync_read_only,
};
use pacman_cli::conf::{ColStr, Config, LOG_ERROR, LOG_WARNING};
use pacman_cli::sync::{Unported, pacman_sync};
use pacman_cli::util::Output;

// a fixture and four handles per case: far slower than string fuzz
fn cases() -> usize {
	(iters() / 100).max(100)
}

fn rust_handle(w: &SyncWorld, dbext: &[u8]) -> Handle {
	let mut h = Handle::initialize(&w.fx.root(), &w.fx.dbpath()).unwrap();
	h.set_dbext(dbext);
	for r in &w.repos {
		h.register_syncdb(r.as_bytes(), 0).unwrap();
	}
	h
}

fn warm(h: &mut Handle) {
	let dbext = h.dbext().to_vec();
	for db in h.syncdbs_mut() {
		let _ = db.pkgcache(&dbext);
	}
}

// one op on fresh handles over w, compared: whether stdout is not empty.
// None when the Rust side stops at an unported branch (the C is not run
// then)
fn compare(
	w: &SyncWorld,
	cfg: &Config,
	targets: &[Vec<u8>],
	cols: u16,
	warmed: bool,
) -> Option<bool> {
	let mut h = rust_handle(w, b".db");
	if warmed {
		warm(&mut h);
	}
	let mut out = Output::default();
	let res = pacman_sync(cfg, &mut h, targets, cols, &mut out);
	let ctx = || {
		let t: Vec<String> = targets
			.iter()
			.map(|t| String::from_utf8_lossy(t).into_owned())
			.collect();
		format!(
			"targets {t:?} group {} info {} list {} quiet {} \
			cols {cols} warm {warmed}\n{}",
			cfg.group,
			cfg.op_s_info,
			cfg.op_q_list,
			cfg.quiet,
			w.log
		)
	};
	let ret = match res {
		Ok(ret) => ret,
		Err(e) => {
			assert!(
				!sync_read_only(cfg, targets),
				"{e:?}: {}",
				ctx()
			);
			return None;
		}
	};
	if !sync_read_only(cfg, targets) {
		// stopped by check_syncdbs before the unported branch
		assert_eq!(ret, 1, "{}", ctx());
		return None;
	}
	let fh = w.c_handle(b".db");
	if warmed {
		fh.warm();
	}
	let c = c_pacman_sync(&fh, cfg, targets, cols);
	let rust = CRun {
		ret,
		stdout: out.stdout,
		stderr: out.stderr,
	};
	if let Some(d) = c.diff(&rust) {
		panic!("{d}\n{}", ctx());
	}
	Some(!c.stdout.is_empty())
}

fn config(rng: &mut Rng) -> Config {
	let mut cfg = Config::new();
	if rng.below(3) == 0 {
		cfg.colstr = ColStr::COLOR;
	}
	cfg.logmask = match rng.below(6) {
		0 => 0,
		1 => LOG_WARNING,
		_ => LOG_ERROR | LOG_WARNING,
	};
	cfg.quiet = u16::from(rng.below(3) == 0);
	cfg
}

// pool: what the op looks up (package, repo or group names); package
// and repo names are often taken from the world, so most lookups hit
fn target(rng: &mut Rng, w: &SyncWorld, pool: &[&str]) -> Vec<u8> {
	let known = match pool == NAMES {
		true => w.pkg_names(),
		false if pool == REPOS => w.repos.clone(),
		false => Vec::new(),
	};
	let name = match rng.below(2) {
		0 if !known.is_empty() => known[rng.below(known.len())],
		_ => pool[rng.below(pool.len())],
	};
	let repo = REPOS[rng.below(REPOS.len())];
	let t = match rng.below(16) {
		0..3 => format!("{repo}/{name}"),
		3 => format!("nope/{name}"),
		4 => format!("/{name}"),
		5 => format!("{repo}/"),
		6 => format!("{repo}/{name}/x"),
		7 => String::new(),
		8 => repo.to_string(),
		_ => name.to_string(),
	};
	t.into_bytes()
}

// -Ss needles: names, EREs, a bad one
const SEARCH: [&str; 10] = [
	"a", "^b", "pkg|lib", "[", "", ".*", "DESC", "g1", "x$", "\\(",
];

fn targets(rng: &mut Rng, w: &SyncWorld, pool: &[&str]) -> Vec<Vec<u8>> {
	if pool == SEARCH {
		let n = rng.below(3);
		return (0..n)
			.map(|_| SEARCH[rng.below(10)].as_bytes().to_vec())
			.collect();
	}
	let n = match rng.below(4) {
		0 => 0,
		_ => 1 + rng.below(3),
	};
	(0..n).map(|_| target(rng, w, pool)).collect()
}

fn op(rng: &mut Rng, cfg: &mut Config) -> &'static [&'static str] {
	match rng.below(9) {
		7 => {
			cfg.op_s_search = 1;
			&SEARCH
		}
		0..3 => {
			cfg.op_s_info = 1 + rng.below(2) as u16;
			&NAMES
		}
		3..5 => {
			cfg.op_q_list = 1;
			&REPOS
		}
		5..7 => {
			cfg.group = 1 + rng.below(2) as u16;
			&GROUPS
		}
		// dispatch: "no targets specified", or a transaction
		_ => {
			cfg.op_s_upgrade = u16::from(rng.below(2) == 0);
			&NAMES
		}
	}
}

#[test]
fn edges() {
	let mut rng = Rng::new(11);
	let w = SyncWorld::generate(&mut rng, "sync-ro-edges");
	let edge: [&[&str]; 9] = [
		&[],
		&[""],
		&["/"],
		&["core/"],
		&["nope/a"],
		&["a", "a", "core/a"],
		&["core", "nope", "extra", "core"],
		&["base", "kde", "g1", "g-2", "nope"],
		&["a/b/c", "//a"],
	];
	for t in edge {
		let t: Vec<Vec<u8>> =
			t.iter().map(|s| s.as_bytes().to_vec()).collect();
		for setup in 0..7 {
			let mut cfg = Config::new();
			match setup {
				5 => cfg.op_s_search = 1,
				0 => cfg.op_s_info = 1,
				1 => cfg.op_s_info = 2,
				2 => cfg.op_q_list = 1,
				3 => cfg.group = 1,
				4 => cfg.group = 2,
				_ => {}
			}
			for cols in [0, 80] {
				compare(&w, &cfg, &t, cols, false);
			}
			cfg.quiet = 1;
			compare(&w, &cfg, &t, 80, true);
		}
	}
}

// the branches left to later ports stop the Rust side; flags only, no C
#[test]
fn unported() {
	let mut rng = Rng::new(5);
	let mut w = SyncWorld::generate(&mut rng, "sync-ro-unported");
	while w.repos.is_empty() {
		w = SyncWorld::generate(&mut rng, "sync-ro-unported");
	}
	let mut h = rust_handle(&w, b".db");
	let mut out = Output::default();
	let none: [&[u8]; 0] = [];
	let mut run = |set: fn(&mut Config), t: &[&[u8]]| {
		let mut cfg = Config::new();
		set(&mut cfg);
		pacman_sync(&cfg, &mut h, t, 0, &mut out)
	};
	assert_eq!(run(|c| c.op_s_clean = 1, &none), Err(Unported::Clean));
	assert_eq!(
		run(|c| c.op_s_upgrade = 1, &none),
		Err(Unported::Transaction)
	);
	assert_eq!(run(|_| {}, &[b"a"]), Err(Unported::Transaction));
}

#[test]
fn fuzz() {
	let mut rng = Rng::new(0x5e1_0001);
	let (mut compared, mut printed) = (0, 0);
	let n = cases();
	for _ in 0..n {
		let w = SyncWorld::generate(&mut rng, "sync-ro");
		for _ in 0..4 {
			let mut cfg = config(&mut rng);
			let pool = op(&mut rng, &mut cfg);
			let t = targets(&mut rng, &w, pool);
			let cols = [0, 30, 80, 200][rng.below(4)];
			let warmed = rng.below(3) == 0;
			let Some(p) = compare(&w, &cfg, &t, cols, warmed)
			else {
				continue;
			};
			compared += 1;
			printed += usize::from(p);
		}
	}
	// the transaction picks are the only ones skipped
	assert!(compared >= n * 4 * 3 / 4, "compared {compared}");
	// listings and package details, not just errors
	assert!(printed * 3 >= compared, "printed {printed} of {compared}");
}
