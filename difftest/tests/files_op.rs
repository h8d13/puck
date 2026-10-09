// pacman_cli::files against C pacman_files for -F, -Fx, -Fl, -Fq and
// --machinereadable: generated worlds under /tmp read through their
// .files dbs (dbext set before registering, like setup_libalpm for -F),
// the same flags in both configs, return value, stdout and stderr
// compared
use alpm_core::internals::handle::Handle;
use difftest::{
	BASENAMES, DIRS, NAMES, REPOS, Rng, SyncWorld, c_pacman_files, iters,
};
use pacman_cli::conf::{ColStr, Config, LOG_ERROR, LOG_WARNING};
use pacman_cli::files::pacman_files;
use pacman_cli::util::Output;

// a fixture and four handles per case: far slower than string fuzz
fn cases() -> usize {
	(iters() / 100).max(100)
}

fn rust_handle(w: &SyncWorld) -> Handle {
	let mut h = Handle::initialize(&w.fx.root(), &w.fx.dbpath()).unwrap();
	h.set_dbext(b".files");
	for r in &w.repos {
		h.register_syncdb(r.as_bytes(), 0).unwrap();
	}
	h
}

// one op on fresh handles over w, compared; true when stdout is not
// empty
fn compare(w: &SyncWorld, cfg: &Config, targets: &[Vec<u8>]) -> bool {
	let mut h = rust_handle(w);
	let mut out = Output::default();
	let ret = pacman_files(cfg, &mut h, targets, &mut out);
	let fh = w.c_handle(b".files");
	let c = c_pacman_files(&fh, cfg, targets);
	let rust = difftest::CRun {
		ret,
		stdout: out.stdout,
		stderr: out.stderr,
	};
	if let Some(d) = c.diff(&rust) {
		let t: Vec<String> = targets
			.iter()
			.map(|t| String::from_utf8_lossy(t).into_owned())
			.collect();
		panic!(
			"{d}\ntargets {t:?} list {} regex {} machine {} \
			quiet {}\n{}",
			cfg.op_q_list,
			cfg.op_f_regex,
			cfg.op_f_machinereadable,
			cfg.quiet,
			w.log
		);
	}
	!c.stdout.is_empty()
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
	cfg.op_f_machinereadable = u16::from(rng.below(4) == 0);
	cfg
}

// ERE pieces around the generated names: no backslashes (back-references
// to repeated groups are a glibc bug the port does not mirror)
const RE: &[&str] = &[
	".",
	"*",
	"+",
	"?",
	"|",
	"^",
	"$",
	"(",
	")",
	"[a-f]",
	"[^/]",
	"[",
	"{2}",
	"{1,",
	"/",
	"o",
	"O",
	"caf\u{e9}",
	"CAF",
	"bin",
	"usr",
];

fn regex(rng: &mut Rng) -> String {
	let mut s = String::new();
	for _ in 0..1 + rng.below(5) {
		match rng.below(3) {
			0 => s.push_str(BASENAMES[rng.below(BASENAMES.len())]),
			_ => s.push_str(RE[rng.below(RE.len())]),
		}
	}
	s
}

fn search_target(rng: &mut Rng, cfg: &Config) -> String {
	let base = BASENAMES[rng.below(BASENAMES.len())];
	let dir = DIRS[rng.below(DIRS.len())];
	if cfg.op_f_regex != 0 && rng.below(3) != 0 {
		let re = regex(rng);
		return match rng.below(3) {
			0 => format!("{dir}{re}"),
			_ => re,
		};
	}
	match rng.below(12) {
		0..4 => base.to_string(),
		4..7 => format!("{dir}{base}"),
		7 => format!("/{dir}{base}"),
		8 => format!("//{dir}"),
		9 => "/".to_string(),
		10 => dir.trim_end_matches('/').to_string(),
		_ => String::new(),
	}
}

fn list_target(rng: &mut Rng, w: &SyncWorld) -> String {
	let names = w.pkg_names();
	let name = match rng.below(3) {
		0 if !names.is_empty() => names[rng.below(names.len())],
		_ => NAMES[rng.below(NAMES.len())],
	};
	let repo = REPOS[rng.below(REPOS.len())];
	match rng.below(10) {
		0..3 => format!("{repo}/{name}"),
		3 => format!("nope/{name}"),
		4 => format!("/{name}"),
		5 => format!("{repo}/"),
		6 => format!("{repo}/{name}/x"),
		7 => String::new(),
		_ => name.to_string(),
	}
}

fn targets(rng: &mut Rng, w: &SyncWorld, cfg: &Config) -> Vec<Vec<u8>> {
	let n = match rng.below(6) {
		0 => 0,
		_ => 1 + rng.below(3),
	};
	(0..n).map(|_| match cfg.op_q_list {
		0 => search_target(rng, cfg),
		_ => list_target(rng, w),
	})
	.map(String::into_bytes)
	.collect()
}

#[test]
fn edges() {
	let mut rng = Rng::new(21);
	let w = SyncWorld::generate(&mut rng, "files-op-edges");
	let edge: [&[&str]; 10] = [
		&[],
		&[""],
		&["/"],
		&["//"],
		&["foo", "usr/bin/foo", "/usr/bin/foo"],
		&["README", "usr/", "usr"],
		&["core/", "nope/a", "a/b/c"],
		&["(", "[", "a{1"],
		&["^f", "o$", "FOO", "usr/.*/foo"],
		&["caf\u{e9}", "CAF\u{c9}", "CAF."],
	];
	for t in edge {
		let t: Vec<Vec<u8>> =
			t.iter().map(|s| s.as_bytes().to_vec()).collect();
		for setup in 0..8 {
			let mut cfg = Config::new();
			cfg.op_q_list = u16::from(setup & 1 != 0);
			cfg.op_f_regex = u16::from(setup & 2 != 0);
			cfg.op_f_machinereadable = u16::from(setup & 4 != 0);
			compare(&w, &cfg, &t);
			cfg.quiet = 1;
			compare(&w, &cfg, &t);
		}
	}
}

#[test]
fn fuzz() {
	let mut rng = Rng::new(0xf11e_0001);
	let (mut runs, mut printed) = (0, 0);
	for _ in 0..cases() {
		let w = SyncWorld::generate(&mut rng, "files-op");
		for _ in 0..4 {
			let mut cfg = config(&mut rng);
			match rng.below(3) {
				0 => cfg.op_q_list = 1,
				1 => cfg.op_f_regex = 1,
				_ => {}
			}
			let t = targets(&mut rng, &w, &cfg);
			printed += usize::from(compare(&w, &cfg, &t));
			runs += 1;
		}
	}
	// matches and listings, not just misses
	assert!(printed * 4 >= runs, "printed {printed} of {runs}");
}
