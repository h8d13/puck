// pacman_cli::pacman against the C pacman binary: parseargs is static in
// pacman.c.o (not linked here), so the C runs as a process and the port
// in process (`main_args`), compared on stdout, stderr and exit status.
//
// every argv starts with --config=<missing file>, so a C run that gets
// past parseargs stops at the root check, the "-" stdin check or
// parseconfig, before setup_libalpm. paths point into a fresh fixture
// directory, no generated token names an existing file. LC_ALL=C on the
// C side: the port prints msgids
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use difftest::{Rng, Stamped, iters, stamped};
use pacman_cli::conf::Config;
use pacman_cli::getopt::{HasArg, LongOpt};
use pacman_cli::pacman::{Io, LONGOPTS, Process, main_args, parseargs};

fn c_pacman() -> PathBuf {
	let dir = match std::env::var_os("PACMAN_BUILD") {
		Some(d) => PathBuf::from(d),
		None => Path::new(env!("CARGO_MANIFEST_DIR"))
			.join("../pacman/build"),
	};
	dir.join("pacman")
}

struct Fixture {
	root: PathBuf,
}

impl Fixture {
	fn new(tag: &str) -> Fixture {
		let root = std::env::temp_dir().join(format!(
			"pacman-args-dt-{}-{tag}",
			std::process::id()
		));
		if root.exists() {
			fs::remove_dir_all(&root).unwrap();
		}
		for d in DIRS {
			fs::create_dir_all(root.join(d)).unwrap();
		}
		Fixture { root }
	}

	fn path(&self, rel: &str) -> String {
		format!("{}/{rel}", self.root.display())
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.root).unwrap();
	}
}

// empty directories --root, --dbpath, ... resolve to
const DIRS: &[&str] = &["root", "db", "cache", "hook", "gpg", "sys"];

// getuid(): pacman refuses root-only operations for uid > 0
fn uid() -> u32 {
	let status = fs::read_to_string("/proc/self/status").unwrap();
	status.lines()
		.find_map(|l| l.strip_prefix("Uid:"))
		.and_then(|v| v.split_whitespace().next())
		.and_then(|v| v.parse().ok())
		.unwrap()
}

// the C child shares this process's controlling terminal (or lack of
// one): its freopen(ctermid()) gets the same result as this open
fn reopen_tty() -> Result<(), i32> {
	match fs::File::open("/dev/tty") {
		Ok(_) => Ok(()),
		Err(e) => Err(e.raw_os_error().unwrap_or(0)),
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Outcome {
	out: String,
	// PACMAN_DEBUG stamps within CLOCK_SLACK
	err: Stamped,
	status: i32,
}

fn lossy(b: &[u8]) -> String {
	String::from_utf8_lossy(b).into_owned()
}

fn run_c(
	fx: &Fixture,
	argv: &[Vec<u8>],
	stdin: Option<&[u8]>,
	posix: bool,
) -> Outcome {
	let mut cmd = Command::new(c_pacman());
	cmd.arg0(std::ffi::OsStr::from_bytes(&argv[0]))
		.args(argv[1..].iter().map(|a| std::ffi::OsStr::from_bytes(a)))
		.current_dir(&fx.root)
		.env_clear()
		.env("LC_ALL", "C")
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.stdin(if stdin.is_some() {
			Stdio::piped()
		} else {
			Stdio::null()
		});
	if posix {
		cmd.env("POSIXLY_CORRECT", "1");
	}
	let mut child = cmd.spawn().unwrap();
	if let Some(data) = stdin {
		let mut pipe = child.stdin.take().unwrap();
		// pacman may exit before reading
		let _ = pipe.write_all(data);
	}
	let o = child.wait_with_output().unwrap();
	Outcome {
		out: lossy(&o.stdout),
		err: stamped(&o.stderr),
		status: o.status.code().expect("C pacman killed by a signal"),
	}
}

fn run_rust(
	argv: &[Vec<u8>],
	stdin: Option<&[u8]>,
	posix: bool,
) -> (Outcome, bool) {
	let mut argv = argv.to_vec();
	let mut io = Io {
		posixly_correct: posix,
		debug_stamps: true,
		..Io::default()
	};
	// /dev/null is not a terminal: stdin always reads, empty for None
	let process = Process {
		uid: uid(),
		stdin: Some(stdin.unwrap_or_default()),
		reopen_tty,
	};
	let r = main_args(&mut argv, process, &mut io);
	let out = Outcome {
		out: lossy(&io.out),
		err: stamped(&io.err),
		status: r.as_ref().map_or_else(|&c| c, |_| 0),
	};
	(out, r.is_ok())
}

// the config file the C would open, None when parseargs fails first
fn config_path(argv: &[Vec<u8>], posix: bool) -> Option<Vec<u8>> {
	let mut config = Config::new();
	let mut argv = argv.to_vec();
	let mut io = Io {
		posixly_correct: posix,
		..Io::default()
	};
	parseargs(&mut config, &mut argv, &mut io).ok()?;
	let file = config.configfile.unwrap_or_default();
	Some(match config.sysroot {
		Some(s) => [s, file].concat(),
		None => file,
	})
}

fn show(argv: &[Vec<u8>]) -> Vec<String> {
	argv.iter().map(|a| lossy(a)).collect()
}

// compares one invocation, returns the C exit status and stderr
fn compare(
	fx: &Fixture,
	argv: &[Vec<u8>],
	stdin: Option<&[u8]>,
	posix: bool,
) -> (i32, String) {
	// never let the C reach setup_libalpm: the config must be missing
	if let Some(p) = config_path(argv, posix) {
		let p = fx.root.join(std::ffi::OsStr::from_bytes(&p));
		assert!(
			!p.exists(),
			"config {p:?} exists for {:?}",
			show(argv)
		);
	}
	let (r, parsed) = run_rust(argv, stdin, posix);
	assert!(!parsed, "parseconfig succeeded for {:?}", show(argv));
	let c = run_c(fx, argv, stdin, posix);
	assert_eq!(
		r,
		c,
		"argv {:?} stdin {:?} posix {posix}",
		show(argv),
		stdin.map(lossy)
	);
	(c.status, lossy(&c.err.text))
}

fn args(fx: &Fixture, a: &[&str]) -> Vec<Vec<u8>> {
	let mut v = vec![b"pacman".to_vec()];
	v.push(format!("--config={}", fx.path("missing.conf")).into_bytes());
	v.extend(a.iter().map(|s| s.replace("@", &fx.path("")).into_bytes()));
	v
}

#[test]
fn fixed() {
	let fx = Fixture::new("fixed");
	let cases: &[&[&str]] = &[
		&[],
		&["-h"],
		&["--help", "-S"],
		&["-Sh"],
		&["-Qh"],
		&["-Rh"],
		&["-Uh"],
		&["-Dh"],
		&["-Th"],
		&["-Fh"],
		&["-V"],
		&["-QV", "-h"],
		&["-QS"],
		&["-QQ"],
		&["-QQQ"],
		&["-Q", "--foo"],
		&["-Qx"],
		&["-Q", "--co=x"],
		&["--db"],
		&["-Q", "-w"],
		&["-Q", "--force"],
		&["-T", "-k"],
		&["-T", "--asdeps"],
		&["-Qsi"],
		&["-Qs", "-g"],
		&["-Qo", "-g"],
		&["-Qpg"],
		&["-Qps"],
		&["-Qpo"],
		&["-Qsu"],
		&["-Qou"],
		&["-Qde"],
		&["-Qnm"],
		&["-Qgk"],
		&["-Sci"],
		&["-Sc", "--color=always", "-i"],
		&["--color=always", "-Q", "-w"],
		&["--color=never", "-Q", "-w"],
		&["--color=auto", "-Q", "-w"],
		&["--color=x", "-Q"],
		&["-Ssl"],
		&["-Sil"],
		&["-Slu"],
		&["-Sgu"],
		&["-Sgw"],
		&["-Sp", "--dbonly"],
		&["-Sp", "--noscriptlet"],
		&["-S", "--asdeps", "--asexplicit"],
		&["-D", "--asdeps", "--asexplicit"],
		&["-Dk", "--asdeps"],
		&["-Dk", "--asexplicit"],
		&["-Rn", "--print"],
		&["-Rn", "--dbonly"],
		&["-Rp", "--dbonly"],
		&["-Fx", "-l"],
		&["-Fs"],
		&["-b"],
		&["-Q", "-b", "@nope"],
		&["-Q", "--root=@nope"],
		&["-Q", "--cachedir", ""],
		&["-Q", "--hookdir=@hook", "--gpgdir=@gpg"],
		&["-Q", "--sysroot=@sys"],
		&["-Q", "--debug=3"],
		&["-Q", "--debug="],
		&["-Q", "--debug=1"],
		&["-Q", "--debug=2"],
		&["-Q", "--debug", "--arch=auto", "--arch", "x"],
		&["-Q", "--ask=-1"],
		&["-Q", "--ask=4294967296"],
		&["-Q", "--ask= 7"],
		&["-Q", "--ask=7 "],
		&["-Q", "--ask="],
		&["-Q", "--ask=99999999999999999999"],
		&["-Q", "--debug", "--", "-"],
		&["-T", "-"],
		&["-S", "-"],
		&["-Sy"],
		&["-Sl"],
		&["-U", "--print"],
		&["-Fy"],
		&["-Dk"],
		&["-D"],
		&["x", "-Q", "y", "--", "-S"],
	];
	for a in cases {
		compare(&fx, &args(&fx, a), None, false);
	}
	// stdin targets: empty lines and lines starting with NUL are skipped
	let stdin: &[&[u8]] = &[b"", b"\n\n", b"\0x\n", b"a\n", b"a\0b", b"x"];
	for s in stdin {
		compare(&fx, &args(&fx, &["-Q", "-", "-"]), Some(s), false);
		compare(
			&fx,
			&args(&fx, &["-T", "--debug", "-"]),
			Some(s),
			false,
		);
	}
	// POSIXLY_CORRECT stops at the first non-option
	compare(&fx, &args(&fx, &["-Q", "x", "-S"]), None, true);
	compare(&fx, &args(&fx, &["x", "-Q"]), None, true);
	// the usage line uses basename(argv[0]), getopt the whole argv[0]
	let mut a = args(&fx, &["-Sh"]);
	a[0] = b"/usr/bin/pacman".to_vec();
	compare(&fx, &a, None, false);
	a = args(&fx, &["--x"]);
	a[0] = b"./pac".to_vec();
	compare(&fx, &a, None, false);
}

// option letters the operations use, a few outside the optstring
const LETTERS: &[u8] = b"DFQRSTUVhcdefgiklmnopqstuvwxyaz";
const OPS: &[u8] = b"DFQRSTU";

// the long options an operation accepts, asked from the port: only
// steers the generator towards the checkargs_* conflicts
fn op_longs(op: u8) -> Vec<LongOpt> {
	LONGOPTS.iter()
		.filter(|o| {
			let name = String::from_utf8(o.name.to_vec()).unwrap();
			let arg = if o.has_arg == HasArg::No {
				format!("--{name}")
			} else {
				format!("--{name}=x")
			};
			let mut argv = vec![
				b"pacman".to_vec(),
				vec![b'-', op],
				arg.into_bytes(),
			];
			let mut io = Io::default();
			let _ = parseargs(
				&mut Config::new(),
				&mut argv,
				&mut io,
			);
			!lossy(&io.err).contains("invalid option '--")
		})
		.copied()
		.collect()
}

// the letters each operation accepts, so conflict checks get reached
fn op_letters(op: u8) -> &'static [u8] {
	match op {
		b'Q' => b"cdegiklmnopqstuv",
		b'S' => b"cdgilpqsuwyv",
		b'R' => b"cdnpsuv",
		b'U' => b"dpwv",
		b'D' => b"kqv",
		b'F' => b"dlpqxyv",
		_ => b"v",
	}
}

fn value(fx: &Fixture, rng: &mut Rng, name: &[u8]) -> String {
	match name {
		b"dbpath" | b"root" | b"cachedir" | b"hookdir" | b"gpgdir"
		| b"sysroot" => match rng.below(5) {
			0 => fx.path("nope"),
			1 => String::new(),
			_ => fx.path(DIRS[rng.below(DIRS.len())]),
		},
		b"config" => fx.path(&format!("missing{}.conf", rng.below(3))),
		b"color" => ["never", "auto", "always", "x", ""][rng.below(5)]
			.into(),
		b"debug" => ["1", "2", "0", "3", "", " 1", "1x"][rng.below(7)]
			.into(),
		b"ask" => ["0", "-1", "7", "4294967295", "4294967296", "x", ""]
			[rng.below(7)]
		.into(),
		b"arch" => ["auto", "x86_64", "a"][rng.below(3)].into(),
		_ => ["a,b", ",a,,b,", "", "x=1", "%n"][rng.below(5)].into(),
	}
}

fn token(fx: &Fixture, rng: &mut Rng, op: u8, out: &mut Vec<String>) {
	match rng.below(12) {
		0..=3 => {
			let mut t = String::from("-");
			for _ in 0..1 + rng.below(3) {
				let set = match rng.below(16) {
					0 => OPS,
					1 | 2 => LETTERS,
					_ => op_letters(op),
				};
				t.push(char::from(rng.pick(set)));
			}
			out.push(t);
		}
		4 => {
			let flag = ["-b", "-r"][rng.below(2)];
			let v = value(fx, rng, b"root");
			if rng.below(2) == 0 {
				out.push(format!("{flag}{v}"));
			} else {
				out.push(flag.into());
				out.push(v);
			}
		}
		5..=8 => {
			let valid = op_longs(op);
			let o = if rng.below(4) != 0 && !valid.is_empty() {
				valid[rng.below(valid.len())]
			} else {
				LONGOPTS[rng.below(LONGOPTS.len())]
			};
			let full = String::from_utf8(o.name.to_vec()).unwrap();
			// a detached --config could take a later token
			let attached = o.name == b"config" || rng.below(2) == 0;
			let name = if o.name == b"config" || rng.below(8) != 0 {
				full
			} else {
				full[..1 + rng.below(full.len())].to_string()
			};
			match o.has_arg {
				HasArg::No if rng.below(10) == 0 => {
					out.push(format!("--{name}=x"));
				}
				HasArg::No => out.push(format!("--{name}")),
				_ if attached => {
					let v = value(fx, rng, o.name);
					out.push(format!("--{name}={v}"));
				}
				HasArg::Optional => {
					out.push(format!("--{name}"))
				}
				HasArg::Required => {
					out.push(format!("--{name}"));
					if rng.below(8) != 0 {
						out.push(value(
							fx, rng, o.name,
						));
					}
				}
			}
		}
		9 => out.push(["pkg", "-", "", "a b"][rng.below(4)].into()),
		10 => out.push("--".into()),
		_ => out.push(format!(
			"--{}",
			["nope", "c", "s", "d"][rng.below(4)]
		)),
	}
}

// one operation in most argvs, so the per-op checks get reached
fn gen_argv(fx: &Fixture, rng: &mut Rng) -> Vec<Vec<u8>> {
	let mut t = Vec::new();
	let op = rng.pick(OPS);
	if rng.below(4) != 0 {
		t.push(format!("-{}", char::from(op)));
	}
	for _ in 0..rng.below(6) {
		token(fx, rng, op, &mut t);
	}
	// keep the C off the real config: no token may be "--config"
	t.retain(|s| s != "--config");
	let n = t.len();
	if n > 0 {
		let i = rng.below(n);
		t.swap(0, i);
	}
	let refs: Vec<&str> = t.iter().map(String::as_str).collect();
	let mut a = args(fx, &refs);
	// targets from stdin now and then
	if rng.below(8) == 0 {
		a.push(b"--".to_vec());
		a.push(b"-".to_vec());
	}
	a
}

// process spawning dominates: runs are spread over threads
const WORKERS: u64 = 8;

#[derive(Default)]
struct Tally {
	exit0: usize,
	valid: usize,
	conflicts: usize,
}

impl Tally {
	fn add(&mut self, status: i32, err: &str) {
		self.exit0 += usize::from(status == 0);
		// parseargs accepted it: stopped by a check after it
		let past = [
			"could not be read",
			"you cannot perform",
			"argument '-' specified",
		];
		self.valid += usize::from(past.iter().any(|p| err.contains(p)));
		let conflict = err.contains("may not be used together");
		self.conflicts += usize::from(conflict);
	}

	fn merge(&mut self, o: Tally) {
		self.exit0 += o.exit0;
		self.valid += o.valid;
		self.conflicts += o.conflicts;
	}
}

fn fuzz_worker(fx: &Fixture, seed: u64, n: usize) -> Tally {
	let mut rng = Rng::new(seed);
	let mut t = Tally::default();
	let stdin: [&[u8]; 3] = [b"", b"a\nb\n", b"\n"];
	for _ in 0..n {
		let argv = gen_argv(fx, &mut rng);
		let s = stdin[rng.below(3)];
		let posix = rng.below(16) == 0;
		let (status, err) = compare(fx, &argv, Some(s), posix);
		t.add(status, &err);
	}
	t
}

#[test]
fn fuzz() {
	let fx = Fixture::new("fuzz");
	let n = iters() / 100;
	let per = n / WORKERS as usize;
	let mut t = Tally::default();
	std::thread::scope(|s| {
		let fx = &fx;
		let hs: Vec<_> = (0..WORKERS)
			.map(|w| {
				s.spawn(move || {
					fuzz_worker(fx, 0x7061_636d + w, per)
				})
			})
			.collect();
		for h in hs {
			t.merge(h.join().unwrap());
		}
	});
	let n = per * WORKERS as usize;
	eprintln!(
		"{n} runs: exit 0 {}, valid {}, conflicts {}",
		t.exit0, t.valid, t.conflicts
	);
	assert!(t.exit0 > n / 100, "exit 0 only {} of {n}", t.exit0);
	assert!(t.valid > n / 10, "valid only {} of {n}", t.valid);
	assert!(
		t.conflicts > n / 100,
		"conflicts only {} of {n}",
		t.conflicts
	);
}

// every pair (and repeated single) of the flags an operation accepts:
// reaches each checkargs_* conflict and the repeat counters
fn pairs_op(fx: &Fixture, op: u8) -> Tally {
	let mut longs = op_longs(op);
	longs.retain(|o| o.has_arg == HasArg::No);
	let mut t = Tally::default();
	for (i, a) in longs.iter().enumerate() {
		for b in &longs[i..] {
			let names = [a.name, b.name].map(|n| {
				String::from_utf8_lossy(n).into_owned()
			});
			let t3 = [
				format!("-{}", char::from(op)),
				format!("--{}", names[0]),
				format!("--{}", names[1]),
			];
			let refs: Vec<&str> =
				t3.iter().map(String::as_str).collect();
			let (status, err) =
				compare(fx, &args(fx, &refs), None, false);
			t.add(status, &err);
		}
	}
	t
}

#[test]
fn pairs() {
	let fx = Fixture::new("pairs");
	let mut t = Tally::default();
	std::thread::scope(|s| {
		let fx = &fx;
		let hs: Vec<_> = OPS
			.iter()
			.map(|&op| s.spawn(move || pairs_op(fx, op)))
			.collect();
		for h in hs {
			t.merge(h.join().unwrap());
		}
	});
	eprintln!("pairs: {} conflicts", t.conflicts);
	// one per invalid_opt call site at least
	assert!(t.conflicts >= 60, "only {} conflicts", t.conflicts);
}
