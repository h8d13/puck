// pacman_cli::getopt against glibc getopt_long: same argv, optstring and
// long table, compared after every call (return, optind, optopt, optarg,
// longind, stderr) and on the final argv permutation. two passes per run
// like parseargs, the second from optind = 1
use difftest::{GetoptRun, GetoptStep, Rng, c_getopt_run, iters};
use pacman_cli::getopt::{Getopt, HasArg, LongOpt};
use pacman_cli::pacman::{LONGOPTS, OPTSTRING};

fn rust_run(
	argv: &[Vec<u8>],
	optstring: &[u8],
	longopts: &[LongOpt],
	print_errors: bool,
	passes: usize,
	longind: usize,
) -> GetoptRun {
	let mut argv = argv.to_vec();
	let mut g = Getopt::new(false);
	g.opterr = print_errors;
	let mut ind = longind;
	let mut steps = Vec::new();
	for pass in 0..passes {
		g.optind = if pass == 0 { 0 } else { 1 };
		loop {
			let mut err = Vec::new();
			let ret = g.getopt_long(
				&mut argv, optstring, longopts, &mut ind,
				&mut err,
			);
			steps.push(GetoptStep {
				ret,
				optind: g.optind,
				optopt: g.optopt,
				optarg: g.optarg.clone(),
				longind: ind,
				stderr: String::from_utf8_lossy(&err)
					.into_owned(),
			});
			if ret == -1 {
				break;
			}
		}
	}
	GetoptRun { steps, argv }
}

fn show(argv: &[Vec<u8>]) -> Vec<String> {
	argv.iter()
		.map(|a| String::from_utf8_lossy(a).into_owned())
		.collect()
}

fn compare_with(
	argv: &[Vec<u8>],
	optstring: &[u8],
	longopts: &[LongOpt],
	print_errors: bool,
) -> GetoptRun {
	let c = c_getopt_run(argv, optstring, longopts, print_errors, 2, 7);
	let r = rust_run(argv, optstring, longopts, print_errors, 2, 7);
	let ctx = || {
		format!(
			"argv {:?} optstring {:?} opterr {print_errors}\n\
			c {:?}\nrust {:?}",
			show(argv),
			String::from_utf8_lossy(optstring),
			c.steps,
			r.steps
		)
	};
	for (i, (cs, rs)) in c.steps.iter().zip(&r.steps).enumerate() {
		assert_eq!(rs, cs, "step {i} differs\n{}", ctx());
	}
	assert_eq!(r.steps.len(), c.steps.len(), "step count\n{}", ctx());
	assert_eq!(show(&r.argv), show(&c.argv), "permutation\n{}", ctx());
	c
}

fn compare(argv: &[&str]) -> GetoptRun {
	let argv: Vec<Vec<u8>> =
		argv.iter().map(|a| a.as_bytes().to_vec()).collect();
	compare_with(&argv, OPTSTRING, LONGOPTS, true)
}

fn errors(run: &GetoptRun) -> String {
	run.steps.iter().map(|s| s.stderr.as_str()).collect()
}

#[test]
fn fixed() {
	let cases: &[&[&str]] = &[
		&["pacman"],
		&["pacman", "-Syu"],
		&["pacman", "a", "-S", "b", "-y", "c"],
		&["pacman", "-b", "db", "x", "-rroot", "y"],
		&["pacman", "x", "--", "-S", "y"],
		&["pacman", "--", "--"],
		&["pacman", "-"],
		&["pacman", ""],
		&["pacman", "-S", "-b"],
		&["pacman", "--dbpath"],
		&["pacman", "--dbpath=x", "--dbpath", "y"],
		&["pacman", "--db"],
		&["pacman", "--co=x"],
		&["pacman", "--conf"],
		&["pacman", "--sync=x"],
		&["pacman", "--sy"],
		&["pacman", "--debug", "1"],
		&["pacman", "--debug=2"],
		&["pacman", "--debug="],
		&["pacman", "--deb"],
		&["pacman", "--d"],
		&["pacman", "--="],
		&["pacman", "--=x"],
		&["pacman", "--nope", "-S"],
		&["pacman", "-Sa", "-:", "-;", "-W", "-\u{e9}"],
		&["pacman", "-S-y"],
		&["pacman", "--machine", "--disable-sandbox"],
		&["pacman", "--disable-sandbox-s"],
		&["pacman", "--print-format", "--", "x"],
		&["pacman", "a", "b", "--", "c", "-S"],
	];
	for argv in cases {
		compare(argv);
	}
	let e = errors(&compare(&["/usr/bin/pacman", "--db", "--x", "-a"]));
	assert_eq!(
		e,
		"/usr/bin/pacman: option '--db' is ambiguous; possibilities: \
		'--dbpath' '--dbonly'\n\
		/usr/bin/pacman: unrecognized option '--x'\n\
		/usr/bin/pacman: invalid option -- 'a'\n\
		/usr/bin/pacman: option '--db' is ambiguous; possibilities: \
		'--dbpath' '--dbonly'\n\
		/usr/bin/pacman: unrecognized option '--x'\n\
		/usr/bin/pacman: invalid option -- 'a'\n"
	);
}

// optstring prefixes ('+', '-', ':') and an optional short argument,
// not used by pacman but part of the same parser
#[test]
fn optstring_modes() {
	let modes: &[&[u8]] = &[
		b"+DFQRSb:y",
		b"-DFQRSb:y",
		b":DFQRSb:y",
		b"+:Sb::y",
		b"Sb::y",
	];
	let cases: &[&[&str]] = &[
		&["p", "a", "-S", "b", "-y"],
		&["p", "-S", "x", "--", "-y"],
		&["p", "-b"],
		&["p", "--dbpath"],
		&["p", "-bx", "-b", "y"],
		&["p", "-z", "--nope", "--sync=1"],
	];
	for m in modes {
		for argv in cases {
			let argv: Vec<Vec<u8>> = argv
				.iter()
				.map(|a| a.as_bytes().to_vec())
				.collect();
			compare_with(&argv, m, LONGOPTS, true);
			compare_with(&argv, m, LONGOPTS, false);
		}
	}
}

// exact duplicates (same has_arg and val) are not ambiguous
const DUPS: &[LongOpt] = &[
	LongOpt {
		name: b"alpha",
		has_arg: HasArg::No,
		val: 1,
	},
	LongOpt {
		name: b"alphabet",
		has_arg: HasArg::No,
		val: 1,
	},
	LongOpt {
		name: b"alps",
		has_arg: HasArg::Required,
		val: 2,
	},
	LongOpt {
		name: b"alpine",
		has_arg: HasArg::No,
		val: 1,
	},
	LongOpt {
		name: b"beta",
		has_arg: HasArg::Optional,
		val: 3,
	},
	LongOpt {
		name: b"betamax",
		has_arg: HasArg::Optional,
		val: 3,
	},
];

#[test]
fn duplicates() {
	for a in ["--alph", "--alp", "--alpha", "--al=x", "--bet", "--bet=1"] {
		let argv = vec![b"p".to_vec(), a.as_bytes().to_vec()];
		compare_with(&argv, b"ab", DUPS, true);
	}
}

// pieces the C special-cases: option letters, letters outside the
// optstring, ':' ';' '-', '=' and bytes >= 0x80
const SHORT: &[u8] = b"DFQRSTUVhbrcdefgiklmnopqstuvwxyaAzW:;-=?\xe9\xff";

fn long_name(rng: &mut Rng) -> Vec<u8> {
	match rng.below(6) {
		0 => rng.bytes(b"abcdeilmnoprstuy-=", 6),
		_ => {
			let name = LONGOPTS[rng.below(LONGOPTS.len())].name;
			// prefixes: unique, ambiguous or empty abbreviations
			let n = if rng.below(2) == 0 {
				name.len()
			} else {
				rng.below(name.len() + 1)
			};
			name[..n].to_vec()
		}
	}
}

fn token(rng: &mut Rng) -> Vec<u8> {
	match rng.below(10) {
		0 | 1 => rng.bytes(b"abc-x/", 5),
		2 => b"--".to_vec(),
		3 => b"-".to_vec(),
		4..=6 => {
			let mut t = vec![b'-'];
			t.extend((0..1 + rng.below(4)).map(|_| rng.pick(SHORT)));
			t
		}
		_ => {
			let mut t = b"--".to_vec();
			t.extend(long_name(rng));
			if rng.below(3) == 0 {
				t.push(b'=');
				t.extend(rng.bytes(b"a1=-", 4));
			}
			t
		}
	}
}

fn fuzz_run(seed: u64, optstring: &[u8], n: usize) {
	let mut rng = Rng::new(seed);
	let argv0: [&[u8]; 2] = [b"pacman", b"/usr/bin/pacman"];
	for _ in 0..n {
		let mut argv = vec![argv0[rng.below(2)].to_vec()];
		argv.extend((0..rng.below(8)).map(|_| token(&mut rng)));
		compare_with(&argv, optstring, LONGOPTS, rng.below(8) != 0);
	}
}

#[test]
fn fuzz() {
	fuzz_run(0x6e70_6f70, OPTSTRING, iters());
}

#[test]
fn fuzz_modes() {
	let n = iters() / 8;
	fuzz_run(11, b"+DFQRSTUVb:cdefghiklmnopqr:stuvwxy", n);
	fuzz_run(12, b"-DFQRSTUVb:cdefghiklmnopqr:stuvwxy", n);
	fuzz_run(13, b":DFQRSTUVb:cdefghiklmnopqr::stuvwxy", n);
}
