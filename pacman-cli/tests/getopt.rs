// unit tests of pacman_cli::getopt with pacman's option table
use pacman_cli::getopt::{Getopt, HasArg, LongOpt};
use pacman_cli::pacman::{LONGOPTS, OP_DBPATH, OP_DEBUG, OPTSTRING};

// (return, optarg) of every call until -1, the stderr text, the final
// argv and optind
struct Run {
	opts: Vec<(i32, Option<String>)>,
	err: String,
	argv: Vec<String>,
	optind: usize,
}

fn run_with(args: &[&str], optstring: &[u8], longopts: &[LongOpt]) -> Run {
	let mut argv: Vec<Vec<u8>> =
		args.iter().map(|a| a.as_bytes().to_vec()).collect();
	let mut g = Getopt::new(false);
	let (mut ind, mut err) = (0, Vec::new());
	let mut opts = Vec::new();
	loop {
		let r = g.getopt_long(
			&mut argv, optstring, longopts, &mut ind, &mut err,
		);
		if r == -1 {
			break;
		}
		let arg =
			g.optarg.as_ref()
				.map(|a| String::from_utf8_lossy(a).into());
		opts.push((r, arg));
	}
	Run {
		opts,
		err: String::from_utf8(err).unwrap(),
		argv: argv
			.iter()
			.map(|a| String::from_utf8_lossy(a).into())
			.collect(),
		optind: g.optind,
	}
}

fn run(args: &[&str]) -> Run {
	run_with(args, OPTSTRING, LONGOPTS)
}

fn c(ch: u8) -> i32 {
	i32::from(ch)
}

#[test]
fn clusters_and_arguments() {
	let r = run(&["p", "-Syu", "-bdb", "-r", "root"]);
	let want: Vec<(i32, Option<String>)> = vec![
		(c(b'S'), None),
		(c(b'y'), None),
		(c(b'u'), None),
		(c(b'b'), Some("db".into())),
		(c(b'r'), Some("root".into())),
	];
	assert_eq!(r.opts, want);
	assert_eq!(r.optind, 5);
	assert_eq!(r.err, "");
}

#[test]
fn permutation() {
	let r = run(&["p", "a", "-S", "b", "--dbpath", "x", "c"]);
	assert_eq!(r.argv, ["p", "-S", "--dbpath", "x", "a", "b", "c"]);
	assert_eq!(r.optind, 4);
	assert_eq!(r.opts[1], (OP_DBPATH, Some("x".into())));
}

#[test]
fn double_dash() {
	let r = run(&["p", "a", "--", "-S"]);
	assert!(r.opts.is_empty());
	assert_eq!(r.argv, ["p", "--", "a", "-S"]);
	assert_eq!(r.optind, 2);
	// a lone "-" is a non-option
	let r = run(&["p", "-", "-Q"]);
	assert_eq!(r.argv, ["p", "-Q", "-"]);
	assert_eq!(r.optind, 2);
}

#[test]
fn posixly_correct_stops_at_non_option() {
	let mut argv: Vec<Vec<u8>> = ["p", "a", "-S"]
		.iter()
		.map(|a| a.as_bytes().to_vec())
		.collect();
	let mut g = Getopt::new(true);
	let (mut ind, mut err) = (0, Vec::new());
	let r = g.getopt_long(
		&mut argv, OPTSTRING, LONGOPTS, &mut ind, &mut err,
	);
	assert_eq!((r, g.optind), (-1, 1));
}

#[test]
fn abbreviations() {
	let r = run(&["p", "--sync", "--sysr=/", "--deb=2", "--deb"]);
	assert_eq!(r.opts[0].0, c(b'S'));
	assert_eq!(r.opts[1].1.as_deref(), Some("/"));
	assert_eq!(r.opts[2], (OP_DEBUG, Some("2".into())));
	assert_eq!(r.opts[3], (OP_DEBUG, None));
	let r = run(&["p", "--db"]);
	assert_eq!(r.opts, [(c(b'?'), None)]);
	assert_eq!(
		r.err,
		"p: option '--db' is ambiguous; possibilities: '--dbpath' \
		'--dbonly'\n"
	);
	// the whole word with its "=value" is quoted
	let r = run(&["p", "--co=x"]);
	assert_eq!(
		r.err,
		"p: option '--co=x' is ambiguous; possibilities: '--confirm' \
		'--config' '--color'\n"
	);
}

#[test]
fn duplicates_not_ambiguous() {
	let t = [
		LongOpt {
			name: b"ab",
			has_arg: HasArg::No,
			val: 1,
		},
		LongOpt {
			name: b"abc",
			has_arg: HasArg::No,
			val: 1,
		},
	];
	let r = run_with(&["p", "--a"], b"", &t);
	assert_eq!(r.opts, [(1, None)]);
}

#[test]
fn error_texts() {
	let r = run(&["/bin/p", "-a", "--nope=1", "--sync=x", "--root", "-:"]);
	assert_eq!(
		r.err,
		"/bin/p: invalid option -- 'a'\n\
		/bin/p: unrecognized option '--nope=1'\n\
		/bin/p: option '--sync' doesn't allow an argument\n"
	);
	// --root took "-:" as its argument
	assert_eq!(r.opts[3], (pacman_cli::pacman::OP_ROOT, Some("-:".into())));
	let r = run(&["p", "-b"]);
	assert_eq!(r.err, "p: option requires an argument -- 'b'\n");
	let r = run(&["p", "--root"]);
	assert_eq!(r.err, "p: option '--root' requires an argument\n");
	// a leading ':' silences errors and reports missing arguments
	let r = run_with(&["p", "-b", "-x"], b":b:", LONGOPTS);
	assert_eq!(r.opts, [(c(b'b'), Some("-x".into()))]);
	let r = run_with(&["p", "-b"], b":b:", LONGOPTS);
	assert_eq!((r.opts[0].0, r.err.as_str()), (c(b':'), ""));
}

#[test]
fn optional_short_argument() {
	let r = run_with(&["p", "-bx", "-b", "y"], b"b::", LONGOPTS);
	assert_eq!(r.opts, [(c(b'b'), Some("x".into())), (c(b'b'), None)]);
	assert_eq!(r.argv, ["p", "-bx", "-b", "y"]);
}

#[test]
fn return_in_order() {
	let r = run_with(&["p", "a", "-S"], b"-S", LONGOPTS);
	assert_eq!(r.opts, [(1, Some("a".into())), (c(b'S'), None)]);
}
