// unit tests of pacman_cli::pacman: the Config parseargs fills for valid
// invocations (the C binary only shows it through later operations),
// targets, exit statuses, stdin targets and needs_root
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use pacman_cli::conf::{
	ColStr, Config, LOG_DEBUG, LOG_ERROR, LOG_FUNCTION, LOG_WARNING,
	PM_COLOR_OFF, PM_COLOR_ON, PM_OP_MAIN,
};
use pacman_cli::pacman::*;

struct Dir(PathBuf);

impl Dir {
	fn new() -> Dir {
		static N: AtomicUsize = AtomicUsize::new(0);
		let n = N.fetch_add(1, Ordering::Relaxed);
		let p = std::env::temp_dir().join(format!(
			"pacman-cli-args-{}-{n}",
			std::process::id()
		));
		if p.exists() {
			fs::remove_dir_all(&p).unwrap();
		}
		fs::create_dir_all(p.join("sub")).unwrap();
		Dir(p)
	}

	fn s(&self) -> String {
		self.0.to_str().unwrap().to_string()
	}
}

impl Drop for Dir {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).unwrap();
	}
}

struct Parsed {
	config: Config,
	r: Result<Vec<Vec<u8>>, i32>,
	io: Io,
}

fn parse(args: &[&str]) -> Parsed {
	let mut argv: Vec<Vec<u8>> = std::iter::once("pacman")
		.chain(args.iter().copied())
		.map(|a| a.as_bytes().to_vec())
		.collect();
	let mut config = Config::new();
	let mut io = Io::default();
	let r = parseargs(&mut config, &mut argv, &mut io);
	Parsed { config, r, io }
}

fn ok(args: &[&str]) -> Config {
	let p = parse(args);
	assert!(
		p.r.is_ok(),
		"{args:?}: {}",
		String::from_utf8_lossy(&p.io.err)
	);
	p.config
}

fn err(args: &[&str]) -> String {
	let p = parse(args);
	assert_eq!(p.r, Err(1), "{args:?}");
	String::from_utf8(p.io.err).unwrap()
}

fn targets(args: &[&str]) -> Vec<String> {
	let p = parse(args);
	let t = p.r.unwrap();
	t.iter().map(|t| String::from_utf8_lossy(t).into())
		.collect()
}

#[test]
fn operations() {
	assert_eq!(ok(&[]).op, PM_OP_MAIN);
	assert_eq!(ok(&["-Q"]).op, PM_OP_QUERY);
	assert_eq!(ok(&["--sync"]).op, PM_OP_SYNC);
	assert_eq!(ok(&["-R"]).op, PM_OP_REMOVE);
	assert_eq!(ok(&["-U"]).op, PM_OP_UPGRADE);
	assert_eq!(ok(&["-D"]).op, PM_OP_DATABASE);
	assert_eq!(ok(&["-T"]).op, PM_OP_DEPTEST);
	assert_eq!(ok(&["-F"]).op, PM_OP_FILES);
	assert_eq!(
		err(&["-QS"]),
		"error: only one operation may be used at a time\n"
	);
	assert_eq!(
		err(&["-Q", "-Q"]),
		"error: only one operation may be used at a time\n"
	);
}

#[test]
fn help_and_version() {
	let p = parse(&["-Sh", "-V"]);
	assert_eq!(p.r, Err(0));
	let out = String::from_utf8(p.io.out).unwrap();
	assert!(out.starts_with("usage:  pacman {-S --sync} [options]"));
	// short options first, then long ones, each sorted
	let b = out.find("  -b, --dbpath").unwrap();
	let y = out.find("  -y, --refresh").unwrap();
	let arch = out.find("      --arch").unwrap();
	assert!(b < y && y < arch, "{out}");
	let p = parse(&["-V"]);
	assert_eq!(p.r, Err(0));
	let out = String::from_utf8(p.io.out).unwrap();
	assert!(out.contains("Pacman v7.1.0 - libalpm v16.0.1\n"));
	let mut main = Vec::new();
	usage(&mut main, PM_OP_MAIN, b"pac");
	let main = String::from_utf8(main).unwrap();
	assert!(main
		.starts_with("usage:  pac <operation> [...]\noperations:\n"));
	assert!(main.contains("    pac {-U --upgrade}  [options] <file(s)>\n"));
}

#[test]
fn query_flags() {
	// filled before checkargs rejects the mix
	let c = parse(&["-Qiikkttg", "-cdlmnopqsu"]).config;
	assert_eq!(
		(c.op_q_info, c.op_q_check, c.op_q_unrequired, c.group),
		(2, 2, 2, 1)
	);
	assert_eq!(c.op_q_changelog + c.op_q_deps + c.op_q_list, 3);
	assert_eq!(c.op_q_locality, PKG_LOCALITY_NATIVE | PKG_LOCALITY_FOREIGN);
	assert_eq!(c.op_q_owns + c.op_q_isfile + c.quiet, 3);
	assert_eq!(c.op_q_search + c.op_q_upgrade, 2);
	// the parse fills, checkargs rejects: -p wins the first branch
	let p = parse(&["-Qpg"]);
	assert_eq!(p.config.op_q_isfile, 1);
	assert_eq!(p.r, Err(1));
}

#[test]
fn sync_flags() {
	let c = ok(&["-Syyuu", "--needed", "-w", "--asdeps", "-dd"]);
	assert_eq!((c.op_s_sync, c.op_s_upgrade), (2, 2));
	assert_eq!(c.op_s_downloadonly, 1);
	let want = TRANS_FLAG_NEEDED
		| TRANS_FLAG_DOWNLOADONLY
		| TRANS_FLAG_NOCONFLICTS
		| TRANS_FLAG_ALLDEPS
		| TRANS_FLAG_NODEPVERSION
		| TRANS_FLAG_NODEPS;
	assert_eq!(c.flags, want);
	let c = ok(&["-Scc"]);
	assert_eq!(c.op_s_clean, 2);
	let c = ok(&["-Siiq"]);
	assert_eq!((c.op_s_info, c.quiet), (2, 1));
	let c = ok(&["-Sgg"]);
	assert_eq!(c.group, 2);
	let c = ok(&["-Ss", "-q"]);
	assert_eq!((c.op_s_search, c.op_q_list), (1, 0));
}

#[test]
fn trans_flags_and_lists() {
	let c = ok(&["-Rss", "-c", "-n", "-u", "--noscriptlet"]);
	let want =
		TRANS_FLAG_RECURSE
			| TRANS_FLAG_RECURSEALL
			| TRANS_FLAG_CASCADE | TRANS_FLAG_NOSAVE
			| TRANS_FLAG_UNNEEDED | TRANS_FLAG_NOSCRIPTLET;
	assert_eq!(c.flags, want);
	let c = ok(&["-R", "--dbonly", "--noprogressbar"]);
	let want =
		TRANS_FLAG_DBONLY | TRANS_FLAG_NOSCRIPTLET | TRANS_FLAG_NOHOOKS;
	assert_eq!((c.flags, c.noprogressbar), (want, 1));
	let c = ok(&[
		"-U",
		"--print-format",
		"%n %v",
		"--assume-installed=a,b",
	]);
	assert_eq!(
		(c.print, c.print_format.as_deref()),
		(1, Some(&b"%n %v"[..]))
	);
	assert_eq!(c.assumeinstalled, [b"a".to_vec(), b"b".to_vec()]);
	// strtok_r drops empty fields
	let c = ok(&[
		"-S",
		"--ignore",
		",a,,b,",
		"--ignore=c",
		"--ignoregroup=",
	]);
	assert_eq!(c.ignorepkg, [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
	assert!(c.ignoregrp.is_empty());
	let c = ok(&["-S", "--overwrite", "/x/*"]);
	assert_eq!(c.overwrite_files, [b"/x/*".to_vec()]);
	let c = ok(&["-D", "--asexplicit", "-q"]);
	assert_eq!((c.flags, c.quiet), (TRANS_FLAG_ALLEXPLICIT, 1));
	// -F takes the transaction options too, and ignores them
	let c = ok(&["-Fxyy", "--machinereadable", "-p", "-l"]);
	assert_eq!((c.op_f_regex, c.op_s_sync, c.op_q_list), (1, 2, 1));
	assert_eq!((c.op_f_machinereadable, c.print), (1, 1));
}

#[test]
fn global_options() {
	let d = Dir::new();
	let sub = format!("{}/sub", d.s());
	let dotted = format!("{}/sub/../sub", d.s());
	let c = ok(&[
		"-Tvv",
		"--verbose",
		"-b",
		&dotted,
		&format!("-r{sub}"),
		&format!("--cachedir={sub}"),
		"--cachedir",
		&d.s(),
		&format!("--hookdir={sub}"),
		&format!("--gpgdir={sub}"),
		&format!("--sysroot={sub}"),
		"--config",
		"rel.conf",
		"--logfile=/l",
		"--arch=x",
		"--arch",
		"y",
		"--noconfirm",
		"--disable-sandbox",
		"--disable-download-timeout",
	]);
	let sub = sub.into_bytes();
	assert_eq!(c.verbose, 3);
	assert_eq!(c.dbpath.as_ref(), Some(&sub));
	assert_eq!(c.rootdir.as_ref(), Some(&sub));
	assert_eq!(c.cachedirs, [sub.clone(), d.s().into_bytes()]);
	assert_eq!(c.hookdirs, std::slice::from_ref(&sub));
	assert_eq!(c.gpgdir.as_ref(), Some(&sub));
	assert_eq!(c.sysroot.as_ref(), Some(&sub));
	assert_eq!(c.configfile.as_deref(), Some(&b"rel.conf"[..]));
	assert_eq!(c.logfile.as_deref(), Some(&b"/l"[..]));
	assert_eq!(c.architectures, [b"x".to_vec(), b"y".to_vec()]);
	assert_eq!(c.noconfirm, 1);
	assert_eq!(
		(c.disable_sandbox_filesystem, c.disable_sandbox_syscalls),
		(1, 1)
	);
	assert_eq!(c.disable_dl_timeout, 1);
	assert_eq!(ok(&["--noconfirm", "--confirm"]).noconfirm, 0);
	// strndup(optarg, PATH_MAX)
	let long = "a".repeat(5000);
	let c = ok(&["--config", &long, "--logfile", &long]);
	assert_eq!(c.configfile.unwrap().len(), 4096);
	assert_eq!(c.logfile.unwrap().len(), 4096);
	assert!(err(&["-b", "/nonexistent/x"]).starts_with(
		"error: 'failed to resolve path '/nonexistent/x' passed to \
		'--dbpath': No such file or directory\n"
	));
}

#[test]
fn debug_ask_color() {
	let base = LOG_ERROR | LOG_WARNING;
	let c = ok(&["--debug"]);
	assert_eq!((c.logmask, c.noprogressbar), (base | LOG_DEBUG, 1));
	assert_eq!(ok(&["--debug=1"]).logmask, base | LOG_DEBUG);
	assert_eq!(ok(&["--debug=2"]).logmask, base | LOG_DEBUG | LOG_FUNCTION);
	assert_eq!(
		ok(&["--debug= +2"]).logmask,
		base | LOG_DEBUG | LOG_FUNCTION
	);
	for bad in ["0", "3", "", "2 ", "x", "99999999999999999999"] {
		let e = err(&[&format!("--debug={bad}")]);
		assert_eq!(
			e,
			format!("error: '{bad}' is not a valid debug level\n")
		);
	}
	let c = ok(&["--ask=7"]);
	assert_eq!((c.noask, c.ask), (1, 7));
	// strtol takes a long: negative values wrap into the unsigned int
	assert_eq!(ok(&["--ask=-1"]).ask, u32::MAX);
	assert_eq!(ok(&["--ask=4294967295"]).ask, u32::MAX);
	for bad in ["4294967296", "", "1x"] {
		let e = err(&[&format!("--ask={bad}")]);
		assert_eq!(
			e,
			format!("error: '{bad}' is not a valid ask level\n")
		);
	}
	let c = ok(&["--color=always"]);
	assert_eq!((c.color, c.colstr), (PM_COLOR_ON, ColStr::COLOR));
	let c = ok(&["--color=always", "--color=never"]);
	assert_eq!((c.color, c.colstr), (PM_COLOR_OFF, ColStr::PLAIN));
	assert_eq!(ok(&["--color=auto"]).color, PM_COLOR_OFF);
	assert_eq!(
		err(&["--color=x"]),
		"error: invalid argument 'x' for --color\n"
	);
	// later errors use the colors set before them
	let e = err(&["--color=always", "-Q", "-w"]);
	assert_eq!(e, "\x1b[1;31merror: \x1b[0minvalid option '-w'\n");
}

#[test]
fn invalid_options() {
	assert_eq!(err(&["-Q", "-w"]), "error: invalid option '-w'\n");
	assert_eq!(
		err(&["-T", "--asdeps"]),
		"error: invalid option '--asdeps'\n"
	);
	assert_eq!(
		err(&["-S", "--force"]),
		"error: invalid option '--force'\n"
	);
	assert_eq!(err(&["-Fs"]), "error: invalid option '-s'\n");
	assert_eq!(err(&["--x"]), "pacman: unrecognized option '--x'\n");
}

#[test]
fn conflicts() {
	let cases: &[(&[&str], &str, &str)] = &[
		(
			&["-D", "--asdeps", "--asexplicit"],
			"--asdeps",
			"--asexplicit",
		),
		(&["-Dk", "--asexplicit"], "--asexplicit", "--check"),
		(&["-Qpo"], "--file", "--owns"),
		(&["-Qsk"], "--search", "--check"),
		(&["-Qou"], "--owns", "--upgrade"),
		(&["-Qgl"], "--groups", "--list"),
		(&["-Qde"], "--deps", "--explicit"),
		(&["-Qmn"], "--native", "--foreign"),
		(&["-Sp", "--dbonly"], "--print", "--dbonly"),
		(&["-Rn", "--dbonly"], "--nosave", "--dbonly"),
		(
			&["-U", "--asdeps", "--asexplicit"],
			"--asdeps",
			"--asexplicit",
		),
		(&["-Scy"], "--clean", "--refresh"),
		(&["-Siw"], "--info", "--downloadonly"),
		(&["-Ssu"], "--search", "--sysupgrade"),
		(&["-Slg"], "--list", "--groups"),
		(&["-Sgu"], "--groups", "--sysupgrade"),
	];
	for (args, a, b) in cases {
		assert_eq!(
			err(args),
			format!(
				"error: invalid option: '{a}' and '{b}' may not be \
				used together\n"
			),
			"{args:?}"
		);
	}
	// the -F check looks at op_q_search, never set under -F
	ok(&["-Fxl"]);
}

#[test]
fn target_collection() {
	assert_eq!(
		targets(&["a", "-Q", "b", "--", "-S", "c"]),
		["a", "b", "-S", "c"]
	);
	assert_eq!(targets(&["-Q", "-b", "/", "x", "-"]), ["x", "-"]);
	let c = Config::new();
	let mut io = Io::default();
	let mut t = vec![b"-".to_vec(), b"a".to_vec(), b"-".to_vec()];
	let stdin = b"x\n\n\0y\nz\0w\nlast";
	stdin_targets(&c, &mut t, Some(stdin), || Ok(()), &mut io).unwrap();
	let want: [&[u8]; 5] = [b"a", b"-", b"x", b"z", b"last"];
	assert_eq!(t, want);
	let mut t = vec![b"-".to_vec()];
	let r = stdin_targets(&c, &mut t, Some(b"\n"), || Err(6), &mut io);
	assert_eq!(r, Err(1));
	assert_eq!(
		String::from_utf8(io.err).unwrap(),
		"error: failed to reopen stdin for reading: (No such device or \
		address)\nerror: argument '-' specified with empty stdin\n"
	);
	let mut io = Io::default();
	let mut t = vec![b"-".to_vec()];
	assert_eq!(stdin_targets(&c, &mut t, None, || Ok(()), &mut io), Err(1));
	assert_eq!(
		String::from_utf8(io.err).unwrap(),
		"error: argument '-' specified without input on stdin\n"
	);
}

#[test]
fn root_operations() {
	let root = |args: &[&str]| needs_root(&ok(args));
	assert!(root(&["-S"]) && root(&["-Sy"]) && root(&["-Sc"]));
	assert!(root(&["-R"])
		&& root(&["-U"])
		&& root(&["-D"])
		&& root(&["-Fy"]));
	assert!(!root(&["-Ss"]) && !root(&["-Si"]) && !root(&["-Sl"]));
	assert!(!root(&["-Sg"]) && !root(&["-Sp"]) && !root(&["-Rp"]));
	assert!(!root(&["-Dk"])
		&& !root(&["-F"])
		&& !root(&["-Q"])
		&& !root(&["-T"]));
	let mut argv = vec![b"pacman".to_vec(), b"-S".to_vec()];
	let mut io = Io::default();
	let process = Process {
		uid: 1000,
		stdin: None,
		reopen_tty: || Ok(()),
	};
	assert_eq!(main_args(&mut argv, process, &mut io).err(), Some(1));
	assert_eq!(
		String::from_utf8(io.err).unwrap(),
		"error: you cannot perform this operation unless you are root.\n"
	);
}
