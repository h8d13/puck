// the milestone 1 gate as a test: C pacman (PACMAN_BUILD) and the Rust
// binary (target/<profile>/pacman, built with the workspace) run the
// same read-only command lines on generated fixture roots (local db,
// sync .db and .files, a pacman.conf, every path option pointing into
// the fixture), stdout, stderr and exit status compared byte for byte.
// prints one line per command; every one must be equal but the --debug
// lines known() explains. root-only commands (-Sy, -Fy, -D) run under
// fakeroot, the dbs they fetch or write compared too.
// scripts/cli-parity-fixtures.sh runs it with the table shown
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use difftest::{LocalEntry, Rng, SyncWorld, section, snapshot};

fn c_pacman() -> PathBuf {
	let dir = match std::env::var_os("PACMAN_BUILD") {
		Some(d) => PathBuf::from(d),
		None => Path::new(env!("CARGO_MANIFEST_DIR"))
			.join("../pacman/build"),
	};
	dir.join("pacman")
}

// target/<profile>/deps/cli_binary-<hash> -> target/<profile>/pacman
fn rust_pacman() -> PathBuf {
	let exe = std::env::current_exe().unwrap();
	let bin = exe.parent().unwrap().parent().unwrap().join("pacman");
	assert!(
		bin.exists(),
		"{} missing: cargo build --release -p pacman-cli",
		bin.display()
	);
	bin
}

// --debug in the world with the default SigLevel (Required, unsigned
// dbs): the C logs the failed .sig lookup (util.c _alpm_access, signing.c
// "sig path ... could not be opened", "missing required signature") and
// GOTO_ERR's "got error ... (signing.c: <line>)"; the port's signing
// logs errors and warnings only and never RET_ERR/GOTO_ERR lines
// (PORTING.md)
fn known(label: &str, siglevel: Option<&str>) -> bool {
	siglevel.is_none() && label.contains("--debug")
}

// "[HH:MM:SS] " before stamped lines: both binaries read the clock
fn unstamp(err: &[u8]) -> Vec<u8> {
	let mut out = Vec::new();
	for line in err.split_inclusive(|&c| c == b'\n') {
		let stamped = line.len() >= 11
			&& line[0] == b'[' && line[3] == b':'
			&& line[6] == b':' && line[9] == b']';
		out.extend_from_slice(if stamped { &line[11..] } else { line });
	}
	out
}

#[derive(Debug, PartialEq, Eq)]
struct Run {
	status: i32,
	out: Vec<u8>,
	err: Vec<u8>,
}

// fake root: fakeroot runs bin as uid 0, for the root-only refreshes
fn run(bin: &Path, args: &[String], cwd: &Path, root: bool) -> Run {
	let mut cmd = match root {
		true => {
			let mut c = Command::new("fakeroot");
			c.arg(bin);
			c
		}
		false => {
			let mut c = Command::new(bin);
			c.arg0("pacman");
			c
		}
	};
	let o = cmd
		.args(args)
		.current_dir(cwd)
		.env_clear()
		.env("LC_ALL", "C.UTF-8")
		.env("TZ", "UTC")
		.env("COLUMNS", "80")
		.env("PATH", "/usr/bin:/bin")
		.stdin(Stdio::null())
		.output()
		.unwrap();
	Run {
		status: o.status.code().expect("killed by a signal"),
		out: o.stdout,
		err: unstamp(&o.stderr),
	}
}

// the fixture's pacman.conf and the path options of every command line
// siglevel None keeps the default (Required: every unsigned db fails)
fn setup(w: &SyncWorld, siglevel: Option<&str>) -> Vec<String> {
	let dir = w.fx.dir();
	for d in ["cache", "hooks", "gnupg", "log"] {
		fs::create_dir_all(dir.join(d)).unwrap();
	}
	let mut conf = String::from("[options]\nArchitecture = x86_64\n");
	if let Some(level) = siglevel {
		conf.push_str(&format!("SigLevel = {level}\n"));
	}
	for r in &w.repos {
		let mirror = dir.join("mirror").display().to_string();
		conf.push_str(&format!("[{r}]\nServer = file://{mirror}\n"));
	}
	fs::write(dir.join("pacman.conf"), conf).unwrap();
	// the mirror -Sy/-Fy fetch from: the sync dbs as they are, the copy
	// under db/sync kept apart to put back before every refresh run
	for d in ["mirror", "sync.orig"] {
		fs::create_dir_all(dir.join(d)).unwrap();
	}
	// the local db -D runs start from
	copy_dir(&dir.join("db/local"), &dir.join("local.orig"));
	for e in fs::read_dir(dir.join("db/sync")).unwrap() {
		let e = e.unwrap();
		fs::copy(e.path(), dir.join("mirror").join(e.file_name()))
			.unwrap();
		fs::copy(e.path(), dir.join("sync.orig").join(e.file_name()))
			.unwrap();
	}
	let p = |rel: &str| dir.join(rel).display().to_string();
	vec![
		format!("--config={}", p("pacman.conf")),
		format!("--root={}", p("root")),
		format!("--dbpath={}", p("db")),
		format!("--cachedir={}", p("cache")),
		format!("--hookdir={}", p("hooks")),
		format!("--gpgdir={}", p("gnupg")),
		format!("--logfile={}", p("log/pacman.log")),
	]
}

// an installed package owning real files under the root, for -Ql/-Qo/-Qk.
// every generated local entry gets an empty files list like a real db: a
// missing one logs "could not open file" from its lazy load, which query
// does up front for -Qkk and prints apart from the op's buffered stderr
// (PORTING.md follow-up)
fn owner_pkg(w: &SyncWorld) {
	for e in fs::read_dir(w.fx.local()).unwrap() {
		let dir = e.unwrap().path();
		if dir.is_dir() && !dir.join("files").exists() {
			fs::write(dir.join("files"), "").unwrap();
		}
	}
	let root = w.fx.dir().join("root");
	fs::create_dir_all(root.join("usr/bin")).unwrap();
	fs::write(root.join("usr/bin/owned"), "x").unwrap();
	let one = |s: &str| vec![s.to_string()];
	let desc = [
		section("NAME", &one("owner")),
		section("VERSION", &one("1.0-1")),
		section("BASE", &one("owner")),
		section("DESC", &one("owns files")),
		// alpm-db wants a URL (PORTING.md, ALPM divergences)
		section("URL", &one("https://example.org/owner")),
		section("ARCH", &one("x86_64")),
		section("BUILDDATE", &one("1700000000")),
		section("INSTALLDATE", &one("1700000001")),
		section("PACKAGER", &one("A B <a@b.org>")),
		section("SIZE", &one("1")),
		section("REASON", &one("1")),
		section("VALIDATION", &one("none")),
	]
	.concat();
	let files = "%FILES%\nusr/\nusr/bin/\nusr/bin/owned\nusr/bin/gone\n\n";
	w.fx.write_local(&[LocalEntry {
		dir: "owner-1.0-1".to_string(),
		desc: Some(desc.into_bytes()),
		files: Some(files.as_bytes().to_vec()),
		install: false,
	}]);
}

// the command lines of one world: (label, args before the path options)
fn commands(w: &SyncWorld) -> Vec<Vec<String>> {
	let sync = w.pkg_names().first().copied().unwrap_or("nope");
	let last = w.pkg_names().last().copied().unwrap_or("nope");
	let root = w.fx.dir().join("root").display().to_string();
	let owned = format!("{root}/usr/bin/owned");
	let repo = w.repos.first().copied().unwrap_or("core");
	let lines: Vec<Vec<&str>> = vec![
		vec!["-Q"],
		vec!["-Qq"],
		vec!["-Qi"],
		vec!["-Qii"],
		vec!["-Qi", "owner"],
		vec!["-Ql"],
		vec!["-Ql", "owner"],
		vec!["-Qlq", "owner"],
		vec!["-Qe"],
		vec!["-Qd"],
		vec!["-Qm"],
		vec!["-Qn"],
		vec!["-Qu"],
		vec!["-Qt"],
		vec!["-Qtt"],
		vec!["-Qs"],
		vec!["-Qs", "a"],
		vec!["-Qsq", "^o"],
		vec!["-Qs", "["],
		vec!["-Qg"],
		vec!["-Qg", "base"],
		vec!["-Qo", &owned],
		vec!["-Qo", "/nonexistent/file"],
		vec!["-Qk"],
		vec!["-Qkk"],
		vec!["-Qk", "owner"],
		vec!["-Qc", "owner"],
		vec!["-Q", "nope"],
		vec!["-Qi", "nope", "owner"],
		vec!["-Si"],
		vec!["-Sii"],
		vec!["-Si", sync],
		vec!["-Si", "nope"],
		vec!["-Sl"],
		vec!["-Sl", repo],
		vec!["-Sl", "nope"],
		vec!["-Sg"],
		vec!["-Sgg"],
		vec!["-Sg", "base"],
		vec!["-Ss"],
		vec!["-Ss", "a"],
		vec!["-Ssq", "a"],
		vec!["-Ss", "a", "e"],
		vec!["-Ss", "("],
		vec!["-F", "owned"],
		vec!["-F", "usr/bin/x"],
		vec!["-Fl"],
		vec!["-Fl", sync],
		vec!["-Fx", "b.n"],
		vec!["-Fq", "bin"],
		vec!["-F", "--machinereadable", "bin"],
		vec!["-F"],
		vec!["-T"],
		vec!["-T", "owner"],
		vec!["-T", "owner>2", "nope", "sh"],
		vec!["-V"],
		vec!["-h"],
		vec!["-Sh"],
		vec!["-Qh"],
		vec!["-Fh"],
		vec!["--help", "-D"],
		vec![],
		vec!["-X"],
		vec!["-Q", "-S"],
		vec!["-Sy"],
		vec!["-Syy"],
		vec!["-Syl"],
		vec!["-Sys", "a"],
		vec!["-Syi", sync],
		vec!["-Fyy"],
		vec!["-Fyl"],
		vec!["-S", sync],
		vec!["-Sc"],
		// transactions as far as --print goes, no root needed
		vec!["-Sp", sync],
		vec!["-S", "--print", sync],
		vec!["-Sp", "--print-format", "%n %v %r %s", sync],
		vec!["-Sp", "nope"],
		vec!["-Sp", sync, "owner"],
		vec!["-Sp", last],
		vec!["-Sp", sync, last],
		vec!["-Spd", sync],
		vec!["-Spdd", sync],
		vec!["-Sup"],
		vec!["-Rp", "owner"],
		vec!["-R", "--print", "owner"],
		vec!["-Rp", "nope"],
		vec!["-Rps", "owner"],
		vec!["-Rpc", "owner"],
		vec!["-Up", "nope.pkg.tar.zst"],
		vec!["-R", "owner"],
		vec!["-U", "x.pkg.tar"],
		vec!["-Fy"],
		vec!["-Dk"],
		vec!["-Dkk"],
		vec!["-Dk", "-q"],
		vec!["-D", "--asdeps", "owner"],
		vec!["-D", "--asexplicit", "owner"],
		vec!["-D", "--asdeps", "nope", "owner", sync],
		vec!["-Dq", "--asdeps", "owner"],
		vec!["-D", "owner"],
		vec!["-D", "--asdeps"],
		vec!["-Dk", "--asdeps", "owner"],
		vec!["-Qv"],
		vec!["-Q", "--color=always", "-i", "owner"],
		vec!["-Ss", "--color=always", "a"],
		vec!["-Q", "--debug"],
		vec!["-Si", "--debug", sync],
	];
	lines.into_iter()
		.map(|l| l.into_iter().map(String::from).collect())
		.collect()
}

fn lossy(b: &[u8]) -> String {
	String::from_utf8_lossy(b).into_owned()
}

// one world: every command on both binaries. (label, equal) per command
fn world(
	w: &SyncWorld,
	siglevel: Option<&str>,
	verbose: bool,
) -> Vec<(String, bool, Option<String>)> {
	owner_pkg(w);
	let paths = setup(w, siglevel);
	let (c, r) = (c_pacman(), rust_pacman());
	let mut out = Vec::new();
	for cmd in commands(w) {
		let mut args = cmd.clone();
		args.extend(paths.iter().cloned());
		let root = refresh(&cmd) || writes_local(&cmd);
		let dir = w.fx.dir();
		let restore = || {
			if root {
				restore_sync(dir);
				restore_local(dir);
			}
		};
		let written = || {
			root.then(|| {
				(
					snapshot_sync(dir),
					snapshot(&dir.join("db/local")),
				)
			})
		};
		restore();
		let cr = run(&c, &args, dir, root);
		let synced_c = written();
		restore();
		let rr = run(&r, &args, dir, root);
		let synced_r = written();
		restore();
		let rr = Run {
			// the fetched or written dbs count as output
			status: if synced_c == synced_r {
				rr.status
			} else {
				-1
			},
			..rr
		};
		let label = cmd
			.join(" ")
			.replace(&w.fx.dir().display().to_string(), "@");
		let diff = (cr != rr).then(|| {
			format!(
				"status C {} Rust {}\n-- C out\n{}-- Rust out\n{}\
				-- C err\n{}-- Rust err\n{}",
				cr.status,
				rr.status,
				lossy(&cr.out),
				lossy(&rr.out),
				lossy(&cr.err),
				lossy(&rr.err)
			)
		});
		if verbose {
			let mark =
				if diff.is_none() { "equal" } else { "DIFF" };
			let (o, e) = (cr.out.len(), cr.err.len());
			println!("{mark:5}  {label}  [{} {o}/{e}]", cr.status);
		}
		out.push((label, diff.is_none(), diff));
	}
	out
}

// the refreshes, run as fake root with a file:// mirror
fn refresh(cmd: &[String]) -> bool {
	cmd.first()
		.is_some_and(|c| c.starts_with("-Sy") || c.starts_with("-Fy"))
}

// -D without -k: root only, writes the local db
fn writes_local(cmd: &[String]) -> bool {
	cmd.first()
		.is_some_and(|c| c.starts_with("-D") && !c.contains('k'))
		&& !cmd.iter().any(|a| a == "-k")
}

fn copy_dir(from: &Path, to: &Path) {
	fs::create_dir_all(to).unwrap();
	for e in fs::read_dir(from).unwrap() {
		let e = e.unwrap();
		let dest = to.join(e.file_name());
		match e.file_type().unwrap().is_dir() {
			true => copy_dir(&e.path(), &dest),
			false => {
				fs::copy(e.path(), dest).unwrap();
			}
		}
	}
}

// db/local back to what the fixture wrote
fn restore_local(dir: &Path) {
	let local = dir.join("db/local");
	fs::remove_dir_all(&local).unwrap();
	copy_dir(&dir.join("local.orig"), &local);
}

// db/sync back to what the fixture wrote, with an old mtime so a
// refresh sees the mirror's copies as newer
fn restore_sync(dir: &Path) {
	let sync = dir.join("db/sync");
	fs::remove_dir_all(&sync).unwrap();
	fs::create_dir_all(&sync).unwrap();
	let old =
		std::time::UNIX_EPOCH + std::time::Duration::from_secs(1 << 20);
	for e in fs::read_dir(dir.join("sync.orig")).unwrap() {
		let e = e.unwrap();
		let to = sync.join(e.file_name());
		fs::copy(e.path(), &to).unwrap();
		let f = fs::File::options().write(true).open(&to).unwrap();
		f.set_modified(old).unwrap();
	}
}

// names and contents under db/sync
fn snapshot_sync(dir: &Path) -> Vec<(String, Vec<u8>)> {
	let mut v: Vec<(String, Vec<u8>)> = fs::read_dir(dir.join("db/sync"))
		.unwrap()
		.map(|e| {
			let e = e.unwrap();
			let n = e.file_name().to_string_lossy().into_owned();
			let data = if e.path().is_file() {
				fs::read(e.path()).unwrap()
			} else {
				Vec::new()
			};
			(n, data)
		})
		.collect();
	v.sort();
	v
}

#[test]
fn parity() {
	let mut rng = Rng::new(0xc11);
	// a world with every repo valid first, then random ones (the second
	// keeps the default SigLevel: unsigned dbs fail)
	let mut worlds = Vec::new();
	loop {
		let w = SyncWorld::generate(&mut rng, "cli-main");
		let valid = w.repos.len() == 3
			&& w.dbs.iter().all(
				|d| matches!(d, difftest::DbFile::Valid(p) if !p.is_empty()),
			);
		if valid {
			worlds.push(w);
			break;
		}
	}
	for i in 0..4 {
		worlds.push(SyncWorld::generate(&mut rng, &format!("cli-{i}")));
	}
	let mut failures = Vec::new();
	let (mut equal, mut total) = (0, 0);
	for (i, w) in worlds.iter().enumerate() {
		println!("== world {i}\n{}", w.log);
		let level = (i != 1).then_some("Never");
		for (label, ok, diff) in world(w, level, true) {
			total += 1;
			equal += usize::from(ok);
			if !ok && !known(&label, level) {
				failures.push(format!(
					"world {i}: {label}\n{}",
					diff.unwrap_or_default()
				));
			}
		}
	}
	println!("== {equal}/{total} equal");
	assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// the fixture XferCommand: logs its cwd and arguments, then fetches $1
// (or into $2) with curl, under a timeout. "-exit" variants fail with 7
// before fetching
fn xfer_script(dir: &Path, name: &str, body: &str) -> String {
	let path = dir.join(name);
	let log = dir.join("xfer.log").display().to_string();
	let script = format!(
		"#!/bin/sh\nprintf '%s|%s\\n' \"$PWD\" \"$*\" >> '{log}'\n{body}\n"
	);
	fs::write(&path, script).unwrap();
	let mut perm = fs::metadata(&path).unwrap().permissions();
	std::os::unix::fs::PermissionsExt::set_mode(&mut perm, 0o755);
	fs::set_permissions(&path, perm).unwrap();
	path.display().to_string()
}

// mkdtemp's "download-XXXXXX" suffix fixed, the C's RET_ERR debug lines
// (file:line, never logged by the port) dropped
fn xfer_norm(b: &[u8]) -> Vec<u8> {
	let mut out = Vec::new();
	for line in b.split_inclusive(|&c| c == b'\n') {
		if line.starts_with(b"debug: returning error ") {
			continue;
		}
		let mut l = line.to_vec();
		let pat = b"download-";
		let mut i = 0;
		while i + pat.len() + 6 <= l.len() {
			if &l[i..i + pat.len()] == pat {
				let at = i + pat.len();
				l[at..at + 6].copy_from_slice(b"XXXXXX");
				i = at + 6;
			} else {
				i += 1;
			}
		}
		out.extend(l);
	}
	out
}

// pacman.conf of the world with extra [options] lines and the repos'
// servers at mirror
fn xfer_conf(dir: &Path, repos: &[&str], options: &str, mirror: &str) {
	let mut conf = format!(
		"[options]\nArchitecture = x86_64\nSigLevel = Never\n{options}"
	);
	for r in repos {
		conf.push_str(&format!("[{r}]\nServer = {mirror}\n"));
	}
	fs::write(dir.join("pacman.conf"), conf).unwrap();
}

// XferCommand (download_with_xfercommand) on both binaries: -Sy/-Syy
// from a loopback HTTP mirror and file://, -U of a url; with %o and
// without (the command's cwd), a failing and a missing command, --debug,
// and DownloadUser (the command run through the sandbox exec helper;
// fakeroot fakes the user switch on both sides). compared: status,
// stdout, stderr, the fetched dbs, the cache, what the command saw
#[test]
fn xfercommand() {
	use difftest::{Reply, Server, TcPkg, tc_package};
	let mut rng = Rng::new(0x7fe7);
	let w = loop {
		let w = SyncWorld::generate(&mut rng, "cli-xfer");
		let valid = !w.repos.is_empty()
			&& w.dbs.iter().all(|d| {
				matches!(d, difftest::DbFile::Valid(_))
			});
		if valid {
			break w;
		}
	};
	let paths = setup(&w, Some("Never"));
	let dir = w.fx.dir().to_path_buf();
	let srv = Server::start();
	let file = |b: Vec<u8>| Reply::File {
		body: b,
		ranges: false,
		mtime: Some(1_000_000_000),
	};
	for e in fs::read_dir(dir.join("mirror")).unwrap() {
		let e = e.unwrap();
		let name = e.file_name().to_string_lossy().into_owned();
		let body = fs::read(e.path()).unwrap();
		srv.route(&format!("/m/{name}"), vec![file(body)]);
	}
	let pkg = TcPkg {
		name: "xfer".into(),
		version: "1-1".into(),
		..TcPkg::default()
	};
	let pkgname = "xfer-1-1-x86_64.pkg.tar";
	srv.route(&format!("/p/{pkgname}"), vec![file(tc_package(&pkg))]);
	let curl = "exec timeout 20 curl -sSf";
	let fetch = xfer_script(
		&dir,
		"xfer.sh",
		&format!("{curl} -o \"$2\" \"$1\""),
	);
	let fetch_cwd =
		xfer_script(&dir, "xfer-O.sh", &format!("{curl} -O \"$1\""));
	let fail = xfer_script(&dir, "xfer-exit.sh", "exit 7");
	let http = srv.url("/m");
	let http = String::from_utf8(http).unwrap();
	let filem = format!("file://{}", dir.join("mirror").display());
	let url = String::from_utf8(srv.url(&format!("/p/{pkgname}"))).unwrap();
	let opts: Vec<(&str, String, &str)> = vec![
		("%o", format!("XferCommand = {fetch} %u %o\n"), &http),
		("file", format!("XferCommand = {fetch} %u %o\n"), &filem),
		("cwd", format!("XferCommand = {fetch_cwd} %u\n"), &http),
		("exit", format!("XferCommand = {fail} %u %o\n"), &http),
		("missing", "XferCommand = /nonexistent/xfer %u %o\n".into(), &http),
		(
			"user",
			format!("XferCommand = {fetch} %u %o\nDownloadUser = nobody\n"),
			&http,
		),
		(
			"user missing",
			"XferCommand = /nonexistent/xfer %u %o\nDownloadUser = nobody\n"
				.into(),
			&http,
		),
	];
	let cmds: [&[&str]; 4] =
		[&["-Sy"], &["-Syy"], &["-Sy", "--debug"], &["-U", &url]];
	let (c, r) = (c_pacman(), rust_pacman());
	let mut failures = Vec::new();
	for (tag, opt, mirror) in &opts {
		xfer_conf(&dir, &w.repos, opt, mirror);
		for cmd in cmds {
			// the failing ones sleep 2 s per file: -Sy only
			let failing = matches!(
				*tag,
				"exit" | "missing" | "user missing"
			);
			if failing
				&& cmd != ["-Sy"] && cmd != ["-Sy", "--debug"]
			{
				continue;
			}
			let mut args: Vec<String> =
				cmd.iter().map(|s| s.to_string()).collect();
			args.extend(paths.iter().cloned());
			let side = |bin: &Path| {
				restore_sync(&dir);
				restore_local(&dir);
				let _ = fs::remove_dir_all(dir.join("cache"));
				fs::create_dir(dir.join("cache")).unwrap();
				let _ = fs::remove_file(dir.join("xfer.log"));
				let run = run(bin, &args, &dir, true);
				let run = Run {
					out: xfer_norm(&run.out),
					err: xfer_norm(&run.err),
					..run
				};
				let log = fs::read(dir.join("xfer.log"))
					.unwrap_or_default();
				let log = xfer_norm(&log);
				let mut cache: Vec<_> =
					fs::read_dir(dir.join("cache"))
						.unwrap()
						.map(|e| e.unwrap().file_name())
						.collect();
				cache.sort();
				// the C keeps a sandbox download dir after a failed
				// fetchcb, the port removes it (UPSTREAM.md)
				let mut synced = snapshot_sync(&dir);
				synced.retain(|(n, _)| {
					!n.starts_with("download-")
				});
				(run, synced, cache, log)
			};
			let (cs, rs) = (side(&c), side(&r));
			let label = format!("{tag}: {}", cmd.join(" "));
			println!(
				"{}  {label}  [{}]",
				if cs == rs { "equal" } else { "DIFF" },
				cs.0.status
			);
			if cs != rs {
				failures.push(format!(
					"{label}\n-- C\n{}\n{}\n{:?}\n{}\n-- Rust\n{}\n{}\n{:?}\n{}",
					lossy(&cs.0.out),
					lossy(&cs.0.err),
					cs.2,
					lossy(&cs.3),
					lossy(&rs.0.out),
					lossy(&rs.0.err),
					rs.2,
					lossy(&rs.3),
				));
			}
		}
	}
	restore_sync(&dir);
	restore_local(&dir);
	assert!(failures.is_empty(), "{}", failures.join("\n"));
}
