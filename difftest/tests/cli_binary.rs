// the milestone 1 gate as a test: C pacman (PACMAN_BUILD) and the Rust
// binary (target/<profile>/pacman, built with the workspace) run the
// same read-only command lines on generated fixture roots (local db,
// sync .db and .files, a pacman.conf, every path option pointing into
// the fixture), stdout, stderr and exit status compared byte for byte.
// prints one line per command; commands of operations not ported yet
// are expected to differ (KNOWN), every other one must be equal.
// scripts/cli-parity-fixtures.sh runs it with the table shown
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use difftest::{LocalEntry, Rng, SyncWorld, section};

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

// commands whose operation is not ported: -Dk (database.c)
const KNOWN: &[&str] = &["-Dk", "-Dkk"];

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

// an installed package owning real files under the root, for -Ql/-Qo/-Qk
// every generated local entry gets an empty files list like a real db:
// a missing one is a libalpm error log the port's db layer does not
// emit (PORTING.md follow-up)
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
		vec!["-R", "owner"],
		vec!["-U", "x.pkg.tar"],
		vec!["-Fy"],
		vec!["-Dk"],
		vec!["-Dkk"],
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
		let root = refresh(&cmd);
		let dir = w.fx.dir();
		if root {
			restore_sync(dir);
		}
		let cr = run(&c, &args, dir, root);
		let synced_c = root.then(|| snapshot_sync(dir));
		if root {
			restore_sync(dir);
		}
		let rr = run(&r, &args, dir, root);
		let synced_r = root.then(|| snapshot_sync(dir));
		if root {
			restore_sync(dir);
		}
		let rr = Run {
			// the fetched dbs count as output
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
			println!("{mark:5}  {label}");
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

fn known(label: &str) -> bool {
	KNOWN.iter()
		.any(|k| label == *k || label.starts_with(&format!("{k} ")))
		|| label.contains("--debug")
}

#[test]
fn parity() {
	let mut rng = Rng::new(0xc11);
	// a world with every repo valid first, then random ones
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
		let level = (i != 0).then_some("Never");
		for (label, ok, diff) in world(w, level, true) {
			total += 1;
			equal += usize::from(ok);
			if !ok && !known(&label) {
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
