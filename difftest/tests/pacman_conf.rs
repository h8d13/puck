// src/pacman/pacman-conf.c: the C binary (PACMAN_BUILD) and the Rust one
// (target/<profile>/pacman-conf) run the same command lines on config
// trees from the conf difftest's generator, stdout, stderr and exit
// status compared byte for byte. fixed: every directive in [options]
// and repos, includes, sysroot, -R, every option, lookup by case and
// quoting, missing files, bad options, POSIXLY_CORRECT. fuzz: random
// trees with random command lines. each run is capped at 60 s.
// scripts/cli-parity-fixtures.sh runs it with the table shown
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use difftest::{
	CONF_INC_FILES, ConfTree, Rng, conf_content, iters, output_capped,
};

fn c_bin() -> PathBuf {
	let dir = match std::env::var_os("PACMAN_BUILD") {
		Some(d) => PathBuf::from(d),
		None => Path::new(env!("CARGO_MANIFEST_DIR"))
			.join("../pacman/build"),
	};
	dir.join("pacman-conf")
}

// target/<profile>/deps/pacman_conf-<hash> -> target/<profile>/pacman-conf
fn rust_bin() -> PathBuf {
	let exe = std::env::current_exe().unwrap();
	let dir = exe.parent().unwrap().parent().unwrap();
	let bin = dir.join("pacman-conf");
	assert!(
		bin.exists(),
		"{} missing: cargo build --release -p pacman-cli",
		bin.display()
	);
	bin
}

#[derive(Debug, PartialEq, Eq)]
struct Run {
	status: i32,
	out: Vec<u8>,
	err: Vec<u8>,
}

// argv[0] "pacman-conf" on both: getopt's messages print it
fn run(bin: &Path, args: &[Vec<u8>], posix: bool) -> Run {
	let mut cmd = Command::new(bin);
	cmd.arg0("pacman-conf")
		.args(args.iter().map(|a| OsStr::from_bytes(a)))
		.env_clear()
		.env("LC_ALL", "C.UTF-8")
		.env("PATH", "/usr/bin:/bin");
	if posix {
		cmd.env("POSIXLY_CORRECT", "1");
	}
	let o = output_capped(&mut cmd, 60);
	Run {
		status: o.status.code().expect("killed by a signal"),
		out: o.stdout,
		err: o.stderr,
	}
}

fn lossy(b: &[u8]) -> String {
	String::from_utf8_lossy(b).into_owned()
}

// both binaries on one command line: the C run and the difference
fn compare(args: &[Vec<u8>], posix: bool) -> (Run, Option<String>) {
	let c = run(&c_bin(), args, posix);
	let r = run(&rust_bin(), args, posix);
	let diff = (c != r).then(|| {
		format!(
			"status C {} Rust {}\n-- C out\n{}-- Rust out\n{}\
			-- C err\n{}-- Rust err\n{}",
			c.status,
			r.status,
			lossy(&c.out),
			lossy(&r.out),
			lossy(&c.err),
			lossy(&r.err)
		)
	});
	(c, diff)
}

fn bytes(v: &[&str]) -> Vec<Vec<u8>> {
	v.iter().map(|s| s.as_bytes().to_vec()).collect()
}

// every name pacman-conf.c tests, then case, quoting and near misses
const DIRECTIVES: &[&str] = &[
	"RootDir",
	"DBPath",
	"CacheDir",
	"HookDir",
	"GPGDir",
	"LogFile",
	"DownloadUser",
	"HoldPkg",
	"IgnorePkg",
	"IgnoreGroup",
	"NoUpgrade",
	"NoExtract",
	"Architecture",
	"XferCommand",
	"UseSyslog",
	"Color",
	"CheckSpace",
	"VerbosePkgLists",
	"DisableDownloadTimeout",
	"ILoveCandy",
	"NoProgressBar",
	"DisableSandbox",
	"DisableSandboxFilesystem",
	"DisableSandboxSyscalls",
	"ParallelDownloads",
	"CleanMethod",
	"SigLevel",
	"LocalFileSigLevel",
	"RemoteFileSigLevel",
	"Include",
	"Server",
	"CacheServer",
	"Usage",
	"rootdir",
	"DBPATH",
	"gpgDir",
	"include",
	"server",
	"'DBPath'",
	"\"DBPath\"",
	" DBPath",
	"DBPath ",
	"DBPath=",
	"DB Path",
	"[options]",
	"options",
	"Bogus",
	"",
];

// a tree with every directive set, two repos and an include
fn full_tree(tree: &ConfTree) -> Vec<u8> {
	let s = lossy(&tree.path());
	let conf = format!(
		"[options]\nRootDir = {s}/root\nDBPath = {s}/root/db\n\
		CacheDir = /c1 /c2/\nHookDir = /h\nGPGDir = {s}/gnupg\n\
		LogFile = {s}/log/pacman.log\nDownloadUser = alpm\nHoldPkg = pacman glibc\n\
		IgnorePkg = a b\nIgnoreGroup = g\nNoUpgrade = etc/x\n\
		NoExtract = usr/share/doc/*\nArchitecture = x86_64 auto\n\
		XferCommand = /usr/bin/curl -o %o %u\nUseSyslog\nColor\n\
		CheckSpace\nVerbosePkgLists\nDisableDownloadTimeout\n\
		ILoveCandy\nNoProgressBar\nDisableSandboxFilesystem\n\
		DisableSandboxSyscalls\nParallelDownloads = 5\n\
		CleanMethod = KeepInstalled KeepCurrent\n\
		SigLevel = Required DatabaseOptional\n\
		LocalFileSigLevel = Optional TrustAll\n\
		RemoteFileSigLevel = PackageNever\n\
		Include = {s}/inc/a.conf\n\
		[core]\nUsage = Sync Search\nSigLevel = PackageOptional\n\
		Server = http://m/$repo/os/$arch\nCacheServer = file:///c/$repo\n\
		[extra]\nUsage = Install Upgrade\nInclude = {s}/inc/b.conf\n\
		[empty]\n[local]\nSigLevel = Never\nUsage = All\n"
	);
	// RootDir, DBPath, GPGDir and LogFile are resolved: they must exist
	for d in ["root/db", "gnupg", "log"] {
		fs::create_dir_all(tree.root.join(d)).unwrap();
	}
	tree.write("pacman.conf", conf.as_bytes());
	tree.write("inc/a.conf", b"IgnorePkg = c\nNoExtract = x\n");
	tree.write("inc/b.conf", b"Server = file:///srv/$repo\n");
	[tree.path(), b"/pacman.conf".to_vec()].concat()
}

// the fixed command lines on a config file (before the --config option)
fn fixed_lines(conf: &[u8], tree: &[u8]) -> Vec<Vec<Vec<u8>>> {
	let c = [b"--config=".to_vec(), conf.to_vec()].concat();
	let with = |v: &[&str]| {
		let mut a = bytes(v);
		a.push(c.clone());
		a
	};
	let mut lines = vec![
		with(&[]),
		with(&["-v"]),
		with(&["--verbose"]),
		with(&["-l"]),
		with(&["--repo-list"]),
		with(&["-l", "-r", "core"]),
		with(&["-l", "--repo=nope"]),
		with(&["-l", "DBPath"]),
		with(&["-r", "core"]),
		with(&["--repo", "extra"]),
		with(&["-r", "empty"]),
		with(&["-r", "local"]),
		with(&["-r", "nope"]),
		with(&["-r", "nope", "Server"]),
		with(&["-r", "core", "Server"]),
		with(&["-r", "core", "-v", "Server"]),
		with(&["-r", "core", "server", "cacheserver", "usage"]),
		with(&["-r", "core", "SigLevel", "Include", "DBPath", "x"]),
		with(&["-r", "extra", "Usage"]),
		with(&["-r", "options"]),
		with(&["DBPath", "RootDir"]),
		with(&["-v", "DBPath"]),
		with(&["DisableSandbox"]),
		with(&["-R", "/srv/x", "DBPath", "LogFile"]),
		with(&["--rootdir=/srv/x/", "RootDir"]),
		with(&["--root=/srv/x", "DBPath"]),
		with(&["--sys", "/nope", "DBPath"]),
		with(&["-h"]),
		with(&["--help"]),
		with(&["-V"]),
		with(&["--version"]),
		with(&["-V", "-h"]),
		with(&["-h", "-x"]),
		with(&["-x"]),
		with(&["--bogus"]),
		with(&["--re", "x"]),
		with(&["--repo"]),
		with(&["-r"]),
		with(&["--verbose=1"]),
		with(&["--", "-v"]),
		with(&["DBPath", "--", "-l"]),
		bytes(&["--config"]),
		bytes(&["-c"]),
		bytes(&["--config=/nonexistent/pacman.conf"]),
		bytes(&["-c", "/nonexistent/pacman.conf", "-V"]),
		bytes(&["-c", ""]),
	];
	for d in DIRECTIVES {
		lines.push(with(&[d]));
		lines.push(with(&["-r", "core", d]));
	}
	// sysroot: the config and its includes looked up under it
	let s = [b"--sysroot=".to_vec(), tree.to_vec()].concat();
	lines.push(vec![s.clone(), b"--config=/pacman.conf".to_vec()]);
	lines.push(vec![s.clone(), b"-c/pacman.conf".to_vec(), b"-l".into()]);
	lines.push(vec![s.clone(), b"-c/nope".to_vec()]);
	lines.push(vec![s, c.clone(), b"DBPath".to_vec()]);
	lines
}

// one table line per run, failures collected
#[derive(Default)]
struct Tally {
	equal: usize,
	// runs the C exits 0 from
	ok: usize,
	total: usize,
	failures: Vec<String>,
}

impl Tally {
	fn check(&mut self, label: &str, args: &[Vec<u8>], posix: bool) {
		let (c, diff) = compare(args, posix);
		self.total += 1;
		self.ok += usize::from(c.status == 0);
		self.equal += usize::from(diff.is_none());
		let mark = if diff.is_none() { "equal" } else { "DIFF" };
		let (o, e) = (c.out.len(), c.err.len());
		println!("{mark:5}  {label}  [{} {o}/{e}]", c.status);
		if let Some(d) = diff {
			self.failures.push(format!("{label}\n{d}"));
		}
	}

	// both outcomes common, or the comparison means little
	fn finish(self, what: &str) {
		println!(
			"== {what}: {}/{} equal, {} exit 0",
			self.equal, self.total, self.ok
		);
		let tenth = self.total / 10;
		assert!(
			self.ok > tenth && self.total - self.ok > tenth,
			"exit 0 in {} of {} runs",
			self.ok,
			self.total
		);
		assert!(
			self.failures.is_empty(),
			"{}",
			self.failures.join("\n")
		);
	}
}

fn label(args: &[Vec<u8>], tree: &[u8]) -> String {
	let s = args.iter().map(|a| format!("{:?}", lossy(a)));
	s.collect::<Vec<_>>().join(" ").replace(&lossy(tree), "@")
}

#[test]
fn fixed() {
	let tree = ConfTree::new("pcbin-fixed", false);
	let conf = full_tree(&tree);
	let mut t = Tally::default();
	for args in fixed_lines(&conf, &tree.path()) {
		t.check(&label(&args, &tree.path()), &args, false);
	}
	// POSIXLY_CORRECT: options after the first directive are directives
	let c = [b"--config=".to_vec(), conf.clone()].concat();
	for first in [&b"DBPath"[..], b"-v"] {
		let args = vec![first.to_vec(), c.clone(), b"-l".to_vec()];
		let l = format!(
			"POSIXLY_CORRECT {}",
			label(&args, &tree.path())
		);
		t.check(&l, &args, true);
	}
	// parse failures: no section, recursion, bad values, $arch unset
	let bad = [
		&b"UseSyslog\n"[..],
		b"[options]\nInclude = /nope\n",
		b"[options]\nParallelDownloads = 0\n",
		b"[core]\nServer = http://m/$arch\n",
		b"[options]\nSigLevel = Bogus\nBogusKey\n",
		b"",
	];
	for content in bad {
		tree.write("pacman.conf", content);
		let args = vec![c.clone(), b"DBPath".to_vec()];
		let l = format!("{:?} {}", lossy(content), label(&args, &[]));
		t.check(&l.replace(&lossy(&tree.path()), "@"), &args, false);
	}
	t.finish("pacman-conf fixed");
}

// a random command line on a generated config
fn random_args(
	rng: &mut Rng,
	conf: &[u8],
	sysroot: Option<&[u8]>,
) -> Vec<Vec<u8>> {
	let repos = ["core", "extra", "$repo", "options", "nope", ""];
	let mut args = Vec::new();
	if let Some(s) = sysroot {
		args.push([b"-S".to_vec(), s.to_vec()].concat());
	}
	args.push([b"--config=".to_vec(), conf.to_vec()].concat());
	match rng.below(8) {
		0 => args.push(b"-l".to_vec()),
		1 | 2 => {
			args.push(b"-r".to_vec());
			args.push(repos[rng.below(repos.len())].into());
		}
		_ => {}
	}
	if rng.below(4) == 0 {
		args.push(b"-v".to_vec());
	}
	if rng.below(6) == 0 {
		let r = ["/", "/srv/r/", "rel", "/srv/r"][rng.below(4)];
		args.push([b"--rootdir=", r.as_bytes()].concat());
	}
	for _ in 0..[0, 0, 1, 1, 1, 2, 3][rng.below(7)] {
		let d = DIRECTIVES[rng.below(DIRECTIVES.len())];
		args.push(d.as_bytes().to_vec());
	}
	// options and directives in any order: getopt permutes
	let n = args.len();
	for i in (1..n).rev() {
		args.swap(i, rng.below(i + 1));
	}
	args
}

// each iteration writes 9 files and runs 4 command lines on both
#[test]
fn fuzz() {
	let tree = ConfTree::new("pcbin-fuzz", false);
	let tree_s = lossy(&tree.path());
	let mut rng = Rng::new(0xc0f);
	let mut t = Tally::default();
	let n = (iters() / 2000).max(20);
	for i in 0..n {
		let sysroot = rng.below(3) == 0;
		let base = if sysroot { "" } else { &tree_s };
		let main = conf_content(&mut rng, 24, &tree_s, base, false);
		tree.write("pacman.conf", &main);
		for f in CONF_INC_FILES {
			let c = conf_content(&mut rng, 6, &tree_s, base, true);
			tree.write(&format!("inc/{f}"), &c);
		}
		let (conf, root) = match sysroot {
			true => (b"/pacman.conf".to_vec(), Some(tree.path())),
			false => {
				let p = [tree.path(), b"/pacman.conf".to_vec()];
				(p.concat(), None)
			}
		};
		for _ in 0..4 {
			let args =
				random_args(&mut rng, &conf, root.as_deref());
			let l = format!("{i}: {}", label(&args, &tree.path()));
			t.check(&l, &args, false);
		}
	}
	t.finish("pacman-conf fuzz");
}
