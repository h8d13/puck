// unit tests for pacman_cli::database on a local db written here: foo
// 1-1 (explicit) depending on bar, with a file list
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use alpm_core::Handle;
use alpm_core::TRANS_FLAG_ALLDEPS;
use pacman_cli::conf::Config;
use pacman_cli::database::pacman_database;
use pacman_cli::util::Output;

// <tmp>/pacman-cli-database-<pid>-<tag>/ with root/ and db/, removed on
// drop
struct Tmp(PathBuf);

impl Tmp {
	fn new(tag: &str) -> Self {
		let dir = std::env::temp_dir().join(format!(
			"pacman-cli-database-{}-{tag}",
			std::process::id()
		));
		if dir.exists() {
			fs::remove_dir_all(&dir).unwrap();
		}
		fs::create_dir_all(dir.join("root")).unwrap();
		let pkg = dir.join("db/local/foo-1-1");
		fs::create_dir_all(&pkg).unwrap();
		fs::write(dir.join("db/local/ALPM_DB_VERSION"), "9\n").unwrap();
		let desc = "%NAME%\nfoo\n\n%VERSION%\n1-1\n\n%REASON%\n0\n\n\
			%DEPENDS%\nbar\n\n";
		fs::write(pkg.join("desc"), desc).unwrap();
		fs::write(pkg.join("files"), "%FILES%\nfoo\n\n").unwrap();
		Tmp(dir)
	}

	fn handle(&self) -> Handle {
		let p = |rel: &str| {
			self.0.join(rel).as_os_str().as_bytes().to_vec()
		};
		Handle::initialize(&p("root"), &p("db")).unwrap()
	}

	fn desc(&self) -> String {
		let path = self.0.join("db/local/foo-1-1/desc");
		fs::read_to_string(path).unwrap()
	}
}

impl Drop for Tmp {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).unwrap();
	}
}

fn run(cfg: &Config, h: &mut Handle, targets: &[&str]) -> (i32, Output) {
	let targets: Vec<Vec<u8>> =
		targets.iter().map(|t| t.as_bytes().to_vec()).collect();
	let mut o = Output::default();
	let ret = pacman_database(cfg, h, &targets, &mut o);
	(ret, o)
}

fn text(v: &[u8]) -> &str {
	std::str::from_utf8(v).unwrap()
}

#[test]
fn nothing_asked() {
	let tmp = Tmp::new("none");
	let (ret, o) = run(&Config::new(), &mut tmp.handle(), &["foo"]);
	assert_eq!((ret, o.stdout, o.stderr), (0, vec![], vec![]));
}

#[test]
fn check_local() {
	let tmp = Tmp::new("check");
	let mut cfg = Config::new();
	cfg.op_q_check = 1;
	let (ret, o) = run(&cfg, &mut tmp.handle(), &[]);
	assert_eq!(ret, 1);
	assert_eq!(text(&o.stdout), "");
	let err = "error: missing 'bar' dependency for 'foo'\n";
	assert_eq!(text(&o.stderr), err);
}

#[test]
fn reason() {
	let tmp = Tmp::new("reason");
	let mut cfg = Config::new();
	cfg.flags = TRANS_FLAG_ALLDEPS;
	let mut h = tmp.handle();
	let (ret, o) = run(&cfg, &mut h, &["foo", "nope"]);
	assert_eq!(ret, 1);
	let out = "foo: install reason has been set to \
		'installed as dependency'\n";
	assert_eq!(text(&o.stdout), out);
	let err = "error: could not set install reason for package nope \
		(could not find or read package)\n";
	assert_eq!(text(&o.stderr), err);
	assert!(tmp.desc().contains("%REASON%\n1\n"), "{}", tmp.desc());
	assert!(!h.is_locked());
	// no targets, no reason
	let (ret, o) = run(&cfg, &mut h, &[]);
	assert_eq!(ret, 1);
	let err = "error: no targets specified (use -h for help)\n";
	assert_eq!(text(&o.stderr), err);
}
