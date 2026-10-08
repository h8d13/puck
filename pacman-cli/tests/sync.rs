// unit tests for pacman_cli::sync: dispatch and messages on a root with
// empty sync dbs (an empty file loads as a db without packages). the
// listings themselves are compared against the C in the equivalence tests
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use alpm_core::handle::Handle;
use pacman_cli::conf::Config;
use pacman_cli::sync::*;
use pacman_cli::util::Output;

// <tmp>/pacman-cli-sync-<pid>-<name>/ with root/ and db/sync/<repo>.db
// for each repo, removed on drop
struct Tmp(PathBuf);

impl Tmp {
	fn new(name: &str, repos: &[&str]) -> (Self, Handle) {
		let dir = std::env::temp_dir().join(format!(
			"pacman-cli-sync-{}-{name}",
			std::process::id()
		));
		if dir.exists() {
			fs::remove_dir_all(&dir).unwrap();
		}
		fs::create_dir_all(dir.join("root")).unwrap();
		fs::create_dir_all(dir.join("db/sync")).unwrap();
		for r in repos {
			fs::write(dir.join(format!("db/sync/{r}.db")), b"")
				.unwrap();
		}
		let path =
			|p: &str| dir.join(p).as_os_str().as_bytes().to_vec();
		let mut h =
			Handle::initialize(&path("root"), &path("db")).unwrap();
		for r in repos {
			h.register_syncdb(r.as_bytes(), 0).unwrap();
		}
		(Tmp(dir), h)
	}
}

impl Drop for Tmp {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).unwrap();
	}
}

fn run(
	h: &mut Handle,
	set: fn(&mut Config),
	targets: &[&str],
) -> (Result<i32, Deferred>, String, String) {
	let mut cfg = Config::new();
	set(&mut cfg);
	let mut out = Output::default();
	let t: Vec<&[u8]> = targets.iter().map(|t| t.as_bytes()).collect();
	let r = pacman_sync(&cfg, h, &t, 80, &mut out);
	let s = |v: Vec<u8>| String::from_utf8(v).unwrap();
	(r, s(out.stdout), s(out.stderr))
}

#[test]
fn no_repos() {
	let (_tmp, mut h) = Tmp::new("none", &[]);
	let (r, o, e) = run(&mut h, |c| c.op_s_info = 1, &["a"]);
	assert_eq!(r, Ok(1));
	assert_eq!(o, "");
	assert_eq!(e, "error: no usable package repositories configured.\n");
	// -Sc comes before the check, -Sy after it
	assert_eq!(
		run(&mut h, |c| c.op_s_clean = 1, &[]).0,
		Err(Deferred::Clean)
	);
	assert_eq!(run(&mut h, |c| c.op_s_sync = 1, &[]).0, Ok(1));
	// logmask hides the message, not the result
	let (r, _, e) = run(&mut h, |c| c.logmask = 0, &[]);
	assert_eq!((r, e.as_str()), (Ok(1), ""));
}

#[test]
fn dispatch() {
	let (_tmp, mut h) = Tmp::new("dispatch", &["core"]);
	// -y on a repo without servers: alpm_db_update refuses it
	let (r, o, e) = run(&mut h, |c| c.op_s_sync = 1, &[]);
	assert_eq!(r, Ok(1));
	assert_eq!(o, ":: Synchronizing package databases...\n");
	assert_eq!(
		e,
		"error: failed to synchronize all databases (no servers \
		 configured for repository)\n"
	);
	assert!(run(&mut h, |c| c.op_s_search = 1, &[]).0.is_ok());
	assert_eq!(run(&mut h, |_| {}, &["a"]).0, Err(Deferred::Transaction));
	assert_eq!(
		run(&mut h, |c| c.op_s_upgrade = 1, &[]).0,
		Err(Deferred::Transaction)
	);
	let (r, _, e) = run(&mut h, |_| {}, &[]);
	assert_eq!(r, Ok(1));
	assert_eq!(e, "error: no targets specified (use -h for help)\n");
	// group comes before info and list
	let (r, _, e) = run(
		&mut h,
		|c| {
			c.group = 1;
			c.op_s_info = 1;
			c.op_q_list = 1;
		},
		&["g"],
	);
	assert_eq!(r, Ok(1));
	assert_eq!(e, "error: package group 'g' was not found\n");
}

#[test]
fn misses() {
	let (_tmp, mut h) = Tmp::new("misses", &["core", "extra"]);
	let (r, o, e) =
		run(&mut h, |c| c.op_s_info = 1, &["a", "nope/a", "core/a/b"]);
	assert_eq!(r, Ok(4));
	assert_eq!(o, "");
	assert_eq!(
		e,
		"error: package 'a' was not found\n\
		error: repository 'nope' does not exist\n\
		error: package 'nope/a' was not found\n\
		error: package 'core/a/b' was not found\n"
	);
	// unknown repos are reported, the others listed (empty here)
	let (r, o, e) = run(&mut h, |c| c.op_q_list = 1, &["core", "nope", ""]);
	assert_eq!((r, o.as_str()), (Ok(1), ""));
	assert_eq!(
		e,
		"error: repository \"nope\" was not found.\n\
		error: repository \"\" was not found.\n"
	);
	// no groups anywhere: 1 without a message
	assert_eq!(
		run(&mut h, |c| c.group = 2, &[]),
		(Ok(1), String::new(), String::new())
	);
	let (r, _, e) = run(&mut h, |c| c.group = 1, &[""]);
	assert_eq!(r, Ok(1));
	assert_eq!(e, "error: package group '' was not found\n");
}
