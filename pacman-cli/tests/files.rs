// unit tests for pacman_cli::files: dispatch and messages on a root with
// an empty .files db. searches and listings are compared against the C
// in the equivalence tests
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use alpm_core::handle::Handle;
use pacman_cli::conf::Config;
use pacman_cli::files::*;
use pacman_cli::sync::Unported;
use pacman_cli::util::Output;

// <tmp>/pacman-cli-files-<pid>-<name>/ with root/ and an empty
// db/sync/core.files, removed on drop
struct Tmp(PathBuf);

impl Tmp {
	fn new(name: &str) -> (Self, Handle) {
		let dir = std::env::temp_dir().join(format!(
			"pacman-cli-files-{}-{name}",
			std::process::id()
		));
		if dir.exists() {
			fs::remove_dir_all(&dir).unwrap();
		}
		fs::create_dir_all(dir.join("root")).unwrap();
		fs::create_dir_all(dir.join("db/sync")).unwrap();
		fs::write(dir.join("db/sync/core.files"), b"").unwrap();
		let path =
			|p: &str| dir.join(p).as_os_str().as_bytes().to_vec();
		let mut h =
			Handle::initialize(&path("root"), &path("db")).unwrap();
		h.set_dbext(b".files");
		h.register_syncdb(b"core", 0).unwrap();
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
) -> (Result<i32, Unported>, String, String) {
	let mut cfg = Config::new();
	set(&mut cfg);
	let mut out = Output::default();
	let t: Vec<&[u8]> = targets.iter().map(|t| t.as_bytes()).collect();
	let r = pacman_files(&cfg, h, &t, &mut out);
	let s = |v: Vec<u8>| String::from_utf8(v).unwrap();
	(r, s(out.stdout), s(out.stderr))
}

#[test]
fn dispatch() {
	let (_tmp, mut h) = Tmp::new("dispatch");
	assert_eq!(
		run(&mut h, |c| c.op_s_sync = 1, &[]).0,
		Err(Unported::Refresh)
	);
	let (r, _, e) = run(&mut h, |_| {}, &[]);
	assert_eq!(r, Ok(1));
	assert_eq!(e, "error: no targets specified (use -h for help)\n");
	// nothing to list, nothing to find: no message
	assert_eq!(
		run(&mut h, |c| c.op_q_list = 1, &[]),
		(Ok(0), String::new(), String::new())
	);
	assert_eq!(
		run(&mut h, |_| {}, &["foo", "/usr/bin/foo"]),
		(Ok(1), String::new(), String::new())
	);
}

#[test]
fn list_errors() {
	let (_tmp, mut h) = Tmp::new("list");
	let (r, o, e) =
		run(&mut h, |c| c.op_q_list = 1, &["core/", "a", "nope/a", ""]);
	assert_eq!((r, o.as_str()), (Ok(4), ""));
	assert_eq!(
		e,
		"error: invalid package: 'core/'\n\
		error: package 'a' was not found\n\
		error: package 'nope/a' was not found\n\
		error: package '' was not found\n"
	);
}

#[test]
fn bad_regex() {
	let (_tmp, mut h) = Tmp::new("regex");
	// every target is compiled first, the leading '/' of paths dropped
	let (r, _, e) =
		run(&mut h, |c| c.op_f_regex = 1, &["(", "ok", "//usr/["]);
	assert_eq!(r, Ok(1));
	assert_eq!(
		e,
		"error: invalid regular expression '('\n\
		error: invalid regular expression 'usr/['\n"
	);
}
