// unit tests for pacman_cli::query on a small root written here: a local
// db (foo explicit, bar a dependency of foo, baz with a group), installed
// files and a sync db "core" with a newer foo
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use alpm_core::Handle;
use pacman_cli::conf::{Config, LOG_ERROR, LOG_WARNING};
use pacman_cli::pacman::{PKG_LOCALITY_FOREIGN, PKG_LOCALITY_NATIVE};
use pacman_cli::query::{QueryEnv, pacman_query};
use pacman_cli::util::Output;

// <tmp>/pacman-cli-query-<pid>-<name>/ with root/ and db/, removed on drop
struct Tmp(PathBuf);

fn desc(name: &str, version: &str, extra: &str) -> String {
	format!(
		"%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%BASE%\n{name}\n\n\
		%DESC%\nthe {name} package\n\n%URL%\nhttps://e.org/\n\n\
		%ARCH%\nany\n\n%BUILDDATE%\n1\n\n%INSTALLDATE%\n2\n\n\
		%PACKAGER%\nA B <a@b.org>\n\n%SIZE%\n1\n\n\
		%VALIDATION%\nnone\n\n{extra}"
	)
}

// ustar with regular files only, short names
fn tar(files: &[(&str, &str)]) -> Vec<u8> {
	let mut b = tar::Builder::new(Vec::new());
	for (name, data) in files {
		let mut h = tar::Header::new_ustar();
		// raw name bytes, set_path would normalise them
		h.as_old_mut().name[..name.len()]
			.copy_from_slice(name.as_bytes());
		h.set_size(data.len() as u64);
		h.set_cksum();
		b.append(&h, data.as_bytes()).unwrap();
	}
	b.into_inner().unwrap()
}

const SYNC_FOO: &str = "%FILENAME%\nfoo-2-1-any.pkg.tar.zst\n\n\
	%NAME%\nfoo\n\n%BASE%\nfoo\n\n%VERSION%\n2-1\n\n%DESC%\nnew\n\n\
	%CSIZE%\n1\n\n%ISIZE%\n2\n\n%SHA256SUM%\n0123456789abcdef0123456789abcdef\
	0123456789abcdef0123456789abcdef\n\n%ARCH%\nany\n\n\
	%BUILDDATE%\n3\n\n%PACKAGER%\nA B <a@b.org>\n\n";

impl Tmp {
	fn new(name: &str) -> Self {
		let dir = std::env::temp_dir().join(format!(
			"pacman-cli-query-{}-{name}",
			std::process::id()
		));
		if dir.exists() {
			fs::remove_dir_all(&dir).unwrap();
		}
		fs::create_dir_all(dir.join("root/usr/bin")).unwrap();
		fs::create_dir_all(dir.join("db/sync")).unwrap();
		fs::write(dir.join("root/usr/bin/foo"), "x").unwrap();
		let local = dir.join("db/local");
		fs::create_dir_all(&local).unwrap();
		fs::write(local.join("ALPM_DB_VERSION"), "9\n").unwrap();
		let pkgs = [
			("foo", "1-1", "%DEPENDS%\nbar\n\n"),
			("bar", "1-1", "%REASON%\n1\n\n%PROVIDES%\nlibbar\n\n"),
			("baz", "1-1", "%GROUPS%\ng\n\n"),
		];
		for (name, version, extra) in pkgs {
			let d = local.join(format!("{name}-{version}"));
			fs::create_dir(&d).unwrap();
			fs::write(d.join("desc"), desc(name, version, extra))
				.unwrap();
			let files = format!(
				"%FILES%\nusr/\nusr/bin/\nusr/bin/{name}\n\n"
			);
			fs::write(d.join("files"), files).unwrap();
		}
		let db = tar(&[("foo-2-1/desc", SYNC_FOO)]);
		fs::write(dir.join("db/sync/core.db"), db).unwrap();
		Tmp(dir)
	}

	fn path(&self, rel: &str) -> Vec<u8> {
		self.0.join(rel).as_os_str().as_bytes().to_vec()
	}

	fn handle(&self, sync: bool) -> Handle {
		let mut h = Handle::initialize(
			&self.path("root"),
			&self.path("db"),
		)
		.unwrap();
		if sync {
			h.register_syncdb(b"core", 0).unwrap();
		}
		h
	}
}

impl Drop for Tmp {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).unwrap();
	}
}

fn config() -> Config {
	let mut c = Config::new();
	c.logmask = LOG_ERROR | LOG_WARNING;
	c
}

fn run(h: &mut Handle, c: &Config, targets: &[&[u8]]) -> (i32, String, String) {
	let targets: Vec<Vec<u8>> =
		targets.iter().map(|t| t.to_vec()).collect();
	let env = QueryEnv {
		cols: 80,
		path: None,
	};
	let mut o = Output::default();
	let ret = pacman_query(c, h, &env, &targets, &mut o);
	let s = |v: Vec<u8>| String::from_utf8(v).unwrap();
	(ret, s(o.stdout), s(o.stderr))
}

fn out(s: &str) -> (i32, String, String) {
	(0, s.to_string(), String::new())
}

#[test]
fn list_and_filters() {
	let t = Tmp::new("list");
	let mut h = t.handle(true);
	let mut c = config();
	assert_eq!(run(&mut h, &c, &[]), out("bar 1-1\nbaz 1-1\nfoo 1-1\n"));
	c.quiet = 1;
	assert_eq!(run(&mut h, &c, &[]), out("bar\nbaz\nfoo\n"));
	c.op_q_deps = 1;
	assert_eq!(run(&mut h, &c, &[]), out("bar\n"));
	c.op_q_deps = 0;
	c.op_q_explicit = 1;
	c.op_q_unrequired = 1;
	assert_eq!(run(&mut h, &c, &[]), out("baz\nfoo\n"));
	c.op_q_explicit = 0;
	c.op_q_unrequired = 0;
	c.op_q_locality = PKG_LOCALITY_NATIVE;
	assert_eq!(run(&mut h, &c, &[]), out("foo\n"));
	c.op_q_locality = PKG_LOCALITY_FOREIGN;
	assert_eq!(run(&mut h, &c, &[]), out("bar\nbaz\n"));
	// nothing matched is 1
	c.op_q_locality = PKG_LOCALITY_NATIVE | PKG_LOCALITY_FOREIGN;
	assert_eq!(run(&mut h, &c, &[]).0, 1);
}

#[test]
fn upgrades() {
	let t = Tmp::new("upgrade");
	let mut h = t.handle(true);
	let mut c = config();
	c.op_q_upgrade = 1;
	assert_eq!(run(&mut h, &c, &[]), out("foo 1-1 -> 2-1\n"));
	h.add_ignorepkg(b"f*");
	assert_eq!(run(&mut h, &c, &[]), out("foo 1-1 -> 2-1 [ignored]\n"));
	// no sync db at all
	let mut h = t.handle(false);
	let err = "error: no usable package repositories configured.\n";
	assert_eq!(run(&mut h, &c, &[]), (1, String::new(), err.into()));
}

#[test]
fn targets() {
	let t = Tmp::new("targets");
	let mut h = t.handle(false);
	let c = config();
	let r = run(&mut h, &c, &[b"local/foo", b"libbar", b"nope"]);
	let err = "error: package 'nope' was not found\n";
	assert_eq!(r, (1, "foo 1-1\nbar 1-1\n".into(), err.into()));
	// a readable file gets the -p hint
	let root = t.path("root/usr/bin/foo");
	let r = run(&mut h, &c, &[&root]);
	let p = String::from_utf8(root).unwrap();
	let err = format!(
		"error: package '{p}' was not found\nwarning: '{p}' is a file, \
		you might want to use -p/--file.\n"
	);
	assert_eq!(r, (1, String::new(), err));
}

#[test]
fn owners() {
	let t = Tmp::new("owns");
	let mut h = t.handle(false);
	let mut c = config();
	c.op_q_owns = 1;
	let root = String::from_utf8(t.path("root")).unwrap();
	let file = format!("{root}/usr/bin/foo");
	let r = run(&mut h, &c, &[file.as_bytes()]);
	assert_eq!(r, out(&format!("{file} is owned by foo 1-1\n")));
	// a directory lists every owner, with its '/'
	let dir = format!("{root}/usr/bin");
	let r = run(&mut h, &c, &[dir.as_bytes()]);
	let dir = format!("{dir}/");
	let owned: String = ["bar", "baz", "foo"]
		.iter()
		.map(|p| format!("{dir} is owned by {p} 1-1\n"))
		.collect();
	assert_eq!(r, out(&owned));
	// one count per target nobody owns
	let r = run(&mut h, &c, &[b"/", b""]);
	let err = "error: No package owns /\n\
		error: empty string passed to file owner query\n";
	assert_eq!(r, (2, String::new(), err.into()));
	let r = run(&mut h, &c, &[]);
	let err = "error: no targets specified (use -h for help)\n";
	assert_eq!(r, (1, String::new(), err.into()));
}

#[test]
fn search_and_groups() {
	let t = Tmp::new("search");
	let mut h = t.handle(false);
	let mut c = config();
	c.op_q_search = 1;
	c.quiet = 1;
	assert_eq!(run(&mut h, &c, &[b"^ba"]), out("bar\nbaz\n"));
	assert_eq!(
		run(&mut h, &c, &[b"zzz"]),
		(1, String::new(), String::new())
	);
	let err = "error: search failed: invalid regular expression\n";
	assert_eq!(run(&mut h, &c, &[b"("]), (1, String::new(), err.into()));
	c.op_q_search = 0;
	c.quiet = 0;
	c.group = 1;
	assert_eq!(run(&mut h, &c, &[]), out("g baz\n"));
	let r = run(&mut h, &c, &[b"g", b"h"]);
	let err = "error: group 'h' was not found\n";
	assert_eq!(r, (1, "g baz\n".into(), err.into()));
}

#[test]
fn package_files() {
	let t = Tmp::new("isfile");
	let mut h = t.handle(false);
	let mut c = config();
	c.op_q_isfile = 1;
	let missing = t.path("nothere.pkg.tar");
	let r = run(&mut h, &c, &[&missing]);
	let p = String::from_utf8(missing).unwrap();
	let err = format!(
		"error: could not load package '{p}': could not find or read \
		package\n"
	);
	assert_eq!(r, (1, String::new(), err));
}
