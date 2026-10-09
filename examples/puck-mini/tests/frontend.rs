// the three subcommands run against a hand-built fixture root in a temp
// dir (std::env::temp_dir, no /tmp): an empty local db, a sync .db with
// two packages, and one of them a real .pkg.tar.gz in a cache dir so the
// sync install needs no network. this is the M4 gate evidence.

use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use alpm_core::{Handle, compute_sha256sum};
use flate2::Compression;
use flate2::write::GzEncoder;
use puck_mini::{Cli, install, query_installed, search};

// a fresh temp dir, unique per test, removed at the end of each test
fn scratch() -> PathBuf {
	static N: AtomicUsize = AtomicUsize::new(0);
	let n = N.fetch_add(1, Ordering::Relaxed);
	let dir = std::env::temp_dir()
		.join(format!("puck-mini-{}-{n}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();
	// canonicalize: the handle realpaths root and dbpath
	fs::canonicalize(&dir).unwrap()
}

// "%KEY%\nv\n\n"
fn section(key: &str, value: &str) -> String {
	format!("%{key}%\n{value}\n\n")
}

// a gzip-compressed tar of (path, bytes) entries
fn targz(entries: &[(&str, &[u8])]) -> Vec<u8> {
	let mut tar = tar::Builder::new(Vec::new());
	for (path, data) in entries {
		let mut h = tar::Header::new_gnu();
		h.set_size(data.len() as u64);
		h.set_mode(0o644);
		h.set_cksum();
		tar.append_data(&mut h, path, &data[..]).unwrap();
	}
	let tar = tar.into_inner().unwrap();
	let mut gz = GzEncoder::new(Vec::new(), Compression::default());
	gz.write_all(&tar).unwrap();
	gz.finish().unwrap()
}

// a minimal but real package: .PKGINFO plus one file to extract
fn package_bytes(name: &str, ver: &str) -> Vec<u8> {
	let info = [
		format!("pkgname = {name}"),
		format!("pkgbase = {name}"),
		format!("pkgver = {ver}"),
		"pkgdesc = example package".to_string(),
		"url = https://example.org/".to_string(),
		"builddate = 1700000000".to_string(),
		"packager = A B <a@b.org>".to_string(),
		"size = 1".to_string(),
		"arch = x86_64".to_string(),
	]
	.join("\n") + "\n";
	targz(&[
		(".PKGINFO", info.as_bytes()),
		(&format!("usr/{name}"), b"x"),
	])
}

struct Fixture {
	root: Vec<u8>,
	dbpath: Vec<u8>,
	cachedir: Vec<u8>,
	dir: PathBuf,
}

impl Drop for Fixture {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.dir);
	}
}

// bytes of a path, as the handle takes them
fn b(p: &Path) -> Vec<u8> {
	p.as_os_str().as_bytes().to_vec()
}

// an empty local db, a cache dir with a real `bar` package, and a sync
// db `testrepo` holding `bar` (installable) and `baz` (search only)
fn build() -> Fixture {
	let dir = scratch();
	let root = dir.join("root");
	let dbpath = dir.join("db");
	let cachedir = dir.join("cache");
	fs::create_dir_all(&root).unwrap();
	fs::create_dir_all(dbpath.join("local")).unwrap();
	fs::write(dbpath.join("local/ALPM_DB_VERSION"), "9\n").unwrap();
	fs::create_dir_all(dbpath.join("sync")).unwrap();
	fs::create_dir_all(&cachedir).unwrap();

	// the cached bar package, then its checksums for the sync desc
	let file = "bar-2.0-1-x86_64.pkg.tar.gz";
	let pkgpath = cachedir.join(file);
	fs::write(&pkgpath, package_bytes("bar", "2.0-1")).unwrap();
	let sha = compute_sha256sum(&b(&pkgpath)).unwrap();
	let sha = String::from_utf8(sha).unwrap();
	let csize = fs::metadata(&pkgpath).unwrap().len();

	let bar_desc = [
		section("FILENAME", file),
		section("NAME", "bar"),
		section("BASE", "bar"),
		section("VERSION", "2.0-1"),
		section("DESC", "example bar package"),
		section("CSIZE", &csize.to_string()),
		section("ISIZE", "1"),
		section("SHA256SUM", &sha),
		section("ARCH", "x86_64"),
		section("BUILDDATE", "1700000000"),
		section("PACKAGER", "A B <a@b.org>"),
	]
	.concat();
	let baz_desc = [
		section("FILENAME", "baz-1.0-1-x86_64.pkg.tar.gz"),
		section("NAME", "baz"),
		section("BASE", "baz"),
		section("VERSION", "1.0-1"),
		section("DESC", "example baz package"),
		section("ARCH", "x86_64"),
	]
	.concat();
	let db = targz(&[
		("bar-2.0-1/desc", bar_desc.as_bytes()),
		("baz-1.0-1/desc", baz_desc.as_bytes()),
	]);
	fs::write(dbpath.join("sync/testrepo.db"), db).unwrap();

	Fixture {
		root: b(&root),
		dbpath: b(&dbpath),
		cachedir: b(&cachedir),
		dir,
	}
}

// a local db entry so query has something to list
fn install_local(dbpath: &[u8], name: &str, ver: &str) {
	let dir = Path::new(std::ffi::OsStr::from_bytes(dbpath))
		.join("local")
		.join(format!("{name}-{ver}"));
	fs::create_dir_all(&dir).unwrap();
	let desc = [section("NAME", name), section("VERSION", ver)].concat();
	fs::write(dir.join("desc"), desc).unwrap();
}

fn open(fx: &Fixture, with_repo: bool) -> Handle {
	let mut h = Handle::initialize(&fx.root, &fx.dbpath).unwrap();
	h.set_callbacks(Box::new(Cli));
	h.add_cachedir(&fx.cachedir);
	if with_repo {
		let server = [b"file://", &fx.cachedir[..]].concat();
		h.register_syncdb(b"testrepo", 0).unwrap();
		let dbs = h.dbs_mut();
		let db = dbs.sync.last_mut().unwrap();
		db.add_server(dbs.cb, &server).unwrap();
	}
	h
}

#[test]
fn query_lists_installed() {
	let fx = build();
	install_local(&fx.dbpath, "foo", "1.0-1");
	let mut h = open(&fx, false);
	let mut out = Vec::new();
	query_installed(&mut h, &mut out).unwrap();
	assert_eq!(out, b"foo 1.0-1\n", "{}", String::from_utf8_lossy(&out));
}

#[test]
fn search_finds_sync_packages() {
	let fx = build();
	let mut h = open(&fx, true);
	let mut out = Vec::new();
	let hits = search(&mut h, b"ba", &mut out).unwrap();
	let text = String::from_utf8_lossy(&out);
	assert_eq!(hits, 2, "{text}");
	assert!(text.contains("testrepo/bar 2.0-1"), "{text}");
	assert!(text.contains("testrepo/baz 1.0-1"), "{text}");
}

#[test]
fn install_commits_a_sync_package() {
	let fx = build();
	let mut h = open(&fx, true);
	let mut out = Vec::new();
	install(&mut h, b"testrepo", b"bar", &mut out).unwrap();
	let text = String::from_utf8_lossy(&out);
	assert!(text.contains("committed"), "{text}");

	// the package's file landed in the root
	let root = Path::new(std::ffi::OsStr::from_bytes(&fx.root));
	assert!(root.join("usr/bar").exists(), "usr/bar not extracted");

	// and it now shows as installed
	let mut listed = Vec::new();
	query_installed(&mut h, &mut listed).unwrap();
	let listed = String::from_utf8_lossy(&listed);
	assert!(listed.contains("bar 2.0-1"), "{listed}");
}
