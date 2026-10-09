// unit tests for alpm_core::internals::handle, on roots under /tmp
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use alpm_core::internals::db::SIG_USE_DEFAULT;
use alpm_core::internals::error::Errno;
use alpm_core::internals::handle::{Handle, set_directory_option};

// <tmp>/alpm-core-handle-<pid>-<name>/{root,db}, removed on drop
struct Tmp(PathBuf);

impl Tmp {
	fn new(name: &str) -> Self {
		let dir = std::env::temp_dir().join(format!(
			"alpm-core-handle-{}-{name}",
			std::process::id()
		));
		if dir.exists() {
			fs::remove_dir_all(&dir).unwrap();
		}
		fs::create_dir_all(dir.join("root")).unwrap();
		fs::create_dir_all(dir.join("db")).unwrap();
		Tmp(dir.canonicalize().unwrap())
	}

	fn path(&self, rel: &str) -> Vec<u8> {
		self.0.join(rel).as_os_str().as_bytes().to_vec()
	}

	fn handle(&self) -> Handle {
		Handle::initialize(&self.path("root"), &self.path("db"))
			.unwrap()
	}
}

impl Drop for Tmp {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).unwrap();
	}
}

#[test]
fn initialize_normalizes_paths() {
	let t = Tmp::new("init");
	let h = Handle::initialize(&t.path("root//"), &t.path("db/./"))
		.unwrap();
	assert_eq!(h.root(), [t.path("root"), b"/".to_vec()].concat());
	assert_eq!(h.dbpath(), [t.path("db"), b"/".to_vec()].concat());
	assert_eq!(h.dbext(), b".db");
	assert_eq!(h.localdb().unwrap().name(), b"local");
	assert!(t.0.join("db/local/ALPM_DB_VERSION").exists());
	assert_eq!(
		Handle::initialize(b"/", &t.path("db")).unwrap().root(),
		b"/"
	);
}

#[test]
fn initialize_errors() {
	let t = Tmp::new("errors");
	fs::write(t.0.join("file"), "").unwrap();
	let init = |r: &str, d: &str| {
		Handle::initialize(&t.path(r), &t.path(d)).err()
	};
	assert_eq!(init("nope", "db"), Some(Errno::NotADir));
	assert_eq!(init("file", "db"), Some(Errno::NotADir));
	assert_eq!(init("root", "nope"), Some(Errno::NotADir));
	assert_eq!(Handle::initialize(b"", b"").err(), Some(Errno::NotADir));
	fs::write(t.0.join("db/local"), "").unwrap();
	assert_eq!(init("root", "db"), Some(Errno::DbOpen));
}

#[test]
fn directory_option_without_stat() {
	assert_eq!(set_directory_option(b"a/b", false), Ok(b"a/b/".to_vec()));
	assert_eq!(set_directory_option(b"a/", false), Ok(b"a/".to_vec()));
	assert_eq!(set_directory_option(b"", false), Ok(b"/".to_vec()));
}

#[test]
fn register_syncdb_names() {
	let t = Tmp::new("register");
	let mut h = t.handle();
	assert_eq!(h.register_syncdb(b"", 0).err(), Some(Errno::WrongArgs));
	assert_eq!(h.register_syncdb(b"a/b", 0).err(), Some(Errno::WrongArgs));
	assert_eq!(
		h.register_syncdb(b"local", 0).err(),
		Some(Errno::DbNotNull)
	);
	h.register_syncdb(b"core", SIG_USE_DEFAULT).unwrap();
	h.register_syncdb(b"extra", 0).unwrap();
	assert_eq!(h.register_syncdb(b"core", 0).err(), Some(Errno::DbNotNull));
	let names: Vec<&[u8]> = h.syncdbs().iter().map(|d| d.name()).collect();
	assert_eq!(names, [&b"core"[..], b"extra"]);
	assert_eq!(h.unregister_syncdb(b"core"), Ok(()));
	assert_eq!(h.unregister_syncdb(b"core"), Err(Errno::DbNotFound));
	h.register_syncdb(b"core", 0).unwrap();
	assert_eq!(h.syncdbs()[1].name(), b"core");
	h.unregister_all_syncdbs();
	assert!(h.syncdbs().is_empty());
	assert_eq!(h.unregister_localdb(), Ok(()));
	assert!(h.localdb().is_none());
	assert_eq!(h.unregister_localdb(), Err(Errno::DbNotFound));
	assert_eq!(
		h.register_syncdb(b"local", 0).err(),
		Some(Errno::DbNotNull)
	);
}

#[test]
fn dbext_applies_to_later_dbs() {
	let t = Tmp::new("dbext");
	let mut h = t.handle();
	h.register_syncdb(b"core", 0).unwrap();
	h.set_dbext(b".files");
	h.register_syncdb(b"extra", 0).unwrap();
	let dbpath = h.dbpath().to_vec();
	let path = |i: usize| h.syncdbs()[i].path().to_vec();
	assert_eq!(path(0), [&dbpath[..], b"sync/core.db"].concat());
	assert_eq!(path(1), [&dbpath[..], b"sync/extra.files"].concat());
}

#[test]
fn siglevels() {
	let t = Tmp::new("siglevel");
	let mut h = t.handle();
	assert_eq!(
		h.set_default_siglevel(SIG_USE_DEFAULT),
		Err(Errno::WrongArgs)
	);
	h.set_default_siglevel(5).unwrap();
	h.set_local_file_siglevel(SIG_USE_DEFAULT | 2);
	h.set_remote_file_siglevel(3);
	assert_eq!((h.local_file_siglevel(), h.remote_file_siglevel()), (5, 3));
	let db = h.register_syncdb(b"core", SIG_USE_DEFAULT | 1).unwrap();
	assert_eq!(db.siglevel(5), 5);
	assert_eq!(db.raw_siglevel(), SIG_USE_DEFAULT | 1);
	assert_eq!(h.localdb().unwrap().siglevel(5), 0);
}

#[test]
fn string_lists() {
	let t = Tmp::new("lists");
	let mut h = t.handle();
	h.add_ignorepkg(b"a");
	h.add_ignorepkg(b"a");
	assert!(h.remove_ignorepkg(b"a"));
	assert_eq!(h.ignorepkgs(), [b"a".to_vec()]);
	assert!(!h.remove_ignoregroup(b"a"));
	h.set_architectures(&[&b"x86_64"[..], b"any"]);
	h.add_architecture(b"i686\0junk");
	assert_eq!(h.architectures()[2], b"i686");
	h.set_noupgrades(&[&b"etc/*"[..], b"!etc/keep"]);
	assert_eq!(h.match_noupgrade(b"etc/x"), Some(false));
	assert_eq!(h.match_noupgrade(b"etc/keep"), Some(true));
	assert_eq!(h.match_noupgrade(b"usr/x"), None);
	h.add_noextract(b"usr/share/doc/*");
	assert_eq!(h.match_noextract(b"usr/share/doc/a"), Some(false));
	assert!(h.remove_noextract(b"usr/share/doc/*"));
	assert!(h.noextracts().is_empty());
}
