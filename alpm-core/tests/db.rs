// unit tests for alpm_core::db, on local dbs and uncompressed sync dbs
// written here
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use alpm_core::be_local::{INFRQ_DESC, INFRQ_ERROR, INFRQ_FILES};
use alpm_core::db::{CacheError, DB_USAGE_ALL, Db, db_cmp};
use alpm_core::error::Errno;
use alpm_core::package::{Package, PkgFrom};
use alpm_core::util::hash_sdbm;

// handle->dbext, what loading a sync cache reads
const DBEXT: &[u8] = b".db";

// <tmp>/alpm-core-db-<pid>-<name>/ as dbpath, removed on drop
struct Tmp(PathBuf);

impl Tmp {
	fn new(name: &str) -> Self {
		let dir = std::env::temp_dir().join(format!(
			"alpm-core-db-{}-{name}",
			std::process::id()
		));
		if dir.exists() {
			fs::remove_dir_all(&dir).unwrap();
		}
		fs::create_dir_all(dir.join("sync")).unwrap();
		Tmp(dir)
	}

	fn dbpath(&self) -> Vec<u8> {
		[self.0.as_os_str().as_bytes(), b"/"].concat()
	}

	// local entry name-1-1 with a desc listing groups
	fn local_pkg(&self, name: &str, groups: &[&str]) {
		let dir = self.0.join(format!("local/{name}-1-1"));
		fs::create_dir_all(&dir).unwrap();
		fs::write(self.0.join("local/ALPM_DB_VERSION"), "9\n").unwrap();
		let groups = match groups.is_empty() {
			true => String::new(),
			false => format!("%GROUPS%\n{}\n\n", groups.join("\n")),
		};
		let desc = format!(
			"%NAME%\n{name}\n\n%VERSION%\n1-1\n\n%BASE%\n{name}\n\n\
			%DESC%\nd\n\n%URL%\nhttps://e.org/\n\n%ARCH%\nany\n\n\
			%BUILDDATE%\n1\n\n%INSTALLDATE%\n2\n\n\
			%PACKAGER%\nA B <a@b.org>\n\n%SIZE%\n1\n\n\
			%VALIDATION%\nnone\n\n{groups}"
		);
		fs::write(dir.join("desc"), desc).unwrap();
	}

	fn local(&self) -> Db {
		Db::register_local(&self.dbpath()).unwrap()
	}
}

impl Drop for Tmp {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).unwrap();
	}
}

fn names(db: &mut Db) -> Vec<Vec<u8>> {
	let cache = db.pkgcache(DBEXT).unwrap();
	cache.iter().map(|p| p.name.clone().unwrap()).collect()
}

fn pkg(name: &str, version: &str) -> Package {
	Package {
		name_hash: hash_sdbm(name.as_bytes()),
		name: Some(name.as_bytes().to_vec()),
		version: Some(version.as_bytes().to_vec()),
		infolevel: INFRQ_DESC,
		..Package::default()
	}
}

#[test]
fn servers() {
	let t = Tmp::new("servers");
	let mut db = Db::register_sync(&t.dbpath(), b".db", b"core", 0);
	assert_eq!(db.add_server(b""), Err(Errno::WrongArgs));
	for url in [&b"a//"[..], b"/", b"http://m/x/", b"b\0junk"] {
		db.add_server(url).unwrap();
	}
	let want: [&[u8]; 4] = [b"a/", b"", b"http://m/x", b"b"];
	assert_eq!(db.servers(), want);
	assert_eq!(db.remove_server(b"http://m/x//"), Ok(false));
	assert_eq!(db.remove_server(b"http://m/x/"), Ok(true));
	assert_eq!(db.remove_server(b"/"), Ok(true));
	assert_eq!(db.remove_server(b""), Err(Errno::WrongArgs));
	assert_eq!(
		db.set_cache_servers(&[&b"x/"[..], b"", b"y"]),
		Err(Errno::WrongArgs)
	);
	assert_eq!(db.cache_servers(), [b"x".to_vec()]);
	db.set_cache_servers::<&[u8]>(&[]).unwrap();
	assert!(db.cache_servers().is_empty());
}

#[test]
fn usage_siglevel_cmp() {
	let t = Tmp::new("usage");
	let mut a = Db::register_sync(&t.dbpath(), b".db", b"a", 7);
	let b = Db::register_sync(&t.dbpath(), b".db", b"b", 0);
	assert_eq!(a.usage(), DB_USAGE_ALL);
	a.set_usage(-3);
	assert_eq!(a.usage(), -3);
	assert_eq!(a.siglevel(1), 7);
	assert!(db_cmp(&a, &b).is_lt());
	assert!(!a.is_local());
}

#[test]
fn missing_sync_db() {
	let t = Tmp::new("missing");
	let mut db = Db::register_sync(&t.dbpath(), b".db", b"core", 0);
	assert_eq!(db.path(), [&t.dbpath()[..], b"sync/core.db"].concat());
	assert_eq!(db.valid(), Ok(()));
	assert_eq!(db.pkgcache(DBEXT).err(), Some(Errno::DbNotFound));
	// missing is decided at registration
	fs::write(t.0.join("sync/core.db"), "").unwrap();
	assert_eq!(db.pkgcache(DBEXT).err(), Some(Errno::DbNotFound));
	assert_eq!(db.get_pkg(DBEXT, b"a").err(), Some(Errno::PkgNotFound));
	assert_eq!(db.groupcache(DBEXT).err(), Some(Errno::DbNotFound));
	assert_eq!(db.groupcache(DBEXT).map(|g| g.len()), Ok(0));
}

#[test]
fn bad_sync_db_turns_invalid() {
	let t = Tmp::new("invalid");
	fs::create_dir(t.0.join("sync/core.db")).unwrap();
	let mut db = Db::register_sync(&t.dbpath(), b".db", b"core", 0);
	assert!(db.pkgcache(DBEXT).is_err());
	assert_eq!(db.valid(), Err(Errno::DbInvalidSig));
	assert_eq!(db.pkgcache(DBEXT).err(), Some(Errno::DbInvalid));
	assert_eq!(db.groupcache(DBEXT).err(), Some(Errno::DbInvalid));
}

#[test]
fn local_pkgcache_and_get_pkg() {
	let t = Tmp::new("local");
	t.local_pkg("b", &[]);
	t.local_pkg("a", &[]);
	let mut db = t.local();
	assert!(db.is_local());
	assert_eq!(db.path(), [&t.dbpath()[..], b"local/"].concat());
	assert_eq!(names(&mut db), [b"a".to_vec(), b"b".to_vec()]);
	assert_eq!(db.get_pkg(DBEXT, b"").err(), Some(Errno::WrongArgs));
	assert_eq!(db.get_pkg(DBEXT, b"c").err(), Some(Errno::PkgNotFound));
	let a = db.get_pkg(DBEXT, b"a\0x").unwrap();
	assert_eq!(a.origin, Some(PkgFrom::LocalDb));
}

#[test]
fn groupcache_order() {
	let t = Tmp::new("groups");
	t.local_pkg("b", &["x", "y"]);
	t.local_pkg("a", &["y", "y", "z"]);
	fs::create_dir(t.0.join("local/c-1-1")).unwrap();
	let mut db = t.local();
	let groups = db.groupcache(DBEXT).unwrap();
	let got: Vec<(&[u8], Vec<&[u8]>)> = groups
		.iter()
		.map(|g| {
			let members = g.packages.iter().map(|p| p.name_bytes());
			(&g.name[..], members.collect())
		})
		.collect();
	let want: Vec<(&[u8], Vec<&[u8]>)> = vec![
		(b"y", vec![b"a", b"b"]),
		(b"y", vec![b"a"]),
		(b"z", vec![b"a"]),
		(b"x", vec![b"b"]),
	];
	assert_eq!(got, want);
	let y = db.get_group(DBEXT, b"y").unwrap().unwrap();
	assert_eq!(y.packages.len(), 2);
	assert_eq!(db.get_group(DBEXT, b"none").unwrap(), None);
	assert_eq!(db.get_group(DBEXT, b"").err(), Some(Errno::WrongArgs));
	// alpm_pkg_get_groups loaded each desc into its cache entry
	let a = db.get_pkg(DBEXT, b"a").unwrap();
	assert_eq!(a.infolevel & INFRQ_DESC, INFRQ_DESC);
	assert_eq!(a.desc.as_deref(), Some(&b"d"[..]));
	let c = db.get_pkg(DBEXT, b"c").unwrap();
	assert_eq!(c.infolevel & INFRQ_ERROR, INFRQ_ERROR);
}

#[test]
fn cache_add_remove() {
	let t = Tmp::new("cache");
	t.local_pkg("b", &[]);
	let mut db = t.local();
	assert_eq!(
		db.add_pkg_in_cache(&pkg("a", "1")),
		Err(CacheError::NotLoaded)
	);
	assert_eq!(
		db.remove_pkg_from_cache(&pkg("b", "1")).err(),
		Some(CacheError::NotLoaded)
	);
	db.pkgcache(DBEXT).unwrap();
	let mut file = pkg("c", "2");
	file.origin = Some(PkgFrom::File(b"/x.pkg".to_vec()));
	file.groups = vec![b"g".to_vec()];
	file.makedepends = vec![alpm_core::deps::dep_from_string(b"m")];
	db.add_pkg_in_cache(&file).unwrap();
	db.add_pkg_in_cache(&pkg("a", "1")).unwrap();
	db.add_pkg_in_cache(&pkg("a", "2")).unwrap();
	assert_eq!(
		names(&mut db),
		[b"a", b"a", b"b", b"c"].map(|n| n.to_vec())
	);
	let c = db.get_pkg(DBEXT, b"c").unwrap();
	assert_eq!(c.origin, Some(PkgFrom::LocalDb));
	assert!(c.makedepends.is_empty());
	assert_eq!(
		db.get_group(DBEXT, b"g").unwrap().unwrap().packages.len(),
		1
	);
	// first in probe order, the earlier add
	let gone = db.remove_pkg_from_cache(&pkg("a", "")).unwrap();
	assert_eq!(gone.version.as_deref(), Some(&b"1"[..]));
	let mut stale = pkg("b", "");
	stale.name_hash ^= 1;
	assert_eq!(
		db.remove_pkg_from_cache(&stale).err(),
		Some(CacheError::NotFound)
	);
	db.remove_pkg_from_cache(&pkg("c", "")).unwrap();
	assert_eq!(db.get_group(DBEXT, b"g").unwrap(), None);
	assert_eq!(CacheError::Memory.errno(), Some(Errno::Memory));
	assert_eq!(CacheError::NotFound.errno(), None);
}

#[test]
fn free_pkgcache_drops_groups() {
	let t = Tmp::new("free");
	t.local_pkg("a", &["g"]);
	let mut db = t.local();
	assert_eq!(db.groupcache(DBEXT).unwrap().len(), 1);
	db.free_pkgcache();
	t.local_pkg("b", &["h"]);
	assert_eq!(db.groupcache(DBEXT).unwrap().len(), 2);
}

// details loaded through load_pkg stay in the cache entry
#[test]
fn load_pkg_in_place() {
	let t = Tmp::new("load");
	t.local_pkg("a", &["g"]);
	let mut db = t.local();
	assert_eq!(
		db.load_pkg(DBEXT, b"", INFRQ_DESC).err(),
		Some(Errno::WrongArgs)
	);
	assert_eq!(
		db.load_pkg(DBEXT, b"b", INFRQ_DESC).err(),
		Some(Errno::PkgNotFound)
	);
	assert_eq!(db.get_pkg(DBEXT, b"a").unwrap().desc, None);
	let a = db.load_pkg(DBEXT, b"a", INFRQ_DESC).unwrap();
	assert_eq!(a.groups, [b"g".to_vec()]);
	let a = db.get_pkg(DBEXT, b"a").unwrap();
	assert_eq!(a.desc.as_deref(), Some(&b"d"[..]));
	// no files file: the error sticks to the entry too
	db.load_pkg(DBEXT, b"a", INFRQ_FILES).unwrap();
	let a = db.get_pkg(DBEXT, b"a").unwrap();
	assert_eq!(a.infolevel & INFRQ_ERROR, INFRQ_ERROR);
	assert_eq!(a.infolevel & INFRQ_FILES, 0);
}

// the path is fixed at registration, the size estimate of the first load
// follows the dbext passed then
#[test]
fn sync_load_reads_current_dbext() {
	let t = Tmp::new("dbext");
	fs::write(t.0.join("sync/core.db"), vec![0u8; 3015 * 40]).unwrap();
	let mut db = Db::register_sync(&t.dbpath(), b".db", b"core", 0);
	assert_eq!(db.pkgcache(b".files").unwrap().buckets(), 19);
	db.free_pkgcache();
	assert_eq!(db.pkgcache(b".db").unwrap().buckets(), 73);
	assert_eq!(db.path(), [&t.dbpath()[..], b"sync/core.db"].concat());
}
