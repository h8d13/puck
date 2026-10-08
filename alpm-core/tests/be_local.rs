use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use alpm_core::be_local::{
	DbError, INFRQ_DESC, INFRQ_ERROR, INFRQ_FILES, INFRQ_SCRIPTLET,
	LocalDb, ReadError,
};
use alpm_core::deps::DepMod;
use alpm_core::error::Errno;
use alpm_core::package::{
	PKG_VALIDATION_SHA256SUM, PKG_VALIDATION_SIGNATURE, PkgFrom, PkgReason,
};

// <tmp>/alpm-core-be-local-<pid>-<name>/, removed on drop
struct Tmp(PathBuf);

impl Tmp {
	fn new(name: &str) -> Self {
		let dir = std::env::temp_dir().join(format!(
			"alpm-core-be-local-{}-{name}",
			std::process::id()
		));
		if dir.exists() {
			fs::remove_dir_all(&dir).unwrap();
		}
		fs::create_dir(&dir).unwrap();
		Tmp(dir)
	}

	fn dbpath(&self) -> Vec<u8> {
		[self.0.as_os_str().as_bytes(), b"/"].concat()
	}

	fn local(&self) -> PathBuf {
		self.0.join("local")
	}

	// local/ with a version file
	fn init(&self) {
		fs::create_dir(self.local()).unwrap();
		fs::write(self.local().join("ALPM_DB_VERSION"), "9\n").unwrap();
	}

	fn pkg(&self, dir: &str, desc: &str, files: &str) {
		let d = self.local().join(dir);
		fs::create_dir_all(&d).unwrap();
		fs::write(d.join("desc"), desc).unwrap();
		fs::write(d.join("files"), files).unwrap();
	}
}

impl Drop for Tmp {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).unwrap();
	}
}

const DESC: &str = "%NAME%\nfoo\n\n%VERSION%\n1:2.0-3\n\n%BASE%\nfoo-base\n\n\
	%DESC%\nA package\n\n%URL%\nhttps://example.org/\n\n%ARCH%\nx86_64\n\n\
	%BUILDDATE%\n1700000000\n\n%INSTALLDATE%\n1700000001\n\n\
	%PACKAGER%\nA B <a@b.org>\n\n%SIZE%\n18446744073709551615\n\n\
	%REASON%\n1\n\n%GROUPS%\ng1\ng2\n\n%LICENSE%\nMIT\n\n\
	%VALIDATION%\nsha256\npgp\nmd5\n\n\
	%DEPENDS%\nbar>=1.0\nlibx.so=1-64\n\n\
	%OPTDEPENDS%\nbaz: does things\n\n%XDATA%\npkgtype=pkg\n\n";
const FILES: &str = "%FILES%\nusr/\nusr/lib/a\nusr/lib-x\nusr/lib/\n\n\
	%BACKUP%\nusr/lib/a\td41d8cd98f00b204e9800998ecf8427e\n\n";

fn names(db: &LocalDb) -> Vec<String> {
	db.populate()
		.unwrap()
		.iter()
		.map(|p| {
			let n = p.name.clone().unwrap();
			let v = p.version.clone().unwrap();
			format!(
				"{}-{}",
				String::from_utf8(n).unwrap(),
				String::from_utf8(v).unwrap()
			)
		})
		.collect()
}

#[test]
fn register_creates_missing_db() {
	let t = Tmp::new("create");
	let db = LocalDb::register(&t.dbpath()).unwrap();
	assert_eq!(db.path(), [&t.dbpath()[..], b"local/"].concat());
	let ver = fs::read(t.local().join("ALPM_DB_VERSION")).unwrap();
	assert_eq!(ver, b"9\n");
	assert!(db.populate().unwrap().is_empty());
}

#[test]
fn register_version_file() {
	let t = Tmp::new("version");
	fs::create_dir(t.local()).unwrap();
	// empty db: version file written
	LocalDb::register(&t.dbpath()).unwrap();
	assert!(t.local().join("ALPM_DB_VERSION").exists());
	for (content, ok) in [
		("9", true),
		(" +09junk", true),
		("-18446744073709551607", true),
		("8\n", false),
		("", false),
		("x9", false),
	] {
		fs::write(t.local().join("ALPM_DB_VERSION"), content).unwrap();
		let r = LocalDb::register(&t.dbpath());
		assert_eq!(r.is_ok(), ok, "{content:?}");
		if let Err(e) = r {
			assert_eq!(e.errno(), Errno::DbVersion);
		}
	}
	// no version file but a package: version error, nothing written
	fs::remove_file(t.local().join("ALPM_DB_VERSION")).unwrap();
	fs::create_dir(t.local().join("p-1-1")).unwrap();
	let r = LocalDb::register(&t.dbpath());
	assert!(matches!(r, Err(DbError::Version)));
	assert!(!t.local().join("ALPM_DB_VERSION").exists());
}

#[test]
fn populate_entries() {
	let t = Tmp::new("populate");
	t.init();
	for dir in ["b-1-1", "a-x-2-1", "nodash", "-1-1", "c-1:1-1"] {
		fs::create_dir(t.local().join(dir)).unwrap();
	}
	fs::write(t.local().join("file-1-1"), "").unwrap();
	// stat follows the link: counts as a directory
	std::os::unix::fs::symlink(
		t.local().join("b-1-1"),
		t.local().join("link-1-1"),
	)
	.unwrap();
	let db = LocalDb::register(&t.dbpath()).unwrap();
	assert_eq!(names(&db), ["a-x-2-1", "b-1-1", "c-1:1-1", "link-1-1"]);
	let cache = db.populate().unwrap();
	let p = cache.find(b"a-x").unwrap();
	assert_eq!(p.origin, Some(PkgFrom::LocalDb));
	assert_eq!(p.infolevel, 0);
	// a duplicate name keeps one entry
	fs::create_dir(t.local().join("b-2-1")).unwrap();
	let n = names(&db);
	assert_eq!(n.iter().filter(|n| n.starts_with("b-")).count(), 1);
}

#[test]
fn read_sections() {
	let t = Tmp::new("read");
	t.init();
	t.pkg("foo-1:2.0-3", DESC, FILES);
	fs::write(t.local().join("foo-1:2.0-3/install"), "").unwrap();
	let db = LocalDb::register(&t.dbpath()).unwrap();
	let mut p = db.populate().unwrap().iter().next().unwrap().clone();
	db.read(&mut p, INFRQ_DESC).unwrap();
	assert_eq!(p.infolevel, INFRQ_DESC);
	assert!(p.files.files.is_empty());
	assert_eq!(p.base.as_deref(), Some(&b"foo-base"[..]));
	assert_eq!(p.url.as_deref(), Some(&b"https://example.org/"[..]));
	// u64::MAX wraps through the off_t cast
	assert_eq!(p.isize, -1);
	assert_eq!(p.reason, PkgReason::Depend);
	assert_eq!(p.groups, [b"g1".to_vec(), b"g2".to_vec()]);
	// md5 maps to no bit, like the C table
	assert_eq!(
		p.validation,
		PKG_VALIDATION_SHA256SUM | PKG_VALIDATION_SIGNATURE
	);
	assert_eq!(p.depends.len(), 2);
	assert_eq!(p.depends[0].depmod, DepMod::Ge);
	assert_eq!(p.depends[1].name, b"libx.so");
	let optdesc = p.optdepends[0].desc.as_deref();
	assert_eq!(optdesc, Some(&b"does things"[..]));
	assert_eq!(p.xdata.len(), 1);
	db.read(&mut p, INFRQ_FILES | INFRQ_SCRIPTLET).unwrap();
	let files: Vec<&[u8]> =
		p.files.files.iter().map(|f| &f.name[..]).collect();
	// strcmp order: '-' sorts before '/'
	let want: [&[u8]; 4] =
		[b"usr/", b"usr/lib-x", b"usr/lib/", b"usr/lib/a"];
	assert_eq!(files, want);
	assert_eq!(p.backup[0].name, b"usr/lib/a");
	assert_eq!(p.scriptlet, 1);
}

#[test]
fn read_error_is_sticky() {
	let t = Tmp::new("sticky");
	t.init();
	t.pkg("foo-1.0-1", "%BUILDDATE%\nx\n", FILES);
	let db = LocalDb::register(&t.dbpath()).unwrap();
	let fresh = db.populate().unwrap().iter().next().unwrap().clone();
	let mut p = fresh.clone();
	// files first: loaded, then the desc failure blocks later sections
	db.read(&mut p, INFRQ_FILES).unwrap();
	let r = db.read(&mut p, INFRQ_DESC);
	assert!(matches!(r, Err(ReadError::Desc(_))));
	assert_eq!(p.infolevel, INFRQ_FILES | INFRQ_ERROR);
	assert!(p.desc.is_none());
	let r = db.read(&mut p, INFRQ_SCRIPTLET);
	assert!(matches!(r, Err(ReadError::Earlier)));
	// loaded sections still answer
	db.read(&mut p, INFRQ_FILES).unwrap();
	assert_eq!(p.files.files.len(), 4);
	// a missing file is an io error
	let mut q = fresh;
	fs::remove_file(t.local().join("foo-1.0-1/files")).unwrap();
	let r = db.read(&mut q, INFRQ_FILES);
	assert!(matches!(r, Err(ReadError::Io(_))));
}
