// unit tests for alpm_core::be_sync, on uncompressed dbs written here
use std::fs;
use std::path::PathBuf;

use alpm_core::be_sync::{Error, Reason, db_path, get_validation, populate};
use alpm_core::error::Errno;
use alpm_core::package::{
	PKG_VALIDATION_NONE, PKG_VALIDATION_SHA256SUM,
	PKG_VALIDATION_SIGNATURE, Package, PkgFrom,
};

// <tmp>/db/sync/, removed on drop
struct Db(PathBuf);

impl Db {
	fn new(name: &str) -> Self {
		let dir = std::env::temp_dir().join(format!(
			"alpm-core-be-sync-{}-{name}",
			std::process::id()
		));
		if dir.exists() {
			fs::remove_dir_all(&dir).unwrap();
		}
		fs::create_dir_all(dir.join("sync")).unwrap();
		Db(dir)
	}

	fn dbpath(&self) -> Vec<u8> {
		let mut p =
			self.0.clone().into_os_string().into_encoded_bytes();
		p.push(b'/');
		p
	}

	fn write(&self, tar: &[u8]) {
		fs::write(self.0.join("sync/repo.db"), tar).unwrap();
	}

	fn path(&self) -> Vec<u8> {
		db_path(&self.dbpath(), b"repo", b".db")
	}

	fn load(&self) -> Result<Vec<Package>, Error> {
		let cache = populate(&self.path(), b".db", b"core", &mut ())?;
		Ok(cache.iter().cloned().collect())
	}
}

impl Drop for Db {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).unwrap();
	}
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

const DESC: &str = "%FILENAME%\nfoo-1-1-any.pkg.tar.zst\n\n\
	%NAME%\nfoo\n\n%BASE%\nfoo\n\n%VERSION%\n1-1\n\n\
	%DESC%\na  b\n\n%CSIZE%\n10\n\n%ISIZE%\n20\n\n\
	%SHA256SUM%\n0123456789abcdef0123456789abcdef\
	0123456789abcdef0123456789abcdef\n\n\
	%URL%\nhttps://example.org\n\n%ARCH%\nany\n\n\
	%BUILDDATE%\n30\n\n%PACKAGER%\nA B <a@b.org>\n\n\
	%DEPENDS%\nbar>=2\nlibx.so=1-64\n\n";

#[test]
fn path() {
	assert_eq!(db_path(b"/db/", b"core", b".db"), b"/db/sync/core.db");
}

#[test]
fn missing_and_empty() {
	let db = Db::new("missing");
	assert!(matches!(db.load(), Err(Error::NotFound)));
	db.write(b"");
	assert_eq!(db.load().unwrap(), vec![]);
}

#[test]
fn fields() {
	let db = Db::new("fields");
	db.write(&tar(&[
		("zed-2-1/desc", &DESC.replace("foo", "zed")),
		("foo-1-1/desc", DESC),
		("foo-1-1/files", "%FILES%\nusr/\nusr/b\nusr/a\n"),
	]));
	let pkgs = db.load().unwrap();
	let names: Vec<&[u8]> = pkgs.iter().map(Package::name_bytes).collect();
	assert_eq!(names, [&b"foo"[..], b"zed"]);
	let foo = &pkgs[0];
	assert_eq!(foo.origin, Some(PkgFrom::SyncDb));
	assert_eq!(foo.size, 10);
	assert_eq!(foo.builddate, 30);
	// as read like the C, alpm-types only normalizes their Display
	assert_eq!(foo.desc.as_deref(), Some(&b"a  b"[..]));
	assert_eq!(foo.url.as_deref(), Some(&b"https://example.org"[..]));
	assert_eq!(&*foo.depends[0].name, b"bar");
	assert_eq!(&*foo.depends[1].name, b"libx.so");
	let files: Vec<&[u8]> =
		foo.files.files.iter().map(|f| &f.name[..]).collect();
	assert_eq!(files, [&b"usr/"[..], b"usr/a", b"usr/b"]);
	// version comes from the entry name, not %VERSION%
	assert_eq!(pkgs[1].version.as_deref(), Some(&b"2-1"[..]));
}

#[test]
fn invalid_entries() {
	let db = Db::new("invalid");
	for name in ["foo/desc", "-foo-1-1/desc", "*-1-1/desc"] {
		db.write(&tar(&[(name, "")]));
		let e = db.load().unwrap_err();
		assert_eq!(e.errno(), Errno::DbInvalid, "{name}");
	}
	db.write(&tar(&[("foo-1-1/desc", "%DATA%\nnoequals\n\n")]));
	let e = db.load().unwrap_err();
	assert!(matches!(
		e,
		Error::Invalid {
			reason: Reason::XData(_),
			..
		}
	));
	// a list running into the end of the data
	db.write(&tar(&[("foo-1-1/desc", "%GROUPS%\ng")]));
	let e = db.load().unwrap_err();
	assert!(matches!(
		e,
		Error::Invalid {
			reason: Reason::Truncated,
			..
		}
	));
}

#[test]
fn validation() {
	let mut p = Package::default();
	assert_eq!(get_validation(&p), PKG_VALIDATION_NONE);
	p.sha256sum = Some(b"x"[..].into());
	p.base64_sig = Some(b"y"[..].into());
	let both = PKG_VALIDATION_SHA256SUM | PKG_VALIDATION_SIGNATURE;
	assert_eq!(get_validation(&p), both);
}

// the size estimate reads the dbext passed in, not the file name: a 3015
// byte uncompressed db per package, divided by 4 for ".files"
#[test]
fn estimate_follows_dbext() {
	let db = Db::new("estimate");
	db.write(&vec![0u8; 3015 * 40]);
	let buckets = |ext: &[u8]| {
		populate(&db.path(), ext, b"core", &mut ())
			.unwrap()
			.buckets()
	};
	// 41 / 0.58 + 1 = 71 gives 73, 10 / 0.58 + 1 = 18 gives 19
	assert_eq!(buckets(b".db"), 73);
	assert_eq!(buckets(b".files"), 19);
	assert_eq!(buckets(b".files\0x"), 19);
	assert_eq!(buckets(b""), 73);
}

// sync_db_validate where no gpg runs
#[test]
fn validate_without_signature() {
	use alpm_core::be_sync::sync_db_validate;
	use alpm_core::callbacks::{Callbacks, LogLevel};
	use alpm_core::signing::{
		Keyring, SIG_DATABASE, SIG_DATABASE_OPTIONAL,
	};
	struct Lines(Vec<Vec<u8>>);
	impl Callbacks for Lines {
		fn log(&mut self, _: LogLevel, msg: &[u8]) {
			self.0.push(msg.to_vec());
		}
	}
	let db = Db::new("validate");
	let mut kr = Keyring::new(b"/nonexistent/");
	kr.set_gpg("/nonexistent/gpg");
	let path = db.path();
	let cb = &mut ();
	// missing file: valid without a check
	let r = sync_db_validate(&mut kr, cb, &path, b"repo", SIG_DATABASE);
	assert_eq!(r, Ok(false));
	db.write(&tar(&[]));
	assert_eq!(sync_db_validate(&mut kr, cb, &path, b"repo", 0), Ok(true));
	let level = SIG_DATABASE | SIG_DATABASE_OPTIONAL;
	let r = sync_db_validate(&mut kr, cb, &path, b"repo", level);
	assert_eq!(r, Ok(true));
	let mut lines = Lines(Vec::new());
	let r = sync_db_validate(
		&mut kr,
		&mut lines,
		&path,
		b"repo",
		SIG_DATABASE,
	);
	assert_eq!(r, Err(Errno::DbInvalidSig));
	// signing.c's debug lines on the way, then the error
	let sig = [&path[..], b".sig"].concat();
	let expected: [&[u8]; 4] = [
		&[
			b"\"",
			&sig[..],
			b"\" is not readable: No such file or ",
			b"directory\n",
		]
		.concat(),
		&[b"sig path ", &sig[..], b" could not be opened\n"].concat(),
		b"missing required signature\n",
		b"repo: missing required signature\n",
	];
	assert_eq!(lines.0, expected);
}
