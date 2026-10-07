// unit tests for be_local's mtree reading (alpm-mtree mapped onto what
// check.c reads)
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use alpm_compress::compression::{
	CompressionEncoder, CompressionSettings, GzipCompressionLevel,
};
use alpm_core::be_local::{
	LocalDb, MtreeError, MtreeType, parse_mtree, read_mtree,
};
use alpm_core::package::Package;

const SHA: &str =
	"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";
const MD5: &str = "0cc175b9c0f1b6a831c399e269772661";

fn text() -> String {
	format!("#mtree\n/set type=file uid=0 gid=0 mode=644\n\
		./b type=dir uid=1000 time=2.0 mode=0755\n\
		./a time=1.5 size=1 md5digest={MD5} sha256digest={SHA}\n\
		./c\\040d type=link link=a\\sb time=3.0 mode=777\n")
}

// <tmp>/alpm-core-be-local-mtree-<pid>-<name>/, removed on drop
struct Tmp(PathBuf);

impl Tmp {
	fn new(name: &str) -> Self {
		let dir = std::env::temp_dir().join(format!(
			"alpm-core-be-local-mtree-{}-{name}",
			std::process::id()
		));
		if dir.exists() {
			fs::remove_dir_all(&dir).unwrap();
		}
		fs::create_dir(&dir).unwrap();
		Tmp(dir)
	}
}

impl Drop for Tmp {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).unwrap();
	}
}

fn gzip(path: &PathBuf, data: &[u8]) {
	let settings = CompressionSettings::Gzip {
		compression_level: GzipCompressionLevel::default(),
	};
	let f = fs::File::create(path).unwrap();
	let mut enc = CompressionEncoder::new(f, &settings).unwrap();
	enc.write_all(data).unwrap();
	enc.finish().unwrap();
}

#[test]
fn entries_sorted_and_mapped() {
	let e = parse_mtree(text().as_bytes()).unwrap();
	let paths: Vec<&[u8]> = e.iter().map(|e| &e.path[..]).collect();
	assert_eq!(paths, [&b"./a"[..], b"./b", b"./c d"]);

	assert_eq!(e[0].kind, MtreeType::File);
	assert_eq!(
		(e[0].mode, e[0].uid, e[0].size, e[0].mtime),
		(0o644, 0, 1, 1)
	);
	assert_eq!(e[0].sha256.as_ref().unwrap().to_string(), SHA);
	assert_eq!(e[0].md5.as_ref().unwrap().to_string(), MD5);

	assert_eq!(e[1].kind, MtreeType::Dir);
	assert_eq!((e[1].mode, e[1].uid, e[1].size), (0o755, 1000, 0));
	assert!(e[1].sha256.is_none() && e[1].link.is_none());

	assert_eq!(e[2].kind, MtreeType::Link);
	assert_eq!(e[2].link.as_deref(), Some(&b"a b"[..]));
	assert_eq!((e[2].mode, e[2].mtime), (0o777, 3));
}

#[test]
fn rejected_data() {
	let bad = [
		"#mtree\n./a type=fifo uid=0 gid=0 mode=644 time=1.0\n",
		"#mtree\n./a type=file uid=0 gid=0 mode=644 time=1.0 size=1\n",
		"#mtree\n./a type=dir uid=0 gid=0 mode=0 time=1.0\n",
	];
	for b in bad {
		let r = parse_mtree(b.as_bytes());
		assert!(matches!(r, Err(MtreeError::Parse(_))), "{b:?}: {r:?}");
	}
	let r = parse_mtree(&b"#mtree\n./\xff type=dir\n"[..]);
	assert!(matches!(r, Err(MtreeError::Parse(_))), "{r:?}");
	// gzip magic, broken stream
	let r = parse_mtree(&[0x1f, 0x8b, 0, 1, 2, 3][..]);
	assert!(matches!(r, Err(MtreeError::Read(_))), "{r:?}");
	assert!(parse_mtree(&b""[..]).unwrap().is_empty());
}

#[test]
fn files_plain_gzip_missing() {
	let t = Tmp::new("files");
	let plain = t.0.join("plain");
	fs::write(&plain, text()).unwrap();
	let gz = t.0.join("gz");
	gzip(&gz, text().as_bytes());
	let a = read_mtree(plain.as_os_str().as_bytes()).unwrap();
	let b = read_mtree(gz.as_os_str().as_bytes()).unwrap();
	assert_eq!(a, b);
	assert_eq!(a.len(), 3);
	let none = t.0.join("none");
	let r = read_mtree(none.as_os_str().as_bytes());
	assert!(matches!(r, Err(MtreeError::Missing)), "{r:?}");
}

#[test]
fn local_db_pkgpath() {
	let t = Tmp::new("db");
	let local = t.0.join("local");
	fs::create_dir(&local).unwrap();
	fs::write(local.join("ALPM_DB_VERSION"), "9\n").unwrap();
	fs::create_dir(local.join("foo-1-1")).unwrap();
	gzip(&local.join("foo-1-1/mtree"), text().as_bytes());
	let dbpath = [t.0.as_os_str().as_bytes(), b"/"].concat();
	let db = LocalDb::register(&dbpath).unwrap();
	let pkg = Package {
		name: Some(b"foo".to_vec()),
		version: Some(b"1-1".to_vec()),
		..Package::default()
	};
	assert_eq!(db.mtree(&pkg).unwrap().len(), 3);
	let other = Package {
		version: Some(b"2-1".to_vec()),
		..pkg
	};
	assert!(matches!(db.mtree(&other), Err(MtreeError::Missing)));
}
