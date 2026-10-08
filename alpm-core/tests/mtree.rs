// unit tests for alpm_core::mtree (libarchive's mtree reader) and
// be_local's mtree file reading on top of it
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use alpm_compress::compression::{
	CompressionEncoder, CompressionSettings, GzipCompressionLevel,
};
use alpm_core::be_local::{LocalDb, MtreeError, read_mtree};
use alpm_core::mtree::{Entry, EntryType, Error, read, read_memory};
use alpm_core::package::Package;

const SHA: &str =
	"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";
const MD5: &str = "0cc175b9c0f1b6a831c399e269772661";
const SET: &str = "#mtree\n/set type=file uid=0 gid=0 mode=644\n";

fn text() -> String {
	format!("#mtree\n/set type=file uid=0 gid=0 mode=644\n\
		./b type=dir uid=1000 time=2.0 mode=0755\n\
		./a time=1.5 size=1 md5digest={MD5} sha256digest={SHA}\n\
		./c\\040d type=link link=a\\sb time=3.0 mode=777\n")
}

fn entries(data: &str) -> Vec<Entry> {
	read(data.as_bytes()).unwrap_or_else(|e| panic!("{e:?}\n{data}"))
}

fn paths(data: &str) -> Vec<Vec<u8>> {
	entries(data).into_iter().map(|e| e.path).collect()
}

fn warning(e: &Entry) -> String {
	String::from_utf8_lossy(e.warning.as_deref().unwrap_or(b"")).into()
}

fn header(data: &[u8]) -> String {
	match read(data) {
		Err(Error::Header(t)) => String::from_utf8_lossy(&t).into(),
		r => panic!("{r:?}"),
	}
}

#[test]
fn entries_in_file_order() {
	let e = entries(&text());
	let p: Vec<&[u8]> = e.iter().map(|e| &e.path[..]).collect();
	assert_eq!(p, [&b"./b"[..], b"./a", b"./c d"]);
	assert_eq!(e[1].kind, EntryType::File);
	assert_eq!(
		(e[1].mode, e[1].uid, e[1].size, e[1].mtime),
		(0o644, 0, 1, 1)
	);
	assert_eq!(e[1].sha256.as_ref().unwrap().to_string(), SHA);
	assert_eq!(e[1].md5.as_ref().unwrap().to_string(), MD5);
	assert_eq!(
		(e[0].kind, e[0].mode, e[0].uid),
		(EntryType::Dir, 0o755, 1000)
	);
	assert!(e[0].sha256.is_none() && e[0].link.is_none());
	assert_eq!(e[2].link.as_deref(), Some(&b"a b"[..]));
	assert!(e.iter().all(|e| e.warning.is_none()));
}

// mode_t bits above the type stay, the type comes from type=
#[test]
fn keyword_values() {
	let one = |kw: &str| entries(&format!("{SET}./a {kw}\n")).remove(0);
	assert_eq!(one("mode=0").mode, 0);
	assert_eq!(one("mode=44").mode, 0o44);
	assert_eq!(one("mode=0100644").mode, 0o644);
	assert_eq!(one("mode=7777777").mode, 0o7607777);
	assert_eq!(one("size=+5").size, 0);
	assert_eq!(one("size=-5").size, 0);
	assert_eq!(one("size=12x").size, 12);
	assert_eq!(one("uid=4294967296").uid, 4294967296);
	assert_eq!(one("uid=-1").uid, 0);
	assert_eq!(one("gid=99999999999999999999").gid, i64::MAX);
	assert_eq!(one("time=7").mtime, 7);
	assert_eq!(one("time=-5.3").mtime, -5);
	assert_eq!(one("time=-99999999999999999999").mtime, i64::MIN);
	assert_eq!(one("link=").link.as_deref(), Some(&b""[..]));
}

// line keywords newest first, then /set ones oldest first: the last read
// of sha256/sha256digest wins
#[test]
fn keyword_order() {
	let other = "0".repeat(64);
	let e = entries(&format!(
		"{SET}/set sha256={SHA}\n/set sha256digest={other}\n./a\n\
		./b sha256={other} sha256digest={SHA} sha256={other}\n"
	));
	assert_eq!(e[0].sha256.as_ref().unwrap().to_string(), other);
	assert_eq!(e[1].sha256.as_ref().unwrap().to_string(), SHA);
}

#[test]
fn duplicates_merge() {
	let e = entries(&format!(
		"{SET}./a size=3\n./b\n./a time=5\n./\\141 uid=3 type=dir\n\
		./\\141\\0x type=link\n"
	));
	assert_eq!(e.len(), 2);
	assert_eq!(e[0].path, b"./a");
	// each line carries the /set keywords again: uid=0 of the last wins
	assert_eq!(
		(e[0].kind, e[0].mtime, e[0].uid, e[0].size),
		(EntryType::Link, 5, 0, 3)
	);
}

#[test]
fn file_types() {
	let e = entries(
		"#mtree\n./b type=block\n./c type=char\n./d type=dir\n\
		./p type=fifo\n./f type=file\n./l type=link\n",
	);
	let t: Vec<EntryType> = e.iter().map(|e| e.kind).collect();
	use EntryType::*;
	assert_eq!(t, [Block, Char, Dir, Fifo, File, Link]);
}

#[test]
fn set_and_unset() {
	let e = entries(
		"#mtree\n/set type=dir uid=1 time=2\n./a\n/unset uid\n./b\n\
		/unset all\n./c type=file\n",
	);
	assert_eq!((e[0].uid, e[0].mtime), (1, 2));
	assert_eq!((e[1].uid, e[1].mtime), (0, 2));
	assert_eq!((e[2].mtime, e[2].kind), (0, EntryType::File));
}

#[test]
fn escapes() {
	let cases: [(&str, &[u8]); 8] = [
		(r"./a\#b", b"./a\\#b"),
		(r"./a\\b", b"./a\\b"),
		(r"./a\sb", b"./a b"),
		(r"./a\040b", b"./a b"),
		(r"./a\377", b"./a\xff"),
		(r"./a\xb\400", b"./a\\xb\\400"),
		(r"./a\0b", b"./a"),
		(r"./a\01x", b"./a\\01x"),
	];
	for (raw, want) in cases {
		let e = entries(&format!("{SET}{raw}\n"));
		assert_eq!(e[0].path, want, "{raw}");
	}
}

// whitespace, continuations (also "\\\r\n"), CRLF ends, comments
#[test]
fn line_syntax() {
	let e = entries(&format!(
		"{SET}  ./a\tsize=1 \\\n uid=2  \r\n\t# comment\n./b \\\r\n uid=3\n\
		./c uid=4 # x\n"
	));
	assert_eq!((e[0].size, e[0].uid, e[1].uid), (1, 2, 3));
	// '#' after the path is a keyword without '='
	assert!(warning(&e[2]).starts_with("Malformed attribute \"#\" (35)"));
	// a last line without newline is not read
	assert_eq!(paths(&format!("{SET}./a\n./b")), [b"./a"]);
}

// relative paths are below the last relative dir, ".." goes up
#[test]
fn relative_paths() {
	let p = paths("#mtree\n/set type=dir\nusr\n./x type=file\nbin\n..\n\
		lib type=file\n..\n..\nz\n");
	let want: [&[u8]; 5] = [b"usr", b"./x", b"usr/bin", b"usr/lib", b"z"];
	assert_eq!(p, want);
	// relative and full paths never merge
	let e = entries(
		"#mtree\na type=file\n./a type=file uid=3\na type=file\n",
	);
	assert_eq!(e.len(), 3);
}

// warnings: libarchive's text, the keyword's value not read
#[test]
fn warnings() {
	let cases = [
		("foo=1", "Unrecognized key foo=1"),
		("foo", "Malformed attribute \"foo\" (102)"),
		("nochange=1", "Unrecognized key nochange=1"),
		(
			"type=fi",
			"Unrecognized file type \"fi\"; assuming \"file\"",
		),
		("mode=u+x", "Symbolic or non-octal mode \"u+x\" unsupported"),
		("md5=abc", "incorrect digest length, ignoring"),
		(
			&format!("sha256={}", SHA.to_uppercase()),
			"invalid digest data, ignoring",
		),
		("device=foo,1,2", "Unknown format `foo'"),
		("device=linux,1", "Not enough arguments"),
		("device=linux,1,,2", "Missing number"),
		("device=bsdos,1,2,3,4", "Too many arguments"),
		("device=linux,256,1", "invalid major number"),
		("device=linux,256,256", "invalid minor number"),
		("device=native,4294967296,1", "invalid major number"),
		("device=linux,1,2,3", "too many fields for format"),
		("device=bsdos,1,1,256", "invalid subunit number"),
	];
	for (kw, want) in cases {
		let e = entries(&format!("{SET}./a time=1 {kw}\n"));
		assert_eq!(warning(&e[0]), want, "{kw}");
		assert_eq!((e[0].kind, e[0].mtime), (EntryType::File, 1));
		assert!(e[0].sha256.is_none());
	}
	let ok = [
		"device=12",
		"device=linux,1,2,",
		"device=freebsd,1,-65281",
		"device=bsdos,1,2,3",
		"resdevice=native,1,2",
	];
	for kw in ok {
		let e = entries(&format!("{SET}./a {kw}\n"));
		assert_eq!(e[0].warning, None, "{kw}");
	}
	// a line without type warns, a merged later line with it does not
	// lift that
	let e = entries("#mtree\n./a uid=1\n./b uid=1\n./b type=dir\n");
	assert_eq!(
		warning(&e[0]),
		"Missing type keyword in mtree specification"
	);
	assert_eq!(
		warning(&e[1]),
		"Missing type keyword in mtree specification"
	);
	assert_eq!(e[1].kind, EntryType::Dir);
}

// lines read_mtree cannot parse fail the whole file
#[test]
fn header_errors() {
	let p = |s: &str| header(format!("{SET}{s}").as_bytes());
	assert_eq!(p("./a\u{e9} type=dir\n"), "Can't parse line 3");
	assert_eq!(p("./a\r type=dir\n"), "Can't parse line 3");
	assert_eq!(p("# x\n/foo\n"), "Can't parse line 4");
	assert_eq!(p("/set\n"), "Can't parse line 3");
	assert_eq!(p("/unset uid=0\n"), "/unset shall not contain `='");
	let long = format!("./{} type=file\n", "a".repeat(65530));
	assert_eq!(p(&long), "Line too long");
	// continuations count as one line
	assert_eq!(p("./a \\\n type=dir\n/x\n"), "Can't parse line 4");
}

// after a nul the line never ends: the rest of the data is read into it
// and lost, or too long
#[test]
fn nul_bytes() {
	let data = format!("{SET}./a type=dir\n./b\0 type=dir\n./c\n");
	assert_eq!(read(data.as_bytes()).unwrap().len(), 1);
	let data = format!("{SET}./a\0\n{}", "./b type=dir\n".repeat(6000));
	assert_eq!(header(data.as_bytes()), "Line too long");
}

// the format bid: the signature, else the first lines must look like
// mtree (detect_form); data shorter than the signature is never mtree
#[test]
fn bid() {
	let no = |d: &[u8]| matches!(read(d), Err(Error::Format));
	assert!(no(b""));
	assert!(no(b"./a\n"));
	assert!(no(b"hello world\n"));
	assert!(no(b"./a type=file foo=1\n"));
	assert_eq!(read(b"#mtree").unwrap().len(), 0);
	assert_eq!(read(b"./a type=file\n").unwrap().len(), 1);
	let three = "./a type=dir\n./b type=dir\n./c type=dir\n./d foo=1\n";
	assert_eq!(read(three.as_bytes()).unwrap().len(), 4);
	assert!(no(b"/set type=file\n"));
	assert!(!no(b"/set type=file\n./a\n"));
}

// form D (NetBSD's mtree -D): the path last, once the first lines say so
#[test]
fn form_d() {
	let e = entries("type=dir uid=2 ./a\ntype=file ./a/b\n");
	assert_eq!(e[0].path, b"./a");
	assert_eq!((e[0].kind, e[0].uid), (EntryType::Dir, 2));
	assert_eq!(e[1].path, b"./a/b");
	// with the signature too, if the entry lines look like it
	let e = entries("#mtree\ntype=dir ./a\n");
	assert_eq!(e[0].path, b"./a");
}

#[test]
fn memory_and_files() {
	let t = Tmp::new("files");
	let plain = t.0.join("plain");
	fs::write(&plain, text()).unwrap();
	let gz = t.0.join("gz");
	gzip(&gz, text().as_bytes());
	let a = read_mtree(plain.as_os_str().as_bytes()).unwrap();
	let b = read_mtree(gz.as_os_str().as_bytes()).unwrap();
	assert_eq!(a, b);
	assert_eq!(read_memory(fs::read(&gz).unwrap()).unwrap(), a);
	// any filter alpm-compress knows, picked by magic bytes
	let xz = t.0.join("xz");
	let settings = CompressionSettings::Xz {
		compression_level: Default::default(),
	};
	compress(&xz, text().as_bytes(), &settings);
	assert_eq!(read_mtree(xz.as_os_str().as_bytes()).unwrap(), a);
	let none = t.0.join("none");
	let r = read_mtree(none.as_os_str().as_bytes());
	assert!(matches!(r, Err(MtreeError::Missing)), "{r:?}");
	// a gzip header libarchive's bidder takes, the stream cut inside the
	// first block: the open fails; a header it does not take is read
	// as it is, not mtree
	let cut = fs::read(&gz).unwrap()[..20].to_vec();
	let r = read_memory(cut);
	assert!(matches!(r, Err(Error::Open(_))), "{r:?}");
	let r = read_memory(b"\x1f\x8bnot gzip".to_vec());
	assert!(matches!(r, Err(Error::Format)), "{r:?}");
	fs::write(&plain, "#mtree\n/foo\n").unwrap();
	let r = read_mtree(plain.as_os_str().as_bytes());
	assert!(matches!(r, Err(MtreeError::Parse(_))), "{r:?}");
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

// <tmp>/alpm-core-mtree-<pid>-<name>/, removed on drop
struct Tmp(PathBuf);

impl Tmp {
	fn new(name: &str) -> Self {
		let dir = std::env::temp_dir().join(format!(
			"alpm-core-mtree-{}-{name}",
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

fn compress(path: &PathBuf, data: &[u8], settings: &CompressionSettings) {
	let f = fs::File::create(path).unwrap();
	let mut enc = CompressionEncoder::new(f, settings).unwrap();
	enc.write_all(data).unwrap();
	enc.finish().unwrap();
}

fn gzip(path: &PathBuf, data: &[u8]) {
	let settings = CompressionSettings::Gzip {
		compression_level: GzipCompressionLevel::default(),
	};
	compress(path, data, &settings);
}
