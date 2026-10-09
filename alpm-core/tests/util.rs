// unit tests for alpm_core::internals::util
use alpm_core::internals::util::*;

#[test]
fn strip_newline_cases() {
	assert_eq!(strip_newline(b"abc\n\n"), b"abc");
	assert_eq!(strip_newline(b"abc\r\n"), b"abc\r");
	assert_eq!(strip_newline(b"\n"), b"");
	assert_eq!(strip_newline(b""), b"");
}

#[test]
fn splitname_cases() {
	assert_eq!(
		splitname(b"pacman-7.1.0-1/desc"),
		Some((&b"pacman"[..], &b"7.1.0-1"[..]))
	);
	assert_eq!(
		splitname(b"lib32-glibc-2.42-1"),
		Some((&b"lib32-glibc"[..], &b"2.42-1"[..]))
	);
	assert_eq!(splitname(b"-1-1"), None);
	assert_eq!(splitname(b"foo-1"), None);
	assert_eq!(splitname(b"foo"), None);
	assert_eq!(splitname(b""), None);
	assert_eq!(splitname(b"/a-1-1"), None);
}

#[test]
fn numbers() {
	assert_eq!(strtoofft(b"0"), Some(0));
	assert_eq!(strtoofft(b"18446744073709551615"), Some(u64::MAX));
	assert_eq!(strtoofft(b"18446744073709551616"), None);
	assert_eq!(strtoofft(b" 1"), None);
	assert_eq!(strtoofft(b"+1"), None);
	assert_eq!(parsedate(b" -9223372036854775808"), Some(i64::MIN));
	assert_eq!(parsedate(b"9223372036854775808"), None);
	assert_eq!(parsedate(b"1x"), None);
	assert_eq!(parsedate(b"-"), None);
}

#[test]
fn fnmatch_cases() {
	assert!(fnmatch(b"*", b"/usr/.hidden"));
	assert!(fnmatch(b"usr/*.conf", b"usr/a/b.conf"));
	assert!(fnmatch(b"?", b"/"));
	assert!(!fnmatch(b"?", b""));
	assert!(fnmatch(b"\\*", b"*"));
	assert!(!fnmatch(b"\\", b"\\"));
	assert!(fnmatch(b"[]a]", b"]"));
	assert!(fnmatch(b"[!a-c]", b"d"));
	assert!(fnmatch(b"[^a-c]", b"d"));
	assert!(!fnmatch(b"[c-a]", b"b"));
	assert!(fnmatch(b"[a-]", b"-"));
	assert!(fnmatch(b"[[:alpha:][:digit:]]", b"7"));
	assert!(!fnmatch(b"[[:alpha:]]", b"\xe9"));
	assert!(!fnmatch(b"[[:foo:]]", b"f"));
	assert!(fnmatch(b"[[=a=]]", b"a"));
	assert!(fnmatch(b"[[.-.]]", b"-"));
	// unterminated bracket is a literal '['
	assert!(fnmatch(b"[a", b"[a"));
	assert!(!fnmatch(b"[a", b"a"));
	assert!(fnmatch(b"*a*b*c", b"xaybzcxc"));
	assert!(fnmatch(b"a\0b", b"a"));
}

#[test]
fn fnmatch_patterns_cases() {
	let none: [&[u8]; 0] = [];
	assert_eq!(fnmatch_patterns(&none, b"a"), None);
	assert_eq!(fnmatch_patterns(&[&b"etc/*"[..]], b"etc/x"), Some(false));
	let pats: [&[u8]; 2] = [b"etc/*", b"!etc/keep"];
	assert_eq!(fnmatch_patterns(&pats, b"etc/keep"), Some(true));
	assert_eq!(fnmatch_patterns(&pats, b"etc/x"), Some(false));
	assert_eq!(fnmatch_patterns(&pats, b"usr/x"), None);
	assert_eq!(fnmatch_patterns(&[&b"\\!x"[..]], b"!x"), Some(false));
}

// fresh directory under /tmp, removed on drop
struct TmpDir(std::path::PathBuf);

impl TmpDir {
	fn new(name: &str) -> Self {
		let dir = std::env::temp_dir().join(format!(
			"alpm-core-util-{}-{name}",
			std::process::id()
		));
		std::fs::create_dir(&dir).unwrap();
		TmpDir(dir)
	}

	fn path(&self, rel: &str) -> Vec<u8> {
		use std::os::unix::ffi::OsStrExt;
		self.0.join(rel).as_os_str().as_bytes().to_vec()
	}
}

impl Drop for TmpDir {
	fn drop(&mut self) {
		std::fs::remove_dir_all(&self.0).unwrap();
	}
}

#[test]
fn fs_helpers() {
	use std::os::unix::fs::PermissionsExt;
	let mode = |p: &[u8]| {
		let p = std::str::from_utf8(p).unwrap();
		std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
	};
	let t = TmpDir::new("fs");
	makepath_mode(&t.path("a//b/c/"), 0o1777).unwrap();
	assert_eq!(mode(&t.path("a/b/c")), 0o1777);
	makepath(&t.path("a/b/c")).unwrap();
	assert_eq!(files_in_directory(&t.path("a"), true).unwrap(), 1);
	assert_eq!(files_in_directory(&t.path("a/b/c"), false).unwrap(), 0);
	assert!(files_in_directory(&t.path("none"), true).is_err());

	std::fs::write(t.0.join("a/b/c/f"), b"long content").unwrap();
	std::fs::write(t.0.join("g"), b"xy").unwrap();
	// no truncation: the longer dest keeps its tail
	copyfile(&t.path("g"), &t.path("a/b/c/f")).unwrap();
	assert_eq!(read_file(&t.path("a/b/c/f")).unwrap(), b"xyng content");
	// a failed open of src still creates dest
	assert!(copyfile(&t.path("none"), &t.path("h")).is_err());
	assert_eq!(mode(&t.path("h")), 0);

	std::fs::write(t.0.join("empty"), b"").unwrap();
	assert_eq!(read_file(&t.path("empty")), Err(ReadFileError::System));
	assert_eq!(read_file(&t.path("a")), Err(ReadFileError::System));
	assert_eq!(read_file(&t.path("none")), Err(ReadFileError::NotAFile));
	// file in the way: EEXIST passes for the last part, fails mid-path
	assert!(makepath(&t.path("g")).is_ok());
	assert!(makepath(&t.path("g/x")).is_err());
}

#[test]
fn checksum_cases() {
	use alpm_core::internals::package::{
		PKG_VALIDATION_MD5SUM, PKG_VALIDATION_SHA256SUM,
	};
	let t = TmpDir::new("checksum");
	std::fs::write(t.0.join("foo"), b"foo\n").unwrap();
	let md5 = b"d3b07384d113edec49eaa6238ad5ff00";
	let sha = b"b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c";
	assert_eq!(compute_md5sum(&t.path("foo")).as_deref(), Some(&md5[..]));
	assert_eq!(
		compute_sha256sum(&t.path("foo")).as_deref(),
		Some(&sha[..])
	);
	// a directory opens, its read fails
	assert_eq!(compute_md5sum(&t.path("")), None);
	assert_eq!(compute_sha256sum(&t.path("none")), None);
	let f = t.path("foo");
	assert_eq!(
		test_checksum(&f, Some(md5), PKG_VALIDATION_MD5SUM),
		Some(true)
	);
	assert_eq!(
		test_checksum(&f, Some(sha), PKG_VALIDATION_SHA256SUM),
		Some(true)
	);
	// strcmp: case matters, the expected value is cut at a nul
	let upper = md5.to_ascii_uppercase();
	assert_eq!(
		test_checksum(&f, Some(&upper), PKG_VALIDATION_MD5SUM),
		Some(false)
	);
	let cut = [&md5[..], b"\0x"].concat();
	assert_eq!(
		test_checksum(&f, Some(&cut), PKG_VALIDATION_MD5SUM),
		Some(true)
	);
	assert_eq!(test_checksum(&f, None, PKG_VALIDATION_MD5SUM), None);
	assert_eq!(test_checksum(&f, Some(md5), 0), None);
	assert_eq!(
		test_checksum(
			&t.path("none"),
			Some(md5),
			PKG_VALIDATION_MD5SUM
		),
		None
	);
}
