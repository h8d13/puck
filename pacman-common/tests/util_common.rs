// unit tests for pacman_common::util_common
use std::io::BufReader;

use pacman_common::util_common::*;

fn chunks(data: &[u8], size: usize) -> Vec<Vec<u8>> {
	let mut r = BufReader::with_capacity(3, data);
	let mut out = Vec::new();
	while let Some(c) = safe_fgets(&mut r, size).unwrap() {
		out.push(c);
		if out.len() > 16 {
			break;
		}
	}
	out
}

#[test]
fn fgets_chunks() {
	assert_eq!(chunks(b"abcde\nf", 4), [&b"abc"[..], b"de\n", b"f"]);
	assert_eq!(chunks(b"ab\n", 3), [&b"ab"[..], b"\n"]);
	assert_eq!(chunks(b"a\0b\n", 8), [b"a\0b\n"]);
	assert_eq!(chunks(b"", 8), Vec::<Vec<u8>>::new());
	assert_eq!(chunks(b"abc", 0), Vec::<Vec<u8>>::new());
	// size 1 never reads, the C caller would spin
	assert_eq!(chunks(b"abc", 1).len(), 17);
}

#[test]
fn paths() {
	assert_eq!(mbasename(b"/usr/bin/pacman"), b"pacman");
	assert_eq!(mbasename(b"dir/"), b"");
	assert_eq!(mbasename(b"a/b\0/c"), b"b");
	assert_eq!(mdirname(b"/usr/bin/pacman"), b"/usr/bin");
	assert_eq!(mdirname(b"/usr"), b"/");
	assert_eq!(mdirname(b"a//b"), b"a/");
	assert_eq!(mdirname(b"a"), b".");
	assert_eq!(mdirname(b""), b".");
	assert_eq!(hex_representation(b"\x00\xab\xff"), b"00abff");
}

#[test]
fn trim_and_split() {
	assert_eq!(strtrim(b" \x0b a b \r\n"), b"a b");
	assert_eq!(strtrim(b"\xa0a\xa0"), b"\xa0a\xa0");
	assert_eq!(strtrim(b"  \0 a"), b"");
	let w = |v: &[&[u8]]| Some(v.iter().map(|s| s.to_vec()).collect());
	assert_eq!(wordsplit(b" a  b "), w(&[b"a", b"b"]));
	assert_eq!(wordsplit(b"'a b'c \"\""), w(&[b"a bc", b""]));
	assert_eq!(wordsplit(b"\\'x \\y"), w(&[b"'x", b"\\y"]));
	assert_eq!(wordsplit(b"'it\\'s'"), w(&[b"it's"]));
	assert_eq!(wordsplit(b""), w(&[]));
	assert_eq!(wordsplit(b"a 'b"), None);
}

#[test]
fn llstat_strips_trailing_slash() {
	let m = llstat(b"/tmp///").unwrap();
	assert!(m.is_dir());
	assert_eq!(llstat(b"").unwrap_err().raw_os_error(), Some(2));
}
