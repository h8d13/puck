// port of src/common/util-common.c
//
// inputs are byte strings as the C would see them, cut at the first nul.
// ctype calls run in the C locale there: isspace is " \t\n\v\f\r", bytes
// >= 0x80 are never space. wordsplit_free is not ported (Vec drop), the
// strnlen/strndup fallbacks are not built (HAVE_STRNLEN, HAVE_STRNDUP).

use std::ffi::OsStr;
use std::fs::{self, Metadata};
use std::io::{self, BufRead, ErrorKind};
use std::os::unix::ffi::OsStrExt;

// limits.h on linux, the buffer size of paths and lines in the C
pub const PATH_MAX: usize = 4096;

// what a C string would see of these bytes
pub(crate) fn until_nul(s: &[u8]) -> &[u8] {
	match s.iter().position(|&c| c == 0) {
		Some(i) => &s[..i],
		None => s,
	}
}

// isspace in the C locale, unlike is_ascii_whitespace it includes '\v'
pub(crate) fn is_space(c: u8) -> bool {
	matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

// hex_representation: lowercase, two digits per byte
pub fn hex_representation(bytes: &[u8]) -> Vec<u8> {
	const DIGITS: &[u8; 16] = b"0123456789abcdef";
	bytes.iter()
		.flat_map(|&b| {
			[
				DIGITS[usize::from(b >> 4)],
				DIGITS[usize::from(b & 0x0f)],
			]
		})
		.collect()
}

// mbasename: everything after the last '/'
pub fn mbasename(path: &[u8]) -> &[u8] {
	let path = until_nul(path);
	match path.iter().rposition(|&c| c == b'/') {
		Some(i) => &path[i + 1..],
		None => path,
	}
}

// mdirname: everything before the last '/', "/" for root, "." without one.
// only the last '/' is cut: "a//b" gives "a/"
pub fn mdirname(path: &[u8]) -> Vec<u8> {
	let path = until_nul(path);
	match path.iter().rposition(|&c| c == b'/') {
		Some(0) => b"/".to_vec(),
		Some(i) => path[..i].to_vec(),
		None => b".".to_vec(),
	}
}

// llstat: lstat with trailing '/' stripped (but not a lone "/"), so
// "dirsymlink/" describes the link instead of its target
pub fn llstat(path: &[u8]) -> io::Result<Metadata> {
	let path = until_nul(path);
	let slashes = path.iter().rev().take_while(|&&c| c == b'/').count();
	let len = (path.len() - slashes).max(1).min(path.len());
	fs::symlink_metadata(OsStr::from_bytes(&path[..len]))
}

// safe_fgets: one fgets(3) call of a buffer of `size` bytes. returns at most
// size - 1 bytes, up to and including the first '\n', so longer lines come
// back in chunks. nul bytes are copied like any other, the C callers then
// only see up to the first one (strlen). None is the C NULL: end of input
// with nothing read, or size 0. size 1 gives an empty chunk without
// reading, like glibc. the C retries fgets on EINTR, read_until-style
// Interrupted retry here
pub fn safe_fgets<R: BufRead>(
	r: &mut R,
	size: usize,
) -> io::Result<Option<Vec<u8>>> {
	let mut out = Vec::new();
	Ok(safe_fgets_into(r, size, &mut out)?.then_some(out))
}

// safe_fgets into the caller's buffer, which is cleared first: the C's
// fixed line buffer, so a reader of many lines allocates once. false is
// the C's NULL
pub fn safe_fgets_into<R: BufRead>(
	r: &mut R,
	size: usize,
	out: &mut Vec<u8>,
) -> io::Result<bool> {
	out.clear();
	let Some(max) = size.checked_sub(1) else {
		return Ok(false);
	};
	while out.len() < max {
		let avail = match r.fill_buf() {
			Ok(b) => b,
			Err(e) if e.kind() == ErrorKind::Interrupted => {
				continue;
			}
			Err(e) => return Err(e),
		};
		if avail.is_empty() {
			break;
		}
		let want = avail.len().min(max - out.len());
		let nl = avail[..want].iter().position(|&c| c == b'\n');
		let n = nl.map_or(want, |i| i + 1);
		out.extend_from_slice(&avail[..n]);
		r.consume(n);
		if nl.is_some() {
			break;
		}
	}
	Ok(!(out.is_empty() && max > 0))
}

// strtrim: leading and trailing C-locale whitespace removed. the C trims in
// place and returns the new length
pub fn strtrim(s: &[u8]) -> &[u8] {
	let s = until_nul(s);
	let start = s.iter().take_while(|&&c| is_space(c)).count();
	let s = &s[start..];
	let end =
		s.len() - s.iter().rev().take_while(|&&c| is_space(c)).count();
	&s[..end]
}

// wordsplit: split on whitespace, '...' and "..." group (may be empty),
// \' and \" escape the quote outside quotes and the enclosing quote inside.
// any other backslash is literal. None for an unbalanced quote (C EINVAL)
pub fn wordsplit(s: &[u8]) -> Option<Vec<Vec<u8>>> {
	let s = until_nul(s);
	let skip_space = |i: usize| {
		i + s[i..].iter().take_while(|&&c| is_space(c)).count()
	};
	let mut words = Vec::new();
	let mut i = skip_space(0);
	while i < s.len() {
		let mut word = Vec::new();
		while i < s.len() && !is_space(s[i]) {
			i = match s[i] {
				q @ (b'\'' | b'"') => {
					quoted(s, i + 1, q, &mut word)?
				}
				c => {
					if c == b'\\'
						&& matches!(
							s.get(i + 1),
							Some(b'\'' | b'"')
						) {
						i += 1;
					}
					word.push(s[i]);
					i + 1
				}
			};
		}
		words.push(word);
		i = skip_space(i);
	}
	Some(words)
}

// copies a quoted run starting after the opening quote, returns the index
// past the closing one, None if it never closes
fn quoted(s: &[u8], mut i: usize, q: u8, word: &mut Vec<u8>) -> Option<usize> {
	loop {
		match *s.get(i)? {
			c if c == q => return Some(i + 1),
			b'\\' if s.get(i + 1) == Some(&q) => i += 1,
			_ => {}
		}
		word.push(s[i]);
		i += 1;
	}
}
