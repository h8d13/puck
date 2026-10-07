// port of src/pacman/util.c, the helpers that need no alpm handle,
// config file or terminal
//
// functions that print in the C append the same bytes to `out` instead.
// inputs are byte strings as the C would see them, cut at the first nul.
//
// display width follows glibc in a UTF-8 locale. pacman runs under the
// user's locale, the port assumes UTF-8: `mbstowcs` is glibc's UTF-8
// decoder, `wcwidth` the per character width of unicode-width with
// glibc's -1 for non printables. messages are the untranslated msgids,
// gettext is not ported. sizes are size_t in the C and wrap: a width of
// -1 from wcwidth/wcswidth is added as usize::MAX, like the C conversion.

use std::iter::repeat_n;

use alpm_core::util::until_nul;
use unicode_width::UnicodeWidthChar;

pub use crate::conf::ColStr;

// alpm_sigstatus_t, alpm_sigvalidity_t and the part of alpm_sigresult_t
// signature_display reads, until signing.c gets there
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigStatus {
	Valid,
	KeyExpired,
	SigExpired,
	KeyUnknown,
	KeyDisabled,
	Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigValidity {
	Full,
	Marginal,
	Never,
	Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigResult {
	pub status: SigStatus,
	pub validity: SigValidity,
	pub uid: Option<Vec<u8>>,
	pub fingerprint: Vec<u8>,
}

// one decoded character and the bytes it came from
struct Wc<'a> {
	c: u32,
	bytes: &'a [u8],
}

// smallest code point per sequence length, shorter forms are overlong
const UTF8_MIN: [u32; 7] = [0, 0, 0x80, 0x800, 0x1_0000, 0x20_0000, 0x400_0000];

// glibc's UTF-8 decoder: the original up to 6 byte forms (to
// 0x7fffffff), overlong forms and surrogates rejected
fn decode_one(s: &[u8]) -> Option<(u32, usize)> {
	let b = s[0];
	let (n, lead) = match b {
		0x00..=0x7f => return Some((u32::from(b), 1)),
		0xc2..=0xdf => (2, b & 0x1f),
		0xe0..=0xef => (3, b & 0x0f),
		0xf0..=0xf7 => (4, b & 0x07),
		0xf8..=0xfb => (5, b & 0x03),
		0xfc..=0xfd => (6, b & 0x01),
		_ => return None,
	};
	let tail = s.get(1..n)?;
	let mut c = u32::from(lead);
	for &x in tail {
		if x & 0xc0 != 0x80 {
			return None;
		}
		c = c << 6 | u32::from(x & 0x3f);
	}
	if c < UTF8_MIN[n] || (0xd800..=0xdfff).contains(&c) {
		return None;
	}
	Some((c, n))
}

// mbstowcs as the C uses it: glibc fills the buffer up to the first
// invalid sequence and returns -1, the calloc'd buffer keeps that prefix
// nul terminated. so the prefix is all the C ever looks at
fn decode(s: &[u8]) -> (Vec<Wc<'_>>, bool) {
	let mut out = Vec::new();
	let mut i = 0;
	while i < s.len() {
		let Some((c, n)) = decode_one(&s[i..]) else {
			return (out, false);
		};
		out.push(Wc {
			c,
			bytes: &s[i..i + n],
		});
		i += n;
	}
	(out, true)
}

// mbstowcs: the decoded prefix, and whether the whole string decoded
// (false = the C got (size_t)-1)
pub fn mbstowcs(s: &[u8]) -> (Vec<u32>, bool) {
	let (w, ok) = decode(until_nul(s));
	(w.iter().map(|w| w.c).collect(), ok)
}

// wcwidth on unicode-width: L'\0' is 0, controls (None) and anything
// that is not a char (surrogates, past U+10FFFF) -1 like glibc
pub fn wcwidth(c: u32) -> i32 {
	if c == 0 {
		return 0;
	}
	char::from_u32(c)
		.and_then(UnicodeWidthChar::width)
		.map_or(-1, |w| w as i32)
}

// wcswidth as size_t: usize::MAX if any character is not printable
fn wcswidth(w: &[Wc]) -> usize {
	w.iter().try_fold(0usize, |n, w| {
		usize::try_from(wcwidth(w.c))
			.ok()
			.map(|x| n.wrapping_add(x))
	})
	.unwrap_or(usize::MAX)
}

// wcwidth -1 added to a size_t
fn add_width(n: usize, c: u32) -> usize {
	n.wrapping_add(wcwidth(c) as usize)
}

// drops terminal colour sequences "\033[<digit>[0-9;]*m"
fn strip_colors(s: &[u8]) -> Vec<u8> {
	let digit = |i: usize| s.get(i).is_some_and(u8::is_ascii_digit);
	let mut out = Vec::with_capacity(s.len());
	let mut i = 0;
	while i < s.len() {
		if s[i] == 0x1b && s.get(i + 1) == Some(&b'[') && digit(i + 2) {
			let mut t = i + 3;
			while digit(t) || s.get(t) == Some(&b';') {
				t += 1;
			}
			if s.get(t) == Some(&b'm') {
				i = t + 1;
				continue;
			}
		}
		out.push(s[i]);
		i += 1;
	}
	out
}

// string_length: display columns, colour sequences excluded. an invalid
// UTF-8 tail is not counted, a non printable character makes it
// usize::MAX ((size_t)-1 from wcswidth)
pub fn string_length(s: &[u8]) -> usize {
	let s = until_nul(s);
	if s.contains(&0x1b) {
		wcswidth(&decode(&strip_colors(s)).0)
	} else {
		wcswidth(&decode(s).0)
	}
}

// "title " with the title colour around the title
fn put_title(out: &mut Vec<u8>, title: &[u8], colstr: &ColStr) {
	out.extend_from_slice(until_nul(colstr.title));
	out.extend_from_slice(until_nul(title));
	out.extend_from_slice(until_nul(colstr.nocolor));
	out.push(b' ');
}

fn put_spaces(out: &mut Vec<u8>, n: usize) {
	out.extend(repeat_n(b' ', n));
}

// indentprint: word wrap at spaces, continuation lines indented. runs of
// spaces collapse, a space is only output before the word that follows
// it. no wrapping if cols is 0 or narrower than the indent
pub fn indentprint(out: &mut Vec<u8>, s: &[u8], indent: u16, cols: u16) {
	let s = until_nul(s);
	if cols == 0 || indent > cols {
		out.extend_from_slice(s);
		return;
	}
	let space = u32::from(b' ');
	let indent = usize::from(indent);
	let (w, _) = decode(s);
	let mut cidx = indent;
	let mut i = 0;
	while i < w.len() {
		if w[i].c != space {
			// %lc re-encodes to the same bytes
			out.extend_from_slice(w[i].bytes);
			cidx = add_width(cidx, w[i].c);
			i += 1;
			continue;
		}
		i += 1;
		if w.get(i).is_some_and(|w| w.c == space) {
			continue;
		}
		let next = w[i..]
			.iter()
			.position(|w| w.c == space)
			.map_or(w.len(), |n| i + n);
		let len = w[i..next].iter().fold(0, |n, w| add_width(n, w.c));
		// size_t arithmetic, cols - cidx wraps once past the edge
		if len.wrapping_add(1) > usize::from(cols).wrapping_sub(cidx) {
			out.push(b'\n');
			put_spaces(out, indent);
			cidx = indent;
		} else {
			out.push(b' ');
			cidx = cidx.wrapping_add(1);
		}
	}
}

// strreplace: every non-overlapping occurrence, left to right. the C
// never terminates on an empty needle, the port returns the string as is
pub fn strreplace(s: &[u8], needle: &[u8], replace: &[u8]) -> Vec<u8> {
	let (s, needle) = (until_nul(s), until_nul(needle));
	let replace = until_nul(replace);
	if needle.is_empty() {
		return s.to_vec();
	}
	let mut out = Vec::with_capacity(s.len());
	let mut p = 0;
	while let Some(q) =
		s[p..].windows(needle.len()).position(|w| w == needle)
	{
		out.extend_from_slice(&s[p..p + q]);
		out.extend_from_slice(replace);
		p += q + needle.len();
	}
	out.extend_from_slice(&s[p..]);
	out
}

// string_display: an empty string prints "None"
pub fn string_display(
	out: &mut Vec<u8>,
	title: Option<&[u8]>,
	s: &[u8],
	cols: u16,
	colstr: &ColStr,
) {
	if let Some(t) = title {
		put_title(out, t, colstr);
	}
	let s = until_nul(s);
	if s.is_empty() {
		out.extend_from_slice(b"None");
	} else {
		// string_length(NULL) is 0, the cast truncates
		let len = string_length(title.unwrap_or(b"")).wrapping_add(1);
		indentprint(out, s, len as u16, cols);
	}
	out.push(b'\n');
}

// list_display: items two spaces apart, wrapped under the title once a
// line would reach maxcols (only if maxcols leaves room past the title)
pub fn list_display<S: AsRef<[u8]>>(
	out: &mut Vec<u8>,
	title: Option<&[u8]>,
	list: &[S],
	maxcols: u16,
	colstr: &ColStr,
) {
	let mut len = 0usize;
	if let Some(t) = title {
		len = string_length(t).wrapping_add(1);
		put_title(out, t, colstr);
	}
	let Some((first, rest)) = list.split_first() else {
		out.extend_from_slice(b"None\n");
		return;
	};
	let maxcols = usize::from(maxcols);
	let first = until_nul(first.as_ref());
	out.extend_from_slice(first);
	let mut cols = len.wrapping_add(string_length(first));
	for s in rest {
		let s = until_nul(s.as_ref());
		let n = string_length(s);
		if maxcols > len
			&& cols.wrapping_add(n).wrapping_add(2) >= maxcols
		{
			cols = len;
			out.push(b'\n');
			put_spaces(out, len);
		} else if cols != len {
			out.extend_from_slice(b"  ");
			cols = cols.wrapping_add(2);
		}
		out.extend_from_slice(s);
		cols = cols.wrapping_add(n);
	}
	out.push(b'\n');
}

// title width + 1 as the C's unsigned short
fn title_indent(title: Option<&[u8]>) -> u16 {
	title.map_or(0, |t| (string_length(t) as u16).wrapping_add(1))
}

// list_display_linebreak: one item per line, each through indentprint
pub fn list_display_linebreak<S: AsRef<[u8]>>(
	out: &mut Vec<u8>,
	title: Option<&[u8]>,
	list: &[S],
	maxcols: u16,
	colstr: &ColStr,
) {
	let len = title_indent(title);
	if let Some(t) = title {
		put_title(out, t, colstr);
	}
	if list.is_empty() {
		out.extend_from_slice(b"None\n");
		return;
	}
	for (i, s) in list.iter().enumerate() {
		// the first line continues after the title
		if i != 0 {
			put_spaces(out, usize::from(len));
		}
		indentprint(out, s.as_ref(), len, maxcols);
		out.push(b'\n');
	}
}

// signature_display: one line per result. no newline after "None",
// unlike the other displays
pub fn signature_display(
	out: &mut Vec<u8>,
	title: Option<&[u8]>,
	sigs: &[SigResult],
	maxcols: u16,
	colstr: &ColStr,
) {
	let len = title_indent(title);
	if let Some(t) = title {
		put_title(out, t, colstr);
	}
	if sigs.is_empty() {
		out.extend_from_slice(b"None");
		return;
	}
	for (i, r) in sigs.iter().enumerate() {
		if i != 0 {
			put_spaces(out, usize::from(len));
		}
		let status: &[u8] = match r.status {
			SigStatus::Valid => b"Valid",
			SigStatus::KeyExpired => b"Key expired",
			SigStatus::SigExpired => b"Expired",
			SigStatus::Invalid => b"Invalid",
			SigStatus::KeyUnknown => b"Key unknown",
			SigStatus::KeyDisabled => b"Key disabled",
		};
		let validity: &[u8] = match r.validity {
			SigValidity::Full => b"full trust",
			SigValidity::Marginal => b"marginal trust",
			SigValidity::Never => b"never trust",
			SigValidity::Unknown => b"unknown trust",
		};
		let name = r.uid.as_deref().unwrap_or(&r.fingerprint);
		let line = [
			status,
			b", ",
			validity,
			b" from \"",
			until_nul(name),
			b"\"",
		]
		.concat();
		indentprint(out, &line, len, maxcols);
		out.push(b'\n');
	}
}

const SIZE_LABELS: [&str; 9] =
	["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"];

// humanize_size: bytes in target_unit (first letter of a label), or with
// target_unit 0 in the first unit that brings it within +-2048. an
// unknown unit ends at YiB. with precision >= 0, values that would print
// as -0.00 become 0
pub fn humanize_size(
	bytes: i64,
	target_unit: u8,
	precision: i32,
) -> (f64, &'static str) {
	let mut val = bytes as f64;
	let mut index = 0;
	while index < SIZE_LABELS.len() - 1 {
		if target_unit != 0 {
			if SIZE_LABELS[index].as_bytes()[0] == target_unit {
				break;
			}
		} else if (-2048.0..=2048.0).contains(&val) {
			break;
		}
		val /= 1024.0;
		index += 1;
	}
	// simple_pow: repeated multiply, inf from 10^309 on, so the loop
	// can stop there
	let pow = (0..precision.min(400)).fold(1.0f64, |p, _| p * 10.0);
	if precision >= 0 && val < 0.0 && val > -0.5 / pow {
		val = 0.0;
	}
	(val, SIZE_LABELS[index])
}

// arg_to_string: arguments joined by single spaces, None for no
// arguments
pub fn arg_to_string<S: AsRef<[u8]>>(args: &[S]) -> Option<Vec<u8>> {
	if args.is_empty() {
		return None;
	}
	let args: Vec<&[u8]> =
		args.iter().map(|a| until_nul(a.as_ref())).collect();
	Some(args.join(&b' '))
}

// console_cursor_move_up: CSI n F
pub fn console_cursor_move_up(out: &mut Vec<u8>, lines: u32) {
	out.extend_from_slice(format!("\x1b[{lines}F").as_bytes());
}

// console_cursor_move_down: CSI n E
pub fn console_cursor_move_down(out: &mut Vec<u8>, lines: u32) {
	out.extend_from_slice(format!("\x1b[{lines}E").as_bytes());
}

// console_erase_line: CSI K, cursor to end of line
pub fn console_erase_line(out: &mut Vec<u8>) {
	out.extend_from_slice(b"\x1b[K");
}
