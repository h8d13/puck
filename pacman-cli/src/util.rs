// port of src/pacman/util.c: display helpers, the table engine and
// transaction summary, --print-format, optdepend lists, the prompts,
// rmrf, pm_printf (with the PACMAN_DEBUG stamp), check_syncdbs, getcols
// and trans_init/trans_release
//
// functions that print in the C append the same bytes to `out` instead;
// Output::flush hands them to the process where the C would have them
// on the terminal (before a prompt reads, before libalpm calls back).
// inputs are byte strings as the C would see them, cut at the first nul.
//
// display width follows glibc in a UTF-8 locale. pacman runs under the
// user's locale, the port assumes UTF-8: `mbstowcs` is glibc's UTF-8
// decoder, `wcwidth` the per character width of unicode-width with
// glibc's -1 for non printables. messages are the untranslated msgids,
// gettext is not ported. sizes are size_t in the C and wrap: a width of
// -1 from wcwidth/wcswidth is added as usize::MAX, like the C conversion.

use std::cmp::Ordering;
use std::ffi::{OsStr, c_int, c_long};
use std::fs;
use std::io::{self, BufRead, IsTerminal};
use std::iter::repeat_n;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use alpm_core::db::Db;
use alpm_core::deps::{Depend, dep_compute_string, find_satisfier};
use alpm_core::handle::Handle;
use alpm_core::log::local_offset;
// time(NULL)
pub use alpm_core::log::now_secs;
use alpm_core::package::{Package, PkgFrom, pkg_cmp, pkg_find};
use alpm_core::trans::{
	InitError, trans_init as alpm_trans_init,
	trans_release as alpm_trans_release,
};
use alpm_core::util::{strerror, until_nul};
use pacman_common::util_common::{PATH_MAX, safe_fgets, strtrim};
use rustix::termios::{QueueSelector, tcflush, tcgetwinsize};
use unicode_width::UnicodeWidthChar;

pub use crate::conf::ColStr;
use crate::conf::{Config, LOG_DEBUG, LOG_ERROR, LOG_FUNCTION, LOG_WARNING};
use crate::pacman::{
	PM_OP_DATABASE, PM_OP_FILES, PM_OP_REMOVE, PM_OP_SYNC, PM_OP_UPGRADE,
};

// what the C writes to stdout and stderr. sink is where flush sends it
// (the binary's std streams), None keeps it buffered (tests, callers
// that read it back); equality is on the bytes
#[derive(Clone, Debug, Default)]
pub struct Output {
	pub stdout: Vec<u8>,
	pub stderr: Vec<u8>,
	pub sink: Option<fn(&mut Output)>,
}

impl PartialEq for Output {
	fn eq(&self, other: &Output) -> bool {
		self.stdout == other.stdout && self.stderr == other.stderr
	}
}

impl Eq for Output {}

impl Output {
	// fflush(stdout), fflush(stderr): the sink takes the bytes
	pub fn flush(&mut self) {
		if let Some(sink) = self.sink {
			sink(self);
		}
	}

	// stdio writes a full block out; flushing at 64 KiB keeps a long
	// listing (-Si of every sync package is ~11 MB) from sitting whole
	// in memory until the end
	pub fn flush_full(&mut self) {
		if self.stdout.len() >= 64 * 1024 {
			self.flush();
		}
	}
}

// PACMAN_DEBUG (set by the meson build): pm_vfprintf puts "[%H:%M:%S] "
// of localtime before every message while debug logging is on
pub fn debug_stamp(secs: i64) -> Vec<u8> {
	let local = secs + i64::from(local_offset(secs).unwrap_or(0));
	let s = local.rem_euclid(86400);
	let (h, m, s) = (s / 3600, s / 60 % 60, s % 60);
	format!("[{h:02}:{m:02}:{s:02}] ").into_bytes()
}

// pm_vasprintf: the message with its level prefix, None when logmask
// filters the level. no PACMAN_DEBUG stamp on this path
pub fn pm_vasprintf(
	config: &Config,
	level: u16,
	msg: &[u8],
) -> Option<Vec<u8>> {
	if config.logmask & level == 0 {
		return None;
	}
	let c = &config.colstr;
	let prefix: &[&[u8]] = match level {
		LOG_ERROR => &[c.err, b"error: ", c.nocolor],
		LOG_WARNING => &[c.warn, b"warning: ", c.nocolor],
		LOG_DEBUG => &[b"debug: "],
		LOG_FUNCTION => &[b"function: "],
		_ => &[],
	};
	Some([&prefix.concat()[..], msg].concat())
}

// pm_vfprintf: pm_vasprintf with the PACMAN_DEBUG stamp of now
pub fn pm_vfprintf(
	config: &Config,
	level: u16,
	msg: &[u8],
	now: i64,
) -> Option<Vec<u8>> {
	let line = pm_vasprintf(config, level, msg)?;
	if config.logmask & LOG_DEBUG == 0 {
		return Some(line);
	}
	Some([debug_stamp(now), line].concat())
}

// pm_printf(level, ...) to stderr
pub fn pm_printf(err: &mut Vec<u8>, config: &Config, level: u16, msg: &[u8]) {
	if let Some(line) = pm_vfprintf(config, level, msg, now_secs()) {
		err.extend_from_slice(&line);
	}
}

// check_syncdbs: 1 without sync dbs when need_repos, or when check_valid
// finds an invalid db (each one reported)
pub fn check_syncdbs(
	err: &mut Vec<u8>,
	config: &Config,
	handle: &Handle,
	need_repos: bool,
	check_valid: bool,
) -> i32 {
	let dbs = handle.syncdbs();
	if need_repos && dbs.is_empty() {
		let msg = b"no usable package repositories configured.\n";
		pm_printf(err, config, LOG_ERROR, msg);
		return 1;
	}
	let mut ret = 0;
	if check_valid {
		for db in dbs {
			if let Err(e) = db.valid() {
				let msg = [
					b"database '",
					db.name(),
					b"' is not valid (",
					e.strerror().as_bytes(),
					b")\n",
				];
				pm_printf(
					err,
					config,
					LOG_ERROR,
					&msg.concat(),
				);
				ret = 1;
			}
		}
	}
	ret
}

fn is_space(c: u8) -> bool {
	matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

// strtol(s, &p, 10) with *p == '\0' checked: None when digits are
// missing or trail. out of range saturates like ERANGE
fn strtol_whole(s: &[u8]) -> Option<c_long> {
	let start = s.iter().take_while(|&&c| is_space(c)).count();
	let mut rest = &s[start..];
	let neg = rest.first() == Some(&b'-');
	if matches!(rest.first(), Some(b'+' | b'-')) {
		rest = &rest[1..];
	}
	let n = rest.iter().take_while(|c| c.is_ascii_digit()).count();
	if n == 0 || n != rest.len() {
		return None;
	}
	let mut v: c_long = 0;
	for &d in rest {
		let d = c_long::from(d - b'0');
		v = match neg {
			true => v.saturating_mul(10).saturating_sub(d),
			false => v.saturating_mul(10).saturating_add(d),
		};
	}
	Some(v)
}

// getcols_fd: 0 for no terminal, the width TIOCGWINSZ gives, -EIO
// (any negative) when that fails or is 0
fn getcols_fd<F: AsFd + IsTerminal>(fd: F) -> c_int {
	if !fd.is_terminal() {
		return 0;
	}
	match tcgetwinsize(fd) {
		Ok(w) if w.ws_col > 0 => c_int::from(w.ws_col),
		_ => -5,
	}
}

// getcols without the cache: COLUMNS when it is a whole number, cut to
// int like the C; else the width of a terminal stdout, 0 for no
// terminal; 80 when neither gives one
pub fn getcols() -> u16 {
	let env = std::env::var_os("COLUMNS");
	let e = env.as_ref().map(|e| e.as_bytes()).unwrap_or_default();
	let mut c: c_int = -1;
	if !e.is_empty() {
		c = strtol_whole(e).map_or(-1, |v| v as c_int);
	}
	if c < 0 {
		c = getcols_fd(io::stdout());
	}
	if c < 0 {
		c = 80;
	}
	c as u16
}

// flush_term_input(fileno(stdin)): typeahead of a terminal stdin is
// dropped before a prompt reads; failure is silent like the C's
pub fn flush_term_input() {
	let stdin = io::stdin();
	if stdin.is_terminal() {
		let _ = tcflush(stdin, QueueSelector::IFlush);
	}
}

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

// colon_printf: the message between the colon colour and nocolor
pub fn colon_printf(out: &mut Vec<u8>, colstr: &ColStr, msg: &[u8]) {
	out.extend_from_slice(until_nul(colstr.colon));
	out.extend_from_slice(msg);
	out.extend_from_slice(until_nul(colstr.nocolor));
}

// snprintf into a PATH_MAX buffer: the result cut to PATH_MAX - 1
fn path_max(mut p: Vec<u8>) -> Vec<u8> {
	p.truncate(PATH_MAX - 1);
	p
}

// errno values (Linux) rmrf tells apart
const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EISDIR: i32 = 21;

// rmrf: rm -rf, the number of entries that would not go. a missing path
// is 0; unlink failing with anything but EPERM/EISDIR is 1 without
// trying it as a directory
pub fn rmrf(path: &[u8]) -> i32 {
	rmrf_errno(path).0
}

// rmrf and what errno holds after a failure: the last call that failed,
// the top level's rmdir when the tree did not go (sync_cleandb prints it)
pub fn rmrf_errno(path: &[u8]) -> (i32, Option<io::Error>) {
	let path = until_nul(path);
	let p = OsStr::from_bytes(path);
	let err = match fs::remove_file(p) {
		Ok(()) => return (0, None),
		Err(e) => e,
	};
	match err.raw_os_error() {
		Some(ENOENT) => return (0, None),
		Some(EPERM | EISDIR) => {}
		_ => return (1, Some(err)),
	}
	let dir = match fs::read_dir(p) {
		Ok(dir) => dir,
		Err(e) => return (1, Some(e)),
	};
	let (mut errflag, mut last) = (0, None);
	// readdir ends the loop on an error as on the end, read_dir skips
	// "." and ".."
	for e in dir.map_while(Result::ok) {
		let name = [path, b"/", e.file_name().as_bytes()].concat();
		let (n, e) = rmrf_errno(&path_max(name));
		errflag += n;
		last = e.or(last);
	}
	if let Err(e) = fs::remove_dir(p) {
		errflag += 1;
		last = Some(e);
	}
	(errflag, last)
}

// a package and the db alpm_pkg_get_db gives for it, None for NULL.
// Package keeps no db pointer, so callers pair them
#[derive(Clone, Copy, Debug)]
pub struct DbPkg<'a> {
	pub pkg: &'a Package,
	pub db: Option<&'a Db>,
}

impl DbPkg<'_> {
	fn db_name(&self) -> Option<&[u8]> {
		self.db.map(Db::name)
	}
}

fn opt(s: &Option<Vec<u8>>) -> &[u8] {
	until_nul(s.as_deref().unwrap_or_default())
}

// "%.2f %s" of humanize_size in MiB
fn mib(size: i64) -> Vec<u8> {
	let (v, unit) = humanize_size(size, b'M', 2);
	format!("{v:.2} {unit}").into_bytes()
}

// table_cell_t modes
const CELL_NORMAL: u8 = 0;
const CELL_TITLE: u8 = 1 << 0;
const CELL_RIGHT_ALIGN: u8 = 1 << 1;

// columns between table cells
const TABLE_PADDING: usize = 2;

// table_cell_t: label None is NULL (no download size), len the
// string_length taken when the cell was added
struct Cell {
	label: Option<Vec<u8>>,
	len: usize,
	mode: u8,
}

// add_table_cell
fn add_table_cell(row: &mut Vec<Cell>, label: Option<Vec<u8>>, mode: u8) {
	let len = label.as_deref().map_or(0, string_length);
	row.push(Cell { label, len, mode });
}

// add_transaction_sizes_row: title label, size right aligned in MiB
fn add_transaction_sizes_row(
	rows: &mut Vec<Vec<Cell>>,
	label: &[u8],
	size: i64,
) {
	let mut row = Vec::new();
	add_table_cell(&mut row, Some(label.to_vec()), CELL_TITLE);
	add_table_cell(&mut row, Some(mib(size)), CELL_RIGHT_ALIGN);
	rows.push(row);
}

// %*s: a negative width pads on the right, widths count bytes
fn put_padded(out: &mut Vec<u8>, s: &[u8], width: c_int) {
	let pad = (width.unsigned_abs() as usize).saturating_sub(s.len());
	if width < 0 {
		out.extend_from_slice(s);
		put_spaces(out, pad);
	} else {
		put_spaces(out, pad);
		out.extend_from_slice(s);
	}
}

// table_print_line: the cells of columns with data, padded to the
// column width in display columns
fn table_print_line(
	out: &mut Vec<u8>,
	colstr: &ColStr,
	line: &[Cell],
	widths: &[usize],
	has_data: &[bool],
) {
	let mut need_padding = false;
	for ((cell, &w), &data) in line.iter().zip(widths).zip(has_data) {
		if !data {
			continue;
		}
		let s = cell.label.as_deref().map_or(&[][..], until_nul);
		// (int)widths[i] - string_length + strlen in size_t, back to
		// int: the byte width that fills w display columns
		let w = (w as c_int as usize)
			.wrapping_sub(string_length(s))
			.wrapping_add(s.len()) as c_int;
		let w = match cell.mode & CELL_RIGHT_ALIGN {
			0 => w.wrapping_neg(),
			_ => w,
		};
		if need_padding {
			put_spaces(out, TABLE_PADDING);
		}
		if cell.mode & CELL_TITLE != 0 {
			out.extend_from_slice(until_nul(colstr.title));
			put_padded(out, s, w);
			out.extend_from_slice(until_nul(colstr.nocolor));
		} else {
			put_padded(out, s, w);
		}
		need_padding = true;
	}
	out.push(b'\n');
}

// table_calc_widths: the widest cell per column (the header counts for
// the width, not for having data), which columns have data, and the
// total width of those plus padding between them. size_t sums wrap
fn table_calc_widths(
	header: &[Cell],
	rows: &[Vec<Cell>],
) -> (usize, Vec<usize>, Vec<bool>) {
	let mut widths: Vec<usize> = header.iter().map(|c| c.len).collect();
	let mut has_data = vec![false; widths.len()];
	for row in rows {
		// the C writes past the header's columns, callers never
		// build wider rows
		for (i, cell) in row.iter().take(widths.len()).enumerate() {
			widths[i] = widths[i].max(cell.len);
			has_data[i] |= cell.len > 0;
		}
	}
	let useful = has_data.iter().filter(|&&d| d).count();
	let mut total = widths
		.iter()
		.zip(&has_data)
		.filter(|(_, d)| **d)
		.fold(0usize, |t, (&w, _)| t.wrapping_add(w));
	if useful > 0 {
		total = total.wrapping_add(TABLE_PADDING * (useful - 1));
	}
	(total, widths, has_data)
}

// table_display: header (if any), an empty line, the rows. -1 when the
// table is wider than cols (warned; cols 0 is no limit) or has no width,
// nothing printed then. no rows prints nothing and is 0
fn table_display(
	out: &mut Output,
	config: &Config,
	header: Option<&[Cell]>,
	rows: &[Vec<Cell>],
	cols: u16,
) -> i32 {
	let Some(first) = rows.first() else {
		return 0;
	};
	let first = header.unwrap_or(first);
	if first.is_empty() {
		return -1;
	}
	let (total, widths, has_data) = table_calc_widths(first, rows);
	if cols != 0 && total > usize::from(cols) {
		let msg = b"insufficient columns available for table display\n";
		pm_printf(&mut out.stderr, config, LOG_WARNING, msg);
		return -1;
	}
	if total == 0 {
		return -1;
	}
	let c = &config.colstr;
	if let Some(h) = header {
		table_print_line(&mut out.stdout, c, h, &widths, &has_data);
		out.stdout.push(b'\n');
	}
	for row in rows {
		table_print_line(&mut out.stdout, c, row, &widths, &has_data);
	}
	0
}

// pm_target_t
#[derive(Clone, Copy, Debug)]
pub struct Target<'a> {
	pub remove: Option<&'a Package>,
	pub install: Option<DbPkg<'a>>,
	pub is_explicit: bool,
}

impl Target<'_> {
	// the C reads install first, a target always has one of the two
	fn name(&self) -> &[u8] {
		match (self.install, self.remove) {
			(Some(i), _) => i.pkg.name_bytes(),
			(None, Some(r)) => r.name_bytes(),
			(None, None) => b"",
		}
	}
}

// create_verbose_header
fn create_verbose_header(count: usize) -> Vec<Cell> {
	let mut row = Vec::new();
	let first = format!("Package ({count})").into_bytes();
	add_table_cell(&mut row, Some(first), CELL_TITLE);
	for t in [
		&b"Old Version"[..],
		b"New Version",
		b"Net Change",
		b"Download Size",
	] {
		add_table_cell(&mut row, Some(t.to_vec()), CELL_TITLE);
	}
	row
}

// create_verbose_row: [db/]name, old and new version, net installed
// size change, download size (NULL when 0)
fn create_verbose_row(target: &Target) -> Vec<Cell> {
	let mut row = Vec::new();
	let name = match (target.install, target.remove) {
		(Some(i), _) => match i.db_name() {
			Some(db) => [until_nul(db), b"/", i.pkg.name_bytes()]
				.concat(),
			None => i.pkg.name_bytes().to_vec(),
		},
		(None, r) => r.map_or(&[][..], Package::name_bytes).to_vec(),
	};
	add_table_cell(&mut row, Some(name), CELL_NORMAL);
	let old = target.remove.map_or(&[][..], |p| opt(&p.version));
	add_table_cell(&mut row, Some(old.to_vec()), CELL_NORMAL);
	let new = target.install.map_or(&[][..], |i| opt(&i.pkg.version));
	add_table_cell(&mut row, Some(new.to_vec()), CELL_NORMAL);
	let size = target
		.install
		.map_or(0, |i| i.pkg.isize)
		.wrapping_sub(target.remove.map_or(0, |p| p.isize));
	add_table_cell(&mut row, Some(mib(size)), CELL_RIGHT_ALIGN);
	let dl = target.install.map_or(0, |i| i.pkg.download_size);
	let dl = (dl != 0).then(|| mib(dl));
	add_table_cell(&mut row, dl, CELL_RIGHT_ALIGN);
	row
}

// the list_display entry of a target
fn target_entry(target: &Target, colstr: &ColStr, isize: i64) -> Vec<u8> {
	let (faint, nocolor) =
		(until_nul(colstr.faint), until_nul(colstr.nocolor));
	let (pkg, removal) = match (target.install, target.remove) {
		(Some(i), _) => (i.pkg, false),
		(None, Some(r)) => (r, isize != 0),
		(None, None) => return Vec::new(),
	};
	let mut s = [pkg.name_bytes(), faint, b"-", opt(&pkg.version)].concat();
	if removal {
		s.extend_from_slice(b" ");
		s.extend_from_slice(nocolor);
		s.extend_from_slice(b"[removal]");
	}
	s.extend_from_slice(nocolor);
	s
}

// _display_targets: the target list (a table with --verbose when it
// fits, else list_display), then download/installed/removed/net sizes.
// off_t sums wrap here where the C overflows
fn display_target_list(
	out: &mut Output,
	config: &Config,
	targets: &[Target],
	cols: u16,
) {
	if targets.is_empty() {
		return;
	}
	let (mut isize, mut rsize, mut dlsize) = (0i64, 0i64, 0i64);
	for t in targets {
		if let Some(i) = t.install {
			dlsize = dlsize.wrapping_add(i.pkg.download_size);
			isize = isize.wrapping_add(i.pkg.isize);
		}
		if let Some(r) = t.remove {
			rsize = rsize.wrapping_add(r.isize);
		}
	}
	let verbose = config.verbosepkglists != 0;
	let rows: Vec<Vec<Cell>> = match verbose {
		true => targets.iter().map(create_verbose_row).collect(),
		false => Vec::new(),
	};
	let names: Vec<Vec<u8>> = targets
		.iter()
		.map(|t| target_entry(t, &config.colstr, isize))
		.collect();
	let title = format!("Packages ({})", targets.len()).into_bytes();
	out.stdout.push(b'\n');
	let header = create_verbose_header(targets.len());
	if !verbose
		|| table_display(out, config, Some(&header), &rows, cols) != 0
	{
		let c = &config.colstr;
		list_display(&mut out.stdout, Some(&title), &names, cols, c);
	}
	out.stdout.push(b'\n');

	let mut rows = Vec::new();
	let downloadonly = config.op_s_downloadonly != 0;
	if dlsize > 0 || downloadonly {
		let label = b"Total Download Size:";
		add_transaction_sizes_row(&mut rows, label, dlsize);
	}
	if !downloadonly {
		if isize > 0 {
			let label = b"Total Installed Size:";
			add_transaction_sizes_row(&mut rows, label, isize);
		}
		if rsize > 0 && isize == 0 {
			let label = b"Total Removed Size:";
			add_transaction_sizes_row(&mut rows, label, rsize);
		}
		// the net value only when it differs from the installed size
		if isize > 0 && rsize > 0 {
			let net = isize.wrapping_sub(rsize);
			let label = b"Net Upgrade Size:";
			add_transaction_sizes_row(&mut rows, label, net);
		}
	}
	table_display(out, config, None, &rows, cols);
}

// target_cmp: implicit targets (deps, pulled in) before explicit ones,
// then by name. the C returns 0 instead of -1 for implicit against
// explicit, which its merge sort (left first on <= 0) orders the same
pub fn target_cmp(a: &Target, b: &Target) -> Ordering {
	a.is_explicit
		.cmp(&b.is_explicit)
		.then_with(|| a.name().cmp(b.name()))
}

// what display_targets reads of the transaction and of config
pub struct TransTargets<'a> {
	// alpm_trans_get_add, alpm_trans_get_remove
	pub add: &'a [DbPkg<'a>],
	pub remove: &'a [&'a Package],
	// config->explicit_adds/explicit_removes, matched by name (pkg_cmp)
	pub explicit_adds: &'a [&'a Package],
	pub explicit_removes: &'a [&'a Package],
}

// alpm_db_get_pkg on the local cache: "" is WrongArgs, no package
fn local_pkg<'a>(local: &[&'a Package], name: &[u8]) -> Option<&'a Package> {
	match name.is_empty() {
		true => None,
		false => pkg_find(local.iter().copied(), name),
	}
}

// display_targets: installs paired with the local package of their name
// (local is the local db cache), then removals, sorted by target_cmp.
// cols is getcols(), verbose is config->verbosepkglists
pub fn display_targets(
	out: &mut Output,
	config: &Config,
	trans: &TransTargets,
	local: &[&Package],
	cols: u16,
) {
	let explicit = |list: &[&Package], pkg: &Package| {
		list.iter().any(|p| pkg_cmp(pkg, p) == Ordering::Equal)
	};
	let mut targets: Vec<Target> = trans
		.add
		.iter()
		.map(|&i| Target {
			remove: local_pkg(local, i.pkg.name_bytes()),
			install: Some(i),
			is_explicit: explicit(trans.explicit_adds, i.pkg),
		})
		.collect();
	targets.extend(trans.remove.iter().map(|&r| Target {
		remove: Some(r),
		install: None,
		is_explicit: explicit(trans.explicit_removes, r),
	}));
	// alpm_list_msort is stable, like sort_by
	targets.sort_by(target_cmp);
	display_target_list(out, config, &targets, cols);
}

// pkg_get_size: what --print-format %s shows for the operation.
// download_size is what alpm_pkg_download_size left in it
fn pkg_get_size(config: &Config, pkg: &Package) -> i64 {
	match config.op {
		PM_OP_SYNC => pkg.download_size,
		PM_OP_UPGRADE => pkg.size,
		_ => pkg.isize,
	}
}

// pkg_get_location: a sync package already in a cache dir (stat, a
// regular file) as file://, else its db's first server, else (and for
// file packages) the filename; local and unknown origins name-version.
// a NULL filename is "" where the C prints "(null)" or crashes
fn pkg_get_location(p: DbPkg, cachedirs: &[Vec<u8>]) -> Vec<u8> {
	let pkg = p.pkg;
	let filename = opt(&pkg.filename);
	match pkg.origin {
		Some(PkgFrom::SyncDb) => {
			if pkg.download_size == 0 {
				for dir in cachedirs {
					let path = [until_nul(dir), filename]
						.concat();
					let path = path_max(path);
					let m = fs::metadata(
						OsStr::from_bytes(&path),
					);
					if m.is_ok_and(|m| m.is_file()) {
						return [b"file://", &path[..]]
							.concat();
					}
				}
			}
			let servers = p.db.map_or(&[][..], Db::servers);
			match servers.first() {
				Some(s) => {
					[until_nul(s), b"/", filename].concat()
				}
				None => filename.to_vec(),
			}
		}
		Some(PkgFrom::File(_)) => filename.to_vec(),
		Some(PkgFrom::LocalDb) | None => {
			[pkg.name_bytes(), b"-", opt(&pkg.version)].concat()
		}
	}
}

// concat_list: items joined by spaces
fn concat_list<S: AsRef<[u8]>>(list: &[S]) -> Vec<u8> {
	let items: Vec<&[u8]> =
		list.iter().map(|s| until_nul(s.as_ref())).collect();
	items.join(&b' ')
}

fn concat_deps(deps: &[Depend]) -> Vec<u8> {
	concat_list(&deps.iter().map(dep_compute_string).collect::<Vec<_>>())
}

// print_packages: --print-format (default "%l") per package, the tokens
// replaced in this order, so text a field brings in can match a later
// token. %b stays as is for a build date of -1. format_date is
// strftime("%c", localtime()), None where localtime fails (the C
// crashes there, "" here). cachedirs are the handle's
pub fn print_packages(
	out: &mut Vec<u8>,
	config: &Config,
	pkgs: &[DbPkg],
	cachedirs: &[Vec<u8>],
	format_date: impl Fn(i64) -> Option<Vec<u8>>,
) {
	let format =
		config.print_format.as_deref().map_or(&b"%l"[..], until_nul);
	for &p in pkgs {
		let pkg = p.pkg;
		let mut s = strreplace(format, b"%a", opt(&pkg.arch));
		if pkg.builddate != -1 {
			let date =
				format_date(pkg.builddate).unwrap_or_default();
			s = strreplace(&s, b"%b", &date);
		}
		let fields: [(&[u8], &[u8]); 8] = [
			(b"%d", opt(&pkg.desc)),
			(b"%e", opt(&pkg.base)),
			(b"%f", opt(&pkg.filename)),
			(b"%g", opt(&pkg.base64_sig)),
			(b"%h", opt(&pkg.sha256sum)),
			(b"%n", opt(&pkg.name)),
			(b"%p", opt(&pkg.packager)),
			(b"%v", opt(&pkg.version)),
		];
		for (token, value) in fields {
			s = strreplace(&s, token, value);
		}
		s = strreplace(&s, b"%l", &pkg_get_location(p, cachedirs));
		let repo = p.db_name().unwrap_or(b"local");
		s = strreplace(&s, b"%r", repo);
		let size = pkg_get_size(config, pkg).to_string();
		s = strreplace(&s, b"%s", size.as_bytes());
		s = strreplace(&s, b"%u", opt(&pkg.url));
		let lists: [(&[u8], Vec<u8>); 9] = [
			(b"%C", concat_deps(&pkg.checkdepends)),
			(b"%D", concat_deps(&pkg.depends)),
			(b"%G", concat_list(&pkg.groups)),
			(b"%H", concat_deps(&pkg.conflicts)),
			(b"%M", concat_deps(&pkg.makedepends)),
			(b"%O", concat_deps(&pkg.optdepends)),
			(b"%P", concat_deps(&pkg.provides)),
			(b"%R", concat_deps(&pkg.replaces)),
			(b"%L", concat_list(&pkg.licenses)),
		];
		for (token, value) in lists {
			s = strreplace(&s, token, &value);
		}
		out.extend_from_slice(&s);
		out.push(b'\n');
	}
}

// strcmp with NULL before any string, the order depend_cmp gives
// version and desc
fn cmp_opt(a: &Option<Vec<u8>>, b: &Option<Vec<u8>>) -> Ordering {
	match (a, b) {
		(Some(a), Some(b)) => until_nul(a).cmp(until_nul(b)),
		_ => a.is_some().cmp(&b.is_some()),
	}
}

// depend_cmp: name, modifier, version, description
pub fn depend_cmp(a: &Depend, b: &Depend) -> Ordering {
	until_nul(&a.name)
		.cmp(until_nul(&b.name))
		.then((a.depmod as i32).cmp(&(b.depmod as i32)))
		.then_with(|| cmp_opt(&a.version, &b.version))
		.then_with(|| cmp_opt(&a.desc, &b.desc))
}

// make_optstring: the optdepend, marked when a package of the local db
// cache (local) or of the transaction's add list (pending) satisfies it
fn make_optstring(
	optdep: &Depend,
	local: &[&Package],
	pending: &[&Package],
) -> Vec<u8> {
	let mut s = dep_compute_string(optdep);
	if find_satisfier(local.iter().copied(), &s).is_some() {
		s.extend_from_slice(b" [installed]");
	} else if find_satisfier(pending.iter().copied(), &s).is_some() {
		s.extend_from_slice(b" [pending]");
	}
	s
}

// the optdepend lines under "<title> <name>"
fn optdepends_display(
	out: &mut Vec<u8>,
	colstr: &ColStr,
	title: &[u8],
	pkg: &Package,
	optdeps: &[&Depend],
	installed: (&[&Package], &[&Package]),
	cols: u16,
) {
	let strings: Vec<Vec<u8>> = optdeps
		.iter()
		.map(|d| make_optstring(d, installed.0, installed.1))
		.collect();
	if strings.is_empty() {
		return;
	}
	out.extend_from_slice(title);
	out.extend_from_slice(pkg.name_bytes());
	out.push(b'\n');
	list_display_linebreak(out, Some(b"   "), &strings, cols, colstr);
}

// alpm_list_diff with depend_cmp: both lists sorted (stable), then
// what only new has, in sorted order; equal entries pair up one to one
fn optdepends_diff<'a>(new: &'a [Depend], old: &[Depend]) -> Vec<&'a Depend> {
	let mut new: Vec<&Depend> = new.iter().collect();
	let mut old: Vec<&Depend> = old.iter().collect();
	new.sort_by(|a, b| depend_cmp(a, b));
	old.sort_by(|a, b| depend_cmp(a, b));
	let mut ret = Vec::new();
	let (mut l, mut r) = (0, 0);
	while l < new.len() && r < old.len() {
		match depend_cmp(new[l], old[r]) {
			Ordering::Less => {
				ret.push(new[l]);
				l += 1;
			}
			Ordering::Greater => r += 1,
			Ordering::Equal => {
				l += 1;
				r += 1;
			}
		}
	}
	ret.extend_from_slice(&new[l..]);
	ret
}

// display_new_optdepends: optdepends newpkg has and oldpkg had not.
// local is the local db cache, pending the transaction's add list,
// cols getcols()
pub fn display_new_optdepends(
	out: &mut Vec<u8>,
	colstr: &ColStr,
	(oldpkg, newpkg): (&Package, &Package),
	(local, pending): (&[&Package], &[&Package]),
	cols: u16,
) {
	let optdeps = optdepends_diff(&newpkg.optdepends, &oldpkg.optdepends);
	let title = b"New optional dependencies for ";
	let installed = (local, pending);
	optdepends_display(
		out, colstr, title, newpkg, &optdeps, installed, cols,
	);
}

// display_optdepends: as display_new_optdepends, all of pkg's
pub fn display_optdepends(
	out: &mut Vec<u8>,
	colstr: &ColStr,
	pkg: &Package,
	(local, pending): (&[&Package], &[&Package]),
	cols: u16,
) {
	let optdeps: Vec<&Depend> = pkg.optdepends.iter().collect();
	let title = b"Optional dependencies for ";
	let installed = (local, pending);
	optdepends_display(out, colstr, title, pkg, &optdeps, installed, cols);
}

// display_repo_list
fn display_repo_list(
	out: &mut Vec<u8>,
	colstr: &ColStr,
	dbname: &[u8],
	list: &[Vec<u8>],
	cols: u16,
) {
	let msg = [b"Repository ", until_nul(colstr.repo), dbname, b"\n"];
	colon_printf(out, colstr, &msg.concat());
	list_display(out, Some(b"  "), list, cols, colstr);
}

// select_display: "<n>) name" numbered across the list, one block per
// run of packages from the same db, each package with the name of its db
// (alpm_pkg_get_db; Package keeps no db, callers pair them). the C needs
// a db per package and a non-empty list (strcmp/printf of NULL); None
// is "" and an empty list prints nothing here
pub fn select_display(
	out: &mut Vec<u8>,
	colstr: &ColStr,
	pkgs: &[(Option<&[u8]>, &Package)],
	cols: u16,
) {
	let name = |p: &(Option<&[u8]>, &Package)| -> Vec<u8> {
		until_nul(p.0.unwrap_or_default()).to_vec()
	};
	let Some(first) = pkgs.first() else {
		return;
	};
	let mut dbname = name(first);
	let mut list = Vec::new();
	for (nth, p) in (1..).zip(pkgs) {
		if name(p) != dbname {
			display_repo_list(out, colstr, &dbname, &list, cols);
			list.clear();
			dbname = name(p);
		}
		let mut entry = format!("{nth}) ").into_bytes();
		entry.extend_from_slice(p.1.name_bytes());
		list.push(entry);
	}
	display_repo_list(out, colstr, &dbname, &list, cols);
}

// the process the prompts and callbacks look at: stdin, whether stdin
// and stdout are terminals (a terminal stdin echoes the answer itself, a
// terminal stdout gets the cursor shown while reading), getcols() and
// the clocks (get_time_ms: CLOCK_MONOTONIC_COARSE in ms; time(NULL) for
// the PACMAN_DEBUG stamp), flush_term_input before a prompt reads
pub struct Term<R> {
	pub stdin: R,
	pub stdin_tty: bool,
	pub stdout_tty: bool,
	pub cols: fn() -> u16,
	pub flush_input: fn(),
	pub now_ms: fn() -> i64,
	pub now_secs: fn() -> i64,
	// callback.c's multibar_ui.move_completed_up, a process global
	// there: run() hands every Term of the process the same flag
	pub move_completed_up: Arc<AtomicBool>,
}

impl<R> Term<R> {
	// no terminal size (getcols 0), nothing to flush, clocks at 0: what
	// prompts alone need
	pub fn new(stdin: R, stdin_tty: bool, stdout_tty: bool) -> Self {
		Term {
			stdin,
			stdin_tty,
			stdout_tty,
			cols: || 0,
			flush_input: || {},
			now_ms: || 0,
			now_secs: || 0,
			move_completed_up: Arc::default(),
		}
	}
}

const CURSOR_HIDE_ANSICODE: &[u8] = b"\x1b[?25l";
const CURSOR_SHOW_ANSICODE: &[u8] = b"\x1b[?25h";

// console_cursor_hide: only on a terminal stdout
pub fn console_cursor_hide(out: &mut Vec<u8>, stdout_tty: bool) {
	if stdout_tty {
		out.extend_from_slice(CURSOR_HIDE_ANSICODE);
	}
}

// console_cursor_show: only on a terminal stdout
pub fn console_cursor_show(out: &mut Vec<u8>, stdout_tty: bool) {
	if stdout_tty {
		out.extend_from_slice(CURSOR_SHOW_ANSICODE);
	}
}

// safe_fgets_stdin: one safe_fgets with the cursor shown, what was
// printed flushed first (the C's fflush before reading). a read error
// is the C's NULL
pub fn safe_fgets_stdin<R: BufRead>(
	out: &mut Output,
	term: &mut Term<R>,
	size: usize,
) -> Option<Vec<u8>> {
	console_cursor_show(&mut out.stdout, term.stdout_tty);
	out.flush();
	let line = safe_fgets(&mut term.stdin, size).ok().flatten();
	console_cursor_hide(&mut out.stdout, term.stdout_tty);
	line
}

// the prompts write to stdout with --noconfirm, else to stderr so they
// show when stdout is redirected
fn prompt_stream<'a>(out: &'a mut Output, config: &Config) -> &'a mut Vec<u8> {
	match config.noconfirm {
		0 => &mut out.stderr,
		_ => &mut out.stdout,
	}
}

// parseindex: s as a whole base 10 strtol, cut to int, within
// [min, max]. "" is 0 like strtol. errors go to stderr
fn parseindex(
	err: &mut Vec<u8>,
	config: &Config,
	s: &[u8],
	min: c_int,
	max: c_int,
) -> Option<c_int> {
	let n = match s.is_empty() {
		true => Some(0),
		false => strtol_whole(s).map(|v| v as c_int),
	};
	let Some(n) = n else {
		let msg = [b"invalid number: ", s, b"\n"].concat();
		pm_printf(err, config, LOG_ERROR, &msg);
		return None;
	};
	if n < min || n > max {
		let msg = format!(
			"invalid value: {n} is not between {min} and {max}\n"
		);
		pm_printf(err, config, LOG_ERROR, msg.as_bytes());
		return None;
	}
	Some(n)
}

// strtok_r(.., " ,") on the C string in buf: the start of the next token
// from *save, the delimiter ending it overwritten with nul. None at the
// end of the string
fn strtok(buf: &mut [u8], save: &mut usize) -> Option<usize> {
	let delim = |c: u8| c == b' ' || c == b',';
	let mut i = *save;
	while buf[i] != 0 && delim(buf[i]) {
		i += 1;
	}
	if buf[i] == 0 {
		*save = i;
		return None;
	}
	let start = i;
	while buf[i] != 0 && !delim(buf[i]) {
		i += 1;
	}
	*save = i;
	if buf[i] != 0 {
		buf[i] = 0;
		*save = i + 1;
	}
	Some(start)
}

// strtrim in place on the C string at buf[start..], its new length: the
// trimmed string moves to start and gets its nul, the bytes after that
// keep what the move left there
fn strtrim_in_place(buf: &mut [u8], start: usize) -> usize {
	let n = until_nul(&buf[start..]).len();
	if n == 0 {
		return 0;
	}
	let s = &buf[start..start + n];
	let lead = s.iter().take_while(|&&c| is_space(c)).count();
	if lead == n {
		buf[start] = 0;
		return 0;
	}
	// memmove of the rest with its nul
	buf.copy_within(start + lead..start + n + 1, start);
	let len = n - lead;
	let s = &buf[start..start + len];
	let trail = s.iter().rev().take_while(|&&c| is_space(c)).count();
	buf[start + len - trail] = 0;
	len - trail
}

// multiselect_parse on the C string in buf, edited in place like the C
// (strtok, strtrim, the range dash cut): tokens split at ' ' and ',',
// each "n", "n-m" or "^"-prefixed to deselect. an including first token
// deselects all first; that is strtok's first token only, so not when
// it is all whitespace. stops at the first invalid token (-1), what came
// before stays applied
fn multiselect_parse(
	err: &mut Vec<u8>,
	config: &Config,
	array: &mut [bool],
	buf: &mut [u8],
) -> i32 {
	let count = c_int::try_from(array.len()).unwrap_or(c_int::MAX);
	let mut save = 0;
	let mut first = true;
	while let Some(token) = strtok(buf, &mut save) {
		let is_first = std::mem::replace(&mut first, false);
		let mut len = strtrim_in_place(buf, token);
		if len == 0 {
			continue;
		}
		let mut starts = token;
		let include = buf[token] != b'^';
		if !include {
			starts += 1;
			len -= 1;
		} else if is_first {
			array.fill(false);
		}
		let mut ends = None;
		// a range dash comes after the first character
		if len > 1 {
			let s = &buf[starts + 1..starts + len];
			if let Some(p) = s.iter().position(|&c| c == b'-') {
				let p = starts + 1 + p;
				buf[p] = 0;
				ends = Some(p + 1);
			}
		}
		let s = until_nul(&buf[starts..]);
		let Some(start) = parseindex(err, config, s, 1, count) else {
			return -1;
		};
		let end = match ends {
			None => start,
			Some(e) => {
				let e = until_nul(&buf[e..]);
				match parseindex(err, config, e, start, count) {
					Some(end) => end,
					None => return -1,
				}
			}
		};
		for k in start..=end {
			array[k as usize - 1] = include;
		}
	}
	0
}

// response buffer of multiselect_question and its growth
const RESPONSE_LEN: usize = 64;
const RESPONSE_INCR: usize = 64;

// fgets into buf at off, at most size - 1 bytes and a nul
fn read_into<R: BufRead>(
	out: &mut Output,
	term: &mut Term<R>,
	buf: &mut [u8],
	off: usize,
	size: usize,
) -> bool {
	let Some(chunk) = safe_fgets_stdin(out, term, size) else {
		return false;
	};
	buf[off..off + chunk.len()].copy_from_slice(&chunk);
	buf[off + chunk.len()] = 0;
	true
}

// multiselect_question: array starts all selected (also with
// --noconfirm and after an invalid answer, which asks again). the
// answer goes through the C's buffer: read whole, grown in chunks while
// its last byte (a sentinel) was overwritten by fgets' nul and the byte
// before is no newline. the buffer keeps its size and bytes across
// answers, edited by the trim and parse, so after an invalid answer the
// stale last bytes can make the next one read on. end of input where a
// read is due is -1
pub fn multiselect_question<R: BufRead>(
	out: &mut Output,
	config: &Config,
	term: &mut Term<R>,
	array: &mut [bool],
) -> i32 {
	let mut len = RESPONSE_LEN;
	// malloc'd: only bytes written before are read
	let mut buf = vec![0u8; len];
	buf[len - 1] = 1;
	loop {
		array.fill(true);
		let s = prompt_stream(out, config);
		s.extend_from_slice(b"\nEnter a selection (default=all): ");
		if config.noconfirm != 0 {
			s.push(b'\n');
			return 0;
		}
		(term.flush_input)();
		if !read_into(out, term, &mut buf, 0, len) {
			return -1;
		}
		while buf[len - 1] == 0 && buf[len - 2] != b'\n' {
			len += RESPONSE_INCR;
			buf.resize(len, 0);
			buf[len - 1] = 1;
			let off = len - RESPONSE_INCR - 1;
			let size = RESPONSE_INCR + 1;
			if !read_into(out, term, &mut buf, off, size) {
				return -1;
			}
		}
		if strtrim_in_place(&mut buf, 0) > 0
			&& multiselect_parse(
				&mut out.stderr,
				config,
				array,
				&mut buf,
			) == -1
		{
			continue;
		}
		return 0;
	}
}

// select_question: index of the chosen package, 0 (the default) for an
// empty answer, end of input or --noconfirm. an invalid number asks
// again
pub fn select_question<R: BufRead>(
	out: &mut Output,
	config: &Config,
	term: &mut Term<R>,
	count: c_int,
) -> c_int {
	let preset = 1;
	loop {
		let s = prompt_stream(out, config);
		let prompt = format!("\nEnter a number (default={preset}): ");
		s.extend_from_slice(prompt.as_bytes());
		if config.noconfirm != 0 {
			s.push(b'\n');
			break;
		}
		let size = 32;
		(term.flush_input)();
		if let Some(line) = safe_fgets_stdin(out, term, size) {
			let response = strtrim(&line);
			if !response.is_empty() {
				let err = &mut out.stderr;
				match parseindex(
					err, config, response, 1, count,
				) {
					Some(n) => return n - 1,
					None => continue,
				}
			}
		}
		break;
	}
	preset - 1
}

// glibc towlower: the simple lowercase mapping, the first character of
// Rust's (only U+0130 lowers to two). non-characters stay
fn towlower(c: u32) -> u32 {
	char::from_u32(c)
		.and_then(|ch| ch.to_lowercase().next())
		.map_or(c, u32::from)
}

// strcasecmp: bytes compared after ASCII tolower (C.UTF-8 leaves bytes
// past 0x7f alone)
fn strcasecmp(a: &[u8], b: &[u8]) -> Ordering {
	let a = a.iter().map(u8::to_ascii_lowercase);
	a.cmp(b.iter().map(u8::to_ascii_lowercase))
}

// mbscasecmp: characters compared after towlower while both strings
// decode, strcasecmp of the rest from an invalid or incomplete one. the
// end compares the next bytes as signed char
pub fn mbscasecmp(s1: &[u8], s2: &[u8]) -> Ordering {
	let (s1, s2) = (until_nul(s1), until_nul(s2));
	let (mut p1, mut p2) = (0, 0);
	while p1 < s1.len() && p2 < s2.len() {
		let (Some((c1, b1)), Some((c2, b2))) =
			(decode_one(&s1[p1..]), decode_one(&s2[p2..]))
		else {
			return strcasecmp(&s1[p1..], &s2[p2..]);
		};
		let (c1, c2) = (towlower(c1), towlower(c2));
		if c1 != c2 {
			return c1.cmp(&c2);
		}
		p1 += b1;
		p2 += b2;
	}
	let end = |s: &[u8], p: usize| s.get(p).map_or(0, |&c| c as i8);
	end(s1, p1).cmp(&end(s2, p2))
}

// question: "<colon><msg> [Y/n] <nocolor>" (preset 1) or [y/N], then a
// line of at most 31 bytes. empty or --noconfirm gives the preset,
// y/yes and n/no in any case 1 and 0, anything else and end of input 0.
// a stdin that is no terminal does not echo, so the answer is repeated
fn question<R: BufRead>(
	out: &mut Output,
	config: &Config,
	term: &mut Term<R>,
	preset: bool,
	msg: &[u8],
) -> bool {
	let c = &config.colstr;
	let s = prompt_stream(out, config);
	s.extend_from_slice(until_nul(c.colon));
	s.extend_from_slice(msg);
	s.extend_from_slice(match preset {
		true => b" [Y/n] ",
		false => b" [y/N] ",
	});
	s.extend_from_slice(until_nul(c.nocolor));
	if config.noconfirm != 0 {
		s.push(b'\n');
		return preset;
	}
	(term.flush_input)();
	let Some(line) = safe_fgets_stdin(out, term, 32) else {
		return false;
	};
	let response = strtrim(&line);
	if response.is_empty() {
		return preset;
	}
	if !term.stdin_tty {
		let s = prompt_stream(out, config);
		s.extend_from_slice(response);
		s.push(b'\n');
	}
	let is = |word: &[u8]| mbscasecmp(response, word) == Ordering::Equal;
	if is(b"Y") || is(b"YES") {
		return true;
	}
	false
}

// yesno: question defaulting to yes. msg is the formatted message
pub fn yesno<R: BufRead>(
	out: &mut Output,
	config: &Config,
	term: &mut Term<R>,
	msg: &[u8],
) -> bool {
	question(out, config, term, true, msg)
}

// noyes: question defaulting to no
pub fn noyes<R: BufRead>(
	out: &mut Output,
	config: &Config,
	term: &mut Term<R>,
	msg: &[u8],
) -> bool {
	question(out, config, term, false, msg)
}

// trans_init_error: the init failure, for a lock failure its errno and
// a hint when the lock file exists
pub fn trans_init_error(
	out: &mut Output,
	config: &Config,
	handle: &Handle,
	err: &InitError,
) {
	let msg = [
		b"failed to init transaction (",
		err.errno().strerror().as_bytes(),
		b")\n",
	];
	pm_printf(&mut out.stderr, config, LOG_ERROR, &msg.concat());
	let InitError::Lock(e) = err else {
		return;
	};
	let msg = [b"could not lock database: ", &strerror(e)[..], b"\n"];
	pm_printf(&mut out.stderr, config, LOG_ERROR, &msg.concat());
	let lockfile = handle.lockfile();
	if fs::metadata(OsStr::from_bytes(lockfile)).is_ok() {
		out.stderr.extend_from_slice(
			b"  if you're sure a package manager is not already\n  \
			running, you can remove ",
		);
		out.stderr.extend_from_slice(lockfile);
		out.stderr.push(b'\n');
	}
}

// trans_init: check_syncdbs (result ignored, its errors printed), then
// alpm_trans_init. false is the C's -1
pub fn trans_init(
	out: &mut Output,
	config: &Config,
	handle: &mut Handle,
	flags: c_int,
	check_valid: bool,
) -> bool {
	check_syncdbs(&mut out.stderr, config, handle, false, check_valid);
	match alpm_trans_init(handle, flags) {
		Ok(()) => true,
		Err(e) => {
			trans_init_error(out, config, handle, &e);
			false
		}
	}
}

// trans_release: false (C -1) when there is no transaction
pub fn trans_release(
	out: &mut Output,
	config: &Config,
	handle: &mut Handle,
) -> bool {
	let Err(e) = alpm_trans_release(handle) else {
		return true;
	};
	let msg = [
		b"failed to release transaction (",
		e.strerror().as_bytes(),
		b")\n",
	];
	pm_printf(&mut out.stderr, config, LOG_ERROR, &msg.concat());
	false
}

// what the transaction front ends (sync.c, remove.c, upgrade.c) use
// besides the handle
pub struct Ui<'a, R> {
	pub config: &'a Config,
	pub term: &'a mut Term<R>,
	// getcols()
	pub cols: u16,
	pub out: &'a mut Output,
	// strftime("%c", localtime()) for --print-format %b
	pub format_date: &'a dyn Fn(i64) -> Option<Vec<u8>>,
	// config->explicit_adds/explicit_removes
	pub explicit_adds: Vec<Package>,
	pub explicit_removes: Vec<Package>,
}

// util.c needs_root: operations that modify the system
pub fn needs_root(config: &Config) -> bool {
	let c = config;
	match c.op {
		PM_OP_DATABASE => c.op_q_check == 0,
		PM_OP_UPGRADE | PM_OP_REMOVE => c.print == 0,
		PM_OP_SYNC => {
			c.op_s_clean != 0
				|| c.op_s_sync != 0 || (c.group == 0
				&& c.op_s_info == 0 && c
				.op_q_list
				== 0 && c.op_s_search == 0 && c
				.print
				== 0)
		}
		PM_OP_FILES => c.op_s_sync != 0,
		_ => false,
	}
}
