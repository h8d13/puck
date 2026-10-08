// port of src/pacman/util.c, the display helpers plus pm_printf,
// check_syncdbs, getcols, the prompts (yesno, noyes, select_question)
// and the displays the callbacks use (colon_printf, select_display,
// display_optdepends)
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

use std::ffi::{c_int, c_long};
use std::io::{self, IsTerminal};
use std::iter::repeat_n;
use std::os::unix::ffi::OsStrExt;

use alpm_core::handle::Handle;
use alpm_core::log::utc_now;
use alpm_core::util::until_nul;
use pacman_common::util_common::strtrim;
use unicode_width::UnicodeWidthChar;

pub use crate::conf::ColStr;
use crate::conf::{Config, LOG_DEBUG, LOG_ERROR, LOG_FUNCTION, LOG_WARNING};

// what the C writes to stdout and stderr
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Output {
	pub stdout: Vec<u8>,
	pub stderr: Vec<u8>,
}

// time(NULL)
pub fn now_secs() -> i64 {
	utc_now().secs
}

// PACMAN_DEBUG (set by the meson build): pm_vfprintf puts "[%H:%M:%S] "
// before every message while debug logging is on. localtime needs the
// zone database, safe std has none: the stamp is UTC (TZ=UTC in the C)
pub fn debug_stamp(secs: i64) -> Vec<u8> {
	let s = secs.rem_euclid(86400);
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

// pm_vfprintf: pm_vasprintf with the PACMAN_DEBUG stamp of now (time(NULL))
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

// getcols without the cache: COLUMNS when it is a whole number, cut to
// int like the C; else 0 when stdout is no terminal. a terminal's width
// needs ioctl(TIOCGWINSZ) (rustix "termios"), here the C's fallback 80
pub fn getcols() -> u16 {
	let env = std::env::var_os("COLUMNS");
	let e = env.as_ref().map(|e| e.as_bytes()).unwrap_or_default();
	let mut c: c_int = -1;
	if !e.is_empty() {
		c = strtol_whole(e).map_or(-1, |v| v as c_int);
	}
	if c < 0 && !io::stdout().is_terminal() {
		c = 0;
	}
	if c < 0 {
		c = 80;
	}
	c as u16
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

// the process the prompts and callbacks talk to: the C stdout, stderr
// and stdin, and the probes the C makes on them
pub trait Term {
	// fputs to stdout, stderr
	fn out(&mut self, s: &[u8]);
	fn err(&mut self, s: &[u8]);
	// fflush(stdout) and fflush(stderr)
	fn flush(&mut self) {}
	// safe_fgets(s, size, stdin): at most size - 1 bytes up to and with
	// a '\n', None at end of input
	fn read_line(&mut self, size: usize) -> Option<Vec<u8>>;
	fn stdin_is_tty(&mut self) -> bool;
	fn stdout_is_tty(&mut self) -> bool;
	// getcols()
	fn cols(&mut self) -> u16;
	// get_time_ms: CLOCK_MONOTONIC_COARSE in milliseconds
	fn now_ms(&mut self) -> i64;
	// time(NULL), for the PACMAN_DEBUG stamp
	fn now_secs(&mut self) -> i64 {
		now_secs()
	}
}

// pm_printf on a Term: stderr, stamped
pub fn pm_printf_term(
	term: &mut dyn Term,
	config: &Config,
	level: u16,
	msg: &[u8],
) {
	let now = term.now_secs();
	if let Some(line) = pm_vfprintf(config, level, msg, now) {
		term.err(&line);
	}
}

// the prompt stream: stdout with --noconfirm, else stderr so prompts
// show when the output is redirected
fn prompt(term: &mut dyn Term, config: &Config, s: &[u8]) {
	match config.noconfirm {
		0 => term.err(s),
		_ => term.out(s),
	}
}

// CURSOR_HIDE_ANSICODE, CURSOR_SHOW_ANSICODE
pub const CURSOR_HIDE: &[u8] = b"\x1b[?25l";
pub const CURSOR_SHOW: &[u8] = b"\x1b[?25h";

// console_cursor_hide
pub fn console_cursor_hide(term: &mut dyn Term) {
	if term.stdout_is_tty() {
		term.out(CURSOR_HIDE);
	}
}

// console_cursor_show
pub fn console_cursor_show(term: &mut dyn Term) {
	if term.stdout_is_tty() {
		term.out(CURSOR_SHOW);
		term.flush();
	}
}

// safe_fgets_stdin: the cursor shows while reading
fn safe_fgets_stdin(term: &mut dyn Term, size: usize) -> Option<Vec<u8>> {
	console_cursor_show(term);
	let line = term.read_line(size);
	console_cursor_hide(term);
	line
}

// colon_printf: the colon prefix, the message, then nocolor
pub fn colon_printf(term: &mut dyn Term, config: &Config, msg: &[u8]) {
	let c = &config.colstr;
	term.out(&[c.colon, msg, c.nocolor].concat());
	term.flush();
}

// question: the yes/no prompt, preset on --noconfirm or an empty answer.
// one fgets of 32 bytes, what does not fit stays for the next read.
// mbscasecmp only meets ASCII here: no other character lowercases to
// y, e, s, n or o. flush_term_input (tcflush on a terminal stdin) needs
// termios, outside safe std: not done
fn question(
	term: &mut dyn Term,
	config: &Config,
	preset: bool,
	msg: &[u8],
) -> i32 {
	term.flush();
	let c = &config.colstr;
	let choice: &[u8] = if preset { b" [Y/n] " } else { b" [y/N] " };
	prompt(term, config, &[c.colon, msg, choice, c.nocolor].concat());
	term.flush();
	if config.noconfirm != 0 {
		prompt(term, config, b"\n");
		return i32::from(preset);
	}
	let Some(line) = safe_fgets_stdin(term, 32) else {
		return 0;
	};
	let response = strtrim(&line);
	if response.is_empty() {
		return i32::from(preset);
	}
	// a piped answer is not echoed by the terminal
	if !term.stdin_is_tty() {
		prompt(term, config, &[response, b"\n"].concat());
	}
	let is = |s: &[u8]| response.eq_ignore_ascii_case(s);
	i32::from(is(b"Y") || is(b"YES"))
}

// yesno: preset yes
pub fn yesno(term: &mut dyn Term, config: &Config, msg: &[u8]) -> i32 {
	question(term, config, true, msg)
}

// noyes: preset no
pub fn noyes(term: &mut dyn Term, config: &Config, msg: &[u8]) -> i32 {
	question(term, config, false, msg)
}

// strtol into an int: ERANGE saturates the long, the conversion to int
// keeps the low 32 bits (gcc). None when no digit was read or some
// trail (endptr not at the end)
fn strtol_int(s: &[u8]) -> Option<c_int> {
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
	let mut v: i64 = 0;
	for &d in rest {
		let d = i64::from(d - b'0');
		v = match neg {
			true => v.saturating_mul(10).saturating_sub(d),
			false => v.saturating_mul(10).saturating_add(d),
		};
	}
	Some(v as c_int)
}

// parseindex: a number within min..=max, errors reported
fn parseindex(
	term: &mut dyn Term,
	config: &Config,
	s: &[u8],
	min: c_int,
	max: c_int,
) -> Option<c_int> {
	let Some(n) = strtol_int(s) else {
		let msg = [b"invalid number: ", s, b"\n"].concat();
		pm_printf_term(term, config, LOG_ERROR, &msg);
		return None;
	};
	if n < min || n > max {
		let msg = format!(
			"invalid value: {n} is not between {min} and {max}\n"
		);
		pm_printf_term(term, config, LOG_ERROR, msg.as_bytes());
		return None;
	}
	Some(n)
}

// select_question: the index picked out of count (default the first),
// asked again after an invalid number
pub fn select_question(
	term: &mut dyn Term,
	config: &Config,
	count: c_int,
) -> c_int {
	let preset = 1;
	loop {
		let ask = format!("\nEnter a number (default={preset}): ");
		prompt(term, config, ask.as_bytes());
		term.flush();
		if config.noconfirm != 0 {
			prompt(term, config, b"\n");
			break;
		}
		let Some(line) = safe_fgets_stdin(term, 32) else {
			break;
		};
		let response = strtrim(&line);
		if response.is_empty() {
			break;
		}
		match parseindex(term, config, response, 1, count) {
			Some(n) => return n - 1,
			None => continue,
		}
	}
	preset - 1
}

// display_repo_list: colon_printf ends the line before its nocolor
fn display_repo_list(
	term: &mut dyn Term,
	config: &Config,
	dbname: &[u8],
	list: &[Vec<u8>],
	cols: u16,
) {
	let c = &config.colstr;
	colon_printf(
		term,
		config,
		&[b"Repository ", c.repo, dbname, b"\n"].concat(),
	);
	let mut out = Vec::new();
	list_display(&mut out, Some(b"  "), list, cols, &config.colstr);
	term.out(&out);
}

// select_display: "n) name" per provider (db name, package name), one
// list per run of the same db. the C prints a NULL db name for an empty
// list, never asked for
pub fn select_display(
	term: &mut dyn Term,
	config: &Config,
	providers: &[(&[u8], &[u8])],
) {
	let cols = term.cols();
	let mut list = Vec::new();
	let mut dbname: Option<&[u8]> = None;
	for (nth, &(db, name)) in providers.iter().enumerate() {
		let db = until_nul(db);
		if let Some(prev) = dbname.filter(|&p| p != db) {
			display_repo_list(term, config, prev, &list, cols);
			list.clear();
		}
		dbname = Some(db);
		let num = format!("{}) ", nth + 1);
		list.push([num.as_bytes(), until_nul(name)].concat());
	}
	let last = dbname.unwrap_or(b"(null)");
	display_repo_list(term, config, last, &list, cols);
}

// display_optdepends: optstrings are make_optstring's texts (the dep
// string and its status), nothing printed without any
pub fn display_optdepends(
	term: &mut dyn Term,
	config: &Config,
	name: &[u8],
	optstrings: &[Vec<u8>],
) {
	optdepends_list(
		term,
		config,
		b"Optional dependencies for ",
		name,
		optstrings,
	);
}

// display_new_optdepends: the same for the optdepends new in an upgrade
pub fn display_new_optdepends(
	term: &mut dyn Term,
	config: &Config,
	name: &[u8],
	optstrings: &[Vec<u8>],
) {
	let title = b"New optional dependencies for ";
	optdepends_list(term, config, title, name, optstrings);
}

fn optdepends_list(
	term: &mut dyn Term,
	config: &Config,
	title: &[u8],
	name: &[u8],
	optstrings: &[Vec<u8>],
) {
	if optstrings.is_empty() {
		return;
	}
	term.out(&[title, until_nul(name), b"\n"].concat());
	let cols = term.cols();
	let mut out = Vec::new();
	list_display_linebreak(
		&mut out,
		Some(b"   "),
		optstrings,
		cols,
		&config.colstr,
	);
	term.out(&out);
}
