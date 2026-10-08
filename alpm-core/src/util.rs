// port of lib/libalpm/util.c, filled in as callers get ported
//
// inputs are byte strings as the C would see them, cut at the first nul.
// _alpm_str_cmp is not ported: byte slices already order like strcmp.
// _alpm_realloc, _alpm_greedy_grow, _alpm_alloc_fail are not ported: Vec
// grows and zero-fills itself.

use std::ffi::{OsStr, c_char, c_ulong};
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{
	DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt,
};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, Stdio};

use alpm_compress::decompression::{CompressionDecoder, DecompressionSettings};
use alpm_compress::tarball::TarballReader;
use rustix::fs::{Access, AtFlags, CWD, accessat};

use crate::deps::LogLevel;

use crate::callbacks::{Callbacks, LogLevel};

// limits.h on linux
const PATH_MAX: usize = 4096;

// what a C string would see of these bytes
pub fn until_nul(s: &[u8]) -> &[u8] {
	match s.iter().position(|&c| c == 0) {
		Some(i) => &s[..i],
		None => s,
	}
}

// _alpm_strip_newline: trailing '\n' only, '\r' stays
pub fn strip_newline(s: &[u8]) -> &[u8] {
	let s = until_nul(s);
	let n = s.iter().rev().take_while(|&&c| c == b'\n').count();
	&s[..s.len() - n]
}

// _alpm_get_fullpath
pub fn get_fullpath(path: &[u8], filename: &[u8], suffix: &[u8]) -> Vec<u8> {
	[until_nul(path), until_nul(filename), until_nul(suffix)].concat()
}

// _alpm_hash_sdbm. C feeds plain char into the sum, signed on x86_64 and
// unsigned on aarch64, c_char keeps the same hash per platform
pub fn hash_sdbm(s: &[u8]) -> c_ulong {
	until_nul(s).iter().fold(0, |hash: c_ulong, &c| {
		let c = c as c_char as i64 as c_ulong;
		c.wrapping_add(hash.wrapping_mul(65599))
	})
}

// _alpm_strtoofft: bare decimal digits only, no sign or whitespace
pub fn strtoofft(s: &[u8]) -> Option<u64> {
	let s = until_nul(s);
	if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
		return None;
	}
	s.iter().try_fold(0u64, |acc, &c| {
		acc.checked_mul(10)?.checked_add(u64::from(c - b'0'))
	})
}

// _alpm_parsedate: strtoll base 10 in the C locale, whole string must parse
pub fn parsedate(s: &[u8]) -> Option<i64> {
	let s = until_nul(s);
	// isspace in the C locale
	let ws =
		s.iter().take_while(|c| {
			matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
		})
		.count();
	let s = &s[ws..];
	let (neg, digits) = match s.first() {
		Some(b'-') => (true, &s[1..]),
		Some(b'+') => (false, &s[1..]),
		_ => (false, s),
	};
	if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
		return None;
	}
	// accumulate negative so i64::MIN parses without overflow
	let n = digits.iter().try_fold(0i64, |acc, &c| {
		acc.checked_mul(10)?.checked_sub(i64::from(c - b'0'))
	})?;
	if neg { Some(n) } else { n.checked_neg() }
}

// _alpm_splitname: "name-ver-rel[/anything]" split at the second-last '-'
// before the first '/', name must not be empty
pub fn splitname(target: &[u8]) -> Option<(&[u8], &[u8])> {
	let target = until_nul(target);
	let end = target
		.iter()
		.position(|&c| c == b'/')
		.unwrap_or(target.len());
	let head = &target[..end];
	let rel = head.iter().rposition(|&c| c == b'-')?;
	let ver = head[..rel].iter().rposition(|&c| c == b'-')?;
	if ver == 0 {
		return None;
	}
	Some((&head[..ver], &head[ver + 1..]))
}

// _alpm_fnmatch: glibc fnmatch(3) with flags 0 in the C locale (byte
// based, MB_CUR_MAX 1, no collation rules). '*' and '?' match '/' and a
// leading '.', backslash escapes, ranges compare byte values. '^' negates
// like '!' (POSIXLY_CORRECT unset, as glibc decides per process).
pub fn fnmatch(pattern: &[u8], string: &[u8]) -> bool {
	let (p, s) = (until_nul(pattern), until_nul(string));
	matches!(fnmatch_at(p, 0, s, 0, false), Fnm::Match)
}

// _alpm_fnmatch_patterns: last matching pattern wins, a leading '!'
// inverts it, a leading '\' is dropped so "\!x" matches "!x".
// None: nothing matched (C -1), Some(inverted) (C 0 or 1)
pub fn fnmatch_patterns<P: AsRef<[u8]>>(
	patterns: &[P],
	string: &[u8],
) -> Option<bool> {
	patterns.iter().rev().find_map(|pat| {
		let pat = until_nul(pat.as_ref());
		let inverted = pat.first() == Some(&b'!');
		let pat = match pat.first() {
			Some(b'!' | b'\\') => &pat[1..],
			_ => pat,
		};
		fnmatch(pat, string).then_some(inverted)
	})
}

// glibc CHAR_CLASS_MAX_LENGTH, CHARCLASS_NAME_MAX
const CHAR_CLASS_MAX: usize = 2048;

enum Fnm {
	Match,
	NoMatch,
	// nested call reached a '*' at (pattern, string): the caller commits
	// to this position, a later '*' covers whatever an earlier one could
	Star(usize, usize),
}

enum Bracket {
	// one byte consumed, pattern continues here
	Hit(usize),
	// unterminated '[': matched as a literal, pattern continues after it
	Literal,
	Fail,
}

// the C reads past the end as the terminating nul
fn at(p: &[u8], i: usize) -> u8 {
	p.get(i).copied().unwrap_or(0)
}

// glibc internal_fnmatch; nested is the `ends` pointer of a recursive call
fn fnmatch_at(
	p: &[u8],
	mut pi: usize,
	s: &[u8],
	mut ni: usize,
	nested: bool,
) -> Fnm {
	while pi < p.len() {
		let c = p[pi];
		pi += 1;
		match c {
			b'?' if ni == s.len() => return Fnm::NoMatch,
			b'?' => {}
			b'\\' => {
				// trailing backslash never matches
				let c = at(p, pi);
				if c == 0 || s.get(ni) != Some(&c) {
					return Fnm::NoMatch;
				}
				pi += 1;
			}
			b'*' if nested => return Fnm::Star(pi - 1, ni),
			b'*' => match star(p, pi, s, ni) {
				Fnm::Star(np, nn) => {
					(pi, ni) = (np, nn);
					continue;
				}
				r => return r,
			},
			b'[' => match bracket(p, pi, s.get(ni).copied()) {
				Bracket::Hit(next) => pi = next,
				Bracket::Literal
					if s.get(ni) == Some(&b'[') => {}
				_ => return Fnm::NoMatch,
			},
			_ if s.get(ni) != Some(&c) => return Fnm::NoMatch,
			_ => {}
		}
		ni += 1;
	}
	if ni == s.len() {
		Fnm::Match
	} else {
		Fnm::NoMatch
	}
}

// '*' at p[pi - 1]: runs of '*' and '?' collapse, then the rest is tried
// at each string position, Star hands the outer loop where to resume
fn star(p: &[u8], mut pi: usize, s: &[u8], mut ni: usize) -> Fnm {
	let mut c = at(p, pi);
	while c == b'?' || c == b'*' {
		if c == b'?' {
			if ni == s.len() {
				return Fnm::NoMatch;
			}
			ni += 1;
		}
		pi += 1;
		c = at(p, pi);
	}
	if c == 0 {
		return Fnm::Match;
	}
	// a literal first byte filters candidate positions, a bracket tries all
	let lit = match c {
		b'[' => None,
		b'\\' => Some(at(p, pi + 1)),
		_ => Some(c),
	};
	for n in ni..s.len() {
		if lit.is_some_and(|l| s[n] != l) {
			continue;
		}
		match fnmatch_at(p, pi, s, n, true) {
			Fnm::NoMatch => {}
			r => return r,
		}
	}
	Fnm::NoMatch
}

// C locale ctype classes known to wctype(3)
fn char_class(name: &[u8]) -> Option<fn(&u8) -> bool> {
	Some(match name {
		b"alnum" => u8::is_ascii_alphanumeric,
		b"alpha" => u8::is_ascii_alphabetic,
		b"blank" => |c| matches!(c, b' ' | b'\t'),
		b"cntrl" => u8::is_ascii_control,
		b"digit" => u8::is_ascii_digit,
		b"graph" => u8::is_ascii_graphic,
		b"lower" => u8::is_ascii_lowercase,
		b"print" => |c| c.is_ascii_graphic() || *c == b' ',
		b"punct" => u8::is_ascii_punctuation,
		// isspace includes '\v', is_ascii_whitespace does not
		b"space" => |c| c.is_ascii_whitespace() || *c == 0x0b,
		b"upper" => u8::is_ascii_uppercase,
		b"xdigit" => u8::is_ascii_hexdigit,
		_ => return None,
	})
}

// "[.x.]" starting at p[pi] == '.': the end of it and its single byte,
// None if unterminated or not one byte (no collating names in C locale)
fn collating(p: &[u8], mut pi: usize) -> Option<(usize, u8)> {
	let start = pi;
	loop {
		pi += 1;
		let c = at(p, pi);
		if c == b'.' && at(p, pi + 1) == b']' {
			break;
		}
		if c == 0 {
			return None;
		}
	}
	(pi - start == 2).then(|| (pi + 2, p[start + 1]))
}

// one bracket expression, pi is just past '['. a matching item jumps to
// the skip of the rest; the item that starts with ']' is a literal
fn bracket(p: &[u8], mut pi: usize, ch: Option<u8>) -> Bracket {
	let Some(fc) = ch else {
		return Bracket::Fail;
	};
	let not = matches!(at(p, pi), b'!' | b'^');
	if not {
		pi += 1;
	}
	let mut c = at(p, pi);
	pi += 1;
	loop {
		// start byte of a possible range and whether it came from [.x.]
		let mut item = None;
		if c == b'\\' {
			c = at(p, pi);
			if c == 0 {
				return Bracket::Fail;
			}
			pi += 1;
			item = Some((c, false));
		} else if c == b'[' && at(p, pi) == b':' {
			match class_item(p, pi, fc) {
				Item::Matched(next) => {
					return skip(p, next, not);
				}
				Item::Next(next) => {
					c = at(p, next);
					pi = next + 1;
				}
				Item::Normal => item = Some((b'[', false)),
				Item::Fail => return Bracket::Fail,
			}
		} else if c == b'[' && at(p, pi) == b'=' {
			let (e, close) = (at(p, pi + 1), at(p, pi + 2));
			if e == 0 || close != b'=' || at(p, pi + 3) != b']' {
				item = Some((b'[', false));
			} else if fc == e {
				return skip(p, pi + 4, not);
			} else {
				c = at(p, pi + 4);
				pi += 5;
			}
		} else if c == 0 {
			return Bracket::Literal;
		} else if c == b'[' && at(p, pi) == b'.' {
			let Some((next, b)) = collating(p, pi) else {
				return Bracket::Fail;
			};
			pi = next;
			item = Some((b, true));
		} else {
			item = Some((c, false));
		}
		if let Some((cold, seq)) = item {
			// a range needs '-' and an end byte; a plain start also
			// refuses ']' as end, [.x.] does not
			let dash = at(p, pi) == b'-' && at(p, pi + 1) != 0;
			let is_range = dash && (seq || at(p, pi + 1) != b']');
			if !is_range && cold == fc {
				return skip(p, pi, not);
			}
			c = at(p, pi);
			pi += 1;
			if c == b'-' && at(p, pi) != b']' {
				let mut cend = at(p, pi);
				pi += 1;
				if cend == b'[' && at(p, pi) == b'.' {
					let Some((next, b)) = collating(p, pi)
					else {
						return Bracket::Fail;
					};
					(pi, cend) = (next, b);
				} else {
					if cend == b'\\' {
						cend = at(p, pi);
						pi += 1;
					}
					if cend == 0 {
						return Bracket::Fail;
					}
				}
				if cold <= fc && fc <= cend {
					return skip(p, pi, not);
				}
				c = at(p, pi);
				pi += 1;
			}
		}
		if c == b']' {
			break;
		}
	}
	if not { Bracket::Hit(pi) } else { Bracket::Fail }
}

enum Item {
	Matched(usize),
	// class did not match, next item starts here
	Next(usize),
	// not a class name, '[' is an ordinary byte
	Normal,
	Fail,
}

// "[:name:]" with p[pi] == ':'. names are 'a'..'y' only, as in glibc
fn class_item(p: &[u8], mut pi: usize, fc: u8) -> Item {
	let start = pi;
	loop {
		if pi - start == CHAR_CLASS_MAX {
			return Item::Fail;
		}
		pi += 1;
		let c = at(p, pi);
		if c == b':' && at(p, pi + 1) == b']' {
			break;
		}
		if !matches!(c, b'a'..=b'y') {
			return Item::Normal;
		}
	}
	match char_class(&p[start + 1..pi]) {
		None => Item::Fail,
		Some(f) if f(&fc) => Item::Matched(pi + 2),
		Some(_) => Item::Next(pi + 2),
	}
}

// rest of a bracket after a matching item, up to and past ']'. a missing
// ']' still makes '[' literal; a bad [=x=] fails here, where the item loop
// reads it as a plain '['
fn skip(p: &[u8], mut pi: usize, not: bool) -> Bracket {
	loop {
		let c = at(p, pi);
		pi += 1;
		match c {
			0 => return Bracket::Literal,
			b'\\' if at(p, pi) == 0 => return Bracket::Fail,
			b'\\' => pi += 1,
			b'[' if at(p, pi) == b':' => {
				let start = pi;
				let mut len = 0;
				loop {
					pi += 1;
					len += 1;
					if len == CHAR_CLASS_MAX {
						return Bracket::Fail;
					}
					let c = at(p, pi);
					if c == b':' && at(p, pi + 1) == b']' {
						break;
					}
					if !matches!(c, b'a'..=b'y') {
						break;
					}
				}
				if at(p, pi) == b':' && at(p, pi + 1) == b']' {
					pi += 2;
				} else {
					// rescan from the ':', bypassing the ']' test
					pi = start;
					continue;
				}
			}
			b'[' if at(p, pi) == b'=' => {
				if at(p, pi + 1) == 0
					|| at(p, pi + 2) != b'=' || at(p, pi + 3)
					!= b']'
				{
					return Bracket::Fail;
				}
				pi += 4;
			}
			b'[' if at(p, pi) == b'.' => {
				loop {
					pi += 1;
					let c = at(p, pi);
					if c == 0 {
						return Bracket::Fail;
					}
					if c == b'.' && at(p, pi + 1) == b']' {
						break;
					}
				}
				pi += 2;
			}
			b']' => break,
			_ => {}
		}
	}
	if not { Bracket::Fail } else { Bracket::Hit(pi) }
}

// C path from bytes, cut at the first nul
fn c_path(path: &[u8]) -> &Path {
	Path::new(OsStr::from_bytes(until_nul(path)))
}

// _alpm_makepath
pub fn makepath(path: &[u8]) -> io::Result<()> {
	makepath_mode(path, 0o755)
}

// _alpm_makepath_mode: mkdir -p. every prefix ending before a '/' that
// follows a non-'/' byte, then the whole path; EEXIST is fine at any step,
// even for a non-directory
pub fn makepath_mode(path: &[u8], mode: u32) -> io::Result<()> {
	let path = until_nul(path);
	for i in 1..path.len() {
		if path[i] == b'/' && path[i - 1] != b'/' {
			mkdir_exact(&path[..i], mode)?;
		}
	}
	mkdir_exact(path, mode)
}

// the C runs mkdir under umask(0), which is process wide. chmod after
// mkdir gives the same bits: mkdir keeps mode & 01777 and the setgid bit
// inherited from the parent
fn mkdir_exact(path: &[u8], mode: u32) -> io::Result<()> {
	let path = c_path(path);
	match DirBuilder::new().mode(mode).create(path) {
		Err(e) if e.kind() == ErrorKind::AlreadyExists => return Ok(()),
		r => r?,
	}
	let got = fs::metadata(path)?.permissions().mode();
	let want = (mode & 0o1777) | (got & 0o2000);
	if got & 0o7777 != want {
		fs::set_permissions(path, Permissions::from_mode(want))?;
	}
	Ok(())
}

// _alpm_copyfile: dest is opened even if src fails (created mode 0000),
// without O_TRUNC so a longer dest keeps its tail, then gets src's mode.
// a read error ends the copy like EOF and still counts as success
pub fn copyfile(src: &[u8], dest: &[u8]) -> io::Result<()> {
	let input = File::open(c_path(src));
	let output = OpenOptions::new()
		.write(true)
		.create(true)
		.truncate(false)
		.mode(0o000)
		.open(c_path(dest));
	let (mut input, mut output) = (input?, output?);
	let mode = input.metadata()?.permissions().mode();
	output.set_permissions(Permissions::from_mode(mode))?;
	let mut buf = vec![0; 8192];
	loop {
		match input.read(&mut buf) {
			Ok(0) => break,
			Ok(n) => output.write_all(&buf[..n])?,
			Err(e) if e.kind() == ErrorKind::Interrupted => {}
			Err(_) => break,
		}
	}
	Ok(())
}

// _alpm_read_file errors, the matching alpm_errno_t
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadFileError {
	// ALPM_ERR_NOT_A_FILE: open or fstat failed
	NotAFile,
	// ALPM_ERR_MEMORY: st_size bytes could not be allocated
	Memory,
	// ALPM_ERR_SYSTEM: fewer than st_size bytes read
	System,
}

// _alpm_read_file: exactly st_size bytes. an empty file is an error, as
// fread of one 0-byte item returns 0
pub fn read_file(path: &[u8]) -> Result<Vec<u8>, ReadFileError> {
	let f = File::open(c_path(path))
		.map_err(|_| ReadFileError::NotAFile)?;
	let size = f.metadata().map_err(|_| ReadFileError::NotAFile)?.len();
	let mut data = Vec::new();
	usize::try_from(size)
		.ok()
		.and_then(|n| data.try_reserve_exact(n).ok())
		.ok_or(ReadFileError::Memory)?;
	// a file grown since fstat is cut at st_size, like the one fread
	match f.take(size).read_to_end(&mut data) {
		Ok(n) if size != 0 && n as u64 == size => Ok(data),
		_ => Err(ReadFileError::System),
	}
}

// _alpm_files_in_directory without the handle, used for debug logging
// only. entries other than "." and "..", counting stops at the first
// unless full_count. a readdir error ends the count like end of directory
pub fn files_in_directory(path: &[u8], full_count: bool) -> io::Result<usize> {
	let entries = fs::read_dir(c_path(path))?.map_while(Result::ok);
	Ok(if full_count {
		entries.count()
	} else {
		entries.take(1).count()
	})
}

// md5_file/sha256_file + hex_representation through alpm-types (md-5,
// sha2), lowercase hex. None when the file cannot be opened or a read
// fails (EINTR retried like the C loop)
fn file_digest<D: alpm_types::digests::Digest>(path: &[u8]) -> Option<Vec<u8>> {
	let f = File::open(c_path(path)).ok()?;
	let sum = alpm_types::Checksum::<D>::calculate_from_reader(f).ok()?;
	Some(sum.to_string().into_bytes())
}

// alpm_compute_md5sum
pub fn compute_md5sum(path: &[u8]) -> Option<Vec<u8>> {
	file_digest::<alpm_types::digests::Md5>(path)
}

// alpm_compute_sha256sum
pub fn compute_sha256sum(path: &[u8]) -> Option<Vec<u8>> {
	file_digest::<alpm_types::digests::Sha256>(path)
}

// _alpm_test_checksum: kind is exactly PKG_VALIDATION_MD5SUM or
// PKG_VALIDATION_SHA256SUM. Some(true) matches (C 0), Some(false) differs
// (C 1), None for another kind, no expected value or no checksum (C -1).
// expected is compared like strcmp
pub fn test_checksum(
	path: &[u8],
	expected: Option<&[u8]>,
	kind: std::ffi::c_int,
) -> Option<bool> {
	use crate::package::{PKG_VALIDATION_MD5SUM, PKG_VALIDATION_SHA256SUM};
	let computed = match kind {
		PKG_VALIDATION_MD5SUM => compute_md5sum(path),
		PKG_VALIDATION_SHA256SUM => compute_sha256sum(path),
		_ => return None,
	};
	Some(until_nul(expected?) == computed?)
}

// llstat (src/common, linked into libalpm): lstat with trailing '/'
// stripped (not a lone "/"), so "dirsymlink/" describes the link
pub fn llstat(path: &[u8]) -> io::Result<fs::Metadata> {
	let path = until_nul(path);
	let slashes = path.iter().rev().take_while(|&&c| c == b'/').count();
	let len = (path.len() - slashes).max(1).min(path.len());
	fs::symlink_metadata(OsStr::from_bytes(&path[..len]))
}

// strerror(errno) of an io::Error: std formats "<strerror_r text> (os
// error N)". errors without errno as std prints them
pub fn strerror(e: &io::Error) -> Vec<u8> {
	let s = e.to_string();
	let Some(n) = e.raw_os_error() else {
		return s.into_bytes();
	};
	let suffix = format!(" (os error {n})");
	s.strip_suffix(&suffix).unwrap_or(&s).as_bytes().to_vec()
}

fn errno_text(e: rustix::io::Errno) -> Vec<u8> {
	strerror(&io::Error::from(e))
}

// snprintf(buf, PATH_MAX, "%s%s", a, b): cut to PATH_MAX - 1 bytes
fn join_path(a: &[u8], b: &[u8]) -> Vec<u8> {
	let mut p = [until_nul(a), until_nul(b)].concat();
	p.truncate(PATH_MAX - 1);
	p
}

// access(2), symlinks followed
fn access(path: &[u8], mode: Access) -> Result<(), rustix::io::Errno> {
	accessat(CWD, c_path(path), mode, AtFlags::empty())
}

// meson options scriptlet-shell and ldconfig, as in config.h
pub const SCRIPTLET_SHELL: &[u8] = b"/bin/sh";
pub const LDCONFIG: &[u8] = b"/sbin/ldconfig";

// ALPM_CALLER_PREFIX, the alpm_logaction prefix of libalpm itself
pub const CALLER_PREFIX: &[u8] = b"ALPM";

// coreutils chroot(8) does the C child's chroot() + chdir("/") + exec
// (METHODOLOGY.md): no pre_exec, and it works under fakechroot
const CHROOT: &str = "/usr/bin/chroot";

// limits.h on linux
const PATH_MAX: usize = 4096;
const LINE_MAX: usize = 2048;

// what _alpm_run_chroot reports through the handle: _alpm_log,
// alpm_logaction and ALPM_EVENT_SCRIPTLET_INFO. messages are formatted
// msgids (no gettext)
pub trait ChrootCb {
	fn log(&mut self, level: LogLevel, msg: &[u8]);
	fn logaction(&mut self, prefix: &[u8], msg: &[u8]);
	fn scriptlet_info(&mut self, line: &[u8]);
}

fn logv(cb: &mut impl ChrootCb, level: LogLevel, parts: &[&[u8]]) {
	cb.log(level, &parts.concat());
}

// _alpm_chroot_process_output: the line goes out as a C string, so a nul
// cuts it (and its '\n')
fn process_output(cb: &mut impl ChrootCb, line: &[u8]) {
	let line = until_nul(line);
	cb.logaction(b"ALPM-SCRIPTLET", line);
	cb.scriptlet_info(line);
}

// glibc strsignal, C locale. 32 and 33 are taken by nptl, SIGRTMIN is 34
fn strsignal(sig: i32) -> Vec<u8> {
	const NAMES: [&str; 31] = [
		"Hangup",
		"Interrupt",
		"Quit",
		"Illegal instruction",
		"Trace/breakpoint trap",
		"Aborted",
		"Bus error",
		"Floating point exception",
		"Killed",
		"User defined signal 1",
		"Segmentation fault",
		"User defined signal 2",
		"Broken pipe",
		"Alarm clock",
		"Terminated",
		"Stack fault",
		"Child exited",
		"Continued",
		"Stopped (signal)",
		"Stopped",
		"Stopped (tty input)",
		"Stopped (tty output)",
		"Urgent I/O condition",
		"CPU time limit exceeded",
		"File size limit exceeded",
		"Virtual timer expired",
		"Profiling timer expired",
		"Window changed",
		"I/O possible",
		"Power failure",
		"Bad system call",
	];
	let s = match sig {
		1..=31 => NAMES[sig as usize - 1].to_string(),
		34..=64 => format!("Real-time signal {}", sig - 34),
		_ => format!("Unknown signal {sig}"),
	};
	s.into_bytes()
}

// the child's output as _alpm_chroot_read_from_child splits it: a line
// goes out at its '\n', or with a '\n' appended once LINE_MAX - 2 bytes
// sit without one (the C reads at most the free space, so the cut does
// not depend on how reads arrive).
//
// chroot(8) reports its own failures where the C child prints them: a
// first line from it is held until the exit status says whether it was
// chroot(8)'s, then reworded as the C child's
struct Output {
	buf: Vec<u8>,
	lines: usize,
	held: Option<Vec<u8>>,
	chroot: bool,
}

impl Output {
	fn new(chroot: bool) -> Self {
		Output {
			buf: Vec::new(),
			lines: 0,
			held: None,
			chroot,
		}
	}

	fn line(&mut self, cb: &mut impl ChrootCb, line: &[u8]) {
		if self.chroot
			&& self.lines == 0 && line.starts_with(b"chroot: ")
		{
			self.held = Some(line.to_vec());
		} else {
			if let Some(h) = self.held.take() {
				process_output(cb, &h);
			}
			process_output(cb, line);
		}
		self.lines += 1;
	}

	fn feed(&mut self, cb: &mut impl ChrootCb, data: &[u8]) {
		for &c in data {
			self.buf.push(c);
			if c == b'\n' {
				let line = std::mem::take(&mut self.buf);
				self.line(cb, &line);
			} else if self.buf.len() == LINE_MAX - 2 {
				let mut line = std::mem::take(&mut self.buf);
				line.push(b'\n');
				self.line(cb, &line);
			}
		}
	}

	// end of file or a read error: an unterminated tail goes out twice,
	// once by the read and once by the C's leftover flush after the poll
	// loop (the read does not reset ilen)
	fn finish(&mut self, cb: &mut impl ChrootCb) {
		if !self.buf.is_empty() {
			let mut line = std::mem::take(&mut self.buf);
			line.push(b'\n');
			self.line(cb, &line);
			self.line(cb, &line);
		}
	}

	// after the exit status: chroot(8) exits 125 when chroot() fails,
	// 126/127 when the exec does, after one "chroot: ...: <strerror>"
	// line. other first lines go out as they were
	fn release(&mut self, cb: &mut impl ChrootCb, code: Option<i32>) {
		let Some(h) = self.held.take() else {
			return;
		};
		let what: &[u8] = match code {
			Some(125) => {
				b"chroot: cannot change root directory to "
			}
			Some(126 | 127) => b"chroot: failed to run command ",
			_ => b"",
		};
		let c_text: &[u8] = match code {
			Some(125) => b"could not change the root directory (",
			_ => b"call to execv failed (",
		};
		let err = h.strip_suffix(b"\n").and_then(|l| {
			let i = l.windows(2).rposition(|w| w == b": ")?;
			Some(&l[i + 2..])
		});
		match err {
			Some(e) if self.lines == 1
				&& !what.is_empty() && h
				.starts_with(what) =>
			{
				process_output(
					cb,
					&[c_text, e, b")\n"].concat(),
				)
			}
			_ => process_output(cb, &h),
		}
	}
}

// chdir(2) of the C parent: ENOENT/ENOTDIR/EACCES as chdir reports them
fn can_chdir(dir: &[u8]) -> Result<(), Vec<u8>> {
	match fs::metadata(c_path(dir)) {
		Err(e) => Err(strerror(&e)),
		Ok(m) if !m.is_dir() => {
			Err(errno_text(rustix::io::Errno::NOTDIR))
		}
		Ok(_) => access(dir, Access::EXEC_OK).map_err(errno_text),
	}
}

// a cmd without '/' is execv'd relative to the cwd ("/"), chroot(8) and
// std would search PATH
fn exec_path(cmd: &[u8]) -> Vec<u8> {
	match cmd.contains(&b'/') {
		true => cmd.to_vec(),
		false => [b"./", cmd].concat(),
	}
}

// the child of _alpm_run_chroot: stdout and stderr on one socket, stdin
// on another, SHLVL defaulted to 1 and BASH_ENV dropped. root "/" runs
// cmd directly like the C (no chroot); otherwise chroot(8) execs it,
// which sets argv[0] to cmd. std resets SIGPIPE and the signal mask in
// the child, the C's _alpm_reset_signals; other ignored signals stay.
// umask(0022) is not set: it needs rustix's process feature
fn command(root: &[u8], cmd: &[u8], argv: &[&[u8]]) -> Command {
	let os = |s: &[u8]| OsStr::from_bytes(until_nul(s)).to_os_string();
	let path = os(&exec_path(cmd));
	let args = argv.get(1..).unwrap_or_default().iter().map(|a| os(a));
	let mut c = if root == b"/" {
		let mut c = Command::new(path);
		if let Some(arg0) = argv.first() {
			c.arg0(os(arg0));
		}
		c.current_dir("/");
		c
	} else {
		let mut c = Command::new(CHROOT);
		c.arg(os(root)).arg(path).current_dir(os(root));
		c
	};
	c.args(args);
	if std::env::var_os("SHLVL").is_none() {
		c.env("SHLVL", "1");
	}
	c.env_remove("BASH_ENV");
	c
}

// the C parent's poll loop on the child's output, until end of file or
// a read error
fn read_output(cb: &mut impl ChrootCb, mut from: UnixStream, out: &mut Output) {
	let mut buf = [0; LINE_MAX];
	loop {
		match from.read(&mut buf) {
			Ok(0) => break,
			Ok(n) => out.feed(cb, &buf[..n]),
			Err(e) if e.kind() == ErrorKind::Interrupted => {}
			Err(e) => {
				out.finish(cb);
				logv(
					cb,
					LogLevel::Error,
					&[
						b"unable to read from pipe (",
						&strerror(&e),
						b")\n",
					],
				);
				return;
			}
		}
	}
	out.finish(cb);
}

// non-blocking writes of data until the socket is full, back to blocking
// after; what is left to write
fn prefill<'a>(to: &mut UnixStream, data: &'a [u8]) -> io::Result<&'a [u8]> {
	to.set_nonblocking(true)?;
	let mut rest = data;
	while !rest.is_empty() {
		match to.write(rest) {
			Ok(n) => rest = &rest[n..],
			Err(e) if e.kind() == ErrorKind::Interrupted => {}
			Err(e) if e.kind() == ErrorKind::WouldBlock => break,
			Err(e) => return Err(e),
		}
	}
	to.set_nonblocking(false)?;
	Ok(rest)
}

// the exit status as the C parent reads it from waitpid
fn report_status(
	cb: &mut impl ChrootCb,
	code: Option<i32>,
	signal: Option<i32>,
) -> bool {
	if let Some(code) = code {
		cb.log(LogLevel::Debug, b"call to waitpid succeeded\n");
		if code != 0 {
			cb.log(
				LogLevel::Error,
				b"command failed to execute correctly\n",
			);
			return false;
		}
		return true;
	}
	let Some(sig) = signal else {
		return true;
	};
	let msg = format!("command terminated by signal {sig}: ");
	logv(
		cb,
		LogLevel::Error,
		&[msg.as_bytes(), &strsignal(sig), b"\n"],
	);
	false
}

// _alpm_run_chroot: cmd with argv under root (with its trailing '/'),
// stdin fed from the bytes the C's stdin_cb would hand out in turn.
// every output line goes through process_output. true when the command
// exited 0 (C 0). root that cannot be entered logs and counts as success
// like the C. cmd None is the C's NULL (an empty hook Exec): its execv
// fails with EFAULT
pub fn run_chroot(
	root: &[u8],
	cmd: Option<&[u8]>,
	argv: &[&[u8]],
	stdin: Option<&[u8]>,
	cb: &mut impl ChrootCb,
) -> bool {
	let root = until_nul(root);
	if let Err(e) = can_chdir(root) {
		logv(
			cb,
			LogLevel::Error,
			&[
				b"could not change directory to ",
				root,
				b" (",
				&e,
				b")\n",
			],
		);
		return true;
	}
	let shown = cmd.map_or(&b"(null)"[..], until_nul);
	logv(
		cb,
		LogLevel::Debug,
		&[b"executing \"", shown, b"\" under chroot \"", root, b"\"\n"],
	);
	let Some(cmd) = cmd else {
		let e = errno_text(rustix::io::Errno::FAULT);
		process_output(
			cb,
			&[b"call to execv failed (", &e[..], b")\n"].concat(),
		);
		return report_status(cb, Some(1), None);
	};

	let pipes = UnixStream::pair().and_then(|out| {
		let input = UnixStream::pair()?;
		let err = out.1.try_clone()?;
		Ok((out, input, err))
	});
	let ((from, out_end), (to, in_end), err_end) = match pipes {
		Ok(p) => p,
		Err(e) => {
			logv(
				cb,
				LogLevel::Error,
				&[
					b"could not create pipe (",
					&strerror(&e),
					b")\n",
				],
			);
			return false;
		}
	};
	// the C parent sends while its child still starts up; what fits in
	// the socket buffer goes in before the spawn, so a child failing
	// fast does not leave it unwritten (EPIPE)
	let mut to = to;
	let rest = match stdin.map(|data| prefill(&mut to, data)) {
		Some(Err(e)) => {
			logv(
				cb,
				LogLevel::Error,
				&[
					b"unable to write to pipe (",
					&strerror(&e),
					b")\n",
				],
			);
			None
		}
		Some(Ok(rest)) => Some(rest),
		None => None,
	};
	let mut c = command(root, cmd, argv);
	c.stdin(Stdio::from(OwnedFd::from(in_end)))
		.stdout(Stdio::from(OwnedFd::from(out_end)))
		.stderr(Stdio::from(OwnedFd::from(err_end)));
	let spawned = c.spawn();
	// the child's ends close with the Command
	drop(c);
	let mut child = match spawned {
		Ok(child) => child,
		// root "/": the exec of cmd itself failed, the C child prints
		// that and exits 1
		Err(e) if root == b"/" => {
			let e = strerror(&e);
			process_output(
				cb,
				&[b"call to execv failed (", &e[..], b")\n"]
					.concat(),
			);
			return report_status(cb, Some(1), None);
		}
		Err(e) => {
			logv(
				cb,
				LogLevel::Error,
				&[
					b"could not fork a new process (",
					&strerror(&e),
					b")\n",
				],
			);
			return false;
		}
	};

	let mut out = Output::new(root != b"/");
	let write_err = std::thread::scope(|s| {
		let writer = s.spawn(move || {
			let mut to = to;
			rest.map_or(Ok(()), |data| to.write_all(data))
		});
		read_output(cb, from, &mut out);
		writer.join().expect("stdin writer panicked")
	});
	if let Err(e) = write_err {
		logv(
			cb,
			LogLevel::Error,
			&[b"unable to write to pipe (", &strerror(&e), b")\n"],
		);
	}

	let status =
		loop {
			match child.wait() {
				Err(e) if e.kind()
					== ErrorKind::Interrupted => {}
				Err(e) => {
					logv(cb, LogLevel::Error, &[
					b"call to waitpid failed (",
					&strerror(&e),
					b")\n",
				]);
					out.release(cb, None);
					return false;
				}
				Ok(st) => break st,
			}
		};
	out.release(cb, status.code());
	report_status(cb, status.code(), status.signal())
}

// _alpm_ldconfig: LDCONFIG under root when root has etc/ld.so.conf and
// an executable root + LDCONFIG (the C's "%s%s" keeps the double '/').
// true when not run (C 0). argv[0] is "ldconfig" in the C, chroot(8)
// passes LDCONFIG
pub fn ldconfig(root: &[u8], cb: &mut impl ChrootCb) -> bool {
	cb.log(LogLevel::Debug, b"running ldconfig\n");
	let conf = join_path(root, b"etc/ld.so.conf");
	if access(&conf, Access::EXISTS).is_ok()
		&& access(&join_path(root, LDCONFIG), Access::EXEC_OK).is_ok()
	{
		return run_chroot(
			root,
			Some(LDCONFIG),
			&[b"ldconfig"],
			None,
			cb,
		);
	}
	true
}

// _alpm_unpack_single for what _alpm_runscriptlet needs: the first entry
// of archive whose name up to its first '/' (kept) is filename,
// extracted below prefix. regular files get 0644, directories 0755;
// other entry types are refused (libarchive would extract them). true
// on success (C 0); no matching entry is a success. libarchive's
// open/extract error texts are the port's
pub fn unpack_single(
	archive: &[u8],
	prefix: &[u8],
	filename: &[u8],
	cb: &mut impl ChrootCb,
) -> bool {
	let (archive, prefix) = (until_nul(archive), until_nul(prefix));
	logv(cb, LogLevel::Debug, &[b"opening archive ", archive, b"\n"]);
	let reader = File::open(c_path(archive)).and_then(|mut f| {
		let mut magic =
			Vec::with_capacity(DecompressionSettings::MAGIC_LEN);
		let len = DecompressionSettings::MAGIC_LEN as u64;
		(&mut f).take(len).read_to_end(&mut magic)?;
		io::Seek::rewind(&mut f)?;
		let settings = DecompressionSettings::from_magic(&magic);
		CompressionDecoder::new(f, settings).map_err(io::Error::other)
	});
	let mut reader = match reader {
		Ok(d) => TarballReader::new(d),
		Err(e) => {
			logv(
				cb,
				LogLevel::Error,
				&[
					b"could not open file ",
					archive,
					b": ",
					&strerror(&e),
					b"\n",
				],
			);
			return false;
		}
	};
	if let Err(e) = can_chdir(prefix) {
		logv(
			cb,
			LogLevel::Error,
			&[
				b"could not change directory to ",
				prefix,
				b" (",
				&e,
				b")\n",
			],
		);
		return false;
	}
	let Ok(entries) = reader.entries() else {
		return true;
	};
	let filename = until_nul(filename);
	// a header error ends the walk like archive_read_next_header's
	// non-OK, which the C takes as the end
	for mut entry in entries.map_while(Result::ok) {
		let name = entry.path().as_os_str().as_bytes().to_vec();
		let head = match name.iter().position(|&c| c == b'/') {
			Some(i) => &name[..=i],
			None => &name[..],
		};
		if head != filename {
			continue;
		}
		logv(cb, LogLevel::Debug, &[b"extracting: ", &name, b"\n"]);
		let dest = [prefix, b"/", &name].concat();
		let done = if entry.is_dir() {
			DirBuilder::new().mode(0o755).create(c_path(&dest))
		} else if entry.is_file() {
			entry.content().map_err(io::Error::other).and_then(
				|data| {
					OpenOptions::new()
						.write(true)
						.create(true)
						.truncate(true)
						.mode(0o644)
						.open(c_path(&dest))?
						.write_all(&data)
				},
			)
		} else {
			Err(io::Error::other("unsupported entry type"))
		};
		if let Err(e) = done {
			logv(
				cb,
				LogLevel::Error,
				&[
					b"could not extract ",
					&name,
					b" (",
					&strerror(&e),
					b")\n",
				],
			);
			return false;
		}
		break;
	}
	true
}

// _alpm_filecache_find: "<cachedir><filename>" of the first cachedir
// holding it as a regular file
pub fn filecache_find(
	cachedirs: &[Vec<u8>],
	filename: &[u8],
	cb: &mut dyn Callbacks,
) -> Option<Vec<u8>> {
	for dir in cachedirs {
		let mut p = [dir, until_nul(filename)].concat();
		// snprintf into char[PATH_MAX]
		p.truncate(PATH_MAX - 1);
		match fs::metadata(c_path(&p)) {
			Ok(md) if md.is_file() => return Some(p),
			Ok(md) => {
				let m = format!(": mode={}\n", md.mode());
				let m = [
					b"cached pkg '",
					&p[..],
					b"' is not a regular file",
					m.as_bytes(),
				];
				cb.log(LogLevel::Warning, &m.concat());
			}
			Err(e) if e.raw_os_error() != Some(2) => {
				let m = [
					b"could not open '",
					&p[..],
					b"'\n: ",
					&strerror(&e),
				];
				cb.log(LogLevel::Warning, &m.concat());
			}
			Err(_) => {}
		}
	}
	None
}

// _alpm_filecache_exists
pub fn filecache_exists(
	cachedirs: &[Vec<u8>],
	filename: &[u8],
	cb: &mut dyn Callbacks,
) -> bool {
	filecache_find(cachedirs, filename, cb).is_some()
}

// _alpm_filecache_setup: the first cachedir that exists (or can be made)
// and is a writable directory with a write bit. without one, "/tmp/" is
// added to the cachedirs and used. the C takes TMPDIR instead only when
// stat(TMPDIR) fails and the last cachedir it stat'ed was a directory
pub fn filecache_setup(
	cachedirs: &mut Vec<Vec<u8>>,
	cb: &mut dyn Callbacks,
) -> Vec<u8> {
	let mut last_dir = None;
	for dir in cachedirs.iter() {
		let md = match fs::metadata(c_path(dir)) {
			Err(_) => {
				let m = [
					b"no ",
					&dir[..],
					b" cache exists, creating...\n",
				];
				cb.log(LogLevel::Warning, &m.concat());
				if makepath(dir).is_ok() {
					return dir.clone();
				}
				continue;
			}
			Ok(md) => md,
		};
		last_dir = Some(md.is_dir());
		let writable = rustix::fs::accessat(
			rustix::fs::CWD,
			c_path(dir),
			rustix::fs::Access::WRITE_OK,
			rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
		)
		.is_ok();
		if md.is_dir() && writable && md.mode() & 0o222 != 0 {
			return dir.clone();
		}
	}
	let tmpdir = std::env::var_os("TMPDIR").map(|t| t.as_bytes().to_vec());
	let tmpdir = match tmpdir {
		Some(t) if fs::metadata(c_path(&t)).is_err()
			&& last_dir == Some(true) =>
		{
			t
		}
		_ => b"/tmp".to_vec(),
	};
	// alpm_option_add_cachedir's canonicalize_path
	let mut dir = tmpdir;
	if dir.last() != Some(&b'/') {
		dir.push(b'/');
	}
	cachedirs.push(dir.clone());
	let m = [
		b"couldn't find or create package cache, using ",
		&dir[..],
		b" instead\n",
	];
	cb.log(LogLevel::Warning, &m.concat());
	dir
}
