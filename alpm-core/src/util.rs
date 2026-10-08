// port of lib/libalpm/util.c, filled in as callers get ported
//
// inputs are byte strings as the C would see them, cut at the first nul.
// _alpm_str_cmp is not ported: byte slices already order like strcmp.
// _alpm_realloc, _alpm_greedy_grow, _alpm_alloc_fail are not ported: Vec
// grows and zero-fills itself.

use std::cell::Cell;
use std::ffi::{OsStr, OsString, c_char, c_ulong};
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, BufRead, BufReader, Cursor, ErrorKind, Read, Seek, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{
	DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink,
};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::rc::Rc;

use alpm_compress::decompression::{CompressionDecoder, DecompressionSettings};
use rustix::fs::{
	Access, AtFlags, CWD, FileType, Mode, accessat, makedev, mknodat,
};

use crate::be_package::tar_mode_size;
use crate::callbacks::{Callbacks, Event, LogLevel, logv};
use crate::error::Errno;
use crate::handle::Handle;

pub use pacman_common::util_common::{PATH_MAX, llstat};

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
pub(crate) fn c_path(path: &[u8]) -> &Path {
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

fn mkdir_exact(path: &[u8], mode: u32) -> io::Result<()> {
	match mkdir_mode(c_path(path), mode) {
		Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(()),
		r => r,
	}
}

// mkdir(path, mode) as the C runs it under a fixed umask, which is
// process wide: mode is the umask-applied value. chmod after mkdir gives
// the same bits: mkdir keeps mode & 01777 and the setgid bit inherited
// from the parent
pub(crate) fn mkdir_mode(path: &Path, mode: u32) -> io::Result<()> {
	DirBuilder::new().mode(mode).create(path)?;
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

// _alpm_access: faccessat of dir and file joined (dir None is the C's
// NULL), a last symlink not followed, a debug line per refused mode bit
pub fn alpm_access(
	cb: &mut dyn Callbacks,
	dir: Option<&[u8]>,
	file: &[u8],
	mode: Access,
) -> Result<(), rustix::io::Errno> {
	let dir = until_nul(dir.unwrap_or_default());
	let path = [dir, until_nul(file)].concat();
	let flags = AtFlags::SYMLINK_NOFOLLOW;
	let Err(e) = accessat(CWD, c_path(&path), mode, flags) else {
		return Ok(());
	};
	let text = errno_text(e);
	let refused: [(bool, &[u8]); 4] = [
		(mode.contains(Access::READ_OK), b"\" is not readable: "),
		(mode.contains(Access::WRITE_OK), b"\" is not writable: "),
		(mode.contains(Access::EXEC_OK), b"\" is not executable: "),
		(mode == Access::EXISTS, b"\" does not exist: "),
	];
	for (_, what) in refused.into_iter().filter(|r| r.0) {
		let msg = [b"\"", &path[..], what, &text, b"\n"].concat();
		cb.log(LogLevel::Debug, &msg);
	}
	Err(e)
}

// access(2), symlinks followed
fn access(path: &[u8], mode: Access) -> Result<(), rustix::io::Errno> {
	accessat(CWD, c_path(path), mode, AtFlags::empty())
}

// getuid(2), geteuid(2) through libc (rustix use-libc): under fakeroot
// its LD_PRELOAD answers with the faked ids, as it does for the C. a raw
// syscall (rustix's default backend, /proc/self/status) shows the real
// ones
pub fn getuid() -> u32 {
	rustix::process::getuid().as_raw()
}

pub fn geteuid() -> u32 {
	rustix::process::geteuid().as_raw()
}

// meson options scriptlet-shell and ldconfig, as in config.h
pub const SCRIPTLET_SHELL: &[u8] = b"/bin/sh";
pub const LDCONFIG: &[u8] = b"/sbin/ldconfig";

// ALPM_CALLER_PREFIX, the alpm_logaction prefix of libalpm itself
pub const CALLER_PREFIX: &[u8] = b"ALPM";

// coreutils chroot(8) does the C child's chroot() + chdir("/") + exec
// (METHODOLOGY.md): no pre_exec, and it works under fakechroot
const CHROOT: &str = "/usr/bin/chroot";

const LINE_MAX: usize = 2048;

// _alpm_chroot_process_output: the line goes out as a C string, so a nul
// cuts it (and its '\n'). alpm_logaction's result is not checked
fn process_output(h: &mut Handle, line: &[u8]) {
	let line = until_nul(line);
	let _ = h.logaction(b"ALPM-SCRIPTLET", line);
	h.callbacks().event(&Event::ScriptletInfo { line });
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

	fn line(&mut self, h: &mut Handle, line: &[u8]) {
		if self.chroot
			&& self.lines == 0 && line.starts_with(b"chroot: ")
		{
			self.held = Some(line.to_vec());
		} else {
			if let Some(held) = self.held.take() {
				process_output(h, &held);
			}
			process_output(h, line);
		}
		self.lines += 1;
	}

	fn feed(&mut self, h: &mut Handle, data: &[u8]) {
		for &c in data {
			self.buf.push(c);
			if c == b'\n' {
				let line = std::mem::take(&mut self.buf);
				self.line(h, &line);
			} else if self.buf.len() == LINE_MAX - 2 {
				let mut line = std::mem::take(&mut self.buf);
				line.push(b'\n');
				self.line(h, &line);
			}
		}
	}

	// end of file or a read error: an unterminated tail goes out twice,
	// once by the read and once by the C's leftover flush after the poll
	// loop (the read does not reset ilen)
	fn finish(&mut self, h: &mut Handle) {
		if !self.buf.is_empty() {
			let mut line = std::mem::take(&mut self.buf);
			line.push(b'\n');
			self.line(h, &line);
			self.line(h, &line);
		}
	}

	// after the exit status: chroot(8) exits 125 when chroot() fails,
	// 126/127 when the exec does, after one "chroot: ...: <strerror>"
	// line. other first lines go out as they were
	fn release(&mut self, h: &mut Handle, code: Option<i32>) {
		let Some(held) = self.held.take() else {
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
		let err = held.strip_suffix(b"\n").and_then(|l| {
			let i = l.windows(2).rposition(|w| w == b": ")?;
			Some(&l[i + 2..])
		});
		match err {
			Some(e) if self.lines == 1
				&& !what.is_empty() && held
				.starts_with(what) =>
			{
				process_output(h, &[c_text, e, b")\n"].concat())
			}
			_ => process_output(h, &held),
		}
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
// the child's umask(0022) is set around the spawn (run_chroot)
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
fn read_output(h: &mut Handle, mut from: UnixStream, out: &mut Output) {
	let mut buf = [0; LINE_MAX];
	loop {
		match from.read(&mut buf) {
			Ok(0) => break,
			Ok(n) => out.feed(h, &buf[..n]),
			Err(e) if e.kind() == ErrorKind::Interrupted => {}
			Err(e) => {
				out.finish(h);
				logv(
					h.callbacks(),
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
	out.finish(h);
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
	h: &mut Handle,
	code: Option<i32>,
	signal: Option<i32>,
) -> bool {
	if let Some(code) = code {
		h.callbacks()
			.log(LogLevel::Debug, b"call to waitpid succeeded\n");
		if code != 0 {
			h.callbacks().log(
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
		h.callbacks(),
		LogLevel::Error,
		&[msg.as_bytes(), &strsignal(sig), b"\n"],
	);
	false
}

// _alpm_run_chroot: cmd with argv under handle->root (with its trailing
// '/'), stdin fed from the bytes the C's stdin_cb would hand out in turn.
// every output line goes through process_output. true when the command
// exited 0 (C 0). root that cannot be entered logs and counts as success
// like the C. cmd None is the C's NULL (an empty hook Exec): its execv
// fails with EFAULT
pub fn run_chroot(
	h: &mut Handle,
	cmd: Option<&[u8]>,
	argv: &[&[u8]],
	stdin: Option<&[u8]>,
) -> bool {
	// the callbacks borrow the handle mutably
	let root = h.root().to_vec();
	let root = &root[..];
	// chdir(2) of the C parent
	if let Err(e) = enter(root) {
		logv(
			h.callbacks(),
			LogLevel::Error,
			&[
				b"could not change directory to ",
				root,
				b" (",
				&strerror(&e),
				b")\n",
			],
		);
		return true;
	}
	let shown = cmd.map_or(&b"(null)"[..], until_nul);
	logv(
		h.callbacks(),
		LogLevel::Debug,
		&[b"executing \"", shown, b"\" under chroot \"", root, b"\"\n"],
	);
	let Some(cmd) = cmd else {
		let e = errno_text(rustix::io::Errno::FAULT);
		process_output(
			h,
			&[b"call to execv failed (", &e[..], b")\n"].concat(),
		);
		return report_status(h, Some(1), None);
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
				h.callbacks(),
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
				h.callbacks(),
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
	// the C child's umask(0022): inherited from here, the process mask
	// put back once the child exists
	let oldmask = rustix::process::umask(Mode::from_raw_mode(0o022));
	let spawned = c.spawn();
	rustix::process::umask(oldmask);
	// the child's ends close with the Command
	drop(c);
	let mut child = match spawned {
		Ok(child) => child,
		// root "/": the exec of cmd itself failed, the C child prints
		// that and exits 1
		Err(e) if root == b"/" => {
			let e = strerror(&e);
			process_output(
				h,
				&[b"call to execv failed (", &e[..], b")\n"]
					.concat(),
			);
			return report_status(h, Some(1), None);
		}
		Err(e) => {
			logv(
				h.callbacks(),
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
		read_output(h, from, &mut out);
		writer.join().expect("stdin writer panicked")
	});
	if let Err(e) = write_err {
		logv(
			h.callbacks(),
			LogLevel::Error,
			&[b"unable to write to pipe (", &strerror(&e), b")\n"],
		);
	}

	let status =
		loop {
			match child.wait() {
				Err(e) if e.kind()
					== ErrorKind::Interrupted =>
				{
					continue;
				}
				Err(e) => {
					logv(h.callbacks(), LogLevel::Error, &[
					b"call to waitpid failed (",
					&strerror(&e),
					b")\n",
				]);
					out.release(h, None);
					return false;
				}
				Ok(st) => break st,
			}
		};
	out.release(h, status.code());
	report_status(h, status.code(), status.signal())
}

// _alpm_ldconfig: LDCONFIG under root when root has etc/ld.so.conf and
// an executable root + LDCONFIG (the C's "%s%s" keeps the double '/').
// true when not run (C 0). argv[0] is "ldconfig" in the C, chroot(8)
// passes LDCONFIG
pub fn ldconfig(h: &mut Handle) -> bool {
	h.callbacks().log(LogLevel::Debug, b"running ldconfig\n");
	let conf = join_path(h.root(), b"etc/ld.so.conf");
	let exe = join_path(h.root(), LDCONFIG);
	if access(&conf, Access::EXISTS).is_ok()
		&& access(&exe, Access::EXEC_OK).is_ok()
	{
		return run_chroot(h, Some(LDCONFIG), &[b"ldconfig"], None);
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
	let using = |cb: &mut dyn Callbacks, dir: &[u8]| {
		let m = [b"using cachedir: ", dir, b"\n"].concat();
		cb.log(LogLevel::Debug, &m);
	};
	let skipping = |cb: &mut dyn Callbacks, why: &[u8], dir: &[u8]| {
		let m = [b"skipping cachedir, ", why, b": ", dir, b"\n"];
		cb.log(LogLevel::Debug, &m.concat());
	};
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
					using(cb, dir);
					return dir.clone();
				}
				continue;
			}
			Ok(md) => md,
		};
		last_dir = Some(md.is_dir());
		if !md.is_dir() {
			skipping(cb, b"not a directory", dir);
			continue;
		}
		if alpm_access(cb, None, dir, Access::WRITE_OK).is_err() {
			skipping(cb, b"not writable", dir);
			continue;
		}
		if md.mode() & 0o222 == 0 {
			skipping(cb, b"no write bits set", dir);
			continue;
		}
		using(cb, dir);
		return dir.clone();
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
	using(cb, &dir);
	let m = [
		b"couldn't find or create package cache, using ",
		&dir[..],
		b" instead\n",
	];
	cb.log(LogLevel::Warning, &m.concat());
	dir
}

// archive extraction: _alpm_open_archive, _alpm_unpack and
// _alpm_unpack_single
//
// libarchive is replaced by alpm-compress's decoders (filter picked by
// magic bytes like libarchive's bidding, for the four filters it has)
// read in libarchive's filter blocks (Filter), and the tar crate.
// archive_read_extract(archive, entry, 0) is translated for what a tar
// carries: without ARCHIVE_EXTRACT_* flags no owner, times, ACLs or
// xattrs are restored, permissions obey the umask (_alpm_unpack sets
// 0022) and lose SUID/SGID/sticky. an object in the way is unlinked (an
// empty directory rmdir'd, a directory kept for a directory), missing
// parents are created. absolute and ".." names are not refused, there are
// no SECURE flags. the C chdir()s into prefix; here names are joined to
// prefix and modes set by chmod, so process cwd and umask stay untouched

// file type bits of mode_t
pub(crate) const S_IFMT: u32 = 0o170000;
pub(crate) const S_IFREG: u32 = 0o100000;
pub(crate) const S_IFDIR: u32 = 0o040000;
pub(crate) const S_IFLNK: u32 = 0o120000;
pub(crate) const S_IFCHR: u32 = 0o020000;
pub(crate) const S_IFBLK: u32 = 0o060000;
pub(crate) const S_IFIFO: u32 = 0o010000;

// util.h, BUFSIZ in glibc
const ALPM_BUFFER_SIZE: u64 = 8192;

// the umask _alpm_unpack extracts under
const UNPACK_UMASK: u32 = 0o022;

// libarchive's decompression filters hand data on in output blocks:
// gzip_filter_read, bzip2_filter_read and xz_filter_read (64 KiB) and
// zstd_filter_read (ZSTD_DStreamOutSize, 128 KiB) fill a whole block or
// reach the stream's clean end before returning any of it. a stream cut
// short fails the read of the block it ends in, what was decoded into
// that block is never seen, and the filter stays failed. the decoders
// themselves deliver every byte up to the cut, so the blocks are redone
// here. no filter (plain tar) reads the file as it is
pub struct Filter<R: Source = BufReader<File>> {
	decoder: CompressionDecoder<'static, R>,
	// out_block_size, 0 without a filter
	size: usize,
	// blocks read ahead, data[pos..] not consumed yet
	data: Vec<u8>,
	pos: usize,
	// a short block: the stream's clean end
	end: bool,
	failed: Option<ErrorKind>,
	// file bytes the decoder has read by the last block, shared with
	// the Archive (archive_filter_bytes(a, -1), add.c's progress)
	consumed: Rc<Cell<u64>>,
}

// the filter's out_block_size, 0 without a filter
fn out_block_size(s: &DecompressionSettings) -> usize {
	match s {
		DecompressionSettings::None => 0,
		DecompressionSettings::Zstd => 128 * 1024,
		_ => 64 * 1024,
	}
}

// what a filter decodes: a file, or a .MTREE read into memory
// (archive_read_open_memory)
pub trait Source: BufRead {
	// bytes of it the decoder has read
	fn offset(&self) -> u64;
}

impl Source for BufReader<File> {
	fn offset(&self) -> u64 {
		self.get_ref().stream_position().unwrap_or_default()
	}
}

impl Source for Cursor<Vec<u8>> {
	fn offset(&self) -> u64 {
		self.position()
	}
}

// bytes uudecode_bidder_bid's line scan goes on over (its ascii table)
fn is_uu_text(c: &u8) -> bool {
	matches!(c, b' '..=b'~' | b'\n' | b'\r')
}

impl<R: Source> Filter<R> {
	pub fn new(
		decoder: CompressionDecoder<'static, R>,
		s: &DecompressionSettings,
	) -> Self {
		Filter {
			decoder,
			size: out_block_size(s),
			data: Vec::new(),
			pos: 0,
			end: false,
			failed: None,
			consumed: Rc::default(),
		}
	}

	// what archive_read_open reads through the filter: its first block
	// (choose_filters asks for data), and while that block is text lines
	// the uudecode bidder reads ahead to 128 KiB (UUENCODE_BID_MAX_READ).
	// a failure here is an open failure. a "begin " line, which makes
	// the bidder read on, is not modelled
	pub fn open(&mut self) -> io::Result<()> {
		if self.size == 0 {
			return Ok(());
		}
		self.ensure(1)?;
		if self.data.iter().all(is_uu_text) {
			self.ensure(128 * 1024)?;
		}
		Ok(())
	}

	// __archive_read_filter_ahead(n): blocks until n bytes are buffered
	// or the stream ended
	fn ensure(&mut self, n: usize) -> io::Result<()> {
		if let Some(kind) = self.failed {
			return Err(kind.into());
		}
		while self.data.len() - self.pos < n && !self.end {
			self.fill()?;
		}
		Ok(())
	}

	// the filter's read callback: a full block, or less at the end
	fn fill(&mut self) -> io::Result<()> {
		self.data.drain(..self.pos);
		self.pos = 0;
		let start = self.data.len();
		self.data.resize(start + self.size, 0);
		let r = read_full(&mut self.decoder, &mut self.data[start..]);
		self.consumed.set(self.decoder.get_ref().offset());
		match r {
			Ok(n) => {
				self.end = n < self.size;
				self.data.truncate(start + n);
				Ok(())
			}
			Err(e) => {
				self.data.truncate(start);
				self.failed = Some(e.kind());
				Err(e)
			}
		}
	}
}

// reads until buf is full or the reader ends: the count read
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
	let mut n = 0;
	while n < buf.len() {
		match r.read(&mut buf[n..]) {
			Ok(0) => break,
			Ok(k) => n += k,
			Err(e) if e.kind() == ErrorKind::Interrupted => {}
			Err(e) => return Err(e),
		}
	}
	Ok(n)
}

impl<R: Source> Read for Filter<R> {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		if self.size == 0 {
			return self.decoder.read(buf);
		}
		self.ensure(1)?;
		let n = buf.len().min(self.data.len() - self.pos);
		buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
		self.pos += n;
		Ok(n)
	}
}

// a tar entry read through the filter
pub type Entry<'a> = tar::Entry<'a, Filter>;

// the rest of an entry's data
pub fn content(entry: &mut Entry) -> io::Result<Vec<u8>> {
	let mut data = Vec::new();
	entry.read_to_end(&mut data)?;
	Ok(data)
}

// _alpm_archive_fgets's line limit, archive_read_buffer.max_line_size as
// its callers set it ("512K for a line length seems reasonable")
pub(crate) const MAX_LINE_SIZE: usize = 512 * 1024;

// archive_read_data_block on an entry: its data in the blocks libarchive
// hands out, which end at multiples of the block size in the archive
// stream. a short read is the truncated archive: what arrived is one
// more block, the next read fails like libarchive's
pub(crate) struct DataBlocks<'e, 'a> {
	entry: &'e mut Entry<'a>,
	block: u64,
	// stream offset of the next byte, entry bytes not read yet
	pos: u64,
	left: u64,
	truncated: bool,
}

impl<'e, 'a> DataBlocks<'e, 'a> {
	pub(crate) fn new(entry: &'e mut Entry<'a>, block: u64) -> Self {
		DataBlocks {
			pos: entry.raw_file_position(),
			left: entry.size(),
			entry,
			block,
			truncated: false,
		}
	}

	// None at the entry's end (ARCHIVE_EOF)
	pub(crate) fn next(&mut self) -> io::Result<Option<Vec<u8>>> {
		if self.truncated {
			return Err(ErrorKind::UnexpectedEof.into());
		}
		if self.left == 0 {
			return Ok(None);
		}
		let want = (self.block - self.pos % self.block).min(self.left);
		let mut data = Vec::new();
		(&mut *self.entry).take(want).read_to_end(&mut data)?;
		if data.is_empty() {
			return Err(ErrorKind::UnexpectedEof.into());
		}
		self.truncated = (data.len() as u64) < want;
		self.pos += data.len() as u64;
		self.left -= data.len() as u64;
		Ok(Some(data))
	}
}

// _alpm_archive_fgets with its archive_read_buffer. a line ends at the
// first '\n' of the block; a block without one ends it at its first nul
// instead, and a line may run over several blocks. the data's end gives
// the last line (empty after a final '\n')
pub(crate) struct ArchiveFgets<'e, 'a> {
	src: DataBlocks<'e, 'a>,
	block: Vec<u8>,
	off: usize,
	// the last read was the entry's end (b->ret == ARCHIVE_EOF)
	eof: bool,
	// b->line allocated: its first allocation skips the size check
	started: bool,
	line: Vec<u8>,
}

impl<'e, 'a> ArchiveFgets<'e, 'a> {
	pub(crate) fn new(src: DataBlocks<'e, 'a>) -> Self {
		ArchiveFgets {
			src,
			block: Vec::new(),
			off: 0,
			eof: false,
			started: false,
			line: Vec::new(),
		}
	}

	// the next line without its end of line, None at the end. an error
	// ends the reading (the C frees the buffer)
	pub(crate) fn next(&mut self) -> io::Result<Option<&[u8]>> {
		self.line.clear();
		loop {
			if self.off == self.block.len() {
				if self.eof {
					return Ok(None);
				}
				let next = self.src.next()?;
				self.eof = next.is_none();
				self.block = next.unwrap_or_default();
				self.off = 0;
			}
			let rest = &self.block[self.off..];
			let eol = rest
				.iter()
				.position(|&c| c == b'\n')
				.or_else(|| rest.iter().position(|&c| c == 0));
			let new = eol.unwrap_or(rest.len());
			let needed = self.line.len() + new + 1;
			if self.started && needed > MAX_LINE_SIZE {
				let range =
					rustix::io::Errno::RANGE.raw_os_error();
				return Err(io::Error::from_raw_os_error(
					range,
				));
			}
			self.started = true;
			self.line.extend_from_slice(&rest[..new]);
			match eol {
				Some(i) => {
					self.off += i + 1;
					return Ok(Some(&self.line));
				}
				None => {
					self.off = self.block.len();
					if new == 0 {
						return Ok(Some(&self.line));
					}
				}
			}
		}
	}
}

// _alpm_open_archive: the reader over the file and its fstat. libarchive
// also reads the first header to pick the format, which unpack does next
pub struct Archive {
	pub reader: tar::Archive<Filter>,
	pub meta: fs::Metadata,
	// how far the decoder read the file, see Filter
	pub consumed: Rc<Cell<u64>>,
	// the filter picked, None: tar offsets are file offsets
	pub settings: DecompressionSettings,
}

impl Archive {
	// the blocks archive_read_data_block hands an entry's data out in:
	// they end where the filter's output blocks end. without a filter
	// the reads of archive_read_open_fd's buffer (_alpm_open_archive:
	// ALPM_BUFFER_SIZE, or st_blksize when larger)
	pub fn block_size(&self) -> u64 {
		match out_block_size(&self.settings) {
			0 => self.meta.blksize().max(ALPM_BUFFER_SIZE),
			n => n as u64,
		}
	}
}

pub(crate) fn archive_io_err(e: alpm_compress::Error) -> io::Error {
	match e {
		alpm_compress::Error::IoRead { source, .. } => source,
		e => io::Error::other(e),
	}
}

// the error is errno at the failing step (open, fstat, the first read
// of archive_read_open_fd: EISDIR for a directory), or the decoder's
// error in what archive_read_open reads through the filter. the filter
// is the one libarchive's bidding would pick, for the four alpm-compress
// has; anything else is read as a plain tar
pub fn open_archive(path: &[u8]) -> io::Result<Archive> {
	let mut file = File::open(c_path(path))?;
	let meta = file.metadata()?;
	let len = DecompressionSettings::MAGIC_LEN;
	let mut magic = Vec::with_capacity(len);
	(&mut file).take(len as u64).read_to_end(&mut magic)?;
	file.rewind()?;
	let settings = DecompressionSettings::from_magic(&magic);
	let decoder = CompressionDecoder::new(file, settings.clone())
		.map_err(archive_io_err)?;
	let mut filter = Filter::new(decoder, &settings);
	filter.open()?;
	let consumed = filter.consumed.clone();
	Ok(Archive {
		reader: tar::Archive::new(filter),
		meta,
		consumed,
		settings,
	})
}

// why _alpm_unpack returned 1
#[derive(Debug)]
pub enum UnpackError {
	// _alpm_open_archive failed: ALPM_ERR_PKG_OPEN
	Open(io::Error),
	// chdir(prefix) failed, pm_errno untouched
	Prefix(io::Error),
	// data of the named entry could not be read (extracted or skipped):
	// truncated or corrupt archive, pm_errno untouched
	Read(Vec<u8>, io::Error),
}

impl UnpackError {
	// the pm_errno the C sets, None where it leaves it alone
	pub fn errno(&self) -> Option<Errno> {
		match self {
			UnpackError::Open(_) => Some(Errno::PkgOpen),
			_ => None,
		}
	}
}

// archive_read_extract's result other than ARCHIVE_OK. header and write
// failures come back as ARCHIVE_WARN (archive_read_extract2 caps them),
// only a failed data read is fatal
enum Failure {
	Warn(io::Error),
	Read(io::Error),
}

// what create_filesystem_object makes of an entry
enum Object<'e> {
	File,
	Dir,
	Symlink(&'e [u8]),
	HardLink(&'e [u8]),
	// mknod type, rdev
	Node(FileType, u64),
}

fn os_path(path: Vec<u8>) -> PathBuf {
	PathBuf::from(OsString::from_vec(path))
}

fn is_kind(r: &io::Result<impl Sized>, kinds: &[ErrorKind]) -> bool {
	matches!(r, Err(e) if kinds.contains(&e.kind()))
}

// cleanup_pathname_fsobj without the SECURE flags: "./" and empty
// components dropped, a trailing "." or '/' cut, ".." kept, a leading
// '/' kept. "." or "/" when nothing is left, None for an empty name
pub(crate) fn cleanup_pathname(name: &[u8]) -> Option<Vec<u8>> {
	if name.is_empty() {
		return None;
	}
	let (mut sep, mut src) = match name.strip_prefix(b"/") {
		Some(rest) => (true, rest),
		None => (false, name),
	};
	let mut out = Vec::with_capacity(name.len());
	loop {
		match src {
			[] | [b'.'] => break,
			[b'/', rest @ ..] | [b'.', b'/', rest @ ..] => {
				src = rest;
				continue;
			}
			_ => {}
		}
		if sep {
			out.push(b'/');
		}
		let end = src.iter().position(|&c| c == b'/');
		out.extend_from_slice(&src[..end.unwrap_or(src.len())]);
		let Some(end) = end else { break };
		sep = true;
		src = &src[end + 1..];
	}
	if out.is_empty() {
		out.push(if sep { b'/' } else { b'.' });
	}
	Some(out)
}

// _alpm_unpack's filter: the name up to and including its first '/' is
// one of list (alpm_list_find_str)
fn wanted<L: AsRef<[u8]>>(list: &[L], name: &[u8]) -> bool {
	let end = name
		.iter()
		.position(|&c| c == b'/')
		.map_or(name.len(), |i| i + 1);
	list.iter().any(|l| until_nul(l.as_ref()) == &name[..end])
}

// libarchive consumes an entry's padding to 512 bytes with its data (the
// last read, or the skip). the tar reader reads it with the next header,
// so it is checked against the length of a plain archive; past a filter
// a missing padding only shows at the next header
pub(crate) fn check_padding(
	entry: &Entry,
	size: u64,
	plain_len: Option<u64>,
) -> io::Result<()> {
	let end = entry.raw_file_position() + size.next_multiple_of(512);
	match plain_len.is_some_and(|len| end > len) {
		true => Err(ErrorKind::UnexpectedEof.into()),
		false => Ok(()),
	}
}

// archive_read_data_skip
pub(crate) fn skip_data(
	entry: &mut Entry,
	size: u64,
	plain_len: Option<u64>,
) -> io::Result<()> {
	let n = io::copy(entry, &mut io::sink())?;
	if n < size {
		return Err(ErrorKind::UnexpectedEof.into());
	}
	check_padding(entry, size, plain_len)
}

// archive_write_disk state across entries
struct Disk<'p> {
	// the C's cwd
	prefix: &'p [u8],
	// st_dev/st_ino of a regular archive file, never overwritten
	// (archive_read_extract's skip file)
	archive: Option<(u64, u64)>,
	// archive length when unfiltered, see check_padding
	plain_len: Option<u64>,
}

impl Disk<'_> {
	// a name as the C resolves it after chdir(prefix)
	fn full(&self, rel: &[u8]) -> PathBuf {
		match rel.first() {
			Some(b'/') => os_path(rel.to_vec()),
			_ => os_path([self.prefix, b"/", rel].concat()),
		}
	}

	// create_filesystem_object, perm with the umask applied. a new
	// regular file comes back open for its data
	fn create(
		&self,
		rel: &[u8],
		obj: &Object,
		perm: u32,
	) -> io::Result<Option<File>> {
		let path = self.full(rel);
		match *obj {
			Object::HardLink(target) => {
				// cleanup_pathname_fsobj (only fails on an empty name)
				// and check_symlinks_fsobj on the target fail as EPERM.
				// linkat(..., 0) links a symlink itself
				if target.is_empty()
					|| self.check_link_target(target)
						.is_err()
				{
					return Err(
						rustix::io::Errno::PERM.into()
					);
				}
				fs::hard_link(self.full(target), &path)?;
			}
			Object::Symlink(target) => {
				symlink(OsStr::from_bytes(target), &path)?
			}
			Object::File => {
				let f = OpenOptions::new()
					.write(true)
					.create_new(true)
					.mode(perm)
					.open(&path)?;
				// set_mode's fchmod
				f.set_permissions(Permissions::from_mode(
					perm,
				))?;
				return Ok(Some(f));
			}
			Object::Dir => mkdir_mode(&path, perm)?,
			Object::Node(kind, rdev) => {
				let mode = Mode::from_raw_mode(perm);
				mknodat(CWD, &path, kind, mode, rdev)?;
				fs::set_permissions(
					&path,
					Permissions::from_mode(perm),
				)?;
			}
		}
		Ok(None)
	}

	// check_symlinks_fsobj on a hard link target, without SECURE flags:
	// lstat each leading component. a missing one ends the walk, other
	// errors fail (a regular file in the middle fails at the next one), a
	// symlink in the middle is followed when it leads to a directory
	fn check_link_target(&self, target: &[u8]) -> io::Result<()> {
		let mut end = usize::from(target.first() == Some(&b'/'));
		loop {
			while target.get(end) == Some(&b'/') {
				end += 1;
			}
			while end < target.len() && target[end] != b'/' {
				end += 1;
			}
			let last = target.len() - end <= 1;
			let path = self.full(&target[..end]);
			let st = match fs::symlink_metadata(&path) {
				Err(e) if e.kind() == ErrorKind::NotFound => {
					return Ok(());
				}
				st => st?,
			};
			if st.is_symlink() && !last {
				match fs::metadata(&path) {
					Err(e) if e.kind()
						== ErrorKind::NotFound =>
					{
						return Ok(());
					}
					Ok(st) if !st.is_dir() => {
						let e = "Cannot extract through symlink";
						return Err(io::Error::other(
							e,
						));
					}
					st => st?,
				};
			}
			if last {
				return Ok(());
			}
			end += 1;
		}
	}

	// create_dir: rel as a directory, missing parents first, a
	// non-directory in the way unlinked. stat follows symlinks, so
	// extraction goes through a symlink to a directory
	fn create_dir(&self, rel: &[u8]) -> io::Result<()> {
		let slash = rel.iter().rposition(|&c| c == b'/');
		let base = &rel[slash.map_or(0, |i| i + 1)..];
		if matches!(base, b"" | b"." | b"..") {
			return match slash {
				Some(i) => self.create_dir(&rel[..i]),
				None => Ok(()),
			};
		}
		let path = self.full(rel);
		match fs::metadata(&path) {
			Ok(st) if st.is_dir() => return Ok(()),
			Ok(_) => fs::remove_file(&path)?,
			Err(e) if !matches!(
				e.kind(),
				ErrorKind::NotFound | ErrorKind::NotADirectory
			) =>
			{
				return Err(e);
			}
			Err(_) => {
				if let Some(i) = slash {
					self.create_dir(&rel[..i])?;
				}
			}
		}
		// DEFAULT_DIR_MODE under the umask
		let r = mkdir_mode(&path, 0o777 & !UNPACK_UMASK);
		// "a/b/../b/c": the second visit finds it made
		if r.is_err() && fs::metadata(&path).is_ok_and(|m| m.is_dir()) {
			return Ok(());
		}
		r
	}

	// restore_entry: create, on ENOENT/ENOTDIR make the parents and
	// retry, on EEXIST clear what is in the way and retry
	fn restore(
		&self,
		rel: &[u8],
		obj: &Object,
		perm: u32,
	) -> io::Result<Option<File>> {
		// a hard link to its own (cleaned) name is refused up front
		if let Object::HardLink(target) = *obj
			&& target == rel
		{
			return Err(io::Error::other("hard link to itself"));
		}
		let mut r = self.create(rel, obj, perm);
		let missing = [ErrorKind::NotFound, ErrorKind::NotADirectory];
		if is_kind(&r, &missing) {
			if let Some(i) = rel.iter().rposition(|&c| c == b'/') {
				let _ = self.create_dir(&rel[..i]);
			}
			r = self.create(rel, obj, perm);
		}
		if !is_kind(&r, &[ErrorKind::AlreadyExists]) {
			return r;
		}
		let path = self.full(rel);
		let dir = matches!(obj, Object::Dir);
		// a directory entry follows a symlink in the way, others not
		let st = match dir {
			true => fs::metadata(&path)
				.or_else(|_| fs::symlink_metadata(&path)),
			false => fs::symlink_metadata(&path),
		}?;
		if self.archive == Some((st.dev(), st.ino())) {
			return Err(io::Error::other(
				"Refusing to overwrite archive",
			));
		}
		if !st.is_dir() {
			fs::remove_file(&path)?;
		} else if !dir {
			fs::remove_dir(&path)?;
		} else {
			// a directory in the way of a directory stays as it is
			return Ok(None);
		}
		self.create(rel, obj, perm)
	}

	// archive_read_extract(archive, entry, 0) on the entry named name
	fn extract(
		&self,
		entry: &mut Entry,
		name: &[u8],
		mode: u32,
		size: u64,
	) -> Result<(), Failure> {
		let header = entry.header();
		let target = entry.link_name_bytes().unwrap_or_default();
		let rdev = || {
			let major = header
				.device_major()
				.ok()
				.flatten()
				.unwrap_or(0);
			let minor = header
				.device_minor()
				.ok()
				.flatten()
				.unwrap_or(0);
			makedev(major, minor)
		};
		let obj = match mode & S_IFMT {
			S_IFDIR => Object::Dir,
			S_IFLNK => Object::Symlink(&target),
			// hard links carry no type bits
			0 => Object::HardLink(&target),
			S_IFCHR => {
				Object::Node(FileType::CharacterDevice, rdev())
			}
			S_IFBLK => Object::Node(FileType::BlockDevice, rdev()),
			S_IFIFO => Object::Node(FileType::Fifo, 0),
			_ => Object::File,
		};
		// _alpm_unpack's archive_entry_set_perm, then libarchive drops
		// SUID/SGID/sticky and applies the umask
		let perm = match mode & S_IFMT {
			S_IFREG => 0o644,
			S_IFDIR => 0o755,
			_ => mode,
		} & 0o777 & !UNPACK_UMASK;
		let rel = cleanup_pathname(name).ok_or_else(|| {
			Failure::Warn(io::Error::other(
				"Invalid empty pathname",
			))
		})?;
		let file = self
			.restore(&rel, &obj, perm)
			.map_err(Failure::Warn)?;
		// only a regular file takes data, the rest is skipped with the
		// next header
		match file {
			Some(f) if size > 0 => {
				copy_data(entry, f, size)?;
				check_padding(entry, size, self.plain_len)
					.map_err(Failure::Read)
			}
			_ => Ok(()),
		}
	}
}

// copy_data then finish_entry: read failures are fatal, the first write
// failure ends the entry with a warning. either way the file is extended
// with zeros to the entry size
fn copy_data(
	entry: &mut Entry,
	mut file: File,
	size: u64,
) -> Result<(), Failure> {
	let r = pour(entry, &mut file, size);
	let len = file.metadata().map_err(Failure::Warn)?.len();
	if len != size {
		file.set_len(size).map_err(Failure::Warn)?;
	}
	r
}

fn pour(entry: &mut Entry, file: &mut File, size: u64) -> Result<(), Failure> {
	let mut buf = vec![0; 64 * 1024];
	let mut got = 0;
	while got < size {
		let n = match entry.read(&mut buf) {
			Ok(0) => {
				let e = ErrorKind::UnexpectedEof.into();
				return Err(Failure::Read(e));
			}
			Ok(n) => n,
			Err(e) if e.kind() == ErrorKind::Interrupted => {
				continue;
			}
			Err(e) => return Err(Failure::Read(e)),
		};
		got += n as u64;
		file.write_all(&buf[..n]).map_err(Failure::Warn)?;
	}
	Ok(())
}

// _alpm_unpack: extract the entries of the archive at path into prefix.
// a non-empty list keeps only the entries whose name up to its first '/'
// is in it (empty is the C's NULL list: every entry), breakfirst stops
// after the first extracted one. entries libarchive warned about are
// logged and do not fail the call. libarchive reads the first header
// while opening (format bidding), its failure is an open failure; the
// loop ends at any later header that cannot be read, which is no error.
// logs go to cb like the C's _alpm_log; libarchive's error texts are the
// port's, an fstat failure is logged as an open failure
pub fn unpack<L: AsRef<[u8]>>(
	cb: &mut dyn Callbacks,
	path: &[u8],
	prefix: &[u8],
	list: &[L],
	breakfirst: bool,
) -> Result<(), UnpackError> {
	let (path, prefix) = (until_nul(path), until_nul(prefix));
	logv(cb, LogLevel::Debug, &[b"opening archive ", path, b"\n"]);
	let open_failed = |cb: &mut dyn Callbacks, e: io::Error| {
		let msg: [&[u8]; 5] = [
			b"could not open file ",
			path,
			b": ",
			&strerror(&e),
			b"\n",
		];
		logv(cb, LogLevel::Error, &msg);
		UnpackError::Open(e)
	};
	let mut archive = open_archive(path).map_err(|e| open_failed(cb, e))?;
	let meta = &archive.meta;
	let plain = archive.settings == DecompressionSettings::None;
	let plain_len = plain.then_some(meta.len());
	let skip_file = meta.is_file().then(|| (meta.dev(), meta.ino()));
	let mut entries =
		archive.reader.entries().map_err(|e| open_failed(cb, e))?;
	let first = match entries.next() {
		Some(Err(e)) => return Err(open_failed(cb, e)),
		first => first,
	};
	if let Err(e) = enter(prefix) {
		let msg: [&[u8]; 5] = [
			b"could not change directory to ",
			prefix,
			b" (",
			&strerror(&e),
			b")\n",
		];
		logv(cb, LogLevel::Error, &msg);
		return Err(UnpackError::Prefix(e));
	}
	let disk = Disk {
		prefix,
		archive: skip_file,
		plain_len,
	};
	for entry in first.into_iter().chain(entries) {
		// archive_read_next_header != ARCHIVE_OK ends the loop
		let Ok(mut entry) = entry else { break };
		let Ok((mode, size)) = tar_mode_size(&entry) else {
			break;
		};
		let size = size as u64;
		let name = until_nul(&entry.path_bytes()).to_vec();
		if !list.is_empty() {
			if !wanted(list, &name) {
				skip_data(&mut entry, size, plain_len)
					.map_err(|e| {
						UnpackError::Read(name, e)
					})?;
				continue;
			}
			logv(
				cb,
				LogLevel::Debug,
				&[b"extracting: ", &name, b"\n"],
			);
		}
		match disk.extract(&mut entry, &name, mode, size) {
			Ok(()) => {}
			Err(Failure::Warn(e)) => {
				let msg: [&[u8]; 5] = [
					b"warning given when extracting ",
					&name,
					b" (",
					&strerror(&e),
					b")\n",
				];
				logv(cb, LogLevel::Warning, &msg);
			}
			Err(Failure::Read(e)) => {
				let msg: [&[u8]; 5] = [
					b"could not extract ",
					&name,
					b" (",
					&strerror(&e),
					b")\n",
				];
				logv(cb, LogLevel::Error, &msg);
				return Err(UnpackError::Read(name, e));
			}
		}
		if breakfirst {
			break;
		}
	}
	Ok(())
}

// chdir(2): a directory the process may search, with the effective ids
// like chdir
pub(crate) fn enter(dir: &[u8]) -> io::Result<()> {
	let path = c_path(dir);
	if !fs::metadata(path)?.is_dir() {
		return Err(rustix::io::Errno::NOTDIR.into());
	}
	accessat(CWD, path, Access::EXEC_OK, AtFlags::EACCESS)?;
	Ok(())
}

// _alpm_unpack_single: the first entry named filename (or under it, for a
// name ending in '/')
pub fn unpack_single(
	cb: &mut dyn Callbacks,
	archive: &[u8],
	prefix: &[u8],
	filename: &[u8],
) -> Result<(), UnpackError> {
	unpack(cb, archive, prefix, &[filename], true)
}
