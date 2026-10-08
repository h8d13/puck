// libarchive's tar format reader (archive_read_support_format_tar.c,
// libarchive 3.8.9) as pacman reads packages, sync dbs and .INSTALL
// files: archive_read_support_format_all picks it for a tar stream, no
// format option is set. what libarchive does to the archive_entry is
// kept for every field pacman or archive_write_disk reads: the pax
// extension records (pax_attribute), GNU long names, GNU and Sun sparse
// maps and Solaris ACL headers, with archive_acl.c's text parser for
// what an ACL does to the mode and the header's result. AppleDouble "._"
// entries are plain ones: mac-ext is on by default on macOS only.
//
// strings of a pax header go through libarchive's conversion from UTF-8
// to the locale's charset, taken as UTF-8 (pacman calls setlocale(LC_ALL,
// "")): an invalid sequence is ARCHIVE_WARN, a CESU-8 surrogate pair is
// joined into one sequence. the NFC composition the same conversion does
// (archive_string_normalize_C, Unicode 6.0 tables) is not modelled.
//
// libarchive reads through __archive_read_ahead, whose buffers end where
// the filter's blocks end (archive_read_open_fd's reads without one): a
// request inside a block sees up to its end, one across a boundary gets
// exactly its size (the copy buffer). that decides how far a pax record's
// name is looked for and where data blocks are cut.
//
// every header result other than ARCHIVE_OK ends pacman's header loops,
// so ARCHIVE_WARN and ARCHIVE_RETRY come out as errors like ARCHIVE_FATAL,
// with archive_error_string ("(null)" when nothing was set).

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read};

use crate::filter::Filter;
use crate::util::{
	S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, until_nul,
};

// archive.h results; err_combine keeps the lowest
const EOF: i32 = 1;
const OK: i32 = 0;
const RETRY: i32 = -10;
const WARN: i32 = -20;
const FAILED: i32 = -25;
const FATAL: i32 = -30;

const GUNAME_LIMIT: usize = 65536;
const PATHNAME_LIMIT: usize = 1048576;
const SPARSE_MAP_LIMIT: usize = 8 * 1048576;
const XATTR_LIMIT: usize = 16 * 1048576;
const FFLAGS_LIMIT: usize = 512;
const ACL_LIMIT: usize = 131072;
const ENTRY_LIMIT: i64 = 0x0fff_ffff_ffff_ffff;

// tar->size_fields
const SIZE_PAX_SIZE: u8 = 1;
const SIZE_GNU_SPARSE_REALSIZE: u8 = 2;
const SIZE_GNU_SPARSE_SIZE: u8 = 4;
const SIZE_SCHILY_SPARSE_REALSIZE: u8 = 8;

// tar_read_header's seen_headers
const SEEN_A: u32 = 1;
const SEEN_G: u32 = 2;
const SEEN_K: u32 = 4;
const SEEN_L: u32 = 8;
const SEEN_V: u32 = 16;
const SEEN_X: u32 = 32;

// archive_entry.h ACL types, tags and permission bits
const ACL_EXECUTE: i32 = 1;
const ACL_WRITE: i32 = 2;
const ACL_READ: i32 = 4;
const ACL_TYPE_ACCESS: i32 = 0x100;
const ACL_TYPE_DEFAULT: i32 = 0x200;
const ACL_TYPE_ALLOW: i32 = 0x400;
const ACL_TYPE_DENY: i32 = 0x800;
const ACL_TYPE_AUDIT: i32 = 0x1000;
const ACL_TYPE_ALARM: i32 = 0x2000;
const ACL_TYPE_POSIX1E: i32 = ACL_TYPE_ACCESS | ACL_TYPE_DEFAULT;
const ACL_TYPE_NFS4: i32 =
	ACL_TYPE_ALLOW | ACL_TYPE_DENY | ACL_TYPE_AUDIT | ACL_TYPE_ALARM;
const ACL_USER: i32 = 10001;
const ACL_USER_OBJ: i32 = 10002;
const ACL_GROUP: i32 = 10003;
const ACL_GROUP_OBJ: i32 = 10004;
const ACL_MASK: i32 = 10005;
const ACL_OTHER: i32 = 10006;
const ACL_EVERYONE: i32 = 10107;

// a->archive.archive_format, as the tar reader sets it
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
	Tar,
	Ustar,
	Pax,
	Gnu,
}

// what __archive_read_ahead found short of a request: the bytes there
// were before the end of the stream, or a failed read
enum Short {
	End(usize),
	Failed,
}

// __archive_read_ahead and __archive_read_consume over the filter. the
// read-ahead bytes are buf[at..], pos is the stream offset of buf[at]
struct Src {
	filter: Filter,
	buf: Vec<u8>,
	at: usize,
	pos: u64,
	block: u64,
	end: bool,
	failed: bool,
}

impl Src {
	// how many bytes past pos libarchive's buffer holds when n are asked
	// for: up to the block's end, exactly n across it
	fn window(&self, n: usize) -> usize {
		let left = (self.block - self.pos % self.block) as usize;
		left.max(n)
	}

	fn buffered(&self) -> usize {
		self.buf.len() - self.at
	}

	// reads until want bytes are buffered or the stream ends or fails
	fn fill(&mut self, want: usize) {
		if self.at > 0
			&& (self.at == self.buf.len() || self.at > 1 << 20)
		{
			self.buf.drain(..self.at);
			self.at = 0;
		}
		while self.buffered() < want && !self.end && !self.failed {
			let start = self.buf.len();
			let n = (want - self.buffered()).max(8192);
			self.buf.resize(start + n, 0);
			let r = self.filter.read(&mut self.buf[start..]);
			let got = match r {
				Ok(0) => {
					self.end = true;
					0
				}
				Ok(k) => k,
				Err(e) if e.kind()
					== ErrorKind::Interrupted =>
				{
					0
				}
				Err(_) => {
					self.failed = true;
					0
				}
			};
			self.buf.truncate(start + got);
		}
	}

	// __archive_read_ahead(n): the bytes the buffer holds, at least n
	fn ahead(&mut self, n: usize) -> Result<&[u8], Short> {
		let w = self.window(n);
		self.fill(w);
		let have = self.buffered();
		if have < n {
			return Err(match self.failed {
				true => Short::Failed,
				false => Short::End(have),
			});
		}
		Ok(&self.buf[self.at..self.at + have.min(w)])
	}

	// exactly n bytes ahead, None when they are not there
	fn peek(&mut self, n: usize) -> Option<Vec<u8>> {
		self.ahead(n).ok().map(|d| d[..n].to_vec())
	}

	// a header block ahead
	fn block_ahead(&mut self) -> Result<[u8; 512], Short> {
		let d = self.ahead(512)?;
		let mut h = [0; 512];
		h.copy_from_slice(&d[..512]);
		Ok(h)
	}

	// n buffered bytes, consumed (after an ahead that held them)
	fn take(&mut self, n: usize) -> Vec<u8> {
		let v = self.buf[self.at..self.at + n].to_vec();
		self.at += n;
		self.pos += n as u64;
		v
	}

	// __archive_read_consume: Err with what was skipped, 0 when a read
	// failed (advance_file_pointer drops its count then)
	fn consume(&mut self, n: u64) -> Result<(), u64> {
		let k = n.min(self.buffered() as u64);
		self.at += k as usize;
		self.pos += k;
		let mut left = n - k;
		let mut scratch = vec![0; left.min(64 * 1024) as usize];
		while left > 0 {
			if self.failed {
				return Err(0);
			}
			if self.end {
				return Err(n - left);
			}
			let want = left.min(scratch.len() as u64) as usize;
			match self.filter.read(&mut scratch[..want]) {
				Ok(0) => self.end = true,
				Ok(r) => {
					self.pos += r as u64;
					left -= r as u64;
				}
				Err(e) if e.kind()
					== ErrorKind::Interrupted => {}
				Err(_) => self.failed = true,
			}
		}
		Ok(())
	}
}

// one block of a sparse_list
#[derive(Clone, Copy, Debug)]
struct Block {
	offset: i64,
	remaining: i64,
	hole: bool,
}

// the fields of struct tar the header and data readers share
#[derive(Debug)]
struct Tar {
	format: Format,
	entry_bytes_remaining: i64,
	entry_padding: i64,
	disk_size: i64,
	gnu_sparse_realsize: i64,
	gnu_sparse_size: i64,
	schily_sparse_realsize: i64,
	pax_size: i64,
	size_fields: u8,
	sparse: VecDeque<Block>,
	sparse_offset: i64,
	sparse_numbytes: i64,
	sparse_gnu_major: i64,
	sparse_gnu_minor: i64,
	sparse_gnu_attributes_seen: bool,
	filetype: u8,
	hdrcharset_utf8: bool,
	entry_pathname: Vec<u8>,
	entry_pathname_override: Vec<u8>,
	entry_uname: Vec<u8>,
	entry_gname: Vec<u8>,
	entry_linkpath: Vec<u8>,
}

impl Tar {
	fn new() -> Tar {
		Tar {
			format: Format::Tar,
			entry_bytes_remaining: 0,
			entry_padding: 0,
			disk_size: 0,
			gnu_sparse_realsize: 0,
			gnu_sparse_size: 0,
			schily_sparse_realsize: 0,
			pax_size: 0,
			size_fields: 0,
			sparse: VecDeque::new(),
			sparse_offset: 0,
			sparse_numbytes: 0,
			sparse_gnu_major: 0,
			sparse_gnu_minor: 0,
			sparse_gnu_attributes_seen: false,
			filetype: 0,
			hdrcharset_utf8: true,
			entry_pathname: Vec::new(),
			entry_pathname_override: Vec::new(),
			entry_uname: Vec::new(),
			entry_gname: Vec::new(),
			entry_linkpath: Vec::new(),
		}
	}

	fn reset_header_state(&mut self) {
		self.hdrcharset_utf8 = true;
		self.sparse_gnu_attributes_seen = false;
		self.entry_gname.clear();
		self.entry_pathname.clear();
		self.entry_pathname_override.clear();
		self.entry_uname.clear();
		self.entry_linkpath.clear();
	}
}

// the archive_entry fields the reader sets and pacman or
// archive_write_disk read
#[derive(Clone, Debug, Default)]
struct Ae {
	path: Option<Vec<u8>>,
	link: Option<Vec<u8>>,
	// AE_SET_HARDLINK, AE_SET_SYMLINK
	hardlink: bool,
	symlink: bool,
	// acl.mode: the type bits and the permissions
	mode: u32,
	perm_set: bool,
	// acl.acl_types of the entries that are not part of the mode
	acl_types: i32,
	uid: Option<i64>,
	gid: Option<i64>,
	mtime: Option<(i64, i64)>,
	atime: Option<(i64, i64)>,
	ctime: Option<(i64, i64)>,
	size: Option<i64>,
	rdev: Option<(u64, u64)>,
	// in record order: archive_entry_xattr_add_entry prepends, and the
	// archive_entry_clone archive_write_disk works on prepends again
	xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

// types without data: no size, nothing to read
fn no_data(ae: &mut Ae, t: &mut Tar, filetype: u32) {
	ae.set_filetype(filetype);
	ae.set_size(0);
	t.entry_bytes_remaining = 0;
}

// FIX_NS
fn fix_ns(mut t: i64, mut ns: i64) -> (i64, i64) {
	t += ns / 1_000_000_000;
	ns %= 1_000_000_000;
	if ns < 0 {
		t -= 1;
		ns += 1_000_000_000;
	}
	(t, ns)
}

impl Ae {
	fn set_filetype(&mut self, t: u32) {
		self.mode = (self.mode & !S_IFMT) | (t & S_IFMT);
	}

	fn set_perm(&mut self, p: u32) {
		self.mode = (self.mode & S_IFMT) | (p & !S_IFMT);
		self.perm_set = true;
	}

	fn filetype(&self) -> u32 {
		self.mode & S_IFMT
	}

	fn set_size(&mut self, s: i64) {
		self.size = Some(s.max(0));
	}

	fn hardlink(&self) -> Option<&[u8]> {
		self.link.as_deref().filter(|_| self.hardlink)
	}

	fn symlink(&self) -> Option<&[u8]> {
		self.link.as_deref().filter(|_| self.symlink)
	}

	// archive_entry_copy_link_l / archive_entry_set_link: a hard link
	// unless a symlink is set
	fn copy_link(&mut self, s: &[u8]) {
		self.link = Some(until_nul(s).to_vec());
		if !self.symlink {
			self.hardlink = true;
		}
	}

	fn add_xattr(&mut self, name: &[u8], value: &[u8]) {
		let name = until_nul(name).to_vec();
		self.xattrs.push((name, value.to_vec()));
	}

	fn set_rdevmajor(&mut self, m: u64) {
		let minor = self.rdev.map_or(0, |r| r.1);
		self.rdev = Some((m, minor));
	}

	fn set_rdevminor(&mut self, m: u64) {
		let major = self.rdev.map_or(0, |r| r.0);
		self.rdev = Some((major, m));
	}
}

fn is_null(h: &[u8]) -> bool {
	h.iter().all(|&c| c == 0)
}

// tar_atol_base_n: blanks, a '-', digits up to the first other byte;
// overflow saturates
fn atol_base(p: &[u8], base: i64) -> i64 {
	let mut i = 0;
	while i < p.len() && (p[i] == b' ' || p[i] == b'\t') {
		i += 1;
	}
	let mut sign = 1;
	if i < p.len() && p[i] == b'-' {
		sign = -1;
		i += 1;
	}
	let mut l: i64 = 0;
	while i < p.len() {
		let digit = i64::from(p[i]) - i64::from(b'0');
		if digit < 0 || digit >= base {
			break;
		}
		let next = l
			.checked_mul(base)
			.and_then(|l| l.checked_add(sign * digit));
		let Some(next) = next else {
			return if sign < 0 { i64::MIN } else { i64::MAX };
		};
		l = next;
		i += 1;
	}
	l
}

fn atol10(p: &[u8]) -> i64 {
	atol_base(p, 10)
}

// tar_atol256: big-endian two's complement, the high bit ignored
fn atol256(p: &[u8]) -> i64 {
	let (neg, mut c, mut l): (u8, u8, u64) = match p[0] & 0x40 {
		0 => (0, p[0] & 0x7f, 0),
		_ => (0xff, p[0] | 0x80, !0),
	};
	let mut i = 0;
	let mut n = p.len();
	while n > 8 {
		n -= 1;
		if c != neg {
			return if neg != 0 { i64::MIN } else { i64::MAX };
		}
		i += 1;
		c = p[i];
	}
	if (c ^ neg) & 0x80 != 0 {
		return if neg != 0 { i64::MIN } else { i64::MAX };
	}
	while n > 1 {
		n -= 1;
		l = (l << 8) | u64::from(c);
		i += 1;
		c = p[i];
	}
	l = (l << 8) | u64::from(c);
	l as i64
}

// tar_atol: base 256 when the high bit is set, else octal
fn atol(p: &[u8]) -> i64 {
	match p[0] & 0x80 {
		0 => atol_base(p, 8),
		_ => atol256(p),
	}
}

// header field offsets (struct archive_entry_header_ustar/_gnutar)
fn field(h: &[u8; 512], at: usize, len: usize) -> &[u8] {
	&h[at..at + len]
}

const NAME: (usize, usize) = (0, 100);
const MODE: (usize, usize) = (100, 8);
const UID: (usize, usize) = (108, 8);
const GID: (usize, usize) = (116, 8);
const SIZE: (usize, usize) = (124, 12);
const MTIME: (usize, usize) = (136, 12);
const CHECKSUM: (usize, usize) = (148, 8);
const LINKNAME: (usize, usize) = (157, 100);
const RDEVMAJOR: (usize, usize) = (329, 8);
const RDEVMINOR: (usize, usize) = (337, 8);
const PREFIX: (usize, usize) = (345, 155);
const GNU_ATIME: (usize, usize) = (345, 12);
const GNU_CTIME: (usize, usize) = (357, 12);
const GNU_SPARSE: usize = 386;
const GNU_ISEXTENDED: usize = 482;
const GNU_REALSIZE: (usize, usize) = (483, 12);

fn num(h: &[u8; 512], f: (usize, usize)) -> i64 {
	atol(field(h, f.0, f.1))
}

// checksum: the field holds octal digits, the sum is taken unsigned or,
// for old writers, signed
fn checksum(h: &[u8; 512]) -> bool {
	let f = field(h, CHECKSUM.0, CHECKSUM.1);
	if f.iter()
		.any(|&c| c != b' ' && c != 0 && !(b'0'..=b'7').contains(&c))
	{
		return false;
	}
	let sum = atol(f) as i32;
	let fold = |b: &dyn Fn(u8) -> i32| -> i32 {
		let head: i32 = h[..148].iter().map(|&c| b(c)).sum();
		let tail: i32 = h[156..].iter().map(|&c| b(c)).sum();
		head + 8 * 32 + tail
	};
	sum == fold(&|c| i32::from(c)) || sum == fold(&|c| i32::from(c as i8))
}

// validate_number_field
fn number_field_ok(f: &[u8]) -> bool {
	if matches!(f[0], 128 | 255 | 0) {
		return true;
	}
	let mut i = f.iter().take_while(|&&c| c == b' ').count();
	i += f[i..]
		.iter()
		.take_while(|c| (b'0'..=b'7').contains(c))
		.count();
	f[i..].iter().all(|&c| c == b' ' || c == 0)
}

// archive_read_format_tar_bid on a header block
fn bid(h: &[u8; 512]) -> i32 {
	if h[0] == 0 && is_null(h) {
		return 10;
	}
	if !checksum(h) {
		return 0;
	}
	let mut bid = 48;
	let (magic, version) = (&h[257..263], &h[263..265]);
	if magic == b"ustar\0" && version == b"00" {
		bid += 56;
	}
	if magic == b"ustar " && version == b" \0" {
		bid += 56;
	}
	let t = h[156];
	if t != 0 && !t.is_ascii_alphanumeric() {
		return 0;
	}
	bid += 2;
	let fields = [MODE, UID, GID, MTIME, SIZE, RDEVMAJOR, RDEVMINOR];
	if !fields.iter().all(|f| number_field_ok(field(h, f.0, f.1))) {
		bid = 0;
	}
	bid
}

// pax_time: seconds and nanoseconds of a decimal time, seconds
// i64::MIN when malformed. a '-' applies to the seconds only
fn pax_time(p: &[u8]) -> (i64, i64) {
	if p.is_empty() {
		return (0, 0);
	}
	let bad = (i64::MIN, 0);
	let (sign, mut p) = match p[0] {
		b'-' => (-1, &p[1..]),
		_ => (1, p),
	};
	let mut s: i64 = 0;
	while let Some(&c) = p.first().filter(|c| c.is_ascii_digit()) {
		let next = s
			.checked_mul(10)
			.and_then(|s| s.checked_add(i64::from(c - b'0')));
		let Some(next) = next else { return bad };
		s = next;
		p = &p[1..];
	}
	let s = s * sign;
	if p.is_empty() {
		return (s, 0);
	}
	if p[0] != b'.' {
		return bad;
	}
	p = &p[1..];
	let mut n: i64 = 0;
	let mut l = 100_000_000;
	while l > 0 {
		let Some(&c) = p.first() else {
			return (s, n);
		};
		if !c.is_ascii_digit() {
			return bad;
		}
		n += i64::from(c - b'0') * l;
		p = &p[1..];
		l /= 10;
	}
	// resolution past nanoseconds is dropped, but must be digits
	match p.iter().all(u8::is_ascii_digit) {
		true => (s, n),
		false => bad,
	}
}

// _utf8_to_unicode: the bytes of the sequence at s[0], negative for an
// invalid one (U+FFFD in its place), 0 at the end
fn utf8_to_unicode(s: &[u8]) -> (i32, u32) {
	const R: u32 = 0xfffd;
	let Some(&ch) = s.first() else { return (0, 0) };
	if ch == 0 {
		return (0, 0);
	}
	let cnt: usize = match ch {
		0x00..=0x7f => 1,
		0xc2..=0xdf => 2,
		0xe0..=0xef => 3,
		0xf0..=0xf4 => 4,
		_ => 0,
	};
	let cont = |i: usize| s[i] & 0xc0 == 0x80;
	let bad = |n: usize| (-(n as i32), R);
	if cnt == 0 {
		let mut n = match ch {
			0xc0 | 0xc1 => 2,
			0xf5..=0xf7 => 4,
			0xf8..=0xfb => 5,
			0xfc | 0xfd => 6,
			_ => 1,
		};
		n = n.min(s.len());
		let n = (1..n).find(|&i| !cont(i)).unwrap_or(n);
		return bad(n);
	}
	if s.len() < cnt {
		let n = (1..s.len()).find(|&i| !cont(i)).unwrap_or(s.len());
		return bad(n);
	}
	if let Some(i) = (1..cnt).find(|&i| !cont(i)) {
		return bad(i);
	}
	let c = |i: usize| u32::from(s[i] & 0x3f);
	let ch = u32::from(ch);
	let wc = match cnt {
		1 => return (1, ch & 0x7f),
		2 => return (2, ((ch & 0x1f) << 6) | c(1)),
		3 => ((ch & 0x0f) << 12) | (c(1) << 6) | c(2),
		_ => ((ch & 0x07) << 18) | (c(1) << 12) | (c(2) << 6) | c(3),
	};
	// overlong, or past U+10FFFF
	if (cnt == 3 && wc < 0x800) || (cnt == 4 && wc < 0x10000) {
		return bad(cnt);
	}
	if wc > 0x10ffff {
		return bad(cnt);
	}
	(cnt as i32, wc)
}

// cesu8_to_unicode: a surrogate pair in two 3-byte sequences is one code
// point, a lone surrogate is invalid
fn cesu8_to_unicode(s: &[u8]) -> (i32, u32) {
	let (cnt, wc) = utf8_to_unicode(s);
	let high = (0xd800..=0xdbff).contains(&wc);
	let low = (0xdc00..=0xdfff).contains(&wc);
	if cnt == 3 && high {
		if s.len() - 3 < 3 {
			return (-3, 0xfffd);
		}
		let (cnt2, wc2) = utf8_to_unicode(&s[3..]);
		if cnt2 != 3 || !(0xdc00..=0xdfff).contains(&wc2) {
			return (-3, 0xfffd);
		}
		let uc = (wc - 0xd800) * 0x400 + (wc2 - 0xdc00) + 0x10000;
		return (6, uc);
	}
	if cnt == 3 && low {
		return (-3, 0xfffd);
	}
	(cnt, wc)
}

// archive_strncat_l from UTF-8 into the UTF-8 locale: the text up to its
// first nul, a joined surrogate pair rewritten as one sequence. None
// when a sequence is invalid (the C's -1)
fn from_utf8(s: &[u8]) -> Option<Vec<u8>> {
	let mut s = until_nul(s);
	let mut out = Vec::with_capacity(s.len());
	while !s.is_empty() {
		let (n, uc) = cesu8_to_unicode(s);
		if n <= 0 {
			return None;
		}
		match n {
			6 => out.extend_from_slice(
				char::from_u32(uc)?
					.encode_utf8(&mut [0; 4])
					.as_bytes(),
			),
			_ => out.extend_from_slice(&s[..n as usize]),
		}
		s = &s[n as usize..];
	}
	Some(out)
}

// url_decode: %XX escapes, up to the first nul
fn url_decode(s: &[u8]) -> Vec<u8> {
	let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
	let s = until_nul(s);
	let mut out = Vec::new();
	let mut i = 0;
	while i < s.len() {
		if s[i] == b'%'
			&& s.len() - i > 2 && let (Some(a), Some(b)) =
			(hex(s[i + 1]), hex(s[i + 2]))
		{
			out.push((a << 4) | b);
			i += 3;
			continue;
		}
		out.push(s[i]);
		i += 1;
	}
	out
}

// the tar reader's base64_decode: illegal bytes skipped, '=' or '_' ends
fn base64_decode(s: &[u8]) -> Vec<u8> {
	let decode = |c: u8| -> Option<u32> {
		match c {
			b'A'..=b'Z' => Some(u32::from(c - b'A')),
			b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
			b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
			b'+' => Some(62),
			b'/' => Some(63),
			_ => None,
		}
	};
	let mut out = Vec::new();
	let mut i = 0;
	let mut done = false;
	while i < s.len() && !done {
		let (mut v, mut group) = (0u32, 0);
		while group < 4 && i < s.len() {
			if s[i] == b'=' || s[i] == b'_' {
				done = true;
				break;
			}
			let Some(d) = decode(s[i]) else {
				i += 1;
				continue;
			};
			v = (v << 6) | d;
			i += 1;
			group += 1;
		}
		v <<= 6 * (4 - group);
		let bytes = [(v >> 16) as u8, (v >> 8) as u8, v as u8];
		out.extend_from_slice(&bytes[..group * 3 / 4]);
	}
	out
}

// ---- archive_acl.c: archive_acl_from_text_nl ----

// next_field: the field from *p, blanks around it skipped; its separator
// (':', ',', '\n' or 0 at the end), a '#' comment skipped to the next ','
// or '\n'
fn next_field(t: &[u8], p: &mut usize) -> (usize, usize, u8) {
	while *p < t.len() && matches!(t[*p], b' ' | b'\t' | b'\n') {
		*p += 1;
	}
	let start = *p;
	while *p < t.len()
		&& !matches!(t[*p], b' ' | b'\t' | b'\n' | b',' | b':' | b'#')
	{
		*p += 1;
	}
	let end = *p;
	while *p < t.len() && !matches!(t[*p], b',' | b':' | b'\n' | b'#') {
		*p += 1;
	}
	let mut sep = t.get(*p).copied().unwrap_or(0);
	if sep == b'#' {
		while *p < t.len() && !matches!(t[*p], b',' | b'\n') {
			*p += 1;
		}
		sep = t.get(*p).copied().unwrap_or(0);
	}
	if *p < t.len() {
		*p += 1;
	}
	(start, end, sep)
}

type Span = Option<(usize, usize)>;

fn span(t: &[u8], f: Span) -> &[u8] {
	f.map_or(&[][..], |(s, e)| &t[s..e])
}

// isint: 1 for a decimal number (into id), 0 for anything else, -1 past
// INT_MAX
fn isint(t: &[u8], f: Span, id: &mut i32) -> i32 {
	let s = span(t, f);
	if s.is_empty() {
		return 0;
	}
	let mut n: i32 = 0;
	for &c in s {
		if !c.is_ascii_digit() {
			return 0;
		}
		let d = i32::from(c - b'0');
		if n > i32::MAX / 10
			|| (n == i32::MAX / 10 && d >= i32::MAX % 10)
		{
			return -1;
		}
		n = n * 10 + d;
	}
	*id = n;
	1
}

// ismode: rwx and '-'. permset is reset first and keeps what a bad
// field set before failing
fn ismode(t: &[u8], f: Span, permset: &mut i32) -> bool {
	let s = span(t, f);
	if s.is_empty() {
		return false;
	}
	*permset = 0;
	for &c in s {
		match c {
			b'r' | b'R' => *permset |= ACL_READ,
			b'w' | b'W' => *permset |= ACL_WRITE,
			b'x' | b'X' => *permset |= ACL_EXECUTE,
			b'-' => {}
			_ => return false,
		}
	}
	true
}

// is_nfs4_perms and is_nfs4_flags, which only check the characters: the
// bits they set never make acl_new_entry refuse
fn nfs4_chars(t: &[u8], f: Span, set: &[u8]) -> bool {
	span(t, f).iter().all(|c| set.contains(c))
}

// archive_acl_add_entry_len_l on the ACL of ae: the owner, group and
// other entries of an access ACL go to the mode (acl_special); others are
// refused when NFSv4 and POSIX.1e types mix. a name is converted like a
// pax string
fn acl_add(ae: &mut Ae, typ: i32, permset: i32, tag: i32, name: &[u8]) -> i32 {
	if typ == ACL_TYPE_ACCESS && permset & !0o7 == 0 {
		let p = (permset & 7) as u32;
		let (mask, shift) = match tag {
			ACL_USER_OBJ => (0o700, 6),
			ACL_GROUP_OBJ => (0o070, 3),
			ACL_OTHER => (0o007, 0),
			_ => (0, 0),
		};
		if mask != 0 {
			ae.mode = (ae.mode & !mask) | (p << shift);
			return OK;
		}
	}
	let other = match typ & ACL_TYPE_NFS4 != 0 {
		true => !ACL_TYPE_NFS4,
		false => !ACL_TYPE_POSIX1E,
	};
	if ae.acl_types & other != 0 {
		return FAILED;
	}
	ae.acl_types |= typ;
	if name.first().is_some_and(|&c| c != 0) && from_utf8(name).is_none() {
		return WARN;
	}
	OK
}

// archive_acl_from_text_nl for want (POSIX.1e access/default or NFSv4):
// ARCHIVE_WARN when an entry is skipped or a name cannot be converted
fn acl_from_text(ae: &mut Ae, t: &[u8], want: i32) -> i32 {
	let numfields = match want {
		ACL_TYPE_NFS4 => 6,
		_ => 5,
	};
	let mut ret = OK;
	let mut p = 0;
	while p < t.len() && t[p] != 0 {
		let mut f: [Span; 6] = [None; 6];
		let mut fields = 0;
		loop {
			let (s, e, sep) = next_field(t, &mut p);
			if fields < numfields {
				f[fields] = Some((s, e));
			}
			fields += 1;
			if sep != b':' {
				break;
			}
		}
		let (f0, _) = f[0].unwrap_or_default();
		if f0 == t.len() {
			// nothing but separators or blanks left
			ret = WARN;
			continue;
		}
		if t[f0] == b'#' {
			continue;
		}
		let r = match want {
			ACL_TYPE_NFS4 => acl_nfs4_entry(ae, t, &f),
			_ => acl_posix_entry(ae, t, &mut f, fields, want),
		};
		match r {
			Some(r) if r < WARN => return r,
			Some(OK) => {}
			_ => ret = WARN,
		}
	}
	ret
}

// one POSIX.1e entry: None when it is skipped
fn acl_posix_entry(
	ae: &mut Ae,
	t: &[u8],
	f: &mut [Span; 6],
	fields: usize,
	want: i32,
) -> Option<i32> {
	let mut n = 0;
	let (mut sol, mut id, mut permset) = (0, -1, 0);
	let (s0, e0) = f[0]?;
	let len = e0 - s0;
	let typ = if t[s0] == b'd'
		&& (len == 1 || (len >= 7 && &t[s0 + 1..s0 + 7] == b"efault"))
	{
		if len > 7 {
			f[0] = Some((s0 + 7, e0));
		} else {
			n = 1;
		}
		ACL_TYPE_DEFAULT
	} else {
		want
	};
	if isint(t, f[n + 1], &mut id) < 0 {
		return None;
	}
	if id == -1 && fields > n + 3 && isint(t, f[n + 3], &mut id) < 0 {
		return None;
	}
	let s = span(t, f[n]);
	if s.is_empty() {
		return None;
	}
	let word = |w: &[u8]| s.len() == 1 || s == w;
	let mut tag = match s[0] {
		b'u' if word(b"user") => ACL_USER_OBJ,
		b'g' if word(b"group") => ACL_GROUP_OBJ,
		b'o' if word(b"other") => ACL_OTHER,
		b'm' if word(b"mask") => ACL_MASK,
		_ => 0,
	};
	let next = f[n + 1].filter(|(s, e)| s < e);
	let mut name = None;
	match tag {
		ACL_OTHER | ACL_MASK => {
			if fields == n + 2
				&& next.is_some() && ismode(
				t,
				f[n + 1],
				&mut permset,
			) {
				// Solaris-style "other:rwx"
				sol = 1;
			} else if fields == n + 3 && next.is_some() {
				return None;
			}
		}
		ACL_USER_OBJ | ACL_GROUP_OBJ => {
			if id != -1 || next.is_some() {
				name = f[n + 1];
				tag = match tag {
					ACL_USER_OBJ => ACL_USER,
					_ => ACL_GROUP,
				};
			}
		}
		_ => return None,
	}
	if permset == 0 && !ismode(t, f[n + 2 - sol], &mut permset) {
		return None;
	}
	Some(acl_add(ae, typ, permset, tag, span(t, name)))
}

// one NFSv4 entry: None when it is skipped
fn acl_nfs4_entry(ae: &mut Ae, t: &[u8], f: &[Span; 6]) -> Option<i32> {
	let mut id = -1;
	let tag = match span(t, f[0]) {
		b"user" => ACL_USER,
		b"group" => ACL_GROUP,
		b"owner@" => ACL_USER_OBJ,
		b"group@" => ACL_GROUP_OBJ,
		b"everyone@" => ACL_EVERYONE,
		_ => return None,
	};
	let (n, name) = match tag {
		ACL_USER | ACL_GROUP => {
			if isint(t, f[1], &mut id) < 0 {
				return None;
			}
			(1, f[1])
		}
		_ => (0, None),
	};
	if !nfs4_chars(t, f[1 + n], b"rwxpDdaARWcCos-") {
		return None;
	}
	if !nfs4_chars(t, f[2 + n], b"fdinSFI-") {
		return None;
	}
	let typ = match span(t, f[3 + n]) {
		b"deny" => ACL_TYPE_DENY,
		b"allow" => ACL_TYPE_ALLOW,
		b"audit" => ACL_TYPE_AUDIT,
		b"alarm" => ACL_TYPE_ALARM,
		_ => return None,
	};
	if isint(t, f[4 + n], &mut id) < 0 {
		return None;
	}
	// NFSv4 types are never part of the mode, the bits do not matter
	Some(acl_add(ae, typ, 0, tag, span(t, name)))
}

// ---- headers ----

// one archive_read_next_header: the stream, the format state, the entry
// being filled, the bytes to consume before the next read, the last
// archive_set_error text
struct Hdr<'a> {
	src: &'a mut Src,
	tar: &'a mut Tar,
	ae: Ae,
	unconsumed: u64,
	error: Option<Vec<u8>>,
}

fn combine(a: i32, b: i32) -> i32 {
	a.min(b)
}

impl Hdr<'_> {
	fn set_error(&mut self, msg: impl Into<Vec<u8>>) {
		self.error = Some(msg.into());
	}

	// __archive_read_consume with the filter's text when it falls short
	fn consume(&mut self, n: u64) -> bool {
		match self.src.consume(n) {
			Ok(()) => true,
			Err(got) => {
				self.set_error(truncated_input(n, got));
				false
			}
		}
	}

	// tar_flush_unconsumed
	fn flush(&mut self) -> i32 {
		if self.unconsumed == 0 {
			return OK;
		}
		if !self.consume(self.unconsumed) {
			return FATAL;
		}
		self.unconsumed = 0;
		OK
	}

	// read_bytes_to_string
	fn read_bytes(&mut self, size: usize) -> Result<Vec<u8>, i32> {
		if self.flush() != OK {
			return Err(FATAL);
		}
		let Some(v) = self.src.peek(size) else {
			self.set_error(
				"Truncated archive detected while reading metadata",
			);
			self.unconsumed = 0;
			return Err(FATAL);
		};
		self.unconsumed += size as u64;
		Ok(v)
	}

	// read_body_to_string: the body of a 'K', 'L' or 'A' header. a body
	// past 1 MiB is skipped and comes back empty with ARCHIVE_WARN
	fn read_body(&mut self, h: &[u8; 512]) -> (i32, Vec<u8>) {
		let size = num(h, SIZE);
		if !(0..=ENTRY_LIMIT).contains(&size) {
			let msg = format!(
				"Special header has invalid size: {size}"
			);
			self.set_error(msg);
			return (FATAL, Vec::new());
		}
		if size > PATHNAME_LIMIT as i64 {
			let to_consume = (size + 511) & !511;
			if !self.consume(to_consume as u64) {
				return (FATAL, Vec::new());
			}
			let msg = format!(
				"Special header too large: {size} > 1MiB"
			);
			self.set_error(msg);
			return (WARN, Vec::new());
		}
		let r = self.read_bytes(size as usize);
		self.unconsumed += (0x1ff & -size) as u64;
		match r {
			Ok(v) => (OK, v),
			Err(e) => (e, Vec::new()),
		}
	}

	// tar_read_header: the extension headers up to the regular one
	fn read_header(&mut self) -> i32 {
		let mut err = OK;
		let mut eof_fatal = false;
		let mut seen: u32 = 0;
		self.tar.reset_header_state();
		loop {
			let h = match self.next_block(eof_fatal) {
				Ok(h) => h,
				Err(r) => return r,
			};
			let flag = h[156];
			let err2 = match flag {
				b'A' => {
					if seen & SEEN_A != 0 {
						self.set_error(
							"Redundant 'A' header",
						);
						return FATAL;
					}
					seen |= SEEN_A;
					self.tar.format = Format::Pax;
					self.header_solaris_acl(&h)
				}
				b'g' => {
					if seen & SEEN_G != 0 {
						self.set_error(
							"Redundant 'g' header",
						);
						return FATAL;
					}
					seen |= SEEN_G;
					self.tar.format = Format::Pax;
					self.header_pax_global(&h)
				}
				b'K' | b'L' => {
					let (bit, what) = match flag {
						b'K' => (
							SEEN_K,
							"'K' headers may cause linknames",
						),
						_ => (
							SEEN_L,
							"'L' headers may cause filenames",
						),
					};
					if seen & bit != 0 {
						self.set_error(format!(
							"Damaged archive: Redundant {what} \
							 to be incorrect"
						));
						err = combine(err, WARN);
					}
					seen |= bit;
					self.tar.format = Format::Gnu;
					self.header_gnu_long(&h, flag)
				}
				b'V' => {
					if seen & SEEN_V != 0 {
						self.set_error(
							"Redundant 'V' header",
						);
						err = combine(err, WARN);
					}
					seen |= SEEN_V;
					self.tar.format = Format::Gnu;
					self.header_volume(&h)
				}
				b'X' | b'x' => {
					if seen & SEEN_X != 0 {
						self.set_error(match flag {
							b'X' => {
								"Redundant 'X'/'x' header"
							}
							_ => {
								"Redundant 'x' header"
							}
						});
						return FATAL;
					}
					seen |= SEEN_X;
					self.tar.format = Format::Pax;
					self.header_pax_extension(&h)
				}
				_ => {
					let err2 = self.header_regular(&h);
					err = combine(err, err2);
					if err < WARN {
						return FATAL;
					}
					return self.reconcile_sparse(err);
				}
			};
			err = combine(err, err2);
			if err == FATAL {
				return err;
			}
			// a lone 'V' or 'g' header may end the archive
			if seen & !SEEN_V & !SEEN_G != 0 {
				eof_fatal = true;
			}
		}
	}

	// the next valid header block, consumed through unconsumed; Err with
	// the result that ends the header
	fn next_block(&mut self, eof_fatal: bool) -> Result<[u8; 512], i32> {
		if self.flush() != OK {
			return Err(FATAL);
		}
		let h = match self.src.block_ahead() {
			Ok(h) => h,
			Err(Short::End(0)) if eof_fatal => {
				self.set_error(
					"Damaged tar archive (end-of-archive \
					 within a sequence of headers)",
				);
				return Err(FATAL);
			}
			Err(Short::End(0)) => return Err(EOF),
			Err(_) => {
				self.set_error(
					"Truncated tar archive detected while \
					 reading next header",
				);
				return Err(FATAL);
			}
		};
		self.unconsumed += 512;
		if h[0] == 0 && is_null(&h) {
			// the end mark; a second null block is taken too
			self.flush();
			if self.src.peek(512).is_some_and(|b| is_null(&b)) {
				let _ = self.src.consume(512);
			}
			self.error = None;
			return Err(EOF);
		}
		if !checksum(&h) {
			if self.flush() != OK {
				return Err(FATAL);
			}
			self.set_error(
				"Damaged tar archive (bad header checksum)",
			);
			return Err(if eof_fatal { FATAL } else { RETRY });
		}
		Ok(h)
	}

	// the default branch: GNU, ustar or old-style header
	fn header_regular(&mut self, h: &[u8; 512]) -> i32 {
		if &h[257..265] == b"ustar  \0" {
			self.tar.format = Format::Gnu;
			self.header_gnutar(h)
		} else if &h[257..262] == b"ustar" {
			if self.tar.format != Format::Pax {
				self.tar.format = Format::Ustar;
			}
			self.header_ustar(h)
		} else {
			self.tar.format = Format::Tar;
			self.header_old_tar(h)
		}
	}

	// the GNU sparse attributes against the entry type; format 1.0 has
	// its map ahead of the data
	fn reconcile_sparse(&mut self, err: i32) -> i32 {
		if !self.tar.sparse_gnu_attributes_seen {
			return err;
		}
		if !matches!(self.tar.filetype, b'S' | b'0') {
			self.set_error("Non-regular file cannot be sparse");
			return WARN;
		}
		match (self.tar.sparse_gnu_major, self.tar.sparse_gnu_minor) {
			(0, 0) | (0, 1) => err,
			(1, 0) => {
				let n = self.gnu_sparse_10_read();
				if n < 0 {
					return n as i32;
				}
				self.tar.entry_bytes_remaining -= n;
				err
			}
			_ => {
				self.set_error(
					"Unrecognized GNU sparse file format",
				);
				WARN
			}
		}
	}

	fn path_unset(&self) -> bool {
		self.ae.path.as_ref().is_none_or(|p| p.is_empty())
	}

	// header_common: the fields of every variant, after the extension
	// headers had their say
	fn header_common(&mut self, h: &[u8; 512]) -> i32 {
		let header_mode = num(h, MODE) as u32;
		self.ae.set_filetype(header_mode);
		if !self.ae.perm_set {
			self.ae.set_perm(header_mode);
		}
		if self.ae.uid.is_none() {
			self.ae.uid = Some(num(h, UID).max(0));
		}
		if self.ae.gid.is_none() {
			self.ae.gid = Some(num(h, GID).max(0));
		}
		if self.ae.mtime.is_none() {
			self.ae.mtime = Some((num(h, MTIME), 0));
		}
		let t = &mut *self.tar;
		let fields = t.size_fields;
		t.disk_size = if fields & SIZE_GNU_SPARSE_REALSIZE != 0 {
			t.gnu_sparse_realsize
		} else if fields & SIZE_GNU_SPARSE_SIZE != 0
			&& t.sparse_gnu_major == 0
		{
			t.gnu_sparse_size
		} else if fields & SIZE_SCHILY_SPARSE_REALSIZE != 0 {
			t.schily_sparse_realsize
		} else if fields & SIZE_PAX_SIZE != 0 {
			t.pax_size
		} else {
			num(h, SIZE)
		};
		if t.disk_size < 0 {
			self.set_error("Tar entry has negative file size");
			return FATAL;
		}
		if t.disk_size > ENTRY_LIMIT {
			self.set_error("Tar entry size overflow");
			return FATAL;
		}
		self.ae.set_size(t.disk_size);
		t.entry_bytes_remaining = if fields & SIZE_GNU_SPARSE_SIZE != 0
			&& t.sparse_gnu_major == 1
		{
			t.gnu_sparse_size
		} else if fields & SIZE_PAX_SIZE != 0 {
			t.pax_size
		} else {
			num(h, SIZE)
		};
		if t.entry_bytes_remaining < 0 {
			t.entry_bytes_remaining = 0;
			self.set_error("Tar entry has negative size");
			return FATAL;
		}
		if t.entry_bytes_remaining > ENTRY_LIMIT {
			t.entry_bytes_remaining = 0;
			self.set_error("Tar entry size overflow");
			return FATAL;
		}
		t.filetype = h[156];
		let linkname = until_nul(field(h, LINKNAME.0, LINKNAME.1));
		match t.filetype {
			b'1' => {
				self.ae.symlink = false;
				self.ae.hardlink = true;
				if self.ae
					.hardlink()
					.is_none_or(|l| l.is_empty())
				{
					self.ae.link = Some(linkname.to_vec());
				}
				let size = self.ae.size.unwrap_or(0);
				if size > 0 {
					self.ae.set_filetype(S_IFREG);
				}
				// tar readers ignore a hard link's size, pax may give
				// it data. the bid looks at the read position, which
				// is still this header
				let ignore = size > 0
					&& match t.format {
						Format::Pax => false,
						Format::Tar | Format::Gnu => {
							true
						}
						Format::Ustar => bid(h) > 50,
					};
				if ignore {
					self.ae.set_size(0);
					t.entry_bytes_remaining = 0;
				}
			}
			b'2' => {
				self.ae.hardlink = false;
				self.ae.symlink = true;
				if self.ae
					.symlink()
					.is_none_or(|l| l.is_empty())
				{
					self.ae.link = Some(linkname.to_vec());
				}
				no_data(&mut self.ae, t, S_IFLNK);
			}
			b'3' => no_data(&mut self.ae, t, S_IFCHR),
			b'4' => no_data(&mut self.ae, t, S_IFBLK),
			b'5' => no_data(&mut self.ae, t, S_IFDIR),
			b'6' => no_data(&mut self.ae, t, S_IFIFO),
			b'D' => self.ae.set_filetype(S_IFDIR),
			// remainder of a file from the last volume: the header's type
			b'M' => {}
			_ => self.ae.set_filetype(S_IFREG),
		}
		OK
	}

	// device numbers for char and block specials, 0 for the rest
	fn header_rdev(&mut self, h: &[u8; 512]) {
		match h[156] {
			b'3' | b'4' => {
				if self.ae.rdev.is_none() {
					let major = num(h, RDEVMAJOR) as u64;
					let minor = num(h, RDEVMINOR) as u64;
					self.ae.rdev = Some((major, minor));
				}
			}
			_ => self.ae.rdev = Some((0, 0)),
		}
	}

	fn padding(&mut self) {
		self.tar.entry_padding =
			0x1ff & -self.tar.entry_bytes_remaining;
	}

	fn header_old_tar(&mut self, h: &[u8; 512]) -> i32 {
		if self.path_unset() {
			let name = until_nul(field(h, NAME.0, NAME.1));
			self.ae.path = Some(name.to_vec());
		}
		let err = self.header_common(h);
		self.padding();
		err
	}

	fn header_ustar(&mut self, h: &[u8; 512]) -> i32 {
		if self.path_unset() {
			let name = until_nul(field(h, NAME.0, NAME.1));
			let prefix = until_nul(field(h, PREFIX.0, PREFIX.1));
			let mut path = Vec::new();
			if h[PREFIX.0] != 0 {
				path.extend_from_slice(prefix);
				if path.last() != Some(&b'/') {
					path.push(b'/');
				}
			}
			path.extend_from_slice(name);
			self.ae.path = Some(path);
		}
		let err = self.header_common(h);
		if err == FATAL {
			return err;
		}
		self.header_rdev(h);
		self.padding();
		err
	}

	fn header_gnutar(&mut self, h: &[u8; 512]) -> i32 {
		if self.path_unset() {
			let name = until_nul(field(h, NAME.0, NAME.1));
			self.ae.path = Some(name.to_vec());
		}
		self.header_rdev(h);
		if self.ae.atime.is_none() {
			let t = num(h, GNU_ATIME);
			if t > 0 {
				self.ae.atime = Some((t, 0));
			}
		}
		if self.ae.ctime.is_none() {
			let t = num(h, GNU_CTIME);
			if t > 0 {
				self.ae.ctime = Some((t, 0));
			}
		}
		if h[GNU_REALSIZE.0] != 0 {
			self.tar.gnu_sparse_realsize = num(h, GNU_REALSIZE);
			self.tar.size_fields |= SIZE_GNU_SPARSE_REALSIZE;
		}
		if h[GNU_SPARSE] != 0 && self.gnu_sparse_old_read(h) != OK {
			return FATAL;
		}
		let err = self.header_common(h);
		if err == FATAL {
			return err;
		}
		self.padding();
		err
	}

	// the old GNU sparse map: four slots in the header, 21 in each
	// extension block that follows while isextended is set
	fn gnu_sparse_old_read(&mut self, h: &[u8; 512]) -> i32 {
		if self.gnu_sparse_old_parse(&h[GNU_SPARSE..], 4) != OK {
			return FATAL;
		}
		if h[GNU_ISEXTENDED] == 0 {
			return OK;
		}
		loop {
			if self.flush() != OK {
				return FATAL;
			}
			let Some(ext) = self.src.peek(512) else {
				self.set_error(
					"Truncated tar archive detected while \
					 reading sparse file data",
				);
				return FATAL;
			};
			self.unconsumed = 512;
			if self.gnu_sparse_old_parse(&ext, 21) != OK {
				return FATAL;
			}
			if ext[504] == 0 {
				return OK;
			}
		}
	}

	fn gnu_sparse_old_parse(&mut self, slots: &[u8], n: usize) -> i32 {
		for s in slots.chunks(24).take(n) {
			if s[0] == 0 {
				break;
			}
			let (offset, size) = (atol(&s[..12]), atol(&s[12..24]));
			if self.add_sparse(offset, size) != OK {
				return FATAL;
			}
		}
		OK
	}

	// gnu_add_sparse_entry
	fn add_sparse(&mut self, offset: i64, remaining: i64) -> i32 {
		if remaining < 0 || offset < 0 || offset > i64::MAX - remaining
		{
			self.set_error("Malformed sparse map data");
			return FATAL;
		}
		let b = Block {
			offset,
			remaining,
			hole: false,
		};
		self.tar.sparse.push_back(b);
		OK
	}

	// readline, for the sparse 1.0 map: a line up to limit bytes
	fn readline(&mut self, limit: usize) -> Result<Vec<u8>, i32> {
		if self.flush() != OK {
			return Err(FATAL);
		}
		let mut line = Vec::new();
		loop {
			let t = match self.src.ahead(1) {
				Ok(t) => t.to_vec(),
				Err(_) => return Err(FATAL),
			};
			let nl = t.iter().position(|&c| c == b'\n');
			let n = nl.map_or(t.len(), |i| i + 1);
			if line.len() + n > limit {
				self.set_error("Line too long");
				return Err(FATAL);
			}
			line.extend_from_slice(&t[..n]);
			self.unconsumed = n as u64;
			if nl.is_some() {
				return Ok(line);
			}
			self.flush();
		}
	}

	// gnu_sparse_10_atol: the next line not starting with '#' as a
	// decimal number ended by '\n', negative when malformed
	fn gnu_sparse_10_atol(&mut self, remaining: &mut i64) -> i64 {
		let line = loop {
			let limit = (*remaining).clamp(0, 100) as usize;
			let Ok(line) = self.readline(limit) else {
				return i64::from(FATAL);
			};
			if line.is_empty() {
				return i64::from(FATAL);
			}
			*remaining -= line.len() as i64;
			if line[0] != b'#' {
				break line;
			}
		};
		let mut l: i64 = 0;
		for &c in &line {
			if c == b'\n' {
				return l;
			}
			if !c.is_ascii_digit() {
				return i64::from(WARN);
			}
			l = l.checked_mul(10)
				.and_then(|l| {
					l.checked_add(i64::from(c - b'0'))
				})
				.unwrap_or(i64::MAX);
		}
		i64::from(WARN)
	}

	// gnu_sparse_10_read: the map ahead of the data, padded to 512;
	// its length, negative on failure
	fn gnu_sparse_10_read(&mut self) -> i64 {
		self.tar.sparse.clear();
		let mut remaining = self.tar.entry_bytes_remaining;
		let entries = self.gnu_sparse_10_atol(&mut remaining);
		if entries < 0 {
			return i64::from(FATAL);
		}
		for _ in 0..entries {
			let offset = self.gnu_sparse_10_atol(&mut remaining);
			if offset < 0 {
				return i64::from(FATAL);
			}
			let size = self.gnu_sparse_10_atol(&mut remaining);
			if size < 0 {
				return i64::from(FATAL);
			}
			if self.add_sparse(offset, size) != OK {
				return i64::from(FATAL);
			}
		}
		if self.flush() != OK {
			return i64::from(FATAL);
		}
		let bytes_read = self.tar.entry_bytes_remaining - remaining;
		let to_skip = 0x1ff & -bytes_read;
		if to_skip > remaining || !self.consume(to_skip as u64) {
			return i64::from(FATAL);
		}
		bytes_read + to_skip
	}

	// 'K' long link name or 'L' long file name
	fn header_gnu_long(&mut self, h: &[u8; 512], flag: u8) -> i32 {
		let (err, body) = self.read_body(h);
		if err == OK {
			match flag {
				b'K' => self.ae.copy_link(&body),
				_ => {
					self.ae.path =
						Some(until_nul(&body).to_vec())
				}
			}
		}
		err
	}

	fn header_volume(&mut self, h: &[u8; 512]) -> i32 {
		let size = num(h, SIZE);
		if !(0..=PATHNAME_LIMIT as i64).contains(&size) {
			return FATAL;
		}
		self.unconsumed += ((size + 511) & !511) as u64;
		OK
	}

	fn header_pax_global(&mut self, h: &[u8; 512]) -> i32 {
		let size = num(h, SIZE);
		if !(0..=ENTRY_LIMIT).contains(&size) {
			let msg = format!(
				"Special header has invalid size: {size}"
			);
			self.set_error(msg);
			return FATAL;
		}
		if size == 0 {
			self.set_error(
				"Invalid empty pax global extended header",
			);
			return FATAL;
		}
		self.unconsumed += ((size + 511) & !511) as u64;
		OK
	}

	// 'A': Solaris tar ACL, an octal type then the text
	fn header_solaris_acl(&mut self, h: &[u8; 512]) -> i32 {
		let (err, text) = self.read_body(h);
		if err != OK {
			return err;
		}
		let mut p = 0;
		let mut typ: u64 = 0;
		let fail = |s: &mut Self, why: &str| {
			let msg = format!(
				"Malformed Solaris ACL attribute ({why})"
			);
			s.set_error(msg);
			WARN
		};
		while p < text.len() && text[p] != 0 {
			let c = text[p];
			if !(b'0'..=b'7').contains(&c) {
				return fail(self, "invalid digit");
			}
			typ = (typ << 3) + u64::from(c - b'0');
			if typ > 0o77777777 {
				return fail(self, "count too large");
			}
			p += 1;
		}
		let acl_type = match typ & !0o777777 {
			0o1000000 => ACL_TYPE_ACCESS,
			0o3000000 => ACL_TYPE_NFS4,
			_ => {
				return fail(
					self,
					&format!("unsupported type {typ}"),
				);
			}
		};
		p += 1;
		if p >= text.len() {
			return fail(self, "body overflow");
		}
		let acl = until_nul(&text[p..]).to_vec();
		let err = acl_from_text(&mut self.ae, &acl, acl_type);
		// perm_is_set forced, the ACL holds the mode
		let perm = self.ae.mode;
		self.ae.set_perm(perm);
		if err != OK {
			let _ = fail(self, "unparsable");
		}
		err
	}

	// header_pax_extension: the records of an 'x' header, then the
	// strings converted by hdrcharset
	fn header_pax_extension(&mut self, h: &[u8; 512]) -> i32 {
		const EXT_SIZE_LIMIT: i64 = 1 << 30;
		const MAX_LINE: usize = 99999999;
		const MAX_SIZE_NAME: i64 = 512;
		let mut ext_size = num(h, SIZE);
		if ext_size > ENTRY_LIMIT {
			return FATAL;
		}
		if ext_size < 0 {
			self.set_error(format!(
				"pax extension header has invalid size: {ext_size}"
			));
			return FATAL;
		}
		if ext_size == 0 {
			self.set_error("Invalid empty pax extended header");
			return FATAL;
		}
		let ext_padding = 0x1ff & -ext_size;
		if ext_size > EXT_SIZE_LIMIT {
			if !self.consume((ext_size + ext_padding) as u64) {
				return FATAL;
			}
			self.set_error(format!(
				"Ignoring oversized pax extensions: \
				 {ext_size} > {EXT_SIZE_LIMIT}"
			));
			return WARN;
		}
		if self.flush() != OK {
			return FATAL;
		}
		let mut err = OK;
		while ext_size > 0 {
			// the size and name of the next record
			let to_read = MAX_SIZE_NAME.min(ext_size) as usize;
			let win = match self.src.ahead(to_read) {
				Ok(d) => d.to_vec(),
				Err(_) => {
					self.set_error(
						"Truncated tar archive detected \
						 while reading pax attribute name",
					);
					return FATAL;
				}
			};
			let did_read = win.len().min(ext_size as usize);
			let skip_rest = (ext_size + ext_padding) as u64;
			let malformed = |s: &mut Self, msg: String| {
				s.set_error(msg);
				s.unconsumed += skip_rest;
				WARN
			};
			let head = "Ignoring malformed pax attributes";
			let mut p = 0;
			let mut line_length: usize = 0;
			loop {
				if p >= did_read {
					let why = "overlarge attribute size field";
					return malformed(
						self,
						format!("{head}: {why}"),
					);
				}
				let c = win[p];
				if c == b' ' {
					p += 1;
					break;
				}
				if !c.is_ascii_digit() {
					let why = "malformed attribute size field";
					return malformed(
						self,
						format!("{head}: {why}"),
					);
				}
				line_length = line_length * 10
					+ usize::from(c - b'0');
				if line_length > MAX_LINE {
					return malformed(
						self,
						format!(
							"Ignoring malformed pax \
							 attribute: size > {MAX_LINE}"
						),
					);
				}
				p += 1;
			}
			if line_length as i64 > ext_size {
				return malformed(
					self,
					format!(
						"Ignoring malformed pax attribute:  \
						 {line_length} > {ext_size}"
					),
				);
			}
			if p >= did_read || p >= line_length || win[p] == b'=' {
				let why = "empty name found";
				return malformed(
					self,
					format!("{head}: {why}"),
				);
			}
			let name_start = p;
			loop {
				if p >= did_read || p >= line_length {
					let why = "overlarge attribute name";
					return malformed(
						self,
						format!("{head}: {why}"),
					);
				}
				if win[p] == b'=' {
					break;
				}
				p += 1;
			}
			// archive_strncpy: the name ends at a nul
			let name = until_nul(&win[name_start..p]).to_vec();
			p += 1;
			ext_size -= p as i64;
			let value_length = line_length - p;
			self.unconsumed += p as u64;
			if self.flush() != OK {
				return FATAL;
			}
			let skip_rest = (ext_size + ext_padding) as u64;
			if value_length == 0 {
				self.set_error("Malformed pax attributes");
				self.unconsumed += skip_rest;
				return WARN;
			}
			let r = self.pax_attribute(&name, value_length - 1);
			ext_size -= (value_length - 1) as i64;
			if r < WARN {
				self.unconsumed +=
					(ext_size + ext_padding) as u64;
				return r;
			}
			err = combine(err, r);
			// the '\n' ending the record
			if self.flush() != OK {
				return FATAL;
			}
			match self.src.peek(1) {
				None => {
					self.set_error(
						"Truncated tar archive detected \
						 while completing pax attribute",
					);
					return FATAL;
				}
				Some(nl) if nl[0] != b'\n' => {
					self.set_error(
						"Malformed pax attributes",
					);
					self.unconsumed +=
						(ext_size + ext_padding) as u64;
					return WARN;
				}
				Some(_) => {}
			}
			ext_size -= 1;
			self.unconsumed += 1;
			if self.flush() != OK {
				return FATAL;
			}
		}
		self.unconsumed += (ext_size + ext_padding) as u64;
		self.apply_pax_strings(err)
	}

	// pathname, uname, gname and linkpath of the pax header, converted
	// from UTF-8 unless hdrcharset is BINARY. a failed conversion is
	// ARCHIVE_WARN and keeps the raw bytes
	fn apply_pax_strings(&mut self, mut err: i32) -> i32 {
		let utf8 = self.tar.hdrcharset_utf8;
		let conv = |s: &[u8]| match utf8 {
			true => from_utf8(s),
			false => Some(until_nul(s).to_vec()),
		};
		let failed = |s: &mut Self, what: &str| {
			s.set_error(format!(
				"{what} can't be converted from UTF-8 to \
				 current locale"
			));
		};
		let t = &*self.tar;
		let pas = match t.entry_pathname_override.is_empty() {
			false => t.entry_pathname_override.clone(),
			true => t.entry_pathname.clone(),
		};
		let (uname, gname) =
			(t.entry_uname.clone(), t.entry_gname.clone());
		let linkpath = t.entry_linkpath.clone();
		if !pas.is_empty() {
			let path = conv(&pas).unwrap_or_else(|| {
				failed(self, "Pathname");
				err = WARN;
				until_nul(&pas).to_vec()
			});
			self.ae.path = Some(path);
		}
		for (name, what) in [(uname, "Uname"), (gname, "Gname")] {
			if !name.is_empty() && conv(&name).is_none() {
				failed(self, what);
				err = WARN;
			}
		}
		if !linkpath.is_empty() {
			let link = conv(&linkpath).unwrap_or_else(|| {
				failed(self, "Linkpath");
				err = WARN;
				until_nul(&linkpath).to_vec()
			});
			self.ae.copy_link(&link);
		}
		self.padding();
		err
	}

	// the value of a skipped or fully peeked record
	fn skip_value(&mut self, n: usize) {
		let _ = self.consume(n as u64);
	}

	// pax_attribute_read_number: (result, value), the value i64::MAX
	// when negative or out of range
	fn read_number(&mut self, n: usize) -> (i32, i64) {
		if n > 64 {
			self.skip_value(n);
			return (FATAL, 0);
		}
		let r = self.read_bytes(n);
		if self.flush() != OK {
			return (FATAL, 0);
		}
		let v = match r {
			Ok(v) => v,
			Err(e) => return (e, 0),
		};
		match atol10(&v) {
			t if t < 0 || t == i64::MAX => (WARN, i64::MAX),
			t => (OK, t),
		}
	}

	// pax_attribute_read_time: (result, seconds, nanoseconds)
	fn read_time(&mut self, n: usize) -> (i32, i64, i64) {
		if n > 128 {
			self.skip_value(n);
			return (FATAL, 0, 0);
		}
		let v = match self.read_bytes(n) {
			Ok(v) => v,
			Err(r) => return (r, 0, 0),
		};
		match pax_time(&v) {
			(i64::MIN, _) => (WARN, 0, 0),
			(s, ns) => (OK, s, ns),
		}
	}

	// a time record: set on success, else libarchive's text
	fn time_record(&mut self, n: usize, what: &str) -> (i32, i64, i64) {
		let r = self.read_time(n);
		if r.0 != OK {
			self.set_error(format!(
				"Ignoring malformed pax {what}"
			));
		}
		r
	}

	// a string record into one of struct tar's strings
	fn string_record(
		&mut self,
		n: usize,
		limit: usize,
	) -> Result<Vec<u8>, i32> {
		if n > limit {
			self.unconsumed += n as u64;
			return Err(WARN);
		}
		self.read_bytes(n)
	}

	// pax_attribute: one key=value record, n bytes of value
	fn pax_attribute(&mut self, key: &[u8], n: usize) -> i32 {
		let r = match key.first() {
			Some(b'G') => self.pax_gnu(key, n),
			Some(b'L') => self.pax_libarchive(key, n),
			Some(b'R') if key == b"RHT.security.selinux" => {
				Some(self.pax_xattr(
					n,
					b"security.selinux",
					"selinux data",
				))
			}
			Some(b'S') => self.pax_schily(key, n),
			Some(_) => self.pax_posix(key, n),
			None => None,
		};
		r.unwrap_or_else(|| {
			// an unknown key: its value is skipped
			self.skip_value(n);
			OK
		})
	}

	// RHT.security.selinux, an xattr under a fixed name
	fn pax_xattr(&mut self, n: usize, name: &[u8], what: &str) -> i32 {
		let mut err = OK;
		if n > XATTR_LIMIT {
			self.set_error(format!(
				"Ignoring unreasonably large security.selinux \
				 attribute: {n} > {XATTR_LIMIT}"
			));
			err = WARN;
		} else {
			let Some(v) = self.src.peek(n) else {
				let msg = format!(
					"Truncated archive detected while reading {what}"
				);
				self.set_error(msg);
				return FATAL;
			};
			self.ae.add_xattr(name, &v);
		}
		self.skip_value(n);
		err
	}

	// GNU.sparse and GNU.sparse.*
	fn pax_gnu(&mut self, key: &[u8], n: usize) -> Option<i32> {
		let k = key.strip_prefix(b"GNU.").filter(|k| !k.is_empty())?;
		if k == b"sparse" {
			self.tar.sparse_gnu_attributes_seen = true;
			return None;
		}
		let k = k.strip_prefix(b"sparse.").filter(|k| !k.is_empty())?;
		self.tar.sparse_gnu_attributes_seen = true;
		let t = &mut *self.tar;
		match k {
			b"numblocks" => {
				t.sparse_offset = -1;
				t.sparse_numbytes = -1;
				t.sparse_gnu_major = 0;
				t.sparse_gnu_minor = 0;
				None
			}
			b"offset" | b"numbytes" => {
				let (err, v) = self.read_number(n);
				if err != OK {
					return Some(err);
				}
				let t = &mut *self.tar;
				let other = match k {
					b"offset" => {
						t.sparse_offset = v;
						t.sparse_numbytes
					}
					_ => {
						t.sparse_numbytes = v;
						t.sparse_offset
					}
				};
				if other != -1 {
					let (o, b) = (
						t.sparse_offset,
						t.sparse_numbytes,
					);
					if self.add_sparse(o, b) != OK {
						return Some(FATAL);
					}
					self.tar.sparse_offset = -1;
					self.tar.sparse_numbytes = -1;
				}
				Some(err)
			}
			b"size" | b"realsize" => {
				let (err, v) = self.read_number(n);
				if err == OK {
					let t = &mut *self.tar;
					if k == b"size" {
						t.gnu_sparse_size = v;
						t.size_fields |=
							SIZE_GNU_SPARSE_SIZE;
					} else {
						t.gnu_sparse_realsize = v;
						t.size_fields |= SIZE_GNU_SPARSE_REALSIZE;
					}
				}
				Some(err)
			}
			b"map" => {
				t.sparse_gnu_major = 0;
				t.sparse_gnu_minor = 1;
				let mut err = OK;
				if n > SPARSE_MAP_LIMIT {
					self.set_error(format!(
						"Unreasonably large sparse map: \
						 {n} > {SPARSE_MAP_LIMIT}"
					));
					err = FAILED;
				} else {
					let Some(v) = self.src.peek(n) else {
						self.set_error(
							"Truncated archive detected \
							 while reading GNU sparse data",
						);
						return Some(FATAL);
					};
					if self.gnu_sparse_01_parse(&v) != OK {
						err = WARN;
					}
				}
				self.skip_value(n);
				Some(err)
			}
			b"major" | b"minor" => {
				let (err, v) = self.read_number(n);
				if err == OK && (0..=10).contains(&v) {
					match k {
						b"major" => self
							.tar
							.sparse_gnu_major = v,
						_ => self
							.tar
							.sparse_gnu_minor = v,
					}
				}
				Some(err)
			}
			b"name" => {
				let r = self.string_record(n, PATHNAME_LIMIT);
				Some(r.map_or_else(
					|e| e,
					|v| {
						self.tar.entry_pathname_override = v;
						OK
					},
				))
			}
			_ => None,
		}
	}

	// gnu_sparse_01_parse: "offset,size,..." decimal pairs; an empty
	// number (",," or a trailing ',') reads as 0
	fn gnu_sparse_01_parse(&mut self, p: &[u8]) -> i32 {
		let mut offset = -1;
		for part in p.split(|&c| c == b',') {
			if !part.iter().all(u8::is_ascii_digit) {
				return WARN;
			}
			let v = atol10(part);
			if v < 0 {
				return WARN;
			}
			if offset < 0 {
				offset = v;
			} else {
				if self.add_sparse(offset, v) != OK {
					return FATAL;
				}
				offset = -1;
			}
		}
		OK
	}

	// LIBARCHIVE.*
	fn pax_libarchive(&mut self, key: &[u8], n: usize) -> Option<i32> {
		let k = key
			.strip_prefix(b"LIBARCHIVE.")
			.filter(|k| !k.is_empty())?;
		if k == b"creationtime" {
			return Some(self.time_record(n, "creationtime").0);
		}
		if k == b"symlinktype" {
			let mut err = OK;
			if n < 16 {
				let Some(v) = self.src.peek(n) else {
					self.set_error(
						"Truncated tar archive detected while \
						 reading `symlinktype` attribute",
					);
					return Some(FATAL);
				};
				if v != b"file" && v != b"dir" {
					self.set_error(
						"Unrecognized symlink type",
					);
					err = WARN;
				}
			} else {
				self.set_error(format!(
					"symlink type is very long(longest \
					 recognized value is 4 bytes, this is {n})"
				));
				err = WARN;
			}
			self.skip_value(n);
			return Some(err);
		}
		let name =
			k.strip_prefix(b"xattr.").filter(|k| !k.is_empty())?;
		let mut err = OK;
		if n > XATTR_LIMIT {
			err = WARN;
		} else {
			let Some(v) = self.src.peek(n) else {
				self.set_error(
					"Truncated archive detected while reading \
					 xattr information",
				);
				return Some(FATAL);
			};
			self.ae.add_xattr(
				&url_decode(name),
				&base64_decode(&v),
			);
		}
		self.skip_value(n);
		Some(err)
	}

	// SCHILY.*, then SUN.* on what is left of the key
	fn pax_schily(&mut self, key: &[u8], n: usize) -> Option<i32> {
		let mut k = key;
		if let Some(rest) =
			key.strip_prefix(b"SCHILY.").filter(|r| !r.is_empty())
		{
			k = rest;
			if let Some(r) = self.pax_schily_key(rest, n) {
				return Some(r);
			}
		}
		let rest = k.strip_prefix(b"SUN.").filter(|r| !r.is_empty())?;
		if rest != b"holesdata" {
			return None;
		}
		let err;
		if n < SPARSE_MAP_LIMIT {
			let Some(v) = self.src.peek(n) else {
				self.set_error(
					"Truncated archive detected while reading \
					 SUN.holesdata",
				);
				return Some(FATAL);
			};
			err = self.sun_holesdata(&v);
			if err < OK {
				self.set_error("Parse error: SUN.holesdata");
			}
		} else {
			self.set_error(format!(
				"Unreasonably large sparse map: \
				 {n} > {SPARSE_MAP_LIMIT}"
			));
			err = FAILED;
		}
		self.skip_value(n);
		Some(err)
	}

	fn pax_schily_key(&mut self, k: &[u8], n: usize) -> Option<i32> {
		let acl = match k {
			b"acl.access" => Some((ACL_TYPE_ACCESS, "access")),
			b"acl.default" => Some((ACL_TYPE_DEFAULT, "default")),
			b"acl.ace" => Some((ACL_TYPE_NFS4, "ace")),
			_ => None,
		};
		if let Some((typ, what)) = acl {
			return Some(self.schily_acl(n, typ, what));
		}
		match k {
			b"devmajor" | b"devminor" | b"dev" | b"ino"
			| b"nlink" | b"realsize" => {
				let (err, v) = self.read_number(n);
				if err == OK {
					match k {
						b"devmajor" => {
							self.ae.set_rdevmajor(
								v as u64,
							)
						}
						b"devminor" => {
							self.ae.set_rdevminor(
								v as u64,
							)
						}
						b"realsize" => {
							let t = &mut *self.tar;
							t.schily_sparse_realsize = v;
							t.size_fields |=
								SIZE_SCHILY_SPARSE_REALSIZE;
						}
						// st_dev, st_ino and st_nlink are not used
						_ => {}
					}
				}
				Some(err)
			}
			b"fflags" => {
				let mut err = OK;
				if n < FFLAGS_LIMIT {
					if self.src.peek(n).is_none() {
						self.set_error(
							"Truncated archive detected \
							 while reading SCHILY.fflags",
						);
						return Some(FATAL);
					}
				} else {
					err = WARN;
				}
				self.skip_value(n);
				Some(err)
			}
			_ => {
				let name = k
					.strip_prefix(b"xattr.")
					.filter(|k| !k.is_empty())?;
				let mut err = OK;
				if n < XATTR_LIMIT {
					let Some(v) = self.src.peek(n) else {
						self.set_error(
							"Truncated archive detected \
							 while reading SCHILY.xattr",
						);
						return Some(FATAL);
					};
					match name.len() {
						1..=128 => self
							.ae
							.add_xattr(name, &v),
						_ => err = WARN,
					}
				} else {
					self.set_error(format!(
						"Unreasonably large xattr: \
						 {n} > {XATTR_LIMIT}"
					));
					err = WARN;
				}
				self.skip_value(n);
				Some(err)
			}
		}
	}

	// pax_attribute_SCHILY_acl: the ACL text into the entry. perm_is_set
	// is forced whatever the text held
	fn schily_acl(&mut self, n: usize, typ: i32, what: &str) -> i32 {
		if n > ACL_LIMIT {
			self.skip_value(n);
			self.set_error(format!(
				"Unreasonably large ACL: {n} > {ACL_LIMIT}"
			));
			return WARN;
		}
		let Some(text) = self.src.peek(n) else {
			self.set_error(
				"Truncated tar archive detected while reading \
				 ACL data",
			);
			return FATAL;
		};
		let r = acl_from_text(&mut self.ae, &text, typ);
		self.skip_value(n);
		let perm = self.ae.mode;
		self.ae.set_perm(perm);
		if r != OK {
			self.set_error(format!(
				"Parse error: SCHILY.acl.{what}"
			));
		}
		r
	}

	// pax_attribute_SUN_holesdata: " hole data hole ..." end offsets
	fn sun_holesdata(&mut self, p: &[u8]) -> i32 {
		let Some(p) = p.strip_prefix(b" ") else {
			return WARN;
		};
		let (mut end, mut hole) = (0, true);
		for part in p.split(|&c| c == b' ') {
			if !part.iter().all(u8::is_ascii_digit) {
				return WARN;
			}
			let start = end;
			end = atol10(part);
			if end < 0 {
				return WARN;
			}
			if start < end {
				if self.add_sparse(start, end - start) != OK {
					return FATAL;
				}
				if let Some(b) = self.tar.sparse.back_mut() {
					b.hole = hole;
				}
			}
			hole = !hole;
		}
		OK
	}

	// the lowercase POSIX keys and hdrcharset
	fn pax_posix(&mut self, key: &[u8], n: usize) -> Option<i32> {
		match key {
			b"atime" | b"ctime" | b"mtime" => {
				let what = std::str::from_utf8(key)
					.unwrap_or_default();
				let (err, s, ns) = self.time_record(n, what);
				if err == OK {
					let t = Some(fix_ns(s, ns));
					match key {
						b"atime" => self.ae.atime = t,
						b"ctime" => self.ae.ctime = t,
						_ => self.ae.mtime = t,
					}
				}
				Some(err)
			}
			b"uid" | b"gid" => {
				let (err, v) = self.read_number(n);
				if err == OK {
					match key {
						b"uid" => self.ae.uid = Some(v),
						_ => self.ae.gid = Some(v),
					}
				}
				Some(err)
			}
			b"size" => {
				let (err, v) = self.read_number(n);
				if err == OK {
					self.tar.pax_size = v;
					self.tar.size_fields |= SIZE_PAX_SIZE;
				} else if v == i64::MAX {
					self.tar.entry_bytes_remaining = 0;
					self.set_error(
						"Tar size attribute overflow",
					);
					return Some(FATAL);
				}
				Some(err)
			}
			b"uname" | b"gname" | b"path" | b"linkpath" => {
				let limit = match key {
					b"uname" | b"gname" => GUNAME_LIMIT,
					_ => PATHNAME_LIMIT,
				};
				let v = match self.string_record(n, limit) {
					Ok(v) => v,
					Err(e) => return Some(e),
				};
				let t = &mut *self.tar;
				match key {
					b"uname" => t.entry_uname = v,
					b"gname" => t.entry_gname = v,
					b"path" => t.entry_pathname = v,
					_ => t.entry_linkpath = v,
				}
				Some(OK)
			}
			b"hdrcharset" => Some(self.hdrcharset(n)),
			_ => None,
		}
	}

	fn hdrcharset(&mut self, n: usize) -> i32 {
		let mut err = OK;
		if n < 64 {
			let Some(v) = self.src.peek(n) else {
				self.set_error(
					"Truncated tar archive detected while \
					 reading hdrcharset attribute",
				);
				return FATAL;
			};
			match &v[..] {
				b"BINARY" => self.tar.hdrcharset_utf8 = false,
				b"ISO-IR 10646 2000 UTF-8" => {
					self.tar.hdrcharset_utf8 = true;
				}
				// an unknown charset, no text set
				_ => err = WARN,
			}
		} else {
			self.set_error(format!(
				"hdrcharset attribute is unreasonably large \
				 ({n} bytes)"
			));
			err = WARN;
		}
		self.skip_value(n);
		err
	}
}

// the text __archive_read_filter_consume leaves when the stream ends or
// fails before n bytes
fn truncated_input(n: u64, got: u64) -> String {
	format!("Truncated input file (needed {n} bytes, only {got} available)")
}

// ---- the reader ----

// archive_read with the tar format over a filter: the stream, the
// format's state, and whether the last header left data to skip
pub struct Reader {
	src: RefCell<Src>,
	tar: RefCell<Tar>,
}

impl Reader {
	// block: the filter's out_block_size, or archive_read_open_fd's
	// block size without a filter
	pub fn new(filter: Filter, block: u64) -> Reader {
		let src = Src {
			filter,
			buf: Vec::new(),
			at: 0,
			pos: 0,
			block: block.max(1),
			end: false,
			failed: false,
		};
		Reader {
			src: RefCell::new(src),
			tar: RefCell::new(Tar::new()),
		}
	}

	// choose_format with the tar and empty bidders: a tar header (or the
	// end mark) first, or no data at all
	pub fn recognized(&self) -> bool {
		let mut src = self.src.borrow_mut();
		match src.block_ahead() {
			Ok(h) => bid(&h) > 0,
			Err(Short::End(0)) => true,
			Err(_) => false,
		}
	}

	// the stream offset of the read position
	fn position(&self) -> u64 {
		self.src.borrow().pos
	}

	pub fn entries(&self) -> Entries<'_> {
		Entries {
			reader: self,
			data: false,
			done: false,
		}
	}

	// _archive_read_next_header2 on the tar format: archive_entry_clear,
	// archive_read_format_tar_read_header
	fn next_header(&self) -> (i32, Ae, Option<Vec<u8>>) {
		let mut src = self.src.borrow_mut();
		let mut tar = self.tar.borrow_mut();
		tar.sparse.clear();
		tar.size_fields = 0;
		let mut h = Hdr {
			src: &mut src,
			tar: &mut tar,
			ae: Ae::default(),
			unconsumed: 0,
			error: None,
		};
		let r = h.read_header();
		h.flush();
		if h.tar.sparse.is_empty() {
			let remaining = h.tar.entry_bytes_remaining;
			if h.add_sparse(0, remaining) != OK {
				return (FATAL, h.ae, h.error);
			}
		}
		// a regular entry named like a directory is one, without data
		let slash =
			h.ae.path
				.as_ref()
				.is_some_and(|p| p.last() == Some(&b'/'));
		if r == OK && h.ae.filetype() == S_IFREG && slash {
			h.ae.set_filetype(S_IFDIR);
			h.tar.entry_bytes_remaining = 0;
			h.tar.entry_padding = 0;
		}
		(r, h.ae, h.error)
	}

	// archive_read_format_tar_skip
	fn skip(&self) -> Result<(), String> {
		let mut tar = self.tar.borrow_mut();
		let request =
			(tar.entry_bytes_remaining + tar.entry_padding) as u64;
		let r = self.src.borrow_mut().consume(request);
		tar.entry_bytes_remaining = 0;
		tar.entry_padding = 0;
		tar.sparse.clear();
		r.map_err(|got| truncated_input(request, got))
	}

	// archive_read_format_tar_read_data: the next data block and its
	// offset in the file, None at the entry's end (the padding taken)
	fn read_data(&self) -> Result<Option<(i64, Vec<u8>)>, String> {
		let mut tar = self.tar.borrow_mut();
		let mut src = self.src.borrow_mut();
		loop {
			while tar
				.sparse
				.front()
				.is_some_and(|b| b.remaining == 0)
			{
				tar.sparse.pop_front();
			}
			if tar.sparse.is_empty()
				|| tar.entry_bytes_remaining == 0
			{
				// what a short map left is consumed again by each
				// later call and the skip: the C keeps the count
				let request = (tar.entry_bytes_remaining
					+ tar.entry_padding) as u64;
				src.consume(request).map_err(|got| {
					truncated_input(request, got)
				})?;
				tar.entry_padding = 0;
				return Ok(None);
			}
			let avail = match src.ahead(1) {
				Ok(d) => d.len() as i64,
				Err(_) => {
					return Err("Truncated tar archive detected \
						    while reading data"
						.to_string());
				}
			};
			let remaining = tar.entry_bytes_remaining;
			let Some(b) = tar.sparse.front_mut() else {
				continue;
			};
			let n = avail.min(remaining).min(b.remaining);
			let offset = b.offset;
			b.remaining -= n;
			b.offset += n;
			let hole = b.hole;
			tar.entry_bytes_remaining -= n;
			let data = src.take(n as usize);
			if !hole {
				return Ok(Some((offset, data)));
			}
		}
	}
}

// archive_read_next_header in a loop: every entry until the end, or the
// first result other than ARCHIVE_OK as the last item
pub struct Entries<'a> {
	reader: &'a Reader,
	// the last header left the archive in ARCHIVE_STATE_DATA
	data: bool,
	done: bool,
}

impl<'a> Iterator for Entries<'a> {
	type Item = io::Result<Entry<'a>>;

	fn next(&mut self) -> Option<io::Result<Entry<'a>>> {
		if self.done {
			return None;
		}
		// whatever the client left of the last entry's data
		if self.data {
			self.data = false;
			if let Err(msg) = self.reader.skip() {
				self.done = true;
				return Some(Err(io::Error::other(msg)));
			}
		}
		let (r, ae, error) = self.reader.next_header();
		if r == EOF {
			self.done = true;
			return None;
		}
		if r != OK {
			self.done = true;
			let msg = error.unwrap_or_else(|| b"(null)".to_vec());
			let msg = String::from_utf8_lossy(&msg).into_owned();
			return Some(Err(io::Error::other(msg)));
		}
		self.data = true;
		let tar = self.reader.tar.borrow();
		Some(Ok(Entry {
			reader: self.reader,
			disk_size: tar.disk_size,
			data_pos: self.reader.position(),
			ae,
			block: None,
			out_offset: 0,
		}))
	}
}

// an archive_entry and the data behind it
pub struct Entry<'a> {
	reader: &'a Reader,
	ae: Ae,
	disk_size: i64,
	// the stream offset the data starts at
	data_pos: u64,
	// archive_read_data's current block: its offset and what is left
	block: Option<(i64, Vec<u8>)>,
	out_offset: i64,
}

impl Entry<'_> {
	// archive_entry_pathname
	pub fn path_bytes(&self) -> &[u8] {
		self.ae.path.as_deref().unwrap_or_default()
	}

	// archive_entry_mode: the type bits and the permissions
	pub fn mode(&self) -> u32 {
		self.ae.mode
	}

	// archive_entry_size
	pub fn size(&self) -> i64 {
		self.ae.size.unwrap_or(0)
	}

	// archive_entry_hardlink, archive_entry_symlink
	pub fn hardlink(&self) -> Option<&[u8]> {
		self.ae.hardlink()
	}

	pub fn symlink(&self) -> Option<&[u8]> {
		self.ae.symlink()
	}

	pub fn uid(&self) -> i64 {
		self.ae.uid.unwrap_or(0)
	}

	pub fn gid(&self) -> i64 {
		self.ae.gid.unwrap_or(0)
	}

	// archive_entry_mtime/_nsec and the same for atime, None when unset
	pub fn mtime(&self) -> Option<(i64, i64)> {
		self.ae.mtime
	}

	pub fn atime(&self) -> Option<(i64, i64)> {
		self.ae.atime
	}

	// archive_entry_rdev's major and minor: makedev takes unsigned ints
	pub fn rdev(&self) -> (u32, u32) {
		let (major, minor) = self.ae.rdev.unwrap_or_default();
		(major as u32, minor as u32)
	}

	// the extended attributes in the order archive_write_disk sets them
	pub fn xattrs(&self) -> &[(Vec<u8>, Vec<u8>)] {
		&self.ae.xattrs
	}

	// the stream offset of the entry's data
	pub fn raw_file_position(&self) -> u64 {
		self.data_pos
	}

	// archive_read_data_block: the next block and its file offset, None
	// at the end of the data
	pub fn data_block(&mut self) -> io::Result<Option<(i64, Vec<u8>)>> {
		self.reader.read_data().map_err(io::Error::other)
	}

	// archive_read_data_skip
	pub fn skip(&mut self) -> io::Result<()> {
		self.reader.skip().map_err(io::Error::other)
	}
}

// archive_read_data: the blocks with the holes between them and up to
// the file size as zeros
impl Read for Entry<'_> {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		let mut done = 0;
		while done < buf.len() {
			let empty = self
				.block
				.as_ref()
				.is_none_or(|b| b.1.is_empty());
			let at = self
				.block
				.as_ref()
				.map_or(self.out_offset, |b| b.0);
			if empty && at == self.out_offset {
				match self.data_block()? {
					Some(b) => self.block = Some(b),
					None if self.disk_size
						== self.out_offset =>
					{
						return Ok(done);
					}
					None => {
						self.block = Some((
							self.disk_size,
							Vec::new(),
						));
					}
				}
			}
			let Some((offset, data)) = &mut self.block else {
				return Ok(done);
			};
			if *offset < self.out_offset {
				return Err(io::Error::other(
					"Encountered out-of-order sparse blocks",
				));
			}
			let left = buf.len() - done;
			let zeros = (*offset - self.out_offset).min(left as i64)
				as usize;
			buf[done..done + zeros].fill(0);
			done += zeros;
			self.out_offset += zeros as i64;
			let n = data.len().min(buf.len() - done);
			if n == 0 {
				continue;
			}
			buf[done..done + n].copy_from_slice(&data[..n]);
			data.drain(..n);
			*offset += n as i64;
			self.out_offset += n as i64;
			done += n;
		}
		Ok(done)
	}
}
