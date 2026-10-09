// libarchive's mtree format reader (archive_read_support_format_mtree.c,
// libarchive 3.8.9) as pacman uses it: the mtree format alone over every
// filter, no options. checkfs is off, so no contents file is opened and
// optional/nochange change nothing; read_data has no data to hand out.
// be_package reads a package's .MTREE with it (build_filelist_from_mtree),
// be_local the local db's mtree file (_cache_mtree_open/_next).
//
// libarchive bids on the format while opening (mtree_bid), reads the whole
// file at the first header (read_mtree) and then hands out one entry per
// header (read_header/parse_file). read() does all three: the entries in
// file order, each with the text of the ARCHIVE_WARN its header returns.
// the data is seen as one buffer, as archive_read_open_memory hands it
// out; libarchive's line readers work on read-ahead blocks, where a few
// line ends depend on block boundaries. archive_set_error
// texts are kept where pacman logs them.

use std::fs;
use std::io::{self, Read};

use crate::filter::{self, Filter};
use crate::util::{
	S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, c_path,
	until_nul,
};

// readline's limit in read_mtree, next_line's in detect_form
const LINE_LIMIT: usize = 65536;
const MAX_LINE_LEN: usize = 1024 * 1024;
// detect_form: this many entry lines make the data mtree
const MAX_BID_ENTRY: usize = 3;

/// the AE_IF* type of an entry
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryType {
	/// AE_IFBLK
	Block,
	/// AE_IFCHR
	Char,
	/// AE_IFDIR
	Dir,
	/// AE_IFIFO
	Fifo,
	/// AE_IFREG
	File,
	/// AE_IFLNK
	Link,
}

impl EntryType {
	/// archive_entry_filetype: the S_IF* bits
	pub fn filetype(self) -> u32 {
		match self {
			EntryType::Block => S_IFBLK,
			EntryType::Char => S_IFCHR,
			EntryType::Dir => S_IFDIR,
			EntryType::Fifo => S_IFIFO,
			EntryType::File => S_IFREG,
			EntryType::Link => S_IFLNK,
		}
	}
}

/// what pacman reads of an archive_entry the reader fills
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
	/// archive_entry_pathname: decoded, with its "./" prefix
	pub path: Vec<u8>,
	pub kind: EntryType,
	/// ~AE_IFMT & archive_entry_mode: mode= keeps bits above the type
	pub mode: u32,
	pub uid: i64,
	pub gid: i64,
	pub size: u64,
	/// archive_entry_mtime, 0 when unset
	pub mtime: i64,
	/// archive_entry_symlink, None when unset
	pub link: Option<Vec<u8>>,
	/// the digests as bytes
	pub sha256: Option<[u8; 32]>,
	pub md5: Option<[u8; 16]>,
	/// the header returned ARCHIVE_WARN: archive_error_string, the last
	/// error set while reading it
	pub warning: Option<Vec<u8>>,
}

// where archive_read_open or the first archive_read_next_header fails
#[derive(Debug)]
pub enum Error {
	/// the decoder fails inside what the open reads through the filter
	Open(io::Error),
	/// archive_read_open_filename's file reader fails: libarchive's text
	File(Vec<u8>),
	/// choose_format: no bid, "Unrecognized archive format"
	Format,
	/// read_mtree returned ARCHIVE_FATAL: libarchive's text
	Header(Vec<u8>),
}

impl Error {
	// archive_error_string; an open failure has the decoder's text where
	// libarchive has its filter's
	pub fn text(&self) -> Vec<u8> {
		match self {
			Error::Open(e) => e.to_string().into_bytes(),
			Error::File(t) => t.clone(),
			Error::Format => {
				b"Unrecognized archive format".to_vec()
			}
			Error::Header(t) => t.clone(),
		}
	}
}

// the C reads its buffers as strings: a past-the-end read is the nul
fn at(d: &[u8], i: usize) -> u8 {
	d.get(i).copied().unwrap_or(0)
}

fn is_blank(c: u8) -> bool {
	c == b' ' || c == b'\t'
}

// the separators process_add_entry and process_global_* split words on
fn is_sep(c: u8) -> bool {
	matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

// bid_entry's safe_char: printable ASCII but space, '#' and '='
fn is_safe(c: u8) -> bool {
	(0x21..=0x7e).contains(&c) && c != b'#' && c != b'='
}

// get_line_size over b: the line length with its newline and the
// newline's length (2 for "\r\n"), -1 at a nul, b.len() without newline
fn get_line_size(b: &[u8]) -> (isize, usize) {
	for (len, &c) in b.iter().enumerate() {
		match c {
			0 => return (-1, 0),
			b'\r' if b.get(len + 1) == Some(&b'\n') => {
				return (len as isize + 2, 2);
			}
			b'\r' | b'\n' => return (len as isize + 1, 1),
			_ => {}
		}
	}
	(b.len() as isize, 0)
}

// next_line with all data read ahead: a line without newline reads ahead
// for more, gets the end of the data and returns 0 (-1 past
// MAX_LINE_LEN)
fn next_line(d: &[u8], p: usize) -> (isize, usize) {
	let rest = &d[p..];
	let (len, nl) = get_line_size(rest);
	if nl == 0 && len == rest.len() as isize {
		if len as usize >= MAX_LINE_LEN {
			return (-1, 0);
		}
		return (0, 0);
	}
	(len, nl)
}

// bid_keycmp: the key's length if d at p starts with key followed by
// '=', a blank, a newline or an escaped newline, within len bytes
fn bid_keycmp(d: &[u8], p: usize, key: &[u8], len: isize) -> usize {
	let (mut i, mut len) = (0, len);
	while len > 0 && at(d, p + i) != 0 && i < key.len() {
		if at(d, p + i) != key[i] {
			return 0;
		}
		len -= 1;
		i += 1;
	}
	if i < key.len() {
		return 0;
	}
	let (c, next) = (at(d, p + i), at(d, p + i + 1));
	let escaped = c == b'\\' && (next == b'\n' || next == b'\r');
	if matches!(c, b'=' | b' ' | b'\t' | b'\n' | b'\r') || escaped {
		return i;
	}
	0
}

// bid_keyword: the length of the keyword at p, 0 if none
fn bid_keyword(d: &[u8], p: usize, len: isize) -> usize {
	let keys: &[&[u8]] = match at(d, p) {
		b'c' => &[b"content", b"contents", b"cksum"],
		b'd' | b'f' => &[b"device", b"flags"],
		b'g' => &[b"gid", b"gname"],
		b'i' | b'l' => &[b"ignore", b"inode", b"link"],
		b'm' => &[b"md5", b"md5digest", b"mode"],
		b'n' | b'o' => &[b"nlink", b"nochange", b"optional"],
		b'r' => &[b"resdevice", b"rmd160", b"rmd160digest"],
		b's' => &[
			b"sha1",
			b"sha1digest",
			b"sha256",
			b"sha256digest",
			b"sha384",
			b"sha384digest",
			b"sha512",
			b"sha512digest",
			b"size",
		],
		b't' => &[b"tags", b"time", b"type"],
		b'u' => &[b"uid", b"uname"],
		_ => return 0,
	};
	keys.iter()
		.map(|k| bid_keycmp(d, p, k, len))
		.find(|&l| l > 0)
		.unwrap_or(0)
}

// bid_keyword_list: the count of keywords from p on, -1 for something
// else. reads past len like the C (form D: up to the name)
fn bid_keyword_list(
	d: &[u8],
	mut p: usize,
	mut len: isize,
	unset: bool,
	last_is_path: bool,
) -> i32 {
	let mut keycnt = 0;
	while len > 0 && at(d, p) != 0 {
		let mut blank = false;
		while len > 0 && is_blank(at(d, p)) {
			p += 1;
			len -= 1;
			blank = true;
		}
		let c = at(d, p);
		if c == b'\n' || c == b'\r' {
			break;
		}
		if c == b'\\' && matches!(at(d, p + 1), b'\n' | b'\r') {
			break;
		}
		if !blank && !last_is_path {
			return -1;
		}
		if last_is_path && len == 0 {
			return keycnt;
		}
		if unset && bid_keycmp(d, p, b"all", len) > 0 {
			return 1;
		}
		let l = bid_keyword(d, p, len);
		if l == 0 {
			return -1;
		}
		p += l;
		len -= l as isize;
		keycnt += 1;
		if at(d, p) == b'=' {
			let mut value = false;
			p += 1;
			len -= 1;
			while len > 0 && !is_blank(at(d, p)) {
				p += 1;
				len -= 1;
				value = true;
			}
			// a value is needed but in /unset
			if !unset && !value {
				return -1;
			}
		}
	}
	keycnt
}

// bid_entry: the keyword count of an entry line (-1: not one) and
// whether the path comes last (NetBSD's mtree -D, "form D")
fn bid_entry(d: &[u8], p: usize, len: usize, nl: usize) -> (i32, bool) {
	let end = p + len;
	let mut f = false;
	let mut pp = p;
	while pp < end {
		if !is_safe(d[pp]) {
			if !is_sep(d[pp]) {
				f = false;
			}
			break;
		}
		f = true;
		pp += 1;
	}
	if f {
		return (
			bid_keyword_list(
				d,
				pp,
				(end - pp) as isize,
				false,
				false,
			),
			false,
		);
	}
	// form D accepts one line per entry
	let pb = end - nl;
	if pb >= p + 2 && d[pb - 1] == b'\\' && is_blank(d[pb - 2]) {
		return (-1, false);
	}
	if pb > p && d[pb - 1] == b'\\' {
		return (-1, false);
	}
	let (mut name_len, mut slash) = (0, false);
	let mut pb = pb as isize;
	loop {
		pb -= 1;
		if pb < p as isize || is_blank(d[pb as usize]) {
			break;
		}
		let c = d[pb as usize];
		if !is_safe(c) {
			return (-1, false);
		}
		name_len += 1;
		slash |= c == b'/';
	}
	// the path has a '/', not as its first byte
	if name_len == 0 || !slash || at(d, (pb + 1) as usize) == b'/' {
		return (-1, false);
	}
	let ll = (len - nl - name_len) as isize;
	(bid_keyword_list(d, p, ll, false, true), true)
}

// detect_form over all of d: the bid (32 when the first lines look like
// mtree, 0 not, -1 no data) and whether it is form D
fn detect_form(d: &[u8]) -> (i32, bool) {
	if d.is_empty() {
		return (-1, false);
	}
	let (mut entry_cnt, mut multiline, mut form_d) = (0, 0, 0);
	let mut p = 0;
	let mut len;
	loop {
		let nl;
		(len, nl) = next_line(d, p);
		// a line ends in "\n" or "\r\n"
		if len <= 0 || nl == 0 {
			break;
		}
		if multiline == 0 {
			// leading whitespace is never significant
			while len > 0 && is_blank(d[p]) {
				p += 1;
				len -= 1;
			}
			if matches!(d[p], b'#' | b'\n' | b'\r') {
				p += len as usize;
				continue;
			}
		} else {
			// the continuation of the line before
			if bid_keyword_list(d, p, len, false, false) <= 0 {
				break;
			}
			if d[p + len as usize - nl - 1] != b'\\' {
				if multiline == 1 {
					entry_cnt += 1;
					if entry_cnt >= MAX_BID_ENTRY {
						break;
					}
				}
				multiline = 0;
			}
			p += len as usize;
			continue;
		}
		let ulen = len as usize;
		let continued = d[p + ulen - nl - 1] == b'\\';
		if d[p] != b'/' {
			let (keywords, last_is_path) =
				bid_entry(d, p, ulen, nl);
			if keywords < 0 {
				break;
			}
			if form_d == 0 {
				if last_is_path {
					form_d = 1;
				} else if keywords > 0 {
					form_d = -1;
				}
			} else if form_d == 1 && !last_is_path && keywords > 0 {
				// no mixed forms
				break;
			}
			if !last_is_path && continued {
				multiline = 1;
			} else {
				entry_cnt += 1;
				if entry_cnt >= MAX_BID_ENTRY {
					break;
				}
			}
		} else if ulen > 4 && d[p..].starts_with(b"/set") {
			if bid_keyword_list(d, p + 4, len - 4, false, false)
				<= 0
			{
				break;
			}
			if continued {
				multiline = 2;
			}
		} else if ulen > 6 && d[p..].starts_with(b"/unset") {
			if bid_keyword_list(d, p + 6, len - 6, true, false) <= 0
			{
				break;
			}
			if continued {
				multiline = 2;
			}
		} else {
			break;
		}
		p += ulen;
	}
	if entry_cnt >= MAX_BID_ENTRY || (entry_cnt > 0 && len == 0) {
		return (32, form_d == 1);
	}
	(0, false)
}

// mtree_bid: the "#mtree" signature, else detect_form; -1 for data
// shorter than the signature
fn mtree_bid(d: &[u8]) -> i32 {
	let signature = b"#mtree";
	if d.len() < signature.len() {
		return -1;
	}
	if d.starts_with(signature) {
		return 8 * signature.len() as i32;
	}
	detect_form(d).0
}

// readline: the next line with its '\n', escaped newlines joined and a
// "\r\n" end made "\n"; None at the end of the data, where a last line
// without newline is lost. after a nul the scan never moves on, so the
// rest of the data is read into the line until it ends or is too long
fn readline(d: &[u8], pos: &mut usize) -> Result<Option<Vec<u8>>, Vec<u8>> {
	let mut line: Vec<u8> = Vec::new();
	let mut find_off = 0;
	loop {
		if *pos == d.len() {
			return Ok(None);
		}
		let rest = &d[*pos..];
		let nl = rest.iter().position(|&c| c == b'\n');
		// a read is trimmed to end at its '\n'
		let chunk = &rest[..nl.map_or(rest.len(), |i| i + 1)];
		if line.len() + chunk.len() + 1 > LINE_LIMIT {
			return Err(b"Line too long".to_vec());
		}
		line.extend_from_slice(chunk);
		*pos += chunk.len();
		let mut u = find_off;
		while u < line.len() && line[u] != 0 {
			match line[u] {
				b'\n' => {
					if u > 0 && line[u - 1] == b'\r' {
						line[u - 1] = b'\n';
						line.truncate(u);
					}
					return Ok(Some(line));
				}
				// a comment waits for its '\n'
				b'#' if nl.is_none() => break,
				b'\\' => {
					let (c1, c2) = (
						at(&line, u + 1),
						at(&line, u + 2),
					);
					if c1 == b'\n' {
						line.truncate(line.len() - 2);
						break;
					} else if c1 == b'\r' && c2 == b'\n' {
						line.truncate(line.len() - 3);
						break;
					} else if c1 != 0 {
						// a two-byte escape
						u += 1;
					}
				}
				_ => {}
			}
			u += 1;
		}
		find_off = u;
	}
}

// key=value options of a /set line or an entry, in libarchive's list
// order: add_option prepends
type Options = Vec<Vec<u8>>;

// the part of an option remove_option compares
fn key(option: &[u8]) -> &[u8] {
	let eq = option.iter().position(|&c| c == b'=');
	&option[..eq.unwrap_or(option.len())]
}

fn add_option(list: &mut Options, option: &[u8]) {
	list.insert(0, option.to_vec());
}

// remove_option: the first option with that key
fn remove_option(list: &mut Options, k: &[u8]) {
	if let Some(i) = list.iter().position(|o| key(o) == k) {
		list.remove(i);
	}
}

// the words of s split on " \t\r\n"
fn words(s: &[u8]) -> impl Iterator<Item = &[u8]> {
	s.split(|&c| is_sep(c)).filter(|w| !w.is_empty())
}

// one entry line: its name decoded, whether it is "full" (a '/' or "."
// as written: matched by name and merged, others below the current dir)
struct MtreeLine {
	name: Vec<u8>,
	full: bool,
	options: Options,
	used: bool,
}

// parse_escapes: \\ \a \b \f \n \r \s \t \v, octal \000 to \377 and \0
// before a non-octal byte; any other backslash stays. the result is a C
// string, it ends at a decoded nul
fn parse_escapes(src: &[u8]) -> Vec<u8> {
	let is_octal = |c: u8| (b'0'..=b'7').contains(&c);
	let mut out = Vec::with_capacity(src.len());
	let mut i = 0;
	while i < src.len() {
		let mut c = src[i];
		i += 1;
		if c == b'\\' {
			let (s0, s1, s2) =
				(at(src, i), at(src, i + 1), at(src, i + 2));
			let simple = match s0 {
				b'0' if !is_octal(s1) => Some(0),
				b'a' => Some(0x07),
				b'b' => Some(0x08),
				b'f' => Some(0x0c),
				b'n' => Some(b'\n'),
				b'r' => Some(b'\r'),
				b's' => Some(b' '),
				b't' => Some(b'\t'),
				b'v' => Some(0x0b),
				b'\\' => Some(b'\\'),
				_ => None,
			};
			if let Some(simple) = simple {
				c = simple;
				i += 1;
			} else if (b'0'..=b'3').contains(&s0)
				&& is_octal(s1) && is_octal(s2)
			{
				c = (s0 - b'0') << 6
					| (s1 - b'0') << 3 | (s2 - b'0');
				i += 3;
			}
		}
		out.push(c);
	}
	let end = out.iter().position(|&c| c == 0).unwrap_or(out.len());
	out.truncate(end);
	out
}

// process_add_entry. form D has the name last, after the keywords
fn add_entry(line: &[u8], global: &Options, form_d: bool) -> MtreeLine {
	let (raw, rest) = if form_d {
		let mut len = line.len();
		while len > 0 && is_sep(line[len - 1]) {
			len -= 1;
		}
		let start = line[..len].iter().rposition(|&c| is_sep(c));
		let start = start.map_or(0, |i| i + 1);
		(&line[start..len], &line[..start])
	} else {
		let n = line
			.iter()
			.position(|&c| is_sep(c))
			.unwrap_or(line.len());
		(&line[..n], &line[n..])
	};
	let mut options = Options::new();
	for o in global {
		add_option(&mut options, o);
	}
	for w in words(rest) {
		remove_option(&mut options, key(w));
		add_option(&mut options, w);
	}
	MtreeLine {
		name: parse_escapes(raw),
		full: raw == b"." || raw.contains(&b'/'),
		options,
		used: false,
	}
}

// process_global_set
fn global_set(global: &mut Options, rest: &[u8]) {
	for w in words(rest) {
		remove_option(global, key(w));
		add_option(global, w);
	}
}

// process_global_unset
fn global_unset(global: &mut Options, rest: &[u8]) -> Result<(), Vec<u8>> {
	if rest.contains(&b'=') {
		return Err(b"/unset shall not contain `='".to_vec());
	}
	for w in words(rest) {
		if w == b"all" {
			global.clear();
		} else {
			remove_option(global, w);
		}
	}
	Ok(())
}

// read_mtree: every line of the data, entries in file order; a line it
// cannot parse fails the whole file
fn read_mtree(d: &[u8]) -> Result<Vec<MtreeLine>, Vec<u8>> {
	let (_, form_d) = detect_form(d);
	let mut global = Options::new();
	let mut lines = Vec::new();
	let (mut pos, mut counter) = (0, 0u64);
	loop {
		counter += 1;
		let Some(line) = readline(d, &mut pos)? else {
			return Ok(lines);
		};
		let start = line.iter().position(|&c| !is_blank(c));
		let p = &line[start.unwrap_or(line.len())..];
		// comments and blank lines
		if matches!(p.first(), None | Some(b'#' | b'\r' | b'\n' | 0)) {
			continue;
		}
		// isprint in the C locale, the last byte is the '\n'
		let printable =
			|c: &u8| (b' '..=b'~').contains(c) || *c == b'\t';
		if !p[..p.len() - 1].iter().all(printable) {
			return Err(format!("Can't parse line {counter}")
				.into_bytes());
		}
		let blank_at = |i: usize| is_blank(at(p, i));
		if p[0] != b'/' {
			lines.push(add_entry(p, &global, form_d));
		} else if p.len() > 4 && p.starts_with(b"/set") && blank_at(4) {
			global_set(&mut global, &p[4..]);
		} else if p.len() > 6 && p.starts_with(b"/unset") && blank_at(6)
		{
			global_unset(&mut global, &p[6..])?;
		} else {
			return Err(format!("Can't parse line {counter}")
				.into_bytes());
		}
	}
}

// mtree_atol: optional '-', digits of base (0: 0x hex, 0 octal, else
// decimal; any case), saturated at the i64 bounds. the value and the
// bytes read
fn atol(s: &[u8], mut base: u32) -> (i64, usize) {
	let mut i = 0;
	if base == 0 {
		base = match (at(s, 0), at(s, 1)) {
			(b'0', b'x' | b'X') => {
				i = 2;
				16
			}
			(b'0', _) => 8,
			_ => 10,
		};
	}
	let negative = at(s, i) == b'-';
	i += usize::from(negative);
	let mut l: i64 = 0;
	while let Some(digit) = char::from(at(s, i)).to_digit(base) {
		let next = l.checked_mul(base.into()).and_then(|l| {
			if negative {
				l.checked_sub(digit.into())
			} else {
				l.checked_add(digit.into())
			}
		});
		let Some(next) = next else {
			let bound = if negative { i64::MIN } else { i64::MAX };
			return (bound, i);
		};
		l = next;
		i += 1;
	}
	(l, i)
}

// the device formats pack_find knows and how they pack
#[derive(Clone, Copy)]
enum Pack {
	// glibc makedev/major/minor, 32-bit numbers
	Native,
	NetBsd,
	Bsdos,
	// major and minor as (shift, mask) each, both checked
	Fields(u32, u64, u32, u64),
}

const P8_8: Pack = Pack::Fields(8, 0x0000ff00, 0, 0x000000ff);
const P12_20: Pack = Pack::Fields(20, 0xfff00000, 0, 0x000fffff);
const P14_18: Pack = Pack::Fields(18, 0xfffc0000, 0, 0x0003ffff);

fn pack_find(name: &[u8]) -> Option<Pack> {
	Some(match name {
		b"386bsd" | b"4bsd" | b"isc" | b"linux" | b"sco" | b"sunos"
		| b"svr3" | b"ultrix" => P8_8,
		b"bsdos" => Pack::Bsdos,
		b"freebsd" => Pack::Fields(8, 0x0000ff00, 0, 0xffff00ff),
		b"hpux" => Pack::Fields(24, 0xff000000, 0, 0x00ffffff),
		b"native" => Pack::Native,
		b"netbsd" => Pack::NetBsd,
		b"osf1" => P12_20,
		b"solaris" | b"svr4" => P14_18,
		_ => return None,
	})
}

// a field of a packed dev_t read back: masked, shifted, then the int32_t
// cast of the macros, widened to unsigned long for the compare
fn field(n: u64, shift: u32, mask: u64) -> u64 {
	(((n << shift) & mask) >> shift) as u32 as i32 as i64 as u64
}

// the pack_* error for numbers that do not round-trip
fn pack(format: Pack, n: &[u64]) -> Option<&'static str> {
	let (major, minor) = ("invalid major number", "invalid minor number");
	match (format, n) {
		(Pack::Native, &[ma, mi]) => {
			// makedev takes unsigned int
			let fits = |x: u64| x <= u64::from(u32::MAX);
			match (fits(ma), fits(mi)) {
				(false, _) => Some(major),
				(_, false) => Some(minor),
				_ => None,
			}
		}
		(Pack::NetBsd, &[ma, mi]) => {
			let back =
				(((mi << 12) & 0xfff00000) >> 12) | (mi & 0xff);
			if field(ma, 8, 0x000fff00) != ma {
				Some(major)
			} else if back != mi {
				Some(minor)
			} else {
				None
			}
		}
		(Pack::Bsdos, &[_, _]) => pack(P12_20, n),
		(Pack::Bsdos, &[ma, unit, sub]) => {
			let mut error = None;
			if field(ma, 20, 0xfff00000) != ma {
				error = Some(major);
			}
			if field(unit, 8, 0x000fff00) != unit {
				error = Some("invalid unit number");
			}
			if field(sub, 0, 0x000000ff) != sub {
				error = Some("invalid subunit number");
			}
			error
		}
		(Pack::Fields(ms, mm, ns, nm), &[ma, mi]) => {
			let mut error = None;
			if field(ma, ms, mm) != ma {
				error = Some(major);
			}
			if field(mi, ns, nm) != mi {
				error = Some(minor);
			}
			error
		}
		_ => Some("too many fields for format"),
	}
}

// parse_device: a raw number, or format,major,minor[,subunit]
fn parse_device(val: &[u8]) -> Result<(), Vec<u8>> {
	let Some(comma) = val.iter().position(|&c| c == b',') else {
		return Ok(());
	};
	let name = &val[..comma];
	let Some(format) = pack_find(name) else {
		let name = String::from_utf8_lossy(name);
		return Err(format!("Unknown format `{name}'").into_bytes());
	};
	let mut numbers = Vec::new();
	// la_strsep: a trailing ',' ends the list
	let mut sp = &val[comma + 1..];
	while !sp.is_empty() {
		let n = sp.iter().position(|&c| c == b',').unwrap_or(sp.len());
		let field = &sp[..n];
		sp = &sp[(n + 1).min(sp.len())..];
		if field.is_empty() {
			return Err(b"Missing number".to_vec());
		}
		if numbers.len() >= 3 {
			return Err(b"Too many arguments".to_vec());
		}
		numbers.push(atol(field, 0).0 as u64);
	}
	if numbers.len() < 2 {
		return Err(b"Not enough arguments".to_vec());
	}
	match pack(format, &numbers) {
		Some(e) => Err(e.as_bytes().to_vec()),
		None => Ok(()),
	}
}

// parse_digest: exactly 2 * len lowercase hex digits
fn parse_digest(val: &[u8], len: usize) -> Result<&[u8], Vec<u8>> {
	if val.len() != 2 * len {
		return Err(b"incorrect digest length, ignoring".to_vec());
	}
	if !val.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
		return Err(b"invalid digest data, ignoring".to_vec());
	}
	Ok(val)
}

// the bytes of a parse_digest'ed value
fn digest<const N: usize>(hex: &[u8]) -> Option<[u8; N]> {
	let nibble = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
	let mut out = [0; N];
	for (b, &[hi, lo]) in out.iter_mut().zip(hex.as_chunks().0) {
		*b = nibble(hi)? << 4 | nibble(lo)?;
	}
	Some(out)
}

fn lossy(b: &[u8]) -> std::borrow::Cow<'_, str> {
	String::from_utf8_lossy(b)
}

// parse_keyword into e; Err is an ARCHIVE_WARN with its text, the
// keyword's value is not read then
fn parse_keyword(
	e: &mut Entry,
	has_type: &mut bool,
	opt: &[u8],
) -> Result<(), Vec<u8>> {
	if opt.is_empty()
		|| matches!(opt, b"nochange" | b"optional" | b"ignore")
	{
		return Ok(());
	}
	let Some(eq) = opt.iter().position(|&c| c == b'=') else {
		let msg = format!(
			"Malformed attribute \"{}\" ({})",
			lossy(opt),
			opt[0] as i8
		);
		return Err(msg.into_bytes());
	};
	let (key, val) = (&opt[..eq], &opt[eq + 1..]);
	match key {
		b"content" | b"contents" | b"cksum" | b"flags" | b"gname"
		| b"inode" | b"nlink" | b"tags" | b"uname" => {}
		b"device" | b"resdevice" => parse_device(val)?,
		b"gid" => e.gid = atol(val, 10).0.max(0),
		b"uid" => e.uid = atol(val, 10).0.max(0),
		b"link" => e.link = Some(parse_escapes(val)),
		b"md5" | b"md5digest" => e.md5 = digest(parse_digest(val, 16)?),
		b"rmd160" | b"rmd160digest" | b"sha1" | b"sha1digest" => {
			parse_digest(val, 20)?;
		}
		b"sha256" | b"sha256digest" => {
			e.sha256 = digest(parse_digest(val, 32)?);
		}
		b"sha384" | b"sha384digest" => {
			parse_digest(val, 48)?;
		}
		b"sha512" | b"sha512digest" => {
			parse_digest(val, 64)?;
		}
		b"mode" => {
			if !matches!(at(val, 0), b'0'..=b'7') {
				let msg = format!(
					"Symbolic or non-octal mode \"{}\" unsupported",
					lossy(val)
				);
				return Err(msg.into_bytes());
			}
			// archive_entry_set_perm of a mode_t
			e.mode = atol(val, 8).0 as u32 & !S_IFMT;
		}
		b"size" => e.size = atol(val, 10).0.max(0) as u64,
		b"time" => {
			// the nanoseconds after a '.' only clamp, and
			// archive_entry_mtime ignores them
			e.mtime = atol(val, 10).0;
		}
		b"type" => {
			let kind = match val {
				b"block" => EntryType::Block,
				b"char" => EntryType::Char,
				b"dir" => EntryType::Dir,
				b"fifo" => EntryType::Fifo,
				b"file" => EntryType::File,
				b"link" => EntryType::Link,
				_ => {
					e.kind = EntryType::File;
					let msg = format!(
						"Unrecognized file type \"{}\"; \
						assuming \"file\"",
						lossy(val)
					);
					return Err(msg.into_bytes());
				}
			};
			e.kind = kind;
			*has_type = true;
		}
		_ => {
			let msg = format!(
				"Unrecognized key {}={}",
				lossy(key),
				lossy(val)
			);
			return Err(msg.into_bytes());
		}
	}
	Ok(())
}

// parse_line: the options of one line in list order, a warning for any
// keyword it warns about, else for a type not set by now
fn parse_line(e: &mut Entry, has_type: &mut bool, options: &Options) {
	let mut warned = false;
	for o in options {
		if let Err(text) = parse_keyword(e, has_type, o) {
			e.warning = Some(text);
			warned = true;
		}
	}
	if !warned && !*has_type {
		let text = b"Missing type keyword in mtree specification";
		e.warning = Some(text.to_vec());
	}
}

// read_header's walk: ".." goes up a directory, every unused line makes
// an entry. a full path takes the lines of the same name after it
// (later keywords win), a relative one is below the current dir, which
// it becomes if a dir
fn entries(mut lines: Vec<MtreeLine>) -> Vec<Entry> {
	let mut dups: std::collections::HashMap<Vec<u8>, Vec<usize>> =
		Default::default();
	for (i, l) in lines.iter().enumerate() {
		if l.full {
			dups.entry(l.name.clone()).or_default().push(i);
		}
	}
	let mut current_dir: Vec<u8> = Vec::new();
	let mut out = Vec::new();
	for i in 0..lines.len() {
		if lines[i].name == b".." {
			lines[i].used = true;
			let up = current_dir.iter().rposition(|&c| c == b'/');
			current_dir.truncate(up.unwrap_or(0));
		}
		if lines[i].used {
			continue;
		}
		// parse_file's defaults on a cleared archive_entry
		let mut e = Entry {
			path: Vec::new(),
			kind: EntryType::File,
			mode: 0,
			uid: 0,
			gid: 0,
			size: 0,
			mtime: 0,
			link: None,
			sha256: None,
			md5: None,
			warning: None,
		};
		let mut has_type = false;
		if lines[i].full {
			e.path = lines[i].name.clone();
			for &j in &dups[&e.path] {
				if !lines[j].used {
					lines[j].used = true;
					parse_line(
						&mut e,
						&mut has_type,
						&lines[j].options,
					);
				}
			}
		} else {
			lines[i].used = true;
			parse_line(&mut e, &mut has_type, &lines[i].options);
			let n = current_dir.len();
			if n > 0 {
				current_dir.push(b'/');
			}
			current_dir.extend_from_slice(&lines[i].name);
			e.path = current_dir.clone();
			if e.kind != EntryType::Dir {
				current_dir.truncate(n);
			}
		}
		out.push(e);
	}
	out
}

// archive_read_open (the format bid) and archive_read_next_header to
// the end on data the filter decoded
pub fn read(data: &[u8]) -> Result<Vec<Entry>, Error> {
	if mtree_bid(data) < 1 {
		return Err(Error::Format);
	}
	Ok(entries(read_mtree(data).map_err(Error::Header)?))
}

// the data through the filter: what the open reads fails it, after that
// a failed read is the end of the data to readline (__archive_read_ahead
// gives NULL)
fn read_filtered(mut filter: Filter) -> Result<Vec<Entry>, Error> {
	let mut data = Vec::new();
	let _ = filter.read_to_end(&mut data);
	read(&data)
}

// archive_read_open_memory on .MTREE data (build_filelist_from_mtree)
pub fn read_memory(data: Vec<u8>) -> Result<Vec<Entry>, Error> {
	read_filtered(filter::open_memory(data).map_err(Error::Open)?)
}

// archive_read_open_filename on a local db mtree file: read whole, the
// filter blocks then come from the data like with read_memory. a file
// that cannot be opened or read fails the open, with the texts of
// libarchive's file reader
pub fn read_file(path: &[u8]) -> Result<Vec<Entry>, Error> {
	let path = until_nul(path);
	let text =
		|what: &[u8]| Error::File([what, b" '", path, b"'"].concat());
	let mut f = fs::File::open(c_path(path))
		.map_err(|_| text(b"Failed to open"))?;
	let mut data = Vec::new();
	f.read_to_end(&mut data)
		.map_err(|_| text(b"Error reading"))?;
	read_memory(data)
}
