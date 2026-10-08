// libarchive 3.8.9's read filters as pacman sets them up
// (_alpm_archive_read_support_filter_all, archive_read_support_filter_all)
//
// archive_read.c's filter chain: choose_filters runs every bidder on the
// data, the best bid wins (the first registered on a tie) and the
// winner's output is bid on again, so gzip-in-gzip is decoded twice, up
// to MAX_NUMBER_FILTERS. each filter hands its output on in blocks of its
// own read callback, buffered for read-ahead like
// __archive_read_filter_ahead, and a failed read fails the filter for
// good. the bidders follow the registration order of
// archive_read_support_filter_all: bzip2, compress, gzip, lzip, lzma, xz,
// uu, rpm, lrzip, lzop, grzip, lz4, zstd.
//
// the readers are translated in filter/ over the codecs libarchive uses
// or ALPM's crates for them (flate2, bzip2, liblzma, zstd; lz4_flex for
// liblz4's blocks), compress (.Z) is libarchive's own; lrzip, lzop and
// grzip run their program like libarchive does without liblzo2.
// uu and rpm are not decoded: their bidders are not modelled, such data
// is read as it is (PORTING.md)

mod bzip2;
mod compress;
mod gzip;
mod lz4;
mod program;
mod xz;
mod zstd;

use std::cell::Cell;
use std::fs::File;
use std::io::{self, BufRead, ErrorKind, Read};
use std::rc::Rc;

// archive_read.c: bidding rounds before "too many filters"
const MAX_NUMBER_FILTERS: usize = 25;

// the filters libarchive's bidders pick (ARCHIVE_FILTER_*), None for the
// client reader under them
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
	None,
	Gzip,
	Bzip2,
	Compress,
	Lzma,
	Xz,
	Lzip,
	Lrzip,
	Lzop,
	Grzip,
	Lz4,
	Zstd,
}

// a filter's read callback and what it reads from
trait Decode {
	// appends the next block of output; true when no block follows
	fn block(&mut self, out: &mut Vec<u8>) -> io::Result<bool>;
	// bytes the client reader has handed out (archive_filter_bytes(-1))
	fn offset(&self) -> u64;
	// the size of the blocks it hands on
	fn block_size(&self) -> usize;
}

// one archive_read_filter: its decoder and the read-ahead buffer over
// that decoder's blocks
pub struct Filter {
	decoder: Box<dyn Decode>,
	code: Code,
	// blocks read ahead, data[pos..] not consumed yet
	data: Vec<u8>,
	pos: usize,
	// no block follows (end_of_file)
	end: bool,
	// the read that failed the filter (fatal)
	failed: Option<Failure>,
	// client bytes read by the last block, shared with the Archive
	// (add.c's progress)
	consumed: Rc<Cell<u64>>,
}

// an io::Error kept to be returned again
struct Failure {
	kind: ErrorKind,
	os: Option<i32>,
	text: String,
}

impl Failure {
	fn new(e: &io::Error) -> Self {
		Failure {
			kind: e.kind(),
			os: e.raw_os_error(),
			text: e.to_string(),
		}
	}

	fn get(&self) -> io::Error {
		match self.os {
			Some(n) => io::Error::from_raw_os_error(n),
			None => io::Error::new(self.kind, self.text.clone()),
		}
	}
}

// libarchive's text for a filter failure, as io::Error's display
pub(crate) fn text(s: &str) -> io::Error {
	io::Error::other(s)
}

impl Filter {
	fn with(decoder: Box<dyn Decode>, code: Code) -> Self {
		Filter {
			decoder,
			code,
			data: Vec::new(),
			pos: 0,
			end: false,
			failed: None,
			consumed: Rc::default(),
		}
	}

	// the filter libarchive's bidders picked last
	pub fn code(&self) -> Code {
		self.code
	}

	// the blocks archive_read_data_block hands data out in: the top
	// filter's output blocks, the client's reads without one
	pub fn block_size(&self) -> usize {
		self.decoder.block_size()
	}

	// client bytes read by the last block of this filter
	pub fn consumed(&self) -> Rc<Cell<u64>> {
		self.consumed.clone()
	}

	fn offset(&self) -> u64 {
		self.decoder.offset()
	}

	// the read callback once more: a block, or the failure for good
	fn fill(&mut self) -> io::Result<()> {
		self.data.drain(..self.pos);
		self.pos = 0;
		let start = self.data.len();
		let r = self.decoder.block(&mut self.data);
		self.consumed.set(self.decoder.offset());
		match r {
			Ok(end) => {
				self.end = end || self.data.len() == start;
				Ok(())
			}
			Err(e) => {
				self.data.truncate(start);
				self.failed = Some(Failure::new(&e));
				Err(e)
			}
		}
	}

	// blocks until n bytes are buffered or the data ended
	fn ensure(&mut self, n: usize) -> io::Result<()> {
		if let Some(f) = &self.failed {
			return Err(f.get());
		}
		while self.data.len() - self.pos < n && !self.end {
			self.fill()?;
		}
		Ok(())
	}

	// __archive_read_filter_ahead(n): what is buffered, at least n
	// bytes; None when the data ends first, the error when it fails
	pub(crate) fn ahead(&mut self, n: usize) -> io::Result<Option<&[u8]>> {
		self.ensure(n)?;
		let d = &self.data[self.pos..];
		Ok((d.len() >= n).then_some(d))
	}

	// __archive_read_filter_consume of buffered bytes
	pub(crate) fn advance(&mut self, n: usize) {
		self.pos += n;
	}

	// __archive_read_filter_consume of any count (advance_file_pointer):
	// the bytes skipped, fewer when the data ended
	pub(crate) fn skip(&mut self, mut n: u64) -> io::Result<u64> {
		let mut done = 0;
		loop {
			let avail = (self.data.len() - self.pos) as u64;
			let k = avail.min(n);
			self.pos += k as usize;
			done += k;
			n -= k;
			if n == 0 || self.end {
				return Ok(done);
			}
			self.ensure(1)?;
		}
	}

	// what the bidders see: n bytes ahead, nothing on failure
	fn peek(&mut self, n: usize) -> Option<&[u8]> {
		self.ahead(n).ok().flatten()
	}
}

impl Read for Filter {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		let d = self.fill_buf()?;
		let n = buf.len().min(d.len());
		buf[..n].copy_from_slice(&d[..n]);
		self.pos += n;
		Ok(n)
	}
}

impl BufRead for Filter {
	fn fill_buf(&mut self) -> io::Result<&[u8]> {
		self.ensure(1)?;
		Ok(&self.data[self.pos..])
	}

	fn consume(&mut self, n: usize) {
		self.pos += n;
	}
}

// archive_read_open_fd's reads of bufsize
struct FileClient {
	file: File,
	size: usize,
	read: u64,
}

impl Decode for FileClient {
	fn block(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
		let start = out.len();
		out.resize(start + self.size, 0);
		let n = loop {
			match self.file.read(&mut out[start..]) {
				Err(e) if e.kind()
					== ErrorKind::Interrupted => {}
				r => break r?,
			}
		};
		out.truncate(start + n);
		self.read += n as u64;
		Ok(n == 0)
	}

	fn offset(&self) -> u64 {
		self.read
	}

	fn block_size(&self) -> usize {
		self.size
	}
}

// archive_read_open_memory: the data as one block
struct MemoryClient {
	data: Option<Vec<u8>>,
	read: u64,
}

impl Decode for MemoryClient {
	fn block(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
		let data = self.data.take().unwrap_or_default();
		self.read += data.len() as u64;
		out.extend_from_slice(&data);
		Ok(true)
	}

	fn offset(&self) -> u64 {
		self.read
	}

	fn block_size(&self) -> usize {
		self.read as usize
	}
}

// the bidder's init: the filter that decodes up's output
fn init(code: Code, up: Filter) -> io::Result<Filter> {
	let decoder: Box<dyn Decode> = match code {
		Code::Gzip => Box::new(gzip::Gzip::new(up)),
		Code::Bzip2 => Box::new(bzip2::Bzip2::new(up)),
		Code::Zstd => Box::new(zstd::Zstd::new(up)?),
		Code::Compress => Box::new(compress::Compress::new(up)),
		Code::Xz | Code::Lzma | Code::Lzip => {
			Box::new(xz::Xz::new(up, code)?)
		}
		Code::Lz4 => Box::new(lz4::Lz4::new(up)),
		Code::Lrzip => {
			program::Program::spawn(up, "lrzip", &["-d", "-q"])
		}
		Code::Lzop => program::Program::spawn(up, "lzop", &["-d"]),
		Code::Grzip => program::Program::spawn(up, "grzip", &["-d"]),
		Code::None => unreachable!("no bidder picks the client"),
	};
	Ok(Filter::with(decoder, code))
}

// archive_read_open's choose_filters over the client: bid, stack the
// winner, bid again; with no bid, verify the top filter by asking it for
// data. a failure on the way fails the open
fn choose_filters(client: Box<dyn Decode>) -> io::Result<Filter> {
	let mut top = Filter::with(client, Code::None);
	for _ in 0..MAX_NUMBER_FILTERS {
		match bid(&mut top) {
			Some(code) => top = init(code, top)?,
			None => {
				top.ensure(1)?;
				return Ok(top);
			}
		}
	}
	Err(text("Input requires too many filters for decoding"))
}

// archive_read_open_fd with bufsize, and the filters on its data
pub fn open_file(file: File, bufsize: usize) -> io::Result<Filter> {
	choose_filters(Box::new(FileClient {
		file,
		size: bufsize,
		read: 0,
	}))
}

// archive_read_open_memory, and the filters on the data
pub fn open_memory(data: Vec<u8>) -> io::Result<Filter> {
	choose_filters(Box::new(MemoryClient {
		data: Some(data),
		read: 0,
	}))
}

// choose_filters' bidding round on f's output: every bidder in
// registration order (each may read ahead), the best bid, the first of
// equal ones
fn bid(f: &mut Filter) -> Option<Code> {
	let bids = [
		(Code::Bzip2, bzip2_bid(f)),
		(Code::Compress, compress_bid(f)),
		(Code::Gzip, gzip_bid(f)),
		(Code::Lzip, lzip_bid(f)),
		(Code::Lzma, lzma_bid(f)),
		(Code::Xz, xz_bid(f)),
		(Code::None, uu_bid(f)),
		(Code::Lrzip, lrzip_bid(f)),
		(Code::Lzop, magic_bid(f, b"\x89LZO\x00\r\n\x1a\n")),
		(Code::Grzip, magic_bid(f, b"GRZipII\x00\x02\x04:)")),
		(Code::Lz4, lz4_bid(f)),
		(Code::Zstd, zstd_bid(f)),
	];
	let mut best = None;
	let mut best_bid = 0;
	for (code, b) in bids {
		if b > best_bid {
			best_bid = b;
			best = Some(code);
		}
	}
	best
}

fn le16(d: &[u8]) -> usize {
	usize::from(u16::from_le_bytes([d[0], d[1]]))
}

pub(crate) fn le32(d: &[u8]) -> u32 {
	u32::from_le_bytes([d[0], d[1], d[2], d[3]])
}

fn le64(d: &[u8]) -> u64 {
	u64::from_le_bytes(d[..8].try_into().unwrap())
}

// bzip2_reader_bid: "BZh", a level digit, a block or end-of-stream magic
pub(crate) fn bzip2_bid(f: &mut Filter) -> i32 {
	let Some(p) = f.peek(14) else {
		return 0;
	};
	if !p.starts_with(b"BZh") || !(b'1'..=b'9').contains(&p[3]) {
		return 0;
	}
	let magic = &p[4..10];
	if magic != b"\x31\x41\x59\x26\x53\x59"
		&& magic != b"\x17\x72\x45\x38\x50\x90"
	{
		return 0;
	}
	24 + 5 + 48
}

// compress_bidder_bid: the magic, reserved bits of the third byte clear
fn compress_bid(f: &mut Filter) -> i32 {
	match f.peek(3) {
		Some(p) if p.starts_with(b"\x1f\x9d") && p[2] & 0x60 == 0 => 18,
		_ => 0,
	}
}

// peek_at_header's limits on the name and comment searched for their nul
const MAX_FILENAME_LENGTH: usize = 1024 * 1024;
const MAX_COMMENT_LENGTH: usize = 1024 * 1024;

// peek_at_header: the header's length, 0 unless it is deflate, has no
// reserved flags and its optional extra field, name, comment and header
// crc are all there. avail is what the filter has buffered
pub(crate) fn gzip_header(f: &mut Filter) -> usize {
	let Some(p) = f.peek(10) else {
		return 0;
	};
	if !p.starts_with(b"\x1f\x8b\x08") || p[3] & 0xe0 != 0 {
		return 0;
	}
	let flags = p[3];
	let mut avail = p.len();
	let mut len = 10;
	if flags & 4 != 0 {
		let Some(p) = f.peek(len + 2) else {
			return 0;
		};
		avail = p.len();
		len += le16(&p[len..]) + 2;
	}
	for (bit, max) in [(8, MAX_FILENAME_LENGTH), (16, MAX_COMMENT_LENGTH)] {
		if flags & bit == 0 {
			continue;
		}
		loop {
			len += 1;
			if avail < len && avail > max {
				return 0;
			}
			let Some(p) = f.peek(len) else {
				return 0;
			};
			avail = p.len();
			if p[len - 1] == 0 {
				break;
			}
		}
	}
	if flags & 2 != 0 {
		if f.peek(len + 2).is_none() {
			return 0;
		}
		len += 2;
	}
	len
}

// gzip_bidder_bid
fn gzip_bid(f: &mut Filter) -> i32 {
	match gzip_header(f) {
		0 => 0,
		_ => 24 + 3,
	}
}

// lzip_has_member: "LZIP", version 0 or 1, a dictionary size of 2^12 to
// 2^29
pub(crate) fn lzip_bid(f: &mut Filter) -> i32 {
	let Some(p) = f.peek(6) else {
		return 0;
	};
	if !p.starts_with(b"LZIP") || p[4] > 1 {
		return 0;
	}
	if !(12..=29).contains(&(p[5] & 0x1f)) {
		return 0;
	}
	32 + 8 + 8
}

// lzma_bidder_bid: lzma_alone's properties byte, an unknown size, a
// dictionary size lzma tools write
fn lzma_bid(f: &mut Filter) -> i32 {
	let Some(p) = f.peek(14) else {
		return 0;
	};
	if p[0] > (4 * 5 + 4) * 9 + 8 {
		return 0;
	}
	let mut bits = 0;
	if p[0] == 0x5d || p[0] == 0x5e {
		bits += 8;
	}
	if le64(&p[5..]) == u64::MAX {
		bits += 64;
	}
	let dicsize = le32(&p[1..]);
	// 2^12 to 2^27, or lzma's -1 MiB steps on low memory
	let steps = (0x0030_0000..=0x03f0_0000).contains(&dicsize)
		&& dicsize & ((1 << 20) - 1) == 0
		&& bits == 8 + 64;
	if (dicsize.is_power_of_two() && (12..=27).contains(&dicsize.ilog2()))
		|| steps
	{
		return bits + 32;
	}
	0
}

// xz_bidder_bid: the stream header magic
fn xz_bid(f: &mut Filter) -> i32 {
	match f.peek(6) {
		Some(p) if p.starts_with(b"\xfd7zXZ\x00") => 48,
		_ => 0,
	}
}

// bytes uudecode_bidder_bid's line scan goes on over (its ascii table)
fn is_uu_text(c: &u8) -> bool {
	matches!(c, b' '..=b'~' | b'\n' | b'\r')
}

// uudecode_bidder_bid for its read-ahead only: while the block is text
// lines it reads on to UUENCODE_BID_MAX_READ (128 KiB). a "begin " line,
// which makes it bid, is not modelled
fn uu_bid(f: &mut Filter) -> i32 {
	if f.peek(1).is_some_and(|d| d.iter().all(is_uu_text)) {
		let _ = f.peek(128 * 1024);
	}
	0
}

// lrzip_bidder_bid: "LRZI", major version 0, minor 6 to 10
fn lrzip_bid(f: &mut Filter) -> i32 {
	match f.peek(6) {
		Some(p) if p.starts_with(b"LRZI\x00")
			&& (6..=10).contains(&p[5]) =>
		{
			6
		}
		_ => 0,
	}
}

// lzop_bidder_bid, grzip_bidder_bid: the magic, 8 bits per byte
fn magic_bid(f: &mut Filter, magic: &[u8]) -> i32 {
	match f.peek(magic.len()) {
		Some(p) if p.starts_with(magic) => magic.len() as i32 * 8,
		_ => 0,
	}
}

// lz4 and zstd skippable frames: magic 0x184d2a5?, then their size
const SKIPPABLE_MASK: u32 = 0xffff_fff0;
const SKIPPABLE_START: u32 = 0x184d_2a50;

// lz4_reader_bid and zstd_bidder_bid skip skippable frames (looking at
// most 64 KiB ahead) to the first real frame: its offset and magic. need
// is what a frame needs after it, avail what the filter has buffered
fn skip_frames(
	f: &mut Filter,
	first: usize,
	need: usize,
) -> Option<(usize, u32)> {
	let p = f.peek(first)?;
	let mut avail = p.len();
	let mut magic = le32(p);
	let mut off = 0usize;
	while magic & SKIPPABLE_MASK == SKIPPABLE_START {
		off += 4;
		if off + 4 > avail {
			avail = f.peek(off + 4)?.len();
		}
		let size = le32(&f.peek(off + 4)?[off..]) as usize;
		off = off.checked_add(4 + size)?;
		let min = off.checked_add(need)?;
		if min > avail {
			if min > 64 * 1024 {
				return None;
			}
			avail = f.peek(min)?.len();
		}
		magic = le32(&f.peek(off + 4)?[off..]);
	}
	Some((off, magic))
}

// lz4_reader_bid: a frame with a valid descriptor's first bytes, or a
// legacy frame, after any skippable ones. the bid counts the skipped
// bytes too
fn lz4_bid(f: &mut Filter) -> i32 {
	let Some((off, magic)) = skip_frames(f, 11, 8) else {
		return 0;
	};
	let bits = off as i32;
	if magic == 0x184c_2102 {
		return bits + 32;
	}
	if magic != 0x184d_2204 {
		return 0;
	}
	let Some(p) = f.peek(off + 6) else {
		return 0;
	};
	let (flag, bd) = (p[off + 4], p[off + 5]);
	if flag >> 6 != 1
		|| flag & 2 != 0
		|| (bd & 0x70) >> 4 < 4
		|| bd & !0x70 != 0
	{
		return 0;
	}
	bits + 48
}

// zstd_bidder_bid: a frame magic after any skippable frames
fn zstd_bid(f: &mut Filter) -> i32 {
	match skip_frames(f, 8, 8) {
		Some((off, 0xfd2f_b528)) => off as i32 + 4,
		_ => 0,
	}
}
