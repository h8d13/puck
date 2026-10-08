// archive_read_support_filter_xz.c: xz (lzma_stream_decoder, concatenated
// streams), lzma (lzma_alone_decoder) and lzip, all through liblzma like
// libarchive; for lzip its own member framing around a raw LZMA1 decoder
// (header, crc32 and size checks in the trailer, further members while
// the data after one looks like a member; anything else is ignored). the
// data's end finishes the decoder (LZMA_FINISH), a stream cut short ends
// in liblzma's "no progress"

use std::io::{self, BufRead};

use flate2::Crc;
use liblzma::stream::{Action, CONCATENATED, Error, Filters, Status, Stream};

use super::{Code, Decode, Filter, le32, lzip_bid, text};

const OUT_BLOCK_SIZE: usize = 64 * 1024;

pub(super) struct Xz {
	up: Box<Filter>,
	lzip: bool,
	stream: Option<Stream>,
	// a stream (lzip: a member) is being decoded
	in_stream: bool,
	eof: bool,
	// lzip only
	lzip_ver: u8,
	crc32: Crc,
	member_in: u64,
	member_out: u64,
}

// set_error's texts for liblzma's results
fn lzma_error(e: Error) -> io::Error {
	text(match e {
		Error::Mem => "Lzma library error: Cannot allocate memory",
		Error::MemLimit => "Lzma library error: Out of memory",
		Error::Format => "Lzma library error: format not recognized",
		Error::Options => "Lzma library error: Invalid options",
		Error::Data => "Lzma library error: Corrupted input data",
		_ => "Lzma decompression failed:  Unknown error",
	})
}

fn no_progress() -> io::Error {
	text("Lzma library error:  No progress is possible")
}

impl Xz {
	// xz_lzma_bidder_init: lzip's decoder waits for its header
	pub(super) fn new(up: Filter, code: Code) -> io::Result<Self> {
		let lzip = code == Code::Lzip;
		let stream = match code {
			Code::Xz => Some(Stream::new_stream_decoder(
				u64::MAX,
				CONCATENATED,
			)),
			Code::Lzma => Some(Stream::new_lzma_decoder(u64::MAX)),
			_ => None,
		};
		Ok(Xz {
			up: Box::new(up),
			lzip,
			stream: stream.transpose().map_err(lzma_error)?,
			in_stream: !lzip,
			eof: false,
			lzip_ver: 0,
			crc32: Crc::new(),
			member_in: 0,
			member_out: 0,
		})
	}

	// lzip_init: the member header gives the dictionary size of the raw
	// LZMA1 decoder (lc 3, lp 0, pb 2 always)
	fn lzip_init(&mut self) -> io::Result<()> {
		// the bidder or lzip_tail saw the header: only a failed
		// upstream fails here, libarchive sets no text then
		let Some(h) = self.up.ahead(6)? else {
			return Err(text("Lzip: truncated member header"));
		};
		self.lzip_ver = h[4];
		let log2dic = u32::from(h[5] & 0x1f);
		if !(12..=29).contains(&log2dic) {
			return Err(text("Lzip: invalid dictionary size"));
		}
		let mut dicsize: u32 = 1 << log2dic;
		if log2dic > 12 {
			dicsize -= (dicsize / 16) * u32::from(h[5] >> 5);
		}
		self.up.advance(6);
		self.member_in = 6;
		let mut props = [0x5d, 0, 0, 0, 0];
		props[1..].copy_from_slice(&dicsize.to_le_bytes());
		let mut filters = Filters::new();
		filters.lzma1_properties(&props).map_err(lzma_error)?;
		let stream = Stream::new_raw_decoder(&filters)
			.map_err(lzma_error)?;
		self.stream = Some(stream);
		Ok(())
	}

	// lzip_tail: the member trailer (crc32, data size, member size for
	// version 1), then the next member if the data goes on with one
	fn lzip_tail(&mut self) -> io::Result<()> {
		let tail = if self.lzip_ver == 0 { 12 } else { 20 };
		let Some(p) = self.up.ahead(tail)? else {
			return Err(text("Lzip: Remaining data is less bytes"));
		};
		if self.crc32.sum() != le32(p) {
			return Err(text("Lzip: CRC32 error"));
		}
		if self.member_out
			!= u64::from_le_bytes(p[4..12].try_into().unwrap())
		{
			return Err(text("Lzip: Uncompressed size error"));
		}
		if self.lzip_ver == 1
			&& self.member_in + tail as u64
				!= u64::from_le_bytes(
					p[12..20].try_into().unwrap(),
				) {
			return Err(text("Lzip: Member size error"));
		}
		self.up.advance(tail);
		if lzip_bid(&mut self.up) != 0 {
			self.in_stream = false;
			self.crc32 = Crc::new();
			self.member_out = 0;
			self.member_in = 0;
			self.eof = false;
		}
		Ok(())
	}

	// xz_filter_read's loop: decode until the block is full or the
	// stream ends; the output count
	fn fill(&mut self, out: &mut [u8]) -> io::Result<usize> {
		let mut pos = 0;
		while pos < out.len() && !self.eof {
			if !self.in_stream {
				self.lzip_init()?;
				self.in_stream = true;
			}
			let input = match self.up.fill_buf() {
				Ok(d) => d,
				Err(_) => return Err(text("truncated input")),
			};
			let action = if input.is_empty() {
				Action::Finish
			} else {
				Action::Run
			};
			let stream =
				self.stream.as_mut().expect("decoder set up");
			let (in0, out0) =
				(stream.total_in(), stream.total_out());
			let r = stream.process(input, &mut out[pos..], action);
			let used = (stream.total_in() - in0) as usize;
			pos += (stream.total_out() - out0) as usize;
			match r {
				Ok(Status::StreamEnd) => self.eof = true,
				Ok(Status::Ok) => {}
				Ok(Status::MemNeeded) => {
					return Err(no_progress());
				}
				Ok(Status::GetCheck) => {
					return Err(lzma_error(Error::Program));
				}
				Err(e) => return Err(lzma_error(e)),
			}
			self.up.consume(used);
			self.member_in += used as u64;
		}
		Ok(pos)
	}
}

impl Decode for Xz {
	// xz_filter_read: a block, empty at the end. lzip checks a member's
	// trailer in the read that decoded its end, and goes on with the
	// next member in the same read when that read decoded nothing
	fn block(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
		let start = out.len();
		loop {
			let member_in = self.member_in;
			out.resize(start + OUT_BLOCK_SIZE, 0);
			let n = self.fill(&mut out[start..]);
			let n = match n {
				Ok(n) => n,
				Err(e) => {
					out.truncate(start);
					return Err(e);
				}
			};
			out.truncate(start + n);
			self.member_out += n as u64;
			if n > 0 {
				if self.lzip {
					self.crc32.update(&out[start..]);
					if self.eof {
						self.lzip_tail()?;
					}
				}
				return Ok(false);
			}
			if member_in != self.member_in && self.lzip && self.eof
			{
				self.lzip_tail()?;
				if !self.eof {
					continue;
				}
			}
			return Ok(true);
		}
	}

	fn offset(&self) -> u64 {
		self.up.offset()
	}

	fn block_size(&self) -> usize {
		OUT_BLOCK_SIZE
	}
}
