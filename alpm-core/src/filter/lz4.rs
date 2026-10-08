// archive_read_support_filter_lz4.c: libarchive reads lz4 frames itself
// (descriptor, block sizes, xxhash32 checksums, skippable and legacy
// frames, several frames in a row) and has liblz4 decode the blocks:
// LZ4_decompress_safe, _usingDict with the previous 64 KiB for linked
// blocks. the blocks are decoded by lz4_flex here. each read hands on one
// lz4 block; data that is no frame after one ends the stream

use std::hash::Hasher;
use std::io;

use lz4_flex::block::{decompress_into, decompress_into_with_dict};
use twox_hash::XxHash32;

use super::{Decode, Filter, le32, text};

const MAGICNUMBER: u32 = 0x184d_2204;
const LEGACY: u32 = 0x184c_2102;
const LEGACY_BLOCK_SIZE: usize = 8 * 1024 * 1024;
const PREFIX: usize = 64 * 1024;

// LZ4_COMPRESSBOUND(LEGACY_BLOCK_SIZE)
const LEGACY_BOUND: u32 =
	(LEGACY_BLOCK_SIZE + LEGACY_BLOCK_SIZE / 255 + 16) as u32;

#[derive(Clone, Copy, PartialEq)]
enum Stage {
	Select,
	// a descriptor (legacy: first block) read failed
	DefaultStream,
	DefaultBlock,
	LegacyStream,
	LegacyBlock,
}

pub(super) struct Lz4 {
	up: Box<Filter>,
	stage: Stage,
	block_independence: bool,
	block_checksum: usize,
	stream_checksum: bool,
	block_maximum_size: usize,
	// linked blocks: the 64 KiB before the block, zero-filled
	prefix: Vec<u8>,
	// bytes of the last decoded block, 0 after a stored one
	decoded_size: usize,
	xxh32: Option<XxHash32>,
	// upstream bytes the last block used, consumed on the next read
	unconsumed: usize,
	eof: bool,
}

fn malformed() -> io::Error {
	text("malformed lz4 data")
}

fn truncated() -> io::Error {
	text("truncated lz4 input")
}

fn failed() -> io::Error {
	text("lz4 decompression failed")
}

// upstream bytes ahead, None when the data ends or fails first: every
// caller sets its own text then
fn ahead(up: &mut Filter, n: usize) -> Option<&[u8]> {
	up.ahead(n).ok().flatten()
}

// what a read returns: a block (possibly empty), or no block (*p NULL)
type Read = Option<Vec<u8>>;

impl Lz4 {
	pub(super) fn new(up: Filter) -> Self {
		Lz4 {
			up: Box::new(up),
			stage: Stage::Select,
			block_independence: false,
			block_checksum: 0,
			stream_checksum: false,
			block_maximum_size: 0,
			prefix: vec![0; PREFIX],
			decoded_size: 0,
			xxh32: None,
			unconsumed: 0,
			eof: false,
		}
	}

	// lz4_filter_read
	fn read(&mut self) -> io::Result<Read> {
		if self.eof {
			return Ok(None);
		}
		self.up.advance(self.unconsumed);
		self.unconsumed = 0;
		match self.stage {
			Stage::Select => {}
			Stage::DefaultStream | Stage::LegacyStream => {
				return Err(text("Invalid sequence"));
			}
			Stage::DefaultBlock | Stage::LegacyBlock => {
				let r = if self.stage == Stage::DefaultBlock {
					self.default_stream()?
				} else {
					self.legacy_stream()?
				};
				if r.as_ref().is_some_and(|b| !b.is_empty())
					|| self.stage != Stage::Select
				{
					return Ok(r);
				}
			}
		}
		while self.stage == Stage::Select {
			let Some(p) = ahead(&mut self.up, 4) else {
				self.eof = true;
				return Ok(None);
			};
			let number = le32(p);
			self.up.advance(4);
			if number == MAGICNUMBER {
				return self.default_stream();
			} else if number == LEGACY {
				return self.legacy_stream();
			} else if number & 0xffff_fff0 == 0x184d_2a50 {
				let Some(p) = ahead(&mut self.up, 4) else {
					return Err(text("Malformed lz4 data"));
				};
				let skip = 4 + u64::from(le32(p));
				if self.up.skip(skip).ok() != Some(skip) {
					return Err(text("Malformed lz4 data"));
				}
			} else {
				// data after the frames is ignored
				self.eof = true;
				return Ok(None);
			}
		}
		self.eof = true;
		Ok(None)
	}

	// lz4_filter_read_descriptor
	fn read_descriptor(&mut self) -> io::Result<()> {
		let Some(p) = ahead(&mut self.up, 2) else {
			return Err(truncated());
		};
		let (flag, bd) = (p[0], p[1]);
		if flag & 0xc0 != 1 << 6 || flag & 0x02 != 0 || bd & 0x8f != 0 {
			return Err(malformed());
		}
		self.block_independence = flag & 0x20 != 0;
		self.block_checksum = if flag & 0x10 != 0 { 4 } else { 0 };
		let stream_size = flag & 0x08 != 0;
		self.stream_checksum = flag & 0x04 != 0;
		let preset_dictionary = flag & 0x01 != 0;
		self.block_maximum_size = match bd >> 4 {
			4 => 64 * 1024,
			5 => 256 * 1024,
			6 => 1024 * 1024,
			7 => 4 * 1024 * 1024,
			_ => return Err(malformed()),
		};
		let mut len = 3;
		if stream_size {
			len += 8;
		}
		if preset_dictionary {
			len += 4;
		}
		let Some(p) = ahead(&mut self.up, len) else {
			return Err(truncated());
		};
		let sum = (XxHash32::oneshot(0, &p[..len - 1]) >> 8) & 0xff;
		if sum != u32::from(p[len - 1]) {
			return Err(malformed());
		}
		self.up.advance(len);
		// lz4_allocate_out_block: the prefix starts zeroed
		if !self.block_independence {
			self.prefix.fill(0);
		}
		if self.stream_checksum {
			self.xxh32 = Some(XxHash32::with_seed(0));
		}
		self.decoded_size = 0;
		Ok(())
	}

	// the prefix for the next linked block: the last 64 KiB of out,
	// zero-filled in front when it is shorter; an empty block keeps it
	fn keep_prefix(&mut self, out: &[u8]) {
		if out.is_empty() {
			return;
		}
		let n = out.len().min(PREFIX);
		self.prefix[..PREFIX - n].fill(0);
		self.prefix[PREFIX - n..]
			.copy_from_slice(&out[out.len() - n..]);
	}

	// lz4_filter_read_data_block: Some(empty) for an empty block, None
	// at the end mark
	fn read_data_block(&mut self) -> io::Result<Read> {
		let Some(p) = ahead(&mut self.up, 4) else {
			return Err(truncated());
		};
		let size = le32(p);
		let compressed = (size & 0x7fff_ffff) as usize;
		if compressed > self.block_maximum_size {
			return Err(malformed());
		}
		if size == 0 {
			self.up.advance(4);
			return Ok(None);
		}
		let stored = size & 0x8000_0000 != 0 && compressed != 0;
		let sum = self.block_checksum;
		let Some(p) = ahead(&mut self.up, 4 + compressed + sum) else {
			return Err(truncated());
		};
		let src = &p[4..4 + compressed];
		if sum != 0
			&& XxHash32::oneshot(0, src)
				!= le32(&p[4 + compressed..])
		{
			return Err(malformed());
		}
		self.unconsumed = 4 + compressed + sum;
		if stored {
			let block = src.to_vec();
			if !self.block_independence {
				self.keep_prefix(&block);
				self.decoded_size = 0;
			}
			return Ok(Some(block));
		}
		let mut out = vec![0; self.block_maximum_size];
		let r = if self.block_independence {
			decompress_into(src, &mut out)
		} else {
			// the C slides the last block's output in front of the
			// buffer first: the prefix is that block's
			decompress_into_with_dict(src, &mut out, &self.prefix)
		};
		let Ok(n) = r else {
			self.unconsumed = 0;
			return Err(failed());
		};
		out.truncate(n);
		if !self.block_independence {
			self.keep_prefix(&out);
		}
		self.decoded_size = n;
		Ok(Some(out))
	}

	// lz4_filter_read_default_stream: a descriptor first, then blocks; the
	// stream checksum after the end mark
	fn default_stream(&mut self) -> io::Result<Read> {
		if self.stage == Stage::Select {
			self.stage = Stage::DefaultStream;
			self.read_descriptor()?;
			self.stage = Stage::DefaultBlock;
		}
		let r = self.read_data_block()?;
		if r.is_none() {
			self.stage = Stage::Select;
		}
		let Some(h) =
			self.xxh32.as_mut().filter(|_| self.stream_checksum)
		else {
			return Ok(r);
		};
		match &r {
			Some(b) => h.write(b),
			None => {
				let digest = h.finish_32();
				self.xxh32 = None;
				let Some(p) = ahead(&mut self.up, 4) else {
					return Err(truncated());
				};
				let checksum = le32(p);
				self.up.advance(4);
				if checksum != digest {
					return Err(text(
						"lz4 stream checksum error",
					));
				}
			}
		}
		Ok(r)
	}

	// lz4_filter_read_legacy_stream: blocks of up to 8 MiB until a size
	// too large for one, which is read again as the next magic
	fn legacy_stream(&mut self) -> io::Result<Read> {
		let Some(p) = ahead(&mut self.up, 4) else {
			if self.stage == Stage::Select {
				self.stage = Stage::LegacyStream;
				return Err(truncated());
			}
			self.stage = Stage::Select;
			return Ok(Some(Vec::new()));
		};
		self.stage = Stage::LegacyBlock;
		let compressed = le32(p);
		if compressed > LEGACY_BOUND {
			self.stage = Stage::Select;
			return Ok(Some(Vec::new()));
		}
		let compressed = compressed as usize;
		let Some(p) = ahead(&mut self.up, 4 + compressed) else {
			return Err(truncated());
		};
		let mut out = vec![0; LEGACY_BLOCK_SIZE];
		let Ok(n) = decompress_into(&p[4..4 + compressed], &mut out)
		else {
			return Err(failed());
		};
		out.truncate(n);
		self.unconsumed = 4 + compressed;
		Ok(Some(out))
	}
}

impl Decode for Lz4 {
	fn block(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
		match self.read()? {
			Some(b) => {
				out.extend_from_slice(&b);
				Ok(false)
			}
			None => Ok(true),
		}
	}

	fn offset(&self) -> u64 {
		self.up.offset()
	}

	fn block_size(&self) -> usize {
		match self.stage {
			Stage::LegacyStream | Stage::LegacyBlock => {
				LEGACY_BLOCK_SIZE
			}
			_ => self.block_maximum_size,
		}
	}
}
