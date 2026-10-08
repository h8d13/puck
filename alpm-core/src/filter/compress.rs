// archive_read_support_filter_compress.c: compress (.Z), LZW, built into
// libarchive. a stream cut short is a shorter stream (getbits' end of
// data ends it cleanly), only an invalid code fails it

use std::io::{self, BufRead};

use super::{Decode, Filter, text};

const OUT_BLOCK_SIZE: usize = 64 * 1024;

const MASK: [u32; 17] = [
	0x00, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff, 0x1ff, 0x3ff,
	0x7ff, 0xfff, 0x1fff, 0x3fff, 0x7fff, 0xffff,
];

pub(super) struct Compress {
	up: Box<Filter>,
	// the upstream block getbits reads, next byte at next
	input: Vec<u8>,
	next: usize,
	bit_buffer: u32,
	bits_avail: u32,
	bytes_in_section: u32,

	initialized: bool,
	use_reset_code: bool,
	end_of_stream: bool,
	maxcode: u32,
	maxcode_bits: u32,
	section_end_code: u32,
	bits: u32,
	// -1 before the first code of a dictionary
	oldcode: i32,
	finbyte: u8,

	free_ent: u32,
	suffix: Vec<u8>,
	prefix: Vec<u16>,
	// an entry's expansion, popped from the end
	stack: Vec<u8>,
}

fn invalid() -> io::Error {
	text("Invalid compressed data")
}

impl Compress {
	pub(super) fn new(up: Filter) -> Self {
		Compress {
			up: Box::new(up),
			input: Vec::new(),
			next: 0,
			bit_buffer: 0,
			bits_avail: 0,
			bytes_in_section: 0,
			initialized: false,
			use_reset_code: false,
			end_of_stream: false,
			maxcode: 0,
			maxcode_bits: 0,
			section_end_code: 0,
			bits: 0,
			oldcode: -1,
			finbyte: 0,
			free_ent: 0,
			suffix: vec![0; 65536],
			prefix: vec![0; 65536],
			stack: Vec::new(),
		}
	}

	// compress_filter_init, on the first read: the header and the first
	// code. the signature bytes' and that code's results are ignored, so
	// an invalid first code is skipped like the C
	fn init(&mut self) -> io::Result<()> {
		self.initialized = true;
		let _ = self.getbits(8);
		let _ = self.getbits(8);
		let code = match self.getbits(8) {
			Ok(Some(c)) if c & 0x1f <= 16 => c,
			_ => return Err(invalid()),
		};
		self.maxcode_bits = code & 0x1f;
		self.maxcode = 1 << self.maxcode_bits;
		self.use_reset_code = code & 0x80 != 0;
		self.free_ent = 256;
		self.stack.clear();
		if self.use_reset_code {
			self.free_ent += 1;
		}
		self.bits = 9;
		self.section_end_code = (1 << self.bits) - 1;
		self.oldcode = -1;
		for code in 0..256 {
			self.prefix[code] = 0;
			self.suffix[code] = code as u8;
		}
		let _ = self.next_code();
		Ok(())
	}

	// the next n bits, None at the end of the data
	fn getbits(&mut self, n: u32) -> io::Result<Option<u32>> {
		while self.bits_avail < n {
			if self.next == self.input.len() {
				// __archive_read_filter_ahead(upstream, 1): all
				// it has buffered
				let chunk = self.up.fill_buf()?;
				if chunk.is_empty() {
					return Ok(None);
				}
				self.input = chunk.to_vec();
				self.next = 0;
				let k = self.input.len();
				self.up.consume(k);
			}
			let byte = u32::from(self.input[self.next]);
			self.bit_buffer |= byte << self.bits_avail;
			self.next += 1;
			self.bits_avail += 8;
			self.bytes_in_section += 1;
		}
		let code = self.bit_buffer;
		self.bit_buffer >>= n;
		self.bits_avail -= n;
		Ok(Some(code & MASK[n as usize]))
	}

	// next_code: one code expanded onto the stack; false at the end
	fn next_code(&mut self) -> io::Result<bool> {
		loop {
			let Some(newcode) = self.getbits(self.bits)? else {
				return Ok(false);
			};
			if newcode == 256 && self.use_reset_code {
				if !self.reset()? {
					return Ok(false);
				}
				continue;
			}
			let mut code = newcode;
			if code > self.free_ent
				|| (code == self.free_ent && self.oldcode < 0)
			{
				return Err(invalid());
			}
			// KwKwK: the entry being defined
			if code >= self.free_ent {
				self.stack.push(self.finbyte);
				code = self.oldcode as u32;
			}
			while code >= 256 {
				self.stack.push(self.suffix[code as usize]);
				code = u32::from(self.prefix[code as usize]);
			}
			self.finbyte = code as u8;
			self.stack.push(self.finbyte);

			let c = self.free_ent;
			if c < self.maxcode && self.oldcode >= 0 {
				self.prefix[c as usize] = self.oldcode as u16;
				self.suffix[c as usize] = self.finbyte;
				self.free_ent += 1;
			}
			if self.free_ent > self.section_end_code {
				self.bits += 1;
				self.bytes_in_section = 0;
				self.section_end_code =
					if self.bits == self.maxcode_bits {
						self.maxcode
					} else {
						(1 << self.bits) - 1
					};
			}
			self.oldcode = newcode as i32;
			return Ok(true);
		}
	}

	// the reset code: compress's writer padded the section to a multiple
	// of bits bytes, skipped here (the C keeps bit_buffer's stale bits,
	// they only reach the skipped bytes); false at the end of the data
	fn reset(&mut self) -> io::Result<bool> {
		let skip = (self.bits - self.bytes_in_section % self.bits)
			% self.bits;
		self.bits_avail = 0;
		for _ in 0..skip {
			if self.getbits(8)?.is_none() {
				return Ok(false);
			}
		}
		self.bytes_in_section = 0;
		self.bits = 9;
		self.section_end_code = (1 << self.bits) - 1;
		self.free_ent = 257;
		self.oldcode = -1;
		Ok(true)
	}
}

impl Decode for Compress {
	// compress_filter_read: a whole block, or less at the end
	fn block(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
		if !self.initialized {
			self.init()?;
		}
		let start = out.len();
		while out.len() - start < OUT_BLOCK_SIZE && !self.end_of_stream
		{
			match self.stack.pop() {
				Some(c) => out.push(c),
				None => {
					self.end_of_stream =
						!self.next_code()?
				}
			}
		}
		Ok(self.end_of_stream)
	}

	fn offset(&self) -> u64 {
		self.up.offset()
	}

	fn block_size(&self) -> usize {
		OUT_BLOCK_SIZE
	}
}
