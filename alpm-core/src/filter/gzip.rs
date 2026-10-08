// archive_read_support_filter_gzip.c over flate2's raw inflate (zlib's
// inflateInit2(-15) in the C): members while a header libarchive's bidder
// takes follows one, anything else after a member is ignored; the trailer
// is read but not checked (the C's "XXX TODO: Verify the length and
// CRC"). each pass asks upstream for data first: none left inside a
// member fails the read

use std::io;

use flate2::{Decompress, FlushDecompress, Status};

use super::{Decode, Filter, gzip_header, text};

const OUT_BLOCK_SIZE: usize = 64 * 1024;

pub(super) struct Gzip {
	up: Box<Filter>,
	inflate: Decompress,
	in_stream: bool,
	eof: bool,
}

impl Gzip {
	pub(super) fn new(up: Filter) -> Self {
		Gzip {
			up: Box::new(up),
			inflate: Decompress::new(false),
			in_stream: false,
			eof: false,
		}
	}

	// consume_header: false when no member follows
	fn consume_header(&mut self) -> io::Result<bool> {
		let len = gzip_header(&mut self.up);
		if len == 0 {
			return Ok(false);
		}
		self.up.advance(len);
		if self.up.ahead(1).is_err() {
			return Err(text("Failed to read gzip input"));
		}
		self.inflate = Decompress::new(false);
		self.in_stream = true;
		Ok(true)
	}

	// consume_trailer: its 8 bytes must be there
	fn consume_trailer(&mut self) -> io::Result<()> {
		self.in_stream = false;
		if self.up.ahead(8)?.is_none() {
			return Err(text("truncated gzip input"));
		}
		self.up.advance(8);
		Ok(())
	}
}

impl Decode for Gzip {
	// gzip_filter_read
	fn block(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
		let start = out.len();
		out.resize(start + OUT_BLOCK_SIZE, 0);
		let mut pos = start;
		while pos < out.len() && !self.eof {
			if !self.in_stream && !self.consume_header()? {
				self.eof = true;
				break;
			}
			let Ok(Some(input)) = self.up.ahead(1) else {
				return Err(text("truncated gzip input"));
			};
			let (in0, out0) = (
				self.inflate.total_in(),
				self.inflate.total_out(),
			);
			let r = self.inflate.decompress(
				input,
				&mut out[pos..],
				FlushDecompress::None,
			);
			let used = (self.inflate.total_in() - in0) as usize;
			let made = (self.inflate.total_out() - out0) as usize;
			pos += made;
			self.up.advance(used);
			match r {
				Ok(Status::StreamEnd) => {
					self.consume_trailer()?
				}
				Ok(Status::Ok) => {}
				// zlib's Z_BUF_ERROR is no progress at all
				Ok(Status::BufError) if used + made > 0 => {}
				_ => {
					return Err(text(
						"gzip decompression failed",
					));
				}
			}
		}
		out.truncate(pos);
		Ok(self.eof)
	}

	fn offset(&self) -> u64 {
		self.up.offset()
	}

	fn block_size(&self) -> usize {
		OUT_BLOCK_SIZE
	}
}
