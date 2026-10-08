// archive_read_support_filter_bzip2.c over the bzip2 crate's decompressor
// (BZ2_bzDecompress in the C): streams one after the other while
// libarchive's bidder takes the data after one (pbzip2 output), anything
// else after a stream is ignored. each pass asks upstream for data first:
// none left inside a stream fails the read, even with a decoded block
// still pending (a 900 KiB block is decoded whole)

use std::io;

use bzip2::{Decompress, Status};

use super::{Decode, Filter, bzip2_bid, text};

const OUT_BLOCK_SIZE: usize = 64 * 1024;

pub(super) struct Bzip2 {
	up: Box<Filter>,
	stream: Option<Decompress>,
	eof: bool,
}

impl Bzip2 {
	pub(super) fn new(up: Filter) -> Self {
		Bzip2 {
			up: Box::new(up),
			stream: None,
			eof: false,
		}
	}
}

impl Decode for Bzip2 {
	// bzip2_filter_read: a full block, or what came before the end
	fn block(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
		if self.eof {
			return Ok(true);
		}
		let start = out.len();
		out.resize(start + OUT_BLOCK_SIZE, 0);
		let mut pos = start;
		loop {
			if self.stream.is_none() {
				if bzip2_bid(&mut self.up) == 0 {
					self.eof = true;
					out.truncate(pos);
					return Ok(true);
				}
				self.stream = Some(Decompress::new(false));
			}
			let Ok(Some(input)) = self.up.ahead(1) else {
				return Err(text("truncated bzip2 input"));
			};
			let stream =
				self.stream.as_mut().expect("set up above");
			let (in0, out0) =
				(stream.total_in(), stream.total_out());
			let r = stream.decompress(input, &mut out[pos..]);
			let used = (stream.total_in() - in0) as usize;
			pos += (stream.total_out() - out0) as usize;
			self.up.advance(used);
			match r {
				Ok(Status::StreamEnd) => self.stream = None,
				Ok(Status::Ok) => {}
				_ => {
					return Err(text(
						"bzip decompression failed",
					));
				}
			}
			if pos == out.len() {
				return Ok(false);
			}
		}
	}

	fn offset(&self) -> u64 {
		self.up.offset()
	}

	fn block_size(&self) -> usize {
		OUT_BLOCK_SIZE
	}
}
