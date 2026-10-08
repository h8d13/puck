// archive_read_support_filter_zstd.c over the zstd crate's streaming
// decoder (ZSTD_decompressStream in the C, the same libzstd): frames one
// after the other, the data ending outside a frame is the clean end,
// inside one "Truncated zstd input", even with output still pending

use std::io;

use zstd::stream::raw::{Decoder, InBuffer, Operation, OutBuffer};

use super::{Decode, Filter, text};

// ZSTD_DStreamOutSize()
const OUT_BLOCK_SIZE: usize = 128 * 1024;

pub(super) struct Zstd {
	up: Box<Filter>,
	decoder: Decoder<'static>,
	in_frame: bool,
	eof: bool,
}

impl Zstd {
	pub(super) fn new(up: Filter) -> io::Result<Self> {
		let decoder = Decoder::new().map_err(|e| {
			text(&format!(
				"Can't allocate data for zstd decompression: {e}"
			))
		})?;
		Ok(Zstd {
			up: Box::new(up),
			decoder,
			in_frame: false,
			eof: false,
		})
	}
}

impl Decode for Zstd {
	// zstd_filter_read
	fn block(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
		let start = out.len();
		out.resize(start + OUT_BLOCK_SIZE, 0);
		let mut pos = start;
		while pos < out.len() && !self.eof {
			if !self.in_frame {
				self.decoder.reinit().map_err(|e| {
					text(&format!(
						"Error initializing zstd decompressor: {e}"
					))
				})?;
			}
			let input = match self.up.ahead(1)? {
				Some(d) => d,
				None if !self.in_frame => {
					self.eof = true;
					break;
				}
				None => {
					return Err(text(
						"Truncated zstd input",
					));
				}
			};
			let mut inb = InBuffer::around(input);
			let mut outb = OutBuffer::around_pos(&mut out[..], pos);
			let r = self.decoder.run(&mut inb, &mut outb);
			pos = outb.pos();
			let used = inb.pos();
			let ret = r.map_err(|e| {
				text(&format!("Zstd decompression failed: {e}"))
			})?;
			self.up.advance(used);
			// ret is above 0 while the frame is not done
			self.in_frame = ret != 0;
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
