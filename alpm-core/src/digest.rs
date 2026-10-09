//! alpm_compute_md5sum and alpm_compute_sha256sum's digests, and the
//! expected values of tests: md-5 and sha2 (ALPM's own digest crates)
//! used directly, hex lowercase like the C's hex_representation
use std::io::{self, Read, Write};

pub use md5::Md5;
pub use sha2::Sha256;
pub use sha2::digest::{Digest, Output};

// a Digest as a Write, so io::copy feeds it: buffered reads, EINTR
// retried like the C's read loop
struct Hasher<D>(D);

impl<D: Digest> Write for Hasher<D> {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		self.0.update(buf);
		Ok(buf.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

/// the digest of everything r reads
pub fn of_reader<D: Digest>(mut r: impl Read) -> io::Result<Output<D>> {
	let mut h = Hasher(D::new());
	io::copy(&mut r, &mut h)?;
	Ok(h.0.finalize())
}

/// lowercase hex of a digest
pub fn hex(sum: &[u8]) -> Vec<u8> {
	const DIGITS: &[u8; 16] = b"0123456789abcdef";
	let mut out = Vec::with_capacity(sum.len() * 2);
	for b in sum {
		out.push(DIGITS[usize::from(b >> 4)]);
		out.push(DIGITS[usize::from(b & 15)]);
	}
	out
}
