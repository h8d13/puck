// port of lib/libalpm/base64.c (PolarSSL 0.14.2, decode only like upstream)
//
// base64_decode's framing is kept here, the bits are decoded by the base64
// crate: "\n" and "\r\n" skipped anywhere, up to two '=', nothing after
// padding, an incomplete trailing group dropped without error.

use ::base64::Engine;
use ::base64::alphabet::STANDARD;
use ::base64::engine::{
	DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
	InvalidCharacter,
}

// only whole groups reach the engine, '=' only at their end. the C keeps
// the top bits of a padded group and ignores the rest
const ENGINE: GeneralPurpose = GeneralPurpose::new(
	&STANDARD,
	GeneralPurposeConfig::new()
		.with_decode_padding_mode(DecodePaddingMode::Indifferent)
		.with_decode_allow_trailing_bits(true),
);

fn is_symbol(c: u8) -> bool {
	c.is_ascii_alphanumeric() || c == b'+' || c == b'/'
}

// the first pass of base64_decode: the symbols, padding included, with
// line breaks removed
fn symbols(src: &[u8]) -> Result<Vec<u8>, Error> {
	let mut out = Vec::with_capacity(src.len());
	let mut pads = 0;
	for (i, &c) in src.iter().enumerate() {
		// lone '\r' is rejected below, only "\r\n" is a line break
		if c == b'\n' || (c == b'\r' && src.get(i + 1) == Some(&b'\n'))
		{
			continue;
		}
		if c == b'=' {
			pads += 1;
			if pads > 2 {
				return Err(Error::InvalidCharacter);
			}
		} else if !is_symbol(c) || pads != 0 {
			// data after padding
			return Err(Error::InvalidCharacter);
		}
		out.push(c);
	}
	Ok(out)
}

// required output buffer size
pub fn decoded_len(src: &[u8]) -> Result<usize, Error> {
	Ok((symbols(src)?.len() * 6).div_ceil(8))
}

pub fn decode(src: &[u8]) -> Result<Vec<u8>, Error> {
	let s = symbols(src)?;
	// the C writes a group once its 4th symbol is read
	let whole = s.len() - s.len() % 4;
	ENGINE.decode(&s[..whole])
		.map_err(|_| Error::InvalidCharacter)
}
