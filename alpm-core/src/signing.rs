// port of lib/libalpm/signing.c, filled in as callers get ported

use crate::base64;
use crate::util::until_nul;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
	InvalidCharacter,
	// output is capped at 3/4 of the input length, so unpadded input whose
	// symbol count is not a multiple of 4 fails unless line breaks pad it
	BufferTooSmall,
}

// alpm_decode_signature
pub fn decode_signature(b64: &[u8]) -> Result<Vec<u8>, DecodeError> {
	let b64 = until_nul(b64);
	let cap = b64.len() * 3 / 4;
	let needed = base64::decoded_len(b64)
		.map_err(|_| DecodeError::InvalidCharacter)?;
	if needed > cap {
		return Err(DecodeError::BufferTooSmall);
	}
	base64::decode(b64).map_err(|_| DecodeError::InvalidCharacter)
}
