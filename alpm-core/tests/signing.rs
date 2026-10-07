// unit tests for alpm_core::signing
use alpm_core::signing::*;

#[test]
fn unpadded_needs_room() {
	assert_eq!(decode_signature(b"Zm9v").unwrap(), b"foo");
	assert_eq!(decode_signature(b"Zg"), Err(DecodeError::BufferTooSmall));
	// line breaks count toward the 3/4 buffer, partial group dropped
	assert_eq!(decode_signature(b"Zg\n\n").unwrap(), b"");
	assert_eq!(decode_signature(b"\n\n\n\n").unwrap(), b"");
}
