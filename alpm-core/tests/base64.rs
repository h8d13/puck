// unit tests for alpm_core::base64
use alpm_core::base64::*;

#[test]
fn rfc4648_vectors() {
	let cases: &[(&[u8], &[u8])] = &[
		(b"", b""),
		(b"Zg==", b"f"),
		(b"Zm8=", b"fo"),
		(b"Zm9v", b"foo"),
		(b"Zm9vYg==", b"foob"),
		(b"Zm9vYmE=", b"fooba"),
		(b"Zm9vYmFy", b"foobar"),
	];
	for &(enc, raw) in cases {
		assert_eq!(decode(enc).unwrap(), raw, "{enc:?}");
	}
}

#[test]
fn line_breaks_and_rejects() {
	assert_eq!(decode(b"Zm9v\r\nYmFy\n").unwrap(), b"foobar");
	assert_eq!(decode(b"Zm9v\rYmFy"), Err(Error::InvalidCharacter));
	assert_eq!(decode(b"Zg==="), Err(Error::InvalidCharacter));
	assert_eq!(decode(b"Zg=a"), Err(Error::InvalidCharacter));
	assert_eq!(decode(b"Zm9v\xc3"), Err(Error::InvalidCharacter));
	// trailing partial group dropped, the crate alone decodes or rejects it
	assert_eq!(decode(b"Zm9vYg").unwrap(), b"foo");
	assert_eq!(decode(b"Zm9vZ").unwrap(), b"foo");
	assert_eq!(decode(b"Zm9vZg=").unwrap(), b"foo");
	// bits past the kept bytes ignored
	assert_eq!(decode(b"Zh==").unwrap(), b"f");
	assert_eq!(decoded_len(b"Zm9v\r\nYg"), Ok(5));
}
