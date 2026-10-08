//! File handling integration.

use std::io::Read;

use flate2::read::MultiGzDecoder;

use crate::Error;

/// Two magic bytes that occur at the beginning of gzip files and can be used to detect whether a
/// file is gzip compressed.
/// Spec: <https://datatracker.ietf.org/doc/html/rfc1952#page-6>
pub const GZIP_MAGIC_NUMBER: [u8; 2] = [0x1f, 0x8b];

/// Creates a [`String`] from a byte vector which may be gzip compressed.
///
/// If `buffer` contains gzip compressed data, it decompressed before converting it into a
/// `String` (see [`mtree_buffer_decompress`]).
///
/// # Errors
///
/// Returns an error if
/// - `buffer` contains invalid gzip compressed data
/// - or `buffer` can not be converted to `String`.
pub fn mtree_buffer_to_string(buffer: Vec<u8>) -> Result<String, Error> {
    Ok(String::from_utf8(mtree_buffer_decompress(buffer)?)?)
}

/// Decompresses a byte vector if it is gzip compressed.
///
/// Detects whether `buffer` contains gzip compressed data by checking if it is longer than two
/// bytes and whether the first two bytes are the [`GZIP_MAGIC_NUMBER`].
/// Like `gzip` and libarchive, all concatenated gzip members are read.
///
/// # Errors
///
/// Returns an error if `buffer` contains invalid gzip compressed data.
pub fn mtree_buffer_decompress(buffer: Vec<u8>) -> Result<Vec<u8>, Error> {
    if buffer.len() >= 2 && [buffer[0], buffer[1]] == GZIP_MAGIC_NUMBER {
        let mut decoder = MultiGzDecoder::new(buffer.as_slice());

        let mut content = Vec::new();
        decoder
            .read_to_end(&mut content)
            .map_err(Error::InvalidGzip)?;
        Ok(content)
    } else {
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{Compression, write::GzEncoder};
    use testresult::TestResult;

    use super::*;

    fn gzip(data: &[u8]) -> TestResult<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    /// Ensures that all members of multi-member gzip data are read.
    #[test]
    fn gzip_members() -> TestResult {
        let buffer = [gzip(b"#mtree\n")?, gzip(b"./a type=dir\n")?].concat();
        assert_eq!(mtree_buffer_to_string(buffer)?, "#mtree\n./a type=dir\n");
        Ok(())
    }
}
