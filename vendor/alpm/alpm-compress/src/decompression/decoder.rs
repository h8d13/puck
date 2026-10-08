//! Decoder for decompression which supports multiple backends.

use std::{
    fmt::Debug,
    fs::File,
    io::{BufRead, BufReader, Read},
};

use bzip2::bufread::BzDecoder;
use flate2::bufread::MultiGzDecoder;
use liblzma::bufread::XzDecoder;
use zstd::Decoder;

use crate::{Error, decompression::DecompressionSettings};

/// Decoder for decompression which supports multiple backends.
///
/// Wraps [`BzDecoder`], [`MultiGzDecoder`], [`XzDecoder`] and [`Decoder`]
/// and provides a unified [`Read`] implementation across all of them.
///
/// The compressed data is read from `R`, a [`BufReader`] over a [`File`] by default.
pub enum CompressionDecoder<'a, R: BufRead = BufReader<File>> {
    /// The bzip2 decompression decoder.
    Bzip2(BzDecoder<R>),

    /// The gzip decompression decoder.
    ///
    /// Like `gzip` and libarchive, it reads all concatenated gzip members.
    Gzip(MultiGzDecoder<R>),

    /// The xz decompression decoder.
    Xz(XzDecoder<R>),

    /// The zstd decompression decoder.
    Zstd(Decoder<'a, R>),

    /// No compression.
    None(R),
}

impl CompressionDecoder<'_> {
    /// Creates a new [`CompressionDecoder`].
    ///
    /// Uses a [`File`] to stream from and initializes a specific backend based on the provided
    /// [`DecompressionSettings`].
    ///
    /// # Errors
    ///
    /// Returns an error if creating the decoder for zstd compression fails
    /// (all other decoder initializations are infallible).
    pub fn new(file: File, settings: DecompressionSettings) -> Result<Self, Error> {
        Self::from_reader(BufReader::new(file), settings)
    }
}

impl<R: BufRead> CompressionDecoder<'_, R> {
    /// Creates a new [`CompressionDecoder`] that reads the compressed data from `reader`.
    ///
    /// Allows decompressing data that is not in a [`File`], e.g. a buffer in memory.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Read;
    ///
    /// use alpm_compress::decompression::{CompressionDecoder, DecompressionSettings};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let data: &[u8] = b"plain data";
    /// let mut decoder = CompressionDecoder::from_reader(data, DecompressionSettings::None)?;
    /// let mut out = String::new();
    /// decoder.read_to_string(&mut out)?;
    /// assert_eq!(out, "plain data");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if creating the decoder for zstd compression fails
    /// (all other decoder initializations are infallible).
    pub fn from_reader(reader: R, settings: DecompressionSettings) -> Result<Self, Error> {
        match settings {
            DecompressionSettings::Bzip2 => Ok(Self::Bzip2(BzDecoder::new(reader))),
            DecompressionSettings::Gzip => Ok(Self::Gzip(MultiGzDecoder::new(reader))),
            DecompressionSettings::Xz => Ok(Self::Xz(XzDecoder::new(reader))),
            DecompressionSettings::Zstd => Ok(Self::Zstd(
                Decoder::with_buffer(reader).map_err(Error::CreateZstandardDecoder)?,
            )),
            DecompressionSettings::None => Ok(Self::None(reader)),
        }
    }

    /// Returns a reference to the reader of the compressed data.
    pub fn get_ref(&self) -> &R {
        match self {
            CompressionDecoder::Bzip2(decoder) => decoder.get_ref(),
            CompressionDecoder::Gzip(decoder) => decoder.get_ref(),
            CompressionDecoder::Xz(decoder) => decoder.get_ref(),
            CompressionDecoder::Zstd(decoder) => decoder.get_ref(),
            CompressionDecoder::None(reader) => reader,
        }
    }
}

impl<R: BufRead> Debug for CompressionDecoder<'_, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CompressionDecoder({})",
            match self {
                CompressionDecoder::Bzip2(_) => "Bzip2",
                CompressionDecoder::Gzip(_) => "Gzip",
                CompressionDecoder::Xz(_) => "Xz",
                CompressionDecoder::Zstd(_) => "Zstd",
                CompressionDecoder::None(_) => "None",
            }
        )
    }
}

impl<R: BufRead> Read for CompressionDecoder<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            CompressionDecoder::Bzip2(decoder) => decoder.read(buf),
            CompressionDecoder::Gzip(decoder) => decoder.read(buf),
            CompressionDecoder::Xz(decoder) => decoder.read(buf),
            CompressionDecoder::Zstd(decoder) => decoder.read(buf),
            CompressionDecoder::None(reader) => reader.read(buf),
        }
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        match self {
            CompressionDecoder::Bzip2(decoder) => decoder.read_to_end(buf),
            CompressionDecoder::Gzip(decoder) => decoder.read_to_end(buf),
            CompressionDecoder::Xz(decoder) => decoder.read_to_end(buf),
            CompressionDecoder::Zstd(decoder) => decoder.read_to_end(buf),
            CompressionDecoder::None(reader) => reader.read_to_end(buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};

    use rstest::rstest;
    use tempfile::tempfile;
    use testresult::TestResult;

    use super::*;
    use crate::compression::{
        Bzip2CompressionLevel,
        CompressionEncoder,
        CompressionSettings,
        GzipCompressionLevel,
        XzCompressionLevel,
        ZstdCompressionLevel,
        ZstdThreads,
    };

    /// Ensures that the [`CompressionDecoder`] can decompress data compressed by
    /// [`CompressionEncoder`].
    #[rstest]
    #[case::bzip2(DecompressionSettings::Bzip2, CompressionSettings::Bzip2 {
        compression_level: Bzip2CompressionLevel::default()
    })]
    #[case::gzip(DecompressionSettings::Gzip, CompressionSettings::Gzip {
        compression_level: GzipCompressionLevel::default()
    })]
    #[case::xz(DecompressionSettings::Xz, CompressionSettings::Xz {
        compression_level: XzCompressionLevel::default()
    })]
    #[case::zstd(DecompressionSettings::Zstd, CompressionSettings::Zstd {
        compression_level: ZstdCompressionLevel::default(),
        threads: ZstdThreads::new(0),
    })]
    #[case::no_compression(DecompressionSettings::None, CompressionSettings::None)]
    fn test_compression_decoder_roundtrip(
        #[case] decompression_settings: DecompressionSettings,
        #[case] compression_settings: CompressionSettings,
    ) -> TestResult {
        // Prepare some sample data
        let input_data = b"alpm4ever";

        // Compress it
        let mut file = tempfile()?;
        {
            let mut encoder = CompressionEncoder::new(file.try_clone()?, &compression_settings)?;
            encoder.write_all(input_data)?;
            encoder.flush()?;
            encoder.finish()?;
        }

        // Rewind the file
        file.rewind()?;
        let mut compressed = Vec::new();
        file.read_to_end(&mut compressed)?;
        file.rewind()?;

        // Decompress it
        let mut decoder = CompressionDecoder::new(file, decompression_settings.clone())?;
        let mut output = Vec::new();
        decoder.read_to_end(&mut output)?;

        // Check data integrity
        assert_eq!(output, input_data);

        // Decompress it from memory
        let mut decoder =
            CompressionDecoder::from_reader(compressed.as_slice(), decompression_settings)?;
        let mut output = Vec::new();
        decoder.read_to_end(&mut output)?;
        assert_eq!(output, input_data);
        Ok(())
    }

    /// Ensures that all members of multi-member gzip data are decompressed.
    #[test]
    fn test_compression_decoder_gzip_members() -> TestResult {
        let settings = CompressionSettings::Gzip {
            compression_level: GzipCompressionLevel::default(),
        };
        let mut file = tempfile()?;
        for member in [b"alpm".as_slice(), b"4ever"] {
            let mut encoder = CompressionEncoder::new(file.try_clone()?, &settings)?;
            encoder.write_all(member)?;
            encoder.finish()?;
        }
        file.rewind()?;

        let mut decoder = CompressionDecoder::new(file, DecompressionSettings::Gzip)?;
        let mut output = Vec::new();
        decoder.read_to_end(&mut output)?;
        assert_eq!(output, b"alpm4ever");
        Ok(())
    }

    #[rstest]
    #[case::bzip2(DecompressionSettings::Bzip2)]
    #[case::gzip(DecompressionSettings::Gzip)]
    #[case::xz(DecompressionSettings::Xz)]
    #[case::zstd(DecompressionSettings::Zstd)]
    #[case::no_compression(DecompressionSettings::None)]
    fn test_compression_decoder_debug(#[case] settings: DecompressionSettings) -> TestResult {
        let file = tempfile()?;
        let decoder = CompressionDecoder::new(file, settings)?;
        let debug_str = format!("{decoder:?}");
        assert!(debug_str.contains("CompressionDecoder"));
        Ok(())
    }
}
