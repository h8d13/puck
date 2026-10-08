//! Settings for a compression decoder.

use std::{fmt::Debug, path::Path};

use alpm_types::CompressionAlgorithmFileExtension;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{compression::CompressionSettings, error::Error};

/// Settings for a compression decoder.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum DecompressionSettings {
    /// The bzip2 compression algorithm.
    Bzip2,
    /// The gzip compression algorithm.
    Gzip,
    /// The xz compression algorithm.
    Xz,
    /// The zstandard compression algorithm.
    Zstd,
    /// No compression.
    None,
}

impl DecompressionSettings {
    /// The number of leading bytes [`DecompressionSettings::from_magic`] needs.
    pub const MAGIC_LEN: usize = 6;

    /// Detects the compression of data from its leading bytes (magic numbers).
    ///
    /// Looks at up to [`DecompressionSettings::MAGIC_LEN`] bytes of `magic`.
    /// Returns [`DecompressionSettings::None`] for data in none of the supported formats.
    /// This allows reading files without a compression file extension, as libarchive does
    /// (e.g. the repository databases of pacman).
    ///
    /// # Examples
    ///
    /// ```
    /// use alpm_compress::decompression::DecompressionSettings;
    ///
    /// assert_eq!(
    ///     DecompressionSettings::from_magic(&[0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x58]),
    ///     DecompressionSettings::Zstd
    /// );
    /// assert_eq!(
    ///     DecompressionSettings::from_magic(b"ustar"),
    ///     DecompressionSettings::None
    /// );
    /// ```
    pub fn from_magic(magic: &[u8]) -> Self {
        if magic.starts_with(&[0x1f, 0x8b]) {
            Self::Gzip
        } else if magic.starts_with(b"BZh") {
            Self::Bzip2
        } else if magic.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
            Self::Xz
        } else if magic.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            Self::Zstd
        } else {
            Self::None
        }
    }
}

impl TryFrom<CompressionAlgorithmFileExtension> for DecompressionSettings {
    type Error = Error;

    /// Converts a [`CompressionAlgorithmFileExtension`] into a [`DecompressionSettings`].
    fn try_from(value: CompressionAlgorithmFileExtension) -> Result<Self, Self::Error> {
        match value {
            CompressionAlgorithmFileExtension::Bzip2 => Ok(Self::Bzip2),
            CompressionAlgorithmFileExtension::Gzip => Ok(Self::Gzip),
            CompressionAlgorithmFileExtension::Xz => Ok(Self::Xz),
            CompressionAlgorithmFileExtension::Zstd => Ok(Self::Zstd),
            _ => Err(Error::UnsupportedCompressionAlgorithm {
                value: value.to_string(),
            }),
        }
    }
}

impl TryFrom<&Path> for DecompressionSettings {
    type Error = Error;

    /// Converts a [`Path`] into a [`DecompressionSettings`] by extracting the file extension.
    ///
    /// Delegates deducing the compression algorithm to
    /// [`CompressionAlgorithmFileExtension::try_from`] and the final conversion to
    /// [`TryFrom<CompressionAlgorithmFileExtension>`][`TryFrom::try_from`].
    ///
    /// # Errors
    ///
    /// Returns an error if the compression algorithm file extension is unknown or unsupported.
    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let ext = CompressionAlgorithmFileExtension::try_from(path)
            .map_err(Error::UnknownCompressionAlgorithmFileExtension)?;
        DecompressionSettings::try_from(ext)
    }
}

impl From<&CompressionSettings> for DecompressionSettings {
    /// Converts a [`CompressionSettings`] into a [`DecompressionSettings`].
    fn from(value: &CompressionSettings) -> Self {
        match value {
            CompressionSettings::Bzip2 { .. } => DecompressionSettings::Bzip2,
            CompressionSettings::Gzip { .. } => DecompressionSettings::Gzip,
            CompressionSettings::Xz { .. } => DecompressionSettings::Xz,
            CompressionSettings::Zstd { .. } => DecompressionSettings::Zstd,
            CompressionSettings::None => DecompressionSettings::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, Write};

    use rstest::rstest;
    use tempfile::tempfile;
    use testresult::TestResult;

    use super::*;
    use crate::compression::{
        Bzip2CompressionLevel,
        CompressionEncoder,
        GzipCompressionLevel,
        XzCompressionLevel,
        ZstdCompressionLevel,
        ZstdThreads,
    };

    /// Ensures that the conversion from [`CompressionAlgorithmFileExtension`] to
    /// [`DecompressionSettings`] works as expected.
    #[rstest]
    #[case(CompressionAlgorithmFileExtension::Bzip2, DecompressionSettings::Bzip2)]
    #[case(CompressionAlgorithmFileExtension::Gzip, DecompressionSettings::Gzip)]
    #[case(CompressionAlgorithmFileExtension::Xz, DecompressionSettings::Xz)]
    #[case(CompressionAlgorithmFileExtension::Zstd, DecompressionSettings::Zstd)]
    fn test_decompression_settings_conversion_success(
        #[case] ext: CompressionAlgorithmFileExtension,
        #[case] expected: DecompressionSettings,
    ) -> TestResult {
        let result = DecompressionSettings::try_from(ext)?;
        assert_eq!(result, expected);
        Ok(())
    }

    /// Ensures that the conversion from [`CompressionAlgorithmFileExtension`] to
    /// [`DecompressionSettings`] fails as expected for unsupported algorithms.
    #[rstest]
    #[case(CompressionAlgorithmFileExtension::Compress, "Z")]
    #[case(CompressionAlgorithmFileExtension::Lrzip, "lrz")]
    #[case(CompressionAlgorithmFileExtension::Lzip, "lz")]
    #[case(CompressionAlgorithmFileExtension::Lz4, "lz4")]
    #[case(CompressionAlgorithmFileExtension::Lzop, "lzo")]
    fn test_decompression_settings_conversion_failure(
        #[case] ext: CompressionAlgorithmFileExtension,
        #[case] expected_str: &str,
    ) -> TestResult {
        match DecompressionSettings::try_from(ext) {
            Ok(settings) => panic!("Expected failure, but got: {settings:?}"),
            Err(Error::UnsupportedCompressionAlgorithm { value }) => {
                assert_eq!(value, expected_str);
                Ok(())
            }
            Err(e) => panic!("Unexpected error variant: {e:?}"),
        }
    }

    /// Ensures that the compression of data written by [`CompressionEncoder`] is detected.
    #[rstest]
    #[case::bzip2(CompressionSettings::Bzip2 {
        compression_level: Bzip2CompressionLevel::default()
    })]
    #[case::gzip(CompressionSettings::Gzip {
        compression_level: GzipCompressionLevel::default()
    })]
    #[case::xz(CompressionSettings::Xz {
        compression_level: XzCompressionLevel::default()
    })]
    #[case::zstd(CompressionSettings::Zstd {
        compression_level: ZstdCompressionLevel::default(),
        threads: ZstdThreads::new(1),
    })]
    #[case::no_compression(CompressionSettings::None)]
    fn test_from_magic(#[case] settings: CompressionSettings) -> TestResult {
        let mut file = tempfile()?;
        let mut encoder = CompressionEncoder::new(file.try_clone()?, &settings)?;
        encoder.write_all(b"alpm4ever")?;
        encoder.finish()?;
        file.rewind()?;

        let mut magic = Vec::new();
        file.take(DecompressionSettings::MAGIC_LEN as u64)
            .read_to_end(&mut magic)?;
        assert_eq!(
            DecompressionSettings::from_magic(&magic),
            DecompressionSettings::from(&settings)
        );
        Ok(())
    }

    /// Ensures that data shorter than a magic number is not compressed data.
    #[rstest]
    #[case::empty(b"")]
    #[case::one_byte(&[0x1f])]
    #[case::partial_xz(&[0xfd, b'7', b'z'])]
    fn test_from_magic_short(#[case] magic: &[u8]) {
        assert_eq!(
            DecompressionSettings::from_magic(magic),
            DecompressionSettings::None
        );
    }

    /// Ensures that the conversion from [`CompressionSettings`] to
    /// [`DecompressionSettings`] works as expected.
    #[rstest]
    #[case::bzip2(CompressionSettings::Bzip2 {
        compression_level: Bzip2CompressionLevel::default()
    }, DecompressionSettings::Bzip2)]
    #[case::gzip(CompressionSettings::Gzip {
        compression_level: GzipCompressionLevel::default()
    }, DecompressionSettings::Gzip)]
    #[case::xz(CompressionSettings::Xz {
        compression_level: XzCompressionLevel::default()
    }, DecompressionSettings::Xz)]
    #[case::zstd(CompressionSettings::Zstd {
        compression_level: ZstdCompressionLevel::default(),
        threads: ZstdThreads::new(4),
    }, DecompressionSettings::Zstd)]
    #[case(CompressionSettings::None, DecompressionSettings::None)]
    fn test_from_compression_settings_to_decompression_settings(
        #[case] settings: CompressionSettings,
        #[case] expected: DecompressionSettings,
    ) -> TestResult {
        let result = DecompressionSettings::from(&settings);
        assert_eq!(result, expected);
        Ok(())
    }
}
