// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Dual header parsing and validation for VHDX files.
//!
//! Reads both VHDX headers, validates their signatures and CRC-32C checksums,
//! selects the active header (higher sequence number), and validates log
//! region parameters.

use crate::AsyncFile;
use crate::error::CorruptionType;
use crate::error::VhdxError;
use crate::format;
use crate::format::Header;
use guid::Guid;
use zerocopy::FromBytes;

/// Parsed and validated header data extracted from a VHDX file.
pub(crate) struct ParsedHeader {
    /// The active header's sequence number.
    pub sequence_number: u64,
    /// GUID changed on every file-level write.
    pub file_write_guid: Guid,
    /// GUID changed on every virtual-disk data write.
    pub data_write_guid: Guid,
    /// GUID identifying the active log. Zero means no active log.
    pub log_guid: Guid,
    /// File offset of the log region.
    #[allow(dead_code)]
    pub log_offset: u64,
    /// Length of the log region in bytes.
    #[allow(dead_code)]
    pub log_length: u32,
    /// File format version.
    pub version: u16,
    /// True if header 1 was chosen as the active header.
    pub first_header_current: bool,
}

/// Read a single 4 KiB header from the file and validate its signature
/// and CRC-32C checksum. Returns `Some(header)` if valid, `None` otherwise.
async fn read_and_validate_header(
    file: &impl AsyncFile,
    offset: u64,
) -> Result<Option<Header>, VhdxError> {
    let mut buf = vec![0u8; format::HEADER_SIZE as usize];
    file.read_at(offset, &mut buf).await?;

    // Check signature.
    let header = match Header::read_from_prefix(&buf) {
        Ok((h, _)) => h,
        Err(_) => return Ok(None),
    };
    if header.signature != format::HEADER_SIGNATURE {
        return Ok(None);
    }

    // Validate CRC-32C checksum (checksum field is at byte offset 4).
    if !format::validate_checksum(&buf, 4) {
        return Ok(None);
    }

    Ok(Some(header.clone()))
}

/// Read both headers from the file, validate them, and return the active one.
///
/// If both headers are valid, the one with the higher sequence number wins.
/// If only one is valid, it is used. If neither is valid, returns an error.
pub(crate) async fn parse_headers(
    file: &impl AsyncFile,
    file_length: u64,
) -> Result<ParsedHeader, VhdxError> {
    let header1 = read_and_validate_header(file, format::HEADER_OFFSET_1).await?;
    let header2 = read_and_validate_header(file, format::HEADER_OFFSET_2).await?;

    // Choose the active header.
    let (header, first_header_current) = match (&header1, &header2) {
        (Some(h1), Some(h2)) => {
            if h1.sequence_number >= h2.sequence_number {
                (h1, true)
            } else {
                (h2, false)
            }
        }
        (Some(h1), None) => (h1, true),
        (None, Some(h2)) => (h2, false),
        (None, None) => return Err(CorruptionType::NoValidHeaders.into()),
    };

    // Validate version.
    if header.version != format::VERSION_1 {
        return Err(VhdxError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported VHDX version",
        )));
    }

    // If log GUID is non-zero, validate log version.
    if header.log_guid != Guid::ZERO && header.log_version != format::LOG_VERSION {
        return Err(VhdxError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported VHDX log version",
        )));
    }

    // Validate log offset and length alignment.
    if !header.log_offset.is_multiple_of(format::REGION_ALIGNMENT)
        || !(header.log_length as u64).is_multiple_of(format::REGION_ALIGNMENT)
    {
        return Err(CorruptionType::InvalidLogOffsetOrLength.into());
    }

    let (log_offset, log_length) = if header.log_length == 0 {
        // Log is empty — log GUID must also be zero.
        if header.log_guid != Guid::ZERO {
            return Err(CorruptionType::MissingLogHasGuid.into());
        }
        (0, 0)
    } else {
        // Log is present — validate offset and bounds.
        if header.log_offset < format::HEADER_AREA_SIZE {
            return Err(CorruptionType::InvalidLogOffset.into());
        }
        if header.log_offset + header.log_length as u64 > file_length {
            return Err(CorruptionType::LogBeyondEndOfFile.into());
        }
        (header.log_offset, header.log_length)
    };

    Ok(ParsedHeader {
        sequence_number: header.sequence_number,
        file_write_guid: header.file_write_guid,
        data_write_guid: header.data_write_guid,
        log_guid: header.log_guid,
        log_offset,
        log_length,
        version: header.version,
        first_header_current,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::support::InMemoryFile;
    use pal_async::async_test;

    #[async_test]
    async fn parse_valid_dual_headers() {
        let (file, _params) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let file_length = file.file_size().await.unwrap();
        let parsed = parse_headers(&file, file_length).await.unwrap();

        // Header 2 has sequence_number 1. Header 1 has 0. So header 2 wins.
        assert_eq!(parsed.sequence_number, 1);
        assert!(!parsed.first_header_current);
        assert_eq!(parsed.version, format::VERSION_1);
        assert_eq!(parsed.log_guid, Guid::ZERO);
        assert_ne!(parsed.file_write_guid, Guid::ZERO);
        assert_ne!(parsed.data_write_guid, Guid::ZERO);
    }

    #[async_test]
    async fn parse_higher_sequence_wins() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let file_length = file.file_size().await.unwrap();

        // Corrupt header 1's CRC by flipping a byte.
        let mut buf = vec![0u8; format::HEADER_SIZE as usize];
        file.read_at(format::HEADER_OFFSET_1, &mut buf)
            .await
            .unwrap();
        buf[10] ^= 0xFF;
        file.write_at(format::HEADER_OFFSET_1, &buf).await.unwrap();

        let parsed = parse_headers(&file, file_length).await.unwrap();
        // Header 1 is invalid, so header 2 is used.
        assert!(!parsed.first_header_current);
        assert_eq!(parsed.sequence_number, 1);
    }

    #[async_test]
    async fn parse_both_headers_corrupt() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let file_length = file.file_size().await.unwrap();

        // Corrupt both headers.
        let mut buf1 = vec![0u8; format::HEADER_SIZE as usize];
        file.read_at(format::HEADER_OFFSET_1, &mut buf1)
            .await
            .unwrap();
        buf1[10] ^= 0xFF;
        file.write_at(format::HEADER_OFFSET_1, &buf1).await.unwrap();

        let mut buf2 = vec![0u8; format::HEADER_SIZE as usize];
        file.read_at(format::HEADER_OFFSET_2, &mut buf2)
            .await
            .unwrap();
        buf2[10] ^= 0xFF;
        file.write_at(format::HEADER_OFFSET_2, &buf2).await.unwrap();

        let result = parse_headers(&file, file_length).await;
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::NoValidHeaders))
        ));
    }

    #[async_test]
    async fn parse_one_valid_header() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let file_length = file.file_size().await.unwrap();

        // Corrupt header 2's CRC.
        let mut buf = vec![0u8; format::HEADER_SIZE as usize];
        file.read_at(format::HEADER_OFFSET_2, &mut buf)
            .await
            .unwrap();
        buf[10] ^= 0xFF;
        file.write_at(format::HEADER_OFFSET_2, &buf).await.unwrap();

        let parsed = parse_headers(&file, file_length).await.unwrap();
        assert!(parsed.first_header_current);
        assert_eq!(parsed.sequence_number, 0);
    }

    #[async_test]
    async fn parse_log_validation() {
        let (file, _) = InMemoryFile::create_test_vhdx(format::GB1).await;
        let file_length = file.file_size().await.unwrap();

        // Manually construct a header with valid signature but misaligned log.
        let mut buf = vec![0u8; format::HEADER_SIZE as usize];
        file.read_at(format::HEADER_OFFSET_1, &mut buf)
            .await
            .unwrap();

        let mut header = Header::read_from_prefix(&buf).unwrap().0.clone();
        header.log_offset = 12345; // Not aligned to REGION_ALIGNMENT.
        header.log_length = format::REGION_ALIGNMENT as u32;
        header.sequence_number = 100; // Make this the winning header.
        header.checksum = 0;

        // Write header bytes, recompute CRC.
        let header_bytes = zerocopy::IntoBytes::as_bytes(&header);
        buf[..header_bytes.len()].copy_from_slice(header_bytes);
        let crc = format::compute_checksum(&buf, 4);
        buf[4..8].copy_from_slice(&crc.to_le_bytes());
        file.write_at(format::HEADER_OFFSET_1, &buf).await.unwrap();

        let result = parse_headers(&file, file_length).await;
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::InvalidLogOffsetOrLength))
        ));
    }
}
