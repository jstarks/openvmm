// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Parent locator parsing for VHDX files.
//!
//! Parses the parent locator metadata item (a key-value table of UTF-16LE
//! strings) into a structured Rust type.

use crate::error::CorruptionType;
use crate::error::VhdxError;
use crate::format;
use crate::format::ParentLocatorEntry;
use crate::format::ParentLocatorHeader;
use guid::Guid;
use zerocopy::FromBytes;

/// A parsed key-value pair from a parent locator.
#[derive(Debug, Clone)]
pub(crate) struct LocatorKeyValue {
    /// The key string.
    pub key: String,
    /// The value string.
    pub value: String,
}

/// A parsed parent locator.
#[derive(Debug, Clone)]
pub(crate) struct ParentLocator {
    /// The locator type GUID.
    pub locator_type: Guid,
    /// The key-value entries.
    pub entries: Vec<LocatorKeyValue>,
}

/// Decode a UTF-16LE byte slice into a Rust `String`.
/// Returns an error if the slice has odd length or contains invalid surrogates.
fn decode_utf16le(data: &[u8]) -> Result<String, VhdxError> {
    if !data.len().is_multiple_of(2) {
        return Err(CorruptionType::InvalidLocatorEntryKey.into());
    }
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&u16s)
        .map_err(|_| VhdxError::Corrupt(CorruptionType::InvalidLocatorEntryKey))
}

/// Check that a UTF-16LE byte slice does not contain embedded null characters.
fn has_embedded_null(data: &[u8]) -> bool {
    data.chunks_exact(2)
        .any(|c| u16::from_le_bytes([c[0], c[1]]) == 0)
}

impl ParentLocator {
    /// Parse a parent locator from its raw metadata item bytes.
    pub fn parse(data: &[u8]) -> Result<Self, VhdxError> {
        let header_size = size_of::<ParentLocatorHeader>();

        // Check minimum size for the header.
        if data.len() < header_size {
            return Err(CorruptionType::LocatorTooSmallForHeader.into());
        }

        let header = ParentLocatorHeader::read_from_prefix(data)
            .map_err(|_| CorruptionType::LocatorTooSmallForHeader)?
            .0
            .clone();

        // Validate key-value count.
        if header.key_value_count == 0
            || header.key_value_count > format::PARENT_LOCATOR_MAXIMUM_KEY_VALUE_COUNT
        {
            return Err(CorruptionType::InvalidLocatorKeyValueCount.into());
        }

        // Check that the buffer is large enough for header + all entries.
        let entry_size = size_of::<ParentLocatorEntry>();
        let entries_end = header_size + header.key_value_count as usize * entry_size;
        if data.len() < entries_end {
            return Err(CorruptionType::LocatorTooSmallForEntries.into());
        }

        // Parse each entry.
        let mut entries = Vec::with_capacity(header.key_value_count as usize);
        for i in 0..header.key_value_count as usize {
            let off = header_size + i * entry_size;
            let entry = ParentLocatorEntry::read_from_prefix(&data[off..])
                .unwrap()
                .0
                .clone();

            // Validate key.
            let key_offset = entry.key_offset as usize;
            let key_length = entry.key_length as usize;

            if key_length == 0 {
                return Err(CorruptionType::EmptyLocatorEntryKey.into());
            }
            if !key_length.is_multiple_of(2) {
                return Err(CorruptionType::InvalidLocatorEntryKey.into());
            }
            if !key_offset.is_multiple_of(2) {
                return Err(CorruptionType::InvalidLocatorEntryKey.into());
            }
            if key_offset + key_length > data.len() {
                return Err(CorruptionType::InvalidLocatorEntryKey.into());
            }
            let key_data = &data[key_offset..key_offset + key_length];
            if has_embedded_null(key_data) {
                return Err(CorruptionType::InvalidLocatorEntryKey.into());
            }

            // Validate value.
            let value_offset = entry.value_offset as usize;
            let value_length = entry.value_length as usize;

            if value_length == 0 {
                return Err(CorruptionType::EmptyLocatorEntryValue.into());
            }
            if !value_length.is_multiple_of(2) {
                return Err(CorruptionType::InvalidLocatorEntryKey.into());
            }
            if !value_offset.is_multiple_of(2) {
                return Err(CorruptionType::InvalidLocatorEntryKey.into());
            }
            if value_offset + value_length > data.len() {
                return Err(CorruptionType::InvalidLocatorEntryKey.into());
            }
            let value_data = &data[value_offset..value_offset + value_length];
            if has_embedded_null(value_data) {
                return Err(CorruptionType::InvalidLocatorEntryKey.into());
            }

            let key = decode_utf16le(key_data)?;
            let value = decode_utf16le(value_data)?;

            entries.push(LocatorKeyValue { key, value });
        }

        Ok(ParentLocator {
            locator_type: header.locator_type,
            entries,
        })
    }

    /// Find a value by key name (case-sensitive match).
    pub fn find(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.key == key)
            .map(|e| e.value.as_str())
    }
}

/// Helper to encode a Rust string into a UTF-16LE byte vector.
#[cfg(test)]
fn encode_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect()
}

/// Build a valid parent locator binary blob from parts.
#[cfg(test)]
fn build_locator(
    locator_type: Guid,
    kvs: &[(&str, &str)],
) -> Vec<u8> {
    use zerocopy::IntoBytes;

    let header_size = size_of::<ParentLocatorHeader>();
    let entry_size = size_of::<ParentLocatorEntry>();
    let entries_end = header_size + kvs.len() * entry_size;

    // Encode all key/value strings.
    let encoded: Vec<(Vec<u8>, Vec<u8>)> = kvs
        .iter()
        .map(|(k, v)| (encode_utf16le(k), encode_utf16le(v)))
        .collect();

    // Compute total size.
    let strings_size: usize = encoded.iter().map(|(k, v)| k.len() + v.len()).sum();
    let total = entries_end + strings_size;
    let mut buf = vec![0u8; total];

    // Write header.
    let header = ParentLocatorHeader {
        locator_type,
        reserved: 0,
        key_value_count: kvs.len() as u16,
    };
    let h_bytes = header.as_bytes();
    buf[..h_bytes.len()].copy_from_slice(h_bytes);

    // Write entries and string data.
    let mut string_offset = entries_end;
    for (i, (key_bytes, val_bytes)) in encoded.iter().enumerate() {
        let entry = ParentLocatorEntry {
            key_offset: string_offset as u32,
            value_offset: (string_offset + key_bytes.len()) as u32,
            key_length: key_bytes.len() as u16,
            value_length: val_bytes.len() as u16,
        };
        let e_bytes = entry.as_bytes();
        let off = header_size + i * entry_size;
        buf[off..off + e_bytes.len()].copy_from_slice(e_bytes);

        buf[string_offset..string_offset + key_bytes.len()].copy_from_slice(key_bytes);
        string_offset += key_bytes.len();
        buf[string_offset..string_offset + val_bytes.len()].copy_from_slice(val_bytes);
        string_offset += val_bytes.len();
    }

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_locator() {
        let data = build_locator(
            format::PARENT_LOCATOR_VHDX_TYPE_GUID,
            &[
                ("parent_linkage", "guid-value-here"),
                ("relative_path", "..\\parent.vhdx"),
                ("absolute_win32_path", "C:\\vms\\parent.vhdx"),
            ],
        );

        let locator = ParentLocator::parse(&data).unwrap();
        assert_eq!(locator.locator_type, format::PARENT_LOCATOR_VHDX_TYPE_GUID);
        assert_eq!(locator.entries.len(), 3);
        assert_eq!(locator.entries[0].key, "parent_linkage");
        assert_eq!(locator.entries[0].value, "guid-value-here");
        assert_eq!(locator.entries[1].key, "relative_path");
        assert_eq!(locator.entries[1].value, "..\\parent.vhdx");
        assert_eq!(locator.entries[2].key, "absolute_win32_path");
        assert_eq!(locator.entries[2].value, "C:\\vms\\parent.vhdx");
    }

    #[test]
    fn find_by_key() {
        let data = build_locator(
            format::PARENT_LOCATOR_VHDX_TYPE_GUID,
            &[
                ("parent_linkage", "link-val"),
                ("relative_path", "rel-val"),
            ],
        );

        let locator = ParentLocator::parse(&data).unwrap();
        assert_eq!(locator.find("parent_linkage"), Some("link-val"));
        assert_eq!(locator.find("relative_path"), Some("rel-val"));
        assert_eq!(locator.find("nonexistent"), None);
    }

    #[test]
    fn parse_empty_locator() {
        // Build a header with 0 entries.
        use zerocopy::IntoBytes;
        let header = ParentLocatorHeader {
            locator_type: format::PARENT_LOCATOR_VHDX_TYPE_GUID,
            reserved: 0,
            key_value_count: 0,
        };
        let data = header.as_bytes().to_vec();
        let result = ParentLocator::parse(&data);
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::InvalidLocatorKeyValueCount))
        ));
    }

    #[test]
    fn parse_invalid_utf16() {
        // Build a locator where key has odd byte length.
        use zerocopy::IntoBytes;

        let header_size = size_of::<ParentLocatorHeader>();
        let entry_size = size_of::<ParentLocatorEntry>();

        // Total buffer: header + 1 entry + key(3 bytes, odd) + value(2 bytes)
        let total = header_size + entry_size + 3 + 2;
        let mut buf = vec![0u8; total];

        let header = ParentLocatorHeader {
            locator_type: format::PARENT_LOCATOR_VHDX_TYPE_GUID,
            reserved: 0,
            key_value_count: 1,
        };
        let h_bytes = header.as_bytes();
        buf[..h_bytes.len()].copy_from_slice(h_bytes);

        let string_start = header_size + entry_size;
        let entry = ParentLocatorEntry {
            key_offset: string_start as u32,
            value_offset: (string_start + 3) as u32,
            key_length: 3, // odd = invalid
            value_length: 2,
        };
        let e_bytes = entry.as_bytes();
        buf[header_size..header_size + e_bytes.len()].copy_from_slice(e_bytes);

        let result = ParentLocator::parse(&buf);
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::InvalidLocatorEntryKey))
        ));
    }

    #[test]
    fn parse_embedded_null() {
        // Build a locator where key contains an embedded null.
        use zerocopy::IntoBytes;

        let header_size = size_of::<ParentLocatorHeader>();
        let entry_size = size_of::<ParentLocatorEntry>();

        // Key: "a\0b" in UTF-16LE = [0x61, 0x00, 0x00, 0x00, 0x62, 0x00] (6 bytes)
        let key_data: Vec<u8> = vec![0x61, 0x00, 0x00, 0x00, 0x62, 0x00];
        let value_data = encode_utf16le("val");

        let total = header_size + entry_size + key_data.len() + value_data.len();
        let mut buf = vec![0u8; total];

        let header = ParentLocatorHeader {
            locator_type: format::PARENT_LOCATOR_VHDX_TYPE_GUID,
            reserved: 0,
            key_value_count: 1,
        };
        let h_bytes = header.as_bytes();
        buf[..h_bytes.len()].copy_from_slice(h_bytes);

        let string_start = header_size + entry_size;
        let entry = ParentLocatorEntry {
            key_offset: string_start as u32,
            value_offset: (string_start + key_data.len()) as u32,
            key_length: key_data.len() as u16,
            value_length: value_data.len() as u16,
        };
        let e_bytes = entry.as_bytes();
        buf[header_size..header_size + e_bytes.len()].copy_from_slice(e_bytes);

        buf[string_start..string_start + key_data.len()].copy_from_slice(&key_data);
        let vs = string_start + key_data.len();
        buf[vs..vs + value_data.len()].copy_from_slice(&value_data);

        let result = ParentLocator::parse(&buf);
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::InvalidLocatorEntryKey))
        ));
    }

    #[test]
    fn parse_truncated_locator() {
        // Header claims 5 entries but buffer only holds header.
        use zerocopy::IntoBytes;

        let header = ParentLocatorHeader {
            locator_type: format::PARENT_LOCATOR_VHDX_TYPE_GUID,
            reserved: 0,
            key_value_count: 5,
        };
        let data = header.as_bytes().to_vec();

        let result = ParentLocator::parse(&data);
        assert!(matches!(
            result,
            Err(VhdxError::Corrupt(CorruptionType::LocatorTooSmallForEntries))
        ));
    }
}
