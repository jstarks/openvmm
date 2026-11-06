// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Synthetic namespace policy: ordinal UTF-16 simple uppercase, without
//! normalization, multi-character expansion, or surrogate-pair case mapping.
//! The Unicode version follows `char::UNICODE_VERSION`, not a native volume's
//! versioned upcase table.

/// Map one UTF-16 unit without expanding it.
pub(crate) fn upcase(unit: u16) -> u16 {
    if unit < 0x80 {
        return u16::from((unit as u8).to_ascii_uppercase());
    }
    // UnicodeData simple uppercase differs from full uppercase for these
    // Greek forms with ypogegrammeni (Unicode 17.0, field 12).
    match unit {
        0x1f80..=0x1f87 | 0x1f90..=0x1f97 | 0x1fa0..=0x1fa7 => return unit + 8,
        0x1fb3 => return 0x1fbc,
        0x1fc3 => return 0x1fcc,
        0x1ff3 => return 0x1ffc,
        _ => {}
    }
    let Some(character) = char::from_u32(u32::from(unit)) else {
        return unit;
    };
    let mut upper = character.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(character), None) if character.len_utf16() == 1 => character as u16,
        _ => unit,
    }
}

pub(crate) fn equal(left: &str, right: &str) -> bool {
    if left.is_ascii() && right.is_ascii() {
        return left.eq_ignore_ascii_case(right);
    }
    left.encode_utf16()
        .map(upcase)
        .eq(right.encode_utf16().map(upcase))
}

pub(crate) fn key(name: &str) -> Vec<u16> {
    name.encode_utf16().map(upcase).collect()
}
