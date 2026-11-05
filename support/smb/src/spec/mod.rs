// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public-specification wire layouts and values, independent of server policy.
//!
//! References use [MS-SMB2] revision 88, [MS-FSCC] revision 60, and [MS-NLMP]
//! revision 37. Integers in packet layouts use alignment-one endian wrappers;
//! embedded bitfields use the same endian wrappers, so nested records remain
//! alignment-one and can be decoded at arbitrary packet offsets.
//!
//! [MS-SMB2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/
//! [MS-FSCC]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/
//! [MS-NLMP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/

/// A fixed SMB2 body, including its specified StructureSize value.
///
/// StructureSize is sometimes one greater than the fixed layout size to account
/// for the first byte of a variable buffer. It is not a Rust structure length.
pub trait SmbBody:
    zerocopy::FromBytes + zerocopy::IntoBytes + zerocopy::KnownLayout + zerocopy::Immutable
{
    /// Value specified in the body's StructureSize field.
    const STRUCTURE_SIZE: u16;
    /// StructureSize received on the wire.
    fn structure_size(&self) -> u16;
}

macro_rules! wire {
    ($(#[$attr:meta])* $name:ident, $size:literal { $($field:ident: $ty:ty),* $(,)? }) => {
        $(#[$attr])*
        #[repr(C)]
        #[derive(Debug, Clone, Copy, zerocopy::FromBytes, zerocopy::IntoBytes,
                 zerocopy::Immutable, zerocopy::KnownLayout)]
        #[expect(missing_docs, reason = "Wire fields use the names in the cited specification.")]
        pub struct $name { $(pub $field: $ty),* }
        const _: () = assert!(size_of::<$name>() == $size);
    };
    ($(#[$attr:meta])* $name:ident, $size:literal, $structure_size:literal { $($field:ident: $ty:ty),* $(,)? }) => {
        wire!($(#[$attr])* $name, $size { $($field: $ty),* });
        impl super::SmbBody for $name {
            const STRUCTURE_SIZE: u16 = $structure_size;
            fn structure_size(&self) -> u16 { self.structure_size.get() }
        }
    };
}

const fn u16_from_le(value: zerocopy::little_endian::U16) -> u16 {
    value.get()
}
const fn u32_from_le(value: zerocopy::little_endian::U32) -> u32 {
    value.get()
}

// bitfield-struct's generated conversions use its representation type. Keep
// raw-bit conversion at the native-integer boundary while storing LE bytes.
macro_rules! le_bitfield_conversions {
    ($name:ident, $native:ty, $storage:ty) => {
        impl $name {
            /// Construct from decoded bits, preserving unknown fields.
            pub const fn from_bits(bits: $native) -> Self {
                Self(<$storage>::new(bits))
            }
            /// Decode the stored little-endian bits.
            pub const fn into_bits(self) -> $native {
                self.0.get()
            }
        }
        impl From<$native> for $name {
            fn from(bits: $native) -> Self {
                Self::from_bits(bits)
            }
        }
        impl From<$name> for $native {
            fn from(value: $name) -> Self {
                value.into_bits()
            }
        }
    };
}

pub mod fscc;
pub mod ntlm;
pub mod smb2;
pub mod tcp;

pub use fscc::*;
pub use smb2::*;
