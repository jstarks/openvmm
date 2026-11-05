// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Raw token layouts used by the guest-only TCP test handshake, not authentication.

use bitfield_struct::bitfield;
use open_enum::open_enum;
use zerocopy::little_endian::{U16, U32};

/// Signature in every NTLM message: [MS-NLMP] §§2.2.1.1–2.2.1.3.
pub const SIGNATURE: [u8; 8] = *b"NTLMSSP\0";
open_enum! {
    /// NTLM message discriminator: [MS-NLMP] §§2.2.1.1–2.2.1.3.
    pub enum MessageType: u32 {
        /// Client negotiation token.
        NEGOTIATE = 1,
        /// Server challenge token.
        CHALLENGE = 2,
        /// Client authentication token.
        AUTHENTICATE = 3,
    }
}
/// Negotiation bits used by the test handshake: [MS-NLMP] §2.2.2.5.
#[bitfield(u32, repr = U32, from = U32::new, into = super::u32_from_le, conversion = false)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct NegotiateFlags {
    pub unicode: bool,
    pub oem: bool,
    pub request_target: bool,
    #[bits(6)]
    other0: u8,
    pub ntlm: bool,
    #[bits(7)]
    other1: u8,
    pub target_type_server: bool,
    #[bits(1)]
    other2: u8,
    pub extended_session_security: bool,
    #[bits(3)]
    other3: u8,
    pub target_info: bool,
    #[bits(8)]
    other4: u8,
}
le_bitfield_conversions!(NegotiateFlags, u32, U32);
/// MsvAvEOL terminates a target-information list: [MS-NLMP] §2.2.2.1.
pub const MSV_AV_EOL: u16 = 0;

wire!(
    /// Common signature/message-type prefix: [MS-NLMP] §§2.2.1.1–2.2.1.3.
    MessageHeader, 12 {
        signature: [u8; 8],
        message_type: U32,
    }
);
wire!(
    /// Length/maximum-length/offset triple: [MS-NLMP] §2.2.1.
    SecurityBuffer, 8 {
        length: U16,
        maximum_length: U16,
        offset: U32,
    }
);
wire!(
    /// CHALLENGE_MESSAGE without the optional Version: [MS-NLMP] §2.2.1.2.
    ChallengeMessage, 48 {
        header: MessageHeader,
        target_name: SecurityBuffer,
        negotiate_flags: NegotiateFlags,
        server_challenge: [u8; 8],
        reserved: [u8; 8],
        target_info: SecurityBuffer,
    }
);
wire!(
    /// AUTHENTICATE_MESSAGE fixed fields before optional Version/MIC: [MS-NLMP] §2.2.1.3.
    AuthenticateMessage, 64 {
        header: MessageHeader,
        lm_response: SecurityBuffer,
        nt_response: SecurityBuffer,
        domain: SecurityBuffer,
        user: SecurityBuffer,
        workstation: SecurityBuffer,
        encrypted_random_session_key: SecurityBuffer,
        negotiate_flags: NegotiateFlags,
    }
);
wire!(
    /// AV_PAIR fixed prefix: [MS-NLMP] §2.2.2.1.
    AvPair, 4 { id: U16, length: U16 }
);
