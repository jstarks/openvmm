// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Direct TCP framing, [MS-SMB2] §2.1: zero byte followed by a 24-bit BE length.

/// Required Direct TCP message type: [MS-SMB2] §2.1.
pub const SESSION_MESSAGE: u8 = 0;
/// Largest length representable by the three-byte field: [MS-SMB2] §2.1.
pub const MAX_FRAME_LENGTH: usize = 0x00ff_ffff;

wire!(
    /// Direct TCP packet prefix: [MS-SMB2] §2.1.
    DirectTcpHeader, 4 { message_type: u8, length: [u8; 3] }
);

impl DirectTcpHeader {
    /// Decode the length without interpreting the message type.
    pub fn length(&self) -> usize {
        u32::from_be_bytes([0, self.length[0], self.length[1], self.length[2]]) as usize
    }
    /// Encode a representable payload length.
    pub fn new(length: usize) -> Option<Self> {
        if length > MAX_FRAME_LENGTH {
            return None;
        }
        let [_, a, b, c] = (length as u32).to_be_bytes();
        Some(Self {
            message_type: SESSION_MESSAGE,
            length: [a, b, c],
        })
    }
}
