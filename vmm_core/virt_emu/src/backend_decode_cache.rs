// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use x86_system::shared::decode::{DecodeDecision, DecodeInput};

#[derive(Clone, Copy)]
struct Receipt {
    rip: u64,
    bytes: [u8; 15],
    length: u8,
    decision: DecodeDecision,
}

pub(super) struct DecodeCache {
    slots: Box<[Option<Receipt>]>,
    #[cfg(test)]
    pub(super) bypass: bool,
}

fn index(rip: u64) -> usize {
    ((rip ^ (rip >> 12) ^ (rip >> 24)) & 4095) as usize
}

impl DecodeCache {
    pub(super) fn new() -> Self {
        Self {
            slots: std::iter::repeat_with(|| None).take(4096).collect(),
            #[cfg(test)]
            bypass: false,
        }
    }

    pub(super) fn decode(&mut self, input: DecodeInput) -> DecodeDecision {
        #[cfg(test)]
        if self.bypass {
            return x86_decode::admit(input);
        }
        let length = usize::from(input.length);
        if length == 0 || length > input.bytes.len() {
            return x86_decode::admit(input);
        }
        let slot = &mut self.slots[index(input.rip)];
        if let Some(receipt) = slot {
            if receipt.rip == input.rip
                && input.length <= receipt.length
                && receipt.bytes[..length] == input.bytes[..length]
            {
                return if input.length == receipt.length {
                    receipt.decision
                } else {
                    DecodeDecision::More
                };
            }
        }
        let decision = x86_decode::admit(input);
        if matches!(
            decision,
            DecodeDecision::Entry(_)
                | DecodeDecision::Scalar { .. }
                | DecodeDecision::Xor32 { .. }
                | DecodeDecision::Wrmsr
                | DecodeDecision::NearCall { .. }
                | DecodeDecision::Legacy
        ) {
            // Validate every shorter prefix before retaining a More receipt.
            // Every lookup still checks freshly fetched bytes; RAM/PTE/code
            // observations and current decode-token identity are never cached.
            if (1..input.length).all(|length| {
                matches!(
                    x86_decode::admit(DecodeInput { length, ..input }),
                    DecodeDecision::More
                )
            }) {
                *slot = Some(Receipt {
                    rip: input.rip,
                    bytes: input.bytes,
                    length: input.length,
                    decision,
                });
            }
        }
        decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(rip: u64, bytes: &[u8]) -> DecodeInput {
        let mut input = DecodeInput {
            rip,
            bytes: [0; 15],
            length: bytes.len() as u8,
            sequence: 91,
        };
        input.bytes[..bytes.len()].copy_from_slice(bytes);
        input
    }

    #[test]
    fn fresh_bytes_and_every_mutated_prefix_match_the_uncached_decoder() {
        let mut cache = DecodeCache::new();
        for original in [
            &[0x48, 0x83, 0xc0, 1][..],
            &[0x48, 0x8b, 0x05, 1, 2, 3, 4][..],
            &[0xf0, 0x48, 0x0f, 0xb1, 0x07][..],
            &[0x44, 0x0f, 0x20, 0xc3][..],
            &[0xe8, 1, 2, 3, 4][..],
            &[0x75, 0xf7][..],
            &[0x90][..],
        ] {
            for byte in 0..original.len() {
                for xor in [0, 1, 0x80, 0xff] {
                    let cold = input(0x10000, original);
                    assert_eq!(cache.decode(cold), x86_decode::admit(cold));
                    let mut modified = original.to_vec();
                    modified[byte] ^= xor;
                    for length in 1..=modified.len() {
                        let mut current = input(0x10000, &modified[..length]);
                        current.sequence = 1000 + length as u64;
                        current.bytes[length..].fill(0xa5);
                        assert_eq!(
                            cache.decode(current),
                            x86_decode::admit(current),
                            "{modified:02x?}/{length}"
                        );
                    }
                }
            }
        }
        for length in [0, 16] {
            let current = DecodeInput {
                length,
                ..input(0x10000, &[0x90])
            };
            assert_eq!(cache.decode(current), x86_decode::admit(current));
        }
    }

    #[test]
    fn same_slot_different_rip_never_reuses_a_relative_target() {
        let mut cache = DecodeCache::new();
        let first = input(0x10000, &[0x75, 0xf7]);
        let second = input(first.rip ^ 0x1001, &[0x75, 0xf7]);
        assert_eq!(index(first.rip), index(second.rip));
        for current in [first, second, first] {
            assert_eq!(cache.decode(current), x86_decode::admit(current));
        }
        assert_ne!(x86_decode::admit(first), x86_decode::admit(second));
    }
}
