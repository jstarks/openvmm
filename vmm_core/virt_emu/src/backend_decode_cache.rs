// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use x86_system::shared::decode::{DecodeDecision, DecodeInput, DecodeWindow};

/// Cache geometry and modular counters; they do not participate in guest execution.
#[derive(Clone, Copy, Debug, Default)]
pub struct DecodeDiagnostics {
    /// Maximum retained encodings.
    pub entries: usize,
    /// Storage allocated for cache sets, excluding allocator metadata.
    pub bytes: usize,
    /// Valid observed-window queries.
    pub windows: u64,
    /// Matching full or partial cached receipts.
    pub hits: u64,
    /// Queries whose cache slot was empty.
    pub empty: u64,
    /// Queries displaced by another RIP.
    pub collisions: u64,
    /// Same-RIP receipts whose observed bytes or length no longer match.
    pub changed: u64,
    /// Uncached decoder admissions.
    pub admissions: u64,
    /// Additional shorter-prefix admissions before caching a terminal result.
    pub prefix_checks: u64,
}

#[derive(Clone, Copy)]
struct Receipt {
    rip: u64,
    bytes: [u8; 15],
    length: u8,
    decision: DecodeDecision,
}

#[derive(Default)]
struct Set {
    slots: [Option<Receipt>; 2],
    victim: usize,
}

pub(super) struct DecodeCache {
    sets: Box<[Set]>,
    diagnostics: DecodeDiagnostics,
    #[cfg(test)]
    pub(super) bypass: bool,
}

fn index(rip: u64) -> usize {
    ((rip ^ (rip >> 12) ^ (rip >> 24)) & 8191) as usize
}

impl DecodeCache {
    pub(super) fn new() -> Self {
        let sets: Box<[Set]> = std::iter::repeat_with(Set::default).take(8192).collect();
        let diagnostics = DecodeDiagnostics {
            entries: sets.len() * 2,
            bytes: size_of_val(&*sets),
            ..DecodeDiagnostics::default()
        };
        Self {
            sets,
            diagnostics,
            #[cfg(test)]
            bypass: false,
        }
    }

    pub(super) fn diagnostics(&self) -> DecodeDiagnostics {
        self.diagnostics
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
        let set = &mut self.sets[index(input.rip)];
        for (way, slot) in set.slots.iter().enumerate() {
            if let Some(receipt) = slot {
                if receipt.rip == input.rip
                    && input.length <= receipt.length
                    && receipt.bytes[..length] == input.bytes[..length]
                {
                    set.victim = way ^ 1;
                    return if input.length == receipt.length {
                        receipt.decision
                    } else {
                        DecodeDecision::More
                    };
                }
            }
        }
        self.diagnostics.admissions = self.diagnostics.admissions.wrapping_add(1);
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
                self.diagnostics.prefix_checks = self.diagnostics.prefix_checks.wrapping_add(1);
                matches!(
                    x86_decode::admit(DecodeInput { length, ..input }),
                    DecodeDecision::More
                )
            }) {
                let way = set
                    .slots
                    .iter()
                    .position(|slot| slot.as_ref().is_some_and(|r| r.rip == input.rip))
                    .unwrap_or(set.victim);
                set.slots[way] = Some(Receipt {
                    rip: input.rip,
                    bytes: input.bytes,
                    length: input.length,
                    decision,
                });
                set.victim = way ^ 1;
            }
        }
        decision
    }

    pub(super) fn decode_window(&mut self, window: DecodeWindow) -> (u8, DecodeDecision) {
        let input = window.input;
        if input.length == 0 || window.available < input.length || window.available > 15 {
            return (input.length, DecodeDecision::Rejected);
        }
        self.diagnostics.windows = self.diagnostics.windows.wrapping_add(1);
        #[cfg(test)]
        let bypass = self.bypass;
        #[cfg(not(test))]
        let bypass = false;
        if !bypass {
            let set = &mut self.sets[index(input.rip)];
            if let Some((way, receipt)) = set.slots.iter().enumerate().find_map(|(way, slot)| {
                slot.as_ref()
                    .filter(|r| r.rip == input.rip)
                    .map(|r| (way, r))
            }) {
                let length = window.available.min(receipt.length);
                if receipt.rip == input.rip
                    && input.length <= length
                    && receipt.bytes[..usize::from(length)] == window.bytes[..usize::from(length)]
                {
                    self.diagnostics.hits = self.diagnostics.hits.wrapping_add(1);
                    set.victim = way ^ 1;
                    return (
                        length,
                        if length == receipt.length {
                            receipt.decision
                        } else {
                            DecodeDecision::More
                        },
                    );
                }
                self.diagnostics.changed = self.diagnostics.changed.wrapping_add(1);
            } else if set.slots.iter().all(Option::is_some) {
                self.diagnostics.collisions = self.diagnostics.collisions.wrapping_add(1);
            } else {
                self.diagnostics.empty = self.diagnostics.empty.wrapping_add(1);
            }
        }
        for length in input.length..=window.available {
            let decision = self.decode(DecodeInput {
                bytes: window.bytes,
                length,
                ..input
            });
            if !matches!(decision, DecodeDecision::More) {
                return (length, decision);
            }
        }
        (window.available, DecodeDecision::More)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn colliding(rip: u64) -> impl Iterator<Item = u64> {
        (rip + 1..rip + 0x10000).filter(move |&candidate| index(candidate) == index(rip))
    }

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
    fn observed_windows_match_incremental_decoding_after_every_prefix_mutation() {
        let mut cache = DecodeCache::new();
        let mut longest = [0x66; 15];
        longest[14] = 0x90;
        for original in [
            &[0x48, 0x83, 0xc0, 1][..],
            &[0x48, 0x8b, 0x05, 1, 2, 3, 4][..],
            &[0xf0, 0x48, 0x0f, 0xb1, 0x07][..],
            &[0xe8, 1, 2, 3, 4][..],
            &[0x75, 0xf7][..],
            &[0x90][..],
            &longest[..],
            &[0x66; 15][..],
        ] {
            for byte in 0..original.len() {
                for xor in [0, 1, 0x80, 0xff] {
                    let cold = input(0x10000, original);
                    assert_eq!(cache.decode(cold), x86_decode::admit(cold));
                    let mut modified = original.to_vec();
                    modified[byte] ^= xor;
                    for available in 1..=modified.len() {
                        for start in 1..=available {
                            let base = input(0x10000, &modified[..start]);
                            let mut bytes = [0xa5; 15];
                            bytes[..available].copy_from_slice(&modified[..available]);
                            let window = DecodeWindow {
                                input: base,
                                bytes,
                                available: available as u8,
                            };
                            let mut expected = (available as u8, DecodeDecision::More);
                            for length in start..=available {
                                let decision = x86_decode::admit(DecodeInput {
                                    bytes,
                                    length: length as u8,
                                    ..base
                                });
                                if !matches!(decision, DecodeDecision::More) {
                                    expected = (length as u8, decision);
                                    break;
                                }
                            }
                            assert_eq!(
                                cache.decode_window(window),
                                expected,
                                "{modified:02x?}/{start}/{available}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn colliding_hot_rips_reuse_receipts_and_evict_only_the_least_recent() {
        let mut cache = DecodeCache::new();
        let a = 0x10000;
        let mut collisions = colliding(a);
        let b = collisions.next().unwrap();
        let c = collisions.next().unwrap();
        assert_eq!(index(a), index(b));
        assert_eq!(index(a), index(c));
        let window = |rip| {
            let full = input(rip, &[0x75, 0xf7]);
            DecodeWindow {
                input: DecodeInput { length: 1, ..full },
                bytes: full.bytes,
                available: 2,
            }
        };
        for rip in [a, b] {
            let w = window(rip);
            assert_eq!(
                cache.decode_window(w),
                (
                    2,
                    x86_decode::admit(DecodeInput {
                        length: 2,
                        ..w.input
                    })
                )
            );
        }
        let warm = cache.diagnostics();
        for rip in [a, b].into_iter().cycle().take(128) {
            let w = window(rip);
            assert_eq!(
                cache.decode_window(w),
                (
                    2,
                    x86_decode::admit(DecodeInput {
                        length: 2,
                        ..w.input
                    })
                )
            );
        }
        assert_eq!(cache.diagnostics().admissions, warm.admissions);
        assert_eq!(cache.diagnostics().prefix_checks, warm.prefix_checks);
        cache.decode_window(window(a));
        cache.decode_window(window(c));
        let replaced = cache.diagnostics().admissions;
        cache.decode_window(window(a));
        assert_eq!(cache.diagnostics().admissions, replaced);
        cache.decode_window(window(b));
        assert!(cache.diagnostics().admissions > replaced);
    }

    #[test]
    fn same_slot_different_rip_never_reuses_a_relative_target() {
        let mut cache = DecodeCache::new();
        let first = input(0x10000, &[0x75, 0xf7]);
        let second = input(colliding(first.rip).next().unwrap(), &[0x75, 0xf7]);
        assert_eq!(index(first.rip), index(second.rip));
        for current in [first, second, first] {
            assert_eq!(cache.decode(current), x86_decode::admit(current));
            let window = DecodeWindow {
                input: DecodeInput {
                    length: 1,
                    ..current
                },
                bytes: current.bytes,
                available: current.length,
            };
            assert_eq!(
                cache.decode_window(window),
                (current.length, x86_decode::admit(current))
            );
        }
        assert_ne!(x86_decode::admit(first), x86_decode::admit(second));
    }
}
