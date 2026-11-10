// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Contracts for owned operands, incremental decode and scalar admission.
use x86_decode::*;

fn outcome(bytes: &[u8], rip: u64) -> Outcome {
    let mut decoder = FetchDecoder::new(rip);
    for (index, &byte) in bytes.iter().enumerate() {
        let request = decoder.request().expect("instruction ended early");
        assert_eq!(request.address, rip.wrapping_add(index as u64));
        decoder.complete(request, byte).unwrap();
    }
    assert!(decoder.request().is_none(), "truncated test input");
    *decoder.outcome().unwrap()
}

fn decode(bytes: &[u8], rip: u64) -> Decoded {
    match outcome(bytes, rip) {
        Outcome::Normalized(decoded) => {
            assert_eq!(decoded.encoding.bytes(), bytes);
            assert_eq!(
                decoded.encoding.next_rip(),
                rip.wrapping_add(bytes.len() as u64)
            );
            decoded
        }
        other => panic!("expected normalized instruction, got {other:?}"),
    }
}

fn reg(index: u8, width: Width, high: bool) -> Register {
    Register::new(Gpr::new(index).unwrap(), width, high).unwrap()
}

fn memory(decoded: Decoded) -> Address {
    match decoded.operands[1] {
        Operand::Memory { address, .. } | Operand::Address(address) => address,
        other => panic!("expected address, got {other:?}"),
    }
}

#[test]
fn register_alias_writes_preserve_only_architecturally_unaffected_bits() {
    let original = 0x1122_3344_5566_7788;
    for index in 0..16 {
        for (width, high, value, expected) in [
            (Width::Byte, false, 0x1aa, 0x1122_3344_5566_77aa),
            (Width::Word, false, 0x1bbcc, 0x1122_3344_5566_bbcc),
            (Width::Dword, false, 0x1_dead_beef, 0xdead_beef),
            (Width::Qword, false, u64::MAX, u64::MAX),
        ] {
            let mut registers = [original; 16];
            reg(index, width, high).write(&mut registers, value);
            assert_eq!(registers[index as usize], expected);
            for (other, &value) in registers.iter().enumerate() {
                if other != index as usize {
                    assert_eq!(value, original);
                }
            }
        }
    }
    for index in 0..4 {
        let mut registers = [original; 16];
        let ah = reg(index, Width::Byte, true);
        assert_eq!(ah.read(&registers), 0x77);
        ah.write(&mut registers, 0x1aa);
        assert_eq!(registers[index as usize], 0x1122_3344_5566_aa88);
    }
    assert!(Gpr::new(16).is_none());
    assert!(Register::new(Gpr::new(4).unwrap(), Width::Byte, true).is_none());
    assert!(Register::new(Gpr::new(0).unwrap(), Width::Word, true).is_none());
}

#[test]
fn high_byte_and_rex_byte_aliases_are_distinct() {
    assert_eq!(
        decode(&[0x88, 0xe0], 0).operands,
        [
            Operand::Register(reg(0, Width::Byte, false)),
            Operand::Register(reg(0, Width::Byte, true))
        ]
    );
    assert_eq!(
        decode(&[0x40, 0x88, 0xe0], 0).operands,
        [
            Operand::Register(reg(0, Width::Byte, false)),
            Operand::Register(reg(4, Width::Byte, false))
        ]
    );
    for index in 0..16 {
        let bytes = [0x40 | (index >> 3), 0xb0 | (index & 7), 0x55];
        assert_eq!(
            decode(&bytes, 0).operands[0],
            Operand::Register(reg(index, Width::Byte, false))
        );
    }
}

#[test]
fn immediate_extension_preserves_encoded_and_operand_widths() {
    for (bytes, encoded_width, width, value) in [
        (
            &[0x48, 0x83, 0xc0, 0x80][..],
            Width::Byte,
            Width::Qword,
            0xffff_ffff_ffff_ff80,
        ),
        (
            &[0x83, 0xc0, 0x80][..],
            Width::Byte,
            Width::Dword,
            0xffff_ff80,
        ),
        (
            &[0x66, 0x83, 0xc0, 0x80][..],
            Width::Byte,
            Width::Word,
            0xff80,
        ),
        (
            &[0x48, 0xc7, 0xc0, 0, 0, 0, 0x80][..],
            Width::Dword,
            Width::Qword,
            0xffff_ffff_8000_0000,
        ),
        (
            &[0xb8, 0xff, 0xff, 0xff, 0xff][..],
            Width::Dword,
            Width::Dword,
            0xffff_ffff,
        ),
        (
            &[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8][..],
            Width::Qword,
            Width::Qword,
            0x0807_0605_0403_0201,
        ),
    ] {
        assert_eq!(
            decode(bytes, 0).operands[1],
            Operand::Immediate(Immediate {
                encoded_width,
                width,
                value,
            })
        );
    }
}

#[test]
fn all_sib_scales_extended_registers_and_signed_displacements() {
    let mut registers = [0; 16];
    registers[13] = 0x1000;
    registers[9] = 7;
    for (bits, factor) in [(0, 1), (1, 2), (2, 4), (3, 8)] {
        let decoded = decode(&[0x4b, 0x8b, 0x44, (bits << 6) | 0x0d, 0xf0], 0);
        let address = memory(decoded);
        assert_eq!(address.base, Base::Register(Gpr::new(13).unwrap()));
        assert_eq!(address.index, Gpr::new(9));
        assert_eq!(
            address.offset(&registers, decoded.encoding.next_rip()),
            0xff0 + 7 * factor
        );
    }
    let no_base = memory(decode(&[0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0x80], 0));
    assert_eq!(no_base.base, Base::None);
    assert_eq!(no_base.index, None);
    assert_eq!(no_base.offset(&registers, 0), 0xffff_ffff_8000_0000);
}

#[test]
fn address32_wraps_before_fs_or_gs_base_is_added() {
    let mut registers = [0; 16];
    registers[0] = 0xaaaa_ffff_ffff_fffc;
    registers[1] = 0xbbbb_0000_0000_0002;
    for (prefix, segment) in [(0x64, Segment::Fs), (0x65, Segment::Gs)] {
        let address = memory(decode(&[prefix, 0x67, 0x48, 0x8b, 0x44, 0x88, 0xff], 0));
        assert_eq!(address.size, AddressSize::Bits32);
        assert_eq!(address.segment, segment);
        assert_eq!(address.offset(&registers, 0), 3);
        assert_eq!(
            address.linear(
                &registers,
                0,
                SegmentBases {
                    fs: 0x1_0000_0000,
                    gs: 0x1_0000_0000
                }
            ),
            0x1_0000_0003
        );
    }
    let absolute = memory(decode(&[0x67, 0x48, 0xa1, 0xff, 0xff, 0xff, 0xff], 0));
    assert_eq!(absolute.offset(&registers, 0), 0xffff_ffff);
}

#[test]
fn rip_and_eip_relative_addresses_use_next_rip_including_wrap() {
    for rip in [0x1000, 0xffff_ffff_ffff_fffc] {
        let decoded = decode(&[0x48, 0x8b, 0x05, 0xf9, 0xff, 0xff, 0xff], rip);
        assert_eq!(
            memory(decoded).offset(&[0; 16], decoded.encoding.next_rip()),
            rip
        );
    }
    let decoded = decode(
        &[0x67, 0x48, 0x8b, 0x05, 0xf8, 0xff, 0xff, 0xff],
        0x1234_ffff_fffc,
    );
    assert_eq!(
        memory(decoded).offset(&[0; 16], decoded.encoding.next_rip()),
        0xffff_fffc
    );
}

#[test]
fn lea_has_no_memory_operand_and_ignores_segment_base() {
    let decoded = decode(&[0x64, 0x48, 0x8d, 0x44, 0x24, 0xf8], 0);
    assert_eq!(decoded.operation, Operation::Lea);
    let Operand::Address(address) = decoded.operands[1] else {
        panic!("LEA must not load memory")
    };
    assert_eq!(address.segment, Segment::Fs);
    let mut registers = [0; 16];
    registers[4] = 0x1000;
    assert_eq!(
        address.offset(&registers, decoded.encoding.next_rip()),
        0xff8
    );
}

#[test]
fn operand_widths_and_effective_segments_are_not_conflated() {
    for (bytes, expected_width, segment) in [
        (&[0x8a, 0x00][..], Width::Byte, Segment::Ds),
        (&[0x66, 0x8b, 0x00][..], Width::Word, Segment::Ds),
        (&[0x8b, 0x00][..], Width::Dword, Segment::Ds),
        (&[0x48, 0x8b, 0x45, 0][..], Width::Qword, Segment::Ss),
        (&[0x3e, 0x48, 0x8b, 0x45, 0][..], Width::Qword, Segment::Ds),
    ] {
        let decoded = decode(bytes, 0);
        let Operand::Memory { address, width } = decoded.operands[1] else {
            panic!("memory")
        };
        assert_eq!(width, expected_width);
        assert_eq!(address.segment, segment);
    }
}

#[test]
fn incremental_fetch_never_touches_the_following_unmapped_page() {
    let mut decoder = FetchDecoder::new(0xffd);
    let bytes = [0x49, 0x89, 0xf7]; // Actual first instruction of the pinned Linux entry.
    let mut observed = Vec::new();
    while let Some(request) = decoder.request() {
        assert!(request.address < 0x1000, "spurious next-page fetch");
        observed.push(request.address);
        decoder
            .complete(request, bytes[(request.address - 0xffd) as usize])
            .unwrap();
    }
    assert_eq!(observed, [0xffd, 0xffe, 0xfff]);
    let Outcome::Normalized(decoded) = decoder.outcome().unwrap() else {
        panic!("MOV")
    };
    assert_eq!(
        decoded.operands,
        [
            Operand::Register(reg(15, Width::Qword, false)),
            Operand::Register(reg(6, Width::Qword, false))
        ]
    );
}

#[test]
fn fetch_fault_retry_retains_progress_and_rejects_stale_completions() {
    let mut decoder = FetchDecoder::new(0xfff);
    let first = decoder.request().unwrap();
    decoder.complete(first, 0x48).unwrap();
    let crossing = decoder.request().unwrap();
    assert_eq!(crossing.address, 0x1000);
    // The MMU may fault or yield without completing this request.
    assert_eq!(decoder.fetched(), &[0x48]);
    assert!(decoder.outcome().is_none());
    assert!(matches!(
        decoder.complete(first, 0xff),
        Err(CompletionError::WrongAddress { .. })
    ));
    assert_eq!(decoder.request(), Some(crossing));
    decoder.complete(crossing, 0x89).unwrap();
    decoder.complete(decoder.request().unwrap(), 0xc8).unwrap();
    let done = *decoder.outcome().unwrap();
    assert_eq!(
        decoder.complete(crossing, 0),
        Err(CompletionError::AlreadyComplete)
    );
    assert_eq!(decoder.outcome(), Some(&done));
}

#[test]
fn invalid_valid_unsupported_and_prefix_length_limit_are_distinct_from_truncation() {
    let mut bytes = [0; 15];
    bytes[..3].copy_from_slice(&[0x89, 0xc8, 0x90]);
    let malformed = x86_system::shared::decode::DecodeInput {
        sequence: 1,
        rip: 0x1000,
        length: 3,
        bytes,
    };
    assert!(matches!(
        admit(malformed),
        x86_system::shared::decode::DecodeDecision::Rejected
    ));
    assert!(matches!(
        outcome(&[0xf0, 0x01, 0xc8], 0),
        Outcome::Rejected(_)
    ));
    for bytes in [
        &[0x0f, 0x30][..],
        &[0x0f, 0x22, 0xd8][..],
        &[0xc5, 0xf8, 0x77][..],
    ] {
        assert!(matches!(outcome(bytes, 0), Outcome::Unsupported { .. }));
    }
    let mut decoder = FetchDecoder::new(0);
    for _ in 0..14 {
        decoder.complete(decoder.request().unwrap(), 0x66).unwrap();
        assert!(decoder.outcome().is_none());
    }
    decoder.complete(decoder.request().unwrap(), 0x66).unwrap();
    assert!(matches!(decoder.outcome(), Some(Outcome::Rejected(_))));
    assert!(decoder.request().is_none());
    let mut maximum = vec![0x66; 13];
    maximum.extend_from_slice(&[0x89, 0xc0]);
    assert_eq!(
        decode(&maximum, 0).operands[0],
        Operand::Register(reg(0, Width::Word, false))
    );
}

#[test]
fn lock_and_repeat_prefixes_survive_normalization_without_enabling_execution() {
    let locked = decode(&[0xf0, 0x48, 0x01, 0x08], 0);
    assert!(locked.prefixes.lock);
    assert!(matches!(locked.operands[0], Operand::Memory { .. }));
    let repeated = decode(&[0xf3, 0x48, 0x89, 0xc8], 0);
    assert_eq!(repeated.prefixes.repeat, Repeat::Rep);
    assert!(!repeated.prefixes.lock);
    for (prefix, hint) in [
        (0xf2, TransactionHint::Acquire),
        (0xf3, TransactionHint::Release),
    ] {
        assert_eq!(
            decode(&[prefix, 0xf0, 0x48, 0x01, 0x08], 0)
                .prefixes
                .transaction,
            hint
        );
    }
}

#[test]
fn old_restricted_register_forms_have_identical_normalized_operands() {
    use x86_system::Kind;
    use x86_system::decoder::{Decode, decode as old_decode};
    for rex in 0x48..=0x4f {
        for opcode in [0x01, 0x11] {
            for modrm in 0xc0..=0xff {
                let bytes = [rex, opcode, modrm];
                let Decode::Success(old) = old_decode(&bytes) else {
                    panic!("old form")
                };
                let decoded = decode(&bytes, 0);
                assert_eq!(
                    decoded.operation,
                    if old.kind == Kind::Add {
                        Operation::Add
                    } else {
                        Operation::Adc
                    }
                );
                assert_eq!(
                    decoded.operands,
                    [
                        Operand::Register(reg(old.dst, Width::Qword, false)),
                        Operand::Register(reg(old.src, Width::Qword, false)),
                    ]
                );
            }
        }
    }
}

#[test]
fn pinned_kernel_entry_operands_are_normalized_without_claiming_execution() {
    let entry = 0x2d98100;
    let decoded = decode(&[0x48, 0x8d, 0x25, 0x3e, 0xbe, 0x86, 0xff], entry + 3);
    assert_eq!(decoded.operation, Operation::Lea);
    assert_eq!(
        decoded.operands[0],
        Operand::Register(reg(4, Width::Qword, false))
    );
    assert!(matches!(decoded.operands[1], Operand::Address(_)));
    let mov = decode(&[0xb9, 1, 1, 0, 0xc0], entry + 0xa);
    assert_eq!(
        mov.operands[0],
        Operand::Register(reg(1, Width::Dword, false))
    );
    assert_eq!(
        mov.operands[1],
        Operand::Immediate(Immediate {
            encoded_width: Width::Dword,
            width: Width::Dword,
            value: 0xc0000101
        })
    );
}

#[test]
fn old_restricted_mov_memory_forms_keep_register_and_address_identity() {
    use x86_system::mmu_core::memory_core::{Op, decode as old_decode};
    for rex in 0x48..=0x4f {
        for opcode in [0x89, 0x8b] {
            for modrm in 0..=0x3f {
                let old = old_decode(rex, opcode, modrm);
                let (register, base, memory_index) = match old {
                    Op::Load { reg, base } => (reg, base, 1),
                    Op::Store { reg, base } => (reg, base, 0),
                    _ => continue,
                };
                let decoded = decode(&[rex, opcode, modrm], 0);
                let Operand::Memory { address, width } = decoded.operands[memory_index] else {
                    panic!("memory")
                };
                assert_eq!(width, Width::Qword);
                assert_eq!(address.base, Base::Register(Gpr::new(base).unwrap()));
                assert_eq!(address.index, None);
                assert_eq!(address.displacement, 0);
                assert_eq!(
                    decoded.operands[1 - memory_index],
                    Operand::Register(reg(register, Width::Qword, false))
                );
            }
        }
    }
}

#[test]
fn absolute64_and_displacement_bytes_do_not_masquerade_as_address_prefixes() {
    let decoded = decode(
        &[0x48, 0xa1, 0x67, 0x45, 0x23, 1, 0x89, 0xab, 0xcd, 0xef],
        0,
    );
    let address = memory(decoded);
    assert_eq!(address.size, AddressSize::Bits64);
    assert_eq!(address.offset(&[0; 16], 0), 0xefcd_ab89_0123_4567);
    let decoded = decode(&[0x48, 0x8b, 0x80, 0x67, 0, 0, 0], 0);
    assert_eq!(memory(decoded).size, AddressSize::Bits64);
}

#[test]
fn actual_kernel_entry_moves_boot_pointer_sets_stack_and_clears_ecx_upper_half() {
    let entry = 0x2d98100;
    let code = [
        &[0x49, 0x89, 0xf7][..],
        &[0x48, 0x8d, 0x25, 0x3e, 0xbe, 0x86, 0xff][..],
        &[0xb9, 1, 1, 0, 0xc0][..],
    ];
    let original = [0xfeed_face_dead_beef; 16];
    let mut registers = original;
    registers[6] = 0x90000;
    let mut rip = entry;
    for bytes in code {
        let decoded = decode(bytes, rip);
        commit_decoded(decoded, &mut registers, &mut rip, 2).unwrap();
    }
    let mut expected = original;
    expected[6] = 0x90000;
    expected[15] = 0x90000;
    expected[4] = 0x2603f48;
    expected[1] = 0xc0000101;
    assert_eq!(registers, expected);
    assert_eq!(rip, entry + 15);
    assert!(matches!(
        outcome(&[0x31, 0xc0], rip),
        Outcome::Unsupported { .. }
    ));
}

#[test]
fn scalar_admission_rejects_unimplemented_effects_without_changing_state() {
    for bytes in [
        &[0x48, 0x8b, 0x00][..],
        &[0x48, 0x89, 0x08][..],
        &[0xf0, 0x48, 0x01, 0x08][..],
        &[0xf3, 0x48, 0x89, 0xc8][..],
        &[0x48, 0x01, 0xc8][..],
    ] {
        let decoded = decode(bytes, 0x1000);
        let mut registers = [0x1234; 16];
        let mut rip = 0x1000;
        assert!(commit_decoded(decoded, &mut registers, &mut rip, 2).is_err());
        assert_eq!(registers, [0x1234; 16]);
        assert_eq!(rip, 0x1000);
    }
    let decoded = decode(&[0x48, 0x89, 0xc8], 0x1000);
    for (ip, flags, expected) in [
        (
            0x1001,
            2,
            ScalarError::WrongRip {
                expected: 0x1000,
                received: 0x1001,
            },
        ),
        (
            0x1000,
            0x102,
            ScalarError::Core(ScalarStatus::DebugRequired),
        ),
        (
            0x1000,
            0x10002,
            ScalarError::Core(ScalarStatus::DebugRequired),
        ),
    ] {
        let mut registers = [0x1234; 16];
        let mut rip = ip;
        assert_eq!(
            commit_decoded(decoded, &mut registers, &mut rip, flags),
            Err(expected)
        );
        assert_eq!(registers, [0x1234; 16]);
        assert_eq!(rip, ip);
    }
}
