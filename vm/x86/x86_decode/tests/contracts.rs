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
        Outcome::InvalidOpcode(_)
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
    assert!(matches!(decoder.outcome(), Some(Outcome::Overlong(_))));
    assert!(decoder.request().is_none());
    let mut maximum = vec![0x66; 13];
    maximum.extend_from_slice(&[0x89, 0xc0]);
    assert_eq!(
        decode(&maximum, 0).operands[0],
        Operand::Register(reg(0, Width::Word, false))
    );
}

#[test]
fn architectural_decode_faults_keep_ambiguous_full_length_failures_diagnostic() {
    use x86_system::shared::decode::{DecodeDecision, DecodeInput};
    for (code, expected) in [
        (&[0x0f, 0x0b][..], DecodeDecision::InvalidOpcode),
        (&[0xf0, 0x01, 0xc8][..], DecodeDecision::InvalidOpcode),
        (&[0x66; 15][..], DecodeDecision::Overlong),
        (&[0x4f; 15][..], DecodeDecision::Overlong),
        (&[0xc5, 0xf8, 0x77][..], DecodeDecision::Unsupported),
    ] {
        let mut bytes = [0; 15];
        bytes[..code.len()].copy_from_slice(code);
        assert_eq!(
            admit(DecodeInput {
                sequence: 1,
                rip: 0xfff,
                length: code.len() as u8,
                bytes
            }),
            expected
        );
    }
    let mut bytes = [0x66; 15];
    bytes[8..10].copy_from_slice(&[0x48, 0xb8]);
    bytes[10..].fill(0);
    assert_eq!(
        admit(DecodeInput {
            sequence: 1,
            rip: 0,
            length: 15,
            bytes
        }),
        DecodeDecision::Rejected
    );
    bytes[..3].copy_from_slice(&[0x0f, 0x0b, 0x90]);
    assert_eq!(
        admit(DecodeInput {
            sequence: 1,
            rip: 0,
            length: 3,
            bytes
        }),
        DecodeDecision::Rejected
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
    let xor = decode(&[0x31, 0xc0], rip);
    assert_eq!(xor.operation, Operation::Xor);
    assert_eq!(
        commit_decoded(xor, &mut registers, &mut rip, 2),
        Err(ScalarError::UnsupportedForm)
    );
    assert_eq!(registers, expected);
    assert_eq!(rip, entry + 15);
}

#[test]
fn entry_xor_and_exact_validated_system_forms_have_bounded_cpu_admission() {
    use x86_system::shared::decode::{DecodeDecision, DecodeInput};
    let input = |bytes: &[u8]| {
        let mut packet = DecodeInput {
            sequence: 1,
            rip: 0x2d98100,
            length: bytes.len() as u8,
            bytes: [0; 15],
        };
        packet.bytes[..bytes.len()].copy_from_slice(bytes);
        packet
    };
    for (bytes, dst, src) in [
        (&[0x31, 0xc0][..], 0, 0),
        (&[0x41, 0x31, 0xc1][..], 9, 0),
        (&[0x44, 0x33, 0xc9][..], 9, 1),
    ] {
        assert_eq!(
            admit(input(bytes)),
            DecodeDecision::Xor32 {
                dst: reg(dst, Width::Dword, false),
                src: reg(src, Width::Dword, false)
            }
        );
    }
    assert_eq!(admit(input(&[0x0f, 0x30])), DecodeDecision::Wrmsr);
    assert_eq!(
        admit(input(&[0xe8, 0x40, 0x2e, 0xff, 0xff])),
        DecodeDecision::NearCall {
            displacement: -0xd1c0
        }
    );
    for bytes in [
        &[0x31, 0x00][..],
        &[0x66, 0x0f, 0x30][..],
        &[0x48, 0xe8, 0, 0, 0, 0][..],
    ] {
        assert_eq!(
            admit(input(bytes)),
            DecodeDecision::Unsupported,
            "{bytes:02x?}"
        );
    }
    assert_eq!(
        admit(input(&[0xe8, 0, 0, 0, 0, 0x90])),
        DecodeDecision::Rejected
    );
    for bytes in [&[0xe8][..], &[0xe8, 0, 0, 0][..], &[0x0f][..], &[0x31][..]] {
        assert_eq!(admit(input(bytes)), DecodeDecision::More);
    }
}

#[test]
fn descriptor_entry_family_preserves_owned_operands_and_extension() {
    use x86_system::memory_core::cpu_core::integer;
    use x86_system::shared::decode::{DecodeDecision, DecodeInput};
    use x86_system::shared::entry::Instruction;
    let packet = |bytes: &[u8]| {
        let mut input = DecodeInput {
            sequence: 19,
            rip: 0x1000,
            length: bytes.len() as u8,
            bytes: [0; 15],
        };
        input.bytes[..bytes.len()].copy_from_slice(bytes);
        input
    };
    assert!(matches!(admit(packet(&[0x48,0x83,0xec,0x10])),
        DecodeDecision::Entry(Instruction::Integer { operation: integer::Operation::Sub, dst,
            source: Operand::Immediate(Immediate { value: 16, width: Width::Qword, .. }) })
        if dst == reg(4,Width::Qword,false)));
    assert!(matches!(
        admit(packet(&[0x48, 0x83, 0xe4, 0xf0])),
        DecodeDecision::Entry(Instruction::Integer {
            operation: integer::Operation::And,
            source: Operand::Immediate(Immediate {
                value: 0xffff_ffff_ffff_fff0,
                ..
            }),
            ..
        })
    ));
    assert!(matches!(admit(packet(&[0x66,0xc7,0x44,0x24,6,0x7f,0])),
        DecodeDecision::Entry(Instruction::Store { address, width:Width::Word,
            source:Operand::Immediate(Immediate{value:0x7f,..}) })
        if address.base == Base::Register(Gpr::new(4).unwrap()) && address.displacement == 6));
    assert!(matches!(admit(packet(&[0x8e,0xd0])),
        DecodeDecision::Entry(Instruction::Segment { segment:Segment::Ss, src })
        if src == reg(0,Width::Word,false)));
    assert!(matches!(admit(packet(&[0x0f,0x01,0x54,0x24,6])),
        DecodeDecision::Entry(Instruction::Table { idt:false,address }) if address.displacement == 6));
    assert!(matches!(admit(packet(&[0x0f,0xb7,0xc7])),
        DecodeDecision::Entry(Instruction::ZeroExtend { dst,src })
        if dst == reg(0,Width::Dword,false) && src == reg(7,Width::Word,false)));
    assert_eq!(
        admit(packet(&[0xc3])),
        DecodeDecision::Entry(Instruction::Return)
    );
    assert_eq!(
        admit(packet(&[0xc9])),
        DecodeDecision::Entry(Instruction::Leave)
    );
    assert!(matches!(
        admit(packet(&[0x74, 0x57])),
        DecodeDecision::Entry(Instruction::Jump {
            target: 0x1059,
            zero: Some(true)
        })
    ));
}

#[test]
fn descriptor_entry_admission_does_not_expand_unrelated_forms_or_skip_truncation() {
    use x86_system::shared::decode::{DecodeDecision, DecodeInput};
    let packet = |bytes: &[u8]| {
        let mut input = DecodeInput {
            sequence: 1,
            rip: 0,
            length: bytes.len() as u8,
            bytes: [0; 15],
        };
        input.bytes[..bytes.len()].copy_from_slice(bytes);
        input
    };
    for bytes in [
        &[0x48, 0x83, 0xec][..],
        &[0x0f, 0x01, 0x54, 0x24][..],
        &[0x66, 0xc7, 0x44, 0x24, 6, 0x7f][..],
    ] {
        assert_eq!(admit(packet(bytes)), DecodeDecision::More);
    }
    for bytes in [
        &[0xcb][..],
        &[0x66, 0xc3][..],
        &[0x66, 0x55][..],
        &[0x8e, 0xe0][..],
        &[0x48, 0xd3, 0xe8][..],
        &[0xf3, 0xc3][..],
        &[0x48, 0x01, 0x08][..],
    ] {
        assert_eq!(
            admit(packet(bytes)),
            DecodeDecision::Unsupported,
            "{bytes:02x?}"
        );
    }
}

#[test]
fn cpu_check_forms_keep_exact_widths_flags_stack_and_branch_conditions() {
    use x86_system::memory_core::cpu_core::{control::Condition, integer};
    use x86_system::shared::decode::{DecodeDecision, DecodeInput};
    use x86_system::shared::entry::Instruction;
    let packet = |bytes: &[u8]| {
        let mut input = DecodeInput {
            sequence: 1,
            rip: 0x1000,
            length: bytes.len() as u8,
            bytes: [0; 15],
        };
        input.bytes[..bytes.len()].copy_from_slice(bytes);
        input
    };
    for (bytes, expected) in [
        (&[0x0f, 0xa2][..], Instruction::Cpuid),
        (&[0x48, 0xcb][..], Instruction::FarReturn),
        (&[0x9c][..], Instruction::PushFlags),
        (&[0x9d][..], Instruction::PopFlags),
        (
            &[0x5b][..],
            Instruction::Pop {
                dst: reg(3, Width::Qword, false),
            },
        ),
        (
            &[0x41, 0x5d][..],
            Instruction::Pop {
                dst: reg(13, Width::Qword, false),
            },
        ),
        (
            &[0x76, 0x10][..],
            Instruction::Branch {
                target: 0x1012,
                condition: Condition::BelowEqual,
            },
        ),
        (
            &[0x72, 0x10][..],
            Instruction::Branch {
                target: 0x1012,
                condition: Condition::Below,
            },
        ),
    ] {
        assert_eq!(admit(packet(bytes)), DecodeDecision::Entry(expected));
    }
    for (bytes, operation, dst, width, value) in [
        (
            &[0x83, 0xf8, 1][..],
            integer::Operation::Cmp,
            0,
            Width::Dword,
            1,
        ),
        (
            &[0x81, 0xf2, 0x69, 0xa1, 0, 7][..],
            integer::Operation::Xor,
            2,
            Width::Dword,
            0x700a169,
        ),
    ] {
        assert!(
            matches!(admit(packet(bytes)),DecodeDecision::Entry(Instruction::Integer {
            operation:actual,dst:register,source:Operand::Immediate(Immediate{value:immediate,..})})
            if actual==operation && register==reg(dst,width,false) && immediate==value)
        );
    }
    for bytes in [
        &[0x66, 0x31, 0xff][..],
        &[0x48, 0x31, 0xc0][..],
        &[0x30, 0xc0][..],
    ] {
        assert!(matches!(
            admit(packet(bytes)),
            DecodeDecision::Entry(Instruction::Integer {
                operation: integer::Operation::Xor,
                ..
            })
        ));
    }
}

#[test]
fn cpu_check_admission_still_rejects_unimplemented_privilege_and_prefix_forms() {
    use x86_system::shared::decode::{DecodeDecision, DecodeInput};
    for bytes in [
        &[0x66, 0x9c][..],
        &[0x66, 0x9d][..],
        &[0xcb][..],
        &[0x66, 0xcb][..],
        &[0xca, 0, 0][..],
        &[0x0f, 0x32][..],
        &[0x66, 0x5b][..],
        &[0xf3, 0x0f, 0xa2][..],
    ] {
        let mut packet = DecodeInput {
            sequence: 1,
            rip: 0,
            length: bytes.len() as u8,
            bytes: [0; 15],
        };
        packet.bytes[..bytes.len()].copy_from_slice(bytes);
        assert_eq!(admit(packet), DecodeDecision::Unsupported, "{bytes:02x?}");
    }
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
