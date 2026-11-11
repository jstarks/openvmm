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
                assert_eq!(
                    admission(&bytes),
                    x86_system::shared::decode::DecodeDecision::Legacy
                );
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
                let bytes = [rex, opcode, modrm];
                assert_eq!(
                    admission(&bytes),
                    x86_system::shared::decode::DecodeDecision::Legacy
                );
                let decoded = decode(&bytes, 0);
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
    for bytes in [&[0x66, 0x0f, 0x30][..], &[0x48, 0xe8, 0, 0, 0, 0][..]] {
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
        &[0x8e, 0x20][..],
        &[0xf3, 0xc3][..],
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
        &[0x0f, 0x33][..],
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

fn admission(bytes: &[u8]) -> x86_system::shared::decode::DecodeDecision {
    let mut packet = x86_system::shared::decode::DecodeInput {
        sequence: 23,
        rip: 0xffff_ffff_82d8_afa6,
        length: bytes.len() as u8,
        bytes: [0; 15],
    };
    packet.bytes[..bytes.len()].copy_from_slice(bytes);
    admit(packet)
}

fn entry(bytes: &[u8]) -> x86_system::shared::entry::Instruction {
    match admission(bytes) {
        x86_system::shared::decode::DecodeDecision::Entry(instruction) => instruction,
        other => panic!("expected entry admission for {bytes:02x?}, got {other:?}"),
    }
}

fn alu(
    bytes: &[u8],
) -> (
    x86_system::memory_core::cpu_core::integer::Operation,
    Operand,
    Operand,
) {
    use x86_system::shared::entry::Instruction;
    match entry(bytes) {
        Instruction::Integer {
            operation,
            dst,
            source,
        } => (operation, Operand::Register(dst), source),
        Instruction::Alu {
            operation,
            destination,
            source,
        } => (operation, destination, source),
        other => panic!("expected ALU admission, got {other:?}"),
    }
}

#[test]
fn binary_alu_widths_cover_both_memory_directions_and_extended_immediates() {
    use x86_system::memory_core::cpu_core::integer::Operation as Integer;
    for (prefix, width) in [
        (&[][..], Width::Byte),
        (&[0x66][..], Width::Word),
        (&[][..], Width::Dword),
        (&[0x48][..], Width::Qword),
    ] {
        let byte = width == Width::Byte;
        let rax = Operand::Register(reg(0, width, false));
        let rcx = Operand::Register(reg(1, width, false));
        let memory = Operand::Memory {
            address: Address {
                size: AddressSize::Bits64,
                segment: Segment::Ds,
                base: Base::Register(Gpr::new(7).unwrap()),
                index: None,
                scale: Scale::One,
                displacement: 8,
            },
            width,
        };
        let immediate = Operand::Immediate(Immediate {
            encoded_width: Width::Byte,
            width,
            value: width.mask(),
        });
        for (suffix, destination, source) in [
            (vec![if byte { 0x28 } else { 0x29 }, 0xc8], rax, rcx),
            (
                vec![if byte { 0x80 } else { 0x83 }, 0xe8, 0xff],
                rax,
                immediate,
            ),
            (vec![if byte { 0x2a } else { 0x2b }, 0x47, 8], rax, memory),
            (vec![if byte { 0x28 } else { 0x29 }, 0x4f, 8], memory, rcx),
            (
                vec![if byte { 0x80 } else { 0x83 }, 0x6f, 8, 0xff],
                memory,
                immediate,
            ),
        ] {
            let bytes = [prefix, suffix.as_slice()].concat();
            assert_eq!(alu(&bytes), (Integer::Sub, destination, source));
        }
    }
    for (bytes, operation) in [
        (&[0x48, 0x01, 0x08][..], Integer::Add),
        (&[0x48, 0x11, 0x08][..], Integer::Adc),
        (&[0x48, 0x19, 0x08][..], Integer::Sbb),
        (&[0x48, 0x21, 0x08][..], Integer::And),
        (&[0x48, 0x09, 0x08][..], Integer::Or),
        (&[0x31, 0x00][..], Integer::Xor),
        (&[0x48, 0x39, 0x08][..], Integer::Cmp),
        (&[0x48, 0x85, 0x08][..], Integer::Test),
    ] {
        let (actual, destination, source) = alu(bytes);
        assert_eq!(actual, operation);
        assert!(matches!(destination, Operand::Memory { .. }));
        assert!(matches!(source, Operand::Register(_)));
    }
    assert_eq!(
        alu(&[0x48, 0x81, 0x20, 0, 0, 0, 0x80]).2,
        Operand::Immediate(Immediate {
            encoded_width: Width::Dword,
            width: Width::Qword,
            value: 0xffff_ffff_8000_0000,
        })
    );
    let (_, destination, source) = alu(&[0x48, 0x2b, 0x3d, 0xf9, 0xff, 0xff, 0xff]);
    assert_eq!(destination, Operand::Register(reg(7, Width::Qword, false)));
    let Operand::Memory { address, width } = source else {
        panic!("memory-source SUB")
    };
    assert_eq!(width, Width::Qword);
    assert_eq!(address.base, Base::NextRip);
    assert_eq!(
        address.offset(&[0; 16], 0xffff_ffff_82d8_afad),
        0xffff_ffff_82d8_afa6
    );
}

#[test]
fn unary_alu_keeps_width_high_byte_aliases_and_fs_address32() {
    use x86_system::memory_core::cpu_core::integer::Operation as Integer;
    for (prefix, width) in [
        (&[][..], Width::Byte),
        (&[0x66][..], Width::Word),
        (&[][..], Width::Dword),
        (&[0x48][..], Width::Qword),
    ] {
        for (operation, opcode, extension) in [
            (Integer::Inc, 0xff, 0),
            (Integer::Dec, 0xff, 1),
            (Integer::Neg, 0xf7, 3),
            (Integer::Not, 0xf7, 2),
        ] {
            let opcode = opcode - u8::from(width == Width::Byte);
            for memory in [false, true] {
                let bytes = if memory {
                    [&[0x64, 0x67][..], prefix, &[opcode, extension << 3]].concat()
                } else {
                    [prefix, &[opcode, 0xc0 | (extension << 3)]].concat()
                };
                let (actual, destination, source) = alu(&bytes);
                assert_eq!(actual, operation);
                assert_eq!(
                    source,
                    Operand::Immediate(Immediate {
                        encoded_width: width,
                        width,
                        value: 0,
                    })
                );
                if memory {
                    let Operand::Memory {
                        address,
                        width: actual_width,
                    } = destination
                    else {
                        panic!("memory destination")
                    };
                    assert_eq!(actual_width, width);
                    assert_eq!(address.size, AddressSize::Bits32);
                    assert_eq!(address.segment, Segment::Fs);
                    let mut registers = [0; 16];
                    registers[0] = 0x1234_5678_ffff_ffff;
                    assert_eq!(
                        address.linear(
                            &registers,
                            0,
                            SegmentBases {
                                fs: 0x1_0000_0000,
                                gs: 0,
                            }
                        ),
                        0x1_ffff_ffff
                    );
                } else {
                    assert_eq!(destination, Operand::Register(reg(0, width, false)));
                }
            }
        }
    }
    assert_eq!(
        alu(&[0xf6, 0xdc]).1,
        Operand::Register(reg(0, Width::Byte, true))
    );
    assert_eq!(
        alu(&[0x40, 0xf6, 0xdc]).1,
        Operand::Register(reg(4, Width::Byte, false))
    );
}

#[test]
fn register_shift_counts_keep_cl_aliases_and_memory_shifts_unsupported() {
    use x86_system::memory_core::cpu_core::integer::Operation as Integer;
    use x86_system::shared::decode::DecodeDecision;
    for (prefix, width) in [
        (&[][..], Width::Byte),
        (&[0x66][..], Width::Word),
        (&[][..], Width::Dword),
        (&[0x48][..], Width::Qword),
    ] {
        for (extension, operation) in [(4, Integer::Shl), (5, Integer::Shr), (7, Integer::Sar)] {
            for (opcode, count) in [
                (
                    0xc1,
                    Operand::Immediate(Immediate {
                        encoded_width: Width::Byte,
                        width: Width::Byte,
                        value: 0xff,
                    }),
                ),
                (0xd3, Operand::Register(reg(1, Width::Byte, false))),
            ] {
                let opcode = opcode - u8::from(width == Width::Byte);
                let mut bytes = [prefix, &[opcode, 0xc1 | (extension << 3)]].concat();
                if matches!(count, Operand::Immediate(_)) {
                    bytes.push(0xff);
                }
                assert_eq!(
                    alu(&bytes),
                    (operation, Operand::Register(reg(1, width, false)), count)
                );
                let opcode_index = prefix.len();
                bytes[opcode_index + 1] &= 0x3f;
                assert_eq!(admission(&bytes), DecodeDecision::Unsupported);
            }
        }
    }
    assert!(matches!(
        alu(&[0x48, 0xd1, 0xe0]).2,
        Operand::Immediate(Immediate { value: 1, .. })
    ));
    assert_eq!(
        admission(&[0x48, 0xc1, 0x20, 0]),
        DecodeDecision::Unsupported
    );
}

#[test]
fn sign_extension_and_division_preserve_source_width_and_memory_address() {
    use x86_system::shared::decode::DecodeDecision;
    use x86_system::shared::entry::Instruction;
    for (bytes, destination_width, source_width, memory) in [
        (
            &[0x66, 0x0f, 0xbe, 0xc4][..],
            Width::Word,
            Width::Byte,
            false,
        ),
        (&[0x0f, 0xbe, 0xc4][..], Width::Dword, Width::Byte, false),
        (
            &[0x48, 0x0f, 0xbf, 0x00][..],
            Width::Qword,
            Width::Word,
            true,
        ),
        (&[0x48, 0x63, 0xc1][..], Width::Qword, Width::Dword, false),
        (
            &[0x65, 0x67, 0x48, 0x63, 0x00][..],
            Width::Qword,
            Width::Dword,
            true,
        ),
    ] {
        let Instruction::SignExtend { dst, source, width } = entry(bytes) else {
            panic!("sign extension")
        };
        assert_eq!(dst, reg(0, destination_width, false));
        assert_eq!(width, source_width);
        if memory {
            assert!(matches!(source, Operand::Memory { width, .. } if width == source_width));
        } else {
            assert!(matches!(source, Operand::Register(src) if src.width() == source_width));
            if source_width == Width::Byte {
                assert_eq!(source, Operand::Register(reg(0, Width::Byte, true)));
            }
        }
        if bytes[0] == 0x65 {
            let Operand::Memory { address, .. } = source else {
                unreachable!()
            };
            assert_eq!(address.size, AddressSize::Bits32);
            assert_eq!(address.segment, Segment::Gs);
        }
    }
    for (bytes, width) in [
        (&[0x66, 0x99][..], Width::Word),
        (&[0x99][..], Width::Dword),
        (&[0x48, 0x99][..], Width::Qword),
    ] {
        assert_eq!(entry(bytes), Instruction::SignHigh { width });
    }
    for (prefix, width) in [(&[][..], Width::Dword), (&[0x48][..], Width::Qword)] {
        for signed in [false, true] {
            for memory in [false, true] {
                let modrm = (if memory { 0 } else { 0xc0 }) | (if signed { 7 } else { 6 } << 3) | 1;
                let bytes = [prefix, &[0xf7, modrm]].concat();
                let Instruction::Divide {
                    source,
                    width: actual_width,
                    signed: actual_signed,
                } = entry(&bytes)
                else {
                    panic!("division")
                };
                assert_eq!((actual_width, actual_signed), (width, signed));
                assert_eq!(matches!(source, Operand::Memory { .. }), memory);
            }
        }
    }
    for bytes in [&[0xf6, 0xf1][..], &[0x66, 0xf7, 0xf9][..]] {
        assert_eq!(admission(bytes), DecodeDecision::Unsupported);
    }
}

#[test]
fn register_bits_mask_immediate_indices_but_reject_memory_bit_strings() {
    use x86_system::memory_core::cpu_core::scalar::BitOperation;
    use x86_system::shared::decode::DecodeDecision;
    use x86_system::shared::entry::Instruction;
    for (prefix, width) in [
        (&[0x66][..], Width::Word),
        (&[][..], Width::Dword),
        (&[0x48][..], Width::Qword),
    ] {
        for (opcode, extension, operation) in [
            (0xa3, 4, BitOperation::Test),
            (0xab, 5, BitOperation::Set),
            (0xb3, 6, BitOperation::Reset),
            (0xbb, 7, BitOperation::Complement),
        ] {
            let bytes = [prefix, &[0x0f, opcode, 0xc8]].concat();
            assert_eq!(
                entry(&bytes),
                Instruction::Bit {
                    operation,
                    dst: reg(0, width, false),
                    index: Operand::Register(reg(1, width, false)),
                }
            );
            let bytes = [prefix, &[0x0f, 0xba, 0xc0 | (extension << 3), 0xff]].concat();
            assert_eq!(
                entry(&bytes),
                Instruction::Bit {
                    operation,
                    dst: reg(0, width, false),
                    index: Operand::Immediate(Immediate {
                        encoded_width: Width::Byte,
                        width: Width::Byte,
                        value: width.bits() as u64 - 1,
                    }),
                }
            );
            let bytes = [prefix, &[0x0f, opcode, 0x08]].concat();
            assert_eq!(admission(&bytes), DecodeDecision::Unsupported);
            let bytes = [prefix, &[0x0f, 0xba, extension << 3, 0xff]].concat();
            assert_eq!(admission(&bytes), DecodeDecision::Unsupported);
        }
    }
}

#[test]
fn control_moves_indirect_jumps_and_prefix_frontiers_are_explicit() {
    use x86_system::shared::decode::DecodeDecision;
    use x86_system::shared::entry::Instruction;
    for number in [0, 3, 4] {
        assert_eq!(
            entry(&[0x41, 0x0f, 0x20, 0xc0 | (number << 3)]),
            Instruction::ReadControl {
                number,
                dst: reg(8, Width::Qword, false),
            }
        );
    }
    assert_eq!(
        entry(&[0x41, 0x0f, 0x22, 0xd8]),
        Instruction::WriteControl {
            number: 3,
            source: Operand::Register(reg(8, Width::Qword, false)),
        }
    );
    assert_eq!(
        entry(&[0x41, 0xff, 0xe0]),
        Instruction::IndirectJump {
            source: Operand::Register(reg(8, Width::Qword, false)),
        }
    );
    let Instruction::IndirectJump {
        source: Operand::Memory { address, width },
    } = entry(&[0x64, 0x67, 0xff, 0x60, 0xf8])
    else {
        panic!("memory indirect jump")
    };
    assert_eq!(width, Width::Qword);
    assert_eq!(address.size, AddressSize::Bits32);
    assert_eq!(address.segment, Segment::Fs);
    let mut registers = [0; 16];
    registers[0] = 0x1234_5678_0000_0010;
    assert_eq!(address.offset(&registers, 0), 8);
    for bytes in [
        &[0x0f, 0x22, 0xd0][..],
        &[0x44, 0x0f, 0x22, 0xc0][..],
        &[0x44, 0x0f, 0x20, 0xc0][..],
        &[0x0f, 0x21, 0xc0][..],
        &[0x0f, 0x33][..],
        &[0xff, 0x28][..],
        &[0xf3, 0x48, 0x83, 0x28, 1][..],
        &[0xf2, 0x48, 0x83, 0x28, 1][..],
        &[0xf2, 0xf0, 0x48, 0x83, 0x28, 1][..],
        &[0xf3, 0xf0, 0x48, 0x83, 0x28, 1][..],
    ] {
        assert_eq!(
            admission(bytes),
            DecodeDecision::Unsupported,
            "{bytes:02x?}"
        );
    }
}

#[test]
fn imul_packets_cover_two_and_three_operands_and_signed_immediates() {
    use x86_system::shared::decode::DecodeDecision;
    use x86_system::shared::entry::Instruction;
    for (prefix, width) in [
        (&[0x66][..], Width::Word),
        (&[][..], Width::Dword),
        (&[0x48][..], Width::Qword),
    ] {
        for memory in [false, true] {
            let source = if memory {
                Operand::Memory {
                    address: Address {
                        size: AddressSize::Bits64,
                        segment: Segment::Ds,
                        base: Base::Register(Gpr::new(0).unwrap()),
                        index: Gpr::new(1),
                        scale: Scale::Four,
                        displacement: (-8i64) as u64,
                    },
                    width,
                }
            } else {
                Operand::Register(reg(1, width, false))
            };
            for immediate in [None, Some(0), Some(0x7f), Some(width.mask() - 0x7f)] {
                let mut suffix = if immediate.is_some() {
                    vec![0x6b]
                } else {
                    vec![0x0f, 0xaf]
                };
                suffix.extend_from_slice(if memory { &[0x44, 0x88, 0xf8] } else { &[0xc1] });
                if let Some(value) = immediate {
                    suffix.push(value as u8);
                }
                let bytes = [prefix, &suffix].concat();
                assert_eq!(
                    entry(&bytes),
                    Instruction::Multiply {
                        dst: reg(0, width, false),
                        source,
                        immediate,
                    },
                    "{bytes:02x?}"
                );
            }
        }
    }
    for (bytes, width, immediate) in [
        (&[0x66, 0x69, 0xc1, 0, 0x80][..], Width::Word, 0x8000),
        (&[0x69, 0xc1, 0, 0, 0, 0x80][..], Width::Dword, 0x8000_0000),
        (
            &[0x48, 0x69, 0xc1, 0, 0, 0, 0x80][..],
            Width::Qword,
            0xffff_ffff_8000_0000,
        ),
    ] {
        assert_eq!(
            entry(bytes),
            Instruction::Multiply {
                dst: reg(0, width, false),
                source: Operand::Register(reg(1, width, false)),
                immediate: Some(immediate),
            }
        );
    }
    let Instruction::Multiply {
        dst,
        source: Operand::Memory { address, width },
        immediate,
    } = entry(&[0x65, 0x67, 0x4d, 0x6b, 0x44, 0x8c, 0xf8, 0xff])
    else {
        panic!("extended-register memory IMUL")
    };
    assert_eq!(dst, reg(8, Width::Qword, false));
    assert_eq!(width, Width::Qword);
    assert_eq!(immediate, Some(u64::MAX));
    assert_eq!(address.size, AddressSize::Bits32);
    assert_eq!(address.segment, Segment::Gs);
    assert_eq!(address.base, Base::Register(Gpr::new(12).unwrap()));
    assert_eq!(address.index, Gpr::new(1));
    for bytes in [
        &[0xf6, 0xe9][..],
        &[0xf7, 0xe9][..],
        &[0x66, 0xf7, 0x28][..],
        &[0x48, 0xf7, 0x28][..],
        &[0xf3, 0x48, 0x0f, 0xaf, 0xc1][..],
    ] {
        assert_eq!(
            admission(bytes),
            DecodeDecision::Unsupported,
            "{bytes:02x?}"
        );
    }
    assert_eq!(admission(&[0x48, 0x6b, 0xc1]), DecodeDecision::More);
    assert_eq!(
        admission(&[0xf0, 0x48, 0x0f, 0xaf, 0xc1]),
        DecodeDecision::InvalidOpcode
    );
}

#[test]
fn repeat_store_admission_distinguishes_width_address_size_and_prefixes() {
    use x86_system::shared::decode::DecodeDecision;
    use x86_system::shared::entry::Instruction;
    for (bytes, width) in [
        (&[0xf3, 0xaa][..], Width::Byte),
        (&[0xf3, 0x66, 0xab][..], Width::Word),
        (&[0x66, 0xf3, 0xab][..], Width::Word),
        (&[0xf3, 0xab][..], Width::Dword),
        (&[0xf3, 0x48, 0xab][..], Width::Qword),
    ] {
        for length in 1..bytes.len() {
            assert_eq!(admission(&bytes[..length]), DecodeDecision::More);
        }
        assert_eq!(entry(bytes), Instruction::RepeatStore { width });
    }
    for bytes in [
        &[0xaa][..],
        &[0x66, 0xab][..],
        &[0xab][..],
        &[0x48, 0xab][..],
        &[0xf2, 0xaa][..],
        &[0xf2, 0x48, 0xab][..],
        &[0xf2, 0xf3, 0x48, 0xab][..],
        &[0xf3, 0xf2, 0x48, 0xab][..],
        &[0xf3, 0x67, 0xaa][..],
        &[0x67, 0xf3, 0x48, 0xab][..],
        &[0xf3, 0xac][..],
        &[0xf3, 0xae][..],
        &[0xf3, 0xa6][..],
    ] {
        assert_eq!(
            admission(bytes),
            DecodeDecision::Unsupported,
            "{bytes:02x?}"
        );
    }
    for bytes in [
        &[0xf0, 0xf3, 0x48, 0xab][..],
        &[0xf2, 0xf0, 0x48, 0xab][..],
        &[0xf3, 0xf0, 0x48, 0xab][..],
    ] {
        assert_eq!(
            admission(bytes),
            DecodeDecision::InvalidOpcode,
            "{bytes:02x?}"
        );
    }
}

#[test]
fn indirect_calls_preserve_rsp_sources_and_address_aliases_without_far_forms() {
    use x86_system::shared::decode::DecodeDecision;
    use x86_system::shared::entry::Instruction;
    for (bytes, index) in [(&[0xff, 0xd4][..], 4), (&[0x41, 0xff, 0xd4][..], 12)] {
        assert_eq!(
            entry(bytes),
            Instruction::IndirectCall {
                source: Operand::Register(reg(index, Width::Qword, false)),
            }
        );
    }
    for (bytes, base, index, segment, size, scale) in [
        (
            &[0xff, 0x54, 0x24, 0xf8][..],
            Base::Register(Gpr::new(4).unwrap()),
            None,
            Segment::Ss,
            AddressSize::Bits64,
            Scale::One,
        ),
        (
            &[0x41, 0xff, 0x54, 0x24, 0xf8][..],
            Base::Register(Gpr::new(12).unwrap()),
            None,
            Segment::Ds,
            AddressSize::Bits64,
            Scale::One,
        ),
        (
            &[0x65, 0x67, 0xff, 0x54, 0x88, 0xf8][..],
            Base::Register(Gpr::new(0).unwrap()),
            Gpr::new(1),
            Segment::Gs,
            AddressSize::Bits32,
            Scale::Four,
        ),
        (
            &[0xff, 0x15, 0xf8, 0xff, 0xff, 0xff][..],
            Base::NextRip,
            None,
            Segment::Ds,
            AddressSize::Bits64,
            Scale::One,
        ),
    ] {
        assert_eq!(
            entry(bytes),
            Instruction::IndirectCall {
                source: Operand::Memory {
                    address: Address {
                        base,
                        index,
                        segment,
                        size,
                        scale,
                        displacement: if size == AddressSize::Bits32 {
                            0xffff_fff8
                        } else {
                            (-8i64) as u64
                        },
                    },
                    width: Width::Qword,
                },
            },
            "{bytes:02x?}"
        );
    }
    for bytes in [
        &[0xff, 0x18][..],
        &[0x48, 0xff, 0x18][..],
        &[0x66, 0xff, 0xd0][..],
        &[0xf2, 0xff, 0xd4][..],
        &[0xf3, 0xff, 0xd4][..],
    ] {
        assert_eq!(
            admission(bytes),
            DecodeDecision::Unsupported,
            "{bytes:02x?}"
        );
    }
    assert_eq!(admission(&[0xff, 0x54, 0x24]), DecodeDecision::More);
}

#[test]
fn startup_control_msr_and_segment_packets_remain_cpu_independent() {
    use x86_system::shared::decode::DecodeDecision;
    use x86_system::shared::entry::Instruction;
    for number in [0, 3, 4] {
        for (prefix, index) in [(&[][..], 0), (&[0x41][..], 8)] {
            let bytes = [prefix, &[0x0f, 0x22, 0xc0 | (number << 3)]].concat();
            assert_eq!(
                entry(&bytes),
                Instruction::WriteControl {
                    number,
                    source: Operand::Register(reg(index, Width::Qword, false)),
                }
            );
        }
    }
    for (extension, segment) in [
        (0, Segment::Es),
        (2, Segment::Ss),
        (3, Segment::Ds),
        (4, Segment::Fs),
        (5, Segment::Gs),
    ] {
        for (prefix, index) in [(&[][..], 1), (&[0x41][..], 9)] {
            let bytes = [prefix, &[0x8e, 0xc1 | (extension << 3)]].concat();
            assert_eq!(
                entry(&bytes),
                Instruction::Segment {
                    segment,
                    src: reg(index, Width::Word, false),
                }
            );
        }
        assert_eq!(
            admission(&[0x8e, extension << 3]),
            DecodeDecision::Unsupported
        );
    }
    assert_eq!(entry(&[0x0f, 0x32]), Instruction::ReadMsr);
    assert_eq!(admission(&[0x0f, 0x30]), DecodeDecision::Wrmsr);
    for bytes in [
        &[0x48, 0x0f, 0x32][..],
        &[0x66, 0x0f, 0x32][..],
        &[0xf3, 0x0f, 0x32][..],
        &[0x0f, 0x22, 0xd0][..],
        &[0x44, 0x0f, 0x22, 0xc0][..],
    ] {
        assert_eq!(
            admission(bytes),
            DecodeDecision::Unsupported,
            "{bytes:02x?}"
        );
    }
}

#[test]
fn memory_bit_immediates_are_bounded_without_masking_or_register_bit_strings() {
    use x86_system::memory_core::cpu_core::integer::Operation as Integer;
    use x86_system::shared::decode::DecodeDecision;
    for (prefix, width) in [
        (&[0x66][..], Width::Word),
        (&[][..], Width::Dword),
        (&[0x48][..], Width::Qword),
    ] {
        for (extension, opcode, operation) in [
            (4, 0xa3, Integer::BitTest),
            (5, 0xab, Integer::BitSet),
            (6, 0xb3, Integer::BitReset),
            (7, 0xbb, Integer::BitComplement),
        ] {
            for index in [0, width.bits() as u8 - 1] {
                let bytes = [prefix, &[0x0f, 0xba, (extension << 3) | 7, index]].concat();
                assert_eq!(
                    alu(&bytes),
                    (
                        operation,
                        Operand::Memory {
                            address: Address {
                                size: AddressSize::Bits64,
                                segment: Segment::Ds,
                                base: Base::Register(Gpr::new(7).unwrap()),
                                index: None,
                                scale: Scale::One,
                                displacement: 0,
                            },
                            width,
                        },
                        Operand::Immediate(Immediate {
                            value: index as u64,
                            width,
                            encoded_width: Width::Byte,
                        }),
                    )
                );
            }
            for index in [width.bits() as u8, 0xff] {
                let bytes = [prefix, &[0x0f, 0xba, extension << 3, index]].concat();
                assert_eq!(admission(&bytes), DecodeDecision::Unsupported);
            }
            let bytes = [prefix, &[0x0f, opcode, 0x08]].concat();
            assert_eq!(admission(&bytes), DecodeDecision::Unsupported);
        }
    }
    let (operation, destination, source) =
        alu(&[0x64, 0x67, 0x48, 0x0f, 0xba, 0x6c, 0x88, 0xf8, 63]);
    assert_eq!(operation, Integer::BitSet);
    assert_eq!(
        source,
        Operand::Immediate(Immediate {
            value: 63,
            width: Width::Qword,
            encoded_width: Width::Byte,
        })
    );
    let Operand::Memory { address, .. } = destination else {
        panic!("memory BTS")
    };
    assert_eq!(address.size, AddressSize::Bits32);
    assert_eq!(address.segment, Segment::Fs);
    assert_eq!(address.base, Base::Register(Gpr::new(0).unwrap()));
    assert_eq!(address.index, Gpr::new(1));
    assert_eq!(address.scale, Scale::Four);
    assert_eq!(address.displacement, 0xffff_fff8);
    assert_eq!(
        admission(&[0xf0, 0x48, 0x0f, 0xba, 0x28, 63]),
        DecodeDecision::Unsupported
    );
}

#[test]
fn startup_admission_keeps_retained_length_and_token_contracts() {
    use x86_system::shared::decode::{DecodeDecision, DecodeInput};
    for bytes in [
        &[0x0f, 0x32][..],
        &[0x0f, 0x22, 0xe0][..],
        &[0x8e, 0xd0][..],
        &[0xff, 0xd4][..],
        &[0x48, 0x6b, 0xc1, 0xff][..],
        &[0x48, 0x0f, 0xba, 0x28, 63][..],
        &[0xf3, 0x48, 0xab][..],
    ] {
        let expected = admission(bytes);
        let mut input = DecodeInput {
            sequence: u64::MAX,
            rip: 0xffff_ffff_82d8_afa6,
            length: bytes.len() as u8,
            bytes: [0; 15],
        };
        input.bytes[..bytes.len()].copy_from_slice(bytes);
        assert_eq!(admit(input), expected);
        input.bytes[bytes.len()] = 0x90;
        input.length += 1;
        assert_eq!(admit(input), DecodeDecision::Rejected, "{bytes:02x?}");
    }
}

#[test]
fn nop_admission_ignores_operands_but_keeps_pause_and_forbidden_prefixes_distinct() {
    use x86_system::shared::decode::DecodeDecision;
    use x86_system::shared::entry::Instruction;
    for bytes in [
        &[0x90][..],
        &[0x66, 0x90][..],
        &[0x48, 0x90][..],
        &[0x67, 0x90][..],
        &[0x0f, 0x1f, 0xc0][..],
        &[0x0f, 0x1f, 0x00][..],
        &[0x0f, 0x1f, 0x40, 0][..],
        &[0x0f, 0x1f, 0x44, 0, 0][..],
        &[0x66, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0][..],
        &[0x67, 0x0f, 0x1f, 0x44, 0, 0xf8][..],
        &[0x64, 0x67, 0x0f, 0x1f, 0x84, 0, 0xff, 0xff, 0xff, 0xff][..],
    ] {
        for length in 1..bytes.len() {
            assert_eq!(admission(&bytes[..length]), DecodeDecision::More);
        }
        assert_eq!(entry(bytes), Instruction::Nop, "{bytes:02x?}");
        let with_trailing_byte = [bytes, &[0x90]].concat();
        assert_eq!(admission(&with_trailing_byte), DecodeDecision::Rejected);
    }
    let mut maximum = [0x66; 15];
    maximum[14] = 0x90;
    assert_eq!(entry(&maximum), Instruction::Nop);
    for bytes in [
        &[0xf3, 0x90][..],
        &[0xf2, 0x90][..],
        &[0xf3, 0x0f, 0x1f, 0x00][..],
        &[0xf2, 0x0f, 0x1f, 0x00][..],
        &[0x41, 0x90][..],
    ] {
        assert_eq!(
            admission(bytes),
            DecodeDecision::Unsupported,
            "{bytes:02x?}"
        );
    }
    for bytes in [
        &[0xf0, 0x90][..],
        &[0xf0, 0x0f, 0x1f, 0x00][..],
        &[0xf2, 0xf0, 0x0f, 0x1f, 0x00][..],
        &[0xf3, 0xf0, 0x0f, 0x1f, 0x00][..],
    ] {
        assert_eq!(
            admission(bytes),
            DecodeDecision::InvalidOpcode,
            "{bytes:02x?}"
        );
    }
}

#[test]
fn compare_exchange_registers_preserve_widths_extensions_and_byte_aliases() {
    use x86_system::shared::entry::Instruction;
    for width in [Width::Byte, Width::Word, Width::Dword, Width::Qword] {
        for dst in 0..16 {
            for src in 0..16 {
                let mut bytes = Vec::new();
                if width == Width::Word {
                    bytes.push(0x66);
                }
                let rex = 0x40
                    | if width == Width::Qword { 8 } else { 0 }
                    | ((src >> 3) << 2)
                    | (dst >> 3);
                if rex != 0x40 || width == Width::Byte {
                    bytes.push(rex);
                }
                bytes.extend_from_slice(&[
                    0x0f,
                    if width == Width::Byte { 0xb0 } else { 0xb1 },
                    0xc0 | ((src & 7) << 3) | (dst & 7),
                ]);
                assert_eq!(
                    entry(&bytes),
                    Instruction::CompareExchange {
                        destination: Operand::Register(reg(dst, width, false)),
                        source: reg(src, width, false),
                    },
                    "{bytes:02x?}"
                );
            }
        }
    }
    for dst in 0..8 {
        for src in 0..8 {
            assert_eq!(
                entry(&[0x0f, 0xb0, 0xc0 | (src << 3) | dst]),
                Instruction::CompareExchange {
                    destination: Operand::Register(reg(dst & 3, Width::Byte, dst >= 4)),
                    source: reg(src & 3, Width::Byte, src >= 4),
                }
            );
        }
    }
}

#[test]
fn locked_compare_exchange_memory_preserves_kernel_bytes_and_normalized_addresses() {
    use x86_system::shared::decode::{DecodeDecision, DecodeInput};
    use x86_system::shared::entry::Instruction;
    let bytes = [0xf0, 0x48, 0x0f, 0xb1, 0x55, 0x00];
    let mut input = DecodeInput {
        sequence: 967_066,
        rip: 0xffff_ffff_81ed_6583,
        length: bytes.len() as u8,
        bytes: [0; 15],
    };
    input.bytes[..bytes.len()].copy_from_slice(&bytes);
    assert_eq!(
        admit(input),
        DecodeDecision::Entry(Instruction::CompareExchange {
            destination: Operand::Memory {
                address: Address {
                    size: AddressSize::Bits64,
                    segment: Segment::Ss,
                    base: Base::Register(Gpr::new(5).unwrap()),
                    index: None,
                    scale: Scale::One,
                    displacement: 0,
                },
                width: Width::Qword,
            },
            source: reg(2, Width::Qword, false),
        })
    );
    for (prefix, opcode, width, source) in [
        (&[][..], 0xb0, Width::Byte, reg(0, Width::Byte, true)),
        (&[0x40][..], 0xb0, Width::Byte, reg(4, Width::Byte, false)),
        (&[0x44][..], 0xb0, Width::Byte, reg(12, Width::Byte, false)),
        (
            &[0x66, 0x44][..],
            0xb1,
            Width::Word,
            reg(12, Width::Word, false),
        ),
        (
            &[0x44][..],
            0xb1,
            Width::Dword,
            reg(12, Width::Dword, false),
        ),
        (
            &[0x4c][..],
            0xb1,
            Width::Qword,
            reg(12, Width::Qword, false),
        ),
    ] {
        let bytes = [&[0xf0][..], prefix, &[0x0f, opcode, 0x60, 0xf2]].concat();
        assert_eq!(
            entry(&bytes),
            Instruction::CompareExchange {
                destination: Operand::Memory {
                    address: Address {
                        size: AddressSize::Bits64,
                        segment: Segment::Ds,
                        base: Base::Register(Gpr::new(0).unwrap()),
                        index: None,
                        scale: Scale::One,
                        displacement: (-14i64) as u64,
                    },
                    width,
                },
                source,
            },
            "{bytes:02x?}"
        );
    }
    for (prefix, segment) in [(0x64, Segment::Fs), (0x65, Segment::Gs)] {
        let Instruction::CompareExchange {
            destination: Operand::Memory { address, width },
            source,
        } = entry(&[prefix, 0x67, 0xf0, 0x4f, 0x0f, 0xb1, 0x44, 0x8c, 0xf8])
        else {
            panic!("locked address32 memory CMPXCHG")
        };
        assert_eq!(width, Width::Qword);
        assert_eq!(source, reg(8, Width::Qword, false));
        assert_eq!(
            address,
            Address {
                size: AddressSize::Bits32,
                segment,
                base: Base::Register(Gpr::new(12).unwrap()),
                index: Gpr::new(9),
                scale: Scale::Four,
                displacement: 0xffff_fff8,
            }
        );
        let mut registers = [0; 16];
        registers[12] = 0x1234_5678_ffff_fffc;
        registers[9] = 4;
        assert_eq!(
            address.linear(
                &registers,
                0,
                SegmentBases {
                    fs: 0x1_0000_0000,
                    gs: 0x1_0000_0000,
                }
            ),
            0x1_0000_0004
        );
    }
    let Instruction::CompareExchange {
        destination: Operand::Memory { address, .. },
        ..
    } = entry(&[0xf0, 0x48, 0x0f, 0xb1, 0x15, 0xf8, 0xff, 0xff, 0xff])
    else {
        panic!("RIP-relative CMPXCHG")
    };
    assert_eq!(address.base, Base::NextRip);
    assert_eq!(address.displacement, (-8i64) as u64);
}

#[test]
fn compare_exchange_rejects_unlocked_memory_repeat_hle_and_wider_atomic_families() {
    use x86_system::shared::decode::DecodeDecision;
    for bytes in [
        &[0x0f, 0xb0, 0x08][..],
        &[0x66, 0x0f, 0xb1, 0x08][..],
        &[0x0f, 0xb1, 0x08][..],
        &[0x48, 0x0f, 0xb1, 0x08][..],
        &[0x0f, 0xc7, 0x08][..],
        &[0x48, 0x0f, 0xc7, 0x08][..],
        &[0xf0, 0x0f, 0xc7, 0x08][..],
        &[0xf0, 0x48, 0x0f, 0xc7, 0x08][..],
        &[0x67, 0x0f, 0xb1, 0xc1][..],
        &[0x64, 0x0f, 0xb1, 0xc1][..],
    ] {
        assert_eq!(
            admission(bytes),
            DecodeDecision::Unsupported,
            "{bytes:02x?}"
        );
    }
    for prefix in [
        &[0xf2][..],
        &[0xf3][..],
        &[0xf2, 0xf3][..],
        &[0xf3, 0xf2][..],
        &[0xf2, 0xf0][..],
        &[0xf3, 0xf0][..],
        &[0xf0, 0xf2][..],
        &[0xf0, 0xf3][..],
    ] {
        let bytes = [prefix, &[0x48, 0x0f, 0xb1, 0x08]].concat();
        assert_eq!(
            admission(&bytes),
            DecodeDecision::Unsupported,
            "{bytes:02x?}"
        );
    }
    for prefix in [0xf2, 0xf3] {
        let bytes = [prefix, 0x48, 0x0f, 0xb1, 0xc1];
        assert_eq!(admission(&bytes), DecodeDecision::Unsupported);
    }
    for bytes in [
        &[0xf0, 0x0f, 0xb0, 0xc1][..],
        &[0xf0, 0x66, 0x0f, 0xb1, 0xc1][..],
        &[0xf0, 0x0f, 0xb1, 0xc1][..],
        &[0xf0, 0x48, 0x0f, 0xb1, 0xc1][..],
        &[0xf2, 0xf0, 0x48, 0x0f, 0xb1, 0xc1][..],
        &[0xf3, 0xf0, 0x48, 0x0f, 0xb1, 0xc1][..],
    ] {
        assert!(matches!(outcome(bytes, 0), Outcome::InvalidOpcode(_)));
        assert_eq!(admission(bytes), DecodeDecision::InvalidOpcode);
    }
}

#[test]
fn compare_exchange_retained_packets_are_incremental_exact_and_bounded() {
    use x86_system::shared::decode::{DecodeDecision, DecodeInput};
    for bytes in [
        &[0x0f, 0xb0, 0xe0][..],
        &[0x66, 0x45, 0x0f, 0xb1, 0xc1][..],
        &[0xf0, 0x48, 0x0f, 0xb1, 0x55, 0][..],
        &[
            0x64, 0x67, 0xf0, 0x4f, 0x0f, 0xb1, 0x84, 0x8c, 0xf8, 0xff, 0xff, 0xff,
        ][..],
    ] {
        let expected = admission(bytes);
        assert!(matches!(expected, DecodeDecision::Entry(_)));
        let mut decoder = FetchDecoder::new(u64::MAX - 2);
        for (index, &byte) in bytes.iter().enumerate() {
            if index != 0 {
                assert_eq!(admission(&bytes[..index]), DecodeDecision::More);
                assert!(decoder.outcome().is_none());
            }
            let request = decoder.request().unwrap();
            assert_eq!(request.address, (u64::MAX - 2).wrapping_add(index as u64));
            decoder.complete(request, byte).unwrap();
        }
        assert!(decoder.request().is_none());
        assert_eq!(decoder.fetched(), bytes);
        let mut input = DecodeInput {
            sequence: u64::MAX,
            rip: u64::MAX - 2,
            length: bytes.len() as u8,
            bytes: [0; 15],
        };
        input.bytes[..bytes.len()].copy_from_slice(bytes);
        assert_eq!(admit(input), expected);
        input.bytes[bytes.len()] = 0x90;
        input.length += 1;
        assert_eq!(admit(input), DecodeDecision::Rejected);
    }
    let mut maximum = [0x66; 15];
    maximum[9..].copy_from_slice(&[0xf0, 0x48, 0x0f, 0xb1, 0x55, 0]);
    for length in 1..maximum.len() {
        assert_eq!(admission(&maximum[..length]), DecodeDecision::More);
    }
    assert!(matches!(admission(&maximum), DecodeDecision::Entry(_)));
    let mut exhausted = [0x66; 15];
    exhausted[11..].copy_from_slice(&[0xf0, 0x48, 0x0f, 0xb1]);
    assert_eq!(admission(&exhausted), DecodeDecision::Rejected);
    assert!(matches!(outcome(&exhausted, 0), Outcome::Rejected(_)));
}

#[test]
fn locked_binary_alu_families_reuse_scalar_register_and_immediate_operands() {
    use x86_system::memory_core::cpu_core::integer::Operation as Integer;
    use x86_system::shared::entry::Instruction;
    for (opcode, extension, operation) in [
        (0x00, 0, Integer::Add),
        (0x10, 2, Integer::Adc),
        (0x28, 5, Integer::Sub),
        (0x18, 3, Integer::Sbb),
        (0x20, 4, Integer::And),
        (0x08, 1, Integer::Or),
        (0x30, 6, Integer::Xor),
    ] {
        for width in [Width::Byte, Width::Word, Width::Dword, Width::Qword] {
            let mut prefix = vec![0xf0];
            if width == Width::Word {
                prefix.push(0x66);
            }
            prefix.push(if width == Width::Qword { 0x4c } else { 0x44 });
            let bytes = [
                &prefix[..],
                &[opcode | u8::from(width != Width::Byte), 0x60, 0x58],
            ]
            .concat();
            let destination = Operand::Memory {
                address: Address {
                    size: AddressSize::Bits64,
                    segment: Segment::Ds,
                    base: Base::Register(Gpr::new(0).unwrap()),
                    index: None,
                    scale: Scale::One,
                    displacement: 0x58,
                },
                width,
            };
            assert_eq!(
                entry(&bytes),
                Instruction::LockedAlu {
                    operation,
                    destination,
                    source: Operand::Register(reg(12, width, false)),
                },
                "{bytes:02x?}"
            );
            let bytes = [
                &prefix[..],
                &[
                    if width == Width::Byte { 0x80 } else { 0x83 },
                    0x40 | (extension << 3),
                    0x58,
                    0x80,
                ],
            ]
            .concat();
            assert_eq!(
                entry(&bytes),
                Instruction::LockedAlu {
                    operation,
                    destination,
                    source: Operand::Immediate(Immediate {
                        encoded_width: Width::Byte,
                        width,
                        value: (-128i64) as u64 & width.mask(),
                    }),
                },
                "{bytes:02x?}"
            );
        }
    }
    for (prefix, source) in [
        (&[][..], reg(0, Width::Byte, true)),
        (&[0x40][..], reg(4, Width::Byte, false)),
    ] {
        let bytes = [&[0xf0][..], prefix, &[0x00, 0x20]].concat();
        let Instruction::LockedAlu {
            operation,
            source: Operand::Register(actual),
            ..
        } = entry(&bytes)
        else {
            panic!("locked byte ADD")
        };
        assert_eq!(operation, Integer::Add);
        assert_eq!(actual, source);
    }
}

#[test]
fn locked_unary_alu_families_cover_measured_inc_and_normalized_memory() {
    use x86_system::memory_core::cpu_core::integer::Operation as Integer;
    use x86_system::shared::entry::Instruction;
    for (opcode, extension, operation) in [
        (0xfe, 0, Integer::Inc),
        (0xfe, 1, Integer::Dec),
        (0xf6, 3, Integer::Neg),
        (0xf6, 2, Integer::Not),
    ] {
        for (prefix, width) in [
            (&[][..], Width::Byte),
            (&[0x66][..], Width::Word),
            (&[][..], Width::Dword),
            (&[0x48][..], Width::Qword),
        ] {
            let bytes = [
                &[0xf0][..],
                prefix,
                &[
                    opcode | u8::from(width != Width::Byte),
                    0x43 | (extension << 3),
                    0x58,
                ],
            ]
            .concat();
            assert_eq!(
                entry(&bytes),
                Instruction::LockedAlu {
                    operation,
                    destination: Operand::Memory {
                        address: Address {
                            size: AddressSize::Bits64,
                            segment: Segment::Ds,
                            base: Base::Register(Gpr::new(3).unwrap()),
                            index: None,
                            scale: Scale::One,
                            displacement: 0x58,
                        },
                        width,
                    },
                    source: Operand::Immediate(Immediate {
                        encoded_width: width,
                        width,
                        value: 0,
                    }),
                },
                "{bytes:02x?}"
            );
        }
    }
    for (prefix, segment) in [(0x64, Segment::Fs), (0x65, Segment::Gs)] {
        let Instruction::LockedAlu {
            operation,
            destination: Operand::Memory { address, width },
            ..
        } = entry(&[prefix, 0x67, 0xf0, 0x4b, 0xff, 0x44, 0x8c, 0xf8])
        else {
            panic!("locked address32 INC")
        };
        assert_eq!(operation, Integer::Inc);
        assert_eq!(width, Width::Qword);
        assert_eq!(
            address,
            Address {
                size: AddressSize::Bits32,
                segment,
                base: Base::Register(Gpr::new(12).unwrap()),
                index: Gpr::new(9),
                scale: Scale::Four,
                displacement: 0xffff_fff8,
            }
        );
    }
}

#[test]
fn locked_alu_packets_reject_other_families_prefixes_and_inexact_lengths() {
    use x86_system::shared::decode::DecodeDecision;
    for bytes in [
        &[0xf0, 0xff, 0x43, 0x58][..],
        &[0xf0, 0x48, 0x01, 0x08][..],
        &[0xf0, 0x48, 0x83, 0x28, 1][..],
        &[0xf0, 0x83, 0x00, 0xf2][..],
        &[0x64, 0x67, 0xf0, 0x4b, 0xf7, 0x5c, 0x8c, 0xf8][..],
    ] {
        assert!(
            matches!(admission(bytes), DecodeDecision::Entry(_)),
            "{bytes:02x?}"
        );
        for length in 1..bytes.len() {
            assert_eq!(admission(&bytes[..length]), DecodeDecision::More);
        }
        assert_eq!(
            admission(&[bytes, &[0x90]].concat()),
            DecodeDecision::Rejected
        );
        for prefix in [
            &[0xf2][..],
            &[0xf3][..],
            &[0xf2, 0xf3][..],
            &[0xf3, 0xf2][..],
        ] {
            assert_eq!(
                admission(&[prefix, bytes].concat()),
                DecodeDecision::Unsupported,
                "{prefix:02x?} {bytes:02x?}"
            );
        }
    }
    for bytes in [
        &[0xf0, 0x0f, 0xc1, 0x08][..],
        &[0xf0, 0x0f, 0xab, 0x08][..],
        &[0xf0, 0x0f, 0xb3, 0x08][..],
        &[0xf0, 0x0f, 0xbb, 0x08][..],
        &[0xf0, 0x0f, 0xba, 0x28, 1][..],
        &[0xf0, 0xf2, 0xff, 0x43, 0x58][..],
        &[0xf0, 0xf3, 0xff, 0x43, 0x58][..],
    ] {
        assert_eq!(
            admission(bytes),
            DecodeDecision::Unsupported,
            "{bytes:02x?}"
        );
    }
    for bytes in [
        &[0xf0, 0x01, 0xc8][..],
        &[0xf0, 0xff, 0xc0][..],
        &[0xf0, 0xf7, 0xd8][..],
        &[0xf0, 0xd1, 0x20][..],
        &[0xf0, 0xd1, 0x28][..],
        &[0xf0, 0xd1, 0x38][..],
        &[0xf0, 0x39, 0x08][..],
        &[0xf0, 0x85, 0x08][..],
    ] {
        assert_eq!(
            admission(bytes),
            DecodeDecision::InvalidOpcode,
            "{bytes:02x?}"
        );
    }
    let mut maximum = [0x66; 15];
    maximum[11..].copy_from_slice(&[0xf0, 0xff, 0x43, 0x58]);
    assert!(matches!(admission(&maximum), DecodeDecision::Entry(_)));
}

fn conditions() -> [x86_system::memory_core::cpu_core::control::Condition; 16] {
    use x86_system::memory_core::cpu_core::control::Condition::*;
    [
        Overflow,
        NotOverflow,
        Below,
        AboveEqual,
        Equal,
        NotEqual,
        BelowEqual,
        Above,
        Sign,
        NotSign,
        Parity,
        NotParity,
        Less,
        GreaterEqual,
        LessEqual,
        Greater,
    ]
}

#[test]
fn conditional_moves_cover_all_conditions_widths_and_register_extensions() {
    use x86_system::shared::entry::Instruction;
    for (cc, condition) in conditions().into_iter().enumerate() {
        for width in [Width::Word, Width::Dword, Width::Qword] {
            for dst in 0..16 {
                let src = 15 - dst;
                let rex = 0x40
                    | if width == Width::Qword { 8 } else { 0 }
                    | ((dst >> 3) << 2)
                    | (src >> 3);
                let mut bytes = Vec::new();
                if width == Width::Word {
                    bytes.push(0x66);
                }
                if rex != 0x40 {
                    bytes.push(rex);
                }
                bytes.extend_from_slice(&[
                    0x0f,
                    0x40 | cc as u8,
                    0xc0 | ((dst & 7) << 3) | (src & 7),
                ]);
                assert_eq!(
                    entry(&bytes),
                    Instruction::ConditionalMove {
                        condition,
                        dst: reg(dst, width, false),
                        source: Operand::Register(reg(src, width, false)),
                    },
                    "{bytes:02x?}"
                );
            }
        }
    }
}

#[test]
fn conditional_moves_preserve_memory_reads_for_every_condition_and_width() {
    use x86_system::shared::entry::Instruction;
    for (cc, condition) in conditions().into_iter().enumerate() {
        for (prefix, width) in [
            (&[0x66][..], Width::Word),
            (&[][..], Width::Dword),
            (&[0x48][..], Width::Qword),
        ] {
            let bytes = [
                prefix,
                &[0x0f, 0x40 | cc as u8, 0x0d, 0xf8, 0xff, 0xff, 0xff],
            ]
            .concat();
            assert_eq!(
                entry(&bytes),
                Instruction::ConditionalMove {
                    condition,
                    dst: reg(1, width, false),
                    source: Operand::Memory {
                        address: Address {
                            size: AddressSize::Bits64,
                            segment: Segment::Ds,
                            base: Base::NextRip,
                            index: None,
                            scale: Scale::One,
                            displacement: (-8i64) as u64,
                        },
                        width,
                    },
                },
                "{bytes:02x?}"
            );
        }
    }
    for (prefix, segment) in [(0x64, Segment::Fs), (0x65, Segment::Gs)] {
        let Instruction::ConditionalMove {
            condition,
            dst,
            source: Operand::Memory { address, width },
        } = entry(&[prefix, 0x67, 0x4f, 0x0f, 0x45, 0x44, 0x8c, 0xf8])
        else {
            panic!("CMOVNE must retain its memory read even when ZF might be set")
        };
        assert_eq!(condition, conditions()[5]);
        assert_eq!(dst, reg(8, Width::Qword, false));
        assert_eq!(width, Width::Qword);
        assert_eq!(
            address,
            Address {
                size: AddressSize::Bits32,
                segment,
                base: Base::Register(Gpr::new(12).unwrap()),
                index: Gpr::new(9),
                scale: Scale::Four,
                displacement: 0xffff_fff8,
            }
        );
        let mut registers = [0; 16];
        registers[12] = 0x1234_5678_ffff_fffc;
        registers[9] = 4;
        assert_eq!(
            address.linear(
                &registers,
                0,
                SegmentBases {
                    fs: 0x1_0000_0000,
                    gs: 0x1_0000_0000,
                }
            ),
            0x1_0000_0004
        );
    }
}

#[test]
fn set_conditions_cover_all_conditions_rex_low_bytes_and_legacy_high_bytes() {
    use x86_system::shared::entry::Instruction;
    for (cc, condition) in conditions().into_iter().enumerate() {
        for index in 0..16 {
            assert_eq!(
                entry(&[
                    0x40 | (index >> 3),
                    0x0f,
                    0x90 | cc as u8,
                    0xc0 | (index & 7)
                ]),
                Instruction::SetCondition {
                    condition,
                    destination: Operand::Register(reg(index, Width::Byte, false)),
                }
            );
        }
        for index in 0..8 {
            assert_eq!(
                entry(&[0x0f, 0x90 | cc as u8, 0xc0 | index]),
                Instruction::SetCondition {
                    condition,
                    destination: Operand::Register(reg(index & 3, Width::Byte, index >= 4)),
                }
            );
        }
    }
    assert_eq!(
        entry(&[0x40, 0x0f, 0x92, 0xc5]),
        Instruction::SetCondition {
            condition: conditions()[2],
            destination: Operand::Register(reg(5, Width::Byte, false)),
        }
    );
}

#[test]
fn set_conditions_keep_byte_memory_addresses_and_ignore_operand_size_prefixes() {
    use x86_system::shared::entry::Instruction;
    for (cc, condition) in conditions().into_iter().enumerate() {
        for (prefix, segment) in [(0x64, Segment::Fs), (0x65, Segment::Gs)] {
            assert_eq!(
                entry(&[prefix, 0x67, 0x43, 0x0f, 0x90 | cc as u8, 0x44, 0x8c, 0xf8]),
                Instruction::SetCondition {
                    condition,
                    destination: Operand::Memory {
                        address: Address {
                            size: AddressSize::Bits32,
                            segment,
                            base: Base::Register(Gpr::new(12).unwrap()),
                            index: Gpr::new(9),
                            scale: Scale::Four,
                            displacement: 0xffff_fff8,
                        },
                        width: Width::Byte,
                    },
                }
            );
        }
    }
    for bytes in [
        &[0x0f, 0x92, 0x05, 0xf9, 0xff, 0xff, 0xff][..],
        &[0x66, 0x0f, 0x92, 0x05, 0xf9, 0xff, 0xff, 0xff][..],
        &[0x48, 0x0f, 0x92, 0x05, 0xf9, 0xff, 0xff, 0xff][..],
    ] {
        let Instruction::SetCondition {
            destination: Operand::Memory { address, width },
            ..
        } = entry(bytes)
        else {
            panic!("SETB memory destination")
        };
        assert_eq!(width, Width::Byte);
        assert_eq!(address.base, Base::NextRip);
        assert_eq!(address.displacement, (-7i64) as u64);
        assert_eq!(address.size, AddressSize::Bits64);
    }
}

#[test]
fn conditional_forms_reject_repeat_lock_and_unrelated_operand_families() {
    use x86_system::shared::decode::DecodeDecision;
    for bytes in [
        &[0x48, 0x0f, 0x45, 0xc1][..],
        &[0x48, 0x0f, 0x45, 0x08][..],
        &[0x40, 0x0f, 0x92, 0xc5][..],
        &[0x0f, 0x92, 0x00][..],
    ] {
        for prefix in [0xf2, 0xf3] {
            assert_eq!(
                admission(&[&[prefix], bytes].concat()),
                DecodeDecision::Unsupported,
                "{prefix:02x} {bytes:02x?}"
            );
        }
        assert_eq!(
            admission(&[&[0xf0], bytes].concat()),
            DecodeDecision::InvalidOpcode
        );
    }
    for bytes in [
        &[0x0f, 0x10, 0xc1][..],
        &[0x0f, 0x50, 0xc1][..],
        &[0xf3, 0x0f, 0x10, 0xc1][..],
    ] {
        assert_eq!(admission(bytes), DecodeDecision::Unsupported);
    }
}

#[test]
fn direction_flags_admit_only_unprefixed_cld_and_std() {
    use x86_system::shared::decode::DecodeDecision;
    use x86_system::shared::entry::Instruction;
    for (byte, set) in [(0xfc, false), (0xfd, true)] {
        assert_eq!(entry(&[byte]), Instruction::Direction { set });
        for prefix in [
            0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0x40, 0x48, 0xf2, 0xf3,
        ] {
            assert_eq!(
                admission(&[prefix, byte]),
                DecodeDecision::Unsupported,
                "{prefix:02x} {byte:02x}"
            );
        }
        assert_eq!(admission(&[0xf0, byte]), DecodeDecision::InvalidOpcode);
    }
}

#[test]
fn repeat_moves_admit_only_the_bounded_string_widths_and_default_segments() {
    use x86_system::shared::decode::DecodeDecision;
    use x86_system::shared::entry::Instruction;
    for (bytes, width) in [
        (&[0xf3, 0xa4][..], Width::Byte),
        (&[0xf3, 0x66, 0xa5][..], Width::Word),
        (&[0x66, 0xf3, 0xa5][..], Width::Word),
        (&[0xf3, 0xa5][..], Width::Dword),
        (&[0xf3, 0x48, 0xa5][..], Width::Qword),
    ] {
        assert_eq!(entry(bytes), Instruction::RepeatMove { width });
        for prefix in [0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x67, 0xf2] {
            assert_eq!(
                admission(&[&[prefix], bytes].concat()),
                DecodeDecision::Unsupported,
                "{prefix:02x} {bytes:02x?}"
            );
        }
        assert_eq!(
            admission(&[&[0xf0], bytes].concat()),
            DecodeDecision::InvalidOpcode
        );
    }
    for bytes in [
        &[0xa4][..],
        &[0xa5][..],
        &[0x66, 0xa5][..],
        &[0x48, 0xa5][..],
        &[0xf2, 0xa4][..],
        &[0xf2, 0x48, 0xa5][..],
        &[0xf3, 0xf2, 0x48, 0xa5][..],
        &[0xf3, 0x67, 0x48, 0xa5][..],
        &[0xf3, 0x64, 0x48, 0xa5][..],
        &[0xf3, 0x65, 0x3e, 0x48, 0xa5][..],
        &[0xf3, 0x0f, 0x10, 0xc1][..],
        &[0xf2, 0x0f, 0x10, 0xc1][..],
        &[0xf3, 0xac][..],
        &[0xf3, 0xa6][..],
        &[0xf3, 0xae][..],
    ] {
        assert_eq!(
            admission(bytes),
            DecodeDecision::Unsupported,
            "{bytes:02x?}"
        );
    }
}

#[test]
fn cr2_reads_use_qword_gprs_without_admitting_cr2_writes_or_other_controls() {
    use x86_system::shared::decode::DecodeDecision;
    use x86_system::shared::entry::Instruction;
    for index in 0..16 {
        let prefix: &[u8] = if index < 8 { &[] } else { &[0x41] };
        assert_eq!(
            entry(&[prefix, &[0x0f, 0x20, 0xd0 | (index & 7)]].concat()),
            Instruction::ReadControl {
                number: 2,
                dst: reg(index, Width::Qword, false),
            }
        );
        assert_eq!(
            admission(&[prefix, &[0x0f, 0x22, 0xd0 | (index & 7)]].concat()),
            DecodeDecision::Unsupported
        );
    }
    for bytes in [&[0x0f, 0x20, 0xd8][..], &[0x0f, 0x20, 0xe0][..]] {
        assert!(matches!(entry(bytes), Instruction::ReadControl { .. }));
    }
    for bytes in [
        &[0x44, 0x0f, 0x20, 0xc0][..],
        &[0xf3, 0x0f, 0x20, 0xd0][..],
        &[0xf2, 0x0f, 0x20, 0xd0][..],
    ] {
        assert_eq!(admission(bytes), DecodeDecision::Unsupported);
    }
    assert_eq!(
        admission(&[0xf0, 0x0f, 0x20, 0xd0]),
        DecodeDecision::InvalidOpcode
    );
}

#[test]
fn fault_handler_and_boot_copy_forms_keep_incremental_and_exact_packet_bounds() {
    use x86_system::shared::decode::DecodeDecision;
    for bytes in [
        &[0xfc][..],
        &[0xfd][..],
        &[0x48, 0x0f, 0x45, 0xc1][..],
        &[0x48, 0x0f, 0x45, 0x0d, 0xf8, 0xff, 0xff, 0xff][..],
        &[0x40, 0x0f, 0x92, 0xc5][..],
        &[0x0f, 0x20, 0xd0][..],
        &[0xf3, 0x48, 0xa5][..],
    ] {
        assert!(matches!(admission(bytes), DecodeDecision::Entry(_)));
        for length in 1..bytes.len() {
            assert_eq!(admission(&bytes[..length]), DecodeDecision::More);
        }
        assert_eq!(
            admission(&[bytes, &[0x90]].concat()),
            DecodeDecision::Rejected
        );
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
