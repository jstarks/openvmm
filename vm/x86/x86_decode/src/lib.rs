// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Trusted iced-x86 adapter to core-owned operands; no memory provider.
#![forbid(unsafe_code)]
#![expect(missing_docs)]

pub use x86_system::memory_core::cpu_core::operand::*;

use iced_x86::Register as IcedRegister;
use iced_x86::{Decoder, DecoderError, DecoderOptions, Instruction, Mnemonic, OpKind};
use x86_system::memory_core::cpu_core::integer;
use x86_system::shared::decode::{DecodeDecision, DecodeInput};
use x86_system::shared::entry::Instruction as EntryInstruction;

pub const MAX_INSTRUCTION_BYTES: usize = 15;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Mov,
    Lea,
    Add,
    Adc,
    Xor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlagEffects {
    pub read: u64,
    pub written: u64,
    pub undefined: u64,
}

impl Operation {
    pub const fn flags(self) -> FlagEffects {
        FlagEffects {
            read: if matches!(self, Self::Adc) { 1 } else { 0 },
            written: if matches!(self, Self::Add | Self::Adc) {
                0x8d5
            } else if matches!(self, Self::Xor) {
                0x8c5
            } else {
                0
            },
            undefined: if matches!(self, Self::Xor) { 0x10 } else { 0 },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Repeat {
    None,
    Rep,
    Repne,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionHint {
    None,
    Acquire,
    Release,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefixes {
    pub lock: bool,
    pub repeat: Repeat,
    pub transaction: TransactionHint,
    pub segment_override: Option<Segment>,
    pub address_size: AddressSize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Encoding {
    rip: u64,
    bytes: [u8; MAX_INSTRUCTION_BYTES],
    length: u8,
}

impl Encoding {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length as usize]
    }

    pub const fn rip(self) -> u64 {
        self.rip
    }

    pub const fn next_rip(self) -> u64 {
        self.rip.wrapping_add(self.length as u64)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decoded {
    pub encoding: Encoding,
    pub operation: Operation,
    pub prefixes: Prefixes,
    pub operands: [Operand; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalarError {
    WrongRip { expected: u64, received: u64 },
    UnsupportedPrefix,
    UnsupportedForm,
    Core(ScalarStatus),
}

/// Bounded scalar admission, not a CPU event loop or a memory-instruction path.
pub fn commit_decoded(
    decoded: Decoded,
    registers: &mut [u64; 16],
    rip: &mut u64,
    flags: u64,
) -> Result<(), ScalarError> {
    if *rip != decoded.encoding.rip() {
        return Err(ScalarError::WrongRip {
            expected: decoded.encoding.rip(),
            received: *rip,
        });
    }
    if decoded.prefixes.lock
        || decoded.prefixes.repeat != Repeat::None
        || decoded.prefixes.transaction != TransactionHint::None
    {
        return Err(ScalarError::UnsupportedPrefix);
    }
    let Operand::Register(dst) = decoded.operands[0] else {
        return Err(ScalarError::UnsupportedForm);
    };
    match (decoded.operation, decoded.operands[1]) {
        (Operation::Mov, Operand::Register(_) | Operand::Immediate(_))
        | (Operation::Lea, Operand::Address(_)) => {}
        _ => return Err(ScalarError::UnsupportedForm),
    }
    match commit_scalar(
        registers,
        rip,
        flags,
        dst,
        decoded.operands[1],
        decoded.encoding.length,
    ) {
        ScalarStatus::Advanced => Ok(()),
        status => Err(ScalarError::Core(status)),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Normalized(Decoded),
    Unsupported {
        encoding: Encoding,
        code: u32,
    },
    InvalidOpcode(Encoding),
    Overlong(Encoding),
    /// Malformed packets or ambiguous full-length failures, not a guest fault.
    Rejected(Encoding),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FetchRequest {
    pub address: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionError {
    WrongAddress { expected: u64, received: u64 },
    AlreadyComplete,
}

/// Retained byte-fetch progress, suitable for an asynchronous MMU owner.
#[derive(Clone, Debug)]
pub struct FetchDecoder {
    encoding: Encoding,
    outcome: Option<Outcome>,
}

impl FetchDecoder {
    pub const fn new(rip: u64) -> Self {
        Self {
            encoding: Encoding {
                rip,
                bytes: [0; MAX_INSTRUCTION_BYTES],
                length: 0,
            },
            outcome: None,
        }
    }

    pub fn request(&self) -> Option<FetchRequest> {
        self.outcome.is_none().then_some(FetchRequest {
            address: self.encoding.next_rip(),
        })
    }

    pub fn outcome(&self) -> Option<&Outcome> {
        self.outcome.as_ref()
    }

    pub fn fetched(&self) -> &[u8] {
        self.encoding.bytes()
    }

    pub fn complete(&mut self, request: FetchRequest, byte: u8) -> Result<(), CompletionError> {
        let expected = self.request().ok_or(CompletionError::AlreadyComplete)?;
        if request != expected {
            return Err(CompletionError::WrongAddress {
                expected: expected.address,
                received: request.address,
            });
        }
        self.encoding.bytes[self.encoding.length as usize] = byte;
        self.encoding.length += 1;
        self.outcome = inspect(self.encoding);
        Ok(())
    }
}

fn inspect(encoding: Encoding) -> Option<Outcome> {
    if encoding.length == MAX_INSTRUCTION_BYTES as u8
        && encoding.bytes().iter().all(|byte| {
            matches!(byte, 0x26 | 0x2e | 0x36 | 0x3e | 0x64..=0x67 | 0xf0 | 0xf2 | 0xf3 | 0x40..=0x4f)
        })
    {
        return Some(Outcome::Overlong(encoding));
    }
    let mut decoder = Decoder::with_ip(64, encoding.bytes(), encoding.rip, DecoderOptions::AMD);
    let instruction = decoder.decode();
    if decoder.last_error() == DecoderError::NoMoreBytes
        && encoding.length < MAX_INSTRUCTION_BYTES as u8
    {
        return None;
    }
    Some(if instruction.len() != encoding.length as usize {
        Outcome::Rejected(encoding)
    } else if decoder.last_error() != DecoderError::None {
        // Iced merges length exhaustion with invalid opcodes at byte 15.
        if encoding.length == MAX_INSTRUCTION_BYTES as u8 {
            Outcome::Rejected(encoding)
        } else {
            Outcome::InvalidOpcode(encoding)
        }
    } else if matches!(
        instruction.mnemonic(),
        Mnemonic::Ud0 | Mnemonic::Ud1 | Mnemonic::Ud2
    ) {
        Outcome::InvalidOpcode(encoding)
    } else {
        match normalize(&instruction, encoding) {
            Some(decoded) => Outcome::Normalized(decoded),
            None => Outcome::Unsupported {
                encoding,
                code: instruction.code() as u32,
            },
        }
    })
}

/// Pure admission for one token-bound prefix already fetched by the core.
pub fn admit(input: DecodeInput) -> DecodeDecision {
    if input.length == 0 || input.length as usize > MAX_INSTRUCTION_BYTES {
        return DecodeDecision::Rejected;
    }
    let encoding = Encoding {
        rip: input.rip,
        bytes: input.bytes,
        length: input.length,
    };
    match inspect(encoding) {
        None => DecodeDecision::More,
        Some(Outcome::Rejected(_)) => DecodeDecision::Rejected,
        Some(Outcome::InvalidOpcode(_)) => DecodeDecision::InvalidOpcode,
        Some(Outcome::Overlong(_)) => DecodeDecision::Overlong,
        Some(Outcome::Unsupported { encoding, .. }) => {
            // Iced validated the full packet; these exact forms have no scalar operand packet.
            match encoding.bytes() {
                [0x0f, 0x30] => DecodeDecision::Wrmsr,
                [0xe8, a, b, c, d] => DecodeDecision::NearCall {
                    displacement: i32::from_le_bytes([*a, *b, *c, *d]),
                },
                _ => {
                    admit_entry(encoding).map_or(DecodeDecision::Unsupported, DecodeDecision::Entry)
                }
            }
        }
        Some(Outcome::Normalized(decoded)) => {
            if decoded.prefixes.lock
                || decoded.prefixes.repeat != Repeat::None
                || decoded.prefixes.transaction != TransactionHint::None
            {
                return DecodeDecision::Unsupported;
            }
            if input.length == 3
                && !matches!(
                    x86_system::memory_core::decode(input.bytes[0], input.bytes[1], input.bytes[2]),
                    x86_system::memory_core::Op::Unsupported
                )
            {
                return DecodeDecision::Legacy;
            }
            match (decoded.operation, decoded.operands) {
                (Operation::Xor, [Operand::Register(dst), Operand::Register(src)])
                    if dst.width() == Width::Dword && src.width() == Width::Dword =>
                {
                    DecodeDecision::Xor32 { dst, src }
                }
                (
                    Operation::Mov,
                    [
                        Operand::Register(dst),
                        source @ (Operand::Register(_) | Operand::Immediate(_)),
                    ],
                )
                | (Operation::Lea, [Operand::Register(dst), source @ Operand::Address(_)]) => {
                    DecodeDecision::Scalar { dst, source }
                }
                _ => admit_entry(decoded.encoding)
                    .map_or(DecodeDecision::Unsupported, DecodeDecision::Entry),
            }
        }
    }
}

fn admit_entry(encoding: Encoding) -> Option<EntryInstruction> {
    let mut decoder = Decoder::with_ip(64, encoding.bytes(), encoding.rip, DecoderOptions::AMD);
    let instruction = decoder.decode();
    if decoder.last_error() != DecoderError::None
        || instruction.len() != encoding.length as usize
        || instruction.has_lock_prefix()
        || instruction.has_rep_prefix()
        || instruction.has_repne_prefix()
        || instruction.has_xacquire_prefix()
        || instruction.has_xrelease_prefix()
    {
        return None;
    }
    let size = address_size(encoding.bytes());
    let get = |index| operand(&instruction, index, Operation::Mov, size);
    match instruction.mnemonic() {
        Mnemonic::Add
        | Mnemonic::Sub
        | Mnemonic::And
        | Mnemonic::Or
        | Mnemonic::Test
        | Mnemonic::Shl
        | Mnemonic::Shr => {
            let Operand::Register(dst) = get(0)? else {
                return None;
            };
            let source = get(1)?;
            let shift = matches!(instruction.mnemonic(), Mnemonic::Shl | Mnemonic::Shr);
            match source {
                Operand::Register(src) if src.width() == dst.width() && !shift => {}
                Operand::Immediate(imm)
                    if imm.width == dst.width() || (shift && imm.width == Width::Byte) => {}
                _ => return None,
            }
            let operation = match instruction.mnemonic() {
                Mnemonic::Add => integer::Operation::Add,
                Mnemonic::Sub => integer::Operation::Sub,
                Mnemonic::And => integer::Operation::And,
                Mnemonic::Or => integer::Operation::Or,
                Mnemonic::Test => integer::Operation::Test,
                Mnemonic::Shl => integer::Operation::Shl,
                _ => integer::Operation::Shr,
            };
            Some(EntryInstruction::Integer {
                operation,
                dst,
                source,
            })
        }
        Mnemonic::Mov | Mnemonic::Movzx => {
            if instruction.mnemonic() == Mnemonic::Mov {
                if let Some(dst @ (Segment::Ds | Segment::Ss | Segment::Es)) =
                    segment(instruction.op0_register())
                {
                    let source = register(instruction.op1_register())?;
                    return Some(EntryInstruction::Segment {
                        segment: dst,
                        src: Register::new(source.gpr(), Width::Word, false)?,
                    });
                }
            }
            match (get(0)?, get(1)?) {
                (Operand::Register(dst), Operand::Memory { address, width })
                    if dst.width() == width || instruction.mnemonic() == Mnemonic::Movzx =>
                {
                    Some(EntryInstruction::Load {
                        dst,
                        address,
                        width,
                    })
                }
                (Operand::Register(dst), Operand::Register(src))
                    if instruction.mnemonic() == Mnemonic::Movzx =>
                {
                    Some(EntryInstruction::ZeroExtend { dst, src })
                }
                (
                    Operand::Memory { address, width },
                    source @ (Operand::Register(_) | Operand::Immediate(_)),
                ) if instruction.mnemonic() == Mnemonic::Mov => {
                    match source {
                        Operand::Register(src) if src.width() == width => {}
                        Operand::Immediate(imm) if imm.width == width => {}
                        _ => return None,
                    }
                    Some(EntryInstruction::Store {
                        address,
                        width,
                        source,
                    })
                }
                _ => None,
            }
        }
        Mnemonic::Lgdt | Mnemonic::Lidt if instruction.op0_kind() == OpKind::Memory => {
            Some(EntryInstruction::Table {
                address: address(&instruction, size)?,
                idt: instruction.mnemonic() == Mnemonic::Lidt,
            })
        }
        Mnemonic::Push => {
            let source = get(0)?;
            match source {
                Operand::Register(reg) if reg.width() == Width::Qword => {}
                Operand::Immediate(imm) if imm.width == Width::Qword => {}
                _ => return None,
            }
            Some(EntryInstruction::Push { source })
        }
        Mnemonic::Ret if encoding.bytes() == [0xc3] => Some(EntryInstruction::Return),
        Mnemonic::Leave if encoding.bytes() == [0xc9] => Some(EntryInstruction::Leave),
        Mnemonic::Jmp | Mnemonic::Je | Mnemonic::Jne
            if instruction.op0_kind() == OpKind::NearBranch64 =>
        {
            Some(EntryInstruction::Jump {
                target: instruction.near_branch64(),
                zero: match instruction.mnemonic() {
                    Mnemonic::Je => Some(true),
                    Mnemonic::Jne => Some(false),
                    _ => None,
                },
            })
        }
        _ => None,
    }
}

fn normalize(instruction: &Instruction, encoding: Encoding) -> Option<Decoded> {
    let operation = match instruction.mnemonic() {
        Mnemonic::Mov => Operation::Mov,
        Mnemonic::Lea => Operation::Lea,
        Mnemonic::Add => Operation::Add,
        Mnemonic::Adc => Operation::Adc,
        Mnemonic::Xor => Operation::Xor,
        _ => return None,
    };
    if instruction.op_count() != 2 {
        return None;
    }
    let prefixes = Prefixes {
        lock: instruction.has_lock_prefix(),
        repeat: if instruction.has_rep_prefix() {
            Repeat::Rep
        } else if instruction.has_repne_prefix() {
            Repeat::Repne
        } else {
            Repeat::None
        },
        transaction: if instruction.has_xacquire_prefix() {
            TransactionHint::Acquire
        } else if instruction.has_xrelease_prefix() {
            TransactionHint::Release
        } else {
            TransactionHint::None
        },
        segment_override: segment(instruction.segment_prefix()),
        address_size: address_size(encoding.bytes()),
    };
    Some(Decoded {
        encoding,
        operation,
        prefixes,
        operands: [
            operand(instruction, 0, operation, prefixes.address_size)?,
            operand(instruction, 1, operation, prefixes.address_size)?,
        ],
    })
}

fn address_size(bytes: &[u8]) -> AddressSize {
    for &byte in bytes {
        match byte {
            0x67 => return AddressSize::Bits32,
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0xf0 | 0xf2 | 0xf3 | 0x40..=0x4f => {}
            _ => break,
        }
    }
    AddressSize::Bits64
}

fn segment(reg: IcedRegister) -> Option<Segment> {
    Some(match reg {
        IcedRegister::ES => Segment::Es,
        IcedRegister::CS => Segment::Cs,
        IcedRegister::SS => Segment::Ss,
        IcedRegister::DS => Segment::Ds,
        IcedRegister::FS => Segment::Fs,
        IcedRegister::GS => Segment::Gs,
        _ => return None,
    })
}

fn register(reg: IcedRegister) -> Option<Register> {
    let (first, width, high_byte) = match reg {
        r if r >= IcedRegister::AL && r <= IcedRegister::BL => {
            (IcedRegister::AL, Width::Byte, false)
        }
        r if r >= IcedRegister::AH && r <= IcedRegister::BH => {
            (IcedRegister::AH, Width::Byte, true)
        }
        r if r >= IcedRegister::SPL && r <= IcedRegister::R15L => {
            (IcedRegister::AL, Width::Byte, false)
        }
        r if r >= IcedRegister::AX && r <= IcedRegister::R15W => {
            (IcedRegister::AX, Width::Word, false)
        }
        r if r >= IcedRegister::EAX && r <= IcedRegister::R15D => {
            (IcedRegister::EAX, Width::Dword, false)
        }
        r if r >= IcedRegister::RAX && r <= IcedRegister::R15 => {
            (IcedRegister::RAX, Width::Qword, false)
        }
        _ => return None,
    };
    let mut index = (reg as u32 - first as u32) as u8;
    if reg >= IcedRegister::SPL && reg <= IcedRegister::R15L {
        index -= 4;
    }
    Register::new(Gpr::new(index)?, width, high_byte)
}

fn width(bytes: usize) -> Option<Width> {
    match bytes {
        1 => Some(Width::Byte),
        2 => Some(Width::Word),
        4 => Some(Width::Dword),
        8 => Some(Width::Qword),
        _ => None,
    }
}

fn address(instruction: &Instruction, size: AddressSize) -> Option<Address> {
    let base_reg = instruction.memory_base();
    let base = match base_reg {
        IcedRegister::None => Base::None,
        IcedRegister::RIP | IcedRegister::EIP => Base::NextRip,
        _ => Base::Register(register(base_reg)?.gpr()),
    };
    let displacement = match base_reg {
        IcedRegister::RIP => instruction
            .memory_displacement64()
            .wrapping_sub(instruction.next_ip()),
        IcedRegister::EIP => {
            (instruction
                .memory_displacement32()
                .wrapping_sub(instruction.next_ip32())) as u64
        }
        _ => instruction.memory_displacement64(),
    };
    let index = match instruction.memory_index() {
        IcedRegister::None => None,
        reg => Some(register(reg)?.gpr()),
    };
    let scale = match instruction.memory_index_scale() {
        1 => Scale::One,
        2 => Scale::Two,
        4 => Scale::Four,
        8 => Scale::Eight,
        _ => return None,
    };
    Some(Address {
        size,
        segment: segment(instruction.memory_segment())?,
        base,
        index,
        scale,
        displacement,
    })
}

fn operand(
    instruction: &Instruction,
    index: u32,
    operation: Operation,
    address_size: AddressSize,
) -> Option<Operand> {
    let (encoded_width, width, value) = match instruction.op_kind(index) {
        OpKind::Register => {
            return Some(Operand::Register(register(instruction.op_register(index))?));
        }
        OpKind::Memory => {
            let address = address(instruction, address_size)?;
            return Some(if operation == Operation::Lea {
                Operand::Address(address)
            } else {
                Operand::Memory {
                    address,
                    width: width(instruction.memory_size().size())?,
                }
            });
        }
        OpKind::Immediate8 => (Width::Byte, Width::Byte, instruction.immediate8() as u64),
        OpKind::Immediate16 => (Width::Word, Width::Word, instruction.immediate16() as u64),
        OpKind::Immediate32 => (Width::Dword, Width::Dword, instruction.immediate32() as u64),
        OpKind::Immediate64 => (Width::Qword, Width::Qword, instruction.immediate64()),
        OpKind::Immediate8to16 => (
            Width::Byte,
            Width::Word,
            instruction.immediate8to16() as u16 as u64,
        ),
        OpKind::Immediate8to32 => (
            Width::Byte,
            Width::Dword,
            instruction.immediate8to32() as u32 as u64,
        ),
        OpKind::Immediate8to64 => (
            Width::Byte,
            Width::Qword,
            instruction.immediate8to64() as u64,
        ),
        OpKind::Immediate32to64 => (
            Width::Dword,
            Width::Qword,
            instruction.immediate32to64() as u64,
        ),
        _ => return None,
    };
    Some(Operand::Immediate(Immediate {
        encoded_width,
        width,
        value,
    }))
}
