// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Trusted iced-x86 adapter to core-owned operands; no memory provider.
#![forbid(unsafe_code)]
#![expect(missing_docs)]

pub use x86_system::memory_core::cpu_core::operand::*;

use iced_x86::Register as IcedRegister;
use iced_x86::{Decoder, DecoderError, DecoderOptions, Instruction, Mnemonic, OpKind};
use x86_system::shared::decode::{DecodeDecision, DecodeInput};

pub const MAX_INSTRUCTION_BYTES: usize = 15;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Mov,
    Lea,
    Add,
    Adc,
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
            } else {
                0
            },
            undefined: 0,
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
    /// Includes overlong encodings. This diagnostic is not an architectural #UD.
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
    let mut decoder = Decoder::with_ip(64, encoding.bytes(), encoding.rip, DecoderOptions::AMD);
    let instruction = decoder.decode();
    if decoder.last_error() == DecoderError::NoMoreBytes
        && encoding.length < MAX_INSTRUCTION_BYTES as u8
    {
        return None;
    }
    Some(if decoder.last_error() != DecoderError::None {
        Outcome::Rejected(encoding)
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
        Some(Outcome::Unsupported { .. }) => DecodeDecision::Unsupported,
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
                _ => DecodeDecision::Unsupported,
            }
        }
    }
}

fn normalize(instruction: &Instruction, encoding: Encoding) -> Option<Decoded> {
    let operation = match instruction.mnemonic() {
        Mnemonic::Mov => Operation::Mov,
        Mnemonic::Lea => Operation::Lea,
        Mnemonic::Add => Operation::Add,
        Mnemonic::Adc => Operation::Adc,
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
