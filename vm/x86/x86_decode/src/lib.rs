// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Trusted iced-x86 adapter to core-owned operands; no memory provider.
#![forbid(unsafe_code)]
#![expect(missing_docs)]

pub use x86_system::memory_core::cpu_core::operand::*;

use iced_x86::Register as IcedRegister;
use iced_x86::{Code, Decoder, DecoderError, DecoderOptions, Instruction, Mnemonic, OpKind};
use x86_system::memory_core::cpu_core::control::Condition;
use x86_system::memory_core::cpu_core::{integer, profile, scalar};
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
                [0xe8, a, b, c, d] | [0x2e, 0xe8, a, b, c, d] | [0x67, 0xe8, a, b, c, d] => {
                    DecodeDecision::NearCall {
                        displacement: i32::from_le_bytes([*a, *b, *c, *d]),
                    }
                }
                _ => {
                    admit_entry(encoding).map_or(DecodeDecision::Unsupported, DecodeDecision::Entry)
                }
            }
        }
        Some(Outcome::Normalized(decoded)) => {
            if decoded.prefixes.lock {
                return admit_entry(decoded.encoding)
                    .map_or(DecodeDecision::Unsupported, DecodeDecision::Entry);
            }
            if decoded.prefixes.repeat != Repeat::None
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
                (operation, [destination, source])
                    if matches!(operation, Operation::Add | Operation::Adc | Operation::Xor) =>
                {
                    let operation = match operation {
                        Operation::Add => integer::Operation::Add,
                        Operation::Adc => integer::Operation::Adc,
                        _ => integer::Operation::Xor,
                    };
                    alu_entry(operation, destination, source)
                        .map_or(DecodeDecision::Unsupported, DecodeDecision::Entry)
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
        || instruction.has_xacquire_prefix()
        || instruction.has_xrelease_prefix()
    {
        return None;
    }
    let size = address_size(encoding.bytes());
    if instruction.mnemonic() == Mnemonic::Pause && encoding.bytes() == [0xf3, 0x90] {
        return Some(EntryInstruction::Nop);
    }
    if matches!(
        instruction.mnemonic(),
        Mnemonic::Endbr64 | Mnemonic::Endbr32
    ) && matches!(
        encoding.bytes(),
        [0xf3, 0x0f, 0x1e, 0xfa] | [0xf3, 0x0f, 0x1e, 0xfb]
    ) && profile::cpuid(7, 0)[3] & (1 << 20) == 0
    {
        return Some(EntryInstruction::Nop);
    }
    // The supported system profile excludes CR4.CET.
    if matches!(instruction.mnemonic(), Mnemonic::Rdsspd | Mnemonic::Rdsspq)
        && profile::cpuid(7, 0)[2] & (1 << 7) == 0
    {
        return Some(EntryInstruction::Nop);
    }
    if matches!(
        instruction.mnemonic(),
        Mnemonic::Movd
            | Mnemonic::Movq
            | Mnemonic::Punpckldq
            | Mnemonic::Punpckhdq
            | Mnemonic::Punpcklqdq
            | Mnemonic::Punpckhqdq
            | Mnemonic::Punpcklbw
            | Mnemonic::Punpcklwd
            | Mnemonic::Punpckhbw
            | Mnemonic::Punpckhwd
            | Mnemonic::Pshufd
            | Mnemonic::Pslldq
            | Mnemonic::Psrldq
            | Mnemonic::Movhps
            | Mnemonic::Movlps
            | Mnemonic::Movhpd
            | Mnemonic::Movlpd
            | Mnemonic::Movhlps
            | Mnemonic::Movlhps
            | Mnemonic::Movaps
            | Mnemonic::Movapd
            | Mnemonic::Movdqa
            | Mnemonic::Movups
            | Mnemonic::Movupd
            | Mnemonic::Movdqu
    ) {
        return admit_xmm(&instruction, size);
    }
    if matches!(
        instruction.mnemonic(),
        Mnemonic::Pand
            | Mnemonic::Pandn
            | Mnemonic::Por
            | Mnemonic::Pxor
            | Mnemonic::Andps
            | Mnemonic::Andpd
            | Mnemonic::Andnps
            | Mnemonic::Andnpd
            | Mnemonic::Orps
            | Mnemonic::Orpd
            | Mnemonic::Xorps
            | Mnemonic::Xorpd
            | Mnemonic::Pcmpeqb
            | Mnemonic::Pcmpeqw
            | Mnemonic::Pcmpeqd
            | Mnemonic::Pmovmskb
            | Mnemonic::Paddb
            | Mnemonic::Paddw
            | Mnemonic::Paddd
            | Mnemonic::Paddq
            | Mnemonic::Psubb
            | Mnemonic::Psubw
            | Mnemonic::Psubd
            | Mnemonic::Psubq
    ) {
        return admit_xmm(&instruction, size);
    }
    if instruction.mnemonic() == Mnemonic::Cmpxchg {
        return admit_compare_exchange(&instruction, encoding, size);
    }
    if instruction.mnemonic() == Mnemonic::Xchg {
        if instruction.has_rep_prefix() || instruction.has_repne_prefix() {
            return None;
        }
        let destination = operand(&instruction, 0, Operation::Mov, size)?;
        let Operand::Register(source) = operand(&instruction, 1, Operation::Mov, size)? else {
            return None;
        };
        return match destination {
            Operand::Memory { address, width } if width == source.width() => {
                Some(EntryInstruction::ExchangeMemory { address, source })
            }
            Operand::Register(left)
                if left.width() == source.width() && !instruction.has_lock_prefix() =>
            {
                Some(EntryInstruction::ExchangeRegisters {
                    left,
                    right: source,
                })
            }
            _ => None,
        };
    }
    if instruction.mnemonic() == Mnemonic::Xadd {
        if instruction.has_rep_prefix() || instruction.has_repne_prefix() {
            return None;
        }
        let destination = operand(&instruction, 0, Operation::Mov, size)?;
        let Operand::Register(source) = operand(&instruction, 1, Operation::Mov, size)? else {
            return None;
        };
        return matches!(destination,Operand::Memory {width,..} if width==source.width())
            .then_some(EntryInstruction::ExchangeAdd {
                destination,
                source,
                locked: instruction.has_lock_prefix(),
            });
    }
    if matches!(
        instruction.mnemonic(),
        Mnemonic::Bsf | Mnemonic::Bsr | Mnemonic::Tzcnt | Mnemonic::Lzcnt
    ) {
        if instruction.has_lock_prefix() || instruction.has_repne_prefix() {
            return None;
        }
        let reverse = matches!(instruction.mnemonic(), Mnemonic::Bsr | Mnemonic::Lzcnt);
        if (instruction.mnemonic() == Mnemonic::Tzcnt && profile::cpuid(7, 0)[1] & (1 << 3) != 0)
            || (instruction.mnemonic() == Mnemonic::Lzcnt
                && profile::cpuid(0x80000001, 0)[2] & (1 << 5) != 0)
        {
            return None;
        }
        let Operand::Register(dst) = operand(&instruction, 0, Operation::Mov, size)? else {
            return None;
        };
        let source = operand(&instruction, 1, Operation::Mov, size)?;
        return (dst.width() != Width::Byte && operand_width(source) == Some(dst.width()))
            .then_some(EntryInstruction::Scan {
                dst,
                source,
                reverse,
            });
    }
    if instruction.has_lock_prefix() {
        if has_repeat_prefix(encoding) {
            return None;
        }
        if matches!(
            instruction.mnemonic(),
            Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc
        ) {
            return admit_memory_bit(&instruction, size, true);
        }
        let EntryInstruction::Alu {
            operation,
            destination,
            source,
        } = admit_alu(&instruction, size)?
        else {
            return None;
        };
        return (matches!(
            operation,
            integer::Operation::Add
                | integer::Operation::Adc
                | integer::Operation::Sub
                | integer::Operation::Sbb
                | integer::Operation::And
                | integer::Operation::Or
                | integer::Operation::Xor
                | integer::Operation::Inc
                | integer::Operation::Dec
                | integer::Operation::Neg
                | integer::Operation::Not
        ) && matches!(source, Operand::Register(_) | Operand::Immediate(_)))
        .then_some(EntryInstruction::LockedAlu {
            operation,
            destination,
            source,
        });
    }
    if instruction.has_rep_prefix() || instruction.has_repne_prefix() {
        if !instruction.has_rep_prefix()
            || instruction.has_repne_prefix()
            || size != AddressSize::Bits64
            || encoding.bytes().contains(&0xf2)
        {
            return None;
        }
        let move_width = match instruction.code() {
            Code::Movsb_m8_m8 => Some(Width::Byte),
            Code::Movsw_m16_m16 => Some(Width::Word),
            Code::Movsd_m32_m32 => Some(Width::Dword),
            Code::Movsq_m64_m64 => Some(Width::Qword),
            _ => None,
        };
        if let Some(width) = move_width {
            return (instruction.segment_prefix() == IcedRegister::None)
                .then_some(EntryInstruction::RepeatMove { width });
        }
        let width = match instruction.mnemonic() {
            Mnemonic::Stosb => Width::Byte,
            Mnemonic::Stosw => Width::Word,
            Mnemonic::Stosd => Width::Dword,
            Mnemonic::Stosq => Width::Qword,
            _ => return None,
        };
        return Some(EntryInstruction::RepeatStore { width });
    }
    let get = |index| operand(&instruction, index, Operation::Mov, size);
    if instruction.mnemonic() == Mnemonic::Bswap {
        let Operand::Register(dst) = get(0)? else {
            return None;
        };
        return matches!(dst.width(), Width::Dword | Width::Qword)
            .then_some(EntryInstruction::ByteSwap { dst });
    }
    match encoding.bytes() {
        [0x0f, 0x31] => return Some(EntryInstruction::ReadTimestamp),
        [0x0f, 0x32] => return Some(EntryInstruction::ReadMsr),
        [0x0f, 0xa2] => return Some(EntryInstruction::Cpuid),
        [0x48, 0xcb] => return Some(EntryInstruction::FarReturn),
        [0x9c] => return Some(EntryInstruction::PushFlags),
        [0x9d] => return Some(EntryInstruction::PopFlags),
        [0xfc] => return Some(EntryInstruction::Direction { set: false }),
        [0xfd] => return Some(EntryInstruction::Direction { set: true }),
        _ => {}
    }
    match instruction.mnemonic() {
        Mnemonic::Prefetchnta
        | Mnemonic::Prefetchw
        | Mnemonic::Prefetcht0
        | Mnemonic::Prefetcht1
        | Mnemonic::Prefetcht2 => Some(EntryInstruction::Nop),
        Mnemonic::In | Mnemonic::Out => {
            use x86_system::shared::entry::Port;
            let write = instruction.mnemonic() == Mnemonic::Out;
            let accumulator = if write { 1 } else { 0 };
            let port = 1 - accumulator;
            let width = match instruction.op_register(accumulator) {
                iced_x86::Register::AL => Width::Byte,
                iced_x86::Register::AX => Width::Word,
                iced_x86::Register::EAX => Width::Dword,
                _ => return None,
            };
            let port = match instruction.op_kind(port) {
                OpKind::Register if instruction.op_register(port) == iced_x86::Register::DX => {
                    Port::Dx
                }
                OpKind::Immediate8 => Port::Immediate(instruction.immediate8()),
                _ => return None,
            };
            Some(EntryInstruction::PortIo { port, width, write })
        }
        Mnemonic::Nop => Some(EntryInstruction::Nop),
        Mnemonic::Lfence | Mnemonic::Sfence | Mnemonic::Mfence => Some(EntryInstruction::Fence),
        Mnemonic::Fninit => Some(EntryInstruction::InitializeX87),
        Mnemonic::Fild => {
            let Operand::Memory { address, width } = get(0)? else {
                return None;
            };
            if width == Width::Byte {
                return None;
            }
            let bytes = encoding.bytes();
            let at = bytes.iter().position(|byte| matches!(byte, 0xdb | 0xdf))?;
            let opcode = (u16::from(bytes[at] & 7) << 8) | u16::from(*bytes.get(at + 1)?);
            Some(EntryInstruction::LoadX87Integer {
                address,
                width,
                opcode,
            })
        }
        Mnemonic::Fnclex | Mnemonic::Emms => Some(EntryInstruction::ControlX87 {
            operation: if instruction.mnemonic() == Mnemonic::Fnclex {
                x86_system::memory_core::cpu_core::system::X87Control::ClearExceptions
            } else {
                x86_system::memory_core::cpu_core::system::X87Control::EmptyMmx
            },
        }),
        Mnemonic::Int3 if encoding.bytes() == [0xcc] => Some(EntryInstruction::Breakpoint),
        Mnemonic::Syscall if encoding.bytes() == [0x0f, 0x05] => Some(EntryInstruction::Syscall),
        Mnemonic::Sysret | Mnemonic::Sysretq if encoding.bytes() == [0x48, 0x0f, 0x07] => {
            Some(EntryInstruction::Sysret)
        }
        Mnemonic::Swapgs if encoding.bytes() == [0x0f, 0x01, 0xf8] => {
            Some(EntryInstruction::SwapGs)
        }
        Mnemonic::Fxsave | Mnemonic::Fxsave64 => Some(EntryInstruction::SaveFp {
            address: address(&instruction, size)?,
            wide: instruction.mnemonic() == Mnemonic::Fxsave64,
        }),
        Mnemonic::Fxrstor | Mnemonic::Fxrstor64 => Some(EntryInstruction::RestoreFp {
            address: address(&instruction, size)?,
            wide: instruction.mnemonic() == Mnemonic::Fxrstor64,
        }),
        Mnemonic::Shld | Mnemonic::Shrd => {
            let Operand::Register(dst) = get(0)? else {
                return None;
            };
            let Operand::Register(source) = get(1)? else {
                return None;
            };
            let count = get(2)?;
            if dst.width() == Width::Byte
                || dst.width() != source.width()
                || !matches!(
                    count,
                    Operand::Immediate(Immediate {
                        width: Width::Byte,
                        ..
                    }) | Operand::Register(_)
                )
            {
                return None;
            }
            if let Operand::Register(reg) = count {
                if reg.gpr().index() != 1 || reg.width() != Width::Byte || reg.high_byte() {
                    return None;
                }
            }
            Some(EntryInstruction::DoubleShift {
                dst,
                source,
                count,
                left: instruction.mnemonic() == Mnemonic::Shld,
            })
        }
        Mnemonic::Cmovo
        | Mnemonic::Cmovno
        | Mnemonic::Cmovb
        | Mnemonic::Cmovae
        | Mnemonic::Cmove
        | Mnemonic::Cmovne
        | Mnemonic::Cmovbe
        | Mnemonic::Cmova
        | Mnemonic::Cmovs
        | Mnemonic::Cmovns
        | Mnemonic::Cmovp
        | Mnemonic::Cmovnp
        | Mnemonic::Cmovl
        | Mnemonic::Cmovge
        | Mnemonic::Cmovle
        | Mnemonic::Cmovg
            if instruction.op_count() == 2 =>
        {
            let Operand::Register(dst) = get(0)? else {
                return None;
            };
            let source = get(1)?;
            if !matches!(dst.width(), Width::Word | Width::Dword | Width::Qword)
                || !matches!(source, Operand::Register(_) | Operand::Memory { .. })
                || operand_width(source)? != dst.width()
            {
                return None;
            }
            // Memory remains an unconditional read obligation for the executor.
            Some(EntryInstruction::ConditionalMove {
                condition: condition(instruction.mnemonic())?,
                dst,
                source,
            })
        }
        Mnemonic::Seto
        | Mnemonic::Setno
        | Mnemonic::Setb
        | Mnemonic::Setae
        | Mnemonic::Sete
        | Mnemonic::Setne
        | Mnemonic::Setbe
        | Mnemonic::Seta
        | Mnemonic::Sets
        | Mnemonic::Setns
        | Mnemonic::Setp
        | Mnemonic::Setnp
        | Mnemonic::Setl
        | Mnemonic::Setge
        | Mnemonic::Setle
        | Mnemonic::Setg
            if instruction.op_count() == 1 =>
        {
            let destination = get(0)?;
            (matches!(destination, Operand::Register(_) | Operand::Memory { .. })
                && operand_width(destination)? == Width::Byte)
                .then_some(EntryInstruction::SetCondition {
                    condition: condition(instruction.mnemonic())?,
                    destination,
                })
        }
        Mnemonic::Add
        | Mnemonic::Adc
        | Mnemonic::Sub
        | Mnemonic::Sbb
        | Mnemonic::And
        | Mnemonic::Or
        | Mnemonic::Test
        | Mnemonic::Shl
        | Mnemonic::Shr
        | Mnemonic::Sar
        | Mnemonic::Rol
        | Mnemonic::Ror
        | Mnemonic::Cmp
        | Mnemonic::Xor
        | Mnemonic::Inc
        | Mnemonic::Dec
        | Mnemonic::Neg
        | Mnemonic::Not => admit_alu(&instruction, size),
        Mnemonic::Movsx | Mnemonic::Movsxd => {
            let Operand::Register(dst) = get(0)? else {
                return None;
            };
            let source = get(1)?;
            let width = operand_width(source)?;
            (width.bits() < dst.width().bits()).then_some(EntryInstruction::SignExtend {
                dst,
                source,
                width,
            })
        }
        Mnemonic::Cbw | Mnemonic::Cwde | Mnemonic::Cdqe => {
            let (width, destination) = match instruction.mnemonic() {
                Mnemonic::Cbw => (Width::Byte, Width::Word),
                Mnemonic::Cwde => (Width::Word, Width::Dword),
                _ => (Width::Dword, Width::Qword),
            };
            let accumulator = Gpr::new(0)?;
            Some(EntryInstruction::SignExtend {
                dst: Register::new(accumulator, destination, false)?,
                source: Operand::Register(Register::new(accumulator, width, false)?),
                width,
            })
        }
        Mnemonic::Cwd | Mnemonic::Cdq | Mnemonic::Cqo => Some(EntryInstruction::SignHigh {
            width: match instruction.mnemonic() {
                Mnemonic::Cwd => Width::Word,
                Mnemonic::Cdq => Width::Dword,
                _ => Width::Qword,
            },
        }),
        Mnemonic::Div | Mnemonic::Idiv => {
            let source = get(0)?;
            let width = operand_width(source)?;
            matches!(width, Width::Dword | Width::Qword).then_some(EntryInstruction::Divide {
                source,
                width,
                signed: instruction.mnemonic() == Mnemonic::Idiv,
            })
        }
        Mnemonic::Mul | Mnemonic::Imul if instruction.op_count() == 1 => {
            let source = get(0)?;
            if !matches!(source, Operand::Register(_) | Operand::Memory { .. }) {
                return None;
            }
            Some(EntryInstruction::MultiplyWide {
                source,
                width: operand_width(source)?,
                signed: instruction.mnemonic() == Mnemonic::Imul,
            })
        }
        Mnemonic::Imul if matches!(instruction.op_count(), 2 | 3) => {
            let Operand::Register(dst) = get(0)? else {
                return None;
            };
            if !matches!(dst.width(), Width::Word | Width::Dword | Width::Qword) {
                return None;
            }
            let source = get(1)?;
            if !matches!(source, Operand::Register(_) | Operand::Memory { .. })
                || operand_width(source)? != dst.width()
            {
                return None;
            }
            let immediate = if instruction.op_count() == 3 {
                let Operand::Immediate(immediate) = get(2)? else {
                    return None;
                };
                if immediate.width != dst.width() {
                    return None;
                }
                Some(immediate.value)
            } else {
                None
            };
            Some(EntryInstruction::Multiply {
                dst,
                source,
                immediate,
            })
        }
        Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc => {
            let destination = get(0)?;
            if matches!(destination, Operand::Memory { .. }) {
                return admit_memory_bit(&instruction, size, false);
            }
            let Operand::Register(dst) = destination else {
                return None;
            };
            let mut index = get(1)?;
            match index {
                Operand::Register(src) if src.width() == dst.width() => {}
                Operand::Immediate(mut immediate) if immediate.width == Width::Byte => {
                    immediate.value &= dst.width().bits() as u64 - 1;
                    index = Operand::Immediate(immediate);
                }
                _ => return None,
            }
            let operation = match instruction.mnemonic() {
                Mnemonic::Bt => scalar::BitOperation::Test,
                Mnemonic::Bts => scalar::BitOperation::Set,
                Mnemonic::Btr => scalar::BitOperation::Reset,
                _ => scalar::BitOperation::Complement,
            };
            Some(EntryInstruction::Bit {
                operation,
                dst,
                index,
            })
        }
        Mnemonic::Mov | Mnemonic::Movzx => {
            if instruction.mnemonic() == Mnemonic::Mov {
                if let Some(segment) = segment(instruction.op1_register()) {
                    let destination = get(0)?;
                    return match destination {
                        Operand::Register(dst) if dst.width() != Width::Byte => {
                            Some(EntryInstruction::ReadSegment {
                                segment,
                                destination,
                            })
                        }
                        Operand::Memory {
                            width: Width::Word, ..
                        } => Some(EntryInstruction::ReadSegment {
                            segment,
                            destination,
                        }),
                        _ => None,
                    };
                }
                let control = match instruction.op1_register() {
                    IcedRegister::CR0 => Some(0),
                    IcedRegister::CR2 => Some(2),
                    IcedRegister::CR3 => Some(3),
                    IcedRegister::CR4 => Some(4),
                    IcedRegister::CR8 => Some(8),
                    _ => None,
                };
                if (IcedRegister::DR0..=IcedRegister::DR7).contains(&instruction.op1_register()) {
                    let dst = register(instruction.op0_register())?;
                    return (dst.width() == Width::Qword).then_some(EntryInstruction::ReadDebug {
                        number: (instruction.op1_register() as u32 - IcedRegister::DR0 as u32)
                            as u8,
                        dst,
                    });
                }
                if (IcedRegister::DR0..=IcedRegister::DR7).contains(&instruction.op0_register()) {
                    let source = register(instruction.op1_register())?;
                    return (source.width() == Width::Qword).then_some(
                        EntryInstruction::WriteDebug {
                            number: (instruction.op0_register() as u32 - IcedRegister::DR0 as u32)
                                as u8,
                            source,
                        },
                    );
                }
                if let Some(number) = control {
                    let dst = register(instruction.op0_register())?;
                    return (dst.width() == Width::Qword)
                        .then_some(EntryInstruction::ReadControl { number, dst });
                }
                let control = match instruction.op0_register() {
                    IcedRegister::CR0 => Some(0),
                    IcedRegister::CR3 => Some(3),
                    IcedRegister::CR4 => Some(4),
                    IcedRegister::CR8 => Some(8),
                    _ => None,
                };
                if let Some(number) = control {
                    let source = register(instruction.op1_register())?;
                    return (source.width() == Width::Qword).then_some(
                        EntryInstruction::WriteControl {
                            number,
                            source: Operand::Register(source),
                        },
                    );
                }
                if let Some(
                    dst @ (Segment::Ds | Segment::Ss | Segment::Es | Segment::Fs | Segment::Gs),
                ) = segment(instruction.op0_register())
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
        Mnemonic::Sgdt | Mnemonic::Sidt => Some(EntryInstruction::StoreTable {
            address: address(&instruction, size)?,
            idt: instruction.mnemonic() == Mnemonic::Sidt,
        }),
        Mnemonic::Ltr => {
            let Operand::Register(source) = get(0)? else {
                return None;
            };
            Some(EntryInstruction::LoadTask {
                source: Register::new(source.gpr(), Width::Word, false)?,
            })
        }
        Mnemonic::Lldt => {
            let Operand::Register(source) = get(0)? else {
                return None;
            };
            Some(EntryInstruction::LoadLdt {
                source: Register::new(source.gpr(), Width::Word, false)?,
            })
        }
        Mnemonic::Push => {
            let source = get(0)?;
            match source {
                Operand::Register(reg) if reg.width() == Width::Qword => {}
                Operand::Immediate(imm) if imm.width == Width::Qword => {}
                Operand::Memory {
                    width: Width::Qword,
                    ..
                } => {}
                _ => return None,
            }
            Some(EntryInstruction::Push { source })
        }
        Mnemonic::Pop => match get(0)? {
            Operand::Register(dst) if dst.width() == Width::Qword => {
                Some(EntryInstruction::Pop { dst })
            }
            Operand::Memory {
                address,
                width: Width::Qword,
            } => Some(EntryInstruction::PopMemory { address }),
            _ => None,
        },
        Mnemonic::Ret if encoding.bytes() == [0xc3] => Some(EntryInstruction::Return),
        Mnemonic::Leave if encoding.bytes() == [0xc9] => Some(EntryInstruction::Leave),
        Mnemonic::Call if matches!(instruction.op0_kind(), OpKind::Register | OpKind::Memory) => {
            let source = get(0)?;
            (operand_width(source)? == Width::Qword)
                .then_some(EntryInstruction::IndirectCall { source })
        }
        Mnemonic::Jmp if matches!(instruction.op0_kind(), OpKind::Register | OpKind::Memory) => {
            let source = get(0)?;
            (operand_width(source)? == Width::Qword)
                .then_some(EntryInstruction::IndirectJump { source })
        }
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
        Mnemonic::Jo
        | Mnemonic::Jno
        | Mnemonic::Jb
        | Mnemonic::Jae
        | Mnemonic::Jbe
        | Mnemonic::Ja
        | Mnemonic::Js
        | Mnemonic::Jns
        | Mnemonic::Jp
        | Mnemonic::Jnp
        | Mnemonic::Jl
        | Mnemonic::Jge
        | Mnemonic::Jle
        | Mnemonic::Jg
            if instruction.op0_kind() == OpKind::NearBranch64 =>
        {
            Some(EntryInstruction::Branch {
                target: instruction.near_branch64(),
                condition: condition(instruction.mnemonic())?,
            })
        }
        _ => None,
    }
}

fn admit_memory_bit(
    instruction: &Instruction,
    size: AddressSize,
    locked: bool,
) -> Option<EntryInstruction> {
    let destination = operand(instruction, 0, Operation::Mov, size)?;
    let Operand::Memory { width, .. } = destination else {
        return None;
    };
    if !matches!(width, Width::Word | Width::Dword | Width::Qword) {
        return None;
    }
    let source = match operand(instruction, 1, Operation::Mov, size)? {
        Operand::Register(index) if index.width() == width => Operand::Register(index),
        Operand::Immediate(mut index) if index.encoded_width == Width::Byte => {
            index.width = width;
            index.value &= width.bits() as u64 - 1;
            Operand::Immediate(index)
        }
        _ => return None,
    };
    let operation = match instruction.mnemonic() {
        Mnemonic::Bt if !locked => integer::Operation::BitTest,
        Mnemonic::Bts => integer::Operation::BitSet,
        Mnemonic::Btr => integer::Operation::BitReset,
        Mnemonic::Btc => integer::Operation::BitComplement,
        _ => return None,
    };
    Some(if locked {
        EntryInstruction::LockedAlu {
            operation,
            destination,
            source,
        }
    } else {
        EntryInstruction::Alu {
            operation,
            destination,
            source,
        }
    })
}

fn condition(mnemonic: Mnemonic) -> Option<Condition> {
    Some(match mnemonic {
        Mnemonic::Jo | Mnemonic::Cmovo | Mnemonic::Seto => Condition::Overflow,
        Mnemonic::Jno | Mnemonic::Cmovno | Mnemonic::Setno => Condition::NotOverflow,
        Mnemonic::Jb | Mnemonic::Cmovb | Mnemonic::Setb => Condition::Below,
        Mnemonic::Jae | Mnemonic::Cmovae | Mnemonic::Setae => Condition::AboveEqual,
        Mnemonic::Je | Mnemonic::Cmove | Mnemonic::Sete => Condition::Equal,
        Mnemonic::Jne | Mnemonic::Cmovne | Mnemonic::Setne => Condition::NotEqual,
        Mnemonic::Jbe | Mnemonic::Cmovbe | Mnemonic::Setbe => Condition::BelowEqual,
        Mnemonic::Ja | Mnemonic::Cmova | Mnemonic::Seta => Condition::Above,
        Mnemonic::Js | Mnemonic::Cmovs | Mnemonic::Sets => Condition::Sign,
        Mnemonic::Jns | Mnemonic::Cmovns | Mnemonic::Setns => Condition::NotSign,
        Mnemonic::Jp | Mnemonic::Cmovp | Mnemonic::Setp => Condition::Parity,
        Mnemonic::Jnp | Mnemonic::Cmovnp | Mnemonic::Setnp => Condition::NotParity,
        Mnemonic::Jl | Mnemonic::Cmovl | Mnemonic::Setl => Condition::Less,
        Mnemonic::Jge | Mnemonic::Cmovge | Mnemonic::Setge => Condition::GreaterEqual,
        Mnemonic::Jle | Mnemonic::Cmovle | Mnemonic::Setle => Condition::LessEqual,
        Mnemonic::Jg | Mnemonic::Cmovg | Mnemonic::Setg => Condition::Greater,
        _ => return None,
    })
}

fn xmm_index(register: IcedRegister) -> Option<u8> {
    use IcedRegister::*;
    match register {
        XMM0 => Some(0),
        XMM1 => Some(1),
        XMM2 => Some(2),
        XMM3 => Some(3),
        XMM4 => Some(4),
        XMM5 => Some(5),
        XMM6 => Some(6),
        XMM7 => Some(7),
        XMM8 => Some(8),
        XMM9 => Some(9),
        XMM10 => Some(10),
        XMM11 => Some(11),
        XMM12 => Some(12),
        XMM13 => Some(13),
        XMM14 => Some(14),
        XMM15 => Some(15),
        _ => Option::None,
    }
}

fn admit_xmm(instruction: &Instruction, size: AddressSize) -> Option<EntryInstruction> {
    if instruction.has_lock_prefix() || profile::cpuid(1, 0)[3] & (1 << 26) == 0 {
        return None;
    }
    let dst = xmm_index(instruction.op0_register());
    let source = xmm_index(instruction.op1_register());
    if instruction.mnemonic() == Mnemonic::Pshufd {
        if instruction.op_count() != 3 || instruction.op2_kind() != OpKind::Immediate8 {
            return None;
        }
        return Some(EntryInstruction::XmmShuffle {
            dst: dst?,
            source: source?,
            control: instruction.immediate8(),
        });
    }
    if instruction.op_count() != 2 {
        return None;
    }
    if matches!(instruction.mnemonic(), Mnemonic::Pslldq | Mnemonic::Psrldq) {
        if instruction.op1_kind() != OpKind::Immediate8 {
            return None;
        }
        return Some(EntryInstruction::XmmByteShift {
            index: dst?,
            count: instruction.immediate8(),
            left: instruction.mnemonic() == Mnemonic::Pslldq,
        });
    }
    if matches!(
        instruction.mnemonic(),
        Mnemonic::Paddb
            | Mnemonic::Paddw
            | Mnemonic::Paddd
            | Mnemonic::Paddq
            | Mnemonic::Psubb
            | Mnemonic::Psubw
            | Mnemonic::Psubd
            | Mnemonic::Psubq
    ) {
        let width = match instruction.mnemonic() {
            Mnemonic::Paddb | Mnemonic::Psubb => Width::Byte,
            Mnemonic::Paddw | Mnemonic::Psubw => Width::Word,
            Mnemonic::Paddd | Mnemonic::Psubd => Width::Dword,
            _ => Width::Qword,
        };
        let subtract = matches!(
            instruction.mnemonic(),
            Mnemonic::Psubb | Mnemonic::Psubw | Mnemonic::Psubd | Mnemonic::Psubq
        );
        let index = dst?;
        return if let Some(source) = source {
            Some(EntryInstruction::XmmArithmetic {
                dst: index,
                source,
                width,
                subtract,
            })
        } else if instruction.op1_kind() == OpKind::Memory {
            Some(EntryInstruction::XmmArithmeticMemory {
                address: address(instruction, size)?,
                index,
                width,
                subtract,
            })
        } else {
            None
        };
    }
    if instruction.mnemonic() == Mnemonic::Pmovmskb {
        let Operand::Register(dst) = operand(instruction, 0, Operation::Mov, size)? else {
            return None;
        };
        return matches!(dst.width(), Width::Dword | Width::Qword).then_some(
            EntryInstruction::XmmMask {
                dst,
                source: source?,
            },
        );
    }
    if matches!(
        instruction.mnemonic(),
        Mnemonic::Pcmpeqb | Mnemonic::Pcmpeqw | Mnemonic::Pcmpeqd
    ) {
        let width = match instruction.mnemonic() {
            Mnemonic::Pcmpeqb => Width::Byte,
            Mnemonic::Pcmpeqw => Width::Word,
            _ => Width::Dword,
        };
        let index = dst?;
        return if let Some(source) = source {
            Some(EntryInstruction::XmmEqual {
                dst: index,
                source,
                width,
            })
        } else if instruction.op1_kind() == OpKind::Memory {
            Some(EntryInstruction::XmmEqualMemory {
                address: address(instruction, size)?,
                index,
                width,
            })
        } else {
            None
        };
    }
    if matches!(
        instruction.mnemonic(),
        Mnemonic::Movhlps | Mnemonic::Movlhps
    ) {
        return Some(EntryInstruction::XmmMerge {
            dst: dst?,
            source: source?,
            high: instruction.mnemonic() == Mnemonic::Movlhps,
        });
    }
    if matches!(
        instruction.mnemonic(),
        Mnemonic::Movhps
            | Mnemonic::Movlps
            | Mnemonic::Movhpd
            | Mnemonic::Movlpd
            | Mnemonic::Movaps
            | Mnemonic::Movapd
            | Mnemonic::Movdqa
            | Mnemonic::Movups
            | Mnemonic::Movupd
            | Mnemonic::Movdqu
    ) {
        use x86_system::shared::entry::XmmMemoryKind;
        if let (Some(dst), Some(source)) = (dst, source) {
            return Some(EntryInstruction::XmmCopy { dst, source });
        }
        let (index, store) = match (dst, source) {
            (Some(index), None) if instruction.op1_kind() == OpKind::Memory => (index, false),
            (None, Some(index)) if instruction.op0_kind() == OpKind::Memory => (index, true),
            _ => return None,
        };
        let kind = match instruction.mnemonic() {
            Mnemonic::Movhps | Mnemonic::Movhpd => XmmMemoryKind::High,
            Mnemonic::Movlps | Mnemonic::Movlpd => XmmMemoryKind::Low,
            Mnemonic::Movaps | Mnemonic::Movapd | Mnemonic::Movdqa => XmmMemoryKind::Aligned,
            _ => XmmMemoryKind::Unaligned,
        };
        return Some(EntryInstruction::XmmMemory {
            address: address(instruction, size)?,
            index,
            store,
            kind,
        });
    }
    if matches!(instruction.mnemonic(), Mnemonic::Movd | Mnemonic::Movq) {
        return match (dst, source) {
            (Some(dst), Some(source)) if instruction.mnemonic() == Mnemonic::Movq => {
                Some(EntryInstruction::XmmCopyLow { dst, source })
            }
            (Some(dst), None) => {
                let source = operand(instruction, 1, Operation::Mov, size)?;
                let width = operand_width(source)?;
                matches!(width, Width::Dword | Width::Qword).then_some(EntryInstruction::XmmLoad {
                    dst,
                    source,
                    width,
                })
            }
            (None, Some(source)) => {
                let destination = operand(instruction, 0, Operation::Mov, size)?;
                let width = operand_width(destination)?;
                matches!(width, Width::Dword | Width::Qword).then_some(EntryInstruction::XmmStore {
                    destination,
                    source,
                    width,
                })
            }
            _ => None,
        };
    }
    use x86_system::memory_core::cpu_core::system::XmmLogic;
    let operation = match instruction.mnemonic() {
        Mnemonic::Pand | Mnemonic::Andps | Mnemonic::Andpd => Some(XmmLogic::And),
        Mnemonic::Pandn | Mnemonic::Andnps | Mnemonic::Andnpd => Some(XmmLogic::AndNot),
        Mnemonic::Por | Mnemonic::Orps | Mnemonic::Orpd => Some(XmmLogic::Or),
        Mnemonic::Pxor | Mnemonic::Xorps | Mnemonic::Xorpd => Some(XmmLogic::Xor),
        _ => None,
    };
    if let Some(operation) = operation {
        return Some(EntryInstruction::XmmLogic {
            dst: dst?,
            source: source?,
            operation,
        });
    }
    match instruction.mnemonic() {
        Mnemonic::Punpcklbw | Mnemonic::Punpcklwd | Mnemonic::Punpckhbw | Mnemonic::Punpckhwd => {
            Some(EntryInstruction::XmmUnpackNarrow {
                dst: dst?,
                source: source?,
                word: matches!(
                    instruction.mnemonic(),
                    Mnemonic::Punpcklwd | Mnemonic::Punpckhwd
                ),
                high: matches!(
                    instruction.mnemonic(),
                    Mnemonic::Punpckhbw | Mnemonic::Punpckhwd
                ),
            })
        }
        Mnemonic::Punpckldq | Mnemonic::Punpckhdq | Mnemonic::Punpcklqdq | Mnemonic::Punpckhqdq => {
            Some(EntryInstruction::XmmUnpack {
                dst: dst?,
                source: source?,
                wide: matches!(
                    instruction.mnemonic(),
                    Mnemonic::Punpcklqdq | Mnemonic::Punpckhqdq
                ),
                high: matches!(
                    instruction.mnemonic(),
                    Mnemonic::Punpckhdq | Mnemonic::Punpckhqdq
                ),
            })
        }
        _ => None,
    }
}

fn has_repeat_prefix(encoding: Encoding) -> bool {
    encoding
        .bytes()
        .iter()
        .take_while(|&&byte| {
            matches!(byte, 0x26 | 0x2e | 0x36 | 0x3e | 0x64..=0x67 | 0xf0 | 0xf2 | 0xf3 | 0x40..=0x4f)
        })
        .any(|&byte| matches!(byte, 0xf2 | 0xf3))
}

/// LOCK is required only for memory; alignment and atomic access belong to the CPU/MMU.
fn admit_compare_exchange(
    instruction: &Instruction,
    encoding: Encoding,
    size: AddressSize,
) -> Option<EntryInstruction> {
    if instruction.op_count() != 2 || has_repeat_prefix(encoding) {
        return None;
    }
    let destination = operand(instruction, 0, Operation::Mov, size)?;
    let Operand::Register(source) = operand(instruction, 1, Operation::Mov, size)? else {
        return None;
    };
    if operand_width(destination)? != source.width() {
        return None;
    }
    match destination {
        Operand::Register(_)
            if !instruction.has_lock_prefix()
                && size == AddressSize::Bits64
                && instruction.segment_prefix() == IcedRegister::None => {}
        Operand::Memory { .. } => {}
        _ => return None,
    }
    Some(EntryInstruction::CompareExchange {
        destination,
        source,
    })
}

fn operand_width(operand: Operand) -> Option<Width> {
    match operand {
        Operand::Register(register) => Some(register.width()),
        Operand::Memory { width, .. } => Some(width),
        Operand::Immediate(immediate) => Some(immediate.width),
        _ => None,
    }
}

fn admit_alu(instruction: &Instruction, size: AddressSize) -> Option<EntryInstruction> {
    let operation = match instruction.mnemonic() {
        Mnemonic::Add => integer::Operation::Add,
        Mnemonic::Adc => integer::Operation::Adc,
        Mnemonic::Sub => integer::Operation::Sub,
        Mnemonic::Sbb => integer::Operation::Sbb,
        Mnemonic::And => integer::Operation::And,
        Mnemonic::Or => integer::Operation::Or,
        Mnemonic::Test => integer::Operation::Test,
        Mnemonic::Shl => integer::Operation::Shl,
        Mnemonic::Shr => integer::Operation::Shr,
        Mnemonic::Sar => integer::Operation::Sar,
        Mnemonic::Rol => integer::Operation::Rol,
        Mnemonic::Ror => integer::Operation::Ror,
        Mnemonic::Cmp => integer::Operation::Cmp,
        Mnemonic::Xor => integer::Operation::Xor,
        Mnemonic::Inc => integer::Operation::Inc,
        Mnemonic::Dec => integer::Operation::Dec,
        Mnemonic::Neg => integer::Operation::Neg,
        Mnemonic::Not => integer::Operation::Not,
        _ => return None,
    };
    let destination = operand(instruction, 0, Operation::Mov, size)?;
    let source = if matches!(
        operation,
        integer::Operation::Inc
            | integer::Operation::Dec
            | integer::Operation::Neg
            | integer::Operation::Not
    ) {
        let width = operand_width(destination)?;
        Operand::Immediate(Immediate {
            encoded_width: width,
            width,
            value: 0,
        })
    } else {
        operand(instruction, 1, Operation::Mov, size)?
    };
    alu_entry(operation, destination, source)
}

fn alu_entry(
    operation: integer::Operation,
    destination: Operand,
    source: Operand,
) -> Option<EntryInstruction> {
    if !matches!(destination, Operand::Register(_) | Operand::Memory { .. }) {
        return None;
    }
    let width = operand_width(destination)?;
    if matches!(
        operation,
        integer::Operation::Shl
            | integer::Operation::Shr
            | integer::Operation::Sar
            | integer::Operation::Rol
            | integer::Operation::Ror
    ) {
        if !matches!(destination, Operand::Register(_))
            && !(matches!(destination, Operand::Memory { .. })
                && matches!(
                    operation,
                    integer::Operation::Shl | integer::Operation::Shr | integer::Operation::Sar
                ))
        {
            return None;
        }
        match source {
            Operand::Immediate(immediate) if immediate.width == Width::Byte => {}
            Operand::Register(register)
                if register.gpr().index() == 1
                    && register.width() == Width::Byte
                    && !register.high_byte() => {}
            _ => return None,
        }
    } else if operand_width(source)? != width
        || matches!(
            (destination, source),
            (Operand::Memory { .. }, Operand::Memory { .. })
        )
    {
        return None;
    }
    Some(match destination {
        Operand::Register(dst) => EntryInstruction::Integer {
            operation,
            dst,
            source,
        },
        _ => EntryInstruction::Alu {
            operation,
            destination,
            source,
        },
    })
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
