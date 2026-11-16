// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::MemoryError;
use thiserror::Error;

/// A single native atomic read-modify-write operation.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AtomicOperation {
    /// XCHG: replace memory and return its old value.
    Exchange,
    /// LOCK XADD: add to memory and return its old value.
    FetchAdd,
    /// LOCK ADD.
    Add,
    /// LOCK ADC, using guest CF.
    Adc,
    /// LOCK SUB.
    Sub,
    /// LOCK SBB, using guest CF.
    Sbb,
    /// LOCK AND.
    And,
    /// LOCK OR.
    Or,
    /// LOCK XOR.
    Xor,
    /// LOCK INC, preserving guest CF.
    Inc,
    /// LOCK DEC, preserving guest CF.
    Dec,
    /// LOCK NEG.
    Neg,
    /// LOCK NOT, preserving all guest flags.
    Not,
    /// LOCK BTS, replacing only guest CF.
    BitSet,
    /// LOCK BTR, replacing only guest CF.
    BitReset,
    /// LOCK BTC, replacing only guest CF.
    BitComplement,
}

/// The architectural result of an atomic operation.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AtomicResult {
    /// The zero-extended old operand, for exchange and fetch-add.
    Value(u64),
    /// Guest flags with only the operation's defined flags replaced.
    Flags(u64),
}

/// An invalid atomic operand or a fault accessing its backing.
#[derive(Debug, Error)]
pub enum AtomicError {
    /// The width is not 1, 2, 4, or 8 bytes.
    #[error("unsupported atomic width {0}; expected 1, 2, 4, or 8 bytes")]
    InvalidWidth(u8),
    /// The address is not a multiple of the operand width.
    #[error("atomic operand is not naturally aligned")]
    Unaligned,
    /// x86 bit operations have no byte form.
    #[error("bit operations do not support byte operands")]
    ByteBitOperation,
    /// Access to the operand faulted.
    #[error(transparent)]
    Memory(#[from] MemoryError),
}

impl AtomicOperation {
    /// Checks the width and natural alignment without accessing memory.
    pub fn validate(self, address: u64, width: u8) -> Result<(), AtomicError> {
        if !matches!(width, 1 | 2 | 4 | 8) {
            return Err(AtomicError::InvalidWidth(width));
        }
        if address & (u64::from(width) - 1) != 0 {
            return Err(AtomicError::Unaligned);
        }
        if width == 1 && matches!(self, Self::BitSet | Self::BitReset | Self::BitComplement) {
            return Err(AtomicError::ByteBitOperation);
        }
        Ok(())
    }
}

/// Performs one sequentially-consistent native x86 atomic operation.
///
/// Width is in bytes. Bit indices are reduced modulo the operand's bit width;
/// the operation never addresses memory outside that operand. ADC/SBB use CF
/// from `flags`. Other unmodified or undefined flags retain their guest values.
/// Exchange and fetch-add return the zero-extended old operand, not flags.
///
/// Call [`crate::initialize_try_copy`] before accessing memory that could fault.
/// An access violation leaves the operand unchanged.
///
/// # Safety
/// `dest..dest+width` must be reserved (but need not be backed). Writes must not
/// violate Rust's aliasing rules.
// xtask-fmt allow-target-arch cpu-intrinsic
#[cfg(target_arch = "x86_64")]
pub unsafe fn try_atomic(
    dest: *mut u8,
    width: u8,
    operation: AtomicOperation,
    source: u64,
    flags: u64,
) -> Result<AtomicResult, AtomicError> {
    use crate::recovery_descriptor;

    operation.validate(dest as u64, width)?;

    // Register-indexed x86 bit instructions otherwise interpret the index as an
    // offset into an unbounded bit string, potentially escaping the reservation.
    let source = if matches!(
        operation,
        AtomicOperation::BitSet | AtomicOperation::BitReset | AtomicOperation::BitComplement
    ) {
        source & (u64::from(width) * 8 - 1)
    } else {
        source
    };

    macro_rules! execute {
        ($instruction:expr) => {{
            let mut value = source;
            let native_flags: u64;
            let result: i32;
            // SAFETY: the caller reserves the validated, naturally aligned
            // operand. Only the RMW can fault, before any stack modification.
            unsafe {
                core::arch::asm!(
                    "bt {carry}, 0",
                    "2:",
                    $instruction,
                    "mov ecx, 0",
                    "3:",
                    "pushfq",
                    "pop {native_flags}",
                    recovery_descriptor!("2b", "3b", "."),
                    dest = in(reg) dest,
                    value = inout(reg) value,
                    carry = in(reg) flags,
                    native_flags = out(reg) native_flags,
                    out("rcx") result,
                    // Deliberately not `nostack`: pushfq/pop must not overwrite
                    // a compiler-owned red zone.
                );
            }
            if result != 0 {
                return Err(MemoryError::from_last_failure(
                    None, dest, usize::from(width),
                ).into());
            }
            (value, native_flags)
        }};
    }
    macro_rules! binary {
        ($opcode:literal) => {
            match width {
                1 => execute!(concat!($opcode, " byte ptr [{dest}], {value:l}")),
                2 => execute!(concat!($opcode, " word ptr [{dest}], {value:x}")),
                4 => execute!(concat!($opcode, " dword ptr [{dest}], {value:e}")),
                8 => execute!(concat!($opcode, " qword ptr [{dest}], {value:r}")),
                _ => return Err(AtomicError::InvalidWidth(width)),
            }
        };
    }
    macro_rules! unary {
        ($opcode:literal) => {
            match width {
                1 => execute!(concat!($opcode, " byte ptr [{dest}] /* {value} */")),
                2 => execute!(concat!($opcode, " word ptr [{dest}] /* {value} */")),
                4 => execute!(concat!($opcode, " dword ptr [{dest}] /* {value} */")),
                8 => execute!(concat!($opcode, " qword ptr [{dest}] /* {value} */")),
                _ => return Err(AtomicError::InvalidWidth(width)),
            }
        };
    }
    macro_rules! bit {
        ($opcode:literal) => {
            match width {
                2 => execute!(concat!($opcode, " word ptr [{dest}], {value:x}")),
                4 => execute!(concat!($opcode, " dword ptr [{dest}], {value:e}")),
                8 => execute!(concat!($opcode, " qword ptr [{dest}], {value:r}")),
                _ => return Err(AtomicError::ByteBitOperation),
            }
        };
    }

    let (value, native_flags) = match operation {
        AtomicOperation::Exchange => binary!("xchg"),
        AtomicOperation::FetchAdd => binary!("lock xadd"),
        AtomicOperation::Add => binary!("lock add"),
        AtomicOperation::Adc => binary!("lock adc"),
        AtomicOperation::Sub => binary!("lock sub"),
        AtomicOperation::Sbb => binary!("lock sbb"),
        AtomicOperation::And => binary!("lock and"),
        AtomicOperation::Or => binary!("lock or"),
        AtomicOperation::Xor => binary!("lock xor"),
        AtomicOperation::Inc => unary!("lock inc"),
        AtomicOperation::Dec => unary!("lock dec"),
        AtomicOperation::Neg => unary!("lock neg"),
        AtomicOperation::Not => unary!("lock not"),
        AtomicOperation::BitSet => bit!("lock bts"),
        AtomicOperation::BitReset => bit!("lock btr"),
        AtomicOperation::BitComplement => bit!("lock btc"),
    };
    let mask = match operation {
        AtomicOperation::Exchange | AtomicOperation::FetchAdd => {
            return Ok(AtomicResult::Value(value & (u64::MAX >> (64 - width * 8))));
        }
        AtomicOperation::Inc | AtomicOperation::Dec => 0x8d4,
        AtomicOperation::And | AtomicOperation::Or | AtomicOperation::Xor => 0x8c5,
        AtomicOperation::Not => 0,
        AtomicOperation::BitSet | AtomicOperation::BitReset | AtomicOperation::BitComplement => 1,
        _ => 0x8d5,
    };
    Ok(AtomicResult::Flags((flags & !mask) | (native_flags & mask)))
}

// xtask-fmt allow-target-arch cpu-intrinsic
#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::AtomicError;
    use super::AtomicOperation;
    use super::AtomicOperation::*;
    use super::AtomicResult;
    use super::try_atomic;
    use test_with_tracing::test;

    fn check(
        width: u8,
        operation: AtomicOperation,
        old: u64,
        source: u64,
        flags: u64,
        expected_memory: u64,
        expected_result: AtomicResult,
    ) {
        let sentinel = 0xa5a5_a5a5_a5a5_a5a5;
        let mask = u64::MAX >> (64 - width * 8);
        let mut memory = [sentinel; 3];
        memory[1] = (old & mask) | (sentinel & !mask);
        // SAFETY: the middle element is reserved, aligned, and exclusively
        // accessed through the raw pointer during this call.
        let result = unsafe {
            try_atomic(
                memory.as_mut_ptr().add(1).cast(),
                width,
                operation,
                source,
                flags,
            )
        }
        .unwrap();
        assert_eq!(result, expected_result, "{operation:?}, width {width}");
        assert_eq!(
            memory,
            [
                sentinel,
                (expected_memory & mask) | (sentinel & !mask),
                sentinel,
            ],
            "{operation:?}, width {width}",
        );
    }

    #[test]
    fn native_atomic_widths_and_flags() {
        for width in [1, 2, 4, 8] {
            let max = u64::MAX >> (64 - width * 8);
            for operation in [Exchange, FetchAdd] {
                check(
                    width,
                    operation,
                    max,
                    1,
                    0,
                    if operation == Exchange { 1 } else { 0 },
                    AtomicResult::Value(max),
                );
            }
            for flags in [0x202, u64::MAX] {
                let carry = flags & 1;
                let logical_af = flags & 0x10;
                for (operation, old, source, result, mask, defined_flags) in [
                    (Add, max, 1, 0, 0x8d5, 0x55),
                    (Adc, max, 1 - carry, 0, 0x8d5, 0x55),
                    (Sub, 0, 1, max, 0x8d5, 0x95),
                    (Sbb, 0, 1 - carry, max, 0x8d5, 0x95),
                    (And, max, 0, 0, 0x8d5, 0x44 | logical_af),
                    (Or, 0, 1, 1, 0x8d5, logical_af),
                    (Xor, max, max, 0, 0x8d5, 0x44 | logical_af),
                    (Inc, max, 0, 0, 0x8d4, 0x54),
                    (Dec, 0, 0, max, 0x8d4, 0x94),
                    (Neg, 1, 0, max, 0x8d5, 0x95),
                    (Not, 0, 0, max, 0, 0),
                    (
                        Add,
                        max >> 1,
                        1,
                        (max >> 1) + 1,
                        0x8d5,
                        if width == 1 { 0x890 } else { 0x894 },
                    ),
                ] {
                    check(
                        width,
                        operation,
                        old,
                        source,
                        flags,
                        result,
                        AtomicResult::Flags((flags & !mask) | defined_flags),
                    );
                }
                if width != 1 {
                    for (operation, old, result, carry) in [
                        (BitSet, 0, 2, 0),
                        (BitReset, 2, 0, 1),
                        (BitComplement, 2, 0, 1),
                    ] {
                        // A large index must not escape the selected operand.
                        check(
                            width,
                            operation,
                            old,
                            u64::MAX - u64::from(width) * 8 + 2,
                            flags,
                            result,
                            AtomicResult::Flags((flags & !1) | carry),
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn native_atomic_rejects_invalid_operands() {
        let mut memory = [0x5a5a_5a5a_5a5a_5a5au64; 2];
        let ptr = memory.as_mut_ptr().cast::<u8>();
        for width in [0, 3, 5, 16, 255] {
            // SAFETY: validation rejects the operand before accessing memory.
            let result = unsafe { try_atomic(ptr, width, Add, 1, 0) };
            assert!(matches!(result, Err(AtomicError::InvalidWidth(w)) if w == width));
        }
        for width in [2, 4, 8] {
            // SAFETY: validation rejects the unaligned reserved operand.
            let result = unsafe { try_atomic(ptr.add(1), width, Add, 1, 0) };
            assert!(matches!(result, Err(AtomicError::Unaligned)));
        }
        for operation in [BitSet, BitReset, BitComplement] {
            // SAFETY: validation rejects byte bit operations before access.
            let result = unsafe { try_atomic(ptr, 1, operation, 1, 0) };
            assert!(matches!(result, Err(AtomicError::ByteBitOperation)));
        }
        assert_eq!(memory, [0x5a5a_5a5a_5a5a_5a5a; 2]);
    }
}
