// xtask-fmt allow-target-arch sys-crate
#![cfg(all(unix, target_arch = "x86_64"))]

use crate::AccessFailure;

macro_rules! asm_recover {
    ($failure:expr, [$($asm:expr),* $(,)?], [$($postasm:expr),*  $(,)?], $($rest:tt)*) => {
        {
            let recover_result: i32;
            core::arch::asm! {
                "2000:",
                $($asm,)*
                "2001:",
                $($postasm,)*
                ".pushsection _try_copy,\"a\"",
                ".quad 2000b - .",
                ".quad 2001b - .",
                ".popsection",
                in("rdx") $failure,
                lateout("rcx") recover_result,
                $($rest)*
            }
            recover_result
        }
    };
}

unsafe fn try_copy_forward(
    dest: *mut u8,
    src: *const u8,
    length: usize,
    failure: *mut AccessFailure,
) -> i32 {
    unsafe {
        asm_recover! {
            failure,
            ["rep movsb", "xor ecx, ecx"],
            [],
            in("rdi") dest,
            in("rsi") src,
            in("rcx") length,
        }
    }
}

unsafe fn try_copy_backward(
    dest: *mut u8,
    src: *const u8,
    length: usize,
    failure: *mut AccessFailure,
) -> i32 {
    // Note, `rep movsb` with the direction flag set is slow, but this path
    // should be rare.
    unsafe {
        asm_recover! {
            failure,
            ["std", "rep movsb", "xor ecx, ecx"],
            ["cld"],
            in("rdi") dest.add(length - 1),
            in("rsi") src.add(length - 1),
            in("rcx") length,
        }
    }
}

pub(crate) unsafe fn try_memmove(
    dest: *mut u8,
    src: *const u8,
    length: usize,
    failure: *mut AccessFailure,
) -> i32 {
    if (dest as usize).wrapping_sub(src as usize) >= length {
        unsafe { try_copy_forward(dest, src, length, failure) }
    } else {
        crate::cold_path();
        unsafe { try_copy_backward(dest, src, length, failure) }
    }
}

pub(crate) unsafe fn try_memset(
    dest: *mut u8,
    c: i32,
    length: usize,
    failure: *mut AccessFailure,
) -> i32 {
    unsafe {
        asm_recover! {
            failure,
            ["rep stosb", "xor ecx, ecx"],
            [],
            in("rdi") dest,
            in("al") c as u8,
            in("rcx") length,
            options(nostack),
        }
    }
}

macro_rules! try_read {
    ($vis:vis $func:ident, $ty:ty, $asm:expr) => {
        $vis unsafe fn $func(dest: *mut $ty, src: *const $ty, failure: *mut AccessFailure) -> i32 {
            unsafe {
                let out: u64;
                let result = asm_recover!(
                    failure,
                    [$asm, "xor ecx, ecx"],
                    [],
                    out = out(reg) out,
                    src = in(reg) src,
                    options(nostack),
                );
                if result == 0 {
                    dest.write(out as $ty);
                }
                result
            }
        }
    };
}

try_read!(pub(crate) try_read8, u8, "movzx {out:e}, byte ptr [{src}]");
try_read!(pub(crate) try_read16, u16, "movzx {out:e}, word ptr [{src}]");
try_read!(pub(crate) try_read32, u32, "mov {out:e}, dword ptr [{src}]");
try_read!(pub(crate) try_read64, u64, "mov {out}, qword ptr [{src}]");

macro_rules! try_write {
    ($vis:vis $func:ident, $ty:ty, $reg_kind:tt, $asm:expr) => {
        $vis unsafe fn $func(dest: *mut $ty, val: $ty, failure: *mut AccessFailure) -> i32 {
            unsafe {
                asm_recover!(
                    failure,
                    [$asm, "xor ecx, ecx"],
                    [],
                    dest = in(reg) dest,
                    val = in(reg) val as u64,
                    options(nostack),
                )
            }
        }
    };
}

try_write!(pub(crate) try_write8, u8, reg_byte, "mov byte ptr [{dest}], {val:l}");
try_write!(pub(crate) try_write16, u16, reg, "mov word ptr [{dest}], {val:x}");
try_write!(pub(crate) try_write32, u32, reg, "mov dword ptr [{dest}], {val:e}");
try_write!(pub(crate) try_write64, u64, reg, "mov qword ptr [{dest}], {val}");

macro_rules! try_cmpxchg {
    ($vis:vis $func:ident, $ty:ty, $ax:tt, $reg_kind:tt, $asm:expr) => {
        $vis unsafe fn $func(
            dest: *mut $ty,
            expected: &mut $ty,
            desired: $ty,
            failure: *mut AccessFailure,
        ) -> i32 {
            let actual;
            let result = unsafe {
                asm_recover! {
                    failure,
                    [$asm, "setz cl", "movzx ecx, cl"],
                    [],
                    dest = in(reg) dest,
                    desired = in($reg_kind) desired,
                    inout($ax) *expected => actual,
                }
            };
            if result == 0 {
                *expected = actual;
            }
            result
        }
    }
}

try_cmpxchg!(pub(crate) try_cmpxchg8, u8, "al", reg_byte, "cmpxchg byte ptr [{dest}], {desired}");
try_cmpxchg!(pub(crate) try_cmpxchg16, u16, "ax", reg, "cmpxchg word ptr [{dest}], {desired:x}");
try_cmpxchg!(pub(crate) try_cmpxchg32, u32, "eax", reg, "cmpxchg dword ptr [{dest}], {desired:e}");
try_cmpxchg!(pub(crate) try_cmpxchg64, u64, "rax", reg, "cmpxchg qword ptr [{dest}], {desired}");
