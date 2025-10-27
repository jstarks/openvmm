// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// xtask-fmt allow-target-arch sys-crate
#![cfg(target_arch = "x86_64")]

use super::Context;
use super::recover_descriptor;
use crate::AccessFailure;

pub(super) fn extract(ctx: &Context) -> (usize, usize) {
    #[cfg(target_os = "linux")]
    {
        let mctx = &ctx.uc_mcontext;
        (
            mctx.gregs[libc::REG_RIP as usize] as _,
            mctx.gregs[libc::REG_RDX as usize] as _,
        )
    }
    #[cfg(target_os = "macos")]
    {
        let mctx = unsafe { &*ctx.uc_mcontext };
        (mctx.__ss.__rip as _, mctx.__ss.__rdx as _)
    }
    #[cfg(target_os = "windows")]
    {
        (ctx.Rip as _, ctx.Rdx as _)
    }
}

pub(super) fn inject(ctx: &mut Context, ip: usize, result: Option<isize>) {
    #[cfg(target_os = "linux")]
    {
        let mctx = &mut ctx.uc_mcontext;
        mctx.gregs[libc::REG_RIP as usize] = ip as _;
        if let Some(result) = result {
            mctx.gregs[libc::REG_RCX as usize] = result as _;
        }
    }
    #[cfg(target_os = "windows")]
    {
        ctx.Rip = ip as _;
        if let Some(result) = result {
            ctx.Rcx = result as _;
        }
    }
}

unsafe fn try_copy_forward(
    mut dest: *mut u8,
    mut src: *const u8,
    mut length: usize,
    failure: *mut AccessFailure,
) -> i32 {
    fn copy1(dest: *mut u8, src: *const u8, length: usize, failure: *mut AccessFailure) -> i32 {
        unsafe {
            core::arch::asm! {
                "
                2:
                mov {s1}, byte ptr [{src} + {i}]
                mov byte ptr [{dest} + {i}], {s1}
                inc {i}
                cmp {i}, {len}
                jne 2b
                3:
                ",
                recover_descriptor!("2b", "3b", "{bail}", 0),
                s1 = out(reg_byte) _,
                i = inout(reg) 0u64 => _,
                src = in(reg) src,
                dest = in(reg) dest,
                len = in(reg) length,
                in("rdx") failure,
                bail = label { return -1 },
                options(nostack),
            }
        }
        0
    }

    fn copy8(dest: *mut u8, src: *const u8, length: usize, failure: *mut AccessFailure) -> i32 {
        unsafe {
            core::arch::asm! {
                "
                2:
                mov {s1}, qword ptr [{src} + {i}]
                mov qword ptr [{dest} + {i}], {s1}
                add {i}, 8
                cmp {i}, {len}
                jne 2b
                3:
                ",
                recover_descriptor!("2b", "3b", "{bail}", 0),
                s1 = out(reg) _,
                i = inout(reg) 0u64 => _,
                src = in(reg) src,
                dest = in(reg) dest,
                len = in(reg) length,
                in("rdx") failure,
                bail = label { return -1 },
                options(nostack),
            }
        }
        0
    }

    fn copy32(dest: *mut u8, src: *const u8, length: usize, failure: *mut AccessFailure) -> i32 {
        unsafe {
            core::arch::asm! {
                "
                2:
                movdqu {s1}, xmmword ptr [{src} + {i}]
                movdqu {s2}, xmmword ptr [{src} + {i} + 16]
                movdqu xmmword ptr [{dest} + {i}], {s1}
                movdqu xmmword ptr [{dest} + {i} + 16], {s2}
                add {i}, 32
                cmp {i}, {len}
                jne 2b
                3:
                ",
                recover_descriptor!("2b", "3f", "{bail}", 0),
                s1 = out(xmm_reg) _,
                s2 = out(xmm_reg) _,
                i = inout(reg) 0u64 => _,
                src = in(reg) src,
                dest = in(reg) dest,
                len = in(reg) length,
                in("rdx") failure,
                bail = label { return -1 },
                options(nostack),
            }
        }
        0
    }

    fn copy_movsb(
        dest: *mut u8,
        src: *const u8,
        length: usize,
        failure: *mut AccessFailure,
    ) -> i32 {
        unsafe {
            core::arch::asm! {
                "2:",
                "rep movsb",
                "3:",
                recover_descriptor!("2b", "3b", "{bail}", 0),
                in("rdi") dest,
                in("rsi") src,
                in("rcx") length,
                in("rdx") failure,
                bail = label { return -1 },
                options(nostack),
            }
        }
        0
    }

    if length >= 1024 {
        return copy_movsb(dest, src, length, failure);
    }
    if length >= 32 {
        let this = length & !31;
        if copy32(dest, src, this, failure) < 0 {
            return -1;
        }
        dest = dest.wrapping_add(this);
        src = src.wrapping_add(this);
        length &= 31;
    }
    if length >= 8 {
        let this = length & !7;
        if copy8(dest, src, this, failure) < 0 {
            return -1;
        }
        dest = dest.wrapping_add(this);
        src = src.wrapping_add(this);
        length &= 7;
    }
    if length > 0 {
        copy1(dest, src, length, failure)
    } else {
        0
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
        core::arch::asm! {
            "2:",
            "std",
            "rep movsb",
            "3:",
            "cld",
            recover_descriptor!("2b", "3b", "{bail}", 0),
            in("rdi") dest.add(length - 1),
            in("rsi") src.add(length - 1),
            in("rcx") length,
            in("rdx") failure,
            bail = label { return -1 },
            options(nostack),
        }
    }
    0
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
    mut dest: *mut u8,
    c: i32,
    mut length: usize,
    failure: *mut AccessFailure,
) -> i32 {
    fn set_stosb(dest: *mut u8, c: i32, length: usize, failure: *mut AccessFailure) -> i32 {
        unsafe {
            core::arch::asm! {
                "2:",
                "rep stosb",
                "3:",
                recover_descriptor!("2b", "3b", "{bail}", 0),
                in("rdi") dest,
                in("al") c as u8,
                in("rcx") length,
                in("rdx") failure,
                bail = label { return -1 },
                options(nostack),
            }
        }
        0
    }

    fn set1(dest: *mut u8, c: i32, length: usize, failure: *mut AccessFailure) -> i32 {
        unsafe {
            core::arch::asm! {
                "
                2:
                mov byte ptr [{dest} + {i}], {c:l}
                inc {i}
                cmp {i}, {len}
                jne 2b
                3:
                ",
                recover_descriptor!("2b", "3b", "{bail}", 0),
                c = in(reg) c,
                i = inout(reg) 0u64 => _,
                dest = in(reg) dest,
                len = in(reg) length,
                in("rdx") failure,
                bail = label { return -1 },
                options(nostack),
            }
        }
        0
    }

    fn set8(dest: *mut u8, c: i32, length: usize, failure: *mut AccessFailure) -> i32 {
        unsafe {
            core::arch::asm! {
                "
                2:
                mov qword ptr [{dest} + {i}], {c}
                add {i}, 8
                cmp {i}, {len}
                jne 2b
                3:
                ",
                recover_descriptor!("2b", "3b", "{bail}", 0),
                c = in(reg) (c & 0xff) as u64 * 0x0101010101010101,
                i = inout(reg) 0u64 => _,
                dest = in(reg) dest,
                len = in(reg) length,
                in("rdx") failure,
                bail = label { return -1 },
                options(nostack),
            }
        }
        0
    }

    fn set32_zero(dest: *mut u8, length: usize, failure: *mut AccessFailure) -> i32 {
        unsafe {
            core::arch::asm! {
                "
                2:
                movdqu xmmword ptr [{dest} + {i}], {c}
                movdqu xmmword ptr [{dest} + {i} + 16], {c}
                add {i}, 32
                cmp {i}, {len}
                jne 2b
                3:
                ",
                recover_descriptor!("2b", "3b", "{bail}", 0),
                c = in(xmm_reg) 0,
                i = inout(reg) 0u64 => _,
                dest = in(reg) dest,
                len = in(reg) length,
                in("rdx") failure,
                bail = label { return -1 },
                options(nostack),
            }
        }
        0
    }

    if length >= 1024 {
        return set_stosb(dest, c, length, failure);
    }
    if c == 0 && length >= 32 {
        let this = length & !31;
        if set32_zero(dest, this, failure) < 0 {
            return -1;
        }
        dest = dest.wrapping_add(this);
        length &= 31;
    }
    if length >= 8 {
        let this = length & !7;
        if set8(dest, c, this, failure) < 0 {
            return -1;
        }
        dest = dest.wrapping_add(this);
        length &= 7;
    }
    if length > 0 {
        set1(dest, c, length, failure)
    } else {
        0
    }
}

macro_rules! try_read {
    ($vis:vis $func:ident, $ty:ty, $asm:expr) => {
        $vis unsafe fn $func(dest: *mut $ty, src: *const $ty, failure: *mut AccessFailure) -> i32 {
            unsafe {
                let out: u64;
                let result;
                core::arch::asm!(
                    "2:",
                    $asm,
                    "xor ecx, ecx",
                    "3:",
                    recover_descriptor!("2b", "3b", "3b", 1),
                    out = out(reg) out,
                    src = in(reg) src,
                    in("rdx") failure,
                    lateout("rcx") result,
                    options(nostack, readonly),
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
                core::arch::asm!(
                    "2:",
                    $asm,
                    "3:",
                    recover_descriptor!("2b", "3b", "{bail}", 0),
                    dest = in(reg) dest,
                    val = in(reg) val as u64,
                    in("rdx") failure,
                    bail = label { return -1 },
                    options(nostack, preserves_flags),
                )
            }
            0
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
            let result;
            unsafe {
                core::arch::asm! {
                    "2:",
                    $asm,
                    "setz cl",
                    "movzx ecx, cl",
                    "3:",
                    recover_descriptor!("2b", "3b", "3b", 1),
                    dest = in(reg) dest,
                    desired = in($reg_kind) desired,
                    inout($ax) *expected => actual,
                    in("rdx") failure,
                    lateout("rcx") result,
                    options(nostack),
                }
            };
            if result == 0 {
                *expected = actual;
            }
            result
        }
    };
}

try_cmpxchg!(pub(crate) try_cmpxchg8, u8, "al", reg_byte, "cmpxchg byte ptr [{dest}], {desired}");
try_cmpxchg!(pub(crate) try_cmpxchg16, u16, "ax", reg, "cmpxchg word ptr [{dest}], {desired:x}");
try_cmpxchg!(pub(crate) try_cmpxchg32, u32, "eax", reg, "cmpxchg dword ptr [{dest}], {desired:e}");
try_cmpxchg!(pub(crate) try_cmpxchg64, u64, "rax", reg, "cmpxchg qword ptr [{dest}], {desired}");
