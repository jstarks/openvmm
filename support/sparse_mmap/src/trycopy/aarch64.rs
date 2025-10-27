#![cfg(target_arch = "aarch64")]

use super::Context;
use crate::AccessFailure;
use super::recover_descriptor;

const FAILURE_REG: usize = 3;

pub(super) fn extract(ctx: &Context) -> (usize, usize) {
    #[cfg(target_os = "linux")]
    {
        let mctx = &ctx.uc_mcontext;
        (mctx.pc as _, mctx.regs[FAILURE_REG] as _)
    }
    #[cfg(target_os = "macos")]
    {
        let mctx = unsafe { &*ctx.uc_mcontext };
        (mctx.__ss.__pc as _, mctx.__ss.__x[FAILURE_REG] as _)
    }
    #[cfg(windows)]
    {
        (ctx.Pc as _, unsafe { ctx.Anonymous.X[FAILURE_REG] as _ })
    }
}

pub(super) fn inject(ctx: &mut Context, ip: usize, result: Option<isize>) {
    #[cfg(target_os = "linux")]
    {
        let mctx = &mut ctx.uc_mcontext;
        mctx.pc = ip as _;
        if let Some(result) = result {
            mctx.regs[0] = result as _;
        }
    }
    #[cfg(target_os = "macos")]
    {
        let mctx = unsafe { &mut *ctx.uc_mcontext };
        mctx.__ss.__pc = ip as _;
        if let Some(result) = result {
            mctx.__ss.__x[0] = result as _;
        }
    }
    #[cfg(windows)]
    {
        ctx.Pc = ip as _;
        if let Some(result) = result {
            unsafe { ctx.Anonymous.X[0] = result as _ };
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
                1:
                ldrb {s1:w}, [{src}], #1
                subs {len}, {len}, #1
                strb {s1:w}, [{dest}], #1
                bne 1b
                2:",
                recover_descriptor!("1b", "2b", "{bail}", 0),
                dest = inout(reg) dest => _,
                src = inout(reg) src => _,
                len = inout(reg) length => _,
                s1 = out(reg) _,
                in("x3") failure,
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
                1:
                ldr {s1:x}, [{src}], #8
                subs {len}, {len}, #8
                str {s1:x}, [{dest}], #8
                bne 1b
                2:",
                recover_descriptor!("1b", "2b", "{bail}", 0),
                dest = inout(reg) dest => _,
                src = inout(reg) src => _,
                len = inout(reg) length => _,
                s1 = out(reg) _,
                in("x3") failure,
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
                1:
                ldr {s1:q}, [{src}], #16
                ldr {s2:q}, [{src}], #16
                subs {len}, {len}, #32
                str {s1:q}, [{dest}], #16
                str {s2:q}, [{dest}], #16
                bne 1b
                2:",
                recover_descriptor!("1b", "2b", "{bail}", 0),
                dest = inout(reg) dest => _,
                src = inout(reg) src => _,
                len = inout(reg) length => _,
                s1 = out(vreg) _,
                s2 = out(vreg) _,
                in("x3") failure,
                bail = label { return -1 },
                options(nostack),
            }
        }
        0
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
    if length >= 1 {
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
    unsafe {
        core::arch::asm! {
            "
            cbz {len}, 2f
            sub {dest}, {dest}, #1
            sub {src}, {src}, #1
            1:
            ldrb {s1:w}, [{src}, {len}]
            strb {s1:w}, [{dest}, {len}]
            subs {len}, {len}, #1
            bne 1b
            2:
            ",
            recover_descriptor!("1b", "2b", "{bail}", 0),
            dest = inout(reg) dest => _,
            src = inout(reg) src => _,
            len = inout(reg) length => _,
            s1 = out(reg) _,
            in("x3") failure,
            bail = label { return -1 },
            options(nostack),
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
    mut dest: *mut u8,
    c: i32,
    mut length: usize,
    failure: *mut AccessFailure,
) -> i32 {
    fn set1(dest: *mut u8, c: i32, length: usize, failure: *mut AccessFailure) -> i32 {
        unsafe {
            core::arch::asm! {
                "
                1:
                strb {c:w}, [{dest}], #1
                subs {len}, {len}, #1
                bne 1b
                2:",
                recover_descriptor!("1b", "2b", "{bail}", 0),
                dest = inout(reg) dest => _,
                c = in(reg) c,
                len = inout(reg) length => _,
                in("x3") failure,
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
                1:
                str {c:x}, [{dest}], #8
                subs {len}, {len}, #8
                bne 1b
                2:",
                recover_descriptor!("1b", "2b", "{bail}", 0),
                dest = inout(reg) dest => _,
                c = in(reg) (c as u64 & 0xff) * 0x0101010101010101,
                len = inout(reg) length => _,
                in("x3") failure,
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
                1:
                str {zero:q}, [{dest}], #16
                str {zero:q}, [{dest}], #16
                subs {len}, {len}, #32
                bne 1b
                2:",
                recover_descriptor!("1b", "2b", "{bail}", 0),
                dest = inout(reg) dest => _,
                zero = in(vreg) 0,
                len = inout(reg) length => _,
                in("x3") failure,
                bail = label { return -1 },
                options(nostack),
            }
        }
        0
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
    if length >= 1 {
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
                    "1:",
                    $asm,
                    "mov w0, wzr",
                    "2:",
                    recover_descriptor!("1b", "2b", "2b", 1),
                    out = out(reg) out,
                    src = in(reg) src,
                    in("x3") failure,
                    lateout("x0") result,
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

try_read!(pub(crate) try_read8, u8, "ldrb {out:w}, [{src}]");
try_read!(pub(crate) try_read16, u16, "ldrh {out:w}, [{src}]");
try_read!(pub(crate) try_read32, u32, "ldr {out:w}, [{src}]");
try_read!(pub(crate) try_read64, u64, "ldr {out}, [{src}]");

macro_rules! try_write {
    ($vis:vis $func:ident, $ty:ty, $asm:expr) => {
        $vis unsafe fn $func(dest: *mut $ty, val: $ty, failure: *mut AccessFailure) -> i32 {
            unsafe {
                core::arch::asm!(
                    "1:",
                    $asm,
                    "2:",
                    recover_descriptor!("1b", "2b", "{bail}", 0),
                    dest = in(reg) dest,
                    val = in(reg) val as u64,
                    in("x3") failure,
                    bail = label { return -1 },
                    options(nostack),
                )
            }
        }
    };
}

try_write!(pub(crate) try_write8, u8, "strb {val:w}, [{dest}]");
try_write!(pub(crate) try_write16, u16, "strh {val:w}, [{dest}]");
try_write!(pub(crate) try_write32, u32, "str {val:w}, [{dest}]");
try_write!(pub(crate) try_write64, u64, "str {val}, [{dest}]");

macro_rules! try_cmpxchg {
    ($vis:vis $func:ident, $ty:ty, $asm:expr) => {
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
                    "1:",
                    $asm,
                    "mov w0, wzr",
                    "2:",
                    recover_descriptor!("1b", "2b", "2b", 1),
                    dest = in(reg) dest,
                    desired = in(reg) desired,
                    expected = inout(reg) *expected => actual,
                    in("x3") failure,
                    lateout("x0") result,
                    options(nostack),
                }
            };
            if result == 0 {
                if *expected == actual {
                    1
                } else {
                    *expected = actual;
                    0
                }
            } else {
                -1
            }
        }
    }
}

try_cmpxchg!(pub(crate) try_cmpxchg8, u8, "casalb {expected:w}, {desired:w}, [{dest}]");
try_cmpxchg!(pub(crate) try_cmpxchg16, u16, "casalh {expected:w}, {desired:w}, [{dest}]");
try_cmpxchg!(pub(crate) try_cmpxchg32, u32, "casal {expected:w}, {desired:w}, [{dest}]");
try_cmpxchg!(pub(crate) try_cmpxchg64, u64, "casal {expected}, {desired}, [{dest}]");
