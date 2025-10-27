#![cfg(target_arch = "aarch64")]

use super::Context;
use crate::AccessFailure;

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

pub(super) fn inject(ctx: &mut Context, ip: usize, result: isize) {
    #[cfg(target_os = "linux")]
    {
        let mctx = &mut ctx.uc_mcontext;
        mctx.pc = ip as _;
        mctx.regs[0] = result as _;
    }
    #[cfg(target_os = "macos")]
    {
        let mctx = unsafe { &mut *ctx.uc_mcontext };
        mctx.__ss.__pc = ip as _;
        mctx.__ss.__x[0] = result as _;
    }
    #[cfg(windows)]
    {
        ctx.Pc = ip as _;
        unsafe { ctx.Anonymous.X[0] = result as _ };
    }
}

macro_rules! asm_recover {
    ($failure:expr, [$($asm:expr),* $(,)?], [$($postasm:expr),*  $(,)?], $($rest:tt)*) => {
        {
            let recover_result: i32;
            core::arch::asm! {
                "2000:",
                $($asm,)*
                "2001:",
                $($postasm,)*
                super::recover_descriptor!("2000b", "2001b"),
                in("x3") $failure,
                lateout("x0") recover_result,
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
            ["
            cbz {len}, 2f
            1:
            ldrb {s1:w}, [{src}], #1
            subs {len}, {len}, #1
            strb {s1:w}, [{dest}], #1
            bne 1b
            mov w0, wzr
            2:
            "],
            [],
            dest = inout(reg) dest => _,
            src = inout(reg) src => _,
            len = inout(reg) length => _,
            s1 = out(reg) _,
            options(nostack),
        }
    }
}

unsafe fn try_copy_backward(
    dest: *mut u8,
    src: *const u8,
    length: usize,
    failure: *mut AccessFailure,
) -> i32 {
    unsafe {
        asm_recover! {
            failure,
            ["
            cbz {len}, 2f
            sub {dest}, {dest}, #1
            sub {src}, {src}, #1
            1:
            ldrb {s1:w}, [{src}, {len}]
            strb {s1:w}, [{dest}, {len}]
            subs {len}, {len}, #1
            bne 1b
            mov w0, wzr
            2:
            "],
            [],
            dest = inout(reg) dest => _,
            src = inout(reg) src => _,
            len = inout(reg) length => _,
            s1 = out(reg) _,
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
    dest: *mut u8,
    c: i32,
    length: usize,
    failure: *mut AccessFailure,
) -> i32 {
    unsafe {
        asm_recover! {
            failure,
            [
            "
            cbz {len}, 2f
            1:
            strb {c:w}, [{dest}], #1
            subs {len}, {len}, #1
            bne 1b
            mov w0, wzr
            2:
            ret
            ",
            ],
            [],
            dest = inout(reg) dest => _,
            c = in(reg) c,
            len = inout(reg) length => _,
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
                    [$asm, "mov w0, wzr"],
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

try_read!(pub(crate) try_read8, u8, "ldrb {out:w}, [{src}]");
try_read!(pub(crate) try_read16, u16, "ldrh {out:w}, [{src}]");
try_read!(pub(crate) try_read32, u32, "ldr {out:w}, [{src}]");
try_read!(pub(crate) try_read64, u64, "ldr {out}, [{src}]");

macro_rules! try_write {
    ($vis:vis $func:ident, $ty:ty, $asm:expr) => {
        $vis unsafe fn $func(dest: *mut $ty, val: $ty, failure: *mut AccessFailure) -> i32 {
            unsafe {
                asm_recover!(
                    failure,
                    [$asm, "mov w0, wzr"],
                    [],
                    dest = in(reg) dest,
                    val = in(reg) val as u64,
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
            let result = unsafe {
                asm_recover! {
                    failure,
                    [$asm, "mov w0, wzr"],
                    [],
                    dest = in(reg) dest,
                    desired = in(reg) desired,
                    expected = inout(reg) *expected => actual,
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
