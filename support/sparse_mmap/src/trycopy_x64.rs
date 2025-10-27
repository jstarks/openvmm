// xtask-fmt allow-target-arch sys-crate

#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::*;
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::*;

use crate::AccessFailure;

#[cfg(unix)]
type Context = libc::ucontext_t;
#[cfg(windows)]
type Context = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;

#[repr(C)]
struct Recover {
    start: i32,
    end: i32,
}

unsafe fn recover(context: &mut Context, failure: AccessFailure) -> bool {
    #[cfg(target_os = "linux")]
    unsafe extern "C" {
        #[link_name = "__start_try_copy"]
        static START_TRY_COPY: [Recover; 0];
        #[link_name = "__stop_try_copy"]
        static STOP_TRY_COPY: [Recover; 0];
    }

    #[cfg(target_os = "macos")]
    unsafe extern "C" {
        #[link_name = "\x01section$start$__DATA$__try_copy"]
        static START_TRY_COPY: [Recover; 0];
        #[link_name = "\x01section$end$__DATA$__try_copy"]
        static STOP_TRY_COPY: [Recover; 0];
    }

    #[cfg(windows)]
    #[unsafe(link_section = ".rdata.trycopy@a")]
    static START_TRY_COPY: [Recover; 0] = [];
    #[cfg(windows)]
    #[unsafe(link_section = ".rdata.trycopy@c")]
    static STOP_TRY_COPY: [Recover; 0] = [];

    let table = unsafe {
        std::slice::from_raw_parts(
            START_TRY_COPY.as_ptr(),
            STOP_TRY_COPY
                .as_ptr()
                .offset_from_unsigned(START_TRY_COPY.as_ptr()),
        )
    };

    let (ip, failure_ptr) = extract(context);

    for r in table {
        let start = ((&raw const r.start) as usize).wrapping_add_signed(r.start as isize);
        let end = ((&raw const r.end) as usize).wrapping_add_signed(r.end as isize);
        if ip >= start && ip < end {
            // Write the recovery info.
            unsafe { (failure_ptr as *mut AccessFailure).write(failure) };

            // Adjust the instruction pointer to the recovery address and write
            // the failure code.
            inject(context, end, -1);
            return true;
        }
    }
    false
}

#[cfg(unix)]
pub(crate) unsafe fn install_signal_handlers() {
    fn handle_signal(sig: i32, info: &libc::siginfo_t, ucontext: &mut libc::ucontext_t) {
        let failure = AccessFailure {
            address: unsafe { info.si_addr().cast() },
            si_signo: sig,
            si_code: info.si_code,
        };
        let recovered = unsafe { recover(ucontext, failure) };
        if !recovered {
            unsafe { libc::raise(sig) };
            std::process::abort();
        }
    }

    unsafe {
        let act = libc::sigaction {
            sa_sigaction: handle_signal as usize,
            sa_flags: libc::SA_SIGINFO,
            ..core::mem::zeroed()
        };
        for signal in [libc::SIGSEGV, libc::SIGBUS] {
            libc::sigaction(signal, &act, std::ptr::null_mut());
        }
    }
}

#[cfg(windows)]
pub(crate) unsafe fn install_signal_handlers() {
    use windows_sys::Win32::Foundation::EXCEPTION_ACCESS_VIOLATION;
    use windows_sys::Win32::System::Diagnostics::Debug::AddVectoredExceptionHandler;
    use windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_EXECUTION;
    use windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_SEARCH;
    use windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS;

    extern "system" fn exception_handler(pointers: *mut EXCEPTION_POINTERS) -> i32 {
        let pointers = unsafe { &*pointers };
        let record = unsafe { &*pointers.ExceptionRecord };
        let context = unsafe { &mut *pointers.ContextRecord };
        if record.ExceptionCode != EXCEPTION_ACCESS_VIOLATION {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        let failure = AccessFailure {
            address: record.ExceptionInformation[1] as *mut u8,
        };
        let recovered = unsafe { recover(context, failure) };
        if recovered {
            EXCEPTION_CONTINUE_EXECUTION
        } else {
            EXCEPTION_CONTINUE_SEARCH
        }
    }

    let handle = unsafe { AddVectoredExceptionHandler(1, Some(exception_handler)) };
    if handle.is_null() {
        panic!("could not install vectored exception handler");
    }
}

#[cfg(target_os = "linux")]
macro_rules! recover_descriptor {
    ($start:tt, $stop:tt) => {
        concat!(
            ".pushsection try_copy,\"a\"\n",
            ".align 4\n",
            ".long ",
            $start,
            " - .\n",
            ".long ",
            $stop,
            " - .\n",
            ".popsection"
        )
    };
}

#[cfg(target_os = "windows")]
macro_rules! recover_descriptor {
    ($start:tt, $stop:tt) => {
        concat!(
            ".pushsection .rdata.trycopy@b,\"dr\"\n",
            ".align 4\n",
            ".long ",
            $start,
            " - .\n",
            ".long ",
            $stop,
            " - .\n",
            ".popsection"
        )
    };
}

#[cfg(target_os = "macos")]
macro_rules! recover_descriptor {
    ($start:tt, $stop:tt) => {
        concat!(
            ".section __DATA,__try_copy,regular,no_dead_strip\n",
            ".align 4\n",
            ".long ",
            $start,
            " - .\n",
            ".long ",
            $stop,
            " - .\n",
            ".previous"
        )
    };
}

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use crate::AccessFailure;

    #[cfg(target_os = "linux")]
    pub(super) fn extract(ctx: &libc::ucontext_t) -> (usize, usize) {
        let mctx = &ctx.uc_mcontext;
        (
            mctx.gregs[libc::REG_RIP as usize] as _,
            mctx.gregs[libc::REG_RDX as usize] as _,
        )
    }

    #[cfg(target_os = "linux")]
    pub(super) fn inject(ctx: &mut libc::ucontext_t, ip: usize, result: isize) {
        let mctx = &mut ctx.uc_mcontext;
        mctx.gregs[libc::REG_RIP as usize] = ip as _;
        mctx.gregs[libc::REG_RCX as usize] = result as _;
    }

    #[cfg(windows)]
    pub(super) fn extract(
        ctx: &windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
    ) -> (usize, usize) {
        (ctx.Rip as _, ctx.Rdx as _)
    }

    #[cfg(windows)]
    pub(super) fn inject(
        ctx: &mut windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
        ip: usize,
        result: isize,
    ) {
        ctx.Rip = ip as _;
        ctx.Rcx = result as _;
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
                recover_descriptor!("2000b", "2001b"),
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
}

#[cfg(target_arch = "aarch64")]
mod aarch64 {
    use crate::AccessFailure;

    const FAILURE_REG: usize = 3;

    #[cfg(target_os = "linux")]
    pub(super) fn extract(ctx: &libc::ucontext_t) -> (usize, usize) {
        let mctx = &ctx.uc_mcontext;
        (mctx.pc as _, mctx.regs[FAILURE_REG] as _)
    }
    #[cfg(target_os = "linux")]
    pub(super) fn inject(ctx: &mut libc::ucontext_t, ip: usize, result: isize) {
        let mctx = &mut ctx.uc_mcontext;
        mctx.pc = ip as _;
        mctx.regs[0] = result as _;
    }

    #[cfg(target_os = "macos")]
    pub(super) fn extract(ctx: &libc::ucontext_t) -> (usize, usize) {
        let mctx = unsafe { &*ctx.uc_mcontext };
        (mctx.__ss.__pc as _, mctx.__ss.__x[FAILURE_REG] as _)
    }
    #[cfg(target_os = "macos")]
    pub(super) fn inject(ctx: &mut libc::ucontext_t, ip: usize, result: isize) {
        let mctx = unsafe { &mut *ctx.uc_mcontext };
        mctx.__ss.__pc = ip as _;
        mctx.__ss.__x[0] = result as _;
    }

    #[cfg(windows)]
    pub(super) fn extract(
        ctx: &windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
    ) -> (usize, usize) {
        (ctx.Pc as _, unsafe { ctx.Anonymous.X[FAILURE_REG] as _ })
    }

    #[cfg(windows)]
    pub(super) fn inject(
        ctx: &mut windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
        ip: usize,
        result: isize,
    ) {
        ctx.Pc = ip as _;
        unsafe { ctx.Anonymous.X[0] = result as _ };
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
                recover_descriptor!("2000b", "2001b"),
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
}
