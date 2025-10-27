mod aarch64;
mod x86_64;

// xtask-fmt allow-target-arch sys-crate
#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::*;
// xtask-fmt allow-target-arch sys-crate
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::*;

use crate::AccessFailure;

#[cfg(unix)]
type Context = libc::ucontext_t;
#[cfg(windows)]
type Context = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;

#[repr(C)]
struct RecoverDescriptor {
    start: i32,
    end: i32,
    recover: i32,
    set_result: i32,
}

unsafe fn recover(context: &mut Context, failure: AccessFailure) -> bool {
    #[cfg(target_os = "linux")]
    unsafe extern "C" {
        #[link_name = "__start_try_copy"]
        static START_TRY_COPY: [RecoverDescriptor; 0];
        #[link_name = "__stop_try_copy"]
        static STOP_TRY_COPY: [RecoverDescriptor; 0];
    }

    #[cfg(target_os = "macos")]
    unsafe extern "C" {
        #[link_name = "\x01section$start$__DATA$__try_copy"]
        static START_TRY_COPY: [RecoverDescriptor; 0];
        #[link_name = "\x01section$end$__DATA$__try_copy"]
        static STOP_TRY_COPY: [RecoverDescriptor; 0];
    }

    #[cfg(windows)]
    #[unsafe(link_section = ".rdata.trycopy@a")]
    static START_TRY_COPY: [RecoverDescriptor; 0] = [];
    #[cfg(windows)]
    #[unsafe(link_section = ".rdata.trycopy@c")]
    static STOP_TRY_COPY: [RecoverDescriptor; 0] = [];

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
        let reloc = |addr: &i32| -> usize {
            core::ptr::from_ref(addr).addr().wrapping_add_signed(*addr as isize)
        };
        if ip >= reloc(&r.start) && ip < reloc(&r.end) {
            // Write the recovery info.
            unsafe { (failure_ptr as *mut AccessFailure).write(failure) };

            // Adjust the instruction pointer to the recovery address and write
            // the failure code.
            inject(context, reloc(&r.recover), (r.set_result != 0).then_some(-1));
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
    ($start:tt, $stop:tt, $recover:tt, $set_result:tt) => {
        concat!(
            ".pushsection try_copy,\"a\"\n",
            ".align 4\n",
            ".long ",
            $start,
            " - .\n",
            ".long ",
            $stop,
            " - .\n",
            ".long ",
            $recover,
            " - .\n",
            ".long ",
            $set_result,
            "\n",
            ".popsection"
        )
    };
}

#[cfg(target_os = "windows")]
macro_rules! recover_descriptor {
    ($start:tt, $stop:tt, $recover:tt, $set_result:tt) => {
        concat!(
            ".pushsection .rdata.trycopy@b,\"dr\"\n",
            ".align 4\n",
            ".long ",
            $start,
            " - .\n",
            ".long ",
            $stop,
            " - .\n",
            ".long ",
            $recover,
            " - .\n",
            ".long ",
            $set_result,
            "\n",
            ".popsection"
        )
    };
}

#[cfg(target_os = "macos")]
macro_rules! recover_descriptor {
    ($start:tt, $stop:tt, $recover:tt, $set_result:tt) => {
        concat!(
            ".section __DATA,__try_copy,regular,no_dead_strip\n",
            ".align 4\n",
            ".long ",
            $start,
            " - .\n",
            ".long ",
            $stop,
            " - .\n",
            ".long ",
            $recover,
            " - .\n",
            ".long ",
            $set_result,
            "\n",
            ".previous"
        )
    };
}

use recover_descriptor;
