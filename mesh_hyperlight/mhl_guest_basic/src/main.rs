#![allow(unsafe_code)]
#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::vec::Vec;
use mhl_guest_infra::FunctionCall;
use mhl_guest_infra::HyperlightGuestError;

#[unsafe(no_mangle)]
pub extern "C" fn hyperlight_main() {
    mhl_guest_infra::guest_func!(add);
}

mhl_guest_infra::host_func!(
    fn log(message: &str) -> ();
);

fn add(params: mhl_common::Add) -> i32 {
    //log(&format!("add called: {}", params.log_annotation));
    params.a + params.b
}

#[unsafe(no_mangle)]
pub fn guest_dispatch_function(
    _function_call: FunctionCall,
) -> Result<Vec<u8>, HyperlightGuestError> {
    panic!()
}
