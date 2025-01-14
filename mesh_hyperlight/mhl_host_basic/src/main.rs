use hyperlight_host::sandbox::uninitialized::UninitializedSandbox;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::GuestBinary;
use hyperlight_host::MultiUseSandbox;
use mhl_host_infra::call_guest_function;
use mhl_host_infra::register_host_function;

fn main() -> anyhow::Result<()> {
    let guest_path = "target/x86_64-unknown-none/debug/mhl_guest_basic";

    let mut usandbox = UninitializedSandbox::new(
        GuestBinary::FilePath(guest_path.to_owned()),
        None,
        None,
        None,
    )?;

    register_host_function(&mut usandbox, "log", |(message,): (String,)| {
        println!("log: {}", message);
    })?;

    let mut sbox = usandbox.evolve(Noop::<UninitializedSandbox, MultiUseSandbox>::default())?;
    let r: i32 = call_guest_function(
        &mut sbox,
        "add",
        mhl_common::Add {
            a: 1,
            b: 2,
            log_annotation: "hello".to_string(),
        },
    )?;
    println!("result: {}", r);
    Ok(())
}
