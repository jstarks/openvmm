// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Optional independent interoperability coverage; no host filesystem share is used.

use futures::FutureExt;
use pal_async::DefaultPool;
use smb::{Server, memory::MemoryFs, provider::FileSystem};
use std::net::TcpListener;
use std::process::Command;
use test_with_tracing::test;

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_read_write_smoke() {
    let backend = MemoryFs::new(16 * 1024 * 1024, 4096);
    #[cfg(feature = "test-support")]
    let (backend, _control) = smb::test_support::ControlledFs::new(backend);
    run_torture(
        backend,
        std::future::pending(),
        &[
            "smb2.connect",
            "smb2.tcon",
            "smb2.rw.rw1",
            "smb2.rw.rw2",
            "smb2.read.eof",
            "smb2.read.position",
            "smb2.read.dir",
            "smb2.read.access",
            "smb2.create.open",
            "smb2.mkdir",
            "smb2.compound.create-write-close",
            "smb2.compound.related5",
            "smb2.compound_find.compound_find_related",
            "smb2.compound_find.compound_find_unrelated",
        ],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_notify() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096),
        std::future::pending(),
        &[
            "smb2.notify.close",
            "smb2.notify.file",
            "smb2.notify.tdis1",
            "smb2.notify.logoff",
            "smb2.notify.handle-permissions",
            "smb2.notify.basedir",
        ],
    );
}

#[test]
#[ignore = "requires corrected Samba smbtorture; set SMBTORTURE to its executable"]
fn samba_notify_corrected_client() {
    assert!(
        std::env::var_os("SMBTORTURE").is_some(),
        "set SMBTORTURE to a Samba client with corrected pre-interim CANCEL identities"
    );
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096),
        std::future::pending(),
        &[
            "--num-ops=10",
            "smb2.notify.tcon",
            "smb2.notify.dir",
            "smb2.notify.tdis",
            "smb2.notify.double",
            "smb2.notify.tcp",
            "smb2.notify.overflow",
            "smb2.notify.rmdir1",
            "smb2.notify.rmdir2",
            "smb2.notify.rmdir3",
            "smb2.notify.rmdir4",
            "smb2.notify.mask-change",
        ],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_rename() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096),
        std::future::pending(),
        &[
            "smb2.rename.simple",
            "smb2.rename.simple_modtime",
            "smb2.rename.simple_nodelete",
            "smb2.rename.no_sharing",
            "smb2.rename.share_delete_no_delete_access",
            "smb2.rename.no_share_delete_no_delete_access",
            "smb2.rename.rename_dir_openfile",
        ],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_lock() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096),
        std::future::pending(),
        &[
            "smb2.lock.valid-request",
            "smb2.lock.rw-shared",
            "smb2.lock.rw-exclusive",
            "smb2.lock.auto-unlock",
            "smb2.lock.lock",
            "smb2.lock.async",
            "smb2.lock.errorcode",
            "smb2.lock.zerobytelength",
            "smb2.lock.zerobyteread",
            "smb2.lock.unlock",
            "smb2.lock.multiple-unlock",
            "smb2.lock.stacking",
            "smb2.lock.contend",
            "smb2.lock.context",
            "smb2.lock.range",
            "smb2.lock.overlap",
            "smb2.lock.truncate",
        ],
    );
}

#[cfg(feature = "test-support")]
#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_gated_async_compounds() {
    use smb::test_support::{ControlledFs, Gate, Operation, Phase, Plan};
    let (backend, control) = ControlledFs::new(MemoryFs::new(16 * 1024 * 1024, 4096));
    for operation in [Operation::Read, Operation::Write, Operation::Flush] {
        control
            .set_plan(
                operation,
                Plan {
                    hold_before: true,
                    ..Plan::default()
                },
            )
            .unwrap();
    }
    let driver = control.clone();
    // The gate controller shares the server's poller, rather than racing an I/O thread.
    let controller = async move {
        loop {
            let call = driver.next_call().await;
            driver.release(call.id, Gate::Before).unwrap();
        }
    };
    run_torture(
        backend,
        controller,
        &[
            "--option=torture:smbd=true",
            "smb2.compound_async.flush_close",
            "smb2.compound_async.flush_flush",
            "smb2.compound_async.write_write",
            "smb2.compound_async.read_read",
        ],
    );
    assert!(
        control
            .calls()
            .iter()
            .any(|call| call.operation == Operation::Write && call.delegated)
    );
    assert!(
        !control
            .calls()
            .iter()
            .any(|call| call.phase == Phase::Abandoned)
    );
}

fn run_torture(
    backend: impl FileSystem,
    controller: impl Future<Output = ()> + Send + 'static,
    suites: &[&str],
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let server = Server::new("memory", backend).unwrap();
    let (stop, stopped) = async_channel::bounded::<()>(1);
    let worker = std::thread::spawn(move || {
        DefaultPool::run_with(async |driver| -> Result<(), smb::Error> {
            let mut service = smb::tcp::Server::new(driver, listener, server)?;
            service.start();
            let mut controller = std::pin::pin!(controller.fuse());
            let mut stopped = std::pin::pin!(stopped.recv().fuse());
            futures::select! {
                () = controller => panic!("test controller unexpectedly completed"),
                result = stopped => { result.unwrap(); }
            }
            service.shutdown().await
        })
    });
    let executable = std::env::var_os("SMBTORTURE").unwrap_or_else(|| "smbtorture".into());
    let result = Command::new(executable)
        .args([
            "//127.0.0.1/memory",
            "-p",
            &port,
            "-U%",
            "--configfile=/dev/null",
            "--use-kerberos=off",
            "--client-protection=off",
            "--option=client min protocol=SMB2_10",
            "--option=client max protocol=SMB2_10",
            "--option=torture:windows=true",
            "--seed=12345",
            "--num-ops=32",
            "--maximum-runtime=90",
        ])
        .args(suites)
        .status();
    stop.send_blocking(()).unwrap();
    worker.join().unwrap().unwrap();
    assert!(
        result
            .expect("install samba-testsuite to run this test")
            .success()
    );
}
