// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Optional independent interoperability coverage; no host filesystem share is used.

use pal_async::DefaultPool;
use smb::{Server, memory::MemoryFs};
use std::net::TcpListener;
use std::process::Command;
use test_with_tracing::test;

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_read_write_smoke() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let backend = MemoryFs::new(16 * 1024 * 1024, 4096);
    #[cfg(feature = "test-support")]
    let (backend, _control) = smb::test_support::ControlledFs::new(backend);
    let server = Server::new("memory", backend).unwrap();
    let (stop, stopped) = async_channel::bounded::<()>(1);
    let worker = std::thread::spawn(move || {
        DefaultPool::run_with(async |driver| -> Result<(), smb::Error> {
            let mut service = smb::tcp::Server::new(driver, listener, server)?;
            service.start();
            stopped.recv().await.unwrap();
            service.shutdown().await
        })
    });
    let result = Command::new("smbtorture")
        .args([
            "//127.0.0.1/memory",
            "-p",
            &port,
            "-U%",
            "--use-kerberos=off",
            "--client-protection=off",
            "--option=client min protocol=SMB2_10",
            "--option=client max protocol=SMB2_10",
            "--option=torture:windows=true",
            "--seed=12345",
            "--num-ops=32",
            "--maximum-runtime=90",
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
        ])
        .status();
    stop.send_blocking(()).unwrap();
    worker.join().unwrap().unwrap();
    assert!(
        result
            .expect("install samba-testsuite to run this test")
            .success()
    );
}
