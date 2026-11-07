// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Optional independent interoperability coverage; no host filesystem share is used.

use futures::FutureExt;
use pal_async::DefaultPool;
use smb::{Server, memory::MemoryFs, provider::FileSystem};
use std::net::TcpListener;
use std::process::Command;
use test_with_tracing::test;

macro_rules! smb21_case {
    ($name:ident, $case:literal) => {
        #[test]
        #[ignore = "requires the Samba smbtorture executable"]
        fn $name() {
            run_torture(
                MemoryFs::new(16 * 1024 * 1024, 4096)
                    .with_short_name_generation()
                    .with_oplocks()
                    .unwrap(),
                std::future::pending(),
                &["--maximum-runtime=20", $case],
            );
        }
    };
}

smb21_case!(samba_smb21_getinfo_complex, "smb2.getinfo.complex");
smb21_case!(
    samba_smb21_getinfo_file_buffer,
    "smb2.getinfo.qfile_buffercheck"
);
smb21_case!(samba_smb21_fileid_file, "smb2.fileid.fileid");
smb21_case!(samba_smb21_fileid_dir, "smb2.fileid.fileid-dir");
smb21_case!(samba_smb21_fileid_unique, "smb2.fileid.unique");
smb21_case!(samba_smb21_fileid_unique_dir, "smb2.fileid.unique-dir");
smb21_case!(samba_smb21_setinfo, "smb2.setinfo");
smb21_case!(samba_smb21_oplock_exclusive3, "smb2.oplock.exclusive3");
smb21_case!(samba_smb21_oplock_exclusive4, "smb2.oplock.exclusive4");
smb21_case!(samba_smb21_oplock_exclusive5, "smb2.oplock.exclusive5");
smb21_case!(samba_smb21_oplock_exclusive9, "smb2.oplock.exclusive9");
smb21_case!(samba_smb21_oplock_batch2, "smb2.oplock.batch2");
smb21_case!(samba_smb21_oplock_batch3, "smb2.oplock.batch3");
smb21_case!(samba_smb21_oplock_batch4, "smb2.oplock.batch4");
smb21_case!(samba_smb21_lease_statopen, "smb2.lease.statopen");
smb21_case!(samba_smb21_lease_statopen2, "smb2.lease.statopen2");
smb21_case!(samba_smb21_lease_statopen3, "smb2.lease.statopen3");
smb21_case!(samba_smb21_lease_statopen4, "smb2.lease.statopen4");

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
            "smb2.getinfo.qsec_buffercheck",
            "smb2.getinfo.granted",
            "smb2.sdread",
            "smb2.acls-with-sysacl.OWNER-RIGHTS",
            "smb2.acls-with-sysacl.OWNER-RIGHTS-DENY",
            "smb2.acls-with-sysacl.MXAC-NOT-GRANTED",
            "smb2.acls-ignore-sysacl.OWNER-RIGHTS-DENY1",
            "smb2.compound.create-write-close",
            "smb2.compound.related5",
            "smb2.compound_find.compound_find_related",
            "smb2.compound_find.compound_find_unrelated",
        ],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_create_and_sharing() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096),
        std::future::pending(),
        &[
            "smb2.create.brlocked",
            "smb2.create.multi",
            "smb2.create.delete",
            "smb2.create.leading-slash",
            "smb2.create.impersonation",
            "smb2.create.mkdir-dup",
            "smb2.create.mkdir-visible",
            "smb2.create.dir-alloc-size",
            "smb2.create.dosattr_tmp_dir",
            "smb2.sharemode.sharemode-access",
            "smb2.sharemode.access-sharemode",
            "smb2.sharemode.bug14375",
            "smb2.maximum_allowed.read_only_file",
            "smb2.maximum_allowed.read_only_dir",
            "smb2.delete-on-close-perms.READONLY",
            "smb2.winattr",
            "smb2.winattr2",
            "smb2.openattr",
        ],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_oplock_exclusive() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096)
            .with_oplocks()
            .unwrap(),
        std::future::pending(),
        &["smb2.oplock.exclusive1", "smb2.oplock.exclusive2"],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_oplock_batch() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096)
            .with_oplocks()
            .unwrap(),
        std::future::pending(),
        &["smb2.oplock.batch1"],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_lease_request() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096)
            .with_oplocks()
            .unwrap(),
        std::future::pending(),
        &["smb2.lease.request"],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_lease_breaks() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096)
            .with_oplocks()
            .unwrap(),
        std::future::pending(),
        &["smb2.lease.break"],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_lease_nobreakself() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096)
            .with_oplocks()
            .unwrap(),
        std::future::pending(),
        &["smb2.lease.nobreakself"],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_lease_upgrades() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096)
            .with_oplocks()
            .unwrap(),
        std::future::pending(),
        &[
            "smb2.lease.upgrade",
            "smb2.lease.upgrade2",
            "smb2.lease.upgrade3",
        ],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_lease_locks() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096)
            .with_oplocks()
            .unwrap(),
        std::future::pending(),
        &["smb2.lease.lock1", "smb2.lease.lock2", "smb2.lease.lock3"],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_lease_sharing_violation() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096)
            .with_oplocks()
            .unwrap(),
        std::future::pending(),
        &["smb2.lease.sharing_violation"],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_lease_oplock_mixing() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096)
            .with_oplocks()
            .unwrap(),
        std::future::pending(),
        &["smb2.lease.oplock"],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_lease_multiple_breaks() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096)
            .with_oplocks()
            .unwrap(),
        std::future::pending(),
        &[
            "smb2.lease.multibreak",
            "smb2.lease.breaking1",
            "smb2.lease.breaking2",
        ],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_volume_quotas() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096).with_quotas().unwrap(),
        std::future::pending(),
        &["smb2.getinfo.fsinfo", "smb2.getinfo.qfs_buffercheck"],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_sparse_compressed() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096),
        std::future::pending(),
        &["smb2.ioctl.sparse_compressed"],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_compression() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096),
        std::future::pending(),
        &[
            "smb2.ioctl.compress_file_flag",
            "smb2.ioctl.compress_dir_inherit",
            "smb2.ioctl.compress_invalid_format",
            "smb2.ioctl.compress_invalid_buf",
            "smb2.ioctl.compress_query_file_attr",
            "smb2.ioctl.compress_create_with_attr",
            "smb2.ioctl.compress_set_file_attr",
            "smb2.ioctl.compress_perms",
        ],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_sparse() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096),
        std::future::pending(),
        &[
            "smb2.ioctl.sparse_file_flag",
            "smb2.ioctl.sparse_file_attr",
            "smb2.ioctl.sparse_dir_flag",
            "smb2.ioctl.sparse_set_nobuf",
            "smb2.ioctl.sparse_set_oversize",
            "smb2.ioctl.sparse_qar",
            "smb2.ioctl.sparse_qar_truncated",
            "smb2.ioctl.sparse_punch",
            "smb2.ioctl.sparse_lock",
        ],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_streams() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096),
        std::future::pending(),
        &[
            "smb2.streams.dir",
            "smb2.streams.io",
            "smb2.streams.sharemodes",
            "smb2.streams.delete",
            "smb2.streams.zero-byte",
            "smb2.streams.rename",
            "smb2.streams.names",
            "smb2.streams.create-disposition",
            "smb2.streams.names2",
            "smb2.streams.attributes1",
            "smb2.streams.attributes2",
            "smb2.streams.basefile-rename-with-open-stream",
            "smb2.streams.perms",
        ],
    );
}

#[test]
#[ignore = "requires the Samba smbtorture executable"]
fn samba_directory() {
    run_torture(
        MemoryFs::new(16 * 1024 * 1024, 4096),
        std::future::pending(),
        &[
            "smb2.dir.find",
            "smb2.dir.fixed",
            "smb2.dir.many",
            "smb2.dir.modify",
            "smb2.dir.sorted",
            "smb2.dir.large-files",
            "smb2.dir.1kfiles_rename",
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
            "smb2.notify.tree",
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
            "smb2.rename.no_share_delete_but_delete_access",
            "smb2.rename.msword",
            "smb2.rename.close-full-information",
            "smb2.rename.rename-open",
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
