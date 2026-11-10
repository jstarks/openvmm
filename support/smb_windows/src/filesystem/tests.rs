// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use pal_async::{DefaultDriver, async_test};
use smb::provider::{ByteRange, FileSystem, LockSettlement, OpenOptions, RequestContext};
use smb::spec::{AccessMask, CreateAction, CreateDisposition, ShareAccess};
use smb::test_support::{
    Operation,
    contracts::{self, Expectations, Feature, Fixture},
};
use test_with_tracing::test;

struct NativeFixture(WindowsFs);

impl Fixture for NativeFixture {
    type Backend = WindowsFs;

    fn filesystem(&self) -> &WindowsFs {
        &self.0
    }

    fn readonly_maximum_delete_child_status(&self) -> Status {
        Status::SUCCESS
    }

    fn notify_delete_state_is_per_registration(&self) -> bool {
        true
    }

    fn expectations(&self) -> Expectations {
        Expectations {
            filesystem_information: Feature::Supported,
            allocation: Feature::Supported,
            creation_allocation: false,
            file_mode: Feature::Unsupported(Status::NOT_SUPPORTED),
            security_queries: Feature::Supported,
            file_acl_updates: Feature::Unsupported(Status::INVALID_DEVICE_REQUEST),
            directory_acl_updates: Feature::Unsupported(Status::INVALID_DEVICE_REQUEST),
            acl_inheritance: Feature::Unsupported(Status::INVALID_DEVICE_REQUEST),
            security_creation: Feature::Unsupported(Status::NOT_SUPPORTED),
            creation_eas: Feature::Unsupported(Status::NOT_SUPPORTED),
            ea_operations: Feature::Unsupported(Status::INVALID_DEVICE_REQUEST),
            stream_queries: Feature::Unsupported(Status::INVALID_INFO_CLASS),
            named_streams: Feature::Unsupported(Status::NOT_SUPPORTED),
            stream_rename: Feature::Unsupported(Status::NOT_SUPPORTED),
            short_names: Feature::Unsupported(Status::NOT_SUPPORTED),
            volume_object_ids: Feature::Unsupported(Status::INVALID_PARAMETER),
            object_id_controls: Feature::Unsupported(Status::INVALID_DEVICE_REQUEST),
            hard_links: Feature::Unsupported(Status::NOT_SUPPORTED),
            reparse_controls: Feature::Unsupported(Status::INVALID_DEVICE_REQUEST),
            sparse_files: Feature::Unsupported(Status::INVALID_DEVICE_REQUEST),
            compression: Feature::Unsupported(Status::INVALID_DEVICE_REQUEST),
            basic_information: Feature::Supported,
            rename: Feature::Supported,
            locks: Feature::Supported,
            notifications: Feature::Supported,
        }
    }

    async fn wait_until_pending(&self, operation: Operation, request: &RequestContext) {
        assert!(matches!(operation, Operation::Notify | Operation::Lock));
        let mut timer = pal_async::timer::PolledTimer::new(&*self.0.0.io.driver);
        loop {
            let pending = if operation == Operation::Lock {
                self.0.0.locks.pending(request.id())
            } else {
                self.0
                    .0
                    .watches
                    .lock()
                    .values()
                    .flatten()
                    .filter_map(Weak::upgrade)
                    .any(|watch| watch.pending(request.id()))
            };
            if pending {
                return;
            }
            timer.sleep(std::time::Duration::from_millis(1)).await;
        }
    }
}

macro_rules! contract_test {
    ($name:ident) => {
        #[async_test]
        async fn $name(driver: DefaultDriver) {
            let root = tempfile::tempdir().unwrap();
            let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
            contracts::$name(&NativeFixture(fs)).await;
        }
    };
}

contract_test!(data_and_identity);
contract_test!(maximum_allowed_access);
contract_test!(sharing_and_handle_release);
contract_test!(filesystem_information);
contract_test!(allocation_reservations);
contract_test!(file_mode_updates);
contract_test!(basic_information);
contract_test!(rename_identity);
contract_test!(rename_namespace_and_replacement);
contract_test!(delete_on_close);
contract_test!(delete_mode_is_deferred_to_close);
contract_test!(directory_delete_mode_checks_emptiness_at_close);
contract_test!(security_queries);
contract_test!(file_acl_updates);
contract_test!(directory_acl_updates);
contract_test!(acl_inheritance);
contract_test!(security_creation);
contract_test!(creation_eas);
contract_test!(extended_attributes);
contract_test!(named_streams);
contract_test!(stream_information);
contract_test!(short_names);
contract_test!(hard_links);
contract_test!(volume_object_ids);
contract_test!(object_id_controls);
contract_test!(compression);
contract_test!(sparse_files);
contract_test!(reparse_controls);
contract_test!(lock_conflicts_and_io);
contract_test!(lock_waiters_and_cancellation);
contract_test!(lock_rollback_and_drop);
contract_test!(notify_registration_and_cancellation);
contract_test!(notify_fifo_and_small_buffer);
contract_test!(notify_subtree_and_filters);
contract_test!(notify_deletion_generations);
contract_test!(notify_nonempty_delete_mode_preserves_watch);

async fn acquire<B: FileSystem>(
    fs: &B,
    file: &B::File,
    range: ByteRange,
    exclusive: bool,
    request: &RequestContext,
) -> Result<(), Status> {
    let mut scope = fs.lock_request(file);
    let result = scope.lock(range, exclusive, true, request).await;
    scope
        .settle(LockSettlement::Preserve, &RequestContext::new(request.id()))
        .await?;
    result
}

async fn release<B: FileSystem>(
    fs: &B,
    file: &B::File,
    range: ByteRange,
    request: &RequestContext,
) -> Result<(), Status> {
    let mut scope = fs.lock_request(file);
    let result = scope.unlock(range, request).await;
    scope
        .settle(LockSettlement::Preserve, &RequestContext::new(request.id()))
        .await?;
    result
}

#[async_test]
async fn native_scope_rollback_preserves_old_locks_at_each_prefix(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (owner, _) = fs
        .open(
            "rollback-array",
            options(CreateDisposition::CREATE),
            &request,
        )
        .await
        .unwrap();
    fs.write(&owner, 0, &[b'a'; 32], &request).await.unwrap();
    std::fs::hard_link(
        root.path().join("rollback-array"),
        root.path().join("alias"),
    )
    .unwrap();
    let (peer, _) = fs
        .open("alias", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    let old = ByteRange {
        offset: 2,
        length: 4,
    };
    let blocked = ByteRange {
        offset: 20,
        length: 1,
    };
    acquire(&fs, &owner, old, true, &request).await.unwrap();
    acquire(&fs, &peer, blocked, true, &request).await.unwrap();
    let additions = [
        (old, false),
        (old, false),
        (
            ByteRange {
                offset: 8,
                length: 1,
            },
            false,
        ),
        (
            ByteRange {
                offset: 10,
                length: 1,
            },
            true,
        ),
        (
            ByteRange {
                offset: 10,
                length: 1,
            },
            false,
        ),
        (
            ByteRange {
                offset: 0,
                length: 0,
            },
            true,
        ),
        (
            ByteRange {
                offset: 0,
                length: 0,
            },
            true,
        ),
    ];
    for prefix in 0..=additions.len() {
        let mut scope = fs.lock_request(&owner);
        for &(range, exclusive) in &additions[..prefix] {
            scope.lock(range, exclusive, true, &request).await.unwrap();
        }
        assert_eq!(
            scope.lock(blocked, true, true, &request).await,
            Err(Status::LOCK_NOT_GRANTED)
        );
        scope
            .settle(LockSettlement::Rollback, &request)
            .await
            .unwrap();
        assert_eq!(
            fs.read(&peer, 2, 1, &request).await,
            Err(Status::FILE_LOCK_CONFLICT)
        );
        assert_eq!(fs.write(&owner, 2, b"a", &request).await, Ok(1));
        assert_eq!(fs.write(&peer, 8, b"a", &request).await, Ok(1));
        assert_eq!(fs.read(&peer, 10, 1, &request).await.unwrap(), b"a");
    }
    release(&fs, &owner, old, &request).await.unwrap();
    assert_eq!(
        release(&fs, &owner, old, &request).await,
        Err(Status::RANGE_NOT_LOCKED)
    );
    acquire(&fs, &peer, old, true, &request).await.unwrap();
    fs.close(&owner, &request).await.unwrap();
    fs.close(&peer, &request).await.unwrap();
}

#[async_test]
async fn committed_shared_backing_protects_append_and_survives_exclusive_unlock(
    driver: DefaultDriver,
) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("append-locked"), b"abcdefghij").unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (owner, _) = fs
        .open(
            "append-locked",
            OpenOptions {
                access: AccessMask::new()
                    .with_read_data(true)
                    .with_append_data(true)
                    .with_read_attributes(true)
                    .into_bits(),
                ..options(CreateDisposition::OPEN)
            },
            &request,
        )
        .await
        .unwrap();
    let (peer, _) = fs
        .open("append-locked", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    let range = ByteRange {
        offset: 2,
        length: 4,
    };
    acquire(&fs, &owner, range, true, &request).await.unwrap();
    let mut scope = fs.lock_request(&owner);
    scope.lock(range, false, true, &request).await.unwrap();
    scope.lock(range, false, true, &request).await.unwrap();
    scope
        .settle(LockSettlement::Preserve, &request)
        .await
        .unwrap();
    let host = peer.get().unwrap();
    native::set_len(host.get(), 3).unwrap();
    assert_eq!(
        fs.write(&owner, 0, b"x", &request).await,
        Err(Status::FILE_LOCK_CONFLICT)
    );
    release(&fs, &owner, range, &request).await.unwrap();
    assert_eq!(fs.read(&peer, 0, 3, &request).await.unwrap(), b"abc");
    assert_eq!(
        fs.write(&peer, 2, b"x", &request).await,
        Err(Status::FILE_LOCK_CONFLICT)
    );
    release(&fs, &owner, range, &request).await.unwrap();
    assert_eq!(
        fs.write(&owner, 0, b"x", &request).await,
        Err(Status::FILE_LOCK_CONFLICT)
    );
    release(&fs, &owner, range, &request).await.unwrap();
    assert_eq!(fs.write(&owner, 0, b"x", &request).await, Ok(1));
    assert_eq!(fs.read(&peer, 0, 4, &request).await.unwrap(), b"abcx");
    fs.close(&owner, &request).await.unwrap();
    fs.close(&peer, &request).await.unwrap();
}

#[async_test]
async fn native_unlock_realizes_shared_backing_without_an_owner_write(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (owner, _) = fs
        .open(
            "unlock-realize",
            options(CreateDisposition::CREATE),
            &request,
        )
        .await
        .unwrap();
    let (peer, _) = fs
        .open("unlock-realize", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    fs.write(&owner, 0, b"abcd", &request).await.unwrap();
    let range = ByteRange {
        offset: 0,
        length: 4,
    };
    acquire(&fs, &owner, range, true, &request).await.unwrap();
    acquire(&fs, &owner, range, false, &request).await.unwrap();
    release(&fs, &owner, range, &request).await.unwrap();
    assert_eq!(fs.read(&peer, 0, 4, &request).await.unwrap(), b"abcd");
    assert_eq!(
        fs.write(&peer, 0, b"x", &request).await,
        Err(Status::FILE_LOCK_CONFLICT)
    );
    assert_eq!(
        fs.write(&owner, 0, b"x", &request).await,
        Err(Status::FILE_LOCK_CONFLICT)
    );
    fs.close(&owner, &request).await.unwrap();
    assert_eq!(fs.write(&peer, 0, b"x", &request).await, Ok(1));
    fs.close(&peer, &request).await.unwrap();
}

#[async_test]
async fn contended_native_waits_allow_same_open_unlock_and_detect_host_unlock(
    driver: DefaultDriver,
) {
    let root = tempfile::tempdir().unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let fixture = NativeFixture(fs);
    let fs = &fixture.0;
    let request = RequestContext::new(1);
    let (owner, _) = fs
        .open(
            "waiting-native",
            options(CreateDisposition::CREATE),
            &request,
        )
        .await
        .unwrap();
    let (host, _) = fs
        .open("waiting-native", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    let host = host.get().unwrap();
    let range = ByteRange {
        offset: 0,
        length: 4,
    };
    for external in [false, true] {
        if external {
            let ((status, _), ()) =
                native::lock(host.overlapped().unwrap(), range, 0, true, true).await;
            native::status(status).unwrap();
        } else {
            acquire(fs, &owner, range, true, &request).await.unwrap();
        }
        let mut scope = fs.lock_request(&owner);
        let waiting = RequestContext::new(2);
        let (result, ()) = futures::join!(scope.lock(range, true, false, &waiting), async {
            fixture.wait_until_pending(Operation::Lock, &waiting).await;
            fs.flush(&owner, &request).await.unwrap();
            if external {
                native::unlock(host.get(), range, 0).unwrap();
            } else {
                release(fs, &owner, range, &request).await.unwrap();
            }
        },);
        result.unwrap();
        scope
            .settle(LockSettlement::Preserve, &request)
            .await
            .unwrap();
        release(fs, &owner, range, &request).await.unwrap();
    }
    fs.close(&owner, &request).await.unwrap();
}

#[async_test]
async fn scoped_locks_drain_concurrent_io_admission_and_cancel_without_grant(
    driver: DefaultDriver,
) {
    let root = tempfile::tempdir().unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (owner, _) = fs
        .open("drain-native", options(CreateDisposition::CREATE), &request)
        .await
        .unwrap();
    let native = owner.get().unwrap();
    let first = native.active(&request).await.unwrap();
    let second = native.active(&request).await.unwrap();
    let range = ByteRange {
        offset: 0,
        length: 1,
    };
    let cancelled = RequestContext::new(2);
    let mut scope = fs.lock_request(&owner);
    {
        let mut lock = std::pin::pin!(scope.lock(range, true, true, &cancelled));
        assert!(futures::poll!(&mut lock).is_pending());
        drop(first);
        assert!(futures::poll!(&mut lock).is_pending());
        cancelled.cancel();
        assert_eq!(lock.await, Err(Status::CANCELLED));
    }
    scope
        .settle(LockSettlement::Preserve, &request)
        .await
        .unwrap();
    drop(second);
    acquire(&fs, &owner, range, true, &request).await.unwrap();
    fs.close(&owner, &request).await.unwrap();
}

#[async_test]
async fn native_lock_capacity_failure_preserves_prefix_and_close_recovers_capacity(
    driver: DefaultDriver,
) {
    let root = tempfile::tempdir().unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (owner, _) = fs
        .open(
            "lock-capacity",
            options(CreateDisposition::CREATE),
            &request,
        )
        .await
        .unwrap();
    let (peer, _) = fs
        .open("lock-capacity", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    let range = ByteRange {
        offset: 0,
        length: 1,
    };
    let mut scope = fs.lock_request(&owner);
    for _ in 0..4096 {
        scope.lock(range, false, true, &request).await.unwrap();
    }
    assert_eq!(
        scope.lock(range, false, true, &request).await,
        Err(Status::INSUFFICIENT_RESOURCES)
    );
    scope
        .settle(LockSettlement::Preserve, &request)
        .await
        .unwrap();
    assert_eq!(
        fs.write(&owner, 0, b"x", &request).await,
        Err(Status::FILE_LOCK_CONFLICT)
    );
    fs.close(&owner, &request).await.unwrap();
    acquire(&fs, &peer, range, true, &request).await.unwrap();
    fs.close(&peer, &request).await.unwrap();
}

#[async_test]
async fn controlled_native_scopes_keep_grants_after_late_cancel(driver: DefaultDriver) {
    use smb::test_support::{ControlledFs, Gate, Phase, Plan};
    let root = tempfile::tempdir().unwrap();
    let driver: Arc<dyn Driver> = Arc::new(driver);
    let native = WindowsFs::new(root.path(), driver.clone()).await.unwrap();
    let (fs, control) = ControlledFs::new(native);
    let request = RequestContext::new(1);
    let (owner, _) = fs
        .open("late-native", options(CreateDisposition::CREATE), &request)
        .await
        .unwrap();
    let (peer, _) = fs
        .open("late-native", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    let range = ByteRange {
        offset: 0,
        length: 1,
    };
    control
        .set_plan(
            Operation::Lock,
            Plan {
                hold_after: true,
                ..Plan::default()
            },
        )
        .unwrap();
    let cancelled = RequestContext::new(2);
    let mut scope = fs.lock_request(&owner);
    let (result, ()) = futures::join!(scope.lock(range, true, true, &cancelled), async {
        let call = control.next_call().await;
        let mut timer = pal_async::timer::PolledTimer::new(&*driver);
        while control.snapshot(call.id).unwrap().phase != Phase::After {
            timer.sleep(std::time::Duration::from_millis(1)).await;
        }
        cancelled.cancel();
        control.release(call.id, Gate::After).unwrap();
    },);
    result.unwrap();
    scope
        .settle(LockSettlement::Preserve, &request)
        .await
        .unwrap();
    assert_eq!(fs.write(&owner, 0, b"x", &request).await, Ok(1));
    assert_eq!(
        fs.write(&peer, 0, b"x", &request).await,
        Err(Status::FILE_LOCK_CONFLICT)
    );
    fs.close(&owner, &request).await.unwrap();
    assert_eq!(fs.write(&peer, 0, b"x", &request).await, Ok(1));
    fs.close(&peer, &request).await.unwrap();
}

#[async_test]
async fn failed_native_scope_cleanup_reports_error_and_retains_accurate_protection(
    driver: DefaultDriver,
) {
    use smb::test_support::{ControlledFs, Plan};
    let root = tempfile::tempdir().unwrap();
    let native = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let (fs, control) = ControlledFs::new(native);
    let request = RequestContext::new(1);
    let (owner, _) = fs
        .open(
            "cleanup-native",
            options(CreateDisposition::CREATE),
            &request,
        )
        .await
        .unwrap();
    let (peer, _) = fs
        .open("cleanup-native", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    let range = ByteRange {
        offset: 0,
        length: 1,
    };
    acquire(&fs, &owner, range, true, &request).await.unwrap();
    let mut scope = fs.lock_request(&owner);
    scope.lock(range, false, true, &request).await.unwrap();
    control
        .set_plan(
            Operation::RollbackLock,
            Plan {
                failure: Some(Status::ACCESS_DENIED),
                ..Plan::default()
            },
        )
        .unwrap();
    assert_eq!(
        scope.settle(LockSettlement::Rollback, &request).await,
        Err(Status::ACCESS_DENIED)
    );
    assert_eq!(
        fs.write(&owner, 0, b"x", &request).await,
        Err(Status::FILE_LOCK_CONFLICT)
    );
    assert_eq!(
        fs.write(&peer, 0, b"x", &request).await,
        Err(Status::FILE_LOCK_CONFLICT)
    );
    release(&fs, &owner, range, &request).await.unwrap();
    assert_eq!(
        fs.write(&peer, 0, b"x", &request).await,
        Err(Status::FILE_LOCK_CONFLICT)
    );
    release(&fs, &owner, range, &request).await.unwrap();
    assert_eq!(fs.write(&peer, 0, b"x", &request).await, Ok(1));
    fs.close(&owner, &request).await.unwrap();
    fs.close(&peer, &request).await.unwrap();
}

#[async_test]
async fn native_scope_rejects_foreign_provider_handles(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let driver: Arc<dyn Driver> = Arc::new(driver);
    let fs = WindowsFs::new(root.path(), driver.clone()).await.unwrap();
    let foreign = WindowsFs::new(root.path(), driver).await.unwrap();
    let request = RequestContext::new(1);
    let (owner, _) = fs
        .open(
            "foreign-native",
            options(CreateDisposition::CREATE),
            &request,
        )
        .await
        .unwrap();
    let range = ByteRange {
        offset: 0,
        length: 1,
    };
    acquire(&fs, &owner, range, true, &request).await.unwrap();
    assert_eq!(
        acquire(&foreign, &owner, range, false, &request).await,
        Err(Status::FILE_CLOSED)
    );
    fs.close(&owner, &request).await.unwrap();
}

#[async_test]
async fn native_unsigned_and_empty_range_conflicts_match_inclusive_rules(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (owner, _) = fs
        .open(
            "unsigned-native",
            options(CreateDisposition::CREATE),
            &request,
        )
        .await
        .unwrap();
    let (peer, _) = fs
        .open(
            "unsigned-native",
            options(CreateDisposition::OPEN),
            &request,
        )
        .await
        .unwrap();
    let owner = owner.get().unwrap();
    let peer = peer.get().unwrap();
    let ranges = [
        ByteRange {
            offset: 0,
            length: 0,
        },
        ByteRange {
            offset: 3,
            length: 0,
        },
        ByteRange {
            offset: u64::MAX,
            length: 0,
        },
        ByteRange {
            offset: 0,
            length: 1,
        },
        ByteRange {
            offset: 3,
            length: 1,
        },
        ByteRange {
            offset: u64::MAX,
            length: 1,
        },
        ByteRange {
            offset: 0,
            length: u64::MAX,
        },
        ByteRange {
            offset: 1,
            length: u64::MAX,
        },
    ];
    for held in ranges {
        let ((status, _), ()) =
            native::lock(owner.overlapped().unwrap(), held, 0, true, true).await;
        native::status(status).unwrap();
        for attempted in ranges {
            let ((status, _), ()) =
                native::lock(peer.overlapped().unwrap(), attempted, 0, true, true).await;
            let expected = if held.overlaps(attempted) {
                Status::LOCK_NOT_GRANTED
            } else {
                Status::SUCCESS
            };
            assert_eq!(Status(status as u32), expected, "{held:?}, {attempted:?}");
            if expected == Status::SUCCESS {
                native::unlock(peer.get(), attempted, 0).unwrap();
            }
        }
        native::unlock(owner.get(), held, 0).unwrap();
    }
}

#[async_test]
async fn native_lock_boundaries_follow_unsigned_range_rules(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (owner, _) = fs
        .open("boundaries", options(CreateDisposition::CREATE), &request)
        .await
        .unwrap();
    let (other, _) = fs
        .open("boundaries", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    let owned = owner.get().unwrap();
    let peer = other.get().unwrap();
    for (held, attempted, conflict) in [
        (
            ByteRange {
                offset: 0,
                length: 0,
            },
            ByteRange {
                offset: 2,
                length: 4,
            },
            false,
        ),
        (
            ByteRange {
                offset: 3,
                length: 0,
            },
            ByteRange {
                offset: 2,
                length: 4,
            },
            true,
        ),
        (
            ByteRange {
                offset: u64::MAX,
                length: 1,
            },
            ByteRange {
                offset: u64::MAX,
                length: 1,
            },
            true,
        ),
    ] {
        let ((status, _), ()) =
            native::lock(owned.overlapped().unwrap(), held, 0, true, true).await;
        native::status(status).unwrap();
        let ((status, _), ()) =
            native::lock(peer.overlapped().unwrap(), attempted, 0, true, true).await;
        if conflict {
            assert_eq!(Status(status as u32), Status::LOCK_NOT_GRANTED);
        } else {
            native::status(status).unwrap();
            native::unlock(peer.get(), attempted, 0).unwrap();
        }
        native::unlock(owned.get(), held, 0).unwrap();
    }
    drop(owned);
    drop(peer);
    fs.close(&owner, &request).await.unwrap();
    fs.close(&other, &request).await.unwrap();
}

#[async_test]
async fn native_shared_backing_is_required_for_append_after_external_eof_change(
    driver: DefaultDriver,
) {
    let root = tempfile::tempdir().unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (owner, _) = fs
        .open("eof", options(CreateDisposition::CREATE), &request)
        .await
        .unwrap();
    let (other, _) = fs
        .open("eof", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    fs.write(&owner, 0, b"abcdefghij", &request).await.unwrap();
    let owned = owner.get().unwrap();
    let peer = other.get().unwrap();
    let range = ByteRange {
        offset: 2,
        length: 4,
    };
    let ((status, _), ()) = native::lock(owned.overlapped().unwrap(), range, 0, true, true).await;
    native::status(status).unwrap();
    assert_eq!(fs.metadata(&owner, &request).await.unwrap().size, 10);
    native::set_len(peer.get(), 3).unwrap();
    let ((status, count), _) = native::write(owned.overlapped().unwrap(), -1, vec![b'x']).await;
    native::status(status).unwrap();
    assert_eq!(count, 1);
    assert_eq!(fs.read(&owner, 0, 10, &request).await.unwrap(), b"abcx");
    let ((status, _), ()) = native::lock(owned.overlapped().unwrap(), range, 0, false, true).await;
    native::status(status).unwrap();
    native::set_len(peer.get(), 3).unwrap();
    let ((status, count), _) = native::write(owned.overlapped().unwrap(), -1, vec![b'y']).await;
    assert_eq!(Status(status as u32), Status::FILE_LOCK_CONFLICT);
    assert_eq!(count, 0);
    assert_eq!(fs.read(&owner, 0, 10, &request).await.unwrap(), b"abc");
    native::unlock(owned.get(), range, 0).unwrap();
    native::unlock(owned.get(), range, 0).unwrap();
    drop(owned);
    drop(peer);
    fs.close(&owner, &request).await.unwrap();
    fs.close(&other, &request).await.unwrap();
}

#[async_test]
async fn native_lock_keys_and_overlapping_acquisitions(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (owner, _) = fs
        .open("keys", options(CreateDisposition::CREATE), &request)
        .await
        .unwrap();
    fs.write(&owner, 0, b"abcdefghij", &request).await.unwrap();
    let (other, _) = fs
        .open("keys", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    let owner_native = owner.get().unwrap();
    let other_native = other.get().unwrap();
    let file = owner_native.overlapped().unwrap();
    let range = ByteRange {
        offset: 2,
        length: 4,
    };
    let ((result, _), ()) = native::lock(file, range, 1, true, true).await;
    native::status(result).unwrap();
    for key in [0, 1, 2] {
        let ((read, _), _) = native::read_with_key(file, 2, vec![0; 1], key).await;
        let ((write, _), _) = native::write_with_key(file, 2, vec![b'c'], key).await;
        let expected = if key == 1 {
            Status::SUCCESS
        } else {
            Status::FILE_LOCK_CONFLICT
        };
        assert_eq!(Status(read as u32), expected);
        assert_eq!(Status(write as u32), expected);
    }
    let ((different, _), ()) = native::lock(file, range, 2, false, true).await;
    assert_eq!(Status(different as u32), Status::LOCK_NOT_GRANTED);
    let ((same, _), ()) = native::lock(file, range, 1, false, true).await;
    native::status(same).unwrap();
    native::unlock(file.get(), range, 1).unwrap();
    let ((after, _), _) = native::write_with_key(file, 2, vec![b'c'], 1).await;
    assert_eq!(Status(after as u32), Status::FILE_LOCK_CONFLICT);
    let ((peer_read, count), data) =
        native::read(other_native.overlapped().unwrap(), 2, vec![0; 1]).await;
    native::status(peer_read).unwrap();
    assert_eq!(&data[..count], b"c");
    native::unlock(file.get(), range, 1).unwrap();
    drop(owner_native);
    drop(other_native);
    fs.close(&owner, &request).await.unwrap();
    fs.close(&other, &request).await.unwrap();
}

#[async_test]
async fn notification_delete_state_belongs_to_existing_registrations(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let directory_options = OpenOptions {
        options: nt::FILE_DIRECTORY_FILE,
        ..options(CreateDisposition::CREATE)
    };
    let (watching, _) = fs.open("state", directory_options, &request).await.unwrap();
    let (deleting, _) = fs
        .open(
            "state",
            OpenOptions {
                disposition: nt::FILE_OPEN,
                ..directory_options
            },
            &request,
        )
        .await
        .unwrap();
    let filter = NotifyFilter::new().with_file_name(true);
    let cancelled = RequestContext::new(2);
    cancelled.cancel();
    assert!(matches!(
        fs.notify(&watching, filter, false, 4096, &cancelled).await,
        Err(Status::CANCELLED)
    ));
    fs.set_delete_on_close(&deleting, true, &request)
        .await
        .unwrap();
    fs.set_delete_on_close(&deleting, false, &request)
        .await
        .unwrap();
    assert!(matches!(
        fs.notify(&watching, filter, false, 4096, &request).await,
        Err(Status::DELETE_PENDING)
    ));
    {
        let native = deleting.get().unwrap();
        let directory = native.directory().unwrap();
        let direct = native::notify(directory.file.clone(), filter, false);
        std::fs::write(root.path().join("state/fresh"), []).unwrap();
        let ((status, used), buffer) = direct.await;
        let changes = native::notify_changes(status, used, &buffer)
            .unwrap()
            .unwrap();
        assert_eq!(
            changes,
            vec![smb::provider::Change {
                action: smb::spec::NotifyAction::ADDED,
                name: "fresh".to_owned(),
            }]
        );
    }
    assert!(matches!(
        fs.notify(&deleting, filter, false, 4096, &cancelled).await,
        Err(Status::CANCELLED)
    ));
    fs.close(&watching, &request).await.unwrap();
    fs.close(&deleting, &request).await.unwrap();
}

#[async_test]
async fn notifications_buffer_external_recursive_host_changes(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (directory, _) = fs
        .open(
            "external",
            OpenOptions {
                options: nt::FILE_DIRECTORY_FILE,
                ..options(CreateDisposition::CREATE)
            },
            &request,
        )
        .await
        .unwrap();
    let filter = NotifyFilter::new().with_file_name(true);
    let cancelled = RequestContext::new(2);
    cancelled.cancel();
    assert!(matches!(
        fs.notify(&directory, filter, true, 4096, &cancelled).await,
        Err(Status::CANCELLED)
    ));
    std::fs::create_dir(root.path().join("external/sub")).unwrap();
    std::fs::write(root.path().join("external/sub/first"), b"host").unwrap();
    for name in ["sub\\first", "sub\\second"] {
        let result = fs
            .notify(&directory, filter, true, 4096, &request)
            .await
            .unwrap();
        let NotifyResult::Changes(changes) = result else {
            panic!("expected external host change, got {result:?}");
        };
        assert_eq!(
            changes,
            vec![smb::provider::Change {
                action: smb::spec::NotifyAction::ADDED,
                name: name.to_owned(),
            }]
        );
        if name == "sub\\first" {
            std::fs::write(root.path().join("external/sub/second"), b"host").unwrap();
        }
    }
    fs.close(&directory, &request).await.unwrap();
}

#[async_test]
async fn notification_close_drains_native_io_and_releases_sharing(driver: DefaultDriver) {
    use std::os::windows::fs::OpenOptionsExt;
    let root = tempfile::tempdir().unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (directory, _) = fs
        .open(
            "closing",
            OpenOptions {
                options: nt::FILE_DIRECTORY_FILE,
                ..options(CreateDisposition::CREATE)
            },
            &request,
        )
        .await
        .unwrap();
    let filter = NotifyFilter::new().with_file_name(true);
    let cancelled = RequestContext::new(2);
    cancelled.cancel();
    assert!(matches!(
        fs.notify(&directory, filter, false, 4096, &cancelled).await,
        Err(Status::CANCELLED)
    ));
    {
        let mut pending = std::pin::pin!(fs.notify(&directory, filter, false, 4096, &request));
        assert!(futures::poll!(&mut pending).is_pending());
        fs.close(&directory, &request).await.unwrap();
        assert!(matches!(pending.await, Err(Status::NOTIFY_CLEANUP)));
    }
    let exclusive = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .custom_flags(fs::FILE_FLAG_BACKUP_SEMANTICS)
        .open(root.path().join("closing"))
        .unwrap();
    drop(exclusive);
}

#[async_test]
async fn accepted_notification_registration_survives_dropped_setup(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (directory, _) = fs
        .open(
            "",
            OpenOptions {
                options: nt::FILE_DIRECTORY_FILE,
                ..options(CreateDisposition::OPEN)
            },
            &request,
        )
        .await
        .unwrap();
    let inner = fs.0.clone();
    let (started, starts) = async_channel::bounded(1);
    let (release, wait) = std::sync::mpsc::channel();
    let barrier = std::thread::spawn(move || {
        let _registry = inner.watches.lock();
        started.try_send(()).unwrap();
        let _ = wait.recv();
    });
    starts.recv().await.unwrap();
    let mut setup = Box::pin(fs.notify(
        &directory,
        NotifyFilter::new().with_file_name(true),
        false,
        4096,
        &request,
    ));
    assert!(futures::poll!(&mut setup).is_pending());
    let mut timer = pal_async::timer::PolledTimer::new(&*fs.0.io.driver);
    while directory.watch.try_lock().is_some() {
        timer.sleep(std::time::Duration::from_millis(1)).await;
    }
    drop(setup);
    release.send(()).unwrap();
    assert!(directory.watch.lock().await.is_some());
    barrier.join().unwrap();
    std::fs::write(root.path().join("retained"), []).unwrap();
    let result = fs
        .notify(
            &directory,
            NotifyFilter::new().with_dir_name(true),
            true,
            4096,
            &request,
        )
        .await
        .unwrap();
    let NotifyResult::Changes(changes) = result else {
        panic!("lost accepted registration: {result:?}");
    };
    assert_eq!(
        changes,
        vec![smb::provider::Change {
            action: smb::spec::NotifyAction::ADDED,
            name: "retained".to_owned(),
        }]
    );
    fs.close(&directory, &request).await.unwrap();
}

#[async_test]
async fn native_notification_storage_overflow_requires_reenumeration(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("overflow")).unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (directory, _) = fs
        .open(
            "overflow",
            OpenOptions {
                options: nt::FILE_DIRECTORY_FILE,
                ..options(CreateDisposition::OPEN)
            },
            &request,
        )
        .await
        .unwrap();
    let filter = NotifyFilter::new().with_file_name(true);
    let cancelled = RequestContext::new(2);
    cancelled.cancel();
    assert!(matches!(
        fs.notify(&directory, filter, false, 4096, &cancelled).await,
        Err(Status::CANCELLED)
    ));
    for index in 0..512 {
        let name = format!("{index:04}-{}", "x".repeat(128));
        std::fs::write(root.path().join("overflow").join(name), []).unwrap();
    }
    let mut timer = pal_async::timer::PolledTimer::new(&*fs.0.io.driver);
    {
        let events = async {
            for _ in 0..4 {
                if matches!(
                    fs.notify(&directory, filter, false, 256 * 1024, &request)
                        .await
                        .unwrap(),
                    NotifyResult::Overflow
                ) {
                    return;
                }
            }
            panic!("native event storm did not report overflow");
        };
        let mut events = std::pin::pin!(events.fuse());
        let timeout = timer.sleep(std::time::Duration::from_secs(5));
        let mut timeout = std::pin::pin!(timeout.fuse());
        futures::select! {
            () = events => {},
            _ = timeout => panic!("native event storm did not complete"),
        }
    }
    fs.close(&directory, &request).await.unwrap();
}

#[async_test]
async fn notification_names_reject_invalid_utf16(driver: DefaultDriver) {
    use std::os::windows::ffi::OsStringExt;
    let root = tempfile::tempdir().unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (directory, _) = fs
        .open(
            "",
            OpenOptions {
                options: nt::FILE_DIRECTORY_FILE,
                ..options(CreateDisposition::OPEN)
            },
            &request,
        )
        .await
        .unwrap();
    let filter = NotifyFilter::new().with_file_name(true);
    let cancelled = RequestContext::new(2);
    cancelled.cancel();
    assert!(matches!(
        fs.notify(&directory, filter, false, 4096, &cancelled).await,
        Err(Status::CANCELLED)
    ));
    let name = std::ffi::OsString::from_wide(&[0xd800]);
    std::fs::write(root.path().join(name), []).unwrap();
    assert!(matches!(
        fs.notify(&directory, filter, false, 4096, &request).await,
        Err(Status::OBJECT_NAME_INVALID)
    ));
    fs.close(&directory, &request).await.unwrap();
}

#[async_test]
async fn native_mutations_change_host_bytes_names_and_attributes(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (source, _) = fs
        .open("before", options(CreateDisposition::CREATE), &request)
        .await
        .unwrap();
    fs.write(&source, 0, b"contents", &request).await.unwrap();
    let volume = fs.filesystem_information(&source, &request).await.unwrap();
    let capabilities = smb::spec::FileSystemAttributes::from_bits(volume.attributes);
    assert!(!capabilities.persistent_acls() && !capabilities.named_streams());
    assert!(!capabilities.extended_attributes() && !capabilities.supports_hard_links());
    assert!(!capabilities.supports_reparse_points() && !capabilities.supports_sparse_files());
    assert!(!capabilities.file_compression() && !capabilities.supports_object_ids());
    fs.set_allocation_size(&source, 8192, &request)
        .await
        .unwrap();
    assert_eq!(
        std::fs::metadata(root.path().join("before")).unwrap().len(),
        8
    );
    assert!(
        fs.metadata(&source, &request)
            .await
            .unwrap()
            .allocation_size
            >= 8192
    );
    let basic = BasicInformation {
        created: 0,
        accessed: 0,
        written: 0,
        changed: 0,
        attributes: fs::FILE_ATTRIBUTE_READONLY,
    };
    fs.set_basic(&source, basic, &request).await.unwrap();
    assert!(
        std::fs::metadata(root.path().join("before"))
            .unwrap()
            .permissions()
            .readonly()
    );
    fs.set_basic(
        &source,
        BasicInformation {
            attributes: fs::FILE_ATTRIBUTE_NORMAL,
            ..basic
        },
        &request,
    )
    .await
    .unwrap();
    std::fs::create_dir(root.path().join("destination")).unwrap();
    fs.rename(&source, "destination\\moved", false, &request)
        .await
        .unwrap();
    assert!(!root.path().join("before").exists());
    assert_eq!(
        std::fs::read(root.path().join("destination/moved")).unwrap(),
        b"contents"
    );
    let (peer, _) = fs
        .open(
            "destination\\moved",
            options(CreateDisposition::OPEN),
            &request,
        )
        .await
        .unwrap();
    fs.set_delete_on_close(&source, true, &request)
        .await
        .unwrap();
    fs.close(&source, &request).await.unwrap();
    assert_eq!(fs.read(&peer, 0, 8, &request).await.unwrap(), b"contents");
    fs.set_delete_on_close(&peer, false, &request)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(root.path().join("destination/moved")).unwrap(),
        b"contents"
    );
    fs.set_delete_on_close(&peer, true, &request).await.unwrap();
    fs.close(&peer, &request).await.unwrap();
    assert!(!root.path().join("destination/moved").exists());
}

#[async_test]
async fn overwrite_checks_implicit_access_before_truncating_native_data(driver: DefaultDriver) {
    use pal::windows::security::{LocalSecurityDescriptor, create_file_with_security};
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let descriptor: LocalSecurityDescriptor = "D:P(D;;0x10;;;WD)(A;;FA;;;WD)".parse().unwrap();
    let mut host = create_file_with_security(&root.path().join("protected"), &descriptor).unwrap();
    host.write_all(b"preserve").unwrap();
    drop(host);
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    assert_eq!(
        fs.open(
            "protected",
            OpenOptions {
                access: AccessMask::new().with_read_attributes(true).into_bits(),
                ..options(CreateDisposition::OVERWRITE)
            },
            &request
        )
        .await
        .err(),
        Some(Status::ACCESS_DENIED)
    );
    assert_eq!(
        std::fs::read(root.path().join("protected")).unwrap(),
        b"preserve"
    );
}

#[async_test]
async fn native_timestamps_and_per_open_write_time_controls(driver: DefaultDriver) {
    use std::os::windows::fs::MetadataExt;
    let root = tempfile::tempdir().unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (file, _) = fs
        .open("times", options(CreateDisposition::CREATE), &request)
        .await
        .unwrap();
    let info = BasicInformation {
        created: 132_000_000_000_000_000,
        accessed: 132_000_000_000_000_010,
        written: 132_000_000_000_000_020,
        changed: 132_000_000_000_000_030,
        attributes: 0,
    };
    fs.set_basic(&file, info, &request).await.unwrap();
    let metadata = std::fs::metadata(root.path().join("times")).unwrap();
    assert_eq!(metadata.creation_time(), info.created as u64);
    assert_eq!(metadata.last_access_time(), info.accessed as u64);
    assert_eq!(metadata.last_write_time(), info.written as u64);
    let control = BasicInformation {
        created: 0,
        accessed: 0,
        written: -1,
        changed: 0,
        attributes: 0,
    };
    fs.set_basic(&file, control, &request).await.unwrap();
    fs.write(&file, 0, b"suppressed", &request).await.unwrap();
    fs.close(&file, &request).await.unwrap();
    assert_eq!(
        std::fs::metadata(root.path().join("times"))
            .unwrap()
            .last_write_time(),
        info.written as u64
    );
    let (file, _) = fs
        .open("times", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    fs.set_basic(&file, control, &request).await.unwrap();
    fs.set_basic(
        &file,
        BasicInformation {
            written: -2,
            ..control
        },
        &request,
    )
    .await
    .unwrap();
    fs.write(&file, 0, b"restored", &request).await.unwrap();
    fs.close(&file, &request).await.unwrap();
    assert_ne!(
        std::fs::metadata(root.path().join("times"))
            .unwrap()
            .last_write_time(),
        info.written as u64
    );
}

fn options(disposition: CreateDisposition) -> OpenOptions<'static> {
    OpenOptions {
        access: AccessMask::FILE_ALL_ACCESS.into_bits(),
        share_access: ShareAccess::ALL.into_bits(),
        disposition: disposition.0,
        options: 0,
        attributes: 0,
        allocation_size: 0,
        security: None,
        extended_attributes: None,
    }
}

#[async_test]
async fn backing_bytes_append_eof_and_close(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (file, action) = fs
        .open("Native", options(CreateDisposition::CREATE), &request)
        .await
        .unwrap();
    assert_eq!(action, CreateAction::CREATED.0);
    assert_eq!(fs.write(&file, 0, b"before", &request).await.unwrap(), 6);
    assert_eq!(
        std::fs::read(root.path().join("Native")).unwrap(),
        b"before"
    );
    std::fs::write(root.path().join("Native"), b"host").unwrap();
    assert_eq!(fs.read(&file, 0, 4, &request).await.unwrap(), b"host");
    let (append, _) = fs
        .open(
            "native",
            OpenOptions {
                access: AccessMask::new()
                    .with_append_data(true)
                    .with_read_attributes(true)
                    .into_bits(),
                ..options(CreateDisposition::OPEN)
            },
            &request,
        )
        .await
        .unwrap();
    assert_eq!(fs.write(&append, 0, b"+", &request).await.unwrap(), 1);
    assert_eq!(std::fs::read(root.path().join("Native")).unwrap(), b"host+");
    assert_eq!(
        fs.read(&file, 100, 1, &request).await.unwrap_err(),
        Status::END_OF_FILE
    );
    assert_eq!(fs.metadata(&append, &request).await.unwrap().name, "Native");
    fs.flush(&file, &request).await.unwrap();
    request.cancel();
    fs.close(&file, &request).await.unwrap();
    fs.close(&file, &request).await.unwrap();
    assert_eq!(
        fs.metadata(&file, &RequestContext::new(2))
            .await
            .unwrap_err(),
        Status::FILE_CLOSED
    );
    fs.close(&append, &request).await.unwrap();
    assert_eq!(fs.0.opens.load(Ordering::Relaxed), 0);
}

#[async_test]
async fn native_sharing_across_host_opens_and_hard_link_aliases(driver: DefaultDriver) {
    use std::os::windows::fs::OpenOptionsExt;
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("data"), b"original").unwrap();
    std::fs::hard_link(root.path().join("data"), root.path().join("alias")).unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let host = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(fs::FILE_SHARE_READ)
        .open(root.path().join("data"))
        .unwrap();
    assert_eq!(
        fs.open("alias", options(CreateDisposition::OVERWRITE), &request)
            .await
            .err(),
        Some(Status::SHARING_VIOLATION)
    );
    assert_eq!(
        std::fs::read(root.path().join("data")).unwrap(),
        b"original"
    );
    drop(host);
    let (first, _) = fs
        .open(
            "data",
            OpenOptions {
                access: AccessMask::FILE_GENERIC_READ.into_bits(),
                share_access: ShareAccess::new().with_read(true).into_bits(),
                ..options(CreateDisposition::OPEN)
            },
            &request,
        )
        .await
        .unwrap();
    assert!(
        std::fs::OpenOptions::new()
            .write(true)
            .open(root.path().join("alias"))
            .is_err()
    );
    let (alias, _) = fs
        .open(
            "alias",
            OpenOptions {
                access: AccessMask::FILE_GENERIC_READ.into_bits(),
                ..options(CreateDisposition::OPEN)
            },
            &request,
        )
        .await
        .unwrap();
    let one = fs.metadata(&first, &request).await.unwrap();
    let two = fs.metadata(&alias, &request).await.unwrap();
    assert_eq!(one.id, two.id);
    assert_eq!(one.number_of_links, 2);
    fs.close(&first, &request).await.unwrap();
    fs.close(&alias, &request).await.unwrap();
    assert!(
        std::fs::OpenOptions::new()
            .write(true)
            .open(root.path().join("alias"))
            .is_ok()
    );
}

#[async_test]
async fn rejected_options_and_cancellation_have_no_effects(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    for (name, bits) in [
        ("backup", nt::FILE_OPEN_FOR_BACKUP_INTENT),
        ("unbuffered", nt::FILE_NO_INTERMEDIATE_BUFFERING),
    ] {
        assert_eq!(
            fs.open(
                name,
                OpenOptions {
                    options: bits,
                    ..options(CreateDisposition::CREATE)
                },
                &request
            )
            .await
            .err(),
            Some(Status::NOT_SUPPORTED)
        );
        assert!(!root.path().join(name).exists());
    }
    for name in ["C:\\outside", "\\absolute", "bad*", "bad\u{0}"] {
        assert!(
            fs.open(name, options(CreateDisposition::CREATE), &request)
                .await
                .is_err()
        );
    }
    std::fs::write(root.path().join("data"), b"preserve").unwrap();
    request.cancel();
    assert_eq!(
        fs.open("data", options(CreateDisposition::OVERWRITE), &request)
            .await
            .err(),
        Some(Status::CANCELLED)
    );
    assert_eq!(
        std::fs::read(root.path().join("data")).unwrap(),
        b"preserve"
    );
    assert_eq!(fs.0.opens.load(Ordering::Relaxed), 0);
}

#[async_test]
async fn captured_root_and_open_identity_survive_host_rename(driver: DefaultDriver) {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("data"), b"old").unwrap();
    let fs = WindowsFs::new(&root, Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    std::fs::rename(&root, parent.path().join("moved")).unwrap();
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("data"), b"replacement").unwrap();
    let (again, _) = fs
        .open("data", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    assert_eq!(fs.read(&again, 0, 3, &request).await.unwrap(), b"old");
    let identity = fs.metadata(&again, &request).await.unwrap().id;
    std::fs::rename(
        parent.path().join("moved/data"),
        parent.path().join("moved/renamed"),
    )
    .unwrap();
    let (file, _) = fs
        .open("renamed", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    assert_eq!(fs.read(&file, 0, 3, &request).await.unwrap(), b"old");
    assert_eq!(fs.metadata(&again, &request).await.unwrap().id, identity);
    fs.close(&again, &request).await.unwrap();
    fs.close(&file, &request).await.unwrap();
}

#[async_test]
async fn native_opens_do_not_add_metadata_or_synchronize_access(driver: DefaultDriver) {
    use pal::windows::security::{LocalSecurityDescriptor, create_file_with_security};
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let descriptor: LocalSecurityDescriptor =
        "D:P(D;;0x00100088;;;WD)(A;;FA;;;WD)".parse().unwrap();
    let mut host = create_file_with_security(&root.path().join("restricted"), &descriptor).unwrap();
    host.write_all(b"allowed").unwrap();
    drop(host);
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (file, _) = fs
        .open(
            "restricted",
            OpenOptions {
                access: AccessMask::new().with_read_data(true).into_bits(),
                ..options(CreateDisposition::OPEN)
            },
            &request,
        )
        .await
        .unwrap();
    assert_eq!(fs.read(&file, 0, 7, &request).await.unwrap(), b"allowed");
    fs.close(&file, &request).await.unwrap();
    assert_eq!(
        fs.open(
            "restricted",
            OpenOptions {
                access: AccessMask::new()
                    .with_read_data(true)
                    .with_synchronize(true)
                    .into_bits(),
                ..options(CreateDisposition::OPEN)
            },
            &request
        )
        .await
        .err(),
        Some(Status::ACCESS_DENIED)
    );
}

#[async_test]
async fn rename_does_not_require_source_metadata_or_synchronize_access(driver: DefaultDriver) {
    use pal::windows::security::{LocalSecurityDescriptor, create_file_with_security};
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let descriptor: LocalSecurityDescriptor =
        "D:P(D;;0x00100088;;;WD)(A;;FA;;;WD)".parse().unwrap();
    let mut host = create_file_with_security(&root.path().join("before"), &descriptor).unwrap();
    host.write_all(b"retained").unwrap();
    drop(host);
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let access = AccessMask::new().with_delete(true).into_bits();
    let (file, _) = fs
        .open(
            "before",
            OpenOptions {
                access,
                ..options(CreateDisposition::OPEN)
            },
            &request,
        )
        .await
        .unwrap();
    fs.rename(&file, "after", false, &request).await.unwrap();
    fs.close(&file, &request).await.unwrap();
    assert_eq!(
        fs.open(
            "before",
            OpenOptions {
                access,
                ..options(CreateDisposition::OPEN)
            },
            &request
        )
        .await
        .err(),
        Some(Status::OBJECT_NAME_NOT_FOUND)
    );
    let (file, _) = fs
        .open(
            "after",
            OpenOptions {
                access: AccessMask::new().with_read_data(true).into_bits(),
                ..options(CreateDisposition::OPEN)
            },
            &request,
        )
        .await
        .unwrap();
    assert_eq!(fs.read(&file, 0, 8, &request).await.unwrap(), b"retained");
    fs.close(&file, &request).await.unwrap();
}

#[async_test]
async fn execute_read_mapping_preserves_directory_rights_and_host_acl_denial(
    driver: DefaultDriver,
) {
    use pal::windows::security::{LocalSecurityDescriptor, create_file_with_security};
    let root = tempfile::tempdir().unwrap();
    let descriptor: LocalSecurityDescriptor = "D:P(D;;0x1;;;WD)(A;;FA;;;WD)".parse().unwrap();
    drop(create_file_with_security(&root.path().join("execute-only"), &descriptor).unwrap());
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let access = AccessMask::new()
        .with_execute(true)
        .with_read_attributes(true)
        .into_bits();
    let (native, _) = native::open(
        Some(&fs.0.root),
        &"execute-only".encode_utf16().collect::<Vec<_>>(),
        &Create {
            access,
            sharing: fs::FILE_SHARE_READ | fs::FILE_SHARE_WRITE | fs::FILE_SHARE_DELETE,
            disposition: nt::FILE_OPEN,
            options: nt::FILE_NON_DIRECTORY_FILE,
            attributes: 0,
        },
    )
    .unwrap();
    drop(native);
    assert_eq!(
        fs.open(
            "execute-only",
            OpenOptions {
                access,
                ..options(CreateDisposition::OPEN)
            },
            &request
        )
        .await
        .err(),
        Some(Status::ACCESS_DENIED)
    );
    std::fs::create_dir(root.path().join("directory")).unwrap();
    let (directory, _) = fs
        .open(
            "directory",
            OpenOptions {
                access,
                options: nt::FILE_DIRECTORY_FILE,
                ..options(CreateDisposition::OPEN)
            },
            &request,
        )
        .await
        .unwrap();
    assert_eq!(
        fs.metadata(&directory, &request)
            .await
            .unwrap()
            .granted_access,
        access
    );
    assert_eq!(
        fs.list(&directory, &request).await.unwrap_err(),
        Status::ACCESS_DENIED
    );
    fs.close(&directory, &request).await.unwrap();
}

#[async_test]
async fn exclusive_directory_enumeration_needs_no_synchronize_and_restarts(driver: DefaultDriver) {
    use pal::windows::security::{LocalSecurityDescriptor, create_directory_with_security};
    let root = tempfile::tempdir().unwrap();
    let descriptor: LocalSecurityDescriptor =
        "D:P(D;;0x00100008;;;WD)(A;;FA;;;WD)".parse().unwrap();
    let path = root.path().join("directory");
    create_directory_with_security(&path, &descriptor).unwrap();
    std::fs::write(path.join("entry"), b"actual").unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (directory, _) = fs
        .open(
            "directory",
            OpenOptions {
                access: AccessMask::new()
                    .with_read_data(true)
                    .with_read_attributes(true)
                    .into_bits(),
                share_access: 0,
                options: nt::FILE_DIRECTORY_FILE,
                ..options(CreateDisposition::OPEN)
            },
            &request,
        )
        .await
        .unwrap();
    for _ in 0..2 {
        let entries = fs.list(&directory, &request).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "entry");
        assert_eq!(entries[0].size, 6);
    }
    fs.close(&directory, &request).await.unwrap();
}

#[async_test]
async fn ill_formed_utf16_enumeration_is_an_error_not_lossy_or_omitted(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (invalid, _) = native::open(
        Some(&fs.0.root),
        &[0xd800],
        &Create {
            access: fs::FILE_READ_ATTRIBUTES,
            sharing: fs::FILE_SHARE_READ | fs::FILE_SHARE_WRITE | fs::FILE_SHARE_DELETE,
            disposition: nt::FILE_CREATE,
            options: nt::FILE_NON_DIRECTORY_FILE,
            attributes: 0,
        },
    )
    .unwrap();
    let (directory, _) = fs
        .open(
            "",
            OpenOptions {
                options: nt::FILE_DIRECTORY_FILE,
                ..options(CreateDisposition::OPEN)
            },
            &request,
        )
        .await
        .unwrap();
    assert_eq!(
        fs.list(&directory, &request).await.unwrap_err(),
        Status::OBJECT_NAME_INVALID
    );
    fs.close(&directory, &request).await.unwrap();
    drop(invalid);
}

#[async_test]
#[ignore = "requires host permission to enable case-sensitive directories"]
async fn case_sensitive_root_and_nested_directory_are_rejected(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let root_handle = native::root(root.path()).unwrap();
    let (directory, _) = native::open(
        Some(&root_handle),
        &[],
        &Create {
            access: fs::FILE_READ_ATTRIBUTES | fs::FILE_WRITE_ATTRIBUTES,
            sharing: fs::FILE_SHARE_READ | fs::FILE_SHARE_WRITE | fs::FILE_SHARE_DELETE,
            disposition: nt::FILE_OPEN,
            options: nt::FILE_DIRECTORY_FILE,
            attributes: 0,
        },
    )
    .unwrap();
    native::set_case_sensitive(&directory, true).unwrap();
    assert_eq!(
        WindowsFs::new(root.path(), Arc::new(driver.clone()))
            .await
            .err()
            .unwrap()
            .0,
        Status::NOT_SUPPORTED
    );
    native::set_case_sensitive(&directory, false).unwrap();
    std::fs::create_dir(root.path().join("nested")).unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let (nested, _) = native::open(
        Some(&fs.0.root),
        &"nested".encode_utf16().collect::<Vec<_>>(),
        &Create {
            access: fs::FILE_READ_ATTRIBUTES | fs::FILE_WRITE_ATTRIBUTES,
            sharing: fs::FILE_SHARE_READ | fs::FILE_SHARE_WRITE | fs::FILE_SHARE_DELETE,
            disposition: nt::FILE_OPEN,
            options: nt::FILE_DIRECTORY_FILE,
            attributes: 0,
        },
    )
    .unwrap();
    native::set_case_sensitive(&nested, true).unwrap();
    let request = RequestContext::new(1);
    assert_eq!(
        fs.open("nested\\new", options(CreateDisposition::CREATE), &request)
            .await
            .err(),
        Some(Status::NOT_SUPPORTED)
    );
    assert!(!root.path().join("nested/new").exists());
    native::set_case_sensitive(&nested, false).unwrap();
}

#[async_test]
async fn junction_traversal_is_rejected_without_host_effects(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("data"), b"preserve").unwrap();
    std::fs::create_dir(root.path().join("junction")).unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let (junction, _) = native::open(
        Some(&fs.0.root),
        &"junction".encode_utf16().collect::<Vec<_>>(),
        &Create {
            access: fs::FILE_GENERIC_WRITE,
            sharing: fs::FILE_SHARE_READ | fs::FILE_SHARE_WRITE | fs::FILE_SHARE_DELETE,
            disposition: nt::FILE_OPEN,
            options: nt::FILE_DIRECTORY_FILE,
            attributes: 0,
        },
    )
    .unwrap();
    native::set_junction(&junction, outside.path()).unwrap();
    drop(junction);
    let request = RequestContext::new(1);
    for (name, disposition) in [
        ("junction\\data", CreateDisposition::OVERWRITE),
        ("junction\\new", CreateDisposition::CREATE),
        ("junction\\..\\data", CreateDisposition::OPEN),
    ] {
        assert_eq!(
            fs.open(name, options(disposition), &request).await.err(),
            Some(Status(
                windows_sys::Win32::Foundation::STATUS_REPARSE_POINT_ENCOUNTERED as u32
            ))
        );
    }
    assert_eq!(
        std::fs::read(outside.path().join("data")).unwrap(),
        b"preserve"
    );
    assert!(!outside.path().join("new").exists());
}

#[async_test]
#[ignore = "requires permission to create native Windows symbolic links"]
async fn intermediate_and_leaf_symlinks_cannot_escape_or_truncate(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("data"), b"preserve").unwrap();
    std::os::windows::fs::symlink_dir(outside.path(), root.path().join("redirect")).unwrap();
    std::os::windows::fs::symlink_file(outside.path().join("data"), root.path().join("leaf"))
        .unwrap();
    let fs = WindowsFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    for name in ["redirect\\data", "redirect\\..\\data", "leaf"] {
        assert_eq!(
            fs.open(name, options(CreateDisposition::OVERWRITE), &request)
                .await
                .err(),
            Some(Status(
                windows_sys::Win32::Foundation::STATUS_REPARSE_POINT_ENCOUNTERED as u32
            ))
        );
    }
    assert_eq!(
        std::fs::read(outside.path().join("data")).unwrap(),
        b"preserve"
    );
    assert_eq!(
        fs.open(
            "redirect\\new",
            options(CreateDisposition::CREATE),
            &request
        )
        .await
        .err(),
        Some(Status(
            windows_sys::Win32::Foundation::STATUS_REPARSE_POINT_ENCOUNTERED as u32
        ))
    );
    assert!(!outside.path().join("new").exists());
}
