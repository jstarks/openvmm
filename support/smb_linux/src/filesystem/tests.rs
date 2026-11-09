// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use pal_async::{DefaultDriver, async_test};
use smb::provider::{
    ByteRange, FileControl, FileControlResult, FileSystem, OpenError, OpenOptions, RequestContext,
};
use smb::spec::{AccessMask, CreateAction, CreateDisposition, CreateOptions, Status};
use smb::test_support::{
    Operation,
    contracts::{self, Expectations, Feature, Fixture},
};
use std::sync::Arc;
use test_with_tracing::test;

struct NativeFixture(LinuxFs);

struct MaskedDriver {
    inner: DefaultDriver,
    unavailable: u8,
}

// UNSAFETY: Forward SQE submission without changing the caller's ownership contract.
#[expect(unsafe_code)]
impl Driver for MaskedDriver {
    fn new_dyn_timer(&self) -> pal_async::driver::PollImpl<dyn pal_async::timer::PollTimer> {
        self.inner.new_dyn_timer()
    }
    fn new_dyn_fd_ready(
        &self,
        fd: std::os::fd::RawFd,
    ) -> std::io::Result<pal_async::driver::PollImpl<dyn pal_async::fd::PollFdReady>> {
        self.inner.new_dyn_fd_ready(fd)
    }
    fn new_dyn_socket_ready(
        &self,
        fd: std::os::fd::RawFd,
    ) -> std::io::Result<pal_async::driver::PollImpl<dyn pal_async::socket::PollSocketReady>> {
        self.inner.new_dyn_socket_ready(fd)
    }
    fn new_dyn_wait(
        &self,
        fd: std::os::fd::RawFd,
        size: usize,
    ) -> std::io::Result<pal_async::driver::PollImpl<dyn pal_async::wait::PollWait>> {
        self.inner.new_dyn_wait(fd, size)
    }
    fn io_uring_probe(&self, opcode: u8) -> bool {
        opcode != self.unavailable && self.inner.io_uring_probe(opcode)
    }
    unsafe fn io_uring_submit(
        &self,
        entry: pal_async::io_uring::Entry,
    ) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<i32>> + Send + '_>> {
        // SAFETY: The wrapper preserves the caller's SQE ownership contract.
        unsafe { self.inner.io_uring_submit(entry) }
    }
}

impl Fixture for NativeFixture {
    type Backend = LinuxFs;
    fn filesystem(&self) -> &LinuxFs {
        &self.0
    }
    fn expectations(&self) -> Expectations {
        Expectations {
            filesystem_information: Feature::Supported,
            allocation: Feature::Unsupported(Status::NOT_SUPPORTED),
            creation_allocation: false,
            file_mode: Feature::Unsupported(Status::NOT_SUPPORTED),
            security_queries: Feature::Supported,
            file_acl_updates: Feature::Unsupported(Status::INVALID_DEVICE_REQUEST),
            directory_acl_updates: Feature::Unsupported(Status::INVALID_DEVICE_REQUEST),
            acl_inheritance: Feature::Unsupported(Status::NOT_SUPPORTED),
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
            basic_information: Feature::Unsupported(Status::NOT_SUPPORTED),
            rename: Feature::Supported,
            locks: Feature::Supported,
            notifications: Feature::Unsupported(Status::NOT_SUPPORTED),
        }
    }
    async fn wait_until_pending(&self, operation: Operation, request: &RequestContext) {
        assert_eq!(operation, Operation::Lock);
        assert!(
            self.0
                .0
                .state
                .lock()
                .waiters
                .values()
                .any(|id| *id == request.id())
        );
    }
}

macro_rules! contract_test {
    ($name:ident) => {
        #[async_test]
        async fn $name(driver: DefaultDriver) {
            let root = tempfile::tempdir().unwrap();
            let fs = LinuxFs::new(root.path(), Arc::new(driver)).await.unwrap();
            contracts::$name(&NativeFixture(fs)).await;
        }
    };
}

contract_test!(data_and_identity);
contract_test!(filesystem_information);
contract_test!(security_queries);
contract_test!(sharing_and_handle_release);
contract_test!(lock_conflicts_and_io);
contract_test!(lock_waiters_and_cancellation);
contract_test!(lock_rollback_and_drop);
contract_test!(rename_identity);
contract_test!(security_creation);
contract_test!(creation_eas);
contract_test!(extended_attributes);
contract_test!(named_streams);
contract_test!(stream_information);

#[async_test]
async fn unavailable_ftruncate_uses_real_bounded_worker_path(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let driver = MaskedDriver {
        inner: driver,
        unavailable: io_uring::opcode::Ftruncate::CODE,
    };
    let fs = LinuxFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (file, _) = fs
        .open("file", options(CreateDisposition::CREATE), &request)
        .await
        .unwrap();
    fs.write(&file, 0, b"abcd", &request).await.unwrap();
    let before = fs.0.io.submitted.load(Ordering::Relaxed);
    fs.set_len(&file, 2, &request).await.unwrap();
    assert_eq!(fs.0.io.submitted.load(Ordering::Relaxed), before);
    assert_eq!(std::fs::read(root.path().join("file")).unwrap(), b"ab");
    fs.close(&file, &request).await.unwrap();
}

#[async_test]
async fn required_data_opcode_has_no_blocking_fallback(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let driver = MaskedDriver {
        inner: driver,
        unavailable: io_uring::opcode::Read::CODE,
    };
    let result = LinuxFs::new(root.path(), Arc::new(driver)).await;
    let error = result
        .err()
        .expect("missing mandatory READ must reject initialization");
    assert_eq!(error.0.kind(), std::io::ErrorKind::Unsupported);
}

#[async_test]
async fn root_delete_mode_is_rejected_before_open_publication(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = LinuxFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let options = OpenOptions {
        options: CreateOptions::new().with_delete_on_close(true).into_bits(),
        ..options(CreateDisposition::OPEN)
    };
    assert_eq!(
        fs.open("", options, &request).await.unwrap_err(),
        Status::CANNOT_DELETE
    );
    assert!(root.path().is_dir());
    assert!(fs.0.state.lock().opens.is_empty());
}

#[async_test]
async fn append_uses_eof_and_does_not_conflict_with_unrelated_locks(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file"), b"head").unwrap();
    let fs = LinuxFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (owner, _) = fs
        .open("file", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    let append = OpenOptions {
        access: AccessMask::new().with_append_data(true).into_bits(),
        ..options(CreateDisposition::OPEN)
    };
    let (append, _) = fs.open("file", append, &request).await.unwrap();
    fs.lock(
        &owner,
        ByteRange {
            offset: 0,
            length: 4,
        },
        false,
        true,
        &request,
    )
    .await
    .unwrap();
    fs.write(&append, 0, b"tail", &request).await.unwrap();
    assert_eq!(
        std::fs::read(root.path().join("file")).unwrap(),
        b"headtail"
    );
    assert_eq!(
        fs.set_len(&append, 0, &request).await.unwrap_err(),
        Status::ACCESS_DENIED
    );
    fs.close(&append, &request).await.unwrap();
    fs.close(&owner, &request).await.unwrap();
}

#[async_test]
async fn disjoint_writes_on_one_open_can_be_in_flight_together(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = LinuxFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let first = RequestContext::new(1);
    let second = RequestContext::new(2);
    let (file, _) = fs
        .open("file", options(CreateDisposition::CREATE), &first)
        .await
        .unwrap();
    let mut a = Box::pin(fs.write(&file, 0, b"one", &first));
    let mut b = Box::pin(fs.write(&file, 8, b"two", &second));
    std::future::poll_fn(|cx| {
        assert!(a.as_mut().poll(cx).is_pending());
        assert!(b.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(fs.0.state.lock().active.len(), 2);
    let (a, b) = futures::join!(a, b);
    assert_eq!((a.unwrap(), b.unwrap()), (3, 3));
    assert_eq!(
        std::fs::read(root.path().join("file")).unwrap(),
        b"one\0\0\0\0\0two"
    );
    fs.close(&file, &first).await.unwrap();
}

fn options(disposition: CreateDisposition) -> OpenOptions<'static> {
    OpenOptions {
        access: AccessMask::FILE_ALL_ACCESS.into_bits(),
        share_access: 7,
        disposition: disposition.0,
        options: 0,
        attributes: 0,
        allocation_size: 0,
        security: None,
        extended_attributes: None,
    }
}

#[async_test]
async fn native_bytes_case_and_projection(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("Upper"), b"upper").unwrap();
    std::fs::write(root.path().join("upper"), b"lower").unwrap();
    std::fs::write(root.path().join("a:b\\c"), b"mapped").unwrap();
    let fs = LinuxFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (upper, _) = fs
        .open("Upper", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    let (lower, _) = fs
        .open("upper", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    assert_ne!(
        fs.metadata(&upper, &request).await.unwrap().id,
        fs.metadata(&lower, &request).await.unwrap().id
    );
    assert_eq!(fs.read(&upper, 0, 32, &request).await.unwrap(), b"upper");
    assert_eq!(fs.read(&lower, 0, 32, &request).await.unwrap(), b"lower");
    let (mapped, _) = fs
        .open(
            "a\u{f03a}b\u{f05c}c",
            options(CreateDisposition::OPEN),
            &request,
        )
        .await
        .unwrap();
    assert_eq!(fs.read(&mapped, 0, 32, &request).await.unwrap(), b"mapped");
    fs.write(&mapped, 0, b"host!!", &request).await.unwrap();
    fs.flush(&mapped, &request).await.unwrap();
    assert_eq!(
        std::fs::read(root.path().join("a:b\\c")).unwrap(),
        b"host!!"
    );
    let (directory, _) = fs
        .open("", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    let names = fs
        .list(&directory, &request)
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect::<Vec<_>>();
    assert!(names.contains(&"a\u{f03a}b\u{f05c}c".to_owned()));
    fs.close(&mapped, &request).await.unwrap();
    assert_eq!(
        fs.read(&mapped, 0, 1, &request).await.unwrap_err(),
        Status::FILE_CLOSED
    );
    fs.close(&mapped, &request).await.unwrap();
}

#[async_test]
async fn host_rename_and_replacement_preserve_open_identity(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file"), b"original").unwrap();
    let fs = LinuxFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (old, _) = fs
        .open("file", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    std::fs::rename(root.path().join("file"), root.path().join("old")).unwrap();
    std::fs::write(root.path().join("file"), b"replacement").unwrap();
    let (new, _) = fs
        .open("file", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    assert_ne!(
        fs.metadata(&old, &request).await.unwrap().id128,
        fs.metadata(&new, &request).await.unwrap().id128
    );
    fs.write(&old, 0, b"retained", &request).await.unwrap();
    assert_eq!(std::fs::read(root.path().join("old")).unwrap(), b"retained");
    assert_eq!(
        fs.read(&new, 0, 32, &request).await.unwrap(),
        b"replacement"
    );
}

#[async_test]
async fn confinement_symlink_errors_and_directory_hints(driver: DefaultDriver) {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret"), b"outside").unwrap();
    std::fs::create_dir(root.path().join("dir")).unwrap();
    std::fs::write(root.path().join("inside"), b"inside").unwrap();
    symlink("dir", root.path().join("relative")).unwrap();
    symlink(outside.path(), root.path().join("absolute")).unwrap();
    symlink("../missing", root.path().join("dangling")).unwrap();
    let fs = LinuxFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (inside, _) = fs
        .open("..\\..\\inside", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    assert_eq!(fs.read(&inside, 0, 32, &request).await.unwrap(), b"inside");
    assert_eq!(
        fs.open(
            "absolute\\secret",
            options(CreateDisposition::OPEN),
            &request
        )
        .await
        .unwrap_err(),
        Status::NOT_SUPPORTED
    );
    let error = fs
        .open_with_reparse(
            "relative\\..\\inside",
            options(CreateDisposition::OPEN),
            &request,
        )
        .await
        .unwrap_err();
    let OpenError::SymbolicLink(link) = error else {
        panic!("expected stopped symlink")
    };
    assert_eq!(link.substitute_name, "dir");
    assert_eq!(link.unparsed_suffix, "\\..\\inside");
    let reparse = OpenOptions {
        options: CreateOptions::new()
            .with_open_reparse_point(true)
            .into_bits(),
        ..options(CreateDisposition::OPEN)
    };
    let (link, _) = fs.open("relative", reparse, &request).await.unwrap();
    let metadata = fs.metadata(&link, &request).await.unwrap();
    assert!(metadata.attributes().reparse_point());
    assert!(metadata.attributes().directory());
    let FileControlResult::ReparsePoint(point) = fs
        .file_control(
            &link,
            FileControl::GetReparsePoint { maximum: 16384 },
            &request,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(&point.data[8..12], &1u32.to_le_bytes());
    let (link, _) = fs.open("dangling", reparse, &request).await.unwrap();
    assert!(
        !fs.metadata(&link, &request)
            .await
            .unwrap()
            .attributes()
            .directory()
    );
    assert_eq!(
        fs.open(
            "absolute\\new",
            options(CreateDisposition::CREATE),
            &request
        )
        .await
        .unwrap_err(),
        Status::NOT_SUPPORTED
    );
    assert!(!outside.path().join("new").exists());
}

#[async_test]
async fn native_creation_truncation_and_close_delete(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = LinuxFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (file, _) = fs
        .open("file", options(CreateDisposition::CREATE), &request)
        .await
        .unwrap();
    fs.write(&file, 0, b"abcd", &request).await.unwrap();
    fs.set_len(&file, 2, &request).await.unwrap();
    fs.set_len(&file, 6, &request).await.unwrap();
    assert_eq!(
        std::fs::read(root.path().join("file")).unwrap(),
        b"ab\0\0\0\0"
    );
    fs.set_delete_on_close(&file, true, &request).await.unwrap();
    assert_eq!(
        fs.open("file", options(CreateDisposition::OPEN), &request)
            .await
            .unwrap_err(),
        Status::DELETE_PENDING
    );
    fs.close(&file, &request).await.unwrap();
    assert!(!root.path().join("file").exists());
    assert_eq!(fs.0.state.lock().opens.len(), 0);
    assert_eq!(fs.0.state.lock().locks.len(), 0);
}

#[async_test]
async fn hardlink_aliases_share_locks_and_drop_releases_them(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file"), b"abcd").unwrap();
    std::fs::hard_link(root.path().join("file"), root.path().join("alias")).unwrap();
    let fs = LinuxFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (owner, _) = fs
        .open("file", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    let (other, _) = fs
        .open("alias", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    let range = ByteRange {
        offset: 0,
        length: 4,
    };
    fs.lock(&owner, range, true, true, &request).await.unwrap();
    fs.lock(&owner, range, false, true, &request).await.unwrap();
    assert_eq!(
        fs.read(&other, 0, 4, &request).await.unwrap_err(),
        Status::FILE_LOCK_CONFLICT
    );
    assert_eq!(
        fs.write(&owner, 0, b"efgh", &request).await.unwrap_err(),
        Status::FILE_LOCK_CONFLICT
    );
    fs.unlock(&owner, range, &request).await.unwrap();
    assert_eq!(fs.read(&other, 0, 4, &request).await.unwrap(), b"abcd");
    assert_eq!(
        fs.write(&other, 0, b"efgh", &request).await.unwrap_err(),
        Status::FILE_LOCK_CONFLICT
    );
    drop(owner);
    fs.write(&other, 0, b"efgh", &request).await.unwrap();
    assert_eq!(std::fs::read(root.path().join("file")).unwrap(), b"efgh");
}

#[async_test]
async fn sharing_checked_before_destructive_open(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file"), b"retained").unwrap();
    let fs = LinuxFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let restrictive = OpenOptions {
        share_access: 1,
        ..options(CreateDisposition::OPEN)
    };
    let (owner, _) = fs.open("file", restrictive, &request).await.unwrap();
    assert_eq!(
        fs.open("file", options(CreateDisposition::OVERWRITE), &request)
            .await
            .unwrap_err(),
        Status::SHARING_VIOLATION
    );
    assert_eq!(
        std::fs::read(root.path().join("file")).unwrap(),
        b"retained"
    );
    fs.close(&owner, &request).await.unwrap();
    let (_file, _) = fs
        .open("file", options(CreateDisposition::OVERWRITE), &request)
        .await
        .unwrap();
    assert_eq!(std::fs::read(root.path().join("file")).unwrap(), b"");
}

#[async_test]
async fn unsupported_creation_metadata_has_no_effect(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = LinuxFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    for (name, security, eas) in [
        ("security", Some(&b"invalid"[..]), None),
        ("eas", None, Some(&b"invalid"[..])),
    ] {
        let options = OpenOptions {
            security,
            extended_attributes: eas,
            ..options(CreateDisposition::CREATE)
        };
        assert_eq!(
            fs.open(name, options, &request).await.unwrap_err(),
            Status::NOT_SUPPORTED
        );
        assert!(!root.path().join(name).exists());
    }
}

#[async_test]
async fn concurrent_open_if_has_one_creator(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = LinuxFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let first = RequestContext::new(1);
    let second = RequestContext::new(2);
    let (first, second) = futures::join!(
        fs.open("same", options(CreateDisposition::OPEN_IF), &first),
        fs.open("same", options(CreateDisposition::OPEN_IF), &second)
    );
    let (first, first_action) = first.unwrap();
    let (second, second_action) = second.unwrap();
    let mut actions = [first_action, second_action];
    actions.sort();
    assert_eq!(actions, [CreateAction::OPENED.0, CreateAction::CREATED.0]);
    let request = RequestContext::new(3);
    assert_eq!(
        fs.metadata(&first, &request).await.unwrap().id128,
        fs.metadata(&second, &request).await.unwrap().id128
    );
    fs.close(&first, &request).await.unwrap();
    fs.close(&second, &request).await.unwrap();
}

#[async_test]
async fn rename_and_close_do_not_act_on_a_host_replacement(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file"), b"original").unwrap();
    let fs = LinuxFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (file, _) = fs
        .open("file", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    fs.set_delete_on_close(&file, true, &request).await.unwrap();
    std::fs::rename(root.path().join("file"), root.path().join("original")).unwrap();
    std::fs::write(root.path().join("file"), b"replacement").unwrap();
    assert_eq!(
        fs.rename(&file, "renamed", false, &request)
            .await
            .unwrap_err(),
        Status::OBJECT_NAME_NOT_FOUND
    );
    fs.close(&file, &request).await.unwrap();
    assert_eq!(
        std::fs::read(root.path().join("file")).unwrap(),
        b"replacement"
    );
    assert!(!root.path().join("renamed").exists());
}

#[async_test]
async fn foreign_provider_handles_are_rejected(driver: DefaultDriver) {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    std::fs::write(first.path().join("file"), b"first").unwrap();
    std::fs::write(second.path().join("file"), b"second").unwrap();
    let first = LinuxFs::new(first.path(), Arc::new(driver.clone()))
        .await
        .unwrap();
    let second = LinuxFs::new(second.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (_file, _) = first
        .open("file", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    let (foreign, _) = second
        .open("file", options(CreateDisposition::OPEN), &request)
        .await
        .unwrap();
    assert_eq!(
        first.read(&foreign, 0, 32, &request).await.unwrap_err(),
        Status::FILE_CLOSED
    );
    assert_eq!(
        first.close(&foreign, &request).await.unwrap_err(),
        Status::FILE_CLOSED
    );
    assert_eq!(
        second.read(&foreign, 0, 32, &request).await.unwrap(),
        b"second"
    );
}

#[async_test]
async fn submitted_write_survives_cancel_and_unpolled_interval(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = LinuxFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (file, _) = fs
        .open("file", options(CreateDisposition::CREATE), &request)
        .await
        .unwrap();
    let mut write = Box::pin(fs.write(&file, 0, b"retained", &request));
    std::future::poll_fn(|cx| {
        assert!(
            write.as_mut().poll(cx).is_pending(),
            "must retain an actually submitted operation"
        );
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(fs.0.state.lock().active.len(), 1);
    request.cancel();
    let unrelated = RequestContext::new(2);
    let (other, _) = fs
        .open("other", options(CreateDisposition::CREATE), &unrelated)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(root.path().join("file")).unwrap(),
        b"retained"
    );
    let mut close = Box::pin(fs.close(&file, &request));
    std::future::poll_fn(|cx| {
        assert!(close.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(write.await.unwrap(), 8);
    close.await.unwrap();
    fs.close(&other, &unrelated).await.unwrap();
    assert_eq!(fs.0.state.lock().active.len(), 0);
    assert_eq!(fs.0.state.lock().opens.len(), 0);
}

#[async_test]
async fn flush_of_committed_write_is_not_skipped_by_late_cancel(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = LinuxFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let (file, _) = fs
        .open("file", options(CreateDisposition::CREATE), &request)
        .await
        .unwrap();
    fs.write(&file, 0, b"durable", &request).await.unwrap();
    request.cancel();
    let before = fs.0.io.submitted.load(Ordering::Relaxed);
    fs.flush(&file, &request).await.unwrap();
    assert!(fs.0.io.submitted.load(Ordering::Relaxed) > before);
    assert_eq!(std::fs::read(root.path().join("file")).unwrap(), b"durable");
    fs.close(&file, &request).await.unwrap();
}

#[async_test]
async fn bounded_workers_cancel_before_start_and_drain_running_jobs(driver: DefaultDriver) {
    use std::sync::atomic::AtomicUsize;
    use unicycle::FuturesUnordered;
    let root = tempfile::tempdir().unwrap();
    let fs = LinuxFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let started = Arc::new(AtomicUsize::new(0));
    let changed = Arc::new(Event::new());
    let (release, wait) = async_channel::bounded(4);
    let mut jobs = FuturesUnordered::new();
    for _ in 0..4 {
        let wait = wait.clone();
        let started = started.clone();
        let changed = changed.clone();
        jobs.push(fs.0.io.worker(&request, move || {
            started.fetch_add(1, Ordering::Release);
            changed.notify(usize::MAX);
            wait.recv_blocking().unwrap();
            Ok(())
        }));
    }
    {
        let started_all = async {
            loop {
                let listener = changed.listen();
                if started.load(Ordering::Acquire) == 4 {
                    break;
                }
                listener.await;
            }
        };
        let mut started_all = std::pin::pin!(started_all.fuse());
        let mut blocked = std::pin::pin!(jobs.next().fuse());
        futures::select! {
            () = started_all => {},
            _ = blocked => panic!("gated worker completed before release"),
        }
    }
    let cancelled = RequestContext::new(2);
    let never = Arc::new(AtomicBool::new(false));
    let ran = never.clone();
    let mut queued = Box::pin(fs.0.io.worker(&cancelled, move || {
        ran.store(true, Ordering::Release);
        Ok(())
    }));
    std::future::poll_fn(|cx| {
        assert!(queued.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    cancelled.cancel();
    assert_eq!(
        queued.await.unwrap_err().raw_os_error(),
        Some(libc::ECANCELED)
    );
    assert!(!never.load(Ordering::Acquire));
    request.cancel();
    for _ in 0..4 {
        release.send(()).await.unwrap();
    }
    while let Some(result) = jobs.next().await {
        result.unwrap();
    }
    assert_eq!(started.load(Ordering::Acquire), 4);
}

#[async_test]
async fn cancellation_after_native_create_preserves_committed_success(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = LinuxFs::new(root.path(), Arc::new(driver)).await.unwrap();
    let request = RequestContext::new(1);
    let mut open = Box::pin(fs.open("created", options(CreateDisposition::CREATE), &request));
    let mut cancelled = false;
    let result = std::future::poll_fn(|cx| {
        if root.path().join("created").exists() && !cancelled {
            request.cancel();
            cancelled = true;
        }
        open.as_mut().poll(cx)
    })
    .await;
    assert!(
        cancelled,
        "test must cancel after the real namespace effect"
    );
    let (file, _) = result.expect("committed creation must not be reported as cancelled");
    fs.close(&file, &request).await.unwrap();
    assert!(root.path().join("created").exists());
}
