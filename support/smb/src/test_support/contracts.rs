// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Direct filesystem-provider contract scenarios, without an SMB connection.
//!
//! Give each scenario a fresh [`Fixture`] with an empty, isolated, writable
//! filesystem and enough capacity for a few small files. Register scenarios as
//! separate tests using the provider's own executor and resource lifetime.
//! Expectations are declarations, not feature detection: an unexpected
//! `NOT_SUPPORTED` fails, and declared unsupported operations are exercised.
//!
//! These scenarios do not establish native durability, cancellation of arbitrary
//! host I/O, allocation limits, or timestamp precision. They also do not test
//! engine-owned access checks, request ordering, CLOSE draining, or wire encoding.

use super::Operation;
use crate::provider::{
    BasicInformation, ByteRange, Change, FileSystem, NotifyResult, OpenOptions, RequestContext,
};
use crate::spec::{
    AccessMask, CreateAction, CreateDisposition, CreateOptions, FileAttributes, NotifyAction,
    NotifyFilter, ShareAccess, Status,
};
use futures::FutureExt;
use std::future::Future;
use std::pin::Pin;

/// Expected behavior of an optional provider feature.
#[derive(Debug, Clone, Copy)]
pub enum Feature {
    /// The provider must implement the scenario's semantics.
    Supported,
    /// The provider must reject the operation with this error, not succeed or skip.
    Unsupported(Status),
}

/// Explicit test expectations, not protocol capability advertisement.
#[derive(Debug, Clone, Copy)]
pub struct Expectations {
    /// Basic metadata mutation.
    pub basic_information: Feature,
    /// Byte-range acquisition, requiring unlock and rollback when supported.
    /// Rejection is probed on acquisition, without inventing a rollback token.
    pub locks: Feature,
    /// Directory change registration and delivery.
    pub notifications: Feature,
}

/// Provider-specific setup, native resource ownership, and pending-operation probes.
///
/// Run the scenarios on the actual provider. A wrapper that cancels before
/// delegation cannot establish the delegate's cancellation contract.
pub trait Fixture {
    /// Filesystem under test.
    type Backend: FileSystem;

    /// The fixture's isolated filesystem.
    fn filesystem(&self) -> &Self::Backend;

    /// Feature expectations chosen by this provider's tests.
    fn expectations(&self) -> Expectations;

    /// Observe actual watch registration or a contended lock entering its wait.
    ///
    /// Called after the operation's first pending poll. The scenario continues
    /// driving that operation while awaiting this checkpoint. A native provider
    /// must observe its registration/wait state, not just submission to a worker
    /// or an arbitrary pending poll. Synchronous registration can return at once.
    /// This probe must not cancel the request, release locks, or generate events.
    fn wait_until_pending(
        &self,
        operation: Operation,
        request: &RequestContext,
    ) -> impl Future<Output = ()>;
}

fn options(disposition: CreateDisposition, directory: bool) -> OpenOptions {
    OpenOptions {
        access: AccessMask::FILE_ALL_ACCESS.into_bits(),
        share_access: ShareAccess::ALL.into_bits(),
        disposition: disposition.0,
        options: CreateOptions::new()
            .with_directory_file(directory)
            .into_bits(),
        attributes: 0,
    }
}

async fn open<B: FileSystem>(
    fs: &B,
    name: &str,
    disposition: CreateDisposition,
    directory: bool,
    request: &RequestContext,
) -> B::File {
    fs.open(name, options(disposition, directory), request)
        .await
        .unwrap()
        .0
}

fn rejected<T>(result: Result<T, Status>, expected: Status) {
    assert!(expected.is_error(), "a rejection must be an error status");
    assert_eq!(result.err(), Some(expected));
}

fn unsupported(feature: Feature) -> Option<Status> {
    match feature {
        Feature::Supported => None,
        Feature::Unsupported(status) => {
            assert!(status.is_error(), "a rejection must be an error status");
            Some(status)
        }
    }
}

async fn pending<F: Fixture, T>(
    fixture: &F,
    operation: Operation,
    request: &RequestContext,
    future: Pin<&mut impl Future<Output = T>>,
) {
    let mut future = future.fuse();
    assert!(
        futures::poll!(&mut future).is_pending(),
        "{operation:?} completed instead of waiting"
    );
    let mut checkpoint = std::pin::pin!(fixture.wait_until_pending(operation, request).fuse());
    futures::select_biased! {
        _ = future => panic!("{operation:?} completed before its pending checkpoint"),
        () = checkpoint => {},
    }
}

async fn write_all<B: FileSystem>(
    fs: &B,
    file: &B::File,
    mut offset: u64,
    mut data: &[u8],
    request: &RequestContext,
) {
    while !data.is_empty() {
        let count = fs.write(file, offset, data, request).await.unwrap();
        assert!(count > 0 && count <= data.len(), "invalid write progress");
        offset += count as u64;
        data = &data[count..];
    }
}

async fn read_bytes<B: FileSystem>(
    fs: &B,
    file: &B::File,
    offset: u64,
    length: usize,
    request: &RequestContext,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    while bytes.len() < length {
        let remaining = length - bytes.len();
        let chunk = fs
            .read(file, offset + bytes.len() as u64, remaining, request)
            .await
            .unwrap();
        assert!(
            !chunk.is_empty() && chunk.len() <= remaining,
            "invalid read progress"
        );
        bytes.extend(chunk);
    }
    bytes
}

fn changes(result: NotifyResult, expected: &[(NotifyAction, &str)]) {
    let NotifyResult::Changes(actual) = result else {
        panic!("unexpected notification overflow");
    };
    let expected: Vec<_> = expected
        .iter()
        .map(|&(action, name)| Change {
            action,
            name: name.into(),
        })
        .collect();
    assert_eq!(actual, expected);
}

const RANGE: ByteRange = ByteRange {
    offset: 2,
    length: 4,
};

async fn rejected_lock<B: FileSystem>(
    fs: &B,
    file: &B::File,
    status: Status,
    request: &RequestContext,
) {
    rejected(fs.lock(file, RANGE, true, true, request).await, status);
}

/// Create/open actions, shared data and identity, truncation, zero extension,
/// flush, EOF, and directory enumeration. Short transfers are allowed.
pub async fn data_and_identity<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let (file, action) = fs
        .open("data", options(CreateDisposition::CREATE, false), &request)
        .await
        .unwrap();
    assert_eq!(action, CreateAction::CREATED.0);
    let initial = fs.metadata(&file, &request).await.unwrap();
    assert_eq!(initial.name, "data");
    assert!(!initial.is_directory());
    assert_eq!(initial.size, 0);
    let (peer, action) = fs
        .open("data", options(CreateDisposition::OPEN, false), &request)
        .await
        .unwrap();
    assert_eq!(action, CreateAction::OPENED.0);
    assert_eq!(fs.metadata(&peer, &request).await.unwrap().id, initial.id);
    let data = b"abcdef";
    let count = fs.write(&file, 3, data, &request).await.unwrap();
    assert!(count > 0 && count <= data.len(), "invalid write progress");
    assert_eq!(
        fs.metadata(&peer, &request).await.unwrap().size,
        3 + count as u64
    );
    let mut prefix = vec![0; 3];
    prefix.extend_from_slice(&data[..count]);
    assert_eq!(
        read_bytes(fs, &peer, 0, prefix.len(), &request).await,
        prefix
    );
    write_all(fs, &file, 3 + count as u64, &data[count..], &request).await;
    assert_eq!(read_bytes(fs, &peer, 0, 9, &request).await, b"\0\0\0abcdef");
    fs.set_len(&peer, 5, &request).await.unwrap();
    fs.set_len(&file, 10, &request).await.unwrap();
    fs.flush(&file, &request).await.unwrap();
    assert_eq!(
        read_bytes(fs, &peer, 0, 10, &request).await,
        b"\0\0\0ab\0\0\0\0\0"
    );
    let metadata = fs.metadata(&peer, &request).await.unwrap();
    assert_eq!((metadata.id, metadata.size), (initial.id, 10));
    match fs.read(&peer, 20, 8, &request).await {
        Ok(bytes) => assert!(bytes.is_empty()),
        Err(status) => assert_eq!(status, Status::END_OF_FILE),
    }
    let directory = open(fs, "directory", CreateDisposition::CREATE, true, &request).await;
    let root = open(fs, "", CreateDisposition::OPEN, true, &request).await;
    let mut entries = fs.list(&root, &request).await.unwrap();
    entries.retain(|entry| entry.name != "." && entry.name != "..");
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "data");
    assert_eq!((entries[0].id, entries[0].size), (initial.id, 10));
    assert!(!entries[0].is_directory());
    assert_eq!(entries[1].name, "directory");
    assert!(entries[1].is_directory());
    assert_ne!(entries[1].id, initial.id);
    fs.close(&root, &request).await.unwrap();
    fs.close(&directory, &request).await.unwrap();
    fs.close(&peer, &request).await.unwrap();
    fs.close(&file, &request).await.unwrap();
    let reopened = open(fs, "data", CreateDisposition::OPEN, false, &request).await;
    assert_eq!(
        fs.metadata(&reopened, &request).await.unwrap().id,
        initial.id
    );
    fs.close(&reopened, &request).await.unwrap();
}

/// Bilateral sharing, idempotent settled close, and fallback drop release.
pub async fn sharing_and_handle_release<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let created = open(fs, "sharing", CreateDisposition::CREATE, false, &request).await;
    fs.close(&created, &request).await.unwrap();
    let read = OpenOptions {
        access: AccessMask::FILE_GENERIC_READ.into_bits(),
        share_access: ShareAccess::new().with_read(true).into_bits(),
        ..options(CreateDisposition::OPEN, false)
    };
    let write = OpenOptions {
        access: AccessMask::FILE_GENERIC_WRITE.into_bits(),
        ..options(CreateDisposition::OPEN, false)
    };
    let (first, _) = fs.open("sharing", read, &request).await.unwrap();
    rejected(
        fs.open("sharing", write, &request).await,
        Status::SHARING_VIOLATION,
    );
    rejected(
        fs.open(
            "sharing",
            OpenOptions {
                share_access: 0,
                ..read
            },
            &request,
        )
        .await,
        Status::SHARING_VIOLATION,
    );
    let (second, _) = fs.open("sharing", read, &request).await.unwrap();
    fs.close(&first, &request).await.unwrap();
    fs.close(&first, &request).await.unwrap();
    rejected(
        fs.open("sharing", write, &request).await,
        Status::SHARING_VIOLATION,
    );
    fs.close(&second, &request).await.unwrap();
    let (writer, _) = fs.open("sharing", write, &request).await.unwrap();
    fs.close(&writer, &request).await.unwrap();
    let (fallback, _) = fs.open("sharing", read, &request).await.unwrap();
    rejected(
        fs.open("sharing", write, &request).await,
        Status::SHARING_VIOLATION,
    );
    drop(fallback);
    let (writer, _) = fs.open("sharing", write, &request).await.unwrap();
    fs.close(&writer, &request).await.unwrap();
}

/// Delete disposition can be cleared; committed deletion waits for the last
/// settled close. An initially delete-on-close open also removes its object.
pub async fn delete_on_close<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let first = open(fs, "delete", CreateDisposition::CREATE, false, &request).await;
    let second = open(fs, "delete", CreateDisposition::OPEN, false, &request).await;
    fs.set_delete_on_close(&first, true, &request)
        .await
        .unwrap();
    assert!(fs.metadata(&second, &request).await.unwrap().delete_pending);
    rejected(
        fs.open("delete", options(CreateDisposition::OPEN, false), &request)
            .await,
        Status::DELETE_PENDING,
    );
    fs.set_delete_on_close(&first, false, &request)
        .await
        .unwrap();
    assert!(!fs.metadata(&second, &request).await.unwrap().delete_pending);
    let third = open(fs, "delete", CreateDisposition::OPEN, false, &request).await;
    fs.close(&third, &request).await.unwrap();
    fs.set_delete_on_close(&first, true, &request)
        .await
        .unwrap();
    fs.close(&first, &request).await.unwrap();
    assert!(fs.metadata(&second, &request).await.unwrap().delete_pending);
    rejected(
        fs.open("delete", options(CreateDisposition::OPEN, false), &request)
            .await,
        Status::DELETE_PENDING,
    );
    fs.close(&second, &request).await.unwrap();
    rejected(
        fs.open("delete", options(CreateDisposition::OPEN, false), &request)
            .await,
        Status::OBJECT_NAME_NOT_FOUND,
    );
    let mut initial = options(CreateDisposition::CREATE, false);
    initial.options = CreateOptions::new().with_delete_on_close(true).into_bits();
    let (file, _) = fs.open("initial", initial, &request).await.unwrap();
    fs.close(&file, &request).await.unwrap();
    rejected(
        fs.open("initial", options(CreateDisposition::OPEN, false), &request)
            .await,
        Status::OBJECT_NAME_NOT_FOUND,
    );
}

/// Basic attribute updates are observable and do not alter identity or length.
/// Timestamp resolution and native clock behavior are provider-specific tests.
pub async fn basic_information<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let file = open(fs, "basic", CreateDisposition::CREATE, false, &request).await;
    let before = fs.metadata(&file, &request).await.unwrap();
    let info = BasicInformation {
        created: 0,
        accessed: 0,
        written: 0,
        changed: 0,
        attributes: FileAttributes::new().with_hidden(true).into_bits(),
    };
    let result = fs.set_basic(&file, info, &request).await;
    if let Some(status) = unsupported(fixture.expectations().basic_information) {
        rejected(result, status);
        assert_eq!(
            fs.metadata(&file, &request).await.unwrap().attributes,
            before.attributes
        );
    } else {
        result.unwrap();
        assert!(
            fs.metadata(&file, &request)
                .await
                .unwrap()
                .attributes()
                .hidden()
        );
        fs.set_basic(
            &file,
            BasicInformation {
                attributes: FileAttributes::new().with_normal(true).into_bits(),
                ..info
            },
            &request,
        )
        .await
        .unwrap();
        let after = fs.metadata(&file, &request).await.unwrap();
        assert!(!after.attributes().hidden());
        assert_eq!((after.id, after.size), (before.id, before.size));
    }
    fs.close(&file, &request).await.unwrap();
}

/// Shared/exclusive ownership and I/O conflicts, exact-range unlock, and valid
/// zero-length/64-bit lock boundaries.
pub async fn lock_conflicts_and_io<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let owner = open(fs, "locks", CreateDisposition::CREATE, false, &request).await;
    if let Some(status) = unsupported(fixture.expectations().locks) {
        rejected_lock(fs, &owner, status, &request).await;
        fs.close(&owner, &request).await.unwrap();
        return;
    }
    let other = open(fs, "locks", CreateDisposition::OPEN, false, &request).await;
    write_all(fs, &owner, 0, b"abcdefghij", &request).await;
    for exclusive in [false, true] {
        fs.lock(&owner, RANGE, exclusive, true, &request)
            .await
            .unwrap();
        assert_eq!(read_bytes(fs, &owner, 2, 4, &request).await, b"cdef");
        rejected(
            fs.lock(&other, RANGE, true, true, &request).await,
            Status::LOCK_NOT_GRANTED,
        );
        rejected(
            fs.lock(&owner, RANGE, true, true, &request).await,
            Status::LOCK_NOT_GRANTED,
        );
        rejected(
            fs.write(&other, 2, b"x", &request).await,
            Status::FILE_LOCK_CONFLICT,
        );
        if exclusive {
            rejected(
                fs.lock(&other, RANGE, false, true, &request).await,
                Status::LOCK_NOT_GRANTED,
            );
            rejected(
                fs.read(&other, 2, 1, &request).await,
                Status::FILE_LOCK_CONFLICT,
            );
            write_all(fs, &owner, 2, b"cdef", &request).await;
        } else {
            fs.lock(&other, RANGE, false, true, &request).await.unwrap();
            assert_eq!(read_bytes(fs, &other, 2, 4, &request).await, b"cdef");
            rejected(
                fs.write(&owner, 2, b"x", &request).await,
                Status::FILE_LOCK_CONFLICT,
            );
            fs.unlock(&other, RANGE, &request).await.unwrap();
        }
        rejected(
            fs.unlock(&other, RANGE, &request).await,
            Status::RANGE_NOT_LOCKED,
        );
        rejected(
            fs.unlock(
                &owner,
                ByteRange {
                    offset: 2,
                    length: 1,
                },
                &request,
            )
            .await,
            Status::RANGE_NOT_LOCKED,
        );
        fs.unlock(&owner, RANGE, &request).await.unwrap();
        rejected(
            fs.unlock(&owner, RANGE, &request).await,
            Status::RANGE_NOT_LOCKED,
        );
    }
    for (held, attempted, conflict) in [
        (
            ByteRange {
                offset: 0,
                length: 0,
            },
            RANGE,
            false,
        ),
        (
            ByteRange {
                offset: 3,
                length: 0,
            },
            RANGE,
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
        fs.lock(&owner, held, true, true, &request).await.unwrap();
        let result = fs.lock(&other, attempted, true, true, &request).await;
        if conflict {
            rejected(result, Status::LOCK_NOT_GRANTED);
        } else {
            result.unwrap();
            fs.unlock(&other, attempted, &request).await.unwrap();
        }
        fs.unlock(&owner, held, &request).await.unwrap();
    }
    fs.close(&other, &request).await.unwrap();
    fs.close(&owner, &request).await.unwrap();
}

/// Naturally contended waits cancel without granting a lock, and unlock wakes
/// a later waiter. Settled close releases the granted lock.
pub async fn lock_waiters_and_cancellation<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let owner = open(fs, "waiting", CreateDisposition::CREATE, false, &request).await;
    if let Some(status) = unsupported(fixture.expectations().locks) {
        rejected_lock(fs, &owner, status, &request).await;
        fs.close(&owner, &request).await.unwrap();
        return;
    }
    let other = open(fs, "waiting", CreateDisposition::OPEN, false, &request).await;
    fs.lock(&owner, RANGE, true, true, &request).await.unwrap();
    {
        let cancelled = RequestContext::new(2);
        let mut work = std::pin::pin!(fs.lock(&other, RANGE, true, false, &cancelled));
        pending(fixture, Operation::Lock, &cancelled, work.as_mut()).await;
        cancelled.cancel();
        rejected(work.await, Status::CANCELLED);
    }
    {
        let waiting = RequestContext::new(3);
        let mut work = std::pin::pin!(fs.lock(&other, RANGE, true, false, &waiting));
        pending(fixture, Operation::Lock, &waiting, work.as_mut()).await;
        fs.unlock(&owner, RANGE, &request).await.unwrap();
        work.await.unwrap();
        waiting.cancel();
        rejected(
            fs.lock(&owner, RANGE, true, true, &request).await,
            Status::LOCK_NOT_GRANTED,
        );
    }
    fs.close(&other, &request).await.unwrap();
    fs.lock(&owner, RANGE, true, true, &request).await.unwrap();
    fs.close(&owner, &request).await.unwrap();
}

/// Rollback targets an acquisition, not an older exact-range lock; ordinary
/// unlock prefers exclusive matches, and fallback drop releases remaining locks.
pub async fn lock_rollback_and_drop<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let owner = open(fs, "rollback", CreateDisposition::CREATE, false, &request).await;
    if let Some(status) = unsupported(fixture.expectations().locks) {
        rejected_lock(fs, &owner, status, &request).await;
        fs.close(&owner, &request).await.unwrap();
        return;
    }
    let other = open(fs, "rollback", CreateDisposition::OPEN, false, &request).await;
    fs.lock(&owner, RANGE, true, true, &request).await.unwrap();
    let acquired = RequestContext::new(2);
    let added = fs
        .lock(&owner, RANGE, false, true, &acquired)
        .await
        .unwrap();
    acquired.cancel();
    fs.rollback_lock(&owner, added, &request).await.unwrap();
    fs.rollback_lock(&owner, added, &request).await.unwrap();
    rejected(
        fs.lock(&other, RANGE, false, true, &request).await,
        Status::LOCK_NOT_GRANTED,
    );
    let shared = fs.lock(&owner, RANGE, false, true, &request).await.unwrap();
    fs.unlock(&owner, RANGE, &request).await.unwrap();
    fs.lock(&other, RANGE, false, true, &request).await.unwrap();
    fs.unlock(&owner, RANGE, &request).await.unwrap();
    fs.rollback_lock(&owner, shared, &request).await.unwrap();
    fs.close(&owner, &request).await.unwrap();
    drop(other);
    let reopened = open(fs, "rollback", CreateDisposition::OPEN, false, &request).await;
    fs.lock(&reopened, RANGE, true, true, &request)
        .await
        .unwrap();
    fs.close(&reopened, &request).await.unwrap();
}

fn file_names() -> NotifyFilter {
    NotifyFilter::new().with_file_name(true)
}

async fn rejected_notify<B: FileSystem>(
    fs: &B,
    directory: &B::File,
    status: Status,
    request: &RequestContext,
) {
    rejected(
        fs.notify(directory, file_names(), false, 4096, request)
            .await,
        status,
    );
}

/// Pre-canceled and pending cancellations retain the first registration's
/// filter and buffered events. A new open gets its own registration policy.
pub async fn notify_registration_and_cancellation<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let directory = open(fs, "watch", CreateDisposition::CREATE, true, &request).await;
    if let Some(status) = unsupported(fixture.expectations().notifications) {
        rejected_notify(fs, &directory, status, &request).await;
        fs.close(&directory, &request).await.unwrap();
        return;
    }
    let cancelled = RequestContext::new(2);
    cancelled.cancel();
    rejected(
        fs.notify(&directory, file_names(), false, 4096, &cancelled)
            .await,
        Status::CANCELLED,
    );
    let first = open(
        fs,
        "watch\\first",
        CreateDisposition::CREATE,
        false,
        &request,
    )
    .await;
    changes(
        fs.notify(
            &directory,
            NotifyFilter::new().with_dir_name(true),
            true,
            4096,
            &request,
        )
        .await
        .unwrap(),
        &[(NotifyAction::ADDED, "first")],
    );
    {
        let cancelled = RequestContext::new(3);
        let mut work = std::pin::pin!(fs.notify(&directory, file_names(), false, 4096, &cancelled));
        pending(fixture, Operation::Notify, &cancelled, work.as_mut()).await;
        cancelled.cancel();
        rejected(work.await, Status::CANCELLED);
    }
    let second = open(
        fs,
        "watch\\second",
        CreateDisposition::CREATE,
        false,
        &request,
    )
    .await;
    changes(
        fs.notify(&directory, file_names(), false, 4096, &request)
            .await
            .unwrap(),
        &[(NotifyAction::ADDED, "second")],
    );
    fs.close(&directory, &request).await.unwrap();
    let reopened = open(fs, "watch", CreateDisposition::OPEN, true, &request).await;
    let cancelled = RequestContext::new(4);
    cancelled.cancel();
    rejected(
        fs.notify(
            &reopened,
            NotifyFilter::new().with_dir_name(true),
            false,
            4096,
            &cancelled,
        )
        .await,
        Status::CANCELLED,
    );
    let child = open(
        fs,
        "watch\\child",
        CreateDisposition::CREATE,
        true,
        &request,
    )
    .await;
    changes(
        fs.notify(&reopened, file_names(), false, 4096, &request)
            .await
            .unwrap(),
        &[(NotifyAction::ADDED, "child")],
    );
    fs.close(&child, &request).await.unwrap();
    fs.close(&second, &request).await.unwrap();
    fs.close(&first, &request).await.unwrap();
    fs.close(&reopened, &request).await.unwrap();
}

/// Overlapping waits are FIFO. An undersized reply reports overflow without
/// consuming a buffered event; provider-specific storage overflow is separate.
pub async fn notify_fifo_and_small_buffer<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let directory = open(fs, "fifo", CreateDisposition::CREATE, true, &request).await;
    if let Some(status) = unsupported(fixture.expectations().notifications) {
        rejected_notify(fs, &directory, status, &request).await;
        fs.close(&directory, &request).await.unwrap();
        return;
    }
    let first_request = RequestContext::new(2);
    let second_request = RequestContext::new(3);
    let first_file;
    let second_file;
    {
        let mut first =
            std::pin::pin!(fs.notify(&directory, file_names(), false, 4096, &first_request));
        pending(fixture, Operation::Notify, &first_request, first.as_mut()).await;
        let mut second =
            std::pin::pin!(fs.notify(&directory, file_names(), false, 4096, &second_request));
        pending(fixture, Operation::Notify, &second_request, second.as_mut()).await;
        first_file = open(
            fs,
            "fifo\\first",
            CreateDisposition::CREATE,
            false,
            &request,
        )
        .await;
        assert!(futures::poll!(&mut second).is_pending());
        changes(first.await.unwrap(), &[(NotifyAction::ADDED, "first")]);
        second_file = open(
            fs,
            "fifo\\second",
            CreateDisposition::CREATE,
            false,
            &request,
        )
        .await;
        changes(second.await.unwrap(), &[(NotifyAction::ADDED, "second")]);
    }
    let retained = open(
        fs,
        "fifo\\retained",
        CreateDisposition::CREATE,
        false,
        &request,
    )
    .await;
    assert!(matches!(
        fs.notify(&directory, file_names(), false, 1, &request)
            .await
            .unwrap(),
        NotifyResult::Overflow
    ));
    changes(
        fs.notify(&directory, file_names(), false, 4096, &request)
            .await
            .unwrap(),
        &[(NotifyAction::ADDED, "retained")],
    );
    fs.close(&retained, &request).await.unwrap();
    fs.close(&second_file, &request).await.unwrap();
    fs.close(&first_file, &request).await.unwrap();
    fs.close(&directory, &request).await.unwrap();
}

/// Recursive changes use share-relative spelling; a nonrecursive registration
/// on another open does not consume those changes.
pub async fn notify_subtree_and_filters<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let local = open(fs, "tree", CreateDisposition::CREATE, true, &request).await;
    if let Some(status) = unsupported(fixture.expectations().notifications) {
        rejected_notify(fs, &local, status, &request).await;
        fs.close(&local, &request).await.unwrap();
        return;
    }
    let recursive = open(fs, "tree", CreateDisposition::OPEN, true, &request).await;
    let subdirectory = open(fs, "tree\\sub", CreateDisposition::CREATE, true, &request).await;
    let child;
    {
        let local_request = RequestContext::new(2);
        let recursive_request = RequestContext::new(3);
        let mut local_wait =
            std::pin::pin!(fs.notify(&local, file_names(), false, 4096, &local_request));
        pending(
            fixture,
            Operation::Notify,
            &local_request,
            local_wait.as_mut(),
        )
        .await;
        let mut recursive_wait =
            std::pin::pin!(fs.notify(&recursive, file_names(), true, 4096, &recursive_request));
        pending(
            fixture,
            Operation::Notify,
            &recursive_request,
            recursive_wait.as_mut(),
        )
        .await;
        child = open(
            fs,
            "tree\\sub\\leaf",
            CreateDisposition::CREATE,
            false,
            &request,
        )
        .await;
        changes(
            recursive_wait.await.unwrap(),
            &[(NotifyAction::ADDED, "sub\\leaf")],
        );
        local_request.cancel();
        rejected(local_wait.await, Status::CANCELLED);
    }
    fs.close(&child, &request).await.unwrap();
    fs.close(&subdirectory, &request).await.unwrap();
    fs.close(&recursive, &request).await.unwrap();
    fs.close(&local, &request).await.unwrap();
}

/// Deletion invalidates old watch generations even after disposition reset or
/// late cancellation. Old waiters cannot steal a replacement registration.
/// Closing a distinct delete-on-close open also invalidates a pending watch.
pub async fn notify_deletion_generations<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let watched = open(fs, "generation", CreateDisposition::CREATE, true, &request).await;
    if let Some(status) = unsupported(fixture.expectations().notifications) {
        rejected_notify(fs, &watched, status, &request).await;
        fs.close(&watched, &request).await.unwrap();
        return;
    }
    let deleting = open(fs, "generation", CreateDisposition::OPEN, true, &request).await;
    let child;
    {
        let first_request = RequestContext::new(2);
        let second_request = RequestContext::new(3);
        let mut first =
            std::pin::pin!(fs.notify(&watched, file_names(), false, 4096, &first_request));
        pending(fixture, Operation::Notify, &first_request, first.as_mut()).await;
        let mut second =
            std::pin::pin!(fs.notify(&watched, file_names(), false, 4096, &second_request));
        pending(fixture, Operation::Notify, &second_request, second.as_mut()).await;
        fs.set_delete_on_close(&deleting, true, &request)
            .await
            .unwrap();
        fs.set_delete_on_close(&deleting, false, &request)
            .await
            .unwrap();
        first_request.cancel();
        second_request.cancel();
        let fresh_request = RequestContext::new(4);
        let mut fresh = std::pin::pin!(fs.notify(
            &watched,
            NotifyFilter::new().with_dir_name(true),
            false,
            4096,
            &fresh_request,
        ));
        pending(fixture, Operation::Notify, &fresh_request, fresh.as_mut()).await;
        rejected(first.await, Status::DELETE_PENDING);
        rejected(second.await, Status::DELETE_PENDING);
        child = open(
            fs,
            "generation\\child",
            CreateDisposition::CREATE,
            true,
            &request,
        )
        .await;
        changes(fresh.await.unwrap(), &[(NotifyAction::ADDED, "child")]);
    }
    rejected(
        fs.notify(&deleting, file_names(), false, 4096, &request)
            .await,
        Status::DELETE_PENDING,
    );
    fs.close(&child, &request).await.unwrap();
    fs.close(&watched, &request).await.unwrap();
    fs.close(&deleting, &request).await.unwrap();
    let watched = open(fs, "initial", CreateDisposition::CREATE, true, &request).await;
    {
        let waiting = RequestContext::new(5);
        let mut work = std::pin::pin!(fs.notify(&watched, file_names(), false, 4096, &waiting));
        pending(fixture, Operation::Notify, &waiting, work.as_mut()).await;
        let mut initial = options(CreateDisposition::OPEN, true);
        initial.options = CreateOptions::from_bits(initial.options)
            .with_delete_on_close(true)
            .into_bits();
        let (deleting, _) = fs.open("initial", initial, &request).await.unwrap();
        fs.close(&deleting, &request).await.unwrap();
        rejected(work.await, Status::DELETE_PENDING);
    }
    fs.close(&watched, &request).await.unwrap();
}
