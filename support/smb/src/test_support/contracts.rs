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
    /// Volume identity, capability and capacity snapshots.
    pub filesystem_information: Feature,
    /// Allocation reservations, including zero-size truncation.
    pub allocation: Feature,
    /// Per-open I/O mode updates.
    pub file_mode: Feature,
    /// Basic owner/group/DACL descriptor queries.
    pub security_queries: Feature,
    /// File DACL updates and future-open enforcement, without privilege bypass.
    pub file_acl_updates: Feature,
    /// Directory DACL updates and namespace authorization, excluding inheritance.
    /// Supporting fixtures also support file ACL updates and rename.
    pub directory_acl_updates: Feature,
    /// Basic inherited file/container ACEs and no-propagate behavior.
    pub acl_inheritance: Feature,
    /// Atomic security descriptors on creation; ignored for existing objects.
    pub security_creation: Feature,
    /// Atomic EA creation, or explicit rejection by a store without EAs.
    pub creation_eas: Feature,
    /// Basic metadata mutation.
    pub basic_information: Feature,
    /// Atomic namespace rename and replacement.
    pub rename: Feature,
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

fn options(disposition: CreateDisposition, directory: bool) -> OpenOptions<'static> {
    OpenOptions {
        access: AccessMask::FILE_ALL_ACCESS.into_bits(),
        share_access: ShareAccess::ALL.into_bits(),
        disposition: disposition.0,
        options: CreateOptions::new()
            .with_directory_file(directory)
            .into_bits(),
        attributes: 0,
        security: None,
        extended_attributes: None,
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

/// Volume queries through file and directory opens describe the same volume,
/// with nonnegative capacities and real, nonzero allocation geometry.
pub async fn filesystem_information<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let root = open(fs, "", CreateDisposition::OPEN, true, &request).await;
    if let Some(status) = unsupported(fixture.expectations().filesystem_information) {
        rejected(fs.filesystem_information(&root, &request).await, status);
    } else {
        let before = fs.filesystem_information(&root, &request).await.unwrap();
        let file = open(fs, "capacity", CreateDisposition::CREATE, false, &request).await;
        write_all(fs, &file, 0, b"data", &request).await;
        let after = fs.filesystem_information(&file, &request).await.unwrap();
        assert_eq!(
            (after.created, after.serial),
            (before.created, before.serial)
        );
        assert_eq!((&after.label, &after.name), (&before.label, &before.name));
        for info in [before, after] {
            assert!(info.total_allocation_units >= 0);
            assert!(info.caller_available_allocation_units >= 0);
            assert!(info.actual_available_allocation_units >= 0);
            assert!(info.caller_available_allocation_units <= info.total_allocation_units);
            assert!(info.sectors_per_allocation_unit > 0);
            assert!(info.bytes_per_sector > 0);
        }
        fs.close(&file, &request).await.unwrap();
    }
    fs.close(&root, &request).await.unwrap();
}

/// Security queries return only selected components and retain the same
/// descriptor components across different selections.
pub async fn security_queries<F: Fixture>(fixture: &F) {
    use crate::security::AclState;
    use crate::spec::SecurityInformation;
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let file = open(fs, "security", CreateDisposition::CREATE, false, &request).await;
    let all = SecurityInformation::new()
        .with_owner(true)
        .with_group(true)
        .with_dacl(true);
    if let Some(status) = unsupported(fixture.expectations().security_queries) {
        rejected(fs.query_security(&file, all, &request).await, status);
    } else {
        let full = fs.query_security(&file, all, &request).await.unwrap();
        for information in [
            SecurityInformation::new(),
            SecurityInformation::new().with_owner(true),
            SecurityInformation::new().with_group(true),
            SecurityInformation::new().with_dacl(true),
        ] {
            let selected = fs
                .query_security(&file, information, &request)
                .await
                .unwrap();
            assert_eq!(
                selected.owner,
                if information.owner() {
                    full.owner.clone()
                } else {
                    None
                }
            );
            assert_eq!(
                selected.group,
                if information.group() {
                    full.group.clone()
                } else {
                    None
                }
            );
            assert_eq!(
                selected.dacl,
                if information.dacl() {
                    full.dacl.clone()
                } else {
                    AclState::Absent
                }
            );
            assert_eq!(selected.sacl, AclState::Absent);
        }
    }
    fs.close(&file, &request).await.unwrap();
}

/// File ACL changes must affect future opens, retain old grants and preserve
/// unselected owner/group components. Fixtures use an identity without DACL bypass.
pub async fn file_acl_updates<F: Fixture>(fixture: &F) {
    use crate::security::{Acl, AclState, SecurityDescriptor};
    use crate::spec::SecurityInformation;
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let file = open(fs, "acl", CreateDisposition::CREATE, false, &request).await;
    let information = SecurityInformation::new().with_dacl(true);
    let mut descriptor = SecurityDescriptor::empty();
    descriptor.dacl = AclState::Present(Acl::access(&[]).unwrap());
    if let Some(status) = unsupported(fixture.expectations().file_acl_updates) {
        rejected(
            fs.set_security(&file, information, &descriptor, &request)
                .await,
            status,
        );
    } else {
        let all = information.with_owner(true).with_group(true);
        let before = fs.query_security(&file, all, &request).await.unwrap();
        let grant = fs.metadata(&file, &request).await.unwrap().granted_access;
        fs.set_security(&file, information, &descriptor, &request)
            .await
            .unwrap();
        let actual = fs.query_security(&file, all, &request).await.unwrap();
        assert_eq!(actual.owner, before.owner);
        assert_eq!(actual.group, before.group);
        assert_eq!(actual.dacl, descriptor.dacl);
        assert_eq!(
            fs.metadata(&file, &request).await.unwrap().granted_access,
            grant
        );
        let read = OpenOptions {
            access: AccessMask::new().with_read_data(true).into_bits(),
            ..options(CreateDisposition::OPEN, false)
        };
        rejected(fs.open("acl", read, &request).await, Status::ACCESS_DENIED);
        write_all(fs, &file, 0, b"old grant", &request).await;
        assert_eq!(read_bytes(fs, &file, 0, 9, &request).await, b"old grant");
        fs.set_security(&file, information, &before, &request)
            .await
            .unwrap();
        let (reopened, _) = fs.open("acl", read, &request).await.unwrap();
        assert_eq!(
            read_bytes(fs, &reopened, 0, 9, &request).await,
            b"old grant"
        );
        fs.close(&reopened, &request).await.unwrap();
    }
    fs.close(&file, &request).await.unwrap();
}

/// Directory DACL changes govern creation and rename destinations. Supporting
/// fixtures also support rename; rejected operations leave the namespace intact.
pub async fn directory_acl_updates<F: Fixture>(fixture: &F) {
    use crate::security::{AccessAce, Acl, AclState, SecurityDescriptor, Sid};
    use crate::spec::{AceFlags, SecurityInformation};
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let directory = open(fs, "directory", CreateDisposition::CREATE, true, &request).await;
    let source = open(fs, "source", CreateDisposition::CREATE, false, &request).await;
    let mut descriptor = SecurityDescriptor::empty();
    descriptor.control.set_dacl_protected(true);
    descriptor.dacl = AclState::Present(Acl::access(&[]).unwrap());
    let information = SecurityInformation::new().with_dacl(true);
    if let Some(status) = unsupported(fixture.expectations().directory_acl_updates) {
        rejected(
            fs.set_security(&directory, information, &descriptor, &request)
                .await,
            status,
        );
    } else {
        fs.set_security(&directory, information, &descriptor, &request)
            .await
            .unwrap();
        rejected(
            fs.open(
                "directory\\new",
                options(CreateDisposition::CREATE, false),
                &request,
            )
            .await,
            Status::ACCESS_DENIED,
        );
        rejected(
            fs.open(
                "directory\\subdirectory",
                options(CreateDisposition::CREATE, true),
                &request,
            )
            .await,
            Status::ACCESS_DENIED,
        );
        rejected(
            fs.rename(&source, "directory\\moved", false, &request)
                .await,
            Status::ACCESS_DENIED,
        );
        descriptor.dacl = AclState::Null;
        fs.set_security(&directory, information, &descriptor, &request)
            .await
            .unwrap();
        let file = open(
            fs,
            "directory\\new",
            CreateDisposition::CREATE,
            false,
            &request,
        )
        .await;
        fs.rename(&source, "directory\\moved", false, &request)
            .await
            .unwrap();
        assert_eq!(
            fs.metadata(&source, &request).await.unwrap().path,
            "\\directory\\moved"
        );
        let target_id = fs.metadata(&file, &request).await.unwrap().id;
        descriptor.dacl = AclState::Present(Acl::access(&[]).unwrap());
        fs.set_security(&file, information, &descriptor, &request)
            .await
            .unwrap();
        fs.close(&file, &request).await.unwrap();
        descriptor.dacl = AclState::Present(
            Acl::access(&[AccessAce {
                deny: false,
                flags: AceFlags::new(),
                mask: AccessMask::new()
                    .with_execute(true)
                    .with_write_data(true)
                    .into_bits(),
                sid: Sid::new([0, 0, 0, 0, 0, 1], &[0]).unwrap(),
            }])
            .unwrap(),
        );
        fs.set_security(&directory, information, &descriptor, &request)
            .await
            .unwrap();
        rejected(
            fs.rename(&source, "directory\\new", true, &request).await,
            Status::ACCESS_DENIED,
        );
        assert_eq!(
            fs.metadata(&source, &request).await.unwrap().path,
            "\\directory\\moved"
        );
        let (target, _) = fs
            .open(
                "directory\\new",
                OpenOptions {
                    access: AccessMask::new().with_read_control(true).into_bits(),
                    ..options(CreateDisposition::OPEN, false)
                },
                &request,
            )
            .await
            .unwrap();
        assert_eq!(fs.metadata(&target, &request).await.unwrap().id, target_id);
        fs.close(&target, &request).await.unwrap();
        descriptor.dacl = AclState::Null;
        fs.set_security(&directory, information, &descriptor, &request)
            .await
            .unwrap();
        fs.rename(&source, "directory\\new", true, &request)
            .await
            .unwrap();
    }
    fs.close(&source, &request).await.unwrap();
    fs.close(&directory, &request).await.unwrap();
}

/// Inheritance carries file-only ACEs through container templates, while
/// no-propagate limits their effect to immediate children.
pub async fn acl_inheritance<F: Fixture>(fixture: &F) {
    use crate::security::{AccessAce, Acl, AclState, SecurityDescriptor, Sid};
    use crate::spec::{AceFlags, SecurityInformation};
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let parent = open(fs, "parent", CreateDisposition::CREATE, true, &request).await;
    let world = Sid::new([0, 0, 0, 0, 0, 1], &[0]).unwrap();
    let mut entries = vec![
        AccessAce {
            deny: false,
            flags: AceFlags::new().with_container_inherit(true),
            mask: AccessMask::FILE_ALL_ACCESS.into_bits(),
            sid: world.clone(),
        },
        AccessAce {
            deny: true,
            flags: AceFlags::new()
                .with_object_inherit(true)
                .with_inherit_only(true),
            mask: AccessMask::new()
                .with_read_data(true)
                .with_execute(true)
                .into_bits(),
            sid: world,
        },
    ];
    let mut descriptor = SecurityDescriptor::empty();
    descriptor.control.set_dacl_protected(true);
    descriptor.dacl = AclState::Present(Acl::access(&entries).unwrap());
    let information = SecurityInformation::new().with_dacl(true);
    if let Some(status) = unsupported(fixture.expectations().acl_inheritance) {
        rejected(
            fs.set_security(&parent, information, &descriptor, &request)
                .await,
            status,
        );
    } else {
        fs.set_security(&parent, information, &descriptor, &request)
            .await
            .unwrap();
        let directory = open(
            fs,
            "parent\\directory",
            CreateDisposition::CREATE,
            true,
            &request,
        )
        .await;
        let file = open(
            fs,
            "parent\\directory\\file",
            CreateDisposition::CREATE,
            false,
            &request,
        )
        .await;
        assert!(
            AccessMask::from_bits(fs.metadata(&file, &request).await.unwrap().granted_access)
                .read_data()
        );
        let read = OpenOptions {
            access: AccessMask::new().with_read_data(true).into_bits(),
            ..options(CreateDisposition::OPEN, false)
        };
        rejected(
            fs.open("parent\\directory\\file", read, &request).await,
            Status::ACCESS_DENIED,
        );
        entries[1].flags.set_no_propagate_inherit(true);
        descriptor.dacl = AclState::Present(Acl::access(&entries).unwrap());
        fs.set_security(&parent, information, &descriptor, &request)
            .await
            .unwrap();
        let immediate = open(
            fs,
            "parent\\immediate",
            CreateDisposition::CREATE,
            false,
            &request,
        )
        .await;
        rejected(
            fs.open("parent\\immediate", read, &request).await,
            Status::ACCESS_DENIED,
        );
        let other_directory = open(
            fs,
            "parent\\other",
            CreateDisposition::CREATE,
            true,
            &request,
        )
        .await;
        let grandchild = open(
            fs,
            "parent\\other\\grandchild",
            CreateDisposition::CREATE,
            false,
            &request,
        )
        .await;
        let (reopened, _) = fs
            .open("parent\\other\\grandchild", read, &request)
            .await
            .unwrap();
        fs.close(&reopened, &request).await.unwrap();
        fs.close(&grandchild, &request).await.unwrap();
        fs.close(&other_directory, &request).await.unwrap();
        fs.close(&immediate, &request).await.unwrap();
        fs.close(&file, &request).await.unwrap();
        fs.close(&directory, &request).await.unwrap();
    }
    fs.close(&parent, &request).await.unwrap();
}

/// Creation applies security before publication and preserves the initial grant.
/// Existing opens ignore descriptor bytes; rejected creations leave no object.
pub async fn security_creation<F: Fixture>(fixture: &F) {
    use crate::security::{Acl, AclState, SecurityDescriptor};
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let mut descriptor = SecurityDescriptor::empty();
    descriptor.control.set_dacl_protected(true);
    descriptor.dacl = AclState::Present(Acl::access(&[]).unwrap());
    let encoded = descriptor.encode();
    let create = OpenOptions {
        security: Some(encoded.as_slice()),
        ..options(CreateDisposition::CREATE, false)
    };
    if let Some(status) = unsupported(fixture.expectations().security_creation) {
        rejected(fs.open("secured", create, &request).await, status);
        rejected(
            fs.open("secured", options(CreateDisposition::OPEN, false), &request)
                .await,
            Status::OBJECT_NAME_NOT_FOUND,
        );
    } else {
        let (file, _) = fs.open("secured", create, &request).await.unwrap();
        let read = OpenOptions {
            access: AccessMask::new().with_read_data(true).into_bits(),
            ..options(CreateDisposition::OPEN, false)
        };
        rejected(
            fs.open("secured", read, &request).await,
            Status::ACCESS_DENIED,
        );
        let existing = OpenOptions {
            access: AccessMask::new().with_read_control(true).into_bits(),
            disposition: CreateDisposition::OPEN_IF.0,
            security: Some(&[0; 20]),
            ..options(CreateDisposition::OPEN, false)
        };
        let (reopened, _) = fs.open("secured", existing, &request).await.unwrap();
        fs.close(&reopened, &request).await.unwrap();
        write_all(fs, &file, 0, b"created grant", &request).await;
        fs.close(&file, &request).await.unwrap();
        rejected(
            fs.open(
                "invalid",
                OpenOptions {
                    security: Some(&[0; 20]),
                    ..options(CreateDisposition::CREATE, false)
                },
                &request,
            )
            .await,
            Status::INVALID_SECURITY_DESCR,
        );
    }
    rejected(
        fs.open("invalid", options(CreateDisposition::OPEN, false), &request)
            .await,
        Status::OBJECT_NAME_NOT_FOUND,
    );
}

/// Creation EAs are ignored for existing objects. Unsupported new-object EAs
/// must fail without creating an object; supporting stores retain nonzero EA data.
pub async fn creation_eas<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let file = open(fs, "existing", CreateDisposition::CREATE, false, &request).await;
    let (existing, _) = fs
        .open(
            "existing",
            OpenOptions {
                disposition: CreateDisposition::OPEN_IF.0,
                extended_attributes: Some(&[1]),
                ..options(CreateDisposition::OPEN, false)
            },
            &request,
        )
        .await
        .unwrap();
    fs.close(&existing, &request).await.unwrap();
    fs.close(&file, &request).await.unwrap();
    let ea = [0, 0, 0, 0, 0, 1, 1, 0, b'A', 0, b'v'];
    let result = fs
        .open(
            "with-eas",
            OpenOptions {
                extended_attributes: Some(&ea),
                ..options(CreateDisposition::CREATE, false)
            },
            &request,
        )
        .await;
    if let Some(status) = unsupported(fixture.expectations().creation_eas) {
        rejected(result, status);
        rejected(
            fs.open(
                "with-eas",
                options(CreateDisposition::OPEN, false),
                &request,
            )
            .await,
            Status::OBJECT_NAME_NOT_FOUND,
        );
    } else {
        let (created, _) = result.unwrap();
        assert!(
            fs.metadata(&created, &request)
                .await
                .unwrap()
                .extended_attributes_length
                > 0
        );
        fs.close(&created, &request).await.unwrap();
    }
}

/// MAXIMUM_ALLOWED is resolved by the provider, not expanded to blanket rights.
/// Actual grants are per-open and distinct from the identity's current maximum.
pub async fn maximum_allowed_access<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let file = open(fs, "grants", CreateDisposition::CREATE, false, &request).await;
    let original = fs.metadata(&file, &request).await.unwrap();
    assert_eq!(
        original.granted_access,
        AccessMask::FILE_ALL_ACCESS.into_bits()
    );
    write_all(fs, &file, 0, b"code", &request).await;
    let execute = AccessMask::new()
        .with_execute(true)
        .with_read_attributes(true)
        .into_bits();
    let (executable, _) = fs
        .open(
            "grants",
            OpenOptions {
                access: execute,
                ..options(CreateDisposition::OPEN, false)
            },
            &request,
        )
        .await
        .unwrap();
    assert_eq!(
        fs.metadata(&executable, &request)
            .await
            .unwrap()
            .granted_access,
        execute
    );
    assert_eq!(read_bytes(fs, &executable, 0, 4, &request).await, b"code");
    fs.close(&executable, &request).await.unwrap();
    let maximum = OpenOptions {
        access: AccessMask::new().with_maximum_allowed(true).into_bits(),
        ..options(CreateDisposition::OPEN, false)
    };
    let (peer, _) = fs.open("grants", maximum, &request).await.unwrap();
    let metadata = fs.metadata(&peer, &request).await.unwrap();
    assert_eq!(metadata.granted_access, metadata.maximal_access);
    assert!(!AccessMask::from_bits(metadata.granted_access).maximum_allowed());
    fs.close(&peer, &request).await.unwrap();
    let info = BasicInformation {
        created: 0,
        accessed: 0,
        written: 0,
        changed: 0,
        attributes: FileAttributes::new().with_readonly(true).into_bits(),
    };
    if let Some(status) = unsupported(fixture.expectations().basic_information) {
        rejected(fs.set_basic(&file, info, &request).await, status);
    } else {
        fs.set_basic(&file, info, &request).await.unwrap();
        let (peer, _) = fs.open("grants", maximum, &request).await.unwrap();
        let metadata = fs.metadata(&peer, &request).await.unwrap();
        let granted = AccessMask::from_bits(metadata.granted_access);
        assert!(granted.read_data());
        assert!(!granted.write_data() && !granted.append_data());
        assert_eq!(
            fs.metadata(&file, &request).await.unwrap().granted_access,
            original.granted_access
        );
        fs.close(&peer, &request).await.unwrap();
    }
    fs.close(&file, &request).await.unwrap();
}

/// Allocation reserves space without extending EOF; writes in that space
/// expose zero-filled gaps and allocation zero truncates the stream.
pub async fn allocation_reservations<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let file = open(fs, "reserved", CreateDisposition::CREATE, false, &request).await;
    write_all(fs, &file, 0, b"data", &request).await;
    if let Some(status) = unsupported(fixture.expectations().allocation) {
        rejected(fs.set_allocation_size(&file, 32, &request).await, status);
    } else {
        fs.set_allocation_size(&file, 32, &request).await.unwrap();
        let info = fs.metadata(&file, &request).await.unwrap();
        assert_eq!(info.size, 4);
        assert!(info.allocation_size >= 32);
        match fs.read(&file, 4, 1, &request).await {
            Ok(data) => assert!(data.is_empty()),
            Err(status) => assert_eq!(status, Status::END_OF_FILE),
        }
        fs.set_len(&file, 8, &request).await.unwrap();
        assert!(fs.metadata(&file, &request).await.unwrap().allocation_size >= 32);
        write_all(fs, &file, 16, b"x", &request).await;
        assert_eq!(fs.metadata(&file, &request).await.unwrap().size, 17);
        assert_eq!(
            read_bytes(fs, &file, 4, 13, &request).await,
            b"\0\0\0\0\0\0\0\0\0\0\0\0x"
        );
        fs.set_allocation_size(&file, 0, &request).await.unwrap();
        let info = fs.metadata(&file, &request).await.unwrap();
        assert_eq!((info.size, info.allocation_size), (0, 0));
    }
    fs.close(&file, &request).await.unwrap();
}

/// Mode changes retain immutable buffering/write-through state and cannot
/// change whether an open is synchronous.
pub async fn file_mode_updates<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let file = open(fs, "mode", CreateDisposition::CREATE, false, &request).await;
    if let Some(status) = unsupported(fixture.expectations().file_mode) {
        rejected(fs.set_mode(&file, 6, &request).await, status);
    } else {
        assert_eq!(fs.set_mode(&file, 6, &request).await.unwrap(), 6);
        for mode in [8, 0x10, 0x20, 0x1000, u32::MAX] {
            rejected(
                fs.set_mode(&file, mode, &request).await,
                Status::INVALID_PARAMETER,
            );
        }
        assert_eq!(fs.set_mode(&file, 0, &request).await.unwrap(), 0);
        for (name, initial, applied) in
            [("unbuffered", 8, 12), ("through", 10, 14), ("sync", 16, 32)]
        {
            let (other, _) = fs
                .open(
                    name,
                    OpenOptions {
                        access: AccessMask::FILE_ALL_ACCESS
                            .with_append_data(false)
                            .into_bits(),
                        options: initial,
                        ..options(CreateDisposition::CREATE, false)
                    },
                    &request,
                )
                .await
                .unwrap();
            let mode = if initial == 16 { 32 } else { 6 };
            assert_eq!(fs.set_mode(&other, mode, &request).await.unwrap(), applied);
            fs.close(&other, &request).await.unwrap();
        }
    }
    fs.close(&file, &request).await.unwrap();
}

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
    assert_eq!(initial.path, "\\data");
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
    assert_eq!(metadata.number_of_links, 1);
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

/// Renames and moves preserve source opens, data, identity and acquired locks.
pub async fn rename_identity<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let file = open(fs, "before", CreateDisposition::CREATE, false, &request).await;
    let peer = open(fs, "before", CreateDisposition::OPEN, false, &request).await;
    write_all(fs, &file, 0, b"payload", &request).await;
    let before = fs.metadata(&file, &request).await.unwrap();
    if let Some(status) = unsupported(fixture.expectations().rename) {
        rejected(fs.rename(&file, "after", false, &request).await, status);
        assert_eq!(fs.metadata(&file, &request).await.unwrap().name, "before");
    } else {
        let locked = matches!(fixture.expectations().locks, Feature::Supported);
        if locked {
            fs.lock(&file, RANGE, true, true, &request).await.unwrap();
        }
        fs.rename(&file, "after", false, &request).await.unwrap();
        let after = fs.metadata(&peer, &request).await.unwrap();
        assert_eq!((after.id, after.size), (before.id, before.size));
        assert_eq!(after.name, "after");
        assert_eq!(after.path, "\\after");
        if locked {
            rejected(
                fs.read(&peer, 0, 7, &request).await,
                Status::FILE_LOCK_CONFLICT,
            );
            fs.unlock(&file, RANGE, &request).await.unwrap();
        }
        assert_eq!(read_bytes(fs, &peer, 0, 7, &request).await, b"payload");
        rejected(
            fs.open("before", options(CreateDisposition::OPEN, false), &request)
                .await,
            Status::OBJECT_NAME_NOT_FOUND,
        );
        fs.rename(&file, "AFTER", false, &request).await.unwrap();
        assert_eq!(fs.metadata(&peer, &request).await.unwrap().name, "AFTER");
        let directory = open(fs, "destination", CreateDisposition::CREATE, true, &request).await;
        fs.rename(&file, "destination\\moved", false, &request)
            .await
            .unwrap();
        assert_eq!(
            fs.metadata(&peer, &request).await.unwrap().path,
            "\\destination\\moved"
        );
        let reopened = open(
            fs,
            "destination\\moved",
            CreateDisposition::OPEN,
            false,
            &request,
        )
        .await;
        assert_eq!(
            fs.metadata(&reopened, &request).await.unwrap().id,
            before.id
        );
        assert_eq!(read_bytes(fs, &reopened, 0, 7, &request).await, b"payload");
        fs.close(&reopened, &request).await.unwrap();
        fs.close(&directory, &request).await.unwrap();
    }
    fs.close(&peer, &request).await.unwrap();
    fs.close(&file, &request).await.unwrap();
}

/// Directory moves reject open descendants and cycles; replacement rejects
/// open targets and preserves both objects on failure.
pub async fn rename_namespace_and_replacement<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let directory = open(fs, "directory", CreateDisposition::CREATE, true, &request).await;
    if let Some(status) = unsupported(fixture.expectations().rename) {
        rejected(
            fs.rename(&directory, "renamed", false, &request).await,
            status,
        );
        fs.close(&directory, &request).await.unwrap();
        return;
    }
    let subdirectory = open(
        fs,
        "directory\\sub",
        CreateDisposition::CREATE,
        true,
        &request,
    )
    .await;
    let child = open(
        fs,
        "directory\\sub\\child",
        CreateDisposition::CREATE,
        false,
        &request,
    )
    .await;
    let child_id = fs.metadata(&child, &request).await.unwrap().id;
    write_all(fs, &child, 0, b"child", &request).await;
    rejected(
        fs.rename(&directory, "renamed", false, &request).await,
        Status::ACCESS_DENIED,
    );
    fs.close(&child, &request).await.unwrap();
    fs.close(&subdirectory, &request).await.unwrap();
    rejected(
        fs.rename(&directory, "directory\\sub\\cycle", false, &request)
            .await,
        Status::ACCESS_DENIED,
    );
    fs.rename(&directory, "renamed", false, &request)
        .await
        .unwrap();
    let moved = open(
        fs,
        "renamed\\sub\\child",
        CreateDisposition::OPEN,
        false,
        &request,
    )
    .await;
    assert_eq!(fs.metadata(&moved, &request).await.unwrap().id, child_id);
    assert_eq!(read_bytes(fs, &moved, 0, 5, &request).await, b"child");
    fs.close(&moved, &request).await.unwrap();

    let source = open(fs, "source", CreateDisposition::CREATE, false, &request).await;
    let target = open(fs, "target", CreateDisposition::CREATE, false, &request).await;
    let source_id = fs.metadata(&source, &request).await.unwrap().id;
    write_all(fs, &source, 0, b"source", &request).await;
    write_all(fs, &target, 0, b"target", &request).await;
    for (name, replace, status) in [
        ("target", false, Status::OBJECT_NAME_COLLISION),
        ("target", true, Status::ACCESS_DENIED),
        ("renamed", true, Status::ACCESS_DENIED),
        ("missing\\name", false, Status::OBJECT_PATH_NOT_FOUND),
        ("target\\name", false, Status::NOT_A_DIRECTORY),
    ] {
        rejected(fs.rename(&source, name, replace, &request).await, status);
        assert_eq!(fs.metadata(&source, &request).await.unwrap().name, "source");
        assert_eq!(read_bytes(fs, &source, 0, 6, &request).await, b"source");
        assert_eq!(read_bytes(fs, &target, 0, 6, &request).await, b"target");
    }
    fs.close(&target, &request).await.unwrap();
    fs.rename(&source, "target", true, &request).await.unwrap();
    let replaced = open(fs, "target", CreateDisposition::OPEN, false, &request).await;
    assert_eq!(
        fs.metadata(&replaced, &request).await.unwrap().id,
        source_id
    );
    assert_eq!(read_bytes(fs, &replaced, 0, 6, &request).await, b"source");
    fs.set_delete_on_close(&source, true, &request)
        .await
        .unwrap();
    rejected(
        fs.rename(&source, "pending", false, &request).await,
        Status::ACCESS_DENIED,
    );
    fs.close(&replaced, &request).await.unwrap();
    fs.close(&source, &request).await.unwrap();
    let container = open(fs, "container", CreateDisposition::CREATE, true, &request).await;
    fs.rename(&directory, "container\\renamed", false, &request)
        .await
        .unwrap();
    let moved = open(
        fs,
        "container\\renamed\\sub\\child",
        CreateDisposition::OPEN,
        false,
        &request,
    )
    .await;
    assert_eq!(fs.metadata(&moved, &request).await.unwrap().id, child_id);
    assert_eq!(read_bytes(fs, &moved, 0, 5, &request).await, b"child");
    fs.close(&moved, &request).await.unwrap();
    fs.close(&container, &request).await.unwrap();
    let shared = open(fs, "shared", CreateDisposition::CREATE, true, &request).await;
    let file = open(
        fs,
        "shared\\file",
        CreateDisposition::CREATE,
        false,
        &request,
    )
    .await;
    fs.close(&shared, &request).await.unwrap();
    let (parent, _) = fs
        .open(
            "shared",
            OpenOptions {
                access: AccessMask::FILE_GENERIC_READ.into_bits(),
                share_access: ShareAccess::new().with_read(true).into_bits(),
                ..options(CreateDisposition::OPEN, true)
            },
            &request,
        )
        .await
        .unwrap();
    rejected(
        fs.rename(&file, "shared\\new", false, &request).await,
        Status::SHARING_VIOLATION,
    );
    fs.close(&parent, &request).await.unwrap();
    fs.rename(&file, "shared\\new", false, &request)
        .await
        .unwrap();
    let (parent, _) = fs
        .open(
            "shared",
            OpenOptions {
                access: AccessMask::new().with_read_attributes(true).into_bits(),
                share_access: 0,
                ..options(CreateDisposition::OPEN, true)
            },
            &request,
        )
        .await
        .unwrap();
    fs.rename(&file, "shared\\metadata", false, &request)
        .await
        .unwrap();
    fs.close(&parent, &request).await.unwrap();
    fs.close(&file, &request).await.unwrap();
    fs.close(&directory, &request).await.unwrap();
}

async fn register<B: FileSystem>(
    fs: &B,
    directory: &B::File,
    filter: NotifyFilter,
    tree: bool,
    id: u64,
) {
    let cancelled = RequestContext::new(id);
    cancelled.cancel();
    rejected(
        fs.notify(directory, filter, tree, 4096, &cancelled).await,
        Status::CANCELLED,
    );
}

/// Rename name records and file metadata compatibility records are filtered;
/// exact replacement produces a single metadata record, not a duplicate.
pub async fn rename_notifications<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let root = open(fs, "", CreateDisposition::OPEN, true, &request).await;
    let left = open(fs, "left", CreateDisposition::CREATE, true, &request).await;
    let right = open(fs, "right", CreateDisposition::CREATE, true, &request).await;
    let file = open(
        fs,
        "left\\source",
        CreateDisposition::CREATE,
        false,
        &request,
    )
    .await;
    if let Some(status) = unsupported(fixture.expectations().rename) {
        rejected(fs.rename(&file, "left\\new", false, &request).await, status);
    } else if let Some(status) = unsupported(fixture.expectations().notifications) {
        rejected_notify(fs, &root, status, &request).await;
    } else {
        let target = open(
            fs,
            "right\\target",
            CreateDisposition::CREATE,
            false,
            &request,
        )
        .await;
        let metadata = open(fs, "", CreateDisposition::OPEN, true, &request).await;
        let creation = open(fs, "", CreateDisposition::OPEN, true, &request).await;
        let combined = open(fs, "", CreateDisposition::OPEN, true, &request).await;
        let directory = open(
            fs,
            "left\\directory",
            CreateDisposition::CREATE,
            true,
            &request,
        )
        .await;
        register(fs, &root, file_names(), true, 2).await;
        register(fs, &left, file_names(), false, 3).await;
        register(fs, &right, file_names(), false, 4).await;
        register(
            fs,
            &metadata,
            NotifyFilter::new().with_attributes(true),
            true,
            5,
        )
        .await;
        register(
            fs,
            &creation,
            NotifyFilter::new().with_creation(true),
            true,
            6,
        )
        .await;
        register(
            fs,
            &combined,
            file_names().with_attributes(true).with_creation(true),
            true,
            7,
        )
        .await;
        fs.rename(&directory, "right\\directory", false, &request)
            .await
            .unwrap();
        fs.close(&directory, &request).await.unwrap();
        fs.rename(&file, "left\\source", false, &request)
            .await
            .unwrap();
        rejected(
            fs.rename(&file, "right\\target", false, &request).await,
            Status::OBJECT_NAME_COLLISION,
        );
        rejected(
            fs.rename(&file, "right\\target", true, &request).await,
            Status::ACCESS_DENIED,
        );
        fs.close(&target, &request).await.unwrap();
        fs.rename(&file, "left\\new", false, &request)
            .await
            .unwrap();
        let initial = fs.metadata(&file, &request).await.unwrap();
        changes(
            fs.notify(&root, file_names(), true, 4096, &request)
                .await
                .unwrap(),
            &[
                (NotifyAction::RENAMED_OLD_NAME, "left\\source"),
                (NotifyAction::RENAMED_NEW_NAME, "left\\new"),
            ],
        );
        changes(
            fs.notify(&left, file_names(), false, 4096, &request)
                .await
                .unwrap(),
            &[
                (NotifyAction::RENAMED_OLD_NAME, "source"),
                (NotifyAction::RENAMED_NEW_NAME, "new"),
            ],
        );
        fs.rename(&file, "right\\moved", false, &request)
            .await
            .unwrap();
        changes(
            fs.notify(&root, file_names(), true, 4096, &request)
                .await
                .unwrap(),
            &[
                (NotifyAction::REMOVED, "left\\new"),
                (NotifyAction::ADDED, "right\\moved"),
            ],
        );
        changes(
            fs.notify(&left, file_names(), false, 4096, &request)
                .await
                .unwrap(),
            &[(NotifyAction::REMOVED, "new")],
        );
        changes(
            fs.notify(&right, file_names(), false, 4096, &request)
                .await
                .unwrap(),
            &[(NotifyAction::ADDED, "moved")],
        );
        fs.rename(&file, "right\\target", true, &request)
            .await
            .unwrap();
        changes(
            fs.notify(&root, file_names(), true, 4096, &request)
                .await
                .unwrap(),
            &[(NotifyAction::REMOVED, "right\\moved")],
        );
        changes(
            fs.notify(&right, file_names(), false, 4096, &request)
                .await
                .unwrap(),
            &[(NotifyAction::REMOVED, "moved")],
        );
        fs.rename(&file, "right\\TARGET", false, &request)
            .await
            .unwrap();
        let renamed = fs.metadata(&file, &request).await.unwrap();
        assert_eq!(renamed.attributes, initial.attributes);
        assert_eq!(renamed.created, initial.created);
        fs.close(&file, &request).await.unwrap();
        changes(
            fs.notify(
                &metadata,
                NotifyFilter::new().with_attributes(true),
                true,
                4096,
                &request,
            )
            .await
            .unwrap(),
            &[
                (NotifyAction::MODIFIED, "left\\new"),
                (NotifyAction::MODIFIED, "right\\moved"),
                (NotifyAction::MODIFIED, "right\\target"),
                (NotifyAction::MODIFIED, "right\\TARGET"),
            ],
        );
        changes(
            fs.notify(
                &creation,
                NotifyFilter::new().with_creation(true),
                true,
                4096,
                &request,
            )
            .await
            .unwrap(),
            &[
                (NotifyAction::MODIFIED, "left\\new"),
                (NotifyAction::MODIFIED, "right\\moved"),
                (NotifyAction::MODIFIED, "right\\target"),
                (NotifyAction::MODIFIED, "right\\TARGET"),
            ],
        );
        changes(
            fs.notify(
                &combined,
                file_names().with_attributes(true),
                true,
                4096,
                &request,
            )
            .await
            .unwrap(),
            &[
                (NotifyAction::RENAMED_OLD_NAME, "left\\source"),
                (NotifyAction::RENAMED_NEW_NAME, "left\\new"),
                (NotifyAction::MODIFIED, "left\\new"),
                (NotifyAction::REMOVED, "left\\new"),
                (NotifyAction::ADDED, "right\\moved"),
                (NotifyAction::MODIFIED, "right\\moved"),
                (NotifyAction::REMOVED, "right\\moved"),
                (NotifyAction::MODIFIED, "right\\target"),
                (NotifyAction::RENAMED_OLD_NAME, "right\\target"),
                (NotifyAction::RENAMED_NEW_NAME, "right\\TARGET"),
                (NotifyAction::MODIFIED, "right\\TARGET"),
            ],
        );
        fs.close(&combined, &request).await.unwrap();
        fs.close(&creation, &request).await.unwrap();
        fs.close(&metadata, &request).await.unwrap();
    }
    fs.close(&file, &request).await.unwrap();
    fs.close(&right, &request).await.unwrap();
    fs.close(&left, &request).await.unwrap();
    fs.close(&root, &request).await.unwrap();
}

/// Bilateral sharing, metadata-only exemptions, and settled close/drop release.
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
    for access in [
        AccessMask::new().with_read_attributes(true),
        AccessMask::new().with_write_attributes(true),
        AccessMask::new().with_synchronize(true),
    ] {
        let metadata = OpenOptions {
            access: access.into_bits(),
            share_access: 0,
            ..options(CreateDisposition::OPEN, false)
        };
        let exclusive = OpenOptions {
            share_access: 0,
            ..write
        };
        let (first, _) = fs.open("sharing", metadata, &request).await.unwrap();
        let (second, _) = fs.open("sharing", exclusive, &request).await.unwrap();
        fs.close(&second, &request).await.unwrap();
        fs.close(&first, &request).await.unwrap();
        let (first, _) = fs.open("sharing", exclusive, &request).await.unwrap();
        let (second, _) = fs.open("sharing", metadata, &request).await.unwrap();
        fs.close(&second, &request).await.unwrap();
        fs.close(&first, &request).await.unwrap();
    }
}

/// Delete disposition can be cleared; pending deletion waits for the last
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

/// CREATE's delete-on-close mode is per-open and applied at close, not an
/// immediate shared disposition. A remaining open can clear the pending link.
pub async fn delete_mode_is_deferred_to_close<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let mut mode = options(CreateDisposition::CREATE, false);
    mode.options = CreateOptions::new().with_delete_on_close(true).into_bits();
    let (first, _) = fs.open("mode", mode, &request).await.unwrap();
    assert!(!fs.metadata(&first, &request).await.unwrap().delete_pending);
    let peer = open(fs, "mode", CreateDisposition::OPEN, false, &request).await;
    write_all(fs, &first, 0, b"retained", &request).await;
    fs.set_delete_on_close(&peer, false, &request)
        .await
        .unwrap();
    fs.set_delete_on_close(&first, false, &request)
        .await
        .unwrap();
    fs.close(&first, &request).await.unwrap();
    assert!(fs.metadata(&peer, &request).await.unwrap().delete_pending);
    rejected(
        fs.open("mode", options(CreateDisposition::OPEN, false), &request)
            .await,
        Status::DELETE_PENDING,
    );
    assert_eq!(read_bytes(fs, &peer, 0, 8, &request).await, b"retained");
    fs.set_delete_on_close(&peer, false, &request)
        .await
        .unwrap();
    assert!(!fs.metadata(&peer, &request).await.unwrap().delete_pending);
    let reopened = open(fs, "mode", CreateDisposition::OPEN, false, &request).await;
    fs.close(&peer, &request).await.unwrap();
    fs.close(&reopened, &request).await.unwrap();
    let preserved = open(fs, "mode", CreateDisposition::OPEN, false, &request).await;
    assert_eq!(
        read_bytes(fs, &preserved, 0, 8, &request).await,
        b"retained"
    );
    fs.close(&preserved, &request).await.unwrap();

    let first = open(
        fs,
        "disposition",
        CreateDisposition::CREATE,
        false,
        &request,
    )
    .await;
    let peer = open(fs, "disposition", CreateDisposition::OPEN, false, &request).await;
    fs.set_delete_on_close(&first, true, &request)
        .await
        .unwrap();
    fs.set_delete_on_close(&peer, false, &request)
        .await
        .unwrap();
    fs.close(&first, &request).await.unwrap();
    assert!(!fs.metadata(&peer, &request).await.unwrap().delete_pending);
    let reopened = open(fs, "disposition", CreateDisposition::OPEN, false, &request).await;
    fs.close(&peer, &request).await.unwrap();
    fs.close(&reopened, &request).await.unwrap();
}

/// Nonempty directories accept CREATE delete-on-close mode but are not deleted
/// on that close. Pending children still block explicit delete disposition.
pub async fn directory_delete_mode_checks_emptiness_at_close<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    for child_directory in [false, true] {
        let parent = open(fs, "parent", CreateDisposition::CREATE, true, &request).await;
        let child = open(
            fs,
            "parent\\child",
            CreateDisposition::CREATE,
            child_directory,
            &request,
        )
        .await;
        if !child_directory {
            write_all(fs, &child, 0, b"retained", &request).await;
        }
        let deleting = open(
            fs,
            "parent\\child",
            CreateDisposition::OPEN,
            child_directory,
            &request,
        )
        .await;
        fs.set_delete_on_close(&deleting, true, &request)
            .await
            .unwrap();
        fs.close(&deleting, &request).await.unwrap();
        rejected(
            fs.set_delete_on_close(&parent, true, &request).await,
            Status::DIRECTORY_NOT_EMPTY,
        );
        let mut mode = options(CreateDisposition::OPEN, true);
        mode.options = CreateOptions::from_bits(mode.options)
            .with_delete_on_close(true)
            .into_bits();
        let (attempt, _) = fs.open("parent", mode, &request).await.unwrap();
        assert!(
            !fs.metadata(&attempt, &request)
                .await
                .unwrap()
                .delete_pending
        );
        fs.close(&attempt, &request).await.unwrap();
        assert!(!fs.metadata(&parent, &request).await.unwrap().delete_pending);
        assert!(fs.metadata(&child, &request).await.unwrap().delete_pending);
        if !child_directory {
            assert_eq!(read_bytes(fs, &child, 0, 8, &request).await, b"retained");
        }
        fs.close(&child, &request).await.unwrap();
        let preserved = open(fs, "parent", CreateDisposition::OPEN, true, &request).await;
        fs.close(&preserved, &request).await.unwrap();
        fs.close(&parent, &request).await.unwrap();
        let (last, _) = fs.open("parent", mode, &request).await.unwrap();
        fs.close(&last, &request).await.unwrap();
        rejected(
            fs.open("parent", options(CreateDisposition::OPEN, true), &request)
                .await,
            Status::OBJECT_NAME_NOT_FOUND,
        );
    }

    let mut mode = options(CreateDisposition::CREATE, true);
    mode.options = CreateOptions::from_bits(mode.options)
        .with_delete_on_close(true)
        .into_bits();
    let (growing, _) = fs.open("growing", mode, &request).await.unwrap();
    let child = open(
        fs,
        "growing\\live",
        CreateDisposition::CREATE,
        false,
        &request,
    )
    .await;
    fs.close(&growing, &request).await.unwrap();
    fs.close(&child, &request).await.unwrap();
    let preserved = open(fs, "growing", CreateDisposition::OPEN, true, &request).await;
    assert!(
        !fs.metadata(&preserved, &request)
            .await
            .unwrap()
            .delete_pending
    );
    fs.close(&preserved, &request).await.unwrap();
}

/// A nonempty directory's deferred-delete close must not invalidate another
/// open's watch. Only an actual deletion disposition does that.
pub async fn notify_nonempty_delete_mode_preserves_watch<F: Fixture>(fixture: &F) {
    let fs = fixture.filesystem();
    let request = RequestContext::new(1);
    let directory = open(fs, "watch", CreateDisposition::CREATE, true, &request).await;
    let child = open(
        fs,
        "watch\\existing",
        CreateDisposition::CREATE,
        false,
        &request,
    )
    .await;
    if let Some(status) = unsupported(fixture.expectations().notifications) {
        rejected_notify(fs, &directory, status, &request).await;
    } else {
        let added;
        {
            let waiting = RequestContext::new(2);
            let mut work =
                std::pin::pin!(fs.notify(&directory, file_names(), false, 4096, &waiting));
            pending(fixture, Operation::Notify, &waiting, work.as_mut()).await;
            let mut mode = options(CreateDisposition::OPEN, true);
            mode.options = CreateOptions::from_bits(mode.options)
                .with_delete_on_close(true)
                .into_bits();
            let (attempt, _) = fs.open("watch", mode, &request).await.unwrap();
            rejected(
                fs.notify(&attempt, file_names(), false, 4096, &request)
                    .await,
                Status::DELETE_PENDING,
            );
            fs.close(&attempt, &request).await.unwrap();
            assert!(futures::poll!(&mut work).is_pending());
            added = open(
                fs,
                "watch\\added",
                CreateDisposition::CREATE,
                false,
                &request,
            )
            .await;
            changes(work.await.unwrap(), &[(NotifyAction::ADDED, "added")]);
        }
        fs.close(&added, &request).await.unwrap();
    }
    fs.close(&child, &request).await.unwrap();
    fs.close(&directory, &request).await.unwrap();
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
