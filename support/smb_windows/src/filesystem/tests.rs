// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use pal_async::{DefaultDriver, async_test};
use smb::provider::{FileSystem, OpenOptions, RequestContext};
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

    fn expectations(&self) -> Expectations {
        Expectations {
            filesystem_information: Feature::Unsupported(Status::NOT_SUPPORTED),
            allocation: Feature::Unsupported(Status::NOT_SUPPORTED),
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
            basic_information: Feature::Unsupported(Status::NOT_SUPPORTED),
            rename: Feature::Unsupported(Status::NOT_SUPPORTED),
            locks: Feature::Unsupported(Status::NOT_SUPPORTED),
            notifications: Feature::Unsupported(Status::NOT_SUPPORTED),
        }
    }

    async fn wait_until_pending(&self, _operation: Operation, _request: &RequestContext) {
        panic!("this foundation has no pending locks or watches");
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
contract_test!(notify_registration_and_cancellation);

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
        ("delete", nt::FILE_DELETE_ON_CLOSE),
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
