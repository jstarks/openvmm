// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Check the exported scenarios from outside the crate, including explicit
//! rejection profiles. The rejecting wrapper tests the suite, not native I/O.

#![cfg(feature = "test-support")]

use futures::executor::block_on;
use smb::memory::MemoryFs;
use smb::provider::RequestContext;
use smb::spec::Status;
use smb::test_support::contracts::{self, Expectations, Feature, Fixture};
use smb::test_support::{ControlledFs, Controller, Gate, Operation, Phase, Plan};
use test_with_tracing::test;

struct MemoryFixture(MemoryFs);

impl Fixture for MemoryFixture {
    type Backend = MemoryFs;

    fn filesystem(&self) -> &Self::Backend {
        &self.0
    }

    fn expectations(&self) -> Expectations {
        Expectations {
            filesystem_information: Feature::Supported,
            allocation: Feature::Supported,
            creation_allocation: true,
            file_mode: Feature::Supported,
            security_queries: Feature::Supported,
            file_acl_updates: Feature::Supported,
            directory_acl_updates: Feature::Supported,
            acl_inheritance: Feature::Supported,
            security_creation: Feature::Supported,
            creation_eas: Feature::Supported,
            ea_operations: Feature::Supported,
            stream_queries: Feature::Supported,
            named_streams: Feature::Supported,
            stream_rename: Feature::Supported,
            short_names: Feature::Supported,
            volume_object_ids: Feature::Supported,
            object_id_controls: Feature::Supported,
            basic_information: Feature::Supported,
            rename: Feature::Supported,
            locks: Feature::Supported,
            notifications: Feature::Supported,
        }
    }

    async fn wait_until_pending(&self, operation: Operation, request: &RequestContext) {
        // MemoryFs registers synchronously before its first pending poll.
        assert!(matches!(operation, Operation::Lock | Operation::Notify));
        assert!(!request.is_cancelled());
    }
}

struct ControlledFixture {
    fs: ControlledFs<MemoryFs>,
    control: Controller,
    expectations: Expectations,
}

impl ControlledFixture {
    fn rejecting() -> Self {
        let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 32));
        for operation in [
            Operation::FileSystemInformation,
            Operation::SetAllocationSize,
            Operation::SetMode,
            Operation::QuerySecurity,
            Operation::SetSecurity,
            Operation::OpenSecurity,
            Operation::SetBasic,
            Operation::Rename,
            Operation::SetShortName,
            Operation::SetVolumeObjectId,
            Operation::FileControl,
            Operation::Lock,
            Operation::Notify,
            Operation::QueryEas,
            Operation::SetEas,
            Operation::QueryStreams,
            Operation::OpenStream,
        ] {
            control
                .set_plan(
                    operation,
                    Plan {
                        failure: Some(Status::NOT_SUPPORTED),
                        ..Plan::default()
                    },
                )
                .unwrap();
        }
        Self {
            fs,
            control,
            expectations: Expectations {
                filesystem_information: Feature::Unsupported(Status::NOT_SUPPORTED),
                allocation: Feature::Unsupported(Status::NOT_SUPPORTED),
                creation_allocation: true,
                file_mode: Feature::Unsupported(Status::NOT_SUPPORTED),
                security_queries: Feature::Unsupported(Status::NOT_SUPPORTED),
                file_acl_updates: Feature::Unsupported(Status::NOT_SUPPORTED),
                directory_acl_updates: Feature::Unsupported(Status::NOT_SUPPORTED),
                acl_inheritance: Feature::Unsupported(Status::NOT_SUPPORTED),
                security_creation: Feature::Unsupported(Status::NOT_SUPPORTED),
                creation_eas: Feature::Supported,
                ea_operations: Feature::Unsupported(Status::NOT_SUPPORTED),
                stream_queries: Feature::Unsupported(Status::NOT_SUPPORTED),
                named_streams: Feature::Unsupported(Status::NOT_SUPPORTED),
                stream_rename: Feature::Unsupported(Status::NOT_SUPPORTED),
                short_names: Feature::Unsupported(Status::NOT_SUPPORTED),
                volume_object_ids: Feature::Unsupported(Status::NOT_SUPPORTED),
                object_id_controls: Feature::Unsupported(Status::NOT_SUPPORTED),
                basic_information: Feature::Unsupported(Status::NOT_SUPPORTED),
                rename: Feature::Unsupported(Status::NOT_SUPPORTED),
                locks: Feature::Unsupported(Status::NOT_SUPPORTED),
                notifications: Feature::Unsupported(Status::NOT_SUPPORTED),
            },
        }
    }

    fn assert_rejected(&self, operations: &[Operation]) {
        let calls = self.control.calls();
        for &operation in operations {
            let rejected: Vec<_> = calls
                .iter()
                .filter(|call| call.operation == operation)
                .collect();
            assert!(!rejected.is_empty(), "{operation:?} was skipped");
            for call in rejected {
                assert!(!call.delegated);
                assert_eq!(call.status, Some(Status::NOT_SUPPORTED));
            }
        }
    }
}

impl Fixture for ControlledFixture {
    type Backend = ControlledFs<MemoryFs>;

    fn filesystem(&self) -> &Self::Backend {
        &self.fs
    }

    fn expectations(&self) -> Expectations {
        self.expectations
    }

    async fn wait_until_pending(&self, operation: Operation, request: &RequestContext) {
        let call = self
            .control
            .calls()
            .into_iter()
            .find(|call| call.operation == operation && call.request_id == request.id())
            .expect("missing controlled call");
        assert_eq!(call.phase, Phase::Before);
        self.control.release(call.id, Gate::Before).unwrap();
        // The delegate is MemoryFs: reaching Executing and returning Pending
        // from the wrapper's poll establishes its synchronous registration.
        self.control
            .wait_for_phase(call.id, Phase::Executing)
            .await
            .unwrap();
    }
}

#[test]
fn exported_lock_wait_contract_can_cancel_private_contexts() {
    let fixture = MemoryFixture(MemoryFs::new(1024, 32));
    block_on(contracts::lock_waiters_and_cancellation(&fixture));
}

#[test]
fn exported_notify_contract_can_cancel_private_contexts() {
    let fixture = MemoryFixture(MemoryFs::new(1024, 32));
    block_on(contracts::notify_registration_and_cancellation(&fixture));
}

#[test]
fn declared_unsupported_basic_information_is_exercised() {
    let fixture = ControlledFixture::rejecting();
    block_on(contracts::basic_information(&fixture));
    fixture.assert_rejected(&[Operation::SetBasic]);
}

#[test]
fn declared_unsupported_filesystem_information_is_exercised() {
    let fixture = ControlledFixture::rejecting();
    block_on(contracts::filesystem_information(&fixture));
    fixture.assert_rejected(&[Operation::FileSystemInformation]);
}

#[test]
fn declared_unsupported_allocation_and_modes_are_exercised() {
    let fixture = ControlledFixture::rejecting();
    block_on(contracts::allocation_reservations(&fixture));
    block_on(contracts::file_mode_updates(&fixture));
    fixture.assert_rejected(&[Operation::SetAllocationSize, Operation::SetMode]);
}

#[test]
fn declared_unsupported_security_queries_are_exercised() {
    let fixture = ControlledFixture::rejecting();
    block_on(contracts::security_queries(&fixture));
    fixture.assert_rejected(&[Operation::QuerySecurity]);
}

#[test]
fn declared_unsupported_acl_updates_are_exercised() {
    let fixture = ControlledFixture::rejecting();
    block_on(contracts::file_acl_updates(&fixture));
    fixture.assert_rejected(&[Operation::SetSecurity]);
}

#[test]
fn declared_unsupported_directory_acl_updates_are_exercised() {
    let fixture = ControlledFixture::rejecting();
    block_on(contracts::directory_acl_updates(&fixture));
    fixture.assert_rejected(&[Operation::SetSecurity]);
}

#[test]
fn declared_unsupported_acl_inheritance_is_exercised() {
    let fixture = ControlledFixture::rejecting();
    block_on(contracts::acl_inheritance(&fixture));
    fixture.assert_rejected(&[Operation::SetSecurity]);
}

#[test]
fn declared_unsupported_security_creation_is_exercised() {
    let fixture = ControlledFixture::rejecting();
    block_on(contracts::security_creation(&fixture));
    fixture.assert_rejected(&[Operation::OpenSecurity]);
}

#[test]
fn exported_ea_creation_contract_checks_retained_storage() {
    let fixture = MemoryFixture(MemoryFs::new(1024, 32));
    block_on(contracts::creation_eas(&fixture));
}

#[test]
fn exported_extended_attribute_contract_checks_storage_and_declines() {
    block_on(contracts::extended_attributes(&MemoryFixture(
        MemoryFs::new(1024, 32),
    )));
    let fixture = ControlledFixture::rejecting();
    block_on(contracts::extended_attributes(&fixture));
    fixture.assert_rejected(&[Operation::QueryEas, Operation::SetEas]);
}
#[test]
fn exported_stream_information_contract_checks_storage_and_declines() {
    block_on(contracts::stream_information(&MemoryFixture(
        MemoryFs::new(1024, 32),
    )));
    let fixture = ControlledFixture::rejecting();
    block_on(contracts::stream_information(&fixture));
    fixture.assert_rejected(&[Operation::QueryStreams]);
}
#[test]
fn exported_named_stream_contract_checks_storage_and_declines() {
    block_on(contracts::named_streams(&MemoryFixture(MemoryFs::new(
        1024, 32,
    ))));
    let fixture = ControlledFixture::rejecting();
    block_on(contracts::named_streams(&fixture));
    fixture.assert_rejected(&[Operation::OpenStream]);
}
#[test]
fn exported_stream_rename_contract_checks_storage_and_declines() {
    block_on(contracts::stream_renames(&MemoryFixture(MemoryFs::new(
        1024, 32,
    ))));
    let fixture = ControlledFixture::rejecting();
    block_on(contracts::stream_renames(&fixture));
    fixture.assert_rejected(&[Operation::Rename]);
}
#[test]
fn exported_short_name_contract_checks_aliases_and_declines() {
    block_on(contracts::short_names(&MemoryFixture(MemoryFs::new(
        1024, 32,
    ))));
    let fixture = ControlledFixture::rejecting();
    block_on(contracts::short_names(&fixture));
    fixture.assert_rejected(&[Operation::SetShortName]);
}
#[test]
fn exported_volume_object_id_contract_checks_shared_metadata_and_declines() {
    block_on(contracts::volume_object_ids(&MemoryFixture(MemoryFs::new(
        1024, 32,
    ))));
    let fixture = ControlledFixture::rejecting();
    block_on(contracts::volume_object_ids(&fixture));
    fixture.assert_rejected(&[Operation::SetVolumeObjectId]);
}
#[test]
fn exported_object_id_control_contract_checks_identity_and_declines() {
    block_on(contracts::object_id_controls(&MemoryFixture(
        MemoryFs::new(1024, 32),
    )));
    let fixture = ControlledFixture::rejecting();
    block_on(contracts::object_id_controls(&fixture));
    fixture.assert_rejected(&[Operation::FileControl]);
}

#[test]
fn declared_unsupported_locks_are_exercised() {
    let fixture = ControlledFixture::rejecting();
    block_on(contracts::lock_conflicts_and_io(&fixture));
    fixture.assert_rejected(&[Operation::Lock]);
}

#[test]
fn declared_unsupported_notifications_are_exercised() {
    let fixture = ControlledFixture::rejecting();
    block_on(contracts::notify_registration_and_cancellation(&fixture));
    fixture.assert_rejected(&[Operation::Notify]);
}

#[test]
fn declared_unsupported_rename_is_exercised() {
    let fixture = ControlledFixture::rejecting();
    block_on(contracts::rename_identity(&fixture));
    fixture.assert_rejected(&[Operation::Rename]);
}

#[test]
fn exported_data_contract_accepts_real_short_transfers() {
    let fixture = ControlledFixture::rejecting();
    for operation in [Operation::Read, Operation::Write] {
        fixture
            .control
            .set_plan(
                operation,
                Plan {
                    transfer_limit: Some(2),
                    ..Plan::default()
                },
            )
            .unwrap();
    }
    block_on(contracts::data_and_identity(&fixture));
    for operation in [Operation::Read, Operation::Write] {
        assert!(fixture.control.calls().iter().any(|call| {
            call.operation == operation && call.delegated && call.transferred == Some(2)
        }));
    }
}

#[test]
fn pending_checkpoint_keeps_driving_the_operation() {
    let (fs, control) = ControlledFs::new(MemoryFs::new(1024, 32));
    control.plan_next(Operation::Lock, Plan::default()).unwrap();
    for _ in 0..2 {
        control
            .plan_next(
                Operation::Lock,
                Plan {
                    hold_before: true,
                    ..Plan::default()
                },
            )
            .unwrap();
    }
    let fixture = ControlledFixture {
        fs,
        control,
        expectations: Expectations {
            filesystem_information: Feature::Supported,
            allocation: Feature::Supported,
            creation_allocation: true,
            file_mode: Feature::Supported,
            security_queries: Feature::Supported,
            file_acl_updates: Feature::Supported,
            directory_acl_updates: Feature::Supported,
            acl_inheritance: Feature::Supported,
            security_creation: Feature::Supported,
            creation_eas: Feature::Supported,
            ea_operations: Feature::Supported,
            stream_queries: Feature::Supported,
            named_streams: Feature::Supported,
            stream_rename: Feature::Supported,
            short_names: Feature::Supported,
            volume_object_ids: Feature::Supported,
            object_id_controls: Feature::Supported,
            basic_information: Feature::Supported,
            rename: Feature::Supported,
            locks: Feature::Supported,
            notifications: Feature::Supported,
        },
    };
    block_on(contracts::lock_waiters_and_cancellation(&fixture));
    for id in [2, 3] {
        let calls = fixture.control.calls();
        let call = calls
            .iter()
            .find(|call| call.operation == Operation::Lock && call.request_id == id)
            .unwrap();
        assert!(call.delegated);
        assert_eq!(call.phase, Phase::Completed);
    }
}
