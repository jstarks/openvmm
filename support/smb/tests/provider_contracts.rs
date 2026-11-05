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
            basic_information: Feature::Supported,
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
        for operation in [Operation::SetBasic, Operation::Lock, Operation::Notify] {
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
                basic_information: Feature::Unsupported(Status::NOT_SUPPORTED),
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
            basic_information: Feature::Supported,
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
