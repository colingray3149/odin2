//! Authorization failures must not consume approvals or reach the executor.

use std::sync::atomic::Ordering;

use odin_domain::knowledge::ResourceConstraint;
use odin_domain::ApprovalStatus;
use odin_kernel::AuthorizationRejection;
use serde_json::json;

use crate::host_tools::operations::HostToolOperationError;

use super::fixture::{Fixture, EXEC_TOOL};

/// A call aimed at a resource the seat does not hold is refused before the gate, so the
/// owner's recorded yes stays unspent and still runs the call against the right resource.
#[test]
fn a_wrong_resource_is_refused_without_spending_the_owners_approval() {
    let fixture = Fixture::new();
    fixture.accept_plan("Approve one governed R3 dispatch");
    let call = |resource: ResourceConstraint, request: &str| {
        fixture.dispatch_named(EXEC_TOOL, Some(resource), json!({"value": "go"}), request)
    };
    let Err(HostToolOperationError::ApprovalRequired {
        approval_id,
        revision,
        ..
    }) = call(fixture.resource.clone(), "resource-mint")
    else {
        panic!("a first R3 dispatch is refused with an approval request");
    };
    fixture.approve(&approval_id, revision);

    let wrong = ResourceConstraint::Named {
        kind: "workspace".to_owned(),
        value: "other".to_owned(),
    };
    let denied = call(wrong, "resource-wrong").expect_err("a resource the seat lacks is refused");
    assert!(
        matches!(
            denied,
            HostToolOperationError::Rejected(AuthorizationRejection::ResourceDenied { .. })
        ),
        "{denied:?}"
    );
    let status = || {
        fixture
            .ledger
            .lock()
            .expect("ledger lock")
            .approval(&approval_id)
            .expect("approval readable")
            .expect("approval record")
            .status
    };
    assert_eq!(
        status(),
        ApprovalStatus::Approved,
        "the denial spent nothing"
    );
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);

    call(fixture.resource.clone(), "resource-right")
        .expect("the owner's yes runs the call against the right resource");
    assert_eq!(status(), ApprovalStatus::Consumed);
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
}
