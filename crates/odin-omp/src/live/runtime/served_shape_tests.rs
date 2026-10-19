use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use odin_domain::huginn::LiveError;
use odin_domain::{Digest, LaneId, NodeId, ProjectId, SeatId, SliceId};

use crate::host_tools::operations::{
    seat_operation_policy, SeatOperationPolicy, SeatOperationPolicyInputs,
};

use super::assembly::validate_served_shape;

/// One legitimately shaped (seat, lane) operation binding, built through
/// the single canonical constructor.
fn one_seat_operation_binding() -> ((SeatId, LaneId), SeatOperationPolicy) {
    let seat = SeatId::new("architect").expect("seat id");
    let lane = LaneId::new("ask").expect("lane id");
    let policy = seat_operation_policy(SeatOperationPolicyInputs {
        seat_id: seat.clone(),
        slice_id: SliceId::new("architect-engineer").expect("slice id"),
        lane_id: lane.clone(),
        seat_revision: Digest::new([7; 32]),
        slice_revision: Digest::new([9; 32]),
        admission: Digest::new([1; 32]),
        seat_tool_refs: BTreeSet::new(),
        slice_capabilities: BTreeSet::new(),
        project_capabilities: BTreeSet::new(),
        lane_capabilities: BTreeSet::new(),
        denied_capabilities: BTreeSet::new(),
        denied_tools: BTreeSet::new(),
        resource_constraints: BTreeMap::new(),
        seat_categories: BTreeSet::new(),
    });
    ((seat, lane), policy)
}

fn refusal_message(error: LiveError) -> String {
    match error {
        LiveError::InvalidRequest { message, .. } => message,
        other => panic!("unexpected non-refusal error: {other:?}"),
    }
}

#[test]
fn follower_composes_the_empty_served_sets() {
    validate_served_shape(
        true,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
    )
    .expect("read-only follower composes the empty served sets");
}

#[test]
fn authority_still_refuses_empty_seat_bindings() {
    let message = refusal_message(
        validate_served_shape(
            false,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
        )
        .expect_err("an authority refuses zero seat operation bindings"),
    );
    assert_eq!(message, "at least one seat operation binding is required");
}

#[test]
fn authority_still_requires_projects_lanes_and_nodes() {
    let bindings = BTreeMap::from([one_seat_operation_binding()]);
    let message = refusal_message(
        validate_served_shape(
            false,
            &bindings,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
        )
        .expect_err("an authority refuses empty registry projects, lanes, and nodes"),
    );
    assert_eq!(
        message,
        "bridge runtime requires registry projects, session lanes, and allowed nodes"
    );
}

#[test]
fn authority_accepts_the_fully_declared_shape() {
    let ((seat, lane), policy) = one_seat_operation_binding();
    let bindings = BTreeMap::from([((seat.clone(), lane.clone()), policy)]);
    let project = ProjectId::new("odin").expect("project id");
    let project_roots = BTreeMap::from([(project.clone(), PathBuf::from("/tmp"))]);
    let session_lanes = BTreeMap::from([((seat.clone(), project), lane.clone())]);
    let allowed_nodes = BTreeSet::from([NodeId::new("laptop").expect("node id")]);
    validate_served_shape(
        false,
        &bindings,
        &project_roots,
        &session_lanes,
        &allowed_nodes,
    )
    .expect("a fully declared authority composition keeps composing");
}
