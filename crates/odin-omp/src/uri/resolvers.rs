//! Scoped ledger-backed URI resolution through resource reference chains.

use std::fmt;

use odin_domain::{
    ApprovalId, ApprovalStatus, ArtifactId, AttemptId, IncidentId, LaneId, LaneStatus, NodeId,
    ProjectId, RunId, RunStatus, Scope, SeatId, SessionId,
};
use odin_ledger::{
    approval::Approval,
    encode_utc,
    incident::IncidentCard,
    lane_run::{self, LaneRecord, RunRecord},
    Ledger, LedgerResult,
};
use serde_json::{json, Value};

use super::ScopedUriRouter;
use super::{UriBody, UriContext, UriError, UriRequest, UriResult, JSON_CONTENT_TYPE};

impl ScopedUriRouter {
    pub(super) fn resolve_lane(
        &self,
        ledger: &Ledger,
        context: &UriContext,
        request: UriRequest,
    ) -> Result<UriResult, UriError> {
        let url = &request.url;
        let id = required_id(&request)?;
        let lane_id: LaneId = parse_resource_id(url, id)?;
        let Some(record) =
            lane_run::read_lane(ledger.connection(), &lane_id).map_err(storage_error)?
        else {
            return Err(unknown_resource(url, "lane", id));
        };
        let object = lane_object_scope(&record)?;
        if let Some(dimension) = scope_shortfall(&context.scope, &object) {
            return Err(scope_denied(url, dimension));
        }
        Ok(json_result(request, lane_json(&record)?))
    }

    pub(super) fn resolve_run(
        &self,
        ledger: &Ledger,
        context: &UriContext,
        request: UriRequest,
    ) -> Result<UriResult, UriError> {
        let url = &request.url;
        let id = required_id(&request)?;
        let run_id: RunId = parse_resource_id(url, id)?;
        let Some(record) =
            lane_run::read_run(ledger.connection(), &run_id).map_err(storage_error)?
        else {
            return Err(unknown_resource(url, "run", id));
        };
        let object = run_object_scope(ledger, &record)?;
        if let Some(dimension) = scope_shortfall(&context.scope, &object) {
            return Err(scope_denied(url, dimension));
        }
        Ok(json_result(request, run_json(&record)?))
    }

    pub(super) fn resolve_incident(
        &self,
        ledger: &Ledger,
        context: &UriContext,
        request: UriRequest,
    ) -> Result<UriResult, UriError> {
        let url = &request.url;
        let id = required_id(&request)?;
        let incident_id: IncidentId = parse_resource_id(url, id)?;
        let Some(card) = ledger.incident(&incident_id).map_err(storage_error)? else {
            return Err(unknown_resource(url, "incident", id));
        };
        let object = incident_object_scope(ledger, &card, &context.scope)?;
        if let Some(dimension) = scope_shortfall(&context.scope, &object) {
            return Err(scope_denied(url, dimension));
        }
        Ok(json_result(request, incident_json(&card)?))
    }

    pub(super) fn resolve_approval(
        &self,
        ledger: &Ledger,
        context: &UriContext,
        request: UriRequest,
    ) -> Result<UriResult, UriError> {
        let url = &request.url;
        let id = required_id(&request)?;
        let approval_id: ApprovalId = parse_resource_id(url, id)?;
        let Some(approval) = ledger.approval(&approval_id).map_err(storage_error)? else {
            return Err(unknown_resource(url, "approval", id));
        };
        let proven = proves_scope(
            ledger,
            url,
            &context.scope,
            &approval.scope.target_kind,
            &approval.scope.target_id,
            2,
        )?;
        if !proven {
            return Err(UriError::ScopeDenied {
                url: url.to_owned(),
                reason: "the approval target does not prove the bound scope".to_owned(),
            });
        }
        Ok(json_result(request, approval_json(&approval)?))
    }
}

pub(super) fn json_result(request: UriRequest, value: Value) -> UriResult {
    UriResult {
        request,
        content_type: JSON_CONTENT_TYPE.to_owned(),
        immutable: true,
        notes: Vec::new(),
        body: UriBody::Json(value),
    }
}

pub(super) fn required_id(request: &UriRequest) -> Result<&str, UriError> {
    request.id.as_deref().ok_or_else(|| UriError::Malformed {
        url: request.url.clone(),
        reason: "canonical URI requires exactly one identifier".to_owned(),
    })
}

pub(super) fn parse_resource_id<T>(url: &str, value: &str) -> Result<T, UriError>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    T::from_str(value).map_err(|error| UriError::NonCanonicalId {
        url: url.to_owned(),
        value: value.to_owned(),
        reason: error.to_string(),
    })
}

pub(super) fn unknown_resource(url: &str, kind: &'static str, id: &str) -> UriError {
    UriError::UnknownResource {
        url: url.to_owned(),
        kind,
        id: id.to_owned(),
    }
}

pub(super) fn storage_error(error: impl fmt::Display) -> UriError {
    UriError::Storage {
        detail: error.to_string(),
    }
}

pub(super) fn scope_denied(url: &str, dimension: &str) -> UriError {
    UriError::ScopeDenied {
        url: url.to_owned(),
        reason: format!("bound scope dimension {dimension:?} is not proven by the resource"),
    }
}

/// Every specified scope dimension must be present and equal; unspecified dimensions are wildcards.
pub(super) fn scope_shortfall(bound: &Scope, object: &Scope) -> Option<&'static str> {
    if bound.seat.is_some() && bound.seat != object.seat {
        return Some("seat");
    }
    if bound.project.is_some() && bound.project != object.project {
        return Some("project");
    }
    if bound.lane.is_some() && bound.lane != object.lane {
        return Some("lane");
    }
    if bound.run.is_some() && bound.run != object.run {
        return Some("run");
    }
    if bound.attempt.is_some() && bound.attempt != object.attempt {
        return Some("attempt");
    }
    if bound.session.is_some() && bound.session != object.session {
        return Some("session");
    }
    if bound.node.is_some() && bound.node != object.node {
        return Some("node");
    }
    None
}

/// Checks all requested dimensions, limiting reference depth so cycles terminate.
pub(super) fn proves_scope(
    ledger: &Ledger,
    url: &str,
    bound: &Scope,
    kind: &str,
    id: &str,
    depth: u8,
) -> Result<bool, UriError> {
    match (kind, depth) {
        ("seat", _) => {
            let seat: SeatId = parse_resource_id(url, id)?;
            Ok(scope_shortfall(
                bound,
                &Scope {
                    seat: Some(seat),
                    ..Scope::default()
                },
            )
            .is_none())
        }
        ("project", _) => {
            let project: ProjectId = parse_resource_id(url, id)?;
            Ok(scope_shortfall(
                bound,
                &Scope {
                    project: Some(project),
                    ..Scope::default()
                },
            )
            .is_none())
        }
        ("node", _) => {
            let node: NodeId = parse_resource_id(url, id)?;
            Ok(scope_shortfall(
                bound,
                &Scope {
                    node: Some(node),
                    ..Scope::default()
                },
            )
            .is_none())
        }
        ("session", _) => {
            let session: SessionId = parse_resource_id(url, id)?;
            Ok(scope_shortfall(
                bound,
                &Scope {
                    session: Some(session),
                    ..Scope::default()
                },
            )
            .is_none())
        }
        ("lane", _) => {
            let lane_id: LaneId = parse_resource_id(url, id)?;
            let Some(record) =
                lane_run::read_lane(ledger.connection(), &lane_id).map_err(storage_error)?
            else {
                return Err(unknown_resource(url, "lane", id));
            };
            let object = lane_object_scope(&record)?;
            Ok(scope_shortfall(bound, &object).is_none())
        }
        ("run", _) => {
            let run_id: RunId = parse_resource_id(url, id)?;
            let Some(record) =
                lane_run::read_run(ledger.connection(), &run_id).map_err(storage_error)?
            else {
                return Err(unknown_resource(url, "run", id));
            };
            let object = run_object_scope(ledger, &record)?;
            Ok(scope_shortfall(bound, &object).is_none())
        }
        ("attempt", _) => {
            let attempt_id: AttemptId = parse_resource_id(url, id)?;
            let Some(record) =
                lane_run::read_attempt(ledger.connection(), &attempt_id).map_err(storage_error)?
            else {
                return Err(unknown_resource(url, "attempt", id));
            };
            let Some(run) =
                lane_run::read_run(ledger.connection(), &record.run_id).map_err(storage_error)?
            else {
                return Err(UriError::Storage {
                    detail: format!(
                        "attempt {} references missing run {}",
                        record.attempt_id, record.run_id
                    ),
                });
            };
            let mut object = run_object_scope(ledger, &run)?;
            object.attempt = Some(record.attempt_id.clone());
            Ok(scope_shortfall(bound, &object).is_none())
        }
        ("incident", _) => {
            let incident_id: IncidentId = parse_resource_id(url, id)?;
            let Some(card) = ledger.incident(&incident_id).map_err(storage_error)? else {
                return Err(unknown_resource(url, "incident", id));
            };
            let object = incident_object_scope(ledger, &card, bound)?;
            Ok(scope_shortfall(bound, &object).is_none())
        }
        ("approval", 1..=u8::MAX) => {
            let approval_id: ApprovalId = parse_resource_id(url, id)?;
            let Some(approval) = ledger.approval(&approval_id).map_err(storage_error)? else {
                return Err(unknown_resource(url, "approval", id));
            };
            proves_scope(
                ledger,
                url,
                bound,
                &approval.scope.target_kind,
                &approval.scope.target_id,
                depth - 1,
            )
        }
        ("artifact", 1..=u8::MAX) => {
            let artifact_id: ArtifactId = parse_resource_id(url, id)?;
            if ledger
                .artifact(&artifact_id)
                .map_err(storage_error)?
                .is_none()
            {
                return Err(unknown_resource(url, "artifact", id));
            }
            let references = ledger
                .artifact_references(&artifact_id)
                .map_err(storage_error)?;
            for reference in &references {
                if proves_scope(
                    ledger,
                    url,
                    bound,
                    &reference.object_kind,
                    &reference.object_id,
                    depth - 1,
                )? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        // Capability, command, and unknown target kinds prove nothing; only an unbound
        // operator scope may read them.
        _ => Ok(scope_shortfall(bound, &Scope::default()).is_none()),
    }
}

/// A lane's persisted authority chain. The ledger stores `session_ref` as text, so it must
/// pass the frozen domain validator before it can prove scope on any direct or indirect path.
fn lane_object_scope(record: &LaneRecord) -> Result<Scope, UriError> {
    let session = match record.session_ref.as_deref() {
        Some(value) => Some(SessionId::parse(value).map_err(|error| {
            storage_error(format!(
                "lane {} stores malformed session_ref {value:?}: {error}",
                record.lane_id
            ))
        })?),
        None => None,
    };
    Ok(Scope {
        seat: Some(record.seat_id.clone()),
        project: record.project_id.clone(),
        lane: Some(record.lane_id.clone()),
        run: record.current_run_id.clone(),
        session,
        ..Scope::default()
    })
}

/// The full ownership chain of a run: its lane's seat, project, lane, session, and the run itself.
fn run_object_scope(ledger: &Ledger, record: &RunRecord) -> Result<Scope, UriError> {
    let Some(lane) =
        lane_run::read_lane(ledger.connection(), &record.lane_id).map_err(storage_error)?
    else {
        return Err(UriError::Storage {
            detail: format!(
                "run {} references missing lane {}",
                record.run_id, record.lane_id
            ),
        });
    };
    let mut object = lane_object_scope(&lane)?;
    object.run = Some(record.run_id.clone());
    Ok(object)
}

/// The incident's anchor scope: its full run chain when linked, plus attempt evidence from the
/// card. An unlinked incident proves no dimension and is readable only from an unbound scope.
fn incident_object_scope(
    ledger: &Ledger,
    card: &IncidentCard,
    bound: &Scope,
) -> Result<Scope, UriError> {
    let mut object = match &card.run_id {
        Some(run_id) => {
            let Some(record) =
                lane_run::read_run(ledger.connection(), run_id).map_err(storage_error)?
            else {
                return Err(UriError::Storage {
                    detail: format!(
                        "incident {} references missing run {run_id}",
                        card.incident_id
                    ),
                });
            };
            run_object_scope(ledger, &record)?
        }
        None => Scope::default(),
    };
    if let Some(attempt) = &bound.attempt {
        if card
            .attempt_ids
            .iter()
            .any(|candidate| candidate == attempt)
        {
            object.attempt = Some(attempt.clone());
        }
    }
    Ok(object)
}

fn timestamp_value(encoded: LedgerResult<String>) -> Result<Value, UriError> {
    encoded
        .map(Value::String)
        .map_err(|error| storage_error(format!("ledger timestamp is not representable: {error}")))
}

fn optional_display<T: fmt::Display>(value: &Option<T>) -> Value {
    value
        .as_ref()
        .map_or(Value::Null, |inner| Value::String(inner.to_string()))
}

fn lane_json(record: &LaneRecord) -> Result<Value, UriError> {
    let created_at = timestamp_value(encode_utc(record.created_at))?;
    let updated_at = timestamp_value(encode_utc(record.updated_at))?;
    Ok(json!({
        "backend": record.backend,
        "createdAt": created_at,
        "createdBy": record.created_by,
        "currentRunId": optional_display(&record.current_run_id),
        "desiredRevision": record.desired_revision,
        "laneId": record.lane_id.to_string(),
        "projectId": optional_display(&record.project_id),
        "providerLeaseId": optional_display(&record.provider_lease_id),
        "retained": record.retained,
        "revision": record.revision,
        "seatId": record.seat_id.to_string(),
        "sessionRef": optional_display(&record.session_ref),
        "status": lane_status_str(record.status),
        "templateId": record.template_id,
        "updatedAt": updated_at,
    }))
}

fn run_json(record: &RunRecord) -> Result<Value, UriError> {
    let created_at = timestamp_value(encode_utc(record.created_at))?;
    let updated_at = timestamp_value(encode_utc(record.updated_at))?;
    let started_at = match record.started_at {
        Some(value) => timestamp_value(encode_utc(value))?,
        None => Value::Null,
    };
    let ended_at = match record.ended_at {
        Some(value) => timestamp_value(encode_utc(value))?,
        None => Value::Null,
    };
    let absolute_deadline = match record.absolute_deadline {
        Some(value) => timestamp_value(encode_utc(value))?,
        None => Value::Null,
    };
    Ok(json!({
        "absoluteDeadline": absolute_deadline,
        "acceptedCapabilityRevision": optional_display(&record.accepted_capability_revision),
        "attemptNumber": record.attempt_number,
        "createdAt": created_at,
        "endedAt": ended_at,
        "inputHash": record.input_hash,
        "laneId": record.lane_id.to_string(),
        "leaseId": optional_display(&record.lease_id),
        "retryBudget": record.retry_budget,
        "retriesUsed": record.retries_used,
        "revision": record.revision,
        "runId": record.run_id.to_string(),
        "startedAt": started_at,
        "status": run_status_str(record.status),
        "updatedAt": updated_at,
        "workflowId": optional_display(&record.workflow_id),
        "workflowVersion": optional_display(&record.workflow_version),
    }))
}

fn approval_json(approval: &Approval) -> Result<Value, UriError> {
    let requested_at = timestamp_value(encode_utc(approval.requested_at))?;
    let expires_at = timestamp_value(encode_utc(approval.expires_at))?;
    let decided_at = match approval.decided_at {
        Some(value) => timestamp_value(encode_utc(value))?,
        None => Value::Null,
    };
    Ok(json!({
        "approvalId": approval.approval_id.to_string(),
        "consumedByCommandId": optional_display(&approval.consumed_by_command_id),
        "decidedAt": decided_at,
        "decidedBy": optional_display(&approval.decided_by),
        "decisionEvidenceRef": optional_display(&approval.decision_evidence_ref),
        "expiresAt": expires_at,
        "issuer": approval.issuer,
        "requestedAt": requested_at,
        "revision": approval.revision,
        "scope": {
            "argumentsDigest": approval.scope.arguments_digest.to_string(),
            "capabilityId": approval.scope.capability_id.to_string(),
            "targetId": approval.scope.target_id,
            "targetKind": approval.scope.target_kind,
        },
        "status": approval_status_str(approval.status),
    }))
}

fn incident_json(card: &IncidentCard) -> Result<Value, UriError> {
    let first_observed_at = timestamp_value(encode_utc(card.first_observed_at))?;
    let last_observed_at = timestamp_value(encode_utc(card.last_observed_at))?;
    let last_useful_progress_at = match card.last_useful_progress_at {
        Some(value) => timestamp_value(encode_utc(value))?,
        None => Value::Null,
    };
    Ok(json!({
        "affectedObjects": card.affected_objects,
        "allowedCapabilities": card
            .allowed_capabilities
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>(),
        "attemptIds": card
            .attempt_ids
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>(),
        "confidenceMicros": card.confidence.get(),
        "deviation": card.deviation,
        "escalationTarget": card.escalation_target,
        "evidenceRefs": card.evidence_refs.as_slice(),
        "expectedState": card.expected_state.clone(),
        "failureSignature": card.failure_signature,
        "firstObservedAt": first_observed_at,
        "incidentId": card.incident_id.to_string(),
        "lastObservedAt": last_observed_at,
        "lastUsefulProgressAt": last_useful_progress_at,
        "observedState": card.observed_state.clone(),
        "recommendedNextAction": card.recommended_next_action,
        "revision": card.revision,
        "runId": optional_display(&card.run_id),
        "severity": incident_severity_str(card.severity),
        "status": incident_status_str(card.status),
    }))
}

const fn lane_status_str(status: LaneStatus) -> &'static str {
    match status {
        LaneStatus::Desired => "desired",
        LaneStatus::Provisioning => "provisioning",
        LaneStatus::Ready => "ready",
        LaneStatus::Running => "running",
        LaneStatus::WaitingApproval => "waitingApproval",
        LaneStatus::Paused => "paused",
        LaneStatus::Recovering => "recovering",
        LaneStatus::Succeeded => "succeeded",
        LaneStatus::Failed => "failed",
        LaneStatus::Blocked => "blocked",
        LaneStatus::Cancelled => "cancelled",
        LaneStatus::Retired => "retired",
    }
}

const fn run_status_str(status: RunStatus) -> &'static str {
    match status {
        RunStatus::Pending => "pending",
        RunStatus::Planning => "planning",
        RunStatus::Running => "running",
        RunStatus::WaitingApproval => "waitingApproval",
        RunStatus::Paused => "paused",
        RunStatus::Recovering => "recovering",
        RunStatus::Succeeded => "succeeded",
        RunStatus::Failed => "failed",
        RunStatus::Blocked => "blocked",
        RunStatus::Cancelled => "cancelled",
    }
}

const fn approval_status_str(status: ApprovalStatus) -> &'static str {
    match status {
        ApprovalStatus::Requested => "requested",
        ApprovalStatus::Approved => "approved",
        ApprovalStatus::Denied => "denied",
        ApprovalStatus::Expired => "expired",
        ApprovalStatus::Consumed => "consumed",
        ApprovalStatus::Cancelled => "cancelled",
    }
}

const fn incident_status_str(status: odin_ledger::incident::IncidentStatus) -> &'static str {
    match status {
        odin_ledger::incident::IncidentStatus::Open => "open",
        odin_ledger::incident::IncidentStatus::Recovering => "recovering",
        odin_ledger::incident::IncidentStatus::Escalated => "escalated",
        odin_ledger::incident::IncidentStatus::Resolved => "resolved",
        odin_ledger::incident::IncidentStatus::Blocked => "blocked",
    }
}

const fn incident_severity_str(severity: odin_ledger::incident::IncidentSeverity) -> &'static str {
    match severity {
        odin_ledger::incident::IncidentSeverity::Info => "info",
        odin_ledger::incident::IncidentSeverity::Warning => "warning",
        odin_ledger::incident::IncidentSeverity::Error => "error",
        odin_ledger::incident::IncidentSeverity::Critical => "critical",
    }
}
