//! Dispatch wire requests through the kernel and map its responses to protocol types.

use odin_domain::operation::{EffectState, RequestCost};
use odin_domain::CapabilityId;
use odin_kernel::{
    AuthorizationRejection, CloseMode, ExecutorFault, InvokeRequest, OperationRejection, PreWorld,
};
use odin_sidecar_protocol::{
    CloseMode as WireCloseMode, Detail, Evidence, OperationState, RejectionCode, Request, Response,
    StopState, U64Wire, Version,
};
use odin_types::PredecessorHash;
use sha2::{Digest as _, Sha256};

use super::store::MAX_DETAIL_CHARS;
use super::Sidecar;
use crate::SidecarError;

impl Sidecar {
    pub fn transport(&self, request: Request) -> Result<Response, TransportRejection> {
        let now = self.now();
        match request {
            Request::InvokeCapability {
                wire: _,
                capsule_id,
                correlation_id,
                capability,
                budget,
                arguments,
            } => {
                let fresh = self.fresh_authority(now)?;
                let capability_id = CapabilityId::parse(capability.as_str()).map_err(|_| {
                    TransportRejection::new(
                        "authority.unknown_capability",
                        format!("capability {:?} is not admitted", capability.as_str()),
                    )
                })?;
                // The caller's budget can narrow the reservation but cannot increase it or set charged cost.
                let requested_ceiling = RequestCost {
                    requests: budget.requests.get(),
                    stops: budget.stops.get(),
                    spend: budget.spend.get(),
                };
                let authorized = self.authorized_invocation(
                    fresh.get(),
                    &capability_id,
                    &capsule_id,
                    &correlation_id,
                    arguments.as_value(),
                    now,
                )?;
                let invoke = InvokeRequest {
                    capsule_id,
                    correlation_id,
                    requested_ceiling,
                };
                let decision = self.authority.invoke_authorized(authorized, &invoke)?;
                Ok(Response::CapabilityInvoked {
                    wire: Version,
                    capsule_id: decision.capsule_id,
                    correlation_id: decision.correlation_id,
                    operation_id: decision.operation_id,
                    state: wire_state(decision.state),
                    replay: decision.replay,
                })
            }
            Request::ResumeOperation {
                wire: _,
                capsule_id,
                correlation_id,
                operation_id,
            } => {
                let fresh = self.fresh_authority(now)?;
                let decision =
                    self.authority
                        .resume(fresh, &capsule_id, &correlation_id, &operation_id)?;
                Ok(Response::OperationResumed {
                    wire: Version,
                    capsule_id,
                    correlation_id,
                    operation_id: decision.operation_id,
                    state: wire_state(decision.state),
                    replay: decision.replay,
                })
            }
            Request::ReconcileOperation {
                wire: _,
                capsule_id,
                correlation_id,
                operation_id,
            } => {
                let fresh = self.fresh_authority(now)?;
                let outcome =
                    self.authority
                        .reconcile(fresh, &capsule_id, &correlation_id, &operation_id)?;
                Ok(Response::OperationReconciled {
                    wire: Version,
                    capsule_id,
                    correlation_id,
                    operation_id: outcome.decision.operation_id,
                    state: wire_state(outcome.decision.state),
                    replay: outcome.decision.replay,
                    evidence: evidence_of(outcome.observed),
                })
            }
            Request::CloseCapsule {
                wire: _,
                capsule_id,
                correlation_id,
                mode,
            } => {
                let fresh = self.fresh_authority(now)?;
                let close_mode = match mode {
                    WireCloseMode::Drain => CloseMode::Drain,
                    WireCloseMode::Abort => CloseMode::Abort,
                };
                let outcome = self.authority.close_capsule(
                    fresh,
                    &capsule_id,
                    &correlation_id,
                    close_mode,
                )?;
                Ok(Response::CapsuleClosed {
                    wire: Version,
                    capsule_id,
                    correlation_id,
                    drained: U64Wire::new(outcome.drained),
                })
            }
            Request::StopIntent {
                wire: _,
                capsule_id,
                correlation_id,
                operation_id,
            } => {
                // A stop must identify the persisted operation row.
                let Some(operation_id) = operation_id else {
                    return Err(TransportRejection {
                        code: "authority.operation_mismatch",
                        detail: "stop intent requires the durable operation id".to_owned(),
                    });
                };
                let fresh = self.fresh_authority(now)?;
                let outcome = self.authority.stop_intent(
                    fresh,
                    &capsule_id,
                    &correlation_id,
                    Some(operation_id),
                )?;
                let state = match outcome.state.as_str() {
                    "stopped" => StopState::Stopped,
                    "failed" => StopState::Failed,
                    _ => StopState::Requested,
                };
                let evidence = match outcome.process {
                    Some(process) => Evidence::Process {
                        pid: process.pid,
                        start_time_ticks: U64Wire::new(process.start_time_ticks),
                        process_group: process.process_group,
                    },
                    None => Evidence::Absent,
                };
                Ok(Response::StopRecorded {
                    wire: Version,
                    capsule_id,
                    correlation_id,
                    operation_id: outcome.operation_id,
                    state,
                    evidence,
                })
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportRejection {
    pub code: &'static str,
    pub detail: String,
}

impl TransportRejection {
    pub(super) fn new(code: &'static str, detail: impl Into<String>) -> Self {
        let mut detail = detail.into();
        if detail.chars().count() > MAX_DETAIL_CHARS {
            detail = detail.chars().take(MAX_DETAIL_CHARS).collect();
        }
        Self { code, detail }
    }
}

impl From<OperationRejection> for TransportRejection {
    fn from(rejection: OperationRejection) -> Self {
        Self::new(rejection_code(&rejection), rejection.to_string())
    }
}

impl From<SidecarError> for TransportRejection {
    fn from(error: SidecarError) -> Self {
        Self::new(error.code_str(), error.detail().to_owned())
    }
}

fn evidence_of(observed: PreWorld) -> Evidence {
    match observed {
        PreWorld::Absent => Evidence::Absent,
        PreWorld::Digest(digest) => {
            let hex = digest.to_string();
            let hex = hex.trim_start_matches("blake3:");
            let digest = PredecessorHash::new(hex).unwrap_or_else(|_| {
                PredecessorHash::new(&odin_types::hash::hex_encode(&Sha256::digest(
                    hex.as_bytes(),
                )))
                .expect("sha256 hex is a valid predecessor hash")
            });
            Evidence::Durable { digest }
        }
    }
}

fn wire_state(state: EffectState) -> OperationState {
    match state {
        EffectState::Prepared => OperationState::Prepared,
        EffectState::EffectStarted => OperationState::EffectStarted,
        EffectState::Committed => OperationState::Committed,
        EffectState::Aborted => OperationState::Aborted,
        EffectState::InDoubt => OperationState::InDoubt,
    }
}

pub fn authorization_code(reason: &AuthorizationRejection) -> &'static str {
    match reason {
        AuthorizationRejection::NeedsPlan { .. } => "authority.plan_required",
        AuthorizationRejection::NeedsApproval { .. } => "authority.approval_required",
        AuthorizationRejection::WrongSeat { .. } => "authority.wrong_seat",
        AuthorizationRejection::UnknownCapability { .. } => "authority.unknown_capability",
        AuthorizationRejection::Unavailable { .. } => "authority.not_admitted",
        AuthorizationRejection::VersionMismatch { .. } => "authority.version_mismatch",
        AuthorizationRejection::StaleListing => "authority.stale_listing",
        AuthorizationRejection::ArgumentDigestMismatch => "authority.argument_digest",
        AuthorizationRejection::StaleRevision { .. } => "authority.stale_revision",
        AuthorizationRejection::ResourceDenied { .. } => "authority.resource_denied",
        AuthorizationRejection::ForgedIdentity => "authority.unauthorized",
    }
}

pub fn rejection_code(rejection: &OperationRejection) -> &'static str {
    match rejection {
        OperationRejection::Unauthorized => "authority.unauthorized",
        OperationRejection::IdentityExpired { .. } => "authority.identity_expired",
        OperationRejection::AuthorityMismatch { .. } => "authority.authority_mismatch",
        OperationRejection::UnknownCapability { .. } => "authority.unknown_capability",
        OperationRejection::NotAdmitted { .. } => "authority.not_admitted",
        OperationRejection::BudgetDenied { .. } => "authority.budget_denied",
        OperationRejection::DuplicateConflict { .. } => "authority.duplicate_conflict",
        OperationRejection::UnknownOperation { .. } => "authority.unknown_operation",
        OperationRejection::OperationMismatch { .. } => "authority.operation_mismatch",
        OperationRejection::CapsuleAuthorityMismatch { .. } => {
            "authority.capsule_authority_mismatch"
        }
        OperationRejection::CapsuleClosed { .. } => "authority.capsule_closed",
        OperationRejection::CapsuleBlocked { .. } => "authority.capsule_blocked",
        OperationRejection::PreWorldMismatch { .. } => "authority.pre_world_mismatch",
        OperationRejection::PayloadDigestMismatch => "authority.payload_digest_mismatch",
        OperationRejection::SchemaInvalid { .. } => "authority.schema_invalid",
        OperationRejection::Durable(_) => "authority.durable",
        OperationRejection::Executor(ExecutorFault::Rejected { .. }) => "executor.rejected",
        OperationRejection::Executor(
            ExecutorFault::Uncertain { .. } | ExecutorFault::PostEffectUncertain { .. },
        ) => "executor.uncertain",
    }
}

pub fn rejection_response(code: &str, detail: &str) -> Response {
    let code = RejectionCode::new(code)
        .unwrap_or_else(|_| RejectionCode::new("sidecar.protocol").expect("fixed code is valid"));
    let mut bounded = detail.to_owned();
    if bounded.chars().count() > MAX_DETAIL_CHARS {
        bounded = bounded.chars().take(MAX_DETAIL_CHARS).collect();
    }
    let detail = Detail::new(&bounded).unwrap_or_else(|_| {
        Detail::new("rejection detail is unavailable").expect("fixed detail is valid")
    });
    Response::Rejected {
        wire: Version,
        code,
        detail,
    }
}
