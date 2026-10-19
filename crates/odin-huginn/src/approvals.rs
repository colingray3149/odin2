use std::sync::Arc;

use odin_domain::huginn::{
    Freshness, FreshnessState, HuginnProtocolError, ObjectDelta, ObjectKind, ObjectRef,
    ObjectSnapshot, QueryScope, Revision, RevisionSource,
};
use odin_domain::{ApprovalId, ApprovalStatus, CapabilityId, CommandId, Digest};
use odin_ledger::approval::Approval;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::read_model::{MaterializedReadModel, ProjectionMetadata};

/// Approval decisions consumed by governed simulation commands.
pub trait ApprovalGate: Send + Sync {
    fn decision(&self, approval_id: &ApprovalId) -> Option<odin_domain::huginn::ApprovalDecision>;
}

pub trait ProjectionPort: Send + Sync {
    fn publish(
        &self,
        snapshot: ObjectSnapshot,
        metadata: ProjectionMetadata,
    ) -> Result<Option<ObjectDelta>, HuginnProtocolError>;
}

impl ProjectionPort for MaterializedReadModel {
    fn publish(
        &self,
        snapshot: ObjectSnapshot,
        metadata: ProjectionMetadata,
    ) -> Result<Option<ObjectDelta>, HuginnProtocolError> {
        self.upsert_indexed(snapshot, metadata).map_err(Into::into)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalView {
    pub approval_id: ApprovalId,
    pub status: ApprovalStatus,
    pub issuer: String,
    pub target_kind: String,
    pub target_id: String,
    pub capability_id: CapabilityId,
    pub arguments_digest: Digest,
    pub requested_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub decided_at: Option<OffsetDateTime>,
    pub decided_by: Option<String>,
    pub consumed_by_command_id: Option<CommandId>,
    pub decision_evidence_ref: Option<String>,
    pub revision: u64,
}

impl TryFrom<&Approval> for ApprovalView {
    type Error = HuginnProtocolError;

    fn try_from(approval: &Approval) -> Result<Self, Self::Error> {
        Ok(Self {
            approval_id: approval.approval_id.clone(),
            status: approval.status,
            issuer: approval.issuer.clone(),
            target_kind: approval.scope.target_kind.clone(),
            target_id: approval.scope.target_id.clone(),
            capability_id: approval.scope.capability_id.clone(),
            arguments_digest: approval.scope.arguments_digest,
            requested_at: approval.requested_at,
            expires_at: approval.expires_at,
            decided_at: approval.decided_at,
            decided_by: approval.decided_by.clone(),
            consumed_by_command_id: approval.consumed_by_command_id.clone(),
            decision_evidence_ref: approval.decision_evidence_ref.clone(),
            revision: u64::try_from(approval.revision)
                .map_err(|_| invalid_projection("approval revision does not fit the read model"))?,
        })
    }
}

#[derive(Clone)]
pub struct ApprovalProjection<P: ProjectionPort> {
    port: Arc<P>,
}

impl<P: ProjectionPort> ApprovalProjection<P> {
    pub fn new(port: Arc<P>) -> Self {
        Self { port }
    }

    pub fn publish(
        &self,
        view: ApprovalView,
        scopes: impl IntoIterator<Item = QueryScope>,
        evidence: impl IntoIterator<Item = ObjectRef>,
    ) -> Result<Option<ObjectDelta>, HuginnProtocolError> {
        if view.revision == 0 {
            return Err(invalid_projection("approval revision must start at one"));
        }
        if view.expires_at <= view.requested_at {
            return Err(invalid_projection(
                "approval expiry must follow its request",
            ));
        }
        let observed_at = view.decided_at.unwrap_or(view.requested_at);
        let title = format!("Approval {}", view.approval_id);
        let summary = format!(
            "{} on {} {}",
            view.capability_id, view.target_kind, view.target_id
        );
        let object = ObjectRef {
            kind: ObjectKind::Approval,
            id: view.approval_id.to_string(),
        };
        let value = serde_json::to_value(&view).map_err(serialization_error)?;
        let content_digest = digest_value(&value)?;
        let snapshot = ObjectSnapshot {
            object,
            revision: Revision::new(view.revision),
            revision_source: RevisionSource::Ledger,
            freshness: Freshness {
                state: FreshnessState::Fresh,
                observed_at,
                source_updated_at: Some(observed_at),
                stale_after_seconds: None,
            },
            content_digest,
            value,
        };
        let mut metadata = ProjectionMetadata::new(title, summary);
        for scope in scopes {
            metadata = metadata.in_scope(scope);
        }
        for link in evidence {
            metadata = metadata.with_evidence(link);
        }
        self.port.publish(snapshot, metadata)
    }
}

pub(crate) fn digest_value(value: &serde_json::Value) -> Result<Digest, HuginnProtocolError> {
    serde_json::to_vec(value)
        .map(|bytes| Digest::hash(&bytes))
        .map_err(serialization_error)
}

pub(crate) fn serialization_error(error: serde_json::Error) -> HuginnProtocolError {
    HuginnProtocolError::InvalidRequest {
        code: "projection".to_owned(),
        message: format!("projection serialization failed: {error}"),
    }
}

pub(crate) fn invalid_projection(message: impl Into<String>) -> HuginnProtocolError {
    HuginnProtocolError::InvalidRequest {
        code: "projection".to_owned(),
        message: message.into(),
    }
}
