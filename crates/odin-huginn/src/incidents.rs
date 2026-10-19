use std::sync::Arc;

use odin_domain::huginn::{
    Freshness, FreshnessState, HuginnProtocolError, ObjectDelta, ObjectKind, ObjectRef,
    ObjectSnapshot, QueryScope, Revision, RevisionSource,
};
use odin_domain::{AttemptId, CapabilityId, IncidentId, RunId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::approvals::{digest_value, invalid_projection, serialization_error, ProjectionPort};
use crate::read_model::ProjectionMetadata;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum IncidentSeverityView {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum IncidentStatusView {
    Open,
    Recovering,
    Escalated,
    Resolved,
    Blocked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IncidentView {
    pub incident_id: IncidentId,
    pub run_id: Option<RunId>,
    pub severity: IncidentSeverityView,
    pub confidence_micros: i64,
    pub deviation: String,
    pub failure_signature: String,
    pub expected_state: Value,
    pub observed_state: Value,
    pub affected_objects: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub allowed_capabilities: Vec<CapabilityId>,
    pub attempt_ids: Vec<AttemptId>,
    pub recommended_next_action: String,
    pub escalation_target: String,
    pub first_observed_at: OffsetDateTime,
    pub last_observed_at: OffsetDateTime,
    pub last_useful_progress_at: Option<OffsetDateTime>,
    pub status: IncidentStatusView,
    pub revision: u64,
}

#[derive(Clone)]
pub struct IncidentProjection<P: ProjectionPort> {
    port: Arc<P>,
}

impl<P: ProjectionPort> IncidentProjection<P> {
    pub fn new(port: Arc<P>) -> Self {
        Self { port }
    }

    pub fn publish(
        &self,
        view: IncidentView,
        scopes: impl IntoIterator<Item = QueryScope>,
        evidence: impl IntoIterator<Item = ObjectRef>,
    ) -> Result<Option<ObjectDelta>, HuginnProtocolError> {
        if view.revision == 0 {
            return Err(invalid_projection("incident revision must start at one"));
        }
        if !(0..=1_000_000).contains(&view.confidence_micros) {
            return Err(invalid_projection(
                "incident confidence is outside 0..=1000000",
            ));
        }
        if view.evidence_refs.len() > 5 {
            return Err(invalid_projection(
                "incident carries more than five evidence refs",
            ));
        }
        if view.failure_signature.trim().is_empty() || view.deviation.trim().is_empty() {
            return Err(invalid_projection(
                "incident signature and deviation must be non-empty",
            ));
        }
        if view.last_observed_at < view.first_observed_at {
            return Err(invalid_projection(
                "incident observation times are reversed",
            ));
        }
        let title = format!("Incident {}", view.incident_id);
        let summary = format!("{:?}: {}", view.severity, view.deviation);
        let object = ObjectRef {
            kind: ObjectKind::Status,
            id: view.incident_id.to_string(),
        };
        let value = serde_json::to_value(&view).map_err(serialization_error)?;
        let snapshot = ObjectSnapshot {
            object,
            revision: Revision::new(view.revision),
            revision_source: RevisionSource::Ledger,
            freshness: Freshness {
                state: FreshnessState::Fresh,
                observed_at: view.last_observed_at,
                source_updated_at: Some(view.last_observed_at),
                stale_after_seconds: None,
            },
            content_digest: digest_value(&value)?,
            value,
        };
        let mut metadata = ProjectionMetadata::new(title, summary);
        if let Some(run_id) = &view.run_id {
            metadata = metadata.in_scope(QueryScope::Run(run_id.clone()));
        }
        for scope in scopes {
            metadata = metadata.in_scope(scope);
        }
        for link in evidence {
            metadata = metadata.with_evidence(link);
        }
        self.port.publish(snapshot, metadata)
    }
}

#[cfg(test)]
mod incident_status_tests {
    use odin_domain::huginn::{urgent_object, ObjectKind};

    /// The shared urgency predicate, pinned from the dispatch consumer
    /// side: the incident identities and nothing else. `incident:<ms>:<uuid>`
    /// (the `IncidentId::from_parts("incident", …)` mints in odind's
    /// incidents, pumps and vehicle-open paths), `incident:stall:<digest>`
    /// (workload recovery) and `incident.recovery.<hex>` (the OMP recovery
    /// driver) are urgent; roster (`roster`) and the model-gateway spend
    /// (`spend`) are also `Status` objects and coalesce.
    #[test]
    fn incident_id_grammars_are_urgent_and_other_status_ids_coalesce() {
        let urgent = [
            "incident:1730000000000:5c0e3c1e-8e14-4a5e-9d0a-2f6d1c3b7a90",
            "incident:stall:blake3:0123abcd",
            "incident.recovery.9f2c88aa11bbccdd",
        ];
        for id in urgent {
            assert!(urgent_object(ObjectKind::Status, id), "{id} must be urgent");
        }
        for id in ["roster", "spend", "incidentx", "incid:one", "Incident:one"] {
            assert!(!urgent_object(ObjectKind::Status, id), "{id} must coalesce");
        }
        assert!(urgent_object(ObjectKind::Session, "session-1"));
        assert!(urgent_object(ObjectKind::Approval, "approval-1"));
        assert!(!urgent_object(ObjectKind::KubeResource, "kube-1"));
    }
}
