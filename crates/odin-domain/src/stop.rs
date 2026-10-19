//! Shared stop verdicts keep the ledger, kernel, CLI, and wire format consistent.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Requested stops block the worker until settlement or recovery.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopState {
    Requested,
    /// No surviving unit, cgroup, or process was found.
    Stopped,
    /// A unit, cgroup, or process survived the stop.
    Failed,
}

impl StopState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "requested" => Some(Self::Requested),
            "stopped" => Some(Self::Stopped),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Requested)
    }
}

impl fmt::Display for StopState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Settled stop intents cannot transition again.
pub fn can_transition_stop(from: StopState, to: StopState) -> bool {
    matches!(
        (from, to),
        (StopState::Requested, StopState::Stopped) | (StopState::Requested, StopState::Failed)
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopVerdictTag {
    Requested,
    Stopped,
    Failed,
    /// Missing evidence requires a retry rather than a successful verdict.
    Indeterminate,
}

impl StopVerdictTag {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Indeterminate => "indeterminate",
        }
    }
}

impl fmt::Display for StopVerdictTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Process correlation identifies residue but does not authorize killing it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StopResidueProcess {
    pub pid: u32,
    pub start_time_ticks: u64,
}

/// Check the unit, cgroup, and processes independently so one clean result cannot hide residue.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct StopResidue {
    pub unit_active: bool,
    pub cgroup_present: bool,
    pub processes: Vec<StopResidueProcess>,
}

impl StopResidue {
    pub fn is_empty(&self) -> bool {
        !self.unit_active && !self.cgroup_present && self.processes.is_empty()
    }
}

/// Retain the missing-evidence reason so recovery can retry the stop.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StopMissing {
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopVerdict {
    Requested,
    Stopped,
    Failed(StopResidue),
    Indeterminate(StopMissing),
}

impl StopVerdict {
    /// Missing evidence takes precedence over residue; neither permits a successful stop.
    pub fn classify(
        stopped: bool,
        residue: Option<StopResidue>,
        missing: Option<StopMissing>,
    ) -> Self {
        if let Some(missing) = missing {
            return Self::Indeterminate(missing);
        }
        if let Some(residue) = residue {
            return Self::Failed(residue);
        }
        if stopped {
            return Self::Stopped;
        }
        Self::Requested
    }

    pub fn tag(&self) -> StopVerdictTag {
        match self {
            Self::Requested => StopVerdictTag::Requested,
            Self::Stopped => StopVerdictTag::Stopped,
            Self::Failed(_) => StopVerdictTag::Failed,
            Self::Indeterminate(_) => StopVerdictTag::Indeterminate,
        }
    }

    /// Indeterminate stops remain requested so recovery can retry them.
    pub fn settle_state(&self) -> Option<StopState> {
        match self {
            Self::Stopped => Some(StopState::Stopped),
            Self::Failed(_) => Some(StopState::Failed),
            Self::Requested | Self::Indeterminate(_) => None,
        }
    }
}

/// Reject inconsistent audit data rather than inventing missing evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopEvidenceError {
    VerdictPayloadMismatch,
}

impl fmt::Display for StopEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("stop audit verdict and payload disagree")
    }
}

impl std::error::Error for StopEvidenceError {}

pub const WORKER_STOP_EVIDENCE_SCHEMA: &str = "odin.worker-stop-evidence.v1";
pub const STOP_AUTHORITY_TRACE_SCHEMA: &str = "odin.stop-authority-trace.v1";

/// Injected faults are recorded separately and never determine the production verdict.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopFaultProbeKind {
    MissingWorkerIdentity,
    CorruptedResidueEvidence,
    CgroupQueryFailure,
    CgroupDescendantSurvivor,
    NetworkDependency,
    ModelDependency,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StopFaultProbe {
    pub probe: StopFaultProbeKind,
    pub detected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StopEvidence {
    pub schema: String,
    pub worker_id: String,
    pub unit: String,
    pub cgroup: String,
    pub leader_reaped: bool,
    pub cgroup_descendants: u64,
    pub evidence_complete: bool,
    pub fault_probes: Vec<StopFaultProbe>,
}

impl StopEvidence {
    pub fn new(
        worker_id: impl Into<String>,
        unit: impl Into<String>,
        cgroup: impl Into<String>,
    ) -> Self {
        Self {
            schema: WORKER_STOP_EVIDENCE_SCHEMA.to_owned(),
            worker_id: worker_id.into(),
            unit: unit.into(),
            cgroup: cgroup.into(),
            leader_reaped: false,
            cgroup_descendants: 0,
            evidence_complete: false,
            fault_probes: Vec::new(),
        }
    }
}

/// Network and model attempts record violations because stopping must work offline.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopTraceEvent {
    Resolve,
    Intent,
    Cooperative,
    Freeze,
    Term,
    CgroupKill,
    Reap,
    ResidueQuery,
    NetworkAttempt,
    ModelAttempt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StopTraceRow {
    pub schema: String,
    pub seq: u64,
    pub event: StopTraceEvent,
    pub worker_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StopAudit {
    pub verdict: StopVerdictTag,
    pub recovered: bool,
    pub term_sent: bool,
    pub cgroup_kill: bool,
    pub unit_identity_verified: bool,
    pub residue: Option<StopResidue>,
    pub missing: Option<StopMissing>,
    pub evidence: StopEvidence,
    pub trace: Vec<StopTraceRow>,
}

impl StopAudit {
    /// Reject mismatched tags and payloads rather than inventing missing residue or reasons.
    pub fn stop_verdict(&self) -> Result<StopVerdict, StopEvidenceError> {
        match (&self.verdict, &self.residue, &self.missing) {
            (StopVerdictTag::Requested, None, None) => Ok(StopVerdict::Requested),
            (StopVerdictTag::Stopped, None, None)
                if self.evidence.evidence_complete
                    && self.evidence.leader_reaped
                    && self.evidence.cgroup_descendants == 0 =>
            {
                Ok(StopVerdict::Stopped)
            }
            (StopVerdictTag::Failed, Some(residue), None) if !residue.is_empty() => {
                Ok(StopVerdict::Failed(residue.clone()))
            }
            (StopVerdictTag::Indeterminate, None, Some(missing))
                if !missing.reason.trim().is_empty() =>
            {
                Ok(StopVerdict::Indeterminate(missing.clone()))
            }
            _ => Err(StopEvidenceError::VerdictPayloadMismatch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn residue(unit_active: bool, cgroup_present: bool, processes: usize) -> StopResidue {
        StopResidue {
            unit_active,
            cgroup_present,
            processes: (0..processes)
                .map(|index| StopResidueProcess {
                    pid: u32::try_from(index + 1).expect("pid fits"),
                    start_time_ticks: 1_000,
                })
                .collect(),
        }
    }

    #[test]
    fn classification_law_prefers_missing_evidence() {
        let classified = StopVerdict::classify(
            true,
            Some(residue(true, false, 0)),
            Some(StopMissing {
                reason: "manager query failed".to_owned(),
            }),
        );
        assert_eq!(
            classified,
            StopVerdict::Indeterminate(StopMissing {
                reason: "manager query failed".to_owned()
            })
        );
    }

    #[test]
    fn classification_law_reports_proved_residue_over_clean_answers() {
        let classified = StopVerdict::classify(true, Some(residue(false, true, 2)), None);
        assert_eq!(classified, StopVerdict::Failed(residue(false, true, 2)));
    }

    #[test]
    fn classification_law_stops_only_on_proof() {
        assert_eq!(
            StopVerdict::classify(true, None, None),
            StopVerdict::Stopped
        );
        assert_eq!(
            StopVerdict::classify(false, None, None),
            StopVerdict::Requested
        );
    }

    #[test]
    fn only_stopped_and_failed_settle_durable_state() {
        assert_eq!(
            StopVerdict::Stopped.settle_state(),
            Some(StopState::Stopped)
        );
        assert_eq!(
            StopVerdict::Failed(residue(false, false, 0)).settle_state(),
            Some(StopState::Failed)
        );
        assert_eq!(StopVerdict::Requested.settle_state(), None);
        assert_eq!(
            StopVerdict::Indeterminate(StopMissing {
                reason: "unavailable".to_owned()
            })
            .settle_state(),
            None
        );
    }

    #[test]
    fn stop_state_law_moves_requested_once() {
        assert!(can_transition_stop(
            StopState::Requested,
            StopState::Stopped
        ));
        assert!(can_transition_stop(StopState::Requested, StopState::Failed));
        assert!(!can_transition_stop(StopState::Stopped, StopState::Failed));
        assert!(!can_transition_stop(StopState::Failed, StopState::Stopped));
        assert!(!can_transition_stop(
            StopState::Requested,
            StopState::Requested
        ));
    }

    #[test]
    fn evidence_round_trips_the_exact_external_schema() {
        let evidence = StopEvidence {
            schema: WORKER_STOP_EVIDENCE_SCHEMA.to_owned(),
            worker_id: "worker-0123456789abcdef".to_owned(),
            unit: "tx-wp-attempt-0-deadbeef.scope".to_owned(),
            cgroup: "/user.slice/tx-wp-attempt-0-deadbeef.scope".to_owned(),
            leader_reaped: true,
            cgroup_descendants: 0,
            evidence_complete: true,
            fault_probes: vec![StopFaultProbe {
                probe: StopFaultProbeKind::MissingWorkerIdentity,
                detected: true,
            }],
        };
        let serialized = serde_json::to_value(&evidence).expect("serialize");
        let object = serialized.as_object().expect("evidence object");
        let keys = object
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            keys,
            std::collections::BTreeSet::from([
                "schema",
                "worker_id",
                "unit",
                "cgroup",
                "leader_reaped",
                "cgroup_descendants",
                "evidence_complete",
                "fault_probes",
            ])
        );
        assert_eq!(
            serialized.get("schema"),
            Some(&serde_json::json!("odin.worker-stop-evidence.v1"))
        );
        let decoded: StopEvidence = serde_json::from_value(serialized).expect("deserialize");
        assert_eq!(decoded, evidence);
    }
}
