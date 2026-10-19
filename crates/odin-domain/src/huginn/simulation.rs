//! Simulation mission, telemetry, render, checkpoint, Judge, and evidence contracts.

use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{ApprovalId, CheckpointId, CommandId, Digest, EventId, NodeId, RunId};

use super::{
    artifact::ArtifactRef,
    ids::{RenderId, RendererId, Sequence, SimulationOutputId, StreamId},
    kube::KubeResourceRef,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SimulationMissionStage {
    Declared,
    Preparing,
    Queued,
    Running,
    Paused,
    Checkpointing,
    Succeeded,
    Failed,
    Aborted,
}

/// Revisioned mission control state. Telemetry and rendered frames are subordinate observations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationMissionView {
    pub run_id: RunId,
    pub revision: u64,
    pub label: String,
    pub stage: SimulationMissionStage,
    pub case: ArtifactRef,
    pub geometry: Option<ArtifactRef>,
    pub node_id: Option<NodeId>,
    pub workload: Option<KubeResourceRef>,
    pub telemetry_stream_id: StreamId,
    pub frame_stream_id: StreamId,
    pub current_checkpoint_id: Option<CheckpointId>,
    pub supported_renderers: Vec<RendererId>,
    /// Mission evidence obligations are a typed, content-addressed document.
    pub evidence_obligations: ArtifactRef,
    pub started_at: Option<OffsetDateTime>,
    pub finished_at: Option<OffsetDateTime>,
    pub updated_at: OffsetDateTime,
    pub stale: bool,
    pub failure: Option<String>,
}

/// A telemetry batch. Numerical series and fields stay in the referenced artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationTelemetryView {
    pub run_id: RunId,
    pub output_id: SimulationOutputId,
    pub sequence: Sequence,
    pub control_revision: u64,
    pub recorded_at: OffsetDateTime,
    pub sample_count: u64,
    pub content: ArtifactRef,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SimulationRenderStatus {
    Requested,
    Running,
    Complete,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationRenderView {
    pub render_id: RenderId,
    pub run_id: RunId,
    pub revision: u64,
    pub renderer_id: RendererId,
    pub renderer_version: String,
    pub parameters_digest: Digest,
    pub input_digest: Digest,
    pub status: SimulationRenderStatus,
    pub progress_basis_points: u16,
    pub requested_at: OffsetDateTime,
    pub finished_at: Option<OffsetDateTime>,
    pub output: Option<ArtifactRef>,
    pub failure_evidence: Option<ArtifactRef>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationCheckpointView {
    pub checkpoint_id: CheckpointId,
    pub run_id: RunId,
    pub revision: u64,
    pub parent_checkpoint_id: Option<CheckpointId>,
    pub label: String,
    pub created_at: OffsetDateTime,
    pub state: ArtifactRef,
    pub state_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SimulationEvidenceKind {
    Configuration,
    Field,
    Telemetry,
    Checkpoint,
    Anchor,
    Sensitivity,
    Resolution,
    Mutation,
    ShadowCalculation,
    InterventionHistory,
    Report,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationEvidenceRef {
    pub kind: SimulationEvidenceKind,
    pub label: String,
    pub content: ArtifactRef,
    pub collected_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationEvidenceView {
    pub run_id: RunId,
    pub revision: u64,
    pub evidence: SimulationEvidenceRef,
    pub scope: String,
    pub source_event_id: Option<EventId>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum JudgeVerdict {
    Pending,
    Supported,
    Unsupported,
    Inconclusive,
    Invalid,
}

/// Judge state references typed evidence and an independent report, never builder narrative.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JudgeClaimView {
    pub claim_event_id: EventId,
    pub run_id: RunId,
    pub revision: u64,
    pub claim: String,
    pub declared_scope: String,
    pub verdict: JudgeVerdict,
    pub support_micros: Option<u32>,
    pub evidence: Vec<SimulationEvidenceRef>,
    pub report: Option<ArtifactRef>,
    pub evaluated_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationCommandContext {
    pub command_id: CommandId,
    pub run_id: RunId,
    pub expected_revision: u64,
    pub arguments_digest: Digest,
    pub approval_id: Option<ApprovalId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SimulationIntervention {
    SetTimeStep { step_micros: NonZeroU64 },
    LocalRecompute { region: ArtifactRef },
    ChangeMesh { mesh: ArtifactRef },
    ChangeDomain { domain: ArtifactRef },
    SwitchBackend { backend: String },
    RequestLowerOrderEvidence { reason: String },
    AbstainAndEscalate { reason: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SimulationCommand {
    Start {
        context: SimulationCommandContext,
    },
    Pause {
        context: SimulationCommandContext,
    },
    Resume {
        context: SimulationCommandContext,
    },
    Abort {
        context: SimulationCommandContext,
        reason: String,
    },
    CreateCheckpoint {
        context: SimulationCommandContext,
        checkpoint_id: CheckpointId,
        label: String,
    },
    RestoreCheckpoint {
        context: SimulationCommandContext,
        checkpoint_id: CheckpointId,
    },
    RequestRender {
        context: SimulationCommandContext,
        render_id: RenderId,
        renderer_id: RendererId,
        renderer_version: String,
        parameters: ArtifactRef,
    },
    Intervene {
        context: SimulationCommandContext,
        intervention: SimulationIntervention,
    },
    RequestJudge {
        context: SimulationCommandContext,
        claim_event_id: EventId,
        claim: String,
        declared_scope: String,
        evidence: Vec<SimulationEvidenceRef>,
    },
}

impl SimulationCommand {
    pub const fn context(&self) -> &SimulationCommandContext {
        match self {
            Self::Start { context }
            | Self::Pause { context }
            | Self::Resume { context }
            | Self::Abort { context, .. }
            | Self::CreateCheckpoint { context, .. }
            | Self::RestoreCheckpoint { context, .. }
            | Self::RequestRender { context, .. }
            | Self::Intervene { context, .. }
            | Self::RequestJudge { context, .. } => context,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SimulationView {
    Mission(Box<SimulationMissionView>),
    Telemetry(SimulationTelemetryView),
    Render(SimulationRenderView),
    Checkpoint(SimulationCheckpointView),
    Evidence(SimulationEvidenceView),
    JudgeClaim(JudgeClaimView),
}
