//! Revision-checked simulation controls with approval-gated interventions and live links.

use std::collections::BTreeMap;
use std::mem;
use std::num::{NonZeroU64, NonZeroUsize};

use odin_domain::huginn::{
    ApprovalDecision, ArtifactRef, CommandOutcome, CommandReceipt, CommandStatus,
    HuginnProtocolError, JudgeClaimView, JudgeVerdict, ObjectDelta, SimulationCheckpointView,
    SimulationCommand, SimulationIntervention, SimulationMissionStage, SimulationRenderView,
    StreamBackpressureLimits, StreamId,
};
use odin_domain::{ApprovalId, ArtifactId, CommandId, EventId, RunId};
use time::OffsetDateTime;

use crate::approvals::ApprovalGate;
use crate::control_core::{execute_command, ControlJournal, DomainControl};
use crate::kube::control::epoch_millis;
use crate::kube::SurfaceArtifacts;

use super::render::SimulationRenderBoard;
use super::telemetry::TelemetryRing;
use super::view::{checkpoint_delta, judge_delta, mission_delta, SimulationBoard};

pub type Result<T, E = HuginnProtocolError> = std::result::Result<T, E>;

fn verify_artifact(store: &SurfaceArtifacts, expected: &ArtifactRef) -> Result<()> {
    let reference = store.reference(&expected.artifact_id).ok_or_else(|| {
        HuginnProtocolError::InvalidRequest {
            code: "simulationArtifact".to_string(),
            message: format!("artifact {} is not stored", expected.artifact_id),
        }
    })?;
    if reference.content_digest != expected.content_digest || !store.verify(&expected.artifact_id) {
        return Err(HuginnProtocolError::InvalidRequest {
            code: "simulationArtifactDigest".to_string(),
            message: format!(
                "artifact {} does not match its published digest",
                expected.artifact_id
            ),
        });
    }
    Ok(())
}

/// One simulation execution: the command plus the per-call approval gate and evidence
/// reference that ride alongside it.
pub(crate) struct SimulationCall<'a> {
    command: &'a SimulationCommand,
    gate: &'a dyn ApprovalGate,
    checkpoint_state: Option<&'a ArtifactRef>,
}

/// Durable simulation command surface. Duplicate command IDs replay the prior outcome; stale
/// revisions, undeclared renderers, unverified evidence artifacts, and unapproved interventions
/// are rejected before any mutation.
pub struct SimulationControl {
    board: SimulationBoard,
    renders: SimulationRenderBoard,
    telemetry: BTreeMap<RunId, TelemetryRing>,
    journal: ControlJournal,
    deltas: Vec<ObjectDelta>,
    frame_counter: u64,
}

impl SimulationControl {
    pub fn new(board: SimulationBoard, renders: SimulationRenderBoard) -> Self {
        Self {
            board,
            renders,
            telemetry: BTreeMap::new(),
            journal: ControlJournal::new(),
            deltas: Vec::new(),
            frame_counter: 0,
        }
    }

    pub fn board(&self) -> &SimulationBoard {
        &self.board
    }

    pub fn board_mut(&mut self) -> &mut SimulationBoard {
        &mut self.board
    }

    pub fn renders(&self) -> &SimulationRenderBoard {
        &self.renders
    }

    pub fn renders_mut(&mut self) -> &mut SimulationRenderBoard {
        &mut self.renders
    }

    /// Returns (creating if absent) the durable telemetry ring for one run.
    pub fn telemetry_ring_mut(
        &mut self,
        run_id: &RunId,
        stream_id: StreamId,
        max_batches: NonZeroUsize,
        max_bytes: NonZeroU64,
        limits: StreamBackpressureLimits,
    ) -> &mut TelemetryRing {
        self.telemetry.entry(run_id.clone()).or_insert_with(|| {
            TelemetryRing::new(run_id.clone(), stream_id, max_batches, max_bytes, limits)
        })
    }

    pub fn telemetry_ring(&self, run_id: &RunId) -> Option<&TelemetryRing> {
        self.telemetry.get(run_id)
    }

    pub fn outcome(&self, command_id: &CommandId) -> Option<&CommandOutcome> {
        self.journal.outcome(command_id)
    }

    pub fn drain_statuses(&mut self) -> Vec<CommandStatus> {
        self.journal.drain_statuses()
    }

    pub fn drain_deltas(&mut self) -> Vec<ObjectDelta> {
        mem::take(&mut self.deltas)
    }

    fn check_intervention_approval(
        &self,
        approval_id: Option<&ApprovalId>,
        gate: &dyn ApprovalGate,
    ) -> Result<()> {
        let approval_id = approval_id.ok_or_else(|| HuginnProtocolError::Conflict {
            code: "approvalRequired".to_string(),
            message: "simulation interventions are consequential and require an approval"
                .to_string(),
        })?;
        match gate.decision(approval_id) {
            Some(ApprovalDecision::Approve) => Ok(()),
            Some(ApprovalDecision::Reject) => Err(HuginnProtocolError::Conflict {
                code: "approvalRejected".to_string(),
                message: format!("approval {approval_id} was rejected"),
            }),
            None => Err(HuginnProtocolError::Conflict {
                code: "approvalPending".to_string(),
                message: format!("approval {approval_id} is not decided"),
            }),
        }
    }

    pub fn execute(
        &mut self,
        command: &SimulationCommand,
        gate: &dyn ApprovalGate,
        checkpoint_state: Option<&ArtifactRef>,
        at: OffsetDateTime,
    ) -> Result<CommandReceipt> {
        execute_command(
            self,
            &SimulationCall {
                command,
                gate,
                checkpoint_state,
            },
            at,
        )
    }

    /// Applies an independent Judge outcome and links the report live.
    pub fn apply_judge_verdict(
        &mut self,
        claim_event_id: &EventId,
        verdict: JudgeVerdict,
        support_micros: Option<u32>,
        report: Option<ArtifactRef>,
        at: OffsetDateTime,
    ) -> Result<(u64, u64)> {
        let (from, to) =
            self.board
                .evaluate_judge(claim_event_id, verdict, support_micros, report, at)?;
        let claim = self
            .board
            .judge_claim(claim_event_id)
            .cloned()
            .expect("claim presence checked above");
        self.deltas.push(judge_delta(&claim, from));
        Ok((from, to))
    }

    /// Builds the next compact model-stream frame for a run's telemetry. The raw batch never
    /// leaves the durable ring; only the compact summary document is streamed to models.
    pub fn next_model_frame(
        &mut self,
        run_id: &RunId,
        stream_id: StreamId,
        at: OffsetDateTime,
    ) -> Result<Option<odin_domain::huginn::StreamFrame>> {
        let batch = match self
            .telemetry
            .get_mut(run_id)
            .and_then(|ring| ring.take(at))
        {
            Some(batch) => batch,
            None => return Ok(None),
        };
        let compact = super::telemetry::CompactTelemetry::of(&batch);
        let frame_artifact_id = ArtifactId::from_parts(
            "simulation-telemetry-compact",
            epoch_millis(at),
            format!("{}-{}", batch.output_id, self.frame_counter),
        )
        .map_err(|error| HuginnProtocolError::InvalidRequest {
            code: "simulationTelemetryIdentity".to_string(),
            message: error.to_string(),
        })?;
        self.frame_counter += 1;
        let frame =
            compact.model_frame(self.board.artifacts_mut(), frame_artifact_id, stream_id, at)?;
        Ok(Some(frame))
    }
}

impl DomainControl for SimulationControl {
    type Command<'a> = SimulationCall<'a>;

    fn command_id(command: &SimulationCall<'_>) -> CommandId {
        command.command.context().command_id.clone()
    }

    fn journal(&mut self) -> &mut ControlJournal {
        &mut self.journal
    }

    fn run(
        &mut self,
        call: &SimulationCall<'_>,
        at: OffsetDateTime,
    ) -> Result<(), HuginnProtocolError> {
        let command = call.command;
        let gate = call.gate;
        let checkpoint_state = call.checkpoint_state;
        let context = command.context();
        let run_id = context.run_id.clone();

        let mission_before = self.board.mission(&run_id).cloned();
        let mission_before = match mission_before {
            Some(mission) => mission,
            None => {
                return Err(HuginnProtocolError::NotFound {
                    object_kind: "simulationMission".to_string(),
                    object_id: run_id.to_string(),
                });
            }
        };
        if mission_before.revision != context.expected_revision {
            return Err(HuginnProtocolError::RevisionMismatch {
                expected: odin_domain::huginn::Revision::new(context.expected_revision),
                actual: odin_domain::huginn::Revision::new(mission_before.revision),
            });
        }

        if matches!(command, SimulationCommand::Intervene { .. }) {
            self.check_intervention_approval(context.approval_id.as_ref(), gate)?;
        }
        let mut checkpoint_delta_view: Option<SimulationCheckpointView> = None;
        match command {
            SimulationCommand::Start { .. } => {
                self.board
                    .transition_stage(&run_id, SimulationMissionStage::Preparing, at)?;
            }
            SimulationCommand::Pause { .. } => {
                self.board
                    .transition_stage(&run_id, SimulationMissionStage::Paused, at)?;
            }
            SimulationCommand::Resume { .. } => {
                self.board
                    .transition_stage(&run_id, SimulationMissionStage::Running, at)?;
            }
            SimulationCommand::Abort { reason, .. } => {
                self.board.abort(&run_id, reason, at)?;
            }
            SimulationCommand::CreateCheckpoint {
                checkpoint_id,
                label,
                ..
            } => {
                if !matches!(
                    mission_before.stage,
                    SimulationMissionStage::Running | SimulationMissionStage::Paused
                ) {
                    return Err(HuginnProtocolError::Conflict {
                        code: "missionStage".to_string(),
                        message: "checkpoints can only be created while running or paused"
                            .to_string(),
                    });
                }
                let state =
                    checkpoint_state.ok_or_else(|| HuginnProtocolError::InvalidRequest {
                        code: "simulationCheckpointState".to_string(),
                        message: "checkpoint creation requires the verified state artifact"
                            .to_string(),
                    })?;
                let view = SimulationCheckpointView {
                    checkpoint_id: checkpoint_id.clone(),
                    run_id: run_id.clone(),
                    revision: 1,
                    parent_checkpoint_id: mission_before.current_checkpoint_id.clone(),
                    label: label.clone(),
                    created_at: at,
                    state: state.clone(),
                    state_digest: state.content_digest,
                };
                self.board.add_checkpoint(view.clone())?;
                self.board
                    .set_current_checkpoint(&run_id, checkpoint_id, at)?;
                checkpoint_delta_view = Some(view);
            }
            SimulationCommand::RestoreCheckpoint { checkpoint_id, .. } => {
                if !matches!(
                    mission_before.stage,
                    SimulationMissionStage::Running | SimulationMissionStage::Paused
                ) {
                    return Err(HuginnProtocolError::Conflict {
                        code: "missionStage".to_string(),
                        message: "checkpoints can only be restored while running or paused"
                            .to_string(),
                    });
                }
                self.board
                    .set_current_checkpoint(&run_id, checkpoint_id, at)?;
            }
            SimulationCommand::RequestRender {
                render_id,
                renderer_id,
                renderer_version,
                parameters,
                ..
            } => {
                let view: SimulationRenderView = self.renders.request(
                    &mission_before,
                    *render_id,
                    renderer_id,
                    renderer_version,
                    parameters.clone(),
                    at,
                )?;
                self.deltas
                    .push(SimulationRenderBoard::render_delta(&view, 0));
            }
            SimulationCommand::Intervene { intervention, .. } => {
                if mission_before.stage != SimulationMissionStage::Running {
                    return Err(HuginnProtocolError::Conflict {
                        code: "missionStage".to_string(),
                        message: "interventions are only applicable while running".to_string(),
                    });
                }
                match intervention {
                    SimulationIntervention::LocalRecompute { region } => {
                        verify_artifact(self.board.artifacts(), region)?;
                    }
                    SimulationIntervention::ChangeMesh { mesh } => {
                        verify_artifact(self.board.artifacts(), mesh)?;
                    }
                    SimulationIntervention::ChangeDomain { domain } => {
                        verify_artifact(self.board.artifacts(), domain)?;
                    }
                    SimulationIntervention::SwitchBackend { backend } => {
                        if backend.trim().is_empty() {
                            return Err(HuginnProtocolError::InvalidRequest {
                                code: "simulationBackend".to_string(),
                                message: "backend must be non-empty".to_string(),
                            });
                        }
                    }
                    SimulationIntervention::SetTimeStep { .. }
                    | SimulationIntervention::RequestLowerOrderEvidence { .. }
                    | SimulationIntervention::AbstainAndEscalate { .. } => {}
                }
                self.board.touch(&run_id, at)?;
            }
            SimulationCommand::RequestJudge {
                claim_event_id,
                claim,
                declared_scope,
                evidence,
                ..
            } => {
                for evidence_ref in evidence {
                    verify_artifact(self.board.artifacts(), &evidence_ref.content)?;
                }
                let view = JudgeClaimView {
                    claim_event_id: claim_event_id.clone(),
                    run_id: run_id.clone(),
                    revision: 1,
                    claim: claim.clone(),
                    declared_scope: declared_scope.clone(),
                    verdict: JudgeVerdict::Pending,
                    support_micros: None,
                    evidence: evidence.clone(),
                    report: None,
                    evaluated_at: None,
                };
                self.board.add_judge_claim(view.clone())?;
                self.deltas.push(judge_delta(&view, 0));
            }
        }

        if let Some(view) = checkpoint_delta_view {
            self.deltas.push(checkpoint_delta(&view, 0));
        }
        let mission_after = self
            .board
            .mission(&run_id)
            .cloned()
            .expect("mission presence checked above");
        if mission_after.revision != mission_before.revision {
            self.deltas
                .push(mission_delta(&mission_after, mission_before.revision));
        }
        Ok(())
    }
}
