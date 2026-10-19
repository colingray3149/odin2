//! Simulation read views: missions, checkpoints, and Judge claims with live links.

use std::collections::BTreeMap;

use odin_domain::huginn::{
    ArtifactRef, HuginnProtocolError, JudgeClaimView, JudgeVerdict, KubeResourceRef, ObjectDelta,
    ObjectKind, Revision, RevisionSource, SimulationCheckpointView, SimulationMissionStage,
    SimulationMissionView,
};
use odin_domain::{CheckpointId, EventId, NodeId, RunId};
use time::OffsetDateTime;

use crate::kube::view::{object_delta, object_snapshot};
use crate::kube::SurfaceArtifacts;

pub type Result<T, E = HuginnProtocolError> = std::result::Result<T, E>;
/// Telemetry and rendered frames do not drive mission stage transitions.
pub fn stage_transition_allowed(from: SimulationMissionStage, to: SimulationMissionStage) -> bool {
    use SimulationMissionStage as Stage;
    matches!(
        (from, to),
        (Stage::Declared, Stage::Preparing)
            | (Stage::Declared, Stage::Queued)
            | (Stage::Preparing, Stage::Queued)
            | (Stage::Queued, Stage::Preparing)
            | (Stage::Preparing, Stage::Running)
            | (Stage::Queued, Stage::Running)
            | (Stage::Running, Stage::Paused)
            | (Stage::Running, Stage::Checkpointing)
            | (Stage::Running, Stage::Succeeded)
            | (Stage::Running, Stage::Failed)
            | (Stage::Paused, Stage::Running)
            | (Stage::Paused, Stage::Checkpointing)
            | (Stage::Checkpointing, Stage::Running)
            | (Stage::Checkpointing, Stage::Paused)
            | (Stage::Checkpointing, Stage::Succeeded)
            | (Stage::Checkpointing, Stage::Failed)
    )
}

fn is_terminal(stage: SimulationMissionStage) -> bool {
    matches!(
        stage,
        SimulationMissionStage::Succeeded
            | SimulationMissionStage::Failed
            | SimulationMissionStage::Aborted
    )
}

/// Read-view board for simulation missions. Checkpoint chains and Judge claims are linked here so
/// every card carries immutable identity, revision, and evidence links.
pub struct SimulationBoard {
    artifacts: SurfaceArtifacts,
    missions: BTreeMap<RunId, SimulationMissionView>,
    checkpoints: BTreeMap<CheckpointId, SimulationCheckpointView>,
    judge_claims: BTreeMap<EventId, JudgeClaimView>,
}

impl SimulationBoard {
    pub fn new(artifacts: SurfaceArtifacts) -> Self {
        Self {
            artifacts,
            missions: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            judge_claims: BTreeMap::new(),
        }
    }

    pub fn artifacts(&self) -> &SurfaceArtifacts {
        &self.artifacts
    }

    pub fn artifacts_mut(&mut self) -> &mut SurfaceArtifacts {
        &mut self.artifacts
    }

    pub fn register_mission(&mut self, view: SimulationMissionView) -> Option<u64> {
        self.missions
            .insert(view.run_id.clone(), view)
            .map(|old| old.revision)
    }

    pub fn mission(&self, run_id: &RunId) -> Option<&SimulationMissionView> {
        self.missions.get(run_id)
    }

    pub fn missions(&self) -> impl Iterator<Item = &SimulationMissionView> {
        self.missions.values()
    }

    fn bump(mission: &mut SimulationMissionView, at: OffsetDateTime) -> Result<(u64, u64)> {
        let from = mission.revision;
        let to = mission
            .revision
            .checked_add(1)
            .ok_or_else(|| HuginnProtocolError::Conflict {
                code: "revisionExhausted".to_string(),
                message: "mission revision space is exhausted".to_string(),
            })?;
        mission.revision = to;
        mission.updated_at = at;
        mission.stale = false;
        Ok((from, to))
    }

    fn mission_or_not_found(&mut self, run_id: &RunId) -> Result<&mut SimulationMissionView> {
        self.missions
            .get_mut(run_id)
            .ok_or_else(|| HuginnProtocolError::NotFound {
                object_kind: "simulationMission".to_string(),
                object_id: run_id.to_string(),
            })
    }

    pub fn touch(&mut self, run_id: &RunId, at: OffsetDateTime) -> Result<(u64, u64)> {
        let mission = self.mission_or_not_found(run_id)?;
        Self::bump(mission, at)
    }

    pub fn transition_stage(
        &mut self,
        run_id: &RunId,
        to: SimulationMissionStage,
        at: OffsetDateTime,
    ) -> Result<(u64, u64)> {
        let mission = self.mission_or_not_found(run_id)?;
        if !stage_transition_allowed(mission.stage, to) {
            return Err(HuginnProtocolError::Conflict {
                code: "missionStage".to_string(),
                message: format!(
                    "transition from {:?} to {to:?} is not allowed",
                    mission.stage
                ),
            });
        }
        mission.stage = to;
        Self::bump(mission, at)
    }

    /// Applies an abort with its reason recorded as mission failure evidence.
    pub fn abort(
        &mut self,
        run_id: &RunId,
        reason: &str,
        at: OffsetDateTime,
    ) -> Result<(u64, u64)> {
        let mission = self.mission_or_not_found(run_id)?;
        if is_terminal(mission.stage) {
            return Err(HuginnProtocolError::Conflict {
                code: "missionStage".to_string(),
                message: format!("mission is already terminal ({:?})", mission.stage),
            });
        }
        mission.stage = SimulationMissionStage::Aborted;
        mission.failure = Some(format!("aborted: {reason}"));
        Self::bump(mission, at)
    }

    /// Updates live node/workload links without touching mission stage truth.
    pub fn set_links(
        &mut self,
        run_id: &RunId,
        node_id: Option<NodeId>,
        workload: Option<KubeResourceRef>,
        at: OffsetDateTime,
    ) -> Result<(u64, u64)> {
        let mission = self.mission_or_not_found(run_id)?;
        if node_id.is_some() {
            mission.node_id = node_id;
        }
        if workload.is_some() {
            mission.workload = workload;
        }
        Self::bump(mission, at)
    }

    pub fn add_checkpoint(&mut self, view: SimulationCheckpointView) -> Result<()> {
        if !self.missions.contains_key(&view.run_id) {
            return Err(HuginnProtocolError::NotFound {
                object_kind: "simulationMission".to_string(),
                object_id: view.run_id.to_string(),
            });
        }
        if self.checkpoints.contains_key(&view.checkpoint_id) {
            return Err(HuginnProtocolError::Conflict {
                code: "checkpointExists".to_string(),
                message: format!("checkpoint {} already exists", view.checkpoint_id),
            });
        }
        self.checkpoints.insert(view.checkpoint_id.clone(), view);
        Ok(())
    }

    /// Links a checkpoint as the mission's current checkpoint; the parent chain is preserved.
    pub fn set_current_checkpoint(
        &mut self,
        run_id: &RunId,
        checkpoint_id: &CheckpointId,
        at: OffsetDateTime,
    ) -> Result<(u64, u64)> {
        let checkpoint =
            self.checkpoints
                .get(checkpoint_id)
                .ok_or_else(|| HuginnProtocolError::NotFound {
                    object_kind: "simulationCheckpoint".to_string(),
                    object_id: checkpoint_id.to_string(),
                })?;
        if &checkpoint.run_id != run_id {
            return Err(HuginnProtocolError::NotFound {
                object_kind: "simulationCheckpoint".to_string(),
                object_id: checkpoint_id.to_string(),
            });
        }
        let mission = self.mission_or_not_found(run_id)?;
        mission.current_checkpoint_id = Some(checkpoint_id.clone());
        Self::bump(mission, at)
    }

    pub fn checkpoint(&self, checkpoint_id: &CheckpointId) -> Option<&SimulationCheckpointView> {
        self.checkpoints.get(checkpoint_id)
    }

    pub fn checkpoints_for_run<'a>(
        &'a self,
        run_id: &'a RunId,
    ) -> impl Iterator<Item = &'a SimulationCheckpointView> + 'a {
        self.checkpoints
            .values()
            .filter(move |checkpoint| &checkpoint.run_id == run_id)
    }

    pub fn add_judge_claim(&mut self, view: JudgeClaimView) -> Result<()> {
        if !self.missions.contains_key(&view.run_id) {
            return Err(HuginnProtocolError::NotFound {
                object_kind: "simulationMission".to_string(),
                object_id: view.run_id.to_string(),
            });
        }
        if self.judge_claims.contains_key(&view.claim_event_id) {
            return Err(HuginnProtocolError::Conflict {
                code: "judgeClaimExists".to_string(),
                message: format!("judge claim {} already exists", view.claim_event_id),
            });
        }
        self.judge_claims.insert(view.claim_event_id.clone(), view);
        Ok(())
    }

    pub fn judge_claim(&self, claim_event_id: &EventId) -> Option<&JudgeClaimView> {
        self.judge_claims.get(claim_event_id)
    }

    /// Applies an independent Judge outcome to a pending claim.
    pub fn evaluate_judge(
        &mut self,
        claim_event_id: &EventId,
        verdict: JudgeVerdict,
        support_micros: Option<u32>,
        report: Option<ArtifactRef>,
        at: OffsetDateTime,
    ) -> Result<(u64, u64)> {
        let claim = self.judge_claims.get_mut(claim_event_id).ok_or_else(|| {
            HuginnProtocolError::NotFound {
                object_kind: "simulationJudgeClaim".to_string(),
                object_id: claim_event_id.to_string(),
            }
        })?;
        let from = claim.revision;
        let to = claim
            .revision
            .checked_add(1)
            .ok_or_else(|| HuginnProtocolError::Conflict {
                code: "revisionExhausted".to_string(),
                message: "judge claim revision space is exhausted".to_string(),
            })?;
        claim.revision = to;
        claim.verdict = verdict;
        claim.support_micros = support_micros;
        claim.report = report;
        claim.evaluated_at = Some(at);
        Ok((from, to))
    }

    pub fn judge_claims_for_run<'a>(
        &'a self,
        run_id: &'a RunId,
    ) -> impl Iterator<Item = &'a JudgeClaimView> + 'a {
        self.judge_claims
            .values()
            .filter(move |claim| &claim.run_id == run_id)
    }

    pub fn snapshots(&self, include_stale: bool) -> Vec<odin_domain::huginn::ObjectSnapshot> {
        self.missions
            .values()
            .filter(|mission| include_stale || !mission.stale)
            .map(|mission| {
                object_snapshot(
                    ObjectKind::Simulation,
                    mission.run_id.to_string(),
                    Revision::new(mission.revision),
                    RevisionSource::Simulation,
                    mission.updated_at,
                    mission.stale,
                    mission,
                )
            })
            .collect()
    }

    pub fn mission_delta(view: &SimulationMissionView, from_revision: u64) -> ObjectDelta {
        object_delta(crate::kube::view::ObjectDeltaInput {
            kind: ObjectKind::Simulation,
            id: view.run_id.to_string(),
            from_revision: Revision::new(from_revision),
            to_revision: Revision::new(view.revision),
            revision_source: RevisionSource::Simulation,
            observed_at: view.updated_at,
            stale: view.stale,
            value: view,
        })
    }

    pub fn checkpoint_delta(view: &SimulationCheckpointView, from_revision: u64) -> ObjectDelta {
        object_delta(crate::kube::view::ObjectDeltaInput {
            kind: ObjectKind::Simulation,
            id: view.checkpoint_id.to_string(),
            from_revision: Revision::new(from_revision),
            to_revision: Revision::new(view.revision),
            revision_source: RevisionSource::Simulation,
            observed_at: view.created_at,
            stale: false,
            value: view,
        })
    }

    pub fn judge_delta(view: &JudgeClaimView, from_revision: u64) -> ObjectDelta {
        object_delta(crate::kube::view::ObjectDeltaInput {
            kind: ObjectKind::Simulation,
            id: view.claim_event_id.to_string(),
            from_revision: Revision::new(from_revision),
            to_revision: Revision::new(view.revision),
            revision_source: RevisionSource::Simulation,
            observed_at: view.evaluated_at.unwrap_or(OffsetDateTime::UNIX_EPOCH),
            stale: false,
            value: view,
        })
    }
}

pub fn mission_delta(view: &SimulationMissionView, from_revision: u64) -> ObjectDelta {
    SimulationBoard::mission_delta(view, from_revision)
}

pub fn checkpoint_delta(view: &SimulationCheckpointView, from_revision: u64) -> ObjectDelta {
    SimulationBoard::checkpoint_delta(view, from_revision)
}

pub fn judge_delta(view: &JudgeClaimView, from_revision: u64) -> ObjectDelta {
    SimulationBoard::judge_delta(view, from_revision)
}
