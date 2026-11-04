//! Simulation read views: missions, checkpoints, and Judge claims with live links.

use std::collections::BTreeMap;

use odin_domain::huginn::{
    ArtifactRef, HuginnProtocolError, JudgeClaimView, JudgeVerdict, KubeResourceRef, ObjectDelta,
    ObjectKind, Revision, RevisionSource, SimulationCheckpointView, SimulationMissionStage,
    SimulationMissionView,
};
use odin_domain::{CheckpointId, EventId, NodeId, RunId};
use time::OffsetDateTime;

use crate::kube::view::object_delta;
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
        let to = from + 1;
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
        if claim.verdict != JudgeVerdict::Pending {
            return Err(HuginnProtocolError::Conflict {
                code: "judgeClaimDecided".to_string(),
                message: format!("judge claim {claim_event_id} already has its verdict"),
            });
        }
        let from = claim.revision;
        let to = from + 1;
        claim.revision = to;
        claim.verdict = verdict;
        claim.support_micros = support_micros;
        claim.report = report;
        claim.evaluated_at = Some(at);
        Ok((from, to))
    }
}

pub fn mission_delta(
    view: &SimulationMissionView,
    from_revision: u64,
) -> Result<ObjectDelta, HuginnProtocolError> {
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

pub fn checkpoint_delta(
    view: &SimulationCheckpointView,
    from_revision: u64,
) -> Result<ObjectDelta, HuginnProtocolError> {
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

/// `at` stands for a claim not yet evaluated.
pub fn judge_delta(
    view: &JudgeClaimView,
    from_revision: u64,
    at: OffsetDateTime,
) -> Result<ObjectDelta, HuginnProtocolError> {
    object_delta(crate::kube::view::ObjectDeltaInput {
        kind: ObjectKind::Simulation,
        id: view.claim_event_id.to_string(),
        from_revision: Revision::new(from_revision),
        to_revision: Revision::new(view.revision),
        revision_source: RevisionSource::Simulation,
        observed_at: view.evaluated_at.unwrap_or(at),
        stale: false,
        value: view,
    })
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use odin_domain::huginn::{
        ArtifactKind, ArtifactRef, HuginnProtocolError, JudgeClaimView, JudgeVerdict,
        LiveSessionId, SimulationMissionStage, SimulationMissionView, StreamId,
    };
    use odin_domain::{ArtifactId, Digest, EventId, LaneId, RunId};
    use time::OffsetDateTime;

    use super::{judge_delta, SimulationBoard};
    use crate::kube::SurfaceArtifacts;

    fn artifact() -> ArtifactRef {
        ArtifactRef {
            artifact_id: ArtifactId::parse("00000000-0000-4000-8000-000000000002").unwrap(),
            session_id: LiveSessionId::parse("00000000-0000-4000-8000-000000000003").unwrap(),
            lane_id: LaneId::new("lane-sim").unwrap(),
            kind: ArtifactKind::File,
            display_name: "case.json".to_owned(),
            media_type: "application/json".to_owned(),
            byte_len: 2,
            content_digest: Digest::hash(b"{}"),
        }
    }

    fn mission(run: &RunId) -> SimulationMissionView {
        SimulationMissionView {
            run_id: run.clone(),
            revision: 1,
            label: "run".to_owned(),
            stage: SimulationMissionStage::Running,
            case: artifact(),
            geometry: None,
            node_id: None,
            workload: None,
            telemetry_stream_id: StreamId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
            frame_stream_id: StreamId::parse("00000000-0000-4000-8000-000000000004").unwrap(),
            current_checkpoint_id: None,
            supported_renderers: Vec::new(),
            evidence_obligations: artifact(),
            started_at: None,
            finished_at: None,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            stale: false,
            failure: None,
        }
    }

    #[test]
    fn a_judge_claim_is_decided_once_and_a_pending_one_is_dated_by_its_request() {
        let run = RunId::new("run-1").unwrap();
        let mut board = SimulationBoard::new(SurfaceArtifacts::new(
            LiveSessionId::parse("00000000-0000-4000-8000-000000000003").unwrap(),
            LaneId::new("lane-sim").unwrap(),
            NonZeroU64::new(1024).unwrap(),
            NonZeroU64::new(1024).unwrap(),
        ));
        board.register_mission(mission(&run));
        let claim_id = EventId::new("event:claim-1").unwrap();
        let pending = JudgeClaimView {
            claim_event_id: claim_id.clone(),
            run_id: run,
            revision: 1,
            claim: "the residual falls".to_owned(),
            declared_scope: "case".to_owned(),
            verdict: JudgeVerdict::Pending,
            support_micros: None,
            evidence: Vec::new(),
            report: None,
            evaluated_at: None,
        };
        board.add_judge_claim(pending.clone()).unwrap();

        let requested = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let delta = judge_delta(&pending, 0, requested).unwrap();
        assert_eq!(delta.freshness.observed_at, requested, "not the epoch");

        let decided_at = requested + time::Duration::minutes(5);
        board
            .evaluate_judge(
                &claim_id,
                JudgeVerdict::Supported,
                Some(900_000),
                None,
                decided_at,
            )
            .unwrap();
        let again = board
            .evaluate_judge(&claim_id, JudgeVerdict::Invalid, None, None, decided_at)
            .unwrap_err();
        assert!(
            matches!(again, HuginnProtocolError::Conflict { ref code, .. } if code == "judgeClaimDecided"),
            "{again}"
        );
        let held = board.judge_claim(&claim_id).unwrap();
        assert_eq!(held.verdict, JudgeVerdict::Supported);
        assert_eq!(held.evaluated_at, Some(decided_at));
    }
}
