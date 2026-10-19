//! The simulation board's producer (the surface's
//! live caller). Generic: Odin knows nothing about what a pod solves.
//!
//! - A run of a workload profile that declares `[simulation]` is a mission:
//!   registered the first time its Job is observed, its stage following the
//!   Job (pending → queued, running, suspended → paused, succeeded, failed,
//!   terminating or gone → aborted).
//! - The pod's `ODIN-STATUS {json}` lines are the mission's telemetry: each
//!   pump pass batches the new lines into one artifact, enqueues it in the
//!   run's durable telemetry ring and publishes the compact frame on the
//!   mission's telemetry stream.
//! - Its `ODIN-CHECKPOINT {json}` lines are checkpoints: the pod wrote its
//!   state to its declared state volume (which survives pause and rehome),
//!   and the board links the checkpoint chain.
//! - Pause, resume, and abort use kube approval; other commands use board revision checks.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use kube::api::{ListParams, LogParams};
use odin_domain::huginn::{
    self as live, ArtifactKind, ArtifactRef, CommandReceipt, HuginnProtocolError,
    KubeResourceOwnership, KubeResourceRef, KubeWorkloadState, LiveStreamKind, LiveStreamMode,
    ObjectDelta, RendererId, Sequence, SimulationCheckpointView, SimulationCommand,
    SimulationMissionStage, SimulationMissionView, SimulationOutputId, SimulationTelemetryView,
    StreamBackpressureLimits, StreamId,
};
use odin_domain::{ArtifactId, CheckpointId, LaneId, NodeId, RunId};
use odin_huginn::kube::SurfaceArtifacts;
use odin_huginn::read_model::MaterializedReadModel;
use odin_huginn::simulation::{
    checkpoint_delta, mission_delta, stage_transition_allowed, SimulationBoard, SimulationControl,
    SimulationRenderBoard,
};
use odin_huginn::streams::BoundedMultiplexer;
use odin_ledger::Ledger;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::huginn_conformance::{publish_frame, StreamFrameSpec};
use crate::kube::KubeRuntimeCell;

/// The line prefix of a checkpoint a pod reports (its state is already on
/// its state volume).
pub(crate) const CHECKPOINT_PREFIX: &str = "ODIN-CHECKPOINT ";
/// Log lines one pump pass asks the API server for.
const LOG_TAIL_LINES: i64 = 400;
/// Samples one telemetry batch carries (the newest; older ones are marked
/// truncated).
const MAX_SAMPLES_PER_BATCH: usize = 256;
/// Artifacts a run keeps on the board (telemetry batches, compact frames,
/// checkpoint states); older ones are dropped from the store.
const KEPT_ARTIFACTS_PER_RUN: usize = 48;
const PUMP_TICK: StdDuration = StdDuration::from_secs(10);

/// One observed Job of a profile that declares `[simulation]`.
#[derive(Clone, Debug)]
pub(crate) struct ObservedRun {
    pub run_id: RunId,
    pub profile: String,
    /// The profile declaration, as published (the mission's case).
    pub declaration: serde_json::Value,
    pub renderers: Vec<RendererId>,
    pub state: KubeWorkloadState,
    pub node_id: Option<NodeId>,
    pub workload: KubeResourceRef,
    pub started_at: Option<OffsetDateTime>,
    pub finished_at: Option<OffsetDateTime>,
}

#[derive(Default)]
struct RunCursor {
    /// The newest log timestamp already consumed.
    after: Option<OffsetDateTime>,
    sequence: u64,
    checkpoints: u64,
    artifacts: VecDeque<ArtifactId>,
    /// The newest status object and when it was printed.
    latest: Option<(OffsetDateTime, serde_json::Value)>,
}

struct Desk {
    control: SimulationControl,
    cursors: BTreeMap<RunId, RunCursor>,
}

/// What one locked pass produced, applied after the lock is released.
#[derive(Default)]
struct Publication {
    deltas: Vec<ObjectDelta>,
    frames: Vec<StreamFrameSpec>,
}

/// The daemon's one simulation board and its producer state.
pub(crate) struct SimulationDesk {
    desk: Mutex<Desk>,
    read_model: Arc<MaterializedReadModel>,
    streams: Arc<BoundedMultiplexer>,
    backpressure: StreamBackpressureLimits,
    approvals: LedgerApprovalGate,
}

/// Interventions are consequential: the board consults Colin's decision on
/// the approval the command names, in the durable ledger.
struct LedgerApprovalGate {
    ledger: Arc<Mutex<Ledger>>,
}

impl odin_huginn::approvals::ApprovalGate for LedgerApprovalGate {
    fn decision(&self, approval_id: &odin_domain::ApprovalId) -> Option<live::ApprovalDecision> {
        let ledger = self.ledger.lock().ok()?;
        let approval = ledger.approval(approval_id).ok()??;
        match approval.status {
            odin_domain::ApprovalStatus::Approved => Some(live::ApprovalDecision::Approve),
            odin_domain::ApprovalStatus::Denied => Some(live::ApprovalDecision::Reject),
            _ => None,
        }
    }
}

/// A stable identity derived from a run: the same run always names the
/// same streams and output across daemon restarts.
fn derived_uuid(purpose: &str, run_id: &RunId) -> uuid::Uuid {
    let hash = blake3::hash(format!("odin.simulation.{purpose}:{run_id}").as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hash.as_bytes()[..16]);
    uuid::Builder::from_random_bytes(bytes).into_uuid()
}

fn run_key(run_id: &RunId) -> String {
    blake3::hash(run_id.as_str().as_bytes()).to_hex()[..16].to_owned()
}

fn invalid(code: &str, message: impl Into<String>) -> HuginnProtocolError {
    HuginnProtocolError::InvalidRequest {
        code: code.to_owned(),
        message: message.into(),
    }
}

/// The mission stage a Job's state is; `None` when the cluster does not say.
fn stage_of(state: KubeWorkloadState) -> Option<SimulationMissionStage> {
    use SimulationMissionStage as Stage;
    match state {
        KubeWorkloadState::Pending | KubeWorkloadState::Scheduling => Some(Stage::Queued),
        KubeWorkloadState::Running => Some(Stage::Running),
        KubeWorkloadState::Suspended => Some(Stage::Paused),
        KubeWorkloadState::Succeeded => Some(Stage::Succeeded),
        KubeWorkloadState::Failed => Some(Stage::Failed),
        KubeWorkloadState::Terminating => Some(Stage::Aborted),
        KubeWorkloadState::Unknown => None,
    }
}

fn is_terminal(stage: SimulationMissionStage) -> bool {
    matches!(
        stage,
        SimulationMissionStage::Succeeded
            | SimulationMissionStage::Failed
            | SimulationMissionStage::Aborted
    )
}

/// One status or checkpoint report from a timestamped log line
/// (`<RFC 3339> <text>`).
enum Report {
    Status(OffsetDateTime, serde_json::Value),
    Checkpoint(OffsetDateTime, serde_json::Value),
}

fn reports(log: &str, after: Option<OffsetDateTime>) -> Vec<Report> {
    log.lines()
        .filter_map(|line| {
            let (stamp, text) = line.split_once(' ')?;
            let at = OffsetDateTime::parse(stamp, &Rfc3339).ok()?;
            if after.is_some_and(|after| at <= after) {
                return None;
            }
            let text = text.trim();
            let parse = |body: &str| {
                serde_json::from_str::<serde_json::Value>(body)
                    .ok()
                    .filter(serde_json::Value::is_object)
            };
            if let Some(body) = text.strip_prefix(odin_kube::telemetry::STATUS_PREFIX) {
                return parse(body).map(|value| Report::Status(at, value));
            }
            if let Some(body) = text.strip_prefix(CHECKPOINT_PREFIX) {
                return parse(body).map(|value| Report::Checkpoint(at, value));
            }
            None
        })
        .collect()
}

impl SimulationDesk {
    pub(crate) fn new(
        read_model: Arc<MaterializedReadModel>,
        streams: Arc<BoundedMultiplexer>,
        backpressure: StreamBackpressureLimits,
        ledger: Arc<Mutex<Ledger>>,
    ) -> Result<Self, String> {
        let session = live::LiveSessionId::new(derived_uuid(
            "board",
            &RunId::new("odind").map_err(|error| error.to_string())?,
        ))
        .map_err(|error| error.to_string())?;
        let lane = LaneId::new("simulation-board").map_err(|error| error.to_string())?;
        let bound = |bytes: u64| NonZeroU64::new(bytes).ok_or("zero artifact bound");
        let artifacts = SurfaceArtifacts::new(session, lane, bound(256 * 1024)?, bound(64 << 20)?);
        let renders = SimulationRenderBoard::new(NonZeroUsize::new(4).ok_or("zero render bound")?);
        Ok(Self {
            desk: Mutex::new(Desk {
                control: SimulationControl::new(SimulationBoard::new(artifacts), renders),
                cursors: BTreeMap::new(),
            }),
            read_model,
            streams,
            backpressure,
            approvals: LedgerApprovalGate { ledger },
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Desk>, HuginnProtocolError> {
        self.desk
            .lock()
            .map_err(|_| HuginnProtocolError::Unavailable {
                code: "simulationBoardLock".to_owned(),
            })
    }

    /// Whether a run's log is still worth reading (its mission is not over).
    pub(crate) fn wants_log(&self, run_id: &RunId) -> bool {
        self.lock().is_ok_and(|desk| {
            desk.control
                .board()
                .mission(run_id)
                .is_none_or(|mission| !is_terminal(mission.stage))
        })
    }

    /// One observation of a mission's Job and its timestamped log tail.
    pub(crate) fn observe(
        &self,
        run: &ObservedRun,
        log: &str,
        at: OffsetDateTime,
    ) -> Result<(), String> {
        let publication = {
            let mut desk = self.lock().map_err(|error| error.to_string())?;
            desk.observe(run, log, self.backpressure, at)?
        };
        self.publish(publication, at);
        Ok(())
    }

    /// Missions whose Job is gone end aborted (deleted or garbage-collected
    /// before the board saw it finish).
    pub(crate) fn retire_missing(&self, live_runs: &BTreeSet<RunId>, at: OffsetDateTime) {
        let publication = match self.lock() {
            Ok(mut desk) => desk.retire_missing(live_runs, at),
            Err(error) => {
                tracing::warn!("simulation retire skipped reason={error}");
                return;
            }
        };
        self.publish(publication, at);
    }

    /// The governed kube verb a mission command is, after the board's own
    /// revision check; `None` for the board's own commands.
    pub(crate) fn kube_command(
        &self,
        command: &SimulationCommand,
        kube_revision: impl Fn(&KubeResourceRef) -> Option<u64>,
    ) -> Result<Option<live::KubeCommand>, HuginnProtocolError> {
        let context = command.context();
        let desk = self.lock()?;
        let mission = desk
            .control
            .board()
            .mission(&context.run_id)
            .ok_or_else(|| HuginnProtocolError::NotFound {
                object_kind: "simulationMission".to_owned(),
                object_id: context.run_id.to_string(),
            })?;
        if mission.revision != context.expected_revision {
            return Err(HuginnProtocolError::RevisionMismatch {
                expected: live::Revision::new(context.expected_revision),
                actual: live::Revision::new(mission.revision),
            });
        }
        if !matches!(
            command,
            SimulationCommand::Pause { .. }
                | SimulationCommand::Resume { .. }
                | SimulationCommand::Abort { .. }
        ) {
            return Ok(None);
        }
        let workload = mission
            .workload
            .as_ref()
            .ok_or_else(|| HuginnProtocolError::Conflict {
                code: "simulationWorkload".to_owned(),
                message: format!("mission {} has no workload", context.run_id),
            })?;
        let expected_revision =
            kube_revision(workload).ok_or_else(|| HuginnProtocolError::Conflict {
                code: "simulationWorkloadUnobserved".to_owned(),
                message: format!(
                    "workload {} of mission {} is not in the read model yet",
                    workload.name, context.run_id
                ),
            })?;
        let (command_id, run_id, arguments_digest) = (
            context.command_id.clone(),
            context.run_id.clone(),
            context.arguments_digest,
        );
        Ok(Some(match command {
            SimulationCommand::Pause { .. } => live::KubeCommand::SuspendWorkload {
                command_id,
                run_id,
                expected_revision,
                arguments_digest,
            },
            SimulationCommand::Resume { .. } => live::KubeCommand::ResumeWorkload {
                command_id,
                run_id,
                expected_revision,
                arguments_digest,
            },
            _ => live::KubeCommand::DeleteWorkload {
                command_id,
                run_id,
                expected_revision,
                arguments_digest,
            },
        }))
    }

    /// Check board revision; checkpoints record the latest reported status and state volume.
    pub(crate) fn execute_board(
        &self,
        command: &SimulationCommand,
        at: OffsetDateTime,
    ) -> Result<CommandReceipt, HuginnProtocolError> {
        let (receipt, publication) = {
            let mut desk = self.lock()?;
            let state = match command {
                SimulationCommand::CreateCheckpoint { context, label, .. } => {
                    Some(desk.checkpoint_state(&context.run_id, label, None, at)?)
                }
                _ => None,
            };
            let receipt = desk
                .control
                .execute(command, &self.approvals, state.as_ref(), at)?;
            let deltas = desk.control.drain_deltas();
            let _ = desk.control.drain_statuses();
            (
                receipt,
                Publication {
                    deltas,
                    frames: Vec::new(),
                },
            )
        };
        self.publish(publication, at);
        Ok(receipt)
    }

    fn publish(&self, publication: Publication, at: OffsetDateTime) {
        for delta in publication.deltas {
            let id = delta.object.id.clone();
            if let Err(error) = self.read_model.apply(delta) {
                tracing::error!("simulation publication failed object={id} error={error}");
            }
        }
        for frame in publication.frames {
            let stream = frame.stream_id;
            if let Err(error) = publish_frame(&self.streams, frame, &self.backpressure, at) {
                tracing::error!("simulation telemetry frame failed stream={stream} error={error}");
            }
        }
    }
}

impl Desk {
    fn observe(
        &mut self,
        run: &ObservedRun,
        log: &str,
        backpressure: StreamBackpressureLimits,
        at: OffsetDateTime,
    ) -> Result<Publication, String> {
        let mut publication = Publication::default();
        let before = match self.control.board().mission(&run.run_id) {
            Some(mission) => mission.revision,
            None => {
                self.register(run, at)?;
                tracing::info!(
                    "simulation mission registered run={} profile={} state={:?}",
                    run.run_id,
                    run.profile,
                    run.state
                );
                0
            }
        };
        self.follow(run, at);
        let cursor = self.cursors.entry(run.run_id.clone()).or_default();
        let new = reports(log, cursor.after);
        if let Some(newest) = new
            .iter()
            .map(|report| match report {
                Report::Status(at, _) | Report::Checkpoint(at, _) => *at,
            })
            .max()
        {
            cursor.after = Some(newest);
        }
        let mut samples = Vec::new();
        for report in new {
            match report {
                Report::Status(stamp, status) => samples.push((stamp, status)),
                Report::Checkpoint(stamp, checkpoint) => {
                    match self.pod_checkpoint(run, stamp, checkpoint) {
                        Ok(view) => publication.deltas.push(checkpoint_delta(&view, 0)),
                        Err(error) => tracing::error!(
                            "simulation checkpoint refused run={} error={error}",
                            run.run_id
                        ),
                    }
                }
            }
        }
        if !samples.is_empty() {
            match self.telemetry(run, samples, backpressure, at) {
                Ok(frame) => publication.frames.push(frame),
                Err(error) => tracing::error!(
                    "simulation telemetry refused run={} error={error}",
                    run.run_id
                ),
            }
        }
        if let Some(mission) = self.control.board().mission(&run.run_id) {
            if mission.revision != before {
                // Checkpoint objects precede the mission that links them.
                publication.deltas.push(mission_delta(mission, before));
            }
        }
        self.prune(&run.run_id);
        Ok(publication)
    }

    fn register(&mut self, run: &ObservedRun, at: OffsetDateTime) -> Result<(), String> {
        let key = run_key(&run.run_id);
        let artifacts = self.control.board_mut().artifacts_mut();
        let mut publish = |name: &str, value: &serde_json::Value| {
            let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
            artifacts
                .publish(
                    ArtifactId::new(format!("sim-{name}-{key}"))
                        .map_err(|error| error.to_string())?,
                    ArtifactKind::File,
                    &format!("{name}.json"),
                    "application/json",
                    &bytes,
                )
                .map_err(|error| error.to_string())
        };
        let case = publish(
            "case",
            &serde_json::json!({"profile": run.profile, "declaration": run.declaration}),
        )?;
        let obligations = publish(
            "obligations",
            &serde_json::json!({"profile": run.profile, "obligations": []}),
        )?;
        let stage = match stage_of(run.state) {
            Some(SimulationMissionStage::Aborted) | None => SimulationMissionStage::Queued,
            Some(stage) => stage,
        };
        let stream = |purpose: &str| {
            StreamId::new(derived_uuid(purpose, &run.run_id)).map_err(|error| error.to_string())
        };
        self.control
            .board_mut()
            .register_mission(SimulationMissionView {
                run_id: run.run_id.clone(),
                revision: 1,
                label: run.profile.clone(),
                stage,
                case,
                geometry: None,
                node_id: run.node_id.clone(),
                workload: Some(run.workload.clone()),
                telemetry_stream_id: stream("telemetry")?,
                frame_stream_id: stream("frames")?,
                current_checkpoint_id: None,
                supported_renderers: run.renderers.clone(),
                evidence_obligations: obligations,
                started_at: run.started_at,
                finished_at: run.finished_at,
                updated_at: at,
                stale: false,
                failure: None,
            });
        Ok(())
    }

    /// Normalize a Job's queued-to-succeeded jump through the required running stage.
    fn follow(&mut self, run: &ObservedRun, at: OffsetDateTime) {
        let board = self.control.board_mut();
        let Some(mission) = board.mission(&run.run_id) else {
            return;
        };
        let (current, node_changed) = (
            mission.stage,
            run.node_id.is_some() && run.node_id != mission.node_id,
        );
        if node_changed || mission.workload.as_ref() != Some(&run.workload) {
            // A rehome moves the run to another node (and Job object).
            let _ = board.set_links(
                &run.run_id,
                run.node_id.clone(),
                Some(run.workload.clone()),
                at,
            );
        }
        let Some(target) = stage_of(run.state) else {
            return;
        };
        if target == current || is_terminal(current) {
            return;
        }
        let result = if target == SimulationMissionStage::Aborted {
            board.abort(&run.run_id, "the workload is terminating", at)
        } else if stage_transition_allowed(current, target) {
            board.transition_stage(&run.run_id, target, at)
        } else if stage_transition_allowed(current, SimulationMissionStage::Running)
            && stage_transition_allowed(SimulationMissionStage::Running, target)
        {
            board
                .transition_stage(&run.run_id, SimulationMissionStage::Running, at)
                .and_then(|_| board.transition_stage(&run.run_id, target, at))
        } else {
            Ok((0, 0))
        };
        if let Err(error) = result {
            tracing::error!(
                "simulation stage not followed run={} from={current:?} to={target:?} error={error}",
                run.run_id
            );
        }
    }

    fn telemetry(
        &mut self,
        run: &ObservedRun,
        mut samples: Vec<(OffsetDateTime, serde_json::Value)>,
        backpressure: StreamBackpressureLimits,
        at: OffsetDateTime,
    ) -> Result<StreamFrameSpec, String> {
        let truncated = samples.len() > MAX_SAMPLES_PER_BATCH;
        if truncated {
            samples.drain(..samples.len() - MAX_SAMPLES_PER_BATCH);
        }
        let mission = self
            .control
            .board()
            .mission(&run.run_id)
            .cloned()
            .ok_or("mission is not registered")?;
        let cursor = self.cursors.entry(run.run_id.clone()).or_default();
        cursor.sequence += 1;
        let sequence = cursor.sequence;
        let recorded_at = samples.last().map_or(at, |(stamp, _)| *stamp);
        cursor.latest = samples.last().cloned();
        let document = serde_json::json!({
            "run": run.run_id,
            "samples": samples
                .iter()
                .map(|(stamp, status)| serde_json::json!({
                    "at": stamp.format(&Rfc3339).unwrap_or_default(),
                    "status": status,
                }))
                .collect::<Vec<_>>(),
        });
        let bytes = serde_json::to_vec(&document).map_err(|error| error.to_string())?;
        let artifact_id =
            ArtifactId::new(format!("sim-telemetry-{}-{sequence}", run_key(&run.run_id)))
                .map_err(|error| error.to_string())?;
        let content = self
            .control
            .board_mut()
            .artifacts_mut()
            .publish(
                artifact_id.clone(),
                ArtifactKind::File,
                "telemetry.json",
                "application/json",
                &bytes,
            )
            .map_err(|error| error.to_string())?;
        let cursor = self.cursors.entry(run.run_id.clone()).or_default();
        cursor.artifacts.push_back(artifact_id);
        let view = SimulationTelemetryView {
            run_id: run.run_id.clone(),
            output_id: SimulationOutputId::new(derived_uuid("output", &run.run_id))
                .map_err(|error| error.to_string())?,
            sequence: Sequence::new(sequence),
            control_revision: mission.revision,
            recorded_at,
            sample_count: u64::try_from(samples.len()).unwrap_or(u64::MAX),
            content,
            truncated,
        };
        let bound = |value: u64| NonZeroU64::new(value).ok_or("zero ring bound");
        self.control
            .telemetry_ring_mut(
                &run.run_id,
                mission.telemetry_stream_id,
                NonZeroUsize::new(16).ok_or("zero ring bound")?,
                bound(4 << 20)?,
                backpressure,
            )
            .push(view, &bytes)
            .map_err(|error| error.to_string())?;
        // The ring is drained at once into the compact frame the stream
        // carries; the raw batch stays a board artifact.
        let frame = self
            .control
            .next_model_frame(&run.run_id, mission.telemetry_stream_id, at)
            .map_err(|error| error.to_string())?
            .ok_or("the telemetry ring yielded no frame")?;
        self.cursors
            .entry(run.run_id.clone())
            .or_default()
            .artifacts
            .push_back(frame.content.artifact_id.clone());
        Ok(StreamFrameSpec {
            stream_id: mission.telemetry_stream_id,
            kind: LiveStreamKind::SimulationTelemetry,
            mode: LiveStreamMode::Durable,
            sequence,
            control_revision: mission.revision,
            content: frame.content,
        })
    }

    /// The state artifact of a checkpoint: what the pod reported (if it
    /// reported the checkpoint itself), its newest status, and the volume
    /// its state lives on.
    fn checkpoint_state(
        &mut self,
        run_id: &RunId,
        label: &str,
        reported: Option<&serde_json::Value>,
        at: OffsetDateTime,
    ) -> Result<ArtifactRef, HuginnProtocolError> {
        let mission = self
            .control
            .board()
            .mission(run_id)
            .cloned()
            .ok_or_else(|| HuginnProtocolError::NotFound {
                object_kind: "simulationMission".to_owned(),
                object_id: run_id.to_string(),
            })?;
        let cursor = self.cursors.entry(run_id.clone()).or_default();
        cursor.checkpoints += 1;
        let ordinal = cursor.checkpoints;
        let latest = cursor.latest.clone();
        let document = serde_json::json!({
            "run": run_id,
            "label": label,
            "at": at.format(&Rfc3339).unwrap_or_default(),
            "reported": reported,
            "latestStatus": latest.map(|(stamp, status)| serde_json::json!({
                "at": stamp.format(&Rfc3339).unwrap_or_default(),
                "status": status,
            })),
            "stateVolume": mission.workload.as_ref().map(|workload| workload.name.clone()),
        });
        let bytes = serde_json::to_vec(&document)
            .map_err(|error| invalid("simulationCheckpointState", error.to_string()))?;
        let artifact_id = ArtifactId::new(format!("sim-checkpoint-{}-{ordinal}", run_key(run_id)))
            .map_err(|error| invalid("simulationCheckpointState", error.to_string()))?;
        let reference = self.control.board_mut().artifacts_mut().publish(
            artifact_id.clone(),
            ArtifactKind::File,
            "checkpoint.json",
            "application/json",
            &bytes,
        )?;
        self.cursors
            .entry(run_id.clone())
            .or_default()
            .artifacts
            .push_back(artifact_id);
        Ok(reference)
    }

    /// A checkpoint the pod reported: linked as the mission's current one.
    fn pod_checkpoint(
        &mut self,
        run: &ObservedRun,
        stamp: OffsetDateTime,
        reported: serde_json::Value,
    ) -> Result<SimulationCheckpointView, HuginnProtocolError> {
        let label = reported
            .get("label")
            .and_then(serde_json::Value::as_str)
            .map(|label| label.chars().take(80).collect::<String>());
        let ordinal = self
            .cursors
            .get(&run.run_id)
            .map_or(0, |cursor| cursor.checkpoints)
            + 1;
        let label = label.unwrap_or_else(|| format!("checkpoint {ordinal}"));
        let state = self.checkpoint_state(&run.run_id, &label, Some(&reported), stamp)?;
        let board = self.control.board_mut();
        let parent = board
            .mission(&run.run_id)
            .and_then(|mission| mission.current_checkpoint_id.clone());
        let view = SimulationCheckpointView {
            checkpoint_id: CheckpointId::new(format!(
                "sim-ckpt-{}-{ordinal}",
                run_key(&run.run_id)
            ))
            .map_err(|error| invalid("simulationCheckpointIdentity", error.to_string()))?,
            run_id: run.run_id.clone(),
            revision: 1,
            parent_checkpoint_id: parent,
            label,
            created_at: stamp,
            state_digest: state.content_digest,
            state,
        };
        board.add_checkpoint(view.clone())?;
        board.set_current_checkpoint(&run.run_id, &view.checkpoint_id, stamp)?;
        Ok(view)
    }

    fn retire_missing(&mut self, live_runs: &BTreeSet<RunId>, at: OffsetDateTime) -> Publication {
        let gone: Vec<(RunId, u64)> = self
            .control
            .board()
            .missions()
            .filter(|mission| !is_terminal(mission.stage) && !live_runs.contains(&mission.run_id))
            .map(|mission| (mission.run_id.clone(), mission.revision))
            .collect();
        let mut publication = Publication::default();
        for (run_id, before) in gone {
            let board = self.control.board_mut();
            if board.abort(&run_id, "the workload is gone", at).is_ok() {
                tracing::error!("simulation mission aborted run={run_id} reason=workload gone");
                if let Some(mission) = board.mission(&run_id) {
                    publication.deltas.push(mission_delta(mission, before));
                }
            }
        }
        publication
    }

    fn prune(&mut self, run_id: &RunId) {
        let Some(cursor) = self.cursors.get_mut(run_id) else {
            return;
        };
        let mut dropped = Vec::new();
        while cursor.artifacts.len() > KEPT_ARTIFACTS_PER_RUN {
            if let Some(id) = cursor.artifacts.pop_front() {
                dropped.push(id);
            }
        }
        let artifacts = self.control.board_mut().artifacts_mut();
        for id in dropped {
            artifacts.remove(&id);
        }
    }
}

fn owned_run(ownership: &KubeResourceOwnership) -> Option<RunId> {
    match ownership {
        KubeResourceOwnership::Odin { run_id, .. } => Some(run_id.clone()),
        KubeResourceOwnership::Foreign => None,
    }
}

/// The newest pod of a Job's timestamped log tail (any phase: a finished
/// pod's last lines still count).
async fn read_log(client: &odin_kube::KubeClient, job: &str) -> Option<String> {
    let pods = client
        .pods()
        .list(&ListParams::default().labels(&format!("job-name={job}")))
        .await
        .inspect_err(|error| {
            tracing::error!("simulation log-unread job={job} reason=pod list: {error}")
        })
        .ok()?;
    let pod = pods
        .items
        .iter()
        .max_by_key(|pod| pod.metadata.creation_timestamp.clone())?;
    client
        .pods()
        .logs(
            pod.metadata.name.as_deref()?,
            &LogParams {
                tail_lines: Some(LOG_TAIL_LINES),
                timestamps: true,
                ..LogParams::default()
            },
        )
        .await
        .inspect_err(|error| {
            tracing::error!("simulation log-unread job={job} reason=pod log: {error}")
        })
        .ok()
}

/// Every [`PUMP_TICK`] the board follows each Job of a `[simulation]`
/// profile (read live from the pin) and ingests its new reports.
pub(crate) fn arm_simulation_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    desk: Arc<SimulationDesk>,
    cell: Arc<KubeRuntimeCell>,
    snapshot: Arc<odin_registry::SnapshotHandle>,
) {
    pumps.spawn(async move {
        let mut ticker = tokio::time::interval(PUMP_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let Ok((_, client)) = cell.parts().await else {
                continue;
            };
            let jobs = match client
                .jobs()
                .list(&ListParams::default().labels(odin_kube::workload::WORKLOAD_LABEL))
                .await
            {
                Ok(jobs) => jobs,
                Err(error) => {
                    tracing::warn!("simulation tick skipped reason=job list failed: {error}");
                    continue;
                }
            };
            let pin = snapshot.current();
            let mut live_runs = BTreeSet::new();
            for job in &jobs.items {
                let Ok(observed) =
                    odin_kube::status::observe_job(&cell.kube_config().cluster, job, 0)
                else {
                    continue;
                };
                let workload = observed.workload;
                let (Some(run_id), Some(profile_id)) =
                    (owned_run(&workload.ownership), workload.profile.clone())
                else {
                    continue;
                };
                let Ok(profile) = pin.workload_profile_ref(&profile_id) else {
                    continue;
                };
                let Some(simulation) = profile.profile.simulation.clone() else {
                    continue;
                };
                let declaration = serde_json::to_value(profile.profile).unwrap_or_default();
                live_runs.insert(run_id.clone());
                let log = if desk.wants_log(&run_id) {
                    read_log(&client, &workload.resource.name)
                        .await
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                let run = ObservedRun {
                    run_id,
                    profile: profile_id,
                    declaration,
                    renderers: simulation.renderers,
                    state: workload.state,
                    node_id: workload.node_id.clone(),
                    workload: workload.resource.clone(),
                    started_at: workload.started_at,
                    finished_at: workload.finished_at,
                };
                if let Err(error) = desk.observe(&run, &log, OffsetDateTime::now_utc()) {
                    tracing::error!(
                        "simulation observation failed run={} error={error}",
                        run.run_id
                    );
                }
            }
            desk.retire_missing(&live_runs, OffsetDateTime::now_utc());
        }
    });
}

#[cfg(test)]
#[path = "tests/simulation.rs"]
mod tests;
