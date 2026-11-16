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
//! - Its `ODIN-RENDER {json}` lines are frames: a PNG or safe SVG the pod wrote under
//!   its export dir, read back by pod exec, published durably and carried on
//!   the mission's frames stream (eight kept per renderer). A frame completes
//!   the running render request for its renderer, else it is recorded as the
//!   pod's own. A requested render runs the profile's `render_command` in the
//!   pod, which prints the same line.
//! - Every Odin Job but a research pod is a mission, so any running pod shows
//!   its counters, frames and exports; `[simulation]` only adds renderers.
//! - A mission entering failed, aborted or paused, a failed render, or stale
//!   telemetry is a stage event: the `simulation_stage` routines and the seats
//!   watching `simulation` or `simulation:<project>` hear it. The project comes
//!   from the workload's lane; an unknown lane matches only unscoped watches.
//! - Pause, resume, and abort use kube approval; other commands use board revision checks.

#[path = "simulation/desk.rs"]
mod desk;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use kube::api::{ListParams, LogParams};
use odin_domain::huginn::{
    self as live, ArtifactRef, CommandReceipt, HuginnProtocolError, KubeResourceOwnership,
    KubeResourceRef, KubeWorkloadState, ObjectDelta, RenderId, RendererId, SimulationCommand,
    SimulationMissionStage, SimulationRenderStatus, StreamBackpressureLimits, StreamId,
};
use odin_domain::{ArtifactId, LaneId, NodeId, RunId};
use odin_huginn::kube::SurfaceArtifacts;
use odin_huginn::read_model::MaterializedReadModel;
use odin_huginn::service::FsPublishedArtifactStore;
use odin_huginn::simulation::{SimulationBoard, SimulationControl, SimulationRenderBoard};
use odin_huginn::streams::BoundedMultiplexer;
use odin_ledger::Ledger;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use odin_registry::schema::WorkloadSimulationToml;

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
/// The line prefix of a frame a pod wrote under its export dir.
pub(crate) const RENDER_PREFIX: &str = "ODIN-RENDER ";
/// Frame paths are relative to the pod's export dir.
const POD_EXPORT_ROOT: &str = "/export";
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
/// Reading a frame or the export listing back may take this long.
const READ_WAIT: StdDuration = StdDuration::from_secs(30);
/// The export listing a read shows (the first entries, by path).
const MAX_LISTED_EXPORTS: usize = 64;
/// Points of each plot key the view's sparkline draws.
const PLOT_POINTS: usize = 60;
/// The Status object views read the board from.
const STATUS_ID: &str = "missions";

/// Run, stage, profile, most recent telemetry time, and start time for heartbeat checks.
pub(crate) type HeartbeatMission = (
    RunId,
    SimulationMissionStage,
    String,
    Option<OffsetDateTime>,
    Option<OffsetDateTime>,
);

/// The executor that produced a mission observation.
#[derive(Clone, Debug)]
pub(crate) enum ObservedWorkload {
    Kube(KubeResourceRef),
    Offload(KubeResourceRef),
}

impl ObservedWorkload {
    fn resource(&self) -> &KubeResourceRef {
        match self {
            Self::Kube(resource) | Self::Offload(resource) => resource,
        }
    }
}

/// One observed workload mission, whether a Job or an offload run.
#[derive(Clone, Debug)]
pub(crate) struct ObservedRun {
    pub run_id: RunId,
    pub lane: Option<LaneId>,
    pub profile: String,
    /// The profile declaration, as published (the mission's case).
    pub declaration: serde_json::Value,
    /// Its profile's `[simulation]` (renderers, render command, frame and stage tunables);
    /// the defaults for a profile that declares none.
    pub simulation: WorkloadSimulationToml,
    /// Whether the profile declares `[simulation]`: only those runs have stage events
    /// (any other pod's failure is already a workload finding).
    pub declared: bool,
    pub state: KubeWorkloadState,
    pub node_id: Option<NodeId>,
    pub workload: ObservedWorkload,
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
    /// Whether the current stale episode was already told.
    stale_told: bool,
    frame_sequence: u64,
    /// Each renderer's kept frames, oldest first.
    frames: BTreeMap<RendererId, VecDeque<KeptFrame>>,
    profile: String,
    lane: Option<LaneId>,
    /// The `[simulation]` the run started with (a publication changes only new runs).
    simulation: WorkloadSimulationToml,
    /// The newest values of each plot key, oldest first.
    series: BTreeMap<String, VecDeque<f64>>,
    declared: bool,
}

/// One published frame of a mission and the render it completed.
#[derive(Clone, Debug)]
struct KeptFrame {
    artifact: ArtifactRef,
    render_id: RenderId,
    seq: u64,
    sim_time_us: Option<f64>,
    at: OffsetDateTime,
}

/// One `ODIN-RENDER` line, checked: a declared renderer and an image path under the export dir.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct FrameReport {
    pub run_id: RunId,
    pub renderer: RendererId,
    pub seq: u64,
    pub path: String,
    pub sim_time_us: Option<f64>,
    pub max_bytes: u64,
}

impl FrameReport {
    /// The bounded in-pod read of the frame: one byte over the cap shows it is over.
    pub(crate) fn read_argv(&self) -> Vec<String> {
        vec![
            "/bin/head".to_owned(),
            "-c".to_owned(),
            (self.max_bytes + 1).to_string(),
            format!("{POD_EXPORT_ROOT}/{}", self.path),
        ]
    }
}

/// A render request odind starts: the argv to run in the pod.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RenderStart {
    pub run_id: RunId,
    pub render_id: RenderId,
    pub renderer: RendererId,
    pub argv: Vec<String>,
    pub max_bytes: u64,
    pub wait: StdDuration,
}

/// A mission moment the `simulation_stage` routines and `simulation` watchers hear.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StageEvent {
    pub run_id: RunId,
    pub lane: Option<LaneId>,
    pub profile: String,
    /// `failed`, `aborted`, `paused`, `render-failed` or `stale`.
    pub kind: &'static str,
    /// Unique per occurrence (a replay fires nothing new).
    pub key: String,
    pub text: String,
    pub at: OffsetDateTime,
}

fn frame_report(run: &ObservedRun, line: &serde_json::Value) -> Result<FrameReport, String> {
    let renderer = line
        .get("renderer")
        .and_then(serde_json::Value::as_str)
        .ok_or("it names no renderer")?;
    let renderer =
        RendererId::new(renderer).map_err(|error| format!("renderer {renderer:?}: {error}"))?;
    if !run.simulation.renderers.contains(&renderer) {
        return Err(format!(
            "renderer {renderer} is not declared by profile {}",
            run.profile
        ));
    }
    let seq = line
        .get("seq")
        .and_then(serde_json::Value::as_u64)
        .ok_or("its seq is not a whole number")?;
    let path = line
        .get("path")
        .and_then(serde_json::Value::as_str)
        .ok_or("it names no path")?;
    if path.starts_with('/')
        || path.len() > 255
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(format!(
            "frame path {path:?} is not a plain path under {POD_EXPORT_ROOT}"
        ));
    }
    let lower = path.to_ascii_lowercase();
    if !lower.ends_with(".png") && !lower.ends_with(".svg") {
        return Err(format!("frame {path} is not a PNG or SVG"));
    }
    Ok(FrameReport {
        run_id: run.run_id.clone(),
        renderer,
        seq,
        path: path.to_owned(),
        sim_time_us: line.get("sim_time_us").and_then(serde_json::Value::as_f64),
        max_bytes: run.simulation.max_frame_bytes(),
    })
}

/// The frame bytes a report read back, checked against its cap and declared format.
fn checked_frame(report: &FrameReport, bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > report.max_bytes {
        return Err(format!(
            "frame {} is over the {}-byte frame cap",
            report.path, report.max_bytes
        ));
    }
    if report.path.to_ascii_lowercase().ends_with(".png") {
        if !bytes.starts_with(PNG_MAGIC) {
            return Err(format!("frame {} is not a PNG file", report.path));
        }
    } else if !safe_svg(&bytes) {
        return Err(format!("frame {} is not a safe SVG file", report.path));
    }
    Ok(bytes)
}

/// Accept a deliberately passive SVG subset. No links, embedded resources, scripts,
/// animation, foreign namespaces, stylesheets or CSS URL references reach a viewer.
fn safe_svg(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let Ok(doc) = roxmltree::Document::parse(text) else {
        return false;
    };
    if doc.descendants().any(|node| node.is_pi()) {
        return false;
    }
    let root = doc.root_element();
    const SVG: &str = "http://www.w3.org/2000/svg";
    if root.tag_name().name() != "svg" || root.tag_name().namespace() != Some(SVG) {
        return false;
    }
    doc.descendants()
        .filter(|node| node.is_element())
        .all(|node| {
            if node.tag_name().namespace() != Some(SVG)
                || !matches!(
                    node.tag_name().name(),
                    "svg"
                        | "g"
                        | "defs"
                        | "path"
                        | "rect"
                        | "circle"
                        | "ellipse"
                        | "line"
                        | "polyline"
                        | "polygon"
                        | "text"
                        | "tspan"
                        | "title"
                        | "desc"
                        | "clipPath"
                        | "linearGradient"
                        | "radialGradient"
                        | "stop"
                )
            {
                return false;
            }
            node.attributes().all(|attr| {
                attr.namespace().is_none()
                    && matches!(
                        attr.name(),
                        "id" | "version"
                            | "width"
                            | "height"
                            | "viewBox"
                            | "preserveAspectRatio"
                            | "x"
                            | "y"
                            | "x1"
                            | "y1"
                            | "x2"
                            | "y2"
                            | "cx"
                            | "cy"
                            | "r"
                            | "rx"
                            | "ry"
                            | "d"
                            | "points"
                            | "transform"
                            | "fill"
                            | "fill-opacity"
                            | "fill-rule"
                            | "stroke"
                            | "stroke-width"
                            | "stroke-opacity"
                            | "stroke-linecap"
                            | "stroke-linejoin"
                            | "stroke-dasharray"
                            | "stroke-dashoffset"
                            | "opacity"
                            | "font-family"
                            | "font-size"
                            | "font-weight"
                            | "font-style"
                            | "text-anchor"
                            | "dominant-baseline"
                            | "dx"
                            | "dy"
                            | "rotate"
                            | "offset"
                            | "stop-color"
                            | "stop-opacity"
                            | "gradientUnits"
                            | "gradientTransform"
                            | "clip-rule"
                    )
                    && !attr.value().contains('\\')
                    && !attr.value().to_ascii_lowercase().contains("url")
            })
        })
}

struct Desk {
    control: SimulationControl,
    cursors: BTreeMap<RunId, RunCursor>,
    events: Vec<StageEvent>,
}

/// What one locked pass produced, applied after the lock is released.
#[derive(Default)]
struct Publication {
    deltas: Vec<ObjectDelta>,
    frames: Vec<StreamFrameSpec>,
    /// Frames the pod reported, to read back.
    reads: Vec<FrameReport>,
    /// Published frames that aged out.
    retired: Vec<ArtifactRef>,
}

/// The daemon's one simulation board and its producer state.
pub(crate) struct SimulationDesk {
    desk: Mutex<Desk>,
    read_model: Arc<MaterializedReadModel>,
    streams: Arc<BoundedMultiplexer>,
    backpressure: StreamBackpressureLimits,
    approvals: LedgerApprovalGate,
    published: Arc<FsPublishedArtifactStore>,
}

/// Interventions are consequential: the board consults the owner's decision on
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
    Render(OffsetDateTime, serde_json::Value),
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
            if let Some(body) = text.strip_prefix(RENDER_PREFIX) {
                return parse(body).map(|value| Report::Render(at, value));
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
        published: Arc<FsPublishedArtifactStore>,
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
                events: Vec::new(),
            }),
            read_model,
            streams,
            backpressure,
            approvals: LedgerApprovalGate { ledger },
            published,
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Desk>, HuginnProtocolError> {
        self.desk
            .lock()
            .map_err(|error| HuginnProtocolError::unavailable("simulationBoardLock", error))
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

    /// One observation of a mission's Job and its timestamped log tail;
    /// returns the frames it reported, to read back from the pod.
    pub(crate) fn observe(
        &self,
        run: &ObservedRun,
        log: &str,
        at: OffsetDateTime,
    ) -> Result<Vec<FrameReport>, String> {
        let mut publication = {
            let mut desk = self.lock().map_err(|error| error.to_string())?;
            desk.observe(run, log, &self.streams, self.backpressure, at)?
        };
        let reads = std::mem::take(&mut publication.reads);
        self.publish(publication, at);
        Ok(reads)
    }

    /// Takes one frame read back from the pod: publishes it, completes the
    /// running render for its renderer (or records the pod's own), and carries
    /// it on the mission's frames stream. A refused frame fails that render.
    pub(crate) async fn take_frame(
        &self,
        report: &FrameReport,
        read: Result<Vec<u8>, String>,
        at: OffsetDateTime,
    ) {
        let published = match read.and_then(|bytes| checked_frame(report, bytes)) {
            Ok(bytes) => {
                let name = format!(
                    "{}-{}-{}.{}",
                    run_key(&report.run_id),
                    report.renderer,
                    report.seq,
                    if report.path.to_ascii_lowercase().ends_with(".svg") {
                        "svg"
                    } else {
                        "png"
                    }
                );
                self.published
                    .publish_simulation_frame(
                        &name,
                        if name.ends_with(".svg") {
                            "image/svg+xml"
                        } else {
                            "image/png"
                        },
                        bytes,
                    )
                    .await
                    .map_err(|error| format!("frame {} was not published: {error}", report.path))
            }
            Err(error) => Err(error),
        };
        let publication = match self.lock() {
            Ok(mut desk) => match published {
                Ok(artifact) => desk.record_frame(report, artifact, at),
                Err(reason) => {
                    tracing::error!(
                        "simulation frame refused run={} reason={reason}",
                        report.run_id
                    );
                    desk.fail_running(&report.run_id, Some(&report.renderer), &reason, at)
                }
            },
            Err(error) => {
                tracing::warn!("simulation frame skipped reason={error}");
                return;
            }
        };
        self.publish(publication, at);
    }

    /// The oldest requested render of a running mission, moved to running,
    /// with the argv that renders it; a mission that cannot render fails it.
    pub(crate) fn start_render(&self, run_id: &RunId, at: OffsetDateTime) -> Option<RenderStart> {
        let (start, publication) = match self.lock() {
            Ok(mut desk) => desk.start_render(run_id, at),
            Err(error) => {
                tracing::warn!("simulation render start skipped reason={error}");
                return None;
            }
        };
        self.publish(publication, at);
        start
    }

    /// A started render whose command ended without a frame.
    pub(crate) fn render_failed(
        &self,
        run_id: &RunId,
        render_id: RenderId,
        reason: &str,
        at: OffsetDateTime,
    ) {
        let publication = match self.lock() {
            Ok(mut desk) => desk.fail_render(run_id, render_id, reason, at),
            Err(error) => {
                tracing::warn!("simulation render failure not recorded reason={error}");
                return;
            }
        };
        self.publish(publication, at);
    }

    /// Stage events since the last drain.
    pub(crate) fn drain_events(&self) -> Vec<StageEvent> {
        self.lock()
            .map(|mut desk| std::mem::take(&mut desk.events))
            .unwrap_or_default()
    }

    /// Every mission, or the one `mission` names (a run id, its label or
    /// workload name): stage, node, the last sample, checkpoints, renders
    /// and kept frames.
    pub(crate) fn read(&self, mission: Option<&str>) -> Result<serde_json::Value, String> {
        let desk = self.lock().map_err(|error| error.to_string())?;
        let missions = desk.matching(mission)?;
        Ok(serde_json::json!({
            "missions": missions.iter().map(|view| desk.describe(view)).collect::<Vec<_>>(),
        }))
    }

    /// Stable mission control fields and the most recent telemetry time for heartbeat checks.
    pub(crate) fn heartbeat_missions(&self) -> Result<Vec<HeartbeatMission>, String> {
        let desk = self.lock().map_err(|error| error.to_string())?;
        Ok(desk
            .control
            .board()
            .missions()
            .map(|view| {
                let cursor = desk.cursors.get(&view.run_id);
                (
                    view.run_id.clone(),
                    view.stage,
                    cursor.map_or_else(|| view.label.clone(), |cursor| cursor.profile.clone()),
                    cursor.and_then(|cursor| cursor.latest.as_ref().map(|(at, _)| *at)),
                    view.started_at,
                )
            })
            .collect())
    }

    /// The newest kept frame of one mission (of `renderer` when named):
    /// the mission's run, the frame's reference and its bytes.
    pub(crate) fn latest_frame(
        &self,
        mission: &str,
        renderer: Option<&str>,
    ) -> Result<(RunId, ArtifactRef), String> {
        let desk = self.lock().map_err(|error| error.to_string())?;
        let missions = desk.matching(Some(mission))?;
        let [view] = missions.as_slice() else {
            return Err(format!(
                "{mission:?} names {} missions; name one by its run id",
                missions.len()
            ));
        };
        let newest = desk
            .cursors
            .get(&view.run_id)
            .into_iter()
            .flat_map(|cursor| cursor.frames.iter())
            .filter(|(id, _)| renderer.is_none_or(|wanted| id.as_str() == wanted))
            .filter_map(|(_, frames)| frames.back())
            .max_by_key(|frame| frame.at)
            .map(|frame| frame.artifact.clone());
        newest
            .map(|artifact| (view.run_id.clone(), artifact))
            .ok_or_else(|| match renderer {
                Some(renderer) => {
                    format!("mission {} has no frame from {renderer} yet", view.label)
                }
                None => format!("mission {} has produced no frame yet", view.label),
            })
    }

    /// The board as views draw it: one row per mission with its plot series and newest frame.
    pub(crate) fn status(&self) -> Option<serde_json::Value> {
        let desk = self.lock().ok()?;
        let stamp = |at: OffsetDateTime| at.format(&Rfc3339).unwrap_or_default();
        let rows: Vec<_> = desk
            .control
            .board()
            .missions()
            .map(|view| {
                let cursor = desk.cursors.get(&view.run_id);
                let frame = cursor
                    .into_iter()
                    .flat_map(|cursor| cursor.frames.iter())
                    .filter_map(|(renderer, frames)| frames.back().map(|frame| (renderer, frame)))
                    .max_by_key(|(_, frame)| frame.at);
                serde_json::json!({
                    "run": view.run_id,
                    "label": view.label,
                    "stage": view.stage,
                    "node": view.node_id,
                    "workload": view.workload.as_ref().map(|workload| &workload.name),
                    "failure": view.failure,
                    "updatedAt": stamp(view.updated_at),
                    "sampleAt": cursor.and_then(|cursor| cursor.latest.as_ref()).map(|(at, _)| stamp(*at)),
                    "lastSample": cursor.and_then(|cursor| cursor.latest.as_ref()).map(|(_, status)| status),
                    "series": cursor.map(|cursor| &cursor.series),
                    "checkpoints": desk.control.board().checkpoints_of(&view.run_id).count(),
                    "renderers": view.supported_renderers,
                    "openRenders": desk
                        .control
                        .renders()
                        .of_run(&view.run_id)
                        .filter(|render| matches!(render.status, SimulationRenderStatus::Requested | SimulationRenderStatus::Running))
                        .count(),
                    "frame": frame.map(|(renderer, frame)| serde_json::json!({
                        "artifact": frame.artifact.artifact_id,
                        "mediaType": frame.artifact.media_type,
                        "renderer": renderer,
                        "seq": frame.seq,
                        "simTimeUs": frame.sim_time_us,
                        "at": stamp(frame.at),
                    })),
                })
            })
            .collect();
        Some(serde_json::json!({ "rows": rows }))
    }

    /// Publishes [`Self::status`] for views (unchanged boards publish nothing).
    pub(crate) fn publish_status(
        &self,
        at: OffsetDateTime,
        view_seconds: u32,
        preview_max_side: u32,
    ) {
        let Some(mut value) = self.status() else {
            return;
        };
        value["viewPollSeconds"] = serde_json::json!(view_seconds);
        value["viewPreviewMaxSide"] = serde_json::json!(preview_max_side);
        if let Err(error) = crate::huginn_spend::publish_status(
            &self.read_model,
            crate::huginn_spend::status_object(STATUS_ID),
            value,
            at,
        ) {
            tracing::error!("simulation status not published error={error}");
        }
    }

    /// One frame's bytes, from the durable store.
    pub(crate) async fn frame_bytes(&self, artifact: &ArtifactRef) -> Result<Vec<u8>, String> {
        self.published
            .read_bytes(&artifact.artifact_id, artifact.byte_len)
            .await
            .map_err(|error| format!("frame {} is unreadable: {error}", artifact.display_name))
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
                    ..Publication::default()
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
                tracing::error!("simulation stream frame failed stream={stream} error={error}");
            }
        }
        if !publication.retired.is_empty() {
            if let Err(error) = self
                .published
                .retire_simulation_frames(&publication.retired)
            {
                tracing::error!("simulation frames not retired error={error}");
            }
        }
    }
}

/// Retires one board object from the read model.
fn remove_delta(id: String, revision: u64, at: OffsetDateTime) -> ObjectDelta {
    use odin_domain::huginn::read_model as rm;
    rm::ObjectDelta {
        object: rm::ObjectRef {
            kind: live::ObjectKind::Simulation,
            id,
        },
        from_revision: live::Revision::new(revision),
        to_revision: live::Revision::new(revision + 1),
        revision_source: live::RevisionSource::Simulation,
        freshness: rm::Freshness {
            state: rm::FreshnessState::Fresh,
            observed_at: at,
            source_updated_at: Some(at),
            stale_after_seconds: None,
        },
        body: rm::ObjectDeltaBody::Remove,
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

/// The board as the `simulation.read` and `simulation.frame` tools see it.
pub(crate) struct DaemonSimulationRoute {
    pub desk: Arc<SimulationDesk>,
    pub cell: Arc<KubeRuntimeCell>,
    pub handle: tokio::runtime::Handle,
}

impl DaemonSimulationRoute {
    fn block<F: std::future::Future>(&self, future: F) -> F::Output {
        // Host tools run on runtime workers; plain threads use the composition handle.
        match tokio::runtime::Handle::try_current() {
            Ok(current) => tokio::task::block_in_place(|| current.block_on(future)),
            Err(_) => self.handle.block_on(future),
        }
    }

    /// A running mission's export files so far: `[{path, bytes}]`, first by path.
    fn exports(&self, run_id: &RunId) -> Result<Vec<serde_json::Value>, String> {
        let client = self
            .cell
            .control()
            .map(|control| control.reconciler().exec_client())
            .ok_or("the k3s API server is unreachable")?;
        let argv = [
            "/bin/find",
            POD_EXPORT_ROOT,
            "-type",
            "f",
            "-printf",
            "%s %P\\0",
        ]
        .map(str::to_owned);
        let listing = self.block(read_in_pod(&client, run_id, &argv, READ_WAIT, 256 * 1024))?;
        let mut files: Vec<(String, u64)> = String::from_utf8_lossy(&listing)
            .split_terminator('\0')
            .filter_map(|entry| {
                let (bytes, path) = entry.split_once(' ')?;
                Some((path.to_owned(), bytes.parse().ok()?))
            })
            .collect();
        files.sort();
        files.truncate(MAX_LISTED_EXPORTS);
        Ok(files
            .into_iter()
            .map(|(path, bytes)| serde_json::json!({"path": path, "bytes": bytes}))
            .collect())
    }
}

impl odin_hermes::runtime::SimulationRoute for DaemonSimulationRoute {
    fn read(&self, mission: Option<&str>, exports: bool) -> Result<serde_json::Value, String> {
        let mut read = self.desk.read(mission)?;
        if exports {
            if let Some(view) = read["missions"]
                .as_array_mut()
                .and_then(|all| all.first_mut())
            {
                let run = view["run"].as_str().map(RunId::new);
                match run {
                    Some(Ok(run_id)) => match self.exports(&run_id) {
                        Ok(files) => view["exports"] = serde_json::Value::Array(files),
                        Err(reason) => view["exportsUnavailable"] = reason.into(),
                    },
                    _ => view["exportsUnavailable"] = "the mission names no run".into(),
                }
            }
        }
        Ok(read)
    }

    fn frame(&self, mission: &str, renderer: Option<&str>) -> Result<(String, Vec<u8>), String> {
        let (_, artifact) = self.desk.latest_frame(mission, renderer)?;
        let bytes = self.block(self.desk.frame_bytes(&artifact))?;
        let name = artifact
            .display_name
            .strip_prefix("frame-")
            .unwrap_or(&artifact.display_name)
            .to_owned();
        Ok((name, bytes))
    }
}

/// A research pod is never a mission: its own report path watches it.
fn is_research(profile: &str) -> bool {
    profile.starts_with("research")
}

/// On the authority node's simulation pump cadence, the board follows each Odin Job but
/// research pods, ingests reports and frames, starts renders, and tells stage events.
pub(crate) fn arm_simulation_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    desk: Arc<SimulationDesk>,
    cell: Arc<KubeRuntimeCell>,
    snapshot: Arc<odin_registry::SnapshotHandle>,
    offload: Option<Arc<crate::live::offload::Offload>>,
    runtime: Option<Arc<odin_hermes::runtime::HermesRuntime>>,
) {
    pumps.spawn(async move {
        let mut next = tokio::time::Instant::now();
        loop {
            tokio::time::sleep_until(next).await;
            let pin = snapshot.current();
            let node = pin.objects.iter().find_map(|object| match &object.config {
                odin_registry::ObjectConfig::Node(node)
                    if node.enabled && node.authoritative_state =>
                {
                    Some(node)
                }
                _ => None,
            });
            let seconds = node
                .and_then(|node| node.simulation_pump_seconds)
                .map_or(10, |seconds| seconds.get());
            let view_seconds = node
                .and_then(|node| node.missions_view_seconds)
                .map_or(5, |seconds| seconds.get());
            let preview_max_side = node
                .and_then(|node| node.missions_preview_max_side)
                .map_or(2048, |side| side.get());
            next = tokio::time::Instant::now() + StdDuration::from_secs(u64::from(seconds));
            desk.publish_status(OffsetDateTime::now_utc(), view_seconds, preview_max_side);
            let Ok((_, client)) = cell.parts().await else {
                publish_board(&desk, runtime.as_ref(), view_seconds, preview_max_side).await;
                continue;
            };
            // The job watch's cache, or one list while that watch is down.
            let jobs = match cell
                .job_cache()
                .labelled(odin_kube::workload::WORKLOAD_LABEL)
            {
                Some(jobs) => jobs,
                None => match client
                    .jobs()
                    .list(&ListParams::default().labels(odin_kube::workload::WORKLOAD_LABEL))
                    .await
                {
                    Ok(jobs) => jobs.items,
                    Err(error) => {
                        tracing::warn!("simulation tick skipped reason=job list failed: {error}");
                        publish_board(&desk, runtime.as_ref(), view_seconds, preview_max_side)
                            .await;
                        continue;
                    }
                },
            };
            let exec = cell
                .control()
                .map(|control| control.reconciler().exec_client());
            let mut live_runs = BTreeSet::new();
            for job in &jobs {
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
                if is_research(&profile_id) {
                    continue;
                }
                let Ok(profile) = pin.workload_profile_ref(&profile_id) else {
                    continue;
                };
                let declared = profile.profile.simulation.is_some();
                let simulation = profile.profile.simulation.clone().unwrap_or_default();
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
                    lane: match &workload.ownership {
                        KubeResourceOwnership::Odin { lane_id, .. } => Some(lane_id.clone()),
                        KubeResourceOwnership::Foreign => None,
                    },
                    profile: profile_id,
                    declaration,
                    simulation,
                    declared,
                    state: workload.state,
                    node_id: workload.node_id.clone(),
                    workload: ObservedWorkload::Kube(workload.resource.clone()),
                    started_at: workload.started_at,
                    finished_at: workload.finished_at,
                };
                let reads = match desk.observe(&run, &log, OffsetDateTime::now_utc()) {
                    Ok(reads) => reads,
                    Err(error) => {
                        tracing::error!(
                            "simulation observation failed run={} error={error}",
                            run.run_id
                        );
                        continue;
                    }
                };
                let Some(exec) = &exec else {
                    continue;
                };
                for report in reads {
                    let read = read_in_pod(
                        exec,
                        &report.run_id,
                        &report.read_argv(),
                        READ_WAIT,
                        report.max_bytes + 1,
                    )
                    .await;
                    desk.take_frame(&report, read, OffsetDateTime::now_utc())
                        .await;
                }
                if let Some(start) = desk.start_render(&run.run_id, OffsetDateTime::now_utc()) {
                    // A render may take minutes; the pass does not wait for it.
                    tokio::spawn(run_render(Arc::clone(&desk), exec.clone(), start));
                }
            }
            // Offload runs are followed by the offload pump, never retired as a missing Job.
            live_runs.extend(
                offload
                    .iter()
                    .flat_map(|offload| offload.runs())
                    .map(|run| run.run_id),
            );
            desk.retire_missing(&live_runs, OffsetDateTime::now_utc());
            publish_board(&desk, runtime.as_ref(), view_seconds, preview_max_side).await;
        }
    });
}

/// Offload missions continue publishing status and stage events even when Kubernetes is down.
async fn publish_board(
    desk: &SimulationDesk,
    runtime: Option<&Arc<odin_hermes::runtime::HermesRuntime>>,
    view_seconds: u32,
    preview_max_side: u32,
) {
    desk.publish_status(OffsetDateTime::now_utc(), view_seconds, preview_max_side);
    let events = desk.drain_events();
    if let Some(runtime) = runtime {
        for event in events {
            tell_stage(runtime, event).await;
        }
    }
}

/// One fixed argv in a pod's worker container: its stdout, or why not.
async fn read_in_pod(
    client: &odin_kube::KubeClient,
    run_id: &RunId,
    argv: &[String],
    wait: StdDuration,
    tail_bytes: u64,
) -> Result<Vec<u8>, String> {
    let tail = usize::try_from(tail_bytes).map_err(|error| error.to_string())?;
    let run = odin_kube::exec::run_in_worker(client, run_id, argv, None, wait, tail)
        .await
        .map_err(|error| format!("{} in the pod failed: {error}", argv.join(" ")))?;
    if run.exit_code != 0 {
        return Err(format!(
            "{} exited {}: {}",
            argv.join(" "),
            run.exit_code,
            String::from_utf8_lossy(&run.stderr_tail).trim()
        ));
    }
    Ok(run.stdout_tail)
}

/// Runs a requested render in the pod; the frame its `ODIN-RENDER` line
/// names completes the request.
async fn run_render(desk: Arc<SimulationDesk>, client: odin_kube::KubeClient, start: RenderStart) {
    let output = read_in_pod(&client, &start.run_id, &start.argv, start.wait, 64 * 1024).await;
    let line = output.and_then(|stdout| {
        String::from_utf8_lossy(&stdout)
            .lines()
            .rev()
            .find_map(|line| line.trim().strip_prefix(RENDER_PREFIX).map(str::to_owned))
            .ok_or_else(|| "the render command printed no ODIN-RENDER line".to_owned())
    });
    let report = line.and_then(|line| {
        let value = serde_json::from_str::<serde_json::Value>(&line)
            .map_err(|error| format!("its ODIN-RENDER line is not JSON: {error}"))?;
        let probe = ObservedRun {
            run_id: start.run_id.clone(),
            lane: None,
            profile: String::new(),
            declaration: serde_json::Value::Null,
            simulation: WorkloadSimulationToml {
                renderers: vec![start.renderer.clone()],
                max_frame_bytes: Some(start.max_bytes),
                ..WorkloadSimulationToml::default()
            },
            declared: true,
            state: KubeWorkloadState::Running,
            node_id: None,
            workload: ObservedWorkload::Kube(KubeResourceRef {
                cluster: String::new(),
                api_version: String::new(),
                kind: String::new(),
                namespace: None,
                name: String::new(),
                uid: String::new(),
            }),
            started_at: None,
            finished_at: None,
        };
        frame_report(&probe, &value)
    });
    match report {
        Ok(report) => {
            let read = read_in_pod(
                &client,
                &report.run_id,
                &report.read_argv(),
                READ_WAIT,
                report.max_bytes + 1,
            )
            .await;
            desk.take_frame(&report, read, OffsetDateTime::now_utc())
                .await;
        }
        Err(reason) => desk.render_failed(
            &start.run_id,
            start.render_id,
            &reason,
            OffsetDateTime::now_utc(),
        ),
    }
}

/// A stage event fires the `simulation_stage` routines and wakes the seats watching `simulation`.
async fn tell_stage(runtime: &Arc<odin_hermes::runtime::HermesRuntime>, event: StageEvent) {
    let detail = serde_json::json!({
        "run": event.run_id,
        "profile": event.profile,
        "kind": event.kind,
        "text": event.text,
    })
    .to_string();
    let at_ms = i64::try_from(event.at.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX);
    if let Err(error) = runtime.routine_event(
        odin_registry::schema::RoutineEvent::SimulationStage,
        Some(&event.profile),
        &event.key,
        &detail,
        at_ms,
    ) {
        tracing::error!(
            "simulation stage routine failed key={} error={error}",
            event.key
        );
    }
    let text = format!(
        "[Odin simulation board] {} Read it with simulation_read; simulation_frame shows its latest frame.",
        event.text
    );
    let project = event
        .lane
        .as_ref()
        .and_then(|lane| runtime.workload_owner(lane).0);
    crate::child_report::wake_declared(
        runtime,
        "simulation",
        project.as_ref().map(odin_domain::ProjectId::as_str),
        &format!("simulation-{}", event.key),
        &text,
    )
    .await;
}

#[cfg(test)]
#[path = "tests/simulation.rs"]
mod tests;
