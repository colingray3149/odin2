//! The launch queue: a `kube.workload.create` that no node has room for is held as one
//! JSON file instead of failing; a batch item also waits on a full seat or lane pod cap.
//! The queue pump in `odind` runs held launches again through
//! [`KubeCommandCoordinator::retry_held`](super::KubeCommandCoordinator::retry_held).

use std::path::{Path, PathBuf};

use odin_domain::{RunId, Scope};
use odin_huginn::kube::KubeControl;
use odin_kube::JobLaunch;
use odin_omp::host_tools::{HostInvocation, HostToolError, KubeCapabilityBinding};
use odin_types::OperationId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::admission::{arguments_error, decode_arguments, kube_failure, require_kube_seat_scope};
use super::evidence::{queued_settlement, serialize_output};
use super::KubeCommandCoordinator;

/// Everything `kube.workload.create` needs to run again. The permit's operation id travels
/// with it, so the rerun is the same operation, not a new one.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QueuedLaunch {
    pub operation_id: String,
    pub timeout_seconds: u32,
    pub scope: Scope,
    pub arguments: Value,
    /// Unix milliseconds when the launch was first held; the queue admits in this order.
    #[serde(default)]
    pub held_at_ms: i64,
    /// The batch this launch belongs to; its session hears one summary for the batch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<String>,
    /// Also wait on a full seat `max_parallel_runs` or lane `pods` cap instead of refusing.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub queue_caps: bool,
    /// Campaign reservation keyed by this launch's operation id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub campaign: Option<String>,
    /// Digest verified against the owner-approved campaign stage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub campaign_stage_sha256: Option<String>,
}

impl QueuedLaunch {
    pub fn new(
        operation_id: &OperationId,
        timeout_seconds: u32,
        invocation: &HostInvocation,
    ) -> Self {
        Self {
            operation_id: operation_id.as_str().to_owned(),
            timeout_seconds,
            scope: invocation.scope.clone(),
            arguments: invocation.arguments.clone(),
            held_at_ms: 0,
            batch: None,
            queue_caps: false,
            campaign: None,
            campaign_stage_sha256: None,
        }
    }

    /// One item of a batch: it waits on caps as well as room. `create_many` holds its items so.
    pub fn in_batch(mut self, batch: impl Into<String>) -> Self {
        self.batch = Some(batch.into());
        self.queue_caps = true;
        self
    }

    pub fn profile(&self) -> &str {
        self.arguments["profile"].as_str().unwrap_or("a pod")
    }

    /// The lane the launch charges; the pump serves lanes in turn.
    pub fn lane(&self) -> &str {
        self.scope.lane.as_ref().map_or("", |lane| lane.as_str())
    }
}

/// GPU memory in bytes a run may take on the named node (free less the desktop's declared
/// reserve), or `None` when the node is not a desktop and declared GPU memory goes unchecked.
pub type VramProbe = std::sync::Arc<
    dyn Fn(
            String,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Option<u64>, String>> + Send>,
        > + Send
        + Sync,
>;

#[derive(Serialize, Deserialize)]
struct CampaignBatchIntent {
    operation: String,
    scope: Scope,
    arguments: Value,
    launches: Vec<QueuedLaunch>,
    campaign: String,
    reservations: Vec<odin_ledger::campaign::Reservation>,
}

/// One file per held launch, named by its operation id. Holding a launch again keeps its place.
#[derive(Clone, Debug)]
pub struct LaunchQueue {
    dir: PathBuf,
}

impl LaunchQueue {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub(super) fn campaign_state_dir(&self) -> Result<&Path, String> {
        self.dir
            .parent()
            .ok_or_else(|| "launch queue has no campaign state root".to_owned())
    }

    /// Record a batch before exposing its individual launches. The record remains after
    /// drain, preventing replay from re-queueing already completed work.
    pub(super) fn hold_batch(
        &self,
        operation: &OperationId,
        invocation: &HostInvocation,
        launches: &[QueuedLaunch],
    ) -> Result<(), String> {
        let _guard = self.lock()?;
        self.hold_batch_locked(operation, invocation, launches)
    }

    fn hold_batch_locked(
        &self,
        operation: &OperationId,
        invocation: &HostInvocation,
        launches: &[QueuedLaunch],
    ) -> Result<(), String> {
        let records = self.dir.join("batches");
        std::fs::create_dir_all(&records).map_err(|error| error.to_string())?;
        let path = records.join(format!("{}.json", operation.as_str()));
        let value =
            serde_json::json!({"scope": invocation.scope, "arguments": invocation.arguments});
        let bytes = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
        if path.exists() {
            let existing = std::fs::read(&path).map_err(|error| error.to_string())?;
            if existing != bytes {
                return Err("batch operation was reused with different input".to_owned());
            }
            return Ok(());
        }
        for launch in launches {
            self.hold_locked(launch.clone())?;
        }
        odin_cli::authority_provision::write_private_atomic(&path, &bytes)?;
        crate::live::launch_queue::wake();
        Ok(())
    }

    /// Persist the complete publication intent before reserving, so a crash at any
    /// subsequent step can be completed by the queue pump without a caller replay.
    pub(super) fn hold_campaign_batch(
        &self,
        operation: &OperationId,
        invocation: &HostInvocation,
        launches: &[QueuedLaunch],
        campaign: &str,
        reservations: &[odin_ledger::campaign::Reservation],
    ) -> Result<(), String> {
        let _guard = self.lock()?;
        let intent = CampaignBatchIntent {
            operation: operation.as_str().to_owned(),
            scope: invocation.scope.clone(),
            arguments: invocation.arguments.clone(),
            launches: launches.to_vec(),
            campaign: campaign.to_owned(),
            reservations: reservations.to_vec(),
        };
        let intents = self.dir.join("campaign-intents");
        std::fs::create_dir_all(&intents).map_err(|error| error.to_string())?;
        sync_dir(&self.dir)?;
        let path = intents.join(format!("{}.json", operation.as_str()));
        let bytes = serde_json::to_vec(&intent).map_err(|error| error.to_string())?;
        if path.exists() {
            if std::fs::read(&path).map_err(|error| error.to_string())? != bytes {
                return Err("batch operation was reused with different campaign intent".to_owned());
            }
        } else {
            odin_cli::authority_provision::write_private_atomic(&path, &bytes)?;
        }
        self.finish_campaign_intent(&path, &intent)
    }

    fn finish_campaign_intent(
        &self,
        path: &Path,
        intent: &CampaignBatchIntent,
    ) -> Result<(), String> {
        let operation = OperationId::new(&intent.operation).map_err(|error| error.to_string())?;
        let committed = self
            .dir
            .join("batches")
            .join(format!("{}.json", intent.operation));
        if !committed.exists() {
            odin_ledger::campaign::reserve(
                self.campaign_state_dir()?,
                &intent.campaign,
                &intent.reservations,
            )
            .map_err(|error| format!("campaign reservation refused: {error}"))?;
        }
        let invocation = HostInvocation {
            scope: intent.scope.clone(),
            arguments: intent.arguments.clone(),
        };
        self.hold_batch_locked(&operation, &invocation, &intent.launches)?;
        std::fs::remove_file(path).map_err(|error| error.to_string())?;
        sync_dir(path.parent().ok_or("campaign intent has no parent")?)?;
        Ok(())
    }

    fn recover_campaign_intents(&self) -> Result<(), String> {
        let dir = self.dir.join("campaign-intents");
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.to_string()),
        };
        for entry in entries {
            let path = entry.map_err(|error| error.to_string())?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let bytes = std::fs::read(&path).map_err(|error| error.to_string())?;
            let intent: CampaignBatchIntent =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            if path.file_stem().and_then(|s| s.to_str()) != Some(intent.operation.as_str()) {
                return Err("campaign intent operation mismatch".to_owned());
            }
            if let Err(error) = self.finish_campaign_intent(&path, &intent) {
                tracing::warn!(operation = %intent.operation, "campaign publication recovery deferred: {error}");
            }
        }
        Ok(())
    }

    pub fn hold(&self, launch: QueuedLaunch) -> Result<(), String> {
        let _guard = self.lock()?;
        self.hold_locked(launch)
    }

    fn hold_locked(&self, mut launch: QueuedLaunch) -> Result<(), String> {
        if self.claim_path(&launch.operation_id).exists()
            || self.drop_path(&launch.operation_id).exists()
        {
            return Err("launch operation has already been dispatched or dropped".to_owned());
        }
        let path = self.path(&launch.operation_id);
        if path.exists() {
            let bytes = std::fs::read(&path).map_err(|error| error.to_string())?;
            let existing: QueuedLaunch =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            if existing.operation_id != launch.operation_id
                || existing.scope != launch.scope
                || existing.arguments != launch.arguments
                || existing.batch != launch.batch
                || existing.queue_caps != launch.queue_caps
                || existing.timeout_seconds != launch.timeout_seconds
                || existing.campaign != launch.campaign
                || existing.campaign_stage_sha256 != launch.campaign_stage_sha256
            {
                return Err("launch operation was reused with different input".to_owned());
            }
            return Ok(());
        }
        std::fs::create_dir_all(&self.dir).map_err(|error| {
            format!(
                "launch queue {} is unavailable: {error}",
                self.dir.display()
            )
        })?;
        launch.held_at_ms =
            i64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
                .unwrap_or(i64::MAX);
        let bytes = serde_json::to_vec(&launch).map_err(|error| error.to_string())?;
        odin_cli::authority_provision::write_private_atomic(&path, &bytes)?;
        crate::live::launch_queue::wake();
        Ok(())
    }

    /// Every held launch, oldest first; an unreadable file fails the queue by name.
    pub fn held(&self) -> Result<Vec<(PathBuf, QueuedLaunch)>, String> {
        let _guard = self.lock()?;
        self.recover_campaign_intents()?;
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(format!(
                    "launch queue {} is unreadable: {error}",
                    self.dir.display()
                ))
            }
        };
        let mut held = Vec::new();
        for entry in entries {
            let path = entry.map_err(|error| error.to_string())?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let operation = match path.file_stem().and_then(|value| value.to_str()) {
                Some(operation) => operation,
                None => return Err(format!("invalid launch queue path {}", path.display())),
            };
            if self.claim_path(operation).exists() || self.drop_path(operation).exists() {
                continue;
            }
            let bytes = std::fs::read(&path).map_err(|error| {
                format!("held launch {} is unreadable: {error}", path.display())
            })?;
            let launch: QueuedLaunch = serde_json::from_slice(&bytes)
                .map_err(|error| format!("held launch {} is malformed: {error}", path.display()))?;
            if launch.operation_id != operation {
                return Err(format!(
                    "held launch {} has a mismatched operation id",
                    path.display()
                ));
            }
            if let Some(batch) = &launch.batch {
                if !self
                    .dir
                    .join("batches")
                    .join(format!("{batch}.json"))
                    .exists()
                {
                    continue;
                }
            }
            held.push((path, launch));
        }
        held.sort_by(|(_, a), (_, b)| {
            (a.held_at_ms, &a.operation_id).cmp(&(b.held_at_ms, &b.operation_id))
        });
        Ok(held)
    }

    /// Atomically claim a held item before any launch effects. Claims survive crashes and
    /// are deliberately not replayed: a dispatch may already have reached the cluster.
    pub fn claim(&self, path: &Path, launch: &QueuedLaunch) -> Result<bool, String> {
        let _guard = self.lock()?;
        if path != self.path(&launch.operation_id) || self.drop_path(&launch.operation_id).exists()
        {
            return Ok(false);
        }
        let claims = self.dir.join("claims");
        std::fs::create_dir_all(&claims).map_err(|error| error.to_string())?;
        let claim = self.claim_path(&launch.operation_id);
        match std::fs::hard_link(path, &claim) {
            Ok(()) => {
                sync_dir(&claims)?;
                std::fs::remove_file(path).map_err(|error| {
                    format!("claimed launch could not be removed from queue: {error}")
                })?;
                sync_dir(&self.dir)?;
                Ok(true)
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::AlreadyExists
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(format!("launch claim failed: {error}")),
        }
    }

    /// Return a claim to the queue only after an explicit capacity-only response.
    pub fn release(&self, launch: &QueuedLaunch) -> Result<(), String> {
        let _guard = self.lock()?;
        let claim = self.claim_path(&launch.operation_id);
        let path = self.path(&launch.operation_id);
        if path.exists() {
            return Err("launch claim has an unexpected queued copy".to_owned());
        }
        std::fs::hard_link(&claim, &path)
            .map_err(|error| format!("launch claim could not be released: {error}"))?;
        sync_dir(&self.dir)?;
        std::fs::remove_file(&claim)
            .map_err(|error| format!("released claim could not be removed: {error}"))?;
        sync_dir(&self.dir.join("claims"))
    }

    /// Drop claims use the same exclusive claim as dispatch. A refund is made only while
    /// holding that claim, so a concurrent pump cannot start the launch.
    pub fn drop_held(
        &self,
        seat: &odin_domain::SeatId,
        select: &HeldSelector,
    ) -> Result<Vec<QueuedLaunch>, String> {
        let mut dropped = Vec::new();
        for (path, launch) in self.held()? {
            if launch.scope.seat.as_ref() != Some(seat)
                || !select.matches(&launch)
                || !self.claim(&path, &launch)?
            {
                continue;
            }
            if launch.campaign.is_some() {
                let root = self
                    .dir
                    .parent()
                    .ok_or("launch queue has no campaign state root")?;
                odin_ledger::campaign::refund(root, &launch.operation_id)
                    .map_err(|error| error.to_string())?;
            }
            let drops = self.dir.join("dropped");
            std::fs::create_dir_all(&drops).map_err(|error| error.to_string())?;
            std::fs::rename(
                self.claim_path(&launch.operation_id),
                self.drop_path(&launch.operation_id),
            )
            .map_err(|error| error.to_string())?;
            sync_dir(&drops)?;
            sync_dir(&self.dir.join("claims"))?;
            dropped.push(launch);
        }
        Ok(dropped)
    }

    fn claim_path(&self, operation_id: &str) -> PathBuf {
        self.dir.join("claims").join(format!("{operation_id}.json"))
    }

    fn drop_path(&self, operation_id: &str) -> PathBuf {
        self.dir
            .join("dropped")
            .join(format!("{operation_id}.json"))
    }

    fn path(&self, operation_id: &str) -> PathBuf {
        self.dir.join(format!("{operation_id}.json"))
    }

    fn lock(&self) -> Result<std::fs::File, String> {
        std::fs::create_dir_all(&self.dir).map_err(|error| error.to_string())?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.dir.join(".lock"))
            .map_err(|error| error.to_string())?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)
            .map_err(|error| format!("launch queue lock failed: {error}"))?;
        Ok(file)
    }
}

fn sync_dir(path: &Path) -> Result<(), String> {
    std::fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("could not sync {}: {error}", path.display()))
}

/// Which held launches a drop removes.
#[derive(Clone, Debug)]
pub enum HeldSelector {
    Batch(String),
    Operation(String),
}

impl HeldSelector {
    fn matches(&self, launch: &QueuedLaunch) -> bool {
        match self {
            Self::Batch(batch) => launch.batch.as_deref() == Some(batch),
            Self::Operation(operation) => &launch.operation_id == operation,
        }
    }
}

/// Holding and rerunning launches: the coordinator side of the queue.
impl KubeCommandCoordinator {
    /// Holds a launch no node has room for instead of failing it, and a batch item whose seat
    /// or lane cap is full. The room check reads the cluster before the launch's journal entry
    /// exists, so a held launch leaves no pending create behind; any other refusal is left to
    /// the create itself to report.
    pub(super) async fn hold_when_full(
        &self,
        tool: &'static str,
        control: &KubeControl,
        launch: &mut JobLaunch,
        held: &QueuedLaunch,
        run_id: &RunId,
    ) -> Result<Option<Value>, HostToolError> {
        let queue = self.launch_queue();
        match control.reconciler().room_for(launch).await {
            Ok(node) => match self.vram_shortfall(launch, node.as_deref()).await {
                Some(reason) => {
                    tracing::info!(run = %run_id.as_str(), "launch held: {reason}");
                    match queue.as_ref() {
                        Some(queue) => Self::hold(tool, queue, held, run_id).map(Some),
                        None => Err(arguments_error(tool, reason)),
                    }
                }
                None => {
                    launch.admitted_node = node;
                    Ok(None)
                }
            },
            Err(error)
                if odin_kube::placement::is_capacity_refusal(&error)
                    || (held.queue_caps
                        && (odin_kube::is_cap_refusal(&error)
                            || odin_kube::is_compute_budget_refusal(&error))) =>
            {
                match queue.as_ref() {
                    Some(queue) => Self::hold(tool, queue, held, run_id).map(Some),
                    None => Err(placement_failure(tool, error)),
                }
            }
            Err(error) => Err(placement_failure(tool, error)),
        }
    }

    pub(super) fn hold(
        tool: &'static str,
        queue: &LaunchQueue,
        held: &QueuedLaunch,
        run_id: &RunId,
    ) -> Result<Value, HostToolError> {
        // A pump owns an exclusive claim while rechecking capacity. It must not
        // reinsert the item itself; the pump releases it after the queued answer.
        if held.held_at_ms == 0 || !queue.claim_path(&held.operation_id).exists() {
            queue
                .hold(held.clone())
                .map_err(|detail| HostToolError::Storage { tool, detail })?;
        }
        serialize_output(
            tool,
            &queued_settlement(run_id.as_str(), &held.operation_id),
        )
    }

    /// Why a launch declaring GPU memory must wait on `node`: the desktop holds too much of
    /// it, or its memory could not be read. `None` lets the launch go ahead.
    pub(super) async fn vram_shortfall(
        &self,
        launch: &JobLaunch,
        node: Option<&str>,
    ) -> Option<String> {
        let (Some(need), Some(node)) = (launch.gpu_vram_gib, node) else {
            return None;
        };
        let Some(probe) = self.vram_probe.as_ref() else {
            return Some(format!(
                "{node}'s free GPU memory cannot be checked: no VRAM probe configured"
            ));
        };
        let want = u64::from(need) * 1024 * 1024 * 1024;
        match probe(node.to_owned()).await {
            Ok(None) => None,
            Ok(Some(usable)) if usable >= want => None,
            Ok(Some(usable)) => Some(format!(
                "{node} has {} MiB of GPU memory to spare beside its desktop reserve; the run declares {need} GiB",
                usable >> 20
            )),
            Err(error) => Some(format!("{node}'s free GPU memory could not be read: {error}")),
        }
    }

    /// Runs a held launch again through the same create path. Only the queue pump calls it.
    pub async fn retry_held(&self, held: QueuedLaunch) -> Result<Value, HostToolError> {
        let tool = KubeCapabilityBinding::WorkloadCreate.id();
        let operation_id =
            OperationId::new(&held.operation_id).map_err(|error| HostToolError::Storage {
                tool,
                detail: format!("held launch has no valid operation id: {error}"),
            })?;
        let invocation = HostInvocation {
            scope: held.scope.clone(),
            arguments: held.arguments.clone(),
        };
        self.create_held(tool, held.timeout_seconds, operation_id, invocation, held)
            .await
    }
}

/// `kube.workload.queue_drop.input`: exactly one selector.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct QueueInput {
    #[serde(default)]
    batch: Option<String>,
    #[serde(default)]
    operation: Option<String>,
}

impl QueueInput {
    pub(super) fn decode(
        tool: &'static str,
        arguments: Value,
    ) -> Result<HeldSelector, HostToolError> {
        let input: Self = decode_arguments(tool, arguments)?;
        match (input.batch, input.operation) {
            (Some(batch), None) if !batch.is_empty() => Ok(HeldSelector::Batch(batch)),
            (None, Some(operation)) if !operation.is_empty() => {
                Ok(HeldSelector::Operation(operation))
            }
            _ => Err(arguments_error(
                tool,
                "drop names exactly one nonempty batch or operation",
            )),
        }
    }
}

/// `kube.workload.queue.output`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct QueueOutput {
    status: QueueStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    held: Option<Vec<HeldRow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dropped: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum QueueStatus {
    Ok,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HeldRow {
    operation: String,
    profile: String,
    lane: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    batch: Option<String>,
    held_at_ms: i64,
    waits_on_caps: bool,
}

impl QueueOutput {
    fn unavailable(reason: String) -> Self {
        Self {
            status: QueueStatus::Unavailable,
            held: None,
            dropped: None,
            reason: Some(reason),
        }
    }

    fn validate(&self) -> Result<(), String> {
        match self.status {
            QueueStatus::Ok if self.held.is_none() => {
                Err("an ok queue answer carries the held array".to_owned())
            }
            QueueStatus::Unavailable if self.reason.as_deref().unwrap_or_default().is_empty() => {
                Err("an unavailable queue answer requires a typed reason".to_owned())
            }
            _ => Ok(()),
        }
    }
}

/// `room_for` only reads, so whatever it refuses with, no Job was created: an unavailable
/// placement (no ready node fits) is a definite refusal with its own reason, never an unproven effect.
fn placement_failure(tool: &'static str, error: odin_kube::KubeError) -> HostToolError {
    match error {
        odin_kube::KubeError::Unavailable { reason } => HostToolError::Unavailable { tool, reason },
        other => kube_failure(tool, other),
    }
}

pub(super) fn extract_queue_evidence(
    tool: &'static str,
    arguments: Value,
) -> Result<Value, HostToolError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EvidenceInput {
        output: Value,
    }
    let input: EvidenceInput = decode_arguments(tool, arguments)?;
    let output: QueueOutput = serde_json::from_value(input.output)
        .map_err(|error| arguments_error(tool, format!("invalid queue output: {error}")))?;
    output
        .validate()
        .map_err(|detail| arguments_error(tool, detail))?;
    serialize_output(tool, &output)
}

/// The caller's held launches after an optional drop.
fn queue_answer(
    queue: &LaunchQueue,
    seat: &odin_domain::SeatId,
    select: Option<&HeldSelector>,
) -> Result<QueueOutput, String> {
    let dropped = select
        .map(|select| queue.drop_held(seat, select))
        .transpose()?
        .map(|dropped| {
            dropped
                .into_iter()
                .map(|launch| launch.operation_id)
                .collect()
        });
    let held = queue
        .held()?
        .into_iter()
        .filter(|(_, launch)| launch.scope.seat.as_ref() == Some(seat))
        .map(|(_, launch)| HeldRow {
            profile: launch.profile().to_owned(),
            lane: launch.lane().to_owned(),
            operation: launch.operation_id,
            batch: launch.batch,
            held_at_ms: launch.held_at_ms,
            waits_on_caps: launch.queue_caps,
        })
        .collect();
    Ok(QueueOutput {
        status: QueueStatus::Ok,
        held: Some(held),
        dropped,
        reason: None,
    })
}

impl KubeCommandCoordinator {
    /// List the caller's launches, or remove selected launches under the drop capability.
    pub(super) fn queue_op(
        &self,
        tool: &'static str,
        invocation: HostInvocation,
        drop: bool,
    ) -> Result<Value, HostToolError> {
        let seat = require_kube_seat_scope(tool, &invocation.scope)?;
        let select = if drop {
            Some(QueueInput::decode(tool, invocation.arguments)?)
        } else {
            let _: super::admission::NoInput = decode_arguments(tool, invocation.arguments)?;
            None
        };
        let output = match self.launch_queue() {
            None => QueueOutput::unavailable("the launch queue is not configured".to_owned()),
            Some(queue) => queue_answer(&queue, &seat, select.as_ref())
                .unwrap_or_else(QueueOutput::unavailable),
        };
        serialize_output(tool, &output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(operation: &str, seat: &str, batch: Option<&str>, at: i64) -> QueuedLaunch {
        let launch = QueuedLaunch {
            operation_id: operation.to_owned(),
            timeout_seconds: 60,
            scope: Scope {
                seat: Some(odin_domain::SeatId::new(seat).expect("seat id")),
                ..Scope::default()
            },
            arguments: serde_json::json!({"profile": "cfd"}),
            held_at_ms: at,
            batch: None,
            queue_caps: false,
            campaign: None,
            campaign_stage_sha256: None,
        };
        match batch {
            Some(batch) => launch.in_batch(batch),
            None => launch,
        }
    }

    #[test]
    fn a_placement_refusal_before_any_job_is_definite() {
        let reason = "no ready schedulable node satisfies the Job capabilities";
        match placement_failure(
            "odin_kube.workload.create",
            odin_kube::KubeError::unavailable(reason),
        ) {
            HostToolError::Unavailable { reason: kept, .. } => assert_eq!(kept, reason),
            other => panic!("a pre-create placement refusal must be definite, got {other:?}"),
        }
    }

    #[test]
    fn campaign_intent_recovers_before_reservation() {
        let root = tempfile::tempdir().unwrap();
        let queue = LaunchQueue::new(root.path().join("queue"));
        odin_ledger::campaign::record_approval(
            root.path(),
            "c",
            &serde_json::json!({
                "campaign":"c", "box":{"x":[0.0,2.0]}, "rung":"r", "cases":1,
                "core_hours":1.0, "nodes":["mini"]
            }),
        )
        .unwrap();
        let intent = CampaignBatchIntent {
            operation: "batch".into(),
            scope: Scope::default(),
            arguments: serde_json::json!({}),
            launches: vec![held("one", "kubert", Some("batch"), 0)],
            campaign: "c".into(),
            reservations: vec![odin_ledger::campaign::Reservation {
                operation_id: "one".into(),
                node: "mini".into(),
                profile: "cfd".into(),
                rung: "r".into(),
                point: [("x".into(), 1.0)].into_iter().collect(),
                core_hours: 1.0,
                stage_sha256: "a".repeat(64),
            }],
        };
        let intents = root.path().join("queue/campaign-intents");
        std::fs::create_dir_all(&intents).unwrap();
        std::fs::write(
            intents.join("batch.json"),
            serde_json::to_vec(&intent).unwrap(),
        )
        .unwrap();
        assert_eq!(queue.held().unwrap().len(), 1);
        assert_eq!(
            odin_ledger::campaign::lookup(root.path(), "one").unwrap().2,
            "reserved"
        );
    }

    #[test]
    fn campaign_intent_recovers_reserved_partial_batch_after_reopen() {
        let root = tempfile::tempdir().expect("state dir");
        let queue = LaunchQueue::new(root.path().join("queue"));
        let approval = serde_json::json!({"campaign":"c", "box":{"x":[0.0,2.0]}, "rung":"r", "cases":2, "core_hours":2.0, "nodes":["mini"]});
        odin_ledger::campaign::record_approval(root.path(), "c", &approval).unwrap();
        let reservation = |operation: &str| odin_ledger::campaign::Reservation {
            operation_id: operation.into(),
            node: "mini".into(),
            profile: "cfd".into(),
            rung: "r".into(),
            point: [("x".into(), 1.0)].into_iter().collect(),
            core_hours: 1.0,
            stage_sha256: "a".repeat(64),
        };
        let launches = vec![
            held("one", "kubert", Some("batch"), 0),
            held("two", "kubert", Some("batch"), 0),
        ];
        let intent = CampaignBatchIntent {
            operation: "batch".into(),
            scope: Scope::default(),
            arguments: serde_json::json!({"profile":"cfd"}),
            launches: launches.clone(),
            campaign: "c".into(),
            reservations: vec![reservation("one"), reservation("two")],
        };
        let intents = root.path().join("queue/campaign-intents");
        std::fs::create_dir_all(&intents).unwrap();
        std::fs::write(
            intents.join("batch.json"),
            serde_json::to_vec(&intent).unwrap(),
        )
        .unwrap();
        odin_ledger::campaign::reserve(root.path(), "c", &intent.reservations).unwrap();
        queue.hold(launches[0].clone()).unwrap();
        let reopened = LaunchQueue::new(root.path().join("queue"));
        assert_eq!(reopened.held().unwrap().len(), 2);
        assert!(!intents.join("batch.json").exists());
        assert!(root.path().join("queue/batches/batch.json").exists());
        assert_eq!(
            odin_ledger::campaign::pending(root.path()).unwrap().len(),
            2
        );
        assert_eq!(reopened.held().unwrap().len(), 2);
    }

    #[test]
    fn create_many_replayed_with_the_same_operation_queues_nothing_new() {
        let dir = tempfile::tempdir().expect("queue dir");
        let queue = LaunchQueue::new(dir.path().to_path_buf());
        let operation = OperationId::new("batch-op").expect("operation");
        let invocation = HostInvocation {
            scope: Scope::default(),
            arguments: serde_json::json!({"profile":"cfd"}),
        };
        let launches = vec![held("child", "kubert", Some("batch-op"), 1)];
        queue
            .hold_batch(&operation, &invocation, &launches)
            .expect("hold");
        let (path, item) = queue.held().expect("held").pop().expect("item");
        assert!(queue.claim(&path, &item).expect("claim"));
        queue
            .hold_batch(&operation, &invocation, &launches)
            .expect("replay");
        assert!(queue.held().expect("held").is_empty());
        let changed = HostInvocation {
            scope: Scope::default(),
            arguments: serde_json::json!({"profile":"other"}),
        };
        assert!(queue.hold_batch(&operation, &changed, &launches).is_err());
    }

    #[test]
    fn held_operation_replay_rejects_different_input() {
        let dir = tempfile::tempdir().expect("queue dir");
        let queue = LaunchQueue::new(dir.path().to_path_buf());
        let launch = held("op", "operator", None, 0);
        queue.hold(launch.clone()).expect("hold");
        queue.hold(launch.clone()).expect("replay");
        let mut changed = launch;
        changed.arguments = serde_json::json!({"profile": "other"});
        assert!(queue.hold(changed).is_err());
    }

    #[test]
    fn a_claim_excludes_a_competing_drop_and_survives_reopening() {
        let dir = tempfile::tempdir().expect("queue dir");
        let queue = LaunchQueue::new(dir.path().to_path_buf());
        queue.hold(held("op", "kubert", None, 0)).expect("hold");
        let (path, launch) = queue.held().expect("held").pop().expect("item");
        assert!(queue.claim(&path, &launch).expect("claim"));
        let reopened = LaunchQueue::new(dir.path().to_path_buf());
        assert!(!reopened.claim(&path, &launch).expect("second claim"));
        let seat = odin_domain::SeatId::new("kubert").expect("seat");
        assert!(reopened
            .drop_held(&seat, &HeldSelector::Operation("op".into()))
            .expect("drop")
            .is_empty());
        assert!(reopened.held().expect("held").is_empty());
        assert!(reopened.hold(launch).is_err());
    }

    #[test]
    fn queue_lists_and_drops_only_the_callers_held_launches() {
        let dir = tempfile::tempdir().expect("queue dir");
        let queue = LaunchQueue::new(dir.path().to_path_buf());
        std::fs::create_dir_all(dir.path().join("batches")).expect("batch dir");
        std::fs::write(dir.path().join("batches/sweep.json"), b"{}").expect("batch record");
        for launch in [
            held("op-a", "kubert", Some("sweep"), 1),
            held("op-b", "kubert", Some("sweep"), 2),
            held("op-c", "kubert", None, 3),
            held("op-d", "sinmara", Some("sweep"), 4),
        ] {
            let bytes = serde_json::to_vec(&launch).expect("json");
            std::fs::write(
                dir.path().join(format!("{}.json", launch.operation_id)),
                bytes,
            )
            .expect("held file");
        }
        let kubert = odin_domain::SeatId::new("kubert").expect("seat id");
        let listed = queue_answer(&queue, &kubert, None).expect("list");
        let operations: Vec<&str> = listed
            .held
            .iter()
            .flatten()
            .map(|row| row.operation.as_str())
            .collect();
        assert_eq!(operations, ["op-a", "op-b", "op-c"]);
        assert!(listed.validate().is_ok());

        let dropped = queue_answer(&queue, &kubert, Some(&HeldSelector::Batch("sweep".into())))
            .expect("drop");
        assert_eq!(
            dropped.dropped.as_deref(),
            Some(&["op-a".to_owned(), "op-b".to_owned()][..])
        );
        let left: Vec<String> = queue
            .held()
            .expect("queue")
            .into_iter()
            .map(|(_, launch)| launch.operation_id)
            .collect();
        assert_eq!(
            left,
            ["op-c", "op-d"],
            "another seat's batch item is not dropped"
        );

        let tool = "kube_workload_queue_drop";
        assert!(QueueInput::decode(tool, serde_json::json!({})).is_err());
        assert!(
            QueueInput::decode(tool, serde_json::json!({"batch": "x", "operation": "y"})).is_err()
        );
        assert!(matches!(
            QueueInput::decode(tool, serde_json::json!({"operation": "op-c"})),
            Ok(HeldSelector::Operation(_))
        ));
    }

    #[test]
    fn a_stored_launch_without_batch_fields_replays_as_a_single_create() {
        let stored = serde_json::json!({
            "operation_id": "op-old",
            "timeout_seconds": 130,
            "scope": {},
            "arguments": {"profile": "research"},
            "held_at_ms": 5
        });
        let launch: QueuedLaunch = serde_json::from_value(stored).expect("replay");
        assert_eq!((launch.batch, launch.queue_caps), (None, false));
    }
}
