//! Offload: a script profile's run on a declared compute target (an HPC login under Slurm, a
//! lab box or a container rental over ssh) instead of as a Job. Odin stays generic: the run is
//! the profile's declared command over its staged inputs.
//!
//! - A `kube.workload.create` of a profile with `[offload]` journals an [`OffloadRun`] (one
//!   JSON file per run) instead of a Job: its inputs and a rendered `run.sh` are copied to
//!   `<remote_root>/<job name>/`, then submitted with `sbatch` or `systemd-run --user`.
//! - Each target's `poll_seconds` the pump reads the run's scheduler state and the last 400
//!   lines of its timestamped log in one ssh round trip. The log carries the same
//!   `ODIN-STATUS` and `ODIN-CHECKPOINT` lines a pod prints: the simulation board follows the
//!   run as a mission on node `offload-<target>`, and the profile's watchdogs evaluate every
//!   new status sample.
//! - Slurm usage is charged from its job-level `sacct` start and elapsed seconds, with a
//!   durable usage cursor; missing final accounting delays completion instead of estimating it.
//!   SSH targets continue to charge observed active intervals.
//! - A stop sends TERM (`scancel --signal=TERM --full`, `systemctl --user kill`) and, after
//!   the target's `stop_grace_seconds`, the hard stop.
//! - A finished run's `export/` is copied into the profile's export host folder under the same
//!   run subfolder a Job uses.
//! - A target that declares a `control_master` is unavailable while that master is down; its
//!   runs wait and are read again once it is back.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use odin_domain::huginn::{KubeResourceRef, KubeWorkloadState};
use odin_domain::{NodeId, RunId};
use odin_kube::JobLaunch;
use odin_registry::{
    ComputeExecutor, ComputeTargetToml, ObjectConfig, RegistryKind, WorkloadProfileToml,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::workload_monitor::{AlertTracker, MonitorProfile};

#[path = "offload/accounting.rs"]
mod accounting;
use accounting::parse_slurm_allocations;
#[cfg(test)]
use accounting::{parse_slurm_duration, parse_slurm_elapsed};

#[path = "offload/transport.rs"]
mod transport;
use transport::{run_script, submit_script};

/// How a run on a target stands, as the board and the kube views read it.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum OffloadState {
    Pending,
    Running,
    Suspended,
    Succeeded,
    Failed,
    Aborted,
}

impl OffloadState {
    pub(crate) fn finished(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Aborted)
    }

    fn workload_state(self) -> KubeWorkloadState {
        match self {
            Self::Pending => KubeWorkloadState::Pending,
            Self::Running => KubeWorkloadState::Running,
            Self::Suspended => KubeWorkloadState::Suspended,
            Self::Succeeded => KubeWorkloadState::Succeeded,
            Self::Failed => KubeWorkloadState::Failed,
            Self::Aborted => KubeWorkloadState::Terminating,
        }
    }
}

/// One journaled offload run.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct OffloadRun {
    pub run_id: RunId,
    pub profile: String,
    #[serde(default)]
    pub seat_id: Option<odin_domain::SeatId>,
    #[serde(default)]
    pub project_id: Option<odin_domain::ProjectId>,
    #[serde(default)]
    pub control: Option<odin_registry::WorkloadControlToml>,
    pub target: String,
    /// The run's folder on the target, also the name of its export subfolder.
    pub name: String,
    pub remote_dir: String,
    /// The Slurm job id or the transient systemd unit.
    pub job: String,
    pub state: OffloadState,
    pub submitted_at: OffsetDateTime,
    /// Lane budgets charged for this run, including its caller's budget lane.
    #[serde(default)]
    pub lanes: Vec<String>,
    #[serde(default)]
    pub cores: u32,
    #[serde(default)]
    pub gpus: u32,
    #[serde(default)]
    pub deadline_seconds: u32,
    #[serde(default)]
    pub usd_per_hour: f64,
    #[serde(default)]
    pub started_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub active_since: Option<OffsetDateTime>,
    /// Scheduler-reported running time already charged, in seconds.
    #[serde(default)]
    pub elapsed_seconds: u64,
    /// Duration already included in `elapsed_seconds` for the current SSH active interval.
    #[serde(default)]
    pub active_elapsed_ms: u64,
    #[serde(default)]
    pub watchdog_after: Option<OffsetDateTime>,
    #[serde(default)]
    pub finished_at: Option<OffsetDateTime>,
    /// Host folder the export lands in, under `name`.
    pub export_host_folder: String,
    #[serde(default)]
    pub exported: bool,
    /// When TERM was sent; the hard stop follows after the target's grace.
    #[serde(default)]
    pub stopping_since: Option<OffsetDateTime>,
    #[serde(default)]
    pub hard_stopped: bool,
    #[serde(default)]
    pub detail: Option<String>,
    /// A restart was dispatched but its outcome has not yet been recorded.
    #[serde(default)]
    pub restart_inflight: bool,
    #[serde(default)]
    pub absolute_deadline_enforced: bool,
    #[serde(default)]
    pub(super) stall: Option<super::workload_recovery::StallState>,
    #[serde(default)]
    pub restart_pending: bool,
    #[serde(default)]
    pub restart_generation: u32,
}

impl OffloadRun {
    pub(crate) fn remaining_seconds(&self) -> u64 {
        u64::from(self.deadline_seconds).saturating_sub(self.elapsed_seconds)
    }

    pub(crate) fn node_id(&self) -> Option<NodeId> {
        NodeId::new(format!("offload:{}", self.target)).ok()
    }

    pub(crate) fn resource(&self) -> KubeResourceRef {
        KubeResourceRef {
            cluster: "offload".to_owned(),
            api_version: "odin.dev/v1".to_owned(),
            kind: "OffloadRun".to_owned(),
            namespace: Some(self.target.clone()),
            name: self.name.clone(),
            uid: self.run_id.as_str().to_owned(),
        }
    }

    pub(crate) fn workload_state(&self) -> KubeWorkloadState {
        self.state.workload_state()
    }
}

/// Why a launch did not go to a target.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum OffloadRefusal {
    /// Every admitted target is at its `max_concurrent` or unavailable: the launch waits.
    Full(String),
    /// The launch cannot run on any declared target.
    Refused(String),
}

/// How commands reach a target. Tests use a local shell over the same scripts, with fake
/// scheduler tools first on its PATH.
#[derive(Clone, Debug)]
pub(crate) enum Transport {
    Ssh {
        ssh: PathBuf,
        rsync: PathBuf,
    },
    #[cfg(test)]
    Local {
        path: PathBuf,
    },
}

/// The registry as published now; read on every use, so a changed target applies at once.
pub(crate) type SnapshotReader = Arc<dyn Fn() -> Arc<odin_registry::Snapshot> + Send + Sync>;

/// The daemon's offload executor.
pub(crate) struct Offload {
    dir: PathBuf,
    transport: Transport,
    snapshot: SnapshotReader,
    huginn_root: PathBuf,
    submit_lock: tokio::sync::Mutex<()>,
    action_lock: tokio::sync::Mutex<()>,
    runs: Mutex<BTreeMap<RunId, OffloadRun>>,
    alerts: Mutex<Vec<WatchdogEvent>>,
    drained: Mutex<BTreeSet<String>>,
    stall_events: Mutex<Vec<(OffloadRun, String, f64, super::workload_recovery::StallStep)>>,
}

struct WatchdogEvent {
    run: OffloadRun,
    alert: odin_registry::schema::ContainerAlertToml,
    value: f64,
}

fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

fn unix_seconds(at: OffsetDateTime) -> i64 {
    at.unix_timestamp()
}

impl Offload {
    /// Loads every journaled run under `dir`.
    pub(crate) fn open(
        dir: PathBuf,
        huginn_root: PathBuf,
        transport: Transport,
        snapshot: SnapshotReader,
    ) -> Result<Self, String> {
        let runs_dir = dir.join("runs");
        std::fs::create_dir_all(&runs_dir)
            .map_err(|error| format!("offload state {} is unavailable: {error}", dir.display()))?;
        let mut runs = BTreeMap::new();
        for entry in std::fs::read_dir(&runs_dir).map_err(|error| error.to_string())? {
            let path = entry.map_err(|error| error.to_string())?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let bytes = std::fs::read(&path).map_err(|error| {
                format!("offload run {} is unreadable: {error}", path.display())
            })?;
            let run: OffloadRun = serde_json::from_slice(&bytes)
                .map_err(|error| format!("offload run {} is malformed: {error}", path.display()))?;
            runs.insert(run.run_id.clone(), run);
        }
        let drained = match std::fs::read(dir.join("drained-targets.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| format!("offload drain state malformed: {error}"))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeSet::new(),
            Err(error) => return Err(format!("offload drain state unreadable: {error}")),
        };
        Ok(Self {
            dir,
            transport,
            snapshot,
            huginn_root,
            submit_lock: tokio::sync::Mutex::new(()),
            action_lock: tokio::sync::Mutex::new(()),
            runs: Mutex::new(runs),
            alerts: Mutex::new(Vec::new()),
            drained: Mutex::new(drained),
            stall_events: Mutex::new(Vec::new()),
        })
    }

    fn save(&self, run: &OffloadRun) -> Result<(), String> {
        let path = self.dir.join("runs").join(format!("{}.json", run.name));
        let bytes = serde_json::to_vec_pretty(run).map_err(|error| error.to_string())?;
        odin_cli::authority_provision::write_private_atomic(&path, &bytes)?;
        if let Ok(mut runs) = self.runs.lock() {
            runs.insert(run.run_id.clone(), run.clone());
        }
        Ok(())
    }

    pub(crate) fn run(&self, run_id: &RunId) -> Option<OffloadRun> {
        self.runs.lock().ok()?.get(run_id).cloned()
    }

    pub(crate) fn runs(&self) -> Vec<OffloadRun> {
        self.runs
            .lock()
            .map(|runs| runs.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Blocks new submissions before checking for in-flight work, durably across restarts.
    pub(crate) async fn drain_target(&self, id: &str) -> Result<bool, String> {
        let _guard = self.submit_lock.lock().await;
        let mut drained = self.drained.lock().map_err(|error| error.to_string())?;
        let mut next = drained.clone();
        next.insert(id.to_owned());
        let bytes = serde_json::to_vec(&next).map_err(|error| error.to_string())?;
        odin_cli::authority_provision::write_private_atomic(
            &self.dir.join("drained-targets.json"),
            &bytes,
        )?;
        *drained = next;
        Ok(self.active_on(id) == 0)
    }

    pub(crate) async fn release_target(&self, id: &str) -> Result<(), String> {
        let _guard = self.submit_lock.lock().await;
        let mut drained = self.drained.lock().map_err(|error| error.to_string())?;
        let mut next = drained.clone();
        next.remove(id);
        let bytes = serde_json::to_vec(&next).map_err(|error| error.to_string())?;
        odin_cli::authority_provision::write_private_atomic(
            &self.dir.join("drained-targets.json"),
            &bytes,
        )?;
        *drained = next;
        Ok(())
    }

    fn target(&self, id: &str) -> Option<ComputeTargetToml> {
        (self.snapshot)()
            .listed_objects(RegistryKind::ComputeTarget)
            .find_map(|object| match &object.config {
                ObjectConfig::ComputeTarget(target) if object.id == id && target.enabled => {
                    Some(target.as_ref().clone())
                }
                _ => None,
            })
            .or_else(
                || match odin_registry::RentalTargets::get(&self.huginn_root, id) {
                    Ok(target) => target,
                    Err(error) => {
                        tracing::error!("rental target {id} unreadable: {error}");
                        None
                    }
                },
            )
    }

    fn active_on(&self, id: &str) -> usize {
        self.runs
            .lock()
            .map(|runs| {
                runs.values()
                    .filter(|run| run.target == id && !run.state.finished())
                    .count()
            })
            .unwrap_or(usize::MAX)
    }

    /// The first of the profile's targets that admits it and has room.
    async fn choose(
        &self,
        profile: &WorkloadProfileToml,
    ) -> Result<(String, ComputeTargetToml), OffloadRefusal> {
        let Some(offload) = &profile.offload else {
            return Err(OffloadRefusal::Refused(
                "the profile declares no offload".to_owned(),
            ));
        };
        let mut waiting = Vec::new();
        // Targets that can never take this profile, apart from ones that are only busy now.
        let mut refused = Vec::new();
        let mut candidates = Vec::new();
        for alias in &offload.targets {
            // Only a current enabled declaration authorizes its rental children. Their
            // connection pins are leased, but their admission policy is the live alias policy.
            let Some(template) = (self.snapshot)()
                .listed_objects(RegistryKind::ComputeTarget)
                .find_map(|object| match &object.config {
                    ObjectConfig::ComputeTarget(target)
                        if object.id == *alias && target.enabled =>
                    {
                        Some(target.as_ref().clone())
                    }
                    _ => None,
                })
            else {
                waiting.push(format!("{alias} is not an enabled compute target"));
                continue;
            };
            let children = odin_registry::RentalTargets::children(&self.huginn_root, alias)
                .map_err(|error| {
                    OffloadRefusal::Refused(format!("rental targets unreadable: {error}"))
                })?;
            for (id, child, project) in children {
                if project != profile.seat.project.as_str()
                    || !template.allowed_projects.contains(&project)
                {
                    continue;
                }
                let mut target = template.clone();
                target.ssh_host = child.ssh_host;
                target.ssh_port = child.ssh_port;
                target.known_host = child.known_host;
                target.allowed_projects = BTreeSet::from([project]);
                // The rental lease accounts the whole machine independently of its runs.
                target.cost = None;
                candidates.push((id, target));
            }
            candidates.push((alias.clone(), template));
        }
        for (id, target) in &candidates {
            if self
                .drained
                .lock()
                .map_or(true, |drained| drained.contains(id))
            {
                waiting.push(format!("{id} is draining"));
                continue;
            }
            if !target
                .allowed_projects
                .contains(profile.seat.project.as_str())
            {
                waiting.push(format!(
                    "{id} does not admit project {}",
                    profile.seat.project
                ));
                continue;
            }
            if offload.restricted_data && !target.restricted_data {
                refused.push(format!("{id} does not take restricted data"));
                continue;
            }
            if let (Some(cap), Some(resources)) =
                (target.max_core_hours_per_run, &profile.resources)
            {
                let deadline = profile
                    .lifetime
                    .as_ref()
                    .map_or(0, |lifetime| u64::from(lifetime.deadline_seconds));
                let core_seconds = u64::from(resources.cpu) * deadline;
                if core_seconds > u64::from(cap.get()) * 3600 {
                    refused.push(format!(
                    "{id} takes at most {cap} core-hours a run; {} cores for {deadline}s exceeds it",
                        resources.cpu
                    ));
                    continue;
                }
            }
            if profile.gpu_count > target.gpus {
                waiting.push(format!("{id} offers {} GPUs per run", target.gpus));
                continue;
            }
            if let Some(reason) = self.unavailable(id, target).await {
                waiting.push(reason);
                continue;
            }
            let active = self.active_on(id);
            if active >= target.max_concurrent.get() as usize {
                waiting.push(format!("{id} runs {active} of {}", target.max_concurrent));
                continue;
            }
            return Ok((id.clone(), target.clone()));
        }
        if waiting.is_empty() {
            return Err(OffloadRefusal::Refused(refused.join("; ")));
        }
        waiting.extend(refused);
        Err(OffloadRefusal::Full(waiting.join("; ")))
    }

    /// Stages and submits a launch. An existing run of the same id is left as it is.
    pub(crate) async fn submit(
        &self,
        launch: &JobLaunch,
        profile_id: &str,
        profile: &WorkloadProfileToml,
        files: Vec<(String, Vec<u8>)>,
    ) -> Result<OffloadRun, OffloadRefusal> {
        let _submission = self.submit_lock.lock().await;
        if let Some(run) = self.run(&launch.labels.run_id) {
            return if run.job.is_empty() {
                Err(OffloadRefusal::Refused(format!(
                    "offload submission for {} has an unknown outcome on {}; reconcile it before retrying",
                    run.run_id, run.target
                )))
            } else {
                Ok(run)
            };
        }
        if launch.deadline_seconds.is_none() {
            return Err(OffloadRefusal::Refused(
                "an offload run needs its profile's lifetime.deadline_seconds".to_owned(),
            ));
        }
        let (id, target) = self.choose(profile).await?;
        let name = launch.job_name();
        let remote_dir = format!("{}/{name}", target.remote_root.trim_end_matches('/'));
        let stage = self.dir.join("stage").join(&name);
        let refuse = |detail: String| OffloadRefusal::Refused(detail);
        let submitted_at = OffsetDateTime::now_utc();
        let deadline_at = submitted_at
            .unix_timestamp()
            .saturating_add(i64::from(launch.deadline_seconds.unwrap_or_default()));
        let write = || -> Result<(), String> {
            let inputs = stage.join("in");
            std::fs::create_dir_all(&inputs).map_err(|error| error.to_string())?;
            for (file, bytes) in &files {
                std::fs::write(inputs.join(file), bytes).map_err(|error| error.to_string())?;
            }
            if profile.control.is_some() {
                let control = stage.join("control");
                std::fs::create_dir_all(&control).map_err(|error| error.to_string())?;
                std::fs::write(
                    control.join("control.json"),
                    b"{\"seq\":0,\"operation\":\"\"}",
                )
                .map_err(|error| error.to_string())?;
            }
            std::fs::write(
                stage.join("run.sh"),
                run_script(&target, launch, profile, &remote_dir, deadline_at),
            )
            .map_err(|error| error.to_string())
        };
        write().map_err(|error| refuse(format!("offload staging failed: {error}")))?;
        let export_host_folder = launch
            .workload
            .as_ref()
            .map(|plan| plan.export_host_folder.clone())
            .unwrap_or_else(|| profile.export.host_folder.clone());
        let mut run = OffloadRun {
            run_id: launch.labels.run_id.clone(),
            profile: profile_id.to_owned(),
            seat_id: Some(launch.labels.seat_id.clone()),
            project_id: Some(launch.labels.project_id.clone()),
            control: profile.control.clone(),
            target: id,
            name,
            remote_dir,
            job: String::new(),
            state: OffloadState::Pending,
            submitted_at,
            lanes: {
                let mut lanes = vec![launch.labels.lane_id.to_string()];
                if let Some(lane) = &launch.budget_lane {
                    let lane = lane.to_string();
                    if !lanes.contains(&lane) {
                        lanes.push(lane);
                    }
                }
                lanes
            },
            cores: profile
                .resources
                .as_ref()
                .map_or(0, |resources| resources.cpu),
            gpus: launch.gpu_count,
            deadline_seconds: launch.deadline_seconds.unwrap_or_default(),
            usd_per_hour: target.cost.as_ref().map_or(0.0, |cost| {
                cost.usd_per_hour.unwrap_or_default()
                    + cost.usd_per_core_hour.unwrap_or_default()
                        * f64::from(
                            profile
                                .resources
                                .as_ref()
                                .map_or(0, |resources| resources.cpu),
                        )
            }),
            started_at: None,
            active_since: None,
            elapsed_seconds: 0,
            active_elapsed_ms: 0,
            watchdog_after: None,
            finished_at: None,
            export_host_folder,
            exported: false,
            stopping_since: None,
            hard_stopped: false,
            detail: None,
            restart_inflight: false,
            absolute_deadline_enforced: true,
            stall: None,
            restart_pending: false,
            restart_generation: 0,
        };
        let staged = async {
            self.remote(
                &run.target,
                &target,
                &format!("mkdir -p {}", quote(&run.remote_dir)),
            )
            .await?;
            self.copy(
                &run.target,
                &target,
                &format!("{}/", stage.display()),
                &format!("{}/", run.remote_dir),
                false,
            )
            .await
        }
        .await;
        if let Err(error) = staged {
            let _ = std::fs::remove_dir_all(&stage);
            return Err(refuse(format!("offload staging failed: {error}")));
        }
        // Persist intent before the scheduler can accept work. An interrupted or ambiguous
        // submission stays visible and is never automatically submitted a second time.
        self.save(&run).map_err(refuse)?;
        let submitted = self
            .remote(
                &run.target,
                &target,
                &submit_script(&target, launch, &run.name, &run.remote_dir),
            )
            .await;
        let _ = std::fs::remove_dir_all(&stage);
        let output = submitted.map_err(|error| {
            refuse(format!(
                "offload submission outcome is unknown for {}: {error}",
                run.run_id
            ))
        })?;
        let job = output
            .trim()
            .split(';')
            .next()
            .unwrap_or_default()
            .to_owned();
        run.job = match target.executor {
            ComputeExecutor::Slurm
                if !job.is_empty() && job.chars().all(|c| c.is_ascii_digit()) =>
            {
                job
            }
            ComputeExecutor::Slurm => {
                return Err(refuse(format!(
                    "offload submission outcome is unknown for {}: sbatch answered {job:?}",
                    run.run_id
                )))
            }
            ComputeExecutor::Ssh => unit_name(&run.name),
        };
        self.save(&run).map_err(refuse)?;
        tracing::info!(
            "offload run submitted run={} target={} job={}",
            run.run_id,
            run.target,
            run.job
        );
        Ok(run)
    }
    /// Schema-check and compare-and-swap a run's control document on the target.
    pub(crate) async fn steer(
        &self,
        run: &OffloadRun,
        expected: u64,
        document: serde_json::Value,
        operation: &str,
        by: &str,
    ) -> Result<odin_kube::control::SteerApplied, String> {
        if run.state.finished() || run.job.is_empty() {
            return Err("the offload run is not active".to_owned());
        }
        run.control
            .as_ref()
            .ok_or("the run declares no control channel")?
            .admit(&document)?;
        let target = self
            .target(&run.target)
            .ok_or("the compute target is unavailable")?;
        if let Some(reason) = self.unavailable(&run.target, &target).await {
            return Err(reason);
        }
        let path = format!("{}/control/control.json", run.remote_dir);
        let old = self
            .remote(&run.target, &target, &format!("cat {}", quote(&path)))
            .await?;
        let current: odin_kube::control::ControlDocument = serde_json::from_str(&old)
            .map_err(|error| format!("invalid control document: {error}"))?;
        if current.operation.as_deref() == Some(operation) {
            return Ok(odin_kube::control::SteerApplied {
                seq: current.seq,
                duplicate: true,
            });
        }
        if current.seq != expected {
            return Err(format!(
                "stale control sequence: expected {expected}, current {}",
                current.seq
            ));
        }
        let seq = expected
            .checked_add(1)
            .ok_or("control sequence exhausted")?;
        let at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|error| error.to_string())?;
        let next = serde_json::to_string(&odin_kube::control::ControlDocument {
            seq,
            at: Some(at),
            by: Some(by.to_owned()),
            operation: Some(operation.to_owned()),
            document: Some(document),
        })
        .map_err(|error| error.to_string())?;
        let script = format!("flock -x {lock} sh -c {body}", lock = quote(&format!("{}/control.lock", run.remote_dir)), body = quote(&format!(
            "[ \"$(cat {path})\" = {old} ] || exit 73; printf %s {next} > {tmp} && mv {tmp} {path}",
            path = quote(&path), old = quote(old.trim_end_matches('\n')), next = quote(&next), tmp = quote(&format!("{path}.tmp"))
        )));
        self.remote(&run.target, &target, &script).await?;
        Ok(odin_kube::control::SteerApplied {
            seq,
            duplicate: false,
        })
    }

    async fn restart_stalled(&self, run_id: &RunId) -> Result<(), String> {
        let _guard = self.action_lock.lock().await;
        let mut run = self.run(run_id).ok_or("offload run is missing")?;
        if run.state.finished() || run.job.is_empty() || run.stopping_since.is_some() {
            return Err("run is not active".to_owned());
        }
        if !run.absolute_deadline_enforced {
            return Err("run predates absolute-deadline enforcement".to_owned());
        }
        if run.restart_inflight {
            return Err(
                "previous restart outcome is unknown; operator reconciliation is required"
                    .to_owned(),
            );
        }
        if !run.restart_pending {
            return Err("no restart decision is pending".to_owned());
        }
        if OffsetDateTime::now_utc().unix_timestamp()
            >= run
                .submitted_at
                .unix_timestamp()
                .saturating_add(i64::from(run.deadline_seconds))
        {
            return Err("the run's original deadline has elapsed".to_owned());
        }
        let target = self.target(&run.target).ok_or("target unavailable")?;
        if let Some(reason) = self.unavailable(&run.target, &target).await {
            return Err(reason);
        }
        // Persist before the irreversible scheduler action. An uncertain outcome is never replayed.
        run.restart_pending = false;
        run.restart_inflight = true;
        run.restart_generation = run
            .restart_generation
            .checked_add(1)
            .ok_or("restart generation exhausted")?;
        self.save(&run)?;
        let script = match target.executor {
            ComputeExecutor::Slurm => format!("scontrol requeue {}", quote(&run.job)),
            ComputeExecutor::Ssh => format!("systemctl --user restart {}", quote(&run.job)),
        };
        self.remote(&run.target, &target, &script)
            .await
            .map_err(|error| format!("restart outcome unknown: {error}"))?;
        run.restart_inflight = false;
        self.save(&run)?;
        Ok(())
    }

    /// Sends TERM now; the pump issues the hard stop after the target's grace.
    pub(crate) async fn stop(&self, run_id: &RunId) -> Result<OffloadRun, String> {
        let _guard = self.action_lock.lock().await;
        let mut run = self
            .run(run_id)
            .ok_or_else(|| format!("{run_id} is not an offload run"))?;
        if run.job.is_empty() {
            return Err(format!(
                "offload submission outcome for {run_id} is unknown; reconcile it first"
            ));
        }
        if run.state.finished() || run.stopping_since.is_some() {
            return Ok(run);
        }
        let target = self
            .target(&run.target)
            .ok_or_else(|| format!("compute target {} is no longer declared", run.target))?;
        let script = match target.executor {
            ComputeExecutor::Slurm => format!("scancel --signal=TERM --full {}", quote(&run.job)),
            ComputeExecutor::Ssh => {
                format!(
                    "systemctl --user kill --signal=TERM {} || true",
                    quote(&run.job)
                )
            }
        };
        self.remote(&run.target, &target, &script).await?;
        run.stopping_since = Some(OffsetDateTime::now_utc());
        run.restart_pending = false;
        run.restart_inflight = false;
        self.save(&run)?;
        Ok(run)
    }

    /// One read of one run: its new state, and its log tail when it has one.
    async fn read(
        &self,
        run: &OffloadRun,
        target: &ComputeTargetToml,
    ) -> Result<(String, String, Option<Vec<(String, u64, u64)>>), String> {
        let state = match target.executor {
            ComputeExecutor::Slurm => format!(
                "s=$(squeue -h -j {job} -o %T 2>/dev/null | head -n 1); \
                 [ -n \"$s\" ] || s=$(sacct -n -X -P -j {job} -o State 2>/dev/null | head -n 1); echo \"$s\"",
                job = quote(&run.job)
            ),
            ComputeExecutor::Ssh => format!(
                "systemctl --user show -p ActiveState --value {} 2>/dev/null",
                quote(&run.job)
            ),
        };
        let accounting = match target.executor {
            ComputeExecutor::Slurm => format!(
                "TZ=UTC SLURM_TIME_FORMAT=%s sacct -n -X -P -D -j {} -o SLUID,Submit,Start,ElapsedRaw,Suspended 2>/dev/null | tr '\\n' ';'",
                quote(&run.job)
            ),
            ComputeExecutor::Ssh => "true".to_owned(),
        };
        let script = format!(
            "cd {dir} 2>/dev/null || {{ echo 'STATE MISSING'; echo ACCOUNTING; echo ---; exit 0; }}; \
             state=$({state}); case \"$state\" in PENDING|RUNNING|REQUEUED|CONFIGURING|SUSPENDED|COMPLETING|active|activating|reloading|deactivating) echo \"STATE $state\" ;; *) if [ -f exit ]; then echo \"EXIT $(cat exit)\"; else echo \"STATE $state\"; fi ;; esac; \
             echo \"ACCOUNTING $({accounting})\"; echo ---; tail -n {lines} log 2>/dev/null; true",
            lines = target.log_tail_lines(),
            dir = quote(&run.remote_dir),
        );
        let output = self.remote(&run.target, target, &script).await?;
        let (header, log) = output.split_once("---\n").unwrap_or((output.as_str(), ""));
        let (head, accounting) = header.split_once('\n').unwrap_or((header, ""));
        let elapsed = accounting
            .trim()
            .strip_prefix("ACCOUNTING ")
            .and_then(|rows| parse_slurm_allocations(rows, run.submitted_at.unix_timestamp()));
        Ok((head.trim().to_owned(), log.to_owned(), elapsed))
    }

    /// Reads each unfinished run, follows its state, evaluates its watchdogs, copies a
    /// finished run's export home, and answers the runs with their log tails.
    async fn poll(
        &self,
        due: impl Fn(&OffloadRun, &ComputeTargetToml) -> bool,
        monitors: &mut AlertTracker,
    ) -> Vec<(OffloadRun, String)> {
        let mut observed = Vec::new();
        'runs: for mut run in self.runs() {
            if run.job.is_empty() {
                tracing::error!(
                    "offload submission outcome unknown run={} target={}",
                    run.run_id,
                    run.target
                );
                observed.push((run, String::new()));
                continue;
            }
            if run.restart_inflight {
                tracing::error!(
                    "offload restart outcome unknown run={} target={}",
                    run.run_id,
                    run.target
                );
                observed.push((run, String::new()));
                continue;
            }
            if run.restart_pending {
                observed.push((run, String::new()));
                continue;
            }
            if run.state.finished() && run.exported {
                continue;
            }
            let Some(target) = self.target(&run.target) else {
                continue;
            };
            if !due(&run, &target) {
                continue;
            }
            if let Some(reason) = self.unavailable(&run.target, &target).await {
                tracing::warn!("offload run {} waits: {reason}", run.run_id);
                continue;
            }
            let mut log = String::new();
            if !run.state.finished() {
                match self.read(&run, &target).await {
                    Ok((head, tail, elapsed)) => {
                        if head.trim() == "STATE" {
                            tracing::warn!("offload run {} has no scheduler state yet", run.run_id);
                            continue;
                        }
                        let now = OffsetDateTime::now_utc();
                        match target.executor {
                            ComputeExecutor::Slurm => {
                                if let Some(rows) = elapsed.as_ref() {
                                    if rows.iter().all(|(_, start, _)| *start == 0)
                                        && run.started_at.is_some()
                                    {
                                        tracing::warn!(
                                            "offload run {} awaits Slurm start accounting",
                                            run.run_id
                                        );
                                        continue 'runs;
                                    }
                                    let observed_ms =
                                        (now.unix_timestamp_nanos() / 1_000_000).max(0) as u64;
                                    let total =
                                        rows.iter().map(|(_, _, active)| *active / 1_000).sum();
                                    if let Err(error) = odin_registry::ComputeUsage::update(
                                        &self.huginn_root,
                                        |usage| {
                                            for (id, start, active_ms) in rows {
                                                if *start == 0 {
                                                    continue;
                                                }
                                                let seconds = *active_ms as f64 / 1_000.0;
                                                let source = format!(
                                                    "offload:{}:slurm-total:{}",
                                                    run.run_id, id
                                                );
                                                usage.replace_source_total(
                                                    &source,
                                                    &run.lanes,
                                                    observed_ms,
                                                    odin_registry::ComputeCharge {
                                                        core_seconds: seconds
                                                            * f64::from(run.cores),
                                                        gpu_seconds: seconds * f64::from(run.gpus),
                                                        usd: seconds / 3_600.0 * run.usd_per_hour,
                                                    },
                                                );
                                            }
                                        },
                                    ) {
                                        tracing::error!(
                                            "offload run {} accounting failed: {error}",
                                            run.run_id
                                        );
                                        continue 'runs;
                                    }
                                    run.elapsed_seconds = total;
                                } else if state_of(&head, run.stopping_since.is_some())
                                    != OffloadState::Pending
                                {
                                    tracing::warn!(
                                        "offload run {} awaits Slurm elapsed accounting",
                                        run.run_id
                                    );
                                    continue;
                                }
                            }
                            ComputeExecutor::Ssh => {
                                if let Some(since) = run.active_since {
                                    let millis = |at: OffsetDateTime| {
                                        (at.unix_timestamp_nanos() / 1_000_000).max(0) as u64
                                    };
                                    let source =
                                        format!("offload:{}:{}", run.run_id, millis(since));
                                    if let Err(error) = odin_registry::ComputeUsage::update(
                                        &self.huginn_root,
                                        |usage| {
                                            usage.charge_source(
                                                &source,
                                                &run.lanes,
                                                millis(since)..millis(now),
                                                f64::from(run.cores),
                                                f64::from(run.gpus),
                                                run.usd_per_hour,
                                            );
                                        },
                                    ) {
                                        tracing::error!(
                                            "offload run {} accounting failed: {error}",
                                            run.run_id
                                        );
                                        continue;
                                    }
                                    let current_ms = millis(now).saturating_sub(millis(since));
                                    let previous_ms = run.active_elapsed_ms;
                                    run.elapsed_seconds = run.elapsed_seconds.saturating_add(
                                        current_ms / 1_000 - previous_ms.min(current_ms) / 1_000,
                                    );
                                    run.active_elapsed_ms = current_ms.max(previous_ms);
                                }
                            }
                        }
                        let state = state_of(&head, run.stopping_since.is_some());
                        if state == OffloadState::Running && run.active_since.is_none() {
                            run.started_at.get_or_insert(now);
                            run.active_since = Some(now);
                        } else if state != OffloadState::Running {
                            run.active_since = None;
                            run.active_elapsed_ms = 0;
                        }
                        if state != run.state {
                            tracing::info!(
                                "offload run {} {:?} -> {state:?} ({head})",
                                run.run_id,
                                run.state
                            );
                            run.state = state;
                            if state.finished() {
                                run.finished_at = Some(OffsetDateTime::now_utc());
                                run.detail = Some(head.clone());
                            }
                        }
                        log = tail;
                    }
                    Err(error) => {
                        tracing::warn!("offload run {} unread: {error}", run.run_id);
                        continue;
                    }
                }
                if !run.state.finished() {
                    self.watch(&mut run, &log, monitors).await;
                    self.hard_stop_when_due(&mut run, &target).await;
                }
            }
            if run.state.finished() && !run.exported {
                match self.export(&run, &target).await {
                    Ok(()) => run.exported = true,
                    Err(error) => {
                        tracing::warn!("offload run {} export waits: {error}", run.run_id)
                    }
                }
            }
            if let Err(error) = self.save(&run) {
                tracing::error!("offload run {} not journaled: {error}", run.run_id);
            }
            observed.push((run, log));
        }
        observed
    }

    async fn watch(&self, run: &mut OffloadRun, log: &str, monitors: &mut AlertTracker) {
        let profile = (self.snapshot)()
            .listed_objects(RegistryKind::Workload)
            .find_map(|object| match &object.config {
                ObjectConfig::Workload(profile) if object.id == run.profile => {
                    profile.monitoring.clone()
                }
                _ => None,
            });
        let Some(monitor) = profile.as_ref().and_then(MonitorProfile::of_workload) else {
            return;
        };
        if let (Some(stall), Some((_, latest))) =
            (&monitor.stall, odin_kube::telemetry::latest_report(log))
        {
            let counters = odin_kube::telemetry::numeric_counters(&latest);
            if let Some(&value) = counters.get(&stall.counter) {
                let now_ms = OffsetDateTime::now_utc()
                    .unix_timestamp()
                    .saturating_mul(1000);
                let state = run.stall.get_or_insert_with(|| {
                    super::workload_recovery::StallState::new(value, now_ms)
                });
                let stuck = state.high_water();
                let signature = format!("stall:{}:{}", run.profile, stall.counter);
                let window = i64::try_from(stall.window.as_millis()).unwrap_or(i64::MAX);
                let worker = format!("{}:{}", run.job, run.restart_generation);
                match state.observe(value, &worker, now_ms, window, &stall.policy, &signature) {
                    Ok(Some(step)) => {
                        if matches!(
                            &step,
                            super::workload_recovery::StallStep::Act {
                                rung: odin_kernel::recovery::RecoveryRung::RestartWorker,
                                ..
                            }
                        ) {
                            run.restart_pending = true;
                        }
                        // Recovery state and restart intent share this one atomic run journal.
                        if let Err(error) = self.save(run) {
                            tracing::error!(
                                "offload recovery not journaled run={}: {error}",
                                run.run_id
                            );
                        } else if let Ok(mut events) = self.stall_events.lock() {
                            events.push((run.clone(), stall.counter.clone(), stuck, step));
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::error!("offload recovery failed run={}: {error}", run.run_id)
                    }
                }
            }
        }
        let after = run.watchdog_after;
        let samples = log.lines().filter_map(|line| {
            let (stamp, text) = line.split_once(' ')?;
            let stamp =
                OffsetDateTime::parse(stamp, &time::format_description::well_known::Rfc3339)
                    .ok()?;
            if after.is_some_and(|after| stamp <= after) {
                return None;
            }
            let body = text
                .trim()
                .strip_prefix(odin_kube::telemetry::STATUS_PREFIX)?;
            let sample =
                serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(body).ok()?;
            Some((stamp, sample))
        });
        let mut stop = None;
        let mut newest = after;
        for (stamp, sample) in samples {
            newest = Some(newest.map_or(stamp, |old| old.max(stamp)));
            let counters = odin_kube::telemetry::numeric_counters(&sample);
            for (alert, value) in monitors.observe(&run.name, &monitor, &counters, Instant::now()) {
                tracing::warn!(
                    "offload watchdog {} fired run={} value={value}",
                    alert.id,
                    run.run_id
                );
                if let Ok(mut alerts) = self.alerts.lock() {
                    alerts.push(WatchdogEvent {
                        run: run.clone(),
                        alert: alert.clone(),
                        value,
                    });
                }
                if alert.action == odin_registry::schema::ContainerAlertActionToml::Stop {
                    stop = Some(alert.id.clone());
                }
            }
        }
        if let Some(alert) = stop {
            match self.stop(&run.run_id).await {
                Ok(stopped) => {
                    *run = stopped;
                    run.detail = Some(format!("stopped by watchdog {alert}"));
                }
                Err(error) => {
                    tracing::error!("offload watchdog stop failed run={}: {error}", run.run_id)
                }
            }
        }
        run.watchdog_after = newest;
    }

    async fn hard_stop_when_due(&self, run: &mut OffloadRun, target: &ComputeTargetToml) {
        let Some(since) = run.stopping_since else {
            return;
        };
        if run.hard_stopped
            || unix_seconds(OffsetDateTime::now_utc()) - unix_seconds(since)
                < i64::from(target.stop_grace_seconds.get())
        {
            return;
        }
        let script = match target.executor {
            ComputeExecutor::Slurm => format!("scancel {}", quote(&run.job)),
            ComputeExecutor::Ssh => format!("systemctl --user stop {} || true", quote(&run.job)),
        };
        match self.remote(&run.target, target, &script).await {
            Ok(_) => run.hard_stopped = true,
            Err(error) => tracing::warn!("offload hard stop failed run={}: {error}", run.run_id),
        }
    }

    async fn export(&self, run: &OffloadRun, target: &ComputeTargetToml) -> Result<(), String> {
        let local = Path::new(&run.export_host_folder).join(&run.name);
        std::fs::create_dir_all(&local).map_err(|error| error.to_string())?;
        self.copy(
            &run.target,
            target,
            &format!("{}/export/", run.remote_dir),
            &format!("{}/", local.display()),
            true,
        )
        .await
    }
}

/// Reads each run at its target's `poll_seconds` and feeds the simulation board.
pub(crate) fn arm_offload_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    offload: Arc<Offload>,
    desk: Option<Arc<crate::simulation::SimulationDesk>>,
    incidents: Arc<crate::incidents::IncidentDesk>,
    owner: Option<Arc<odin_omp::host_tools::delegation::GovernedTaskOwner>>,
    runtime: Option<Arc<odin_hermes::runtime::HermesRuntime>>,
) {
    pumps.spawn(async move {
        let mut monitors = AlertTracker::default();
        let mut read_at: BTreeMap<RunId, Instant> = BTreeMap::new();
        if let Some(desk) = &desk {
            for run in offload.runs().into_iter().filter(|run| run.state.finished()) {
                let log = match offload.target(&run.target) {
                    Some(target) => offload.read(&run, &target).await.map(|(_, log, _)| log).unwrap_or_default(),
                    None => String::new(),
                };
                offload.observe_mission(desk, &run, &log);
            }
        }
        loop {
            tokio::time::sleep(offload.shortest_poll()).await;
            let now = Instant::now();
            let observed = offload
                .poll(
                    |run, target| {
                        read_at.get(&run.run_id).is_none_or(|at| {
                            now.duration_since(*at)
                                >= Duration::from_secs(u64::from(target.poll_seconds.get()))
                        })
                    },
                    &mut monitors,
                )
                .await;
            for (run, log) in observed {
                read_at.insert(run.run_id.clone(), now);
                if let Some(desk) = &desk {
                    offload.observe_mission(desk, &run, &log);
                }
            }
            let alerts = offload.alerts.lock().map(|mut alerts| std::mem::take(&mut *alerts)).unwrap_or_default();
            for event in alerts {
                notify_watchdog(&offload, &incidents, owner.as_ref(), runtime.as_ref(), event).await;
            }
            let stalls = offload.stall_events.lock().map(|mut events| std::mem::take(&mut *events)).unwrap_or_default();
            for (run, counter, value, step) in stalls {
                if step == super::workload_recovery::StallStep::Cooldown { continue; }
                let outcome = match &step {
                    super::workload_recovery::StallStep::Act { rung: odin_kernel::recovery::RecoveryRung::RestartWorker, .. } => {
                        match offload.restart_stalled(&run.run_id).await {
                            Ok(()) => "The scheduler accepted a restart within the original deadline.".to_owned(),
                            Err(error) => format!("Restart not confirmed: {error}."),
                        }
                    }
                    _ => "Operator action is required.".to_owned(),
                };
                let detail = format!("Offload {} stalled on {counter} at {value}; recovery decision {step:?}. {outcome}", run.name);
                let raised = crate::incidents::RaisedIncident {
                    source: format!("recovery:{}", run.profile),
                    severity: odin_huginn::incidents::IncidentSeverityView::Error,
                    summary: format!("Offload {} is stalled", run.name),
                    detail: detail.clone(),
                    affected: vec![run.name.clone()],
                    signature: format!("stall:{}:{counter}", run.name),
                };
                let desk = Arc::clone(&incidents);
                let _ = tokio::task::spawn_blocking(move || desk.raise(raised)).await;
                if let (Some(owner), Some(runtime)) = (&owner, &runtime) {
                    let finding = super::workload_watch::Finding {
                        key: format!("{}:stall:{}", run.run_id, unix_seconds(OffsetDateTime::now_utc())),
                        session: super::workload_watch::launching_session(&run.run_id),
                        source: "recovery", text: detail,
                        lane: run.lanes.first().and_then(|lane| odin_domain::LaneId::new(lane).ok()),
                    };
                    if let Err(error) = super::workload_watch::route_finding(owner, runtime, finding).await {
                        tracing::error!("offload recovery finding not delivered: {error}");
                    }
                }
            }
            // A restart decision committed before a crash is retried until dispatch starts.
            for run in offload.runs().into_iter().filter(|run| run.restart_pending && !run.restart_inflight) {
                if let Err(error) = offload.restart_stalled(&run.run_id).await {
                    tracing::warn!("pending offload restart waits run={}: {error}", run.run_id);
                }
            }
        }
    });
}

async fn notify_watchdog(
    offload: &Offload,
    incidents: &Arc<crate::incidents::IncidentDesk>,
    owner: Option<&Arc<odin_omp::host_tools::delegation::GovernedTaskOwner>>,
    runtime: Option<&Arc<odin_hermes::runtime::HermesRuntime>>,
    event: WatchdogEvent,
) {
    use odin_huginn::incidents::IncidentSeverityView;
    use odin_registry::schema::{ContainerAlertActionToml, ContainerAlertSeverityToml};
    let WatchdogEvent { run, alert, value } = event;
    let outcome = match alert.action {
        ContainerAlertActionToml::Stop => "A stop was requested.".to_owned(),
        ContainerAlertActionToml::Steer => {
            let result = async {
                let patch = alert.patch.as_ref().ok_or("no control patch declared")?;
                let target = offload.target(&run.target).ok_or("target unavailable")?;
                let path = format!("{}/control/control.json", run.remote_dir);
                let text = offload
                    .remote(&run.target, &target, &format!("cat {}", quote(&path)))
                    .await?;
                let current: odin_kube::control::ControlDocument =
                    serde_json::from_str(&text).map_err(|error| error.to_string())?;
                let operation = format!("watchdog:{}:{}:{}", run.run_id, alert.id, current.seq + 1);
                offload
                    .steer(
                        &run,
                        current.seq,
                        patch.0.clone(),
                        &operation,
                        &format!("watchdog:{}", alert.id),
                    )
                    .await
            }
            .await;
            match result {
                Ok(applied) => format!("Control sequence {} was applied.", applied.seq),
                Err(error) => format!("Steering failed: {error}."),
            }
        }
        ContainerAlertActionToml::Notify => String::new(),
    };
    let detail = format!(
        "Offload {} on {}: watchdog {} fired — {} (now {value}). {outcome}",
        run.name, run.target, alert.id, alert.condition
    );
    let raised = crate::incidents::RaisedIncident {
        source: format!("monitor:{}/{}", run.profile, alert.id),
        severity: match alert.severity {
            ContainerAlertSeverityToml::Info => IncidentSeverityView::Info,
            ContainerAlertSeverityToml::Warning => IncidentSeverityView::Warning,
            ContainerAlertSeverityToml::Error => IncidentSeverityView::Error,
            ContainerAlertSeverityToml::Critical => IncidentSeverityView::Critical,
        },
        summary: detail.clone(),
        detail: detail.clone(),
        affected: vec![run.name.clone()],
        signature: format!("watchdog:{}:{}", run.name, alert.id),
    };
    let desk = Arc::clone(incidents);
    let receipt = tokio::task::spawn_blocking(move || desk.raise(raised)).await;
    if receipt.as_ref().is_ok_and(|receipt| receipt.coalesced) {
        return;
    }
    if let (Some(owner), Some(runtime)) = (owner, runtime) {
        let finding = super::workload_watch::Finding {
            key: format!(
                "{}:{}:{}",
                run.run_id,
                alert.id,
                unix_seconds(OffsetDateTime::now_utc())
            ),
            session: super::workload_watch::launching_session(&run.run_id),
            source: "monitoring",
            text: detail.clone(),
            lane: run
                .lanes
                .first()
                .and_then(|lane| odin_domain::LaneId::new(lane).ok()),
        };
        if let Err(error) = super::workload_watch::route_finding(owner, runtime, finding).await {
            tracing::error!("offload monitoring finding not delivered: {error}");
        }
        let runtime = Arc::clone(runtime);
        let key = format!(
            "{}:{}:{}",
            run.run_id,
            alert.id,
            unix_seconds(OffsetDateTime::now_utc())
        );
        let profile = run.profile.clone();
        let _ = tokio::task::spawn_blocking(move || {
            runtime.routine_event(
                odin_registry::schema::RoutineEvent::Watchdog,
                Some(&profile),
                &key,
                &detail,
                OffsetDateTime::now_utc()
                    .unix_timestamp()
                    .saturating_mul(1000),
            )
        })
        .await;
    }
}

impl Offload {
    /// The pump wakes at the shortest `poll_seconds` any enabled target declares, read anew
    /// each round; with no target it looks again a minute later.
    fn shortest_poll(&self) -> Duration {
        let snapshot = (self.snapshot)();
        snapshot
            .listed_objects(RegistryKind::ComputeTarget)
            .filter_map(|object| match &object.config {
                ObjectConfig::ComputeTarget(target) if target.enabled => {
                    Some(Duration::from_secs(u64::from(target.poll_seconds.get())))
                }
                _ => None,
            })
            .min()
            .unwrap_or_else(|| {
                Duration::from_secs(
                    snapshot
                        .listed_objects(RegistryKind::Node)
                        .find_map(|object| match &object.config {
                            ObjectConfig::Node(node) if node.authoritative_state => node
                                .offload_empty_poll_seconds
                                .map(|value| u64::from(value.get())),
                            _ => None,
                        })
                        .unwrap_or(60),
                )
            })
    }

    /// A run is a mission on node `offload:<target>`.
    fn observe_mission(
        &self,
        desk: &crate::simulation::SimulationDesk,
        run: &OffloadRun,
        log: &str,
    ) {
        let pin = (self.snapshot)();
        let Ok(profile) = pin.workload_profile_ref(&run.profile) else {
            return;
        };
        let declared = profile.profile.simulation.is_some();
        let simulation = profile.profile.simulation.clone().unwrap_or_default();
        let observed = crate::simulation::ObservedRun {
            run_id: run.run_id.clone(),
            lane: run
                .lanes
                .first()
                .and_then(|lane| odin_domain::LaneId::new(lane).ok()),
            profile: run.profile.clone(),
            declaration: serde_json::to_value(profile.profile).unwrap_or_default(),
            simulation,
            declared,
            state: run.workload_state(),
            node_id: run.node_id(),
            workload: crate::simulation::ObservedWorkload::Offload(run.resource()),
            started_at: run.started_at,
            finished_at: run.finished_at,
        };
        if let Err(error) = desk.observe(&observed, log, OffsetDateTime::now_utc()) {
            tracing::error!(
                "offload mission observation failed run={}: {error}",
                run.run_id
            );
        }
    }
}

fn unit_name(name: &str) -> String {
    format!("odin-offload-{name}")
}

/// The scheduler's word for a run. `EXIT n` is the run's own exit status, written only when its
/// command returned; anything else that is over without it was stopped or lost.
fn state_of(head: &str, stopping: bool) -> OffloadState {
    if let Some(code) = head.strip_prefix("EXIT ") {
        return if stopping {
            OffloadState::Aborted
        } else if code.trim() == "0" {
            OffloadState::Succeeded
        } else {
            OffloadState::Failed
        };
    }
    let word = head
        .strip_prefix("STATE")
        .unwrap_or(head)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_end_matches('+')
        .to_ascii_uppercase();
    match word.as_str() {
        "PENDING" | "REQUEUED" | "CONFIGURING" | "ACTIVATING" => OffloadState::Pending,
        "RUNNING" | "COMPLETING" | "ACTIVE" | "RELOADING" | "DEACTIVATING" => OffloadState::Running,
        "SUSPENDED" => OffloadState::Suspended,
        "COMPLETED" => OffloadState::Succeeded,
        "CANCELLED" => OffloadState::Aborted,
        _ if stopping => OffloadState::Aborted,
        // FAILED, TIMEOUT, NODE_FAIL, OUT_OF_MEMORY, a vanished unit or a missing run folder.
        _ => OffloadState::Failed,
    }
}

#[cfg(test)]
#[path = "tests/offload.rs"]
mod tests;
