//! PID 1 supervises the sole Claude writer in each pod; recovery only replays output.
#[path = "claude_pod_backend/account.rs"]
mod account;
#[path = "claude_pod_backend/publication.rs"]
mod publication;
#[path = "claude_pod_backend/publication_authority.rs"]
mod publication_authority;
#[path = "claude_pod_backend/resolve.rs"]
mod resolve;
#[path = "claude_pod_backend/transport.rs"]
mod transport;
#[path = "claude_pod_backend/worker.rs"]
mod worker;

use crate::claude_protocol::{ClaudeProtocol, ProtocolLimits};
use crate::claude_sessions::{ClaudeBackendOutcome, ClaudeSessionBackend};
use odin_domain::RunId;
use odin_hermes::runtime::claude::{ClaudeOpenRequest, ClaudeSessionRecord};
use odin_kube::claude_pod::{self, ClaudePodPlan, ClaudePodReceipt};
use odin_omp::host_tools::HostToolError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

const TOOL: &str = "claude_session";
const SUPERVISOR: &[u8] = include_bytes!("claude_pod_backend/supervisor.py");
const GIT_HELPER: &[u8] = include_bytes!("claude_pod_backend/git_remote_odin.py");
fn uncertain(detail: impl ToString) -> HostToolError {
    HostToolError::Uncertain {
        tool: TOOL,
        detail: detail.to_string(),
    }
}
fn unavailable(detail: impl ToString) -> HostToolError {
    HostToolError::Unavailable {
        tool: TOOL,
        reason: detail.to_string(),
    }
}
fn arguments(detail: impl ToString) -> HostToolError {
    HostToolError::Arguments {
        tool: TOOL,
        detail: detail.to_string(),
    }
}

#[derive(Serialize, Deserialize)]
struct Journal {
    session: String,
    owner_run: String,
    workload: String,
    account: String,
    project: String,
    project_root: PathBuf,
    branch: String,
    revision: String,
    skip_permissions: bool,
    remote_control: bool,
    name: String,
    version: Option<String>,
    receipt: Option<ClaudePodReceipt>,
    grant_registration: Option<String>,
    next_seq: u64,
    pending: bool,
    stopped: bool,
    stop_admitted: bool,
    final_events: Vec<Value>,
}

pub struct ClaudePodBackend {
    pin: Arc<odin_registry::SnapshotHandle>,
    projects: BTreeMap<String, PathBuf>,
    kube: Option<Arc<crate::kube::KubeRuntimeCell>>,
    runtime: tokio::runtime::Handle,
    home: PathBuf,
    root: PathBuf,
    serial: Mutex<()>,
    observed: Mutex<BTreeMap<String, transport::Replay>>,
    workers: Mutex<BTreeMap<String, worker::WorkerCustody>>,
    recovery_store: Arc<Mutex<odin_ledger::Ledger>>,
    clock: odin_kernel::operation::Clock,
}

impl ClaudePodBackend {
    pub fn new(
        pin: Arc<odin_registry::SnapshotHandle>,
        config: &odin_huginn::OdindConfig,
        kube: Option<Arc<crate::kube::KubeRuntimeCell>>,
        runtime: tokio::runtime::Handle,
        recovery_store: Arc<Mutex<odin_ledger::Ledger>>,
        clock: odin_kernel::operation::Clock,
    ) -> Self {
        Self {
            pin,
            projects: config
                .projects
                .iter()
                .map(|(id, project)| (id.clone(), project.root.clone()))
                .collect(),
            kube,
            runtime,
            home: std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default(),
            root: config.paths.state_root.join("claude-pods"),
            serial: Mutex::new(()),
            observed: Mutex::new(BTreeMap::new()),
            workers: Mutex::new(BTreeMap::new()),
            recovery_store,
            clock,
        }
    }
    fn bridge<T>(&self, future: impl std::future::Future<Output = T>) -> T {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| handle.block_on(future)),
            Err(_) => self.runtime.block_on(future),
        }
    }
    fn cell(&self) -> Result<&crate::kube::KubeRuntimeCell, HostToolError> {
        self.kube
            .as_deref()
            .ok_or_else(|| unavailable("Claude pod carrier is not configured"))
    }
    fn path(&self, session: &str) -> Result<PathBuf, HostToolError> {
        let id = uuid::Uuid::parse_str(session).map_err(|_| arguments("invalid session UUID"))?;
        if id.is_nil() || id.to_string() != session {
            return Err(arguments("invalid session UUID"));
        }
        Ok(self.root.join(format!("{session}.json")))
    }
    fn save(&self, journal: &Journal) -> Result<(), HostToolError> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        fs::create_dir_all(&self.root).map_err(uncertain)?;
        fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700)).map_err(uncertain)?;
        let path = self.path(&journal.session)?;
        let temp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(uncertain)?;
        file.write_all(&serde_json::to_vec(journal).map_err(uncertain)?)
            .map_err(uncertain)?;
        file.sync_all().map_err(uncertain)?;
        fs::rename(temp, path).map_err(uncertain)?;
        fs::File::open(&self.root)
            .and_then(|file| file.sync_all())
            .map_err(uncertain)
    }
    fn load(&self, session: &str) -> Result<Journal, HostToolError> {
        let journal: Journal =
            serde_json::from_slice(&fs::read(self.path(session)?).map_err(uncertain)?)
                .map_err(uncertain)?;
        if journal.session != session {
            return Err(uncertain("Claude journal identity mismatch"));
        }
        Ok(journal)
    }
    fn outcome(
        journal: &Journal,
        protocol: &ClaudeProtocol,
        events: Vec<Value>,
    ) -> Result<ClaudeBackendOutcome, HostToolError> {
        Ok(ClaudeBackendOutcome {
            resource: Some(
                json!({"placement":"pod","workload":journal.workload,"account":journal.account,"project":journal.project,"worktree":claude_pod::WORKSPACE,"carrier":journal.receipt,"skip_permissions":journal.skip_permissions}),
            ),
            claude_session_id: Some(journal.session.clone()),
            remote_control: protocol
                .remote_control()
                .map(serde_json::to_value)
                .transpose()
                .map_err(uncertain)?,
            events,
        })
    }
    async fn send(
        &self,
        client: &odin_kube::KubeClient,
        journal: &mut Journal,
        data: Vec<u8>,
    ) -> Result<(), HostToolError> {
        if journal.pending {
            return Err(uncertain(
                "prior prompt delivery is uncertain; refusing replay",
            ));
        }
        journal.pending = true;
        self.save(journal)?;
        let text = String::from_utf8(data).map_err(uncertain)?;
        transport::request(
            client,
            journal
                .receipt
                .as_ref()
                .ok_or_else(|| uncertain("missing carrier receipt"))?,
            json!({"op":"write","session":journal.session,"seq":journal.next_seq,"data":text}),
        )
        .await
        .map_err(uncertain)?;
        journal.next_seq = journal
            .next_seq
            .checked_add(1)
            .ok_or_else(|| uncertain("input sequence exhausted"))?;
        journal.pending = false;
        self.save(journal)
    }
}

#[derive(Debug)]
struct PresetLaunch {
    skip_permissions: bool,
    remote_control: bool,
}

fn honored_pod_preset(
    id: &str,
    preset: &odin_registry::ClaudePresetToml,
) -> Result<PresetLaunch, String> {
    if preset.placement != odin_registry::ClaudePlacement::Pod {
        return Err(format!("preset_placement: {id} is not pod"));
    }
    if preset.unsandboxed {
        return Err(format!(
            "preset_unsandboxed: {id} cannot launch in a pod worktree"
        ));
    }
    if preset.driver != odin_registry::ClaudeDriver::Sinmara {
        return Err(format!(
            "preset_driver: {id} is not sinmara; pod launch has no driver switch"
        ));
    }
    Ok(PresetLaunch {
        skip_permissions: preset.skip_permissions,
        remote_control: preset.remote_control,
    })
}

fn preset_launch(
    pin: &odin_registry::SnapshotHandle,
    request: &ClaudeOpenRequest,
) -> Result<Option<PresetLaunch>, HostToolError> {
    let Some(id) = request.preset.as_deref() else {
        return Ok(None);
    };
    let preset = crate::claude_host::declared_preset(&pin.current(), id).map_err(unavailable)?;
    honored_pod_preset(id, &preset)
        .map(Some)
        .map_err(unavailable)
}

impl ClaudeSessionBackend for ClaudePodBackend {
    fn resolve(&self, request: &ClaudeOpenRequest) -> Result<ClaudeOpenRequest, HostToolError> {
        let preset = preset_launch(&self.pin, request)?;
        let resolved = resolve::resolve(
            &self.pin,
            &self.projects,
            self.cell()?,
            request,
            &uuid::Uuid::new_v4().to_string(),
        )
        .map_err(arguments)?;
        account::selected_credentials(&self.home, &request.account).map_err(unavailable)?;
        let mut request = request.clone();
        request.placement = Some(odin_hermes::runtime::claude::ClaudePlacement::Pod);
        request.skip_permissions = Some(match preset {
            Some(preset) => preset.skip_permissions,
            None => request
                .skip_permissions
                .unwrap_or_else(|| resolved.profile.skip_permissions()),
        });
        Ok(request)
    }
    fn preflight(&self, request: &ClaudeOpenRequest) -> Result<(), HostToolError> {
        preset_launch(&self.pin, request)?;
        let cell = self.cell()?;
        resolve::resolve(
            &self.pin,
            &self.projects,
            cell,
            request,
            &uuid::Uuid::new_v4().to_string(),
        )
        .map_err(arguments)?;
        account::selected_credentials(&self.home, &request.account).map_err(unavailable)?;
        Ok(())
    }
    fn open(
        &self,
        effect: &odin_kernel::PreparedEffect,
        session: &ClaudeSessionRecord,
    ) -> Result<ClaudeBackendOutcome, HostToolError> {
        let _serial = self.serial.lock().map_err(uncertain)?;
        let cell = self.cell()?;
        if self.path(&session.session)?.exists() {
            return Err(uncertain(
                "open already has durable intent; use read or stop, never launch again",
            ));
        }
        let preset = preset_launch(&self.pin, &session.request)?;
        let resolved = resolve::resolve(
            &self.pin,
            &self.projects,
            cell,
            &session.request,
            &session.session,
        )
        .map_err(arguments)?;
        let credentials = account::selected_credentials(&self.home, &session.request.account)
            .map_err(unavailable)?;
        if publication::remote_tip(&resolved.project_root, &resolved.branch)
            .map_err(unavailable)?
            .is_some()
        {
            return Err(arguments(
                "Claude branch already exists upstream; choose a unique name",
            ));
        }
        // A branch is reserved by its durable session intent, including uncertain opens.
        if self.root.exists() {
            for entry in fs::read_dir(&self.root).map_err(unavailable)? {
                let path = entry.map_err(unavailable)?.path();
                if path.extension().and_then(|v| v.to_str()) != Some("json") {
                    continue;
                }
                let prior: Journal = serde_json::from_slice(&fs::read(path).map_err(unavailable)?)
                    .map_err(unavailable)?;
                if prior.project == session.request.project && prior.branch == resolved.branch {
                    return Err(arguments(
                        "Claude branch name is already reserved; choose a unique name",
                    ));
                }
            }
        }
        let profile = &resolved.profile;
        let mut journal = Journal {
            session: session.session.clone(),
            owner_run: session.owner_run.clone(),
            workload: resolved.workload,
            account: session.request.account.clone(),
            project: session.request.project.clone(),
            project_root: resolved.project_root,
            branch: resolved.branch.clone(),
            revision: resolved.revision.clone(),
            skip_permissions: match &preset {
                Some(preset) => preset.skip_permissions,
                None => session
                    .request
                    .skip_permissions
                    .unwrap_or_else(|| profile.skip_permissions()),
            },
            remote_control: match &preset {
                Some(preset) => preset.remote_control,
                None => profile.remote_control,
            },
            name: session
                .request
                .name
                .clone()
                .unwrap_or_else(|| session.session.clone()),
            version: None,
            receipt: None,
            grant_registration: None,
            next_seq: 1,
            pending: false,
            stopped: false,
            stop_admitted: false,
            final_events: Vec::new(),
        };
        let plan = ClaudePodPlan {
            run_id: RunId::new(format!("run:claude:{}", session.session)).map_err(arguments)?,
            session: session.session.clone(),
            image: profile.image.reference.clone(),
            clone_url: resolved.clone_url,
            revision: resolved.revision,
            branch: resolved.branch,
            account_files: credentials,
            mcp_config: profile
                .mcp_config(&session.request.mcp, claude_pod::WORKSPACE)
                .map_err(arguments)?,
            allow_hosts: resolved.allow_hosts,
            egress_targets: resolved.egress_targets,
            cpu_request: profile.resources.cpu_request.clone(),
            cpu_limit: profile.resources.cpu_limit.clone(),
            memory_request: profile.resources.memory_request.clone(),
            memory_limit: profile.resources.memory_limit.clone(),
            storage_limit: profile.resources.storage_limit.clone(),
            supervisor_script: SUPERVISOR.to_vec(),
            git_helper_script: GIT_HELPER.to_vec(),
        };
        self.save(&journal)?;
        let grant =
            publication_authority::mint(effect, session, &journal.branch).map_err(uncertain)?;
        journal.grant_registration = Some(grant.registration_id().to_owned());
        self.save(&journal)?;
        self.bridge(async {
            let client = cell.client().await.map_err(uncertain)?;
            let receipt = {
                let _lifecycle = cell.terminal_lifecycle().await.map_err(uncertain)?;
                claude_pod::ensure(
                    &client,
                    &cell.stop_authority(),
                    &cell.kube_config().cluster,
                    &cell.kube_config().namespace,
                    &plan,
                )
                .await
                .map_err(uncertain)?
            };
            journal.receipt = Some(receipt.clone());
            self.save(&journal)?;
            let version_reply = transport::request(&client, &receipt, json!({"op":"version"}))
                .await
                .map_err(uncertain)?;
            let version = version_reply
                .get("version")
                .and_then(Value::as_str)
                .ok_or_else(|| uncertain("Claude version proof missing"))?
                .to_owned();
            let mut protocol = ClaudeProtocol::new(
                &session.session,
                &version,
                journal.remote_control,
                ProtocolLimits::default(),
            )
            .map_err(uncertain)?;
            journal.version = Some(version);
            self.save(&journal)?;
            let mut argv = vec!["/odin/bin/claude".to_owned()];
            argv.extend(protocol.launch_args());
            argv.extend([
                "--strict-mcp-config".into(),
                "--mcp-config".into(),
                claude_pod::MCP_CONFIG.into(),
            ]);
            if journal.skip_permissions {
                argv.push("--dangerously-skip-permissions".into());
            }
            transport::request(
                &client,
                &receipt,
                json!({"op":"start","session":session.session,"argv":argv}),
            )
            .await
            .map_err(uncertain)?;
            self.send(
                &client,
                &mut journal,
                protocol.initialize().map_err(uncertain)?,
            )
            .await?;
            let mut offset = 0;
            let mut events = Vec::new();
            let mut rc_sent = false;
            tokio::time::timeout(Duration::from_secs(60), async {
                while !protocol.is_ready() {
                    events.extend(
                        transport::read_more(
                            &client,
                            &receipt,
                            &session.session,
                            &mut protocol,
                            &mut offset,
                        )
                        .await
                        .map_err(uncertain)?,
                    );
                    if protocol.is_initialized() && journal.remote_control && !rc_sent {
                        let input = protocol
                            .enable_remote_control(&journal.name)
                            .map_err(uncertain)?;
                        self.send(&client, &mut journal, input).await?;
                        rc_sent = true;
                    }
                    if !protocol.is_ready() {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
                Ok::<_, HostToolError>(())
            })
            .await
            .map_err(|_| uncertain("Claude initialize/Remote Control proof deadline exceeded"))??;
            let outcome = Self::outcome(&journal, &protocol, events.clone())?;
            self.observed.lock().map_err(uncertain)?.insert(
                journal.session.clone(),
                transport::Replay {
                    protocol,
                    offset,
                    events,
                    last_seq: journal.next_seq - 1,
                    state: "running".into(),
                },
            );
            self.start_worker(&journal, grant)?;
            Ok(outcome)
        })
    }
    fn prompt(
        &self,
        _effect: &odin_kernel::PreparedEffect,
        session: &ClaudeSessionRecord,
        text: &str,
    ) -> Result<ClaudeBackendOutcome, HostToolError> {
        let _serial = self.serial.lock().map_err(uncertain)?;
        let mut journal = self.load(&session.session)?;
        if journal.stopped || journal.stop_admitted {
            return Err(arguments(
                "Claude session is stopped or admitted for stopping",
            ));
        }
        self.bridge(async {
            let client = self.cell()?.client().await.map_err(uncertain)?;
            let mut replay = self
                .observe(&client, &journal, session.last_driver_cursor)
                .await?;
            if replay.state != "running" {
                return Err(arguments(
                    "Claude writer is not running; refusing a replacement process",
                ));
            }
            if replay.last_seq.checked_add(1) != Some(journal.next_seq) {
                return Err(uncertain(
                    "supervisor input sequence disagrees with durable journal",
                ));
            }
            let input = replay.protocol.prompt(text).map_err(arguments)?;
            self.send(&client, &mut journal, input).await?;
            let outcome = Self::outcome(&journal, &replay.protocol, replay.events.clone())?;
            self.observed
                .lock()
                .map_err(uncertain)?
                .insert(journal.session.clone(), replay);
            Ok(outcome)
        })
    }
    fn read(&self, session: &ClaudeSessionRecord) -> Result<ClaudeBackendOutcome, HostToolError> {
        let _serial = self.serial.lock().map_err(uncertain)?;
        let journal = self.load(&session.session)?;
        if journal.stopped {
            return Ok(ClaudeBackendOutcome {
                events: journal.final_events,
                ..Default::default()
            });
        }
        self.bridge(async {
            let client = self.cell()?.client().await.map_err(uncertain)?;
            let replay = self
                .observe(&client, &journal, session.last_driver_cursor)
                .await?;
            let mut events = replay.events.clone();
            events.extend(
                worker::events(&self.root, &journal.session)
                    .map_err(uncertain)?
                    .into_iter()
                    .filter(|event| {
                        event
                            .get("publication_cursor")
                            .and_then(Value::as_u64)
                            .is_none_or(|cursor| {
                                cursor > session.last_publication_cursor.unwrap_or(0)
                            })
                    }),
            );
            let outcome = Self::outcome(&journal, &replay.protocol, events)?;
            self.observed
                .lock()
                .map_err(uncertain)?
                .insert(journal.session.clone(), replay);
            Ok(outcome)
        })
    }
    fn stop(
        &self,
        _effect: &odin_kernel::PreparedEffect,
        session: &ClaudeSessionRecord,
        discard_unpushed: bool,
    ) -> Result<ClaudeBackendOutcome, HostToolError> {
        self.stop_session(session, discard_unpushed)
    }
}

impl ClaudePodBackend {
    fn stop_session(
        &self,
        session: &ClaudeSessionRecord,
        discard: bool,
    ) -> Result<ClaudeBackendOutcome, HostToolError> {
        let _serial = self.serial.lock().map_err(uncertain)?;
        match fs::symlink_metadata(self.path(&session.session)?) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return self.bridge(async {
                    let cell = self.cell()?;
                    let _client = cell.client().await.map_err(uncertain)?;
                    let _lifecycle = cell.terminal_lifecycle().await.map_err(uncertain)?;
                    let correlation = odin_kube::terminal_pod::terminal_correlation(&session.session).map_err(uncertain)?;
                    if cell.stop_authority().pod_worker_for_correlation(&correlation).map_err(uncertain)?.is_some() {
                        return Err(uncertain("carrier custody exists without the required backend journal"));
                    }
                    Ok(ClaudeBackendOutcome { events: vec![json!({"type":"no_effect_reconciled","session":session.session,"correlation":correlation.as_str(),"backend_journal":"absent","carrier_custody":"absent"})], ..Default::default() })
                });
            }
            Err(error) => return Err(uncertain(error)),
            Ok(_) => {}
        }
        let mut journal = self.load(&session.session)?;
        if journal.stopped {
            return Ok(ClaudeBackendOutcome {
                events: journal.final_events,
                ..Default::default()
            });
        }
        let mut custody = self
            .workers
            .lock()
            .map_err(uncertain)?
            .remove(&journal.session);
        if let Some(worker) = custody.as_mut() {
            self.bridge(worker.quiesce()).map_err(uncertain)?;
        }
        let mut frozen = false;
        let mut stop_attempted = false;
        let result = self.bridge(async {
            let cell = self.cell()?;
            let client = cell.client().await.map_err(uncertain)?;
            let stops = cell.stop_authority();
            if journal.receipt.is_none() {
                let correlation = odin_kube::terminal_pod::terminal_correlation(&journal.session).map_err(uncertain)?;
                if let Some((worker, identity, _)) = stops.pod_worker_for_correlation(&correlation).map_err(uncertain)? {
                    journal.receipt = Some(ClaudePodReceipt { worker: worker.as_str().into(), identity, branch: journal.branch.clone(), policy_spec: None });
                    self.save(&journal)?;
                } else {
                    // An intent with no registered carrier cannot have released a Claude writer.
                    journal.stopped = true;
                    self.save(&journal)?;
                    return Ok(ClaudeBackendOutcome::default());
                }
            }
            let receipt = journal.receipt.as_ref().ok_or_else(|| uncertain("missing recovered carrier"))?;
            let presence = claude_pod::inspect(&client, receipt).await.map_err(uncertain)?;
            if presence == claude_pod::ClaudePodPresence::Running {
                // Freeze the entire process group before reading git state. A refusal
                // always thaws; a failed thaw is uncertain and preserves the carrier.
                let observed = transport::request(&client, receipt, json!({"op":"inspect"})).await.map_err(uncertain)?;
                let empty = observed.get("state").and_then(Value::as_str) == Some("empty") && observed.get("session").is_some_and(Value::is_null);
                if !empty { frozen = true; transport::request(&client, receipt, json!({"op":"freeze","session":journal.session})).await.map_err(uncertain)?; }
                    let admitted = if empty { Ok(true) } else { publication::clean(&client, receipt, &journal.project_root, &self.root, &journal.revision, discard).await };
                    if !matches!(admitted, Ok(true)) {
                        if !empty { transport::request(&client, receipt, json!({"op":"thaw","session":journal.session})).await.map_err(uncertain)?; frozen = false; }
                        return match admitted {
                            Ok(false) => Err(arguments("stop refused: dirty/untracked work or unpublished commits; discard_unpushed never discards uncommitted files")),
                            Err(error) => Err(uncertain(error)),
                            Ok(true) => unreachable!(),
                        };
                    }
                if !empty && journal.version.is_some() {
                    match self.observe(&client, &journal, session.last_driver_cursor).await {
                        Ok(replay) => journal.final_events = replay.events,
                        Err(_) => {
                            let bytes = self.preserve_raw_transcript(&client, receipt, &journal.session).await?;
                            journal.final_events.push(json!({"type":"transcript_recovery_failed","session":journal.session,"raw_transcript_preserved":true,"bytes":bytes,"reason":"Claude output could not be reconstructed; owned carrier stop remained independently admitted"}));
                        }
                    }
                }
            } else if presence == claude_pod::ClaudePodPresence::NotRunning {
                return Err(uncertain("non-running carrier workspace cannot be proved free of uncommitted data"));
            }
            journal.final_events.extend(worker::events(&self.root, &journal.session).map_err(uncertain)?);
            self.save(&journal)?;
            let _lifecycle = cell.terminal_lifecycle().await.map_err(uncertain)?;
            stop_attempted = true;
            journal.stop_admitted = true;
            self.save(&journal)?;
            claude_pod::stop(&stops, receipt).map_err(uncertain)?;
            journal.stopped = true;
            self.save(&journal)?;
            let mut events = journal.final_events.clone();
            events.push(json!({"type":"stopped","discard_unpushed":discard,"branch":journal.branch}));
            Ok(ClaudeBackendOutcome { events, ..Default::default() })
        });
        if result.is_err() {
            if frozen && !stop_attempted {
                self.bridge(async {
                    let client = self.cell()?.client().await.map_err(uncertain)?;
                    transport::request(
                        &client,
                        journal
                            .receipt
                            .as_ref()
                            .ok_or_else(|| uncertain("missing carrier receipt"))?,
                        json!({"op":"thaw","session":journal.session}),
                    )
                    .await
                    .map_err(uncertain)?;
                    Ok::<_, HostToolError>(())
                })?;
            }
            if let Some(mut worker) = custody.filter(|_| !stop_attempted) {
                worker.restart(&self.runtime).map_err(uncertain)?;
                self.workers
                    .lock()
                    .map_err(uncertain)?
                    .insert(journal.session.clone(), worker);
            }
        }
        result
    }
}

impl ClaudePodBackend {
    async fn observe(
        &self,
        client: &odin_kube::KubeClient,
        journal: &Journal,
        acknowledged: Option<u64>,
    ) -> Result<transport::Replay, HostToolError> {
        let receipt = journal
            .receipt
            .as_ref()
            .ok_or_else(|| uncertain("carrier receipt missing"))?;
        let cached = self
            .observed
            .lock()
            .map_err(uncertain)?
            .remove(&journal.session);
        if let Some(mut replay) = cached {
            replay.events.retain(|event| {
                event
                    .get("driver_cursor")
                    .and_then(Value::as_u64)
                    .is_none_or(|cursor| cursor > acknowledged.unwrap_or(0))
            });
            let new_events = transport::follow(client, receipt, &journal.session, &mut replay)
                .await
                .map_err(uncertain)?;
            replay.events.extend(new_events);
            Ok(replay)
        } else {
            let mut replay = transport::replay(
                client,
                receipt,
                &journal.session,
                journal
                    .version
                    .as_deref()
                    .ok_or_else(|| uncertain("version proof missing"))?,
                journal.remote_control,
                &journal.name,
            )
            .await
            .map_err(uncertain)?;
            replay.events.retain(|event| {
                event
                    .get("driver_cursor")
                    .and_then(Value::as_u64)
                    .is_none_or(|cursor| cursor > acknowledged.unwrap_or(0))
            });
            Ok(replay)
        }
    }
}

impl ClaudePodBackend {
    fn start_worker(
        &self,
        journal: &Journal,
        grant: odin_kernel::operation::ChildEffectGrant,
    ) -> Result<(), HostToolError> {
        let mut workers = self.workers.lock().map_err(uncertain)?;
        if workers.contains_key(&journal.session) {
            return Ok(());
        }
        let cell = self
            .kube
            .as_ref()
            .ok_or_else(|| unavailable("Claude pod carrier is not configured"))?
            .clone();
        let receipt = journal
            .receipt
            .as_ref()
            .ok_or_else(|| uncertain("missing carrier receipt"))?
            .clone();
        workers.insert(
            journal.session.clone(),
            worker::start(
                &self.runtime,
                worker::Context {
                    cell,
                    grant,
                    receipt,
                    project_root: journal.project_root.clone(),
                    project_id: journal.project.clone(),
                    session: journal.session.clone(),
                    state_root: self.root.clone(),
                },
            ),
        );
        Ok(())
    }
    fn recovered_grant(
        &self,
        journal: &Journal,
    ) -> Result<odin_kernel::operation::ChildEffectGrant, HostToolError> {
        odin_kernel::operation::ChildEffectGrant::recover(
            self.recovery_store.clone(),
            self.clock.clone(),
            journal
                .grant_registration
                .as_deref()
                .ok_or_else(|| uncertain("publication grant missing"))?,
        )
        .map_err(uncertain)
    }
    pub fn recover_workers(&self) -> Result<(), HostToolError> {
        if !self.root.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(&self.root).map_err(uncertain)? {
            let path = entry.map_err(uncertain)?.path();
            if path.extension().and_then(|p| p.to_str()) != Some("json") {
                continue;
            }
            let journal: Journal =
                serde_json::from_slice(&fs::read(path).map_err(uncertain)?).map_err(uncertain)?;
            if !journal.stopped
                && !journal.stop_admitted
                && journal.receipt.is_some()
                && journal.grant_registration.is_some()
            {
                match self.recovered_grant(&journal) {
                    Ok(grant) => self.start_worker(&journal, grant)?,
                    Err(_) => {
                        worker::recovery_refused(&self.root, &journal.session).map_err(uncertain)?
                    }
                }
            }
        }
        Ok(())
    }
}

impl ClaudePodBackend {
    async fn preserve_raw_transcript(
        &self,
        client: &odin_kube::KubeClient,
        receipt: &ClaudePodReceipt,
        session: &str,
    ) -> Result<u64, HostToolError> {
        use base64::Engine;
        use std::os::unix::fs::OpenOptionsExt;
        let path = self.path(session)?.with_extension("transcript.ndjson");
        let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(uncertain)?;
        let observed = transport::request(client, receipt, json!({"op":"inspect"}))
            .await
            .map_err(uncertain)?;
        if observed.get("session").and_then(Value::as_str) != Some(session) {
            return Err(uncertain("transcript capture session mismatch"));
        }
        let end = observed
            .get("output_bytes")
            .and_then(Value::as_u64)
            .filter(|n| *n <= 256 * 1024 * 1024)
            .ok_or_else(|| uncertain("invalid transcript capture bound"))?;
        let mut offset = 0u64;
        while offset < end {
            let limit = (end - offset).min(262144);
            let reply = transport::request(
                client,
                receipt,
                json!({"op":"read","session":session,"offset":offset,"limit":limit}),
            )
            .await
            .map_err(uncertain)?;
            let data = base64::engine::general_purpose::STANDARD
                .decode(
                    reply
                        .get("data")
                        .and_then(Value::as_str)
                        .ok_or_else(|| uncertain("missing transcript bytes"))?,
                )
                .map_err(|_| uncertain("invalid transcript encoding"))?;
            if data.is_empty()
                || data.len() as u64 > limit
                || reply.get("next_offset").and_then(Value::as_u64)
                    != Some(offset + data.len() as u64)
            {
                return Err(uncertain("invalid transcript capture offset"));
            }
            file.write_all(&data).map_err(uncertain)?;
            offset += data.len() as u64;
        }
        file.sync_all().map_err(uncertain)?;
        fs::rename(temporary, path).map_err(uncertain)?;
        fs::File::open(&self.root)
            .and_then(|file| file.sync_all())
            .map_err(uncertain)?;
        Ok(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::honored_pod_preset;
    use odin_registry::{ClaudeDriver, ClaudePlacement, ClaudePresetToml, ClaudePresetWorkspace};

    fn preset(
        placement: ClaudePlacement,
        driver: ClaudeDriver,
        unsandboxed: bool,
        skip_permissions: bool,
        remote_control: bool,
    ) -> ClaudePresetToml {
        ClaudePresetToml {
            placement,
            driver,
            skip_permissions,
            remote_control,
            workspace: ClaudePresetWorkspace::NormalCheckout,
            default_account: "default".into(),
            default_host: String::new(),
            default_dir: String::new(),
            unsandboxed,
        }
    }

    #[test]
    fn pod_presets_reject_incompatible_placement_sandbox_and_driver() {
        for rejected in [
            preset(
                ClaudePlacement::HostTab,
                ClaudeDriver::Sinmara,
                false,
                false,
                false,
            ),
            preset(
                ClaudePlacement::Pod,
                ClaudeDriver::Sinmara,
                true,
                false,
                false,
            ),
            preset(
                ClaudePlacement::Pod,
                ClaudeDriver::Colin,
                false,
                false,
                false,
            ),
        ] {
            assert!(honored_pod_preset("test", &rejected).is_err());
        }
    }
}
