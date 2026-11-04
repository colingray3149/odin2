//! Daemon Hermes bindings: the live intake-authority facts, the terminal
//! and Huginn read routes bridged onto the composition runtime, and the
//! strict `[hermes]` wire-section mapping.

use std::future::Future;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use odin_domain::huginn as live;
use odin_domain::huginn::OmpLivePlane as _;
use odin_huginn::NodePosture;
use odin_kernel::RevocationStore as _;
use odin_ledger::Ledger;

#[path = "hermes/workspace_launch.rs"]
mod workspace_launch;

use workspace_launch::{
    desktop_script, workspace_open_command, workspace_owned_command, OPEN_LOCKED, OPEN_NO_SESSION,
};

/// The daemon's live seat-authority facts, consulted by the Hermes intake
/// governance on every external intent. Both facts read the same durable
/// state the dispatch path verifies against: the provisioned seat tokens
/// under the authority token root, the shared bridge ledger's durable token
/// revocations, and its correlation-keyed stop rows. No compiled default
/// anywhere — a seat whose live token cannot be proven reports revoked, and
/// an unreadable revocation or stop state reports revoked/stopped, so a
/// degraded authority refuses intake instead of admitting blindly.
pub(super) struct DaemonIntakeAuthority {
    pub(super) ledger: Arc<Mutex<Ledger>>,
    pub(super) token_root: PathBuf,
    pub(super) posture: NodePosture,
}

impl odin_hermes::runtime::IntakeAuthorityFacts for DaemonIntakeAuthority {
    fn seat_token_revoked(&self, seat: &str) -> bool {
        if self.posture == NodePosture::Follower {
            return true;
        }
        let Ok(expected) = odin_domain::SeatId::new(seat) else {
            tracing::error!("intake-authority refused seat={seat:?} reason=invalid seat id");
            return true;
        };
        let entries = match std::fs::read_dir(&self.token_root) {
            Ok(entries) => entries,
            Err(error) => {
                tracing::error!(
                    "intake-authority refused seat={seat} reason=token root {} unreadable: {error}",
                    self.token_root.display()
                );
                return true;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .extension()
                .map(|extension| extension != "json")
                .unwrap_or(true)
            {
                continue;
            }
            let token = match std::fs::read(&path)
                .map_err(|error| error.to_string())
                .and_then(|bytes| {
                    serde_json::from_slice::<odin_domain::SeatToken>(&bytes)
                        .map_err(|error| error.to_string())
                }) {
                Ok(token) => token,
                Err(error) => {
                    tracing::warn!(
                        "intake-authority skipped token={} reason={error}",
                        path.display()
                    );
                    continue;
                }
            };
            if token.seat.as_str() != expected.as_str() {
                continue;
            }
            let revoked = {
                // A poisoned bridge ledger is degraded authority: report
                // revoked instead of admitting blindly.
                let Ok(ledger) = self.ledger.lock() else {
                    tracing::error!(
                        "intake-authority refused seat={seat} reason=bridge ledger lock poisoned"
                    );
                    return true;
                };
                odin_kernel::token::LedgerRevocations::new(&ledger)
                    .is_revoked(&token.token_id)
                    .unwrap_or_else(|error| {
                        tracing::error!(
                            "intake-authority treats token={} as revoked reason=revocation read failed: {error}",
                            token.token_id
                        );
                        true
                    })
            };
            if !revoked {
                return false;
            }
        }
        // No provisioned token for the seat, or every one of them revoked:
        // the seat holds no live dispatch authority, so intake refuses.
        true
    }

    fn stopped(&self, identity: &str) -> bool {
        if self.posture == NodePosture::Follower {
            return true;
        }
        let Ok(ledger) = self.ledger.lock() else {
            // Unreadable stop state is degraded authority: report stopped.
            tracing::error!(
                "stop state unreadable identity={identity} reason=bridge ledger lock poisoned; reporting stopped"
            );
            return true;
        };
        odin_ledger::operation::stop_row(ledger.connection(), identity)
            .map(|row| row.is_some())
            .unwrap_or(true)
    }
}

/// The daemon's real `terminal.read` source: the supervisor's bounded
/// read-only screen capture of the resolved governed terminal target,
/// bridged from the sync seam onto the composition runtime through a
/// dedicated thread so no runtime worker is ever blocked. The receive
/// bound stays under the capability's 30s timeout; a late capture only
/// lands in a dropped channel.
pub(super) struct DaemonTerminalReadRoute {
    pub(super) supervisor: Arc<odin_omp::live::supervisor::LiveSupervisor>,
    pub(super) handle: tokio::runtime::Handle,
}

impl odin_hermes::runtime::TerminalReadRoute for DaemonTerminalReadRoute {
    fn read_screen(
        &self,
        session: &str,
        max_bytes: usize,
    ) -> Result<odin_hermes::runtime::TerminalScreenRead, String> {
        let supervisor = Arc::clone(&self.supervisor);
        let handle = self.handle.clone();
        let session = session.to_owned();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("odind-terminal-read".to_owned())
            .spawn(move || {
                let outcome = handle
                    .block_on(supervisor.capture_terminal_screen(&session, max_bytes))
                    .map_err(|error| error.to_string());
                let _ = sender.send(outcome);
            })
            .map_err(|error| format!("terminal read bridge thread failed: {error}"))?;
        let capture = receiver
            .recv_timeout(StdDuration::from_secs(20))
            .map_err(|error| {
                format!("terminal screen capture did not return within its bound: {error}")
            })?
            .map_err(|error| format!("terminal screen capture failed: {error}"))?;
        Ok(odin_hermes::runtime::TerminalScreenRead {
            session: capture.zellij_session,
            content: capture.content,
            truncated: capture.truncated,
        })
    }
}

/// The daemon's real `huginn.read` source: the live plane's own roster and
/// session listing joined with supervisor facts, projected read-only.
/// Nothing is synthesized — an unreachable plane is a typed error, and a
/// session the plane does not serve is an honest refusal, never a
/// fabricated snapshot.
pub(super) struct DaemonHuginnReadRoute {
    pub(super) plane: Arc<odin_omp::live::service::OmpLiveService>,
    pub(super) supervisor: Arc<odin_omp::live::supervisor::LiveSupervisor>,
    pub(super) node: String,
    pub(super) handle: tokio::runtime::Handle,
}

impl DaemonHuginnReadRoute {
    fn bridge<T: Send + 'static>(
        &self,
        future: impl Future<Output = Result<T, String>> + Send + 'static,
    ) -> Result<T, String> {
        let (sender, receiver) = std::sync::mpsc::channel::<Result<T, String>>();
        let handle = self.handle.clone();
        std::thread::Builder::new()
            .name("odind-huginn-read".to_owned())
            .spawn(move || {
                let _ = sender.send(handle.block_on(future));
            })
            .map_err(|error| format!("huginn read bridge thread failed: {error}"))?;
        receiver
            .recv_timeout(StdDuration::from_secs(20))
            .map_err(|error| format!("huginn read did not return within its bound: {error}"))?
    }

    async fn live_sessions(
        plane: Arc<odin_omp::live::service::OmpLiveService>,
    ) -> Result<Vec<live::LiveSessionSummary>, String> {
        let mut sessions = Vec::new();
        let mut cursor = None;
        loop {
            let page = plane
                .sessions(live::SessionListQuery {
                    seat_id: None,
                    include_ended: false,
                    cursor,
                    limit: NonZeroU16::new(128).expect("128 is non-zero"),
                })
                .await
                .map_err(|error| format!("live session listing failed: {error}"))?;
            sessions.extend(page.sessions);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => return Ok(sessions),
            }
        }
    }
}

impl odin_hermes::runtime::HuginnReadRoute for DaemonHuginnReadRoute {
    fn status(&self) -> Result<serde_json::Value, String> {
        let node = self.node.clone();
        let supervisor = Arc::clone(&self.supervisor);
        let plane = Arc::clone(&self.plane);
        self.bridge(async move {
            // The live count is the plane's roster: each bound seat's current
            // sessions in the warm working set (live actors and parked
            // recoverable sessions) — the exact population the public
            // sessions surface adopts. The durable listing is not it: its
            // non-terminal rows include cold sessions an earlier daemon
            // lifetime left resumable on demand, which no actor serves.
            let roster = plane
                .roster()
                .await
                .map_err(|error| format!("live session roster failed: {error}"))?;
            let live_sessions: usize = roster
                .seats
                .iter()
                .map(|seat| seat.active_sessions.len())
                .sum();
            let terminal = supervisor
                .terminal_target_status()
                .await
                .map_err(|error| format!("terminal target status failed: {error}"))?;
            Ok(serde_json::json!({
                "node": node,
                "liveSessions": live_sessions,
                "terminalTarget": {
                    "bound": terminal.bound,
                    "zellijSession": terminal.zellij_session,
                },
            }))
        })
    }

    fn session_projection(&self, session: &str) -> Result<serde_json::Value, String> {
        let wanted = session.to_owned();
        let plane = Arc::clone(&self.plane);
        self.bridge(async move {
            let sessions = Self::live_sessions(plane).await?;
            let Some(summary) = sessions
                .iter()
                .find(|summary| summary.session_id.to_string() == wanted)
            else {
                return Err(format!(
                    "no live session {wanted} is served by this daemon; the projection \
                     refuses to synthesize one"
                ));
            };
            Ok(serde_json::json!({
                "sessionId": summary.session_id.to_string(),
                "seat": summary.seat_id.as_str(),
                "state": format!("{:?}", summary.state),
                "epoch": summary.epoch.get(),
                "eventHead": serde_json::to_value(summary.event_head)
                    .unwrap_or(serde_json::Value::Null),
                "pendingPermissions": summary.pending_permission_count,
                "startedAt": summary.started_at.unix_timestamp(),
                "updatedAt": summary.updated_at.unix_timestamp(),
            }))
        })
    }
}

/// The daemon's real `workspace.connect` resolver: read-only resolution
/// over the pinned registry snapshot and the shared live read model. A
/// zellij session target resolves from the projected `zellij-sessions`
/// placements; a project target resolves to the declared authority host
/// (or the explicitly named host); every host name, tailscale name, and
/// source root is declaration or read-model data — nothing is hardcoded.
/// An offline host and an unknown target refuse typed; nothing here
/// executes the resolved command.
pub(super) struct DaemonWorkspaceConnectRoute {
    pub(super) pin: Arc<odin_registry::SnapshotHandle>,
    pub(super) read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
    /// The host-provisioned project roots (`[projects.<id>] root`), the
    /// same on every fleet host; the registry never carries host paths.
    pub(super) project_roots:
        std::collections::BTreeMap<String, odin_huginn::config::OdindProjectConfig>,
    /// The runtime manifest's declared ssh.
    pub(super) ssh: std::path::PathBuf,
}

impl DaemonWorkspaceConnectRoute {
    /// The declared tailscale name of one host: the live fleet view first,
    /// the pinned declaration as the authority of record, and a typed
    /// refusal when the host is not an enabled+enrolled declaration.
    fn host_tailscale(
        registry: &odin_registry::Snapshot,
        capture: &odin_huginn::read_model::ReadModelCapture,
        host_id: &str,
    ) -> Result<String, String> {
        for object in &capture.objects {
            if object.object.kind != live::ObjectKind::FleetHost || object.object.id != host_id {
                continue;
            }
            if let Some(tailscale) = object.value.get("tailscale").and_then(|v| v.as_str()) {
                return Ok(tailscale.to_owned());
            }
        }
        for object in registry.listed_objects(odin_registry::RegistryKind::Host) {
            let odin_registry::ObjectConfig::Host(host) = &object.config else {
                continue;
            };
            if object.id == host_id && host.enabled && host.enrolled {
                return Ok(host.tailscale.clone());
            }
        }
        Err(format!(
            "host {host_id} is not a declared enabled+enrolled fleet host"
        ))
    }

    /// Refuse offline hosts with their preserved last-seen timestamp.
    fn refuse_offline(
        capture: &odin_huginn::read_model::ReadModelCapture,
        host_id: &str,
    ) -> Result<(), String> {
        for object in &capture.objects {
            if object.object.kind != live::ObjectKind::FleetHost || object.object.id != host_id {
                continue;
            }
            if object.value.get("online") == Some(&serde_json::Value::Bool(false)) {
                let last_seen = object
                    .value
                    .get("lastSeen")
                    .and_then(|v| v.as_str())
                    .unwrap_or("never");
                return Err(format!("host {host_id} is offline (last seen {last_seen})"));
            }
            return Ok(());
        }
        // No live observation yet: liveness cannot be proven either way,
        // so the declared host resolves and the connect attempt itself
        // stays the bounded probe of record.
        Ok(())
    }
}

impl odin_hermes::runtime::WorkspaceConnectRoute for DaemonWorkspaceConnectRoute {
    fn connect(
        &self,
        host: Option<&str>,
        target: &str,
    ) -> Result<odin_hermes::runtime::WorkspaceConnection, String> {
        use odin_hermes::runtime::WorkspaceConnectionKind;
        let target = target.trim();
        if target.is_empty() {
            return Err("target must name a zellij session or a declared project".to_owned());
        }
        let registry = self.pin.current();
        let capture = self.read_model.capture().map_err(|error| {
            format!("workspace connect could not capture the live read model: {error}")
        })?;

        // (a) A zellij session: the target names itself in some projected
        // `zellij-sessions` placement (narrowed to the explicit host when
        // one is given).
        for object in &capture.objects {
            if object.object.kind != live::ObjectKind::FleetPlacement {
                continue;
            }
            if object.value.get("thing").and_then(|v| v.as_str()) != Some("zellij-sessions") {
                continue;
            }
            if let Some(want) = host {
                if object.value.get("host").and_then(|v| v.as_str()) != Some(want) {
                    continue;
                }
            }
            let names = object.value.get("names").and_then(|v| v.as_array());
            let named = names
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str())
                .any(|name| name == target);
            if !named {
                continue;
            }
            let Some(placement_host) = object.value.get("host").and_then(|v| v.as_str()) else {
                return Err(format!(
                    "the zellij placement {} carries no host",
                    object.object.id
                ));
            };
            Self::refuse_offline(&capture, placement_host)?;
            let tailscale = Self::host_tailscale(&registry, &capture, placement_host)?;
            return Ok(odin_hermes::runtime::WorkspaceConnection {
                command: format!("zr {tailscale} {target}"),
                kind: WorkspaceConnectionKind::Zellij,
                host: placement_host.to_owned(),
                target: target.to_owned(),
            });
        }

        // (b) A declared project: the explicitly named host, else the
        // declared authority host's live placement.
        for object in registry.listed_objects(odin_registry::RegistryKind::Project) {
            let odin_registry::ObjectConfig::Project(project) = &object.config else {
                continue;
            };
            if object.id != target || !project.enabled {
                continue;
            }
            let resolved_host = match host {
                Some(host) => host.to_owned(),
                None => capture
                    .objects
                    .iter()
                    .find(|object| {
                        object.object.kind == live::ObjectKind::FleetPlacement
                            && object.value.get("thing").and_then(|v| v.as_str())
                                == Some("odind-authority")
                    })
                    .and_then(|object| object.value.get("host").and_then(|v| v.as_str()))
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        "no odind-authority placement is projected yet; name the host \
                         explicitly"
                            .to_owned()
                    })?,
            };
            Self::refuse_offline(&capture, &resolved_host)?;
            let tailscale = Self::host_tailscale(&registry, &capture, &resolved_host)?;
            let root = self
                .project_roots
                .get(target)
                .ok_or_else(|| format!("project {target} has no provisioned root on the fleet"))?;
            let source_root = root.root.to_string_lossy();
            let source_root = source_root.trim_start_matches('/');
            return Ok(odin_hermes::runtime::WorkspaceConnection {
                command: format!("zed ssh://{tailscale}/{source_root}"),
                kind: WorkspaceConnectionKind::Zed,
                host: resolved_host,
                target: target.to_owned(),
            });
        }

        Err(format!(
            "zellij session or project {target} was not found in the fleet placements or \
             the declared projects"
        ))
    }

    fn open(
        &self,
        connection: &odin_hermes::runtime::WorkspaceConnection,
        device: &str,
    ) -> Result<String, String> {
        let (command, what) = workspace_open_command(connection)?;
        self.on_desktop(
            device,
            &format!("systemd-run --user --collect --quiet -- {command}"),
            None,
        )
        .map_err(|failure| failure.sentence(device, "nothing was opened"))?;
        tracing::info!(
            "workspace opened device={device} kind={} target={} host={}",
            connection.kind.as_str(),
            connection.target,
            connection.host
        );
        Ok(format!("{what} opened on the {device}'s screen"))
    }

    fn open_owned(
        &self,
        connection: &odin_hermes::runtime::WorkspaceConnection,
        device: &str,
        launch_owner: &str,
    ) -> Result<(String, odin_hermes::runtime::WorkspaceOwnership), String> {
        let (script, what) = workspace_owned_command(connection, launch_owner)?;
        /// How long an owned workspace launch may take to return its lease.
        const OWNED_LAUNCH_BOUND: std::time::Duration = std::time::Duration::from_secs(45);
        let output = self
            .on_desktop(device, &script, Some(OWNED_LAUNCH_BOUND))
            .map_err(|failure| {
                failure.sentence(device, "owned workspace launch did not return a lease")
            })?;
        let ownership: odin_hermes::runtime::WorkspaceOwnership =
            serde_json::from_slice(&output)
                .map_err(|error| format!("invalid owned workspace lease: {error}"))?;
        if ownership.unit != format!("odin-workspace-{launch_owner}.service")
            || ownership.owner.invocation.len() != 32
            || !ownership
                .owner
                .invocation
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || !ownership.owner.group.starts_with("/user.slice/")
            || !ownership
                .owner
                .group
                .ends_with(&format!("/{}", ownership.unit))
            || ownership.owner.inode == 0
        {
            return Err("owned workspace lease did not match its dedicated launch".to_owned());
        }
        tracing::info!(
            "workspace opened device={device} kind={} target={} host={} owner={launch_owner} unit={}",
            connection.kind.as_str(),
            connection.target,
            connection.host,
            ownership.unit
        );
        Ok((format!("{what} opened on the {device}'s screen"), ownership))
    }
}

/// Why a command did not run in the owner's desktop session on a device.
enum DesktopFailure {
    NoSession,
    Locked,
    Unreachable,
    Failed(String),
}

impl DesktopFailure {
    fn sentence(self, device: &str, outcome: &str) -> String {
        match self {
            Self::NoSession => {
                format!("nobody is logged in to a desktop on the {device}, so {outcome}")
            }
            Self::Locked => {
                format!("the {device}'s screen is locked, so {outcome}; unlock it and ask again")
            }
            Self::Unreachable => {
                format!("the {device} could not be reached over ssh, so {outcome}")
            }
            Self::Failed(detail) => format!("on the {device} it failed ({detail}), so {outcome}"),
        }
    }
}

impl DaemonWorkspaceConnectRoute {
    /// Runs `command` over ssh in the owner's graphical session on the declared
    /// fleet `device`: only when a desktop session is up and its screen is
    /// not locked. `bound` kills a wait that never returns (a hung ssh).
    /// Opening a window is unbounded: that ssh lives as long as the window.
    fn on_desktop(
        &self,
        device: &str,
        command: &str,
        bound: Option<std::time::Duration>,
    ) -> Result<Vec<u8>, DesktopFailure> {
        let registry = self.pin.current();
        let capture = self
            .read_model
            .capture()
            .map_err(|error| DesktopFailure::Failed(format!("live read model: {error}")))?;
        Self::refuse_offline(&capture, device).map_err(DesktopFailure::Failed)?;
        let tailscale =
            Self::host_tailscale(&registry, &capture, device).map_err(DesktopFailure::Failed)?;
        // Odin's shared ssh options: without `-F none` the sandboxed daemon's
        // ssh refuses the store-linked user config. A bound wraps ssh in
        // timeout(1) so a hung connection is killed.
        let mut command_line = match bound {
            Some(bound) => {
                let mut command_line = std::process::Command::new("timeout");
                command_line
                    .arg("--signal=KILL")
                    .arg(bound.as_secs().max(1).to_string())
                    .arg(&self.ssh);
                command_line
            }
            None => std::process::Command::new(&self.ssh),
        };
        let child = command_line
            .args(odin_omp::live::harness::SSH_OPTIONS)
            .args([tailscale.as_str(), desktop_script(command).as_str()])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|error| DesktopFailure::Failed(format!("could not start ssh: {error}")))?;
        let output = child
            .wait_with_output()
            .map_err(|error| DesktopFailure::Failed(format!("ssh did not finish: {error}")))?;
        // timeout(1) exits 124, or 137 after KILL.
        if matches!(output.status.code(), Some(124 | 137)) {
            return Err(DesktopFailure::Unreachable);
        }
        match output.status.code() {
            Some(0) => Ok(output.stdout),
            Some(OPEN_NO_SESSION) => Err(DesktopFailure::NoSession),
            Some(OPEN_LOCKED) => Err(DesktopFailure::Locked),
            Some(255) | None => Err(DesktopFailure::Unreachable),
            Some(code) => Err(DesktopFailure::Failed(format!(
                "exit {code}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))),
        }
    }
}

/// The daemon's real `fleet.drain`/`fleet.restore` surface: declaration +
/// read-model resolution over the SAME pinned snapshot and shared live
/// read model every other fleet seam reads, plus the composed kube cell
/// (`None` — `[kube]` unconfigured — keeps every cluster-touching
/// dispatch typed-unavailable). One route serves both model tools. On an
/// authority host the authority stays: the drain moves its Odin pods,
/// cordons its node and names the standby candidates. The real drain
/// rides the cell's own lazily-connected client under per-node
/// `request_timeout` bounds; anything still present at the bound is
/// reported, never retried into a hang.
pub(super) struct DaemonFleetDrainRoute {
    pub(super) pin: Arc<odin_registry::SnapshotHandle>,
    pub(super) read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
    pub(super) kube_cell: Option<Arc<crate::kube::KubeRuntimeCell>>,
    pub(super) handle: tokio::runtime::Handle,
    /// Where a drain remembers the pods it paused, for the restore.
    pub(super) state_root: PathBuf,
}

impl DaemonFleetDrainRoute {
    /// Moves the host's running Odin pods per declaration: rehome where their
    /// placement holds on another online node,
    /// else pause until the restore. One sentence per pod.
    fn drain_workloads(
        &self,
        registry: &odin_registry::Snapshot,
        host: &str,
        nodes: &[String],
    ) -> Result<Vec<String>, String> {
        let Some(cell) = self.kube_cell.as_ref() else {
            return Err("the kube surface is not composed on this daemon".to_owned());
        };
        let (control, client) = Self::bridge(&self.handle, cell.parts())
            .map_err(|error| format!("the kube surface is unavailable: {error}"))?;
        let capture = self.read_model.capture().map_err(|error| {
            format!("fleet drain could not capture the live read model: {error}")
        })?;
        let candidates: Vec<String> = Self::standby_candidates(registry, &capture, host)
            .into_iter()
            .map(|candidate| candidate.node)
            .collect();
        Self::bridge(
            &self.handle,
            super::fleet_workloads::drain(
                &control,
                &client,
                host,
                nodes,
                &candidates,
                &self.state_root,
            ),
        )
    }

    /// Use block_in_place on a runtime worker; plain threads use the composition handle.
    fn bridge<T>(handle: &tokio::runtime::Handle, future: impl Future<Output = T>) -> T {
        match tokio::runtime::Handle::try_current() {
            Ok(current) => tokio::task::block_in_place(|| current.block_on(future)),
            Err(_) => handle.block_on(future),
        }
    }

    /// The host's enabled registry nodes, read from the pinned snapshot:
    /// every name is declaration data, never a model argument.
    fn host_nodes(registry: &odin_registry::Snapshot, host_id: &str) -> Vec<String> {
        registry
            .listed_objects(odin_registry::RegistryKind::Node)
            .filter_map(|object| match &object.config {
                odin_registry::ObjectConfig::Node(node) if node.enabled && node.host == host_id => {
                    Some(object.id.clone())
                }
                _ => None,
            })
            .collect()
    }

    /// The declared standby candidates: enabled nodes that do not hold
    /// the authoritative state, allow workloads, sit on an
    /// enabled+enrolled host that is online in the live fleet view, and
    /// are not on the host being drained. Listing a candidate is not
    /// choosing it — the choice is the operator's.
    fn standby_candidates(
        registry: &odin_registry::Snapshot,
        capture: &odin_huginn::read_model::ReadModelCapture,
        drained_host: &str,
    ) -> Vec<odin_hermes::runtime::StandbyCandidate> {
        let host_enabled_enrolled = |host_id: &str| {
            registry
                .listed_objects(odin_registry::RegistryKind::Host)
                .any(|object| {
                    object.id == host_id
                        && matches!(
                            &object.config,
                            odin_registry::ObjectConfig::Host(host)
                                if host.enabled && host.enrolled
                        )
                })
        };
        let host_online = |host_id: &str| {
            capture.objects.iter().all(|object| {
                object.object.kind != live::ObjectKind::FleetHost
                    || object.object.id != host_id
                    || object.value.get("online") != Some(&serde_json::Value::Bool(false))
            })
        };
        registry
            .listed_objects(odin_registry::RegistryKind::Node)
            .filter_map(|object| match &object.config {
                odin_registry::ObjectConfig::Node(node)
                    if node.enabled
                        && !node.authoritative_state
                        && node.allow_workloads
                        && node.host != drained_host
                        && host_enabled_enrolled(&node.host)
                        && host_online(&node.host) =>
                {
                    Some(odin_hermes::runtime::StandbyCandidate {
                        node: object.id.clone(),
                        host: node.host.clone(),
                    })
                }
                _ => None,
            })
            .collect()
    }
}

/// Distinguish completed pod moves and cordon from the authority move drain leaves undone.
fn authority_drain_note(workloads: &[String], node: &str, cordoned: bool) -> String {
    let moved = if workloads.is_empty() {
        "no Odin pod was running there".to_owned()
    } else {
        "every Odin pod listed in `workloads` was moved or paused exactly as each line says"
            .to_owned()
    };
    let cordon = if cordoned {
        format!("node {node} is cordoned, so no new pod lands on it")
    } else {
        format!("node {node} could NOT be cordoned")
    };
    format!(
        "ALREADY DONE by this drain: {moved}; {cordon}. NOT done: Odin's authority stays on this \
         host; `candidates` lists the declared nodes that could take it."
    )
}

impl odin_hermes::runtime::FleetDrainRoute for DaemonFleetDrainRoute {
    fn resolve(&self, host: &str) -> Result<odin_hermes::runtime::FleetDrainResolution, String> {
        let registry = self.pin.current();
        let declared = registry
            .listed_objects(odin_registry::RegistryKind::Host)
            .any(|object| {
                object.id == host
                    && matches!(
                        &object.config,
                        odin_registry::ObjectConfig::Host(host)
                            if host.enabled && host.enrolled
                    )
            });
        if !declared {
            return Err(format!(
                "host {host} is not a declared enabled+enrolled fleet host"
            ));
        }
        let capture = self.read_model.capture().map_err(|error| {
            format!("fleet drain could not capture the live read model: {error}")
        })?;
        DaemonWorkspaceConnectRoute::refuse_offline(&capture, host)?;
        let nodes = Self::host_nodes(&registry, host);
        if nodes.is_empty() {
            return Err(format!("host {host} declares no enabled registry nodes"));
        }
        let authority_node = registry
            .listed_objects(odin_registry::RegistryKind::Node)
            .find_map(|object| match &object.config {
                odin_registry::ObjectConfig::Node(node)
                    if node.enabled && node.authoritative_state && nodes.contains(&object.id) =>
                {
                    Some(object.id.clone())
                }
                _ => None,
            });
        Ok(odin_hermes::runtime::FleetDrainResolution {
            host: host.to_owned(),
            nodes,
            authority_node,
            kube_ready: self.kube_cell.is_some(),
        })
    }

    fn drain(&self, host: &str) -> Result<odin_hermes::runtime::FleetDrainOutcome, String> {
        let resolution = self.resolve(host)?;
        let registry = self.pin.current();
        // The host's Odin pods move first, per declaration, through the
        // kernel's own lifecycle operations.
        let workloads = self.drain_workloads(&registry, host, &resolution.nodes)?;
        if let Some(authority_node) = resolution.authority_node.as_deref() {
            // The authority itself stays; the answer names where it could
            // go. Its node is cordoned so nothing new lands there; the
            // cluster's own pods are not evicted.
            let capture = self.read_model.capture().map_err(|error| {
                format!("fleet drain could not capture the live read model: {error}")
            })?;
            let candidates = Self::standby_candidates(&registry, &capture, host);
            let mut cordoned = false;
            if let Some(cell) = self.kube_cell.as_ref() {
                let (_control, client) = Self::bridge(&self.handle, cell.parts())
                    .map_err(|error| format!("the kube surface is unavailable: {error}"))?;
                cordoned = true;
                for node in &resolution.nodes {
                    if let Err(error) =
                        Self::bridge(&self.handle, odin_kube::node_admin::cordon(&client, node))
                    {
                        tracing::error!("fleet drain cordon failed node={node}: {error}");
                        cordoned = false;
                    }
                }
            }
            return Ok(odin_hermes::runtime::FleetDrainOutcome {
                host: host.to_owned(),
                node: authority_node.to_owned(),
                result: odin_hermes::runtime::FleetDrainResult::AuthorityMovePlan,
                cordoned,
                evicted: Vec::new(),
                remained: Vec::new(),
                authority_holds: true,
                plan: Some(odin_hermes::runtime::AuthorityMovePlan {
                    candidates,
                    note: authority_drain_note(&workloads, authority_node, cordoned),
                }),
                workloads,
            });
        }
        let Some(cell) = self.kube_cell.as_ref() else {
            return Err("the kube surface is not composed on this daemon".to_owned());
        };
        let (request_timeout, _teardown) = cell.kube_bounds();
        let (_control, client) = Self::bridge(&self.handle, cell.parts())
            .map_err(|error| format!("the kube surface is unavailable: {error}"))?;
        // One reporting-margin second: the drain folds its own honest
        // remained-report at the deadline, and the outer uncertainty
        // backstop only ever fires on a genuinely hung request.
        let inner_deadline = request_timeout
            .checked_sub(StdDuration::from_secs(1))
            .unwrap_or(request_timeout);
        let mut evicted = Vec::new();
        let mut remained = Vec::new();
        let mut cordoned = true;
        for node in &resolution.nodes {
            let attempt = Self::bridge(
                &self.handle,
                tokio::time::timeout(
                    request_timeout,
                    odin_kube::node_admin::drain(&client, node, inner_deadline),
                ),
            );
            match attempt {
                Ok(Ok(report)) => {
                    evicted.extend(report.evicted);
                    remained.extend(report.remained);
                    cordoned &= report.cordoned;
                }
                Ok(Err(error)) if error.is_unavailable() => {
                    return Err(format!(
                        "fleet drain of node {node} exceeded its bounded window after \
                         dispatch: the node may already be cordoned with pods still \
                         draining — treat the node state as uncertain, re-observe before \
                         any retry ({error})"
                    ));
                }
                Ok(Err(error)) => {
                    return Err(format!(
                        "the API server refused the fleet drain of node {node}: {error}"
                    ));
                }
                Err(_elapsed) => {
                    return Err(format!(
                        "fleet drain of node {node} exceeded its bounded window after \
                         dispatch: the node may already be cordoned with pods still \
                         draining — treat the node state as uncertain, re-observe before \
                         any retry"
                    ));
                }
            }
        }
        Ok(odin_hermes::runtime::FleetDrainOutcome {
            host: host.to_owned(),
            node: resolution.nodes.join(", "),
            result: odin_hermes::runtime::FleetDrainResult::Drained,
            cordoned,
            evicted,
            remained,
            authority_holds: false,
            plan: None,
            workloads,
        })
    }

    fn restore(&self, host: &str) -> Result<odin_hermes::runtime::FleetRestoreOutcome, String> {
        let resolution = self.resolve(host)?;
        let Some(cell) = self.kube_cell.as_ref() else {
            return Err("the kube surface is not composed on this daemon".to_owned());
        };
        let (control, client) = Self::bridge(&self.handle, cell.parts())
            .map_err(|error| format!("the kube surface is unavailable: {error}"))?;
        let uncordoned = true;
        let mut schedulable = true;
        for node in &resolution.nodes {
            match Self::bridge(&self.handle, odin_kube::node_admin::uncordon(&client, node)) {
                Ok(node_schedulable) => {
                    schedulable &= node_schedulable;
                }
                Err(error) => {
                    return Err(format!(
                        "the restore of node {node} was refused by the kube surface: {error}"
                    ));
                }
            }
        }
        Ok(odin_hermes::runtime::FleetRestoreOutcome {
            host: host.to_owned(),
            node: resolution.nodes.join(", "),
            uncordoned,
            schedulable,
            resumed: Self::bridge(
                &self.handle,
                super::fleet_workloads::restore(&control, host, &self.state_root),
            ),
        })
    }
}

/// A failed bridge or timed-out wait cannot establish command completion.
enum BridgeFailure {
    Timeout(String),
    Failed(String),
}

/// The daemon's real live model-command route: the live plane's own
/// session authority and governed command seam, plus the declared
/// conversation vehicle of the surface seat. Both methods bridge the
/// async plane onto the composition runtime through a dedicated thread
/// (the same discipline as the read routes), bounded under the
/// capability's timeout. Unbound (hermes absent) keeps every model-switch
/// dispatch typed-unavailable, never stubbed.
pub(super) struct DaemonModelCommandRoute {
    pub(super) plane: Arc<odin_omp::live::service::OmpLiveService>,
    /// Resolve the assistant session from the conversation record when present;
    /// otherwise use the live-session authority.
    pub(super) vehicle: Option<(
        odin_domain::SeatId,
        Arc<odin_hermes::conversation::ConversationRoot>,
    )>,
    pub(super) handle: tokio::runtime::Handle,
    /// Declares a seat's model in the registry; `None` without an authoring
    /// repository.
    pub(super) declare: Option<Arc<crate::project_authoring::DaemonProjectRoute>>,
}

impl DaemonModelCommandRoute {
    /// Run on a dedicated thread with a receive timeout; late results are discarded.
    fn bridge<T: Send + 'static>(
        &self,
        name: &str,
        future: impl Future<Output = Result<T, String>> + Send + 'static,
    ) -> Result<T, BridgeFailure> {
        let (sender, receiver) = std::sync::mpsc::channel::<Result<T, String>>();
        let handle = self.handle.clone();
        std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                let _ = sender.send(handle.block_on(future));
            })
            .map_err(|error| {
                BridgeFailure::Failed(format!("model route bridge thread failed: {error}"))
            })?;
        receiver
            .recv_timeout(StdDuration::from_secs(20))
            .map_err(|error| {
                if error == std::sync::mpsc::RecvTimeoutError::Timeout {
                    BridgeFailure::Timeout(format!(
                        "the live model route did not return within its bound: {error}"
                    ))
                } else {
                    BridgeFailure::Failed(format!(
                        "the live model route bridge closed early: {error}"
                    ))
                }
            })?
            .map_err(BridgeFailure::Failed)
    }

    async fn survey(
        plane: Arc<odin_omp::live::service::OmpLiveService>,
        root: Option<Arc<odin_hermes::conversation::ConversationRoot>>,
        seat: odin_domain::SeatId,
    ) -> Result<odin_hermes::runtime::SeatSessionSurvey, String> {
        let declared_vehicle = match &root {
            Some(root) => root.current_vehicle_session().await?,
            None => None,
        };
        let mut live_sessions = Vec::new();
        let mut cursor = None;
        loop {
            let page = plane
                .sessions(live::SessionListQuery {
                    seat_id: Some(seat.clone()),
                    include_ended: false,
                    cursor,
                    limit: NonZeroU16::new(128).expect("128 is non-zero"),
                })
                .await
                .map_err(|error| format!("live session listing failed: {error}"))?;
            live_sessions.extend(page.sessions);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => {
                    return Ok(odin_hermes::runtime::SeatSessionSurvey {
                        declared_vehicle,
                        live_sessions,
                    })
                }
            }
        }
    }
}

impl odin_hermes::runtime::ModelCommandRoute for DaemonModelCommandRoute {
    fn survey_seat(
        &self,
        seat: &odin_domain::SeatId,
    ) -> Result<odin_hermes::runtime::SeatSessionSurvey, odin_hermes::runtime::ModelRouteError>
    {
        // The vehicle only ever serves ITS OWN seat's survey: another
        // seat's selection stays purely on the live-session authority.
        let root = self
            .vehicle
            .as_ref()
            .filter(|(vehicle_seat, _)| vehicle_seat == seat)
            .map(|(_, root)| Arc::clone(root));
        let plane = Arc::clone(&self.plane);
        let seat = seat.clone();
        self.bridge("odind-model-survey", Self::survey(plane, root, seat))
            .map_err(|failure| match failure {
                BridgeFailure::Timeout(detail) | BridgeFailure::Failed(detail) => {
                    odin_hermes::runtime::ModelRouteError::Refused(detail)
                }
            })
    }

    fn persist_choice(
        &self,
        seat: &odin_domain::SeatId,
        provider: &live::ProviderName,
        model: &live::ModelName,
        by: &str,
    ) -> Result<String, odin_hermes::runtime::ModelRouteError> {
        let route = self.declare.as_ref().ok_or_else(|| {
            odin_hermes::runtime::ModelRouteError::Refused(format!(
                "seat {seat}'s model cannot be declared: this authority has no authoring repository"
            ))
        })?;
        route
            .declare_seat_model(seat.as_str(), provider.as_str(), model.as_str(), by)
            .map_err(odin_hermes::runtime::ModelRouteError::Refused)
    }

    fn command_set_model(
        &self,
        command: odin_hermes::runtime::ModelSetCommand,
    ) -> Result<live::CommandReceipt, odin_hermes::runtime::ModelRouteError> {
        let plane = Arc::clone(&self.plane);
        self.bridge("odind-model-command", async move {
            // The sole route: the real plane command seam issuing the
            // governed `SetModel` body against the exact session and
            // epoch. A moved epoch or inapplicable state surfaces as
            // the receipt's typed rejection — never a retry here.
            plane
                .command(live::LiveCommand {
                    command_id: command.command_id,
                    session_id: command.session_id,
                    expected_epoch: command.expected_epoch,
                    expected_event_head: None,
                    body: live::LiveCommandBody::SetModel {
                        provider: command.provider,
                        model: command.model,
                        route: None,
                    },
                })
                .await
                .map_err(|error| format!("the live model command did not settle: {error}"))
        })
        .map_err(|failure| match failure {
            BridgeFailure::Timeout(detail) | BridgeFailure::Failed(detail) => {
                odin_hermes::runtime::ModelRouteError::Uncertain(detail)
            }
        })
    }
}

/// Maps the strict daemon `[hermes]` wire section onto the validated
/// runtime settings. Pure field binding: the semantic validation lives in
/// the daemon schema and the `odin-hermes` composition constructors.
pub(super) fn hermes_settings(
    section: &odin_huginn::config::OdindHermesConfig,
) -> Result<odin_hermes::config::HermesSettings, String> {
    let discord = match &section.discord {
        Some(discord) => Some(
            odin_hermes::config::DiscordSettings::new(odin_hermes::config::DiscordSettingsInput {
                seat: &discord.seat,
                project: &discord.project,
                owner_user_id: discord.owner_user_id.clone(),
                owner_name: discord.owner_name.clone(),
                notify_channel_id: discord.notify_channel_id.clone(),
                capability: &discord.capability,
                egress_capacity: discord.egress_capacity,
                gateway_intents: discord.gateway_intents,
                bot_token_handle: discord.bot_token_handle.clone(),
                scrub_tokens: discord.scrub_tokens.clone(),
                ttl_seconds: discord.ttl_seconds,
            })
            .map_err(|error| error.to_string())?,
        ),
        None => None,
    };
    let vault = section
        .vault
        .as_ref()
        .map(|vault| odin_hermes::vault::VaultConfig {
            vault_root: vault.vault_root.clone(),
            source_id: vault.source_id.clone(),
            silverbullet: vault.silverbullet_port.map(|port| {
                odin_hermes::vault::SilverBulletConfig {
                    port,
                    expected_space_root: vault.silverbullet_space_root.clone(),
                }
            }),
            general_namespaces: vault.general_namespaces.clone(),
            generated_namespace: vault.generated_namespace.clone(),
            excluded_namespaces: vault.excluded_namespaces.clone(),
            max_pages: vault.max_pages,
            max_page_bytes: vault.max_page_bytes,
            timeout_ms: vault.timeout_ms,
        });
    let accounts = section
        .accounts
        .iter()
        .map(|account| {
            let provider = match &account.provider {
                odin_huginn::config::OdindHermesProviderConfig::Jmap {
                    session_url,
                    identity_id,
                    from_address,
                    drafts_mailbox_id,
                    archive_mailbox_id,
                    trash_mailbox_id,
                    calendar_id,
                    request_timeout_ms,
                    max_response_bytes,
                } => odin_hermes::config::LifeProviderSettings::Jmap {
                    session_url: session_url.clone(),
                    identity_id: identity_id.clone(),
                    from_address: from_address.clone(),
                    drafts_mailbox_id: drafts_mailbox_id.clone(),
                    archive_mailbox_id: archive_mailbox_id.clone(),
                    trash_mailbox_id: trash_mailbox_id.clone(),
                    calendar_id: calendar_id.clone(),
                    request_timeout_ms: *request_timeout_ms,
                    max_response_bytes: *max_response_bytes,
                },
                odin_huginn::config::OdindHermesProviderConfig::Google {
                    token_url,
                    gmail_api_url,
                    calendar_api_url,
                    calendar_id,
                    request_timeout_ms,
                    max_response_bytes,
                    ..
                } => odin_hermes::config::LifeProviderSettings::Google {
                    token_url: token_url.clone(),
                    gmail_api_url: gmail_api_url.clone(),
                    calendar_api_url: calendar_api_url.clone(),
                    calendar_id: calendar_id.clone(),
                    request_timeout_ms: *request_timeout_ms,
                    max_response_bytes: *max_response_bytes,
                },
                odin_huginn::config::OdindHermesProviderConfig::Generic {
                    from_address,
                    imap_host,
                    imap_port,
                    imap_tls,
                    smtp_host,
                    smtp_port,
                    smtp_tls,
                    helo_name,
                    inbox_mailbox_id,
                    drafts_mailbox_id,
                    archive_mailbox_id,
                    trash_mailbox_id,
                    caldav_base_url,
                    caldav_calendar_url,
                    request_timeout_ms,
                    max_response_bytes,
                } => {
                    let tls = |mode: &odin_huginn::config::OdindHermesMailTls| match mode {
                        odin_huginn::config::OdindHermesMailTls::ImplicitTls => {
                            odin_hermes::config::MailTls::ImplicitTls
                        }
                        odin_huginn::config::OdindHermesMailTls::StartTls => {
                            odin_hermes::config::MailTls::StartTls
                        }
                    };
                    odin_hermes::config::LifeProviderSettings::Generic {
                        from_address: from_address.clone(),
                        imap_host: imap_host.clone(),
                        imap_port: *imap_port,
                        imap_tls: tls(imap_tls),
                        smtp_host: smtp_host.clone(),
                        smtp_port: *smtp_port,
                        smtp_tls: tls(smtp_tls),
                        helo_name: helo_name.clone(),
                        inbox_mailbox_id: inbox_mailbox_id.clone(),
                        drafts_mailbox_id: drafts_mailbox_id.clone(),
                        archive_mailbox_id: archive_mailbox_id.clone(),
                        trash_mailbox_id: trash_mailbox_id.clone(),
                        caldav_base_url: caldav_base_url.clone(),
                        caldav_calendar_url: caldav_calendar_url.clone(),
                        request_timeout_ms: *request_timeout_ms,
                        max_response_bytes: *max_response_bytes,
                    }
                }
            };
            odin_hermes::config::LifeAccountSettings {
                account: account.account.clone(),
                secret_handle: account.secret_handle.clone(),
                secret_path: account.secret_path.clone(),
                provider,
            }
        })
        .collect();
    let mut settings = odin_hermes::config::HermesSettings::new(
        section.state_dir.clone(),
        discord,
        vault,
        accounts,
    )
    .map_err(|error| error.to_string())?;
    settings.brain_raw_root = section.brain_raw_root.clone();
    Ok(settings)
}

/// The one shared Hermes-vault derivation for brain composition outside
/// the live runtime: the same `hermes_settings` mapper and the same
/// `VaultBridge::new` validation the daemon's `HermesRuntime::open`
/// applies to its vault singleton. Operator commands (the archive CLI)
/// pass the resulting bridge's config to `brain_sources` so a declared
/// `memory.<seat>` source composes on exactly the terms the daemon
/// composes it; no [hermes.vault] section yields `None` and the source
/// refuses typed downstream — never a second, weaker authority.
pub(super) fn configured_hermes_vault(
    config: &odin_huginn::OdindConfig,
) -> Result<Option<odin_hermes::vault::VaultBridge>, String> {
    let settings = match config.hermes.as_ref().map(hermes_settings) {
        Some(parsed) => Some(parsed?),
        None => None,
    };
    Ok(match settings.and_then(|settings| settings.vault) {
        Some(vault) => Some(
            odin_hermes::vault::VaultBridge::new(vault)
                .map_err(|error| format!("the configured Hermes vault is invalid: {error}"))?,
        ),
        None => None,
    })
}

#[cfg(test)]
mod vault_derivation_tests {
    use super::*;

    fn vault_section(root: &std::path::Path) -> odin_huginn::config::OdindHermesConfig {
        odin_huginn::config::OdindHermesConfig {
            consult: None,
            state_dir: root.join("hermes"),
            discord: None,
            vault: Some(odin_huginn::config::OdindHermesVaultConfig {
                vault_root: root.join("vault"),
                source_id: "atlas.personal".to_owned(),
                silverbullet_port: None,
                silverbullet_space_root: None,
                general_namespaces: vec!["knowledge".to_owned()],
                generated_namespace: "generated".to_owned(),
                excluded_namespaces: vec!["credentials".to_owned()],
                max_pages: 5000,
                max_page_bytes: 4_194_304,
                timeout_ms: 10_000,
            }),
            finance: None,
            accounts: Vec::new(),
            model_gateway: None,
            brain_raw_root: None,
        }
    }

    fn base_config() -> odin_huginn::OdindConfig {
        let text = crate::test_fixture::fixture_config_text(
            &std::env::temp_dir(),
            &std::env::temp_dir().join("no-such-snapshot.json"),
        );
        odin_huginn::OdindConfig::parse(&text).expect("fixture config parses")
    }

    #[test]
    fn configured_vault_derives_the_shared_validated_bridge() {
        let root = tempfile::tempdir().unwrap();
        let mut config = base_config();
        config.hermes = Some(vault_section(root.path()));
        let bridge = configured_hermes_vault(&config)
            .expect("a configured vault derives the shared bridge")
            .expect("the vault section yields a bridge");
        assert_eq!(bridge.config().source_id, "atlas.personal");
    }
}

#[cfg(test)]
#[path = "tests/model_route.rs"]
mod model_route_tests;
