//! Lazy k3s connections, durable R3 command admission, and posture-gated journal recovery.

use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use async_trait::async_trait;

use odin_cli::browser_runtime;
use odin_domain::extension_policy::{EXTENSION_POLICY_DIGEST_ENV, EXTENSION_POLICY_PATH_ENV};
use odin_domain::huginn as live;
use odin_domain::huginn::LiveError;
use odin_domain::huginn::SessionManifest;
use odin_domain::{ApprovalId, ArtifactId};
use odin_huginn::dispatch::AuthenticatedCommandPort;
use odin_huginn::NodePosture;
use odin_kernel::{ApprovalCommand, ApprovalGate, ApprovalRedirect, ConsumeOutcome, StopAuthority};

use odin_kube::exec::{decompose, exec_fixed, WorkloadExecStream, WorkloadLauncherSpec};
use odin_kube::job::{JobExtensionLaunch, JobModelsConfigLaunch};
use odin_ledger::approval::{Approval, ApprovalScope, NewApproval};
use odin_ledger::stop::JobStopAction;
use odin_ledger::Ledger;
use odin_omp::process::{
    HarnessStdin, OmpProcessSpec, RemoteAttachError, RemoteExit, RemoteHarnessAdmission,
    RemoteHarnessChannel, RemoteHarnessFactory,
};
use odin_types::WorkerId;
use time::OffsetDateTime;

use crate::huginn_conformance;

/// Production kube surface identities: one bounded surface artifact capsule
/// and one durable kube-events stream shared by every kube projection.
pub(super) const KUBE_SURFACE_SESSION: &str = "00000000-0000-4000-8000-000000000631";
pub(super) const KUBE_SURFACE_LANE: &str = "odin-kube-surface";
const KUBE_EVENTS_STREAM: &str = "00000000-0000-4000-8000-000000000625";

/// Real composition context for kube Job label bindings, resolved once from
/// the daemon's configured delegation route and the pinned published
/// snapshot. `launch_binding` is `None` whenever no delegation route is
/// configured — the coordinator must then refuse kube create with a typed
/// unavailable, never fabricate a binding.
#[derive(Clone, Debug)]
pub struct KubeLaunchBinding {
    pub model: String,
    pub budget_policy_digest: odin_domain::Digest,
}

/// The pinned workload image identity: the typed
/// `odin.workload-image-identity.v1` document bound to the content-addressed
/// ledger artifact holding its exact bytes. Composed once from the
/// operator-declared `kube.image_identity` path; every admission re-reads
/// the identity through the artifact, so the build output path itself is
/// consumed exactly once at startup.
#[derive(Clone, Debug)]
pub struct WorkloadExtensionIdentity {
    pub artifact: ArtifactId,
    /// The pinned image's deployment facts, for completing workload drafts.
    pub deployment: WorkloadDeploymentFacts,
}

/// The pinned workload image's deployment facts a workload draft is
/// completed from: its reference and in-image paths. The model states what
/// a pod is for; these it cannot know, so it never has to guess them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkloadDeploymentFacts {
    pub image_reference: String,
    pub launcher: String,
    pub browser: String,
    pub supervisor: String,
    pub playwright: String,
    pub xvfb: String,
    pub state_path: Option<String>,
    pub export_pod_path: Option<String>,
    /// The node's declared host export root (`[kube] export_root`).
    pub export_host_folder: Option<String>,
    /// The declared default agent-pod gateway lane (`[kube] agent_lane`).
    pub agent_lane: Option<String>,
}

impl WorkloadDeploymentFacts {
    pub fn of(
        identity: &odin_domain::WorkloadImageIdentity,
        export_root: Option<&std::path::Path>,
        agent_lane: Option<&str>,
    ) -> Self {
        let mount = |path: &str| {
            identity
                .mount_points
                .iter()
                .find(|mount| mount.as_str() == path)
                .cloned()
        };
        Self {
            image_reference: identity.reference.clone(),
            launcher: identity.tools.omp.in_image.clone(),
            browser: identity.tools.chromium.in_image.clone(),
            supervisor: identity.tools.odind.in_image.clone(),
            playwright: identity.module_roots.playwright.in_image.clone(),
            xvfb: identity.tools.xvfb.in_image.clone(),
            state_path: mount("/state"),
            export_pod_path: mount("/export"),
            export_host_folder: export_root.map(|root| root.display().to_string()),
            agent_lane: agent_lane.map(str::to_owned),
        }
    }
}

/// Lazily-connected k3s runtime cell for one configured cluster. A
/// configured surface that starts unavailable (k3s down) retries on every
/// use and every pump tick; once the API server appears it connects exactly
/// once and stays connected. Nothing here mutates the cluster and no
/// in-memory fallback cluster exists.
pub(super) struct KubeRuntimeCell {
    config: odin_kube::config::KubeConfig,
    ledger: Arc<Mutex<Ledger>>,
    stops: Arc<StopAuthority>,
    terminal_lifecycle: Arc<odin_kube::terminal_pod::PodLifecycle>,
    artifact_root: PathBuf,
    snapshot: Arc<odin_registry::Snapshot>,
    /// The generated controller config revision, pinned once at composition
    /// — the admitted generation's revision, never a value re-read at call
    /// time.
    config_revision: u64,
    launch_binding: Option<KubeLaunchBinding>,
    /// The pinned declared image identity of this deployment. Required with
    /// kube composition; workload admission refuses without one.
    workload_identity: WorkloadExtensionIdentity,
    connected:
        tokio::sync::Mutex<Option<(Arc<odin_huginn::kube::KubeControl>, odin_kube::KubeClient)>>,
}
pub(super) struct CellInputs {
    pub config: odin_kube::config::KubeConfig,
    pub ledger: Arc<Mutex<Ledger>>,
    pub stops: Arc<StopAuthority>,
    pub artifact_root: PathBuf,
    pub snapshot: Arc<odin_registry::Snapshot>,
    pub config_revision: u64,
    pub launch_binding: Option<KubeLaunchBinding>,
    pub workload_identity: WorkloadExtensionIdentity,
}

impl KubeRuntimeCell {
    pub(super) fn new(inputs: CellInputs) -> Arc<Self> {
        Arc::new(Self {
            config: inputs.config,
            ledger: inputs.ledger,
            stops: inputs.stops,
            terminal_lifecycle: Arc::default(),
            artifact_root: inputs.artifact_root,
            snapshot: inputs.snapshot,
            config_revision: inputs.config_revision,
            launch_binding: inputs.launch_binding,
            workload_identity: inputs.workload_identity,
            connected: tokio::sync::Mutex::new(None),
        })
    }

    /// The connected cluster client (connected once, shared).
    pub(crate) async fn client(&self) -> Result<odin_kube::KubeClient, odin_kube::KubeError> {
        self.parts().await.map(|(_, client)| client)
    }

    pub(crate) fn stop_authority(&self) -> Arc<StopAuthority> {
        Arc::clone(&self.stops)
    }

    pub(crate) async fn terminal_lifecycle(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, bool>, odin_kernel::stop::StopAuthorityError> {
        terminal::terminal_lifecycle_guard(&self.stops, &self.terminal_lifecycle).await
    }

    pub fn workload_identity(&self) -> &WorkloadExtensionIdentity {
        &self.workload_identity
    }

    /// The controller configuration revision pinned at composition — the
    /// admitted generation's revision for every launch this cell admits.
    pub fn config_revision(&self) -> u64 {
        self.config_revision
    }

    /// An artifact store over this cell's ledger and confined root, for
    /// digest-verified reads of registered admission artifacts.
    pub fn artifact_store(&self) -> odin_kube::artifacts::ArtifactStore {
        odin_kube::artifacts::ArtifactStore::new(
            Arc::clone(&self.ledger),
            self.artifact_root.clone(),
        )
    }

    /// The durable artifact ledger this cell registers admission material
    /// into: the same ledger the artifact store above wraps, handed to the
    /// workload producers so generated admission material binds to the
    /// launching run at registration time.
    pub fn ledger(&self) -> Arc<Mutex<Ledger>> {
        Arc::clone(&self.ledger)
    }

    /// The cell's declared cluster binding: the ownership coordinates the
    /// admission journal scopes its stored run definitions by.
    pub fn kube_config(&self) -> &odin_kube::KubeConfig {
        &self.config
    }

    /// Currently connected control, if any. `None` means the cell has not
    /// connected yet, or a connect is in progress: not a per-run release
    /// failure. Callers that need to force a connect use [`Self::parts`].
    pub fn control(&self) -> Option<Arc<odin_huginn::kube::KubeControl>> {
        self.connected
            .try_lock()
            .ok()?
            .as_ref()
            .map(|(control, _)| Arc::clone(control))
    }

    /// Connected control, waiting out a connect already in progress. `None`
    /// only when the cell has not connected yet.
    pub async fn connected_control(&self) -> Option<Arc<odin_huginn::kube::KubeControl>> {
        self.connected
            .lock()
            .await
            .as_ref()
            .map(|(control, _)| Arc::clone(control))
    }

    /// The pinned published container profile by registry id. Only enabled
    /// declarations are candidates; the caller owns seat/capability checks.
    pub fn container_profile(&self, name: &str) -> Option<&odin_registry::schema::ContainerToml> {
        let object = self
            .snapshot
            .object(odin_registry::RegistryKind::Container, name)?;
        match &object.config {
            odin_registry::schema::ObjectConfig::Container(container) if container.enabled => {
                Some(container.as_ref())
            }
            _ => None,
        }
    }

    /// Every enabled published profile with its container identity — the
    /// digest its Jobs carry — for the monitoring kernel's profile lookup.
    pub fn monitored_profiles(
        &self,
    ) -> Vec<(odin_domain::Digest, odin_registry::schema::ContainerToml)> {
        self.snapshot
            .objects
            .iter()
            .filter_map(|object| match &object.config {
                odin_registry::schema::ObjectConfig::Container(container) if container.enabled => {
                    odin_registry::ContainerIdentity::calculate(container)
                        .ok()
                        .map(|identity| (identity.digest(), (**container).clone()))
                }
                _ => None,
            })
            .collect()
    }

    /// Every enabled workload profile that declares `[monitoring]`, keyed by
    /// the bounded label value its pods carry (`odin.dev/workload`).
    pub fn monitored_workloads(
        &self,
    ) -> Vec<(String, odin_registry::schema::WorkloadMonitoringToml)> {
        odin_registry::compose_workload_profiles(&self.snapshot.objects)
            .into_iter()
            .filter_map(|profile| {
                let monitoring = profile.profile.monitoring?;
                Some((odin_kube::job::bounded_label_value(&profile.id), monitoring))
            })
            .collect()
    }

    /// Enabled profiles with executable images, in registry order.
    pub fn launchable_profiles(&self) -> Vec<odin_omp::host_tools::LaunchableProfile> {
        self.snapshot
            .objects
            .iter()
            .filter_map(|object| match &object.config {
                odin_registry::schema::ObjectConfig::Container(container)
                    if container.enabled && container.image_executable_paths() =>
                {
                    Some(odin_omp::host_tools::LaunchableProfile {
                        id: object.id.clone(),
                        description: container.description.clone(),
                        gpu_count: container.gpu_count,
                        seats: container
                            .seats_offered
                            .iter()
                            .map(ToString::to_string)
                            .collect(),
                    })
                }
                _ => None,
            })
            .chain(
                // Script and agent profiles use the same create route.
                odin_registry::compose_workload_profiles(&self.snapshot.objects)
                    .into_iter()
                    .map(|profile| odin_omp::host_tools::LaunchableProfile {
                        description: format!(
                            "{} ({} pod{}{})",
                            profile.profile.description,
                            if profile.profile.runs_agent() {
                                "agent"
                            } else {
                                "script"
                            },
                            if profile.profile.mode == odin_registry::WorkloadMode::Service {
                                ", long-lived service"
                            } else {
                                ""
                            },
                            if profile.profile.placement.is_empty() {
                                String::new()
                            } else {
                                format!(", on {}", profile.profile.placement.join("+"))
                            },
                        ),
                        gpu_count: profile.profile.gpu_count,
                        seats: vec![profile.profile.seat.seat.to_string()],
                        id: profile.id,
                    }),
            )
            .collect()
    }

    /// Real label composition context for Job creation, or `None` when the
    /// daemon cannot resolve it without fabrication.
    pub fn launch_binding(&self) -> Option<KubeLaunchBinding> {
        self.launch_binding.clone()
    }

    /// The deployment's declared kube bounds: `(request_timeout,
    /// teardown_timeout)`. The cell is the composition root's only seam for
    /// these config facts — the coordinator derives its mutation deadlines
    /// from them instead of fabricating constants.
    pub fn kube_bounds(&self) -> (StdDuration, StdDuration) {
        (self.config.request_timeout, self.config.teardown_timeout)
    }

    pub(super) async fn parts(
        &self,
    ) -> Result<(Arc<odin_huginn::kube::KubeControl>, odin_kube::KubeClient), odin_kube::KubeError>
    {
        let mut guard = self.connected.lock().await;
        if let Some(connected) = &*guard {
            return Ok((Arc::clone(&connected.0), connected.1.clone()));
        }
        let unavailable = |reason: String| odin_kube::KubeError::Unavailable { reason };
        let client = odin_kube::client::KubeClient::connect(self.config.clone()).await?;
        self.stops
            .register_pod_backend(Arc::new(
                odin_kube::terminal_pod::KubernetesPodBackend::new(
                    client.clone(),
                    self.config.cluster.clone(),
                    self.config.namespace.clone(),
                )?,
            ))
            .map_err(|error| unavailable(error.to_string()))?;
        let reconciler = odin_kube::JobReconciler::new(
            client.clone(),
            Arc::clone(&self.ledger),
            Arc::clone(&self.stops),
            Arc::clone(&self.terminal_lifecycle),
            self.artifact_root.clone(),
        )?;
        let session = live::LiveSessionId::parse(KUBE_SURFACE_SESSION)
            .map_err(|error| unavailable(error.to_string()))?;
        let lane = odin_domain::LaneId::new(KUBE_SURFACE_LANE)
            .map_err(|error| unavailable(error.to_string()))?;
        let catalog = odin_huginn::kube::KubeCatalog::new(
            odin_huginn::kube::SurfaceArtifacts::new(
                session,
                lane,
                const { NonZeroU64::new(65_536).expect("nonzero bound") },
                const { NonZeroU64::new(1_048_576).expect("nonzero bound") },
            ),
            const { NonZeroUsize::new(256).expect("nonzero bound") },
            const { NonZeroU64::new(16_384).expect("nonzero bound") },
            const { NonZeroU64::new(128).expect("nonzero bound") },
        );
        let control = Arc::new(odin_huginn::kube::KubeControl::new(
            catalog,
            Arc::new(reconciler),
            Arc::clone(&self.ledger),
            client.clone(),
        ));
        *guard = Some((Arc::clone(&control), client.clone()));
        Ok((control, client))
    }
}

/// Ledger-only outcome of one kube admission pass.
#[derive(Debug)]
enum KubeAdmission {
    /// The approval exists but nothing consumed it yet: the paired device
    /// still owes its decision.
    Pending(Approval),
    /// The exact command binding consumed the approval exactly once.
    Consumed(Approval),
}

pub(super) struct RuntimeCommandPort {
    ledger: Arc<Mutex<Ledger>>,
    read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
    browser: Option<Arc<browser_runtime::BrowserRoutes>>,
    streams: Arc<odin_huginn::streams::BoundedMultiplexer>,
    kube: Option<Arc<KubeRuntimeCell>>,
    kube_backpressure: live::StreamBackpressureLimits,
    kube_frame_sequence: AtomicU64,
    conversation: Option<Arc<crate::conversation_surface::ConversationSurface>>,
    live: Option<Arc<dyn live::OmpLivePlane>>,
    /// Without a board, simulation commands return unavailable.
    simulation: Option<Arc<crate::simulation::SimulationDesk>>,
    ring: Option<Arc<RingIntake>>,
    /// The device-bound session authority; without it, an authenticated
    /// open answers a typed unavailable.
    device_open: Option<Arc<super::device_open::DeviceOpenAuthority>>,
    owner_preview: std::collections::BTreeSet<String>,
}

pub(super) type RingIntake = crate::ring_gesture::RingGestureIntake<
    odin_huginn::devices::SqliteDeviceTrustStore,
    odin_hermes::runtime::HermesRuntime,
>;

impl RuntimeCommandPort {
    pub(super) fn new(
        ledger: Arc<Mutex<Ledger>>,
        read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
        browser: Option<Arc<browser_runtime::BrowserRoutes>>,
        streams: Arc<odin_huginn::streams::BoundedMultiplexer>,
        kube: Option<Arc<KubeRuntimeCell>>,
        kube_backpressure: live::StreamBackpressureLimits,
    ) -> Self {
        Self {
            ledger,
            read_model,
            browser,
            streams,
            kube,
            kube_backpressure,
            kube_frame_sequence: AtomicU64::new(0),
            conversation: None,
            live: None,
            simulation: None,
            ring: None,
            device_open: None,
            owner_preview: std::collections::BTreeSet::new(),
        }
    }

    pub(super) fn with_owner_preview(mut self, ids: std::collections::BTreeSet<String>) -> Self {
        self.owner_preview = ids;
        self
    }

    pub(super) fn with_ring(mut self, ring: Option<Arc<RingIntake>>) -> Self {
        self.ring = ring;
        self
    }

    pub(super) fn with_simulation(
        mut self,
        simulation: Option<Arc<crate::simulation::SimulationDesk>>,
    ) -> Self {
        self.simulation = simulation;
        self
    }

    /// Pause, resume, and abort require kube approval; other commands use the board.
    async fn execute_simulation(
        &self,
        device: live::DeviceId,
        command: live::SimulationCommand,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        let desk = self
            .simulation
            .as_ref()
            .ok_or_else(|| unavailable("simulationUnavailable"))?;
        let read_model = &self.read_model;
        let kube_revision = |resource: &live::KubeResourceRef| {
            read_model
                .get(&live::ObjectRef {
                    kind: live::ObjectKind::KubeResource,
                    id: odin_huginn::kube::view::kube_object_id(resource),
                })
                .ok()
                .flatten()
                .map(|snapshot| snapshot.revision.get())
        };
        match desk.kube_command(&command, kube_revision)? {
            Some(kube) => self.execute_kube(device, kube).await,
            None => desk
                .execute_board(&command, OffsetDateTime::now_utc())
                .map(live::HuginnResponse::Command),
        }
    }

    pub(super) fn with_live(mut self, plane: Arc<dyn live::OmpLivePlane>) -> Self {
        self.live = Some(plane);
        self
    }

    /// Binds the device-bound session authority: an authenticated open
    /// mints, claims, and opens under the calling device's identity.
    pub(super) fn with_device_open(
        mut self,
        device_open: Option<Arc<super::device_open::DeviceOpenAuthority>>,
    ) -> Self {
        self.device_open = device_open;
        self
    }

    pub(super) fn with_conversation(
        mut self,
        conversation: Option<Arc<crate::conversation_surface::ConversationSurface>>,
    ) -> Self {
        self.conversation = conversation;
        self
    }

    /// Runs the durable R3 admission gate for one kube command against the
    /// ledger alone. First sight requests the approval with the submitting
    /// device as its immutable issuer; a re-issue journals the exact command
    /// through the one canonical kube spec and then consumes the approval at
    /// the exact stored revision — the consumption names the journaled row
    /// through `approvals.consumed_by_command_id`; any other device is
    /// refused before the gate can mutate or consume; an exact replay of
    /// the already consumed command by its own issuer returns the stored
    /// consumption untouched.
    fn admit_kube_command(
        ledger: &Mutex<Ledger>,
        device: &live::DeviceId,
        command: &live::KubeCommand,
    ) -> Result<KubeAdmission, live::HuginnProtocolError> {
        let command_id = command.command_id().clone();
        let approval_id = ApprovalId::new(format!("kube-{command_id}"))
            .map_err(|_| unavailable("kubeApprovalIdentity"))?;
        let now = OffsetDateTime::now_utc();
        let issuer = device.to_string();
        // One canonical durable kube command spec — the exact journaled row
        // an approval consumption names — with the gate scope derived from
        // it, so the approval binding and the command binding are one
        // construction and cannot diverge.
        let spec = odin_huginn::kube::kube_command_spec(command, &approval_id, now)
            .map_err(|_| unavailable("kubeCommandSpec"))?;
        let scope = ApprovalScope {
            target_kind: spec.target_kind.clone(),
            target_id: spec.target_id.clone(),
            capability_id: spec.capability_id.clone(),
            arguments_digest: spec.arguments_hash,
        };

        let mut ledger = ledger.lock().map_err(|_| unavailable("kubeLedgerLock"))?;
        let approval = ledger
            .approval(&approval_id)
            .map_err(|_| unavailable("kubeApprovalLookup"))?;
        let approval = match approval {
            None => {
                ApprovalGate::new(&mut ledger)
                    .request(NewApproval {
                        approval_id: approval_id.clone(),
                        issuer: issuer.clone(),
                        scope: scope.clone(),
                        requested_at: now,
                        expires_at: now + time::Duration::minutes(15),
                    })
                    .map_err(|_| unavailable("kubeApprovalRequest"))?;
                ledger
                    .approval(&approval_id)
                    .map_err(|_| unavailable("kubeApprovalLookup"))?
                    .ok_or_else(|| unavailable("kubeApprovalLookup"))?
            }
            Some(approval) => {
                if approval.issuer != issuer {
                    // The approval is bound to the device that requested
                    // it. No other device may consume, replay, or redirect
                    // it — including after consumption.
                    return Err(live::HuginnProtocolError::Conflict {
                        code: "kubeApprovalIssuer".to_owned(),
                        message: "kube approval was requested by a different device".to_owned(),
                    });
                }
                if approval.status == odin_domain::ApprovalStatus::Consumed
                    && approval.consumed_by_command_id.as_ref() == Some(&command_id)
                    && approval.scope == scope
                {
                    // Exact replay of the already admitted command by its
                    // own issuer: the stored consumption is the standing
                    // authority. The persisted record is returned without
                    // re-consumption, re-approval, or new authority.
                    return Ok(KubeAdmission::Consumed(approval));
                }
                // The consumption names this command as a durable foreign
                // key (`approvals.consumed_by_command_id` references
                // `commands`), so the exact command is journaled through the
                // one canonical spec after the approval exists and before
                // the gate consumes — and only after the issuer check,
                // never on the read-only exact-replay path. An identical
                // retry reclaims the same row; a different payload cannot
                // overwrite it and stays denied by the exact-scope gate
                // below.
                ledger
                    .record_command(&spec)
                    .map_err(|_| unavailable("kubeCommandJournal"))?;
                let consumed = ApprovalGate::new(&mut ledger)
                    .authorize_command(
                        odin_domain::EffectClass::R3,
                        ApprovalCommand {
                            command_id: &command_id,
                            approval_id: Some(&approval_id),
                            scope: &scope,
                            expected_revision: Some(approval.revision),
                            now,
                        },
                    )
                    .map_err(|_| unavailable("kubeApprovalConsume"))?;
                match consumed {
                    ConsumeOutcome::Consumed(approval) => approval,
                    ConsumeOutcome::Redirect(ApprovalRedirect::Denied(_)) => {
                        return Err(live::HuginnProtocolError::Conflict {
                            code: "kubeApprovalDenied".to_owned(),
                            message: "kube approval was denied".to_owned(),
                        });
                    }
                    ConsumeOutcome::Redirect(_) => {
                        return Err(live::HuginnProtocolError::Conflict {
                            code: "kubeApprovalRedirect".to_owned(),
                            message: "kube approval did not authorize this command binding"
                                .to_owned(),
                        });
                    }
                    // Workload mutations are R3 and cannot bypass approval.
                    ConsumeOutcome::NotRequired => {
                        return Err(live::HuginnProtocolError::Conflict {
                            code: "kubeApprovalRequired".to_owned(),
                            message: "kube mutation requires an exact approval".to_owned(),
                        });
                    }
                }
            }
        };
        drop(ledger);
        if approval.consumed_by_command_id.is_none() {
            Ok(KubeAdmission::Pending(approval))
        } else {
            Ok(KubeAdmission::Consumed(approval))
        }
    }

    /// Consume exact device/run/arguments/revision approval before cluster contact.
    /// First requests return pending approval; only the issuing device can consume it.
    /// Applied commands publish revision deltas and durable event frames.
    async fn execute_kube(
        &self,
        device: live::DeviceId,
        command: live::KubeCommand,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        let cell = match &self.kube {
            Some(cell) => cell,
            None => return Err(unavailable("kubeUnavailable")),
        };
        let control = cell
            .parts()
            .await
            .map(|(control, _)| control)
            .map_err(|error| unavailable(&format!("kubeUnavailable: {error}")))?;

        // Exact-revision admission under the ledger lock. Nothing in this
        // phase touches KubeControl or the cluster.
        let approval = match Self::admit_kube_command(&self.ledger, &device, &command)? {
            KubeAdmission::Pending(approval) => {
                self.publish_approval(&approval)?;
                // Pending: the paired device decides through the existing
                // approval route, then re-issues this identical command.
                return Ok(live::HuginnResponse::Command(
                    live::CommandReceipt::Accepted {
                        command_id: command.command_id().clone(),
                    },
                ));
            }
            KubeAdmission::Consumed(approval) => approval,
        };
        self.publish_approval(&approval)?;

        // Recheck run ownership and revision, journal the verdict, then mutate the cluster.
        let receipt = control
            .execute(&command, &approval.approval_id, OffsetDateTime::now_utc())
            .await?;
        for note in control.publish(&self.read_model, []).await {
            tracing::info!("kube command publication {note:?}");
        }
        for frame in control.drain_events().await {
            let sequence = self.kube_frame_sequence.fetch_add(1, Ordering::SeqCst) + 1;
            huginn_conformance::publish_frame(
                &self.streams,
                huginn_conformance::StreamFrameSpec {
                    stream_id: live::StreamId::parse(KUBE_EVENTS_STREAM)
                        .map_err(|_| unavailable("kubeStreamIdentity"))?,
                    kind: live::LiveStreamKind::KubeEvents,
                    mode: live::LiveStreamMode::Durable,
                    sequence,
                    control_revision: frame.event.revision,
                    content: frame.content,
                },
                &self.kube_backpressure,
                OffsetDateTime::now_utc(),
            )
            .map_err(|error| unavailable(&format!("kubeFrame: {error}")))?;
        }
        let _ = control.drain_statuses().await;
        Ok(live::HuginnResponse::Command(receipt))
    }

    /// Publishes one approval projection through the shared read model.
    fn publish_approval(&self, approval: &Approval) -> Result<(), live::HuginnProtocolError> {
        odin_huginn::approvals::ApprovalProjection::new(Arc::clone(&self.read_model))
            .publish(
                odin_huginn::approvals::ApprovalView::try_from(approval)?,
                std::iter::empty(),
                std::iter::empty(),
            )
            .map(|_delta| ())
    }
}

#[async_trait]
impl live::HuginnCommandPort for RuntimeCommandPort {
    async fn execute(
        &self,
        request: live::HuginnRequest,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        match request {
            live::HuginnRequest::BrowserObserve(_)
            | live::HuginnRequest::BrowserCommand(_)
            | live::HuginnRequest::KubeCommand(_)
            | live::HuginnRequest::ApprovalDecision(_)
            | live::HuginnRequest::ConversationStatus
            | live::HuginnRequest::ConversationThread(_)
            | live::HuginnRequest::ConversationSay(_)
            | live::HuginnRequest::ConversationReply(_)
            | live::HuginnRequest::Spend(_)
            | live::HuginnRequest::LaneCommand(_)
            | live::HuginnRequest::SimulationCommand(_)
            | live::HuginnRequest::RingGesture(_)
            | live::HuginnRequest::OpenSession(_)
            | live::HuginnRequest::EmergencyStop(_) => {
                Err(live::HuginnProtocolError::Unauthenticated)
            }
            _ => Err(unsupported("misrouted Huginn request")),
        }
    }
}

#[async_trait]
impl AuthenticatedCommandPort for RuntimeCommandPort {
    async fn execute_authenticated(
        &self,
        device: live::DeviceId,
        request: live::HuginnRequest,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        // Register the continuation before deciding so it resumes from the durable decision.
        match (&self.conversation, request) {
            (Some(conversation), live::HuginnRequest::ApprovalDecision(command)) => {
                let approval_id = command.approval_id.clone();
                let approved = command.decision == live::ApprovalDecision::Approve;
                conversation
                    .decide(
                        &approval_id,
                        approved,
                        self.route_authenticated(
                            device,
                            live::HuginnRequest::ApprovalDecision(command),
                        ),
                    )
                    .await
            }
            (_, request) => self.route_authenticated(device, request).await,
        }
    }
}

impl RuntimeCommandPort {
    async fn route_authenticated(
        &self,
        device: live::DeviceId,
        request: live::HuginnRequest,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        match (&self.browser, request) {
            (
                Some(browser),
                request @ (live::HuginnRequest::BrowserObserve(_)
                | live::HuginnRequest::BrowserCommand(_)
                | live::HuginnRequest::ApprovalDecision(_)),
            ) => browser.execute_authenticated(device, request).await,
            (None, live::HuginnRequest::ApprovalDecision(command)) => {
                self.decide_approval(command, device)
            }
            (None, live::HuginnRequest::BrowserObserve(_))
            | (None, live::HuginnRequest::BrowserCommand(_)) => {
                Err(unsupported("browser command adapter"))
            }
            (_, live::HuginnRequest::KubeCommand(command)) => {
                self.execute_kube(device, command).await
            }
            (_, live::HuginnRequest::SimulationCommand(command)) => {
                self.execute_simulation(device, command).await
            }
            (_, live::HuginnRequest::ConversationStatus) => match &self.conversation {
                Some(conversation) => conversation.status(None).await,
                None => Err(unavailable("conversationUnavailable")),
            },
            (_, live::HuginnRequest::ConversationThread(request)) => match &self.conversation {
                Some(conversation) => conversation.thread(request).await,
                None => Err(unavailable("conversationUnavailable")),
            },
            (_, live::HuginnRequest::ConversationSay(request)) => match &self.conversation {
                Some(conversation) => conversation.say(device, request).await,
                None => Err(unavailable("conversationUnavailable")),
            },
            (_, live::HuginnRequest::ConversationReply(request)) => match &self.conversation {
                Some(conversation) => conversation.committed_reply(&request.command_id),
                None => Err(unavailable("conversationUnavailable")),
            },
            (_, live::HuginnRequest::Spend(request)) => crate::huginn_spend::read(request).await,
            (_, live::HuginnRequest::EmergencyStop(request)) => {
                crate::emergency_stop::start(device, &request)
            }
            (_, live::HuginnRequest::RingGesture(report)) => match &self.ring {
                Some(ring) => ring.report(device, report).await,
                None => Err(unavailable("ringGestureUnavailable")),
            },
            (_, live::HuginnRequest::LaneCommand(command)) => match &self.live {
                Some(plane) => crate::lane_command::execute(&self.ledger, plane, command).await,
                None => Err(unavailable("livePlaneUnavailable")),
            },
            (_, live::HuginnRequest::OpenSession(request)) => match &self.device_open {
                Some(authority) => authority
                    .open_session_for_device(device, request)
                    .await
                    .map(live::HuginnResponse::SessionOpened)
                    .map_err(odin_huginn::state::live_error_into_protocol),
                None => Err(unavailable("deviceSessionAuthority")),
            },
            (_, request) => <Self as live::HuginnCommandPort>::execute(self, request).await,
        }
    }
}

/// The journal pass before each kube watch opens. `recover()` re-drives
/// admitted but unsettled journal operations against the real cluster —
/// replayed creates and restarts — so it is armed ONLY for the snapshot
/// authority: a demoted node still carries pending journal rows from before
/// demotion, and replaying them here would re-drive cluster mutations
/// without authority. Observation — the watch's own list — stays live on
/// every posture and feeds only the local read model.
pub(super) async fn kube_reconcile_tick(
    posture: NodePosture,
    control: &odin_huginn::kube::KubeControl,
    log: &mut crate::pumps::WatchLog,
) {
    if posture == NodePosture::Authoritative {
        if let Err(error) = control.recover().await {
            log.note(format!("journal recovery failed: {error}"));
        }
        // Recovery returns before cleanup when a replay is unavailable.
        // Outstanding marked residue only — not every registered run.
        if let Err(error) = control.reconciler().reap_marked_residue().await {
            log.note(format!("finished-run cleanup failed: {error}"));
        }
    }
}

fn unsupported(operation: &str) -> live::HuginnProtocolError {
    live::HuginnProtocolError::Unsupported {
        operation: operation.to_owned(),
    }
}

fn unavailable(code: &str) -> live::HuginnProtocolError {
    live::HuginnProtocolError::Unavailable {
        code: code.to_owned(),
    }
}

#[path = "kube_approval.rs"]
mod approval;

#[cfg(test)]
#[path = "tests/kube.rs"]
mod tests;

#[path = "kube_browser.rs"]
mod browser;
use browser::open_pod_browser;
#[path = "kube_terminal.rs"]
mod terminal;

/// Transport constant of the in-image env executable the exec argv is
/// composed through (imageRoot coreutils; build-validated in-image by the
/// image contract). Mechanism only — never a profile field.
const WORKLOAD_ENV_EXECUTABLE: &str = "/bin/env";
/// Bounds of the composed env carriage: few, bounded, NUL-free pairs.
const WORKLOAD_ENV_MAX_PAIRS: usize = 16;
const WORKLOAD_ENV_PAIR_BYTES_MAX: usize = 4096;

fn bad_env(reason: String) -> RemoteAttachError {
    RemoteAttachError { detail: reason }
}

fn validate_env_pair(key: &str, value: &str) -> Result<(), RemoteAttachError> {
    if key.is_empty() || value.contains('\0') || key.contains('\0') {
        return Err(bad_env(
            "workload env pair is empty-keyed or carries NUL".to_owned(),
        ));
    }
    if key.len() > 128 || value.len() > WORKLOAD_ENV_PAIR_BYTES_MAX {
        return Err(bad_env(
            "workload env pair exceeds the composed bounds".to_owned(),
        ));
    }
    Ok(())
}

/// The kube-admitted remote carrier resolver: proves one workload binding's
/// operation against the durable kube launch journal, then attaches the
/// exact admitted pod exec channel of that run. The pinned launcher,
/// extension binding, and digest-pinned image come from the durable launch
/// record and the pinned image identity — never from a live declaration
/// re-read. No local fallback exists.
pub(crate) struct KubeWorkloadCarrier {
    cell: Arc<KubeRuntimeCell>,
    /// The controller's pinned OMP source revision, carried into the remote
    /// spec exactly as the local composition pins it.
    omp_revision: String,
    /// Browser tools open an in-pod browser through these routes.
    browsers: Arc<browser_runtime::BrowserRoutes>,
    /// The profiles whose pods run their own browser.
    browser_profiles: std::collections::BTreeSet<String>,
}

impl KubeWorkloadCarrier {
    pub fn new(
        cell: Arc<KubeRuntimeCell>,
        omp_revision: String,
        browsers: Arc<browser_runtime::BrowserRoutes>,
        browser_profiles: std::collections::BTreeSet<String>,
    ) -> Self {
        Self {
            cell,
            omp_revision,
            browsers,
            browser_profiles,
        }
    }
}

#[async_trait::async_trait]
impl odin_omp::live::runtime::WorkloadCarrierPort for KubeWorkloadCarrier {
    async fn carrier_for(
        &self,
        binding: &odin_domain::huginn::WorkloadSessionBinding,
        manifest: &SessionManifest,
    ) -> Result<Arc<dyn RemoteHarnessFactory>, LiveError> {
        let control = self.cell.control().ok_or_else(|| LiveError::Unavailable {
            code: "workload_carrier: the k3s API server is unreachable".to_owned(),
        })?;
        let reconciler = control.reconciler();
        let Some((run, launch)) =
            reconciler
                .operation_launch(&binding.operation)
                .map_err(|error| LiveError::Unavailable {
                    code: format!("workload_carrier: {error}"),
                })?
        else {
            return Err(LiveError::Unavailable {
                code: format!(
                    "workload_carrier: operation {} admits no durable launch record",
                    binding.operation
                ),
            });
        };
        // Declared identity must agree across binding, durable launch
        // record, and live manifest: profile, seat, and project. Node
        // placement is Kubernetes-selected and carries no durable field;
        // serving-node identity was proven at open against the seat
        // binding's allowed-node set.
        let Some(plan) = launch.workload.as_ref() else {
            return Err(LiveError::Unavailable {
                code: "workload_carrier: the admitted launch carries no workload plan".to_owned(),
            });
        };
        let Some(extension) = launch.extension.as_ref() else {
            return Err(LiveError::Unavailable {
                code: "workload_carrier: the admitted launch carries no extension binding"
                    .to_owned(),
            });
        };
        let mut staged_paths =
            reconciler
                .staged_paths(&run)
                .map_err(|error| LiveError::Unavailable {
                    code: format!("workload_carrier: {error}"),
                })?;
        let Some(staged_policy_path) = staged_paths.remove(&extension.policy_artifact) else {
            return Err(LiveError::Unavailable {
                code: format!(
                    "workload_carrier: the staged policy artifact {} has no recorded staging \
                     path for run {run}",
                    extension.policy_artifact
                ),
            });
        };
        let Some(models) = launch.models_config.as_ref() else {
            return Err(LiveError::Unavailable {
                code: "workload_carrier: the admitted launch carries no models document".to_owned(),
            });
        };
        let Some(staged_models_path) = staged_paths.remove(&models.config_artifact) else {
            return Err(LiveError::Unavailable {
                code: format!(
                    "workload_carrier: the staged models artifact {} has no recorded staging \
                     path for run {run}",
                    models.config_artifact
                ),
            });
        };
        // The unique per-run agent dir lives under the declared state mount:
        // session-persistent, never the read-only staging mount, never a
        // shared persistent user state.
        let agent_dir = format!("{}/.omp-agent/{}", plan.state_mount, run);
        let spec = compose_remote_spec(
            &AdmittedCarrierComposition {
                extension,
                models,
                staged_policy_path: &staged_policy_path,
                staged_models_path: &staged_models_path,
                agent_dir: &agent_dir,
            },
            plan,
            &self.omp_revision,
        )
        .map_err(|reason| LiveError::InvalidRequest {
            code: "workload_carrier_spec".to_owned(),
            message: reason,
        })?;
        if plan.profile != binding.profile
            || launch.labels.run_id != run
            || launch.labels.seat_id != manifest.seat_id
            || launch.labels.project_id != manifest.project_id
        {
            return Err(LiveError::InvalidRequest {
                code: "workload_carrier_identity".to_owned(),
                message: "the admitted launch record disagrees with the session binding".to_owned(),
            });
        }
        // Reserve the derived browser session for reattachment, then open it when the pod runs.
        if self.browser_profiles.contains(&plan.profile) {
            let session = live::pod_browser_session_id(&manifest.session_id);
            let owner =
                odin_domain::SessionId::new(manifest.session_id.to_string()).map_err(|error| {
                    LiveError::InvalidRequest {
                        code: "pod_browser_owner".to_owned(),
                        message: error.to_string(),
                    }
                })?;
            if self.browsers.reserve(session, owner) {
                tokio::spawn(open_pod_browser(
                    reconciler.exec_client(),
                    run.clone(),
                    plan.clone(),
                    session,
                    Arc::clone(&self.browsers),
                ));
            }
        }
        Ok(Arc::new(KubeExecHarness {
            client: reconciler.exec_client(),
            run,
            worker_id: launch.worker_id.clone(),
            admission: RemoteHarnessAdmission {
                profile: binding.profile.clone(),
                image: launch.image.clone(),
            },
            spec,
        }))
    }
}

/// One admitted pod exec channel factory: the host-admitted remote
/// harness of a workload session. The composed remote spec (verifier entry,
/// staged policy carriage, declared launcher) and the digest-pinned image
/// are the durable launch record's, carried as admission evidence.
struct KubeExecHarness {
    client: odin_kube::KubeClient,
    run: odin_domain::RunId,
    worker_id: WorkerId,
    admission: RemoteHarnessAdmission,
    spec: OmpProcessSpec,
}

#[async_trait::async_trait]
impl RemoteHarnessFactory for KubeExecHarness {
    async fn attach(
        &self,
        args: &[String],
        env: &[(String, String)],
    ) -> Result<RemoteHarnessChannel, RemoteAttachError> {
        // Env carriage is argv-only through the image's own /bin/env
        // (coreutils; build-validated in-image by the image contract):
        // ["/bin/env", "--", K=V..., <composed remote spec argv>...].
        // Plain argv, no shell, no interpolation, no stdin protocol; only
        // the caller-composed capability-identity pairs ride here, exactly
        // as composed — never wholesale host env, never secrets or paths.
        // The composed spec argv itself starts at the in-image verifier
        // entrypoint and carries the declared launcher verbatim after `--`.
        let mut arguments: Vec<String> = Vec::with_capacity(env.len() + args.len() + 2);
        if !env.is_empty() {
            if env.len() > WORKLOAD_ENV_MAX_PAIRS {
                return Err(bad_env(format!(
                    "env carries {} pairs, over the {} pair bound",
                    env.len(),
                    WORKLOAD_ENV_MAX_PAIRS
                )));
            }
            arguments.push("--".into());
            for (key, value) in env {
                validate_env_pair(key, value)?;
                arguments.push(format!("{key}={value}"));
            }
        }
        // The composed spec's executable is the in-image verifier entry —
        // the first real argv element of the exec, exactly as the remote
        // API composes it: [/bin/env, --, K=V..., <verifier>, "workload-exec", ...].
        arguments.push(self.spec.executable.to_string_lossy().into_owned());
        arguments.extend(args.iter().cloned());
        let spec = WorkloadLauncherSpec {
            launcher_path: WORKLOAD_ENV_EXECUTABLE.to_owned(),
            arguments,
        };
        let attached = exec_fixed(
            &self.client,
            &self.run,
            odin_kube::exec::JobExecTarget::Worker,
            &spec,
        )
        .await
        .map_err(|error| RemoteAttachError {
            detail: error.to_string(),
        })?;
        let stream = decompose(attached).map_err(|error| RemoteAttachError {
            detail: error.to_string(),
        })?;
        Ok(map_channel(stream))
    }

    fn job_worker_id(&self) -> &WorkerId {
        &self.worker_id
    }

    fn stop_action(&self) -> JobStopAction {
        JobStopAction::Delete
    }

    fn admission(&self) -> &RemoteHarnessAdmission {
        &self.admission
    }

    fn process_spec(&self) -> OmpProcessSpec {
        self.spec.clone()
    }
}

/// The admitted carrier composition of one workload run: the launch
/// record's own verified bindings paired with the exact staged read-only
/// paths the reconciler recorded for them, plus the unique per-run agent
/// dir under the declared state mount. Every member is journaled-with-
/// the-launch or admission-resolved state; nothing is inferred from the
/// environment, argv shapes, or path conventions.
struct AdmittedCarrierComposition<'a> {
    extension: &'a JobExtensionLaunch,
    models: &'a JobModelsConfigLaunch,
    staged_policy_path: &'a str,
    staged_models_path: &'a str,
    agent_dir: &'a str,
}

/// Composes the remote carrier's process spec. The in-image verifier entry —
/// the image identity's own `odind`, whose `workload-exec` mode re-proves
/// the staged policy bytes and the pinned extension bytes with the existing
/// `ExtensionPolicyV1` verifier pair — carries the declared launcher
/// verbatim after `--` and execs it only on success. The policy binding
/// travels as explicit typed arguments; the extension path is exactly the
/// image identity's declared in-image value, never a host path and never a
/// store path.
fn compose_remote_spec(
    composition: &AdmittedCarrierComposition<'_>,
    plan: &odin_kube::workload::WorkloadPodPlan,
    omp_revision: &str,
) -> Result<OmpProcessSpec, String> {
    let extension = composition.extension;
    let models = composition.models;
    let staged_policy_path = composition.staged_policy_path;
    let staged_models_path = composition.staged_models_path;
    let agent_dir = composition.agent_dir;
    let state_mount = plan.state_mount.as_str();
    let verifier = extension.verifier.as_str();
    let launcher = plan
        .agent
        .as_ref()
        .ok_or_else(|| format!("workload {} runs no agent harness to attach", plan.profile))?
        .launcher
        .as_str();
    if !odin_registry::schema::valid_pod_path(verifier) {
        return Err(format!(
            "the in-image verifier path {verifier:?} is invalid"
        ));
    }
    if !odin_registry::schema::valid_pod_path(launcher) {
        return Err(format!(
            "the declared launcher path {launcher:?} is invalid"
        ));
    }
    if !odin_registry::schema::valid_pod_path(staged_policy_path) {
        return Err(format!(
            "the staged policy path {staged_policy_path:?} is invalid"
        ));
    }
    if !odin_registry::schema::valid_pod_path(staged_models_path) {
        return Err(format!(
            "the staged models path {staged_models_path:?} is invalid"
        ));
    }
    if !odin_registry::schema::valid_pod_path(agent_dir) {
        return Err(format!("the agent dir {agent_dir:?} is invalid"));
    }
    odin_domain::extension_policy::validate_digest(&extension.policy_digest)
        .map_err(|error| format!("the launch policy digest is malformed: {error}"))?;
    odin_domain::extension_policy::validate_digest(&models.config_digest)
        .map_err(|error| format!("the models config digest is malformed: {error}"))?;
    let mut explicit_args = vec![
        "workload-exec".to_owned(),
        "--extension-policy".to_owned(),
        staged_policy_path.to_owned(),
        "--extension-policy-digest".to_owned(),
        extension.policy_digest.clone(),
        "--models-config".to_owned(),
        staged_models_path.to_owned(),
        "--models-config-digest".to_owned(),
        models.config_digest.clone(),
        "--agent-dir".to_owned(),
        agent_dir.to_owned(),
        "--state-mount".to_owned(),
        state_mount.to_owned(),
        "--credential-env".to_owned(),
        models.credential_env.clone(),
        "--working-dir".to_owned(),
        state_mount.to_owned(),
        "--trusted-extension".to_owned(),
        extension.trusted_extension.clone(),
        "--".to_owned(),
        launcher.to_owned(),
    ];
    // Share tool-exposure flags with local launches: read only, never `--no-tools`.
    explicit_args.extend(odin_omp::process::governed_harness_args(
        std::path::Path::new(&extension.trusted_extension),
    ));
    let explicit_env = vec![
        (
            EXTENSION_POLICY_PATH_ENV.to_owned(),
            staged_policy_path.to_owned(),
        ),
        (
            EXTENSION_POLICY_DIGEST_ENV.to_owned(),
            extension.policy_digest.clone(),
        ),
        ("PI_CODING_AGENT_DIR".to_owned(), agent_dir.to_owned()),
    ];
    Ok(OmpProcessSpec {
        executable: PathBuf::from(verifier),
        cwd: PathBuf::from(state_mount),
        explicit_args,
        explicit_env,
        expected_source_revision: omp_revision.to_owned(),
        startup_timeout: StdDuration::from_secs(120),
        drain_timeout: StdDuration::from_secs(10),
        kill_timeout: StdDuration::from_secs(5),
    })
}

/// Maps the kube exec stream halves into the transport-agnostic remote
/// harness channel the process boundary consumes: every carrier outcome is
/// mapped onto the typed [`RemoteExit`] — `None` (clean channel close) is
/// clean, `Some(reason)` (Failure status, missing verdict, or canceled
/// wait) is unclean with the exact reason.
fn map_channel(stream: WorkloadExecStream) -> RemoteHarnessChannel {
    RemoteHarnessChannel {
        stdin: Box::new(ExecStdin {
            writer: Some(stream.stdin),
        }),
        stdout: Box::new(stream.stdout),
        stderr: stream.stderr,
        exit: Box::pin(async move {
            match stream.exit.await {
                Some(reason) => RemoteExit {
                    status: None,
                    clean: false,
                    failure: Some(reason),
                },
                None => RemoteExit {
                    status: None,
                    clean: true,
                    failure: None,
                },
            }
        }),
    }
}

/// The exec stdin half: ordered framed writes while the carrier is
/// attached, graceful stdin EOF on shutdown.
struct ExecStdin {
    writer: Option<Box<dyn tokio::io::AsyncWrite + Unpin + Send>>,
}

#[async_trait::async_trait]
impl HarnessStdin for ExecStdin {
    async fn write_all(&mut self, bytes: Vec<u8>) -> std::io::Result<()> {
        match self.writer.as_mut() {
            Some(writer) => tokio::io::AsyncWriteExt::write_all(writer, &bytes).await,
            None => Err(std::io::Error::other(
                "the exec stdin half is already closed",
            )),
        }
    }

    fn shutdown(mut self: Box<Self>) -> std::io::Result<()> {
        // Graceful: close stdin EOF. The carrier drains, exits, and the
        // owned exit waiter resolves from the real carrier status.
        self.writer = None;
        Ok(())
    }
}
