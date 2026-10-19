//! The live/control lifecycle: the full asynchronous composition and
//! serving loop of the daemon runtime, entered through the synchronous
//! serving composition in `serving`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use odin_brain::retrieval::LaneEmbeddingProvider;
use odin_cli::runtime_bindings::{operation_contracts, seat_operation_bindings, RuntimeInputs};
use odin_domain::extension_policy::ExtensionPolicyBinding;
use odin_domain::huginn as live;
use odin_domain::{CapabilityId, ProjectId};
use odin_huginn::dispatch::AuthenticatedCommandPort;
use odin_huginn::{NodePosture, OdindConfig};
use odin_ledger::Ledger;
use odin_registry::{Snapshot, SnapshotHandle, SnapshotStore};
use time::OffsetDateTime;

use crate::authority::{
    compose_operation_authority, declared_conversation_binding, SessionStopCoordinator,
};
use crate::browser::browser_runtime_config;
use crate::child_report::arm_child_report_pump;
use crate::composition::RuntimeWorkers;
use crate::composition::{
    context_read_runtime_config, load_runtime_manifest, renderer_registry, runtime_workers,
};
use crate::hermes::{hermes_settings, DaemonIntakeAuthority};
use crate::huginn_conformance;
use crate::huginn_spend::arm_spend_pump;
use crate::kube::{KubeRuntimeCell, RuntimeCommandPort};
use crate::kube_runtime;
use crate::projection::{
    brain_sources, seed_read_model, served_brain_policies, served_lane_windows,
    shared_seat_atlas_scope,
};
use crate::pumps::{
    arm_brain_warm_pump, arm_device_activity_pump, arm_durable_feed_pump, arm_egress_lane_pumps,
    arm_fleet, arm_render_pump, arm_service_pumps,
};
use crate::state_knowledge;

#[path = "live/adapter_inputs.rs"]
mod adapter_inputs;
#[path = "live/brain_bindings.rs"]
mod brain_bindings;
#[path = "live/browser_capsule.rs"]
mod browser_capsule;
#[path = "live/harness_launch.rs"]
mod harness_launch;
#[path = "live/hermes_routes.rs"]
pub(crate) mod hermes_routes;
#[path = "live/kube_cell.rs"]
mod kube_cell;
#[path = "repo_watch.rs"]
pub(crate) mod repo_watch;
#[path = "live/serving.rs"]
pub(crate) mod serving;
#[path = "live/session_discovery.rs"]
mod session_discovery;
#[path = "live/settle.rs"]
mod settle;
#[path = "live/shutdown.rs"]
mod shutdown;
#[path = "live/vehicle_open.rs"]
mod vehicle_open;
#[path = "live/worker_process.rs"]
mod worker_process;
#[path = "workload.rs"]
pub(crate) mod workload;
#[path = "workload_monitor.rs"]
mod workload_monitor;
#[path = "workload_recovery.rs"]
mod workload_recovery;
#[path = "workload_watch.rs"]
mod workload_watch;

/// Provisions the durable feed stack's private directory on a fresh root:
/// the cursor ordinal must persist from the very first discovery change.
pub(super) fn ensure_feeds_dir(huginn_root: &std::path::Path) -> Result<(), String> {
    let feeds_dir = huginn_root.join("feeds");
    odin_cli::eval_daemon::create_private_dir(&feeds_dir)
        .map_err(|error| format!("could not provision the feeds directory: {error}"))
}

#[allow(clippy::too_many_arguments)]
async fn serve_huginn_async(
    config: OdindConfig,
    validated: odin_huginn::ValidatedHuginnConfig,
    snapshot: Arc<Snapshot>,
    snapshot_handle: Arc<SnapshotHandle>,
    runtime: RuntimeInputs,
    extension_policy: ExtensionPolicyBinding,
    posture: NodePosture,
    shutdown_started: Arc<Mutex<Option<std::time::Instant>>>,
) -> Result<(), String> {
    // Every registry/schema/listing/policy request below reads this exact
    // pinned revision; the Arc stays immutable for the process lifetime.
    let registry = &snapshot.objects;
    // The owner-facing conversation seats: every other open session is a
    // delegated child the idle reload waits for.
    let conversation_seats: std::collections::BTreeSet<odin_domain::SeatId> = registry
        .iter()
        .filter_map(|object| match &object.config {
            odin_registry::ObjectConfig::Seat(seat) if seat.conversation.is_some() => {
                object.id.parse().ok()
            }
            _ => None,
        })
        .collect();
    let admission_revision = i64::try_from(snapshot.revision)
        .map_err(|_| "published snapshot revision does not fit i64".to_owned())?;
    use odin_huginn::dispatch::DispatchGuard as _;
    use odin_huginn::files::RootCatalog;
    use odin_huginn::renders::{FileRenderSource, RenderPublisher};
    use odin_huginn::service::{
        FsExternalContentIndex, FsPublishedArtifactStore, HuginnCommandPlane,
        HuginnContentTicketIssuer,
    };
    use odin_huginn::state::FsDispatchGuard;
    use odin_omp::host_tools::delegation::{
        ChildStopCoordinator, DelegationGovernance, DelegationLinkLedger, GovernedTaskOwner,
        TaskOwner, TaskOwnerSlot,
    };
    use odin_omp::host_tools::BrowserCapabilityOwner;
    use odin_omp::live::lane_artifacts::{
        FsLaneArtifactPort, LaneArtifactPort, LaneTransferBridge,
    };
    use odin_omp::live::ledger::{fs::FsLiveLedger, LiveLedger};
    use odin_omp::live::runtime::{ProductionBridgeRuntimeConfig, ProductionBridgeRuntimeFactory};
    use odin_omp::live::supervisor::{BridgeRuntimeFactory, LiveBridgeLauncher, LiveSupervisor};
    use odin_omp::live::transfer::{
        RegistryTransferLaneResolver, TransferLaneResolver, TransferManager,
    };

    let RuntimeInputs {
        project_roots,
        session_lanes,
        node: node_identity,
        seat_bindings,
        transfer_lanes,
        rollover_seats,
        egress_lanes,
        file_roots,
        tailnet_peers,
        allowed_nodes,
        render_session,
        file_publish_lane,
        render_publish_lane,
    } = runtime;
    let limits = validated.limits().clone();
    let mut context_read = context_read_runtime_config(
        &config,
        &project_roots,
        u64::from(limits.files.max_read_chunk_bytes.get()),
    )?;
    let huginn_root = validated.state().root().to_path_buf();
    let guard = FsDispatchGuard::new(&config.paths.state_root)
        .map_err(|error| format!("could not construct STOP guard: {error}"))?;
    guard
        .check_stop()
        .await
        .map_err(|error| error.to_string())?;
    let guard: Arc<dyn odin_huginn::dispatch::DispatchGuard> = Arc::new(guard);
    std::fs::create_dir_all(validated.state().streams_dir())
        .map_err(|error| format!("could not create Huginn streams root: {error}"))?;

    let live_ledger: Arc<dyn LiveLedger> = Arc::new(
        FsLiveLedger::open(huginn_root.join("live"))
            .map_err(|error| format!("could not open live ledger: {error}"))?,
    );
    let bridge_ledger = Arc::new(Mutex::new(
        Ledger::open(config.paths.state_root.join("ledger.sqlite3"))
            .map_err(|error| format!("could not open controller ledger: {error}"))?,
    ));

    // The delegation link ledger opens here — before the task-state reader
    // and the factory both bind clones of the same shared-core handle — so
    // the factory's persists and the state sources' scans observe one
    // gate and one notification channel.
    let delegation_links = DelegationLinkLedger::open(huginn_root.join("delegation-links"))
        .map_err(|error| format!("could not open delegation link ledger: {error}"))?;
    let odin_root = config
        .paths
        .registry_root
        .parent()
        .ok_or_else(|| "registry root has no Odin repository parent".to_owned())?
        .to_path_buf();
    let atlas = Arc::new(
        odin_atlas::build(odin_atlas::AtlasSources::new(&odin_root))
            .map_err(|error| format!("could not build Atlas for live sessions: {error}"))?,
    );
    let extension = config
        .executables
        .extension
        .canonicalize()
        .map_err(|error| format!("could not resolve extension path: {error}"))?;
    if !extension.is_file() {
        return Err(format!(
            "trusted extension entrypoint {} is not a file",
            extension.display()
        ));
    }
    let manifest = load_runtime_manifest()?;
    // Fail-closed pairing gate: every declared adapter backend needs its
    // manifest executable `adapter.<id>` before any worker is assembled.
    manifest
        .require_adapter_support(&config)
        .map_err(|error| format!("runtime manifest adapter support rejected: {error}"))?;
    let RuntimeWorkers {
        omp: omp_worker,
        zellij: zellij_worker,
    } = runtime_workers(&config, &manifest)?;
    // Unit terminals are owned through the daemon's own stop authority —
    // the same ledger the Huginn workers use — retained here because the
    // launch binding itself moves into the process cell below.
    let terminal_stops = Arc::clone(&omp_worker.authority);
    let browser_config = browser_runtime_config(&config, &manifest)?;
    let adapter_inputs::AdapterInputs {
        adapters,
        adapter_status_ttl,
    } = adapter_inputs::compose(&config, &manifest)?;
    let kube_cell: Option<Arc<KubeRuntimeCell>> =
        kube_cell::compose(&config, &manifest, &snapshot, &bridge_ledger, &huginn_root)?;
    let (process, zellij) = worker_process::compose(
        &config,
        extension,
        &extension_policy,
        &omp_worker,
        zellij_worker,
        &huginn_root,
    )
    .await?;
    // The shutdown seam closes this same factory's admission at the stop
    // and drains its action lock under the one shutdown deadline.
    let shutdown_terminals = zellij.clone();
    let published = Arc::new(
        FsPublishedArtifactStore::open(
            huginn_root.join("published"),
            render_session,
            file_publish_lane,
            render_publish_lane,
        )
        .map_err(|error| error.to_string())?,
    );
    let catalog = RootCatalog::new(file_roots.clone()).map_err(|error| error.to_string())?;
    let files = Arc::new(odin_huginn::HuginnFileService::new(
        catalog,
        limits.files.clone(),
    ));
    let render_source: Arc<dyn odin_huginn::renders::RenderSourceResolver> =
        Arc::new(FileRenderSource::new(files.browse_engine().clone()));
    let render_publisher: Arc<dyn RenderPublisher> = published.clone();
    let renders = Arc::new(
        odin_huginn::HuginnRenderService::new(
            validated.state().renders_dir(),
            limits.renders.clone(),
            renderer_registry()?,
            render_source,
            render_publisher,
        )
        .map_err(|error| error.to_string())?,
    );

    let max_objects = registry
        .len()
        .saturating_add(file_roots.len())
        .saturating_add(65_536);
    let read_model = Arc::new(odin_huginn::read_model::MaterializedReadModel::with_limits(
        max_objects,
        max_objects.saturating_mul(2),
        OffsetDateTime::now_utc(),
    ));
    seed_read_model(
        &read_model,
        registry,
        &file_roots,
        node_identity.node(),
        config.listener.address,
    )?;
    let replay = odin_huginn::streams::DurableReplayStore::open(
        validated.state().streams_dir().join("replay.sqlite3"),
        limits.streams.replay_buffer_events.get(),
        u64::try_from(limits.streams.max_stream_frame_bytes.get())
            .map_err(|_| "stream frame limit does not fit u64".to_owned())?,
    )
    .map_err(|error| error.to_string())?;
    let streams = Arc::new(odin_huginn::streams::BoundedMultiplexer::new(
        replay,
        limits.streams.frame_queue_depth.get(),
        limits.connections.max_subscriptions_per_connection.get(),
    ));

    let devices = Arc::new(
        odin_huginn::devices::SqliteDeviceTrustStore::open(validated.state().devices_db())
            .map_err(|error| error.to_string())?,
    );
    let tailnet = Arc::new(odin_huginn::private_network::InterfaceTailnetVerifier::new(
        tailnet_peers,
    ));
    let connections =
        odin_huginn::ConnectionRegistry::with_limit(limits.connections.max_connections.get());
    // Paired devices and their live activity (last authentication, open
    // connections) ride the read model; the service pumps re-publish
    // what moved.
    odin_huginn::devices::publish_device_activity(
        devices.as_ref(),
        &connections,
        &read_model,
        OffsetDateTime::now_utc(),
    )
    .await?;
    let ticket_ttl = StdDuration::from_secs(
        u64::try_from(limits.transfers.ticket_ttl.whole_seconds())
            .map_err(|_| "content ticket TTL does not fit u64".to_owned())?,
    );
    let ticket_store = odin_huginn::router::ContentTicketStore::new(
        limits.transfers.queue_depth.get(),
        limits.transfers.max_transfer_bytes.get(),
        ticket_ttl,
    );
    let external_content = Arc::new(
        FsExternalContentIndex::open(huginn_root.join("content-aliases"))
            .map_err(|error| error.to_string())?,
    );
    // The sole operation authority composition: exact contracts and policy
    // from the one pinned published snapshot revision, real schemas, and an
    // externally provisioned signed-token verifier. No optional authority,
    // issuer, or fallback seam exists.
    let operation_contracts = operation_contracts(registry)?;
    let owner_preview_ids: BTreeSet<String> = operation_contracts
        .iter()
        .filter(|(_, contract)| contract.preview.is_some())
        .map(|(id, _)| id.to_string())
        .collect();
    let admission = odin_omp::host_tools::operations::admission_digest(
        &operation_contracts,
        admission_revision,
    )
    .map_err(|error| error.to_string())?;
    // Admission is data: the pinned snapshot decides which capabilities this
    // node must be able to serve. When it enables `context.read` without an
    // operator-provisioned context root, the node composes the real bounded
    // reader over its own sealed node-local root (created empty beside the
    // other state-root surfaces) — the same published-contract composition
    // the follower ask lane uses instead of config-bound sections.
    let context_read_capability = CapabilityId::new("context.read")
        .map_err(|_| "compiled context.read capability id is invalid".to_owned())?;
    if context_read.is_none() && operation_contracts.contains_key(&context_read_capability) {
        let root = config.paths.state_root.join("context");
        std::fs::create_dir_all(&root).map_err(|error| {
            format!(
                "could not create node context root {}: {error}",
                root.display()
            )
        })?;
        context_read = Some(odin_omp::live::runtime::ContextReadRuntimeConfig {
            root,
            max_bytes: u64::from(limits.files.max_read_chunk_bytes.get()),
        });
    }
    odin_cli::runtime_bindings::ensure_seat_tools_granted(registry, &seat_bindings)?;
    let seat_operation_bindings =
        seat_operation_bindings(registry, &seat_bindings, &session_lanes, admission)?;
    let allowed_atlas_scope = if posture == NodePosture::Follower && seat_bindings.is_empty() {
        // Seatless followers may read untagged Atlas content; authorities must serve a seat.
        odin_atlas::AtlasScope::seat([])
            .map_err(|error| format!("follower Atlas scope is invalid: {error}"))?
    } else {
        shared_seat_atlas_scope(registry, &seat_bindings)?
    };
    let brain_policies =
        served_brain_policies(&config, snapshot.revision, registry, &seat_bindings)?;
    let lane_windows_by_seat = served_lane_windows(&config, &brain_policies, &seat_bindings)?;
    let brain_embedding = crate::projection::served_embedding(&config, &snapshot)?;
    let brain_postgres = crate::projection::served_brain_postgres(&config).await?;
    // Compose workload scopes and model policies; invalid profiles are skipped individually.
    let workload_brain_scopes = workload::brain_source_scopes(&brain_policies);
    let workload_serving_node = odin_domain::NodeId::new(node_identity.node())
        .map_err(|error| format!("the daemon's declared serving node is invalid: {error}"))?;
    let mut workload_runtime = workload::compose_workload(
        registry,
        &seat_bindings,
        &session_lanes,
        &workload_brain_scopes,
        &workload_serving_node,
    )?;
    // Skip profiles missing a digest-pinned route; launch refuses them without stopping the daemon.
    workload::retain_servable_workloads(&config, &mut workload_runtime);
    for (profile, reason) in &workload_runtime.skipped {
        tracing::error!("workload {profile} is not served: {reason}");
    }
    let workload_sessions = workload_runtime.laws.clone();
    // Profiles granting browser tools open an in-pod browser on attachment.
    let browser_profiles: std::collections::BTreeSet<String> = workload_runtime
        .laws
        .iter()
        .filter(|(_, law)| {
            law.tools
                .iter()
                .any(|tool| matches!(tool.as_str(), "browser.observe" | "browser.interact"))
        })
        .map(|(profile, _)| profile.clone())
        .collect();
    let workload_supervisor: Arc<std::sync::OnceLock<Arc<LiveSupervisor>>> =
        Arc::new(std::sync::OnceLock::new());
    let workload_port: Arc<dyn crate::kube_runtime::WorkloadLaunchPort> =
        Arc::new(workload::LaunchPort {
            snapshot: Arc::clone(&snapshot_handle),
            composition: workload_runtime,
            supervisor: Arc::clone(&workload_supervisor),
            config: config.clone(),
            deployment: kube_cell
                .as_ref()
                .map(|cell| cell.workload_identity().deployment.clone()),
            session_lanes: session_lanes.clone(),
        });
    // The runtime task-state reader behind `state.tasks`: one adapter over
    // the daemon's own controller ledger, delegation link ledger, and
    // materialized read model. Shared handles — the factory, the serving
    // surfaces, and the brain's task source all observe the same
    // authorities.
    let task_state_reader: Arc<dyn odin_brain::source::state::tasks::TaskStateReader> =
        Arc::new(state_knowledge::OdindTaskStateReader::new(
            Arc::clone(&bridge_ledger),
            delegation_links.clone(),
            read_model.as_ref().clone(),
        ));
    // Operator-provisioned verification material and signed-token source;
    // odind never generates, signs, prints, or forwards a production token.
    // Posture-explicit: the minting secret is read only on the verified
    // authority (see compose_operation_authority).
    let (operation_authority_provider, session_capsule_authority) =
        compose_operation_authority(posture, &config, &manifest)?;
    // Any later setup error may leave already-admitted synchronous work.
    // Drop closes admission and disarms retirement; only the explicit shared-
    // deadline shutdown below is allowed to retire live authority.
    let _authority_shutdown = session_capsule_authority.shutdown_guard();
    let browser = match browser_config {
        Some(config) => Some(
            config
                .launch(
                    registry,
                    Arc::clone(&bridge_ledger),
                    Arc::clone(&read_model),
                    Arc::clone(&streams),
                    Arc::clone(&published),
                    Arc::clone(&external_content),
                )
                .await
                .map_err(|error| format!("could not launch browser runtime: {error:?}"))?,
        ),
        None => None,
    };
    let (browser_projection, mut browser_coordinator, pod_browser_opener) = match browser {
        Some(browser) => (
            Some(browser.projection),
            Some(browser.coordinator),
            Some(browser.pods),
        ),
        None => (None, None, None),
    };
    if let Some(coordinator) = browser_coordinator.as_mut() {
        coordinator.set_owner_preview(owner_preview_ids.clone());
    }
    if browser_coordinator.is_none() {
        return Err("enabled browser capabilities require the BrowserArm runtime".to_owned());
    }
    // Route both authority and in-pod browsers by session id.
    let browser_routes = Arc::new(odin_cli::browser_runtime::BrowserRoutes::new(
        browser_coordinator.clone(),
        pod_browser_opener,
    ));
    let concrete_browser: Arc<dyn BrowserCapabilityOwner> = browser_routes.clone();
    let canonical_v2_owner: Arc<dyn odin_omp::host_tools::CanonicalV2CapabilityOwner> =
        Arc::clone(&session_capsule_authority) as _;
    // A weak pool handle lets child stops retire backends without creating an Arc cycle.
    let pool_cell: Arc<
        std::sync::OnceLock<std::sync::Weak<crate::live_authority::SessionAuthorityPool>>,
    > = Arc::new(std::sync::OnceLock::new());
    pool_cell
        .set(Arc::downgrade(&session_capsule_authority))
        .map_err(|_| "session authority pool cell was already populated".to_owned())?;
    // Real governed delegation composition. The provisioner and lifecycle
    // control hold only Weak cells (live supervisor, session authority pool);
    // the durable link ledger is also passed to the factory so every child
    // build/reopen reconstructs the actual persisted parent chain.
    let supervisor_cell: Arc<std::sync::OnceLock<std::sync::Weak<LiveSupervisor>>> =
        Arc::new(std::sync::OnceLock::new());
    let task_slot = Arc::new(TaskOwnerSlot::new());
    // A completed task is reviewed by the Hermes runtime's learning loop,
    // bound once the runtime exists (single-assignment cell); the capture
    // only fires on a real task's terminal transition, long after startup.
    let task_review_runtime: Arc<std::sync::OnceLock<Arc<odin_hermes::runtime::HermesRuntime>>> =
        Arc::new(std::sync::OnceLock::new());
    let task_owner = match &config.delegation {
        Some(delegation) => {
            let max_prompt_bytes = usize::try_from(delegation.max_prompt_bytes.get())
                .map_err(|_| "delegation prompt ceiling does not fit usize".to_owned())?;
            let provisioner = Arc::new(crate::live_authority::PoolChildProvisioner::new(
                Arc::clone(&session_capsule_authority),
                &config,
                delegation.provider.clone(),
                delegation.model.clone(),
                delegation.child_token_ttl_seconds.get(),
                Arc::clone(&supervisor_cell),
                Arc::clone(&bridge_ledger),
            ));
            let control = Arc::new(
                crate::live_authority::SupervisorChildControl::new(
                    Arc::clone(&supervisor_cell),
                    Arc::clone(&pool_cell),
                )
                .with_reload_gate(crate::live_authority::ReloadGate {
                    pending: Box::new(crate::project_authoring::reload_requested),
                    deferred_file: crate::project_authoring::deferred_delegations_file(
                        &config.paths.state_root,
                    ),
                })
                .with_branch_reader(Box::new(crate::coding_route::capsule_branch_diff)),
            );
            Some(Arc::new(
                GovernedTaskOwner::new(
                    provisioner,
                    control,
                    delegation_links.clone(),
                    Arc::clone(&bridge_ledger),
                    DelegationGovernance {
                        provider: delegation.provider.clone(),
                        model: delegation.model.clone(),
                        max_children_per_session: delegation.max_children_per_session.get(),
                        max_prompt_bytes,
                        approved_projects: project_roots.clone(),
                        operation_bindings: seat_operation_bindings.clone(),
                    },
                )
                .with_learning(Some(Arc::new(FactoryTaskLearningCapture::new(
                    Arc::clone(&task_review_runtime),
                    Arc::clone(&live_ledger),
                )))),
            ))
        }
        None => None,
    };
    // Declared Hermes surfaces, composed only when the operator
    // renders `[hermes]`. Everything routes through the governed seams the
    // factory composes below: the sole operation authority for dispatch, the
    // durable bridge ledger for receipts, and the governed task owner for
    // delegation. Absence of the section composes nothing.
    let hermes_settings = config.hermes.as_ref().map(hermes_settings).transpose()?;
    let hermes_route = hermes_settings
        .as_ref()
        .and_then(|settings| settings.discord.as_ref())
        .map(|discord| {
            declared_conversation_binding(
                registry,
                &operation_contracts,
                &seat_bindings,
                &session_lanes,
                discord,
                posture,
            )
        })
        .transpose()?;
    // Intents, approvals, and live plans retain one authoritative ledger.
    let conversation_ledger_path = config.paths.state_root.join("ledger.sqlite3");
    let hermes_runtime = match hermes_settings {
        Some(settings) => {
            let hermes_ledger = Ledger::open(&conversation_ledger_path)
                .map_err(|error| format!("could not open hermes ledger: {error}"))?;
            let adapter_ledger = Ledger::open(&conversation_ledger_path)
                .map_err(|error| format!("could not open hermes adapter ledger: {error}"))?;
            let max_prompt_bytes = config
                .delegation
                .as_ref()
                .map(|delegation| delegation.max_prompt_bytes.get() as usize)
                .unwrap_or(0);
            let task_owner: Option<Arc<dyn odin_omp::host_tools::delegation::TaskOwner>> =
                task_owner
                    .clone()
                    .map(|owner| owner as Arc<dyn odin_omp::host_tools::delegation::TaskOwner>);
            let mut seat_bound_projects: BTreeMap<odin_domain::SeatId, BTreeSet<ProjectId>> =
                BTreeMap::new();
            for (seat, project) in session_lanes.keys() {
                seat_bound_projects
                    .entry(seat.clone())
                    .or_default()
                    .insert(project.clone());
            }
            Some(
                odin_hermes::runtime::HermesRuntime::open(
                    settings,
                    odin_hermes::runtime::HermesLedgers {
                        conversation: hermes_ledger,
                        adapter: Arc::new(parking_lot::Mutex::new(adapter_ledger)),
                        purchase: Arc::clone(&bridge_ledger),
                    },
                    &operation_contracts,
                    task_owner,
                    max_prompt_bytes,
                    seat_bound_projects,
                    hermes_route.as_ref().map(|route| route.ownership.clone()),
                )
                .map_err(|error| error.to_string())?,
            )
        }
        None => None,
    };
    // The gateway intake governs against the daemon's LIVE seat authority:
    // the same provisioned tokens and durable revocation/stop rows the
    // dispatch path verifies against. Unbound, external intake refuses
    // closed — a disconnected integration, never a permissive one.
    // The owner's task grants: one ledger the operation stack decides
    // covered calls against and `task.grant` records into.
    let task_grants = Arc::new(odin_omp::host_tools::task_grants::TaskGrantStore::open(
        config.paths.state_root.join("task-grants.json"),
    ));
    if let Some(runtime) = &hermes_runtime {
        runtime.set_task_grants(Arc::clone(&task_grants));
        if let Some(gateway) = config
            .hermes
            .as_ref()
            .and_then(|hermes| hermes.review_gateway.clone())
        {
            runtime.set_review_gateway(gateway);
        }
        let _ = task_review_runtime.set(Arc::clone(runtime));
    }
    // Checkout uses the signed-in browser only after exact kernel approval is consumed.
    if let (Some(runtime), Some(coordinator)) = (&hermes_runtime, &browser_coordinator) {
        let contract = odin_hermes::purchase::PurchaseAdapterContract::governed_browser()
            .map_err(|error| format!("the governed-browser purchase contract: {error}"))?;
        runtime.bind_purchase_backend(
            contract,
            odin_cli::browser_runtime::BrowserCheckoutBackend::new(coordinator.clone()),
        )?;
        tracing::info!("purchase backend bound backend=governed-browser");
    }
    if let Some(runtime) = &hermes_runtime {
        runtime.set_intake_authority(Arc::new(DaemonIntakeAuthority {
            ledger: Arc::clone(&bridge_ledger),
            token_root: config.paths.authority_token_root.clone(),
            posture,
        }));
    }
    // The model-switch target set is a STARTUP fact: the exact declared
    // launch tuples of the pinned snapshot's seat bindings, pinned into
    // the runtime before the compiled catalog is built, so the
    // model-facing surface is generated from the same declaration the
    // supervisor admission enforces — never a per-dispatch derivation.
    if let Some(runtime) = &hermes_runtime {
        runtime.set_model_launch_declaration(
            odin_hermes::runtime::ModelLaunchDeclaration::from_bindings(&seat_bindings),
        );
        // `registry.read` and the seat-ask surfaces (which seats declare a
        // conversation) read the one pinned snapshot from tool generation on.
        runtime.set_registry_pin(Arc::clone(&snapshot_handle));
    }
    let incident_desk = Arc::new(crate::incidents::IncidentDesk::new(
        Arc::clone(&read_model),
        hermes_runtime.clone(),
        config
            .alerts
            .as_ref()
            .map(|alerts| alerts.phone_url.clone()),
    ));
    if let Some(runtime) = &hermes_runtime {
        runtime.set_incident_route(Arc::clone(&incident_desk) as Arc<_>);
    }
    // Declared brain sources compose AFTER the Hermes surface exists: a
    // `memory.<seat>` source's sole authority is the daemon's VALIDATED
    // Hermes vault singleton, so composition follows that construction
    // instead of inventing an alternate filesystem or port authority.
    let hermes_vault = hermes_runtime
        .as_ref()
        .and_then(|runtime| runtime.vault().as_ref())
        .map(|vault| vault.config());
    let brain_source_set = match config.brain.as_ref() {
        // Per-seat policies compose only over really declared sources; the
        // per-seat filtering to each policy's authorized set happens in the
        // factory assembly, so an authorized-but-undeclared id simply stays
        // typed-unavailable for that seat.
        Some(brain) if !brain_policies.is_empty() => brain_sources(
            &brain_policies,
            &crate::projection::DeclaredBrainSources {
                sources: &brain.sources,
                project_roots: &config.projects,
            },
            &snapshot_handle,
            &read_model,
            &task_state_reader,
            hermes_vault,
            &bridge_ledger,
        )?,
        _ => BTreeMap::new(),
    };
    let repo_heads = state_knowledge::RepoHeads::from_sources(&brain_source_set)?;
    let hermes_tools: Vec<Arc<dyn odin_omp::host_tools::HostTool>> = match &hermes_runtime {
        Some(runtime) => odin_hermes::runtime::hermes_host_tools(runtime),
        None => Vec::new(),
    };
    let hermes_internal_bindings: Vec<(&'static str, Arc<dyn odin_omp::host_tools::HostTool>)> =
        match &hermes_runtime {
            Some(runtime) => odin_hermes::runtime::hermes_capability_bindings(runtime),
            None => Vec::new(),
        };
    // Without delegation configuration, task handlers remain unbound and refuse invocation.
    let task_create_capability = CapabilityId::new("task.create")
        .map_err(|_| "compiled task.create capability id is invalid".to_owned())?;
    let task_read_capability = CapabilityId::new("task.read")
        .map_err(|_| "compiled task.read capability id is invalid".to_owned())?;
    let runtime_task_slot = match &task_owner {
        Some(_) => Some(Arc::clone(&task_slot)),
        None if operation_contracts.contains_key(&task_create_capability)
            || operation_contracts.contains_key(&task_read_capability) =>
        {
            Some(Arc::clone(&task_slot))
        }
        None => None,
    };
    let conversation_guidance = odin_omp::live::runtime::declared_conversation_guidance(registry)?;
    let tool_exposure = odin_omp::live::runtime::declared_tool_exposure(registry)?;
    let seat_sandboxes = odin_omp::live::runtime::declared_seat_sandboxes(registry)?;
    let seat_memory_max = odin_omp::live::runtime::declared_seat_memory_max(registry);
    let sandbox_host = odin_omp::process::sandbox_host_from_env()?;
    let operation_clock = odin_omp::host_tools::operations::wall_clock();
    let kube_coordinator = Arc::new(
        kube_runtime::KubeCommandCoordinator::new(kube_cell.clone())
            .with_overseers(conversation_seats.clone()),
    );
    kube_coordinator
        .arm_workload_port(workload_port)
        .map_err(|error| error.to_string())?;
    // The kube-admitted remote carrier of workload sessions: resolves the
    // exact pod exec channel of each binding's operation. Unconfigured kube
    // composes `None`, and workload sessions then refuse typed.
    let workload_carrier = kube_cell.as_ref().map(|cell| {
        Arc::new(crate::kube::KubeWorkloadCarrier::new(
            Arc::clone(cell),
            config.executables.omp_revision.clone(),
            Arc::clone(&browser_routes),
            browser_profiles.clone(),
        )) as Arc<dyn odin_omp::live::runtime::WorkloadCarrierPort>
    });
    let workload_drafts = Some(Arc::new(
        odin_omp::host_tools::WorkloadDraftStore::seal(&config.paths.state_root)
            .map_err(|error| error.to_string())?,
    ));
    let production_factory = Arc::new(
        ProductionBridgeRuntimeFactory::new(
            ProductionBridgeRuntimeConfig {
                workload_drafts,
                task_grants: Some(Arc::clone(&task_grants)),
                // The admission revision is the published SnapshotStore
                // revision this process pinned at startup, and the
                // contracts are that same snapshot's derivation — the one
                // (contracts, revision) pair the startup admission digest
                // binds.
                admission_revision,
                operation_contracts,
                // Capabilities whose concrete owner is the one-shot operator
                // CLI. They are admitted at registry publication by the
                // operator catalog and are excluded from the kernel dispatch
                // catalog, so no HostTool owner is invented for them and no
                // session can dispatch them.
                operator_capabilities: {
                    let mut ids = BTreeSet::new();
                    for binding in odin_cli::runtime_bindings::OPERATOR_CAPABILITY_BINDINGS {
                        ids.insert(CapabilityId::new(binding.capability).map_err(|error| {
                            format!("compiled operator capability id is invalid: {error}")
                        })?);
                    }
                    ids
                },
                operation_authority_provider,
                revision_material: Arc::new(
                    odin_cli::runtime_bindings::StoreRevisionMaterial::new(
                        SnapshotStore::new(&config.paths.registry_snapshot),
                        config.clone(),
                    ),
                ),
                schema_catalog: Arc::new(
                    odin_omp::host_tools::operations::FilesystemSchemaCatalog::new(odin_root),
                ),
                // Consumptive spend enforcement is the deployed gateway's
                // declared cap (LiteLLM max_budget at the gateway seam) —
                // the pinned worker is never patched for enforcement and
                // the odin-ledger reservation/settlement tables are
                // unwired (an open blocker tracked with the operator).
                // Durable operation accounting still records every charge.
                operation_limits: odin_domain::operation::Limits::new(u64::MAX, u64::MAX, u64::MAX),
                operation_clock: Arc::clone(&operation_clock),
                seat_operation_bindings,
                delegation_links: delegation_links.clone(),
                // Only seats whose registry declaration carries a
                // `[live.rollover]` section arm the bounded turn-boundary
                rollover_by_seat: rollover_seats.clone(),
                lane_windows_by_seat,
                workload_sessions,
                workload_carrier,
                conversation_guidance,
                tool_exposure,
                session_capsule_authority: Arc::clone(&session_capsule_authority)
                    as Arc<dyn odin_omp::live::runtime::SessionCapsuleAuthority>,
                process,
                worker: omp_worker,
                bridge_ledger: Arc::clone(&bridge_ledger),
                live_ledger: Arc::clone(&live_ledger),
                atlas,
                allowed_atlas_scope,
                brain_policies,
                // The trusted knowledge sources the brain service pins and
                // indexes, taken exactly from the operator `brain.sources`
                // configuration and validated against the served policy's
                // authorized set.
                brain_sources: brain_source_set,
                // The brain-embedding route resolves from the published
                // snapshot: a declared provider with a live route composes
                // the kernel-lease-governed executor factory through the
                // private gateway transport; an absent or unpublished route
                // stays `None`, so vector and hybrid retrieval fail typed
                // EmbeddingUnavailable instead of downgrading. Each session
                // binds its own requesting runtime lane through the factory
                // at context construction — the lease names the session
                // lane, never the gateway route lane. The acceptance gate
                // stays `None` here: it is a trusted runtime dependency
                // supplied only by an authentic kernel wiring, never
                // serialized configuration.
                brain_embedding: brain_embedding
                    .as_ref()
                    .map(|binding| binding.executor.clone() as Arc<dyn LaneEmbeddingProvider>),
                brain_embedding_model: brain_embedding
                    .as_ref()
                    .map(|binding| binding.model.clone()),
                brain_postgres,
                artifact_root: huginn_root.join("artifacts"),
                project_roots,
                session_lanes,
                context_read,
                allowed_nodes,
                // The follower posture composes the runtime with exactly the
                // empty served sets above; the sole authoritative posture
                // keeps every non-empty assembly requirement.
                read_only: posture == NodePosture::Follower,
                owner_id: format!("odind:{}", config.identity.node),
                hooks_root: huginn_root.join("hooks"),
                lease_ttl: StdDuration::from_secs(15 * 60),
                max_artifact_read_bytes: limits
                    .transfers
                    .max_transfer_bytes
                    .get()
                    .min(odin_omp::uri::MAX_ARTIFACT_READ_BOUND),
                zellij: Some(zellij),
                task_slot: runtime_task_slot,
                // The declared adapter backends (dispatch + health) and the
                // status freshness bound, composed above.
                adapters,
                adapter_status_ttl,
                // Hermes tools still dispatch through the operation authority.
                hermes_tools,
                hermes_internal_bindings,
                seat_sandboxes,
                seat_memory_max,
                sandbox_host: Some(sandbox_host),
            },
            concrete_browser,
            canonical_v2_owner,
            kube_coordinator,
        )
        .map_err(|error| error.to_string())?,
    );
    if let Some(runtime) = &hermes_runtime {
        brain_bindings::bind_hermes_brains(runtime, &production_factory, &live_ledger)?;
    }
    brain_bindings::prune_retired_brain_stores(posture, &production_factory);
    let brain_warm_targets =
        brain_bindings::brain_warm_targets(posture, &config, &production_factory);
    let factory: Arc<dyn BridgeRuntimeFactory> = production_factory.clone();
    // Every production session stops under a bounded coordinator, including
    // delegation-disabled seats: no session's own capsule backend outlives
    // its stop.
    let stop_coordinator: Arc<dyn ChildStopCoordinator> = match &task_owner {
        Some(owner) => owner.clone(),
        None => Arc::new(SessionStopCoordinator(Arc::clone(
            &session_capsule_authority,
        ))),
    };
    let launcher = LiveBridgeLauncher::new(factory)
        .with_child_stop_coordinator(&stop_coordinator)
        .map_err(|error| error.to_string())?;
    // Instance-local cancellation prevents shutdown state leaking between daemons.
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let (launcher, harness_routes, mcp_bridge) =
        harness_launch::compose(harness_launch::HarnessLaunchInputs {
            config: &config,
            snapshot: &snapshot,
            launcher,
            production_factory: &production_factory,
            incident_desk: &incident_desk,
            kube_cell: &kube_cell,
            stops: terminal_stops,
            supervisor: Arc::clone(&supervisor_cell),
            pool: Arc::clone(&pool_cell),
            stopping: stop_rx,
        })
        .await?;
    let supervisor = LiveSupervisor::discover(
        Arc::clone(&live_ledger),
        launcher,
        limits.sessions.max_sessions.get(),
        Some(Arc::new(SessionTurnReview {
            owner: task_owner.as_ref().map(|owner| {
                Arc::clone(owner)
                    as Arc<dyn odin_omp::host_tools::delegation::CompletionEventObserver>
            }),
            links: delegation_links.clone(),
            runtime: Arc::clone(&task_review_runtime),
            live_ledger: Arc::clone(&live_ledger),
        })),
    )
    .await
    .map_err(|error| error.to_string())?;
    for binding in seat_bindings {
        supervisor
            .bind(binding)
            .await
            .map_err(|error| error.to_string())?;
    }
    // Open observers only after Huginn listens: their attach clients connect immediately.
    let observers = (posture == NodePosture::Authoritative).then(|| {
        crate::harness::ObservedSessions::own(
            Arc::clone(&supervisor),
            config.clone(),
            harness_routes.clone(),
        )
    });
    if posture == NodePosture::Authoritative {
        settle::settle_stale_sessions(
            &supervisor,
            &bridge_ledger,
            hermes_runtime
                .as_ref()
                .map(|runtime| runtime.settings().state_dir.clone())
                .as_deref(),
        )
        .await;
        settle::remove_ended_capsules(&supervisor, config.paths.state_root.clone());
    }
    workload_supervisor
        .set(Arc::clone(&supervisor))
        .map_err(|_| "workload supervisor slot was already armed".to_owned())?;
    // The real supervisor identity exists only now: publish it through the
    // Weak cell (provisioner and child control upgrade it per call, never
    // pinning it) and bind the concrete owner exactly once before listen.
    supervisor_cell
        .set(Arc::downgrade(&supervisor))
        .map_err(|_| "live supervisor cell was already populated".to_owned())?;
    if let Some(owner) = &task_owner {
        let bound_owner: Arc<dyn TaskOwner> = owner.clone();
        task_slot
            .bind(bound_owner)
            .map_err(|error| format!("could not bind task owner: {error}"))?;
    }
    let lane_port: Arc<dyn LaneArtifactPort> = Arc::new(
        FsLaneArtifactPort::open(huginn_root.join("lane-artifacts"))
            .map_err(|error| error.to_string())?,
    );
    let lane_artifacts = Arc::new(LaneTransferBridge::new(lane_port));
    // A read-only follower serves no seats, so its transfer lane registry
    // is legitimately empty: every lookup stays a typed denial while
    // assembly no longer demands the authority-shaped non-empty seat set.
    let lane_resolver: Arc<dyn TransferLaneResolver> =
        if posture == NodePosture::Follower && transfer_lanes.is_empty() {
            Arc::new(RegistryTransferLaneResolver::read_only(Arc::clone(
                &live_ledger,
            )))
        } else {
            Arc::new(
                RegistryTransferLaneResolver::new(Arc::clone(&live_ledger), transfer_lanes)
                    .map_err(|error| error.to_string())?,
            )
        };
    let transfers = Arc::new(
        TransferManager::open(
            huginn_root.join("live-transfers"),
            Arc::clone(&live_ledger),
            lane_resolver,
            Arc::clone(&lane_artifacts),
        )
        .map_err(|error| error.to_string())?,
    );
    let omp = Arc::new(odin_omp::live::service::OmpLiveService::new(
        Arc::clone(&live_ledger),
        Arc::clone(&supervisor),
        transfers,
    ));
    let conversation_root: Option<hermes_routes::VehicleRouteBinding> = hermes_routes::bind(
        &hermes_runtime,
        hermes_route,
        &omp,
        &supervisor,
        &config,
        &manifest,
        &conversation_ledger_path,
        &snapshot_handle,
        &read_model,
        &kube_cell,
        &rollover_seats,
        &delegation_links,
        Some(&incident_desk),
        Arc::clone(&bridge_ledger),
        operation_clock,
        &session_capsule_authority,
    )
    .await?;
    let live_plane: Arc<dyn live::OmpLivePlane> = omp.clone();
    // Durable session and approval feeds share the read model and run only on the authority.
    let session_projection_store = Arc::new(
        odin_huginn::sessions::SessionProjectionStore::new(
            live::SeatRoster::new(
                live::RosterRevision::new(0),
                OffsetDateTime::UNIX_EPOCH,
                Vec::new(),
            ),
            limits.sessions.max_sessions.get(),
            limits.sessions.max_list_page,
        )
        .map_err(|error| format!("could not compose the session projection store: {error}"))?,
    );
    // The durable feed's cursor file lives in a private feeds directory:
    // provision it here, in the owning composition, before the pump's
    // startup-checked cursor load reads it on a fresh root.
    ensure_feeds_dir(&huginn_root)?;
    let durable_feed_pump = Arc::new(odin_huginn::feed::DurableFeedPump::new(
        posture,
        Arc::clone(&live_plane),
        Arc::clone(&bridge_ledger),
        Arc::new(session_discovery::LiveLedgerSessionDiscovery {
            ledger: Arc::clone(&live_ledger),
        }) as Arc<dyn odin_huginn::feed::DurableSessionDiscovery>,
        Some(huginn_root.join("feeds").join("change-cursor")),
        Arc::clone(&read_model),
        Arc::new(odin_huginn::feed::RosterFeed::new(Arc::clone(
            &session_projection_store,
        ))),
        Arc::new(tokio::sync::Mutex::new(
            odin_huginn::feed::SessionEventFeed::new(
                Arc::clone(&streams),
                Arc::clone(&published),
                huginn_conformance::stream_backpressure_limits(&limits)?,
                u64::try_from(limits.streams.max_stream_frame_bytes.get())
                    .map_err(|_| "stream frame limit does not fit u64".to_owned())?,
            ),
        )),
        odin_huginn::feed::ApprovalFeed::new(),
        limits.sessions.max_history_page,
        limits.sessions.max_sessions.get(),
    ));
    let ticket_issuer: Arc<dyn live::ContentTicketIssuer> = Arc::new(
        HuginnContentTicketIssuer::new(
            ticket_store.clone(),
            Arc::clone(&live_plane),
            Arc::clone(&files),
            Arc::clone(&published),
            external_content.as_ref().clone(),
            ticket_ttl,
            limits.transfers.queue_depth.get(),
        )
        .map_err(|error| error.to_string())?,
    );
    production_factory
        .validate_capability_composition()
        .map_err(|error| error.to_string())?;
    let conversation_surface = match (&hermes_runtime, &conversation_root) {
        (Some(runtime), Some(binding)) => Some(Arc::new(
            crate::conversation_surface::ConversationSurface::new(
                Arc::clone(runtime),
                Arc::clone(&binding.root),
                Arc::clone(&devices),
            )?,
        )),
        _ => None,
    };
    // Route ring gestures to the conversation seat's routines, wherever it runs.
    let ring_intake = hermes_runtime.as_ref().map(|runtime| {
        Arc::new(crate::ring_gesture::RingGestureIntake::new(
            Arc::clone(&devices),
            Arc::clone(runtime),
        ))
    });
    // The authority pump feeds missions from simulation profile runs.
    let simulation_desk = match (&kube_cell, posture) {
        (Some(_), NodePosture::Authoritative) => {
            Some(Arc::new(crate::simulation::SimulationDesk::new(
                Arc::clone(&read_model),
                Arc::clone(&streams),
                huginn_conformance::stream_backpressure_limits(&limits)?,
                Arc::clone(&bridge_ledger),
            )?))
        }
        _ => None,
    };
    // Device-bound session authority: mint where the key lives, claim, open.
    let device_open = Arc::new(super::device_open::DeviceOpenAuthority::new(
        config.clone(),
        Arc::clone(&devices),
        Arc::clone(&bridge_ledger),
        Arc::clone(&live_plane),
    ));
    let device_open_stop = device_open.stop_handle();
    let general: Arc<dyn AuthenticatedCommandPort> = Arc::new(
        RuntimeCommandPort::new(
            Arc::clone(&bridge_ledger),
            Arc::clone(&read_model),
            Some(Arc::clone(&browser_routes)),
            Arc::clone(&streams),
            kube_cell.clone(),
            huginn_conformance::stream_backpressure_limits(&limits)?,
        )
        .with_conversation(conversation_surface)
        .with_live(Arc::clone(&live_plane))
        .with_device_open(Some(device_open))
        .with_simulation(simulation_desk.clone())
        .with_ring(ring_intake)
        .with_owner_preview(owner_preview_ids),
    );
    let commands = Arc::new(HuginnCommandPlane::new(general, live_plane));
    let device_activity = (Arc::clone(&devices), connections.clone());
    // The local admin revoke surface: one admin over the live registry for
    // the socket handler, one for the pump's crash redrive; both share the
    // same store and registry, so a revoke lands exactly once.
    let device_admin = Arc::new(odin_huginn::devices::DeviceAdmin::new(
        Arc::clone(&devices),
        connections.clone(),
    ));
    let admin_listener =
        crate::device_admin::bind_device_admin_socket(&validated.state().admin_socket())?;
    // Built before the ports move takes `devices` and `connections`: the
    // socket handler and the pump's crash redrive share this store and
    // registry, so a revoke lands exactly once.
    let admin_handle = crate::device_admin::DeviceAdminHandle {
        admin: odin_huginn::devices::DeviceAdmin::new(Arc::clone(&devices), connections.clone()),
        ledger: Arc::clone(&bridge_ledger),
    };
    let shutdown_connections = connections.clone();
    let render_activity = Arc::clone(&renders);
    let state = odin_huginn::HuginnLiveState::new(odin_huginn::state::HuginnPorts {
        read_model: Arc::clone(&read_model),
        commands,
        streams,
        files,
        renders,
        devices,
        tailnet,
        connections,
        guard,
        posture,
        tickets: ticket_issuer,
    });
    let service = odin_huginn::HuginnService::new(validated, state, ticket_store);
    let listen_address = config.listener.address;
    let listener = tokio::net::TcpListener::bind(listen_address)
        .await
        .map_err(|error| format!("Huginn could not listen on {listen_address}: {error}"))?;

    let mut pumps = tokio::task::JoinSet::new();
    crate::device_admin::arm_device_admin_socket(&mut pumps, admin_listener, admin_handle);
    // The one vehicle-open lane: the Hermes conversation root initializes
    // against the composed plane WITHOUT gating the daemon — a failed
    // vehicle open is a typed Huginn incident plus a bounded backoff
    // retry of the same governed open, never an exit. Arming joins the
    // same pump set the owning shutdown aborts, and the retained root
    // handle keeps the shutdown's bounded background join below.
    let vehicle_root = conversation_root
        .as_ref()
        .map(|binding| std::sync::Arc::clone(&binding.root));
    vehicle_open::arm_vehicle_open_lane(
        &mut pumps,
        conversation_root,
        Arc::clone(&read_model),
        vehicle_open::VehicleRetrySchedule::production(),
    );
    // The state-source heads subscribe NOW — strictly before the pump's
    // initial generation — so an authority that moves during the first
    // build is already pending on its channel. Composition yields `None`
    // when no state source is wired: the pump is state plumbing, not a
    // general brain ticker.
    let state_heads = state_knowledge::compose_state_heads(
        &config,
        &snapshot_handle,
        &read_model,
        &delegation_links,
        &bridge_ledger,
        repo_heads,
    )?;
    let wired_state_ids = state_knowledge::wired_state_source_ids(&config);
    let state_rebuild_brains =
        state_knowledge::state_rebuild_seats(production_factory.brains(), &wired_state_ids);
    let pump_setup =
        arm_egress_lane_pumps(&mut pumps, &lane_artifacts, &omp, egress_lanes, posture)
            .await
            .map(|()| {
                arm_service_pumps(
                    &mut pumps,
                    posture,
                    &hermes_runtime,
                    &kube_cell,
                    &read_model,
                );
                arm_fleet(
                    &mut pumps,
                    Arc::clone(&snapshot_handle),
                    Arc::clone(&read_model),
                    Arc::new(odin_huginn::fleet::TcpFleetProbe),
                    Arc::new(crate::fleet_probe::SshZellijProbe),
                );
                arm_durable_feed_pump(&mut pumps, posture, Arc::clone(&durable_feed_pump));
                arm_device_activity_pump(
                    &mut pumps,
                    device_activity,
                    Arc::clone(&read_model),
                    Arc::clone(&device_admin),
                    Arc::clone(&bridge_ledger),
                );
                arm_render_pump(&mut pumps, render_activity, Arc::clone(&read_model));
                arm_spend_pump(&mut pumps, posture, Arc::clone(&read_model));
                arm_brain_warm_pump(&mut pumps, brain_warm_targets);
                if let (Some(desk), Some(cell)) = (&simulation_desk, &kube_cell) {
                    crate::simulation::arm_simulation_pump(
                        &mut pumps,
                        Arc::clone(desk),
                        Arc::clone(cell),
                        Arc::clone(&snapshot_handle),
                    );
                }
                if posture != NodePosture::Follower {
                    crate::project_authoring::arm_reload_pump(
                        &mut pumps,
                        Arc::clone(&omp),
                        conversation_seats.clone(),
                        crate::harness::observer_titles(&harness_routes),
                    );
                    if let Some(runtime) = &hermes_runtime {
                        crate::project_authoring::arm_seat_retire_pump(
                            &mut pumps,
                            Arc::clone(&omp),
                            Arc::clone(runtime),
                            conversation_seats.clone(),
                            crate::harness::observer_titles(&harness_routes),
                        );
                    }
                    crate::retention::arm_retention_pump(
                        &mut pumps,
                        conversation_ledger_path.clone(),
                    );
                    crate::retention::arm_approval_expiry_pump(
                        &mut pumps,
                        conversation_ledger_path.clone(),
                    );
                }
                if let (Some(runtime), Some(owner)) = (&hermes_runtime, &task_owner) {
                    if let Some(discord) = runtime.settings().discord.as_ref() {
                        arm_child_report_pump(
                            &mut pumps,
                            Arc::clone(runtime),
                            Arc::clone(owner),
                            discord.seat.clone(),
                            config.delegation.as_ref().map(|delegation| {
                                (
                                    std::time::Duration::from_secs(
                                        delegation.child_timeout_seconds.get(),
                                    ),
                                    delegation
                                        .child_idle_seconds
                                        .map(|idle| std::time::Duration::from_secs(idle.get())),
                                    delegation
                                        .child_stall_seconds
                                        .map(|stall| std::time::Duration::from_secs(stall.get())),
                                )
                            }),
                            kube_cell.clone(),
                            Arc::clone(&incident_desk),
                        );
                        if posture == NodePosture::Authoritative {
                            crate::project_authoring::wake_deferred_delegations(
                                runtime,
                                &config.paths.state_root,
                            );
                            workload_watch::arm_workload_watch(
                                &mut pumps,
                                Arc::clone(&read_model),
                                Arc::clone(owner),
                                Arc::clone(runtime),
                                kube_cell.clone(),
                                config.paths.state_root.clone(),
                                discord.seat.clone(),
                            );
                            repo_watch::arm_repo_watch(
                                &mut pumps,
                                Arc::clone(runtime),
                                config
                                    .projects
                                    .iter()
                                    .map(|(project, entry)| (project.clone(), entry.root.clone()))
                                    .collect(),
                                config.paths.state_root.clone(),
                                Arc::clone(&session_capsule_authority),
                            );
                            if let Some(cell) = kube_cell.as_ref() {
                                workload_monitor::arm_workload_monitor(
                                    &mut pumps,
                                    Arc::clone(cell),
                                    Arc::clone(owner),
                                    Arc::clone(runtime),
                                    Arc::clone(&incident_desk),
                                    config.paths.state_root.clone(),
                                );
                            }
                        }
                    }
                }
                if let Some(heads) = state_heads {
                    state_knowledge::arm_state_rebuild_pump(
                        &mut pumps,
                        state_rebuild_brains,
                        heads,
                    );
                }
            });
    // An ordinary stop owns no capture and reads no root backup state: the
    // one serving grace begins when the owned shutdown starts below.
    let signal_stop = serving::arm_stop_signal()?;
    // The browser capsule's supervision inputs are handed to the owning
    // orchestration at the final serving point — after every fallible
    // composition step — so the seam spawns the supervisor and owns it
    // through the joined retirement; a startup error before this point
    // never detaches it, and owner-drop signals the same one-time
    // retirement if the owner ever goes away early.
    let browser_capsule = match (browser_projection, browser_coordinator.clone()) {
        (Some(projection), Some(coordinator)) => Some(
            browser_capsule::BrowserCapsuleSupervision::capsule_terminal_and_retirement(
                projection,
                coordinator,
            ),
        ),
        _ => None,
    };
    // A pump-arming failure routes through the SAME orchestration: the
    // capsule ladder always runs, and the original setup error is
    // preserved verbatim as the daemon result — never mislabeled as a
    // Huginn serving failure.
    // The opener is SPAWNED here but never detached: the owning seam stops admission at the stop
    // signal and joins the opener and its followers under the shutdown deadline.
    if let Some(observers) = &observers {
        observers.spawn();
    }
    let (result, accounting) = orchestrate_serving(
        pump_setup.map(|()| service.serve_on(listener)),
        pumps,
        signal_stop,
        browser_capsule,
        serving::ServingShutdown::own(
            stop_tx,
            shutdown_connections,
            mcp_bridge.listeners,
            mcp_bridge.dispatches,
            observers,
            device_open_stop,
        )
        .with_session_supervisor(Arc::clone(&supervisor))
        .with_harness_turns(supervisor.harness_turns())
        .with_authority_pool(Arc::clone(&session_capsule_authority))
        .with_background_root(vehicle_root.clone())
        .with_notifications(hermes_runtime.clone())
        .with_terminals(shutdown_terminals),
    )
    .await;
    shutdown_started
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get_or_insert(accounting.started);
    shutdown::finalize(result, accounting, vehicle_root, &session_capsule_authority).await
}

use crate::learning::{FactoryTaskLearningCapture, SessionTurnReview};
use serving::orchestrate_serving;

#[cfg(test)]
#[path = "tests/browser_capsule.rs"]
mod browser_capsule_tests;
