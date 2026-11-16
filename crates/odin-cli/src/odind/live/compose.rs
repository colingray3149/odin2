//! Live daemon composition.

#[path = "compose/hermes.rs"]
mod hermes;
#[path = "compose/kube_coordinator.rs"]
mod kube_coordinator;
#[path = "compose/offload_binding.rs"]
mod offload_binding;
#[path = "compose/seat_roots.rs"]
mod seat_roots;
#[path = "compose/transfers.rs"]
mod transfers;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use odin_brain::retrieval::LaneEmbeddingProvider;
use odin_cli::runtime_bindings::{operation_contracts, seat_operation_bindings, RuntimeInputs};
use odin_domain::huginn as live;
use odin_domain::CapabilityId;
use odin_huginn::dispatch::AuthenticatedCommandPort;
use odin_huginn::NodePosture;
use odin_ledger::Ledger;
use odin_registry::SnapshotStore;
use time::OffsetDateTime;

type ValueValidator = Arc<dyn Fn(&serde_json::Value) -> Result<(), String> + Send + Sync>;

use super::serving::{orchestrate_serving, HuginnServe};
use super::*;
use crate::authority::{compose_operation_authority, SessionStopCoordinator};
use crate::browser::browser_runtime_config;
use crate::child_report::bind_run_stats;
use crate::composition::RuntimeWorkers;
use crate::composition::{
    context_read_runtime_config, load_runtime_manifest, renderer_registry, runtime_workers,
};
use crate::huginn_conformance;
use crate::kube::{KubeRuntimeCell, RuntimeCommandPort};
use crate::projection::{
    brain_sources, seed_read_model, served_brain_policies, served_lane_windows,
    shared_seat_atlas_scope,
};
use crate::pumps::arm_egress_lane_pumps;
use crate::state_knowledge;

pub(super) async fn serve_huginn_async(serve: HuginnServe) -> Result<(), String> {
    let HuginnServe {
        config,
        validated,
        snapshot,
        snapshot_handle,
        runtime,
        extension_policy,
        posture,
        shutdown_started,
        launched,
    } = serve;
    // Every registry/schema/listing/policy request below reads this exact
    // pinned revision; the Arc stays immutable for the process lifetime.
    let registry = &snapshot.objects;
    if let Some(list) = &config.models.local_list {
        odin_hermes::runtime::set_local_list(list.clone());
    }
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
    let admission_revision = i64::try_from(snapshot.revision).map_err(|error| {
        format!(
            "published snapshot revision {} does not fit i64: {error}",
            snapshot.revision
        )
    })?;
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
    use odin_omp::live::ledger::{fs::FsLiveLedger, LiveLedger};
    use odin_omp::live::runtime::{ProductionBridgeRuntimeConfig, ProductionBridgeRuntimeFactory};
    use odin_omp::live::supervisor::{BridgeRuntimeFactory, LiveBridgeLauncher, LiveSupervisor};

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
    // The knowledge index builds after the listeners bind (see the atlas pump below); sessions
    // share this cell and read it once it is set.
    let atlas = Arc::new(std::sync::OnceLock::new());
    let atlas_sources = odin_atlas::AtlasSources::new(&odin_root);
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
    let kube_cell: Option<Arc<KubeRuntimeCell>> = kube_cell::compose(
        &config,
        &manifest,
        &snapshot,
        &snapshot_handle,
        &bridge_ledger,
        &huginn_root,
    )?;
    // None of these three reads another's output, so they open together; each failure stays
    // fatal, reported in the original order.
    let (process, devices, brain_postgres) = tokio::join!(
        worker_process::compose(
            &config,
            extension,
            &extension_policy,
            &omp_worker,
            zellij_worker,
            &huginn_root,
        ),
        async {
            odin_huginn::devices::SqliteDeviceTrustStore::open(validated.state().devices_db())
                .map_err(|error| error.to_string())
        },
        crate::projection::served_brain_postgres(&config),
    );
    let (process, zellij) = process?;
    let devices = Arc::new(devices?);
    let brain_postgres = brain_postgres?;
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
            .map_err(|error| format!("stream frame limit does not fit u64: {error}"))?,
    )
    .map_err(|error| error.to_string())?
    .with_content_retirement(published.clone());
    let streams = Arc::new(odin_huginn::streams::BoundedMultiplexer::new(
        replay,
        limits.streams.frame_queue_depth.get(),
        limits.connections.max_subscriptions_per_connection.get(),
    ));

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
        u64::try_from(limits.transfers.ticket_ttl.whole_seconds()).map_err(|error| {
            format!(
                "content ticket TTL {} does not fit u64: {error}",
                limits.transfers.ticket_ttl
            )
        })?,
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
        .map_err(|error| format!("compiled context.read capability id is invalid: {error}"))?;
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
    let card_windows =
        model_windows::selectable_card_windows(registry, &config.paths.registry_root)?;
    let card_tokenizers = model_windows::selectable_card_tokenizers(registry);
    let lane_windows_by_seat = served_lane_windows(
        &config,
        &brain_policies,
        &seat_bindings,
        &card_windows,
        &card_tokenizers,
    )?;
    let brain_embedding = crate::projection::served_embedding(&config, &snapshot)?;
    // Compose workload scopes and model policies; invalid profiles are skipped individually.
    let workload_brain_scopes = workload::brain_source_scopes(&brain_policies);
    let workload_serving_node = odin_domain::NodeId::new(node_identity.node())
        .map_err(|error| format!("the daemon's declared serving node is invalid: {error}"))?;
    let gateway = crate::projection::load_gateway_projection(&config);
    let mut workload_runtime = workload::compose_workload(
        registry,
        &seat_bindings,
        &session_lanes,
        &workload_brain_scopes,
        &workload_serving_node,
        gateway.as_ref().ok(),
    )?;
    // Skip profiles missing a digest-pinned route; launch refuses them without stopping the daemon.
    workload::retain_servable_workloads(&config, gateway.as_ref(), &mut workload_runtime);
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
            serving_node: workload_serving_node.clone(),
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
    // Compose the governed browser runtime without launching any browser:
    // validation, the pod-browser opener, and the lazy local lifecycle.
    // Chromium opens on the first governed browser call or checkout.
    let (browser_local, pod_browser_opener) = match browser_config {
        Some(config) => {
            let mut prepared = config
                .prepare(
                    registry,
                    Arc::clone(&bridge_ledger),
                    Arc::clone(&read_model),
                    Arc::clone(&streams),
                    Arc::clone(&published),
                    Arc::clone(&external_content),
                )
                .map_err(|error| format!("could not compose browser runtime: {error:?}"))?;
            prepared.set_owner_preview(owner_preview_ids.clone());
            let pods = prepared.pods.clone();
            (Some(prepared.local_browser()), Some(pods))
        }
        None => (None, None),
    };
    if browser_local.is_none() {
        return Err("enabled browser capabilities require the BrowserArm runtime".to_owned());
    }
    // Route both authority and in-pod browsers by session id.
    let browser_routes = Arc::new(odin_cli::browser_runtime::BrowserRoutes::new(
        browser_local.clone(),
        pod_browser_opener,
    ));
    let concrete_browser: Arc<dyn BrowserCapabilityOwner> = browser_routes.clone();
    let canonical_v2_owner: Arc<dyn odin_omp::host_tools::CanonicalV2CapabilityOwner> =
        Arc::clone(&session_capsule_authority) as _;
    // A weak pool handle lets child stops retire backends without creating an Arc cycle.
    let pool_cell: Arc<
        std::sync::OnceLock<std::sync::Weak<crate::live_authority::SessionAuthorityPool>>,
    > = Arc::new(std::sync::OnceLock::new());
    if pool_cell
        .set(Arc::downgrade(&session_capsule_authority))
        .is_err()
    {
        return Err("session authority pool cell was already populated".into());
    }
    // Real governed delegation composition. The provisioner and lifecycle
    // control hold only Weak cells (live supervisor, session authority pool);
    // the durable link ledger is also passed to the factory so every child
    // build/reopen reconstructs the actual persisted parent chain.
    let supervisor_cell: Arc<std::sync::OnceLock<std::sync::Weak<LiveSupervisor>>> =
        Arc::new(std::sync::OnceLock::new());
    let task_slot = Arc::new(TaskOwnerSlot::new());
    let task_owner = match &config.delegation {
        Some(delegation) => {
            let max_prompt_bytes =
                usize::try_from(delegation.max_prompt_bytes.get()).map_err(|error| {
                    format!(
                        "delegation prompt ceiling {} does not fit usize: {error}",
                        delegation.max_prompt_bytes
                    )
                })?;
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
                        registry: Some(std::sync::Arc::clone(&snapshot_handle)),
                    },
                )
                .with_learning(None),
            ))
        }
        None => None,
    };
    let hermes::HermesComposition {
        route: hermes_route,
        ledger_path: conversation_ledger_path,
        runtime: hermes_runtime,
    } = hermes::compose(
        &config,
        hermes::ConversationAuthority {
            registry,
            contracts: &operation_contracts,
            seat_bindings: &seat_bindings,
            session_lanes: &session_lanes,
            posture,
        },
        &task_owner,
        &bridge_ledger,
    )?;
    // The gateway intake governs against the daemon's LIVE seat authority:
    // the same provisioned tokens and durable revocation/stop rows the
    // dispatch path verifies against. Unbound, external intake refuses
    // closed — a disconnected integration, never a permissive one.
    // The owner's task grants: one ledger the operation stack decides
    // covered calls against and `task.grant` records into.
    let task_grants = Arc::new(odin_omp::host_tools::task_grants::TaskGrantStore::open(
        config.paths.state_root.join("task-grants.json"),
    ));
    let declared_gateway = config
        .hermes
        .as_ref()
        .and_then(|hermes| hermes.model_gateway.clone());
    if let Some(runtime) = &hermes_runtime {
        runtime.set_task_grants(Arc::clone(&task_grants));
        runtime.set_compute_usage_root(config.paths.state_root.join("huginn"));
        if let Some(gateway) = declared_gateway.clone() {
            runtime.set_model_gateway(gateway);
        }
    }
    hermes::bind_authorities(
        &hermes_runtime,
        &browser_local,
        &config,
        &bridge_ledger,
        posture,
        &seat_bindings,
        &snapshot_handle,
    )?;
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
        odin_hermes::runtime::set_out_notice(incident_desk.out_notice());
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
    let (hermes_tools, hermes_internal_bindings) = match &hermes_runtime {
        Some(runtime) => (
            odin_hermes::runtime::hermes_host_tools(runtime),
            odin_hermes::runtime::hermes_capability_bindings(runtime),
        ),
        None => (Vec::new(), Vec::new()),
    };
    // Without delegation configuration, task handlers remain unbound and refuse invocation.
    let runtime_task_slot = (task_owner.is_some()
        || operation_contracts
            .keys()
            .any(|id| matches!(id.as_str(), "task.create" | "task.read")))
    .then(|| Arc::clone(&task_slot));
    let conversation_guidance = odin_omp::live::runtime::declared_conversation_guidance(registry)?;
    let tool_result_budgets = odin_omp::live::runtime::declared_tool_result_budgets(
        registry,
        seat_bindings
            .iter()
            .map(|binding| (&binding.seat_id, &binding.slice_id)),
    )?;
    let seat_sandboxes = odin_omp::live::runtime::declared_seat_sandboxes(registry)?;
    // A seat's file roots on this host, bound read-only into its bubble so `read` works on them.
    let seat_read_roots = seat_roots::declared(registry, &file_roots, node_identity.node());
    let project_spheres = spheres::declared_project_spheres(registry)?;
    let sandbox_host = odin_omp::process::sandbox_host_from_env()?;
    let seat_memory_max = odin_omp::live::runtime::declared_seat_memory_max(registry);
    let operation_clock = odin_omp::host_tools::operations::wall_clock();
    let offload = offload_binding::compose(&config, &manifest, &huginn_root, &snapshot_handle)?;
    let kube_coordinator = kube_coordinator::compose(
        &config,
        &manifest,
        &snapshot_handle,
        &kube_cell,
        &offload,
        kube_coordinator::LaunchEnvironment {
            models_file: sandbox_host.models_file.clone(),
            conversation_seats: &conversation_seats,
            local_node: node_identity.node(),
        },
    )?;
    let launch_coordinator = Arc::clone(&kube_coordinator);
    kube_coordinator
        .arm_workload_port(workload_port)
        .map_err(|error| error.to_string())?;
    // The kube-admitted remote carrier of workload sessions: resolves the
    // exact pod exec channel of each binding's operation. Unconfigured kube
    // composes `None`, and workload sessions then refuse typed.
    let pod_exec = odin_omp::host_tools::pod_exec::PodExecBinding {
        specs: odin_cli::runtime_bindings::pod_exec_specs(registry),
        pods: Arc::default(),
        exec: Arc::new(crate::kube::KubePodWorkerExec::new(kube_cell.clone())),
        web_save: config.executables.web_save.clone(),
        research: crate::adapter::research_exit(&config),
    };
    let run_stats_pods = Arc::clone(&pod_exec.pods);
    let run_stats_exec = Arc::clone(&pod_exec.exec);
    let (seed_findings, seed_findings_rx) = tokio::sync::mpsc::unbounded_channel();
    let workload_carrier = kube_cell.as_ref().map(|cell| {
        Arc::new(crate::kube::KubeWorkloadCarrier::new(
            Arc::clone(cell),
            config.executables.omp_revision.clone(),
            Arc::clone(&browser_routes),
            browser_profiles.clone(),
            Arc::clone(&pod_exec.pods),
            seed_recon::ReconCarriage {
                plans: odin_cli::runtime_bindings::recon_plans(registry)
                    .into_iter()
                    .map(|(profile, plan)| (profile, with_pool(plan, &config)))
                    .collect(),
                exec: Arc::clone(&pod_exec.exec),
                findings: seed_findings,
            },
        )) as Arc<dyn odin_omp::live::runtime::WorkloadCarrierPort>
    });
    let workflows = crate::workflows::binding(
        &config,
        &manifest,
        hermes_runtime.as_ref(),
        &incident_desk,
        &read_model,
    )?;
    let workload_drafts = Some(Arc::new(
        odin_omp::host_tools::WorkloadDraftStore::seal(&config.paths.state_root)
            .map_err(|error| error.to_string())?,
    ));
    let production_factory = Arc::new(
        ProductionBridgeRuntimeFactory::new(
            ProductionBridgeRuntimeConfig {
                tool_result_budgets,
                workload_drafts,
                task_grants: Some(Arc::clone(&task_grants)),
                approved_calls: hermes_runtime
                    .as_ref()
                    .map(|runtime| runtime.approved_calls()),
                root_plan_consent: hermes_runtime.as_ref().map(|_| {
                    let ledger = Arc::clone(&bridge_ledger);
                    Arc::new(
                        move |run: &odin_domain::RunId,
                              session: &odin_domain::SessionId,
                              seat: &str,
                              revision: i64,
                              objective: &str| {
                            ledger
                                .lock()
                                .map_err(|error| format!("root consent ledger lock: {error}"))?
                                .request_root_plan_consent(
                                    run,
                                    session,
                                    seat,
                                    revision,
                                    objective,
                                    time::OffsetDateTime::now_utc(),
                                )
                                .map(|_| ())
                                .map_err(|error| format!("root consent request: {error}"))
                        },
                    ) as odin_omp::host_tools::operations::RootPlanConsent
                }),
                // Sinmara's slow calls run as jobs whose outcomes wake her.
                jobs: hermes_runtime
                    .as_ref()
                    .and_then(|runtime| runtime.job_board()),
                delivery_acknowledger: hermes_runtime.as_ref().map(|runtime| {
                    let runtime = Arc::clone(runtime);
                    Arc::new(move |result: &serde_json::Value| {
                        runtime.acknowledge_inline_delegation(result)
                    })
                        as Arc<dyn Fn(&serde_json::Value) -> Result<(), String> + Send + Sync>
                }),
                // Contracts and admission revision come from the same pinned snapshot.
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
                card_windows,
                workload_sessions,
                workload_carrier,
                conversation_guidance,
                toolsets: odin_registry::toolsets::declared_toolsets(registry),
                deferred_toolsets: odin_registry::toolsets::declared_deferrals(registry),
                session_capsule_authority: Arc::clone(&session_capsule_authority)
                    as Arc<dyn odin_omp::live::runtime::SessionCapsuleAuthority>,
                process,
                worker: omp_worker,
                bridge_ledger: Arc::clone(&bridge_ledger),
                live_ledger: Arc::clone(&live_ledger),
                atlas: Arc::clone(&atlas),
                allowed_atlas_scope,
                brain_policies,
                brain_sources: brain_source_set,
                // Unpublished embedding routes stay unavailable. Each session's lease names
                // its requesting lane, not the gateway route lane. The acceptance gate is
                // a runtime dependency, never serialized configuration.
                brain_embedding: brain_embedding
                    .as_ref()
                    .map(|binding| binding.executor.clone() as Arc<dyn LaneEmbeddingProvider>),
                brain_embedding_model: brain_embedding
                    .as_ref()
                    .map(|binding| binding.model.clone()),
                brain_postgres,
                brain_rerank: config
                    .brain
                    .as_ref()
                    .and_then(|brain| brain.rerank.as_ref())
                    .map(|rerank| odin_brain::retrieval::rerank::Reranker {
                        address: rerank.address,
                        candidates: usize::from(rerank.candidates.get()),
                    }),
                artifact_root: huginn_root.join("artifacts"),
                promotion_verifier: {
                    let _verifier: Option<ValueValidator> = None;
                    _verifier
                },
                campaign_validator: Some(Arc::new(|input| {
                    odin_ledger::campaign::validate_approval(input)
                        .map_err(|error| error.to_string())
                })),
                spend_validator: Some(Arc::new(|project, input| {
                    rental_approval(project, input, "pending")?.validate()
                })),
                campaign_recorder: Some({
                    let state_root = config.paths.state_root.clone();
                    Arc::new(move |input, result| {
                        if result.get("isError").and_then(serde_json::Value::as_bool) == Some(true)
                        {
                            return Err("campaign approval returned an MCP error".to_owned());
                        }
                        let campaign_id = result
                            .get("structuredContent")
                            .and_then(|content| content.get("campaign_id"))
                            .and_then(serde_json::Value::as_str)
                            .filter(|id| !id.is_empty())
                            .ok_or_else(|| {
                                "campaign approval returned no structured campaign_id".to_owned()
                            })?;
                        odin_ledger::campaign::record_approval(&state_root, campaign_id, input)
                            .map_err(|error| error.to_string())
                    })
                }),
                spend_recorder: Some({
                    let huginn_root = huginn_root.clone();
                    Arc::new(
                        move |project: &str,
                              input: &serde_json::Value,
                              result: &serde_json::Value| {
                            if result.get("isError").and_then(serde_json::Value::as_bool)
                                == Some(true)
                            {
                                return Err("spend approval returned an MCP error".to_owned());
                            }
                            let id = result
                                .get("structuredContent")
                                .and_then(|content| content.get("spend_id"))
                                .and_then(serde_json::Value::as_str)
                                .filter(|id| !id.is_empty())
                                .ok_or_else(|| {
                                    "spend approval returned no structured spend_id".to_owned()
                                })?;
                            odin_registry::RentalApprovals::record(
                                &huginn_root,
                                rental_approval(project, input, id)?,
                            )
                        },
                    )
                }),
                context_trace_root: Some(odin_omp::live::context_trace::root(
                    &config.paths.state_root,
                )),
                project_roots,
                session_lanes,
                context_read,
                device_run: Some(spheres::device_binding(
                    &snapshot_handle,
                    &config.paths.state_root,
                    &manifest,
                    Arc::clone(&session_capsule_authority),
                )),
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
                // Photos the owner sends ride his turn as image blocks.
                turn_images: hermes_runtime.as_ref().map(|runtime| {
                    Arc::new(odin_hermes::runtime::IntakeImages::new(
                        &runtime.settings().state_dir,
                    )) as Arc<dyn odin_omp::live::control::TurnImages>
                }),
                seat_sandboxes,
                seat_read_roots,
                project_spheres,
                seat_memory_max,
                sandbox_host: Some(sandbox_host),
            },
            concrete_browser,
            canonical_v2_owner,
            kube_coordinator,
            pod_exec,
            workflows,
        )
        .map_err(|error| error.to_string())?,
    );
    if let Some(runtime) = &hermes_runtime {
        brain_bindings::bind_hermes_brains(runtime, &production_factory, &live_ledger)?;
    }
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
    let (launcher, mcp_bridge) = harness_launch::compose(harness_launch::HarnessLaunchInputs {
        config: &config,
        launcher,
        production_factory: &production_factory,
        incident_desk: &incident_desk,
        stops: terminal_stops,
        supervisor: Arc::clone(&supervisor_cell),
        pool: Arc::clone(&pool_cell),
        stopping: stop_rx,
        bwrap: manifest
            .executable("bwrap")
            .ok()
            .map(|binding| binding.path.clone()),
    })
    .await?;
    let supervisor = LiveSupervisor::discover(
        Arc::clone(&live_ledger),
        launcher,
        limits.sessions.max_sessions.get(),
        task_owner.as_ref().map(|owner| {
            Arc::clone(owner) as Arc<dyn odin_omp::host_tools::delegation::CompletionEventObserver>
        }),
    )
    .await
    .map_err(|error| error.to_string())?;
    for binding in seat_bindings {
        supervisor
            .bind(binding)
            .await
            .map_err(|error| error.to_string())?;
    }
    if posture == NodePosture::Authoritative {
        let conversation_state = hermes_runtime
            .as_ref()
            .map(|runtime| runtime.settings().state_dir.clone());
        settle::settle_stale_sessions(&supervisor, &bridge_ledger, conversation_state.as_deref())
            .await;
        settle::remove_ended_capsules(
            &supervisor,
            odin_omp::live::capsules::SessionRoots {
                state_root: config.paths.state_root.clone(),
                huginn_root: huginn_root.clone(),
            },
            conversation_state.as_deref(),
        );
    }
    if workload_supervisor.set(Arc::clone(&supervisor)).is_err() {
        return Err("workload supervisor slot was already armed".into());
    }
    // The real supervisor identity exists only now: publish it through the
    // Weak cell (provisioner and child control upgrade it per call, never
    // pinning it) and bind the concrete owner exactly once before listen.
    if supervisor_cell.set(Arc::downgrade(&supervisor)).is_err() {
        return Err("live supervisor cell was already populated".into());
    }
    if let Some(owner) = &task_owner {
        let bound_owner: Arc<dyn TaskOwner> = owner.clone();
        task_slot
            .bind(bound_owner)
            .map_err(|error| format!("could not bind task owner: {error}"))?;
    }
    let (lane_artifacts, transfers) = transfers::compose(
        &huginn_root,
        &config.paths.state_root,
        &live_ledger,
        posture,
        transfer_lanes,
    )?;
    let omp = Arc::new(odin_omp::live::service::OmpLiveService::new(
        Arc::clone(&live_ledger),
        Arc::clone(&supervisor),
        transfers,
    ));
    odin_omp::live::service::OmpLiveService::install_live(&omp);
    omp.set_delegation_links(delegation_links.clone());
    supervisor.set_fresh_handoff(production_factory.clone());
    supervisor.set_delegation_links(delegation_links.clone());
    omp.set_fresh_handoff(production_factory.clone());
    // A handoff that cannot finish (its successor holds no seat token) is
    // journaled, not fatal: the daemon serves everything else and retries it
    // at the next start.
    if let Err(error) = supervisor.resume_pending_handoffs().await {
        tracing::error!("odind: pending fresh handoff did not resume: {error}");
    }
    for (seat, config) in &rollover_seats {
        supervisor.set_heartbeat_interval(seat, config.policy().heartbeat());
        supervisor.set_heartbeat_when(seat, config.policy().heartbeat_when);
    }
    let conversation_root: Option<hermes_routes::VehicleRouteBinding> =
        hermes_routes::bind(hermes_routes::HermesBind {
            hermes_runtime: &hermes_runtime,
            hermes_route,
            omp: &omp,
            supervisor: &supervisor,
            config: &config,
            manifest: &manifest,
            conversation_ledger_path: &conversation_ledger_path,
            pin: &snapshot_handle,
            read_model: &read_model,
            kube_cell: &kube_cell,
            rollover_seats: &rollover_seats,
            delegation_links: &delegation_links,
            incidents: Some(&incident_desk),
            operation_store: Arc::clone(&bridge_ledger),
            operation_clock,
            session_capsule_authority: &session_capsule_authority,
            gateway: gateway.as_ref().ok(),
        })
        .await?;
    let live_plane: Arc<dyn live::OmpLivePlane> = omp.clone();
    bind_run_stats(
        hermes_runtime.as_ref(),
        Arc::clone(&omp),
        declared_gateway.clone(),
        run_stats_pods,
        run_stats_exec,
    );
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
    serving::ensure_feeds_dir(&huginn_root)?;
    let durable_feed_pump = Arc::new(odin_huginn::feed::DurableFeedPump::new(
        odin_huginn::feed::DurableFeedPumpInput {
            posture,
            plane: Arc::clone(&live_plane),
            ledger: Arc::clone(&bridge_ledger),
            discovery: Arc::new(session_discovery::LiveLedgerSessionDiscovery {
                ledger: Arc::clone(&live_ledger),
            }),
            discovery_cursor_path: Some(huginn_root.join("feeds").join("change-cursor")),
            read_model: Arc::clone(&read_model),
            roster_feed: Arc::new(odin_huginn::feed::RosterFeed::new(Arc::clone(
                &session_projection_store,
            ))),
            event_feed: Arc::new(tokio::sync::Mutex::new(
                odin_huginn::feed::SessionEventFeed::new(
                    Arc::clone(&streams),
                    Arc::clone(&published),
                    huginn_conformance::stream_backpressure_limits(&limits)?,
                    u64::try_from(limits.streams.max_stream_frame_bytes.get())
                        .map_err(|error| format!("stream frame limit does not fit u64: {error}"))?,
                ),
            )),
            approval_feed: odin_huginn::feed::ApprovalFeed::new(),
            history_page: limits.sessions.max_history_page,
            discovery_page: limits.sessions.max_sessions.get(),
        },
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
    // The authority pump feeds missions from simulation profile runs.
    let simulation_desk = match (&kube_cell, posture) {
        (Some(_), NodePosture::Authoritative) => {
            Some(Arc::new(crate::simulation::SimulationDesk::new(
                Arc::clone(&read_model),
                Arc::clone(&streams),
                huginn_conformance::stream_backpressure_limits(&limits)?,
                Arc::clone(&bridge_ledger),
                Arc::clone(&published),
            )?))
        }
        _ => None,
    };
    supervisor.set_heartbeat_watched(Arc::new(crate::incidents::HeartbeatWatch {
        read_model: Arc::clone(&read_model),
        incidents: Arc::clone(&incident_desk),
        tasks: Arc::clone(&task_state_reader),
        registry: Arc::clone(&snapshot_handle),
        simulation: simulation_desk.clone(),
    }));
    if let (Some(desk), Some(cell), Some(runtime)) = (&simulation_desk, &kube_cell, &hermes_runtime)
    {
        runtime.set_simulation_route(Arc::new(crate::simulation::DaemonSimulationRoute {
            desk: Arc::clone(desk),
            cell: Arc::clone(cell),
            handle: tokio::runtime::Handle::current(),
        }));
    }
    // Device-bound session authority: mint where the key lives, claim, open.
    let device_open = Arc::new(crate::device_open::DeviceOpenAuthority::new(
        config.clone(),
        Arc::clone(&devices),
        Arc::clone(&bridge_ledger),
        Arc::clone(&live_plane),
    ));
    let device_open_stop = device_open.stop_handle();
    let (features_refresh, features_trigger) = crate::features::refresh_pair();
    let node_yield = Arc::new(crate::node_modes::NodeYieldSlot::default());
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
        .with_recovery(Arc::clone(&production_factory))
        .with_live(Arc::clone(&live_plane))
        .with_device_open(Some(device_open))
        .with_simulation(simulation_desk.clone())
        .with_features(features_refresh)
        .with_project_events(crate::project_event::intake(
            &devices,
            hermes_runtime.as_ref(),
        ))
        .with_owner_preview(owner_preview_ids)
        .with_gateway(declared_gateway.clone())
        .with_claude_runtime(hermes_runtime.clone())
        .with_catalog(Some(Arc::new(crate::model_catalog::ModelCatalog::new(
            config.executables.omp_bin.clone(),
            config.models.lanes.clone(),
            crate::model_catalog::family_card(registry),
        ))))
        .with_compute(
            Arc::clone(&snapshot_handle),
            node_identity.node().to_owned(),
            manifest
                .executable("ssh")
                .map_err(|error| format!("runtime manifest ssh: {error}"))?
                .path
                .clone(),
        ),
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
        exchange_timeout: odin_cli::authority_provision::ADMIN_EXCHANGE_TIMEOUT,
    };
    let shutdown_connections = connections.clone();
    let render_activity = Arc::clone(&renders);
    let expiring_streams = Arc::clone(&streams);
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
    let router = service.mount();
    let listen_address = config.listener.address;
    let listener = tokio::net::TcpListener::bind(listen_address)
        .await
        .map_err(|error| format!("Huginn could not listen on {listen_address}: {error}"))?;
    tracing::info!("odind ready in {} ms", launched.elapsed().as_millis());
    brain_bindings::prune_retired_brain_stores(posture, &production_factory);

    let mut pumps = tokio::task::JoinSet::new();
    // The knowledge index builds on the blocking pool. A failed build still ends the daemon through
    // the serving select; a built index parks this pump, so its completion never ends the daemon.
    let atlas_build = Arc::clone(&atlas);
    pumps.spawn(async move {
        let built = tokio::task::spawn_blocking(move || odin_atlas::build(atlas_sources))
            .await
            .map_err(|error| format!("Atlas build did not finish: {error}"))?
            .map_err(|error| format!("could not build Atlas for live sessions: {error}"))?;
        let _ = atlas_build.set(Arc::new(built));
        std::future::pending::<Result<(), String>>().await
    });
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
    let owner_brains = production_factory.brains().clone();
    let fleet_ssh = manifest
        .executable("ssh")
        .map_err(|error| format!("runtime manifest ssh: {error}"))?
        .path
        .clone();
    let pump_setup =
        arm_egress_lane_pumps(&mut pumps, &lane_artifacts, &omp, egress_lanes, posture)
            .await
            .map(|()| {
                pump_arming::arm_pumps(
                    &mut pumps,
                    pump_arming::PumpInputs {
                        seed_findings: seed_findings_rx,
                        config,
                        posture,
                        hermes_runtime: hermes_runtime.clone(),
                        kube_cell,
                        launch_coordinator,
                        read_model,
                        snapshot_handle,
                        fleet_ssh,
                        local_node: node_identity.node().to_owned(),
                        declared_gateway,
                        features_trigger,
                        durable_feed_pump,
                        device_activity,
                        device_admin,
                        bridge_ledger,
                        render_activity,
                        expiring_streams,
                        brain_warm_targets,
                        incident_desk,
                        simulation_desk,
                        offload,
                        omp,
                        conversation_seats,
                        conversation_ledger_path,
                        task_owner,
                        session_capsule_authority: Arc::clone(&session_capsule_authority),
                        state_heads,
                        state_rebuild_brains,
                        owner_brains,
                    },
                )
            });
    // An ordinary stop owns no capture and reads no root backup state: the
    // one serving grace begins when the owned shutdown starts below.
    let signal_stop = serving::arm_stop_signal()?;
    // Start capsule supervision only after fallible composition. Serving owns and joins
    // retirement; owner-drop also signals it. The local browser ends idle/dead-page sessions.
    let browser_capsule = browser_local.map(|local| {
        (
            std::future::pending::<Result<(), odin_huginn::browser::BrowserProjectionError>>(),
            move || Box::pin(async move { local.retire().await }),
        )
    });
    // A pump-arming failure routes through the SAME orchestration: the
    // capsule ladder always runs, and the original setup error is
    // preserved verbatim as the daemon result — never mislabeled as a
    // Huginn serving failure.
    let (result, accounting) = orchestrate_serving(
        pump_setup.map(|()| async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
        }),
        pumps,
        signal_stop,
        browser_capsule,
        serving::ServingShutdown::own(
            stop_tx,
            shutdown_connections,
            mcp_bridge.listeners,
            mcp_bridge.dispatches,
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
