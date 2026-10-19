//! Served-seat policy composition and read-model projection: the shared
//! Atlas scope, the per-seat effective brain policies and their declared
//! sources, the snapshot-resolved embedding route, and the
//! registry/file-root/status seeding of the materialized read model.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use odin_brain::retrieval::embedding::{KernelEmbeddingExecutor, PrivateGatewayTransport};
use odin_domain::huginn as live;
use odin_domain::knowledge::EmbeddingModelId;
use odin_domain::{Digest, LaneId, ProviderId};
use odin_huginn::OdindConfig;
use odin_kernel::provider::{ProviderCoordinatorTemplate, ProviderLeaseCoordinator};
use odin_ledger::Ledger;
use odin_registry::{
    resolve_provider_policy, EmbeddingProtocolToml, GatewayProjectionManifest, ObjectConfig,
    ProviderPolicyError, RegistryKind, RegistryObject, ResolvedProviderRoute, Snapshot,
    SnapshotHandle, SnapshotStore,
};
use time::OffsetDateTime;

/// Re-adopts registry-derived bindings without retaining an earlier publication's bindings.
pub(super) fn future_brain_config(
    config: &OdindConfig,
    registry: &[RegistryObject],
) -> OdindConfig {
    let mut candidate = config.clone();
    candidate.projects.retain(|_, project| !project.runtime);
    candidate.seats.retain(|seat| !seat.runtime);
    candidate.lane_bindings.retain(|lane| !lane.runtime);
    if let Some(root) = candidate
        .paths
        .authoring_repository
        .as_ref()
        .and_then(|repository| repository.parent())
        .map(Path::to_path_buf)
    {
        candidate.adopt_projects_from(&root, registry);
    }
    candidate
}

/// The final publication candidate must resolve under the bindings its reload will adopt.
pub(super) fn admit_brain_policies(
    config: &OdindConfig,
    registry_revision: u64,
    registry: &[RegistryObject],
    previous_registry: &[RegistryObject],
) -> Result<(), String> {
    let candidate = future_brain_config(config, registry);
    for object in registry {
        let ObjectConfig::Seat(seat) = &object.config else {
            continue;
        };
        if seat.enabled
            && !previous_registry
                .iter()
                .any(|previous| previous.kind() == RegistryKind::Seat && previous.id == object.id)
            && !candidate
                .seats
                .iter()
                .any(|binding| binding.seat.as_str() == object.id)
        {
            return Err(format!(
                "new seat {} has no future runtime binding",
                object.id
            ));
        }
    }
    bound_brain_policies(
        &candidate,
        registry_revision,
        registry,
        candidate
            .seats
            .iter()
            .map(|binding| (&binding.seat, &binding.slice)),
    )?;
    Ok(())
}

/// The factory is shared by all served seats, so its immutable Atlas grant is
/// the safe intersection of their validated category grants. `*` is universal
/// rather than a literal category; disjoint seats receive only untagged
/// globally visible nodes, never a union that one seat could abuse.
pub(super) fn shared_seat_atlas_scope(
    registry: &[RegistryObject],
    seat_bindings: &[odin_omp::live::supervisor::LiveSeatBinding],
) -> Result<odin_atlas::AtlasScope, String> {
    let mut common: Option<BTreeSet<String>> = None;
    for binding in seat_bindings {
        let object = registry
            .iter()
            .find(|object| {
                object.kind() == RegistryKind::Seat && object.id == binding.seat_id.as_str()
            })
            .ok_or_else(|| format!("seat {} is absent from the registry", binding.seat_id))?;
        let ObjectConfig::Seat(seat) = &object.config else {
            return Err(format!("registry object {} is not a seat", binding.seat_id));
        };
        if !seat.enabled {
            return Err(format!("served seat {} is disabled", binding.seat_id));
        }
        common = Some(match common.take() {
            None => seat.categories.clone(),
            Some(current) if current.contains("*") => seat.categories.clone(),
            Some(current) if seat.categories.contains("*") => current,
            Some(current) => current.intersection(&seat.categories).cloned().collect(),
        });
    }
    let categories =
        common.ok_or_else(|| "at least one served seat is required for Atlas scope".to_owned())?;
    odin_atlas::AtlasScope::seat(categories)
        .map_err(|error| format!("served seat Atlas scope is invalid: {error}"))
}

/// A declared brain context tokenizer identity, or the exact-byte default
/// when none is declared; an unsupported identity fails instead of
/// downgrading to an approximation.
fn declared_tokenizer(
    raw: Option<&str>,
    field: &str,
) -> Result<odin_domain::knowledge::ids::TokenizerId, String> {
    let Some(raw) = raw else {
        return odin_brain::context::PinnedTokenizer::id()
            .map_err(|error| format!("default brain tokenizer id is invalid: {error}"));
    };
    let declared = odin_domain::knowledge::ids::TokenizerId::new(raw)
        .map_err(|error| format!("{field} {raw:?} is not a valid tokenizer identity: {error}"))?;
    odin_brain::context::ContextTokenizer::for_id(&declared).map_err(|error| {
        format!("{field} {raw:?} is not a supported brain context tokenizer: {error}")
    })?;
    Ok(declared)
}

/// The declared context window of every served seat's launch options: the
/// serving model's window and tokenizer from its resolved brain policy, and
/// every other lane's window and tokenizer from `brain.lane_windows` (byte
/// counted when it declares none). A launch option with neither runs
/// unguarded; a declared switch to it is refused by the session's control
/// seam.
pub(super) fn served_lane_windows(
    config: &OdindConfig,
    brain_policies: &BTreeMap<odin_domain::SeatId, odin_brain::config::EffectiveBrainPolicy>,
    seat_bindings: &[odin_omp::live::supervisor::LiveSeatBinding],
) -> Result<BTreeMap<odin_domain::SeatId, Vec<odin_omp::live::runtime::LaneWindow>>, String> {
    let Some(brain) = config.brain.as_ref() else {
        return Ok(BTreeMap::new());
    };
    let mut windows = BTreeMap::new();
    for binding in seat_bindings {
        let Some(policy) = brain_policies.get(&binding.seat_id) else {
            continue;
        };
        let mut lanes = Vec::new();
        for option in &binding.launch_options {
            let model = option.model.as_str();
            let (window, tokenizer) = if model == policy.model.name.as_str() {
                (
                    policy.model.context_window_tokens,
                    policy.model.tokenizer.clone(),
                )
            } else {
                let Some(declared) = brain.lane_windows.get(model) else {
                    continue;
                };
                (
                    declared.window(),
                    declared_tokenizer(
                        declared.tokenizer(),
                        &format!("brain.lane_windows.{model}.tokenizer"),
                    )?,
                )
            };
            lanes.push(odin_omp::live::runtime::LaneWindow {
                provider: option.provider.as_str().to_owned(),
                model: model.to_owned(),
                window,
                tokenizer,
            });
        }
        windows.insert(binding.seat_id.clone(), lanes);
    }
    Ok(windows)
}

/// Every served seat resolves its OWN effective brain policy from the
/// pinned published snapshot (project memory declarations, slice
/// delegation, seat restriction, serving model) bound to the pinned
/// registry revision. Seats intentionally serve
/// different knowledge scopes — personal vaults or code atlases — so
/// policies are composed per seat and never converged,
/// widened, or disabled: each seat keeps exactly its published allowed
/// source set, and cross-seat leakage stays structurally impossible because
/// each seat's brain service pins only its own authorized sources. Within a
/// seat, project memory composes only from each scoped project's explicit
/// `memory_namespaces`, so project A's memory never serves to project B
/// unless both projects declare the namespace as shared.
pub(super) fn served_brain_policies(
    config: &OdindConfig,
    registry_revision: u64,
    registry: &[RegistryObject],
    seat_bindings: &[odin_omp::live::supervisor::LiveSeatBinding],
) -> Result<BTreeMap<odin_domain::SeatId, odin_brain::config::EffectiveBrainPolicy>, String> {
    bound_brain_policies(
        config,
        registry_revision,
        registry,
        seat_bindings
            .iter()
            .map(|binding| (&binding.seat_id, &binding.slice_id)),
    )
}

/// Resolves the same policy for live bindings and not-yet-published bindings.
pub(super) fn bound_brain_policies<'a>(
    config: &OdindConfig,
    registry_revision: u64,
    registry: &[RegistryObject],
    seat_bindings: impl IntoIterator<Item = (&'a odin_domain::SeatId, &'a odin_domain::SliceId)>,
) -> Result<BTreeMap<odin_domain::SeatId, odin_brain::config::EffectiveBrainPolicy>, String> {
    // Absent operator brain section: the daemon composes no brain service
    // and no policy; brain operations stay typed-unavailable while every
    // unrelated session surface keeps serving.
    let Some(brain) = config.brain.as_ref() else {
        return Ok(BTreeMap::new());
    };
    // Every project declaration of the same pinned snapshot — disabled
    // projects included: a namespace some project declares as its memory is
    // project memory everywhere in the snapshot, so reservation reads all
    // declarations and never degrades a declared namespace to seat-general
    // for a seat whose scope does not reach the declaring project.
    // Scoped-but-disabled projects still refuse inside resolve() itself, so
    // admission strictness is unchanged.
    let projects: BTreeMap<&str, &odin_registry::schema::ProjectToml> = registry
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Project(project) => Some((object.id.as_str(), project.as_ref())),
            _ => None,
        })
        .collect();
    let mut policies = BTreeMap::new();
    for (seat_id, slice_id) in seat_bindings {
        let seat_object = registry
            .iter()
            .find(|object| object.kind() == RegistryKind::Seat && object.id == seat_id.as_str())
            .ok_or_else(|| format!("seat {seat_id} is absent from the registry"))?;
        let ObjectConfig::Seat(seat) = &seat_object.config else {
            return Err(format!("registry object {seat_id} is not a seat"));
        };
        if !seat.enabled {
            return Err(format!("served seat {seat_id} is disabled"));
        }
        let slice_object = registry
            .iter()
            .find(|object| object.kind() == RegistryKind::Slice && object.id == slice_id.as_str())
            .ok_or_else(|| {
                format!("slice {slice_id} served by seat {seat_id} is absent from the registry")
            })?;
        let ObjectConfig::Slice(slice) = &slice_object.config else {
            return Err(format!("registry object {slice_id} is not a slice"));
        };
        let model = seat_model_descriptor(&brain.serving_model, seat_id.as_str())?;
        let resolved = odin_brain::config::EffectiveBrainPolicy::resolve(
            registry_revision,
            slice,
            seat,
            &projects,
            &odin_registry::context_profiles(registry),
            &model,
        )
        .map_err(|error| format!("brain policy for served seat {seat_id} is invalid: {error}"))?;
        policies.insert(seat_id.clone(), resolved);
    }
    if policies.is_empty() {
        return Err("at least one served seat is required for the brain policy".to_owned());
    }
    Ok(policies)
}

/// The snapshot-resolved embedding binding served to every brain service:
/// the kernel-lease-governed executor factory and the exact embedding model
/// the resolved route executes under. Both compose together or neither
/// does — the BrainService open boundary refuses a partial binding. The
/// route's lane/model/account remain SELECTION POLICY: each session binds
/// its own requesting runtime lane through the executor factory, and the
/// kernel provider lease names that session lane, never the route lane.
pub(super) struct ServedEmbedding {
    pub executor: Arc<KernelEmbeddingExecutor>,
    pub model: EmbeddingModelId,
}

/// The composed embedding execution parts behind one [`ServedEmbedding`]:
/// the raw provider identity, lease coordinator, ledger, private transport,
/// and the resolved route's declared embedding protocol the archive
/// backfill lane drives one lease-governed batch at a time through the same
/// `embed` execution the brain's query executor uses. The lane owns these
/// parts; nothing else shares them (the coordinator is single-owner), so
/// backfill lease bindings never collide with retrieval bindings.
pub(super) struct ServedEmbeddingParts {
    pub(super) model: EmbeddingModelId,
    pub(super) provider: ProviderId,
    pub(super) coordinator: ProviderLeaseCoordinator,
    pub(super) ledger: Ledger,
    pub(super) transport: PrivateGatewayTransport,
    pub(super) protocol: Option<EmbeddingProtocolToml>,
}

/// The brain's PostgreSQL store when `[brain] postgres` declares one,
/// connected off the async workers.
pub(super) async fn served_brain_postgres(
    config: &OdindConfig,
) -> Result<Option<Arc<odin_brain::index::postgres::BrainPostgres>>, String> {
    let Some(conninfo) = config
        .brain
        .as_ref()
        .and_then(|brain| brain.postgres.clone())
    else {
        return Ok(None);
    };
    let opened = tokio::task::spawn_blocking(move || {
        odin_brain::index::postgres::BrainPostgres::connect(&conninfo)
    })
    .await
    .map_err(|error| format!("the brain postgres store did not open: {error}"))?
    .map_err(|error| format!("the brain postgres store did not open: {error}"))?;
    tracing::info!("brain store backend=postgres");
    Ok(Some(Arc::new(opened)))
}

/// Resolve embedding through the pinned gateway projection. Absent or ineligible
/// routes leave vector retrieval unavailable; missing declared pairs or invalid
/// projections refuse startup. Only gateway adapters bind an executor, and the
/// deployed gateway enforces provider spending caps.
pub(super) fn served_embedding(
    config: &OdindConfig,
    snapshot: &Snapshot,
) -> Result<Option<ServedEmbedding>, String> {
    compose_embedding(config, snapshot, &mut |name| std::env::var(name).ok())
}

/// Inject credential lookup without consulting undeclared environment variables.
fn compose_embedding(
    config: &OdindConfig,
    snapshot: &Snapshot,
    credential_environment: &mut dyn FnMut(&str) -> Option<String>,
) -> Result<Option<ServedEmbedding>, String> {
    let Some(parts) = compose_embedding_parts(config, snapshot, credential_environment)? else {
        return Ok(None);
    };
    // The executor is bound to exactly the provider this resolved policy
    // names: every lease binding it accepts must be that provider's, so the
    // declared identity governs instead of a compiled-in constant.
    let executor = Arc::new(KernelEmbeddingExecutor::new(
        parts.provider,
        parts.template,
        parts.ledger,
        parts.transport,
        parts.protocol,
    ));
    Ok(Some(ServedEmbedding {
        executor,
        model: parts.model,
    }))
}

/// The lane-independent composition of one declared embedding route: the
/// resolved model identity, provider identity, coordinator template,
/// ledger, and private transport. Lease lanes bind per consumer at
/// materialization (`for_lane`), never here — the projection route lane is
/// policy, never lease identity.
struct EmbeddingComposition {
    model: EmbeddingModelId,
    provider: ProviderId,
    template: Arc<ProviderCoordinatorTemplate>,
    ledger: Ledger,
    transport: PrivateGatewayTransport,
    protocol: Option<EmbeddingProtocolToml>,
}

/// The raw execution parts the archive backfill lane drives one
/// lease-governed batch at a time, composed under the process credential
/// environment exactly as [`served_embedding`] composes the serving
/// executor.
pub(super) fn served_embedding_parts(
    config: &OdindConfig,
    snapshot: &Snapshot,
    lease_lane: &LaneId,
    custody: &mut dyn FnMut(&str) -> Option<String>,
) -> Result<Option<ServedEmbeddingParts>, String> {
    let Some(parts) = compose_embedding_parts(config, snapshot, custody)? else {
        return Ok(None);
    };
    // Provider leases are ledger rows bound to a registered lane: the
    // backfill leases under the declared session lane of the seat it works
    // for (the gateway route's lane id has no ledger lane row). The
    // coordinator reuses that lane's active lease verbatim; its request ids
    // are its own.
    let coordinator = parts
        .template
        .for_lane(lease_lane.clone())
        .map_err(|error| format!("embedding backfill lane rejected: {error}"))?;
    Ok(Some(ServedEmbeddingParts {
        model: parts.model,
        provider: parts.provider,
        coordinator,
        ledger: parts.ledger,
        transport: parts.transport,
        protocol: parts.protocol,
    }))
}
/// Include the declared protocol id in the embedding model identity so protocol
/// changes invalidate index generations and fail serving/backfill identity checks.
pub(super) fn effective_embedding_model(
    route: &ResolvedProviderRoute,
) -> Result<EmbeddingModelId, String> {
    match route.protocol.as_ref() {
        Some(protocol) => {
            let effective = format!("{}:{}", route.gateway_model_id, protocol.id);
            EmbeddingModelId::new(effective.as_str()).map_err(|error| {
                format!(
                    "embedding route model {:?} under protocol {:?} is not a valid \
                     embedding model id: {error}",
                    route.gateway_model_id, protocol.id
                )
            })
        }
        None => EmbeddingModelId::new(route.gateway_model_id.as_str()).map_err(|error| {
            format!(
                "embedding route model {:?} is not a valid embedding model id: {error}",
                route.gateway_model_id
            )
        }),
    }
}

/// The composing body shared by the serving executor and the archive
/// backfill parts: the declared route resolved and validated once, with
/// everything lane-independent left to materialize per consumer.
fn compose_embedding_parts(
    config: &OdindConfig,
    snapshot: &Snapshot,
    credential_environment: &mut dyn FnMut(&str) -> Option<String>,
) -> Result<Option<EmbeddingComposition>, String> {
    let embedding = config
        .brain
        .as_ref()
        .and_then(|brain| brain.embedding.as_ref());
    let Some(embedding) = embedding else {
        return Ok(None);
    };
    let projection = load_gateway_projection(config)?;
    let provider_id = ProviderId::new(embedding.provider.clone())
        .map_err(|error| format!("brain.embedding.provider is invalid: {error}"))?;
    let policy = match resolve_provider_policy(snapshot, &provider_id, &projection) {
        Ok(policy) => policy,
        // Absent or disabled provider, or every declared route currently
        // ineligible in the pinned projection: the offline posture the
        // configuration promises — no binding, typed-unavailable retrieval,
        // never a downgrade. The startup line names the exact state.
        Err(
            error @ (ProviderPolicyError::ProviderUnavailable(_, _)
            | ProviderPolicyError::NoEligibleRoute(_)
            | ProviderPolicyError::NativeProvider { .. }),
        ) => {
            tracing::warn!(
                "brain.embedding provider {:?} has no eligible published route \
                 ({error}); vector and hybrid retrieval stay typed-unavailable",
                embedding.provider
            );
            return Ok(None);
        }
        // The provider declaration names a (lane, model) pair the pinned
        // projection never issued. The projection digest is pinned by this
        // same configuration, so the route cannot become eligible while this
        // configuration runs: the declaration is dead wiring, and startup
        // refuses instead of serving a brain that looks offline but is
        // really misdeclared.
        Err(error @ ProviderPolicyError::UnknownRoute { .. }) => {
            return Err(format!(
                "brain.embedding provider {:?} declares a route the pinned gateway \
                 projection does not carry: {error}",
                embedding.provider
            ));
        }
        Err(error) => return Err(error.to_string()),
    };
    // The executor executes under exactly one model identity and the brain
    // service pins that identity at open: a multi-route embedding provider
    // could rotate the lane lease onto a different model than the one the
    // service was opened with. The ambiguity is refused, never guessed.
    let [route] = policy.routes.as_slice() else {
        return Err(format!(
            "brain.embedding provider {:?} resolves {} eligible routes; the embedding \
             executor requires exactly one",
            embedding.provider,
            policy.routes.len()
        ));
    };
    let model = effective_embedding_model(route)?;
    // Validate the declared credential source before constructing transport.
    let credential = crate::credentials::resolve_gateway_credential(
        &config.gateway_host_credentials,
        &route.credential_handle,
        credential_environment,
    )
    .map_err(|error| error.to_string())?;
    let bearer =
        odin_brain::retrieval::embedding::GatewayBearer::new(credential).map_err(|error| {
            format!(
                "gateway credential for handle {:?} is not a valid bearer: {error}",
                route.credential_handle
            )
        })?;
    let transport = PrivateGatewayTransport::with_bearer(&embedding.endpoint, bearer)
        .map_err(|error| format!("embedding endpoint rejected: {error}"))?;
    // The lane-independent coordinator template: the route selects the
    // provider candidate set, while the kernel lease lane is bound per
    // requesting session at runtime — the projection route lane is policy,
    // never lease identity.
    let template =
        ProviderCoordinatorTemplate::from_resolved_policy(&snapshot.objects, None, &policy)
            .map_err(|error| format!("embedding provider lease rejected: {error}"))?;
    let ledger = Ledger::open(config.paths.state_root.join("ledger.sqlite3"))
        .map_err(|error| format!("could not open the embedding provider ledger: {error}"))?;
    materialize_declared_lanes(&ledger, &config.lane_bindings)?;
    Ok(Some(EmbeddingComposition {
        model,
        provider: policy.provider_id.clone(),
        template: Arc::new(template),
        ledger,
        transport,
        protocol: route.protocol.clone(),
    }))
}

/// Materializes every declared lane binding as its live-session ledger row.
/// Provider leases name their lane by foreign key, and a lane otherwise gets
/// its row only when a session first opens on it: a seat warming or
/// backfilling through a lane no session has used yet would fail the key.
pub(super) fn materialize_declared_lanes(
    ledger: &Ledger,
    bindings: &[odin_huginn::OdindLaneBinding],
) -> Result<(), String> {
    for binding in bindings {
        odin_ledger::lane_run::ensure_lane(
            ledger.connection(),
            &odin_omp::live::runtime::live_session_lane(
                binding.lane.clone(),
                binding.seat.clone(),
                binding.project.clone(),
            ),
        )
        .map_err(|error| format!("declared lane {} is unusable: {error}", binding.lane))?;
    }
    Ok(())
}

/// A route catalog should not require a data-sized read.
const MAX_GATEWAY_PROJECTION_BYTES: usize = 1024 * 1024;

/// Read within the size limit, verify the configured digest, and validate the projection.
pub(super) fn load_gateway_projection(
    config: &OdindConfig,
) -> Result<GatewayProjectionManifest, String> {
    let reference = &config.catalogs.gateway_projection;
    let bytes =
        read_bounded_file(&reference.path, MAX_GATEWAY_PROJECTION_BYTES).map_err(|error| {
            format!(
                "gateway projection {} is unreadable: {error}",
                reference.path.display()
            )
        })?;
    let digest = Digest::hash(&bytes).to_string();
    if digest != reference.digest {
        return Err(format!(
            "gateway projection {} digests to {digest}, config declares {}",
            reference.path.display(),
            reference.digest
        ));
    }
    let projection: GatewayProjectionManifest = serde_json::from_slice(&bytes)
        .map_err(|error| format!("gateway projection is malformed: {error}"))?;
    projection
        .verify()
        .map_err(|error| format!("gateway projection failed typed verification: {error}"))?;
    Ok(projection)
}

/// Resolve a workload credential from its pinned route, or derive it from the
/// pinned provider-lane carrier as `generate_gateway_projection` does for runtime lanes.
/// The pod endpoint comes separately from the explicitly selected target node.
pub(super) fn workload_gateway_credential(
    projection: &GatewayProjectionManifest,
    lane: &str,
    model: &str,
) -> Result<String, String> {
    let pinned = projection
        .routes
        .iter()
        .any(|route| route.gateway_lane_id == lane && route.gateway_model_id == model);
    if pinned {
        return served_workload_gateway_credential(projection, lane, model);
    }
    let mut carriers = projection
        .routes
        .iter()
        .filter(|route| route.gateway_lane_id == model);
    match (carriers.next(), carriers.next()) {
        (Some(carrier), None) if carrier.eligible => Ok(carrier.credential_handle.clone()),
        (Some(_), None) => Err(format!(
            "carrier lane {model:?} route is ineligible in the pinned projection"
        )),
        (Some(_), Some(_)) => Err(format!(
            "provider lane {model:?} matches multiple projection routes; the carrier is ambiguous"
        )),
        (None, _) => served_workload_gateway_credential(projection, lane, model),
    }
}

pub(super) fn served_workload_gateway_credential(
    projection: &GatewayProjectionManifest,
    lane: &str,
    model: &str,
) -> Result<String, String> {
    // Exact lane/model matching keeps the models document consistent with set_model.
    let mut matches = projection.routes.iter().filter(|route| {
        route.eligible && route.gateway_lane_id == lane && route.gateway_model_id == model
    });
    let route = match matches.next() {
        Some(route) => route,
        None => {
            let declared = projection
                .routes
                .iter()
                .any(|route| route.gateway_lane_id == lane && route.gateway_model_id == model);
            return Err(if declared {
                format!(
                    "gateway lane {lane:?} model {model:?} has no eligible route in the pinned \
                     projection; the declared route is dead"
                )
            } else {
                format!(
                    "the pinned gateway projection carries no route for lane {lane:?} model \
                     {model:?}"
                )
            });
        }
    };
    if matches.next().is_some() {
        return Err(format!(
            "gateway lane {lane:?} model {model:?} matches multiple eligible routes in the \
             pinned projection; the credential is ambiguous"
        ));
    }
    Ok(route.credential_handle.clone())
}

fn read_bounded_file(path: &Path, ceiling: usize) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(ceiling as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > ceiling {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds the bounded read size",
        ));
    }
    Ok(bytes)
}

/// The `odind check` composition scope: run the same synchronous startup
/// derivations the serving daemon runs — Huginn config validation, the
/// pinned published snapshot, the strict runtime inputs, the
/// posture-scoped Atlas scope, the served brain policies, the embedding
/// resolution, and the declared workload surface with its served-projection
/// route coverage. This is the subset check exercises, not a promise
/// of a serving daemon: async serving, worker launches, and runtime
/// surfaces stay the daemon's to prove. A failing check names the same
/// declaration defect the daemon would refuse on in this subset.
pub(super) fn check_serving_composition(
    config: &OdindConfig,
    authoritative: bool,
) -> Result<(), String> {
    let huginn = odin_huginn::HuginnConfig {
        bind: config.listener_address(),
        limits: config.capacity.clone(),
        state_root: config.paths.state_root.join("huginn"),
    };
    huginn.validate().map_err(|error| error.to_string())?;
    let snapshot = SnapshotHandle::open(SnapshotStore::new(&config.paths.registry_snapshot))
        .map_err(|error| format!("published registry snapshot is invalid: {error}"))?
        .current();
    let runtime = odin_cli::runtime_bindings::RuntimeInputs::parse(config, &snapshot.objects)?;
    odin_cli::runtime_bindings::ensure_seat_tools_granted(
        &snapshot.objects,
        &runtime.seat_bindings,
    )?;
    if authoritative {
        shared_seat_atlas_scope(&snapshot.objects, &runtime.seat_bindings)?;
    }
    let policies = served_brain_policies(
        config,
        snapshot.revision,
        &snapshot.objects,
        &runtime.seat_bindings,
    )?;
    served_embedding(config, &snapshot)?;
    if let Some(brain) = &config.brain {
        if !policies.is_empty() {
            let vault = config
                .hermes
                .as_ref()
                .is_some_and(|hermes| hermes.vault.is_some());
            brain_wiring(&policies, &brain.sources, vault)?;
        }
    }
    // Check routes strictly here; serving may skip individual unservable profiles.
    let workload_brain_scopes = crate::live::workload::brain_source_scopes(&policies);
    let serving_node = odin_domain::NodeId::new(runtime.node.node())
        .map_err(|error| format!("the declared serving node is invalid: {error}"))?;
    let workload = crate::live::workload::compose_workload(
        &snapshot.objects,
        &runtime.seat_bindings,
        &runtime.session_lanes,
        &workload_brain_scopes,
        &serving_node,
    )?;
    crate::live::workload::validate_workload_gateway_routes(config, &workload)?;
    Ok(())
}

/// Derive workload rows from declared provider-lane routes, preserving explicit
/// pairs. Validate routes and credentials before returning canonical bytes and digest.
pub(super) fn generate_gateway_projection(
    config: &OdindConfig,
) -> Result<(Vec<u8>, String), String> {
    let projection = load_gateway_projection(config)?;
    let snapshot = SnapshotHandle::open(SnapshotStore::new(&config.paths.registry_snapshot))
        .map_err(|error| format!("published registry snapshot is invalid: {error}"))?
        .current();
    let runtime = odin_cli::runtime_bindings::RuntimeInputs::parse(config, &snapshot.objects)?;
    let policies = served_brain_policies(
        config,
        snapshot.revision,
        &snapshot.objects,
        &runtime.seat_bindings,
    )?;
    let serving_node = odin_domain::NodeId::new(runtime.node.node())
        .map_err(|error| format!("the declared serving node is invalid: {error}"))?;
    let composition = crate::live::workload::compose_workload(
        &snapshot.objects,
        &runtime.seat_bindings,
        &runtime.session_lanes,
        &crate::live::workload::brain_source_scopes(&policies),
        &serving_node,
    )?;
    let mut routes = projection.routes.clone();
    let mut generated: BTreeSet<(String, String)> = BTreeSet::new();
    for (profile_id, policy) in &composition.models {
        let crate::live::workload::WorkloadModelPolicy::Exact { model, .. } = policy else {
            // A typed-unavailable lane is the declared posture; the launch
            // refuses it with the composed fallback offer, so no row.
            continue;
        };
        let Some((_, lane, _)) = composition.bindings.get(profile_id) else {
            return Err(format!(
                "workload {profile_id} has a model policy but no served seat binding"
            ));
        };
        if !generated.insert((lane.as_str().to_owned(), model.clone())) {
            continue;
        }
        if routes.iter().any(|route| {
            route.gateway_lane_id.as_str() == lane.as_str() && route.gateway_model_id == *model
        }) {
            // The operator already declares this exact pair; declared facts win.
            continue;
        }
        let mut carriers = projection
            .routes
            .iter()
            .filter(|route| route.gateway_lane_id == *model);
        let Some(carrier) = carriers.next() else {
            return Err(format!(
                "workload {profile_id}: provider lane {model:?} has no route in the pinned \
                 projection; no carrier can serve the workload"
            ));
        };
        if carriers.next().is_some() {
            return Err(format!(
                "workload {profile_id}: provider lane {model:?} matches multiple projection \
                 routes; the carrier is ambiguous"
            ));
        }
        if !carrier.eligible {
            return Err(format!(
                "workload {profile_id}: carrier lane {model:?} route is ineligible in the \
                 pinned projection"
            ));
        }
        // The derived row copies the carrier's declared endpoint verbatim.
        // Pod reachability is NOT decided here: the pods' address is the
        // explicitly selected target node's declared gateway endpoint, so a
        // daemon-local (even loopback) carrier endpoint is a lawful
        // declaration for the local clients that use it.
        routes.push(odin_registry::GatewayProjectionRoute {
            gateway_lane_id: lane.as_str().to_owned(),
            gateway_model_id: model.clone(),
            account_handle: carrier.account_handle.clone(),
            endpoint: carrier.endpoint.clone(),
            credential_handle: carrier.credential_handle.clone(),
            role: carrier.role.clone(),
            affinity_key: carrier.affinity_key.clone(),
            eligible: true,
        });
    }
    let manifest = GatewayProjectionManifest::build(routes)
        .map_err(|error| format!("generated gateway projection is invalid: {error}"))?;
    crate::live::workload::validate_workload_routes(config, &manifest, &composition)?;
    let mut bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("generated gateway projection is unserializable: {error}"))?;
    bytes.push(b'\n');
    let digest = Digest::hash(&bytes).to_string();
    Ok((bytes, digest))
}

/// The model descriptor serving every seat: the operator-declared served
/// model identity and window from the daemon runtime config, with the
/// operator-declared optional brain context tokenizer — absent keeps the
/// pinned `odin.tokenizer.utf8-bytes.v1` byte-count default, while
/// `odin.tokenizer.qwen3.v1` selects the pinned Qwen3-family counter and
/// any other declared value refuses startup. The registry publishes
/// neither a model name nor a window (there is no Model registry kind, and
/// the seat's model policy is a policy id, not a model identity), and odind
/// mints neither — the provider name comes from the actual served route,
/// never from registry policy vocabulary or this file.
fn seat_model_descriptor(
    serving: &odin_huginn::config::OdindServingModelConfig,
    seat_id: &str,
) -> Result<odin_domain::knowledge::retrieval::ModelDescriptor, String> {
    let name =
        odin_domain::huginn::ids::ModelName::new(serving.name.as_str()).map_err(|error| {
            format!(
                "brain.serving_model.name {:?} for seat {} is not a valid model identity: {error}",
                serving.name, seat_id
            )
        })?;
    let tokenizer = declared_tokenizer(
        serving.tokenizer.as_deref(),
        &format!("brain.serving_model.tokenizer for seat {seat_id}"),
    )?;
    Ok(odin_domain::knowledge::retrieval::ModelDescriptor {
        name,
        tokenizer,
        context_window_tokens: serving.context_window_tokens,
    })
}

/// Watch enabled, in-scope projects whose host-provisioned roots are Git repositories;
/// registry paths and non-repository roots are not used.
pub(super) fn declared_repo_roots(
    objects: &[RegistryObject],
    in_scope: &BTreeSet<odin_domain::ProjectId>,
    project_roots: &BTreeMap<String, odin_huginn::config::OdindProjectConfig>,
) -> Result<BTreeMap<odin_domain::ProjectId, std::path::PathBuf>, String> {
    let mut declared = BTreeMap::new();
    for object in objects {
        if let ObjectConfig::Project(project) = &object.config {
            let project_id =
                odin_domain::ProjectId::new(&object.id).map_err(|error| error.to_string())?;
            if let (true, true, Some(root)) = (
                project.enabled,
                in_scope.contains(&project_id),
                project_roots.get(&object.id),
            ) {
                if root.root.join(".git").exists() {
                    declared.insert(project_id, root.root.clone());
                }
            }
        }
    }
    Ok(declared)
}

/// The operator's declared brain sources and the host-provisioned project
/// roots (`[projects.<id>] root`) the repository state source watches.
pub(super) struct DeclaredBrainSources<'a> {
    pub sources: &'a BTreeMap<String, odin_huginn::config::OdindBrainSourceConfig>,
    pub project_roots: &'a BTreeMap<String, odin_huginn::config::OdindProjectConfig>,
}

/// Require declared sources to be authorized, add implicit authorized memory
/// sources, and require Hermes vault support for memory. Returns sources to compose.
pub(super) fn brain_wiring(
    policies: &BTreeMap<odin_domain::SeatId, odin_brain::config::EffectiveBrainPolicy>,
    declared: &BTreeMap<String, odin_huginn::config::OdindBrainSourceConfig>,
    hermes_vault: bool,
) -> Result<BTreeMap<String, odin_huginn::config::OdindBrainSourceConfig>, String> {
    let authorized: BTreeSet<&str> = policies
        .values()
        .filter_map(|policy| policy.knowledge.as_ref())
        .flat_map(|knowledge| knowledge.atlas_sources.iter().map(|id| id.as_str()))
        .collect();
    if let Some(key) = declared
        .keys()
        .find(|key| !authorized.contains(key.as_str()))
    {
        return Err(format!(
            "brain.sources.{key} is wired but no served seat's published policy authorizes it"
        ));
    }
    let mut wired = declared.clone();
    for id in authorized.iter().filter(|id| id.starts_with("memory.")) {
        wired
            .entry((*id).to_owned())
            .or_insert_with(odin_huginn::config::OdindBrainSourceConfig::memory);
    }
    if !hermes_vault {
        if let Some(key) = wired
            .iter()
            .find(|(_, source)| source.kind == "memory")
            .map(|(key, _)| key)
        {
            return Err(format!(
                "brain.sources.{key}: a memory source composes only from the configured \
                 Hermes vault, but no [hermes.vault] section exists"
            ));
        }
    }
    Ok(wired)
}

/// Return the strictest source/project privacy class only when it withholds model access.
pub(super) fn withheld_class(
    id: &odin_domain::knowledge::AtlasId,
    declared: Option<odin_domain::knowledge::PrivacyClass>,
    objects: &[odin_registry::RegistryObject],
) -> Option<odin_domain::knowledge::PrivacyClass> {
    objects
        .iter()
        .filter_map(|object| match &object.config {
            odin_registry::ObjectConfig::Project(project)
                if project.memory_namespaces.contains(id) =>
            {
                project.privacy
            }
            _ => None,
        })
        .chain(declared)
        .max()
        .filter(|class| class.withheld_from_models())
}

pub(super) fn brain_sources(
    policies: &BTreeMap<odin_domain::SeatId, odin_brain::config::EffectiveBrainPolicy>,
    declared_sources: &DeclaredBrainSources<'_>,
    registry_handle: &Arc<SnapshotHandle>,
    read_model: &odin_huginn::read_model::MaterializedReadModel,
    task_reader: &Arc<dyn odin_brain::source::state::tasks::TaskStateReader>,
    hermes_vault: Option<&odin_hermes::vault::VaultConfig>,
    ledger: &Arc<std::sync::Mutex<odin_ledger::Ledger>>,
) -> Result<BTreeMap<odin_domain::knowledge::AtlasId, odin_brain::service::BrainSourceConfig>, String>
{
    let configured = brain_wiring(policies, declared_sources.sources, hermes_vault.is_some())?;
    let registry_objects = registry_handle.current();
    // One physical root is one knowledge source identity, fail-closed: two
    // source ids over the same root would let a write or a retrieval under
    // one declared namespace alias another's memory. Deliberate sharing is
    // declared by co-declaring the SAME source id in several projects'
    // memory_namespaces — never by aliasing roots.
    let mut roots: BTreeMap<std::path::PathBuf, String> = BTreeMap::new();
    let mut sources = BTreeMap::new();
    for (key, source) in &configured {
        let id = odin_domain::knowledge::AtlasId::new(key)
            .map_err(|error| format!("brain.sources.{key} is not a valid AtlasId: {error}"))?;
        let composed = match source.kind.as_str() {
            "atlas" => odin_brain::service::BrainSourceConfig::Atlas {
                root: source.root.clone().ok_or_else(|| {
                    format!("brain.sources.{key}: atlas source requires an absolute root")
                })?,
            },
            "silverbullet" => odin_brain::service::BrainSourceConfig::SilverBullet {
                port: source.port.ok_or_else(|| {
                    format!("brain.sources.{key}: silverbullet source requires a loopback port")
                })?,
                expected_space_root: source.expected_space_root.clone(),
                general_namespaces: source.general_namespaces.clone(),
                generated_namespace: source.generated_namespace.clone().ok_or_else(|| {
                    format!(
                        "brain.sources.{key}: silverbullet source requires a generated namespace"
                    )
                })?,
                excluded_namespaces: source.excluded_namespaces.clone(),
                max_pages: source.max_pages.ok_or_else(|| {
                    format!(
                        "brain.sources.{key}: silverbullet source requires a page-count ceiling"
                    )
                })?,
            },
            "memory" => {
                // One seat's reserved memory namespace, composed ONLY from
                // the daemon's validated Hermes vault singleton: canonical
                // id memory.<seat>, scope exactly
                // <vault generated>/memories/<seat>, and no caller root,
                // port, or namespace override exists for this kind.
                let vault = hermes_vault.ok_or_else(|| {
                    format!(
                        "brain.sources.{key}: a memory source composes only from \
                         the configured Hermes vault, but no [hermes.vault] \
                         section exists"
                    )
                })?;
                let silverbullet = vault.silverbullet.as_ref().ok_or_else(|| {
                    format!(
                        "brain.sources.{key}: the configured Hermes vault has no \
                         loopback SilverBullet server, so a memory source could \
                         never serve"
                    )
                })?;
                let seat = key.strip_prefix("memory.").ok_or_else(|| {
                    format!("brain.sources.{key}: a memory source id is memory.<seat>")
                })?;
                let namespace = odin_brain::source::silverbullet::memory_namespace(
                    &vault.generated_namespace,
                    seat,
                )
                .map_err(|error| format!("brain.sources.{key}: {error}"))?;
                let scope = odin_brain::source::silverbullet::VaultScope::generated_only(
                    &namespace,
                    &vault.excluded_namespaces,
                )
                .map_err(|error| format!("brain.sources.{key}: {error}"))?;
                let mut memory = odin_brain::source::silverbullet::SilverBulletSource::new(
                    id.clone(),
                    silverbullet.port,
                    scope,
                )
                .with_limits(
                    odin_brain::source::silverbullet::MAX_RESPONSE_BYTES,
                    vault.max_page_bytes,
                    std::time::Duration::from_millis(vault.timeout_ms),
                )
                .with_page_bound(vault.max_pages);
                if let Some(space_root) = &silverbullet.expected_space_root {
                    memory = memory.with_expected_space_root(space_root.clone());
                }
                odin_brain::service::BrainSourceConfig::Memory { source: memory }
            }
            "state.registry" => odin_brain::service::BrainSourceConfig::StateRegistry {
                source: odin_brain::source::state::registry::RegistrySource::new(
                    id.clone(),
                    Arc::clone(registry_handle),
                ),
            },
            "state.live" => odin_brain::service::BrainSourceConfig::StateLive {
                source: odin_brain::source::state::live::LiveSource::new(
                    id.clone(),
                    read_model.clone(),
                ),
            },
            "state.tasks" => odin_brain::service::BrainSourceConfig::StateTasks {
                source: odin_brain::source::state::tasks::TasksSource::new(
                    id.clone(),
                    Arc::clone(task_reader),
                ),
            },
            "state.repos" => {
                let snapshot = registry_handle.current();
                let projects: BTreeSet<_> = policies
                    .values()
                    .filter(|policy| {
                        policy
                            .knowledge
                            .as_ref()
                            .is_some_and(|knowledge| knowledge.atlas_sources.contains(&id))
                    })
                    .flat_map(|policy| policy.project_memory.keys().cloned())
                    .collect();
                let declared = declared_repo_roots(
                    &snapshot.objects,
                    &projects,
                    declared_sources.project_roots,
                )?;
                // An unreadable project root (mid-clone, emptied) leaves
                // this source instead of stopping odind; the next start
                // re-validates it.
                let (source, refused) =
                    odin_brain::source::state::repos::ReposSource::new_available(
                        id.clone(),
                        declared,
                    );
                for (project, error) in refused {
                    tracing::warn!("brain.sources.{key}: project {project} skipped: {error}");
                }
                odin_brain::service::BrainSourceConfig::StateRepos { source }
            }
            "ops.history" => odin_brain::service::BrainSourceConfig::OpsHistory {
                source: odin_brain::source::ops::HistorySource::new(id.clone(), Arc::clone(ledger)),
            },
            "archive" => {
                // The archive arm composes the strict domain declaration
                // from the huginn mirror fields (huginn validate already
                // enforced required-exactly); re-validating here keeps the
                // projection fail-closed when it is composed outside the
                // config-load path.
                let declaration = odin_domain::knowledge::ArchiveSourceDeclaration {
                    format: source.format.ok_or_else(|| {
                        format!("brain.sources.{key}: archive source requires a format")
                    })?,
                    path: source.export_path.clone().ok_or_else(|| {
                        format!("brain.sources.{key}: archive source requires an export path")
                    })?,
                    memory_namespace: source.memory_namespace.clone().ok_or_else(|| {
                        format!("brain.sources.{key}: archive source requires a memory namespace")
                    })?,
                    privacy_class: source.privacy_class.ok_or_else(|| {
                        format!("brain.sources.{key}: archive source requires a privacy class")
                    })?,
                    dedupe_key: source.dedupe_key.ok_or_else(|| {
                        format!("brain.sources.{key}: archive source requires a dedupe key")
                    })?,
                    selection: source.selection.clone().ok_or_else(|| {
                        format!("brain.sources.{key}: archive source requires a selection policy")
                    })?,
                };
                declaration.validate().map_err(|error| {
                    format!("brain.sources.{key}: archive declaration is invalid: {error}")
                })?;
                odin_brain::service::BrainSourceConfig::Archive { declaration }
            }
            other => {
                return Err(format!(
                    "brain.sources.{key}: unknown kind {other:?} (expected atlas, \
                     silverbullet, memory, state.registry, state.live, state.tasks, \
                     state.repos, ops.history, or archive)"
                ));
            }
        };
        // Canonicalize filesystem roots to reject aliases across source kinds;
        // unreadable or missing roots must fail before opening any service.
        let physical_root: Option<&std::path::Path> = match &composed {
            odin_brain::service::BrainSourceConfig::Atlas { root } => Some(root),
            odin_brain::service::BrainSourceConfig::Archive { declaration } => {
                Some(declaration.path.as_path())
            }
            odin_brain::service::BrainSourceConfig::SilverBullet { .. } => None,
            odin_brain::service::BrainSourceConfig::Memory { .. } => None,
            odin_brain::service::BrainSourceConfig::StateRegistry { .. } => None,
            odin_brain::service::BrainSourceConfig::StateLive { .. } => None,
            odin_brain::service::BrainSourceConfig::StateTasks { .. } => None,
            odin_brain::service::BrainSourceConfig::StateRepos { .. } => None,
            odin_brain::service::BrainSourceConfig::OpsHistory { .. } => None,
            odin_brain::service::BrainSourceConfig::Withheld { .. } => None,
        };
        if let Some(root) = physical_root {
            let canonical = std::fs::canonicalize(root).map_err(|error| {
                format!(
                    "brain.sources.{key}: source root {} cannot be proven a real \
                     path: {error}",
                    root.display()
                )
            })?;
            if let Some(previous) = roots.insert(canonical, key.clone()) {
                return Err(format!(
                    "brain.sources.{key} and brain.sources.{previous} declare the same \
                     physical root {:?}; one root is one source identity, and shared memory \
                     is declared by co-declaring one source id, never by aliasing roots",
                    root.display()
                ));
            }
        }
        let composed = match withheld_class(&id, source.privacy, &registry_objects.objects) {
            Some(class) => odin_brain::service::BrainSourceConfig::Withheld { class },
            None => composed,
        };
        sources.insert(id, composed);
    }
    // Ordinary vault sources must not alias reserved seat memory or feed
    // generated knowledge back into their own authority. Check both trees
    // against the authoritative vault namespace, not the source's spelling.
    if let Some(vault) = hermes_vault {
        let is_segment_prefix = |prefix: &[&str], full: &[&str]| {
            full.len() >= prefix.len() && full[..prefix.len()] == prefix[..]
        };
        let reserved_roots = [
            odin_brain::source::silverbullet::RESERVED_MEMORY_SEGMENT,
            odin_brain::source::silverbullet::RESERVED_KNOWLEDGE_SEGMENT,
        ]
        .map(|reserved| {
            let root: Vec<&str> = vault
                .generated_namespace
                .split('/')
                .chain(std::iter::once(reserved))
                .collect();
            (reserved, root)
        });
        for (key, source) in configured {
            if source.kind != "silverbullet" {
                continue;
            }
            let generated = source.generated_namespace.as_deref().ok_or_else(|| {
                format!(
                    "brain.sources.{key}: silverbullet source requires a generated \
                     namespace"
                )
            })?;
            let exact_vault_namespace = generated == vault.generated_namespace;
            let segments: Vec<&str> = generated.split('/').collect();
            for (reserved, reserved_root) in &reserved_roots {
                if let Some(first) = reserved_root.first() {
                    if source.general_namespaces.iter().any(|name| name == first) {
                        return Err(format!(
                            "brain.sources.{key}: general namespace {first:?} nests \
                             the reserved {reserved} root {:?}",
                            reserved_root.join("/")
                        ));
                    }
                }
                if !exact_vault_namespace
                    && (is_segment_prefix(&segments, reserved_root)
                        || is_segment_prefix(reserved_root, &segments))
                {
                    return Err(format!(
                        "brain.sources.{key}: generated namespace {generated:?} overlaps \
                         the reserved {reserved} root {:?}. Declare exactly the vault's \
                         generated namespace or a disjoint one",
                        reserved_root.join("/")
                    ));
                }
            }
        }
    }
    Ok(sources)
}

pub(super) fn seed_read_model(
    model: &odin_huginn::read_model::MaterializedReadModel,
    registry: &[RegistryObject],
    file_roots: &[live::FileRoot],
    node: &str,
    bind: SocketAddr,
) -> Result<(), String> {
    let observed_at = OffsetDateTime::now_utc();
    for object in registry {
        let kind = match object.kind() {
            RegistryKind::Seat => Some(live::ObjectKind::Seat),
            RegistryKind::Lane => Some(live::ObjectKind::Lane),
            RegistryKind::Node => Some(live::ObjectKind::Node),
            RegistryKind::Container => Some(live::ObjectKind::Container),
            _ => None,
        };
        let Some(kind) = kind else {
            continue;
        };
        let value = serde_json::to_value(&object.config)
            .map_err(|error| format!("could not project registry object {}: {error}", object.id))?;
        publish_snapshot(
            model,
            kind,
            object.id.clone(),
            live::RevisionSource::Registry,
            observed_at,
            value,
        )?;
    }
    for root in file_roots {
        publish_snapshot(
            model,
            live::ObjectKind::File,
            root.root_id.to_string(),
            live::RevisionSource::FileSystem {
                root: root.root_id.clone(),
            },
            observed_at,
            serde_json::json!({
                "rootId": root.root_id.clone(),
                "displayName": root.display_name.clone(),
                "access": root.access,
                "mediaPolicy": root.media_policy.clone(),
                "maxObjectBytes": root.max_object_bytes.get(),
                "watchPolicy": root.watch_policy,
                "allowedSeats": root.allowed_seats.clone(),
            }),
        )?;
    }
    publish_snapshot(
        model,
        live::ObjectKind::Status,
        "odind".to_owned(),
        live::RevisionSource::Kernel,
        observed_at,
        serde_json::json!({
            "node": node,
            "listener": bind.to_string(),
            "state": "ready",
        }),
    )
}

pub(super) fn publish_snapshot(
    model: &odin_huginn::read_model::MaterializedReadModel,
    kind: live::ObjectKind,
    id: String,
    revision_source: live::RevisionSource,
    observed_at: OffsetDateTime,
    value: serde_json::Value,
) -> Result<(), String> {
    let encoded = serde_json::to_vec(&value)
        .map_err(|error| format!("could not encode read-model object {id}: {error}"))?;
    model
        .upsert(live::ObjectSnapshot {
            object: live::ObjectRef { kind, id },
            revision: live::Revision::new(1),
            revision_source,
            freshness: live::Freshness {
                state: live::FreshnessState::Fresh,
                observed_at,
                source_updated_at: Some(observed_at),
                stale_after_seconds: None,
            },
            content_digest: Digest::hash(&encoded),
            value,
        })
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
#[path = "tests/projection.rs"]
mod tests;
