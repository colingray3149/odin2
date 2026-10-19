use std::collections::BTreeMap;
use std::fs;
use std::sync::{Arc, Mutex};

use odin_brain::retrieval::QueryEmbedder;
use odin_brain::service::{BrainService, BrainServiceConfig, BrainSourceConfig};
use odin_domain::huginn::LiveError;
use odin_domain::knowledge::AtlasId;
use odin_domain::{LaneId, SeatId};
use odin_registry::relational::AdmittedBinding;

use crate::host_tools::delegation::{DelegationLink, ParentSessionLink};
use crate::host_tools::executor::HostToolExecutor;
use crate::host_tools::operations::{
    admission_digest, resolve_session_generation, session_capsule_id, DeclaredOperationCatalog,
    HostToolOperations, LiveSessionBindings, OperationStackInputs, SessionOperationBinding,
};
use crate::host_tools::{
    BrowserCapabilityOwner, CanonicalV2CapabilityOwner, CompiledHostToolCatalog, HostToolRegistry,
    KubeCapabilityOwner, ModelVisibleToolConfig,
};
use crate::live::runtime::adapter_stack::{
    compose_adapter_stack, AdapterStack, AdapterStackConfig,
};
use crate::live::runtime::brain_tools::RuntimeBrainTools;
use crate::live::runtime::config::ProductionBridgeRuntimeConfig;
use crate::live::runtime::errors::{invalid, io_error, unavailable};
use crate::live::runtime::launch_support::BridgeRolloverChildren;
use crate::uri::ScopedUriRouter;

use super::{
    listing_failure_kind, validate_served_shape, FactoryWorkloadTurns,
    ProductionBridgeRuntimeFactory,
};

impl ProductionBridgeRuntimeFactory {
    pub fn new(
        config: ProductionBridgeRuntimeConfig,
        owner: Arc<dyn BrowserCapabilityOwner>,
        canonical_v2_owner: Arc<dyn CanonicalV2CapabilityOwner>,
        kube_owner: Arc<dyn KubeCapabilityOwner>,
    ) -> Result<Self, LiveError> {
        Self::assemble(config, &move |host_tools| {
            host_tools
                .register_browser_capabilities(Arc::clone(&owner))
                .map_err(|error| unavailable(&format!("omp_browser_host_tools: {error}")))?;
            host_tools
                .register_canonical_v2_capabilities(Arc::clone(&canonical_v2_owner))
                .map_err(|error| unavailable(&format!("omp_canonical_v2_host_tools: {error}")))?;
            host_tools
                .register_kube_capabilities(Arc::clone(&kube_owner))
                .map_err(|error| unavailable(&format!("omp_kube_host_tools: {error}")))
        })
    }

    /// Restricted construction: never registers cataloged browser HostTools.
    /// Every enabled served declaration must resolve to a composed listed or
    /// internal HostTool; unmatched Builtin/Exec is rejected before start.
    pub fn restricted(
        config: ProductionBridgeRuntimeConfig,
        enabled: impl IntoIterator<Item = AdmittedBinding>,
    ) -> Result<Self, LiveError> {
        let enabled: Vec<AdmittedBinding> = enabled.into_iter().collect();
        Self::assemble(config, &move |host_tools| {
            for declaration in &enabled {
                if !host_tools.resolves_admitted(&declaration.handler)
                    || !host_tools.resolves_admitted(&declaration.evidence_extractor)
                {
                    return Err(invalid(
                        "enabled declaration has no composed HostTool binding",
                    ));
                }
            }
            Ok(())
        })
    }

    fn assemble(
        config: ProductionBridgeRuntimeConfig,
        register: &dyn Fn(&mut HostToolRegistry) -> Result<(), LiveError>,
    ) -> Result<Self, LiveError> {
        config
            .process
            .validate()
            .map_err(|error| unavailable(&format!("omp_process_config: {error}")))?;
        if config.owner_id.trim().is_empty() || config.lease_ttl.is_zero() {
            return Err(invalid("bridge runtime owner and lease TTL are required"));
        }
        validate_served_shape(
            config.read_only,
            &config.seat_operation_bindings,
            &config.project_roots,
            &config.session_lanes,
            &config.allowed_nodes,
        )?;
        for (seat, rollover) in &config.rollover_by_seat {
            rollover
                .validate()
                .map_err(|detail| invalid(format!("omp_rollover_policy seat {seat}: {detail}")))?;
        }
        fs::create_dir_all(&config.artifact_root).map_err(io_error)?;
        fs::create_dir_all(&config.hooks_root).map_err(io_error)?;
        let artifact_root = config.artifact_root.canonicalize().map_err(io_error)?;
        let hooks_root = config.hooks_root.canonicalize().map_err(io_error)?;
        let mut project_roots = BTreeMap::new();
        for (project, root) in config.project_roots {
            let root = root.canonicalize().map_err(|error| {
                unavailable(&format!(
                    "production_live_filesystem: project {project:?} root {}: {error}",
                    root.display()
                ))
            })?;
            if !root.is_dir() {
                return Err(invalid("registry project root is not a directory"));
            }
            project_roots.insert(project, root);
        }
        let mut host_tools = HostToolRegistry::model_visible(ModelVisibleToolConfig {
            ledger: Arc::clone(&config.bridge_ledger),
            atlas: Arc::clone(&config.atlas),
            allowed_atlas_scope: config.allowed_atlas_scope.clone(),
            artifact_root: artifact_root.clone(),
        })
        .map_err(|error| unavailable(&format!("omp_host_tools: {error}")))?;
        let brain_tools = Arc::new(std::sync::OnceLock::new());
        crate::host_tools::brain::register(&mut host_tools, Arc::clone(&brain_tools))
            .map_err(|error| unavailable(&format!("omp_brain_tools: {error}")))?;
        for tool in &config.hermes_tools {
            host_tools
                .register(Arc::clone(tool))
                .map_err(|error| unavailable(&format!("omp_hermes_host_tools: {error}")))?;
        }
        for (builtin_id, tool) in &config.hermes_internal_bindings {
            host_tools
                .register_internal(
                    crate::host_tools::InternalBindingKey::Builtin((*builtin_id).to_owned()),
                    Arc::clone(tool),
                )
                .map_err(|error| unavailable(&format!("omp_hermes_internal_bindings: {error}")))?;
        }
        if let Some(slot) = &config.task_slot {
            host_tools
                .register_task_capabilities(Arc::clone(slot))
                .map_err(|error| unavailable(&format!("omp_task_capabilities: {error}")))?;
        }
        if let Some(context) = &config.context_read {
            host_tools
                .register_context_read(&context.root, context.max_bytes)
                .map_err(|error| unavailable(&format!("omp_context_read: {error}")))?;
        }
        register(&mut host_tools)?;
        crate::host_tools::adapter::register_adapter_markers(&mut host_tools)
            .map_err(|error| unavailable(&format!("omp_adapter_markers: {error}")))?;
        crate::host_tools::adapter::register_adapter_tools(
            &mut host_tools,
            &config.operation_contracts,
            &*config.schema_catalog,
        )
        .map_err(|error| unavailable(&format!("omp_adapter_tools: {error}")))?;
        let registry = Arc::new(host_tools.clone());
        let executor = Arc::new(HostToolExecutor::new(Arc::clone(&registry)));
        if config.admission_revision <= 0 {
            return Err(invalid(
                "bridge runtime requires a published snapshot revision",
            ));
        }
        let digest = admission_digest(&config.operation_contracts, config.admission_revision)
            .map_err(|error| invalid(error.to_string()))?;
        let catalog: Arc<dyn odin_kernel::OperationCatalog> = Arc::new(
            DeclaredOperationCatalog::from_contracts(
                &config.operation_contracts,
                config.admission_revision,
                digest,
                registry,
                &config.operator_capabilities,
            )
            .map_err(|error| invalid(error.to_string()))?
            .with_equivalence(Arc::new(
                crate::host_tools::operations::CompositionEquivalence::new(
                    u64::try_from(config.admission_revision)
                        .map_err(|_| invalid("admission revision is negative"))?,
                    Arc::new(config.operation_contracts.clone()),
                    Arc::clone(&config.revision_material),
                ),
            )),
        );
        let AdapterStack {
            executor: adapter_executor,
            status: adapter_status,
        } = compose_adapter_stack(
            AdapterStackConfig {
                adapters: Arc::clone(&config.adapters),
                status_ttl: config.adapter_status_ttl,
            },
            Arc::clone(&executor),
            Arc::clone(&config.schema_catalog),
            &config.bridge_ledger,
            &config.operation_clock,
        )
        .map_err(invalid)?;
        let operations = HostToolOperations::new(
            OperationStackInputs {
                workload_drafts: config.workload_drafts.clone(),
                catalog,
                schemas: config.schema_catalog.clone(),
                executor,
                adapter_executor,
                adapter_status,
                limits: config.operation_limits,
                clock: config.operation_clock.clone(),
                ledger: Arc::clone(&config.bridge_ledger),
                revisions: Arc::clone(&config.revision_material),
            },
            config.operation_contracts.clone(),
            Arc::clone(&config.operation_authority_provider),
        )
        .map_err(|error| invalid(error.to_string()))?;
        let operations = match &config.task_grants {
            Some(grants) => operations.with_task_grants(Arc::clone(grants)),
            None => operations,
        };
        // The brain service composes from the published real registry policy
        // and the same bridge ledger the URI router shares; its durable store
        // is confined under this runtime's artifact root, and it serves
        // exactly the knowledge sources the policy authorizes — Atlas roots
        // and loopback vaults alike. A policy without a knowledge authority
        // composes no source; the affected operations fail typed-unavailable
        // instead of refusing unrelated sessions. An absent policy composes
        // no service whatsoever: the URI router runs brain-less and
        // `brain://` fails typed while every other scheme resolves.
        let session_bindings = Arc::new(LiveSessionBindings::new(operations.clone()));
        // One brain service per served seat, each composed from that seat's
        // OWN published policy and pinning only the declared sources the
        // seat's policy authorizes. Seats intentionally serve different
        // knowledge scopes, so policies are never converged and cross-seat
        // leakage is structural impossibility, not discipline. An
        // authorized-but-undeclared source is missing composition, not
        // runtime unavailability: the source-set validator refuses the
        // seat's open instead of silently pinning a reduced pool, so the
        // seat-named assembly error points at the binding the operator
        // must declare.
        // Lexical retrieval composes and serves without any embeddings
        // backend; only vector/hybrid operations fail typed when none is
        // bound.
        let mut brains = BTreeMap::new();
        for (seat, policy) in &config.brain_policies {
            let sources: BTreeMap<AtlasId, BrainSourceConfig> = config
                .brain_sources
                .iter()
                .filter(|(id, _)| {
                    policy
                        .knowledge
                        .as_ref()
                        .is_some_and(|knowledge| knowledge.atlas_sources.contains(id))
                })
                .map(|(id, source)| (id.clone(), source.clone()))
                .collect();
            let service = BrainService::open(
                BrainServiceConfig {
                    store_root: artifact_root.join("brain-store").join(seat.as_str()),
                    sources,
                    embedding_available: config.brain_embedding.is_some(),
                    embedding_model: config.brain_embedding_model.clone(),
                    // Ingest through daemon-held brains is typed
                    // unavailable: the archive ingest gate is composed only
                    // by the operator one-shot archive entrypoint, so there
                    // is no live path that ingests without the verified
                    // ledger gate.
                    archive_ingest_gate: None,
                    postgres: config.brain_postgres.clone(),
                },
                policy.clone(),
                Arc::clone(&config.bridge_ledger),
            )
            .map_err(|error| {
                unavailable(&format!(
                    "omp_brain_service seat {}: {error}",
                    seat.as_str()
                ))
            })?;
            brains.insert(seat.clone(), Arc::new(service));
        }
        let workload_turns = Arc::new(FactoryWorkloadTurns {
            brains: brains.clone(),
            laws: config.workload_sessions.clone(),
        });
        // The rollover every seat's sessions actually run with: one
        // composition pass over the declared policies and the per-seat lane
        // ceilings — a dropped declaration is never re-inserted raw, and a
        // declaration without a context lane stands exactly. The
        // delegated-children state source exists exactly when at least one
        // seat runs a rollover policy.
        let rollover_lanes: Vec<_> = config
            .brain_policies
            .iter()
            .map(|(seat, policy)| {
                (
                    seat.clone(),
                    policy.context.as_ref().map(|context| {
                        (
                            policy.model.context_window_tokens.get(),
                            context.reserve_output_tokens.get(),
                        )
                    }),
                )
            })
            .collect();
        let rollover_by_seat = crate::live::rollover::compose_seat_rollovers(
            &rollover_lanes,
            &config.rollover_by_seat,
        )
        .map_err(|detail| invalid(format!("omp_rollover_policy: {detail}")))?;
        let rollover_children = (!rollover_by_seat.is_empty()).then(|| {
            Arc::new(BridgeRolloverChildren {
                links: config.delegation_links.clone(),
                live: Arc::clone(&config.live_ledger),
            }) as Arc<dyn crate::live::rollover::RolloverChildrenSource>
        });
        let uri_router = ScopedUriRouter::new(
            Arc::clone(&config.bridge_ledger),
            Arc::clone(&config.atlas),
            config.allowed_atlas_scope,
            artifact_root.clone(),
            config.max_artifact_read_bytes,
            brains.clone(),
        )
        .map_err(|error| unavailable(&format!("omp_uri_router: {error}")))?;
        brain_tools
            .set(Arc::new(RuntimeBrainTools {
                brains: brains.clone(),
                sessions: Arc::downgrade(&session_bindings),
                router: uri_router.clone(),
                embedding: config.brain_embedding.clone(),
            }))
            .map_err(|_| unavailable("omp_brain_tools_already_bound"))?;
        Ok(Self {
            process: config.process,
            worker: config.worker,
            bridge_ledger: config.bridge_ledger,
            live_ledger: config.live_ledger,
            host_tools,
            operations,
            session_bindings,
            _brain_tools: brain_tools,
            revisions: config.revision_material,
            delegation_links: config.delegation_links,
            workload_turns,
            conversation_guidance: config.conversation_guidance,
            tool_exposure: config.tool_exposure,
            rollover_children,
            rollover_by_seat,
            lane_windows_by_seat: config.lane_windows_by_seat,
            uri_router,
            artifact_root,
            project_roots,
            allowed_nodes: config.allowed_nodes,
            owner_id: Arc::from(config.owner_id),
            hooks_root,
            owner_preview: config
                .operation_contracts
                .iter()
                .filter(|(_, contract)| contract.preview.is_some())
                .map(|(id, _)| id.to_string())
                .collect(),
            lease_ttl: config.lease_ttl,
            zellij: config.zellij,
            session_capsule_authority: config.session_capsule_authority,
            admitted_bindings: crate::host_tools::production_bindings(),
            workload_carrier: config.workload_carrier,
            brains,
            core_tokens: Mutex::new(BTreeMap::new()),
            embedding: config.brain_embedding,
            seat_sandboxes: config.seat_sandboxes,
            seat_memory_max: config.seat_memory_max,
            sandbox_host: config.sandbox_host,
        })
    }

    /// The per-seat brain services this runtime composed. Read-only view
    /// for the daemon composition, which binds the exact services that serve
    /// retrieval, never a second instance.
    pub fn brains(&self) -> &BTreeMap<SeatId, Arc<BrainService>> {
        &self.brains
    }

    /// Binds a runtime lane to the shared embedding executor. A session binds
    /// its own lane once at launch; the daemon's background brain warm binds
    /// each seat's declared session lane. A bind refusal is typed — no
    /// default embedder, no silent lexical downgrade.
    pub fn bind_session_embedder(
        &self,
        lane: &LaneId,
    ) -> Result<Option<Arc<QueryEmbedder>>, LiveError> {
        self.embedding
            .as_ref()
            .map(|provider| {
                Arc::clone(provider)
                    .bind_lane(lane)
                    .map_err(|error| unavailable(&format!("omp_embedding_lane_bind: {error:?}")))
            })
            .transpose()
    }

    /// Proves every compiled handler/extractor binding the runtime admits
    /// resolves through the concrete production HostTool registry. The
    /// admitted set mirrors the assembly: the web-search adapter binding is
    /// admitted only when the adapter backend is actually wired, so an
    /// undeployed adapter stays typed-unavailable per request. Call
    /// immediately before listen.
    pub fn validate_capability_composition(&self) -> Result<(), LiveError> {
        CompiledHostToolCatalog::compile(self.admitted_bindings)
            .and_then(|catalog| catalog.validate_production_composition(&self.host_tools))
            .map_err(|error| unavailable(&format!("omp_host_tool_composition: {error}")))
    }

    /// Reconstructs the exact parent link of one durable delegation row:
    /// identity and run come from the row, while the parent's exact
    /// operation binding comes from the parent's own generation — resolved
    /// from the parent's installed token the same way every session
    /// resolves, then recomposed from that retained publication. The
    /// parent is never verified against startup or current material.
    pub(super) async fn persisted_parent_link(
        &self,
        row: DelegationLink,
    ) -> Result<Arc<ParentSessionLink>, LiveError> {
        let parent_session = row.parent.clone();
        let parent_live = crate::host_tools::delegation::live_session_id(&parent_session)
            .map_err(|error| invalid(error.to_string()))?;
        let parent_manifest = self
            .live_ledger
            .session(parent_live)
            .await
            .map_err(|_| unavailable("live_ledger_parent_session"))?
            .manifest;
        let parent_token = self
            .operations
            .provisioned_token(&parent_session)
            .map_err(|error| {
                unavailable(&format!(
                    "published_operation_authority:{}",
                    listing_failure_kind(&error)
                ))
            })?;
        let parent_generation = resolve_session_generation(
            &parent_session,
            &parent_token,
            parent_manifest.served_revision,
            self.revisions.as_ref(),
        )
        .map_err(invalid)?;
        let parent_material = self
            .operations
            .material_at(parent_generation)
            .map_err(|error| invalid(error.to_string()))?;
        let parent_lane = parent_material
            .session_lanes
            .get(&(
                parent_manifest.seat_id.clone(),
                parent_manifest.project_id.clone(),
            ))
            .ok_or_else(|| {
                invalid("parent session has no session lane for its seat and project")
            })?;
        let parent_policy = parent_material
            .seat_operation_bindings
            .get(&(parent_manifest.seat_id.clone(), parent_lane.clone()))
            .ok_or_else(|| {
                invalid("parent session has no operation binding for its seat and lane")
            })?;
        let parent_capsule =
            session_capsule_id(&parent_session).map_err(|error| invalid(error.to_string()))?;
        let parent_depth = row
            .depth
            .checked_sub(1)
            .ok_or_else(|| invalid("delegation link row carries an impossible zero depth"))?;
        Ok(Arc::new(ParentSessionLink {
            session: parent_session,
            binding: SessionOperationBinding {
                policy: parent_policy.policy.clone(),
                context_policy_digest: parent_policy.context_policy_digest,
                capsule_id: parent_capsule,
                served_revision: parent_generation,
                // Delegation is one level deep, so every valid parent is a root session.
                parent: None,
            },
            run: row.parent_run,
            depth: parent_depth,
        }))
    }
}
