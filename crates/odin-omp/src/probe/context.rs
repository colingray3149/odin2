//! The exact per-case context: deterministic identity minting, the retained
//! work-dir layout, the real brain service over a fixture corpus, and the
//! probe's live authority composition (host tools, operation stack, provisioned
//! token authority) behind the assembled bridge configuration.

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ::time::OffsetDateTime;
use odin_atlas::Atlas;
use odin_brain::config::EffectiveBrainPolicy;
use odin_brain::service::{BrainService, BrainServiceConfig, BrainSourceConfig};
use odin_domain::huginn::ids::ModelName;
use odin_domain::knowledge::ids::TokenizerId;
use odin_domain::knowledge::retrieval::ModelDescriptor;
use odin_domain::knowledge::{AtlasId, EmbeddingBackend, RetrievalMode};
use odin_domain::{LaneId, ProjectId, RunId, Scope, SeatId, SessionId};
use odin_ledger::lane_run::{self, NewLane, NewRun};
use odin_ledger::Ledger;
use odin_registry::schema::{
    AccountingWindowToml, ApprovalDefaultToml, ApprovalDefaultsToml, BudgetPolicyToml,
    RegistryKind, SeatKnowledgeToml, SeatLimitsToml, SeatToml, SliceKnowledgeToml,
    SliceRedirectsToml, SliceToml, REGISTRY_SCHEMA,
};

use crate::bridge::{BridgeBinding, LiveSessionDescriptor, OmpBridgeConfig};
use crate::host_tools::lane_status::{LaneStatusEvidenceTool, LaneStatusTool};
use crate::host_tools::operations::{HostToolOperations, SessionOperationBinding};
use crate::host_tools::{HostToolError, HostToolRegistry, ModelVisibleToolConfig};
use crate::process::{OmpProcessSpec, OmpWorkerLaunch};
use crate::uri::{ScopedUriRouter, MAX_ARTIFACT_READ_BOUND};

use super::config::{ProbeConfig, DEFAULT_MODEL_SELECTOR, FIXTURE_MODEL_A, FIXTURE_PROVIDER};
use super::contracts::{ConformanceCaseId, ProbeError};
use super::{digest_hex, CaseContext};

/// Session lease TTL stamped onto every probe bridge binding.
const SESSION_LEASE_TTL: Duration = Duration::from_secs(60);

/// Deterministic per-case identity set, derived from the case id alone (no
/// clock, no entropy source): rerunning a case reproduces the same ids.
#[derive(Clone, Debug)]
pub struct CaseIds {
    pub case: ConformanceCaseId,
    pub seat: SeatId,
    pub project: ProjectId,
    pub lane: LaneId,
    pub run: RunId,
    pub session: SessionId,
    pub owner: String,
}

impl CaseIds {
    pub fn mint(case: ConformanceCaseId) -> Self {
        let entropy = format!("odin-probe-case-{:02}", case.get());
        let at = u64::from(case.get());
        let expect = "probe id minting is infallible";
        Self {
            case,
            seat: SeatId::from_parts("seat", at, &entropy).expect(expect),
            project: ProjectId::from_parts("project", at, &entropy).expect(expect),
            lane: LaneId::from_parts("lane", at, &entropy).expect(expect),
            run: RunId::from_parts("run", at, &entropy).expect(expect),
            session: SessionId::new(format!("00000000-0000-4000-8000-{:012}", case.get()))
                .expect(expect),
            owner: format!("odin-probe-owner-{:02}", case.get()),
        }
    }
}

/// The probe brain's single fixture atlas source id.
const BRAIN_FIXTURE_ATLAS_ID: &str = "atlas.fixture";

/// Registry revision the fixture brain policy resolves from.
const BRAIN_FIXTURE_REGISTRY_REVISION: u64 = 74;

/// Deterministic fixture crate the atlas builder parses into the probe
/// brain's retrieval corpus: real Rust source, never canned results.
const BRAIN_FIXTURE_ATLAS_SOURCE: &str = "//! Probe brain fixture crate.\n\n/// Adds one.\npub fn brain_fixture_add_one(value: u64) -> u64 { value + 1 }\n";

fn nz16(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).expect("fixture value is non-zero")
}

fn nz32(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).expect("fixture value is non-zero")
}

/// Resolves the probe brain's fixture policy through the real registry
/// resolution path: lexical-only retrieval (the probe composes no embedding
/// executor), a single atlas source, and a digest-bound binding the service
/// verifies on open.
fn brain_fixture_policy() -> Result<EffectiveBrainPolicy, ProbeError> {
    let atlas_sources: BTreeSet<AtlasId> = [BRAIN_FIXTURE_ATLAS_ID]
        .into_iter()
        .map(|value| AtlasId::new(value).expect("fixture atlas id is valid"))
        .collect();
    let slice = SliceToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Slice,
        enabled: true,
        description: "probe brain fixture slice".to_owned(),
        capabilities: BTreeSet::new(),
        variables: BTreeMap::new(),
        redirects: SliceRedirectsToml {
            out_of_scope: "NeedsPlan".to_owned(),
        },
        knowledge: Some(SliceKnowledgeToml {
            required: false,
            atlas_sources: atlas_sources.clone(),
            retrieval_mode: RetrievalMode::Lexical,
            candidate_limit: nz16(128),
            top_k: nz16(16),
            min_score_micros: 100_000,
            chunk_tokens: nz32(512),
            chunk_overlap_tokens: 64,
            embedding_backend: EmbeddingBackend::Disabled,
        }),
        context: None,
        tools: None,
        live: None,
        budget: None,
    };
    let seat = SeatToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Seat,
        enabled: true,
        description: "probe brain fixture seat".to_owned(),
        categories: BTreeSet::new(),
        tool_refs: BTreeSet::new(),
        project_scope: BTreeSet::new(),
        read_project_scope: BTreeSet::new(),
        models: Vec::new(),
        approval_defaults: ApprovalDefaultsToml {
            r0: ApprovalDefaultToml::Auto,
            r1: ApprovalDefaultToml::Auto,
            r2: ApprovalDefaultToml::Auto,
            r3: ApprovalDefaultToml::Approval,
        },
        brain_scope: atlas_sources.clone(),
        limits: SeatLimitsToml {
            max_parallel_runs: 4,
            max_sessions: 4,
            budget: Some(BudgetPolicyToml {
                usd_micros: 30_000_000,
                window: AccountingWindowToml {
                    duration_seconds: NonZeroU64::new(2_592_000)
                        .expect("fixture window is non-zero"),
                },
            }),
        },
        live: None,
        knowledge: Some(SeatKnowledgeToml {
            atlas_sources: atlas_sources.clone(),
            required_tags: BTreeSet::new(),
            denied_tags: BTreeSet::new(),
            top_k: nz16(8),
        }),
        context: None,
        tools: None,
        guidance: None,
        conversation: None,
        profile_namespace: None,
        ephemeral: None,
        sandbox: odin_registry::schema::SeatSandboxToml::default(),
    };
    let model = ModelDescriptor {
        name: ModelName::new("model.probe").expect("fixture model name is valid"),
        tokenizer: TokenizerId::new("odin.tokenizer.utf8-bytes.v1")
            .expect("pinned tokenizer id is valid"),
        context_window_tokens: nz32(65536),
    };
    EffectiveBrainPolicy::resolve(
        BRAIN_FIXTURE_REGISTRY_REVISION,
        &slice,
        &seat,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &model,
    )
    .map_err(|error| ProbeError::Config {
        detail: format!("brain fixture policy resolve: {error}"),
    })
}

impl CaseContext {
    /// Builds the context for one case: a fresh migrated in-memory ledger
    /// seeded with the case's deterministic lane and run, plus the retained
    /// work-dir path (created by [`crate::probe::run_case`] before the body runs).
    pub fn for_case(
        config: &Arc<ProbeConfig>,
        case: ConformanceCaseId,
        name: &'static str,
    ) -> Result<Self, ProbeError> {
        let ledger = Ledger::open_in_memory()?;
        let ids = CaseIds::mint(case);
        let created_at =
            OffsetDateTime::from_unix_timestamp(i64::from(case.get())).map_err(|error| {
                ProbeError::Config {
                    detail: format!("deterministic case timestamp is invalid: {error}"),
                }
            })?;
        lane_run::create_lane(
            ledger.connection(),
            &NewLane {
                lane_id: ids.lane.clone(),
                seat_id: ids.seat.clone(),
                project_id: Some(ids.project.clone()),
                template_id: "odin-probe-template".to_owned(),
                backend: "local_omp".to_owned(),
                created_by: ids.owner.clone(),
                created_at,
                retained: true,
            },
        )?;
        lane_run::create_run(
            ledger.connection(),
            &NewRun {
                run_id: ids.run.clone(),
                lane_id: ids.lane.clone(),
                attempt_number: 1,
                workflow_id: Some("odin-omp-conformance".to_owned()),
                workflow_version: Some(1),
                input_hash: digest_hex(format!("case-{:02}", case.get()).as_bytes()),
                accepted_capability_revision: None,
                lease_id: None,
                absolute_deadline: None,
                retry_budget: 0,
                created_at,
            },
        )?;
        Ok(Self {
            config: Arc::clone(config),
            ids,
            ledger: Arc::new(Mutex::new(ledger)),
            work_dir: config
                .work_root
                .join("cases")
                .join(format!("{:02}-{name}", case.get())),
        })
    }

    pub fn config(&self) -> &ProbeConfig {
        &self.config
    }

    pub fn ids(&self) -> &CaseIds {
        &self.ids
    }

    pub fn ledger(&self) -> Arc<Mutex<Ledger>> {
        Arc::clone(&self.ledger)
    }

    pub fn atlas(&self) -> Arc<Atlas> {
        Arc::clone(&self.config.atlas)
    }

    /// The case's real brain service over a deterministic fixture corpus: a
    /// real Rust source tree the atlas builder parses, a registry-resolved
    /// digest-verified lexical policy, and the case's own durable ledger.
    /// The generation is built eagerly so brain:// resolution serves the
    /// pinned head immediately.
    fn brain_service(&self) -> Result<BrainService, ProbeError> {
        let atlas_root = self.work_dir.join("brain-atlas");
        // The atlas builder rejects a root missing any source-class directory
        // (crates, extension, registry, skeletons); empty dirs are valid.
        for source_dir in ["crates/demo/src", "extension", "registry", "skeletons"] {
            std::fs::create_dir_all(atlas_root.join(source_dir))?;
        }
        std::fs::write(
            atlas_root
                .join("crates")
                .join("demo")
                .join("src")
                .join("lib.rs"),
            BRAIN_FIXTURE_ATLAS_SOURCE,
        )?;
        let policy = brain_fixture_policy()?;
        let service = BrainService::open(
            BrainServiceConfig {
                store_root: self.work_dir.join("brain-store"),
                sources: BTreeMap::from([(
                    AtlasId::new(BRAIN_FIXTURE_ATLAS_ID).map_err(|error| ProbeError::Config {
                        detail: format!("brain fixture atlas id: {error}"),
                    })?,
                    BrainSourceConfig::Atlas { root: atlas_root },
                )]),
                embedding_available: false,
                embedding_model: None,
                archive_ingest_gate: None,
                postgres: None,
            },
            policy,
            self.ledger(),
        )
        .map_err(|error| ProbeError::Config {
            detail: format!("brain service open: {error}"),
        })?;
        service
            .ensure_generation()
            .map_err(|error| ProbeError::Config {
                detail: format!("brain fixture generation: {error}"),
            })?;
        Ok(service)
    }

    /// The case's retained work dir; the runner creates it before the case
    /// body runs. Cases may create their own fixtures underneath; nothing may
    /// remove the dir itself or the suite work root.
    pub fn work_dir(&self) -> &Path {
        &self.work_dir
    }

    /// Runner-managed evidence dir under the work dir; cases never write here.
    pub fn evidence_dir(&self) -> PathBuf {
        self.work_dir.join("evidence")
    }

    pub fn artifact_root(&self) -> PathBuf {
        self.work_dir.join("artifacts")
    }

    /// The suite's default per-case deadline, for cases without a tighter one.
    pub fn default_case_deadline(&self) -> Duration {
        self.config.deadlines.default_case
    }

    pub fn scope(&self) -> Scope {
        Scope {
            seat: Some(self.ids.seat.clone()),
            project: Some(self.ids.project.clone()),
            lane: Some(self.ids.lane.clone()),
            run: Some(self.ids.run.clone()),
            attempt: None,
            session: Some(self.ids.session.clone()),
            node: None,
        }
    }

    /// A blank (epoch 0, lease-less) binding ready for `OmpBridge::start`.
    pub fn binding(&self) -> BridgeBinding {
        BridgeBinding::new(
            self.scope(),
            self.ids.session.clone(),
            self.ids.run.clone(),
            self.ids.lane.clone(),
            self.ids.owner.clone(),
        )
    }

    /// The default durable-session columns: fixture provider and model A, no
    /// tab, a manifest naming the case.
    pub fn session_descriptor(&self) -> LiveSessionDescriptor {
        LiveSessionDescriptor {
            slice_id: "odin-probe-slice".to_owned(),
            target_node_id: "odin-probe-node".to_owned(),
            provider: FIXTURE_PROVIDER.to_owned(),
            model: FIXTURE_MODEL_A.to_owned(),
            title: None,
            open_tab: false,
            manifest: serde_json::json!({
                "fixture": true,
                "case": self.ids.case.get(),
            }),
        }
    }

    /// A pinned-OMP child spec for this case: fixture extension loaded,
    /// `--model` set, working directory bound to the case work dir.
    /// `extra_args` are appended after the harness arguments.
    pub fn process_spec(&self, model_selector: &str, extra_args: Vec<String>) -> OmpProcessSpec {
        let mut args = vec![
            "--extension".to_owned(),
            self.config
                .provider_fixture_path()
                .to_string_lossy()
                .into_owned(),
            "--model".to_owned(),
            model_selector.to_owned(),
        ];
        args.extend(extra_args);
        self.config.omp.spec_for(self.work_dir.clone(), args)
    }

    /// Resolves the sole StopAuthority worker contract for a spec's exact
    /// executable: the omp template worker for pinned-OMP specs, the fault
    /// fixture worker for Bun specs. Mismatch is a hard error.
    pub fn worker_for(&self, spec: &OmpProcessSpec) -> OmpWorkerLaunch {
        let omp = &self.config.omp.worker;
        let fault = &self.config.fault.worker;
        let executable = spec.executable.clone();
        if omp.binding.executable() == executable {
            omp.clone()
        } else if fault.binding.executable() == executable {
            fault.clone()
        } else {
            panic!(
                "spec executable {} has no registered StopAuthority worker contract",
                executable.display()
            );
        }
    }

    /// A child spec running the RPC transport fault fixture under Bun.
    /// `script_args` are passed to the fixture verbatim.
    pub fn fault_spec(&self, script_args: Vec<String>) -> OmpProcessSpec {
        self.config.fault.spec_for(
            self.config.fault_fixture_path(),
            self.work_dir.clone(),
            script_args,
        )
    }

    /// Assembles the full adapter configuration over this case's ledger and
    /// default fixture model. The six compiled fixture implementations remain
    /// unadvertised because the probe's operation listing admits no contract.
    pub fn bridge_config(
        &self,
        session: LiveSessionDescriptor,
    ) -> Result<OmpBridgeConfig, ProbeError> {
        self.bridge_config_with(session, DEFAULT_MODEL_SELECTOR)
    }

    /// [`CaseContext::bridge_config`] with an explicit `--model` selector.
    pub fn bridge_config_with(
        &self,
        session: LiveSessionDescriptor,
        model_selector: &str,
    ) -> Result<OmpBridgeConfig, ProbeError> {
        let artifact_root = self.artifact_root();
        std::fs::create_dir_all(&artifact_root)?;
        let ledger = self.ledger();
        let atlas = self.atlas();
        let allowed_atlas_scope =
            odin_atlas::AtlasScope::seat([format!("probe:{}", self.ids.seat)])
                .map_err(HostToolError::Atlas)?;
        let host_tools = HostToolRegistry::model_visible(ModelVisibleToolConfig {
            ledger: Arc::clone(&ledger),
            atlas: Arc::clone(&atlas),
            allowed_atlas_scope: allowed_atlas_scope.clone(),
            artifact_root: artifact_root.clone(),
        })?;
        let brain = Arc::new(self.brain_service()?);
        let uri_router = ScopedUriRouter::new(
            ledger.clone(),
            atlas,
            allowed_atlas_scope,
            artifact_root.clone(),
            MAX_ARTIFACT_READ_BOUND,
            BTreeMap::from([(self.ids.seat.clone(), brain)]),
        )?;
        let (operations, operation_binding, admitted_host_tools) =
            self.operation_surface(&host_tools, &ledger)?;
        Ok(OmpBridgeConfig {
            process: self.process_spec(model_selector, Vec::new()),
            worker: self.config.omp.worker.clone(),
            ledger,
            operations,
            operation_binding,
            admitted_host_tools,
            uri_router,
            artifact_root,
            binding: self.binding(),
            session,
            lease_ttl: SESSION_LEASE_TTL,
            rollover: None,
            rollover_children: None,
            requested_epoch: None,
            transport: None,
        })
    }

    /// The probe's real admitted operation surface: every authority seam is
    /// live, exactly one lane-status capability is admitted through a
    /// fixture-provisioned token, and every dispatch traverses the sole
    /// kernel authority. There is no empty-admission or fallback surface.
    fn operation_surface(
        &self,
        host_tools: &HostToolRegistry,
        ledger: &Arc<Mutex<Ledger>>,
    ) -> Result<
        (
            HostToolOperations,
            SessionOperationBinding,
            BTreeSet<String>,
        ),
        ProbeError,
    > {
        use std::collections::BTreeMap;
        use std::num::NonZeroU32;

        use odin_domain::knowledge::{ToolName, ToolSchema};
        use odin_domain::operation::Limits;
        use odin_domain::{CapabilityId, Digest, EffectClass, SliceId};

        use odin_kernel::{
            ApprovalRequirement, CapabilityContract, HandlerBinding, IdempotencyPolicy,
            MintRequest, RetryPolicy, TokenIssuer,
        };

        use crate::host_tools::executor::HostToolExecutor;
        use crate::host_tools::operations::{
            admission_digest, seat_operation_policy, session_capsule_id, wall_clock,
            DeclaredOperationCatalog, ProvisionedFreshAuthorityProvider, SessionOperationBinding,
            StaticSchemaCatalog, SupervisedAdapterStatus, UnsupervisedAdapterStatus,
        };

        /// Fixture signing/verification material for the probe's provisioned
        /// token authority. The probe is the external provisioner of its own
        /// disposable fixture; production odind never mints.
        const AUTHORITY_KEY: &[u8] = b"odin-probe deterministic authority key v1";
        const INPUT_SCHEMA_REF: &str = "probe/odin.lane_status.input.json";
        const OUTPUT_SCHEMA_REF: &str = "probe/odin.lane_status.output.json";

        let invalid = |detail: String| ProbeError::Fixture { detail };
        let capability =
            CapabilityId::new("odin.lane_status").map_err(|error| invalid(error.to_string()))?;
        let contract = CapabilityContract {
            id: capability.clone(),
            delegate_to: None,
            version: 1,
            tool_name: ToolName::new(LaneStatusTool::NAME)
                .map_err(|error| invalid(error.to_string()))?,
            description: "Probe-admitted durable status snapshot of the bound lane.".to_owned(),
            handler: HandlerBinding::Builtin {
                name: LaneStatusTool::NAME.to_owned(),
            },
            input_schema_ref: INPUT_SCHEMA_REF.to_owned(),
            output_schema_ref: OUTPUT_SCHEMA_REF.to_owned(),
            effect_class: EffectClass::R0,
            seat_tags: BTreeSet::from(["*".to_owned()]),
            timeout_seconds: NonZeroU32::new(5).expect("probe timeout"),
            idempotency: IdempotencyPolicy::Required,
            retry: RetryPolicy { max_attempts: 1 },
            approval: ApprovalRequirement::None,
            evidence_extractor: HandlerBinding::Builtin {
                name: LaneStatusEvidenceTool::ID.to_owned(),
            },
            adapter: None,
            preview: None,
            batchable: false,
            batch: None,
        };
        let contracts = BTreeMap::from([(capability.clone(), contract.clone())]);
        let admission =
            admission_digest(&contracts, 1).map_err(|error| invalid(error.to_string()))?;
        let registry = Arc::new(host_tools.clone());
        let executor = Arc::new(HostToolExecutor::new(Arc::clone(&registry)));
        let catalog: Arc<dyn odin_kernel::OperationCatalog> = Arc::new(
            DeclaredOperationCatalog::from_contracts(
                &contracts,
                1,
                admission,
                registry,
                &BTreeSet::new(),
            )
            .map_err(|error| invalid(error.to_string()))?,
        );
        let input = ToolSchema::from_value(serde_json::json!({
            "type": "object",
            "properties": {
                "laneId": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Lane to report; must equal the lane bound to this invocation."
                }
            },
            "required": ["laneId"],
            "additionalProperties": false
        }))
        .map_err(|error| invalid(error.to_string()))?;
        let output = ToolSchema::from_value(serde_json::json!({
            "type": "object",
            "additionalProperties": true
        }))
        .map_err(|error| invalid(error.to_string()))?;
        let schemas: Arc<dyn odin_kernel::SchemaCatalog + Send + Sync> = Arc::new(
            StaticSchemaCatalog::new([
                (INPUT_SCHEMA_REF.to_owned(), input),
                (OUTPUT_SCHEMA_REF.to_owned(), output),
            ])
            .map_err(|error| invalid(error.to_string()))?,
        );
        let token_root = self.work_dir.join("authority-tokens");
        std::fs::create_dir_all(&token_root)?;
        let now_ms = (wall_clock())();
        let issuer =
            TokenIssuer::new(AUTHORITY_KEY.to_vec()).map_err(|error| invalid(error.to_string()))?;
        let policy_draft =
            seat_operation_policy(crate::host_tools::operations::SeatOperationPolicyInputs {
                seat_id: self.ids.seat.clone(),
                slice_id: SliceId::new("odin-probe-slice")
                    .map_err(|error| invalid(error.to_string()))?,
                lane_id: self.ids.lane.clone(),
                seat_revision: Digest::hash(
                    format!("odin-probe-seat-revision:{}", self.ids.seat).as_bytes(),
                ),
                slice_revision: Digest::hash(b"odin-probe-slice-revision"),
                admission,
                seat_tool_refs: BTreeSet::from([capability.clone()]),
                slice_capabilities: BTreeSet::from([capability.clone()]),
                project_capabilities: BTreeSet::from([capability.clone()]),
                lane_capabilities: BTreeSet::from([capability]),
                denied_capabilities: BTreeSet::new(),
                denied_tools: BTreeSet::new(),
                resource_constraints: BTreeMap::new(),
                seat_categories: BTreeSet::new(),
            });
        // The probe's provisioned token is generation-bound like every
        // other: it names the probe's single composition revision, the one
        // the binding below serves.
        let token = issuer
            .mint_bound(
                MintRequest {
                    seat: policy_draft.policy.seat_id.clone(),
                    slice: policy_draft.policy.slice_id.clone(),
                    lane: policy_draft.policy.lane_id.clone(),
                    session: self.ids.session.clone(),
                    seat_revision: policy_draft.policy.seat_revision,
                    slice_revision: policy_draft.policy.slice_revision,
                    capability_policy_digest: admission,
                    context_policy_digest: policy_draft.context_policy_digest,
                    issued_at_ms: 0,
                    expires_at_ms: now_ms + 3_600_000,
                    entropy: b"odin-probe lane-status fixture token",
                },
                1,
            )
            .map_err(|error| invalid(error.to_string()))?;
        std::fs::write(
            token_root.join(format!("{}.json", self.ids.session.as_str())),
            serde_json::to_vec(&token).map_err(|error| invalid(error.to_string()))?,
        )?;
        let authority_provider = Arc::new(
            ProvisionedFreshAuthorityProvider::open(token_root, AUTHORITY_KEY.to_vec())
                .map_err(|error| invalid(error.to_string()))?,
        );
        // The probe's single-generation material source: the exact contracts
        // and policy this probe composed, pinned at the admission revision
        // its token was minted from — the one generation the binding below
        // resolves; nothing else ever serves.
        let probe_revision = 1_u64;
        let probe_lane = (
            policy_draft.policy.seat_id.clone(),
            policy_draft.policy.lane_id.clone(),
        );
        let material_source: Arc<dyn crate::host_tools::operations::RevisionMaterialSource> =
            Arc::new(ProbeMaterialSource {
                material: crate::host_tools::operations::RevisionMaterial {
                    revision: probe_revision,
                    contracts: Arc::new(contracts.clone()),
                    admission_digest: admission,
                    seat_operation_bindings: BTreeMap::from([(probe_lane, policy_draft.clone())]),
                    session_lanes: BTreeMap::new(),
                    tool_index: contracts
                        .iter()
                        .map(|(id, contract)| (contract.tool_name.as_ref().to_owned(), id.clone()))
                        .collect(),
                    contract_adapters: contracts
                        .values()
                        .filter_map(|contract| contract.adapter.clone())
                        .collect(),
                    declaration_decided: std::collections::BTreeSet::new(),
                    escalation_targets: Default::default(),
                },
            });
        let operations = HostToolOperations::new(
            crate::host_tools::operations::OperationStackInputs {
                workload_drafts: None,
                catalog,
                schemas,
                executor: Arc::clone(&executor),
                adapter_executor: Arc::clone(&executor) as Arc<dyn odin_kernel::OperationExecutor>,
                adapter_status: Arc::new(SupervisedAdapterStatus::new(
                    Arc::new(UnsupervisedAdapterStatus),
                    std::collections::BTreeSet::new(),
                    std::time::Duration::ZERO,
                )),
                limits: Limits::new(u64::MAX, u64::MAX, u64::MAX),
                clock: wall_clock(),
                ledger: Arc::clone(ledger),
                revisions: material_source,
            },
            contracts,
            authority_provider,
        )
        .map_err(|error| invalid(error.to_string()))?;
        let binding = SessionOperationBinding {
            policy: policy_draft.policy,
            context_policy_digest: policy_draft.context_policy_digest,
            capsule_id: session_capsule_id(&self.ids.session)
                .map_err(|error| invalid(error.to_string()))?,
            served_revision: probe_revision,
            parent: None,
        };
        let listing = operations
            .session_listing(&binding, &self.ids.session)
            .map_err(|error| invalid(error.to_string()))?;
        let registered = host_tools.listed_names().collect::<BTreeSet<_>>();
        let admitted_host_tools = listing
            .tools
            .iter()
            .map(|tool| tool.tool_name.as_str())
            .filter(|name| registered.contains(*name))
            .map(str::to_owned)
            .collect();
        Ok((operations, binding, admitted_host_tools))
    }
}

/// The probe's retained-publication source: one generation, the exact
/// contracts and policy the probe composed at its admission revision.
/// Every other revision and every legacy resolution refuses — the probe
/// never widens beyond the material it minted its token from.
struct ProbeMaterialSource {
    material: crate::host_tools::operations::RevisionMaterial,
}

impl crate::host_tools::operations::RevisionMaterialSource for ProbeMaterialSource {
    fn material_at(
        &self,
        revision: u64,
    ) -> Result<crate::host_tools::operations::RevisionMaterial, String> {
        if revision == self.material.revision {
            return Ok(self.material.clone());
        }
        Err(format!(
            "probe serves only publication revision {} (asked for {revision})",
            self.material.revision
        ))
    }

    fn resolve_legacy(&self, _token: &odin_domain::SeatToken) -> Result<u64, String> {
        Err("probe authority resolves no legacy generation".to_owned())
    }
}
