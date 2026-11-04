//! The exact per-case context: deterministic identity minting, the retained
//! work-dir layout, and the probe's live authority composition (host tools, operation stack, provisioned
//! token authority) behind the assembled bridge configuration.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ::time::OffsetDateTime;
use odin_atlas::Atlas;
use odin_domain::{Digest, LaneId, ProjectId, RunId, Scope, SeatId, SessionId};
use odin_ledger::lane_run::{self, NewLane, NewRun};
use odin_ledger::Ledger;

use crate::bridge::{BridgeBinding, LiveSessionDescriptor, OmpBridgeConfig};
use crate::host_tools::lane_status::{LaneStatusEvidenceTool, LaneStatusTool};
use crate::host_tools::operations::{HostToolOperations, SessionOperationBinding};
use crate::host_tools::{HostToolError, HostToolRegistry, ModelVisibleToolConfig};
use crate::process::{OmpProcessSpec, OmpWorkerLaunch};
use crate::uri::{ScopedUriRouter, MAX_ARTIFACT_READ_BOUND};

use super::config::{ProbeConfig, DEFAULT_MODEL_SELECTOR, FIXTURE_MODEL_A, FIXTURE_PROVIDER};
use super::contracts::{ConformanceCaseId, ProbeError};
use super::CaseContext;

/// Session lease TTL stamped onto every probe bridge binding.
const SESSION_LEASE_TTL: Duration = Duration::from_secs(60);
/// The slice every probe session and its admitted capability belong to.
const PROBE_SLICE_ID: &str = "odin-probe-slice";
/// Timeout the probe's lane-status capability declares.
const PROBE_TOOL_TIMEOUT_SECONDS: u32 = 5;
/// Lifetime of the probe's provisioned token; the suite runs far inside it.
const PROBE_TOKEN_TTL_MS: u64 = 3_600_000;

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
                input_hash: Digest::hash(format!("case-{:02}", case.get()).as_bytes()).hex(),
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
            slice_id: PROBE_SLICE_ID.to_owned(),
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
        let artifact_root = self.artifact_root();
        std::fs::create_dir_all(&artifact_root)?;
        let ledger = self.ledger();
        let atlas = Arc::new(OnceLock::from(self.atlas()));
        let allowed_atlas_scope =
            odin_atlas::AtlasScope::seat([format!("probe:{}", self.ids.seat)])
                .map_err(HostToolError::Atlas)?;
        let host_tools = HostToolRegistry::model_visible(ModelVisibleToolConfig {
            ledger: Arc::clone(&ledger),
            atlas: Arc::clone(&atlas),
            allowed_atlas_scope: allowed_atlas_scope.clone(),
        })?;
        let uri_router = ScopedUriRouter::new(
            ledger.clone(),
            atlas,
            allowed_atlas_scope,
            artifact_root.clone(),
            MAX_ARTIFACT_READ_BOUND,
            BTreeMap::new(),
        )?;
        let (operations, operation_binding, admitted_host_tools) =
            self.operation_surface(&host_tools, &ledger)?;
        Ok(OmpBridgeConfig {
            process: self.process_spec(DEFAULT_MODEL_SELECTOR, Vec::new()),
            worker: self.config.omp.worker.clone(),
            ledger,
            operations,
            operation_binding,
            admitted_host_tools,
            uri_router,
            artifact_root,
            context_trace_root: None,
            binding: self.binding(),
            session,
            lease_ttl: SESSION_LEASE_TTL,
            rollover: None,
            rollover_children: None,
            requested_epoch: None,
            fresh_bound: None,
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
        use std::num::NonZeroU32;

        use odin_domain::knowledge::{ToolName, ToolSchema};
        use odin_domain::operation::Limits;
        use odin_domain::{CapabilityId, EffectClass, SliceId};

        use odin_kernel::{
            ApprovalRequirement, CapabilityContract, HandlerBinding, IdempotencyPolicy,
            MintRequest, RetryPolicy, TokenIssuer,
        };

        use crate::host_tools::executor::HostToolExecutor;
        use crate::host_tools::operations::{
            admission_digest, seat_operation_policy, session_capsule_id, wall_clock,
            DeclaredOperationCatalog, ProvisionedFreshAuthorityProvider, StaticSchemaCatalog,
            SupervisedAdapterStatus, UnsupervisedAdapterStatus,
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
            toolset: None,
            op: None,
            expose: None,
            seat_ops: Default::default(),
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
            timeout_seconds: NonZeroU32::new(PROBE_TOOL_TIMEOUT_SECONDS).expect("probe timeout"),
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
                slice_id: SliceId::new(PROBE_SLICE_ID)
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
                    expires_at_ms: now_ms + PROBE_TOKEN_TTL_MS,
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
